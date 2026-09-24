//! Logging, scrolling, toast notifications, and utility helpers.

use std::time::Instant;

use base64::engine::{general_purpose::STANDARD as BASE64, Engine as _};

use super::{App, FocusedPanel, Toast, ToastType};
use crate::constants;
use crate::logger::{self, LogLevel};

impl App {
    /// Profile name for logs and dialogs. Profile ids are 64-char digests and
    /// mean nothing to the reader.
    pub(crate) fn profile_display_name(&self, profile_id: &crate::profile::ProfileId) -> String {
        self.runtime
            .profiles
            .iter()
            .find(|profile| &profile.id == profile_id)
            .map_or_else(
                || format!("ProfileMissing:{profile_id}"),
                |profile| profile.name.clone(),
            )
    }

    /// The tunnel the dashboard treats as current: the primary, else the
    /// first one.
    #[must_use]
    pub fn current_tunnel(&self) -> Option<&crate::control::TunnelView> {
        self.primary_id()
            .and_then(|pid| self.tunnel(pid))
            .or_else(|| self.tunnels().into_iter().next())
    }

    /// How long one telemetry observation may go unrefreshed before its
    /// value stops standing for the present.
    ///
    /// Each field is refreshed by its own probe on its own schedule, so this
    /// is asked per observation, never once for the whole panel. A few poll
    /// intervals absorbs a slow poll and a retry; the floor keeps a very
    /// short configured interval from making normal jitter look like a stall.
    pub(crate) fn telemetry_stale_after(&self) -> std::time::Duration {
        let polls = u64::from(constants::TELEMETRY_STALE_AFTER_POLLS);
        std::time::Duration::from_secs(
            self.runtime
                .config
                .telemetry_poll_rate
                .saturating_mul(polls)
                .max(constants::TELEMETRY_STALE_FLOOR_SECS),
        )
    }

    /// Whether an observation taken at `observed_at` is too old to present as
    /// current. An observation that has never landed is not stale — it is
    /// still pending, which callers render differently.
    #[must_use]
    pub(crate) fn observation_is_stale(&self, observed_at: Option<Instant>) -> bool {
        observed_at.is_some_and(|at| at.elapsed() > self.telemetry_stale_after())
    }

    pub(crate) fn has_active_connection(&self) -> bool {
        self.control_snapshot
            .tunnels
            .iter()
            .any(|tunnel| tunnel.phase == crate::control::Phase::Up)
    }

    /// Add a log message via centralized logger
    pub(crate) fn log(&mut self, message: &str) {
        let (category, content, level) = classify_log_message(message);

        // Log via centralized logger
        logger::log(level, category, content);

        if self.logs_auto_scroll {
            self.logs_scroll = self.logs_max_scroll;
        }

        // Auto-save to log file
        let timestamp = crate::ui::helpers::format_local_time();
        let level_tag = level.prefix();
        crate::logger::append_to_file(
            &[format!("{timestamp} [{level_tag}] {category}: {content}")],
            &self.runtime.config_dir,
            self.runtime.config.log_rotation_size,
            self.runtime.config.log_retention_days,
        );
    }

    /// Resolve a user/scanner-facing display name at the App boundary.
    /// Internal engine snapshot and lifecycle code carries the returned stable ID.
    #[must_use]
    pub(crate) fn profile_id_for_name(
        &self,
        display_name: &str,
    ) -> Option<crate::profile::ProfileId> {
        self.runtime
            .profiles
            .iter()
            .find(|profile| profile.name == display_name)
            .map(|profile| profile.id.clone())
    }

    /// Whether the named profile has a tunnel in any phase; deletion refuses
    /// while it does.
    #[must_use]
    pub(crate) fn is_profile_active(&self, profile_name: &str) -> bool {
        self.profile_id_for_name(profile_name)
            .is_some_and(|id| self.tunnel(&id).is_some())
    }

    /// Whether the profile at `idx` is currently Connecting (in-flight).
    /// Used by the `c` cancel keybinding.
    #[must_use]
    pub(crate) fn is_profile_connecting(&self, idx: usize) -> bool {
        let Some(profile) = self.runtime.profiles.get(idx) else {
            return false;
        };
        self.tunnel(&profile.id)
            .is_some_and(|tunnel| tunnel.phase == crate::control::Phase::Starting)
    }

    /// Resolve the profile index that the Connection Details panel is
    /// currently focused on. Always mirrors the sidebar selection —
    /// the user picks which tunnel's details to view by navigating
    /// the profile list (j/k on the sidebar). Earlier multi-tunnel
    /// iteration added a Tab-in-Details binding to cycle across
    /// active tunnels; that broke global panel navigation, so it was
    /// removed and Connection Details went back to the simpler
    /// "follow the sidebar" rule.
    #[must_use]
    pub(crate) fn connection_details_focused_idx(&self) -> Option<usize> {
        self.profile_list_state.selected()
    }

    /// Show a toast notification and log it
    pub(crate) fn show_toast(&mut self, message: String, toast_type: ToastType) {
        let level_prefix = match toast_type {
            ToastType::Error => "ERR",
            ToastType::Warning => "WARN",
            ToastType::Success | ToastType::Info => "APP",
        };
        self.log(&format!("{level_prefix}: {message}"));
        if self
            .toast
            .as_ref()
            .is_some_and(|toast| toast.toast_type == ToastType::Error)
            && toast_type == ToastType::Info
        {
            return;
        }
        let expires = Instant::now() + toast_type.dismiss_duration();
        self.toast = Some(Toast {
            message,
            toast_type,
            expires,
        });
    }

    /// Step the Event Log down, resuming follow-the-tail near the bottom.
    pub(crate) fn scroll_logs_down(&mut self) {
        if self.logs_scroll < self.logs_max_scroll {
            self.logs_scroll = self.logs_scroll.saturating_add(1);
        }
        if self.logs_scroll
            >= self
                .logs_max_scroll
                .saturating_sub(constants::LOGS_AUTO_SCROLL_THRESHOLD)
        {
            self.logs_auto_scroll = true;
        }
    }

    /// Step the Event Log up, which stops following the tail.
    pub(crate) fn scroll_logs_up(&mut self) {
        self.logs_auto_scroll = false;
        self.logs_scroll = self.logs_scroll.saturating_sub(1);
    }

    pub(crate) fn scroll_down(&mut self) {
        // 1. Config Viewer Overlay (Highest Priority)
        if self.show_config {
            let max_scroll = self.get_config_max_scroll();
            if self.config_scroll < max_scroll {
                self.config_scroll += 1;
            }
            return;
        }

        // 2. Focused Panel
        match self.focused_panel {
            FocusedPanel::Sidebar => {
                let current = self.profile_list_state.selected().unwrap_or(0);
                let last = self.runtime.profiles.len().saturating_sub(1);
                if current < last {
                    self.profile_list_state.select(Some(current + 1));
                }
            }
            FocusedPanel::Logs => {
                self.scroll_logs_down();
            }
            _ => {}
        }
    }

    pub(crate) fn scroll_up(&mut self) {
        // 1. Config Viewer Overlay (Highest Priority)
        if self.show_config {
            self.config_scroll = self.config_scroll.saturating_sub(1);
            return;
        }

        // 2. Focused Panel
        match self.focused_panel {
            FocusedPanel::Sidebar => {
                let current = self.profile_list_state.selected().unwrap_or(0);
                if current > 0 {
                    self.profile_list_state.select(Some(current - 1));
                }
            }
            FocusedPanel::Logs => {
                self.scroll_logs_up();
            }
            _ => {}
        }
    }

    // Cycle to next panel
    pub(crate) fn next_panel(&mut self) {
        self.focused_panel = match self.focused_panel {
            FocusedPanel::Sidebar => FocusedPanel::Chart,
            FocusedPanel::Chart => FocusedPanel::ConnectionDetails,
            FocusedPanel::ConnectionDetails => FocusedPanel::Security,
            FocusedPanel::Security => FocusedPanel::Logs,
            FocusedPanel::Logs => FocusedPanel::Sidebar,
        };
    }

    // Cycle to previous panel
    pub(crate) fn previous_panel(&mut self) {
        self.focused_panel = match self.focused_panel {
            FocusedPanel::Sidebar => FocusedPanel::Logs,
            FocusedPanel::Logs => FocusedPanel::Security,
            FocusedPanel::Security => FocusedPanel::ConnectionDetails,
            FocusedPanel::ConnectionDetails => FocusedPanel::Chart,
            FocusedPanel::Chart => FocusedPanel::Sidebar,
        };
    }

    /// Return the panel whose rendered area contains the given screen coordinate.
    pub(crate) fn panel_at(&self, col: u16, row: u16) -> Option<FocusedPanel> {
        for (panel, area) in &self.panel_areas {
            if col >= area.x
                && col < area.x + area.width
                && row >= area.y
                && row < area.y + area.height
            {
                return Some(panel.clone());
            }
        }
        None
    }

    /// Maximum scroll position for the config viewer overlay.
    ///
    /// O(1): reads the line count cached in [`CachedConfigView`] (built
    /// once when the user opened the viewer) instead of iterating
    /// `content.lines()` on every keystroke. Aggressive `j`/`k` /
    /// arrow-key spam used to wedge the TUI here because each call paid
    /// the full file scan; now it's a struct-field read.
    pub(crate) fn get_config_max_scroll(&self) -> u16 {
        let Some(cached) = self.cached_config.as_ref() else {
            return 0;
        };
        let viewport_height = (self.terminal_size.1 * constants::CONFIG_VIEWER_HEIGHT_PCT / 100)
            .saturating_sub(constants::CONFIG_VIEWER_CHROME_LINES);
        cached.total_lines.saturating_sub(viewport_height)
    }

    /// Copy the current public IPv4 address to clipboard.
    pub(crate) fn copy_ip_to_clipboard(&mut self) {
        let ip_str = self.runtime.public_ip.clone();
        if ip_str.is_empty() || ip_str == constants::MSG_FETCHING || ip_str.starts_with("Error") {
            self.show_toast("No valid IPv4 available yet".to_string(), ToastType::Error);
            return;
        }
        let result = {
            use std::io::Write as _;
            let mut stdout = std::io::stdout();
            stdout
                .write_all(osc52_clipboard(&ip_str).as_bytes())
                .and_then(|()| stdout.flush())
        };
        match result {
            Ok(()) => self.show_toast(format!("Copied IPv4: {ip_str}"), ToastType::Success),
            Err(error) => self.show_toast(
                format!("Failed to copy to clipboard: {error}"),
                ToastType::Error,
            ),
        }
    }
}

fn classify_log_message(message: &str) -> (&str, &str, LogLevel) {
    let Some(idx) = message.find(':') else {
        return ("APP", message, LogLevel::Info);
    };
    let category = message[..idx].trim();
    let content = message[idx + 1..].trim();
    let level = match category {
        "ERR" | "CMD_ERR" => LogLevel::Error,
        "WARN" => LogLevel::Warning,
        _ => LogLevel::Info,
    };
    (category, content, level)
}

fn osc52_clipboard(text: &str) -> String {
    format!("\x1b]52;c;{}\x1b\\", BASE64.encode(text))
}

#[cfg(test)]
mod tests {
    #[test]
    fn clipboard_sequence_targets_terminal_host_clipboard() {
        assert_eq!(
            super::osc52_clipboard("203.0.113.5"),
            "\x1b]52;c;MjAzLjAuMTEzLjU=\x1b\\"
        );
    }
}
