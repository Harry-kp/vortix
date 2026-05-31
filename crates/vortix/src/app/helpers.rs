//! Logging, scrolling, toast notifications, and utility helpers.

use std::path::Path;
use std::time::Instant;
use time::OffsetDateTime;

use super::{App, FocusedPanel, Toast, ToastType, DISMISS_DURATION};
use crate::constants;
use crate::logger::{self, LogLevel};
use crate::utils;

impl App {
    /// Derive a legacy `ConnectionState` view from the registry primary.
    ///
    /// Post-P5d the App layer no longer carries a `connection_state`
    /// field on `VpnRuntime`; this method computes the single-tunnel
    /// view from `registry.primary()`. Falls back to the first
    /// non-Disconnected entry when no primary is set (so Connecting
    /// transitions surface before the FSM owns the default route).
    ///
    /// Used by code paths that still think in single-tunnel terms
    /// (kill switch sync, profile delete safety, scanner dispatch).
    /// All multi-tunnel-aware paths read `app.registry.snapshot_all`
    /// directly.
    #[must_use]
    pub fn legacy_state(&self) -> crate::vpn_runtime::ConnectionState {
        use crate::vortix_core::engine::state::Connection;
        use crate::vpn_runtime::{ConnectionState, DetailedConnectionInfo};

        let snap = self
            .registry
            .primary()
            .and_then(|pid| self.registry.snapshot(pid))
            .or_else(|| {
                self.registry
                    .snapshot_all()
                    .into_iter()
                    .find(|s| !matches!(s.state, Connection::Disconnected { .. }))
            });
        let Some(snap) = snap else {
            return ConnectionState::Disconnected;
        };

        let now = std::time::SystemTime::now();
        let to_instant = |t: std::time::SystemTime| {
            now.duration_since(t)
                .ok()
                .and_then(|d| Instant::now().checked_sub(d))
                .unwrap_or_else(Instant::now)
        };

        match snap.state {
            Connection::Disconnected { .. } => ConnectionState::Disconnected,
            Connection::Connecting { started_at, .. }
            | Connection::Reconnecting { started_at, .. } => ConnectionState::Connecting {
                started: to_instant(started_at),
                profile: snap.profile_id.as_str().to_string(),
            },
            Connection::AwaitingUserInput { since, .. } => ConnectionState::Connecting {
                started: to_instant(since),
                profile: snap.profile_id.as_str().to_string(),
            },
            Connection::Connected { since, details, .. } => {
                let server_location = self
                    .runtime
                    .profiles
                    .iter()
                    .find(|p| p.name == snap.profile_id.as_str())
                    .map_or_else(|| "Unknown".to_string(), |p| p.location.clone());
                ConnectionState::Connected {
                    since: to_instant(since),
                    profile: snap.profile_id.as_str().to_string(),
                    server_location,
                    latency_ms: 0,
                    details: Box::new(DetailedConnectionInfo {
                        interface: details.interface.clone(),
                        internal_ip: details.internal_ip.clone(),
                        endpoint: details.endpoint.clone(),
                        mtu: details.mtu.clone(),
                        public_key: details.public_key.clone(),
                        listen_port: details.listen_port.clone(),
                        transfer_rx: details.transfer_rx.clone(),
                        transfer_tx: details.transfer_tx.clone(),
                        latest_handshake: details.latest_handshake.clone(),
                        pid: details.pid,
                    }),
                }
            }
            Connection::Disconnecting { started_at, .. } => ConnectionState::Disconnecting {
                started: to_instant(started_at),
                profile: snap.profile_id.as_str().to_string(),
            },
        }
    }

    /// Build the `ActiveTunnelInfo` slice consumed by the kill switch
    /// from registry snapshots. Multi-tunnel-aware — every Connected
    /// entry contributes a tunnel, with the registry's primary marked
    /// `is_primary: true`.
    #[must_use]
    pub(crate) fn active_tunnels_for_killswitch(
        &self,
    ) -> Vec<crate::core::killswitch::ActiveTunnelInfo> {
        use crate::core::killswitch::ActiveTunnelInfo;
        use crate::vortix_core::engine::state::Connection;
        let primary = self.registry.primary().cloned();
        self.registry
            .snapshot_all()
            .into_iter()
            .filter_map(|s| match s.state {
                Connection::Connected { details, .. } => {
                    let server_ips = details
                        .endpoint
                        .split(':')
                        .next()
                        .and_then(|h| h.parse().ok())
                        .into_iter()
                        .collect();
                    let is_primary = primary.as_ref() == Some(&s.profile_id);
                    Some(ActiveTunnelInfo {
                        interface: details.interface.clone(),
                        server_ips,
                        declared_cidrs: Vec::new(),
                        is_primary,
                    })
                }
                _ => None,
            })
            .collect()
    }

    /// Whether the registry currently has at least one Connected tunnel.
    #[must_use]
    pub(crate) fn has_active_connection(&self) -> bool {
        use crate::vortix_core::engine::state::Connection;
        self.registry
            .snapshot_all()
            .iter()
            .any(|s| matches!(s.state, Connection::Connected { .. }))
    }

    /// Add a log message via centralized logger
    pub(crate) fn log(&mut self, message: &str) {
        // Parse "PREFIX: content" — the prefix determines both the category and the level.
        let (category, content, level) = if let Some(idx) = message.find(':') {
            let prefix = message[..idx].trim();
            let msg = message[idx + 1..].trim();

            let lvl = match prefix {
                // Errors
                "ERR" | "CMD_ERR" => LogLevel::Error,
                // Warnings
                "WARN" => LogLevel::Warning,
                // Everything else is informational (STATUS, ACTION, NET, SEC, AUTH, etc.)
                _ => LogLevel::Info,
            };

            (prefix, msg, lvl)
        } else {
            ("APP", message, LogLevel::Info)
        };

        // Log via centralized logger
        logger::log(level, category, content);

        if self.logs_auto_scroll {
            self.logs_scroll = self.logs_max_scroll;
        }

        // Auto-save to log file
        let timestamp = utils::format_local_time();
        let level_tag = level.prefix();
        Self::append_to_log_file(
            &format!("{timestamp} [{level_tag}] {category}: {content}"),
            &self.runtime.config_dir,
            self.runtime.config.log_rotation_size,
            self.runtime.config.log_retention_days,
        );
    }

    /// Count active tunnels for keybinding decisions (multi-connection plan
    /// #001 U19). "Active" means the FSM is not `Disconnected` — that
    /// includes `Connecting`, `Connected`, `Disconnecting`,
    /// `AwaitingUserInput`, and any other in-flight states.
    #[must_use]
    pub(crate) fn active_tunnel_count(&self) -> usize {
        use crate::vortix_core::engine::state::Connection;
        self.registry
            .snapshot_all()
            .iter()
            .filter(|s| !matches!(s.state, Connection::Disconnected { .. }))
            .count()
    }

    /// Return the list of `ProfileId`s for currently-active tunnels in a
    /// stable order. Used by the `Tab` focus-cycle in Connection Details.
    pub(crate) fn active_tunnel_ids(&self) -> Vec<crate::vortix_core::profile::ProfileId> {
        use crate::vortix_core::engine::state::Connection;
        let mut out: Vec<_> = self
            .registry
            .snapshot_all()
            .into_iter()
            .filter(|s| !matches!(s.state, Connection::Disconnected { .. }))
            .map(|s| s.profile_id)
            .collect();
        out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        out
    }

    /// Whether the profile at `idx` is currently in a Connected state. Used
    /// by the `d` / `Enter` keybindings to decide between connect and
    /// disconnect routing (multi-connection plan #001 U19).
    #[must_use]
    pub(crate) fn is_profile_connected(&self, idx: usize) -> bool {
        use crate::vortix_core::engine::state::Connection;
        use crate::vortix_core::profile::ProfileId;
        let Some(profile) = self.runtime.profiles.get(idx) else {
            return false;
        };
        self.registry
            .snapshot(&ProfileId::new(&profile.name))
            .is_some_and(|snap| matches!(snap.state, Connection::Connected { .. }))
    }

    /// Whether the named profile is currently in any non-`Disconnected` state
    /// (`Connecting` / `Connected` / `Disconnecting` / `Reconnecting` /
    /// `AwaitingUserInput`). Used by deletion-safety checks where we need
    /// to refuse to delete a profile that has an in-flight or active
    /// tunnel.
    #[must_use]
    pub(crate) fn is_profile_active(&self, profile_name: &str) -> bool {
        use crate::vortix_core::engine::state::Connection;
        use crate::vortix_core::profile::ProfileId;
        self.registry
            .snapshot(&ProfileId::new(profile_name))
            .is_some_and(|snap| !matches!(snap.state, Connection::Disconnected { .. }))
    }

    /// Whether the profile at `idx` is currently Connecting (in-flight).
    /// Used by the `c` cancel keybinding (multi-connection plan #001 U19).
    #[must_use]
    pub(crate) fn is_profile_connecting(&self, idx: usize) -> bool {
        use crate::vortix_core::engine::state::Connection;
        use crate::vortix_core::profile::ProfileId;
        let Some(profile) = self.runtime.profiles.get(idx) else {
            return false;
        };
        self.registry
            .snapshot(&ProfileId::new(&profile.name))
            .is_some_and(|snap| matches!(snap.state, Connection::Connecting { .. }))
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
        self.toast = Some(Toast {
            message,
            toast_type,
            expires: Instant::now() + DISMISS_DURATION,
        });
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
                self.logs_auto_scroll = false;
                self.logs_scroll = self.logs_scroll.saturating_sub(1);
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

    /// Copy public IP address to clipboard.
    ///
    /// Plan 002 U8: replaced platform-specific shell-outs (pbcopy on
    /// macOS; xclip/wl-copy/xsel on Linux) with the `arboard` crate,
    /// which auto-detects the platform clipboard backend. Users no
    /// longer need any of those binaries installed.
    pub(crate) fn copy_ip_to_clipboard(&mut self) {
        let ip_str = self.runtime.public_ip.clone();
        if ip_str.is_empty() || ip_str == constants::MSG_FETCHING || ip_str.starts_with("Error") {
            self.show_toast("No valid IP available yet".to_string(), ToastType::Error);
            return;
        }
        match arboard::Clipboard::new() {
            Ok(mut clipboard) => match clipboard.set_text(ip_str.clone()) {
                Ok(()) => {
                    self.show_toast(format!("Copied IP: {ip_str}"), ToastType::Success);
                }
                Err(e) => {
                    self.show_toast(
                        format!("Failed to copy to clipboard: {e}"),
                        ToastType::Error,
                    );
                }
            },
            Err(e) => {
                // Common in headless environments (CI, SSH without
                // X-forwarding). Match the prior implementation's
                // soft-fail behavior.
                self.show_toast(format!("Clipboard unavailable: {e}"), ToastType::Error);
            }
        }
    }

    /// Append log entry to file with automatic rotation
    fn append_to_log_file(
        entry: &str,
        config_dir: &std::path::Path,
        rotation_size: u64,
        retention_days: u64,
    ) {
        static CLEANUP_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        use std::io::Write;

        let log_dir = config_dir.join(constants::LOGS_DIR_NAME);

        // Create log directory if needed
        if crate::utils::create_user_dir(&log_dir).is_err() {
            return;
        }

        // Use date-based log file
        let today = OffsetDateTime::now_local()
            .unwrap_or_else(|_| OffsetDateTime::now_utc())
            .date();
        let log_file = log_dir.join(format!("vortix-{today}.log"));

        // Rotate if the file exceeds the configured size
        if let Ok(metadata) = std::fs::metadata(&log_file) {
            if metadata.len() > rotation_size {
                let rotated = log_dir.join(format!("vortix-{today}.1.log"));
                let _ = std::fs::rename(&log_file, rotated);
            }
        }

        // Append to log file
        let is_new_log = !log_file.exists();
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
        {
            let _ = writeln!(file, "{entry}");
            if is_new_log {
                crate::config::fix_ownership(&log_file);
            }
        }

        // Clean up old logs periodically
        let count = CLEANUP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count % constants::LOG_CLEANUP_INTERVAL == 0 {
            Self::cleanup_old_logs(&log_dir, retention_days);
        }
    }

    /// Remove log files older than `retention_days` days.
    fn cleanup_old_logs(log_dir: &Path, retention_days: u64) {
        use std::time::{Duration, SystemTime};

        let max_age = Duration::from_secs(retention_days * 24 * 60 * 60);
        let cutoff = SystemTime::now()
            .checked_sub(max_age)
            .unwrap_or(SystemTime::UNIX_EPOCH);

        if let Ok(entries) = std::fs::read_dir(log_dir) {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    if let Ok(modified) = metadata.modified() {
                        if modified < cutoff {
                            let _ = std::fs::remove_file(entry.path());
                        }
                    }
                }
            }
        }
    }
}
