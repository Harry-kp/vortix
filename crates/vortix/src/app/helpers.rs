//! Logging, scrolling, toast notifications, and utility helpers.

use std::path::Path;
use std::time::Instant;
use time::OffsetDateTime;

use super::{App, FocusedPanel, Toast, ToastType, DISMISS_DURATION};
use crate::constants;
use crate::logger::{self, LogLevel};
use crate::utils;

impl App {
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
            &self.config_dir,
            self.config.log_rotation_size,
            self.config.log_retention_days,
        );
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
                let last = self.profiles.len().saturating_sub(1);
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

    /// Get the maximum scroll position for the config viewer.
    /// This accounts for viewport height so scrolling stops when last line is visible.
    pub(crate) fn get_config_max_scroll(&self) -> u16 {
        if let Some(content) = &self.cached_config_content {
            #[allow(clippy::cast_possible_truncation)]
            let total_lines = content.lines().count() as u16;
            let viewport_height = (self.terminal_size.1 * constants::CONFIG_VIEWER_HEIGHT_PCT
                / 100)
                .saturating_sub(constants::CONFIG_VIEWER_CHROME_LINES);
            return total_lines.saturating_sub(viewport_height);
        }
        0
    }

    /// Copy public IP address to clipboard
    pub(crate) fn copy_ip_to_clipboard(&mut self) {
        let ip_str = self.public_ip.clone();
        if ip_str.is_empty() || ip_str == constants::MSG_FETCHING || ip_str.starts_with("Error") {
            self.show_toast("No valid IP available yet".to_string(), ToastType::Error);
            return;
        }
        #[cfg(target_os = "macos")]
        {
            use std::io::Write;
            if let Ok(mut child) = std::process::Command::new("pbcopy")
                .stdin(std::process::Stdio::piped())
                .spawn()
            {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(ip_str.as_bytes());
                }
                let _ = child.wait();
                self.show_toast(format!("Copied IP: {ip_str}"), ToastType::Success);
                return;
            }
        }
        #[cfg(target_os = "linux")]
        {
            use std::io::Write;
            // Wayland-first: try wl-copy when $WAYLAND_DISPLAY is set,
            // then fall back to X11 tools (xclip, xsel).
            let is_wayland = std::env::var("WAYLAND_DISPLAY").is_ok();
            let tools: &[(&str, &[&str])] = if is_wayland {
                &[
                    ("wl-copy", &[]),
                    ("xclip", &["-selection", "clipboard"]),
                    ("xsel", &["--clipboard", "--input"]),
                ]
            } else {
                &[
                    ("xclip", &["-selection", "clipboard"]),
                    ("xsel", &["--clipboard", "--input"]),
                    ("wl-copy", &[]),
                ]
            };
            for (cmd, args) in tools {
                if let Ok(mut child) = std::process::Command::new(cmd)
                    .args(*args)
                    .stdin(std::process::Stdio::piped())
                    .spawn()
                {
                    if let Some(mut stdin) = child.stdin.take() {
                        let _ = stdin.write_all(ip_str.as_bytes());
                    }
                    if child.wait().is_ok_and(|s| s.success()) {
                        self.show_toast(format!("Copied IP: {ip_str}"), ToastType::Success);
                        return;
                    }
                }
            }
        }
        #[allow(unreachable_code)]
        self.show_toast("Failed to copy to clipboard".to_string(), ToastType::Error);
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
