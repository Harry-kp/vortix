//! UI state types.

use super::Protocol;
use std::time::{Duration, Instant};

/// Duration for toast notifications to remain visible.
pub const DISMISS_DURATION: Duration = Duration::from_secs(4);
pub const HELP_OVERLAY_MAX_HEIGHT: u16 = 38;

/// Currently focused UI panel for keyboard navigation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub enum FocusedPanel {
    /// VPN profiles sidebar.
    #[default]
    Sidebar,
    /// Connection details panel (bottom left).
    ConnectionDetails,
    /// Throughput chart (top right).
    Chart,
    /// Security guard panel (bottom right -> left).
    Security,
    /// Activity log panel (bottom right -> right).
    Logs,
}

/// Which field is focused in the auth credentials overlay.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AuthField {
    /// Username text input.
    Username,
    /// Password text input (masked).
    Password,
    /// "Save credentials" checkbox.
    SaveCheckbox,
}

/// Current input mode determining keyboard behavior.
#[derive(Clone, Debug, PartialEq, Default)]
pub enum InputMode {
    /// Normal navigation mode.
    #[default]
    Normal,
    /// File path import dialog is active.
    Import {
        /// Current input path string.
        path: String,
        /// Current cursor position in the path string.
        cursor: usize,
    },
    /// Dependency error dialog showing missing tools.
    DependencyError {
        /// Protocol that requires the missing dependencies.
        protocol: Protocol,
        /// List of missing tool names.
        missing: Vec<String>,
    },
    /// Permission denied error dialog.
    PermissionDenied {
        /// Description of the action that was denied.
        action: String,
    },
    /// Delete confirmation dialog.
    ConfirmDelete {
        /// Index of the profile to delete.
        index: usize,
        /// Name of the profile to delete.
        name: String,
        /// Is "Yes" selected?
        confirm_selected: bool,
    },
    /// Help overlay showing all keybindings.
    Help {
        /// Vertical scroll offset.
        scroll: u16,
    },
    /// Profile rename dialog.
    Rename {
        /// Index of the profile being renamed.
        index: usize,
        /// New name being typed.
        new_name: String,
        /// Cursor position.
        cursor: usize,
    },
    /// Profile search/filter mode.
    Search {
        /// Current search query string.
        query: String,
        /// Cursor position in the query.
        cursor: usize,
    },
    /// Confirmation dialog for switching VPN profile while connected.
    ConfirmSwitch {
        from: String,
        to_idx: usize,
        to_name: String,
        confirm_selected: bool,
    },
    /// `OpenVPN` authentication credentials dialog.
    AuthPrompt {
        /// Index of the profile requiring auth.
        profile_idx: usize,
        /// Name of the profile (for display).
        profile_name: String,
        /// Username input.
        username: String,
        /// Cursor position in the username field.
        username_cursor: usize,
        /// Password input.
        password: String,
        /// Cursor position in the password field.
        password_cursor: usize,
        /// Which field is currently focused.
        focused_field: AuthField,
        /// Whether to persist credentials for future sessions.
        save_credentials: bool,
        /// Whether to auto-connect after submitting (false = save-only mode).
        connect_after: bool,
    },
}

#[must_use]
pub fn help_max_scroll_for_terminal_height(terminal_height: u16, total_lines: u16) -> u16 {
    if terminal_height == 0 {
        return 0;
    }

    let overlay_height = terminal_height
        .saturating_sub(2)
        .min(HELP_OVERLAY_MAX_HEIGHT);
    let inner_height = overlay_height.saturating_sub(2);
    total_lines.saturating_sub(inner_height)
}

/// State for the panel flip animation.
pub struct FlipAnimation {
    /// Which panel is being animated.
    pub panel: FocusedPanel,
    /// When the animation started.
    pub started: Instant,
    /// Whether flipping toward the back (true) or toward the front (false).
    pub to_back: bool,
}

impl FlipAnimation {
    /// Progress from 0.0 (start) to 1.0 (complete), clamped.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn progress(&self) -> f64 {
        let elapsed_us = self.started.elapsed().as_micros().min(u128::from(u64::MAX)) as f64;
        let duration_us = (crate::constants::FLIP_ANIMATION_DURATION_MS * 1000) as f64;
        (elapsed_us / duration_us).min(1.0)
    }

    /// True when the animation has run its full duration.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.started.elapsed()
            >= Duration::from_millis(crate::constants::FLIP_ANIMATION_DURATION_MS)
    }

    /// Width ratio for the current animation frame (1.0 → 0.0 → 1.0).
    #[must_use]
    pub fn width_ratio(&self) -> f64 {
        let p = self.progress();
        if p < 0.5 {
            1.0 - (p * 2.0)
        } else {
            (p - 0.5) * 2.0
        }
    }

    /// True when past the midpoint (showing the target view).
    #[must_use]
    pub fn past_midpoint(&self) -> bool {
        self.progress() >= 0.5
    }
}

/// Profile list sort ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ProfileSortOrder {
    /// Alphabetical A → Z (default).
    #[default]
    NameAsc,
    /// Alphabetical Z → A.
    NameDesc,
    /// Most recently used first.
    LastUsed,
    /// Group by protocol (`WireGuard` first, then `OpenVPN`).
    Protocol,
}

impl ProfileSortOrder {
    /// Cycle to the next sort order.
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Self::NameAsc => Self::NameDesc,
            Self::NameDesc => Self::LastUsed,
            Self::LastUsed => Self::Protocol,
            Self::Protocol => Self::NameAsc,
        }
    }

    /// Short label for display in the sidebar title.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NameAsc => "A→Z",
            Self::NameDesc => "Z→A",
            Self::LastUsed => "Recent",
            Self::Protocol => "Proto",
        }
    }
}

/// Types of toast notifications for color coding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ToastType {
    /// Informational message (Blue)
    #[default]
    Info,
    /// Success message (Green)
    Success,
    /// Warning message (Yellow)
    Warning,
    /// Error message (Red)
    Error,
}

/// Toast notification for temporary messages.
#[derive(Clone)]
pub struct Toast {
    /// Message to display.
    pub message: String,
    /// Type of toast for styling.
    #[allow(clippy::struct_field_names)]
    pub toast_type: ToastType,
    /// When the toast should disappear.
    pub expires: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum QualityLevel {
    #[default]
    Unknown,
    Excellent,
    Fair,
    Poor,
}

impl QualityLevel {
    #[must_use]
    pub fn from_metrics(latency_ms: u64, packet_loss: f32, jitter_ms: u64) -> Self {
        if latency_ms == 0 && packet_loss == 0.0 && jitter_ms == 0 {
            return Self::Unknown;
        }
        if packet_loss >= 5.0 || jitter_ms >= 15 || latency_ms >= 300 {
            Self::Poor
        } else if packet_loss >= 1.0 || jitter_ms >= 5 || latency_ms >= 100 {
            Self::Fair
        } else {
            Self::Excellent
        }
    }
}

impl Toast {
    /// Check if the toast notification has expired
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_unknown_when_all_zero() {
        assert_eq!(QualityLevel::from_metrics(0, 0.0, 0), QualityLevel::Unknown);
    }

    #[test]
    fn quality_excellent_low_metrics() {
        assert_eq!(
            QualityLevel::from_metrics(30, 0.0, 2),
            QualityLevel::Excellent
        );
    }

    #[test]
    fn quality_fair_moderate_latency() {
        assert_eq!(QualityLevel::from_metrics(150, 0.0, 0), QualityLevel::Fair);
    }

    #[test]
    fn quality_poor_high_latency() {
        assert_eq!(QualityLevel::from_metrics(400, 0.0, 0), QualityLevel::Poor);
    }

    #[test]
    fn quality_poor_high_packet_loss() {
        assert_eq!(QualityLevel::from_metrics(20, 6.0, 1), QualityLevel::Poor);
    }

    #[test]
    fn quality_fair_moderate_jitter() {
        assert_eq!(QualityLevel::from_metrics(20, 0.0, 8), QualityLevel::Fair);
    }

    #[test]
    fn help_scroll_is_zero_when_terminal_height_unknown() {
        assert_eq!(help_max_scroll_for_terminal_height(0, 44), 0);
    }

    // --- FlipAnimation tests ---

    fn make_animation(to_back: bool) -> FlipAnimation {
        FlipAnimation {
            panel: FocusedPanel::Chart,
            started: Instant::now(),
            to_back,
        }
    }

    #[test]
    fn animation_starts_not_complete() {
        let anim = make_animation(true);
        assert!(!anim.is_complete());
        assert!(anim.progress() < 0.1);
    }

    #[test]
    fn animation_width_ratio_starts_near_one() {
        let anim = make_animation(true);
        assert!(anim.width_ratio() > 0.8);
    }

    #[test]
    fn animation_not_past_midpoint_at_start() {
        let anim = make_animation(true);
        assert!(!anim.past_midpoint());
    }

    #[test]
    fn animation_complete_after_duration() {
        let anim = FlipAnimation {
            panel: FocusedPanel::Security,
            started: Instant::now()
                .checked_sub(Duration::from_millis(
                    crate::constants::FLIP_ANIMATION_DURATION_MS + 10,
                ))
                .unwrap(),
            to_back: false,
        };
        assert!(anim.is_complete());
        assert!((anim.progress() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn animation_past_midpoint_after_duration() {
        let anim = FlipAnimation {
            panel: FocusedPanel::Chart,
            started: Instant::now()
                .checked_sub(Duration::from_millis(
                    crate::constants::FLIP_ANIMATION_DURATION_MS,
                ))
                .unwrap(),
            to_back: true,
        };
        assert!(anim.past_midpoint());
    }

    #[test]
    fn animation_width_ratio_one_when_complete() {
        let anim = FlipAnimation {
            panel: FocusedPanel::ConnectionDetails,
            started: Instant::now()
                .checked_sub(Duration::from_millis(
                    crate::constants::FLIP_ANIMATION_DURATION_MS + 50,
                ))
                .unwrap(),
            to_back: true,
        };
        assert!((anim.width_ratio() - 1.0).abs() < f64::EPSILON);
    }
}
