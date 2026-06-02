//! UI state types.

use super::Protocol;
use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::profile::ProfileId;
use std::time::{Duration, Instant};

/// Duration for toast notifications to remain visible.
pub const DISMISS_DURATION: Duration = Duration::from_secs(4);
pub const HELP_OVERLAY_MAX_HEIGHT: u16 = 40;

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

/// Active tab in the Help overlay. `?` opens the overlay on
/// [`HelpTab::Keys`] by default; `Tab` / `Shift+Tab` cycle through
/// the tabs. Each tab renders its own content with an appropriate
/// layout (compact two-column for Keys; card-style with multi-line
/// prose for the glossary tabs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum HelpTab {
    /// Keybindings reference — `?`'s historic content.
    #[default]
    Keys,
    /// Role label glossary for the Connection Details panel.
    Roles,
    /// Sigil reference for the Security Guard panel and sidebar.
    Sigils,
    /// Security Guard panel reference: what each row checks, what the
    /// headline states (EXPOSED / PARTIAL / PROTECTED) mean, when to
    /// worry vs ignore.
    Guard,
}

impl HelpTab {
    /// Tabs in cycle order — used by `Tab` / `Shift+Tab` navigation
    /// in the Help overlay.
    pub const ALL: &'static [HelpTab] = &[
        HelpTab::Keys,
        HelpTab::Roles,
        HelpTab::Sigils,
        HelpTab::Guard,
    ];

    /// Title shown in the tab strip at the top of the overlay.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            HelpTab::Keys => "Keys",
            HelpTab::Roles => "Roles",
            HelpTab::Sigils => "Sigils",
            HelpTab::Guard => "Guard",
        }
    }

    /// Next tab in [`HelpTab::ALL`] (wraps).
    #[must_use]
    pub fn next(self) -> HelpTab {
        let idx = Self::ALL.iter().position(|t| *t == self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }

    /// Previous tab in [`HelpTab::ALL`] (wraps).
    #[must_use]
    pub fn prev(self) -> HelpTab {
        let idx = Self::ALL.iter().position(|t| *t == self).unwrap_or(0);
        Self::ALL[(idx + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

/// Which field is focused in the auth credentials overlay.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AuthField {
    /// Username text input.
    Username,
    /// Password text input (masked).
    Password,
    /// OTP / 2FA code text input (always masked). Only rendered when the
    /// profile declares an `OpenVPN` `static-challenge` directive — plan
    /// 2026-06-02-001 U3.
    Otp,
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
    /// Help overlay showing all keybindings + glossaries.
    Help {
        /// Vertical scroll offset within the active tab. Reset to 0
        /// on tab switch — no per-tab scroll memory (simplifies the
        /// state and matches user expectation of "switching gives a
        /// fresh page").
        scroll: u16,
        /// Currently active tab. `?` opens on [`HelpTab::Keys`];
        /// `Tab` / `Shift+Tab` cycle.
        tab: HelpTab,
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
    /// Confirmation dialog when connecting a new profile would take over the
    /// default route from an already-active tunnel (multi-connection plan #001
    /// U7 — formerly `ConfirmSwitch`). On confirm the connect path retries
    /// with `force=true`, inverting the primary.
    ConfirmDefaultRouteTakeover {
        /// Name of the profile currently holding the default route (display only).
        from: String,
        /// Profile id of the new tunnel attempting the takeover.
        to_profile_id: ProfileId,
        /// Display name of the new tunnel.
        to_name: String,
        /// "Yes" button currently selected?
        confirm_selected: bool,
    },
    /// Confirmation dialog when a new profile's `AllowedIPs` overlap with an
    /// already-active tunnel's `AllowedIPs` on a non-default-route CIDR (R10).
    /// On confirm the connect path retries with `force=true`.
    ConfirmRouteOverlap {
        /// Profile id of the conflicting (already-active) tunnel.
        with_profile_id: ProfileId,
        /// The overlapping CIDRs reported by the registry's conflict detector.
        overlapping_cidrs: Vec<Cidr>,
        /// Profile id of the new tunnel attempting to connect.
        to_profile_id: ProfileId,
        /// Display name of the new tunnel.
        to_name: String,
        /// "Yes" button currently selected?
        confirm_selected: bool,
    },
    /// Confirmation dialog for "Disconnect all N tunnels?" (multi-connection
    /// plan #001 U19). Fired by Shift+`D` from the sidebar when more than one
    /// active tunnel exists; with N≤1 the shortcut acts identically to plain
    /// `d` and this overlay is skipped (backwards-compatible single-tunnel
    /// behavior).
    ConfirmDisconnectAll {
        /// Number of currently active tunnels (for display).
        count: usize,
        /// "Yes" button currently selected?
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
        /// OTP / 2FA code input (always initialized to an empty string at
        /// overlay-open so the field cannot inherit prior state — plan
        /// 2026-06-02-001 U3 / FYI-8). Only used when
        /// `static_challenge_prompt.is_some()`.
        otp: String,
        /// Cursor position in the OTP field.
        otp_cursor: usize,
        /// Which field is currently focused.
        focused_field: AuthField,
        /// Whether to persist credentials for future sessions.
        save_credentials: bool,
        /// Whether to auto-connect after submitting (false = save-only mode).
        connect_after: bool,
        /// Prompt text from the .ovpn's `static-challenge` directive. When
        /// `Some`, the overlay renders a third (OTP) field labelled with
        /// this text and the submit handler embeds the OTP in the
        /// SCRV1 envelope (plan 2026-06-02-001 U3). When `None`, the
        /// overlay renders the two-field layout unchanged.
        static_challenge_prompt: Option<String>,
    },
}

/// Number of rows the tabbed help-overlay's chrome eats from the
/// inner area (tab strip + divider). The actual content paragraph
/// gets `inner_height - HELP_OVERLAY_CHROME_ROWS`.
pub const HELP_OVERLAY_CHROME_ROWS: u16 = 3;

#[must_use]
pub fn help_max_scroll_for_terminal_height(terminal_height: u16, total_lines: u16) -> u16 {
    if terminal_height == 0 {
        return 0;
    }

    let overlay_height = terminal_height
        .saturating_sub(2)
        .min(HELP_OVERLAY_MAX_HEIGHT);
    // Subtract 2 for the Block border (top+bottom), then 3 more for
    // the tab strip + divider that `render` inserts at the top of the
    // inner area. Without the chrome subtraction, the bottom 3 lines
    // of each tab would be unreachable via scroll.
    let inner_height = overlay_height.saturating_sub(2);
    let content_height = inner_height.saturating_sub(HELP_OVERLAY_CHROME_ROWS);
    total_lines.saturating_sub(content_height)
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
