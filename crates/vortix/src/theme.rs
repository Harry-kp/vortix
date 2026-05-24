//! Theming infrastructure for the Vortix UI.
//!
//! All UI colors are defined in a single [`Theme`] struct. The active theme
//! is returned by [`current()`]. Adding a new theme is just adding one more
//! `const Theme` block and wiring it into `current()`.
//!
//! ## Phase 1 (v0.1.8): Foundation
//! All hardcoded colors live in `Theme`. A single built-in theme (`SYNTHWAVE`).
//!
//! ## Phase 2 (future): User Selection
//! `theme` field in `config.toml`, multiple built-in themes, runtime switching.

#![allow(dead_code)]
use ratatui::style::Color;

// ── Theme struct ─────────────────────────────────────────────────────────

/// Complete color palette for the Vortix UI.
///
/// Every color used in rendering is a field here. Semantic names describe
/// *purpose* (not hue) so themes can diverge wildly in palette while the
/// rest of the code stays unchanged.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    // --- Backgrounds ---
    pub warm_bg: Color,
    pub panel_bg: Color,
    pub panel_bg_dark: Color,
    pub panel_header_bg: Color,

    // --- Accents ---
    pub accent_primary: Color,
    pub accent_secondary: Color,
    pub accent_dark: Color,
    pub teal_accent: Color,

    // --- Status ---
    pub success: Color,
    pub warning: Color,
    pub error: Color,
    pub inactive: Color,

    // --- Text ---
    pub text_primary: Color,
    pub text_secondary: Color,
    pub text_light: Color,
    pub text_dark: Color,

    // --- Borders ---
    pub border_default: Color,
    pub border_focused: Color,

    // --- Rows / Selection ---
    pub row_selected_bg: Color,
    pub row_selected_fg: Color,

    // --- Buttons ---
    pub btn_connect_bg: Color,
    pub btn_terminate_bg: Color,
    pub btn_default_bg: Color,

    // --- Footer / Hints ---
    pub key_hint: Color,
    pub key_hint_desc: Color,
    pub separator: Color,

    // --- Toast notification colors ---
    pub toast_info: Color,
    pub toast_success: Color,
    pub toast_warning: Color,
    pub toast_error: Color,

    // --- Palette-specific colors (used for protocol badges, charts, etc.) ---
    pub yellow: Color,
    pub nord_polar_night_3: Color,
    pub nord_polar_night_4: Color,
    pub nord_frost_3: Color,
    pub nord_purple: Color,
}

// ── Built-in themes ──────────────────────────────────────────────────────

/// Default Synthwave / Cyberpunk theme — warm backgrounds, cyan accents.
pub const SYNTHWAVE: Theme = Theme {
    warm_bg: Color::Rgb(180, 160, 140),
    panel_bg: Color::Rgb(30, 41, 59),
    panel_bg_dark: Color::Rgb(20, 30, 45),
    panel_header_bg: Color::Rgb(40, 55, 75),

    accent_primary: Color::Rgb(6, 182, 212),
    accent_secondary: Color::Rgb(34, 211, 238),
    accent_dark: Color::Rgb(8, 145, 178),
    teal_accent: Color::Rgb(20, 184, 166),

    success: Color::Rgb(16, 185, 129),
    warning: Color::Rgb(245, 158, 11),
    error: Color::Rgb(239, 68, 68),
    inactive: Color::Gray,

    text_primary: Color::Rgb(248, 250, 252),
    text_secondary: Color::Rgb(148, 163, 184),
    text_light: Color::Rgb(203, 213, 225),
    text_dark: Color::Rgb(30, 41, 59),

    border_default: Color::Rgb(71, 85, 105),
    border_focused: Color::Rgb(6, 182, 212),

    row_selected_bg: Color::Rgb(40, 55, 75),
    row_selected_fg: Color::Rgb(34, 211, 238),

    btn_connect_bg: Color::Rgb(6, 182, 212),
    btn_terminate_bg: Color::Rgb(239, 68, 68),
    btn_default_bg: Color::Rgb(71, 85, 105),

    key_hint: Color::Rgb(6, 182, 212),
    key_hint_desc: Color::DarkGray,
    separator: Color::Rgb(76, 86, 106),

    toast_info: Color::Rgb(136, 192, 208),
    toast_success: Color::Rgb(163, 190, 140),
    toast_warning: Color::Rgb(235, 203, 139),
    toast_error: Color::Rgb(191, 97, 106),

    yellow: Color::Rgb(234, 179, 8),
    nord_polar_night_3: Color::Rgb(67, 76, 94),
    nord_polar_night_4: Color::Rgb(76, 86, 106),
    nord_frost_3: Color::Rgb(129, 161, 193),
    nord_purple: Color::Rgb(180, 142, 173),
};

/// Returns the active theme. Phase 1 always returns `SYNTHWAVE`.
/// Phase 2 will read from user config and support runtime switching.
#[must_use]
pub fn current() -> &'static Theme {
    &SYNTHWAVE
}

// ── Backward-compatible const aliases ────────────────────────────────────
//
// Existing code references `theme::ACCENT_PRIMARY` etc. These aliases
// delegate to the built-in theme so nothing breaks. Phase 2 will migrate
// call-sites to `theme::current().field` for runtime theme switching.

// Backgrounds
pub const WARM_BG: Color = SYNTHWAVE.warm_bg;
pub const PANEL_BG: Color = SYNTHWAVE.panel_bg;
pub const PANEL_BG_DARK: Color = SYNTHWAVE.panel_bg_dark;
pub const PANEL_HEADER_BG: Color = SYNTHWAVE.panel_header_bg;

// Accents
pub const CYAN_PRIMARY: Color = SYNTHWAVE.accent_primary;
pub const CYAN_LIGHT: Color = SYNTHWAVE.accent_secondary;
pub const CYAN_DARK: Color = SYNTHWAVE.accent_dark;
pub const TEAL_ACCENT: Color = SYNTHWAVE.teal_accent;

// Status
pub const EMERALD: Color = SYNTHWAVE.success;
pub const CORAL_RED: Color = SYNTHWAVE.error;
pub const AMBER: Color = SYNTHWAVE.warning;
pub const YELLOW: Color = SYNTHWAVE.yellow;

// Text
pub const TEXT_WHITE: Color = SYNTHWAVE.text_primary;
pub const TEXT_LIGHT: Color = SYNTHWAVE.text_light;
pub const TEXT_MUTED: Color = SYNTHWAVE.text_secondary;
pub const TEXT_DARK: Color = SYNTHWAVE.text_dark;

// Legacy Nord compatibility
pub const NORD_POLAR_NIGHT_3: Color = SYNTHWAVE.nord_polar_night_3;
pub const NORD_POLAR_NIGHT_4: Color = SYNTHWAVE.nord_polar_night_4;
pub const NORD_FROST_2: Color = SYNTHWAVE.accent_primary;
pub const NORD_FROST_3: Color = SYNTHWAVE.nord_frost_3;
pub const NORD_GREEN: Color = SYNTHWAVE.success;
pub const NORD_RED: Color = SYNTHWAVE.error;
pub const NORD_YELLOW: Color = SYNTHWAVE.yellow;
pub const NORD_PURPLE: Color = SYNTHWAVE.nord_purple;

// Semantic aliases
pub const BG_COLOR: Color = SYNTHWAVE.warm_bg;
pub const SURFACE_COLOR: Color = SYNTHWAVE.panel_bg;
pub const TEXT_PRIMARY: Color = SYNTHWAVE.text_primary;
pub const TEXT_SECONDARY: Color = SYNTHWAVE.text_secondary;
pub const ACCENT_PRIMARY: Color = SYNTHWAVE.accent_primary;
pub const ACCENT_SECONDARY: Color = SYNTHWAVE.accent_secondary;
pub const SUCCESS: Color = SYNTHWAVE.success;
pub const WARNING: Color = SYNTHWAVE.warning;
pub const ERROR: Color = SYNTHWAVE.error;
pub const INACTIVE: Color = SYNTHWAVE.inactive;

// UI elements
pub const BORDER_DEFAULT: Color = SYNTHWAVE.border_default;
pub const BORDER_FOCUSED: Color = SYNTHWAVE.border_focused;
pub const BORDER_ACCENT: Color = SYNTHWAVE.accent_primary;
pub const ROW_SELECTED_BG: Color = SYNTHWAVE.row_selected_bg;
pub const ROW_SELECTED_FG: Color = SYNTHWAVE.row_selected_fg;

// Buttons
pub const BTN_CONNECT_BG: Color = SYNTHWAVE.btn_connect_bg;
pub const BTN_TERMINATE_BG: Color = SYNTHWAVE.btn_terminate_bg;
pub const BTN_DEFAULT_BG: Color = SYNTHWAVE.btn_default_bg;

// Footer
pub const KEY_HINT: Color = SYNTHWAVE.key_hint;
pub const KEY_HINT_DESC: Color = SYNTHWAVE.key_hint_desc;
pub const SEPARATOR: Color = SYNTHWAVE.separator;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_returns_synthwave() {
        let t = current();
        assert_eq!(t.accent_primary, SYNTHWAVE.accent_primary);
        assert_eq!(t.error, SYNTHWAVE.error);
        assert_eq!(t.toast_info, SYNTHWAVE.toast_info);
    }

    #[test]
    fn const_aliases_match_theme_fields() {
        assert_eq!(ACCENT_PRIMARY, SYNTHWAVE.accent_primary);
        assert_eq!(ACCENT_SECONDARY, SYNTHWAVE.accent_secondary);
        assert_eq!(EMERALD, SYNTHWAVE.success);
        assert_eq!(CORAL_RED, SYNTHWAVE.error);
        assert_eq!(AMBER, SYNTHWAVE.warning);
        assert_eq!(YELLOW, SYNTHWAVE.yellow);
        assert_eq!(NORD_YELLOW, SYNTHWAVE.yellow);
        assert_eq!(PANEL_BG, SYNTHWAVE.panel_bg);
        assert_eq!(TEXT_WHITE, SYNTHWAVE.text_primary);
        assert_eq!(BORDER_DEFAULT, SYNTHWAVE.border_default);
        assert_eq!(BORDER_FOCUSED, SYNTHWAVE.border_focused);
        assert_eq!(KEY_HINT, SYNTHWAVE.key_hint);
        assert_eq!(SEPARATOR, SYNTHWAVE.separator);
    }

    #[test]
    fn nord_legacy_aliases_consistent() {
        assert_eq!(NORD_GREEN, SYNTHWAVE.success);
        assert_eq!(NORD_RED, SYNTHWAVE.error);
        assert_eq!(NORD_FROST_2, SYNTHWAVE.accent_primary);
        assert_eq!(NORD_FROST_3, SYNTHWAVE.nord_frost_3);
        assert_eq!(NORD_PURPLE, SYNTHWAVE.nord_purple);
        assert_eq!(NORD_POLAR_NIGHT_3, SYNTHWAVE.nord_polar_night_3);
        assert_eq!(NORD_POLAR_NIGHT_4, SYNTHWAVE.nord_polar_night_4);
    }
}
