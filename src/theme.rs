//! Synthwave/Cyberpunk color theme definitions.
//!
//! This module defines the color palette used throughout the Vortix UI,
//! inspired by synthwave aesthetics with warm backgrounds and cyan accents.

#![allow(dead_code)]
use ratatui::style::Color;

// === Synthwave Background Colors ===

/// Warm beige background (approximation of gradient).
pub const WARM_BG: Color = Color::Rgb(180, 160, 140);
/// Dark slate for panels.
pub const PANEL_BG: Color = Color::Rgb(30, 41, 59);
/// Darker panel background variant.
pub const PANEL_BG_DARK: Color = Color::Rgb(20, 30, 45);
/// Panel header background.
pub const PANEL_HEADER_BG: Color = Color::Rgb(40, 55, 75);

// === Primary Accent (Cyan/Teal) ===

/// Primary cyan accent - main highlight color.
pub const CYAN_PRIMARY: Color = Color::Rgb(6, 182, 212);
/// Lighter cyan for highlights.
pub const CYAN_LIGHT: Color = Color::Rgb(34, 211, 238);
/// Darker cyan for borders.
pub const CYAN_DARK: Color = Color::Rgb(8, 145, 178);
/// Teal variant for radar/visuals.
pub const TEAL_ACCENT: Color = Color::Rgb(20, 184, 166);

// === Status Colors ===

/// Success green - connected state.
pub const EMERALD: Color = Color::Rgb(16, 185, 129);
/// Coral red - errors and warnings.
pub const CORAL_RED: Color = Color::Rgb(239, 68, 68);
/// Warning amber.
pub const AMBER: Color = Color::Rgb(245, 158, 11);
/// Yellow for caution.
pub const YELLOW: Color = Color::Rgb(234, 179, 8);

// === Text Colors ===

/// White text on dark backgrounds.
pub const TEXT_WHITE: Color = Color::Rgb(248, 250, 252);
/// Light gray text.
pub const TEXT_LIGHT: Color = Color::Rgb(203, 213, 225);
/// Muted gray text.
pub const TEXT_MUTED: Color = Color::Rgb(148, 163, 184);
/// Dark text on light backgrounds.
pub const TEXT_DARK: Color = Color::Rgb(30, 41, 59);

// === Legacy Nord Colors (for compatibility) ===

/// Polar night 3 (legacy).
pub const NORD_POLAR_NIGHT_3: Color = Color::Rgb(67, 76, 94);
/// Polar night 4 (legacy).
pub const NORD_POLAR_NIGHT_4: Color = Color::Rgb(76, 86, 106);
/// Nord frost 2 (legacy, maps to `CYAN_PRIMARY`).
pub const NORD_FROST_2: Color = CYAN_PRIMARY;
/// Nord frost 3 (legacy).
pub const NORD_FROST_3: Color = Color::Rgb(129, 161, 193);
/// Nord green (legacy).
pub const NORD_GREEN: Color = EMERALD;
/// Nord red (legacy).
pub const NORD_RED: Color = CORAL_RED;
/// Nord yellow (legacy).
pub const NORD_YELLOW: Color = YELLOW;
/// Nord purple (legacy).
pub const NORD_PURPLE: Color = Color::Rgb(180, 142, 173);

// === Semantic Color Aliases ===

/// Main background color.
pub const BG_COLOR: Color = WARM_BG;
/// Panel/surface background.
pub const SURFACE_COLOR: Color = PANEL_BG;
/// Primary text color.
pub const TEXT_PRIMARY: Color = TEXT_WHITE;
/// Secondary/muted text color.
pub const TEXT_SECONDARY: Color = TEXT_MUTED;
/// Primary accent color.
pub const ACCENT_PRIMARY: Color = CYAN_PRIMARY;
/// Secondary accent color.
pub const ACCENT_SECONDARY: Color = CYAN_LIGHT;
/// Success state color.
pub const SUCCESS: Color = EMERALD;
/// Warning state color.
pub const WARNING: Color = AMBER;
/// Error state color.
pub const ERROR: Color = CORAL_RED;
/// Inactive/disabled state color.
pub const INACTIVE: Color = Color::Gray;

// === UI Element Colors ===

/// Default border color.
pub const BORDER_DEFAULT: Color = CYAN_DARK;
/// Focused element border color.
pub const BORDER_FOCUSED: Color = CYAN_PRIMARY;
/// Panel border with accent.
pub const BORDER_ACCENT: Color = CYAN_PRIMARY;
/// Selected row background color.
pub const ROW_SELECTED_BG: Color = Color::Rgb(40, 55, 75);
/// Selected row text color.
pub const ROW_SELECTED_FG: Color = CYAN_LIGHT;

// === Button Colors ===

/// Connect button background (cyan).
pub const BTN_CONNECT_BG: Color = CYAN_PRIMARY;
/// Terminate button background (coral).
pub const BTN_TERMINATE_BG: Color = CORAL_RED;
/// Default button background.
pub const BTN_DEFAULT_BG: Color = Color::Rgb(71, 85, 105);

