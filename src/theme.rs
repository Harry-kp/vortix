//! Nordic Frost color theme definitions.
//!
//! This module defines the color palette used throughout the Vortix UI,
//! based on the Nord color scheme with semantic color assignments.

#![allow(dead_code)]
use ratatui::style::Color;

// === Nord Polar Night (Dark backgrounds) ===

/// Darkest polar night shade.
pub const NORD_POLAR_NIGHT_1: Color = Color::Rgb(46, 52, 64);
/// Dark polar night shade.
pub const NORD_POLAR_NIGHT_2: Color = Color::Rgb(59, 66, 82);
/// Medium polar night shade.
pub const NORD_POLAR_NIGHT_3: Color = Color::Rgb(67, 76, 94);
/// Lightest polar night shade.
pub const NORD_POLAR_NIGHT_4: Color = Color::Rgb(76, 86, 106);

// === Nord Snow Storm (Light text) ===

/// Primary snow storm shade.
pub const NORD_SNOW_STORM_1: Color = Color::Rgb(216, 222, 233);
/// Secondary snow storm shade.
pub const NORD_SNOW_STORM_2: Color = Color::Rgb(229, 233, 240);
/// Brightest snow storm shade.
pub const NORD_SNOW_STORM_3: Color = Color::Rgb(236, 239, 244);

// === Nord Frost (Accent blues/cyans) ===

/// Frost accent 1 - teal.
pub const NORD_FROST_1: Color = Color::Rgb(143, 188, 187);
/// Frost accent 2 - cyan (primary accent).
pub const NORD_FROST_2: Color = Color::Rgb(136, 192, 208);
/// Frost accent 3 - light blue.
pub const NORD_FROST_3: Color = Color::Rgb(129, 161, 193);
/// Frost accent 4 - deep blue.
pub const NORD_FROST_4: Color = Color::Rgb(94, 129, 172);

// === Nord Aurora (Status colors) ===

/// Aurora red - errors and disconnected state.
pub const NORD_RED: Color = Color::Rgb(191, 97, 106);
/// Aurora orange - warnings.
pub const NORD_ORANGE: Color = Color::Rgb(208, 135, 112);
/// Aurora yellow - caution/pending.
pub const NORD_YELLOW: Color = Color::Rgb(235, 203, 139);
/// Aurora green - success/connected.
pub const NORD_GREEN: Color = Color::Rgb(163, 190, 140);
/// Aurora purple - special highlights.
pub const NORD_PURPLE: Color = Color::Rgb(180, 142, 173);

// === Semantic Color Aliases ===

/// Main background color (darker than Polar Night 1).
pub const BG_COLOR: Color = Color::Rgb(20, 20, 25);
/// Primary text color.
pub const TEXT_PRIMARY: Color = NORD_SNOW_STORM_1;
/// Secondary/muted text color.
pub const TEXT_SECONDARY: Color = NORD_POLAR_NIGHT_4;
/// Primary accent color.
pub const ACCENT_PRIMARY: Color = NORD_FROST_2;
/// Secondary accent color.
pub const ACCENT_SECONDARY: Color = NORD_FROST_3;
/// Success state color.
pub const SUCCESS: Color = NORD_GREEN;
/// Warning state color.
pub const WARNING: Color = NORD_YELLOW;
/// Error state color.
pub const ERROR: Color = NORD_RED;
/// Inactive/disabled state color.
pub const INACTIVE: Color = Color::Gray;

// === UI Element Colors ===

/// Default border color.
pub const BORDER_DEFAULT: Color = NORD_POLAR_NIGHT_3;
/// Focused element border color.
pub const BORDER_FOCUSED: Color = NORD_FROST_2;
/// Selected row background color.
pub const ROW_SELECTED_BG: Color = Color::Rgb(40, 40, 40);
/// Selected row text color.
pub const ROW_SELECTED_FG: Color = NORD_FROST_2;
