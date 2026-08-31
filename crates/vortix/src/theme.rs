//! Theming infrastructure for the Vortix UI.
//!
//! All UI colors are defined in a single [`Theme`] struct. The active theme
//! is returned by [`current()`]. A render frame scopes its configured choice
//! through [`with_choice`] so live switching cannot mix palettes.

#![allow(dead_code)]
use ratatui::style::Color;
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalColorSupport {
    TrueColor,
    Indexed256,
}

impl TerminalColorSupport {
    fn from_environment(
        term_program: Option<&str>,
        color_term: Option<&str>,
        term: Option<&str>,
        sudo_user: Option<&str>,
    ) -> Self {
        if term_program.is_some_and(|value| value.eq_ignore_ascii_case("Apple_Terminal")) {
            return Self::Indexed256;
        }

        let terminal_name_advertises_truecolor = term.is_some_and(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("truecolor")
                || value.contains("direct")
                || value.contains("ghostty")
                || value.contains("kitty")
                || value.contains("wezterm")
        });
        // `sudo` commonly keeps COLORTERM but strips TERM_PROGRAM. A generic
        // xterm-256color identity therefore cannot safely inherit the parent
        // shell's true-color claim (Terminal.app is the concrete case).
        if sudo_user.is_some() && term_program.is_none() && !terminal_name_advertises_truecolor {
            return Self::Indexed256;
        }

        let advertises_truecolor = color_term.is_some_and(|value| {
            value.eq_ignore_ascii_case("truecolor") || value.eq_ignore_ascii_case("24bit")
        }) || terminal_name_advertises_truecolor;

        if advertises_truecolor {
            Self::TrueColor
        } else {
            Self::Indexed256
        }
    }

    fn detect() -> Self {
        Self::from_environment(
            std::env::var("TERM_PROGRAM").ok().as_deref(),
            std::env::var("COLORTERM").ok().as_deref(),
            std::env::var("TERM").ok().as_deref(),
            std::env::var("SUDO_USER").ok().as_deref(),
        )
    }
}

static TERMINAL_COLOR_SUPPORT: OnceLock<TerminalColorSupport> = OnceLock::new();

/// Built-in theme selected through the top-level `theme` key in `config.toml`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ThemeChoice {
    /// Fixed 24-bit palette retained as the default for compatibility.
    #[default]
    Synthwave,
    /// Terminal-native foreground/background plus named ANSI status colors.
    Terminal,
    /// Catppuccin's dark Mocha palette.
    CatppuccinMocha,
    /// Dracula's high-contrast dark palette.
    Dracula,
    /// Nord's cool arctic palette.
    Nord,
    /// Gruvbox's warm retro dark palette.
    GruvboxDark,
    /// Tokyo Night's Storm palette.
    TokyoNight,
}

impl ThemeChoice {
    /// Resolve this choice to its immutable palette.
    #[must_use]
    pub const fn palette(self) -> &'static Theme {
        match self {
            Self::Synthwave => &SYNTHWAVE,
            Self::Terminal => &TERMINAL,
            Self::CatppuccinMocha => &CATPPUCCIN_MOCHA,
            Self::Dracula => &DRACULA,
            Self::Nord => &NORD,
            Self::GruvboxDark => &GRUVBOX_DARK,
            Self::TokyoNight => &TOKYO_NIGHT,
        }
    }

    const fn palette_for_support(self, support: TerminalColorSupport) -> &'static Theme {
        if matches!(support, TerminalColorSupport::TrueColor) {
            return self.palette();
        }

        match self {
            Self::Synthwave => &SYNTHWAVE_INDEXED,
            Self::Terminal => &TERMINAL,
            Self::CatppuccinMocha => &CATPPUCCIN_MOCHA_INDEXED,
            Self::Dracula => &DRACULA_INDEXED,
            Self::Nord => &NORD_INDEXED,
            Self::GruvboxDark => &GRUVBOX_DARK_INDEXED,
            Self::TokyoNight => &TOKYO_NIGHT_INDEXED,
        }
    }

    /// Resolve this choice for the capabilities of the active terminal.
    #[must_use]
    pub fn render_palette(self) -> &'static Theme {
        self.palette_for_support(
            TERMINAL_COLOR_SUPPORT
                .get()
                .copied()
                .unwrap_or(TerminalColorSupport::TrueColor),
        )
    }

    /// Return the next built-in theme, wrapping to Synthwave.
    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::Synthwave => Self::Terminal,
            Self::Terminal => Self::CatppuccinMocha,
            Self::CatppuccinMocha => Self::Dracula,
            Self::Dracula => Self::Nord,
            Self::Nord => Self::GruvboxDark,
            Self::GruvboxDark => Self::TokyoNight,
            Self::TokyoNight => Self::Synthwave,
        }
    }

    /// Human-readable theme name used by TUI feedback.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Synthwave => "Synthwave",
            Self::Terminal => "Terminal",
            Self::CatppuccinMocha => "Catppuccin Mocha",
            Self::Dracula => "Dracula",
            Self::Nord => "Nord",
            Self::GruvboxDark => "Gruvbox Dark",
            Self::TokyoNight => "Tokyo Night",
        }
    }

    /// Stable value persisted in `config.toml`.
    #[must_use]
    pub const fn config_value(self) -> &'static str {
        match self {
            Self::Synthwave => "synthwave",
            Self::Terminal => "terminal",
            Self::CatppuccinMocha => "catppuccin-mocha",
            Self::Dracula => "dracula",
            Self::Nord => "nord",
            Self::GruvboxDark => "gruvbox-dark",
            Self::TokyoNight => "tokyo-night",
        }
    }
}

thread_local! {
    static SCOPED_THEME: Cell<ThemeChoice> = const { Cell::new(ThemeChoice::Synthwave) };
}

struct ScopedThemeGuard<'a> {
    active: &'a Cell<ThemeChoice>,
    previous: ThemeChoice,
}

impl Drop for ScopedThemeGuard<'_> {
    fn drop(&mut self) {
        self.active.set(self.previous);
    }
}

// ── Theme struct ─────────────────────────────────────────────────────────

/// Complete color palette for the Vortix UI.
///
/// Every color used in rendering is a field here. Semantic names describe
/// *purpose* (not hue) so themes can diverge wildly in palette while the
/// rest of the code stays unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl Theme {
    #[cfg(test)]
    const fn colors(self) -> [Color; 35] {
        [
            self.warm_bg,
            self.panel_bg,
            self.panel_bg_dark,
            self.panel_header_bg,
            self.accent_primary,
            self.accent_secondary,
            self.accent_dark,
            self.teal_accent,
            self.success,
            self.warning,
            self.error,
            self.inactive,
            self.text_primary,
            self.text_secondary,
            self.text_light,
            self.text_dark,
            self.border_default,
            self.border_focused,
            self.row_selected_bg,
            self.row_selected_fg,
            self.btn_connect_bg,
            self.btn_terminate_bg,
            self.btn_default_bg,
            self.key_hint,
            self.key_hint_desc,
            self.separator,
            self.toast_info,
            self.toast_success,
            self.toast_warning,
            self.toast_error,
            self.yellow,
            self.nord_polar_night_3,
            self.nord_polar_night_4,
            self.nord_frost_3,
            self.nord_purple,
        ]
    }
}

// ── Built-in themes ──────────────────────────────────────────────────────

/// Default Synthwave / Cyberpunk theme — warm backgrounds, cyan accents.
pub const SYNTHWAVE: Theme = Theme {
    warm_bg: Color::Rgb(180, 160, 140),
    // Match the legacy rendered surface captured before palette switching.
    // The old constant was blue-slate but the old renderer inherited this
    // neutral-purple terminal surface instead.
    panel_bg: Color::Rgb(28, 28, 40),
    panel_bg_dark: Color::Rgb(22, 22, 32),
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

/// Terminal-adaptive theme. Ordinary surfaces and text inherit the user's
/// terminal palette; semantic signals use only the named ANSI colors.
pub const TERMINAL: Theme = Theme {
    warm_bg: Color::Reset,
    panel_bg: Color::Reset,
    panel_bg_dark: Color::Reset,
    panel_header_bg: Color::Reset,

    accent_primary: Color::Cyan,
    accent_secondary: Color::LightCyan,
    accent_dark: Color::Blue,
    teal_accent: Color::Cyan,

    success: Color::Green,
    warning: Color::Yellow,
    error: Color::Red,
    inactive: Color::DarkGray,

    text_primary: Color::Reset,
    text_secondary: Color::Reset,
    text_light: Color::Reset,
    text_dark: Color::Black,

    border_default: Color::DarkGray,
    border_focused: Color::Cyan,

    row_selected_bg: Color::Blue,
    row_selected_fg: Color::White,

    btn_connect_bg: Color::Cyan,
    btn_terminate_bg: Color::Red,
    btn_default_bg: Color::Blue,

    key_hint: Color::Cyan,
    key_hint_desc: Color::DarkGray,
    separator: Color::DarkGray,

    toast_info: Color::Cyan,
    toast_success: Color::Green,
    toast_warning: Color::Yellow,
    toast_error: Color::Red,

    yellow: Color::Yellow,
    nord_polar_night_3: Color::DarkGray,
    nord_polar_night_4: Color::DarkGray,
    nord_frost_3: Color::Blue,
    nord_purple: Color::Magenta,
};

/// Catppuccin Mocha — soft pastels over a deep blue-black base.
pub const CATPPUCCIN_MOCHA: Theme = Theme {
    warm_bg: Color::Rgb(17, 17, 27),
    panel_bg: Color::Rgb(30, 30, 46),
    panel_bg_dark: Color::Rgb(24, 24, 37),
    panel_header_bg: Color::Rgb(49, 50, 68),

    accent_primary: Color::Rgb(203, 166, 247),
    accent_secondary: Color::Rgb(137, 180, 250),
    accent_dark: Color::Rgb(116, 199, 236),
    teal_accent: Color::Rgb(148, 226, 213),

    success: Color::Rgb(166, 227, 161),
    warning: Color::Rgb(249, 226, 175),
    error: Color::Rgb(243, 139, 168),
    inactive: Color::Rgb(166, 173, 200),

    text_primary: Color::Rgb(205, 214, 244),
    text_secondary: Color::Rgb(166, 173, 200),
    text_light: Color::Rgb(186, 194, 222),
    text_dark: Color::Rgb(17, 17, 27),

    border_default: Color::Rgb(108, 112, 134),
    border_focused: Color::Rgb(203, 166, 247),

    row_selected_bg: Color::Rgb(69, 71, 90),
    row_selected_fg: Color::Rgb(180, 190, 254),

    btn_connect_bg: Color::Rgb(137, 180, 250),
    btn_terminate_bg: Color::Rgb(243, 139, 168),
    btn_default_bg: Color::Rgb(88, 91, 112),

    key_hint: Color::Rgb(203, 166, 247),
    key_hint_desc: Color::Rgb(166, 173, 200),
    separator: Color::Rgb(108, 112, 134),

    toast_info: Color::Rgb(137, 180, 250),
    toast_success: Color::Rgb(166, 227, 161),
    toast_warning: Color::Rgb(249, 226, 175),
    toast_error: Color::Rgb(243, 139, 168),

    yellow: Color::Rgb(249, 226, 175),
    nord_polar_night_3: Color::Rgb(49, 50, 68),
    nord_polar_night_4: Color::Rgb(69, 71, 90),
    nord_frost_3: Color::Rgb(137, 180, 250),
    nord_purple: Color::Rgb(203, 166, 247),
};

/// Dracula — vivid status colors over its canonical charcoal background.
pub const DRACULA: Theme = Theme {
    warm_bg: Color::Rgb(33, 34, 44),
    panel_bg: Color::Rgb(40, 42, 54),
    panel_bg_dark: Color::Rgb(33, 34, 44),
    panel_header_bg: Color::Rgb(68, 71, 90),

    accent_primary: Color::Rgb(189, 147, 249),
    accent_secondary: Color::Rgb(139, 233, 253),
    accent_dark: Color::Rgb(98, 114, 164),
    teal_accent: Color::Rgb(139, 233, 253),

    success: Color::Rgb(80, 250, 123),
    warning: Color::Rgb(241, 250, 140),
    error: Color::Rgb(255, 85, 85),
    inactive: Color::Rgb(164, 166, 183),

    text_primary: Color::Rgb(248, 248, 242),
    text_secondary: Color::Rgb(164, 166, 183),
    text_light: Color::Rgb(248, 248, 242),
    text_dark: Color::Rgb(40, 42, 54),

    border_default: Color::Rgb(98, 114, 164),
    border_focused: Color::Rgb(139, 233, 253),

    row_selected_bg: Color::Rgb(68, 71, 90),
    row_selected_fg: Color::Rgb(248, 248, 242),

    btn_connect_bg: Color::Rgb(139, 233, 253),
    btn_terminate_bg: Color::Rgb(255, 85, 85),
    btn_default_bg: Color::Rgb(98, 114, 164),

    key_hint: Color::Rgb(255, 121, 198),
    key_hint_desc: Color::Rgb(164, 166, 183),
    separator: Color::Rgb(98, 114, 164),

    toast_info: Color::Rgb(139, 233, 253),
    toast_success: Color::Rgb(80, 250, 123),
    toast_warning: Color::Rgb(255, 184, 108),
    toast_error: Color::Rgb(255, 85, 85),

    yellow: Color::Rgb(241, 250, 140),
    nord_polar_night_3: Color::Rgb(40, 42, 54),
    nord_polar_night_4: Color::Rgb(68, 71, 90),
    nord_frost_3: Color::Rgb(139, 233, 253),
    nord_purple: Color::Rgb(189, 147, 249),
};

/// Nord — the original Polar Night, Snow Storm, Frost, and Aurora colors.
pub const NORD: Theme = Theme {
    warm_bg: Color::Rgb(46, 52, 64),
    panel_bg: Color::Rgb(46, 52, 64),
    panel_bg_dark: Color::Rgb(46, 52, 64),
    panel_header_bg: Color::Rgb(59, 66, 82),

    accent_primary: Color::Rgb(136, 192, 208),
    accent_secondary: Color::Rgb(143, 188, 187),
    accent_dark: Color::Rgb(94, 129, 172),
    teal_accent: Color::Rgb(143, 188, 187),

    success: Color::Rgb(163, 190, 140),
    warning: Color::Rgb(235, 203, 139),
    error: Color::Rgb(220, 130, 139),
    inactive: Color::Rgb(129, 161, 193),

    text_primary: Color::Rgb(236, 239, 244),
    text_secondary: Color::Rgb(216, 222, 233),
    text_light: Color::Rgb(229, 233, 240),
    text_dark: Color::Rgb(16, 18, 22),

    border_default: Color::Rgb(123, 136, 161),
    border_focused: Color::Rgb(136, 192, 208),

    row_selected_bg: Color::Rgb(67, 76, 94),
    row_selected_fg: Color::Rgb(236, 239, 244),

    btn_connect_bg: Color::Rgb(136, 192, 208),
    btn_terminate_bg: Color::Rgb(191, 97, 106),
    btn_default_bg: Color::Rgb(76, 86, 106),

    key_hint: Color::Rgb(136, 192, 208),
    key_hint_desc: Color::Rgb(129, 161, 193),
    separator: Color::Rgb(123, 136, 161),

    toast_info: Color::Rgb(129, 161, 193),
    toast_success: Color::Rgb(163, 190, 140),
    toast_warning: Color::Rgb(235, 203, 139),
    toast_error: Color::Rgb(220, 130, 139),

    yellow: Color::Rgb(235, 203, 139),
    nord_polar_night_3: Color::Rgb(67, 76, 94),
    nord_polar_night_4: Color::Rgb(76, 86, 106),
    nord_frost_3: Color::Rgb(129, 161, 193),
    nord_purple: Color::Rgb(180, 142, 173),
};

/// Gruvbox Dark — warm, high-separation retro colors.
pub const GRUVBOX_DARK: Theme = Theme {
    warm_bg: Color::Rgb(29, 32, 33),
    panel_bg: Color::Rgb(29, 32, 33),
    panel_bg_dark: Color::Rgb(29, 32, 33),
    panel_header_bg: Color::Rgb(60, 56, 54),

    accent_primary: Color::Rgb(131, 165, 152),
    accent_secondary: Color::Rgb(142, 192, 124),
    accent_dark: Color::Rgb(69, 133, 136),
    teal_accent: Color::Rgb(142, 192, 124),

    success: Color::Rgb(184, 187, 38),
    warning: Color::Rgb(250, 189, 47),
    error: Color::Rgb(251, 73, 52),
    inactive: Color::Rgb(168, 153, 132),

    text_primary: Color::Rgb(235, 219, 178),
    text_secondary: Color::Rgb(189, 174, 147),
    text_light: Color::Rgb(213, 196, 161),
    text_dark: Color::Rgb(29, 32, 33),

    border_default: Color::Rgb(146, 131, 116),
    border_focused: Color::Rgb(131, 165, 152),

    row_selected_bg: Color::Rgb(80, 73, 69),
    row_selected_fg: Color::Rgb(251, 241, 199),

    btn_connect_bg: Color::Rgb(131, 165, 152),
    btn_terminate_bg: Color::Rgb(251, 73, 52),
    btn_default_bg: Color::Rgb(102, 92, 84),

    key_hint: Color::Rgb(142, 192, 124),
    key_hint_desc: Color::Rgb(168, 153, 132),
    separator: Color::Rgb(146, 131, 116),

    toast_info: Color::Rgb(131, 165, 152),
    toast_success: Color::Rgb(184, 187, 38),
    toast_warning: Color::Rgb(250, 189, 47),
    toast_error: Color::Rgb(251, 73, 52),

    yellow: Color::Rgb(250, 189, 47),
    nord_polar_night_3: Color::Rgb(60, 56, 54),
    nord_polar_night_4: Color::Rgb(80, 73, 69),
    nord_frost_3: Color::Rgb(131, 165, 152),
    nord_purple: Color::Rgb(211, 134, 155),
};

/// Tokyo Night Storm — saturated cool accents on a midnight-blue surface.
pub const TOKYO_NIGHT: Theme = Theme {
    warm_bg: Color::Rgb(22, 22, 30),
    panel_bg: Color::Rgb(26, 27, 38),
    panel_bg_dark: Color::Rgb(22, 22, 30),
    panel_header_bg: Color::Rgb(41, 46, 66),

    accent_primary: Color::Rgb(122, 162, 247),
    accent_secondary: Color::Rgb(125, 207, 255),
    accent_dark: Color::Rgb(61, 89, 161),
    teal_accent: Color::Rgb(180, 249, 248),

    success: Color::Rgb(158, 206, 106),
    warning: Color::Rgb(224, 175, 104),
    error: Color::Rgb(247, 118, 142),
    inactive: Color::Rgb(169, 177, 214),

    text_primary: Color::Rgb(192, 202, 245),
    text_secondary: Color::Rgb(169, 177, 214),
    text_light: Color::Rgb(180, 249, 248),
    text_dark: Color::Rgb(22, 22, 30),

    border_default: Color::Rgb(115, 122, 162),
    border_focused: Color::Rgb(122, 162, 247),

    row_selected_bg: Color::Rgb(41, 46, 66),
    row_selected_fg: Color::Rgb(192, 202, 245),

    btn_connect_bg: Color::Rgb(122, 162, 247),
    btn_terminate_bg: Color::Rgb(247, 118, 142),
    btn_default_bg: Color::Rgb(59, 66, 97),

    key_hint: Color::Rgb(187, 154, 247),
    key_hint_desc: Color::Rgb(169, 177, 214),
    separator: Color::Rgb(115, 122, 162),

    toast_info: Color::Rgb(125, 207, 255),
    toast_success: Color::Rgb(158, 206, 106),
    toast_warning: Color::Rgb(224, 175, 104),
    toast_error: Color::Rgb(247, 118, 142),

    yellow: Color::Rgb(224, 175, 104),
    nord_polar_night_3: Color::Rgb(41, 46, 66),
    nord_polar_night_4: Color::Rgb(59, 66, 97),
    nord_frost_3: Color::Rgb(122, 162, 247),
    nord_purple: Color::Rgb(187, 154, 247),
};

const XTERM_LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];

const fn color_distance(left: u8, right: u8) -> u32 {
    let difference = left.abs_diff(right) as u32;
    difference * difference
}

const fn nearest_xterm_component(value: u8) -> (u8, u8) {
    let mut best_index: u8 = 0;
    let mut best_distance = u32::MAX;
    let mut index: u8 = 0;
    while (index as usize) < XTERM_LEVELS.len() {
        let distance = color_distance(value, XTERM_LEVELS[index as usize]);
        if distance < best_distance {
            best_index = index;
            best_distance = distance;
        }
        index += 1;
    }
    (best_index, XTERM_LEVELS[best_index as usize])
}

const fn nearest_xterm_index(red: u8, green: u8, blue: u8) -> u8 {
    let (red_index, cube_red) = nearest_xterm_component(red);
    let (green_index, cube_green) = nearest_xterm_component(green);
    let (blue_index, cube_blue) = nearest_xterm_component(blue);
    let cube_distance = color_distance(red, cube_red)
        + color_distance(green, cube_green)
        + color_distance(blue, cube_blue);
    let cube_index = 16 + (36 * red_index) + (6 * green_index) + blue_index;

    let mut best_gray_index = 0;
    let mut best_gray_distance = u32::MAX;
    let mut gray_index = 0;
    while gray_index < 24 {
        let gray = 8 + (10 * gray_index);
        let distance =
            color_distance(red, gray) + color_distance(green, gray) + color_distance(blue, gray);
        if distance < best_gray_distance {
            best_gray_index = gray_index;
            best_gray_distance = distance;
        }
        gray_index += 1;
    }

    if best_gray_distance < cube_distance {
        232 + best_gray_index
    } else {
        cube_index
    }
}

const fn indexed_color(color: Color) -> Color {
    match color {
        Color::Rgb(red, green, blue) => Color::Indexed(nearest_xterm_index(red, green, blue)),
        other => other,
    }
}

const fn indexed_theme(theme: Theme) -> Theme {
    Theme {
        warm_bg: indexed_color(theme.warm_bg),
        panel_bg: indexed_color(theme.panel_bg),
        panel_bg_dark: indexed_color(theme.panel_bg_dark),
        panel_header_bg: indexed_color(theme.panel_header_bg),
        accent_primary: indexed_color(theme.accent_primary),
        accent_secondary: indexed_color(theme.accent_secondary),
        accent_dark: indexed_color(theme.accent_dark),
        teal_accent: indexed_color(theme.teal_accent),
        success: indexed_color(theme.success),
        warning: indexed_color(theme.warning),
        error: indexed_color(theme.error),
        inactive: indexed_color(theme.inactive),
        text_primary: indexed_color(theme.text_primary),
        text_secondary: indexed_color(theme.text_secondary),
        text_light: indexed_color(theme.text_light),
        text_dark: indexed_color(theme.text_dark),
        border_default: indexed_color(theme.border_default),
        border_focused: indexed_color(theme.border_focused),
        row_selected_bg: indexed_color(theme.row_selected_bg),
        row_selected_fg: indexed_color(theme.row_selected_fg),
        btn_connect_bg: indexed_color(theme.btn_connect_bg),
        btn_terminate_bg: indexed_color(theme.btn_terminate_bg),
        btn_default_bg: indexed_color(theme.btn_default_bg),
        key_hint: indexed_color(theme.key_hint),
        key_hint_desc: indexed_color(theme.key_hint_desc),
        separator: indexed_color(theme.separator),
        toast_info: indexed_color(theme.toast_info),
        toast_success: indexed_color(theme.toast_success),
        toast_warning: indexed_color(theme.toast_warning),
        toast_error: indexed_color(theme.toast_error),
        yellow: indexed_color(theme.yellow),
        nord_polar_night_3: indexed_color(theme.nord_polar_night_3),
        nord_polar_night_4: indexed_color(theme.nord_polar_night_4),
        nord_frost_3: indexed_color(theme.nord_frost_3),
        nord_purple: indexed_color(theme.nord_purple),
    }
}

const SYNTHWAVE_INDEXED: Theme = indexed_theme(SYNTHWAVE);
const CATPPUCCIN_MOCHA_INDEXED: Theme = indexed_theme(CATPPUCCIN_MOCHA);
const DRACULA_INDEXED: Theme = indexed_theme(DRACULA);
const NORD_INDEXED: Theme = indexed_theme(NORD);
const GRUVBOX_DARK_INDEXED: Theme = indexed_theme(GRUVBOX_DARK);
const TOKYO_NIGHT_INDEXED: Theme = indexed_theme(TOKYO_NIGHT);

/// Detect and cache the active terminal's color capability before rendering.
pub fn configure_for_terminal() {
    let _ = TERMINAL_COLOR_SUPPORT.set(TerminalColorSupport::detect());
}

/// Run one complete render operation with a stable active palette.
pub fn with_choice<T>(choice: ThemeChoice, render: impl FnOnce() -> T) -> T {
    SCOPED_THEME.with(|active| {
        let previous = active.replace(choice);
        let _restore = ScopedThemeGuard { active, previous };
        render()
    })
}

/// Return the palette scoped to the current render operation.
#[must_use]
pub fn current() -> &'static Theme {
    SCOPED_THEME.with(|choice| choice.get().render_palette())
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
    fn synthwave_matches_the_legacy_rendered_palette() {
        assert_eq!(
            SYNTHWAVE,
            Theme {
                warm_bg: Color::Rgb(180, 160, 140),
                panel_bg: Color::Rgb(28, 28, 40),
                panel_bg_dark: Color::Rgb(22, 22, 32),
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
            }
        );
    }

    #[test]
    fn choice_cycles_and_scopes_without_leaking() {
        assert_eq!(ThemeChoice::Synthwave.next(), ThemeChoice::Terminal);
        assert_eq!(ThemeChoice::Terminal.next(), ThemeChoice::CatppuccinMocha);
        assert_eq!(ThemeChoice::CatppuccinMocha.next(), ThemeChoice::Dracula);
        assert_eq!(ThemeChoice::Dracula.next(), ThemeChoice::Nord);
        assert_eq!(ThemeChoice::Nord.next(), ThemeChoice::GruvboxDark);
        assert_eq!(ThemeChoice::GruvboxDark.next(), ThemeChoice::TokyoNight);
        assert_eq!(ThemeChoice::TokyoNight.next(), ThemeChoice::Synthwave);
        assert_eq!(ThemeChoice::Terminal.display_name(), "Terminal");
        assert_eq!(
            ThemeChoice::CatppuccinMocha.display_name(),
            "Catppuccin Mocha"
        );
        assert_eq!(ThemeChoice::GruvboxDark.config_value(), "gruvbox-dark");
        assert_eq!(ThemeChoice::TokyoNight.config_value(), "tokyo-night");
        assert_eq!(ThemeChoice::Synthwave.config_value(), "synthwave");

        with_choice(ThemeChoice::Terminal, || {
            assert_eq!(current().accent_primary, TERMINAL.accent_primary);
        });
        assert_eq!(current().accent_primary, SYNTHWAVE.accent_primary);
    }

    #[test]
    fn fixed_palettes_resolve_to_distinct_readable_semantic_colors() {
        fn luminance(color: Color) -> f64 {
            let Color::Rgb(red, green, blue) = color else {
                panic!("fixed palettes must use 24-bit colors, got {color:?}");
            };
            let linear = |component: u8| {
                let value = f64::from(component) / 255.0;
                if value <= 0.040_45 {
                    value / 12.92
                } else {
                    ((value + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * linear(red) + 0.7152 * linear(green) + 0.0722 * linear(blue)
        }

        fn assert_contrast(
            choice: ThemeChoice,
            foreground: Color,
            background: Color,
            minimum: f64,
        ) {
            let lighter = luminance(foreground).max(luminance(background));
            let darker = luminance(foreground).min(luminance(background));
            let ratio = (lighter + 0.05) / (darker + 0.05);
            assert!(
                ratio >= minimum,
                "{choice:?} contrast is {ratio:.2}:1 for {foreground:?} on {background:?}"
            );
        }

        // Synthwave is frozen to the legacy rendered palette, including two
        // terminal-defined ANSI colors. New fixed palettes meet the stricter
        // contrast contract independently.
        let choices = [
            ThemeChoice::CatppuccinMocha,
            ThemeChoice::Dracula,
            ThemeChoice::Nord,
            ThemeChoice::GruvboxDark,
            ThemeChoice::TokyoNight,
        ];

        for choice in choices {
            let palette = choice.palette();
            for foreground in [
                palette.text_primary,
                palette.text_secondary,
                palette.accent_primary,
                palette.success,
                palette.warning,
                palette.error,
                palette.inactive,
                palette.key_hint,
                palette.key_hint_desc,
            ] {
                assert_contrast(choice, foreground, palette.panel_bg, 4.5);
            }
            for structural in [palette.border_default, palette.separator] {
                assert_contrast(choice, structural, palette.panel_bg, 3.0);
            }
            assert_contrast(
                choice,
                palette.row_selected_fg,
                palette.row_selected_bg,
                4.5,
            );
            for background in [
                palette.accent_primary,
                palette.success,
                palette.warning,
                palette.error,
                palette.toast_info,
                palette.toast_success,
                palette.toast_warning,
                palette.toast_error,
            ] {
                assert_contrast(choice, palette.text_dark, background, 4.5);
            }
            assert_ne!(palette.success, palette.warning, "{choice:?}");
            assert_ne!(palette.success, palette.error, "{choice:?}");
            assert_ne!(palette.warning, palette.error, "{choice:?}");
        }
    }

    #[test]
    fn theme_config_values_are_stable_and_round_trip() {
        let choices = [
            (ThemeChoice::Synthwave, "synthwave"),
            (ThemeChoice::Terminal, "terminal"),
            (ThemeChoice::CatppuccinMocha, "catppuccin-mocha"),
            (ThemeChoice::Dracula, "dracula"),
            (ThemeChoice::Nord, "nord"),
            (ThemeChoice::GruvboxDark, "gruvbox-dark"),
            (ThemeChoice::TokyoNight, "tokyo-night"),
        ];

        for (choice, value) in choices {
            assert_eq!(choice.config_value(), value);
            assert_eq!(
                serde_json::to_string(&choice).expect("theme value should serialize"),
                format!("\"{value}\"")
            );
            assert_eq!(
                serde_json::from_str::<ThemeChoice>(&format!("\"{value}\""))
                    .expect("theme value should deserialize"),
                choice
            );
        }
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

    #[test]
    fn terminal_theme_uses_terminal_defaults_and_named_ansi_colors() {
        let theme = ThemeChoice::Terminal.palette();

        assert_eq!(theme.panel_bg, Color::Reset);
        assert_eq!(theme.panel_bg_dark, Color::Reset);
        assert_eq!(theme.panel_header_bg, Color::Reset);
        assert_eq!(theme.text_primary, Color::Reset);
        assert_eq!(theme.text_secondary, Color::Reset);
        for color in [
            theme.accent_primary,
            theme.accent_secondary,
            theme.success,
            theme.warning,
            theme.error,
        ] {
            assert!(!matches!(color, Color::Rgb(_, _, _)));
        }
    }

    #[test]
    fn apple_terminal_uses_indexed_palettes_instead_of_misreading_rgb_sequences() {
        assert_eq!(
            TerminalColorSupport::from_environment(
                Some("Apple_Terminal"),
                None,
                Some("xterm-256color"),
                None,
            ),
            TerminalColorSupport::Indexed256,
        );
        assert_eq!(
            TerminalColorSupport::from_environment(
                None,
                Some("truecolor"),
                Some("xterm-256color"),
                Some("alice"),
            ),
            TerminalColorSupport::Indexed256,
            "sudo strips TERM_PROGRAM, so a generic 256-color TERM must win over inherited COLORTERM",
        );

        for choice in [
            ThemeChoice::Synthwave,
            ThemeChoice::CatppuccinMocha,
            ThemeChoice::Dracula,
            ThemeChoice::Nord,
            ThemeChoice::GruvboxDark,
            ThemeChoice::TokyoNight,
        ] {
            let palette = choice.palette_for_support(TerminalColorSupport::Indexed256);
            for color in palette.colors() {
                assert!(
                    !matches!(color, Color::Rgb(_, _, _)),
                    "{choice:?} leaked an RGB escape into a 256-color terminal: {color:?}"
                );
            }
        }
    }

    #[test]
    fn terminals_that_advertise_truecolor_keep_the_exact_rgb_palette() {
        assert_eq!(
            TerminalColorSupport::from_environment(
                Some("ghostty"),
                Some("truecolor"),
                Some("xterm-ghostty"),
                Some("alice"),
            ),
            TerminalColorSupport::TrueColor,
        );
        assert_eq!(
            TerminalColorSupport::from_environment(
                None,
                Some("truecolor"),
                Some("xterm-256color"),
                None,
            ),
            TerminalColorSupport::TrueColor,
        );
        assert_eq!(
            ThemeChoice::Synthwave.palette_for_support(TerminalColorSupport::TrueColor),
            &SYNTHWAVE,
        );
    }

    #[test]
    fn production_ui_uses_semantic_theme_colors() {
        fn inspect(directory: &std::path::Path, leaks: &mut Vec<String>) {
            for entry in std::fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if path.is_dir() {
                    inspect(&path, leaks);
                    continue;
                }
                if path.extension().and_then(std::ffi::OsStr::to_str) != Some("rs") {
                    continue;
                }
                let source = std::fs::read_to_string(&path).unwrap();
                for raw in [
                    "Color::Black",
                    "Color::Blue",
                    "Color::Cyan",
                    "Color::DarkGray",
                    "Color::Green",
                    "Color::Gray",
                    "Color::Indexed",
                    "Color::Light",
                    "Color::Magenta",
                    "Color::Red",
                    "Color::Rgb",
                    "Color::White",
                    "Color::Yellow",
                ] {
                    if source.contains(raw) {
                        leaks.push(format!("{} uses {raw}", path.display()));
                    }
                }
            }
        }

        let mut leaks = Vec::new();
        inspect(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ui"),
            &mut leaks,
        );
        assert!(
            leaks.is_empty(),
            "production UI colors must come from theme::current(): {leaks:?}"
        );
    }
}
