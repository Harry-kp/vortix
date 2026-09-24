//! Core application state and logic.
//!
//! This module contains the main [`App`] struct that manages all application state,
//! including VPN connection status, profile management, telemetry data, and UI state.
//!
//! ## Architecture
//!
//! `App` is a control client: it caches one immutable engine snapshot and
//! renders tunnels straight from it (`App::tunnels`). Telemetry
//! and profile presentation remain in [`VpnRuntime`]; lifecycle, retry,
//! scanner, policy, and protocol ownership do not.
//!
//! An earlier refactor removed `App: Deref<Target = VpnRuntime>`. VPN-state
//! accesses are now explicit via `self.runtime.X` / `app.runtime.X`. The
//! optional `engine_handle` field carries the `EngineHandle`
//! for code paths that want to query/command through the FSM actor.
//!
//! ## Module structure
//! - `input` — Keyboard and mouse event handling
//! - `update` — Message dispatching (TEA-style update function)
//! - `connection` — VPN connection lifecycle management
//! - `profile` — Profile CRUD and import operations
//! - `helpers` — Logging, scrolling, toast notifications, and utilities

pub(crate) mod connection;
pub use connection::Role;
mod helpers;
mod input;
mod profile;
pub mod runtime;
pub mod state;
mod update;

pub(crate) use input::{focused_tunnel_action, FocusedTunnelAction};

#[cfg(test)]
mod tests;

use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::TableState;

/// Pre-computed view of a profile config file for the `v` overlay.
///
/// Built once when the user opens the viewer; reused on every render and
/// every scroll keystroke. Without this cache, two O(N) operations
/// happen per keypress: `content.lines().count()` to compute scroll
/// bounds (in `helpers.rs::get_config_max_scroll`), and a fresh
/// `content.lines().map(highlight_config_line).collect()` per render
/// frame. Aggressive scrolling spams keys faster than the main thread
/// can re-process the full file, so the TUI wedges. With this cache,
/// scroll-bound checks are O(1) and the renderer just clones a Vec.
pub struct CachedConfigView {
    /// Raw file contents retained so live theme changes can rebuild the
    /// highlighted lines without rereading the profile from disk. The
    /// renderer reads from [`Self::highlighted_lines`] instead.
    pub content: String,
    /// Line count computed once at load time. `u16` matches the
    /// `Paragraph::scroll((u16, u16))` API.
    pub total_lines: u16,
    /// Pre-parsed + syntax-highlighted lines, ready to feed to
    /// `Paragraph::new`. Building this is the expensive part; cloning
    /// the Vec for `Paragraph` consumption per frame is cheap.
    pub highlighted_lines: Vec<Line<'static>>,
}

impl CachedConfigView {
    /// Build a fresh view from raw file content. Pre-counts lines and
    /// pre-highlights them so the open-config keypress pays the cost
    /// once and every subsequent scroll/render frame is constant-time.
    #[must_use]
    pub fn from_content(content: String, choice: crate::ui::theme::ThemeChoice) -> Self {
        let highlighted_lines = crate::ui::theme::with_choice(choice, || {
            content
                .lines()
                .map(crate::ui::overlays::config_viewer::highlight_config_line)
                .collect::<Vec<Line<'static>>>()
        });
        let total_lines = u16::try_from(highlighted_lines.len()).unwrap_or(u16::MAX);
        Self {
            content,
            total_lines,
            highlighted_lines,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingThemeChange {
    previous: crate::ui::theme::ThemeChoice,
    selected: crate::ui::theme::ThemeChoice,
    quit_after: bool,
}
use std::collections::HashMap;

use crate::constants;
use crate::logger;
use crate::message::Message;
use runtime::VpnRuntime;

// Re-export state types for convenient access
pub use state::{
    AuthField, FlipState, FocusedPanel, InputMode, ProfileSortOrder, Toast, ToastType,
    DISMISS_DURATION,
};

/// Main application state container.
///
/// Holds the VPN runtime (telemetry, profiles, config, background workers),
/// the engine snapshot, and TUI state (panels, overlays, animations).
#[allow(clippy::struct_excessive_bools)]
pub struct App {
    /// The headless VPN runtime — telemetry, profile catalog, config,
    /// background workers, kill-switch mode.
    pub runtime: VpnRuntime,

    /// The connection engine. `None` while it is starting.
    pub(crate) control: Option<crate::control::Control>,
    pub(crate) control_starting: bool,
    /// Last snapshot received from the engine.
    pub control_snapshot: std::sync::Arc<crate::control::Snapshot>,
    /// Engine prompt the credential overlay is answering.
    pub(crate) control_prompt: Option<u64>,
    /// Highest engine notice already shown.
    pub(crate) notices_seen: u64,
    /// Kept when every tunnel is gone, so reconnect means "the last one".
    pub(crate) last_control_connected_profile: Option<crate::profile::ProfileId>,
    /// Kill switch mode sent but not yet in a snapshot.
    pub(crate) pending_control_killswitch_mode: Option<crate::control::killswitch::KillSwitchMode>,

    /// Flag indicating the application should exit.
    pub should_quit: bool,

    // === Logs UI State ===
    pub logs_scroll: u16,
    pub logs_auto_scroll: bool,
    pub logs_max_scroll: u16,
    pub log_level_filter: Option<crate::logger::LogLevel>,
    /// Last network-quality category emitted to the Event Log. Raw telemetry
    /// remains dashboard state and only semantic transitions are logged.
    pub(crate) last_logged_network_quality: crate::app::state::QualityLevel,

    // === UI State (Panel-based) ===
    pub focused_panel: FocusedPanel,
    pub zoomed_panel: Option<FocusedPanel>,
    /// Per-panel flip animation state (front/back card-flip via ratatui-flip-panel).
    pub flip_states: HashMap<FocusedPanel, FlipState>,
    pub input_mode: InputMode,
    pub show_config: bool,
    pub show_action_menu: bool,
    pub show_bulk_menu: bool,
    pub action_menu_state: ratatui::widgets::ListState,
    pub config_scroll: u16,
    /// Cached state for the config-viewer overlay (opened with `v`).
    /// Built once when the user opens the viewer; cleared when they
    /// close it. Caching the highlighted `Vec<Line>` + the line count
    /// turns aggressive scroll-spam from O(N²) (re-parse on every key)
    /// into O(N) once + O(viewport) per frame.
    pub cached_config: Option<CachedConfigView>,
    /// The one in-flight theme persistence transaction. The palette changes
    /// immediately; a failed write restores the previous choice.
    pub(crate) pending_theme_change: Option<PendingThemeChange>,
    pub search_match_count: usize,
    pub profile_list_state: TableState,
    pub panel_areas: HashMap<FocusedPanel, Rect>,
    pub toast: Option<Toast>,
    pub terminal_size: (u16, u16),
}

impl App {
    /// Create a new App instance with the given configuration.
    #[must_use]
    pub fn new(config: crate::config::AppConfig, config_dir: std::path::PathBuf) -> Self {
        let mut runtime = VpnRuntime::new(config, config_dir);

        // Load metadata and sort
        runtime.sort_profiles();

        // Apply user's logging preferences
        logger::configure(&runtime.config.log_level, runtime.config.max_log_entries);

        // Seed from disk so the first frame cannot show Off while a
        // persisted firewall is still present.
        let (kill_switch, kill_switch_state) = crate::control::killswitch::persisted();

        let mut app = Self {
            runtime,
            control: None,
            control_starting: true,
            control_snapshot: std::sync::Arc::new(crate::control::Snapshot {
                kill_switch,
                kill_switch_state,
                ..crate::control::Snapshot::default()
            }),
            control_prompt: None,
            notices_seen: 0,
            last_control_connected_profile: None,
            pending_control_killswitch_mode: None,

            should_quit: false,

            logs_scroll: 0,
            logs_auto_scroll: true,
            logs_max_scroll: 0,
            log_level_filter: None,
            last_logged_network_quality: crate::app::state::QualityLevel::Unknown,

            focused_panel: FocusedPanel::Sidebar,
            zoomed_panel: None,
            flip_states: HashMap::new(),
            input_mode: InputMode::Normal,
            show_config: false,
            show_action_menu: false,
            show_bulk_menu: false,
            action_menu_state: ratatui::widgets::ListState::default(),
            config_scroll: 0,
            cached_config: None,
            pending_theme_change: None,
            search_match_count: 0,
            profile_list_state: TableState::default(),
            panel_areas: HashMap::new(),
            toast: None,
            terminal_size: (0, 0),
        };

        // Select first profile if available
        if !app.runtime.profiles.is_empty() {
            app.profile_list_state.select(Some(0));
        }

        // Initialize logs with boot sequence
        app.log(&format!(
            "INIT: {} v{} starting...",
            constants::APP_NAME,
            constants::APP_VERSION
        ));
        app.log(constants::MSG_BACKEND_INIT);

        {
            let log_path = app.runtime.config_dir.join(constants::LOGS_DIR_NAME);
            app.log(&format!("IO: Auto-logging to {}", log_path.display()));
        }

        app.log("INIT: Interface ready; VPN service starting in the background");

        app.check_system_dependencies();

        app.process_external();

        app
    }

    /// Periodic tick from the event loop.
    pub fn on_tick(&mut self) {
        self.handle_message(Message::Tick);
    }

    /// Process all pending external events (telemetry and background commands).
    pub fn process_external(&mut self) {
        if let Some(snapshot) = self
            .control
            .as_ref()
            .and_then(crate::control::Control::changed)
        {
            self.apply_control_snapshot(snapshot);
        }
        self.process_telemetry();

        while let Ok(msg) = self.runtime.cmd_rx.try_recv() {
            self.handle_message(msg);
        }
    }

    /// Called when terminal is resized.
    pub fn on_resize(&mut self, width: u16, height: u16) {
        self.handle_message(Message::Resize(width, height));
    }

    /// Check if a specific panel should be drawn as focused (visually)
    #[must_use]
    pub fn should_draw_focus(&self, panel: &FocusedPanel) -> bool {
        if self.show_config
            || self.show_action_menu
            || self.show_bulk_menu
            || self.input_mode != InputMode::Normal
        {
            return false;
        }
        if let Some(zoomed) = &self.zoomed_panel {
            return *zoomed == *panel;
        }
        self.focused_panel == *panel
    }

    /// Check if a panel is currently showing its back (detailed) view.
    /// Mid-animation aware: returns the post-midpoint face during a flip.
    #[must_use]
    pub fn is_flipped(&self, panel: &FocusedPanel) -> bool {
        self.flip_states
            .get(panel)
            .is_some_and(FlipState::showing_back)
    }

    /// Whether any panel is currently mid-flip.
    #[must_use]
    pub fn has_active_animation(&self) -> bool {
        self.flip_states.values().any(FlipState::is_animating)
    }

    /// Drive every flip state machine forward one tick. Call once per frame.
    pub fn advance_animation(&mut self) {
        for state in self.flip_states.values_mut() {
            state.tick();
        }
    }

    /// Effective flip state for rendering, accounting for mid-animation view swap.
    #[must_use]
    pub fn effective_flipped(&self, panel: &FocusedPanel) -> bool {
        self.is_flipped(panel)
    }

    /// Borrow the flip state for `panel`, creating a default one if missing.
    pub fn flip_state_mut(&mut self, panel: FocusedPanel) -> &mut FlipState {
        self.flip_states.entry(panel).or_default()
    }
}

impl App {
    /// Lightweight constructor for testing.
    #[must_use]
    pub fn new_test() -> Self {
        let runtime = VpnRuntime::new_test();
        Self {
            runtime,
            control: None,
            control_starting: false,
            control_snapshot: std::sync::Arc::default(),
            control_prompt: None,
            notices_seen: 0,
            last_control_connected_profile: None,
            pending_control_killswitch_mode: None,

            should_quit: false,

            logs_scroll: 0,
            logs_auto_scroll: true,
            logs_max_scroll: 0,
            log_level_filter: None,
            last_logged_network_quality: crate::app::state::QualityLevel::Unknown,

            focused_panel: FocusedPanel::Sidebar,
            zoomed_panel: None,
            flip_states: HashMap::new(),
            input_mode: InputMode::Normal,
            show_config: false,
            show_action_menu: false,
            show_bulk_menu: false,
            action_menu_state: ratatui::widgets::ListState::default(),
            config_scroll: 0,
            cached_config: None,
            pending_theme_change: None,
            search_match_count: 0,
            profile_list_state: TableState::default(),
            panel_areas: HashMap::new(),
            toast: None,
            terminal_size: (80, 24),
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new(
            crate::config::AppConfig::default(),
            std::env::temp_dir().join("vortix_default"),
        )
    }
}
