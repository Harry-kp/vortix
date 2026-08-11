//! Core application state and logic.
//!
//! This module contains the main [`App`] struct that manages all application state,
//! including VPN connection status, profile management, telemetry data, and UI state.
//!
//! ## Architecture
//!
//! `App` is a control client: it caches one immutable canonical snapshot and
//! copies its tunnel projection into the renderer-facing registry. Telemetry
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
//! - `telemetry_poll` — Background telemetry and scanner polling
//! - `helpers` — Logging, scrolling, toast notifications, and utilities

pub(crate) mod connection;
mod helpers;
mod input;
mod profile;
mod telemetry_poll;
mod update;

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
    /// Raw file contents. Stored for completeness (so external code
    /// reading `app.cached_config` sees what's actually loaded). The
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
    pub fn from_content(content: String) -> Self {
        let highlighted_lines: Vec<Line<'static>> = content
            .lines()
            .map(crate::ui::overlays::config_viewer::highlight_config_line)
            .collect();
        let total_lines = u16::try_from(highlighted_lines.len()).unwrap_or(u16::MAX);
        Self {
            content,
            total_lines,
            highlighted_lines,
        }
    }
}
use std::collections::HashMap;

use crate::constants;
use crate::logger;
use crate::message::Message;
use crate::tunnel::TunnelKind;
use crate::vortix_core::engine::TunnelRegistry;
use crate::vpn_runtime::VpnRuntime;

// Re-export state types for convenient access
pub use crate::state::{
    AuthField, FlipState, FocusedPanel, InputMode, ProfileSortOrder, Protocol, Toast, ToastType,
    VpnProfile, DISMISS_DURATION,
};
// The legacy single-tunnel `ConnectionState`/`DetailedConnectionInfo` enum
// lives on `crate::vpn_runtime` after the registry migration; re-export through `app::`
// so the existing `app/connection.rs` / `app/update.rs` code paths that
// drive the legacy mirror still resolve `app::ConnectionState`.
pub use crate::vpn_runtime::{ConnectionState, DetailedConnectionInfo};

/// Main application state container.
///
/// Holds the VPN runtime (telemetry, profiles, config, background workers)
/// alongside the `TunnelRegistry` (active tunnel FSMs) and TUI-specific
/// state (panels, overlays, animations). Reads explicitly route through
/// `self.runtime.X` for telemetry/profiles and `self.registry` for
/// active-tunnel snapshots.
#[allow(clippy::struct_excessive_bools)]
pub struct App {
    /// The headless VPN runtime — telemetry, profile catalog, config,
    /// background workers, kill-switch mode. Active tunnel FSMs live on
    /// `self.registry`.
    pub runtime: VpnRuntime,

    /// Optional plan-005 `EngineHandle`. Non-load-bearing today — kept for
    /// IPC / remote-control surfaces that drive a single tunnel through the
    /// FSM actor. Multi-tunnel callers bypass this and use `self.registry`.
    pub engine_handle: Option<crate::vortix_core::engine::EngineHandle>,

    /// The `TunnelRegistry` owns active tunnel
    /// FSMs. Panels read tunnel snapshots from here (sidebar, header,
    /// `connection_details`, security, chart).
    pub registry: TunnelRegistry<TunnelKind>,

    /// Long-lived Standard-mode canonical authority used by the TUI. Tests
    /// that characterize presentation-only helpers may leave it detached.
    pub(crate) control_session: Option<crate::cli::control::ClientControlSession>,

    /// Last complete immutable publication received from the control owner.
    pub control_snapshot: crate::vortix_core::control::ControlSnapshot,

    /// Service-owned challenge currently displayed by the existing auth
    /// overlay. The answer is returned directly to the service and never
    /// journaled or persisted in this client.
    pub(crate) control_challenge: Option<crate::vortix_core::control::ChallengeId>,

    /// Stable identity retained when the canonical projection becomes empty,
    /// so reconnect means "the last tunnel I used" rather than "all".
    pub(crate) last_control_connected_profile: Option<crate::vortix_core::profile::ProfileId>,

    /// Latest admitted-but-not-yet-published kill-switch intent. Rapid key
    /// presses compose from this value until the snapshot acknowledges it.
    pub(crate) pending_control_killswitch_mode: Option<crate::state::KillSwitchMode>,

    control_request_sequence: u64,

    /// Flag indicating the application should exit.
    pub should_quit: bool,

    // === Logs UI State ===
    pub logs_scroll: u16,
    pub logs_auto_scroll: bool,
    pub logs_max_scroll: u16,
    pub log_level_filter: Option<crate::logger::LogLevel>,

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
    pub search_match_count: usize,
    pub profile_list_state: TableState,
    pub panel_areas: HashMap<FocusedPanel, Rect>,
    pub toast: Option<Toast>,
    pub terminal_size: (u16, u16),
    /// Shared user-visible operating-mode projection.
    pub background_mode: crate::background::BackgroundModeRecord,
    pub(crate) background_diagnostics_loading: bool,
    pub(crate) background_diagnostics_fallback: bool,
}

// An earlier refactor removed the previous `impl Deref<Target = VpnRuntime>` — the
// porous boundary let every TUI/app/CLI callsite reach into VpnRuntime
// without the indirection being visible at the call site. Use
// `app.runtime.X` for runtime fields and `app.registry` for active
// tunnels explicitly.

impl App {
    /// Create a new App instance with the given configuration.
    #[must_use]
    pub fn new(config: crate::config::AppConfig, config_dir: std::path::PathBuf) -> Self {
        let mut runtime = VpnRuntime::new(config, config_dir);

        // Load metadata and sort
        runtime.load_metadata();
        runtime.sort_profiles();

        // Apply user's logging preferences
        logger::configure(&runtime.config.log_level, runtime.config.max_log_entries);

        let mut app = Self {
            runtime,
            engine_handle: None,
            registry: TunnelRegistry::new(),
            control_session: None,
            control_snapshot: crate::vortix_core::control::ControlSnapshot::default(),
            control_challenge: None,
            last_control_connected_profile: None,
            pending_control_killswitch_mode: None,
            control_request_sequence: 0,

            should_quit: false,

            logs_scroll: 0,
            logs_auto_scroll: true,
            logs_max_scroll: 0,
            log_level_filter: None,

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
            search_match_count: 0,
            profile_list_state: TableState::default(),
            panel_areas: HashMap::new(),
            toast: None,
            terminal_size: (0, 0),
            background_mode: crate::background::BackgroundModeRecord::default(),
            background_diagnostics_loading: false,
            background_diagnostics_fallback: true,
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

        // Log kill switch recovery if it happened
        if app.runtime.killswitch_state == crate::state::KillSwitchState::Disabled {
            // Check if we recovered from crash — the engine already handled this
        }

        app.log("SUCCESS: System active. Press [x] for actions.");

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
        let control_update = self.control_session.as_ref().map(|control| {
            control.progress().and_then(|()| {
                let admissions = control.take_tui_admission_results();
                let snapshot = control.take_changed_snapshot()?;
                let catalog = snapshot
                    .as_ref()
                    .and_then(|snapshot| control.take_catalog_update(snapshot));
                Ok((admissions, snapshot, catalog))
            })
        });
        match control_update {
            Some(Ok((admissions, snapshot, catalog))) => {
                self.handle_control_admission_results(admissions);
                if let Some(catalog) = catalog {
                    self.apply_local_catalog_update(catalog);
                }
                if let Some(snapshot) = snapshot {
                    self.handle_message(Message::ControlSnapshot(Box::new(snapshot)));
                }
            }
            Some(Err(error)) => self.handle_message(Message::Toast(
                format!("Control service unavailable: {error}"),
                ToastType::Error,
            )),
            None => {}
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
    /// Attach an `EngineHandle` to the app. The handle is not yet load-bearing — the TUI still
    /// mutates `self.engine` through `Deref` — but future units swap UI
    /// reads / commands over to it.
    #[must_use]
    pub fn with_engine_handle(mut self, handle: crate::vortix_core::engine::EngineHandle) -> Self {
        self.engine_handle = Some(handle);
        self
    }

    /// Lightweight constructor for testing.
    #[must_use]
    pub fn new_test() -> Self {
        let runtime = VpnRuntime::new_test();
        Self {
            runtime,
            engine_handle: None,
            registry: TunnelRegistry::new(),
            control_session: None,
            control_snapshot: crate::vortix_core::control::ControlSnapshot::default(),
            control_challenge: None,
            last_control_connected_profile: None,
            pending_control_killswitch_mode: None,
            control_request_sequence: 0,

            should_quit: false,

            logs_scroll: 0,
            logs_auto_scroll: true,
            logs_max_scroll: 0,
            log_level_filter: None,

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
            search_match_count: 0,
            profile_list_state: TableState::default(),
            panel_areas: HashMap::new(),
            toast: None,
            terminal_size: (80, 24),
            background_mode: crate::background::BackgroundModeRecord::default(),
            background_diagnostics_loading: false,
            background_diagnostics_fallback: true,
        }
    }

    pub fn set_background_diagnostics_fallback(&mut self, enabled: bool) {
        self.background_diagnostics_fallback = enabled;
    }
}

impl Drop for App {
    fn drop(&mut self) {
        // VpnRuntime's Drop handles kill switch cleanup and VPN process termination.
        // Nothing additional needed here.
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
