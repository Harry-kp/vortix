//! Core application state and logic.
//!
//! This module contains the main [`App`] struct that manages all application state,
//! including VPN connection status, profile management, telemetry data, and UI state.
//!
//! ## Architecture
//!
//! `App` embeds a [`VpnRuntime`] that owns all VPN-related state (connection,
//! profiles, telemetry, kill switch, retry logic). The TUI-specific state
//! (panels, overlays, animations, scroll positions) remains directly on `App`.
//!
//! Plan #005 U5 removed `App: Deref<Target = VpnRuntime>`. VPN-state
//! accesses are now explicit via `self.runtime.X` / `app.runtime.X`. The
//! optional `engine_handle` field carries the plan #005 `EngineHandle`
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
use std::collections::{HashMap, HashSet};

use crate::constants;
use crate::logger;
use crate::message::Message;
use crate::tunnel::TunnelKind;
use crate::vortix_core::engine::TunnelRegistry;
use crate::vpn_runtime::VpnRuntime;

// Re-export state types for convenient access
pub use crate::state::{
    AuthField, FlipAnimation, FocusedPanel, InputMode, ProfileSortOrder, Protocol, Toast,
    ToastType, VpnProfile, DISMISS_DURATION,
};
// The legacy single-tunnel `ConnectionState`/`DetailedConnectionInfo` enum
// lives on `crate::vpn_runtime` after U6 Stage B; re-export through `app::`
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
    /// `self.registry` (plan #001 U6).
    pub runtime: VpnRuntime,

    /// Optional plan-005 `EngineHandle`. Non-load-bearing today — kept for
    /// IPC / remote-control surfaces that drive a single tunnel through the
    /// FSM actor. Multi-tunnel callers bypass this and use `self.registry`.
    pub engine_handle: Option<crate::vortix_core::engine::EngineHandle>,

    /// Multi-connection plan #001: the `TunnelRegistry` owns active tunnel
    /// FSMs. Panels read tunnel snapshots from here (sidebar, header,
    /// `connection_details`, security, chart).
    pub registry: TunnelRegistry<TunnelKind>,

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
    pub panel_flipped: HashSet<FocusedPanel>,
    pub flip_animation: Option<FlipAnimation>,
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
}

// Plan 005 U5 removed the previous `impl Deref<Target = VpnRuntime>` — the
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

            should_quit: false,

            logs_scroll: 0,
            logs_auto_scroll: true,
            logs_max_scroll: 0,
            log_level_filter: None,

            focused_panel: FocusedPanel::Sidebar,
            zoomed_panel: None,
            panel_flipped: HashSet::new(),
            flip_animation: None,
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
    #[must_use]
    pub fn is_flipped(&self, panel: &FocusedPanel) -> bool {
        self.panel_flipped.contains(panel)
    }

    /// Whether a flip animation is in progress.
    #[must_use]
    pub fn has_active_animation(&self) -> bool {
        self.flip_animation.is_some()
    }

    /// Advance the flip animation; finalize the state change when complete.
    pub fn advance_animation(&mut self) {
        let complete = self
            .flip_animation
            .as_ref()
            .is_some_and(FlipAnimation::is_complete);
        if complete {
            if let Some(anim) = self.flip_animation.take() {
                if anim.to_back {
                    self.panel_flipped.insert(anim.panel);
                } else {
                    self.panel_flipped.remove(&anim.panel);
                }
            }
        }
    }

    /// Effective flip state for rendering, accounting for mid-animation view switch.
    #[must_use]
    pub fn effective_flipped(&self, panel: &FocusedPanel) -> bool {
        let base = self.is_flipped(panel);
        if let Some(anim) = &self.flip_animation {
            if anim.panel == *panel && anim.past_midpoint() {
                return !base;
            }
        }
        base
    }
}

impl App {
    /// Attach an `EngineHandle` to the app (plan 005 U5 incremental
    /// adoption). The handle is not yet load-bearing — the TUI still
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

            should_quit: false,

            logs_scroll: 0,
            logs_auto_scroll: true,
            logs_max_scroll: 0,
            log_level_filter: None,

            focused_panel: FocusedPanel::Sidebar,
            zoomed_panel: None,
            panel_flipped: HashSet::new(),
            flip_animation: None,
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
        }
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
