//! Core application state and logic.
//!
//! This module contains the main [`App`] struct that manages all application state,
//! including VPN connection status, profile management, telemetry data, and UI state.
//!
//! ## Architecture
//!
//! `App` embeds a [`VpnEngine`] that owns all VPN-related state (connection,
//! profiles, telemetry, kill switch, retry logic). The TUI-specific state
//! (panels, overlays, animations, scroll positions) remains directly on `App`.
//!
//! `App` implements `Deref<Target = VpnEngine>` and `DerefMut`, so all existing
//! code that accesses VPN fields (`self.profiles`, `app.connection_state`, …)
//! resolves transparently through the engine.
//!
//! ## Module structure
//! - `input` — Keyboard and mouse event handling
//! - `update` — Message dispatching (TEA-style update function)
//! - `connection` — VPN connection lifecycle management
//! - `profile` — Profile CRUD and import operations
//! - `telemetry_poll` — Background telemetry and scanner polling
//! - `helpers` — Logging, scrolling, toast notifications, and utilities

mod connection;
mod helpers;
mod input;
mod profile;
mod telemetry_poll;
mod update;

#[cfg(test)]
mod tests;

use ratatui::layout::Rect;
use ratatui::widgets::TableState;
use std::collections::{HashMap, HashSet};

use crate::constants;
use crate::engine::VpnEngine;
use crate::logger;
use crate::message::Message;

// Re-export state types for convenient access
pub use crate::state::{
    AuthField, ConnectionState, DetailedConnectionInfo, FlipAnimation, FocusedPanel, InputMode,
    ProfileSortOrder, Protocol, Toast, ToastType, VpnProfile, DISMISS_DURATION,
};

/// Main application state container.
///
/// Holds the VPN engine (all VPN state) and TUI-specific state (panels,
/// overlays, animations). Implements `Deref`/`DerefMut` to `VpnEngine` so
/// that VPN field accesses are transparent.
#[allow(clippy::struct_excessive_bools)]
pub struct App {
    /// The headless VPN engine — owns all VPN state and operations.
    pub engine: VpnEngine,

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
    pub cached_config_content: Option<String>,
    pub search_match_count: usize,
    pub profile_list_state: TableState,
    pub panel_areas: HashMap<FocusedPanel, Rect>,
    pub toast: Option<Toast>,
    pub terminal_size: (u16, u16),
}

// Allow transparent access to VpnEngine fields from App.
// `self.profiles`, `app.connection_state`, etc. all resolve through the engine.
impl std::ops::Deref for App {
    type Target = VpnEngine;
    fn deref(&self) -> &VpnEngine {
        &self.engine
    }
}

impl std::ops::DerefMut for App {
    fn deref_mut(&mut self) -> &mut VpnEngine {
        &mut self.engine
    }
}

impl App {
    /// Create a new App instance with the given configuration.
    #[must_use]
    pub fn new(config: crate::config::AppConfig, config_dir: std::path::PathBuf) -> Self {
        let mut engine = VpnEngine::new(config, config_dir);

        // Load metadata and sort
        engine.load_metadata();
        engine.sort_profiles();

        // Apply user's logging preferences
        logger::configure(&engine.config.log_level, engine.config.max_log_entries);

        let mut app = Self {
            engine,

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
            cached_config_content: None,
            search_match_count: 0,
            profile_list_state: TableState::default(),
            panel_areas: HashMap::new(),
            toast: None,
            terminal_size: (0, 0),
        };

        // Select first profile if available
        if !app.profiles.is_empty() {
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
            let log_path = app.engine.config_dir.join(constants::LOGS_DIR_NAME);
            app.log(&format!("IO: Auto-logging to {}", log_path.display()));
        }

        // Log kill switch recovery if it happened
        if app.engine.killswitch_state == crate::state::KillSwitchState::Disabled {
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

        while let Ok(msg) = self.engine.cmd_rx.try_recv() {
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
    /// Lightweight constructor for testing.
    #[must_use]
    pub fn new_test() -> Self {
        let engine = VpnEngine::new_test();
        Self {
            engine,

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
            cached_config_content: None,
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
        // VpnEngine's Drop handles kill switch cleanup and VPN process termination.
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
