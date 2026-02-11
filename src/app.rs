//! Core application state and logic.
//!
//! This module contains the main [`App`] struct that manages all application state,
//! including VPN connection status, profile management, telemetry data, and UI state.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;
use ratatui::widgets::TableState;
use std::collections::HashMap;
use std::path::Path;
use std::sync::mpsc;
use std::time::Instant;

use crate::constants;
use crate::core::scanner;
use crate::core::telemetry::{self, TelemetryUpdate};
use crate::logger::{self, LogLevel};
use crate::message::{self, Message, ScrollMove, SelectionMove};
use crate::utils;

// Re-export state types for convenient access
pub use crate::state::{
    AuthField, ConnectionState, DetailedConnectionInfo, FocusedPanel, InputMode, Protocol, Toast,
    ToastType, VpnProfile, DISMISS_DURATION,
};

/// Main application state container.
///
/// The `App` struct holds all state for the Vortix TUI application including
/// VPN connection status, loaded profiles, network telemetry, and UI state.
///
/// # Example
///
/// ```ignore
/// let mut app = App::new();
/// app.connect_by_name("my-vpn-profile");
/// ```
#[allow(clippy::struct_excessive_bools)]
pub struct App {
    /// Flag indicating the application should exit.
    pub should_quit: bool,

    // === VPN State ===
    /// Current VPN connection state.
    pub connection_state: ConnectionState,
    /// Loaded VPN profiles.
    pub profiles: Vec<VpnProfile>,
    /// When the current session started.
    pub session_start: Option<Instant>,

    // === Network Telemetry ===
    /// Historical download throughput data points for charting.
    pub down_history: Vec<(f64, f64)>,
    /// Historical upload throughput data points for charting.
    pub up_history: Vec<(f64, f64)>,
    /// Current download rate in bytes/second.
    pub current_down: u64,
    /// Current upload rate in bytes/second.
    pub current_up: u64,
    pub latency_ms: u64,
    pub packet_loss: f32,
    pub jitter_ms: u64,
    pub location: String,
    pub isp: String,
    pub dns_server: String,
    pub ipv6_leak: bool,

    // === System Info ===
    pub public_ip: String,
    /// Real IP captured when disconnected (for comparison when connected)
    pub real_ip: Option<String>,
    /// Scroll position for logs panel (logs stored in logger module)
    pub logs_scroll: u16,
    pub logs_auto_scroll: bool,

    // === UI State (Panel-based) ===
    pub focused_panel: FocusedPanel,
    pub zoomed_panel: Option<FocusedPanel>,
    pub input_mode: InputMode,
    pub show_config: bool,
    pub show_action_menu: bool,
    pub show_bulk_menu: bool,
    pub action_menu_state: ratatui::widgets::ListState,
    pub config_scroll: u16,
    pub profile_list_state: TableState,
    pub panel_areas: HashMap<FocusedPanel, Rect>,
    pub toast: Option<Toast>,
    pub terminal_size: (u16, u16),
    pub is_root: bool,
    /// User-configurable application settings.
    pub config: crate::config::AppConfig,
    /// Resolved config directory path.
    pub config_dir: std::path::PathBuf,
    /// Number of connection drops detected this session.
    pub connection_drops: u32,
    /// Profile index queued for auto-connect after current disconnect completes.
    pub pending_connect: Option<usize>,

    // === Kill Switch ===
    /// Kill switch operating mode (Off, Auto, `AlwaysOn`).
    pub killswitch_mode: crate::state::KillSwitchMode,
    /// Current kill switch state (Disabled, Armed, Blocking).
    pub killswitch_state: crate::state::KillSwitchState,

    // === Async Communication ===
    telemetry_rx: Option<mpsc::Receiver<TelemetryUpdate>>,
    cmd_tx: mpsc::Sender<Message>,
    cmd_rx: mpsc::Receiver<Message>,
    /// Shared profile list for the background scanner thread.
    shared_profiles: std::sync::Arc<std::sync::Mutex<Vec<VpnProfile>>>,
}

impl App {
    /// Create a new App instance with the given configuration.
    #[allow(clippy::too_many_lines)]
    pub fn new(config: crate::config::AppConfig, config_dir: std::path::PathBuf) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel::<Message>();
        let down_history = (0..60).map(|i| (f64::from(i), 0.0)).collect();
        let up_history = (0..60).map(|i| (f64::from(i), 0.0)).collect();
        let mut app = Self {
            should_quit: false,

            connection_state: ConnectionState::Disconnected,
            profiles: Vec::new(),
            session_start: None,

            down_history,
            up_history,
            current_down: 0,
            current_up: 0,
            latency_ms: 0,
            packet_loss: 0.0,
            jitter_ms: 0,
            location: "Detecting...".to_string(),
            isp: "Detecting...".to_string(),
            dns_server: "Detecting...".to_string(),
            ipv6_leak: false,

            public_ip: "Detecting...".to_string(),
            real_ip: None,
            logs_scroll: 0,
            logs_auto_scroll: true,

            // Panel-based UI state
            focused_panel: FocusedPanel::Sidebar,
            zoomed_panel: None,
            input_mode: InputMode::Normal,
            show_config: false,
            show_action_menu: false,
            show_bulk_menu: false,
            action_menu_state: ratatui::widgets::ListState::default(),
            config_scroll: 0,
            profile_list_state: TableState::default(),
            panel_areas: HashMap::new(),
            toast: None,
            terminal_size: (0, 0),
            is_root: utils::is_root(),
            config,
            config_dir,
            connection_drops: 0,
            pending_connect: None,

            // Kill switch - load from persisted state for crash recovery
            killswitch_mode: crate::state::KillSwitchMode::default(),
            killswitch_state: crate::state::KillSwitchState::default(),

            telemetry_rx: None,
            cmd_tx,
            cmd_rx,
            shared_profiles: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        };

        // Recover kill switch state from crash if persisted
        if let Some(persisted) = crate::core::killswitch::load_state() {
            app.killswitch_mode = persisted.mode;
            // If we were blocking when crashed, release it now
            if persisted.state == crate::state::KillSwitchState::Blocking {
                app.log("WARN: Kill switch was blocking when app crashed. Releasing...");
                let _ = crate::core::killswitch::disable_blocking();
                app.killswitch_state = crate::state::KillSwitchState::Disabled;
                crate::core::killswitch::clear_state();
            } else {
                app.killswitch_state = persisted.state;
            }
        }

        // Load profiles from ~/.config/vortix/profiles/
        app.profiles = crate::vpn::load_profiles();

        app.load_metadata();
        app.sort_profiles();
        app.sync_shared_profiles();

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

        // Log auto-save location
        {
            let log_path = app.config_dir.join(constants::LOGS_DIR_NAME);
            app.log(&format!("IO: Auto-logging to {}", log_path.display()));
        }

        app.log("SUCCESS: System active. Press [x] for actions.");

        // Start background telemetry worker
        let telemetry_config = telemetry::TelemetryConfig::from(&app.config);
        app.telemetry_rx = Some(telemetry::spawn_telemetry_worker(telemetry_config));

        // Start background scanner thread (replaces synchronous per-tick scanning)
        {
            let profiles = std::sync::Arc::clone(&app.shared_profiles);
            let tx = app.cmd_tx.clone();
            let tick = std::time::Duration::from_millis(app.config.tick_rate);
            std::thread::spawn(move || loop {
                let snap = profiles.lock().map(|p| p.clone()).unwrap_or_default();
                let active = scanner::get_active_profiles(&snap);
                if tx.send(Message::SyncSystemState(active)).is_err() {
                    break; // Main thread dropped — exit
                }
                std::thread::sleep(tick);
            });
        }

        // Start background network stats thread
        {
            let tx = app.cmd_tx.clone();
            let tick = std::time::Duration::from_millis(app.config.tick_rate);
            std::thread::spawn(move || {
                let mut stats = telemetry::NetworkStats::default();
                loop {
                    let (down, up) = stats.update();
                    if tx.send(Message::NetworkStatsUpdate(down, up)).is_err() {
                        break;
                    }
                    std::thread::sleep(tick);
                }
            });
        }

        app.process_external(); // Flush any early messages

        app
    }

    /// Add a log message via centralized logger
    fn log(&mut self, message: &str) {
        // Parse category and level from message prefix (e.g., "NET:", "SEC:", "STATUS:")
        let (category, content, level) = if let Some(idx) = message.find(':') {
            let cat = &message[..idx];
            let msg = message[idx + 1..].trim();

            // Determine level based on content
            let lvl = if msg.contains("Error") || msg.contains("Failed") || msg.contains("LEAK") {
                LogLevel::Error
            } else if msg.contains("⚠") || msg.contains("WARNING") || msg.contains("dropped") {
                LogLevel::Warning
            } else {
                LogLevel::Info
            };

            (cat, msg, lvl)
        } else {
            ("APP", message, LogLevel::Info)
        };

        // Log via centralized logger
        logger::log(level, category, content);

        // Update scroll position based on logger entries
        let log_count = logger::get_logs().len();
        if self.logs_auto_scroll {
            self.logs_scroll = u16::try_from(log_count.saturating_sub(1)).unwrap_or(u16::MAX);
        }

        // Auto-save to log file
        let timestamp = utils::format_local_time();
        Self::append_to_log_file(&format!("{timestamp} {message}"), &self.config_dir);
    }

    /// Handle keyboard input
    pub fn handle_key(&mut self, key: KeyEvent) {
        // 1. Global: Quit (Always takes priority)
        if (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
            || (key.code == KeyCode::Char('q') && self.input_mode == InputMode::Normal)
        {
            self.handle_message(Message::Quit);
            return;
        }

        // 2. Dismiss toast on Esc
        if key.code == KeyCode::Esc && self.toast.is_some() {
            self.toast = None;
            return;
        }

        // 3. Global: Handle Config View - scroll or close
        if self.show_config {
            match key.code {
                KeyCode::Esc | KeyCode::Char('v') => {
                    self.handle_message(Message::CloseOverlay);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.handle_message(Message::Scroll(ScrollMove::Up));
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.handle_message(Message::Scroll(ScrollMove::Down));
                }
                KeyCode::Home | KeyCode::Char('g') => {
                    self.handle_message(Message::Scroll(ScrollMove::Top));
                }
                KeyCode::End | KeyCode::Char('G') => {
                    self.handle_message(Message::Scroll(ScrollMove::Bottom));
                }
                _ => {} // Ignore other keys
            }
            return;
        }

        // 4. Global: Handle Action Menu
        if self.show_action_menu || self.show_bulk_menu {
            self.handle_action_menu_keys(key);
            return;
        }

        // Handle based on Input Mode
        let input_mode = self.input_mode.clone();
        match input_mode {
            InputMode::Import {
                mut path,
                mut cursor,
            } => {
                self.handle_input_import(key, &mut path, &mut cursor);
                if let InputMode::Import { .. } = self.input_mode {
                    self.input_mode = InputMode::Import { path, cursor };
                }
            }
            InputMode::AuthPrompt {
                profile_idx,
                profile_name,
                mut username,
                mut username_cursor,
                mut password,
                mut password_cursor,
                mut focused_field,
                mut save_credentials,
                connect_after,
            } => {
                self.handle_input_auth(
                    key,
                    profile_idx,
                    &profile_name,
                    &mut username,
                    &mut username_cursor,
                    &mut password,
                    &mut password_cursor,
                    &mut focused_field,
                    &mut save_credentials,
                    connect_after,
                );
                // Update state if still in AuthPrompt mode
                if let InputMode::AuthPrompt { .. } = self.input_mode {
                    self.input_mode = InputMode::AuthPrompt {
                        profile_idx,
                        profile_name,
                        username,
                        username_cursor,
                        password,
                        password_cursor,
                        focused_field,
                        save_credentials,
                        connect_after,
                    };
                }
            }
            InputMode::DependencyError { .. } | InputMode::PermissionDenied { .. } => {
                if key.code == KeyCode::Esc {
                    self.handle_message(Message::CloseOverlay);
                }
            }
            InputMode::ConfirmDelete { .. } => self.handle_confirm_delete_keys(key),
            InputMode::Normal => self.handle_normal_keys(key),
        }
    }

    pub fn handle_mouse(&mut self, mouse: crossterm::event::MouseEvent) {
        use crossterm::event::{MouseButton, MouseEventKind};
        match mouse.kind {
            MouseEventKind::ScrollDown => self.handle_message(Message::Scroll(ScrollMove::Down)),
            MouseEventKind::ScrollUp => self.handle_message(Message::Scroll(ScrollMove::Up)),
            MouseEventKind::Down(MouseButton::Left) => {
                // Check if any panel was clicked
                for (panel, area) in &self.panel_areas {
                    if mouse.column >= area.x
                        && mouse.column < area.x + area.width
                        && mouse.row >= area.y
                        && mouse.row < area.y + area.height
                    {
                        self.handle_message(Message::FocusPanel(panel.clone()));
                        break;
                    }
                }
            }
            _ => {}
        }
    }

    fn scroll_down(&mut self) {
        // 1. Config Viewer Overlay (Highest Priority)
        if self.show_config {
            let max_scroll = self.get_config_max_scroll();
            if self.config_scroll < max_scroll {
                self.config_scroll += 1;
            }
            return;
        }

        // 2. Focused Panel
        match self.focused_panel {
            FocusedPanel::Sidebar => {
                // Scroll Profiles
                let current = self.profile_list_state.selected().unwrap_or(0);
                let last = self.profiles.len().saturating_sub(1);
                if current < last {
                    self.profile_list_state.select(Some(current + 1));
                }
            }
            FocusedPanel::Logs => {
                // Scroll Logs
                let max_scroll =
                    u16::try_from(logger::get_logs().len().saturating_sub(1)).unwrap_or(u16::MAX);
                if self.logs_scroll < max_scroll {
                    self.logs_scroll = self.logs_scroll.saturating_add(1);
                }
                // Re-enable auto-scroll if near bottom
                if self.logs_scroll >= max_scroll.saturating_sub(2) {
                    self.logs_auto_scroll = true;
                }
            }
            _ => {}
        }
    }

    fn scroll_up(&mut self) {
        // 1. Config Viewer Overlay (Highest Priority)
        if self.show_config {
            self.config_scroll = self.config_scroll.saturating_sub(1);
            return;
        }

        // 2. Focused Panel
        match self.focused_panel {
            FocusedPanel::Sidebar => {
                // Scroll Profiles
                let current = self.profile_list_state.selected().unwrap_or(0);
                if current > 0 {
                    self.profile_list_state.select(Some(current - 1));
                }
            }
            FocusedPanel::Logs => {
                // Scroll Logs
                self.logs_auto_scroll = false;
                self.logs_scroll = self.logs_scroll.saturating_sub(1);
            }
            _ => {}
        }
    }

    fn handle_confirm_delete_keys(&mut self, key: KeyEvent) {
        if let InputMode::ConfirmDelete {
            index: _,
            name: _,
            confirm_selected,
        } = &mut self.input_mode
        {
            match key.code {
                KeyCode::Tab => {
                    *confirm_selected = !*confirm_selected;
                }
                KeyCode::Left | KeyCode::Char('h') => {
                    *confirm_selected = true;
                }
                KeyCode::Right | KeyCode::Char('l') => {
                    *confirm_selected = false;
                }
                KeyCode::Char('y') => {
                    self.handle_message(Message::ConfirmDelete);
                }
                KeyCode::Char('n') | KeyCode::Esc => {
                    self.handle_message(Message::CloseOverlay);
                }
                KeyCode::Enter => {
                    if *confirm_selected {
                        self.handle_message(Message::ConfirmDelete);
                    } else {
                        self.handle_message(Message::CloseOverlay);
                    }
                }
                _ => {}
            }
        }
    }

    fn handle_input_import(&mut self, key: KeyEvent, path: &mut String, cursor: &mut usize) {
        match key.code {
            KeyCode::Esc => self.handle_message(Message::CloseOverlay),
            KeyCode::Enter => {
                let path_clone = path.clone();
                self.handle_message(Message::Import(path_clone));
                self.handle_message(Message::CloseOverlay);
            }
            KeyCode::Left => {
                *cursor = cursor.saturating_sub(1);
            }
            KeyCode::Right => {
                if *cursor < path.len() {
                    *cursor += 1;
                }
            }
            KeyCode::Home => {
                *cursor = 0;
            }
            KeyCode::End => {
                *cursor = path.len();
            }
            KeyCode::Backspace => {
                if *cursor > 0 {
                    path.remove(*cursor - 1);
                    *cursor -= 1;
                }
            }
            KeyCode::Delete => {
                if *cursor < path.len() {
                    path.remove(*cursor);
                }
            }
            KeyCode::Char(c) => {
                path.insert(*cursor, c);
                *cursor += 1;
            }
            _ => {}
        }
    }

    /// Handle keyboard input for the auth credentials overlay.
    #[allow(clippy::too_many_arguments)]
    fn handle_input_auth(
        &mut self,
        key: KeyEvent,
        profile_idx: usize,
        _profile_name: &str,
        username: &mut String,
        username_cursor: &mut usize,
        password: &mut String,
        password_cursor: &mut usize,
        focused_field: &mut AuthField,
        save_credentials: &mut bool,
        connect_after: bool,
    ) {
        match key.code {
            KeyCode::Esc => self.handle_message(Message::CloseOverlay),
            KeyCode::Tab | KeyCode::BackTab => {
                // Cycle through fields: Username -> Password -> SaveCheckbox -> Username
                *focused_field = match (&focused_field, key.code) {
                    (AuthField::Username, KeyCode::Tab)
                    | (AuthField::SaveCheckbox, KeyCode::BackTab) => AuthField::Password,
                    (AuthField::Password, KeyCode::Tab)
                    | (AuthField::Username, KeyCode::BackTab) => AuthField::SaveCheckbox,
                    (AuthField::SaveCheckbox, KeyCode::Tab)
                    | (AuthField::Password, KeyCode::BackTab) => AuthField::Username,
                    _ => focused_field.clone(),
                };
            }
            KeyCode::Enter => {
                // On SaveCheckbox, toggle the checkbox instead of submitting
                if *focused_field == AuthField::SaveCheckbox {
                    *save_credentials = !*save_credentials;
                    return;
                }
                // Require both fields to be non-empty
                if username.is_empty() || password.is_empty() {
                    self.show_toast(
                        "Both username and password are required".to_string(),
                        ToastType::Warning,
                    );
                    return;
                }
                self.handle_message(Message::AuthSubmit {
                    idx: profile_idx,
                    username: username.clone(),
                    password: password.clone(),
                    save: *save_credentials,
                    connect_after,
                });
            }
            KeyCode::Char(' ') if *focused_field == AuthField::SaveCheckbox => {
                *save_credentials = !*save_credentials;
            }
            _ => {
                // Route text editing to the focused field
                let (text, cursor) = match focused_field {
                    AuthField::Username => (username, username_cursor),
                    AuthField::Password => (password, password_cursor),
                    AuthField::SaveCheckbox => return, // No text editing on checkbox
                };
                Self::handle_text_field_input(key, text, cursor);
            }
        }
    }

    /// Generic text field input handler for cursor movement and editing.
    fn handle_text_field_input(key: KeyEvent, text: &mut String, cursor: &mut usize) {
        match key.code {
            KeyCode::Left => {
                *cursor = cursor.saturating_sub(1);
            }
            KeyCode::Right => {
                if *cursor < text.len() {
                    *cursor += 1;
                }
            }
            KeyCode::Home => {
                *cursor = 0;
            }
            KeyCode::End => {
                *cursor = text.len();
            }
            KeyCode::Backspace => {
                if *cursor > 0 {
                    text.remove(*cursor - 1);
                    *cursor -= 1;
                }
            }
            KeyCode::Delete => {
                if *cursor < text.len() {
                    text.remove(*cursor);
                }
            }
            KeyCode::Char(c) => {
                text.insert(*cursor, c);
                *cursor += 1;
            }
            _ => {}
        }
    }

    fn handle_normal_keys(&mut self, key: KeyEvent) {
        match key.code {
            // Global Toggles
            KeyCode::Tab | KeyCode::Char('l') => {
                if self.zoomed_panel.is_none() {
                    self.handle_message(Message::NextPanel);
                }
            }
            KeyCode::BackTab | KeyCode::Char('h') => {
                if self.zoomed_panel.is_none() {
                    self.handle_message(Message::PreviousPanel);
                }
            }

            // Expert Mode: Zoom
            KeyCode::Char('z') => self.handle_message(Message::ToggleZoom),
            KeyCode::Char('x') => self.handle_message(Message::OpenActionMenu),
            KeyCode::Char('b') => self.handle_message(Message::OpenBulkMenu),
            KeyCode::Esc => {
                if self.zoomed_panel.is_some() {
                    self.zoomed_panel = None;
                }
            }

            // Profile List Navigation (always available in Normal mode)
            KeyCode::Home | KeyCode::Char('g') => {
                self.handle_message(Message::ProfileMove(SelectionMove::First));
            }
            KeyCode::End | KeyCode::Char('G') => {
                self.handle_message(Message::ProfileMove(SelectionMove::Last));
            }
            KeyCode::PageUp => {
                let current = self.profile_list_state.selected().unwrap_or(0);
                let next = current.saturating_sub(10);
                self.profile_list_state.select(Some(next));
            }
            KeyCode::PageDown => {
                let current = self.profile_list_state.selected().unwrap_or(0);
                let last = self.profiles.len().saturating_sub(1);
                let next = (current + 10).min(last);
                self.profile_list_state.select(Some(next));
            }

            // Quick Actions (always available)
            KeyCode::Char('1') => self.handle_message(Message::QuickConnect(0)),
            KeyCode::Char('2') => self.handle_message(Message::QuickConnect(1)),
            KeyCode::Char('3') => self.handle_message(Message::QuickConnect(2)),
            KeyCode::Char('4') => self.handle_message(Message::QuickConnect(3)),
            KeyCode::Char('5') => self.handle_message(Message::QuickConnect(4)),
            KeyCode::Char('6') => self.handle_message(Message::QuickConnect(5)),
            KeyCode::Char('7') => self.handle_message(Message::QuickConnect(6)),
            KeyCode::Char('8') => self.handle_message(Message::QuickConnect(7)),
            KeyCode::Char('9') => self.handle_message(Message::QuickConnect(8)),
            KeyCode::Char('d') => self.handle_message(Message::Disconnect),
            KeyCode::Char('r') => self.handle_message(Message::Reconnect),
            KeyCode::Char('i') => self.handle_message(Message::OpenImport),
            KeyCode::Char('y') => self.handle_message(Message::CopyIp),

            // Kill Switch toggle (Shift+K for safety)
            KeyCode::Char('K') => self.handle_message(Message::ToggleKillSwitch),

            // Delegation to focused panel for other keys
            _ => self.handle_panel_keys(key),
        }
    }

    fn handle_panel_keys(&mut self, key: KeyEvent) {
        match self.focused_panel {
            FocusedPanel::Sidebar => match key.code {
                KeyCode::Char('j') | KeyCode::Down => {
                    self.handle_message(Message::ProfileMove(SelectionMove::Next));
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    self.handle_message(Message::ProfileMove(SelectionMove::Prev));
                }
                KeyCode::Char('x') => self.handle_message(Message::OpenActionMenu),
                KeyCode::Char('b') => self.handle_message(Message::OpenBulkMenu),
                KeyCode::Delete | KeyCode::Backspace => {
                    self.handle_message(Message::OpenDelete(None));
                }
                KeyCode::Char('c') | KeyCode::Enter => {
                    self.handle_message(Message::ToggleConnect(None));
                }
                KeyCode::Char('v') => {
                    if self.profile_list_state.selected().is_some() {
                        self.handle_message(Message::OpenConfig);
                    } else {
                        self.show_toast(
                            "Select a profile to view its config".to_string(),
                            ToastType::Info,
                        );
                    }
                }
                KeyCode::Char('a') => self.handle_message(Message::ManageAuth),
                KeyCode::Char('A') => self.handle_message(Message::ClearAuth),
                _ => {}
            },
            FocusedPanel::Logs => {
                // Activity Log navigation (scroll through log history)
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        self.logs_auto_scroll = false;
                        self.logs_scroll = self.logs_scroll.saturating_sub(1);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let max_scroll = u16::try_from(logger::get_logs().len().saturating_sub(1))
                            .unwrap_or(u16::MAX);
                        if self.logs_scroll < max_scroll {
                            self.logs_scroll = self.logs_scroll.saturating_add(1);
                        }
                        // Re-enable auto-scroll when reaching the end
                        if self.logs_scroll >= max_scroll.saturating_sub(5) {
                            self.logs_auto_scroll = true;
                        }
                    }
                    KeyCode::End | KeyCode::Char('G') => {
                        // Jump to end and re-enable auto-scroll
                        self.logs_auto_scroll = true;
                    }
                    KeyCode::Home | KeyCode::Char('g') => {
                        // Jump to start
                        self.logs_auto_scroll = false;
                        self.logs_scroll = 0;
                    }
                    KeyCode::Char('L') => self.handle_message(Message::ClearLogs),
                    _ => {}
                }
            }
            // Read-only panels
            FocusedPanel::ConnectionDetails | FocusedPanel::Chart | FocusedPanel::Security => {}
        }
    }

    // Cycle to next panel
    fn next_panel(&mut self) {
        self.focused_panel = match self.focused_panel {
            FocusedPanel::Sidebar => FocusedPanel::Chart,
            FocusedPanel::Chart => FocusedPanel::ConnectionDetails,
            FocusedPanel::ConnectionDetails => FocusedPanel::Security,
            FocusedPanel::Security => FocusedPanel::Logs,
            FocusedPanel::Logs => FocusedPanel::Sidebar,
        };
    }

    // Cycle to previous panel
    fn previous_panel(&mut self) {
        self.focused_panel = match self.focused_panel {
            FocusedPanel::Sidebar => FocusedPanel::Logs,
            FocusedPanel::Logs => FocusedPanel::Security,
            FocusedPanel::Security => FocusedPanel::ConnectionDetails,
            FocusedPanel::ConnectionDetails => FocusedPanel::Chart,
            FocusedPanel::Chart => FocusedPanel::Sidebar,
        };
    }

    /// Handle keys when the action menu is open
    fn handle_action_menu_keys(&mut self, key: KeyEvent) {
        let actions = if self.show_bulk_menu {
            message::get_bulk_actions()
        } else {
            message::get_single_actions(&self.focused_panel)
        };
        let action_count = actions.len();

        match key.code {
            KeyCode::Esc | KeyCode::Char('q' | 'x' | 'b') => {
                self.handle_message(Message::CloseOverlay);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(current) = self.action_menu_state.selected() {
                    if current > 0 {
                        self.action_menu_state.select(Some(current - 1));
                    } else {
                        self.action_menu_state.select(Some(action_count - 1));
                    }
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(current) = self.action_menu_state.selected() {
                    if current < action_count - 1 {
                        self.action_menu_state.select(Some(current + 1));
                    } else {
                        self.action_menu_state.select(Some(0));
                    }
                }
            }
            KeyCode::Enter => {
                if let Some(selected) = self.action_menu_state.selected() {
                    if let Some(item) = actions.get(selected) {
                        let msg = item.message.clone();
                        self.show_action_menu = false;
                        self.show_bulk_menu = false;
                        self.handle_message(msg);
                    }
                }
            }
            KeyCode::Char(c) => {
                // Try exact (case-sensitive) match first, fall back to case-insensitive.
                // This allows a/A to be distinct keys while keeping i/I convenience.
                let item = actions
                    .iter()
                    .find(|a| a.key.len() == 1 && a.key.starts_with(c))
                    .or_else(|| {
                        actions.iter().find(|a| {
                            a.key.len() == 1
                                && a.key
                                    .chars()
                                    .next()
                                    .is_some_and(|kc| kc.eq_ignore_ascii_case(&c))
                        })
                    });
                if let Some(item) = item {
                    let msg = item.message.clone();
                    self.show_action_menu = false;
                    self.show_bulk_menu = false;
                    self.handle_message(msg);
                }
            }
            KeyCode::Delete | KeyCode::Backspace => {
                if let Some(item) = actions.iter().find(|a| a.key == "DEL") {
                    let msg = item.message.clone();
                    self.show_action_menu = false;
                    self.show_bulk_menu = false;
                    self.handle_message(msg);
                }
            }
            _ => {}
        }
    }

    /// Handle a message from the action menu or other sources
    #[allow(clippy::too_many_lines)]
    pub fn handle_message(&mut self, msg: crate::message::Message) {
        match msg {
            // Navigation
            Message::NextPanel => self.next_panel(),
            Message::PreviousPanel => self.previous_panel(),
            Message::FocusPanel(panel) => self.focused_panel = panel,

            // Imports
            Message::Import(path) => self.import_profile_from_path(&path),

            // Profile actions
            Message::ToggleConnect(idx) => {
                let index = idx.or_else(|| self.profile_list_state.selected());
                if let Some(i) = index {
                    self.toggle_connection(i);
                }
            }
            Message::OpenConfig => {
                if self.profile_list_state.selected().is_some() {
                    self.show_config = true;
                }
            }
            Message::ManageAuth => {
                if let Some(idx) = self.profile_list_state.selected() {
                    if let Some(profile) = self.profiles.get(idx) {
                        if !matches!(profile.protocol, Protocol::OpenVPN) {
                            self.show_toast(
                                "Auth credentials only apply to OpenVPN profiles".to_string(),
                                ToastType::Info,
                            );
                        } else if !utils::openvpn_config_needs_auth(&profile.config_path) {
                            self.show_toast(
                                "This profile does not use auth-user-pass".to_string(),
                                ToastType::Info,
                            );
                        } else {
                            // Pre-fill with existing credentials if saved
                            let (username, password) =
                                utils::read_openvpn_saved_auth(&profile.name).unwrap_or_default();
                            let username_cursor = username.len();
                            let password_cursor = password.len();
                            self.input_mode = InputMode::AuthPrompt {
                                profile_idx: idx,
                                profile_name: profile.name.clone(),
                                username,
                                username_cursor,
                                password,
                                password_cursor,
                                focused_field: crate::state::AuthField::Username,
                                save_credentials: true,
                                connect_after: false,
                            };
                        }
                    }
                }
            }
            Message::ClearAuth => {
                if let Some(idx) = self.profile_list_state.selected() {
                    if let Some(profile) = self.profiles.get(idx) {
                        let is_openvpn = matches!(profile.protocol, Protocol::OpenVPN);
                        let has_auth = utils::openvpn_config_needs_auth(&profile.config_path);
                        let name = profile.name.clone();
                        if !is_openvpn {
                            self.show_toast(
                                "Auth credentials only apply to OpenVPN profiles".to_string(),
                                ToastType::Info,
                            );
                        } else if !has_auth {
                            self.show_toast(
                                "This profile does not use auth-user-pass".to_string(),
                                ToastType::Info,
                            );
                        } else if utils::read_openvpn_saved_auth(&name).is_none() {
                            self.show_toast(
                                format!("No saved credentials for '{name}'"),
                                ToastType::Info,
                            );
                        } else {
                            utils::delete_openvpn_auth_file(&name);
                            self.log(&format!("AUTH: Cleared saved credentials for '{name}'"));
                            self.show_toast(
                                format!("Credentials cleared for '{name}'"),
                                ToastType::Success,
                            );
                        }
                    }
                }
            }
            Message::OpenDelete(idx) => {
                let index = idx.or_else(|| self.profile_list_state.selected());
                if let Some(i) = index {
                    self.request_delete(i);
                }
            }
            Message::ConfirmDelete => {
                if let InputMode::ConfirmDelete { index, .. } = self.input_mode {
                    self.confirm_delete(index);
                }
            }
            Message::ProfileMove(mv) => match mv {
                SelectionMove::Next => self.profile_next(),
                SelectionMove::Prev => self.profile_previous(),
                SelectionMove::First => self.profile_list_state.select(Some(0)),
                SelectionMove::Last => {
                    let last = self.profiles.len().saturating_sub(1);
                    self.profile_list_state.select(Some(last));
                }
            },

            // Connection
            Message::Disconnect => {
                if matches!(self.connection_state, ConnectionState::Disconnecting { .. }) {
                    self.force_disconnect();
                } else {
                    self.disconnect();
                }
            }
            Message::Reconnect => self.reconnect(),
            Message::QuickConnect(idx) => {
                if idx < self.profiles.len() {
                    self.toggle_connection(idx);
                }
            }

            // Disconnect result from background thread
            Message::DisconnectResult {
                profile,
                success,
                error,
            } => {
                if success {
                    self.complete_disconnect(&profile);
                } else {
                    let err_msg = error.unwrap_or_else(|| "unknown error".to_string());
                    self.log(&format!(
                        "CMD_ERR: Failed to disconnect '{profile}': {err_msg}"
                    ));
                    // Clear pending -- don't auto-connect after a failed disconnect
                    self.pending_connect = None;
                    // Revert to Disconnected so the scanner can re-detect if VPN is still running
                    if matches!(self.connection_state, ConnectionState::Disconnecting { .. }) {
                        self.connection_state = ConnectionState::Disconnected;
                    }
                    self.show_toast(format!("Failed to disconnect: {err_msg}"), ToastType::Error);
                    self.sync_killswitch();
                }
            }

            // Connect result from background thread
            Message::ConnectResult {
                profile,
                success,
                error,
            } => {
                // Ignore stale results if we're no longer in Connecting state for this profile.
                // This prevents spurious errors when the connect polling thread outlives a
                // disconnect (e.g., user disconnects while log polling is still running).
                let still_connecting = matches!(
                    &self.connection_state,
                    ConnectionState::Connecting { profile: p, .. } if *p == profile
                );
                if !still_connecting {
                    self.log(&format!(
                        "CMD: Ignoring stale ConnectResult for '{profile}' \
                         (state is no longer Connecting)"
                    ));
                } else if success {
                    self.log(&format!("CMD: Successfully started VPN for '{profile}'"));
                    // Keep state as Connecting -- the scanner will promote to Connected
                    // once the interface appears.
                } else {
                    let err_msg = error.unwrap_or_else(|| "unknown error".to_string());
                    self.log(&format!(
                        "CMD_ERR: Failed to connect '{profile}': {err_msg}"
                    ));
                    self.connection_state = ConnectionState::Disconnected;
                    self.session_start = None;
                    self.show_toast(format!("Failed to connect: {err_msg}"), ToastType::Error);
                    // Drain pending_connect on failure (don't auto-connect)
                    self.pending_connect = None;
                }
            }

            // UI Toggles
            Message::ToggleZoom => {
                if self.zoomed_panel.is_some() {
                    self.zoomed_panel = None;
                } else {
                    self.zoomed_panel = Some(self.focused_panel.clone());
                }
            }
            Message::CloseOverlay => {
                self.show_config = false;
                self.show_action_menu = false;
                self.show_bulk_menu = false;
                self.zoomed_panel = None;
                self.input_mode = InputMode::Normal;
            }
            Message::OpenActionMenu => {
                if self.profile_list_state.selected().is_some()
                    || self.focused_panel != FocusedPanel::Sidebar
                {
                    self.show_action_menu = true;
                    self.action_menu_state.select(Some(0));
                }
            }
            Message::OpenBulkMenu => {
                self.show_bulk_menu = true;
                self.action_menu_state.select(Some(0));
            }
            Message::OpenImport => {
                self.input_mode = InputMode::Import {
                    path: String::new(),
                    cursor: 0,
                };
            }

            // Scrolling
            Message::Scroll(mv) => match mv {
                ScrollMove::Up => self.scroll_up(),
                ScrollMove::Down => self.scroll_down(),
                ScrollMove::Top => {
                    if self.show_config {
                        self.config_scroll = 0;
                    }
                }
                ScrollMove::Bottom => {
                    if self.show_config {
                        self.config_scroll = self.get_config_max_scroll();
                    }
                }
            },

            // Kill Switch
            Message::AuthSubmit {
                idx,
                username,
                password,
                save,
                connect_after,
            } => {
                // Close the overlay first
                self.input_mode = InputMode::Normal;

                // Get profile name for file path
                let profile_name = self
                    .profiles
                    .get(idx)
                    .map(|p| p.name.clone())
                    .unwrap_or_default();

                if profile_name.is_empty() {
                    self.show_toast("Invalid profile index".to_string(), ToastType::Error);
                    return;
                }

                // Write credentials to auth file
                match utils::write_openvpn_auth_file(&profile_name, &username, &password) {
                    Ok(_) => {
                        if save {
                            self.log(&format!("AUTH: Saved credentials for '{profile_name}'"));
                        } else {
                            self.log(&format!(
                                "AUTH: Using one-time credentials for '{profile_name}'"
                            ));
                        }

                        if connect_after {
                            // Now connect -- saved creds will be found by connect_profile
                            self.connect_profile(idx);

                            // If user chose not to save, clean up after connect starts
                            if !save {
                                // Schedule cleanup -- the connect thread has already read the
                                // path, so we can remove it after a brief delay. However,
                                // since OpenVPN reads it during fork, we defer cleanup to
                                // the disconnect handler instead.
                            }
                        } else {
                            // Save-only mode (from ManageAuth)
                            self.show_toast(
                                format!("Credentials updated for '{profile_name}'"),
                                ToastType::Success,
                            );
                        }
                    }
                    Err(e) => {
                        self.show_toast(
                            format!("Failed to write auth file: {e}"),
                            ToastType::Error,
                        );
                    }
                }
            }

            Message::ToggleKillSwitch => {
                use crate::state::KillSwitchMode;

                // Cycle to next mode
                self.killswitch_mode = self.killswitch_mode.next();

                // Sync state and firewall
                self.sync_killswitch();

                // Log and toast based on new mode
                match self.killswitch_mode {
                    KillSwitchMode::Off => {
                        self.log("SEC: Kill switch DISABLED");
                        self.show_toast("Kill Switch OFF".to_string(), ToastType::Info);
                    }
                    KillSwitchMode::Auto => {
                        self.log("SEC: Kill switch mode set to AUTO");
                        self.show_toast(
                            "Kill Switch ON - will block if VPN drops".to_string(),
                            ToastType::Success,
                        );
                    }
                    KillSwitchMode::AlwaysOn => {
                        self.log("SEC: Kill switch mode set to STRICT (AlwaysOn)");
                        self.show_toast(
                            "Kill Switch STRICT - blocks until VPN connects".to_string(),
                            ToastType::Warning,
                        );
                    }
                }

                // Save state for recovery
                let _ = crate::core::killswitch::save_state(
                    self.killswitch_mode,
                    self.killswitch_state,
                    None,
                    None,
                );
            }

            // System
            Message::Quit => self.should_quit = true,
            Message::Log(msg) => self.log(&msg),
            Message::Toast(msg, t_type) => self.show_toast(msg, t_type),
            Message::CopyIp => self.copy_ip_to_clipboard(),
            Message::ClearLogs => {
                logger::clear_logs();
                self.logs_scroll = 0;
                self.log("APP: Logs cleared");
            }
            Message::Telemetry(update) => {
                match update {
                    TelemetryUpdate::PublicIp(ip) => {
                        let is_connected =
                            matches!(self.connection_state, ConnectionState::Connected { .. });
                        let old_ip = self.public_ip.clone();

                        // Store as real_ip when disconnected (for security comparison)
                        if matches!(self.connection_state, ConnectionState::Disconnected) {
                            if self.real_ip.is_none() {
                                self.log(&format!("NET: Real IP detected: {ip}"));
                            }
                            self.real_ip = Some(ip.clone());
                        } else if self.public_ip != ip && self.public_ip != constants::MSG_FETCHING
                        {
                            self.log(&format!("NET: ✓ Public IP changed from {old_ip} to {ip}"));
                        } else if is_connected
                            && self.public_ip == ip
                            && self.public_ip != constants::MSG_FETCHING
                        {
                            // CRITICAL: IP hasn't changed despite being connected to VPN!
                            self.log(&format!(
                                "NET: ⚠ WARNING: Public IP unchanged ({ip}) while connected to VPN!"
                            ));
                            self.log("NET: → Possible issues: 1) VPN not routing traffic 2) Split-tunnel active 3) Kill switch blocking telemetry");

                            // Log the real IP for comparison
                            if let Some(ref real) = self.real_ip {
                                if real == &ip {
                                    self.log(&format!("NET: → LEAK DETECTED: Current IP ({ip}) matches pre-VPN IP ({real})"));
                                }
                            }
                        }
                        self.public_ip = ip;
                    }
                    TelemetryUpdate::Latency(ms) => self.latency_ms = ms,
                    TelemetryUpdate::PacketLoss(loss) => {
                        self.packet_loss = loss;
                        self.log(&format!("NET: Packet loss: {loss:.1}%"));
                    }
                    TelemetryUpdate::Jitter(jitter) => {
                        self.jitter_ms = jitter;
                        self.log(&format!("NET: Jitter: {jitter}ms"));
                    }
                    TelemetryUpdate::Location(loc) => {
                        if self.location != loc && self.location != constants::MSG_DETECTING {
                            self.log(&format!("NET: Location: {loc}"));
                        }
                        self.location = loc;
                    }
                    TelemetryUpdate::Isp(isp) => {
                        if self.isp != isp && self.isp != constants::MSG_DETECTING {
                            self.log(&format!("NET: Exit node: {isp}"));
                        }
                        self.isp = isp;
                    }
                    TelemetryUpdate::Dns(dns) => {
                        if self.dns_server != dns && self.dns_server != constants::MSG_NO_DATA {
                            let leak_warn = if utils::is_private_ip(&dns) {
                                " ⚠ POSSIBLE LEAK"
                            } else {
                                ""
                            };
                            self.log(&format!("SEC: DNS server: {dns}{leak_warn}"));
                        }
                        self.dns_server = dns;
                    }
                    TelemetryUpdate::Ipv6Leak(leak) => {
                        if self.ipv6_leak != leak {
                            if leak {
                                self.log("SEC: ⚠ IPv6 leak detected!");
                            } else {
                                self.log("SEC: IPv6 secure (blocked)");
                            }
                        }
                        self.ipv6_leak = leak;
                    }
                    TelemetryUpdate::Log(level, msg) => {
                        // Log through central logging system
                        logger::log(level, "TELEMETRY", msg);
                    }
                }
            }
            Message::SyncSystemState(active) => {
                // Guard: While Disconnecting, the scanner must NEVER override to Connected.
                // Only two exits: (1) interface disappears -> Disconnected, or
                // (2) 30s safety timeout -> Disconnected with warning.
                // The primary path is via DisconnectResult from the background thread.
                if let ConnectionState::Disconnecting { started, profile } = &self.connection_state
                {
                    let elapsed = started.elapsed().as_secs();
                    let interface_gone = !active.iter().any(|s| &s.name == profile);

                    if interface_gone {
                        // Interface disappeared -- confirm disconnection and drain pending
                        let profile_name = profile.clone();
                        self.complete_disconnect(&profile_name);
                    } else if elapsed >= 30 {
                        // Safety timeout: VPN teardown is taking too long
                        let profile_name = profile.clone();
                        self.log(&format!(
                            "WARN: Disconnect timed out for '{profile_name}' after 30s"
                        ));
                        // Clear pending -- don't auto-connect when the previous VPN may still be running
                        self.pending_connect = None;
                        self.connection_state = ConnectionState::Disconnected;
                        self.session_start = None;
                        self.show_toast(
                            "Disconnect timed out — VPN process may still be running".to_string(),
                            ToastType::Warning,
                        );
                        self.sync_killswitch();
                    }
                    // Always return: never fall through to the general scanner logic
                    // while in Disconnecting state.
                    return;
                }

                // Debounce: Don't let scanner override Connecting back to Disconnected
                if let ConnectionState::Connecting { started, profile } = &self.connection_state {
                    if started.elapsed().as_secs() < 10 {
                        let profile_name = profile.clone();
                        if let Some(session) = active.iter().find(|s| s.name == profile_name) {
                            let location = self
                                .profiles
                                .iter()
                                .find(|p| p.name == profile_name)
                                .map_or_else(|| "Unknown".to_string(), |p| p.location.clone());

                            let start_time = session
                                .started_at
                                .and_then(|real| {
                                    std::time::SystemTime::now()
                                        .duration_since(real)
                                        .ok()
                                        .and_then(|d| Instant::now().checked_sub(d))
                                })
                                .unwrap_or_else(Instant::now);

                            self.connection_state = ConnectionState::Connected {
                                profile: profile_name.clone(),
                                server_location: location,
                                since: start_time,
                                latency_ms: 0,
                                details: Box::new(DetailedConnectionInfo {
                                    interface: session.interface.clone(),
                                    internal_ip: session.internal_ip.clone(),
                                    endpoint: session.endpoint.clone(),
                                    mtu: session.mtu.clone(),
                                    public_key: session.public_key.clone(),
                                    listen_port: session.listen_port.clone(),
                                    transfer_rx: session.transfer_rx.clone(),
                                    transfer_tx: session.transfer_tx.clone(),
                                    latest_handshake: session.latest_handshake.clone(),
                                    pid: session.pid,
                                }),
                            };

                            self.log(&format!(
                                "STATUS: Connection established to '{profile_name}'"
                            ));

                            // KILL SWITCH: Arm when VPN connects
                            if self.killswitch_mode != crate::state::KillSwitchMode::Off {
                                self.sync_killswitch();
                                self.log("SEC: Kill switch armed");
                            }

                            if let Some(profile) =
                                self.profiles.iter_mut().find(|p| p.name == profile_name)
                            {
                                profile.last_used = Some(std::time::SystemTime::now());
                            }
                            self.save_metadata();
                            self.session_start = Some(start_time);
                        }
                        return;
                    }
                }

                if let Some(session) = active.first() {
                    let active_name = session.name.clone();
                    let real_start = session.started_at;

                    if let ConnectionState::Connected {
                        profile,
                        details,
                        since,
                        ..
                    } = &mut self.connection_state
                    {
                        if profile == &active_name {
                            if let Some(real) = real_start {
                                if let Ok(duration) =
                                    std::time::SystemTime::now().duration_since(real)
                                {
                                    let calculated_start = Instant::now()
                                        .checked_sub(duration)
                                        .unwrap_or(Instant::now());
                                    if since.elapsed().as_secs().abs_diff(duration.as_secs()) > 5 {
                                        *since = calculated_start;
                                        self.session_start = Some(calculated_start);
                                    }
                                }
                            }

                            details.interface.clone_from(&session.interface);
                            details.transfer_rx.clone_from(&session.transfer_rx);
                            details.transfer_tx.clone_from(&session.transfer_tx);
                            details
                                .latest_handshake
                                .clone_from(&session.latest_handshake);
                            details.internal_ip.clone_from(&session.internal_ip);
                            details.endpoint.clone_from(&session.endpoint);
                            details.mtu.clone_from(&session.mtu);
                            details.listen_port.clone_from(&session.listen_port);
                            details.public_key.clone_from(&session.public_key);
                            return;
                        }
                    }

                    let location = self
                        .profiles
                        .iter()
                        .find(|p| p.name == active_name)
                        .map_or_else(|| "Unknown".to_string(), |p| p.location.clone());

                    let start_time = if let Some(real) = real_start {
                        if let Ok(duration) = std::time::SystemTime::now().duration_since(real) {
                            Instant::now()
                                .checked_sub(duration)
                                .unwrap_or(Instant::now())
                        } else {
                            Instant::now()
                        }
                    } else {
                        self.session_start.unwrap_or(Instant::now())
                    };

                    self.connection_state = ConnectionState::Connected {
                        profile: active_name.clone(),
                        server_location: location,
                        since: start_time,
                        latency_ms: 0,
                        details: Box::new(DetailedConnectionInfo {
                            interface: session.interface.clone(),
                            internal_ip: session.internal_ip.clone(),
                            endpoint: session.endpoint.clone(),
                            mtu: session.mtu.clone(),
                            public_key: session.public_key.clone(),
                            listen_port: session.listen_port.clone(),
                            transfer_rx: session.transfer_rx.clone(),
                            transfer_tx: session.transfer_tx.clone(),
                            latest_handshake: session.latest_handshake.clone(),
                            pid: session.pid,
                        }),
                    };

                    if self.session_start.is_none() {
                        self.log(&format!(
                            "STATUS: Connection established to '{active_name}'"
                        ));
                        if real_start.is_some() {
                            self.log("INFO: Synced uptime with system process.");
                        }
                        self.log("INFO: Waiting for telemetry...");
                    }
                    self.session_start = Some(start_time);
                } else if !matches!(self.connection_state, ConnectionState::Disconnected) {
                    // Extract data we need before mutating self
                    let drop_info = match &self.connection_state {
                        ConnectionState::Connected {
                            profile, details, ..
                        } => Some((
                            profile.clone(),
                            details.interface.clone(),
                            details.endpoint.split(':').next().unwrap_or("").to_string(),
                        )),
                        ConnectionState::Disconnecting { profile, .. }
                        | ConnectionState::Connecting { profile, .. } => {
                            Some((profile.clone(), String::new(), String::new()))
                        }
                        ConnectionState::Disconnected => None,
                    };

                    if let Some((profile_name, _, _)) = drop_info {
                        // Check if this was an unexpected drop from Connected state
                        let was_connected =
                            matches!(self.connection_state, ConnectionState::Connected { .. });

                        if was_connected {
                            self.connection_drops += 1;
                            self.log(&format!(
                                "STATUS: Connection dropped from '{}' (#{} this session)",
                                profile_name, self.connection_drops
                            ));

                            // KILL SWITCH: Activate on unexpected VPN drop
                            if self.killswitch_mode != crate::state::KillSwitchMode::Off
                                && self.killswitch_state == crate::state::KillSwitchState::Armed
                            {
                                // Mark as blocking first, so sync_killswitch knows what to do
                                self.killswitch_state = crate::state::KillSwitchState::Blocking;

                                // We keep the manual call here if we need specific interface/server_ip
                                // but sync_killswitch normally handles DEFAULT_VPN_INTERFACE.
                                // Actually, sync_killswitch is safer if it uses the interface that just dropped.
                                // But if it just dropped, it's likely DEFAULT_VPN_INTERFACE.

                                self.sync_killswitch();

                                self.log("SEC: Kill switch ACTIVATED - blocking traffic");
                                self.show_toast(
                                    "VPN dropped! Kill Switch blocking traffic".to_string(),
                                    ToastType::Error,
                                );
                            }
                        } else if matches!(
                            self.connection_state,
                            ConnectionState::Disconnecting { .. }
                        ) {
                            self.log(&format!("STATUS: Disconnected from '{profile_name}'"));
                        } else if matches!(
                            self.connection_state,
                            ConnectionState::Connecting { .. }
                        ) {
                            self.log(&format!(
                                "STATUS: Connection to '{profile_name}' failed or cancelled"
                            ));
                        }
                    }
                    self.connection_state = ConnectionState::Disconnected;
                    self.session_start = None;
                }
            }
            Message::ConnectionTimeout(profile_name) => {
                self.connection_state = ConnectionState::Disconnected;
                self.log(&format!("ERR: Connection timed out for '{profile_name}'"));
            }
            Message::NetworkStatsUpdate(down, up) => {
                self.current_down = down;
                self.current_up = up;
            }
            Message::Tick => {
                // 1. Connection Timeout Safeguard
                if let ConnectionState::Connecting { started, profile } = &self.connection_state {
                    if started.elapsed() > std::time::Duration::from_secs(30) {
                        let p = profile.clone();
                        self.handle_message(Message::ConnectionTimeout(p));
                    }
                }
                // 2. Expire toast
                if let Some(toast) = &self.toast {
                    if toast.is_expired() {
                        self.toast = None;
                    }
                }
                // 3. Process telemetry and background results (non-blocking)
                self.process_telemetry();

                // 4. Update network stats history
                for i in 0..59 {
                    self.down_history[i].1 = self.down_history[i + 1].1;
                    self.up_history[i].1 = self.up_history[i + 1].1;
                }
                #[allow(clippy::cast_precision_loss)]
                {
                    self.down_history[59].1 = self.current_down as f64;
                    self.up_history[59].1 = self.current_up as f64;
                }
            }
            Message::Resize(width, height) => {
                self.terminal_size = (width, height);
            }
        }
    }

    /// Check if a specific panel should be drawn as focused (visually)
    pub fn should_draw_focus(&self, panel: &FocusedPanel) -> bool {
        // If an overlay is active, no background panel has focus
        if self.show_config
            || self.show_action_menu
            || self.show_bulk_menu
            || self.input_mode != InputMode::Normal
        {
            return false;
        }
        // If Zoom is active, ONLY the zoomed panel has focus
        if let Some(zoomed) = &self.zoomed_panel {
            return *zoomed == *panel;
        }
        // Otherwise, standard focus
        self.focused_panel == *panel
    }

    /// Get the maximum scroll position for the config viewer
    /// This accounts for viewport height so scrolling stops when last line is visible
    fn get_config_max_scroll(&self) -> u16 {
        if let Some(idx) = self.profile_list_state.selected() {
            if let Some(profile) = self.profiles.get(idx) {
                if let Ok(content) = std::fs::read_to_string(&profile.config_path) {
                    #[allow(clippy::cast_possible_truncation)]
                    let total_lines = content.lines().count() as u16;
                    // Viewport height: 85% of terminal height - 4 (borders + path line + title bottom)
                    let viewport_height = (self.terminal_size.1 * 85 / 100).saturating_sub(4);
                    return total_lines.saturating_sub(viewport_height);
                }
            }
        }
        0
    }

    fn profile_next(&mut self) {
        let i = match self.profile_list_state.selected() {
            Some(i) => {
                if i >= self.profiles.len().saturating_sub(1) {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.profile_list_state.select(Some(i));
    }

    fn profile_previous(&mut self) {
        let i = match self.profile_list_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.profiles.len().saturating_sub(1)
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.profile_list_state.select(Some(i));
    }

    /// Request deletion of a profile (Safety Check)
    fn request_delete(&mut self, idx: usize) {
        if let Some(profile) = self.profiles.get(idx) {
            // 1. Prevent deleting connected profile
            if let ConnectionState::Connected {
                profile: connected_name,
                ..
            } = &self.connection_state
            {
                if &profile.name == connected_name {
                    self.show_toast(
                        "Cannot delete active profile".to_string(),
                        ToastType::Warning,
                    );
                    return;
                }
            }

            // 2. Switch to confirm mode
            self.input_mode = InputMode::ConfirmDelete {
                index: idx,
                name: profile.name.clone(),
                confirm_selected: false, // Default to "No" for safety
            };
        }
    }

    /// Execute deletion after confirmation
    fn confirm_delete(&mut self, idx: usize) {
        if idx >= self.profiles.len() {
            return;
        }

        // Get profile info before removing
        let config_path = self.profiles[idx].config_path.clone();
        let profile_name = self.profiles[idx].name.clone();
        let protocol = self.profiles[idx].protocol;

        // Remove from profiles
        self.profiles.remove(idx);
        self.sync_shared_profiles();

        // Try to delete from disk
        if config_path.exists() {
            let _ = std::fs::remove_file(&config_path);
        }

        // Clean up OpenVPN auth and runtime files
        if matches!(protocol, Protocol::OpenVPN) {
            utils::delete_openvpn_auth_file(&profile_name);
            utils::cleanup_openvpn_run_files(&profile_name);
        }

        // Adjust selection
        if self.profiles.is_empty() {
            self.profile_list_state.select(None);
        } else if let Some(selected) = self.profile_list_state.selected() {
            if selected >= self.profiles.len() {
                self.profile_list_state
                    .select(Some(self.profiles.len() - 1));
            }
        }

        self.show_toast("Profile deleted".to_string(), ToastType::Success);
        self.input_mode = InputMode::Normal;
    }

    fn load_metadata(&mut self) {
        if let Ok(metadata) = utils::load_profile_metadata() {
            for profile in &mut self.profiles {
                let key = profile.config_path.to_string_lossy().to_string();
                if let Some(meta) = metadata.get(&key) {
                    profile.last_used = meta.last_used;
                }
            }
        }
    }

    fn save_metadata(&self) {
        use std::collections::HashMap;

        let mut metadata = HashMap::new();
        for profile in &self.profiles {
            let key = profile.config_path.to_string_lossy().to_string();
            metadata.insert(
                key,
                utils::ProfileMetadata {
                    last_used: profile.last_used,
                },
            );
        }

        let _ = utils::save_profile_metadata(&metadata);
    }

    /// Sort profiles alphabetically by name, updating quick slots
    fn sort_profiles(&mut self) {
        self.profiles.sort_by(|a, b| a.name.cmp(&b.name));

        // Update quick slots logic removed - key `1` now maps to index `0` dynamically
    }

    /// Smart connection toggle: Connect, Disconnect, or Switch.
    ///
    /// Uses `pending_connect` to queue a connection that fires automatically
    /// after the current disconnect completes, avoiding the race condition
    /// of starting connect while disconnect is still in-flight.
    fn toggle_connection(&mut self, idx: usize) {
        if let Some(target_profile) = self.profiles.get(idx) {
            let target_name = target_profile.name.clone();
            match &self.connection_state {
                // If connecting, ignore to prevent races
                ConnectionState::Connecting { .. } => {}
                // If disconnecting, queue the connection for after disconnect completes
                ConnectionState::Disconnecting { .. } => {
                    self.pending_connect = Some(idx);
                }
                // If connected...
                ConnectionState::Connected {
                    profile: current_name,
                    ..
                } => {
                    if *current_name == target_name {
                        // Same profile -> Disconnect (toggle off)
                        self.pending_connect = None;
                        self.disconnect();
                    } else {
                        // Different profile -> Queue switch: disconnect first, connect after
                        self.pending_connect = Some(idx);
                        self.disconnect();
                    }
                }
                // If disconnected -> Connect immediately
                ConnectionState::Disconnected => {
                    self.connect_profile(idx);
                }
            }
        }
    }

    /// Check if required binaries are available for a given protocol
    fn check_dependencies(protocol: Protocol) -> Vec<String> {
        let mut missing = Vec::new();
        match protocol {
            Protocol::WireGuard => {
                if std::process::Command::new("wg-quick")
                    .arg("--version")
                    .output()
                    .is_err()
                {
                    missing.push("wg-quick".to_string());
                }
                if std::process::Command::new("wg")
                    .arg("--version")
                    .output()
                    .is_err()
                {
                    missing.push("wireguard-tools".to_string());
                }
            }
            Protocol::OpenVPN => {
                if std::process::Command::new("openvpn")
                    .arg("--version")
                    .output()
                    .is_err()
                {
                    missing.push("openvpn".to_string());
                }
            }
        }
        missing
    }

    /// Connect to a profile
    #[allow(clippy::too_many_lines)]
    fn connect_profile(&mut self, idx: usize) {
        // Clone needed data to release borrow on self
        let (name, protocol, config_path, cmd_tx) = if let Some(profile) = self.profiles.get(idx) {
            (
                profile.name.clone(),
                profile.protocol,
                profile.config_path.clone(),
                self.cmd_tx.clone(),
            )
        } else {
            return;
        };

        // Check dependencies FIRST (no point asking for root if tool is missing)
        let missing = Self::check_dependencies(protocol);
        if !missing.is_empty() {
            self.input_mode = InputMode::DependencyError { protocol, missing };
            return;
        }

        // Check root second
        if !self.is_root {
            self.input_mode = InputMode::PermissionDenied {
                action: format!("Manage {protocol}"),
            };
            return;
        }

        // Check if OpenVPN config needs auth credentials
        if matches!(protocol, Protocol::OpenVPN) && utils::openvpn_config_needs_auth(&config_path) {
            // Check for saved credentials first
            if utils::read_openvpn_saved_auth(&name).is_none() {
                // No saved creds -- show the auth prompt overlay
                self.input_mode = InputMode::AuthPrompt {
                    profile_idx: idx,
                    profile_name: name,
                    username: String::new(),
                    username_cursor: 0,
                    password: String::new(),
                    password_cursor: 0,
                    focused_field: crate::state::AuthField::Username,
                    save_credentials: true,
                    connect_after: true,
                };
                return;
            }
            // Saved creds exist -- they'll be picked up in the thread below
        }

        // Start connecting
        self.connection_state = ConnectionState::Connecting {
            started: Instant::now(),
            profile: name.clone(),
        };
        self.log(&format!("ACTION: Connecting to '{name}' [{protocol}]..."));

        let connect_timeout_secs = self.config.connect_timeout;

        // Execute command in background to prevent TUI freeze
        std::thread::spawn(move || match protocol {
            Protocol::WireGuard => {
                // wg-quick is a one-shot command: sets up interface and exits
                match std::process::Command::new("wg-quick")
                    .args(["up", config_path.to_str().unwrap_or("")])
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .output()
                {
                    Ok(out) if out.status.success() => {
                        let _ = cmd_tx.send(Message::ConnectResult {
                            profile: name,
                            success: true,
                            error: None,
                        });
                    }
                    Ok(out) => {
                        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                        let _ = cmd_tx.send(Message::ConnectResult {
                            profile: name,
                            success: false,
                            error: Some(format!("WireGuard: {stderr}")),
                        });
                    }
                    Err(e) => {
                        let _ = cmd_tx.send(Message::ConnectResult {
                            profile: name,
                            success: false,
                            error: Some(format!("Failed to execute wg-quick: {e}")),
                        });
                    }
                }
            }
            Protocol::OpenVPN => {
                // OpenVPN is designed to run as a daemon. We use --daemon with
                // --writepid and --log so we can track the process and poll the
                // log for definitive success/failure markers.
                let run_paths = crate::utils::get_openvpn_run_paths(&name);
                let (pid_path, log_path) = match run_paths {
                    Ok(paths) => paths,
                    Err(e) => {
                        let _ = cmd_tx.send(Message::ConnectResult {
                            profile: name,
                            success: false,
                            error: Some(format!("Failed to create run directory: {e}")),
                        });
                        return;
                    }
                };

                // Clean up stale files from previous runs
                let _ = std::fs::remove_file(&pid_path);
                let _ = std::fs::remove_file(&log_path);

                // Build openvpn args
                let mut args = vec![
                    "--config".to_string(),
                    config_path.to_str().unwrap_or("").to_string(),
                    "--daemon".to_string(),
                    format!("vortix-{name}"),
                    "--writepid".to_string(),
                    pid_path.to_str().unwrap_or("").to_string(),
                    "--log".to_string(),
                    log_path.to_str().unwrap_or("").to_string(),
                    "--verb".to_string(),
                    "3".to_string(),
                ];

                // If auth credentials exist, pass them via --auth-user-pass
                if let Ok(auth_path) = crate::utils::get_openvpn_auth_path(&name) {
                    if auth_path.exists() {
                        args.push("--auth-user-pass".to_string());
                        args.push(auth_path.to_str().unwrap_or("").to_string());
                    }
                }

                let output = std::process::Command::new("openvpn")
                    .args(&args)
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .output();

                // --daemon: parent forks and exits. A non-zero exit here means
                // the config failed basic validation before the fork.
                match output {
                    Ok(out) if !out.status.success() => {
                        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                        let _ = cmd_tx.send(Message::ConnectResult {
                            profile: name,
                            success: false,
                            error: Some(format!("OpenVPN: {}", stderr.trim())),
                        });
                        return;
                    }
                    Err(e) => {
                        let _ = cmd_tx.send(Message::ConnectResult {
                            profile: name,
                            success: false,
                            error: Some(format!("Failed to start OpenVPN: {e}")),
                        });
                        return;
                    }
                    Ok(_) => {} // Fork succeeded, daemon is running
                }

                // Chown the run files so normal users can read PID/log status.
                // OpenVPN creates them as root; we fix ownership after a brief
                // delay to let the daemon write them.
                std::thread::sleep(std::time::Duration::from_millis(200));
                crate::config::fix_ownership(
                    pid_path.parent().unwrap_or(std::path::Path::new("/")),
                );

                // Poll the log file for definitive success/failure from the daemon.
                let timeout = std::time::Duration::from_secs(connect_timeout_secs);
                let poll_interval = std::time::Duration::from_millis(constants::OVPN_LOG_POLL_MS);
                let start = std::time::Instant::now();

                loop {
                    std::thread::sleep(poll_interval);

                    // Check if the daemon died (pid file gone or process not running)
                    if start.elapsed() > std::time::Duration::from_secs(2) {
                        if let Ok(content) = std::fs::read_to_string(&pid_path) {
                            if let Ok(pid) = content.trim().parse::<u32>() {
                                // Check if process is still alive
                                let alive = std::process::Command::new("kill")
                                    .args(["-0", &pid.to_string()])
                                    .output()
                                    .is_ok_and(|o| o.status.success());
                                if !alive {
                                    // Daemon died -- read log for the reason
                                    let log =
                                        std::fs::read_to_string(&log_path).unwrap_or_default();
                                    let last_lines: String = log
                                        .lines()
                                        .rev()
                                        .take(5)
                                        .collect::<Vec<_>>()
                                        .into_iter()
                                        .rev()
                                        .collect::<Vec<_>>()
                                        .join("\n");
                                    let _ = cmd_tx.send(Message::ConnectResult {
                                        profile: name,
                                        success: false,
                                        error: Some(format!(
                                            "OpenVPN daemon exited:\n{last_lines}"
                                        )),
                                    });
                                    return;
                                }
                            }
                        } else if start.elapsed() > std::time::Duration::from_secs(3) {
                            // No pid file after 3s -- daemon likely failed to start
                            let log = std::fs::read_to_string(&log_path)
                                .unwrap_or_else(|_| "No log output".to_string());
                            let _ = cmd_tx.send(Message::ConnectResult {
                                profile: name,
                                success: false,
                                error: Some(format!("OpenVPN: no PID file. Log:\n{log}")),
                            });
                            return;
                        }
                    }

                    // Read the log file and check for markers
                    if let Ok(log_content) = std::fs::read_to_string(&log_path) {
                        // Success marker
                        if log_content.contains(constants::OVPN_LOG_SUCCESS) {
                            let _ = cmd_tx.send(Message::ConnectResult {
                                profile: name,
                                success: true,
                                error: None,
                            });
                            return;
                        }

                        // Error markers
                        for pattern in constants::OVPN_LOG_ERRORS {
                            if log_content.contains(pattern) {
                                // Extract the line containing the error for context
                                let error_line = log_content
                                    .lines()
                                    .find(|l| l.contains(pattern))
                                    .unwrap_or(pattern);
                                let _ = cmd_tx.send(Message::ConnectResult {
                                    profile: name,
                                    success: false,
                                    error: Some(format!("OpenVPN: {error_line}")),
                                });
                                return;
                            }
                        }
                    }

                    // Timeout -- let the scanner take over
                    if start.elapsed() >= timeout {
                        let _ = cmd_tx.send(Message::ConnectResult {
                            profile: name.clone(),
                            success: true,
                            error: None,
                        });
                        let _ = cmd_tx.send(Message::Log(format!(
                            "WARN: OpenVPN log confirmation timed out for '{name}' \
                             after {connect_timeout_secs}s — scanner will confirm tunnel status"
                        )));
                        return;
                    }
                }
            }
        });
    }

    /// DISCONNECT from VPN
    /// Synchronizes the kill switch state with the current mode and connection status.
    /// This is the single source of truth for kill switch state transitions and firewall control.
    fn sync_killswitch(&mut self) {
        use crate::state::{KillSwitchMode, KillSwitchState};

        let old_state = self.killswitch_state;

        // 1. Determine the target state
        self.killswitch_state = match self.killswitch_mode {
            KillSwitchMode::Off => KillSwitchState::Disabled,
            KillSwitchMode::Auto => {
                if matches!(self.connection_state, ConnectionState::Connected { .. }) {
                    KillSwitchState::Armed
                } else if old_state == KillSwitchState::Blocking {
                    // Stay blocking if we were already blocking in Auto mode
                    KillSwitchState::Blocking
                } else {
                    KillSwitchState::Armed // Show intent even if disconnected
                }
            }
            KillSwitchMode::AlwaysOn => {
                if matches!(self.connection_state, ConnectionState::Connected { .. }) {
                    KillSwitchState::Armed
                } else {
                    KillSwitchState::Blocking
                }
            }
        };

        // 2. Sync physical firewall state if target state changed or if forcing sync
        if self.killswitch_state != old_state || self.killswitch_state == KillSwitchState::Blocking
        {
            if self.killswitch_state.is_blocking() {
                // Determine VPN interface and server IP if connected
                let (interface, server_ip) = match &self.connection_state {
                    ConnectionState::Connected { details, .. } => (
                        details.interface.as_str(),
                        Some(details.endpoint.split(':').next().unwrap_or("")),
                    ),
                    _ => (crate::platform::DEFAULT_VPN_INTERFACE, None),
                };

                if self.is_root {
                    if let Err(e) = crate::core::killswitch::enable_blocking(interface, server_ip) {
                        self.log(&format!("WARN: Failed to enable kill switch: {e}"));
                    }
                }
            } else if old_state.is_blocking() {
                // Target is not blocking, but we were blocking - release
                if let Err(e) = crate::core::killswitch::disable_blocking() {
                    self.log(&format!("WARN: Failed to release kill switch: {e}"));
                }
            }
        }

        // 3. Persist state
        let _ = crate::core::killswitch::save_state(
            self.killswitch_mode,
            self.killswitch_state,
            None,
            None,
        );
    }

    /// Finalize a disconnect: transition to `Disconnected`, sync kill switch,
    /// and drain `pending_connect` (auto-connect to the queued profile, if any).
    fn complete_disconnect(&mut self, profile_name: &str) {
        self.log(&format!("STATUS: Disconnected from '{profile_name}'"));
        self.connection_state = ConnectionState::Disconnected;
        self.session_start = None;
        self.sync_killswitch();

        // Clean up OpenVPN runtime files if this was an OpenVPN profile
        if self
            .profiles
            .iter()
            .any(|p| p.name == profile_name && matches!(p.protocol, Protocol::OpenVPN))
        {
            crate::utils::cleanup_openvpn_run_files(profile_name);
        }

        // Drain pending_connect: auto-connect to the queued profile
        if let Some(idx) = self.pending_connect.take() {
            if idx < self.profiles.len() {
                let next_name = self.profiles[idx].name.clone();
                self.log(&format!(
                    "ACTION: Auto-connecting to queued profile '{next_name}'"
                ));
                self.connect_profile(idx);
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn disconnect(&mut self) {
        // Extract connection info from Connected or Connecting state
        let connection_info = match &self.connection_state {
            ConnectionState::Connected {
                profile: ref profile_name,
                details,
                ..
            } => self
                .profiles
                .iter()
                .find(|p| p.name == *profile_name)
                .map(|profile| {
                    (
                        profile.name.clone(),
                        profile.protocol,
                        profile.config_path.clone(),
                        details.pid,
                        self.cmd_tx.clone(),
                    )
                }),
            ConnectionState::Connecting {
                profile: ref profile_name,
                ..
            } => self
                .profiles
                .iter()
                .find(|p| p.name == *profile_name)
                .map(|profile| {
                    (
                        profile.name.clone(),
                        profile.protocol,
                        profile.config_path.clone(),
                        None, // no PID yet while connecting
                        self.cmd_tx.clone(),
                    )
                }),
            _ => None,
        };

        if let Some((profile_name, protocol, config_path, pid, cmd_tx)) = connection_info {
            self.log(&format!("ACTION: Disconnecting from '{profile_name}'..."));

            // Set disconnecting state
            self.connection_state = ConnectionState::Disconnecting {
                started: Instant::now(),
                profile: profile_name.clone(),
            };

            // KILL SWITCH: Sync state after changing connection state
            self.sync_killswitch();

            if self.killswitch_state.is_blocking() {
                self.show_toast(
                    "Kill Switch blocking - Strict mode active".to_string(),
                    ToastType::Warning,
                );
            }

            std::thread::spawn(move || {
                let output = match protocol {
                    Protocol::WireGuard => std::process::Command::new("wg-quick")
                        .args(["down", config_path.to_str().unwrap_or("")])
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .output(),
                    Protocol::OpenVPN => {
                        // Try PID file first (most reliable), then scanner PID, then pkill
                        let target_pid = crate::utils::read_openvpn_pid(&profile_name).or(pid);
                        if let Some(p) = target_pid {
                            std::process::Command::new("kill")
                                .arg(p.to_string())
                                .stdout(std::process::Stdio::piped())
                                .stderr(std::process::Stdio::piped())
                                .output()
                        } else {
                            std::process::Command::new("pkill")
                                .arg("openvpn")
                                .stdout(std::process::Stdio::piped())
                                .stderr(std::process::Stdio::piped())
                                .output()
                        }
                    }
                };

                match output {
                    Ok(out) if out.status.success() => {
                        // Clean up OpenVPN runtime files
                        if matches!(protocol, Protocol::OpenVPN) {
                            crate::utils::cleanup_openvpn_run_files(&profile_name);
                        }
                        let _ = cmd_tx.send(Message::DisconnectResult {
                            profile: profile_name,
                            success: true,
                            error: None,
                        });
                    }
                    Ok(out) => {
                        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                        let _ = cmd_tx.send(Message::DisconnectResult {
                            profile: profile_name,
                            success: false,
                            error: Some(format!("{protocol}: {stderr}")),
                        });
                    }
                    Err(e) => {
                        let _ = cmd_tx.send(Message::DisconnectResult {
                            profile: profile_name,
                            success: false,
                            error: Some(format!("Failed to execute: {e}")),
                        });
                    }
                }
            });
        }
    }

    /// Force-disconnect: escalates a stuck disconnect.
    ///
    /// For `OpenVPN`, sends SIGKILL instead of SIGTERM.
    /// For `WireGuard`, retries `wg-quick down`.
    fn force_disconnect(&mut self) {
        let profile_name =
            if let ConnectionState::Disconnecting { profile, .. } = &self.connection_state {
                profile.clone()
            } else {
                return;
            };

        // Look up protocol and config from the profile
        let force_info = self
            .profiles
            .iter()
            .find(|p| p.name == profile_name)
            .map(|profile| {
                (
                    profile.name.clone(),
                    profile.protocol,
                    profile.config_path.clone(),
                    self.cmd_tx.clone(),
                )
            });

        if let Some((name, protocol, config_path, cmd_tx)) = force_info {
            self.log(&format!("ACTION: Force-disconnecting '{name}'..."));
            self.show_toast(
                format!("Force-disconnecting '{name}'..."),
                ToastType::Warning,
            );

            // Reset the Disconnecting timer so the 30s safety timeout starts fresh
            self.connection_state = ConnectionState::Disconnecting {
                started: Instant::now(),
                profile: name.clone(),
            };

            std::thread::spawn(move || {
                let output = match protocol {
                    Protocol::WireGuard => {
                        // Retry wg-quick down
                        std::process::Command::new("wg-quick")
                            .args(["down", config_path.to_str().unwrap_or("")])
                            .stdout(std::process::Stdio::piped())
                            .stderr(std::process::Stdio::piped())
                            .output()
                    }
                    Protocol::OpenVPN => {
                        // Escalate to SIGKILL: try PID file first, then pkill -9
                        let target_pid = crate::utils::read_openvpn_pid(&name);
                        if let Some(p) = target_pid {
                            std::process::Command::new("kill")
                                .args(["-9", &p.to_string()])
                                .stdout(std::process::Stdio::piped())
                                .stderr(std::process::Stdio::piped())
                                .output()
                        } else {
                            std::process::Command::new("pkill")
                                .args(["-9", "openvpn"])
                                .stdout(std::process::Stdio::piped())
                                .stderr(std::process::Stdio::piped())
                                .output()
                        }
                    }
                };

                match output {
                    Ok(out) if out.status.success() => {
                        if matches!(protocol, Protocol::OpenVPN) {
                            crate::utils::cleanup_openvpn_run_files(&name);
                        }
                        let _ = cmd_tx.send(Message::DisconnectResult {
                            profile: name,
                            success: true,
                            error: None,
                        });
                    }
                    Ok(out) => {
                        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                        let _ = cmd_tx.send(Message::DisconnectResult {
                            profile: name,
                            success: false,
                            error: Some(format!("Force {protocol}: {stderr}")),
                        });
                    }
                    Err(e) => {
                        let _ = cmd_tx.send(Message::DisconnectResult {
                            profile: name,
                            success: false,
                            error: Some(format!("Force-kill failed: {e}")),
                        });
                    }
                }
            });
        }
    }

    /// Reconnect to VPN: queues the same profile for auto-connect after disconnect.
    fn reconnect(&mut self) {
        if let ConnectionState::Connected { profile, .. } = &self.connection_state {
            let profile_name = profile.clone();
            if let Some(idx) = self.profiles.iter().position(|p| p.name == profile_name) {
                self.pending_connect = Some(idx);
                self.disconnect();
            }
        }
    }

    /// Show a toast notification and log it
    fn show_toast(&mut self, message: String, toast_type: ToastType) {
        self.log(&message);
        self.toast = Some(Toast {
            message,
            toast_type,
            expires: Instant::now() + DISMISS_DURATION,
        });
    }

    /// Copy public IP address to clipboard
    fn copy_ip_to_clipboard(&mut self) {
        let ip_str = self.public_ip.clone();
        if ip_str.is_empty() || ip_str == constants::MSG_FETCHING || ip_str.starts_with("Error") {
            self.show_toast("No valid IP available yet".to_string(), ToastType::Error);
            return;
        }
        #[cfg(target_os = "macos")]
        {
            use std::io::Write;
            if let Ok(mut child) = std::process::Command::new("pbcopy")
                .stdin(std::process::Stdio::piped())
                .spawn()
            {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(ip_str.as_bytes());
                }
                let _ = child.wait();
                self.show_toast(format!("Copied IP: {ip_str}"), ToastType::Success);
                return;
            }
        }
        #[cfg(target_os = "linux")]
        {
            use std::io::Write;
            // Try xclip first, then xsel
            for cmd in &["xclip", "xsel"] {
                let args: &[&str] = if *cmd == "xclip" {
                    &["-selection", "clipboard"]
                } else {
                    &["--clipboard", "--input"]
                };
                if let Ok(mut child) = std::process::Command::new(cmd)
                    .args(args)
                    .stdin(std::process::Stdio::piped())
                    .spawn()
                {
                    if let Some(mut stdin) = child.stdin.take() {
                        let _ = stdin.write_all(ip_str.as_bytes());
                    }
                    let _ = child.wait();
                    self.show_toast(format!("Copied IP: {ip_str}"), ToastType::Success);
                    return;
                }
            }
        }
        #[allow(unreachable_code)]
        self.show_toast("Failed to copy to clipboard".to_string(), ToastType::Error);
    }

    /// Append log entry to file with automatic rotation
    fn append_to_log_file(entry: &str, config_dir: &std::path::Path) {
        static CLEANUP_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        use std::io::Write;

        let log_dir = config_dir.join(constants::LOGS_DIR_NAME);

        // Create log directory if needed
        if crate::utils::create_user_dir(&log_dir).is_err() {
            return;
        }

        // Use date-based log file (get date from system)
        let today = std::process::Command::new("date")
            .arg("+%Y-%m-%d")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map_or_else(|| "unknown".to_string(), |s| s.trim().to_string());

        let log_file = log_dir.join(format!("vortix-{today}.log"));

        // Check file size and rotate if > 5MB
        if let Ok(metadata) = std::fs::metadata(&log_file) {
            if metadata.len() > 5 * 1024 * 1024 {
                // Rotate: rename to .1 and start fresh
                let rotated = log_dir.join(format!("vortix-{today}.1.log"));
                let _ = std::fs::rename(&log_file, rotated);
            }
        }

        // Append to log file
        let is_new_log = !log_file.exists();
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
        {
            let _ = writeln!(file, "{entry}");
            if is_new_log {
                crate::config::fix_ownership(&log_file);
            }
        }

        // Clean up old logs (keep last 7 days) - run occasionally
        let count = CLEANUP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count % 100 == 0 {
            Self::cleanup_old_logs(&log_dir);
        }
    }

    /// Remove log files older than 7 days
    fn cleanup_old_logs(log_dir: &Path) {
        use std::time::{Duration, SystemTime};

        let seven_days = Duration::from_secs(7 * 24 * 60 * 60);
        let cutoff = SystemTime::now()
            .checked_sub(seven_days)
            .unwrap_or(SystemTime::UNIX_EPOCH);

        if let Ok(entries) = std::fs::read_dir(log_dir) {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    if let Ok(modified) = metadata.modified() {
                        if modified < cutoff {
                            let _ = std::fs::remove_file(entry.path());
                        }
                    }
                }
            }
        }
    }

    /// Periodic tick from the event loop.
    pub fn on_tick(&mut self) {
        self.handle_message(Message::Tick);
    }

    /// Processes pending telemetry updates from the background worker.
    /// Called frequently to ensure logs appear immediately.
    fn process_telemetry(&mut self) {
        use crate::message::Message;

        // Collect all pending updates first to avoid borrow issues
        let updates: Vec<_> = if let Some(rx) = &self.telemetry_rx {
            rx.try_iter().collect()
        } else {
            return;
        };

        for update in updates {
            self.handle_message(Message::Telemetry(update));
        }
    }

    /// Process all pending external events (telemetry and background commands).
    /// Called by main loop to ensure background feedback appears immediately.
    pub fn process_external(&mut self) {
        // 1. Process Telemetry
        self.process_telemetry();

        // 2. Process Command Feedback
        while let Ok(msg) = self.cmd_rx.try_recv() {
            self.handle_message(msg);
        }
    }

    /// Push the current profile list to the background scanner thread.
    fn sync_shared_profiles(&self) {
        if let Ok(mut shared) = self.shared_profiles.lock() {
            shared.clone_from(&self.profiles);
        }
    }

    /// Called when terminal is resized
    /// Handle terminal resize.
    /// In TEA, this dispatches a Resize message.
    pub fn on_resize(&mut self, width: u16, height: u16) {
        self.handle_message(Message::Resize(width, height));
    }

    /// Import a profile from a file path or bulk import from directory
    fn import_profile_from_path(&mut self, path_str: &str) {
        use crate::core::importer::{resolve_target, ImportTarget};

        match resolve_target(path_str) {
            Ok(ImportTarget::Url(url)) => {
                let tx = self.cmd_tx.clone();
                self.show_toast(constants::MSG_DOWNLOADING.to_string(), ToastType::Info);

                std::thread::spawn(
                    move || match crate::core::downloader::download_profile(&url) {
                        Ok(path) => {
                            let path_string = path.to_string_lossy().to_string();
                            let _ = tx.send(Message::Import(path_string));
                        }
                        Err(e) => {
                            let _ = tx.send(Message::Toast(
                                format!("{}{}", constants::MSG_DOWNLOAD_FAILED, e),
                                ToastType::Error,
                            ));
                        }
                    },
                );
            }
            Ok(ImportTarget::File(path)) => {
                self.import_single_file(&path);
            }
            Ok(ImportTarget::Directory(path)) => {
                self.import_from_directory(&path);
            }
            Err(e) => {
                self.show_toast(e, ToastType::Error);
            }
        }

        self.sort_profiles();
    }

    /// Import a single VPN profile file
    fn import_single_file(&mut self, path: &Path) {
        match crate::vpn::import_profile(path) {
            Ok(profile) => {
                let name = profile.name.clone();
                self.profiles.push(profile);
                self.sync_shared_profiles();

                self.show_toast(
                    format!("{}{}", constants::MSG_IMPORT_SUCCESS, name),
                    ToastType::Success,
                );
            }
            Err(e) => {
                self.show_toast(
                    format!("{}{}", constants::MSG_IMPORT_ERROR, e),
                    ToastType::Error,
                );
            }
        }
    }

    /// Bulk import all .conf and .ovpn files from a directory
    fn import_from_directory(&mut self, dir_path: &Path) {
        let mut imported = 0;
        let mut failed = 0;

        match std::fs::read_dir(dir_path) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();

                    // Only process .conf and .ovpn files
                    if path.is_file()
                        && path
                            .extension()
                            .is_some_and(|ext| ext == "conf" || ext == "ovpn")
                    {
                        match crate::vpn::import_profile(&path) {
                            Ok(profile) => {
                                self.profiles.push(profile);

                                imported += 1;
                            }
                            Err(e) => {
                                self.log(&format!(
                                    "IMPORT: Failed to import {}: {}",
                                    path.display(),
                                    e
                                ));
                                failed += 1;
                            }
                        }
                    }
                }

                if imported > 0 {
                    self.sync_shared_profiles();
                }

                // Show summary feedback
                if imported > 0 {
                    let msg = if failed > 0 {
                        format!("Imported {imported} profile(s), {failed} failed")
                    } else {
                        format!(
                            "{}{}{}",
                            constants::MSG_BATCH_IMPORTED,
                            imported,
                            constants::MSG_BATCH_IMPORTED_SUFFIX
                        )
                    };
                    // Use Warning if significant failures, but Success is generally appropriate to confirm the action
                    let t_type = if failed > imported {
                        ToastType::Warning
                    } else {
                        ToastType::Success
                    };
                    self.show_toast(msg.clone(), t_type);

                    self.log(&format!(
                        "IMPORT: Batch imported {imported} profiles from {}",
                        dir_path.display()
                    ));
                } else if failed > 0 {
                    // Files found but all failed
                    self.show_toast(
                        format!("Failed to import {failed} profiles"),
                        ToastType::Error,
                    );
                } else {
                    // Truly no files found
                    self.show_toast(
                        constants::MSG_NO_FILES_FOUND.to_string(),
                        ToastType::Warning,
                    );
                }
            }
            Err(e) => {
                self.log(&format!("IMPORT: Error reading directory: {e}"));
                self.show_toast(format!("Error reading directory: {e}"), ToastType::Error);
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scanner::ActiveSession;

    /// Build a minimal `App` for unit testing (no filesystem / scanner / telemetry).
    fn test_app() -> App {
        let (cmd_tx, cmd_rx) = mpsc::channel::<Message>();
        App {
            should_quit: false,
            connection_state: ConnectionState::Disconnected,
            profiles: Vec::new(),
            session_start: None,
            down_history: vec![(0.0, 0.0)],
            up_history: vec![(0.0, 0.0)],
            current_down: 0,
            current_up: 0,
            latency_ms: 0,
            packet_loss: 0.0,
            jitter_ms: 0,
            location: String::new(),
            isp: String::new(),
            dns_server: String::new(),
            ipv6_leak: false,
            public_ip: String::new(),
            real_ip: None,
            logs_scroll: 0,
            logs_auto_scroll: true,
            focused_panel: FocusedPanel::Sidebar,
            zoomed_panel: None,
            input_mode: InputMode::Normal,
            show_config: false,
            show_action_menu: false,
            show_bulk_menu: false,
            action_menu_state: ratatui::widgets::ListState::default(),
            config_scroll: 0,
            profile_list_state: TableState::default(),
            panel_areas: HashMap::new(),
            toast: None,
            terminal_size: (80, 24),
            is_root: false,
            config: crate::config::AppConfig::default(),
            config_dir: std::env::temp_dir().join("vortix_test"),
            connection_drops: 0,
            pending_connect: None,
            killswitch_mode: crate::state::KillSwitchMode::Off,
            killswitch_state: crate::state::KillSwitchState::Disabled,
            telemetry_rx: None,
            cmd_tx,
            cmd_rx,
            shared_profiles: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    /// Helper: put app into a Connected state for a given profile name.
    fn set_connected(app: &mut App, name: &str) {
        app.session_start = Some(Instant::now());
        app.connection_state = ConnectionState::Connected {
            since: Instant::now(),
            profile: name.to_string(),
            server_location: "Test".to_string(),
            latency_ms: 10,
            details: Box::new(DetailedConnectionInfo {
                interface: "wg0".to_string(),
                pid: Some(12345),
                ..Default::default()
            }),
        };
    }

    /// Helper: put app into a Disconnecting state for a given profile name.
    fn set_disconnecting(app: &mut App, name: &str) {
        app.connection_state = ConnectionState::Disconnecting {
            started: Instant::now(),
            profile: name.to_string(),
        };
    }

    /// Helper: create a fake `ActiveSession` for scanner results.
    fn fake_session(name: &str) -> ActiveSession {
        ActiveSession {
            name: name.to_string(),
            interface: "wg0".to_string(),
            endpoint: "1.2.3.4:51820".to_string(),
            internal_ip: "10.0.0.2".to_string(),
            mtu: "1420".to_string(),
            public_key: String::new(),
            listen_port: "51820".to_string(),
            transfer_rx: "100 KiB".to_string(),
            transfer_tx: "50 KiB".to_string(),
            latest_handshake: "5 seconds ago".to_string(),
            pid: Some(12345),
            started_at: None,
        }
    }

    // ====================================================================
    // DisconnectResult handler tests
    // ====================================================================

    #[test]
    fn test_disconnect_result_success_transitions_to_disconnected() {
        let mut app = test_app();
        set_disconnecting(&mut app, "test-vpn");

        app.handle_message(Message::DisconnectResult {
            profile: "test-vpn".to_string(),
            success: true,
            error: None,
        });

        assert!(
            matches!(app.connection_state, ConnectionState::Disconnected),
            "Expected Disconnected after successful DisconnectResult"
        );
        assert!(app.session_start.is_none());
        // No success toast -- header state indicator is the feedback
    }

    #[test]
    fn test_disconnect_result_failure_shows_error_toast() {
        let mut app = test_app();
        set_disconnecting(&mut app, "test-vpn");

        app.handle_message(Message::DisconnectResult {
            profile: "test-vpn".to_string(),
            success: false,
            error: Some("permission denied".to_string()),
        });

        // Should transition out of Disconnecting
        assert!(
            matches!(app.connection_state, ConnectionState::Disconnected),
            "Expected Disconnected after failed DisconnectResult"
        );
        // Should show error toast
        let toast = app.toast.as_ref().expect("toast should be set");
        assert_eq!(toast.toast_type, ToastType::Error);
        assert!(toast.message.contains("permission denied"));
    }

    #[test]
    fn test_disconnect_result_success_from_non_disconnecting_state() {
        let mut app = test_app();
        // Already Disconnected -- result arrives late
        app.connection_state = ConnectionState::Disconnected;

        app.handle_message(Message::DisconnectResult {
            profile: "test-vpn".to_string(),
            success: true,
            error: None,
        });

        // Should still be Disconnected, no panic
        assert!(matches!(
            app.connection_state,
            ConnectionState::Disconnected
        ));
    }

    // ====================================================================
    // Scanner debounce guard tests (SyncSystemState while Disconnecting)
    // ====================================================================

    #[test]
    fn test_scanner_never_overrides_disconnecting_to_connected() {
        let mut app = test_app();
        set_disconnecting(&mut app, "test-vpn");

        // Scanner sees interface still up
        let sessions = vec![fake_session("test-vpn")];
        app.handle_message(Message::SyncSystemState(sessions));

        // Must still be Disconnecting -- NOT Connected
        assert!(
            matches!(app.connection_state, ConnectionState::Disconnecting { .. }),
            "Scanner must never override Disconnecting to Connected, got {:?}",
            app.connection_state
        );
    }

    #[test]
    fn test_scanner_confirms_disconnect_when_interface_gone() {
        let mut app = test_app();
        set_disconnecting(&mut app, "test-vpn");

        // Scanner sees no active sessions
        app.handle_message(Message::SyncSystemState(vec![]));

        assert!(
            matches!(app.connection_state, ConnectionState::Disconnected),
            "Scanner should confirm Disconnected when interface is gone"
        );
        assert!(app.session_start.is_none());
    }

    #[test]
    fn test_scanner_safety_timeout_after_30s() {
        let mut app = test_app();
        // Set disconnecting with a start time 31 seconds in the past
        app.connection_state = ConnectionState::Disconnecting {
            started: Instant::now()
                .checked_sub(std::time::Duration::from_secs(31))
                .unwrap(),
            profile: "test-vpn".to_string(),
        };

        // Scanner sees interface still up
        let sessions = vec![fake_session("test-vpn")];
        app.handle_message(Message::SyncSystemState(sessions));

        assert!(
            matches!(app.connection_state, ConnectionState::Disconnected),
            "Should time out to Disconnected after 30s"
        );
        // Should show warning toast
        let toast = app.toast.as_ref().expect("timeout should show toast");
        assert_eq!(toast.toast_type, ToastType::Warning);
        assert!(toast.message.contains("timed out"));
    }

    #[test]
    fn test_scanner_disconnecting_does_not_affect_other_profiles() {
        let mut app = test_app();
        set_disconnecting(&mut app, "vpn-a");

        // Scanner sees a different profile active (shouldn't affect our Disconnecting guard)
        let sessions = vec![fake_session("vpn-b")];
        app.handle_message(Message::SyncSystemState(sessions));

        // Interface for "vpn-a" is gone (vpn-b is someone else), so confirm disconnect
        // Actually, the guard checks `!active.iter().any(|s| &s.name == profile)`.
        // "vpn-a" is not in the list -> interface_gone = true -> Disconnected
        assert!(
            matches!(app.connection_state, ConnectionState::Disconnected),
            "Should detect our profile is gone even if other profiles are active"
        );
    }

    // ====================================================================
    // Force disconnect (d pressed twice) tests
    // ====================================================================

    #[test]
    fn test_d_while_disconnecting_escalates_to_force() {
        let mut app = test_app();
        set_disconnecting(&mut app, "test-vpn");
        add_profiles(&mut app, &["test-vpn"]);

        let before = if let ConnectionState::Disconnecting { started, .. } = &app.connection_state {
            *started
        } else {
            panic!("expected Disconnecting");
        };

        // 'd' while Disconnecting => force disconnect (resets the timer)
        app.handle_message(Message::Disconnect);

        // Should still be Disconnecting (the force thread was spawned)
        assert!(matches!(
            app.connection_state,
            ConnectionState::Disconnecting { .. }
        ));

        // Timer should have been reset (new started >= old started)
        if let ConnectionState::Disconnecting { started, .. } = &app.connection_state {
            assert!(*started >= before);
        }

        // Should show a warning toast about force disconnect
        let toast = app.toast.as_ref().expect("force disconnect shows toast");
        assert_eq!(toast.toast_type, ToastType::Warning);
        assert!(toast.message.contains("Force"));
    }

    #[test]
    fn test_d_while_disconnected_is_noop() {
        let mut app = test_app();
        app.handle_message(Message::Disconnect);
        assert!(matches!(
            app.connection_state,
            ConnectionState::Disconnected
        ));
    }

    // ====================================================================
    // Helpers for new tests
    // ====================================================================

    /// Helper: put app into a Connecting state for a given profile name.
    fn set_connecting(app: &mut App, name: &str) {
        app.connection_state = ConnectionState::Connecting {
            started: Instant::now(),
            profile: name.to_string(),
        };
    }

    /// Helper: add test profiles to the app.
    fn add_profiles(app: &mut App, names: &[&str]) {
        for name in names {
            app.profiles.push(VpnProfile {
                name: (*name).to_string(),
                protocol: Protocol::WireGuard,
                config_path: std::path::PathBuf::from(format!("/tmp/{name}.conf")),
                location: "Test".to_string(),
                last_used: None,
            });
        }
    }

    // ====================================================================
    // Pending connect / VPN switching tests
    // ====================================================================

    #[test]
    fn test_toggle_connected_different_profile_sets_pending() {
        let mut app = test_app();
        add_profiles(&mut app, &["vpn-a", "vpn-b"]);
        set_connected(&mut app, "vpn-a");

        // Toggle to profile index 1 ("vpn-b") while connected to "vpn-a"
        app.toggle_connection(1);

        // Should set pending_connect to index 1
        assert_eq!(app.pending_connect, Some(1));
        // State should be Disconnecting (disconnect was called for vpn-a)
        // Note: disconnect() requires root / matching profile, so state change
        // depends on whether the profile was found. Since we added profiles, it should work.
        // But since is_root is false in test, connect_profile won't actually run.
        // disconnect() transitions to Disconnecting if it finds the profile.
        assert!(
            matches!(app.connection_state, ConnectionState::Disconnecting { .. }),
            "Expected Disconnecting after switch request, got {:?}",
            app.connection_state
        );
    }

    #[test]
    fn test_toggle_connected_same_profile_disconnects_without_pending() {
        let mut app = test_app();
        add_profiles(&mut app, &["vpn-a"]);
        set_connected(&mut app, "vpn-a");

        // Toggle same profile => just disconnect
        app.toggle_connection(0);

        assert_eq!(
            app.pending_connect, None,
            "Same-profile toggle should not set pending"
        );
        assert!(matches!(
            app.connection_state,
            ConnectionState::Disconnecting { .. }
        ));
    }

    #[test]
    fn test_toggle_while_disconnecting_queues_pending() {
        let mut app = test_app();
        add_profiles(&mut app, &["vpn-a", "vpn-b"]);
        set_disconnecting(&mut app, "vpn-a");

        // Press '2' (toggle profile index 1) while disconnecting
        app.toggle_connection(1);

        assert_eq!(app.pending_connect, Some(1));
        // Should still be in Disconnecting state (not overridden)
        assert!(matches!(
            app.connection_state,
            ConnectionState::Disconnecting { .. }
        ));
        // No toast -- header state indicator is the feedback
    }

    #[test]
    fn test_toggle_while_connecting_is_rejected() {
        let mut app = test_app();
        add_profiles(&mut app, &["vpn-a", "vpn-b"]);
        set_connecting(&mut app, "vpn-a");

        app.toggle_connection(1);

        // Should be rejected (still Connecting)
        assert!(matches!(
            app.connection_state,
            ConnectionState::Connecting { .. }
        ));
        assert_eq!(app.pending_connect, None);
        // No toast -- header state indicator shows "Connecting..."
    }

    #[test]
    fn test_pending_connect_drained_on_disconnect_success() {
        let mut app = test_app();
        add_profiles(&mut app, &["vpn-a", "vpn-b"]);
        set_disconnecting(&mut app, "vpn-a");
        app.pending_connect = Some(1);
        app.is_root = true; // so connect_profile can run

        // Simulate successful disconnect result
        app.handle_message(Message::DisconnectResult {
            profile: "vpn-a".to_string(),
            success: true,
            error: None,
        });

        // pending_connect should have been drained
        assert_eq!(app.pending_connect, None);
        // State should now be Connecting (auto-connected to vpn-b)
        assert!(
            matches!(app.connection_state, ConnectionState::Connecting { ref profile, .. } if profile == "vpn-b"),
            "Expected Connecting to vpn-b, got {:?}",
            app.connection_state
        );
    }

    #[test]
    fn test_pending_connect_drained_on_scanner_interface_gone() {
        let mut app = test_app();
        add_profiles(&mut app, &["vpn-a", "vpn-b"]);
        set_disconnecting(&mut app, "vpn-a");
        app.pending_connect = Some(1);
        app.is_root = true;

        // Scanner sees no active sessions (interface gone)
        app.handle_message(Message::SyncSystemState(vec![]));

        assert_eq!(app.pending_connect, None);
        assert!(
            matches!(app.connection_state, ConnectionState::Connecting { ref profile, .. } if profile == "vpn-b"),
            "Expected auto-connect to vpn-b after scanner confirms disconnect"
        );
    }

    #[test]
    fn test_pending_cleared_on_disconnect_failure() {
        let mut app = test_app();
        add_profiles(&mut app, &["vpn-a", "vpn-b"]);
        set_disconnecting(&mut app, "vpn-a");
        app.pending_connect = Some(1);

        // Simulate failed disconnect
        app.handle_message(Message::DisconnectResult {
            profile: "vpn-a".to_string(),
            success: false,
            error: Some("permission denied".to_string()),
        });

        // Pending should be cleared (don't auto-connect after failure)
        assert_eq!(app.pending_connect, None);
        // State should be Disconnected (scanner will re-detect if VPN is still up)
        assert!(matches!(
            app.connection_state,
            ConnectionState::Disconnected
        ));
    }

    #[test]
    fn test_pending_cleared_on_30s_timeout() {
        let mut app = test_app();
        add_profiles(&mut app, &["vpn-a", "vpn-b"]);
        app.connection_state = ConnectionState::Disconnecting {
            started: Instant::now()
                .checked_sub(std::time::Duration::from_secs(31))
                .unwrap(),
            profile: "vpn-a".to_string(),
        };
        app.pending_connect = Some(1);

        // Scanner sees interface still up -> 30s timeout triggers
        let sessions = vec![fake_session("vpn-a")];
        app.handle_message(Message::SyncSystemState(sessions));

        // Pending should be cleared on timeout (VPN may still be running)
        assert_eq!(app.pending_connect, None);
        assert!(matches!(
            app.connection_state,
            ConnectionState::Disconnected
        ));
    }

    // ====================================================================
    // ConnectResult tests
    // ====================================================================

    #[test]
    fn test_connect_result_success_keeps_connecting() {
        let mut app = test_app();
        set_connecting(&mut app, "test-vpn");

        app.handle_message(Message::ConnectResult {
            profile: "test-vpn".to_string(),
            success: true,
            error: None,
        });

        // Should still be Connecting -- scanner will promote to Connected
        assert!(
            matches!(app.connection_state, ConnectionState::Connecting { .. }),
            "Successful ConnectResult should keep Connecting state"
        );
    }

    #[test]
    fn test_connect_result_failure_transitions_to_disconnected() {
        let mut app = test_app();
        set_connecting(&mut app, "test-vpn");

        app.handle_message(Message::ConnectResult {
            profile: "test-vpn".to_string(),
            success: false,
            error: Some("wg-quick: already exists".to_string()),
        });

        assert!(
            matches!(app.connection_state, ConnectionState::Disconnected),
            "Failed ConnectResult should transition to Disconnected"
        );
        let toast = app.toast.as_ref().expect("should show error toast");
        assert_eq!(toast.toast_type, ToastType::Error);
        assert!(toast.message.contains("Failed to connect"));
    }

    #[test]
    fn test_connect_result_failure_clears_pending() {
        let mut app = test_app();
        set_connecting(&mut app, "test-vpn");
        app.pending_connect = Some(1);

        app.handle_message(Message::ConnectResult {
            profile: "test-vpn".to_string(),
            success: false,
            error: Some("error".to_string()),
        });

        assert_eq!(
            app.pending_connect, None,
            "Connect failure should clear pending"
        );
    }

    // ====================================================================
    // Disconnect from Connecting state tests
    // ====================================================================

    #[test]
    fn test_disconnect_from_connecting_state() {
        let mut app = test_app();
        add_profiles(&mut app, &["test-vpn"]);
        set_connecting(&mut app, "test-vpn");

        app.disconnect();

        // Should transition to Disconnecting
        assert!(
            matches!(app.connection_state, ConnectionState::Disconnecting { .. }),
            "disconnect() should work from Connecting state, got {:?}",
            app.connection_state
        );
    }

    #[test]
    fn test_d_key_from_connecting_state_disconnects() {
        let mut app = test_app();
        add_profiles(&mut app, &["test-vpn"]);
        set_connecting(&mut app, "test-vpn");

        app.handle_message(Message::Disconnect);

        assert!(
            matches!(app.connection_state, ConnectionState::Disconnecting { .. }),
            "d key should cancel Connecting state"
        );
    }

    // ====================================================================
    // Reconnect uses pending_connect (no race)
    // ====================================================================

    #[test]
    fn test_reconnect_sets_pending_not_immediate_connect() {
        let mut app = test_app();
        add_profiles(&mut app, &["test-vpn"]);
        set_connected(&mut app, "test-vpn");

        app.reconnect();

        // Should set pending_connect and disconnect (not immediately reconnect)
        assert_eq!(app.pending_connect, Some(0));
        assert!(
            matches!(app.connection_state, ConnectionState::Disconnecting { .. }),
            "Reconnect should disconnect first"
        );
    }

    #[test]
    fn test_reconnect_auto_connects_after_disconnect_completes() {
        let mut app = test_app();
        add_profiles(&mut app, &["test-vpn"]);
        set_disconnecting(&mut app, "test-vpn");
        app.pending_connect = Some(0);
        app.is_root = true;

        // Disconnect completes
        app.handle_message(Message::DisconnectResult {
            profile: "test-vpn".to_string(),
            success: true,
            error: None,
        });

        // Should auto-connect to index 0
        assert_eq!(app.pending_connect, None);
        assert!(
            matches!(app.connection_state, ConnectionState::Connecting { ref profile, .. } if profile == "test-vpn"),
            "Reconnect should auto-connect after disconnect"
        );
    }

    // ====================================================================
    // QuickConnect (1-9) edge cases
    // ====================================================================

    #[test]
    fn test_quick_connect_while_connected_switches_vpn() {
        let mut app = test_app();
        add_profiles(&mut app, &["vpn-a", "vpn-b", "vpn-c"]);
        set_connected(&mut app, "vpn-a");

        // Press '2' to switch to vpn-b
        app.handle_message(Message::QuickConnect(1));

        assert_eq!(app.pending_connect, Some(1));
        assert!(matches!(
            app.connection_state,
            ConnectionState::Disconnecting { .. }
        ));
    }

    #[test]
    fn test_quick_connect_while_disconnecting_updates_pending() {
        let mut app = test_app();
        add_profiles(&mut app, &["vpn-a", "vpn-b", "vpn-c"]);
        set_disconnecting(&mut app, "vpn-a");
        app.pending_connect = Some(1); // originally queued vpn-b

        // User changes mind, presses '3' for vpn-c
        app.handle_message(Message::QuickConnect(2));

        assert_eq!(
            app.pending_connect,
            Some(2),
            "Should update pending to new choice"
        );
    }

    #[test]
    fn test_quick_connect_from_disconnected() {
        let mut app = test_app();
        add_profiles(&mut app, &["vpn-a"]);
        app.is_root = true;

        app.handle_message(Message::QuickConnect(0));

        // Should go directly to Connecting (no pending)
        assert!(
            matches!(app.connection_state, ConnectionState::Connecting { .. }),
            "QuickConnect from Disconnected should go to Connecting"
        );
        assert_eq!(app.pending_connect, None);
    }

    // ====================================================================
    // Auth prompt tests
    // ====================================================================

    /// Helper: add `OpenVPN` profiles with a temp config file containing auth-user-pass.
    fn add_openvpn_profiles_with_auth(app: &mut App, names: &[&str]) {
        let dir = std::env::temp_dir().join("vortix_test_auth_profiles");
        let _ = std::fs::create_dir_all(&dir);
        for name in names {
            let config_path = dir.join(format!("{name}.ovpn"));
            std::fs::write(
                &config_path,
                "client\nremote example.com 1194\nauth-user-pass\ndev tun\nproto udp\n",
            )
            .unwrap();
            app.profiles.push(VpnProfile {
                name: (*name).to_string(),
                protocol: Protocol::OpenVPN,
                config_path,
                location: "Test".to_string(),
                last_used: None,
            });
        }
    }

    /// Helper: add `OpenVPN` profiles WITHOUT auth-user-pass.
    fn add_openvpn_profiles_no_auth(app: &mut App, names: &[&str]) {
        let dir = std::env::temp_dir().join("vortix_test_noauth_profiles");
        let _ = std::fs::create_dir_all(&dir);
        for name in names {
            let config_path = dir.join(format!("{name}.ovpn"));
            std::fs::write(
                &config_path,
                "client\nremote example.com 1194\ndev tun\nproto udp\n<ca>\n</ca>\n",
            )
            .unwrap();
            app.profiles.push(VpnProfile {
                name: (*name).to_string(),
                protocol: Protocol::OpenVPN,
                config_path,
                location: "Test".to_string(),
                last_used: None,
            });
        }
    }

    #[test]
    fn test_auth_prompt_shown_for_openvpn_with_auth_user_pass() {
        let mut app = test_app();
        add_openvpn_profiles_with_auth(&mut app, &["auth-vpn"]);
        app.is_root = true;

        // Clean up any leftover saved creds
        utils::delete_openvpn_auth_file("auth-vpn");

        app.connect_profile(0);

        // Should show auth prompt instead of connecting
        assert!(
            matches!(app.input_mode, InputMode::AuthPrompt { .. }),
            "OpenVPN with auth-user-pass and no saved creds should show AuthPrompt"
        );
        assert!(
            matches!(app.connection_state, ConnectionState::Disconnected),
            "Should not start connecting before credentials are provided"
        );
    }

    #[test]
    fn test_auth_prompt_skipped_when_creds_saved() {
        let mut app = test_app();
        add_openvpn_profiles_with_auth(&mut app, &["saved-vpn"]);
        app.is_root = true;

        // Pre-save credentials
        let _ = utils::write_openvpn_auth_file("saved-vpn", "user", "pass");

        app.connect_profile(0);

        // Should skip prompt and go to Connecting
        assert!(
            !matches!(app.input_mode, InputMode::AuthPrompt { .. }),
            "Should not show AuthPrompt when creds are already saved"
        );
        assert!(
            matches!(app.connection_state, ConnectionState::Connecting { .. }),
            "Should proceed to Connecting with saved credentials"
        );

        // Clean up
        utils::delete_openvpn_auth_file("saved-vpn");
    }

    #[test]
    fn test_auth_prompt_skipped_for_wireguard() {
        let mut app = test_app();
        add_profiles(&mut app, &["wg-vpn"]);
        app.is_root = true;

        app.connect_profile(0);

        // WireGuard should never show auth prompt
        assert!(
            !matches!(app.input_mode, InputMode::AuthPrompt { .. }),
            "WireGuard profiles should never show AuthPrompt"
        );
    }

    #[test]
    fn test_auth_prompt_skipped_for_openvpn_without_auth_directive() {
        let mut app = test_app();
        add_openvpn_profiles_no_auth(&mut app, &["noauth-vpn"]);
        app.is_root = true;

        app.connect_profile(0);

        // No auth-user-pass in config => no prompt
        assert!(
            !matches!(app.input_mode, InputMode::AuthPrompt { .. }),
            "OpenVPN without auth-user-pass should not show AuthPrompt"
        );
        assert!(
            matches!(app.connection_state, ConnectionState::Connecting { .. }),
            "Should proceed to Connecting directly"
        );
    }

    #[test]
    fn test_auth_submit_triggers_connect() {
        let mut app = test_app();
        add_openvpn_profiles_with_auth(&mut app, &["submit-vpn"]);
        app.is_root = true;

        // Clean up any leftover
        utils::delete_openvpn_auth_file("submit-vpn");

        app.handle_message(Message::AuthSubmit {
            idx: 0,
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            save: true,
            connect_after: true,
        });

        // Should be in Normal mode (overlay closed)
        assert_eq!(app.input_mode, InputMode::Normal);
        // Should be Connecting
        assert!(
            matches!(app.connection_state, ConnectionState::Connecting { .. }),
            "AuthSubmit should trigger connect_profile"
        );

        // Verify credentials were saved
        let creds = utils::read_openvpn_saved_auth("submit-vpn");
        assert!(creds.is_some());
        let (user, pass) = creds.unwrap();
        assert_eq!(user, "testuser");
        assert_eq!(pass, "testpass");

        // Clean up
        utils::delete_openvpn_auth_file("submit-vpn");
    }

    #[test]
    fn test_auth_cancel_returns_to_normal() {
        let mut app = test_app();
        add_openvpn_profiles_with_auth(&mut app, &["cancel-vpn"]);
        app.is_root = true;

        // Clean up
        utils::delete_openvpn_auth_file("cancel-vpn");

        // Trigger auth prompt
        app.connect_profile(0);
        assert!(matches!(app.input_mode, InputMode::AuthPrompt { .. }));

        // Cancel via CloseOverlay
        app.handle_message(Message::CloseOverlay);
        assert_eq!(app.input_mode, InputMode::Normal);
        assert!(
            matches!(app.connection_state, ConnectionState::Disconnected),
            "Cancelling auth should keep Disconnected state"
        );
    }

    #[test]
    fn test_auth_field_switching() {
        let mut app = test_app();
        app.input_mode = InputMode::AuthPrompt {
            profile_idx: 0,
            profile_name: "test".to_string(),
            username: String::new(),
            username_cursor: 0,
            password: String::new(),
            password_cursor: 0,
            focused_field: AuthField::Username,
            save_credentials: true,
            connect_after: true,
        };

        // Tab from Username -> Password
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        if let InputMode::AuthPrompt { focused_field, .. } = &app.input_mode {
            assert_eq!(*focused_field, AuthField::Password);
        } else {
            panic!("Expected AuthPrompt");
        }

        // Tab from Password -> SaveCheckbox
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        if let InputMode::AuthPrompt { focused_field, .. } = &app.input_mode {
            assert_eq!(*focused_field, AuthField::SaveCheckbox);
        } else {
            panic!("Expected AuthPrompt");
        }

        // Tab from SaveCheckbox -> Username (wraps around)
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        if let InputMode::AuthPrompt { focused_field, .. } = &app.input_mode {
            assert_eq!(*focused_field, AuthField::Username);
        } else {
            panic!("Expected AuthPrompt");
        }
    }

    #[test]
    fn test_auth_delete_profile_cleans_auth_file() {
        let mut app = test_app();
        add_openvpn_profiles_with_auth(&mut app, &["del-vpn"]);
        app.profile_list_state.select(Some(0));

        // Pre-save credentials
        let auth_path = utils::write_openvpn_auth_file("del-vpn", "user", "pass").unwrap();
        assert!(auth_path.exists());

        // Delete the profile
        app.confirm_delete(0);

        // Auth file should be cleaned up
        assert!(
            !auth_path.exists(),
            "Auth file should be deleted when profile is deleted"
        );
    }
}
