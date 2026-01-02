//! Core application state and logic.
//!
//! This module contains the main [`App`] struct that manages all application state,
//! including VPN connection status, profile management, telemetry data, and UI state.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::TableState;
use std::time::Instant;

/// Detailed information about an active VPN connection.
///
/// Contains technical details parsed from the VPN interface including
/// network addresses, transfer statistics, and cryptographic information.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DetailedConnectionInfo {
    /// Internal IP address assigned by the VPN.
    pub internal_ip: String,
    /// Remote server endpoint (IP:port).
    pub endpoint: String,
    /// Maximum Transmission Unit size.
    pub mtu: String,
    /// `WireGuard` public key (empty for `OpenVPN`).
    pub public_key: String,
    /// Local listening port.
    pub listen_port: String,
    /// Total bytes received.
    pub transfer_rx: String,
    /// Total bytes transmitted.
    pub transfer_tx: String,
    /// Time since last successful handshake.
    pub latest_handshake: String,
}

/// VPN connection state machine.
///
/// Represents the current state of the VPN connection, transitioning between
/// disconnected, connecting, and connected states.
#[derive(Clone, PartialEq, Default)]
pub enum ConnectionState {
    /// No active VPN connection.
    #[default]
    Disconnected,
    /// Connection attempt in progress.
    Connecting {
        /// When the connection attempt started.
        started: Instant,
        /// Name of the profile being connected.
        profile: String,
    },
    /// Active VPN connection established.
    Connected {
        /// When the connection was established.
        since: Instant,
        /// Name of the connected profile.
        profile: String,
        /// Geographic location of the server.
        server_location: String,
        /// Current latency in milliseconds.
        latency_ms: u64,
        /// Detailed connection information.
        details: Box<DetailedConnectionInfo>,
    },
}

/// Security check status tracking.
#[derive(Clone, Default)]
pub struct SecurityStatus {
    /// Timestamp of the last security check.
    pub last_check: Option<Instant>,
}

/// Currently focused UI panel for keyboard navigation.
#[derive(Clone, PartialEq, Default)]
pub enum FocusedPanel {
    /// VPN profiles sidebar.
    #[default]
    Sidebar,
    /// Activity log panel.
    Logs,
}

/// Current input mode determining keyboard behavior.
#[derive(Clone, PartialEq, Default)]
pub enum InputMode {
    /// Normal navigation mode.
    #[default]
    Normal,
    /// Profile selection modal is open.
    ProfileModal,
    /// File path import dialog is active.
    Import {
        /// Current input path string.
        path: String,
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
    },
}

/// Toast notification for temporary messages.
#[derive(Clone)]
pub struct Toast {
    /// Message to display.
    pub message: String,
    /// When the toast should disappear.
    pub expires: Instant,
}

/// Supported VPN protocol types.
#[derive(Clone, Copy, PartialEq, Default, Debug)]
pub enum Protocol {
    /// `WireGuard` VPN protocol.
    #[default]
    WireGuard,
    /// `OpenVPN` protocol.
    OpenVPN,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::WireGuard => write!(f, "WireGuard"),
            Protocol::OpenVPN => write!(f, "OpenVPN"),
        }
    }
}

/// VPN profile configuration.
///
/// Represents a saved VPN configuration file that can be used to establish connections.
#[derive(Clone, Debug)]
pub struct VpnProfile {
    /// Display name for the profile.
    pub name: String,
    /// VPN protocol type (`WireGuard` or `OpenVPN`).
    pub protocol: Protocol,
    /// Geographic location or server identifier.
    pub location: String,
    /// Path to the configuration file on disk.
    pub config_path: std::path::PathBuf,
}

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
    /// Quick access slots (1-5 keys) mapped to profile indices.
    pub quick_slots: [Option<usize>; 5],
    /// When the current session started.
    pub session_start: Option<Instant>,

    // === Security ===
    /// Security check status.
    pub security: SecurityStatus,

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
    pub isp: String,
    pub dns_server: String,
    pub ipv6_leak: bool,
    pub handshake: String,
    pub cipher: String,

    // === System Info ===
    pub public_ip: String,
    pub logs: Vec<String>,
    pub logs_scroll: u16,
    pub logs_auto_scroll: bool,

    // === UI State (Panel-based) ===
    pub focused_panel: FocusedPanel,
    pub input_mode: InputMode,
    pub show_help: bool,
    pub profile_list_state: TableState,
    pub toast: Option<Toast>,
    pub terminal_size: (u16, u16),
    pub is_root: bool,

    // === Async Telemetry ===
    telemetry_rx: Option<std::sync::mpsc::Receiver<crate::telemetry::TelemetryUpdate>>,
    network_stats: crate::telemetry::NetworkStats,
}

impl App {
    /// Create a new App instance with default state
    pub fn new() -> Self {
        let mut app = Self {
            should_quit: false,

            connection_state: ConnectionState::Disconnected,
            profiles: Vec::new(),
            quick_slots: [None; 5],
            session_start: None,

            security: SecurityStatus::default(),

            down_history: (0..60).map(|i| (f64::from(i), 0.0)).collect(),
            up_history: (0..60).map(|i| (f64::from(i), 0.0)).collect(),
            current_down: 0,
            current_up: 0,
            latency_ms: 0,
            isp: String::from(crate::constants::MSG_DETECTING),
            dns_server: String::from(crate::constants::MSG_NO_DATA),
            ipv6_leak: false,
            handshake: String::new(),
            cipher: String::from(crate::constants::DEFAULT_CIPHER),

            public_ip: String::from(crate::constants::MSG_FETCHING),
            logs: Vec::new(),
            logs_scroll: 0,
            logs_auto_scroll: true,

            // Panel-based UI state
            focused_panel: FocusedPanel::Sidebar,
            input_mode: InputMode::Normal,
            show_help: false,
            profile_list_state: TableState::default(),
            toast: None,
            terminal_size: (80, 24),
            is_root: std::process::Command::new("id")
                .arg("-u")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
                .unwrap_or(false),

            telemetry_rx: None,
            network_stats: crate::telemetry::NetworkStats::new(),
        };

        // Load profiles from ~/.config/vortix/profiles/
        app.profiles = crate::vpn::load_profiles();

        // Set up quick slots with first 5 profiles
        for (i, _) in app.profiles.iter().enumerate().take(5) {
            app.quick_slots[i] = Some(i);
        }

        // Select first profile if available
        if !app.profiles.is_empty() {
            app.profile_list_state.select(Some(0));
        }

        // Initialize logs with boot sequence
        app.log(&format!(
            "INIT: VORTIX v{} starting...",
            env!("CARGO_PKG_VERSION")
        ));
        app.log(crate::constants::MSG_BACKEND_INIT);
        app.log(crate::constants::MSG_READY);

        // Initial Scanner Run (Immediate State)
        app.update_connection_state_from_system();

        // Start background telemetry worker
        app.telemetry_rx = Some(crate::telemetry::spawn_telemetry_worker());

        app
    }

    /// Add a log message with timestamp
    pub fn log(&mut self, message: &str) {
        let timestamp = crate::utils::format_local_time();
        self.logs.push(format!("{timestamp} {message}"));

        if self.logs_auto_scroll {
            #[allow(clippy::cast_possible_truncation)]
            let scroll = self.logs.len().saturating_sub(1) as u16;
            self.logs_scroll = scroll;
        }
    }

    /// Handle keyboard input
    pub fn handle_key(&mut self, key: KeyEvent) {
        // Global: Handle Help Toggle
        if self.show_help {
            self.show_help = false;
            return;
        }

        // Global: Quit
        if (key.code == KeyCode::Char('q')
            || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL)))
            && self.input_mode == InputMode::Normal
        {
            self.should_quit = true;
            return;
        }

        // Handle based on Input Mode
        let input_mode = self.input_mode.clone();
        match input_mode {
            InputMode::Import { mut path } => {
                self.handle_input_import(key, &mut path);
                if self.input_mode != InputMode::Normal {
                    self.input_mode = InputMode::Import { path };
                }
            }
            InputMode::ProfileModal => self.handle_profile_modal_keys(key),
            InputMode::DependencyError { .. } | InputMode::PermissionDenied { .. } => {
                if key.code == KeyCode::Esc {
                    self.input_mode = InputMode::Normal;
                }
            }
            InputMode::ConfirmDelete { index, .. } => self.handle_confirm_delete_keys(key, index),
            InputMode::Normal => self.handle_normal_keys(key),
        }
    }

    fn handle_confirm_delete_keys(&mut self, key: KeyEvent, index: usize) {
        match key.code {
            KeyCode::Char('y') | KeyCode::Enter => {
                self.confirm_delete(index);
                self.input_mode = InputMode::Normal;
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                self.input_mode = InputMode::Normal;
            }
            _ => {}
        }
    }

    fn handle_input_import(&mut self, key: KeyEvent, path: &mut String) {
        match key.code {
            KeyCode::Esc => self.input_mode = InputMode::Normal,
            KeyCode::Enter => {
                let path_clone = path.clone();
                self.import_profile_from_path(&path_clone);
                self.input_mode = InputMode::Normal;
            }
            KeyCode::Backspace => {
                path.pop();
            }
            KeyCode::Char(c) => {
                path.push(c);
            }
            _ => {}
        }
    }

    fn handle_normal_keys(&mut self, key: KeyEvent) {
        match key.code {
            // Global Toggles
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Tab => self.next_panel(),
            KeyCode::BackTab => self.previous_panel(),
            KeyCode::Char('p') => self.input_mode = InputMode::ProfileModal,

            // Quick Actions (always available)
            KeyCode::Char('1') => self.connect_slot(0),
            KeyCode::Char('2') => self.connect_slot(1),
            KeyCode::Char('3') => self.connect_slot(2),
            KeyCode::Char('4') => self.connect_slot(3),
            KeyCode::Char('5') => self.connect_slot(4),
            KeyCode::Char('c') | KeyCode::Enter => {
                if let Some(idx) = self.profile_list_state.selected() {
                    self.toggle_connection(idx);
                } else {
                    self.show_toast("Select a profile first".to_string());
                }
            }
            KeyCode::Char('d') => self.disconnect(),
            KeyCode::Char('r') => self.reconnect(),
            KeyCode::Char('i') => {
                self.input_mode = InputMode::Import {
                    path: String::new(),
                };
            }

            // Delegation to focused panel
            _ => self.handle_panel_keys(key),
        }
    }

    fn handle_profile_modal_keys(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('p') => self.input_mode = InputMode::Normal,
            KeyCode::Up | KeyCode::Char('k') => self.profile_previous(),
            KeyCode::Down | KeyCode::Char('j') => self.profile_next(),
            KeyCode::Char('i') => {
                // Import from within profile modal
                self.input_mode = InputMode::Import {
                    path: String::new(),
                };
            }
            KeyCode::Char('x') | KeyCode::Delete => {
                if let Some(idx) = self.profile_list_state.selected() {
                    self.request_delete(idx);
                }
            }
            KeyCode::Enter => {
                if let Some(idx) = self.profile_list_state.selected() {
                    // In modal, Enter implies "Select & Connect/Toggle"
                    self.toggle_connection(idx);

                    // Only close modal if no blocking error
                    if matches!(self.input_mode, InputMode::ProfileModal) {
                        self.input_mode = InputMode::Normal;
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_panel_keys(&mut self, key: KeyEvent) {
        // Handle global keys first (leak test)
        if key.code == KeyCode::Char('t') {
            self.show_toast("Running leak tests...".to_string());
            self.security.last_check = Some(Instant::now());
            return;
        }

        match self.focused_panel {
            FocusedPanel::Sidebar => match key.code {
                KeyCode::Up | KeyCode::Char('k') => self.profile_previous(),
                KeyCode::Down | KeyCode::Char('j') => self.profile_next(),
                KeyCode::Char('x') => {
                    if let Some(idx) = self.profile_list_state.selected() {
                        self.request_delete(idx);
                    }
                }
                KeyCode::Enter => {
                    if let Some(idx) = self.profile_list_state.selected() {
                        self.toggle_connection(idx);
                    }
                }
                _ => {}
            },
            FocusedPanel::Logs => {
                // Activity Log navigation
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        self.logs_auto_scroll = false;
                        self.logs_scroll = self.logs_scroll.saturating_sub(1);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        self.logs_scroll = self.logs_scroll.saturating_add(1);
                        #[allow(clippy::cast_possible_truncation)]
                        let max_scroll = self.logs.len().saturating_sub(1) as u16;
                        if self.logs_scroll >= max_scroll {
                            self.logs_auto_scroll = true;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Cycle to next panel
    fn next_panel(&mut self) {
        self.focused_panel = match self.focused_panel {
            FocusedPanel::Sidebar => FocusedPanel::Logs,
            FocusedPanel::Logs => FocusedPanel::Sidebar,
        };
    }

    // Cycle to previous panel
    fn previous_panel(&mut self) {
        self.next_panel(); // Only 2 panels, so same logic
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
                    self.show_toast("Cannot delete active profile".to_string());
                    return;
                }
            }

            // 2. Switch to confirm mode
            self.input_mode = InputMode::ConfirmDelete {
                index: idx,
                name: profile.name.clone(),
            };
        }
    }

    /// Execute deletion after confirmation
    fn confirm_delete(&mut self, idx: usize) {
        if idx >= self.profiles.len() {
            return;
        }

        // Get config path before removing
        let config_path = self.profiles[idx].config_path.clone();

        // Remove from profiles
        self.profiles.remove(idx);

        // Try to delete from disk
        if config_path.exists() {
            let _ = std::fs::remove_file(&config_path);
        }

        // Adjust quick slots (remove reference and shift)
        for slot in &mut self.quick_slots {
            if let Some(slot_idx) = slot {
                if *slot_idx == idx {
                    *slot = None;
                } else if *slot_idx > idx {
                    *slot_idx -= 1;
                }
            }
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

        self.show_toast("Profile deleted".to_string());
    }

    /// Connect to a quick slot
    fn connect_slot(&mut self, slot: usize) {
        if let Some(Some(profile_idx)) = self.quick_slots.get(slot) {
            self.toggle_connection(*profile_idx);
        }
    }

    /// Smart connection toggle: Connect, Disconnect, or Switch
    fn toggle_connection(&mut self, idx: usize) {
        if let Some(target_profile) = self.profiles.get(idx) {
            match &self.connection_state {
                // If connecting, ignore to prevent races
                ConnectionState::Connecting { .. } => {
                    self.show_toast("Connection in progress...".to_string());
                }
                // If connected...
                ConnectionState::Connected {
                    profile: current_name,
                    ..
                } => {
                    if current_name == &target_profile.name {
                        // Same profile -> Disconnect
                        self.disconnect();
                    } else {
                        // Different profile -> Switch (Disconnect then Connect)
                        // Note: Because disconnect is synchronous (waits for process),
                        // we can validly call connect immediately after.
                        self.disconnect();
                        self.connect_profile(idx);
                    }
                }
                // If disconnected -> Connect
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
    fn connect_profile(&mut self, idx: usize) {
        // Clone needed data to release borrow on self
        let (name, protocol, config_path) = if let Some(profile) = self.profiles.get(idx) {
            (
                profile.name.clone(),
                profile.protocol,
                profile.config_path.clone(),
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

        // Start connecting
        self.connection_state = ConnectionState::Connecting {
            started: Instant::now(),
            profile: name.clone(),
        };

        // Execute real command
        let output = match protocol {
            Protocol::WireGuard => {
                std::process::Command::new("wg-quick")
                    .args(["up", config_path.to_str().unwrap_or("")])
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null()) // Don't care about stderr for UI state
                    .output()
            }
            Protocol::OpenVPN => std::process::Command::new("openvpn")
                .args(["--config", config_path.to_str().unwrap_or(""), "--daemon"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .output(),
        };

        if let Err(e) = output {
            self.show_toast(format!("Command Failed: {e}"));
        }
    }

    /// DISCONNECT from VPN
    pub fn disconnect(&mut self) {
        // Clone needed data to release borrow on self
        let connection_info = if let ConnectionState::Connected {
            profile: ref profile_name,
            ..
        } = self.connection_state
        {
            self.profiles
                .iter()
                .find(|p| p.name == *profile_name)
                .map(|profile| (profile.protocol, profile.config_path.clone()))
        } else {
            None
        };

        if let Some((protocol, config_path)) = connection_info {
            let output = match protocol {
                Protocol::WireGuard => std::process::Command::new("wg-quick")
                    .args(["down", config_path.to_str().unwrap_or("")])
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null())
                    .output(),
                Protocol::OpenVPN => std::process::Command::new("pkill")
                    .arg("openvpn")
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null())
                    .output(),
            };

            if let Err(e) = output {
                self.show_toast(format!("Disconnect Error: {e}"));
            }
            // We do NOT set state here. Scanner handles it.
        }
    }

    /// Reconnect to VPN
    fn reconnect(&mut self) {
        if let ConnectionState::Connected { profile, .. } = &self.connection_state {
            let profile_name = profile.clone();
            if let Some(idx) = self.profiles.iter().position(|p| p.name == profile_name) {
                self.disconnect();
                self.connect_profile(idx);
            }
        }
    }

    /// Show a toast notification and log it
    fn show_toast(&mut self, message: String) {
        self.add_log(&message);
        self.toast = Some(Toast {
            message,
            expires: Instant::now() + std::time::Duration::from_secs(3),
        });
    }

    /// Add a message to the persistent log
    fn add_log(&mut self, message: &str) {
        let timestamp = crate::utils::format_local_time();
        self.logs.push(format!("{timestamp} {message}"));

        // Keep only last 100 logs
        if self.logs.len() > 1000 {
            self.logs.remove(0);
        }

        // Auto-scroll logic
        if self.logs_auto_scroll {
            // Very simpler: ensure scroll is pointing to the "end"
            // Since Ratatui paragraph scrolling is line-based, setting it to len() usually shows emptiness
            // Setting it to len() - height is ideal, but we don't know height here.
            // But we can store logical index.
            #[allow(clippy::cast_possible_truncation)]
            let scroll = self.logs.len().saturating_sub(1) as u16;
            self.logs_scroll = scroll;
        }
    }

    /// Called on each tick (1 second)
    pub fn on_tick(&mut self) {
        // Poll System State (Stateless Architecture)
        self.update_connection_state_from_system();

        // Handle background telemetry updates
        self.handle_telemetry_updates();

        // Expire toast
        if let Some(ref toast) = self.toast {
            if Instant::now() > toast.expires {
                self.toast = None;
            }
        }

        // Update network stats from system
        self.update_network_stats();

        // Update throughput history for larger line chart (shift left)
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

    /// Poll system for active connections and update state
    fn update_connection_state_from_system(&mut self) {
        let active = crate::scanner::get_active_profiles(&self.profiles);

        if let Some(session) = active.first() {
            let active_name = &session.name;
            let real_start = session.started_at;

            // System says: Connected

            // 1. Try to update existing connection state in-place (keeps latency/logs intact)
            if let ConnectionState::Connected {
                profile,
                details,
                since,
                ..
            } = &mut self.connection_state
            {
                if profile == active_name {
                    // Sync Uptime if needed
                    if let Some(real) = real_start {
                        if let Ok(duration) = std::time::SystemTime::now().duration_since(real) {
                            let calculated_start = Instant::now()
                                .checked_sub(duration)
                                .unwrap_or(Instant::now());
                            if since.elapsed().as_secs().abs_diff(duration.as_secs()) > 5 {
                                *since = calculated_start;
                                self.session_start = Some(calculated_start);
                            }
                        }
                    }

                    // Update dynamic details
                    details.transfer_rx.clone_from(&session.transfer_rx);
                    details.transfer_tx.clone_from(&session.transfer_tx);
                    details
                        .latest_handshake
                        .clone_from(&session.latest_handshake);
                    details.internal_ip.clone_from(&session.internal_ip);
                    details.endpoint.clone_from(&session.endpoint);
                    // Static-ish details
                    details.mtu.clone_from(&session.mtu);
                    details.listen_port.clone_from(&session.listen_port);
                    details.public_key.clone_from(&session.public_key);

                    return; // Done updating
                }
            }

            // 2. If we reach here, it's a NEW connection or Profile Switch
            let needs_update = true; // For structure compatibility with below code logic flow
            if needs_update {
                // Always true here
                // Find profile details
                let location = self
                    .profiles
                    .iter()
                    .find(|p| &p.name == active_name)
                    .map_or_else(|| "Unknown".to_string(), |p| p.location.clone());

                // Calculate session start
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
                        internal_ip: session.internal_ip.clone(),
                        endpoint: session.endpoint.clone(),
                        mtu: session.mtu.clone(),
                        public_key: session.public_key.clone(),
                        listen_port: session.listen_port.clone(),
                        transfer_rx: session.transfer_rx.clone(),
                        transfer_tx: session.transfer_tx.clone(),
                        latest_handshake: session.latest_handshake.clone(),
                    }),
                };

                // Only log if this is a fresh detection (previous state was different)
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
            }
        } else {
            // System says: Disconnected
            if !matches!(self.connection_state, ConnectionState::Disconnected) {
                // Determine if we should clear session start (yes if we were connected)
                if let ConnectionState::Connected { profile, .. } = &self.connection_state {
                    self.log(&format!("STATUS: Disconnected from '{profile}'"));
                }

                self.connection_state = ConnectionState::Disconnected;
                self.session_start = None;
            }
        }
    }

    /// Processes pending telemetry updates from the background worker.
    fn handle_telemetry_updates(&mut self) {
        use crate::telemetry::TelemetryUpdate;
        if let Some(rx) = &self.telemetry_rx {
            while let Ok(update) = rx.try_recv() {
                match update {
                    TelemetryUpdate::PublicIp(ip) => self.public_ip = ip,
                    TelemetryUpdate::Latency(ms) => self.latency_ms = ms,
                    TelemetryUpdate::Isp(isp) => self.isp = isp,
                    TelemetryUpdate::Dns(dns) => self.dns_server = dns,
                    TelemetryUpdate::Ipv6Leak(leak) => self.ipv6_leak = leak,
                }
            }
        }
    }

    /// Updates network throughput statistics from system interfaces.
    fn update_network_stats(&mut self) {
        let (down, up) = self.network_stats.update();
        self.current_down = down;
        self.current_up = up;
    }

    /// Called when terminal is resized
    pub fn on_resize(&mut self, width: u16, height: u16) {
        self.terminal_size = (width, height);
    }

    /// Import a profile from a file path
    fn import_profile_from_path(&mut self, path_str: &str) {
        use std::path::Path;

        let path = Path::new(path_str);

        // Expand ~ to home directory
        let expanded_path = if let Some(stripped) = path_str.strip_prefix("~/") {
            if let Some(home) = crate::utils::home_dir() {
                home.join(stripped)
            } else {
                path.to_path_buf()
            }
        } else {
            path.to_path_buf()
        };

        match crate::vpn::import_profile(&expanded_path) {
            Ok(profile) => {
                let name = profile.name.clone();
                self.profiles.push(profile);

                // Add to quick slot if available
                for slot in &mut self.quick_slots {
                    if slot.is_none() {
                        *slot = Some(self.profiles.len() - 1);
                        break;
                    }
                }

                self.show_toast(format!("Imported: {name}"));
            }
            Err(e) => {
                self.show_toast(format!("Error: {e}"));
            }
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}
