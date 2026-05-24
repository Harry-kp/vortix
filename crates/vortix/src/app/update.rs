//! Central message dispatcher (TEA-style update function).
//!
//! Private handler methods receive owned values destructured from the `Message` enum.
#![allow(clippy::needless_pass_by_value)]

use std::time::Instant;

use super::{
    App, ConnectionState, DetailedConnectionInfo, FocusedPanel, InputMode, Protocol, ToastType,
};
use crate::constants;
use crate::core::scanner::ActiveSession;
use crate::core::telemetry::TelemetryUpdate;
use crate::logger;
use crate::message::{Message, ScrollMove, SelectionMove};
use crate::utils;

impl App {
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
                if let Some(idx) = self.profile_list_state.selected() {
                    if let Some(profile) = self.profiles.get(idx) {
                        self.cached_config_content = Some(
                            std::fs::read_to_string(&profile.config_path)
                                .unwrap_or_else(|e| format!("Error reading config: {e}")),
                        );
                    }
                    self.show_config = true;
                    self.config_scroll = 0;
                }
            }
            Message::ManageAuth => self.handle_manage_auth(),
            Message::ClearAuth => self.handle_clear_auth(),
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
            Message::ConfirmSwitch { idx } => {
                self.input_mode = InputMode::Normal;
                if let Some(profile) = self.profiles.get(idx) {
                    self.log(&format!("ACTION: Switching to '{}'...", profile.name));
                }
                if matches!(self.connection_state, ConnectionState::Disconnected) {
                    self.pending_connect = None;
                    self.toggle_connection(idx);
                } else {
                    self.pending_connect = Some(idx);
                    self.disconnect();
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
            Message::ConnectSelected => {
                if let Some(idx) = self.profile_list_state.selected() {
                    let target = self.profiles.get(idx).map(|p| p.name.clone());
                    match (&self.connection_state, target) {
                        (ConnectionState::Connected { profile, .. }, Some(name))
                            if *profile == name =>
                        {
                            self.pending_connect = Some(idx);
                            self.disconnect();
                        }
                        (_, Some(_)) => {
                            self.toggle_connection(idx);
                        }
                        _ => {}
                    }
                }
            }
            Message::QuickConnect(idx) => {
                if idx < self.profiles.len() {
                    self.profile_list_state.select(Some(idx));
                    self.toggle_connection(idx);
                }
            }

            Message::DisconnectResult {
                profile,
                success,
                error,
            } => self.handle_disconnect_result(profile, success, error),

            Message::ConnectResult {
                profile,
                success,
                error,
            } => self.handle_connect_result(profile, success, error),

            // UI Toggles
            Message::ToggleZoom => {
                if self.zoomed_panel.is_some() {
                    self.zoomed_panel = None;
                } else {
                    self.zoomed_panel = Some(self.focused_panel.clone());
                }
            }
            Message::ToggleFlip => {
                let panel = self.focused_panel.clone();
                if matches!(
                    panel,
                    FocusedPanel::Chart | FocusedPanel::ConnectionDetails | FocusedPanel::Security
                ) && self.flip_animation.is_none()
                {
                    let to_back = !self.is_flipped(&panel);
                    self.flip_animation = Some(crate::state::FlipAnimation {
                        panel,
                        started: std::time::Instant::now(),
                        to_back,
                    });
                }
            }
            Message::CloseOverlay => {
                self.show_config = false;
                self.cached_config_content = None;
                self.show_action_menu = false;
                self.show_bulk_menu = false;
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

            Message::AuthSubmit {
                idx,
                username,
                password,
                save,
                connect_after,
            } => self.handle_auth_submit(idx, username, password, save, connect_after),

            Message::CycleSortOrder => {
                let selected_name = self
                    .profile_list_state
                    .selected()
                    .and_then(|i| self.profiles.get(i))
                    .map(|p| p.name.clone());
                self.sort_order = self.sort_order.next();
                self.sort_profiles();
                if let Some(name) = selected_name {
                    if let Some(new_idx) = self.profiles.iter().position(|p| p.name == name) {
                        self.profile_list_state.select(Some(new_idx));
                    }
                }
                self.show_toast(
                    format!("Sorted: {}", self.sort_order.label()),
                    ToastType::Info,
                );
            }

            Message::ToggleKillSwitch => self.handle_toggle_killswitch(),

            Message::OpenRename => self.handle_open_rename(),
            Message::OpenSearch => {
                self.input_mode = InputMode::Search {
                    query: String::new(),
                    cursor: 0,
                };
            }
            Message::OpenHelp => {
                self.input_mode = InputMode::Help { scroll: 0 };
            }
            Message::CycleLogFilter => self.handle_cycle_log_filter(),

            // System
            Message::Quit => self.handle_quit(),
            Message::Log(msg) => self.log(&msg),
            Message::Toast(msg, t_type) => self.show_toast(msg, t_type),
            Message::CopyIp => self.copy_ip_to_clipboard(),
            Message::ClearLogs => {
                logger::clear_logs();
                self.logs_scroll = 0;
                self.log("APP: Logs cleared");
            }
            Message::Telemetry(update) => self.handle_telemetry(update),
            Message::SyncSystemState(active) => self.handle_sync_system_state(active),
            Message::ConnectionTimeout(profile_name) => {
                self.handle_connection_timeout(profile_name);
            }
            Message::RetryConnect { idx, attempt } => {
                self.handle_retry_connect(idx, attempt);
            }
            Message::NetworkChanged => {
                self.handle_network_changed();
            }
            Message::Tick => self.handle_tick(),
            Message::Resize(width, height) => {
                self.terminal_size = (width, height);
            }
        }
    }

    fn handle_manage_auth(&mut self) {
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

    fn handle_clear_auth(&mut self) {
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

    fn handle_disconnect_result(&mut self, profile: String, success: bool, error: Option<String>) {
        // Guard: ignore stale results if we're no longer disconnecting this profile.
        let still_disconnecting = matches!(
            &self.connection_state,
            ConnectionState::Disconnecting { profile: p, .. } if *p == profile
        );
        if !still_disconnecting {
            self.log(&format!(
                "INFO: Ignoring stale DisconnectResult for '{profile}' (state changed)"
            ));
            // Still clean up files — the disconnect thread likely did kill the process
            utils::cleanup_openvpn_run_files(&profile);
        } else if success {
            self.complete_disconnect(&profile);
        } else {
            let err_msg = error.unwrap_or_else(|| "unknown error".to_string());
            self.log(&format!("ERR: Failed to disconnect '{profile}': {err_msg}"));
            // Keep Disconnecting state — the VPN process may still be running.
            // The user can press 'd' again to force-disconnect (SIGKILL).
            // Do NOT sync kill switch to a "disconnected" posture.
            self.show_toast(
                format!("Disconnect failed: {err_msg}. Press d to force-disconnect."),
                ToastType::Error,
            );
        }
    }

    fn handle_connect_result(&mut self, profile: String, success: bool, error: Option<String>) {
        // Ignore stale results if we're no longer in Connecting state for this profile.
        let still_connecting = matches!(
            &self.connection_state,
            ConnectionState::Connecting { profile: p, .. } if *p == profile
        );
        if !still_connecting {
            self.log(&format!(
                "INFO: Ignoring stale ConnectResult for '{profile}' (state changed)"
            ));
        } else if success {
            // Reset retry and auto-reconnect state on success
            self.retry_count = 0;
            self.retry_profile_idx = None;
            self.auto_reconnect_profile = None;

            let location = self
                .profiles
                .iter()
                .find(|p| p.name == profile)
                .map_or_else(|| "Unknown".to_string(), |p| p.location.clone());

            let now = Instant::now();
            self.connection_state = ConnectionState::Connected {
                profile: profile.clone(),
                server_location: location,
                since: now,
                latency_ms: 0,
                details: Box::new(DetailedConnectionInfo::default()),
            };
            self.session_start = Some(now);

            if let Some(p) = self.profiles.iter_mut().find(|p| p.name == profile) {
                p.last_used = Some(std::time::SystemTime::now());
            }
            self.save_metadata();

            self.last_connected_profile = Some(profile.clone());
            self.log(&format!("STATUS: Connected to '{profile}'"));
            self.refresh_telemetry();

            // KILL SWITCH: Arm when VPN connects
            if self.killswitch_mode != crate::state::KillSwitchMode::Off {
                self.sync_killswitch();
                self.log("SEC: Kill switch armed");
            }
        } else {
            let err_msg = error.unwrap_or_else(|| "unknown error".to_string());
            self.log(&format!("ERR: Failed to connect '{profile}': {err_msg}"));
            self.cleanup_vpn_resources(&profile);

            // Attempt retry with exponential backoff if configured
            let max_retries = self.config.connect_max_retries;
            let profile_idx = self.profiles.iter().position(|p| p.name == profile);

            if let Some(idx) = profile_idx.filter(|_| {
                max_retries > 0 && self.retry_count < max_retries && self.pending_connect.is_none()
            }) {
                self.retry_count += 1;
                let attempt = self.retry_count;
                self.retry_profile_idx = Some(idx);

                let base = self.config.connect_retry_base_delay_secs;
                let shift = (attempt - 1).min(63);
                let delay_secs = base
                    .saturating_mul(1u64 << shift)
                    .min(self.config.connect_retry_max_delay_secs);

                self.log(&format!(
                    "RETRY: Attempt {attempt}/{max_retries} for '{profile}' in {delay_secs}s..."
                ));
                self.show_toast(
                    format!("Retrying in {delay_secs}s ({attempt}/{max_retries})"),
                    ToastType::Warning,
                );

                self.connection_state = ConnectionState::Disconnected;
                self.session_start = None;

                let cmd_tx = self.cmd_tx.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_secs(delay_secs));
                    let _ = cmd_tx.send(crate::message::Message::RetryConnect { idx, attempt });
                });
            } else {
                // No retry: final failure
                self.retry_count = 0;
                self.retry_profile_idx = None;
                self.connection_state = ConnectionState::Disconnected;
                self.session_start = None;
                self.show_toast(format!("Failed to connect: {err_msg}"), ToastType::Error);
                self.pending_connect = None;
            }
        }
    }

    fn handle_auth_submit(
        &mut self,
        idx: usize,
        username: String,
        password: String,
        save: bool,
        connect_after: bool,
    ) {
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
                    self.connect_profile(idx);
                } else {
                    // Save-only mode (from ManageAuth)
                    self.show_toast(
                        format!("Credentials updated for '{profile_name}'"),
                        ToastType::Success,
                    );
                }
            }
            Err(e) => {
                self.show_toast(format!("Failed to write auth file: {e}"), ToastType::Error);
            }
        }
    }

    fn handle_toggle_killswitch(&mut self) {
        use crate::state::KillSwitchMode;

        // Cycle to next mode
        self.killswitch_mode = self.killswitch_mode.next();

        // Sync state and firewall (may refuse Blocking if not root)
        self.sync_killswitch();

        // If sync_killswitch refused Blocking because we're not root (only
        // possible in AlwaysOn mode when disconnected), preserve the root
        // warning toast instead of overwriting it with the mode toast.
        let blocking_refused = matches!(self.killswitch_mode, KillSwitchMode::AlwaysOn)
            && !self.is_root
            && !self.killswitch_state.is_blocking();

        if !blocking_refused {
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
        }

        // Save state for recovery
        let _ = crate::core::killswitch::save_state(
            self.killswitch_mode,
            self.killswitch_state,
            None,
            None,
        );
    }

    fn handle_quit(&mut self) {
        // VPN connections are independent OS processes (wg-quick configures the
        // kernel; openvpn runs as a daemon). They should persist after the TUI
        // exits so the user can reopen the TUI or run `vortix status` later.
        // Only explicit disconnect actions (`vortix down`, disconnect button)
        // should tear them down.
        //
        // Kill switch state is saved so the next launch can recover it.
        let _ = crate::core::killswitch::save_state(
            self.killswitch_mode,
            self.killswitch_state,
            None,
            None,
        );
        self.should_quit = true;
    }

    fn handle_telemetry(&mut self, update: TelemetryUpdate) {
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
                } else if self.public_ip != ip && self.public_ip != constants::MSG_FETCHING {
                    self.ip_unchanged_warned = false;
                    self.log(&format!("NET: Public IP changed {old_ip} -> {ip}"));
                } else if is_connected
                    && self.public_ip == ip
                    && self.public_ip != constants::MSG_FETCHING
                    && !self.ip_unchanged_warned
                {
                    self.ip_unchanged_warned = true;
                    self.log(&format!(
                        "WARN: Public IP unchanged ({ip}) while connected — possible leak or split-tunnel"
                    ));
                    if let Some(ref real) = self.real_ip {
                        if real == &ip {
                            self.log(&format!("ERR: IP leak detected — current IP ({ip}) matches pre-VPN IP ({real})"));
                        }
                    }
                }
                self.public_ip = ip;
                self.last_security_check = Some(Instant::now());
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
                if matches!(self.connection_state, ConnectionState::Disconnected) {
                    if self.real_dns.is_none() {
                        self.log(&format!("NET: Pre-VPN DNS: {dns}"));
                    }
                    self.real_dns = Some(dns.clone());
                } else if self.dns_server != dns && self.dns_server != constants::MSG_NO_DATA {
                    self.log(&format!("SEC: DNS server: {dns}"));
                }
                self.dns_server = dns;
                self.last_security_check = Some(Instant::now());
            }
            TelemetryUpdate::Ipv6Leak(leak) => {
                if self.ipv6_leak != leak {
                    if leak {
                        self.log("WARN: IPv6 leak detected — traffic may bypass VPN tunnel");
                    } else {
                        self.log("SEC: IPv6 secure (blocked)");
                    }
                }
                self.ipv6_leak = leak;
                self.last_security_check = Some(Instant::now());
            }
            TelemetryUpdate::Log(level, msg) => {
                logger::log(level, "TELEMETRY", msg);
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn handle_sync_system_state(&mut self, active: Vec<ActiveSession>) {
        // Guard: While Disconnecting, the scanner must NEVER override to Connected.
        if let ConnectionState::Disconnecting { started, profile } = &self.connection_state {
            let elapsed = started.elapsed().as_secs();
            let interface_gone = !active.iter().any(|s| &s.name == profile);

            if interface_gone {
                let profile_name = profile.clone();
                self.complete_disconnect(&profile_name);
            } else if elapsed >= self.config.disconnect_timeout {
                let profile_name = profile.clone();
                self.log(&format!(
                    "WARN: Disconnect timed out for '{profile_name}' after {}s, forcing cleanup",
                    self.config.disconnect_timeout
                ));
                self.cleanup_vpn_resources(&profile_name);
                self.pending_connect = None;
                self.connection_state = ConnectionState::Disconnected;
                self.session_start = None;
                self.show_toast(
                    "Disconnect timed out — forced cleanup".to_string(),
                    ToastType::Warning,
                );
                self.sync_killswitch();
            }
            return;
        }

        // While Connecting, the scanner can only PROMOTE to Connected
        if let ConnectionState::Connecting { started, profile } = &self.connection_state {
            let profile_name = profile.clone();
            let elapsed = started.elapsed().as_secs();
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

                if self.killswitch_mode != crate::state::KillSwitchMode::Off {
                    self.sync_killswitch();
                    self.log("SEC: Kill switch armed");
                }

                if let Some(profile) = self.profiles.iter_mut().find(|p| p.name == profile_name) {
                    profile.last_used = Some(std::time::SystemTime::now());
                }
                self.save_metadata();
                self.session_start = Some(start_time);
            } else if elapsed > 0 && elapsed % constants::SCANNER_LOG_INTERVAL_SECS == 0 {
                self.log(&format!(
                    "NET: Scanner: no tunnel interface for '{profile_name}' yet ({elapsed}s elapsed, \
                     {} active session{})",
                    active.len(),
                    if active.len() == 1 { "" } else { "s" }
                ));
            }
            return;
        }

        if let Some(session) = active.first() {
            let active_name = session.name.clone();
            let real_start = session.started_at;

            if let ConnectionState::Connected {
                profile,
                details,
                since,
                ..
            } = &mut self.engine.connection_state
            {
                if profile == &active_name {
                    if let Some(real) = real_start {
                        if let Ok(duration) = std::time::SystemTime::now().duration_since(real) {
                            let calculated_start = Instant::now()
                                .checked_sub(duration)
                                .unwrap_or(Instant::now());
                            if since.elapsed().as_secs().abs_diff(duration.as_secs())
                                > constants::SESSION_TIME_DRIFT_SECS
                            {
                                *since = calculated_start;
                                self.engine.session_start = Some(calculated_start);
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
                let was_connected =
                    matches!(self.connection_state, ConnectionState::Connected { .. });

                if was_connected {
                    self.connection_drops += 1;
                    self.log(&format!(
                        "WARN: Connection dropped from '{}' (#{} this session)",
                        profile_name, self.connection_drops
                    ));
                } else if matches!(self.connection_state, ConnectionState::Disconnecting { .. }) {
                    self.log(&format!("STATUS: Disconnected from '{profile_name}'"));
                } else if matches!(self.connection_state, ConnectionState::Connecting { .. }) {
                    self.log(&format!(
                        "WARN: Connection to '{profile_name}' failed or was cancelled"
                    ));
                }

                utils::cleanup_openvpn_run_files(&profile_name);

                // Transition to Disconnected BEFORE syncing killswitch so that
                // sync_killswitch sees the correct connection state.
                self.connection_state = ConnectionState::Disconnected;
                self.session_start = None;

                // KILL SWITCH: Activate on unexpected VPN drop
                if was_connected
                    && self.killswitch_mode != crate::state::KillSwitchMode::Off
                    && self.killswitch_state == crate::state::KillSwitchState::Armed
                {
                    self.killswitch_state = crate::state::KillSwitchState::Blocking;
                    self.sync_killswitch();
                    self.log("SEC: Kill switch ACTIVATED - blocking traffic");
                    self.show_toast(
                        "VPN dropped! Kill Switch blocking traffic".to_string(),
                        ToastType::Error,
                    );
                }

                // AUTO-RECONNECT: Queue reconnection for unexpected drops
                if was_connected && self.config.auto_reconnect {
                    if let Some(idx) = self.profiles.iter().position(|p| p.name == profile_name) {
                        self.auto_reconnect_profile = Some(idx);
                        let delay = self.config.auto_reconnect_delay_secs;
                        let max = self.config.connect_max_retries;
                        self.log(&format!(
                            "NET: Auto-reconnect scheduled for '{profile_name}' in {delay}s (max {max} retries)"
                        ));
                        self.show_toast(
                            format!("VPN dropped — reconnecting in {delay}s"),
                            ToastType::Warning,
                        );

                        self.retry_count = 1;
                        self.retry_profile_idx = Some(idx);

                        let cmd_tx = self.cmd_tx.clone();
                        std::thread::spawn(move || {
                            std::thread::sleep(std::time::Duration::from_secs(delay));
                            let _ = cmd_tx
                                .send(crate::message::Message::RetryConnect { idx, attempt: 1 });
                        });
                    }
                }
            } else {
                self.connection_state = ConnectionState::Disconnected;
                self.session_start = None;
            }
        }
    }

    fn handle_retry_connect(&mut self, idx: usize, attempt: u32) {
        // Only proceed if retry state is still consistent
        if self.retry_profile_idx != Some(idx) || self.retry_count != attempt {
            self.log(&format!(
                "INFO: Ignoring stale RetryConnect (attempt {attempt}, idx {idx})"
            ));
            return;
        }
        // Don't retry if user started a different action
        if !matches!(self.connection_state, ConnectionState::Disconnected) {
            self.log("INFO: Skipping retry — connection state changed");
            self.retry_count = 0;
            self.retry_profile_idx = None;
            return;
        }
        if let Some(profile) = self.profiles.get(idx) {
            let max = self.config.connect_max_retries;
            self.log(&format!(
                "RETRY: Attempting reconnect to '{}' ({attempt}/{max})",
                profile.name
            ));
            self.connect_profile(idx);
        } else {
            self.retry_count = 0;
            self.retry_profile_idx = None;
        }
    }

    fn handle_network_changed(&mut self) {
        self.log("NET: Network change detected (gateway changed)");

        match &self.connection_state {
            ConnectionState::Connected { profile, .. } => {
                self.log(&format!(
                    "NET: VPN '{profile}' still connected — monitoring for disruption"
                ));
            }
            ConnectionState::Disconnected => {
                // If there's a pending auto-reconnect, trigger it now
                if let Some(idx) = self.auto_reconnect_profile {
                    if idx < self.profiles.len() && self.config.auto_reconnect {
                        let name = self.profiles[idx].name.clone();
                        let delay = self.config.auto_reconnect_delay_secs;
                        self.log(&format!(
                            "NET: Network available — auto-reconnecting to '{name}' in {delay}s"
                        ));
                        self.show_toast(
                            format!("Network changed — reconnecting in {delay}s"),
                            ToastType::Info,
                        );

                        let cmd_tx = self.cmd_tx.clone();
                        std::thread::spawn(move || {
                            std::thread::sleep(std::time::Duration::from_secs(delay));
                            let _ = cmd_tx
                                .send(crate::message::Message::RetryConnect { idx, attempt: 1 });
                        });

                        self.retry_count = 1;
                        self.retry_profile_idx = Some(idx);
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_connection_timeout(&mut self, profile_name: String) {
        self.cleanup_vpn_resources(&profile_name);
        self.connection_state = ConnectionState::Disconnected;
        self.session_start = None;
        self.pending_connect = None;
        self.retry_count = 0;
        self.retry_profile_idx = None;
        self.log(&format!("ERR: Connection timed out for '{profile_name}'"));
        self.show_toast(
            format!("Connection timed out for '{profile_name}'"),
            ToastType::Error,
        );
        self.sync_killswitch();
        self.refresh_telemetry();
    }

    fn handle_tick(&mut self) {
        // 1. Connection Timeout Safeguard
        if let ConnectionState::Connecting { started, profile } = &self.connection_state {
            if started.elapsed() > std::time::Duration::from_secs(self.config.connect_timeout) {
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

        // 4. Poll scanner (spawn-on-demand, non-blocking)
        self.poll_scanner();

        // 5. Poll network monitor for gateway changes
        self.poll_network_monitor();

        // 6. Poll network stats (spawn-on-demand, non-blocking)
        self.poll_network_stats();

        // 7. Update network stats history (O(1) ring-buffer rotation)
        self.engine.down_history.pop_front();
        self.engine.up_history.pop_front();
        #[allow(clippy::cast_precision_loss)]
        {
            let down = self.engine.current_down;
            let up = self.engine.current_up;
            self.engine.down_history.push_back(down as f64);
            self.engine.up_history.push_back(up as f64);
        }
    }

    fn handle_open_rename(&mut self) {
        if let Some(idx) = self.profile_list_state.selected() {
            if let Some(profile) = self.profiles.get(idx) {
                let active_profile = match &self.connection_state {
                    ConnectionState::Connected { profile: p, .. }
                    | ConnectionState::Connecting { profile: p, .. }
                    | ConnectionState::Disconnecting { profile: p, .. } => Some(p.as_str()),
                    ConnectionState::Disconnected => None,
                };
                if active_profile == Some(&profile.name) {
                    self.show_toast(
                        "Cannot rename an active profile — disconnect first".to_string(),
                        ToastType::Warning,
                    );
                } else {
                    let name = profile.name.clone();
                    let char_len = name.chars().count();
                    self.input_mode = InputMode::Rename {
                        index: idx,
                        new_name: name,
                        cursor: char_len,
                    };
                }
            }
        }
    }

    fn handle_cycle_log_filter(&mut self) {
        self.log_level_filter = match self.log_level_filter {
            None => Some(crate::logger::LogLevel::Error),
            Some(crate::logger::LogLevel::Error) => Some(crate::logger::LogLevel::Warning),
            Some(crate::logger::LogLevel::Warning) => Some(crate::logger::LogLevel::Info),
            _ => None,
        };
        let label = match self.log_level_filter {
            Some(crate::logger::LogLevel::Error) => "Errors only",
            Some(crate::logger::LogLevel::Warning) => "Warn+Error",
            Some(crate::logger::LogLevel::Info) => "Info+Warn+Error",
            None | Some(_) => "All",
        };
        self.logs_scroll = 0;
        self.logs_auto_scroll = true;
        self.show_toast(format!("Log filter: {label}"), ToastType::Info);
    }
}
