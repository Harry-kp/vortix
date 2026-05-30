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
                    if let Some(profile) = self.runtime.profiles.get(idx) {
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
            Message::ConfirmDefaultRouteTakeover { idx } => {
                self.input_mode = InputMode::Normal;
                if let Some(profile) = self.runtime.profiles.get(idx) {
                    self.log(&format!(
                        "ACTION: Switching active exit to '{}'; both tunnels stay connected",
                        profile.name
                    ));
                }
                // Plan 001 SC3 ("primary inverts"): both tunnels stay
                // connected; the new one claims the kernel default
                // route and the prior primary becomes
                // `Split tunnel (0.0.0.0/0, yielded)` in the registry's
                // role derivation. Symmetric with
                // `ConfirmRouteOverlap` below — neither path
                // disconnects the existing tunnel. The conflict was
                // already surfaced via the overlay, so retry the
                // connect with the `detect_conflict` gate bypassed.
                self.runtime.pending_connect = None;
                self.connect_profile_forced(idx);
            }
            Message::SwitchExclusiveAndConnect { idx } => {
                // User chose the legacy "switch VPNs" path on the
                // takeover overlay: disconnect the current tunnel,
                // queue the new one to fire once teardown completes.
                // This is the pre-multi-tunnel UX preserved as an
                // opt-in `[S]` hotkey for users who don't want both
                // VPNs active at once.
                self.input_mode = InputMode::Normal;
                if let Some(profile) = self.runtime.profiles.get(idx) {
                    self.log(&format!(
                        "ACTION: Disconnecting current tunnel before connecting '{}'",
                        profile.name
                    ));
                }
                self.runtime.pending_connect = Some(idx);
                self.disconnect();
            }
            Message::ConfirmRouteOverlap { idx } => {
                self.input_mode = InputMode::Normal;
                if let Some(profile) = self.runtime.profiles.get(idx) {
                    self.log(&format!(
                        "ACTION: Route-overlap confirmed; connecting '{}'...",
                        profile.name
                    ));
                }
                // Route-overlap does not require a disconnect (R10): both
                // tunnels can stay up; the killswitch synthesiser handles
                // CIDR subtraction. Connect directly with force=true.
                self.connect_profile_forced(idx);
            }
            Message::DisconnectProfile { idx } => self.disconnect_profile_by_idx(idx),
            Message::RequestDisconnectAll => {
                let count = self.active_tunnel_count();
                if count > 1 {
                    self.input_mode = InputMode::ConfirmDisconnectAll {
                        count,
                        confirm_selected: true,
                    };
                } else {
                    // N≤1 is identical-to-`d` semantics; close any overlay
                    // and fall through to the legacy global disconnect.
                    self.disconnect_all_active();
                }
            }
            Message::ConfirmDisconnectAll => {
                self.input_mode = InputMode::Normal;
                self.disconnect_all_active();
            }
            Message::CycleConnectionDetailsFocus => {
                let ids = self.active_tunnel_ids();
                if ids.len() < 2 {
                    return;
                }
                // Resolve the current focus to find the next in stable order.
                let current = self.connection_details_focus.clone().or_else(|| {
                    self.profile_list_state
                        .selected()
                        .and_then(|i| self.runtime.profiles.get(i))
                        .map(|p| crate::vortix_core::profile::ProfileId::new(&p.name))
                });
                let pos = current
                    .as_ref()
                    .and_then(|c| ids.iter().position(|i| i == c));
                let next_idx = match pos {
                    Some(p) => (p + 1) % ids.len(),
                    None => 0,
                };
                let next = ids[next_idx].clone();
                self.log(&format!(
                    "ACTION: Connection Details focus → '{}'",
                    next.as_str()
                ));
                self.connection_details_focus = Some(next);
            }
            Message::CancelConnect { idx } => self.cancel_connect(idx),
            Message::RevertAutoPromote => self.handle_revert_auto_promote(),
            Message::DismissAutoPromoteBanner => {
                self.auto_promote_banner = None;
            }
            Message::ProfileMove(mv) => {
                // Multi-connection plan #001 U19: any sidebar movement
                // clears the Tab-driven Connection Details focus override
                // so the panel stays coherent with the visible row.
                self.connection_details_focus = None;
                match mv {
                    SelectionMove::Next => self.profile_next(),
                    SelectionMove::Prev => self.profile_previous(),
                    SelectionMove::First => self.profile_list_state.select(Some(0)),
                    SelectionMove::Last => {
                        let last = self.runtime.profiles.len().saturating_sub(1);
                        self.profile_list_state.select(Some(last));
                    }
                }
            }

            // Connection
            Message::Disconnect => {
                if matches!(self.legacy_state(), ConnectionState::Disconnecting { .. }) {
                    self.force_disconnect();
                } else {
                    self.disconnect();
                }
            }
            Message::Reconnect => self.reconnect(),
            Message::ConnectSelected => {
                if let Some(idx) = self.profile_list_state.selected() {
                    let target = self.runtime.profiles.get(idx).map(|p| p.name.clone());
                    let legacy = self.legacy_state();
                    match (&legacy, target) {
                        (ConnectionState::Connected { profile, .. }, Some(name))
                            if *profile == name =>
                        {
                            self.runtime.pending_connect = Some(idx);
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
                if idx < self.runtime.profiles.len() {
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
                    .and_then(|i| self.runtime.profiles.get(i))
                    .map(|p| p.name.clone());
                self.runtime.sort_order = self.runtime.sort_order.next();
                self.sort_profiles();
                if let Some(name) = selected_name {
                    if let Some(new_idx) = self.runtime.profiles.iter().position(|p| p.name == name)
                    {
                        self.profile_list_state.select(Some(new_idx));
                    }
                }
                self.show_toast(
                    format!("Sorted: {}", self.runtime.sort_order.label()),
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
            if let Some(profile) = self.runtime.profiles.get(idx) {
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
            if let Some(profile) = self.runtime.profiles.get(idx) {
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
            self.legacy_state(),
            ConnectionState::Disconnecting { profile: ref p, .. } if *p == profile
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
            self.legacy_state(),
            ConnectionState::Connecting { profile: ref p, .. } if *p == profile
        );
        if !still_connecting {
            self.log(&format!(
                "INFO: Ignoring stale ConnectResult for '{profile}' (state changed)"
            ));
        } else if success {
            // Reset this profile's retry / auto-reconnect bookkeeping on
            // success. Other profiles' retry state is untouched (P5b
            // U-P5b-1 per-profile retry).
            self.runtime
                .retry_state
                .remove(&crate::vortix_core::profile::ProfileId::new(&profile));

            let location = self
                .runtime
                .profiles
                .iter()
                .find(|p| p.name == profile)
                .map_or_else(|| "Unknown".to_string(), |p| p.location.clone());

            let now = Instant::now();
            self.runtime.session_start = Some(now);
            let _ = location; // server location is sourced from the catalog in `legacy_state`

            // Plan 001 U6/U7 / P5d: registry is the single source of
            // truth. Push a Connected entry directly; the scanner will
            // refresh kernel-truthful details on its next tick.
            self.mirror_connect_into_registry(&profile, &DetailedConnectionInfo::default(), now);

            if let Some(p) = self.runtime.profiles.iter_mut().find(|p| p.name == profile) {
                p.last_used = Some(std::time::SystemTime::now());
            }
            self.save_metadata();

            self.runtime.last_connected_profile = Some(profile.clone());
            self.log(&format!("STATUS: Connected to '{profile}'"));
            self.refresh_telemetry();

            // KILL SWITCH: Arm when VPN connects
            if self.runtime.killswitch_mode != crate::state::KillSwitchMode::Off {
                self.sync_killswitch();
                self.log("SEC: Kill switch armed");
            }
        } else {
            let err_msg = error.unwrap_or_else(|| "unknown error".to_string());
            self.log(&format!("ERR: Failed to connect '{profile}': {err_msg}"));
            // Plan A.3: mirror the failed attempt into the registry so
            // sidebar renders the `✗` badge until the user retries
            // (which the Connecting mirror will overwrite) or
            // dismisses. Before this, failed connects left no trace
            // in the registry and the sidebar reverted to blank.
            self.mirror_failed_into_registry(&profile, &err_msg);
            self.cleanup_vpn_resources(&profile);

            // Attempt retry with exponential backoff if configured.
            // Per-profile retry (P5b U-P5b-1): each profile's attempt
            // counter lives in runtime.retry_state[profile_id], so a
            // failed connect on A no longer blocks/overwrites a retry on
            // B. The auto_reconnect flag is preserved across attempts so
            // drop-recovery retries keep their identity through their
            // retry budget.
            let max_retries = self.runtime.config.connect_max_retries;
            let profile_id = crate::vortix_core::profile::ProfileId::new(&profile);
            let profile_idx = self.runtime.profiles.iter().position(|p| p.name == profile);
            let current_attempt = self
                .runtime
                .retry_state
                .get(&profile_id)
                .map_or(0, |r| r.attempt);
            let prior_auto = self
                .runtime
                .retry_state
                .get(&profile_id)
                .is_some_and(|r| r.auto_reconnect);

            if let Some(idx) = profile_idx.filter(|_| {
                max_retries > 0
                    && current_attempt < max_retries
                    && self.runtime.pending_connect.is_none()
            }) {
                let attempt = current_attempt + 1;
                self.runtime.retry_state.insert(
                    profile_id.clone(),
                    crate::state::RetryState {
                        attempt,
                        profile_idx: idx,
                        auto_reconnect: prior_auto,
                    },
                );

                let base = self.runtime.config.connect_retry_base_delay_secs;
                let shift = (attempt - 1).min(63);
                let delay_secs = base
                    .saturating_mul(1u64 << shift)
                    .min(self.runtime.config.connect_retry_max_delay_secs);

                self.log(&format!(
                    "RETRY: Attempt {attempt}/{max_retries} for '{profile}' in {delay_secs}s..."
                ));
                self.show_toast(
                    format!("Retrying in {delay_secs}s ({attempt}/{max_retries})"),
                    ToastType::Warning,
                );

                self.runtime.session_start = None;

                let cmd_tx = self.runtime.cmd_tx.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_secs(delay_secs));
                    let _ = cmd_tx.send(crate::message::Message::RetryConnect { idx, attempt });
                });
            } else {
                // No retry: final failure for this profile.
                self.runtime.retry_state.remove(&profile_id);
                self.runtime.session_start = None;
                self.show_toast(format!("Failed to connect: {err_msg}"), ToastType::Error);
                self.runtime.pending_connect = None;
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
            .runtime
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
        self.runtime.killswitch_mode = self.runtime.killswitch_mode.next();

        // Sync state and firewall (may refuse Blocking if not root)
        self.sync_killswitch();

        // If sync_killswitch refused Blocking because we're not root (only
        // possible in AlwaysOn mode when disconnected), preserve the root
        // warning toast instead of overwriting it with the mode toast.
        let blocking_refused = matches!(self.runtime.killswitch_mode, KillSwitchMode::AlwaysOn)
            && !self.runtime.is_root
            && !self.runtime.killswitch_state.is_blocking();

        if !blocking_refused {
            match self.runtime.killswitch_mode {
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
        let active = self.active_tunnels_for_killswitch();
        let persisted_tunnels = crate::core::killswitch::persisted_from_active(&active);
        let _ = crate::core::killswitch::save_state(
            self.runtime.killswitch_mode,
            self.runtime.killswitch_state,
            persisted_tunnels,
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
        let active = self.active_tunnels_for_killswitch();
        let persisted_tunnels = crate::core::killswitch::persisted_from_active(&active);
        let _ = crate::core::killswitch::save_state(
            self.runtime.killswitch_mode,
            self.runtime.killswitch_state,
            persisted_tunnels,
        );
        self.should_quit = true;
    }

    fn handle_telemetry(&mut self, update: TelemetryUpdate) {
        match update {
            TelemetryUpdate::PublicIp(ip) => {
                let is_connected = self.has_active_connection();
                let old_ip = self.runtime.public_ip.clone();

                // Plan 005 U7: emit IpChanged into the journal so the
                // bug-report and downstream subscribers see the trail.
                // Only fires on actual changes, not initial detection.
                if old_ip != ip
                    && old_ip != constants::MSG_FETCHING
                    && old_ip != constants::MSG_DETECTING
                {
                    if let Some(journal) = crate::vortix_core::journal::global_journal() {
                        let _ =
                            journal.append(crate::vortix_core::engine::EngineEvent::IpChanged {
                                old: Some(old_ip.clone()),
                                new: ip.clone(),
                            });
                    }
                }

                // Store as real_ip when disconnected (for security comparison)
                if !is_connected {
                    if self.runtime.real_ip.is_none() {
                        self.log(&format!("NET: Real IP detected: {ip}"));
                    }
                    self.runtime.real_ip = Some(ip.clone());
                } else if self.runtime.public_ip != ip
                    && self.runtime.public_ip != constants::MSG_FETCHING
                {
                    self.runtime.ip_unchanged_warned = false;
                    self.log(&format!("NET: Public IP changed {old_ip} -> {ip}"));
                } else if is_connected
                    && self.runtime.public_ip == ip
                    && self.runtime.public_ip != constants::MSG_FETCHING
                    && !self.runtime.ip_unchanged_warned
                {
                    self.runtime.ip_unchanged_warned = true;
                    self.log(&format!(
                        "WARN: Public IP unchanged ({ip}) while connected — possible leak or split-tunnel"
                    ));
                    if let Some(ref real) = self.runtime.real_ip {
                        if real == &ip {
                            self.log(&format!("ERR: IP leak detected — current IP ({ip}) matches pre-VPN IP ({real})"));
                        }
                    }
                }
                self.runtime.public_ip = ip;
                self.runtime.last_security_check = Some(Instant::now());
            }
            TelemetryUpdate::Latency(ms) => self.runtime.latency_ms = ms,
            TelemetryUpdate::PacketLoss(loss) => {
                self.runtime.packet_loss = loss;
                self.log(&format!("NET: Packet loss: {loss:.1}%"));
            }
            TelemetryUpdate::Jitter(jitter) => {
                self.runtime.jitter_ms = jitter;
                self.log(&format!("NET: Jitter: {jitter}ms"));
            }
            TelemetryUpdate::Location(loc) => {
                if self.runtime.location != loc && self.runtime.location != constants::MSG_DETECTING
                {
                    self.log(&format!("NET: Location: {loc}"));
                }
                self.runtime.location = loc;
            }
            TelemetryUpdate::Isp(isp) => {
                if self.runtime.isp != isp && self.runtime.isp != constants::MSG_DETECTING {
                    self.log(&format!("NET: Exit node: {isp}"));
                }
                self.runtime.isp = isp;
            }
            TelemetryUpdate::Dns(dns) => {
                if !self.has_active_connection() {
                    if self.runtime.real_dns.is_none() {
                        self.log(&format!("NET: Pre-VPN DNS: {dns}"));
                    }
                    self.runtime.real_dns = Some(dns.clone());
                } else if self.runtime.dns_server != dns
                    && self.runtime.dns_server != constants::MSG_NO_DATA
                {
                    self.log(&format!("SEC: DNS server: {dns}"));
                }
                self.runtime.dns_server = dns;
                self.runtime.last_security_check = Some(Instant::now());
            }
            TelemetryUpdate::Ipv6Leak(leak) => {
                if self.runtime.ipv6_leak != leak {
                    if leak {
                        self.log("WARN: IPv6 leak detected — traffic may bypass VPN tunnel");
                    } else {
                        self.log("SEC: IPv6 secure (blocked)");
                    }
                }
                self.runtime.ipv6_leak = leak;
                self.runtime.last_security_check = Some(Instant::now());
            }
            TelemetryUpdate::Log(level, msg) => {
                logger::log(level, "TELEMETRY", msg);
            }
        }
    }

    /// Per-profile scanner — reconcile every registry entry against the
    /// scanner's active sessions.
    ///
    /// Each profile is processed independently: a drop on tunnel A no
    /// longer blocks observing the (also dropped) tunnel B. Auto-adoption
    /// (D-4) registers externally-started VPNs at the end of the pass.
    ///
    /// The registry is the single source of truth — all transitions go
    /// through `set_connected` / `set_disconnected` / `set_disconnecting`
    /// / `set_failed` here. The few residual single-tunnel-shaped reads
    /// (kill-switch sync, scanner-dispatch helpers) consult
    /// [`App::legacy_state`], a derived view from the registry primary.
    fn handle_sync_system_state(&mut self, active: Vec<ActiveSession>) {
        use crate::vortix_core::engine::state::Connection;
        use crate::vortix_core::profile::ProfileId;
        use std::collections::HashSet;
        use std::time::SystemTime;

        let snapshots = self.registry.snapshot_all();
        let session_count = active.len();
        let mut handled: HashSet<ProfileId> = HashSet::new();

        for snap in &snapshots {
            let profile_name = snap.profile_id.as_str().to_string();
            handled.insert(snap.profile_id.clone());
            let matching_session = active.iter().find(|s| s.name == profile_name);

            match (&snap.state, matching_session) {
                (Connection::Disconnecting { .. }, None) => {
                    self.complete_disconnect(&profile_name);
                }
                (Connection::Disconnecting { started_at, .. }, Some(_)) => {
                    let elapsed = SystemTime::now()
                        .duration_since(*started_at)
                        .unwrap_or_default()
                        .as_secs();
                    if elapsed >= self.runtime.config.disconnect_timeout {
                        self.scanner_force_disconnect(&profile_name);
                    }
                }
                (Connection::Connecting { started_at, .. }, Some(session)) => {
                    self.scanner_promote_to_connected(&profile_name, session);
                    let _ = started_at; // elapsed not needed on success path
                }
                (Connection::Connecting { started_at, .. }, None) => {
                    let elapsed = SystemTime::now()
                        .duration_since(*started_at)
                        .unwrap_or_default()
                        .as_secs();
                    if elapsed > 0 && elapsed % constants::SCANNER_LOG_INTERVAL_SECS == 0 {
                        self.log(&format!(
                            "NET: Scanner: no tunnel interface for '{profile_name}' yet \
                             ({elapsed}s elapsed, {} active session{})",
                            session_count,
                            if session_count == 1 { "" } else { "s" }
                        ));
                    }
                }
                (Connection::Connected { .. }, Some(session)) => {
                    self.scanner_refresh_connected(&profile_name, session);
                }
                (
                    Connection::Connected { .. }
                    | Connection::Reconnecting { .. }
                    | Connection::AwaitingUserInput { .. },
                    None,
                ) => {
                    let was_connected = matches!(snap.state, Connection::Connected { .. });
                    self.scanner_handle_drop(&profile_name, was_connected);
                }
                (Connection::Disconnected { .. }, _) => {
                    // Historic marker (post-failure entry kept for the
                    // ✗ badge). Scanner never auto-promotes these — the
                    // user must retry or dismiss.
                }
                (
                    Connection::Reconnecting { .. } | Connection::AwaitingUserInput { .. },
                    Some(_),
                ) => {
                    // These FSM states aren't currently driven by the
                    // App's connect flow (reserved for plan 008 U2
                    // interactive prompts and FSM auto-reconnect). If
                    // they ever materialize alongside an active
                    // kernel session, treat as a refresh — the kernel
                    // is the truth.
                    if let Some(session) = matching_session {
                        self.scanner_refresh_connected(&profile_name, session);
                    }
                }
            }
        }

        // Auto-adopt (D-4): sessions not represented in the registry
        // that match a catalog profile. Externally-started VPNs
        // (`wg-quick up X` outside vortix) get registered here on the
        // next scanner tick so the TUI shows them.
        for session in &active {
            let pid = ProfileId::new(&session.name);
            if !handled.contains(&pid)
                && self.runtime.profiles.iter().any(|p| p.name == session.name)
            {
                self.scanner_adopt_session(session);
            }
        }
    }

    /// Scanner helper (P5b U-P5b-2): force-cleanup a profile stuck in
    /// the Disconnecting state past `disconnect_timeout`. The kernel
    /// interface is still up but the teardown isn't returning;
    /// surface a forced-cleanup toast and drop the entry from the
    /// registry. Mirrors the legacy timeout path.
    fn scanner_force_disconnect(&mut self, profile_name: &str) {
        self.log(&format!(
            "WARN: Disconnect timed out for '{profile_name}' after {}s, forcing cleanup",
            self.runtime.config.disconnect_timeout
        ));
        self.cleanup_vpn_resources(profile_name);
        self.runtime.pending_connect = None;
        if self.legacy_matches(profile_name) {
            self.runtime.session_start = None;
        }
        self.mirror_disconnect_into_registry(profile_name);
        self.show_toast(
            "Disconnect timed out — forced cleanup".to_string(),
            ToastType::Warning,
        );
        self.sync_killswitch();
    }

    /// Scanner helper (P5b U-P5b-2): promote a `Connecting` profile to
    /// `Connected` once the kernel interface appears. Mirrors the
    /// legacy `Connecting` → `Connected` branch including kill-switch
    /// arm, `last_used` update, and metadata save.
    fn scanner_promote_to_connected(&mut self, profile_name: &str, session: &ActiveSession) {
        let start_time = session
            .started_at
            .and_then(|real| {
                std::time::SystemTime::now()
                    .duration_since(real)
                    .ok()
                    .and_then(|d| Instant::now().checked_sub(d))
            })
            .unwrap_or_else(Instant::now);

        // Track session_start for telemetry uptime when this profile
        // is what the App considers primary (registry's primary, or
        // any in-flight tunnel when none is primary yet).
        if self.legacy_matches(profile_name) || self.legacy_is_disconnected() {
            self.runtime.session_start = Some(start_time);
        }
        // Push to registry directly from session details (single
        // source of truth post-P5d).
        self.refresh_registry_from_session(profile_name, session);

        self.log(&format!(
            "STATUS: Connection established to '{profile_name}'"
        ));

        if self.runtime.killswitch_mode != crate::state::KillSwitchMode::Off {
            self.sync_killswitch();
            self.log("SEC: Kill switch armed");
        }

        if let Some(profile) = self
            .runtime
            .profiles
            .iter_mut()
            .find(|p| p.name == profile_name)
        {
            profile.last_used = Some(std::time::SystemTime::now());
        }
        self.save_metadata();
    }

    /// Scanner helper (P5b U-P5b-2): refresh kernel-reported details
    /// on an existing Connected entry. Resyncs session-start drift
    /// and updates the registry; updates the legacy state only if it
    /// already tracks this profile.
    fn scanner_refresh_connected(&mut self, profile_name: &str, session: &ActiveSession) {
        // Drift correction for session_start when this profile is the
        // primary (or sole) active tunnel. Other multi-tunnel cases
        // don't affect session_start since that's a single-slot field.
        if self.legacy_matches(profile_name) {
            if let Some(real) = session.started_at {
                if let Ok(duration) = std::time::SystemTime::now().duration_since(real) {
                    let calculated_start = Instant::now()
                        .checked_sub(duration)
                        .unwrap_or(Instant::now());
                    let drift = self
                        .runtime
                        .session_start
                        .map_or(0u64, |s| s.elapsed().as_secs().abs_diff(duration.as_secs()));
                    if drift > constants::SESSION_TIME_DRIFT_SECS {
                        self.runtime.session_start = Some(calculated_start);
                    }
                }
            }
        }
        // Push kernel-truthful details to the registry — single source
        // of truth after P5d.
        self.refresh_registry_from_session(profile_name, session);
    }

    /// Scanner helper (P5b U-P5b-2): handle drop detection for a
    /// profile that has a Connected/Connecting/Reconnecting/Awaiting
    /// registry entry but no matching kernel session. Mirrors the
    /// legacy drop path including `connection_drops` counter, kill
    /// switch activation, and per-profile auto-reconnect scheduling.
    fn scanner_handle_drop(&mut self, profile_name: &str, was_connected: bool) {
        if was_connected {
            self.runtime.connection_drops += 1;
            self.log(&format!(
                "WARN: Connection dropped from '{}' (#{} this session)",
                profile_name, self.runtime.connection_drops
            ));
        } else if self.legacy_matches_disconnecting(profile_name) {
            self.log(&format!("STATUS: Disconnected from '{profile_name}'"));
        } else if self.legacy_matches_connecting(profile_name) {
            self.log(&format!(
                "WARN: Connection to '{profile_name}' failed or was cancelled"
            ));
        } else {
            // No legacy match — log the secondary drop generically.
            self.log(&format!(
                "WARN: Secondary tunnel '{profile_name}' no longer present"
            ));
        }

        utils::cleanup_openvpn_run_files(profile_name);

        if self.legacy_matches(profile_name) {
            self.runtime.session_start = None;
        }
        self.mirror_disconnect_into_registry(profile_name);

        // KILL SWITCH: activate on unexpected drop of any Connected
        // tunnel. Multi-tunnel: any tunnel dropping triggers the
        // existing killswitch policy.
        if was_connected
            && self.runtime.killswitch_mode != crate::state::KillSwitchMode::Off
            && self.runtime.killswitch_state == crate::state::KillSwitchState::Armed
        {
            self.runtime.killswitch_state = crate::state::KillSwitchState::Blocking;
            self.sync_killswitch();
            self.log("SEC: Kill switch ACTIVATED - blocking traffic");
            self.show_toast(
                "VPN dropped! Kill Switch blocking traffic".to_string(),
                ToastType::Error,
            );
        }

        // AUTO-RECONNECT: per-profile (P5b U-P5b-1 / D-2). Each dropped
        // Connected tunnel schedules its own retry; multiple drops can
        // recover concurrently.
        if was_connected && self.runtime.config.auto_reconnect {
            if let Some(idx) = self
                .runtime
                .profiles
                .iter()
                .position(|p| p.name == profile_name)
            {
                let delay = self.runtime.config.auto_reconnect_delay_secs;
                let max = self.runtime.config.connect_max_retries;
                self.log(&format!(
                    "NET: Auto-reconnect scheduled for '{profile_name}' in {delay}s (max {max} retries)"
                ));
                self.show_toast(
                    format!("VPN dropped — reconnecting in {delay}s"),
                    ToastType::Warning,
                );

                let profile_id = crate::vortix_core::profile::ProfileId::new(profile_name);
                self.runtime.retry_state.insert(
                    profile_id,
                    crate::state::RetryState {
                        attempt: 1,
                        profile_idx: idx,
                        auto_reconnect: true,
                    },
                );

                let cmd_tx = self.runtime.cmd_tx.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_secs(delay));
                    let _ = cmd_tx.send(crate::message::Message::RetryConnect { idx, attempt: 1 });
                });
            }
        }
    }

    /// Scanner helper (P5b U-P5b-2 / D-4): adopt an externally-started
    /// VPN session into the registry. Triggered when scanner sees an
    /// active session for a catalog profile not currently in the
    /// registry — e.g., the user ran `wg-quick up X` outside vortix,
    /// or vortix restarted while a tunnel was already up.
    fn scanner_adopt_session(&mut self, session: &ActiveSession) {
        let profile_name = session.name.clone();

        let start_time = if let Some(real) = session.started_at {
            if let Ok(duration) = std::time::SystemTime::now().duration_since(real) {
                Instant::now()
                    .checked_sub(duration)
                    .unwrap_or(Instant::now())
            } else {
                Instant::now()
            }
        } else {
            self.runtime.session_start.unwrap_or(Instant::now())
        };

        // First-tunnel adoption (Disconnected slot or this profile
        // already in flight) updates session_start + logs the
        // establishment; secondary tunnels just register silently.
        let claim_primary_slot = self.legacy_is_disconnected()
            || self.legacy_matches_connecting(&profile_name)
            || self.legacy_matches_disconnecting(&profile_name);
        if claim_primary_slot {
            if self.runtime.session_start.is_none() {
                self.log(&format!(
                    "STATUS: Connection established to '{profile_name}'"
                ));
                if session.started_at.is_some() {
                    self.log("INFO: Synced uptime with system process.");
                }
                self.log("INFO: Waiting for telemetry...");
            }
            self.runtime.session_start = Some(start_time);
        } else {
            self.log(&format!(
                "INFO: Adopting externally-started tunnel '{profile_name}' as a secondary"
            ));
        }
        self.refresh_registry_from_session(&profile_name, session);
    }

    /// Whether the derived single-tunnel view refers to the given
    /// profile in any non-Disconnected variant. Post-P5d this reads
    /// the registry primary (or first non-Disconnected entry) instead
    /// of a stored field.
    pub(crate) fn legacy_matches(&self, profile_name: &str) -> bool {
        match self.legacy_state() {
            ConnectionState::Connected { profile, .. }
            | ConnectionState::Connecting { profile, .. }
            | ConnectionState::Disconnecting { profile, .. } => profile == profile_name,
            ConnectionState::Disconnected => false,
        }
    }

    pub(crate) fn legacy_matches_connecting(&self, profile_name: &str) -> bool {
        matches!(
            self.legacy_state(),
            ConnectionState::Connecting { profile, .. } if profile == profile_name
        )
    }

    pub(crate) fn legacy_matches_disconnecting(&self, profile_name: &str) -> bool {
        matches!(
            self.legacy_state(),
            ConnectionState::Disconnecting { profile, .. } if profile == profile_name
        )
    }

    pub(crate) fn legacy_is_disconnected(&self) -> bool {
        matches!(self.legacy_state(), ConnectionState::Disconnected)
    }

    fn handle_retry_connect(&mut self, idx: usize, attempt: u32) {
        // Per-profile retry (P5b U-P5b-1): stale check by profile_id.
        // The message carries `idx` for backwards compatibility; we
        // resolve it to the profile's id and verify the retry_state
        // entry still matches before firing.
        let profile_id_for_idx = self
            .runtime
            .profiles
            .get(idx)
            .map(|p| crate::vortix_core::profile::ProfileId::new(&p.name));

        let entry_matches = profile_id_for_idx
            .as_ref()
            .and_then(|pid| self.runtime.retry_state.get(pid))
            .is_some_and(|r| r.profile_idx == idx && r.attempt == attempt);

        if !entry_matches {
            self.log(&format!(
                "INFO: Ignoring stale RetryConnect (attempt {attempt}, idx {idx})"
            ));
            return;
        }
        // Don't retry if a tunnel is now in-flight on any profile.
        if self.active_tunnel_count() > 0 {
            self.log("INFO: Skipping retry — connection state changed");
            if let Some(pid) = &profile_id_for_idx {
                self.runtime.retry_state.remove(pid);
            }
            return;
        }
        if let Some(profile) = self.runtime.profiles.get(idx) {
            let max = self.runtime.config.connect_max_retries;
            self.log(&format!(
                "RETRY: Attempting reconnect to '{}' ({attempt}/{max})",
                profile.name
            ));
            self.connect_profile(idx);
        } else if let Some(pid) = &profile_id_for_idx {
            self.runtime.retry_state.remove(pid);
        }
    }

    fn handle_network_changed(&mut self) {
        self.log("NET: Network change detected (gateway changed)");

        let legacy = self.legacy_state();
        match &legacy {
            ConnectionState::Connected { profile, .. } => {
                self.log(&format!(
                    "NET: VPN '{profile}' still connected — monitoring for disruption"
                ));
            }
            ConnectionState::Disconnected => {
                // Re-trigger any auto-reconnect entries now that the
                // network is back. Per-profile (P5b U-P5b-1 / D-2):
                // every profile with auto_reconnect=true gets its
                // RetryConnect re-fired — disjoint tunnels can recover
                // in parallel without contending for a single slot.
                if !self.runtime.config.auto_reconnect {
                    return;
                }
                let to_retry: Vec<(usize, String)> = self
                    .runtime
                    .retry_state
                    .values()
                    .filter(|r| r.auto_reconnect)
                    .filter_map(|r| {
                        self.runtime
                            .profiles
                            .get(r.profile_idx)
                            .map(|p| (r.profile_idx, p.name.clone()))
                    })
                    .collect();
                let delay = self.runtime.config.auto_reconnect_delay_secs;
                for (idx, name) in to_retry {
                    let pid = crate::vortix_core::profile::ProfileId::new(&name);
                    self.log(&format!(
                        "NET: Network available — auto-reconnecting to '{name}' in {delay}s"
                    ));
                    self.show_toast(
                        format!("Network changed — reconnecting in {delay}s"),
                        ToastType::Info,
                    );

                    let cmd_tx = self.runtime.cmd_tx.clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(std::time::Duration::from_secs(delay));
                        let _ =
                            cmd_tx.send(crate::message::Message::RetryConnect { idx, attempt: 1 });
                    });

                    self.runtime.retry_state.insert(
                        pid,
                        crate::state::RetryState {
                            attempt: 1,
                            profile_idx: idx,
                            auto_reconnect: true,
                        },
                    );
                }
            }
            _ => {}
        }
    }

    fn handle_connection_timeout(&mut self, profile_name: String) {
        self.cleanup_vpn_resources(&profile_name);
        let profile_id = crate::vortix_core::profile::ProfileId::new(&profile_name);
        self.runtime.session_start = None;
        self.runtime.pending_connect = None;
        self.runtime.retry_state.remove(&profile_id);
        // Drop the in-flight registry entry so the renderers stop
        // showing the phantom Connecting state.
        self.registry.set_disconnected(&profile_id);
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
        if let ConnectionState::Connecting { started, profile } = self.legacy_state() {
            if started.elapsed()
                > std::time::Duration::from_secs(self.runtime.config.connect_timeout)
            {
                self.handle_message(Message::ConnectionTimeout(profile));
            }
        }
        // 1b. Multi-connection plan #001 U19 (D-3): detect primary-tunnel
        //     transitions and fire / expire the auto-promote banner.
        self.detect_primary_change_for_banner();
        if let Some(banner) = &self.auto_promote_banner {
            if banner.is_expired() {
                self.auto_promote_banner = None;
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
        self.runtime.down_history.pop_front();
        self.runtime.up_history.pop_front();
        #[allow(clippy::cast_precision_loss)]
        {
            let down = self.runtime.current_down;
            let up = self.runtime.current_up;
            self.runtime.down_history.push_back(down as f64);
            self.runtime.up_history.push_back(up as f64);
        }
    }

    fn handle_open_rename(&mut self) {
        if let Some(idx) = self.profile_list_state.selected() {
            if let Some(profile) = self.runtime.profiles.get(idx) {
                let profile_name = profile.name.clone();
                if self.is_profile_active(&profile_name) {
                    self.show_toast(
                        "Cannot rename an active profile — disconnect first".to_string(),
                        ToastType::Warning,
                    );
                } else {
                    let char_len = profile_name.chars().count();
                    self.input_mode = InputMode::Rename {
                        index: idx,
                        new_name: profile_name,
                        cursor: char_len,
                    };
                }
            }
        }
    }

    /// Multi-connection plan #001 U19 (D-3): poll the registry's current
    /// primary against `last_known_primary` and fire the auto-promote
    /// banner toast on a `Some(old) -> Some(new)` transition triggered by
    /// a prior-primary disconnect. We approximate the
    /// `PrimaryChangeReason::PriorPrimaryDisconnected` heuristic by
    /// checking that the previous primary's snapshot is now Disconnected
    /// (or absent from the registry entirely) — that catches the user-
    /// initiated disconnect case the plan targets and avoids firing on
    /// `InitialConnect` (no prior primary) or `ExternalRouteChange`
    /// (previous primary still up, route flapped).
    fn detect_primary_change_for_banner(&mut self) {
        use crate::vortix_core::engine::state::Connection;
        let current = self.registry.primary().cloned();
        if current == self.last_known_primary {
            return;
        }
        let previous = self.last_known_primary.clone();
        self.last_known_primary.clone_from(&current);

        // Only fire on Some(old) -> Some(new); no-primary transitions and
        // initial-connect transitions are silent.
        let (Some(old), Some(new)) = (previous, current) else {
            return;
        };
        if old == new {
            return;
        }

        // Heuristic: the prior primary should have just disconnected
        // (snapshot is Disconnected or gone). When the prior primary is
        // still active this is an `ExternalRouteChange`-shaped transition
        // and the banner is not appropriate.
        let prior_active = self
            .registry
            .snapshot(&old)
            .is_some_and(|s| !matches!(s.state, Connection::Disconnected { .. }));
        if prior_active {
            return;
        }

        let banner_msg = format!(
            "Promoted '{}' to primary because '{}' disconnected — [u] to revert ({}s)",
            new.as_str(),
            old.as_str(),
            crate::state::AUTO_PROMOTE_REVERT_WINDOW_SECS,
        );
        self.log(&format!("STATUS: {banner_msg}"));
        self.auto_promote_banner = Some(crate::state::AutoPromoteBanner::new(old, new));
        // Surface the message through the existing toast channel so users
        // see it even if the banner widget hasn't rendered yet (U17 owns
        // banner painting; U19 wires the data flow).
        self.show_toast(banner_msg, ToastType::Warning);
    }

    /// Multi-connection plan #001 U19 (D-3): revert an auto-promotion.
    /// Reconnects the old primary (re-fires the takeover overlay because
    /// the new primary now holds the default route) and clears the
    /// banner. The actual demotion of the new tunnel is the user's
    /// implicit choice when they confirm the takeover overlay.
    fn handle_revert_auto_promote(&mut self) {
        let Some(banner) = self.auto_promote_banner.take() else {
            return;
        };
        let old_name = banner.from.as_str().to_string();
        let new_name = banner.to.as_str().to_string();
        self.log(&format!(
            "ACTION: Reverting auto-promotion — reconnecting '{old_name}' (demoting '{new_name}' if eligible)"
        ));

        // Find the old primary by name; route it through the existing
        // connect path so the conflict gate fires (the new primary holds
        // 0/0 now, so ConfirmDefaultRouteTakeover is the expected overlay).
        if let Some(idx) = self
            .runtime
            .profiles
            .iter()
            .position(|p| p.name == old_name)
        {
            self.connect_profile(idx);
        } else {
            self.show_toast(
                format!("Cannot revert — profile '{old_name}' not found"),
                ToastType::Error,
            );
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
