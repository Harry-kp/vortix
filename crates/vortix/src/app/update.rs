//! Central message dispatcher (TEA-style update function).
//!
//! Private handler methods receive owned values destructured from the `Message` enum.
#![allow(clippy::needless_pass_by_value)]

use std::time::{Duration, Instant};

use super::{App, ConnectionState, FocusedPanel, InputMode, Protocol, ToastType};
use crate::constants;
use crate::core::telemetry::TelemetryUpdate;
use crate::logger;
use crate::message::{Message, ScrollMove, SelectionMove};
use crate::utils;

/// A `Message` handler taking longer than this is treated as a UI-thread
/// stutter and surfaced via `tracing::warn`. Threshold is empirically the
/// point at which keystrokes start to feel "queued" rather than instant
/// — ~50ms is one render frame at 20fps. Production binaries log at this
/// threshold via `RUST_LOG=vortix::app=warn`; the value is silent otherwise.
const UI_HANDLER_SLOW_THRESHOLD: Duration = Duration::from_millis(50);

/// Extract the variant name (without the payload) from a `Message` for
/// observability. `format!("{msg:?}")` produces `"NextPanel"` for unit
/// variants, `"ConnectResult { ... }"` for struct variants, etc. — we
/// want just the name so `tracing` events are aggregatable.
fn message_variant_label(msg: &Message) -> String {
    if matches!(msg, Message::BackgroundDiagnosticsLoaded(_)) {
        return "BackgroundDiagnosticsLoaded".into();
    }
    let s = format!("{msg:?}");
    s.split_once([' ', '(', '{'])
        .map_or(s.clone(), |(prefix, _)| prefix.to_string())
}

impl App {
    /// Handle a message from the action menu or other sources
    #[allow(clippy::too_many_lines)]
    pub fn handle_message(&mut self, msg: crate::message::Message) {
        // Slow-handler observability. The UI thread runs every
        // `handle_message` synchronously, so anything that ties it up
        // for more than ~50ms is likely to manifest as visible TUI
        // stutter. We log via `tracing::warn` (silent by default;
        // surface with `RUST_LOG=vortix::app=warn`) so production
        // binaries don't spam stderr but operators investigating a
        // performance complaint can turn on observability without a
        // rebuild.
        let started = std::time::Instant::now();
        let variant_label = message_variant_label(&msg);
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
                        let content = std::fs::read_to_string(&profile.config_path)
                            .unwrap_or_else(|e| format!("Error reading config: {e}"));
                        // Build the highlighted-lines + total-lines cache
                        // once here; aggressive scrolling later reads from
                        // this cache instead of re-parsing the file every
                        // keystroke (see `CachedConfigView` doc).
                        self.cached_config = Some(super::CachedConfigView::from_content(content));
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
                // The "primary inverts" scenario: both tunnels stay
                // connected; the new one claims the kernel default
                // route and the prior primary becomes
                // `Split tunnel (0.0.0.0/0, yielded)` in the registry's
                // role derivation. Symmetric with
                // `ConfirmRouteOverlap` below — neither path
                // disconnects the existing tunnel. The conflict was
                // already surfaced via the overlay, so retry the
                // connect with the `detect_conflict` gate bypassed.
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
                if let Some(profile_id) = self
                    .runtime
                    .profiles
                    .get(idx)
                    .map(|profile| profile.id.clone())
                {
                    self.issue_control_command(
                        crate::vortix_core::control::UserCommand::ConnectExclusive { profile_id },
                    );
                }
            }
            Message::ConfirmRouteOverlap { idx } => {
                self.input_mode = InputMode::Normal;
                if let Some(profile) = self.runtime.profiles.get(idx) {
                    self.log(&format!(
                        "ACTION: Route-overlap confirmed; connecting '{}'...",
                        profile.name
                    ));
                }
                // Route-overlap does not require a disconnect: both
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
            Message::CancelConnect { idx } => self.cancel_connect(idx),
            Message::ProfileMove(mv) => match mv {
                SelectionMove::Next => self.profile_next(),
                SelectionMove::Prev => self.profile_previous(),
                SelectionMove::First => self.profile_list_state.select(Some(0)),
                SelectionMove::Last => {
                    let last = self.runtime.profiles.len().saturating_sub(1);
                    self.profile_list_state.select(Some(last));
                }
            },

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
                            if let Some(profile_id) = self
                                .runtime
                                .profiles
                                .get(idx)
                                .map(|profile| profile.id.clone())
                            {
                                self.issue_control_command(
                                    crate::vortix_core::control::UserCommand::Reconnect {
                                        profile_id: Some(profile_id),
                                    },
                                );
                            }
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
                ) {
                    self.flip_state_mut(panel).flip();
                }
            }
            Message::OpenBackgroundSetup => {
                self.input_mode = InputMode::BackgroundSetup {
                    state: crate::background::BackgroundOverlayState::new(
                        crate::background::BackgroundWorkflow::Setup,
                    ),
                };
            }
            Message::OpenBackgroundStatus => {
                self.input_mode = InputMode::BackgroundSetup {
                    state: crate::background::BackgroundOverlayState::new(
                        crate::background::BackgroundWorkflow::Status,
                    ),
                };
            }
            Message::OpenBackgroundRecover => {
                self.input_mode = InputMode::BackgroundSetup {
                    state: crate::background::BackgroundOverlayState::new(
                        crate::background::BackgroundWorkflow::Recover,
                    ),
                };
            }
            Message::OpenBackgroundDisable => {
                self.input_mode = InputMode::BackgroundSetup {
                    state: crate::background::BackgroundOverlayState::new(
                        crate::background::BackgroundWorkflow::Disable,
                    ),
                };
            }
            Message::OpenBackgroundDiagnostics => self.open_background_diagnostics(),
            Message::BackgroundDiagnosticsLoaded(result) => {
                self.background_diagnostics_loading = false;
                match result {
                    Ok(view) => self.log_batch(&background_diagnostic_log_lines(&view)),
                    Err(error) => self.log(&format!(
                        "BACKGROUND: diagnostics unavailable ({error}); status remains Standard and no authority claim was made"
                    )),
                }
            }
            Message::ConfirmBackgroundAction => {
                let workflow = match &self.input_mode {
                    InputMode::BackgroundSetup { state } => Some(state.workflow),
                    _ => None,
                };
                if workflow != Some(crate::background::BackgroundWorkflow::Status) {
                    self.show_toast(
                        "Background enrollment is not enabled in this release; Standard mode is unchanged".into(),
                        ToastType::Info,
                    );
                }
                self.input_mode = InputMode::Normal;
            }
            Message::CloseOverlay => {
                if let Some(challenge_id) = self.control_challenge.take() {
                    if let Some(control) = &self.control_session {
                        if let Err(error) = control.cancel_challenge(challenge_id) {
                            self.log(&format!("WARN: Could not cancel challenge: {error}"));
                        }
                    }
                }
                self.show_config = false;
                self.cached_config = None;
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
                otp,
                save,
                connect_after,
            } => self.handle_auth_submit(idx, username, password, otp, save, connect_after),

            Message::CycleSortOrder => {
                let selected_name = self
                    .profile_list_state
                    .selected()
                    .and_then(|i| self.runtime.profiles.get(i))
                    .map(|p| p.name.clone());
                self.runtime.sort_order = self.runtime.sort_order.next();
                self.runtime.sort_profiles();
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
                self.input_mode = InputMode::Help {
                    scroll: 0,
                    tab: crate::state::HelpTab::default(),
                };
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
            Message::ControlSnapshot(snapshot) => self.apply_control_snapshot(*snapshot),
            Message::Tick => self.handle_tick(),
            Message::Resize(width, height) => {
                self.terminal_size = (width, height);
            }
        }
        let elapsed = started.elapsed();
        if elapsed > UI_HANDLER_SLOW_THRESHOLD {
            tracing::warn!(
                target: "vortix::app",
                variant = variant_label,
                elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                "ui-handler slow: a Message handler blocked the UI thread for longer than the perceptible-stutter threshold"
            );
        }
    }

    fn open_background_diagnostics(&mut self) {
        self.focused_panel = FocusedPanel::Logs;
        self.logs_auto_scroll = true;
        if self.background_diagnostics_loading {
            self.show_toast(
                "Background diagnostics are already loading".into(),
                ToastType::Info,
            );
            return;
        }
        self.background_diagnostics_loading = true;
        self.log("BACKGROUND: loading redacted diagnostics");
        let socket = crate::daemon::daemon_socket_path_override()
            .unwrap_or_else(crate::daemon::default_socket_path);
        let fallback = self
            .runtime
            .config_dir
            .join("control")
            .join("diagnostics.json");
        let allow_fallback = self.background_diagnostics_fallback;
        let tx = self.runtime.cmd_tx.clone();
        std::thread::spawn(move || {
            let result = crate::background::load_diagnostics(
                &socket,
                &fallback,
                allow_fallback,
                crate::daemon::diagnostics::unix_millis(),
            )
            .map(Box::new)
            .map_err(|error| error.to_string());
            let _ = tx.send(Message::BackgroundDiagnosticsLoaded(result));
        });
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
                    // Pre-fill with existing credentials if saved. ManageAuth
                    // is save-only (`connect_after: false`) so we DO NOT
                    // surface the OTP field even on static-challenge profiles:
                    // (1) the OTP is single-use and expires in ~30s, so
                    // pre-saving has no value; (2) the submit handler writes
                    // a `.scrv1.auth` bundle whenever `otp.is_some()`, and
                    // without a connect path consuming it that bundle would
                    // persist on disk with the plaintext OTP until the next
                    // startup scrub -- a real leak window. Setting
                    // static_challenge_prompt=None here keeps the overlay at
                    // 2 fields (Username/Password) and forces `otp = None`
                    // in the AuthSubmit message.
                    let (username, password) =
                        utils::read_openvpn_saved_auth_compat(profile.id.as_str(), &profile.name)
                            .unwrap_or_default();
                    let username_cursor = username.len();
                    let password_cursor = password.len();
                    self.input_mode = InputMode::AuthPrompt {
                        profile_idx: idx,
                        profile_name: profile.name.clone(),
                        username,
                        username_cursor,
                        password,
                        password_cursor,
                        otp: String::new(),
                        otp_cursor: 0,
                        focused_field: crate::state::AuthField::Username,
                        save_credentials: true,
                        connect_after: false,
                        static_challenge_prompt: None,
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
                let profile_id = profile.id.clone();
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
                } else if utils::read_openvpn_saved_auth_compat(profile_id.as_str(), &name)
                    .is_none()
                {
                    self.show_toast(
                        format!("No saved credentials for '{name}'"),
                        ToastType::Info,
                    );
                } else {
                    utils::delete_openvpn_auth_file_compat(profile_id.as_str(), &name);
                    self.log(&format!("AUTH: Cleared saved credentials for '{name}'"));
                    self.show_toast(
                        format!("Credentials cleared for '{name}'"),
                        ToastType::Success,
                    );
                }
            }
        }
    }
    fn handle_auth_submit(
        &mut self,
        idx: usize,
        username: String,
        password: String,
        otp: Option<String>,
        save: bool,
        connect_after: bool,
    ) {
        if let Some(challenge_id) = self.control_challenge {
            if save {
                let Some(profile) = self.runtime.profiles.get(idx) else {
                    self.show_toast(
                        "Challenge profile is unavailable".to_string(),
                        ToastType::Error,
                    );
                    return;
                };
                if let Err(error) =
                    utils::write_openvpn_auth_file(profile.id.as_str(), &username, &password)
                {
                    self.show_toast(
                        format!("Failed to save credentials: {error}"),
                        ToastType::Error,
                    );
                    return;
                }
            }
            let answer = otp.filter(|answer| !answer.trim().is_empty());
            let payload = crate::vortix_core::control::Secret::openvpn_credentials(
                &username,
                &password,
                answer.as_deref(),
            )
            .into_vec();
            let result = self
                .control_session
                .as_ref()
                .expect("service challenge requires attached control session")
                .respond_challenge(challenge_id, payload);
            match result {
                Ok(()) => {
                    self.control_challenge = None;
                    self.input_mode = InputMode::Normal;
                    self.log("AUTH: Submitted service-owned challenge response");
                }
                Err(error) => self.show_toast(
                    format!("Challenge response failed: {error}"),
                    ToastType::Error,
                ),
            }
            return;
        }

        let Some(profile) = self.runtime.profiles.get(idx) else {
            self.show_toast("Invalid profile index".to_string(), ToastType::Error);
            return;
        };
        if connect_after {
            self.show_toast(
                "The connection challenge expired; start the connection again".to_string(),
                ToastType::Warning,
            );
            self.input_mode = InputMode::Normal;
            return;
        }
        if let Err(error) =
            utils::write_openvpn_auth_file(profile.id.as_str(), &username, &password)
        {
            self.show_toast(
                format!("Failed to save credentials: {error}"),
                ToastType::Error,
            );
            return;
        }
        let profile_name = profile.name.clone();
        self.input_mode = InputMode::Normal;
        self.log(&format!("AUTH: Saved credentials for '{profile_name}'"));
        self.show_toast(
            format!("Credentials updated for '{profile_name}'"),
            ToastType::Success,
        );
    }
    fn handle_toggle_killswitch(&mut self) {
        if self.control_session.is_none() {
            self.show_toast(
                "Control service is not attached".to_string(),
                ToastType::Error,
            );
            return;
        }
        let next = self
            .pending_control_killswitch_mode
            .unwrap_or(self.control_snapshot.desired.kill_switch)
            .next();
        if self
            .issue_control_command(crate::vortix_core::control::UserCommand::SetKillSwitch {
                mode: next,
            })
            .is_some()
        {
            self.pending_control_killswitch_mode = Some(next);
        }
    }
    fn handle_quit(&mut self) {
        self.should_quit = true;
    }

    #[allow(clippy::too_many_lines)] // TEA-style dispatch — every arm is one telemetry variant; splitting would obscure the handler shape without simplifying it
    fn handle_telemetry(&mut self, update: TelemetryUpdate) {
        match update {
            TelemetryUpdate::PublicIp(ip) => {
                let is_connected = self.has_active_connection();
                let old_ip = self.runtime.public_ip.clone();

                // emit IpChanged into the journal so the
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

                // Store as real_ip ONLY when we have positive proof
                // there's no VPN active. Three conditions must hold:
                //
                // 1. Scanner has completed at least one tick — without
                //    this, telemetry-on-startup races and we'd cache
                //    the wrong IP before the scanner reports kernel
                //    state.
                // 2. Kernel reports zero VPN sessions — using raw
                //    scanner state (not the registry) catches tunnels
                //    that are kernel-visible but not yet adopted
                //    (e.g. external openvpn awaiting lsof Method A on
                //    macOS).
                // 3. Registry has no Connected tunnel — defensive belt
                //    against the scanner race; cheap so include it.
                //
                // Without ALL three, withhold caching. real_ip stays
                // None and the UI shows "detecting…" — honest about
                // not knowing rather than fabricating the VPN's exit
                // IP as the user's real IP.
                let safe_to_cache = self.runtime.scanner_first_tick_done
                    && self.runtime.last_kernel_session_count == 0
                    && !is_connected;
                if safe_to_cache {
                    let first_detection = self.runtime.real_ip.is_none();
                    let changed = self.runtime.real_ip.as_deref() != Some(ip.as_str());
                    if first_detection {
                        self.log(&format!("NET: Real IPv4 detected: {ip}"));
                    }
                    self.runtime.real_ip = Some(ip.clone());
                    if first_detection || changed {
                        crate::core::real_ip_cache::save(&self.runtime.config_dir, &ip);
                    }
                } else if self.runtime.public_ip != ip
                    && self.runtime.public_ip != constants::MSG_FETCHING
                {
                    self.runtime.ip_unchanged_warned = false;
                    self.log(&format!("NET: Public IPv4 changed {old_ip} -> {ip}"));
                } else if is_connected
                    && self.runtime.public_ip == ip
                    && self.runtime.public_ip != constants::MSG_FETCHING
                    && !self.runtime.ip_unchanged_warned
                {
                    self.runtime.ip_unchanged_warned = true;
                    self.log(&format!(
                        "WARN: Public IPv4 unchanged ({ip}) while connected — possible leak or split-tunnel"
                    ));
                    if let Some(ref real) = self.runtime.real_ip {
                        if real == &ip {
                            self.log(&format!("ERR: IPv4 leak detected — current IPv4 ({ip}) matches pre-VPN IPv4 ({real})"));
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
                if self.runtime.dns_server != dns
                    && self.runtime.dns_server != constants::MSG_NO_DATA
                    && self.runtime.dns_server != constants::MSG_DETECTING
                {
                    self.log(&format!("SEC: DNS server: {dns}"));
                }
                self.runtime.dns_server = dns;
                self.spawn_dns_leak_probe();
                self.runtime.last_security_check = Some(Instant::now());
            }
            TelemetryUpdate::DnsLeak(status) => {
                use crate::core::dns_leak::DnsLeakStatus;
                if let DnsLeakStatus::Leaking {
                    recursor,
                    configured,
                } = &status
                {
                    self.log(&format!(
                        "WARN: DNS leak — recursor {recursor} answered, expected {configured}"
                    ));
                }
                self.runtime.dns_leak = status;
            }
            TelemetryUpdate::PublicIpv6(observed) => {
                let is_connected = self.has_active_connection();
                let disconnect_safe = self.runtime.scanner_first_tick_done
                    && self.runtime.last_kernel_session_count == 0
                    && !is_connected;
                let no_tunnel_routes_v6 = is_connected
                    && !self.registry.snapshot_all().into_iter().any(|snap| {
                        use crate::vortix_core::engine::{Connection, Role};
                        match (snap.state, snap.role) {
                            (
                                Connection::Connected { .. },
                                Role::Primary { allowed_ips }
                                | Role::Addressable { allowed_ips }
                                | Role::AddressableSuppressed { allowed_ips },
                            ) => crate::vortix_core::cidr::claims_default_route_v6(&allowed_ips),
                            _ => false,
                        }
                    });
                let safe_to_cache = disconnect_safe || no_tunnel_routes_v6;
                if safe_to_cache {
                    if let Some(ref ip) = observed {
                        let changed = self.runtime.real_ipv6.as_deref() != Some(ip.as_str());
                        if changed {
                            let first = self.runtime.real_ipv6.is_none();
                            if first {
                                self.log(&format!("NET: Real IPv6 detected: {ip}"));
                            }
                            self.runtime.real_ipv6 = Some(ip.clone());
                            crate::core::real_ip_cache::save_ipv6(&self.runtime.config_dir, ip);
                        }
                    }
                }
                if is_connected {
                    if let (Some(real), Some(public)) = (&self.runtime.real_ipv6, &observed) {
                        if real == public {
                            self.log(&format!(
                                "WARN: IPv6 leak detected — public {public} matches real {real}"
                            ));
                        }
                    }
                }
                self.runtime.public_ipv6 = observed;
                self.runtime.last_security_check = Some(Instant::now());
            }
            TelemetryUpdate::Log(level, msg) => {
                logger::log(level, "TELEMETRY", msg);
            }
        }
    }

    // Removed by the state-authority rework: `scanner_promote_to_connected`. The scanner can no
    // longer drive the Connecting → Connected transition. Only the
    // protocol layer's `Tunnel::up()` success result (via
    // `Message::ConnectResult` → `mirror_connect_into_registry`) can.
    // The (Connecting, Some(session)) arm in `handle_sync_system_state`
    // now just logs the kernel-visible-but-not-yet-tracked state at
    // SCANNER_LOG_INTERVAL_SECS cadence; the connect-timeout safety
    // net in `handle_connection_timeout` catches genuinely-stuck cases.
    fn handle_tick(&mut self) {
        self.tick_presentation();
    }

    fn tick_presentation(&mut self) {
        if self
            .toast
            .as_ref()
            .is_some_and(crate::state::Toast::is_expired)
        {
            self.toast = None;
        }
        self.process_telemetry();
        self.poll_network_stats();
        self.runtime.down_history.pop_front();
        self.runtime.up_history.pop_front();
        #[allow(clippy::cast_precision_loss)]
        {
            self.runtime
                .down_history
                .push_back(self.runtime.current_down as f64);
            self.runtime
                .up_history
                .push_back(self.runtime.current_up as f64);
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

fn background_diagnostic_log_lines(
    view: &crate::vortix_core::control::DiagnosticView,
) -> Vec<String> {
    let mut lines = Vec::with_capacity(view.snapshot.records.len() + 1);
    lines.push(format!(
        "BACKGROUND: diagnostics source={:?} stale={} age_ms={} generation={}",
        view.source, view.stale, view.age_millis, view.snapshot.generation
    ));
    lines.extend(view.snapshot.records.iter().map(|record| {
        format!(
            "BACKGROUND: diagnostic #{} {:?}/{:?} {:?} {:?}",
            record.sequence, record.component, record.severity, record.code, record.fields
        )
    }));
    lines
}
