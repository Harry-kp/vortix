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

fn is_unknown_identity_value(value: &str) -> bool {
    value.is_empty()
        || value == "Unknown"
        || value == constants::MSG_DETECTING
        || value == constants::MSG_FETCHING
}

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
                        self.cached_config = Some(super::CachedConfigView::from_content(
                            content,
                            self.runtime.config.theme,
                        ));
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
                if let InputMode::ConfirmDelete { profile_id, .. } = self.input_mode.clone() {
                    self.confirm_delete_profile(&profile_id);
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
            Message::ForceDisconnectProfile { idx } => {
                self.force_disconnect_profile_by_idx(idx);
            }
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
                    Err(error) => {
                        self.log(&format!(
                            "BACKGROUND: diagnostics unavailable ({error}); status remains Standard and no authority claim was made"
                        ));
                        self.show_toast(
                            "Background diagnostics are unavailable. Standard mode is unchanged."
                                .to_string(),
                            ToastType::Warning,
                        );
                    }
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
                profile_id,
                username,
                password,
                otp,
                save,
                connect_after,
            } => self.handle_auth_submit(profile_id, username, password, otp, save, connect_after),

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
            Message::ToggleTheme => self.handle_toggle_theme(),
            Message::ThemePersisted {
                previous,
                selected,
                result,
            } => self.handle_theme_persisted(previous, selected, result),

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

    fn handle_toggle_theme(&mut self) {
        if self.pending_theme_change.is_some() {
            self.show_toast(
                "The color theme is still being saved".into(),
                ToastType::Info,
            );
            return;
        }
        let current = self.runtime.config.theme;
        let next = current.next();
        self.runtime.config.theme = next;
        self.pending_theme_change = Some(super::PendingThemeChange {
            previous: current,
            selected: next,
            quit_after: false,
        });
        if let Some(cached) = self.cached_config.take() {
            self.cached_config = Some(super::CachedConfigView::from_content(cached.content, next));
        }

        let config_dir = self.runtime.config_dir.clone();
        let tx = self.runtime.cmd_tx.clone();
        let worker = std::thread::Builder::new()
            .name("vortix-theme-persist".into())
            .spawn(move || {
                let result = crate::config::persist_theme_choice(&config_dir, next);
                let _ = tx.send(Message::ThemePersisted {
                    previous: current,
                    selected: next,
                    result,
                });
            });
        if let Err(error) = worker {
            self.pending_theme_change = None;
            self.runtime.config.theme = current;
            if let Some(cached) = self.cached_config.take() {
                self.cached_config = Some(super::CachedConfigView::from_content(
                    cached.content,
                    current,
                ));
            }
            self.show_toast(
                format!(
                    "Couldn't start the color-theme save; restored {}: {error}",
                    current.display_name()
                ),
                ToastType::Error,
            );
        }
    }

    fn handle_theme_persisted(
        &mut self,
        previous: crate::theme::ThemeChoice,
        selected: crate::theme::ThemeChoice,
        result: Result<crate::config::ThemePersistOutcome, String>,
    ) {
        let Some(pending) = self.pending_theme_change else {
            return;
        };
        if pending.previous != previous || pending.selected != selected {
            return;
        }
        self.pending_theme_change = None;
        match result {
            Ok(crate::config::ThemePersistOutcome::Durable) => self.show_toast(
                format!("Color theme: {}", selected.display_name()),
                ToastType::Success,
            ),
            Ok(crate::config::ThemePersistOutcome::PublishedDurabilityUncertain(error)) => {
                self.show_toast(
                    format!(
                        "Color theme changed to {}, but crash-safe disk confirmation failed: {error}",
                        selected.display_name()
                    ),
                    ToastType::Warning,
                );
            }
            Err(error) => {
                self.runtime.config.theme = previous;
                if let Some(cached) = self.cached_config.take() {
                    self.cached_config = Some(super::CachedConfigView::from_content(
                        cached.content,
                        previous,
                    ));
                }
                self.show_toast(
                    format!(
                        "Couldn't save the color theme; restored {}: {error}",
                        previous.display_name()
                    ),
                    ToastType::Error,
                );
            }
        }
        if pending.quit_after {
            self.should_quit = true;
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
                    // Manage mode persists only reusable username/password.
                    // OTP and static-challenge answers are one-shot values, so
                    // this save-only overlay intentionally omits that field.
                    let profile_id = profile.id.clone();
                    let profile_name = profile.name.clone();
                    let Some(control) = self.control_session.as_ref() else {
                        self.show_toast(
                            "Credential service is unavailable".to_string(),
                            ToastType::Error,
                        );
                        return;
                    };
                    let (username, password) = match control
                        .load_openvpn_credentials(&profile_id, &profile_name)
                    {
                        Ok(Some(credentials)) => (
                            crate::state::SecretText::from(credentials.username()),
                            crate::state::SecretText::from(credentials.password()),
                        ),
                        Ok(None) => Default::default(),
                        Err(error) => {
                            self.log(&format!(
                                "WARN: Remembered OpenVPN credentials are unavailable: {error}"
                            ));
                            self.show_toast(
                                "Saved credentials couldn't be used. Enter new credentials to replace them."
                                    .to_string(),
                                ToastType::Warning,
                            );
                            Default::default()
                        }
                    };
                    let username_cursor = username.len();
                    let password_cursor = password.len();
                    self.input_mode = InputMode::AuthPrompt {
                        profile_id,
                        profile_name,
                        username,
                        username_cursor,
                        password,
                        password_cursor,
                        otp: crate::state::SecretText::default(),
                        otp_cursor: 0,
                        focused_field: crate::state::AuthField::Username,
                        save_credentials: true,
                        connect_after: false,
                        static_challenge_prompt: None,
                        reveal_secrets: false,
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
                } else {
                    let Some(control) = self.control_session.as_ref() else {
                        self.show_toast(
                            "Credential service is unavailable".to_string(),
                            ToastType::Error,
                        );
                        return;
                    };
                    match control.clear_openvpn_credentials(&profile_id, &name) {
                        Ok(crate::cli::control::CredentialClearOutcome::NotFound) => self
                            .show_toast(
                                format!("No saved credentials for '{name}'"),
                                ToastType::Info,
                            ),
                        Ok(crate::cli::control::CredentialClearOutcome::Cleared) => {
                            self.log(&format!("AUTH: Cleared saved credentials for '{name}'"));
                            self.show_toast(
                                format!("Credentials cleared for '{name}'"),
                                ToastType::Success,
                            );
                        }
                        Err(
                            crate::cli::control::LocalControlError::CredentialDurabilityUncertain,
                        ) => {
                            self.log(&format!(
                                "WARN: Credentials for '{name}' were removed but disk durability is uncertain"
                            ));
                            self.show_toast(
                                "Credentials were cleared, but disk confirmation failed. Verify after restarting."
                                    .to_string(),
                                ToastType::Warning,
                            );
                        }
                        Err(error) => {
                            self.log(&format!(
                                "ERR: Remembered OpenVPN credentials could not be cleared: {error}"
                            ));
                            self.show_toast(
                                "Saved credentials couldn't be cleared. Check permissions and try again."
                                    .to_string(),
                                ToastType::Error,
                            );
                        }
                    }
                }
            }
        }
    }
    fn handle_auth_submit(
        &mut self,
        profile_id: crate::vortix_core::profile::ProfileId,
        username: crate::state::SecretText,
        password: crate::state::SecretText,
        otp: Option<crate::state::SecretText>,
        save: bool,
        connect_after: bool,
    ) {
        if let Some(challenge_id) = self.control_challenge {
            self.handle_control_auth_submit(
                challenge_id,
                profile_id,
                username,
                password,
                otp,
                save,
            );
            return;
        }

        let Some(profile) = self
            .runtime
            .profiles
            .iter()
            .find(|profile| profile.id == profile_id)
        else {
            self.show_toast("Profile is unavailable".to_string(), ToastType::Error);
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
        let profile_name = profile.name.clone();
        let Some(control) = self.control_session.as_ref() else {
            self.show_toast(
                "Credential service is unavailable".to_string(),
                ToastType::Error,
            );
            return;
        };
        match control.remember_openvpn_credentials(
            &profile_id,
            username.expose(),
            password.expose(),
        ) {
            Ok(()) => {
                self.input_mode = InputMode::Normal;
                self.log(&format!("AUTH: Saved credentials for '{profile_name}'"));
                self.show_toast(
                    format!("Credentials updated for '{profile_name}'"),
                    ToastType::Success,
                );
            }
            Err(crate::cli::control::LocalControlError::CredentialDurabilityUncertain) => {
                self.input_mode = InputMode::Normal;
                self.log(&format!(
                    "WARN: Credential update for '{profile_name}' is visible but disk durability is uncertain"
                ));
                self.show_toast(
                    "Credentials were updated, but disk confirmation failed. You may be asked again after a restart."
                        .to_string(),
                    ToastType::Warning,
                );
            }
            Err(error) => {
                self.log(&format!(
                    "ERR: Remembered OpenVPN credentials could not be saved: {error}"
                ));
                self.show_toast(
                    "Credentials weren't saved. Check permissions and try again.".to_string(),
                    ToastType::Error,
                );
            }
        }
    }

    fn handle_control_auth_submit(
        &mut self,
        challenge_id: crate::vortix_core::control::ChallengeId,
        profile_id: crate::vortix_core::profile::ProfileId,
        username: crate::state::SecretText,
        password: crate::state::SecretText,
        otp: Option<crate::state::SecretText>,
        save: bool,
    ) {
        let challenge_matches_profile = self
            .control_snapshot
            .challenges
            .get(&challenge_id)
            .is_some_and(|challenge| challenge.profile_id == profile_id);
        if !challenge_matches_profile {
            self.show_toast(
                "The connection prompt expired; start the connection again".to_string(),
                ToastType::Warning,
            );
            return;
        }
        let answer = otp.filter(|answer| !answer.trim().is_empty());
        let payload = crate::vortix_core::control::Secret::openvpn_credentials(
            username.expose(),
            password.expose(),
            answer.as_deref(),
        )
        .into_vec();
        let control = self
            .control_session
            .as_ref()
            .expect("service challenge requires attached control session");
        if let Err(error) = control.respond_challenge(challenge_id, payload) {
            self.show_toast(
                format!("Challenge response failed: {error}"),
                ToastType::Error,
            );
            return;
        }

        self.control_challenge = None;
        self.input_mode = InputMode::Normal;
        self.log("AUTH: Submitted service-owned challenge response");
        if !save {
            return;
        }
        let profile_name = self
            .runtime
            .profiles
            .iter()
            .find(|profile| profile.id == profile_id)
            .map_or_else(|| profile_id.to_string(), |profile| profile.name.clone());
        // Held, not written. The server has not judged this pair yet, and a
        // profile with stored credentials raises no challenge — persisting a
        // rejected password here is what silently suppressed the next prompt.
        self.pending_credential_save = Some(super::PendingCredentialSave {
            profile_id,
            profile_name,
            username,
            password,
        });
    }

    fn handle_toggle_killswitch(&mut self) {
        if self.control_session.is_none() {
            self.show_toast(
                super::connection::CONTROL_STARTING_MESSAGE.to_string(),
                ToastType::Info,
            );
            return;
        }
        let next = self
            .queued_killswitch_target
            .or(self.pending_control_killswitch_mode)
            .unwrap_or(self.control_snapshot.desired.kill_switch)
            .next();

        // One change at a time. Each press used to submit its own operation
        // while the control worker applies them serially, so a few quick taps
        // left the later ones to expire on their own deadline. That surfaced
        // as "kill switch change timed out" and, because a timed-out change
        // never publishes an effective state, as "Degraded" in Security Guard
        // — while the firewall itself was applied and correct the whole time.
        //
        // Cycling stays responsive: the target moves immediately and is
        // submitted once the running change settles.
        if self.killswitch_change_in_flight() {
            self.queued_killswitch_target = Some(next);
            return;
        }

        if self
            .issue_control_command(crate::vortix_core::control::UserCommand::SetKillSwitch {
                mode: next,
            })
            .is_some()
        {
            self.pending_control_killswitch_mode = Some(next);
        }
    }

    /// Submit the coalesced kill-switch target once the running change ends.
    pub(crate) fn submit_queued_killswitch_target(&mut self) {
        let Some(target) = self.queued_killswitch_target else {
            return;
        };
        if self.killswitch_change_in_flight() {
            return;
        }
        self.queued_killswitch_target = None;
        if target == self.control_snapshot.desired.kill_switch {
            return;
        }
        if self
            .issue_control_command(crate::vortix_core::control::UserCommand::SetKillSwitch {
                mode: target,
            })
            .is_some()
        {
            self.pending_control_killswitch_mode = Some(target);
        }
    }
    fn handle_quit(&mut self) {
        if let Some(pending) = &mut self.pending_theme_change {
            if pending.quit_after {
                self.should_quit = true;
                return;
            }
            pending.quit_after = true;
            self.show_toast(
                "Finishing the color-theme save before quitting; press Ctrl-C again to quit now"
                    .into(),
                ToastType::Info,
            );
        } else {
            self.should_quit = true;
        }
    }

    #[allow(clippy::too_many_lines)] // TEA-style dispatch — every arm is one telemetry variant; splitting would obscure the handler shape without simplifying it
    fn handle_telemetry(&mut self, update: TelemetryUpdate) {
        match update {
            TelemetryUpdate::PublicIp(ip) => self.apply_public_ipv4(ip),
            TelemetryUpdate::EgressIdentity(identity) => {
                self.apply_egress_identity(identity);
            }
            TelemetryUpdate::EgressUnavailable => self.apply_egress_unavailable(),
            TelemetryUpdate::NetworkQuality {
                latency_ms,
                packet_loss,
                jitter_ms,
            } => {
                self.runtime.latency_ms = latency_ms;
                self.runtime.packet_loss = packet_loss;
                self.runtime.jitter_ms = jitter_ms;
                self.log_network_quality_transition();
            }
            TelemetryUpdate::Dns(dns) => {
                if self.runtime.dns_server != dns
                    && self.runtime.dns_server != constants::MSG_NO_DATA
                    && self.runtime.dns_server != constants::MSG_DETECTING
                {
                    self.log(&format!("SEC: DNS server: {dns}"));
                }
                self.runtime.dns_server = dns;
                self.runtime.last_security_check = Some(Instant::now());
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
                let checked_at = Instant::now();
                self.runtime.last_ipv6_check = Some(checked_at);
                self.runtime.last_security_check = Some(checked_at);
            }
            TelemetryUpdate::Log(level, msg) => {
                logger::log(level, "TELEMETRY", msg);
            }
        }
    }

    fn apply_egress_identity(&mut self, identity: crate::core::telemetry::EgressIdentity) {
        let same_exit = self.runtime.public_ip == identity.public_ip;
        self.apply_public_ipv4(identity.public_ip);

        let next_isp = identity.isp.unwrap_or_else(|| {
            if same_exit && !is_unknown_identity_value(&self.runtime.isp) {
                self.runtime.isp.clone()
            } else {
                "Unknown".to_string()
            }
        });
        if self.runtime.isp != next_isp && self.runtime.isp != constants::MSG_DETECTING {
            self.log(&format!("NET: Exit node: {next_isp}"));
        }
        self.runtime.isp = next_isp;

        let next_location = identity.location.unwrap_or_else(|| {
            if same_exit && !is_unknown_identity_value(&self.runtime.location) {
                self.runtime.location.clone()
            } else {
                "Unknown".to_string()
            }
        });
        if self.runtime.location != next_location
            && self.runtime.location != constants::MSG_DETECTING
        {
            self.log(&format!("NET: Location: {next_location}"));
        }
        self.runtime.location = next_location;
    }

    fn apply_egress_unavailable(&mut self) {
        if !is_unknown_identity_value(&self.runtime.isp) {
            self.log("NET: Exit node: Unknown");
        }
        if !is_unknown_identity_value(&self.runtime.location) {
            self.log("NET: Location: Unknown");
        }
        self.runtime.public_ip = "Unavailable".to_string();
        self.runtime.isp = "Unknown".to_string();
        self.runtime.location = "Unknown".to_string();
        self.runtime.last_security_check = Some(Instant::now());
    }

    fn apply_public_ipv4(&mut self, ip: String) {
        let is_connected = self.has_active_connection();
        let old_ip = self.runtime.public_ip.clone();

        if old_ip != ip && old_ip != constants::MSG_FETCHING && old_ip != constants::MSG_DETECTING {
            if let Some(journal) = crate::vortix_core::journal::global_journal() {
                let _ = journal.append(crate::vortix_core::engine::EngineEvent::IpChanged {
                    old: Some(old_ip.clone()),
                    new: ip.clone(),
                });
            }
        }

        // Cache the real address only after both scanner and registry prove
        // that no tunnel owns the egress path.
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
        } else if self.runtime.public_ip != ip && self.runtime.public_ip != constants::MSG_FETCHING
        {
            self.runtime.ip_unchanged_warned = false;
            self.log(&format!("NET: Public IPv4 changed {old_ip} -> {ip}"));
        }
        if is_connected
            && self.runtime.real_ip.as_deref() == Some(ip.as_str())
            && !self.runtime.ip_unchanged_warned
        {
            self.runtime.ip_unchanged_warned = true;
            self.log(&format!(
                "WARN: Public IPv4 matches the pre-VPN address ({ip}) — possible leak or split-tunnel"
            ));
        }
        self.runtime.public_ip = ip;
        self.runtime.last_security_check = Some(Instant::now());
    }

    fn log_network_quality_transition(&mut self) {
        use crate::state::QualityLevel;

        let quality = QualityLevel::from_metrics(
            self.runtime.latency_ms,
            self.runtime.packet_loss,
            self.runtime.jitter_ms,
        );
        if quality == self.last_logged_network_quality {
            return;
        }
        self.last_logged_network_quality = quality;
        match quality {
            QualityLevel::Unknown => self.log("WARN: Network quality unavailable"),
            QualityLevel::Excellent => self.log("NET: Network quality: excellent"),
            QualityLevel::Fair => self.log("WARN: Network quality degraded: fair"),
            QualityLevel::Poor => self.log("WARN: Network quality degraded: poor"),
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
        self.flush_catalog_feedback(false);
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
                        profile_id: profile.id.clone(),
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
