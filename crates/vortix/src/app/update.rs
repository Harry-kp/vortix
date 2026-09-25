//! Central message dispatcher (TEA-style update function).
//!
//! Private handler methods receive owned values destructured from the `Message` enum.
#![allow(clippy::needless_pass_by_value)]

use std::time::{Duration, Instant};

use super::{App, FocusedPanel, InputMode, ToastType};
use crate::constants;
use crate::logger;
use crate::message::{Message, ScrollMove, SelectionMove};
use crate::profile::{ProfileId, ProtocolKind};
use crate::telemetry::TelemetryUpdate;

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
            Message::SwitchExclusiveAndConnect { idx } | Message::ConfirmRouteOverlap { idx } => {
                self.input_mode = InputMode::Normal;
                if let Some(profile) = self.runtime.profiles.get(idx).cloned() {
                    self.log(&format!(
                        "ACTION: Switching to '{}'; conflicting tunnels stop once it is up",
                        profile.name
                    ));
                    self.send(crate::control::Command::Switch(profile.id));
                }
            }
            Message::DisconnectProfile { idx } | Message::CancelConnect { idx } => {
                self.disconnect_profile_by_idx(idx);
            }
            Message::RequestDisconnectAll => {
                let count = self.tunnel_count();
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
            Message::Disconnect => self.disconnect(),
            Message::Reconnect => self.reconnect(),
            Message::ConnectSelected => {
                if let Some((idx, profile_id)) = self
                    .profile_list_state
                    .selected()
                    .and_then(|idx| Some((idx, self.runtime.profiles.get(idx)?.id.clone())))
                {
                    // The selected row's own tunnel, primary or not.
                    if self.tunnel(&profile_id).is_some() {
                        self.send(crate::control::Command::Reconnect(profile_id));
                    } else {
                        self.toggle_connection(idx);
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
            Message::CloseOverlay => {
                // Only closing the prompt's own form cancels the connect.
                let closing_prompt = matches!(
                    self.input_mode,
                    InputMode::AuthPrompt {
                        connect_after: true,
                        ..
                    }
                );
                if closing_prompt {
                    self.answer_prompt(None);
                }
                self.show_config = false;
                self.cached_config = None;
                self.show_action_menu = false;
                self.show_bulk_menu = false;
                self.input_mode = InputMode::Normal;
                self.show_pending_prompt();
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
                    tab: crate::app::state::HelpTab::default(),
                };
            }
            Message::CycleLogFilter => self.handle_cycle_log_filter(),

            // System
            Message::Quit => self.handle_quit(),
            Message::Toast(msg, t_type) => self.show_toast(msg, t_type),
            Message::CopyIp => self.copy_ip_to_clipboard(),
            Message::ClearLogs => {
                logger::clear_logs();
                self.logs_scroll = 0;
                self.log("APP: Logs cleared");
            }
            Message::Telemetry(update) => self.handle_telemetry(update),
            Message::Tick => {
                self.handle_tick();
                self.show_pending_prompt();
            }
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
        previous: crate::ui::theme::ThemeChoice,
        selected: crate::ui::theme::ThemeChoice,
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
                if !matches!(profile.protocol, ProtocolKind::OpenVpn) {
                    self.show_toast(
                        "Auth credentials only apply to OpenVPN profiles".to_string(),
                        ToastType::Info,
                    );
                } else if !crate::openvpn::parser::needs_credentials(&profile.config_path) {
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
                    let Some(control) = self.control.as_ref() else {
                        self.show_toast(
                            "Credential service is unavailable".to_string(),
                            ToastType::Error,
                        );
                        return;
                    };
                    let (username, password) = match control
                        .load_credentials(&profile_id, &profile_name)
                    {
                        Ok(Some(credentials)) => (
                            crate::app::state::SecretText::from(credentials.username()),
                            crate::app::state::SecretText::from(credentials.password()),
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
                        otp: crate::app::state::SecretText::default(),
                        otp_cursor: 0,
                        focused_field: crate::app::state::AuthField::Username,
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
                let is_openvpn = matches!(profile.protocol, ProtocolKind::OpenVpn);
                let has_auth = crate::openvpn::parser::needs_credentials(&profile.config_path);
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
                    let Some(control) = self.control.as_ref() else {
                        self.show_toast(
                            "Credential service is unavailable".to_string(),
                            ToastType::Error,
                        );
                        return;
                    };
                    match control.clear_credentials(&profile_id, &name) {
                        Ok(
                            crate::config::openvpn_credentials::CredentialClearOutcome::NotFound,
                        ) => self.show_toast(
                            format!("No saved credentials for '{name}'"),
                            ToastType::Info,
                        ),
                        Ok(crate::config::openvpn_credentials::CredentialClearOutcome::Cleared) => {
                            self.log(&format!("AUTH: Cleared saved credentials for '{name}'"));
                            self.show_toast(
                                format!("Credentials cleared for '{name}'"),
                                ToastType::Success,
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
        profile_id: crate::profile::ProfileId,
        username: crate::app::state::SecretText,
        password: crate::app::state::SecretText,
        otp: Option<crate::app::state::SecretText>,
        save: bool,
        connect_after: bool,
    ) {
        // Only the form opened for the pending prompt may answer it.
        let answers_prompt = self.control_prompt.is_some_and(|id| {
            self.control_snapshot
                .prompts
                .iter()
                .any(|prompt| prompt.id == id && prompt.profile_id == profile_id)
        });
        if answers_prompt {
            let answer = crate::control::Credentials {
                username: username.expose().to_owned(),
                password: password.expose().to_owned(),
                otp: otp
                    .filter(|answer| !answer.trim().is_empty())
                    .map(|answer| answer.expose().to_owned()),
                remember: save,
            };
            self.answer_prompt(Some(answer));
            self.input_mode = InputMode::Normal;
            self.log("AUTH: Credentials submitted");
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
                "The connection prompt expired; start the connection again".to_string(),
                ToastType::Warning,
            );
            self.input_mode = InputMode::Normal;
            return;
        }
        let profile_name = profile.name.clone();
        let Some(control) = self.control.as_ref() else {
            self.show_toast(
                "Credential service is unavailable".to_string(),
                ToastType::Error,
            );
            return;
        };
        match control.remember_credentials(&profile_id, username.expose(), password.expose()) {
            Ok(()) => {
                self.input_mode = InputMode::Normal;
                self.log(&format!("AUTH: Saved credentials for '{profile_name}'"));
                self.show_toast(
                    format!("Credentials updated for '{profile_name}'"),
                    ToastType::Success,
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

    fn handle_toggle_killswitch(&mut self) {
        let next = self
            .pending_control_killswitch_mode
            .unwrap_or(self.control_snapshot.kill_switch)
            .next();
        self.pending_control_killswitch_mode = Some(next);
        self.send(crate::control::Command::SetKillSwitch(next));
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
                let checked_at = Instant::now();
                self.runtime.last_dns_check = Some(checked_at);
                self.runtime.last_security_check = Some(checked_at);
            }
            TelemetryUpdate::PublicIpv6(observed) => {
                let is_connected = self.has_active_connection();
                let no_tunnel_routes_v6 = is_connected
                    && !self
                        .control_snapshot
                        .tunnels
                        .iter()
                        .any(|tunnel| crate::cidr::claims_default_route_v6(&tunnel.routes));
                let safe_to_cache = self.no_tunnel_on_egress() || no_tunnel_routes_v6;
                if safe_to_cache {
                    if let Some(ref ip) = observed {
                        let changed = self.runtime.real_ipv6.as_deref() != Some(ip.as_str());
                        if changed {
                            let first = self.runtime.real_ipv6.is_none();
                            if first {
                                self.log(&format!("NET: Real IPv6 detected: {ip}"));
                            }
                            self.runtime.real_ipv6 = Some(ip.clone());
                            crate::telemetry::ip_cache::save_ipv6(&self.runtime.config_dir, ip);
                        }
                        self.runtime.real_ipv6_from_cache = false;
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

    fn apply_egress_identity(&mut self, identity: crate::telemetry::EgressIdentity) {
        let same_exit = self.runtime.public_ip == identity.public_ip;
        self.apply_public_ipv4(identity.public_ip);

        let next_isp = identity.isp.unwrap_or_else(|| {
            if same_exit && !constants::is_unknown(&self.runtime.isp) {
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
            if same_exit && !constants::is_unknown(&self.runtime.location) {
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
        if !constants::is_unknown(&self.runtime.isp) {
            self.log("NET: Exit node: Unknown");
        }
        if !constants::is_unknown(&self.runtime.location) {
            self.log("NET: Location: Unknown");
        }
        self.runtime.public_ip = constants::MSG_UNAVAILABLE.to_string();
        self.runtime.isp = constants::MSG_UNKNOWN.to_string();
        self.runtime.location = constants::MSG_UNKNOWN.to_string();
        let checked_at = Instant::now();
        self.runtime.last_egress_check = Some(checked_at);
        self.runtime.last_security_check = Some(checked_at);
    }

    fn apply_public_ipv4(&mut self, ip: String) {
        let is_connected = self.has_active_connection();
        let old_ip = self.runtime.public_ip.clone();

        if old_ip != ip && old_ip != constants::MSG_FETCHING && old_ip != constants::MSG_DETECTING {
            if let Some(journal) = crate::journal::global_journal() {
                let _ = journal.append(crate::journal::JournalEvent::IpChanged {
                    old: Some(old_ip.clone()),
                    new: ip.clone(),
                });
            }
        }

        if self.no_tunnel_on_egress() {
            let first_detection = self.runtime.real_ip.is_none();
            let changed = self.runtime.real_ip.as_deref() != Some(ip.as_str());
            if first_detection {
                self.log(&format!("NET: Real IPv4 detected: {ip}"));
            }
            self.runtime.real_ip = Some(ip.clone());
            self.runtime.real_ip_from_cache = false;
            if first_detection || changed {
                crate::telemetry::ip_cache::save(&self.runtime.config_dir, &ip);
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
        let checked_at = Instant::now();
        self.runtime.last_egress_check = Some(checked_at);
        self.runtime.last_security_check = Some(checked_at);
    }

    fn log_network_quality_transition(&mut self) {
        use crate::app::state::QualityLevel;

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
    // protocol layer's the protocol `up()` success result (via
    // `Message::ConnectResult` → `the connect result`) can.
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
            .is_some_and(crate::app::state::Toast::is_expired)
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
        use crate::app::state::LogsSource;
        use crate::logger::LogLevel;
        let steps = self.openvpn_log_steps();
        let next_openvpn = |index: usize| steps.get(index).cloned().map(LogsSource::OpenVpn);
        let next = match (&self.logs_source, self.log_level_filter) {
            (LogsSource::Events, None) => (LogsSource::Events, Some(LogLevel::Error)),
            (LogsSource::Events, Some(LogLevel::Error)) => {
                (LogsSource::Events, Some(LogLevel::Warning))
            }
            (LogsSource::Events, Some(LogLevel::Warning)) => {
                (LogsSource::Events, Some(LogLevel::Info))
            }
            (LogsSource::Events, Some(_)) => (next_openvpn(0).unwrap_or_default(), None),
            (LogsSource::OpenVpn(current), _) => {
                let position = steps.iter().position(|step| step == current);
                let after = position.and_then(|index| next_openvpn(index + 1));
                (after.unwrap_or_default(), None)
            }
        };
        (self.logs_source, self.log_level_filter) = next;
        self.logs_scroll = 0;
        self.logs_auto_scroll = true;
        let message = match (&self.logs_source, self.log_level_filter) {
            (LogsSource::OpenVpn(Some(profile_id)), _) => {
                let name = self
                    .runtime
                    .profiles
                    .iter()
                    .find(|profile| &profile.id == profile_id)
                    .map_or("", |profile| profile.name.as_str());
                let place = steps
                    .iter()
                    .position(|step| step.as_ref() == Some(profile_id));
                match place {
                    Some(index) if steps.len() > 1 => format!(
                        "Showing: OpenVPN log ({name}), {} of {}",
                        index + 1,
                        steps.len()
                    ),
                    _ => format!("Showing: OpenVPN log ({name})"),
                }
            }
            (LogsSource::OpenVpn(None), _) => "Showing: OpenVPN log".to_string(),
            (LogsSource::Events, Some(LogLevel::Error)) => "Log filter: Errors only".into(),
            (LogsSource::Events, Some(LogLevel::Warning)) => "Log filter: Warn+Error".into(),
            (LogsSource::Events, Some(LogLevel::Info)) => "Log filter: Info+Warn+Error".into(),
            (LogsSource::Events, _) => "Showing: all events".into(),
        };
        self.show_toast(message, ToastType::Info);
    }

    /// Connecting, up or reconnecting: the tunnel's log is still being written.
    pub(crate) fn tunnel_is_active(&self, profile_id: &ProfileId) -> bool {
        self.control_snapshot
            .tunnel(profile_id)
            .is_some_and(|tunnel| tunnel.phase != crate::control::Phase::Stopping)
    }

    /// The `OpenVPN` steps of the `f` cycle: every active `OpenVPN` tunnel in
    /// sidebar order; with none active, the most recently connected `OpenVPN`
    /// profile (or a placeholder before any has connected). Empty when there
    /// are no `OpenVPN` profiles.
    pub(crate) fn openvpn_log_steps(&self) -> Vec<Option<ProfileId>> {
        let openvpn = || {
            self.runtime
                .profiles
                .iter()
                .filter(|profile| profile.protocol == ProtocolKind::OpenVpn)
        };
        let active = openvpn()
            .filter(|profile| self.tunnel_is_active(&profile.id))
            .map(|profile| Some(profile.id.clone()))
            .collect::<Vec<_>>();
        if !active.is_empty() {
            return active;
        }
        if openvpn().next().is_none() {
            return Vec::new();
        }
        vec![openvpn()
            .filter(|profile| profile.last_used.is_some())
            .max_by_key(|profile| profile.last_used)
            .map(|profile| profile.id.clone())]
    }
}

/// Whether an interface name is a tunnel device.
///
/// The real-IP gate proves Vortix owns no tunnel, which is not the same as
/// there being none: a VPN started outside Vortix still carries the egress,
/// and caching then records that VPN's exit as the user's real address.
/// Naming is the only signal available here, and it is the same vocabulary
/// the platform layer creates these devices with.
fn interface_is_tunnel(name: &str) -> bool {
    const TUNNEL_PREFIXES: [&str; 6] = ["utun", "tun", "tap", "wg", "ipsec", "ppp"];
    let name = name.trim();
    TUNNEL_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

impl App {
    /// Whether the kernel's last observed default route leaves through a
    /// tunnel device, managed by Vortix or not.
    /// Whether a public-IP reading is the real address: no tunnel in any
    /// phase (a connecting one already carries routes), none outside Vortix,
    /// and the default route is not on a tunnel.
    pub(crate) fn no_tunnel_on_egress(&self) -> bool {
        self.runtime.scanner_first_tick_done
            && self.control_snapshot.tunnels.is_empty()
            && self.control_snapshot.external.is_empty()
            && !self.default_route_is_tunnel()
    }

    pub(crate) fn default_route_is_tunnel(&self) -> bool {
        self.control_snapshot
            .default_route
            .as_deref()
            .is_some_and(interface_is_tunnel)
    }
}
