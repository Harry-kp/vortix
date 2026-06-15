//! Central message dispatcher (TEA-style update function).
//!
//! Private handler methods receive owned values destructured from the `Message` enum.
#![allow(clippy::needless_pass_by_value)]

use std::time::{Duration, Instant};

use super::{
    App, ConnectionState, DetailedConnectionInfo, FocusedPanel, InputMode, Protocol, ToastType,
};
use crate::constants;
use crate::core::scanner::ActiveSession;
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
                interface,
                pid,
            } => self.handle_connect_result(profile, success, error, interface, pid),

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
            Message::SyncSystemState {
                sessions,
                default_route_interface,
            } => {
                // Pre-feed the scanner's route-iface probe into the
                // registry's cache BEFORE processing sessions. Every
                // downstream `set_connected` / `set_disconnected` calls
                // `recompute_primary`, which now reads this cached value
                // instead of shelling out from the main thread.
                self.registry
                    .feed_default_route_interface(default_route_interface);
                self.handle_sync_system_state(sessions);
            }
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
        // Stale-arrival check: read THIS profile's own registry state,
        // not `legacy_state()`. In multi-tunnel topologies the legacy
        // view reports the PRIMARY's state, and a name-equality check
        // against the SECONDARY being disconnected would wrongly mark
        // its result as stale — silently skipping `complete_disconnect`
        // and leaving the entry as Disconnecting forever. Same pattern
        // as the prior ConnectResult fix.
        use crate::vortix_core::engine::state::Connection;
        use crate::vortix_core::profile::ProfileId;
        let still_disconnecting = self
            .registry
            .snapshot(&ProfileId::new(&profile))
            .is_some_and(|snap| matches!(snap.state, Connection::Disconnecting { .. }));
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

    #[allow(clippy::too_many_lines)] // single linear sequence of stale-check, success bookkeeping, failure logging; splitting would obscure the flow
    fn handle_connect_result(
        &mut self,
        profile: String,
        success: bool,
        error: Option<String>,
        interface: Option<String>,
        pid: Option<u32>,
    ) {
        // Stale-arrival check. A `ConnectResult` is stale ONLY when the
        // user cancelled / changed context before the spawn thread's
        // result arrived. The check MUST read this specific profile's
        // entry in the registry — not `legacy_state()`, which returns
        // the primary's state. In multi-tunnel topologies (e.g., Shift+B
        // takeover where a second connect runs while the first is still
        // primary), `legacy_state()` still reports the original primary,
        // and a name-equality check against the SECOND profile would
        // wrongly mark the second connect's result as stale — leaving
        // the tunnel stuck in Connecting forever post-U4 (the scanner
        // can no longer promote on its own).
        use crate::vortix_core::engine::state::Connection;
        use crate::vortix_core::profile::ProfileId;
        let still_relevant = self
            .registry
            .snapshot(&ProfileId::new(&profile))
            .is_some_and(|snap| {
                matches!(
                    snap.state,
                    Connection::Connecting { .. } | Connection::Connected { .. }
                )
            });
        if !still_relevant {
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

            // Push a Connected entry with the authoritative iface
            // and PID returned by the protocol layer's `Tunnel::up()`
            // result (carried through `Message::ConnectResult`). The
            // scanner's metadata-only refreshes (U4) will then patch
            // in transfer counts / MTU / endpoint on subsequent ticks
            // without touching the iface. R1 of the state-authority
            // contract: this is the ONE write path for iface; the
            // scanner has no business overwriting it later.
            let mut details_seed = DetailedConnectionInfo::default();
            if let Some(iface) = interface {
                details_seed.interface = iface;
            }
            if let Some(p) = pid {
                details_seed.pid = Some(p);
            }
            self.mirror_connect_into_registry(&profile, &details_seed, now);

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
        otp: Option<String>,
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

        // Plan 2026-06-02-001 U3 / PF-2 (#191): write the canonical
        // `<safe>.auth` exactly once with plain credentials (when
        // `save=true` or when there's no OTP to save), and write the
        // single-use SCRV1 envelope to a transient sibling
        // `<safe>.scrv1.auth` that the protocol layer prefers and
        // deletes after openvpn forks. This eliminates the race the
        // earlier "write-SCRV1-then-restore" approach had against the
        // async connect-worker thread.
        let result = (|| -> std::io::Result<()> {
            if save || otp.is_none() {
                utils::write_openvpn_auth_file(&profile_name, &username, &password)?;
            }
            if let Some(ref code) = otp {
                utils::write_openvpn_scrv1_auth_file(
                    &profile_name,
                    &username,
                    &password,
                    code.as_str(),
                )?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                // No OTP/SCRV1 content in logs — the OTP value is single-use
                // and must never appear in tracing spans (plan 2026-06-02-001
                // PF-8).
                if save {
                    self.log(&format!("AUTH: Saved credentials for '{profile_name}'"));
                } else {
                    self.log(&format!(
                        "AUTH: Using one-time credentials for '{profile_name}'"
                    ));
                }

                if connect_after {
                    // Call the post-auth connect path so the
                    // static-challenge gate in `connect_profile_inner`
                    // doesn't re-open the overlay we just closed —
                    // the OTP is already baked into the transient
                    // `<safe>.scrv1.auth` file the protocol layer
                    // consumes during openvpn spawn.
                    self.connect_profile_after_auth(idx);
                    // For the one-time-only path (no save), the
                    // canonical plain auth file must not linger.
                    // The SCRV1 envelope cleanup happens in the
                    // protocol layer after openvpn forks.
                    if otp.is_none() && !save {
                        utils::delete_openvpn_auth_file(&profile_name);
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
            // Toast / log strings use the user-facing UI labels
            // (`KillSwitchMode::display_name`). Log lines keep the
            // enum variant name in parens so on-disk logs stay
            // greppable against the stable contract — see the
            // `vortix_core::state::killswitch` module docs.
            let mode = self.runtime.killswitch_mode;
            let label = mode.display_name();
            let one_liner = mode.one_liner();
            match mode {
                KillSwitchMode::Off => {
                    self.log(&format!("SEC: Kill switch → {label} (Off): {one_liner}"));
                    self.show_toast(
                        format!("Kill Switch: {label} — {one_liner}"),
                        ToastType::Info,
                    );
                }
                KillSwitchMode::Auto => {
                    self.log(&format!("SEC: Kill switch → {label} (Auto): {one_liner}"));
                    self.show_toast(
                        format!("Kill Switch: {label} — {one_liner}"),
                        ToastType::Success,
                    );
                }
                KillSwitchMode::AlwaysOn => {
                    self.log(&format!(
                        "SEC: Kill switch → {label} (AlwaysOn): {one_liner}"
                    ));
                    self.show_toast(
                        format!("Kill Switch: {label} — {one_liner}"),
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

    #[allow(clippy::too_many_lines)] // TEA-style dispatch — every arm is one telemetry variant; splitting would obscure the handler shape without simplifying it
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

        // Record raw kernel state for the real-IP cache gate. Reading
        // active.len() (not registry.tunnel_count) catches tunnels
        // that aren't adopted yet — the startup-race window where
        // telemetry fires before the registry has a chance to mirror
        // kernel state.
        self.runtime.scanner_first_tick_done = true;
        self.runtime.last_kernel_session_count = active.len();

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
                (Connection::Connecting { started_at, .. }, Some(_session)) => {
                    // U4 contract: scanner cannot promote Connecting →
                    // Connected. Only the protocol layer's `Tunnel::up()`
                    // success result (delivered via
                    // `Message::ConnectResult` → `mirror_connect_into_registry`)
                    // can complete the transition. The scanner observing
                    // a matching kernel session is informational only —
                    // the connect is proceeding; the protocol layer
                    // will report the authoritative iface shortly. The
                    // existing `handle_connection_timeout` safety net
                    // catches the genuinely-stuck case.
                    let elapsed = SystemTime::now()
                        .duration_since(*started_at)
                        .unwrap_or_default()
                        .as_secs();
                    if elapsed > 0 && elapsed % constants::SCANNER_LOG_INTERVAL_SECS == 0 {
                        self.log(&format!(
                            "NET: Scanner: kernel tunnel visible for '{profile_name}' \
                             ({elapsed}s elapsed) — awaiting protocol-layer success"
                        ));
                    }
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
                    // ✗ badge). User must retry or dismiss.
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

    // Removed in U4: `scanner_promote_to_connected`. The scanner can no
    // longer drive the Connecting → Connected transition. Only the
    // protocol layer's `Tunnel::up()` success result (via
    // `Message::ConnectResult` → `mirror_connect_into_registry`) can.
    // The (Connecting, Some(session)) arm in `handle_sync_system_state`
    // now just logs the kernel-visible-but-not-yet-tracked state at
    // SCANNER_LOG_INTERVAL_SECS cadence; the connect-timeout safety
    // net in `handle_connection_timeout` catches genuinely-stuck cases.

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
        // U4: adoption goes through the dedicated entry-creation path,
        // NOT refresh_registry_from_session (which is metadata-only on
        // existing Connected entries). The new entry's
        // interface_authoritative flag is read from
        // session.interface_authoritative (U5 wires the per-platform
        // decision into the scanner; default is true).
        self.adopt_registry_from_session(&profile_name, session);
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
