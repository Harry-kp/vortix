//! VPN connection lifecycle management and kill switch control.

use std::time::Instant;

use super::{App, ConnectionState, InputMode, Protocol, ToastType};
use crate::message::Message;
use crate::utils;
use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::engine::Conflict;
use crate::vortix_core::profile::ProfileId;

impl App {
    /// Smart connection toggle: Connect, Disconnect, or Switch.
    ///
    /// Uses `pending_connect` to queue a connection that fires automatically
    /// after the current disconnect completes, avoiding the race condition
    /// of starting connect while disconnect is still in-flight.
    pub(crate) fn toggle_connection(&mut self, idx: usize) {
        // Cancel this profile's retry / auto-reconnect when the user
        // initiates a new action on it. Other profiles' retry state is
        // independent (P5b U-P5b-1 per-profile retry).
        if let Some(target_profile) = self.runtime.profiles.get(idx) {
            self.runtime
                .retry_state
                .remove(&ProfileId::new(&target_profile.name));
        }

        // Multi-connection plan #001 U19: registry-aware Enter routing for
        // secondaries. If the focused row corresponds to a tunnel the
        // registry already knows about, disconnect/cancel it via the
        // registry path instead of falling through to the legacy single-
        // tunnel state machine (which only tracks one active profile).
        if let Some(target_profile) = self.runtime.profiles.get(idx) {
            use crate::vortix_core::engine::state::Connection;
            let target_id = ProfileId::new(&target_profile.name);
            if let Some(snap) = self.registry.snapshot(&target_id) {
                match snap.state {
                    Connection::Connected { .. } => {
                        // Uniform `(Connected, Enter_on_same)` arm — applies
                        // to both primary and secondary rows per U19's
                        // "no primary/secondary distinction" rule.
                        self.disconnect_profile_by_idx(idx);
                        return;
                    }
                    Connection::Connecting { .. } => {
                        // `(Connecting, Enter_on_same)` is a no-op; the
                        // user can press `c` on Connection Details to cancel.
                        return;
                    }
                    Connection::Disconnected { .. }
                    | Connection::Disconnecting { .. }
                    | Connection::AwaitingUserInput { .. }
                    | Connection::Reconnecting { .. } => {
                        // Fall through to the existing single-tunnel state
                        // machine: Disconnected → connect path; the other
                        // in-flight states defer to legacy handling.
                        // U19's primary scope is the Enter/d/D race-cases.
                    }
                }
            }
        }

        if let Some(target_profile) = self.runtime.profiles.get(idx) {
            let target_name = target_profile.name.clone();
            let legacy = self.legacy_state();
            match &legacy {
                // If connecting, ignore to prevent races
                ConnectionState::Connecting { .. } => {}
                // If disconnecting, queue the connection for after disconnect completes
                ConnectionState::Disconnecting { .. } => {
                    if let Some(old) = self.runtime.pending_connect {
                        if old != idx {
                            if let Some(old_profile) = self.runtime.profiles.get(old) {
                                self.log(&format!(
                                    "ACTION: Switched queue from '{}' to '{target_name}'",
                                    old_profile.name
                                ));
                            }
                        }
                    }
                    self.runtime.pending_connect = Some(idx);
                }
                ConnectionState::Connected {
                    profile: current_name,
                    ..
                } => {
                    if *current_name == target_name {
                        self.runtime.pending_connect = None;
                        self.disconnect();
                    } else {
                        // Multi-connection plan #001 U7: in the single-tunnel
                        // world this used to be "switch profile". With the
                        // registry, switching while connected is a
                        // default-route takeover by definition (the active
                        // tunnel holds the route, the new one wants it).
                        self.input_mode = InputMode::ConfirmDefaultRouteTakeover {
                            from: current_name.clone(),
                            to_profile_id: ProfileId::new(&target_name),
                            to_name: target_name,
                            confirm_selected: true,
                        };
                    }
                }
                // If disconnected -> Connect immediately
                ConnectionState::Disconnected => {
                    self.connect_profile(idx);
                }
            }
        }
    }

    /// Check for system-wide dependencies at startup and warn the user.
    pub(crate) fn check_system_dependencies(&mut self) {
        let mut missing: Vec<&str> = Vec::new();

        if !utils::binary_exists("openvpn") {
            missing.push("openvpn");
        }

        // wg / wg-quick both ship in wireguard-tools — single label so the
        // install hint doesn't duplicate when both are absent.
        if !utils::binary_exists("wg-quick") || !utils::binary_exists("wg") {
            missing.push("wireguard-tools");
        }

        if missing.is_empty() {
            return;
        }

        for tool in &missing {
            self.log(&format!(
                "WARN: '{}' not found - run: {}",
                tool,
                crate::platform::install_hint(tool)
            ));
        }

        self.show_toast(
            format!(
                "Missing tools: {}. Telemetry/VPN features may not work.",
                missing.join(", ")
            ),
            ToastType::Warning,
        );
    }

    /// Connect to a profile. Runs the multi-connection conflict check (plan
    /// #001 U7) before the existing tunnel-up flow; on conflict, fires the
    /// appropriate overlay and returns without touching the tunnel.
    pub(crate) fn connect_profile(&mut self, idx: usize) {
        self.connect_profile_inner(idx, false, false);
    }

    /// Bypass the multi-connection conflict check and force the connect.
    /// Called after the user accepts the [`InputMode::ConfirmDefaultRouteTakeover`]
    /// or [`InputMode::ConfirmRouteOverlap`] overlay.
    pub(crate) fn connect_profile_forced(&mut self, idx: usize) {
        self.connect_profile_inner(idx, true, false);
    }

    /// Connect immediately after the user submitted the auth overlay. Skips
    /// the static-challenge gate that would otherwise re-open the overlay
    /// (plan 2026-06-02-001 U3 — the OTP has just been written into the
    /// auth file; re-prompting would loop).
    pub(crate) fn connect_profile_after_auth(&mut self, idx: usize) {
        self.connect_profile_inner(idx, false, true);
    }

    #[allow(clippy::too_many_lines)]
    fn connect_profile_inner(&mut self, idx: usize, force: bool, skip_auth_overlay: bool) {
        // Clone needed data to release borrow on self
        let (name, protocol, config_path, cmd_tx) =
            if let Some(profile) = self.runtime.profiles.get(idx) {
                (
                    profile.name.clone(),
                    profile.protocol,
                    profile.config_path.clone(),
                    self.runtime.cmd_tx.clone(),
                )
            } else {
                return;
            };

        // Check dependencies FIRST (no point asking for root if tool is missing).
        // Single source of truth: VpnRuntime::check_dependencies — same gate
        // the CLI runs in `validate_connect`, so the two surfaces refuse
        // identical dep sets (including the OpenVPN 2.4+ probe).
        let missing = crate::vpn_runtime::VpnRuntime::check_dependencies(protocol, &config_path);
        if !missing.is_empty() {
            self.input_mode = InputMode::DependencyError { protocol, missing };
            return;
        }

        // Check root second
        if !self.runtime.is_root {
            self.input_mode = InputMode::PermissionDenied {
                action: format!("Manage {protocol}"),
            };
            return;
        }

        // Multi-connection plan #001 U7: route the connect path through
        // `registry.detect_conflict` before the existing tunnel-up flow.
        // When `force` is true (user just accepted the overlay), the gate
        // is skipped and we fall through to the legacy path.
        if !force {
            let target_id = ProfileId::new(&name);
            let allowed_ips = extract_allowed_ips(protocol, &config_path);
            if let Some(conflict) = self.registry.detect_conflict(&target_id, &allowed_ips) {
                self.fire_conflict_overlay(conflict, idx, name);
                return;
            }
        }

        // Check if OpenVPN config needs auth credentials. Two distinct
        // gates:
        //   - `static_challenge_prompt.is_some()` — the .ovpn declares a
        //     `static-challenge` directive (plan 2026-06-02-001 U3, #191).
        //     The OTP is single-use, so the overlay MUST fire on every
        //     connect attempt regardless of whether username/password are
        //     saved. When creds are saved we pre-fill them and focus the
        //     OTP field directly so the user only types the code.
        //   - `read_openvpn_saved_auth(...).is_none()` — legacy path for
        //     non-MFA `auth-user-pass` profiles. Show the overlay only
        //     when creds aren't saved; saved-creds connects go straight
        //     through.
        if !skip_auth_overlay
            && matches!(protocol, Protocol::OpenVPN)
            && utils::openvpn_config_needs_auth(&config_path)
        {
            let static_challenge_prompt = utils::read_openvpn_static_challenge_prompt(&config_path);
            let saved = utils::read_openvpn_saved_auth(&name);
            let force_overlay = static_challenge_prompt.is_some();
            if force_overlay || saved.is_none() {
                let (username, password) = saved.unwrap_or_default();
                let username_cursor = username.chars().count();
                let password_cursor = password.chars().count();
                // When the profile is MFA AND username+password are
                // pre-filled, focus the OTP field directly — the user
                // only needs to type the single-use code. Otherwise
                // start at Username (today's behaviour).
                let focused_field = if force_overlay && !username.is_empty() && !password.is_empty()
                {
                    crate::state::AuthField::Otp
                } else {
                    crate::state::AuthField::Username
                };
                self.input_mode = InputMode::AuthPrompt {
                    profile_idx: idx,
                    profile_name: name,
                    username,
                    username_cursor,
                    password,
                    password_cursor,
                    otp: String::new(),
                    otp_cursor: 0,
                    focused_field,
                    save_credentials: true,
                    connect_after: true,
                    static_challenge_prompt,
                };
                return;
            }
            // Saved creds exist AND no static-challenge -- they'll be
            // picked up in the connect thread below.
        }

        // Start connecting — write directly to the registry (P5d: the
        // legacy field is gone, the helper now also stamps the
        // started_at + attempt counters from the retry HashMap).
        let started_at = std::time::SystemTime::now();
        self.mirror_connecting_into_registry_at(&name, started_at);
        self.log(&format!("ACTION: Connecting to '{name}' [{protocol}]..."));

        let connect_timeout_secs = self.runtime.config.connect_timeout;
        let ovpn_verbosity = self.runtime.config.openvpn_verbosity.clone();

        // Plan #004 U4: route once via TunnelKind, no protocol match arm.
        std::thread::spawn(move || {
            use crate::vortix_core::profile::{Profile, ProfileId, ProtocolKind};

            let config_dir = crate::utils::get_app_config_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));
            let profile = Profile::new(
                ProfileId::new(&name),
                &name,
                match protocol {
                    Protocol::WireGuard => ProtocolKind::WireGuard,
                    Protocol::OpenVPN => ProtocolKind::OpenVpn,
                },
                config_path,
            );
            let mut tunnel = crate::tunnel::tunnel_for(
                protocol,
                &config_dir,
                &ovpn_verbosity,
                connect_timeout_secs,
            );

            match tunnel.up(&profile) {
                Ok(handle) => {
                    // Carry the authoritative iface + PID back to the
                    // main thread. Pre-U4 these were re-detected by the
                    // scanner; post-U4 the scanner is metadata-only,
                    // so this message IS the only seed path into the
                    // registry's `details.interface` field. R1 of the
                    // state-authority contract.
                    let _ = cmd_tx.send(Message::ConnectResult {
                        profile: name,
                        success: true,
                        error: None,
                        interface: Some(handle.interface_name),
                        pid: handle.pid,
                    });
                }
                Err(err) => {
                    let _ = cmd_tx.send(Message::ConnectResult {
                        profile: name,
                        success: false,
                        error: Some(format!("{protocol}: {err}")),
                        interface: None,
                        pid: None,
                    });
                }
            }
        });
    }

    /// Synchronizes the kill switch state with the current mode and
    /// connection status.
    ///
    /// Plan P5d: reads "is anything Connected?" and the active-tunnel
    /// slice from the registry instead of the (now-deleted) legacy
    /// `runtime.connection_state` field, then defers to
    /// `VpnRuntime::sync_killswitch` which carries the state-machine
    /// transitions and firewall calls.
    pub(crate) fn sync_killswitch(&mut self) {
        use crate::state::KillSwitchState;

        let is_connected = self.has_active_connection();
        let active = self.active_tunnels_for_killswitch();
        let pre_state = self.runtime.killswitch_state;
        self.runtime.sync_killswitch(is_connected, &active);
        // VpnRuntime::sync_killswitch silently downgrades a requested
        // Blocking state to Armed when not running as root. Surface
        // that to the user only when the downgrade actually happened
        // here (the runtime helper can't show toasts).
        if pre_state != KillSwitchState::Armed
            && self.runtime.killswitch_state == KillSwitchState::Armed
            && !self.runtime.is_root
            && matches!(
                self.runtime.killswitch_mode,
                crate::state::KillSwitchMode::AlwaysOn
            )
        {
            self.show_toast(
                "Kill switch requires root — run with sudo".to_string(),
                ToastType::Warning,
            );
            self.log("WARN: Kill switch blocked — not running as root");
        }
    }

    /// Kill any running VPN process and remove run files for a profile.
    ///
    /// Plan #004 U4: routes through the `TunnelKind` dispatch so this no
    /// longer match-branches on protocol.
    pub(crate) fn cleanup_vpn_resources(&self, profile_name: &str) {
        if let Some(profile) = self
            .runtime
            .profiles
            .iter()
            .find(|p| p.name == profile_name)
        {
            use crate::vortix_core::ports::tunnel::{TunnelHandle, TunnelKindTag};
            use crate::vortix_core::profile::ProfileId;

            let iface = match profile.protocol {
                Protocol::WireGuard => profile.config_path.to_string_lossy().into_owned(),
                Protocol::OpenVPN => {
                    format!("openvpn-{}", utils::sanitize_profile_name(profile_name))
                }
            };
            let pid = match profile.protocol {
                Protocol::OpenVPN => utils::read_openvpn_pid(profile_name),
                Protocol::WireGuard => None,
            };
            let handle = TunnelHandle {
                profile_id: ProfileId::new(profile_name),
                interface_name: iface,
                pid,
                started_at: std::time::SystemTime::now(),
                kind: match profile.protocol {
                    Protocol::WireGuard => TunnelKindTag::WireGuard,
                    Protocol::OpenVPN => TunnelKindTag::OpenVpn,
                },
            };

            let config_dir =
                utils::get_app_config_dir().unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));
            let mut tunnel = crate::tunnel::tunnel_for(profile.protocol, &config_dir, "3", 30);
            let _ = tunnel.down(handle);

            if matches!(profile.protocol, Protocol::OpenVPN) {
                utils::cleanup_openvpn_run_files(profile_name);
            }
        }
    }

    /// Finalize a disconnect: transition to `Disconnected`, sync kill switch,
    /// and drain `pending_connect` (auto-connect to the queued profile, if any).
    pub(crate) fn complete_disconnect(&mut self, profile_name: &str) {
        self.runtime.session_start = None;
        self.runtime.scanner_rx = None; // discard stale scanner data pre-disconnect
        self.flip_states.clear();

        self.runtime.public_ip = crate::constants::MSG_DETECTING.to_string();
        self.runtime.location = crate::constants::MSG_DETECTING.to_string();
        self.runtime.isp = crate::constants::MSG_DETECTING.to_string();
        self.runtime.dns_server = crate::constants::MSG_DETECTING.to_string();
        self.runtime.dns_leak = crate::core::dns_leak::DnsLeakStatus::Unknown;
        self.runtime.public_ipv6 = None;
        self.runtime.latency_ms = 0;
        self.runtime.packet_loss = 0.0;
        self.runtime.jitter_ms = 0;
        self.runtime.last_security_check = None;
        self.runtime.ip_unchanged_warned = false;
        self.runtime.current_down = 0;
        self.runtime.current_up = 0;

        // Clean up OpenVPN runtime files if this was an OpenVPN profile
        if self
            .runtime
            .profiles
            .iter()
            .any(|p| p.name == profile_name && matches!(p.protocol, Protocol::OpenVPN))
        {
            crate::utils::cleanup_openvpn_run_files(profile_name);
        }

        // Mirror the registry teardown BEFORE the pending-switch
        // branch's early return. The [S] flow on the takeover overlay
        // queues pending_connect; if we only mirrored in the
        // no-pending branch (the legacy shape), the old profile's
        // registry entry would leak across the switch — sidebar dot
        // staying green and header continuing to list the
        // disconnected tunnel even after logs reported success.
        self.mirror_disconnect_into_registry(profile_name);

        // Drain pending_connect: switch directly to the next profile
        if let Some(idx) = self.runtime.pending_connect.take() {
            if idx < self.runtime.profiles.len() {
                let next_name = self.runtime.profiles[idx].name.clone();
                self.log(&format!(
                    "STATUS: Disconnected from '{profile_name}', connecting to '{next_name}'..."
                ));
                self.sync_killswitch();
                self.connect_profile(idx);
                return;
            }
        }

        // Normal disconnect (no pending switch)
        self.log(&format!("STATUS: Disconnected from '{profile_name}'"));
        self.sync_killswitch();
        self.refresh_telemetry();
    }

    /// Mirror a legacy-path connect success into `self.registry` so the
    /// renderer-facing snapshots (header, sidebar, Connection Details,
    /// Security Guard) match the live tunnel state.
    ///
    /// Today the connect path drives `tunnel.up()` directly from a
    /// worker thread (see `connect_profile_inner`); the registry is
    /// touched only for the pre-up `detect_conflict` check. Plan 001
    /// U7 will eventually route the whole flow through
    /// `EngineHandle::Local`; until then, this mirror is how the
    /// registry stays in sync with kernel state.
    ///
    /// Implementation: copies the full `DetailedConnectionInfo` from
    /// `runtime.connection_state.details` (kernel-truthful values
    /// populated by the scanner — interface, pid, endpoint, mtu,
    /// transfer counters, public key) into the registry via
    /// [`TunnelRegistry::set_connected`](crate::vortix_core::engine::TunnelRegistry::set_connected).
    /// No `Tunnel::up` invocation;
    /// no synthetic handle. The placeholder `Engine<TunnelKind>` the
    /// registry constructs is never driven — its inner tunnel field
    /// is dead storage required only to satisfy the generic `T:
    /// Tunnel` bound.
    ///
    /// Why the rich details matter: renderers read these directly
    /// from the registry snapshot. With the prior MockTunnel-based
    /// shim, the FSM stored only `interface_name` + `pid` from the
    /// synthetic `TunnelHandle` — every other field
    /// (endpoint/mtu/etc.) defaulted to empty, so Connection Details
    /// showed `Server: empty`, `Role: Addressable (-)`, `Latency:
    /// n/a (secondary tunnel)`. With the bookkeeping API the entire
    /// `DetailedConnectionInfo` flows through unchanged.
    ///
    /// Idempotent: scanner ticks every ~1s re-call this with the
    /// latest details. `set_connected` updates the existing entry's
    /// state in place — no FSM churn.
    pub fn mirror_connect_into_registry(
        &mut self,
        profile_name: &str,
        details: &crate::vpn_runtime::DetailedConnectionInfo,
        since: Instant,
    ) {
        let Some(profile) = self
            .runtime
            .profiles
            .iter()
            .find(|p| p.name == profile_name)
            .cloned()
        else {
            return;
        };
        let profile_id = ProfileId::new(&profile.name);
        let allowed_ips = extract_allowed_ips(profile.protocol, &profile.config_path);
        let core_details = legacy_to_core_details(details);
        let elapsed = since.elapsed();
        let core_since = std::time::SystemTime::now()
            .checked_sub(elapsed)
            .unwrap_or_else(std::time::SystemTime::now);

        self.registry.set_connected(
            profile_id,
            allowed_ips,
            core_details,
            core_since,
            placeholder_engine_for_profile(&profile),
        );
    }

    /// Push fresh kernel-reported details for a profile into the
    /// registry directly from a scanner `ActiveSession`, bypassing the
    /// legacy `connection_state` field. Used by the per-profile
    /// scanner (P5b U-P5b-2) for secondary tunnels and adoption paths
    /// where the legacy slot is occupied by a different profile (or
    /// no-op when this is the only path keeping the registry fresh).
    ///
    /// Idempotent on the registry side (`set_connected` upserts the
    /// existing entry's state). When the profile isn't in the catalog
    /// or the registry has no prior entry, behaves the same as a fresh
    /// insertion via `set_connected`.
    /// Register a brand-new Connected entry from a scanner-detected
    /// session for a tunnel started outside vortix. This is the
    /// adoption-side counterpart to `mirror_connect_into_registry`
    /// (which handles vortix-started tunnels).
    ///
    /// U4 contract: this is the ONLY path other than
    /// `mirror_connect_into_registry` that creates a Connected entry.
    /// `refresh_registry_from_session` is strictly metadata-only on
    /// existing Connected entries and will early-return when the entry
    /// doesn't exist.
    ///
    /// The `interface_authoritative` flag is read from
    /// `session.interface_authoritative` (set by the scanner's
    /// platform-specific iface-detection method — see U5). Unauthoritative
    /// adoptions are excluded from primary-election candidacy per R4.
    pub fn adopt_registry_from_session(
        &mut self,
        profile_name: &str,
        session: &crate::core::scanner::ActiveSession,
    ) {
        let Some(profile) = self
            .runtime
            .profiles
            .iter()
            .find(|p| p.name == profile_name)
            .cloned()
        else {
            return;
        };
        let profile_id = ProfileId::new(&profile.name);
        let allowed_ips = extract_allowed_ips(profile.protocol, &profile.config_path);
        let core_details = crate::vortix_core::engine::state::DetailedConnectionInfo {
            interface: session.interface.clone(),
            interface_authoritative: session.interface_authoritative,
            internal_ip: session.internal_ip.clone(),
            endpoint: session.endpoint.clone(),
            mtu: session.mtu.clone(),
            public_key: session.public_key.clone(),
            listen_port: session.listen_port.clone(),
            transfer_rx: session.transfer_rx.clone(),
            transfer_tx: session.transfer_tx.clone(),
            latest_handshake: session.latest_handshake.clone(),
            pid: session.pid,
        };
        let since = session
            .started_at
            .unwrap_or_else(std::time::SystemTime::now);
        self.registry.set_connected(
            profile_id,
            allowed_ips,
            core_details,
            since,
            placeholder_engine_for_profile(&profile),
        );
    }

    pub fn refresh_registry_from_session(
        &mut self,
        profile_name: &str,
        session: &crate::core::scanner::ActiveSession,
    ) {
        // U4 contract: this function is metadata-only on existing
        // Connected entries. The interface name and
        // interface_authoritative flag are written exactly once — at
        // connect-success by `mirror_connect_into_registry` (Tunnel::up
        // path) or at adoption time by `scanner_adopt_session` — and
        // are NEVER overwritten by a scanner refresh. The scanner's
        // per-PID iface detection is unreliable enough on macOS
        // multi-OpenVPN that allowing it to win would silently corrupt
        // primary-election and per-tunnel killswitch ACCEPT rules.
        //
        // Therefore: if the entry doesn't exist OR isn't Connected,
        // early-return. The scanner can't drive state transitions;
        // that's the protocol layer's responsibility (or
        // scanner_adopt_session for genuinely-external tunnels).
        let Some(profile) = self
            .runtime
            .profiles
            .iter()
            .find(|p| p.name == profile_name)
            .cloned()
        else {
            return;
        };
        let profile_id = ProfileId::new(&profile.name);

        let Some(snap) = self.registry.snapshot(&profile_id) else {
            return;
        };
        let crate::vortix_core::engine::state::Connection::Connected {
            details: existing_details,
            since,
            ..
        } = snap.state
        else {
            return;
        };

        let allowed_ips = extract_allowed_ips(profile.protocol, &profile.config_path);
        // Interface and authoritativity carry over from the existing
        // entry verbatim — scanner never touches them. Mutable
        // metadata fields take the scanner's fresh observation.
        let refreshed_details = crate::vortix_core::engine::state::DetailedConnectionInfo {
            interface: existing_details.interface.clone(),
            interface_authoritative: existing_details.interface_authoritative,
            internal_ip: session.internal_ip.clone(),
            endpoint: session.endpoint.clone(),
            mtu: session.mtu.clone(),
            public_key: session.public_key.clone(),
            listen_port: session.listen_port.clone(),
            transfer_rx: session.transfer_rx.clone(),
            transfer_tx: session.transfer_tx.clone(),
            latest_handshake: session.latest_handshake.clone(),
            pid: session.pid,
        };
        self.registry.set_connected(
            profile_id,
            allowed_ips,
            refreshed_details,
            since,
            placeholder_engine_for_profile(&profile),
        );
    }

    /// Mirror a legacy-path disconnect into `self.registry`: seed the
    /// registry's FSM to `Disconnected` (without running `Disconnecting`
    /// or `tunnel.down()`) and remove the entry. Idempotent — a profile
    /// the registry never had is a no-op.
    pub fn mirror_disconnect_into_registry(&mut self, profile_name: &str) {
        let profile_id = ProfileId::new(profile_name);
        self.registry.set_disconnected(&profile_id);
    }

    /// Mirror a legacy-path Connecting transition into `self.registry`
    /// so renderers show the `◐` badge during the connect window. Called
    /// from `connect_profile_inner` right after setting
    /// `connection_state = Connecting{...}` and spawning the worker
    /// thread. Without this the sidebar/header stay blank for the
    /// (sometimes seconds-long) gap until the worker reports back.
    pub fn mirror_connecting_into_registry_at(
        &mut self,
        profile_name: &str,
        started_at: std::time::SystemTime,
    ) {
        let Some(profile) = self
            .runtime
            .profiles
            .iter()
            .find(|p| p.name == profile_name)
            .cloned()
        else {
            return;
        };
        let profile_id = ProfileId::new(&profile.name);
        let allowed_ips = extract_allowed_ips(profile.protocol, &profile.config_path);
        let attempt = self
            .runtime
            .retry_state
            .get(&profile_id)
            .map_or(1, |r| r.attempt);
        let retry_budget = std::time::Duration::from_secs(
            crate::vortix_core::engine::state::DEFAULT_RETRY_BUDGET_SECS,
        );
        self.registry.set_connecting(
            profile_id,
            allowed_ips,
            started_at,
            attempt,
            retry_budget,
            placeholder_engine_for_profile(&profile),
        );
    }

    /// Convenience wrapper: anchor `started_at` to "now". Used by
    /// callsites that don't have a pre-computed start time.
    pub fn mirror_connecting_into_registry(&mut self, profile_name: &str) {
        self.mirror_connecting_into_registry_at(profile_name, std::time::SystemTime::now());
    }

    /// Mirror a legacy-path Disconnecting transition into
    /// `self.registry` so renderers show the `◑` badge during the
    /// teardown window. Called when the legacy `disconnect()` enters
    /// Disconnecting state. No-op when the registry doesn't already
    /// have a Connected entry to transition — `set_disconnecting`
    /// internally skips missing entries.
    pub fn mirror_disconnecting_into_registry(&mut self, profile_name: &str) {
        let profile_id = ProfileId::new(profile_name);
        let started_at = std::time::SystemTime::now();
        self.registry.set_disconnecting(&profile_id, started_at);
    }

    /// Mirror a failed-connect outcome into `self.registry` so
    /// renderers show the `✗` badge until the user retries or
    /// dismisses. Called from `handle_connect_result`'s failure
    /// branch.
    pub fn mirror_failed_into_registry(&mut self, profile_name: &str, error: &str) {
        let Some(profile) = self
            .runtime
            .profiles
            .iter()
            .find(|p| p.name == profile_name)
            .cloned()
        else {
            return;
        };
        let profile_id = ProfileId::new(&profile.name);
        let allowed_ips = extract_allowed_ips(profile.protocol, &profile.config_path);
        // Map the error string to a `FailureReason`. The legacy connect
        // path stringifies the TunnelError before passing it back via
        // Message::ConnectResult, so we can't recover the structured
        // variant here. Use the generic `Other(msg)` carrier — when
        // P5 retires the legacy mirror and the FSM drives directly,
        // we'll get the typed reason back via the FSM's
        // `handle_connect_failure` path.
        let failure = crate::vortix_core::engine::state::FailureReason::Other(error.to_string());
        self.registry.set_failed(
            profile_id,
            allowed_ips,
            failure,
            placeholder_engine_for_profile(&profile),
        );
    }

    #[allow(clippy::too_many_lines)]
    /// Global single-tunnel disconnect — finds the profile from the
    /// derived legacy view (registry primary) and delegates to
    /// [`disconnect_specific`] for the real teardown. Used by the
    /// `d` key on non-sidebar panels and the legacy `Message::Disconnect`
    /// path.
    pub(crate) fn disconnect(&mut self) {
        let target = match self.legacy_state() {
            ConnectionState::Connected { profile, .. }
            | ConnectionState::Connecting { profile, .. }
            | ConnectionState::Disconnecting { profile, .. } => Some(profile),
            ConnectionState::Disconnected => None,
        };
        if let Some(name) = target {
            self.disconnect_specific(&name);
        }
    }

    /// Force-disconnect: escalates a stuck disconnect.
    pub(crate) fn force_disconnect(&mut self) {
        let ConnectionState::Disconnecting {
            profile: profile_name,
            ..
        } = self.legacy_state()
        else {
            return;
        };

        self.runtime.scanner_rx = None; // discard stale scanner data

        let force_info = self
            .runtime
            .profiles
            .iter()
            .find(|p| p.name == profile_name)
            .map(|profile| {
                (
                    profile.name.clone(),
                    profile.protocol,
                    profile.config_path.clone(),
                    self.runtime.cmd_tx.clone(),
                )
            });

        if let Some((name, protocol, config_path, cmd_tx)) = force_info {
            self.log(&format!("ACTION: Force-disconnecting '{name}'..."));
            self.show_toast(
                format!("Force-disconnecting '{name}'..."),
                ToastType::Warning,
            );

            // Reset the Disconnecting timer (registry-side) so the 30s
            // safety timeout starts fresh on this force-disconnect tick.
            self.mirror_disconnecting_into_registry(&name);

            // Plan #004 U4: force-disconnect now routes through TunnelKind.
            // The OvpnTunnel's down() path already escalates to pkill if the
            // pid file is stale; treating the force-flag as equivalent to a
            // regular down preserves the existing semantics on macOS where
            // SIGKILL was used (TODO plan #005: add a force flag to Tunnel
            // trait to escalate to SIGKILL where supported).
            std::thread::spawn(move || {
                use crate::vortix_core::ports::tunnel::{TunnelHandle, TunnelKindTag};
                use crate::vortix_core::profile::ProfileId;

                let iface = match protocol {
                    Protocol::WireGuard => config_path.to_string_lossy().into_owned(),
                    Protocol::OpenVPN => {
                        format!("openvpn-{}", crate::utils::sanitize_profile_name(&name))
                    }
                };
                let pid_for_handle = match protocol {
                    Protocol::OpenVPN => crate::utils::read_openvpn_pid(&name),
                    Protocol::WireGuard => None,
                };
                let handle = TunnelHandle {
                    profile_id: ProfileId::new(&name),
                    interface_name: iface,
                    pid: pid_for_handle,
                    started_at: std::time::SystemTime::now(),
                    kind: match protocol {
                        Protocol::WireGuard => TunnelKindTag::WireGuard,
                        Protocol::OpenVPN => TunnelKindTag::OpenVpn,
                    },
                };
                let config_dir = crate::utils::get_app_config_dir()
                    .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));
                let mut tunnel = crate::tunnel::tunnel_for(protocol, &config_dir, "3", 30);

                match tunnel.down(handle) {
                    Ok(()) => {
                        if matches!(protocol, Protocol::OpenVPN) {
                            crate::utils::cleanup_openvpn_run_files(&name);
                        }
                        let _ = cmd_tx.send(Message::DisconnectResult {
                            profile: name,
                            success: true,
                            error: None,
                        });
                    }
                    Err(err) => {
                        let _ = cmd_tx.send(Message::DisconnectResult {
                            profile: name,
                            success: false,
                            error: Some(format!("Force {protocol}: {err}")),
                        });
                    }
                }
            });
        }
    }

    /// Fire the appropriate confirm overlay for a registry-reported
    /// conflict (plan #001 U7). Logs an ACTION line so the activity panel
    /// reflects the blocked attempt.
    fn fire_conflict_overlay(&mut self, conflict: Conflict, _idx: usize, target_name: String) {
        match conflict {
            Conflict::DefaultRouteTakeover { current, new } => {
                self.log(&format!(
                    "ACTION: Connect to '{target_name}' blocked by default-route takeover ('{current}' holds 0/0)"
                ));
                self.input_mode = InputMode::ConfirmDefaultRouteTakeover {
                    from: current.as_str().to_string(),
                    to_profile_id: new,
                    to_name: target_name,
                    confirm_selected: true,
                };
            }
            Conflict::RouteOverlap {
                with,
                overlapping_cidrs,
            } => {
                self.log(&format!(
                    "ACTION: Connect to '{target_name}' blocked by route-overlap with '{with}' ({} CIDR(s))",
                    overlapping_cidrs.len()
                ));
                self.input_mode = InputMode::ConfirmRouteOverlap {
                    with_profile_id: with,
                    overlapping_cidrs,
                    to_profile_id: ProfileId::new(&target_name),
                    to_name: target_name,
                    confirm_selected: true,
                };
            }
        }
    }

    /// Disconnect a specific profile by sidebar index (multi-connection
    /// plan #001 U19). Drives the real per-protocol teardown via
    /// [`disconnect_specific`] — that's what actually kills the
    /// wg-quick / openvpn process. The registry's own `disconnect`
    /// would only drive the placeholder `MockTunnel` and leave the
    /// kernel interface running. No-op when the profile isn't in
    /// the catalog or isn't currently active.
    pub(crate) fn disconnect_profile_by_idx(&mut self, idx: usize) {
        let Some(profile) = self.runtime.profiles.get(idx) else {
            return;
        };
        let name = profile.name.clone();
        if !self.is_profile_active(&name) {
            return;
        }
        self.disconnect_specific(&name);
    }

    /// Tear down every active tunnel (multi-connection plan #001 U19).
    /// Used by Shift+`D` after the user confirms the
    /// [`InputMode::ConfirmDisconnectAll`] dialog, and by the
    /// `Message::Disconnect` global when only one tunnel exists.
    ///
    /// Critically: the per-tunnel teardown spawns a real
    /// `tunnel.down()` thread for each active profile via
    /// `disconnect_specific`. Calling only `registry.disconnect()`
    /// drives the placeholder `MockTunnel` (from
    /// `mirror_connect_into_registry`) which removes the registry
    /// entry but does NOT kill the real wg-quick / openvpn process —
    /// that's what an earlier version of this method did and it left
    /// every secondary tunnel's kernel interface running while the
    /// sidebar lied that they were down.
    pub(crate) fn disconnect_all_active(&mut self) {
        // Snapshot the active profile names first so we don't hold
        // any borrows across mutation. We need profile NAMES (not
        // just ids) because the per-tunnel disconnect needs the
        // profile/protocol/config_path to drive the real teardown.
        let names: Vec<String> = self
            .active_tunnel_ids()
            .into_iter()
            .map(|id| id.as_str().to_string())
            .collect();
        let count = names.len();
        self.log(&format!(
            "ACTION: Disconnecting all {count} active tunnel(s)..."
        ));

        for name in &names {
            self.disconnect_specific(name);
        }
    }

    /// Disconnect a single named profile via the real protocol
    /// teardown (`tunnel.down()` in a spawned thread). Mirrors the
    /// Disconnecting transition into the registry, clears that
    /// profile's retry state, and syncs the kill switch.
    ///
    /// Used by [`disconnect_all_active`], [`disconnect_profile_by_idx`]
    /// (for non-primary tunnels), and [`disconnect`] (which derives
    /// the target from `legacy_state` and then delegates here).
    /// No-op when the named profile isn't in the catalog.
    fn disconnect_specific(&mut self, profile_name: &str) {
        use crate::vortix_core::engine::state::Connection;

        // Clear this profile's retry / auto-reconnect entry (per-
        // profile, not global).
        let profile_id = ProfileId::new(profile_name);
        self.runtime.retry_state.remove(&profile_id);
        // Discard any in-flight scanner result so stale data doesn't
        // re-promote this profile back to Connected after teardown.
        self.runtime.scanner_rx = None;

        let Some(profile) = self
            .runtime
            .profiles
            .iter()
            .find(|p| p.name == profile_name)
            .cloned()
        else {
            return;
        };
        let protocol = profile.protocol;
        let config_path = profile.config_path.clone();
        let cmd_tx = self.runtime.cmd_tx.clone();

        // Recover the OpenVPN PID from the registry's snapshot (the
        // scanner refresh populates it). Falls through to None for
        // WireGuard or when the registry has no Connected entry.
        let pid = self
            .registry
            .snapshot(&profile_id)
            .and_then(|snap| match snap.state {
                Connection::Connected { details, .. } => details.pid,
                _ => None,
            });

        self.log(&format!("ACTION: Disconnecting from '{profile_name}'..."));

        // Mirror the Disconnecting transition into the registry so
        // renderers show the `◑` badge during the teardown window.
        self.mirror_disconnecting_into_registry(profile_name);

        // Sync kill switch (multi-tunnel-aware via the registry).
        self.sync_killswitch();
        if self.runtime.killswitch_state.is_blocking() {
            self.show_toast(
                "Kill Switch blocking - Strict mode active".to_string(),
                ToastType::Warning,
            );
        }

        let pn = profile_name.to_string();
        std::thread::spawn(move || {
            use crate::vortix_core::ports::tunnel::{TunnelHandle, TunnelKindTag};

            let iface = match protocol {
                Protocol::WireGuard => config_path.to_string_lossy().into_owned(),
                Protocol::OpenVPN => {
                    format!("openvpn-{}", crate::utils::sanitize_profile_name(&pn))
                }
            };
            let pid_for_handle = match protocol {
                Protocol::OpenVPN => crate::utils::read_openvpn_pid(&pn).or(pid),
                Protocol::WireGuard => None,
            };
            let handle = TunnelHandle {
                profile_id: ProfileId::new(&pn),
                interface_name: iface,
                pid: pid_for_handle,
                started_at: std::time::SystemTime::now(),
                kind: match protocol {
                    Protocol::WireGuard => TunnelKindTag::WireGuard,
                    Protocol::OpenVPN => TunnelKindTag::OpenVpn,
                },
            };
            let config_dir = crate::utils::get_app_config_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));
            let mut tunnel = crate::tunnel::tunnel_for(protocol, &config_dir, "3", 30);

            match tunnel.down(handle) {
                Ok(()) => {
                    if matches!(protocol, Protocol::OpenVPN) {
                        crate::utils::cleanup_openvpn_run_files(&pn);
                    }
                    let _ = cmd_tx.send(Message::DisconnectResult {
                        profile: pn,
                        success: true,
                        error: None,
                    });
                }
                Err(err) => {
                    let _ = cmd_tx.send(Message::DisconnectResult {
                        profile: pn,
                        success: false,
                        error: Some(format!("{protocol}: {err}")),
                    });
                }
            }
        });
    }

    /// Cancel an in-flight connect (multi-connection plan #001 U19).
    /// Currently delegates to the existing disconnect machinery — the
    /// legacy `disconnect()` already handles the Connecting state
    /// (extracting the in-flight profile and transitioning to
    /// Disconnecting). Registry-aware cancellation lands when the
    /// registry-driven connect path arrives in a later unit.
    pub(crate) fn cancel_connect(&mut self, idx: usize) {
        let Some(profile) = self.runtime.profiles.get(idx) else {
            return;
        };
        let name = profile.name.clone();
        self.log(&format!(
            "ACTION: Cancelling in-flight connect for '{name}'"
        ));

        // Registry-first: if the FSM tracks this connect, drive a
        // Disconnect through it.
        let target_id = ProfileId::new(&name);
        if self.registry.snapshot(&target_id).is_some() {
            if let Err(err) = self.registry.disconnect(&target_id) {
                self.log(&format!("ERR: registry.disconnect('{name}') failed: {err}"));
            }
        }

        // Derived legacy view: if this profile is still in Connecting
        // there, drive the global disconnect (covers the path where
        // the registry didn't have an entry but the legacy slot did).
        if self.legacy_matches_connecting(&name) {
            self.disconnect();
        }
    }

    /// Reconnect to VPN: queues the same profile for auto-connect after disconnect.
    pub(crate) fn reconnect(&mut self) {
        let legacy = self.legacy_state();
        match &legacy {
            ConnectionState::Connected { profile, .. } => {
                let profile_name = profile.clone();
                if let Some(idx) = self
                    .runtime
                    .profiles
                    .iter()
                    .position(|p| p.name == profile_name)
                {
                    self.runtime.pending_connect = Some(idx);
                    self.disconnect();
                }
            }
            ConnectionState::Disconnected => {
                if let Some(ref last) = self.runtime.last_connected_profile {
                    if let Some(idx) = self.runtime.profiles.iter().position(|p| p.name == *last) {
                        self.log(&format!("STATUS: Reconnecting to '{last}'"));
                        self.connect_profile(idx);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Build the `Profile` that the registry's `profile_resolver` closure
/// returns for the mirror-into-registry path. Mirrors the inline
/// construction inside `connect_profile_inner`'s spawned thread so the
/// two paths produce identical `Profile` values for the same
/// `VpnProfile` row.
fn profile_for_resolver(
    profile: &crate::state::VpnProfile,
) -> crate::vortix_core::profile::Profile {
    use crate::vortix_core::profile::{Profile, ProfileId, ProtocolKind};
    Profile::new(
        ProfileId::new(&profile.name),
        &profile.name,
        match profile.protocol {
            Protocol::WireGuard => ProtocolKind::WireGuard,
            Protocol::OpenVPN => ProtocolKind::OpenVpn,
        },
        profile.config_path.clone(),
    )
}

/// Copy the legacy `vpn_runtime::DetailedConnectionInfo` (populated by
/// the scanner with kernel-truthful values) into the
/// `vortix_core::engine::state::DetailedConnectionInfo` shape that
/// `TunnelRegistry` stores. The two structs have identical field
/// names + types; this is a straight field-for-field translation.
fn legacy_to_core_details(
    legacy: &crate::vpn_runtime::DetailedConnectionInfo,
) -> crate::vortix_core::engine::state::DetailedConnectionInfo {
    crate::vortix_core::engine::state::DetailedConnectionInfo {
        interface: legacy.interface.clone(),
        internal_ip: legacy.internal_ip.clone(),
        endpoint: legacy.endpoint.clone(),
        mtu: legacy.mtu.clone(),
        public_key: legacy.public_key.clone(),
        listen_port: legacy.listen_port.clone(),
        transfer_rx: legacy.transfer_rx.clone(),
        transfer_tx: legacy.transfer_tx.clone(),
        latest_handshake: legacy.latest_handshake.clone(),
        pid: legacy.pid,
        // mirror_connect_into_registry funnels through this helper after
        // `Tunnel::up()` succeeds. The interface is authoritative by
        // construction — it's whatever the protocol layer (OpenVPN log
        // scrape / wg-quick + platform port resolution) returned.
        interface_authoritative: true,
    }
}

/// Construct a placeholder `Engine<TunnelKind>` for the bookkeeping
/// mirror path. The returned engine's tunnel field is dead storage —
/// `TunnelRegistry::set_connected` seeds the FSM's state directly via
/// `Engine::seed_connected_state` immediately after construction, so
/// `Tunnel::up`/`down`/`status` are never invoked.
///
/// `TunnelKind::Mock(MockTunnel::new())` is used as the inert filler
/// because `Engine<T>` requires `T: Tunnel` and we need *some* impl
/// to satisfy the bound — not because the engine ever calls into it.
/// When U7 lands and the connect path drives the registry directly,
/// this whole helper becomes dead code.
fn placeholder_engine_for_profile(
    profile: &crate::state::VpnProfile,
) -> impl FnOnce() -> crate::vortix_core::engine::Engine<crate::tunnel::TunnelKind> {
    let resolved_profile = profile_for_resolver(profile);
    let profile_resolver = move |_id: &ProfileId| Some(resolved_profile.clone());
    move || {
        let placeholder_tunnel = crate::tunnel::TunnelKind::Mock(
            crate::vortix_core::ports::tunnel::mock::MockTunnel::new(),
        );
        crate::vortix_core::engine::Engine::new(placeholder_tunnel, profile_resolver)
    }
}

/// Extract the `AllowedIPs` (`WireGuard`) or `route` directives (`OpenVPN`)
/// from a profile config file into the shared `vortix_core::cidr::Cidr`
/// representation that `TunnelRegistry::detect_conflict` consumes.
///
/// Plan #001 U7: this is the App-side adapter that bridges the per-protocol
/// parsers' route declarations into the registry's conflict-detection
/// surface. Unparseable files return an empty list so the conflict gate
/// degrades to "no conflict" (the existing tunnel-up path will still
/// surface a parse failure if applicable).
pub(crate) fn extract_allowed_ips(protocol: Protocol, config_path: &std::path::Path) -> Vec<Cidr> {
    let Ok(text) = std::fs::read_to_string(config_path) else {
        return Vec::new();
    };
    match protocol {
        Protocol::WireGuard => extract_wg_allowed_ips(&text),
        Protocol::OpenVPN => extract_ovpn_routes(&text),
    }
}

/// Walk a `.conf` body and collect every `AllowedIPs` entry across all
/// `[Peer]` sections as `vortix_core::cidr::Cidr`. The `WireGuard` parser
/// uses its own local `Cidr` type; converting at the App boundary keeps
/// the shared `vortix_core` types canonical for downstream consumers.
fn extract_wg_allowed_ips(text: &str) -> Vec<Cidr> {
    let Ok(parsed) = crate::vortix_protocol_wireguard::parser::parse_wg_conf(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for peer in &parsed.peers {
        for c in &peer.allowed_ips {
            // Both Cidr types share the same field shape (addr, prefix_len);
            // `Cidr::new` re-validates the prefix bound.
            if let Some(converted) = Cidr::new(c.addr, c.prefix_len) {
                out.push(converted);
            }
        }
    }
    out
}

/// Best-effort extraction of `route` directives from an `.ovpn` file. Only
/// canonical `route <ip> <netmask>` and `route-ipv6 <prefix>` forms are
/// recognised; anything else is skipped silently (the registry's role in
/// U7 is detection, not validation — the `OpenVPN` binary still owns parse
/// errors). Returns an empty list when nothing parses.
fn extract_ovpn_routes(text: &str) -> Vec<Cidr> {
    use std::net::{IpAddr, Ipv4Addr};
    let mut out = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(directive) = parts.next() else {
            continue;
        };
        match directive {
            "redirect-gateway" => {
                // Push the full IPv4 default route on the client; the
                // registry's `claims_default_route_v4` recognises 0/0.
                if let Some(c) = Cidr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0) {
                    out.push(c);
                }
            }
            "route" => {
                let Some(addr_s) = parts.next() else { continue };
                let Ok(addr) = addr_s.parse::<Ipv4Addr>() else {
                    continue;
                };
                let prefix = match parts.next() {
                    Some(mask_s) => mask_s
                        .parse::<Ipv4Addr>()
                        .ok()
                        .map_or(32, ipv4_netmask_to_prefix),
                    None => 32,
                };
                if let Some(c) = Cidr::new(IpAddr::V4(addr), prefix) {
                    out.push(c);
                }
            }
            "route-ipv6" => {
                let Some(cidr_s) = parts.next() else { continue };
                if let Ok(c) = cidr_s.parse::<Cidr>() {
                    out.push(c);
                }
            }
            _ => {}
        }
    }
    out
}

fn ipv4_netmask_to_prefix(mask: std::net::Ipv4Addr) -> u8 {
    let bits = u32::from(mask);
    // count contiguous leading 1-bits; non-canonical masks degrade to /32
    // (treated as "very specific") rather than poisoning the conflict gate.
    if bits == 0 {
        return 0;
    }
    let leading = bits.leading_ones();
    // verify it's a contiguous prefix
    let expected = u32::MAX.checked_shl(32 - leading).unwrap_or(0);
    if bits == expected {
        // `leading` is bounded by 32 (u32 bit width), so the cast is safe.
        u8::try_from(leading).unwrap_or(32)
    } else {
        32
    }
}

#[cfg(test)]
mod u7_conflict_tests {
    //! Plan #001 U7 — App-side conflict-detection wiring.
    //!
    //! Coverage focuses on the App's role: extracting `AllowedIPs` from a
    //! profile config and translating a `Conflict` variant into the right
    //! `InputMode` overlay. The registry's `detect_conflict` itself is
    //! tested in `vortix_core::engine::registry`.
    use super::{extract_allowed_ips, extract_ovpn_routes, extract_wg_allowed_ips, Protocol};
    use crate::vortix_core::cidr::claims_default_route_v4;
    use std::io::Write;

    fn write_tmp(name: &str, body: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("vortix_u7_tests");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).expect("create tmp config");
        f.write_all(body.as_bytes()).expect("write tmp config");
        path
    }

    #[test]
    fn wg_parser_extracts_default_route_v4() {
        let body = "\
[Interface]
PrivateKey = aGVsbG8=
Address = 10.0.0.2/32

[Peer]
PublicKey = d29ybGQ=
AllowedIPs = 0.0.0.0/0
Endpoint = 1.2.3.4:51820
";
        let cidrs = extract_wg_allowed_ips(body);
        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0].prefix_len, 0);
    }

    #[test]
    fn wg_parser_extracts_disjoint_subnet() {
        let body = "\
[Interface]
PrivateKey = aGVsbG8=

[Peer]
PublicKey = d29ybGQ=
AllowedIPs = 10.0.0.0/24, 192.168.5.0/24
Endpoint = 1.2.3.4:51820
";
        let cidrs = extract_wg_allowed_ips(body);
        assert_eq!(cidrs.len(), 2);
        // Disjoint /24s — neither claims the default route.
        assert!(!claims_default_route_v4(&cidrs));
    }

    #[test]
    fn ovpn_redirect_gateway_yields_default_route() {
        let body = "\
client
dev tun
remote vpn.example.com 1194
redirect-gateway def1
";
        let cidrs = extract_ovpn_routes(body);
        assert!(!cidrs.is_empty());
        assert!(claims_default_route_v4(&cidrs));
    }

    #[test]
    fn ovpn_route_with_netmask_parses_to_prefix() {
        let body = "\
client
dev tun
route 10.0.0.0 255.255.255.0
";
        let cidrs = extract_ovpn_routes(body);
        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0].prefix_len, 24);
    }

    #[test]
    fn unreadable_path_returns_empty() {
        let p = std::path::PathBuf::from("/nonexistent/vortix_u7/never.conf");
        let cidrs = extract_allowed_ips(Protocol::WireGuard, &p);
        assert!(cidrs.is_empty());
    }

    #[test]
    fn fire_default_route_takeover_sets_overlay() {
        use super::App;
        use crate::vortix_core::engine::Conflict;
        use crate::vortix_core::profile::ProfileId;

        let mut app = App::new_test();
        let conflict = Conflict::DefaultRouteTakeover {
            current: ProfileId::new("home"),
            new: ProfileId::new("corp"),
        };
        app.fire_conflict_overlay(conflict, 0, "corp".to_string());
        assert!(matches!(
            app.input_mode,
            crate::state::InputMode::ConfirmDefaultRouteTakeover { ref from, .. }
                if from == "home"
        ));
    }

    #[test]
    fn fire_route_overlap_sets_overlay() {
        use super::App;
        use crate::vortix_core::cidr::Cidr;
        use crate::vortix_core::engine::Conflict;
        use crate::vortix_core::profile::ProfileId;

        let mut app = App::new_test();
        let cidr: Cidr = "10.0.0.0/8".parse().unwrap();
        let conflict = Conflict::RouteOverlap {
            with: ProfileId::new("home"),
            overlapping_cidrs: vec![cidr],
        };
        app.fire_conflict_overlay(conflict, 1, "corp".to_string());
        match &app.input_mode {
            crate::state::InputMode::ConfirmRouteOverlap {
                with_profile_id,
                overlapping_cidrs,
                ..
            } => {
                assert_eq!(with_profile_id.as_str(), "home");
                assert_eq!(overlapping_cidrs.len(), 1);
            }
            other => panic!("expected ConfirmRouteOverlap, got {other:?}"),
        }
    }

    #[test]
    fn connect_with_empty_registry_skips_overlay() {
        // Multi-connection plan #001 U7: until U6 Stage B populates the
        // registry, detect_conflict against an empty registry always
        // returns None — the connect path proceeds without firing the
        // overlay. This locks in the "no false-positive" invariant.
        use super::App;
        use crate::state::InputMode;
        let path = write_tmp("u7_skip.conf", "[Interface]\nPrivateKey = a=\n");
        let app = App::new_test();
        let allowed = extract_allowed_ips(Protocol::WireGuard, &path);
        let conflict = app.registry.detect_conflict(
            &crate::vortix_core::profile::ProfileId::new("any"),
            &allowed,
        );
        assert!(conflict.is_none());
        assert!(matches!(app.input_mode, InputMode::Normal));
    }
}
