//! VPN connection lifecycle management and kill switch control.

use std::sync::OnceLock;
use std::time::Instant;

use super::{App, ConnectionState, InputMode, Protocol, ToastType};
use crate::message::Message;
use crate::utils;
use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::engine::Conflict;
use crate::vortix_core::profile::ProfileId;
use crate::vortix_process::{self, CommandSpec};

/// Semantic version of an installed `openvpn` binary, as reported by
/// `openvpn --version`. Used by `check_dependencies` to assert the
/// `--pull-filter` multi-tunnel-DNS-suppression baseline (plan 001 U14, R13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OvpnVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl OvpnVersion {
    /// Minimum `OpenVPN` release supporting `--pull-filter` reliably. Anything
    /// older fails multi-tunnel's DNS-scoping precondition (R13).
    const MIN_MULTI_TUNNEL: Self = Self {
        major: 2,
        minor: 4,
        patch: 0,
    };

    fn supports_multi_tunnel_dns(self) -> bool {
        self >= Self::MIN_MULTI_TUNNEL
    }
}

impl std::fmt::Display for OvpnVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Outcome of probing `openvpn --version`.
#[derive(Debug, Clone)]
pub(crate) enum OvpnVersionProbe {
    /// Parsed a usable semantic version from `--version` stdout.
    Parsed(OvpnVersion),
    /// `--version` ran but its first line did not contain a parseable
    /// `OpenVPN <X.Y.Z>` token. The `--help` fallback was consulted and
    /// confirmed `--pull-filter` is present.
    HelpFallbackOk,
    /// Both `--version` parsing and the `--help` fallback failed — we cannot
    /// confirm the binary supports `--pull-filter`. Treated as a missing
    /// dependency for multi-tunnel.
    Unparseable,
}

/// Parse the `OpenVPN` semantic version from the first line of `openvpn --version`.
///
/// The stable format across `OpenVPN` 2.x / 3.x releases is:
/// `OpenVPN <major>.<minor>.<patch>[<suffix>] ...`. Vendor-patched builds
/// occasionally prefix the line (e.g. `Vendor-OpenVPN 2.5.8 ...`) — we scan
/// for the `OpenVPN ` token rather than anchoring to the start so those still
/// parse.
pub(crate) fn parse_openvpn_version(stdout: &str) -> Option<OvpnVersion> {
    let first_line = stdout.lines().next()?;
    // Locate the `OpenVPN ` marker (case-sensitive — every upstream release
    // uses this exact capitalisation).
    let after = first_line.find("OpenVPN ").map(|i| i + "OpenVPN ".len())?;
    let rest = &first_line[after..];
    // Take the next whitespace-delimited token, then strip any trailing
    // non-digit / non-dot suffix (e.g. `2.5.8-git` → `2.5.8`).
    let token = rest.split_whitespace().next()?;
    let core: String = token
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    let patch = parts.next().unwrap_or("0").parse::<u32>().unwrap_or(0);
    Some(OvpnVersion {
        major,
        minor,
        patch,
    })
}

/// Cached outcome of probing `openvpn --version` (plan 001 U14). The subprocess
/// runs at most once per process lifetime; subsequent dependency checks reuse
/// the cached value.
static OVPN_VERSION_PROBE: OnceLock<OvpnVersionProbe> = OnceLock::new();

/// Probe the installed `openvpn` for its version, falling back to a `--help`
/// grep when `--version` is unparseable. Cached for the process lifetime.
///
/// Prefers `--version` because its first-line format has stayed stable across
/// every `OpenVPN` 2.x / 3.x release; the `--help` grep is a last resort because
/// distro-patched help text can either omit the `--pull-filter` line on a
/// capable binary (false negative) or list it on a binary that doesn't
/// actually implement it (false positive).
pub(crate) fn probe_openvpn_version() -> OvpnVersionProbe {
    OVPN_VERSION_PROBE
        .get_or_init(probe_openvpn_version_uncached)
        .clone()
}

fn probe_openvpn_version_uncached() -> OvpnVersionProbe {
    // xtask:allow-protocol-leak: dependency-version probe runs before any tunnel exists; app-layer concern (R13)
    let version_output =
        vortix_process::run_to_output(CommandSpec::oneshot("openvpn", vec!["--version".into()]));
    if let Ok(out) = version_output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        // openvpn --version exits with code 1 by convention but still prints
        // the version banner to stdout — accept both 0 and 1 here.
        if let Some(v) = parse_openvpn_version(&stdout) {
            return OvpnVersionProbe::Parsed(v);
        }
        // Some vendor builds print the banner on stderr; check there too.
        let stderr = String::from_utf8_lossy(&out.stderr);
        if let Some(v) = parse_openvpn_version(&stderr) {
            return OvpnVersionProbe::Parsed(v);
        }
    }

    // Fallback: scan `--help` for `--pull-filter`. The flag has been listed
    // in --help since 2.4, so its presence is a serviceable proxy.
    // xtask:allow-protocol-leak: dependency-feature probe runs before any tunnel exists; app-layer concern (R13)
    let help_output =
        vortix_process::run_to_output(CommandSpec::oneshot("openvpn", vec!["--help".into()]));
    if let Ok(out) = help_output {
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        if combined.contains("--pull-filter") {
            return OvpnVersionProbe::HelpFallbackOk;
        }
    }

    OvpnVersionProbe::Unparseable
}

impl App {
    /// Smart connection toggle: Connect, Disconnect, or Switch.
    ///
    /// Uses `pending_connect` to queue a connection that fires automatically
    /// after the current disconnect completes, avoiding the race condition
    /// of starting connect while disconnect is still in-flight.
    pub(crate) fn toggle_connection(&mut self, idx: usize) {
        // Cancel any in-flight retry/auto-reconnect when user initiates a new action
        self.runtime.retry_count = 0;
        self.runtime.retry_profile_idx = None;
        self.runtime.auto_reconnect_profile = None;

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
            match &self.runtime.connection_state {
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

    /// Check if required binaries are available for a given protocol.
    /// Uses `which` to locate binaries — avoids running them directly since
    /// some tools (e.g. `wg-quick --version`) hang on macOS.
    fn check_dependencies(protocol: Protocol, config_path: &std::path::Path) -> Vec<String> {
        let mut missing = Vec::new();
        match protocol {
            Protocol::WireGuard => {
                if !utils::binary_exists("wg-quick") {
                    missing.push("wg-quick".to_string());
                }
                if !utils::binary_exists("wg") {
                    missing.push("wireguard-tools".to_string());
                }
                // On Linux, wg-quick uses `resolvconf` to set DNS when the
                // config contains a DNS directive.  We must verify that a
                // working resolvconf is present — `openresolv` installed on
                // a systemd-resolved system will exist but fail at runtime
                // with "signature mismatch".
                #[cfg(target_os = "linux")]
                // xtask:allow-platform-cfg: resolvconf detection is Linux-only DNS plumbing
                if utils::wireguard_config_has_dns(config_path) && !utils::resolvconf_works() {
                    // Point the user to the right package for their system.
                    if utils::is_systemd_resolved() {
                        missing.push("resolvconf (systemd)".to_string());
                    } else {
                        missing.push("resolvconf".to_string());
                    }
                }
                #[cfg(not(target_os = "linux"))]
                let _ = config_path; // suppress unused warning on non-Linux
            }
            Protocol::OpenVPN => {
                if utils::binary_exists("openvpn") {
                    // Plan 001 U14 / R13: assert OpenVPN >= 2.4 so the
                    // multi-tunnel DNS-scoping `--pull-filter` flag is
                    // available when the registry brings up a secondary.
                    // Older builds would silently ignore the flag and leak
                    // pushed DNS into the primary's resolver. We only fail
                    // when the version is definitively too old; an unparseable
                    // probe surfaces as a tracing warn (fail-open) so vendor-
                    // patched builds and test environments aren't blocked.
                    match probe_openvpn_version() {
                        OvpnVersionProbe::Parsed(v) if v.supports_multi_tunnel_dns() => {}
                        OvpnVersionProbe::Parsed(v) => {
                            missing.push(format!(
                                "openvpn 2.4+ required for multi-tunnel DNS scoping (found {v})"
                            ));
                        }
                        OvpnVersionProbe::HelpFallbackOk => {
                            // --help confirms --pull-filter is wired up — treat as OK.
                        }
                        OvpnVersionProbe::Unparseable => {
                            tracing::warn!(
                                target: "vortix::app::connection",
                                "openvpn version could not be determined; \
                                 multi-tunnel DNS scoping may not work if the \
                                 installed binary is older than 2.4"
                            );
                        }
                    }
                } else {
                    missing.push("openvpn".to_string());
                }
            }
        }
        missing
    }

    /// Check for system-wide dependencies at startup and warn the user.
    pub(crate) fn check_system_dependencies(&mut self) {
        let mut missing: Vec<&str> = Vec::new();

        if !utils::binary_exists("curl") {
            missing.push("curl");
        }

        if !utils::binary_exists("openvpn") {
            missing.push("openvpn");
        }

        if !utils::binary_exists("wg-quick") {
            missing.push("wg-quick");
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
        self.connect_profile_inner(idx, false);
    }

    /// Bypass the multi-connection conflict check and force the connect.
    /// Called after the user accepts the [`InputMode::ConfirmDefaultRouteTakeover`]
    /// or [`InputMode::ConfirmRouteOverlap`] overlay.
    pub(crate) fn connect_profile_forced(&mut self, idx: usize) {
        self.connect_profile_inner(idx, true);
    }

    #[allow(clippy::too_many_lines)]
    fn connect_profile_inner(&mut self, idx: usize, force: bool) {
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

        // Check dependencies FIRST (no point asking for root if tool is missing)
        let missing = Self::check_dependencies(protocol, &config_path);
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
        self.runtime.connection_state = ConnectionState::Connecting {
            started: Instant::now(),
            profile: name.clone(),
        };
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
                Ok(_handle) => {
                    let _ = cmd_tx.send(Message::ConnectResult {
                        profile: name,
                        success: true,
                        error: None,
                    });
                }
                Err(err) => {
                    let _ = cmd_tx.send(Message::ConnectResult {
                        profile: name,
                        success: false,
                        error: Some(format!("{protocol}: {err}")),
                    });
                }
            }
        });
    }

    /// Synchronizes the kill switch state with the current mode and connection status.
    /// This is the single source of truth for kill switch state transitions and firewall control.
    pub(crate) fn sync_killswitch(&mut self) {
        use crate::state::{KillSwitchMode, KillSwitchState};

        let old_state = self.runtime.killswitch_state;

        // 1. Determine the target state
        self.runtime.killswitch_state = match self.runtime.killswitch_mode {
            KillSwitchMode::Off => KillSwitchState::Disabled,
            KillSwitchMode::Auto => {
                if matches!(
                    self.runtime.connection_state,
                    ConnectionState::Connected { .. }
                ) {
                    KillSwitchState::Armed
                } else if old_state == KillSwitchState::Blocking {
                    KillSwitchState::Blocking
                } else {
                    KillSwitchState::Armed
                }
            }
            KillSwitchMode::AlwaysOn => {
                if matches!(
                    self.runtime.connection_state,
                    ConnectionState::Connected { .. }
                ) {
                    KillSwitchState::Armed
                } else {
                    KillSwitchState::Blocking
                }
            }
        };

        // 2. Refuse Blocking state when not running as root — firewall rules
        //    require elevated privileges and the UI must not claim a security
        //    posture that isn't enforced.
        if self.runtime.killswitch_state.is_blocking() && !self.runtime.is_root {
            self.runtime.killswitch_state = KillSwitchState::Armed;
            self.show_toast(
                "Kill switch requires root — run with sudo".to_string(),
                ToastType::Warning,
            );
            self.log("WARN: Kill switch blocked — not running as root");
        }

        // 3. Sync physical firewall state if target state changed or if forcing sync
        if self.runtime.killswitch_state != old_state
            || self.runtime.killswitch_state == KillSwitchState::Blocking
        {
            if self.runtime.killswitch_state.is_blocking() {
                let active = build_active_tunnels_from_state(&self.runtime.connection_state);
                if let Err(e) = crate::core::killswitch::enable_blocking_multi(&active) {
                    self.log(&format!("WARN: Failed to enable kill switch: {e}"));
                }
            } else if old_state.is_blocking() {
                if let Err(e) = crate::core::killswitch::disable_blocking() {
                    self.log(&format!("WARN: Failed to release kill switch: {e}"));
                }
            }
        }

        // 4. Persist state (multi-connection U11: V2 schema carries
        // active_tunnels derived from the current connection so
        // recovery on next launch can reconstruct the per-tunnel
        // ruleset).
        let active = build_active_tunnels_from_state(&self.runtime.connection_state);
        let persisted_tunnels = crate::core::killswitch::persisted_from_active(&active);
        let _ = crate::core::killswitch::save_state(
            self.runtime.killswitch_mode,
            self.runtime.killswitch_state,
            persisted_tunnels,
        );
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
        self.panel_flipped.clear();
        self.flip_animation = None;

        self.runtime.public_ip = crate::constants::MSG_DETECTING.to_string();
        self.runtime.location = crate::constants::MSG_DETECTING.to_string();
        self.runtime.isp = crate::constants::MSG_DETECTING.to_string();
        self.runtime.dns_server = crate::constants::MSG_DETECTING.to_string();
        self.runtime.ipv6_leak = false;
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

        // Drain pending_connect: switch directly to the next profile
        if let Some(idx) = self.runtime.pending_connect.take() {
            if idx < self.runtime.profiles.len() {
                let next_name = self.runtime.profiles[idx].name.clone();
                self.log(&format!(
                    "STATUS: Disconnected from '{profile_name}', connecting to '{next_name}'..."
                ));
                self.runtime.connection_state = ConnectionState::Disconnected;
                self.sync_killswitch();
                self.connect_profile(idx);
                return;
            }
        }

        // Normal disconnect (no pending switch)
        self.log(&format!("STATUS: Disconnected from '{profile_name}'"));
        self.runtime.connection_state = ConnectionState::Disconnected;
        self.mirror_disconnect_into_registry(profile_name);
        self.sync_killswitch();
        self.refresh_telemetry();
    }

    /// Mirror a legacy-path connect success into `self.registry` so the
    /// renderer-facing snapshots (header, sidebar, Connection Details,
    /// Security Guard) match the live tunnel state. Today the connect
    /// path drives `tunnel.up()` directly from a worker thread (see
    /// `connect_profile_inner`); the registry is touched only for the
    /// pre-up `detect_conflict` check. Plan 001 U6 Stage C / U7 will
    /// eventually route the whole flow through `registry.connect`; this
    /// mirror keeps the UI honest until then.
    ///
    /// Implementation: register a fresh `Engine<TunnelKind>` backed by
    /// a `MockTunnel` scripted with the **real** interface name + pid
    /// from `runtime.connection_state.details` (which the scanner
    /// populates with kernel-truthful values). `registry.connect_with_tunnel`
    /// drives the FSM `Disconnected → Connecting → Connected` synchronously;
    /// the mock returns the scripted handle without touching the kernel.
    /// `force: true` skips the conflict check because the real connect
    /// already passed it in `connect_profile_inner`.
    ///
    /// Why the real interface matters: `TunnelRegistry::recompute_primary`
    /// matches `details.interface == kernel_default_route_interface` to
    /// decide which tunnel is "primary". With a `mock0` placeholder the
    /// match never hits, the tunnel reads as a non-primary
    /// "Addressable secondary", telemetry routes around it
    /// (`Latency: n/a (secondary tunnel)`), and `Server`/`PID` come
    /// back empty — exactly the screenshot the user reported.
    ///
    /// Idempotent + replace-on-change: every scanner tick that
    /// updates `details.interface` (the kernel-true value lands a
    /// tick or two after the worker thread's `ConnectResult`) calls
    /// the mirror again. We compare the current registry snapshot to
    /// the new details and short-circuit when nothing changed,
    /// preventing per-tick FSM churn. When data differs (e.g., empty
    /// → real interface name), we remove the stale entry and
    /// re-connect with the latest values.
    pub(crate) fn mirror_connect_into_registry(&mut self, profile_name: &str) {
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

        // Pull live kernel-reported values from the legacy state's
        // details. When details are still default (e.g.,
        // handle_connect_result fires before scanner ticks), iface is
        // empty and we fall through to a placeholder entry — the
        // next scanner tick replaces it.
        let (iface, pid) = match &self.runtime.connection_state {
            ConnectionState::Connected { details, .. } => (details.interface.clone(), details.pid),
            _ => (String::new(), None),
        };

        // Short-circuit when the registry already holds this same
        // data: avoid per-tick disconnect/reconnect churn that would
        // make renderers flicker.
        if let Some(snap) = self.registry.snapshot(&profile_id) {
            use crate::vortix_core::engine::state::Connection;
            if let Connection::Connected {
                details: registry_details,
                ..
            } = &snap.state
            {
                if registry_details.interface == iface && registry_details.pid == pid {
                    return;
                }
            }
        }

        // Replace any stale entry so the new connect carries the
        // refreshed handle through the FSM.
        let _ = self.registry.disconnect(&profile_id);
        let _ = self.registry.remove(&profile_id);

        let allowed_ips = extract_allowed_ips(profile.protocol, &profile.config_path);
        let mock = crate::vortix_core::ports::tunnel::mock::MockTunnel::new();
        if !iface.is_empty() {
            mock.script_up(
                crate::vortix_core::ports::tunnel::mock::ScriptedTunnelOutcome::UpSuccess {
                    interface_name: iface,
                    pid,
                },
            );
        }
        let mock_kind = crate::tunnel::TunnelKind::Mock(mock);

        let resolved_profile = profile_for_resolver(&profile);
        let profile_resolver = move |_id: &ProfileId| Some(resolved_profile.clone());

        if let Err(err) = self.registry.connect_with_tunnel(
            profile_id,
            allowed_ips,
            mock_kind,
            profile_resolver,
            /* force */ true,
        ) {
            self.log(&format!(
                "WARN: registry mirror-connect failed for '{profile_name}': {err}"
            ));
        }
    }

    /// Mirror a legacy-path disconnect into `self.registry`: drive the
    /// FSM `Connected → Disconnecting → Disconnected` (mock `down()`
    /// returns success immediately) and then remove the entry so the
    /// registry's `tunnel_count` and `snapshot_all` reflect the
    /// teardown. See [`Self::mirror_connect_into_registry`] for the
    /// rationale behind this bookkeeping path.
    pub(crate) fn mirror_disconnect_into_registry(&mut self, profile_name: &str) {
        let profile_id = ProfileId::new(profile_name);
        // Idempotent: if the registry doesn't know about this profile
        // (mirror skipped, race condition, test setup) the disconnect
        // call returns ProfileNotFound — ignore it.
        let _ = self.registry.disconnect(&profile_id);
        let _ = self.registry.remove(&profile_id);
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn disconnect(&mut self) {
        self.runtime.retry_count = 0;
        self.runtime.retry_profile_idx = None;
        self.runtime.auto_reconnect_profile = None;
        // Discard any in-flight scanner result captured before this disconnect;
        // stale data showing the interface "up" would otherwise re-promote to
        // Connected and trigger a spurious "VPN dropped" auto-reconnect.
        self.runtime.scanner_rx = None;
        // Extract connection info from Connected or Connecting state
        let connection_info = match &self.runtime.connection_state {
            ConnectionState::Connected {
                profile: ref profile_name,
                details,
                ..
            } => self
                .runtime
                .profiles
                .iter()
                .find(|p| p.name == *profile_name)
                .map(|profile| {
                    (
                        profile.name.clone(),
                        profile.protocol,
                        profile.config_path.clone(),
                        details.pid,
                        self.runtime.cmd_tx.clone(),
                    )
                }),
            ConnectionState::Connecting {
                profile: ref profile_name,
                ..
            } => self
                .runtime
                .profiles
                .iter()
                .find(|p| p.name == *profile_name)
                .map(|profile| {
                    (
                        profile.name.clone(),
                        profile.protocol,
                        profile.config_path.clone(),
                        None, // no PID yet while connecting
                        self.runtime.cmd_tx.clone(),
                    )
                }),
            _ => None,
        };

        if let Some((profile_name, protocol, config_path, pid, cmd_tx)) = connection_info {
            self.log(&format!("ACTION: Disconnecting from '{profile_name}'..."));

            // Set disconnecting state
            self.runtime.connection_state = ConnectionState::Disconnecting {
                started: Instant::now(),
                profile: profile_name.clone(),
            };

            // KILL SWITCH: Sync state after changing connection state
            self.sync_killswitch();

            if self.runtime.killswitch_state.is_blocking() {
                self.show_toast(
                    "Kill Switch blocking - Strict mode active".to_string(),
                    ToastType::Warning,
                );
            }

            // Plan #004 U4: route the disconnect through TunnelKind.
            std::thread::spawn(move || {
                use crate::vortix_core::ports::tunnel::{TunnelHandle, TunnelKindTag};
                use crate::vortix_core::profile::ProfileId;

                let iface = match protocol {
                    Protocol::WireGuard => config_path.to_string_lossy().into_owned(),
                    Protocol::OpenVPN => {
                        format!(
                            "openvpn-{}",
                            crate::utils::sanitize_profile_name(&profile_name)
                        )
                    }
                };
                let pid_for_handle = match protocol {
                    Protocol::OpenVPN => crate::utils::read_openvpn_pid(&profile_name).or(pid),
                    Protocol::WireGuard => None,
                };
                let handle = TunnelHandle {
                    profile_id: ProfileId::new(&profile_name),
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
                            crate::utils::cleanup_openvpn_run_files(&profile_name);
                        }
                        let _ = cmd_tx.send(Message::DisconnectResult {
                            profile: profile_name,
                            success: true,
                            error: None,
                        });
                    }
                    Err(err) => {
                        let _ = cmd_tx.send(Message::DisconnectResult {
                            profile: profile_name,
                            success: false,
                            error: Some(format!("{protocol}: {err}")),
                        });
                    }
                }
            });
        }
    }

    /// Force-disconnect: escalates a stuck disconnect.
    pub(crate) fn force_disconnect(&mut self) {
        let profile_name = if let ConnectionState::Disconnecting { profile, .. } =
            &self.runtime.connection_state
        {
            profile.clone()
        } else {
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

            // Reset the Disconnecting timer so the 30s safety timeout starts fresh
            self.runtime.connection_state = ConnectionState::Disconnecting {
                started: Instant::now(),
                profile: name.clone(),
            };

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
    /// plan #001 U19). Routes through the registry when an FSM entry
    /// exists for that profile; otherwise falls back to the legacy
    /// single-tunnel `disconnect()` when the index matches the active
    /// connection. No-op when the profile is not currently active.
    pub(crate) fn disconnect_profile_by_idx(&mut self, idx: usize) {
        let Some(profile) = self.runtime.profiles.get(idx) else {
            return;
        };
        let name = profile.name.clone();
        let target_id = ProfileId::new(&name);

        // Registry-first: drive the FSM through `Disconnect` when the
        // tunnel is tracked there. Errors propagate to the activity log.
        if self.registry.snapshot(&target_id).is_some() {
            match self.registry.disconnect(&target_id) {
                Ok(()) => {
                    self.log(&format!("ACTION: Disconnecting '{name}' via registry"));
                }
                Err(err) => {
                    self.log(&format!("ERR: registry.disconnect('{name}') failed: {err}"));
                }
            }
            // The legacy single-tunnel state machine may also still hold
            // this profile (U6 has not finished migrating the connect
            // path). Mirror the disconnect into it so the sidebar /
            // header reflect the change without waiting for the next
            // scanner sync.
            let still_active_in_legacy = matches!(
                &self.runtime.connection_state,
                crate::vpn_runtime::ConnectionState::Connected { profile: p, .. }
                | crate::vpn_runtime::ConnectionState::Connecting { profile: p, .. }
                if *p == name
            );
            if still_active_in_legacy {
                self.disconnect();
            }
            return;
        }

        // Legacy path: profile is the only active tunnel tracked in
        // `runtime.connection_state` — defer to the existing disconnect.
        let is_legacy_match = matches!(
            &self.runtime.connection_state,
            crate::vpn_runtime::ConnectionState::Connected { profile: p, .. }
            | crate::vpn_runtime::ConnectionState::Connecting { profile: p, .. }
            if *p == name
        );
        if is_legacy_match {
            self.disconnect();
        }
    }

    /// Tear down every active tunnel (multi-connection plan #001 U19).
    /// Used by Shift+`D` after the user confirms the
    /// [`InputMode::ConfirmDisconnectAll`] dialog, and by the
    /// `Message::Disconnect` global when only one tunnel exists.
    pub(crate) fn disconnect_all_active(&mut self) {
        // Snapshot ids first so we don't hold a borrow across mutation.
        let ids = self.active_tunnel_ids();
        let count = ids.len();
        self.log(&format!(
            "ACTION: Disconnecting all {count} active tunnel(s)..."
        ));

        // Disconnect via the registry path for any tracked FSMs.
        for id in &ids {
            if self.registry.snapshot(id).is_some() {
                if let Err(err) = self.registry.disconnect(id) {
                    self.log(&format!(
                        "ERR: registry.disconnect('{}') failed: {err}",
                        id.as_str()
                    ));
                }
            }
        }

        // Mirror the disconnect into the legacy single-tunnel state if it
        // is still active (U6 has not finished migrating the connect path).
        if !matches!(
            self.runtime.connection_state,
            crate::vpn_runtime::ConnectionState::Disconnected
        ) {
            self.disconnect();
        }
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

        // Legacy path: connecting state lives in `runtime.connection_state`.
        let is_legacy_connecting = matches!(
            &self.runtime.connection_state,
            crate::vpn_runtime::ConnectionState::Connecting { profile: p, .. } if *p == name
        );
        if is_legacy_connecting {
            self.disconnect();
        }
    }

    /// Reconnect to VPN: queues the same profile for auto-connect after disconnect.
    pub(crate) fn reconnect(&mut self) {
        match &self.runtime.connection_state {
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

/// Build the `ActiveTunnelInfo` slice that the killswitch synthesiser
/// consumes from the current single-connection engine state.
///
/// Until U6/U7 wire `TunnelRegistry` into this path, only the currently
/// connected tunnel (if any) contributes; everything else collapses to
/// the empty slice. The single tunnel is always treated as primary —
/// declared CIDRs are not yet plumbed through `ConnectionState`.
pub(crate) fn build_active_tunnels_from_state(
    state: &ConnectionState,
) -> Vec<crate::core::killswitch::ActiveTunnelInfo> {
    use crate::core::killswitch::ActiveTunnelInfo;

    match state {
        ConnectionState::Connected { details, .. } => {
            let server_ips = details
                .endpoint
                .split(':')
                .next()
                .and_then(|s| s.parse().ok())
                .into_iter()
                .collect();
            vec![ActiveTunnelInfo {
                interface: details.interface.clone(),
                server_ips,
                declared_cidrs: Vec::new(),
                is_primary: true,
            }]
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod ovpn_version_tests {
    //! Tests for plan 001 U14 — `OpenVPN` `--version` parsing and the 2.4+
    //! precondition assertion. The parse helper is pure so we can cover the
    //! happy path, the major-bump edge case, and the malformed-output
    //! fallback without spawning a subprocess.
    use super::{parse_openvpn_version, OvpnVersion};

    #[test]
    fn parses_standard_first_line() {
        let stdout =
            "OpenVPN 2.5.8 [git:release/2.5/...] x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4]";
        let v = parse_openvpn_version(stdout).expect("should parse");
        assert_eq!(
            v,
            OvpnVersion {
                major: 2,
                minor: 5,
                patch: 8
            }
        );
        assert!(v.supports_multi_tunnel_dns());
    }

    #[test]
    fn parses_exact_2_4_0_as_passing() {
        let v = parse_openvpn_version("OpenVPN 2.4.0 amd64-pc-linux").expect("should parse");
        assert_eq!(
            v,
            OvpnVersion {
                major: 2,
                minor: 4,
                patch: 0
            }
        );
        assert!(v.supports_multi_tunnel_dns());
    }

    #[test]
    fn rejects_2_3_18_below_baseline() {
        let v = parse_openvpn_version("OpenVPN 2.3.18 x86_64").expect("should parse");
        assert_eq!(
            v,
            OvpnVersion {
                major: 2,
                minor: 3,
                patch: 18
            }
        );
        assert!(!v.supports_multi_tunnel_dns());
    }

    #[test]
    fn accepts_major_version_3() {
        let v = parse_openvpn_version("OpenVPN 3.0.0 something").expect("should parse");
        assert_eq!(
            v,
            OvpnVersion {
                major: 3,
                minor: 0,
                patch: 0
            }
        );
        assert!(v.supports_multi_tunnel_dns());
    }

    #[test]
    fn handles_vendor_prefix_via_token_scan() {
        // Vendor-patched builds sometimes prefix the banner — the parser
        // should still locate the `OpenVPN ` token.
        let v = parse_openvpn_version("vendor-patched OpenVPN 2.6.10 abc").expect("should parse");
        assert_eq!(
            v,
            OvpnVersion {
                major: 2,
                minor: 6,
                patch: 10
            }
        );
    }

    #[test]
    fn strips_trailing_non_numeric_suffix() {
        let v = parse_openvpn_version("OpenVPN 2.5.8-git build").expect("should parse");
        assert_eq!(
            v,
            OvpnVersion {
                major: 2,
                minor: 5,
                patch: 8
            }
        );
    }

    #[test]
    fn returns_none_on_malformed_output() {
        // No `OpenVPN ` marker → unparseable → caller's `--help` fallback fires.
        assert!(parse_openvpn_version("Custom-VPN-Tool 1.2.3").is_none());
        assert!(parse_openvpn_version("").is_none());
        assert!(parse_openvpn_version("OpenVPN notaversion").is_none());
    }

    #[test]
    fn major_minor_only_accepts_with_zero_patch() {
        // Some banners only emit major.minor — accept with implicit .0 patch.
        let v = parse_openvpn_version("OpenVPN 2.5 something").expect("should parse");
        assert_eq!(
            v,
            OvpnVersion {
                major: 2,
                minor: 5,
                patch: 0
            }
        );
    }

    #[test]
    fn ordering_is_semver_like() {
        let a = OvpnVersion {
            major: 2,
            minor: 4,
            patch: 0,
        };
        let b = OvpnVersion {
            major: 2,
            minor: 3,
            patch: 99,
        };
        assert!(a > b);
        let c = OvpnVersion {
            major: 3,
            minor: 0,
            patch: 0,
        };
        assert!(c > a);
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
