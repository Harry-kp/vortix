//! VPN connection lifecycle management and kill switch control.

use std::sync::OnceLock;
use std::time::Instant;

use super::{App, ConnectionState, InputMode, Protocol, ToastType};
use crate::message::Message;
use crate::utils;
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
        self.engine.retry_count = 0;
        self.engine.retry_profile_idx = None;
        self.engine.auto_reconnect_profile = None;

        if let Some(target_profile) = self.engine.profiles.get(idx) {
            let target_name = target_profile.name.clone();
            match &self.engine.connection_state {
                // If connecting, ignore to prevent races
                ConnectionState::Connecting { .. } => {}
                // If disconnecting, queue the connection for after disconnect completes
                ConnectionState::Disconnecting { .. } => {
                    if let Some(old) = self.engine.pending_connect {
                        if old != idx {
                            if let Some(old_profile) = self.engine.profiles.get(old) {
                                self.log(&format!(
                                    "ACTION: Switched queue from '{}' to '{target_name}'",
                                    old_profile.name
                                ));
                            }
                        }
                    }
                    self.engine.pending_connect = Some(idx);
                }
                ConnectionState::Connected {
                    profile: current_name,
                    ..
                } => {
                    if *current_name == target_name {
                        self.engine.pending_connect = None;
                        self.disconnect();
                    } else {
                        self.input_mode = InputMode::ConfirmSwitch {
                            from: current_name.clone(),
                            to_idx: idx,
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

    /// Connect to a profile
    #[allow(clippy::too_many_lines)]
    pub(crate) fn connect_profile(&mut self, idx: usize) {
        // Clone needed data to release borrow on self
        let (name, protocol, config_path, cmd_tx) =
            if let Some(profile) = self.engine.profiles.get(idx) {
                (
                    profile.name.clone(),
                    profile.protocol,
                    profile.config_path.clone(),
                    self.engine.cmd_tx.clone(),
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
        if !self.engine.is_root {
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
        self.engine.connection_state = ConnectionState::Connecting {
            started: Instant::now(),
            profile: name.clone(),
        };
        self.log(&format!("ACTION: Connecting to '{name}' [{protocol}]..."));

        let connect_timeout_secs = self.engine.config.connect_timeout;
        let ovpn_verbosity = self.engine.config.openvpn_verbosity.clone();

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

        let old_state = self.engine.killswitch_state;

        // 1. Determine the target state
        self.engine.killswitch_state = match self.engine.killswitch_mode {
            KillSwitchMode::Off => KillSwitchState::Disabled,
            KillSwitchMode::Auto => {
                if matches!(
                    self.engine.connection_state,
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
                    self.engine.connection_state,
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
        if self.engine.killswitch_state.is_blocking() && !self.engine.is_root {
            self.engine.killswitch_state = KillSwitchState::Armed;
            self.show_toast(
                "Kill switch requires root — run with sudo".to_string(),
                ToastType::Warning,
            );
            self.log("WARN: Kill switch blocked — not running as root");
        }

        // 3. Sync physical firewall state if target state changed or if forcing sync
        if self.engine.killswitch_state != old_state
            || self.engine.killswitch_state == KillSwitchState::Blocking
        {
            if self.engine.killswitch_state.is_blocking() {
                let (interface, server_ip) = match &self.engine.connection_state {
                    ConnectionState::Connected { details, .. } => (
                        details.interface.as_str(),
                        Some(details.endpoint.split(':').next().unwrap_or("")),
                    ),
                    _ => (crate::platform::DEFAULT_VPN_INTERFACE, None),
                };

                if let Err(e) = crate::core::killswitch::enable_blocking(interface, server_ip) {
                    self.log(&format!("WARN: Failed to enable kill switch: {e}"));
                }
            } else if old_state.is_blocking() {
                if let Err(e) = crate::core::killswitch::disable_blocking() {
                    self.log(&format!("WARN: Failed to release kill switch: {e}"));
                }
            }
        }

        // 4. Persist state
        let _ = crate::core::killswitch::save_state(
            self.engine.killswitch_mode,
            self.engine.killswitch_state,
            None,
            None,
        );
    }

    /// Kill any running VPN process and remove run files for a profile.
    ///
    /// Plan #004 U4: routes through the `TunnelKind` dispatch so this no
    /// longer match-branches on protocol.
    pub(crate) fn cleanup_vpn_resources(&self, profile_name: &str) {
        if let Some(profile) = self.engine.profiles.iter().find(|p| p.name == profile_name) {
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
        self.engine.session_start = None;
        self.engine.scanner_rx = None; // discard stale scanner data pre-disconnect
        self.panel_flipped.clear();
        self.flip_animation = None;

        self.engine.public_ip = crate::constants::MSG_DETECTING.to_string();
        self.engine.location = crate::constants::MSG_DETECTING.to_string();
        self.engine.isp = crate::constants::MSG_DETECTING.to_string();
        self.engine.dns_server = crate::constants::MSG_DETECTING.to_string();
        self.engine.ipv6_leak = false;
        self.engine.latency_ms = 0;
        self.engine.packet_loss = 0.0;
        self.engine.jitter_ms = 0;
        self.engine.last_security_check = None;
        self.engine.ip_unchanged_warned = false;
        self.engine.current_down = 0;
        self.engine.current_up = 0;

        // Clean up OpenVPN runtime files if this was an OpenVPN profile
        if self
            .engine
            .profiles
            .iter()
            .any(|p| p.name == profile_name && matches!(p.protocol, Protocol::OpenVPN))
        {
            crate::utils::cleanup_openvpn_run_files(profile_name);
        }

        // Drain pending_connect: switch directly to the next profile
        if let Some(idx) = self.engine.pending_connect.take() {
            if idx < self.engine.profiles.len() {
                let next_name = self.engine.profiles[idx].name.clone();
                self.log(&format!(
                    "STATUS: Disconnected from '{profile_name}', connecting to '{next_name}'..."
                ));
                self.engine.connection_state = ConnectionState::Disconnected;
                self.sync_killswitch();
                self.connect_profile(idx);
                return;
            }
        }

        // Normal disconnect (no pending switch)
        self.log(&format!("STATUS: Disconnected from '{profile_name}'"));
        self.engine.connection_state = ConnectionState::Disconnected;
        self.sync_killswitch();
        self.refresh_telemetry();
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn disconnect(&mut self) {
        self.engine.retry_count = 0;
        self.engine.retry_profile_idx = None;
        self.engine.auto_reconnect_profile = None;
        // Discard any in-flight scanner result captured before this disconnect;
        // stale data showing the interface "up" would otherwise re-promote to
        // Connected and trigger a spurious "VPN dropped" auto-reconnect.
        self.engine.scanner_rx = None;
        // Extract connection info from Connected or Connecting state
        let connection_info = match &self.engine.connection_state {
            ConnectionState::Connected {
                profile: ref profile_name,
                details,
                ..
            } => self
                .engine
                .profiles
                .iter()
                .find(|p| p.name == *profile_name)
                .map(|profile| {
                    (
                        profile.name.clone(),
                        profile.protocol,
                        profile.config_path.clone(),
                        details.pid,
                        self.engine.cmd_tx.clone(),
                    )
                }),
            ConnectionState::Connecting {
                profile: ref profile_name,
                ..
            } => self
                .engine
                .profiles
                .iter()
                .find(|p| p.name == *profile_name)
                .map(|profile| {
                    (
                        profile.name.clone(),
                        profile.protocol,
                        profile.config_path.clone(),
                        None, // no PID yet while connecting
                        self.engine.cmd_tx.clone(),
                    )
                }),
            _ => None,
        };

        if let Some((profile_name, protocol, config_path, pid, cmd_tx)) = connection_info {
            self.log(&format!("ACTION: Disconnecting from '{profile_name}'..."));

            // Set disconnecting state
            self.engine.connection_state = ConnectionState::Disconnecting {
                started: Instant::now(),
                profile: profile_name.clone(),
            };

            // KILL SWITCH: Sync state after changing connection state
            self.sync_killswitch();

            if self.engine.killswitch_state.is_blocking() {
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
        let profile_name =
            if let ConnectionState::Disconnecting { profile, .. } = &self.engine.connection_state {
                profile.clone()
            } else {
                return;
            };

        self.engine.scanner_rx = None; // discard stale scanner data

        let force_info = self
            .engine
            .profiles
            .iter()
            .find(|p| p.name == profile_name)
            .map(|profile| {
                (
                    profile.name.clone(),
                    profile.protocol,
                    profile.config_path.clone(),
                    self.engine.cmd_tx.clone(),
                )
            });

        if let Some((name, protocol, config_path, cmd_tx)) = force_info {
            self.log(&format!("ACTION: Force-disconnecting '{name}'..."));
            self.show_toast(
                format!("Force-disconnecting '{name}'..."),
                ToastType::Warning,
            );

            // Reset the Disconnecting timer so the 30s safety timeout starts fresh
            self.engine.connection_state = ConnectionState::Disconnecting {
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

    /// Reconnect to VPN: queues the same profile for auto-connect after disconnect.
    pub(crate) fn reconnect(&mut self) {
        match &self.engine.connection_state {
            ConnectionState::Connected { profile, .. } => {
                let profile_name = profile.clone();
                if let Some(idx) = self
                    .engine
                    .profiles
                    .iter()
                    .position(|p| p.name == profile_name)
                {
                    self.engine.pending_connect = Some(idx);
                    self.disconnect();
                }
            }
            ConnectionState::Disconnected => {
                if let Some(ref last) = self.engine.last_connected_profile {
                    if let Some(idx) = self.engine.profiles.iter().position(|p| p.name == *last) {
                        self.log(&format!("STATUS: Reconnecting to '{last}'"));
                        self.connect_profile(idx);
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod ovpn_version_tests {
    //! Tests for plan 001 U14 — `OpenVPN` `--version` parsing and the 2.4+
    //! precondition assertion. The parse helper is pure so we can cover the
    //! happy path, the major-bump edge case, and the malformed-output
    //! fallback without spawning a subprocess.
    use super::{OvpnVersion, parse_openvpn_version};

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
        let v =
            parse_openvpn_version("vendor-patched OpenVPN 2.6.10 abc").expect("should parse");
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
