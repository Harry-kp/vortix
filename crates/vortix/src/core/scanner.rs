//! System VPN connection scanner.
//!
//! This module provides functionality to detect active VPN connections
//! by scanning system interfaces and processes for `WireGuard` and `OpenVPN` sessions.

use crate::app::{Protocol, VpnProfile};
use crate::vortix_process::simple_output as cmd_output;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Information about an active VPN session detected on the system.
#[derive(Clone, Debug)]
pub struct ActiveSession {
    /// Profile name associated with this session.
    pub name: String,
    /// Process ID for `OpenVPN` or interface index (not used yet).
    pub pid: Option<u32>,
    /// Timestamp when the connection was established.
    pub started_at: Option<SystemTime>,
    /// System interface name (e.g., utun3, wg0, tun0).
    pub interface: String,
    /// Whether `interface` came from a reliable per-tunnel source.
    ///
    /// `true` when the platform's per-PID iface detection is reliable
    /// (Linux `/proc/PID/fd/*`, macOS `/var/run/wireguard/<name>.name`
    /// for WG). `false` only when the scanner fell back to the macOS
    /// ifconfig-scan heuristic (`check_openvpn_by_pid` Method B), which
    /// collides across multiple `OpenVPN` PIDs and so cannot
    /// truthfully identify which utun belongs to which process.
    /// Scanner evidence remains observational regardless of this bit. It is
    /// useful for display attribution, but U6 no longer grants primary or
    /// retry authority to scanner-only sessions.
    ///
    /// Defaults to `true` — most platforms / protocols / paths are
    /// reliable. The macOS `OpenVPN` Method-B fallback is the narrow
    /// exception that opts out.
    pub interface_authoritative: bool,
    /// Internal VPN IP address assigned to this interface.
    pub internal_ip: String,
    /// Remote server endpoint address.
    pub endpoint: String,
    /// Maximum transmission unit size.
    pub mtu: String,
    /// `WireGuard` public key (empty for `OpenVPN`).
    pub public_key: String,
    /// Local listening port for the VPN interface.
    pub listen_port: String,
    /// Total bytes received over the tunnel.
    pub transfer_rx: String,
    /// Total bytes transmitted over the tunnel.
    pub transfer_tx: String,
    /// Time since last successful handshake.
    pub latest_handshake: String,
    /// Typed `WireGuard` peer facts. Empty for `OpenVPN`. Display strings above
    /// are compatibility projections and never control authority.
    pub wireguard_peers: Vec<crate::vortix_core::ports::tunnel::TunnelPeerStatus>,
}

impl Default for ActiveSession {
    fn default() -> Self {
        Self {
            name: String::new(),
            pid: None,
            started_at: None,
            interface: String::new(),
            interface_authoritative: true,
            internal_ip: String::new(),
            endpoint: String::new(),
            mtu: String::new(),
            public_key: String::new(),
            listen_port: String::new(),
            transfer_rx: String::new(),
            transfer_tx: String::new(),
            latest_handshake: String::new(),
            wireguard_peers: Vec::new(),
        }
    }
}

/// Combined result of a scanner sweep: active VPN sessions plus the
/// kernel default-route interface (probed in the same background
/// thread so the main thread doesn't pay the `route get default` cost).
#[derive(Default, Debug)]
pub struct ScannerResult {
    pub sessions: Vec<ActiveSession>,
    pub default_route: crate::vortix_core::ports::route_table::DefaultRouteObservation,
    /// `false` means at least one protocol-wide probe failed, so missing
    /// sessions are unknown rather than proof of absence.
    pub tunnel_observation_complete: bool,
}

/// Gather both active VPN sessions and the kernel default-route
/// interface in one shot. Designed to be called from the scanner's
/// per-tick background thread. The default-route probe runs through
/// the same subprocess machinery as the session probes, with the
/// platform-specific 1s timeout in place (see `route_table.rs`).
#[must_use]
pub fn gather_system_state(profiles: &[VpnProfile]) -> ScannerResult {
    let (sessions, tunnel_observation_complete) = scan_active_profiles(profiles);
    ScannerResult {
        sessions,
        default_route: crate::platform::current_platform()
            .route_table
            .default_route_observation(),
        tunnel_observation_complete,
    }
}

/// Scans the system for active VPN sessions matching known profiles.
///
/// Iterates through provided profiles and checks if corresponding VPN
/// interfaces or processes are active on the system.
///
/// # Arguments
///
/// * `profiles` - Slice of VPN profiles to check against system state
///
/// # Returns
///
/// A best-effort vector of [`ActiveSession`] structs for each detected active
/// connection. Authority paths must use [`gather_system_state`] and require
/// `tunnel_observation_complete` before treating a missing session as absent.
#[must_use]
pub fn get_active_profiles(profiles: &[VpnProfile]) -> Vec<ActiveSession> {
    scan_active_profiles(profiles).0
}

fn scan_active_profiles(profiles: &[VpnProfile]) -> (Vec<ActiveSession>, bool) {
    let mut active = Vec::new();

    // One protocol-owned, bounded `wg show all dump` replaces one subprocess
    // per WireGuard profile. Interface resolution remains platform-owned; the
    // exact resolved interface selects its typed status from this snapshot.
    let (wireguard_statuses, wireguard_observation_complete) = if profiles
        .iter()
        .any(|profile| matches!(profile.protocol, Protocol::WireGuard))
    {
        match crate::vortix_protocol_wireguard::WgTunnel::observe_all_interfaces() {
            Ok(statuses) => (statuses, true),
            Err(_) => (std::collections::BTreeMap::new(), false),
        }
    } else {
        (std::collections::BTreeMap::new(), true)
    };

    // 1. Batch lookup for OpenVPN
    let (openvpn_pids, openvpn_observation_complete) = if profiles
        .iter()
        .any(|profile| matches!(profile.protocol, Protocol::OpenVPN))
    {
        get_all_openvpn_pids().map_or_else(|| (Vec::new(), false), |pids| (pids, true))
    } else {
        (Vec::new(), true)
    };
    for profile in profiles {
        let session_info = match profile.protocol {
            Protocol::WireGuard => check_wireguard_by_name(&profile.name, &wireguard_statuses),
            Protocol::OpenVPN => {
                let path_str = profile.config_path.to_str().unwrap_or("");
                // Match either the exact source config argument or Vortix's
                // exact generation-bound private config name.
                openvpn_pids
                    .iter()
                    .find(|(path, _)| {
                        openvpn_config_matches_profile(path, path_str, profile.id.as_str())
                    })
                    .and_then(|(_, pid)| {
                        check_openvpn_by_pid(
                            *pid,
                            &profile.config_path,
                            profile.id.as_str(),
                            &profile.name,
                        )
                    })
            }
        };

        if let Some(mut session) = session_info {
            session.name.clone_from(&profile.name);
            active.push(session);
        }
    }

    (
        active,
        wireguard_observation_complete && openvpn_observation_complete,
    )
}

fn openvpn_config_matches_profile(
    config: &Path,
    source_config_path: &str,
    profile_id: &str,
) -> bool {
    let source = Path::new(source_config_path);
    if config == source {
        return true;
    }
    let Some(source_parent) = source.parent() else {
        return false;
    };
    if config.parent() != Some(source_parent) {
        return false;
    }
    let Some(file_name) = config.file_name().and_then(std::ffi::OsStr::to_str) else {
        return false;
    };
    let prefix = format!(".vortix-{profile_id}-");
    let Some(suffix) = file_name
        .strip_prefix(&prefix)
        .and_then(|name| name.strip_suffix(".ovpn"))
    else {
        return false;
    };
    let Some((generation, token)) = suffix.split_once('-') else {
        return false;
    };
    let valid = [generation, token]
        .into_iter()
        .all(|part| part.len() == 16 && part.bytes().all(|byte| byte.is_ascii_hexdigit()));
    valid
}

fn openvpn_config_argument(command: &str) -> Option<String> {
    let arguments = shell_words(command);
    arguments.iter().enumerate().find_map(|(index, argument)| {
        if argument == "--config" {
            arguments.get(index + 1).cloned()
        } else {
            argument.strip_prefix("--config=").map(str::to_owned)
        }
    })
}

fn shell_words(command: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in command.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        match (quote, character) {
            (_, '\\') => escaped = true,
            (Some(active), value) if value == active => quote = None,
            (None, '\'' | '"') => quote = Some(character),
            (None, value) if value.is_whitespace() => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(character),
        }
    }
    if escaped {
        current.push('\\');
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn get_all_openvpn_pids() -> Option<Vec<(PathBuf, u32)>> {
    let mut processes = Vec::new();
    // Use ps -ax -o pid,args to get PID and full command line
    let output = cmd_output("ps", &["-ax", "-o", "pid,command"])?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines().skip(1) {
        // Skip header
        let line = line.trim();
        // Parse each process command once; profile matching below stays
        // allocation-free even with many profiles and processes.
        let mut fields = line.splitn(2, char::is_whitespace);
        let Some(pid) = fields.next().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        let command = fields.next().map(str::trim).unwrap_or_default();
        if command.contains("openvpn") {
            if let Some(config) = openvpn_config_argument(command) {
                processes.push((PathBuf::from(config), pid));
            }
        }
    }
    Some(processes)
}

/// Checks if a `WireGuard` interface exists and returns session details.
///
/// Uses platform-specific interface detection:
/// - macOS: /var/run/wireguard/*.name + ifconfig
/// - Linux: kernel interface lookup + typed `WireGuard` protocol observation
fn check_wireguard_by_name(
    name: &str,
    statuses: &std::collections::BTreeMap<
        String,
        crate::vortix_protocol_wireguard::tunnel::WgStatus,
    >,
) -> Option<ActiveSession> {
    // Platform-dispatched interface check via the platform aggregate.
    let platform = crate::platform::current_platform();

    // On macOS, `resolve_wireguard_interface` reads /var/run/wireguard/
    // <name>.name and returns Some(utunN). On Linux, the kernel device
    // is the config name. Protocol identity is established below by the
    // typed WireGuard observer.
    let interface_name = platform.interface.resolve_wireguard_interface(name)?;

    let mut session = ActiveSession {
        interface: interface_name.clone(),
        interface_authoritative: true,
        ..Default::default()
    };

    // 1. Attempt to find PID (wireguard-go or similar)
    if let Some(pid) = platform.interface.get_wireguard_pid(&interface_name) {
        session.pid = Some(pid);

        // Primary method: Get start time from process (works cross-platform)
        if let Some(output) = cmd_output("ps", &["-p", &pid.to_string(), "-o", "etime="]) {
            let etime = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !etime.is_empty() {
                if let Some(duration) = parse_ps_etime(&etime) {
                    session.started_at = SystemTime::now().checked_sub(duration);
                }
            }
        }
    }

    // 2. Fallback: Try file metadata (only reliable on macOS)
    #[cfg(target_os = "macos")]
    // xtask:allow-platform-cfg: WIREGUARD_RUN_DIR file metadata is a macOS-only fallback
    if session.started_at.is_none() {
        let pid_file =
            PathBuf::from(crate::constants::WIREGUARD_RUN_DIR).join(format!("{name}.name"));
        if pid_file.exists() {
            session.started_at = std::fs::metadata(&pid_file).and_then(|m| m.created()).ok();
        }
    }

    // Log if we couldn't determine start time
    if session.started_at.is_none() {
        crate::logger::log(
            crate::logger::LogLevel::Debug,
            "SCANNER",
            format!(
                "Could not determine start time for WireGuard interface '{interface_name}' (ps/metadata fallbacks failed)"
            ),
        );
    }

    // Protocol-owned machine-readable observation. The scanner projects
    // display metadata but cannot manufacture connection truth.
    let status = statuses.get(&interface_name)?;
    session.public_key.clone_from(&status.interface_public_key);
    session.listen_port = status
        .listen_port
        .map_or_else(String::new, |port| port.to_string());
    session.endpoint = status
        .peers
        .iter()
        .find_map(|peer| peer.endpoint.clone())
        .unwrap_or_default();
    session.transfer_rx = status
        .peers
        .iter()
        .map(|peer| peer.bytes_rx)
        .sum::<u64>()
        .to_string();
    session.transfer_tx = status
        .peers
        .iter()
        .map(|peer| peer.bytes_tx)
        .sum::<u64>()
        .to_string();
    session.latest_handshake = status
        .peers
        .iter()
        .filter_map(|peer| peer.latest_handshake)
        .max()
        .and_then(|handshake| SystemTime::now().duration_since(handshake).ok())
        .map_or_else(String::new, |age| format!("{}s ago", age.as_secs()));
    session.wireguard_peers.clone_from(&status.peers);

    // 4. Get IP and MTU using platform-specific interface info
    let (ip, mtu) = platform.interface.get_interface_info(&interface_name);
    if !ip.is_empty() {
        session.internal_ip = ip;
    }
    if !mtu.is_empty() {
        session.mtu = mtu;
    }

    Some(session)
}

/// Checks if an `OpenVPN` process is running AND has an active tunnel.
///
/// Returns `None` if the process is running but no tun/tap interface is
/// detected — this means `OpenVPN` is still negotiating or has failed silently.
///
/// Extracts detailed session information including:
/// - Process start time from `ps` command
/// - Internal IP from the tun/tap interface
/// - MTU from the interface
/// - Remote endpoint from process args or config file
#[allow(clippy::too_many_lines)]
fn check_openvpn_by_pid(
    pid: u32,
    config_path: &Path,
    profile_id: &str,
    display_name: &str,
) -> Option<ActiveSession> {
    let mut session = ActiveSession {
        pid: Some(pid),
        ..Default::default()
    };

    // Get process elapsed time using ps etime format: [[dd-]hh:]mm:ss
    if let Some(output) = cmd_output("ps", &["-p", &pid.to_string(), "-o", "etime="]) {
        let etime = String::from_utf8_lossy(&output.stdout);
        let etime = etime.trim();
        if !etime.is_empty() {
            if let Some(duration) = parse_ps_etime(etime) {
                session.started_at = SystemTime::now().checked_sub(duration);
            }
        }
    }

    // 2. Find OpenVPN tun/tap interface
    let mut detected_iface = String::new();
    // Tracks whether the interface name written into `session.interface`
    // came from a per-PID-reliable source.
    //
    // Resolution order:
    //   Method 0 -- read the authoritative iface from vortix's own
    //               openvpn log (`<run_dir>/<profile_id>.log`). Vortix
    //               writes this on every `OvpnTunnel::up` call (CLI or
    //               TUI) and `parse_kernel_interface` extracts the iface
    //               from openvpn's log output. If the file exists and
    //               parses, we know vortix spawned this tunnel and the
    //               iface is authoritatively attributable -- works
    //               across vortix process restarts (e.g. `vortix up`
    //               then opening the TUI).
    //   Method A -- macOS: `lsof -p <pid>` looking for `/dev/utun*`.
    //               Works for legacy openvpn that opens the tun device
    //               file directly; FAILS for modern openvpn that uses
    //               the utun socket API (PF_SYSTEM/com.apple.net.utun_-
    //               control). When it works, attributable to THIS pid.
    //   Method B -- ifconfig scan for "first utun with an inet that
    //               isn't WG". Cannot distinguish between multiple
    //               openvpn pids; marked unauthoritative.
    //
    // The flag flows into `session.interface_authoritative` at session-
    // return time so `App::adopt_registry_from_session` can mark the
    // adopted entry ineligible for primary-election when the iface
    // can't be trusted against the kernel.
    let mut iface_authoritative = false;

    // Method 0: vortix-spawned tunnel? If our run-dir holds an openvpn
    // log for this profile, parse the authoritative iface from it.
    // Works for both `vortix up` (CLI) and TUI-spawned tunnels -- and
    // crucially across process restarts, which is the path the user
    // hits when they connect via CLI and then open the TUI: the TUI's
    // scanner sees a live openvpn process, and instead of guessing the
    // iface via lsof (which fails on macOS for modern openvpn's utun
    // socket), we read the log vortix's own protocol layer wrote.
    if let Ok(config_dir) = crate::utils::get_app_config_dir() {
        let run_dir = config_dir.join(crate::constants::OPENVPN_RUN_DIR);
        let canonical_log = run_dir.join(format!("{profile_id}.log"));
        let log_path = if canonical_log.exists() {
            canonical_log
        } else if let Some(legacy_key) =
            crate::vortix_core::profile::unambiguous_legacy_artifact_key(display_name)
        {
            run_dir.join(format!("{legacy_key}.log"))
        } else {
            canonical_log
        };
        if let Ok(log_text) = std::fs::read_to_string(&log_path) {
            if let Some(iface) =
                crate::vortix_protocol_openvpn::tunnel::parse_kernel_interface(&log_text)
            {
                detected_iface = iface;
                iface_authoritative = true;
            }
        }
    }

    #[cfg(target_os = "macos")]
    // xtask:allow-platform-cfg: lsof-based OpenVPN tun-iface discovery is macOS-only; Interface port extension deferred
    {
        // Skip Method A when Method 0 already resolved the iface
        // authoritatively from vortix's own log -- lsof Method A
        // returns a /dev/utun device file only for legacy openvpn
        // builds; on modern openvpn (utun-socket API) it returns
        // nothing and would leave detected_iface untouched anyway,
        // but the explicit skip keeps the intent obvious.
        if !iface_authoritative {
            if let Some(output) = cmd_output("lsof", &["-n", "-P", "-p", &pid.to_string()]) {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if let Some(idx) = line.find("/dev/") {
                        let dev_path = line[idx..].split_whitespace().next().unwrap_or("");
                        if dev_path.contains("utun")
                            || dev_path.contains("tun")
                            || dev_path.contains("tap")
                        {
                            detected_iface = dev_path.trim_start_matches("/dev/").to_string();
                            // Method A succeeded — lsof showed THIS PID's
                            // own /dev/utun fd, so the iface is reliably
                            // attributable to this process.
                            iface_authoritative = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    // Method B: Scan for tun/tap interfaces and get IP/MTU
    #[cfg(target_os = "macos")]
    // xtask:allow-platform-cfg: ifconfig-based OpenVPN tun-iface discovery is macOS-only
    {
        if let Some(output) = cmd_output("ifconfig", &[]) {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut current_iface = String::new();
            let mut found_openvpn_iface = false;
            let mut iface_mtu = String::new();

            for line in stdout.lines() {
                if !line.starts_with(' ') && !line.starts_with('\t') {
                    if let Some(iface_name) = line.split(':').next() {
                        current_iface = iface_name.to_string();
                        if detected_iface.is_empty() {
                            found_openvpn_iface = current_iface.starts_with("utun")
                                || current_iface.starts_with("tun")
                                || current_iface.starts_with("tap");
                        } else {
                            found_openvpn_iface = current_iface == detected_iface;
                        }

                        if found_openvpn_iface {
                            if let Some(mtu_idx) = line.find("mtu ") {
                                iface_mtu = line[mtu_idx + 4..]
                                    .split_whitespace()
                                    .next()
                                    .unwrap_or("")
                                    .to_string();
                                if !detected_iface.is_empty() {
                                    session.interface.clone_from(&detected_iface);
                                    session.mtu.clone_from(&iface_mtu);
                                }
                            }
                        }
                    }
                } else if found_openvpn_iface {
                    let line = line.trim();
                    if line.starts_with("inet ") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2
                            && !crate::vortix_protocol_wireguard::WgTunnel::interface_exists(
                                &current_iface,
                            )
                        {
                            session.internal_ip = parts[1].to_string();
                            session.mtu.clone_from(&iface_mtu);
                            session.interface.clone_from(&current_iface);
                            break;
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    // xtask:allow-platform-cfg: ip-addr-based OpenVPN tun-iface discovery is Linux-only
    {
        // On Linux, use `ip addr` to find tun/tap interfaces
        if let Some(output) = cmd_output("ip", &["addr"]) {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut current_iface = String::new();
            let mut found_tun = false;

            for line in stdout.lines() {
                // Interface line: "5: tun0: <POINTOPOINT,...> mtu 1500 ..."
                if !line.starts_with(' ') {
                    if let Some(name_part) = line.split(':').nth(1) {
                        current_iface = name_part.trim().to_string();
                        found_tun =
                            current_iface.starts_with("tun") || current_iface.starts_with("tap");

                        if found_tun {
                            // Check it's not a WireGuard interface through the
                            // protocol-owned typed observer.
                            if crate::vortix_protocol_wireguard::WgTunnel::interface_exists(
                                &current_iface,
                            ) {
                                found_tun = false;
                                continue;
                            }

                            // Extract MTU
                            if let Some(mtu_idx) = line.find("mtu ") {
                                session.mtu = line[mtu_idx + 4..]
                                    .split_whitespace()
                                    .next()
                                    .unwrap_or("")
                                    .to_string();
                            }
                            detected_iface.clone_from(&current_iface);
                        }
                    }
                } else if found_tun {
                    let trimmed = line.trim();
                    if trimmed.starts_with("inet ") {
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 2 {
                            session.internal_ip =
                                parts[1].split('/').next().unwrap_or("").to_string();
                            session.interface.clone_from(&current_iface);
                            // Linux `ip addr` reliably attributes each
                            // tun/tap device — no multi-PID collision
                            // surface like the macOS Method B fallback.
                            iface_authoritative = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    // Ensure interface is set if we detected one
    if session.interface.is_empty() && !detected_iface.is_empty() {
        session.interface = detected_iface;
    }

    // Record the iface-attribution-reliability decision on the session.
    // The macOS Method-B fallback (first utun with `inet` that isn't WG)
    // is the only branch above that leaves `iface_authoritative=false`:
    // it cannot distinguish between concurrent OpenVPN processes, so
    // when two are up, both `check_openvpn_by_pid` calls return the
    // same utun — corrupting primary-election and per-tunnel killswitch
    // ACCEPT rules if the registry takes that value as authoritative.
    // By contract: adopted entries with unreliable iface are
    // excluded from primary-election by the registry.
    session.interface_authoritative = iface_authoritative;

    // No tun/tap interface means OpenVPN is running but NOT connected yet
    // (still negotiating TLS, authenticating, or has failed silently).
    // Don't report this as an active session — the scanner will re-check next tick.
    if session.interface.is_empty() {
        crate::logger::log(
            crate::logger::LogLevel::Debug,
            "SCANNER",
            format!("OpenVPN pid {pid} running but no tunnel interface detected yet"),
        );
        return None;
    }

    // Try to get remote server from process arguments first
    if let Some(output) = cmd_output("ps", &["-p", &pid.to_string(), "-o", "args="]) {
        let args = String::from_utf8_lossy(&output.stdout);
        if let Some(remote_idx) = args.find("--remote") {
            let rest = args.get(remote_idx + "--remote ".len()..).unwrap_or("");
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if !parts.is_empty() {
                let host = parts[0];
                let port = parts.get(1).unwrap_or(&"1194");
                session.endpoint = format!("{host}:{port}");
            }
        }
    }

    // Set cipher info (OpenVPN default or from config)
    session.public_key = "OpenVPN".to_string();

    // Read config file once for both endpoint and cipher extraction
    if let Ok(config_content) = std::fs::read_to_string(config_path) {
        // If no endpoint from args, try parsing the config file
        if session.endpoint.is_empty() {
            for line in config_content.lines() {
                let line = line.trim();
                if line.to_lowercase().starts_with("remote ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let host = parts[1];
                        let port = parts.get(2).unwrap_or(&"1194");
                        session.endpoint = format!("{host}:{port}");
                        break;
                    }
                }
            }
        }

        // Try to get cipher from config
        for line in config_content.lines() {
            let line = line.trim();
            if line.to_lowercase().starts_with("cipher ") {
                if let Some(cipher) = line.split_whitespace().nth(1) {
                    session.latest_handshake = format!("Cipher: {cipher}");
                    break;
                }
            }
        }
    }

    Some(session)
}

/// Parse ps etime format: [[dd-]hh:]mm:ss or just ss for very short uptimes
///
/// Handles various formats:
/// - "5" → 5 seconds (new processes)
/// - "01:23" → 1 minute 23 seconds
/// - "12:34:56" → 12 hours 34 minutes 56 seconds
/// - "2-03:45:12" → 2 days 3 hours 45 minutes 12 seconds
fn parse_ps_etime(etime: &str) -> Option<std::time::Duration> {
    use std::time::Duration;

    let etime = etime.trim();

    // Handle edge case: empty or invalid input
    if etime.is_empty() || etime == "-" {
        return None;
    }

    // Handle edge case: just seconds (no colon) for newly started processes
    if !etime.contains(':') {
        return etime.parse::<u64>().ok().map(Duration::from_secs);
    }

    let parts: Vec<&str> = etime.split(':').collect();
    if parts.len() < 2 {
        return None;
    }

    let mut seconds = 0u64;

    // Handle minutes and seconds (always present in MM:SS format)
    let secs: u64 = parts.last()?.parse().ok()?;
    let mins: u64 = parts[parts.len() - 2].parse().ok()?;
    seconds += secs + (mins * 60);

    // Handle hours and days if present
    if parts.len() >= 3 {
        let hour_part = parts[parts.len() - 3];
        if let Some(dash_idx) = hour_part.find('-') {
            // Format: dd-hh:mm:ss
            let days: u64 = hour_part[..dash_idx].parse().ok()?;
            let hours: u64 = hour_part[dash_idx + 1..].parse().ok()?;
            seconds += (days * 86400) + (hours * 3600);
        } else {
            // Format: hh:mm:ss
            let hours: u64 = hour_part.parse().ok()?;
            seconds += hours * 3600;
        }
    }

    // Handle case where we have more than 3 parts (e.g., dd:hh:mm:ss which some ps might return)
    if parts.len() == 4 && !parts[0].contains('-') {
        let days: u64 = parts[0].parse().ok()?;
        seconds += days * 86400;
    }

    Some(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_parse_ps_etime_minutes_seconds() {
        assert_eq!(parse_ps_etime("01:23"), Some(Duration::from_secs(83)));
        assert_eq!(parse_ps_etime("00:05"), Some(Duration::from_secs(5)));
        assert_eq!(parse_ps_etime("59:59"), Some(Duration::from_secs(3599)));
    }

    #[test]
    fn test_parse_ps_etime_hours_minutes_seconds() {
        assert_eq!(parse_ps_etime("1:02:03"), Some(Duration::from_secs(3723)));
        assert_eq!(parse_ps_etime("12:34:56"), Some(Duration::from_secs(45296)));
    }

    #[test]
    fn test_parse_ps_etime_days_hours_minutes_seconds() {
        // Format: dd-hh:mm:ss
        assert_eq!(
            parse_ps_etime("2-03:04:05"),
            Some(Duration::from_secs(2 * 86400 + 3 * 3600 + 4 * 60 + 5))
        );
        assert_eq!(
            parse_ps_etime("1-00:00:00"),
            Some(Duration::from_secs(86400))
        );
    }

    #[test]
    fn test_parse_ps_etime_just_seconds() {
        assert_eq!(parse_ps_etime("5"), Some(Duration::from_secs(5)));
        assert_eq!(parse_ps_etime("0"), Some(Duration::from_secs(0)));
    }

    #[test]
    fn test_parse_ps_etime_empty_and_invalid() {
        assert_eq!(parse_ps_etime(""), None);
        assert_eq!(parse_ps_etime("-"), None);
        assert_eq!(parse_ps_etime("abc"), None);
    }

    #[test]
    fn test_parse_ps_etime_whitespace() {
        assert_eq!(parse_ps_etime("  01:23  "), Some(Duration::from_secs(83)));
        assert_eq!(parse_ps_etime("  5  "), Some(Duration::from_secs(5)));
    }

    /// `ScannerResult::default()` must produce a sentinel "nothing
    /// observed yet" value — empty session list AND `None` route
    /// interface. The registry's `feed_default_route_interface(None)`
    /// is a legitimate "kernel reports no default route" signal, so
    /// we need a way to distinguish "scanner ran and saw nothing"
    /// from the initial pre-scan state. Default supplies the latter.
    #[test]
    fn scanner_result_default_is_empty() {
        let result = ScannerResult::default();
        assert!(
            result.sessions.is_empty(),
            "default ScannerResult must have no sessions"
        );
        assert!(
            matches!(
                result.default_route,
                crate::vortix_core::ports::route_table::DefaultRouteObservation::ProbeFailed
            ),
            "default ScannerResult must have no route interface"
        );
    }

    #[test]
    fn managed_openvpn_config_matches_only_its_exact_stable_profile_id() {
        use crate::vortix_core::profile::ProfileId;

        let id = "a".repeat(ProfileId::HEX_LEN);
        let source = "/profiles/corp.ovpn";
        let managed = PathBuf::from(format!(
            "/profiles/.vortix-{id}-0000000000000007-bbbbbbbbbbbbbbbb.ovpn"
        ));
        assert!(openvpn_config_matches_profile(&managed, source, &id));

        let other = format!("{}b", "a".repeat(ProfileId::HEX_LEN - 1));
        let foreign = PathBuf::from(format!(
            "/profiles/.vortix-{other}-0000000000000007-bbbbbbbbbbbbbbbb.ovpn"
        ));
        assert!(!openvpn_config_matches_profile(&foreign, source, &id));

        assert!(!openvpn_config_matches_profile(
            Path::new("/profiles/corp.ovpn.backup"),
            source,
            &id,
        ));
    }
}
