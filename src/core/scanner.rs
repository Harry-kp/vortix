//! System VPN connection scanner.
//!
//! This module provides functionality to detect active VPN connections
//! by scanning system interfaces and processes for `WireGuard` and `OpenVPN` sessions.

use crate::app::{Protocol, VpnProfile};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

/// Run a command and return its output.
///
/// No timeout — the scanner runs in a background thread so it cannot block the UI.
/// Commands like `lsof` and `ifconfig` need to run to completion for reliable detection.
fn cmd_output(cmd: &mut Command) -> Option<std::process::Output> {
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .ok()
}

/// Information about an active VPN session detected on the system.
#[derive(Clone, Default, Debug)]
pub struct ActiveSession {
    /// Profile name associated with this session.
    pub name: String,
    /// Process ID for `OpenVPN` or interface index (not used yet).
    pub pid: Option<u32>,
    /// Timestamp when the connection was established.
    pub started_at: Option<SystemTime>,
    /// System interface name (e.g., utun3, wg0, tun0).
    pub interface: String,
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
/// A vector of [`ActiveSession`] structs for each detected active connection.
pub fn get_active_profiles(profiles: &[VpnProfile]) -> Vec<ActiveSession> {
    let mut active = Vec::new();

    // 1. Batch lookup for OpenVPN
    let openvpn_pids = get_all_openvpn_pids();
    for profile in profiles {
        let session_info = match profile.protocol {
            Protocol::WireGuard => check_wireguard_by_name(&profile.name),
            Protocol::OpenVPN => {
                let path_str = profile.config_path.to_str().unwrap_or("");
                // Check if any PID matches this path
                openvpn_pids
                    .iter()
                    .find(|(path, _)| path.contains(path_str) || path_str.contains(*path))
                    .and_then(|(_, &pid)| check_openvpn_by_pid(pid, &profile.config_path))
            }
        };

        if let Some(mut session) = session_info {
            session.name.clone_from(&profile.name);
            active.push(session);
        }
    }

    active
}

fn get_all_openvpn_pids() -> std::collections::HashMap<String, u32> {
    let mut pids = std::collections::HashMap::new();
    // Use ps -ax -o pid,args to get PID and full command line
    if let Some(output) = cmd_output(Command::new("ps").args(["-ax", "-o", "pid,command"])) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1) {
            // Skip header
            let line = line.trim();
            // Match any openvpn process with --config (covers .ovpn, .conf, and any extension)
            if line.contains("openvpn") && line.contains("--config") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(pid) = parts[0].parse::<u32>() {
                        // Store the whole command line as the key for fuzzy matching
                        let cmd = parts[1..].join(" ");
                        pids.insert(cmd, pid);
                    }
                }
            }
        }
    }
    pids
}

/// Checks if a `WireGuard` interface exists and returns session details.
///
/// Uses platform-specific interface detection:
/// - macOS: /var/run/wireguard/*.name + ifconfig
/// - Linux: ip addr + wg show
fn check_wireguard_by_name(name: &str) -> Option<ActiveSession> {
    use crate::platform::InterfaceDetector;

    // Platform-dispatched interface check
    #[cfg(target_os = "macos")]
    type PlatformInterface = crate::platform::macos::interface::MacInterface;
    #[cfg(target_os = "linux")]
    type PlatformInterface = crate::platform::linux::interface::LinuxInterface;

    if !PlatformInterface::check_wireguard_interface(name) {
        return None;
    }

    let interface_name =
        PlatformInterface::resolve_wireguard_interface(name).unwrap_or_else(|| name.to_string());

    let mut session = ActiveSession {
        interface: interface_name.clone(),
        ..Default::default()
    };

    // 1. Attempt to find PID (wireguard-go or similar)
    if let Some(pid) = PlatformInterface::get_wireguard_pid(&interface_name) {
        session.pid = Some(pid);

        // Primary method: Get start time from process (works cross-platform)
        if let Some(output) =
            cmd_output(Command::new("ps").args(["-p", &pid.to_string(), "-o", "etime="]))
        {
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

    // 3. Parse `wg show {interface_name}` (works the same on both platforms)
    if let Some(output) = cmd_output(Command::new("wg").args(["show", &interface_name])) {
        let out = String::from_utf8_lossy(&output.stdout);
        for line in out.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("public key: ") {
                session.public_key = v.to_string();
            }
            if let Some(v) = line.strip_prefix("listening port: ") {
                session.listen_port = v.to_string();
            }
            if let Some(v) = line.strip_prefix("endpoint: ") {
                session.endpoint = v.to_string();
            }
            if let Some(v) = line.strip_prefix("latest handshake: ") {
                session.latest_handshake = v.to_string();
            }
            if let Some(v) = line.strip_prefix("transfer: ") {
                let parts: Vec<&str> = v.split_terminator(',').collect();
                if parts.len() >= 2 {
                    session.transfer_rx = parts[0].trim().replace(" received", "");
                    session.transfer_tx = parts[1].trim().replace(" sent", "");
                }
            }
        }
    }

    // 4. Get IP and MTU using platform-specific interface info
    let (ip, mtu) = PlatformInterface::get_interface_info(&interface_name);
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
fn check_openvpn_by_pid(pid: u32, config_path: &Path) -> Option<ActiveSession> {
    let mut session = ActiveSession {
        pid: Some(pid),
        ..Default::default()
    };

    // Get process elapsed time using ps etime format: [[dd-]hh:]mm:ss
    if let Some(output) =
        cmd_output(Command::new("ps").args(["-p", &pid.to_string(), "-o", "etime="]))
    {
        let etime = String::from_utf8_lossy(&output.stdout);
        let etime = etime.trim();
        if !etime.is_empty() {
            if let Some(duration) = parse_ps_etime(etime) {
                session.started_at = SystemTime::now().checked_sub(duration);
            }
        }
    }

    // 2. Find OpenVPN tun/tap interface
    // Method A: Use lsof to find the device file opened by the process (most reliable on macOS)
    let mut detected_iface = String::new();

    #[cfg(target_os = "macos")]
    {
        if let Some(output) =
            cmd_output(Command::new("lsof").args(["-n", "-P", "-p", &pid.to_string()]))
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Some(idx) = line.find("/dev/") {
                    let dev_path = line[idx..].split_whitespace().next().unwrap_or("");
                    if dev_path.contains("utun")
                        || dev_path.contains("tun")
                        || dev_path.contains("tap")
                    {
                        detected_iface = dev_path.trim_start_matches("/dev/").to_string();
                        break;
                    }
                }
            }
        }
    }

    // Method B: Scan for tun/tap interfaces and get IP/MTU
    #[cfg(target_os = "macos")]
    {
        if let Some(output) = cmd_output(&mut Command::new("ifconfig")) {
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
                        if parts.len() >= 2 {
                            let wg_check =
                                cmd_output(Command::new("wg").args(["show", &current_iface]));
                            if !matches!(wg_check, Some(o) if o.status.success()) {
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
    }

    #[cfg(target_os = "linux")]
    {
        // On Linux, use `ip addr` to find tun/tap interfaces
        if let Some(output) = cmd_output(Command::new("ip").args(["addr"])) {
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
                            // Check it's not a WireGuard interface
                            let wg_check =
                                cmd_output(Command::new("wg").args(["show", &current_iface]));
                            if matches!(wg_check, Some(o) if o.status.success()) {
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
    if let Some(output) =
        cmd_output(Command::new("ps").args(["-p", &pid.to_string(), "-o", "args="]))
    {
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
}
