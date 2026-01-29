//! System VPN connection scanner.
//!
//! This module provides functionality to detect active VPN connections
//! by scanning system interfaces and processes for `WireGuard` and `OpenVPN` sessions.

use crate::app::{Protocol, VpnProfile};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

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
                    .map(|(_, &pid)| check_openvpn_by_pid(pid, &profile.config_path))
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
    if let Ok(output) = Command::new("ps")
        .args(["-ax", "-o", "pid,command"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1) {
            // Skip header
            let line = line.trim();
            if line.contains("openvpn") && line.contains(".ovpn") {
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
fn check_wireguard_by_name(name: &str) -> Option<ActiveSession> {
    let pid_file = PathBuf::from(format!("/var/run/wireguard/{name}.name"));

    // Check if mapping file exists OR if interface named after profile exists
    if !pid_file.exists() && !check_interface_exists(name) {
        return None;
    }

    // Resolve Real Interface Name (macOS uses utunX, mapped in the .name file)
    let interface_name = if pid_file.exists() {
        std::fs::read_to_string(&pid_file)
            .map_or_else(|_| name.to_string(), |s| s.trim().to_string())
    } else {
        name.to_string()
    };

    let mut session = ActiveSession {
        interface: interface_name.clone(),
        ..Default::default()
    };

    // 1. Attempt to find PID (wireguard-go or similar) - Do this FIRST
    if let Some(pid) = get_wireguard_pid(&interface_name) {
        session.pid = Some(pid);

        // Primary method: Get start time from process (works cross-platform)
        if let Ok(output) = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "etime="])
            .output()
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
    // On Linux, created() returns Err, and modified() can be wrong if file was touched
    #[cfg(target_os = "macos")]
    if session.started_at.is_none() && pid_file.exists() {
        session.started_at = std::fs::metadata(&pid_file)
            .and_then(|m| m.created())  // Only use created() on macOS
            .ok();
    }

    // Log if we couldn't determine start time (helps debug connection duration issues)
    if session.started_at.is_none() {
        crate::logger::log(
            crate::logger::LogLevel::Debug,
            "SCANNER",
            format!(
                "Could not determine start time for WireGuard interface '{interface_name}' (ps/metadata fallbacks failed)"
            ),
        );
    }

    // 2. Parse `wg show {interface_name}`
    if let Ok(output) = Command::new("wg").args(["show", &interface_name]).output() {
        let out = String::from_utf8_lossy(&output.stdout);
        for line in out.lines() {
            let line = line.trim();
            // Parsing logic...
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

    // 3. Parse `ifconfig {interface_name}` for IP and MTU
    if let Ok(output) = Command::new("ifconfig").arg(&interface_name).output() {
        let out = String::from_utf8_lossy(&output.stdout);
        for line in out.lines() {
            let line = line.trim();
            if line.starts_with("inet ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    session.internal_ip = parts[1].to_string();
                }
            }
            if let Some(v) = line.split("mtu ").nth(1) {
                session.mtu = v.to_string();
            }
        }
    }

    Some(session)
}

/// Finds the PID of the wireguard process managing the given interface.
///
/// Uses `lsof` to find the process holding the control socket.
/// Requires root privileges (which the app checks for on startup).
fn get_wireguard_pid(interface: &str) -> Option<u32> {
    let sock_path = format!("/var/run/wireguard/{interface}.sock");

    // Use lsof to get the PID (-t for terse output) of the process holding the socket
    if let Ok(output) = Command::new("lsof").args(["-t", &sock_path]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !stdout.is_empty() {
            return stdout.parse::<u32>().ok();
        }
    }

    // Fallback: Check if we can find it via ps if lsof fails (e.g. missing binary)
    // using the more robust search we tried earlier
    if let Ok(output) = Command::new("ps")
        .args(["-ax", "-o", "pid,command"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line_lower = line.to_lowercase();
            // Match "wireguard" AND the interface name
            if line_lower.contains("wireguard") && line_lower.contains(&interface.to_lowercase()) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(pid_str) = parts.first() {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        return Some(pid);
                    }
                }
            }
        }
    }

    None
}

fn check_interface_exists(name: &str) -> bool {
    // Basic check using wg show
    Command::new("wg")
        .args(["show", name, "public-key"])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Checks if an `OpenVPN` process is running for the given config file.
///
/// Extracts detailed session information including:
/// - Process start time from `ps` command
/// - Internal IP from the tun/tap interface
/// - MTU from the interface
/// - Remote endpoint from process args or config file
#[allow(clippy::too_many_lines)]
fn check_openvpn_by_pid(pid: u32, config_path: &Path) -> ActiveSession {
    let mut session = ActiveSession {
        pid: Some(pid),
        ..Default::default()
    };

    // Get process elapsed time using ps etime format: [[dd-]hh:]mm:ss
    if let Ok(output) = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "etime="])
        .output()
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
    // Method A: Use lsof to find the device file opened by the process (Most reliable on macOS)
    let mut detected_iface = String::new();
    if let Ok(output) = Command::new("lsof")
        .args(["-n", "-P", "-p", &pid.to_string()])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            // Look for /dev/utun, /dev/tun, or /dev/tap
            if let Some(idx) = line.find("/dev/") {
                let dev_path = line[idx..].split_whitespace().next().unwrap_or("");
                if dev_path.contains("utun") || dev_path.contains("tun") || dev_path.contains("tap")
                {
                    // Extract interface name from path: /dev/utun3 -> utun3
                    detected_iface = dev_path.trim_start_matches("/dev/").to_string();
                    break;
                }
            }
        }
    }

    // Method B: Fallback to ifconfig scanning
    if let Ok(output) = Command::new("ifconfig").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut current_iface = String::new();
        let mut found_openvpn_iface = false;
        let mut iface_mtu = String::new();

        for line in stdout.lines() {
            // Interface line starts with the interface name (no leading whitespace)
            if !line.starts_with(' ') && !line.starts_with('\t') {
                // New interface block
                if let Some(iface_name) = line.split(':').next() {
                    current_iface = iface_name.to_string();

                    // If we found the interface via lsof, we strictly look for that
                    if detected_iface.is_empty() {
                        // OpenVPN typically uses utun (macOS) or tun (Linux)
                        found_openvpn_iface = current_iface.starts_with("utun")
                            || current_iface.starts_with("tun")
                            || current_iface.starts_with("tap");
                    } else {
                        found_openvpn_iface = current_iface == detected_iface;
                    }

                    // Extract MTU from flags line: "utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500"
                    if found_openvpn_iface {
                        if let Some(mtu_idx) = line.find("mtu ") {
                            iface_mtu = line[mtu_idx + 4..]
                                .split_whitespace()
                                .next()
                                .unwrap_or("")
                                .to_string();

                            // If we already know the interface from lsof, we can still use this block to get MTU
                            if !detected_iface.is_empty() {
                                session.interface.clone_from(&detected_iface);
                                session.mtu.clone_from(&iface_mtu);
                            }
                        }
                    }
                }
            } else if found_openvpn_iface {
                let line = line.trim();
                // Look for inet address
                if line.starts_with("inet ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        // Verify this isn't a WireGuard interface by checking if wg knows about it
                        let wg_check = Command::new("wg")
                            .args(["show", &current_iface])
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .status();

                        // If wg doesn't recognize it, it's likely OpenVPN
                        if matches!(wg_check, Ok(s) if !s.success()) {
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

    // Ensure interface is set if we found it via lsof, even if ifconfig didn't show IP yet
    if session.interface.is_empty() && !detected_iface.is_empty() {
        session.interface = detected_iface;
    }

    // If we couldn't get internal IP, show process is active
    if session.internal_ip.is_empty() {
        session.internal_ip = "Active".to_string();
    }

    // Try to get remote server from process arguments first
    if let Ok(output) = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "args="])
        .output()
    {
        let args = String::from_utf8_lossy(&output.stdout);
        // Look for --remote argument
        if let Some(remote_idx) = args.find("--remote") {
            let rest = &args[remote_idx + 9..];
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if !parts.is_empty() {
                // Format: --remote host port
                let host = parts[0];
                let port = parts.get(1).unwrap_or(&"1194");
                session.endpoint = format!("{host}:{port}");
            }
        }
    }

    // If no endpoint from args, try parsing the config file
    if session.endpoint.is_empty() {
        if let Ok(content) = std::fs::read_to_string(config_path) {
            for line in content.lines() {
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
    }

    // Set cipher info (OpenVPN default or from config)
    session.public_key = "OpenVPN".to_string(); // Use this field to indicate protocol

    // Try to get cipher from config
    if let Ok(content) = std::fs::read_to_string(config_path) {
        for line in content.lines() {
            let line = line.trim();
            if line.to_lowercase().starts_with("cipher ") {
                if let Some(cipher) = line.split_whitespace().nth(1) {
                    session.latest_handshake = format!("Cipher: {cipher}");
                    break;
                }
            }
        }
    }

    session
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
