//! System VPN connection scanner.
//!
//! This module provides functionality to detect active VPN connections
//! by scanning system interfaces and processes for `WireGuard` and `OpenVPN` sessions.

use crate::app::{Protocol, VpnProfile};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

/// Information about an active VPN session detected on the system.
#[derive(Clone, Default)]
pub struct ActiveSession {
    /// Profile name associated with this session.
    pub name: String,
    /// Timestamp when the connection was established.
    pub started_at: Option<SystemTime>,
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

    for profile in profiles {
        let session_info = match profile.protocol {
            Protocol::WireGuard => check_wireguard(&profile.name),
            Protocol::OpenVPN => check_openvpn(&profile.config_path),
        };

        if let Some(mut session) = session_info {
            session.name.clone_from(&profile.name);
            active.push(session);
        }
    }

    active
}

/// Checks if a `WireGuard` interface exists and returns session details.
fn check_wireguard(name: &str) -> Option<ActiveSession> {
    let pid_file = PathBuf::from(format!("/var/run/wireguard/{name}.name"));

    // Resolve Real Interface Name (macOS uses utunX, mapped in the .name file)
    let interface_name = if pid_file.exists() {
        std::fs::read_to_string(&pid_file)
            .map_or_else(|_| name.to_string(), |s| s.trim().to_string())
    } else {
        name.to_string()
    };

    // Check if interface exists (using the resolved name)
    if pid_file.exists() || check_ifconfig_exists(&interface_name) {
        let mut session = ActiveSession::default();

        // 1. Start Time (from PID file)
        if pid_file.exists() {
            session.started_at = std::fs::metadata(&pid_file)
                .and_then(|m| m.created().or(m.modified()))
                .ok();
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

        return Some(session);
    }

    None
}

/// Checks if an `OpenVPN` process is running for the given config file.
///
/// `OpenVPN` session detection is more limited than `WireGuard` as `OpenVPN`
/// does not expose detailed interface statistics in the same way.
/// Internal IP detection requires parsing `OpenVPN` status logs which
/// may not always be available.
fn check_openvpn(config_path: &Path) -> Option<ActiveSession> {
    let path_str = config_path.to_str()?;

    let output = Command::new("pgrep")
        .args(["-f", &format!("openvpn.*{path_str}")])
        .output();

    if matches!(output, Ok(o) if o.status.success()) {
        Some(ActiveSession {
            name: String::new(), // Populated by caller
            started_at: None,
            internal_ip: "OpenVPN (Active)".to_string(),
            ..Default::default()
        })
    } else {
        None
    }
}

/// Verifies if a network interface exists using ifconfig.
fn check_ifconfig_exists(name: &str) -> bool {
    let output = Command::new("ifconfig")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();
    matches!(output, Ok(o) if o.status.success())
}
