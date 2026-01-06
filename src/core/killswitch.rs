//! Kill switch firewall control module.
//!
//! Controls macOS `pf` (Packet Filter) to block non-VPN traffic when kill switch is active.
//!
//! # Safety
//!
//! This module modifies system firewall rules and requires root privileges.
//! Firewall rules are designed to:
//! - Always allow loopback traffic
//! - Always allow local network (RFC1918) traffic
//! - Allow VPN server IP for reconnection
//! - Allow all traffic on VPN interface

use crate::logger::{self, LogLevel};
use crate::state::{KillSwitchMode, KillSwitchState};
use crate::utils;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{self, Write as IoWrite};
use std::path::PathBuf;
use std::process::Command;

/// State file path for kill switch persistence
const STATE_FILE: &str = "killswitch.state";

/// pf configuration file path
const PF_CONF_PATH: &str = "/tmp/vortix_killswitch.conf";

/// Default VPN interface when none is known (macOS `WireGuard` default)
pub const DEFAULT_VPN_INTERFACE: &str = "utun0";

/// Result type for kill switch operations
pub type Result<T> = std::result::Result<T, KillSwitchError>;

/// Errors that can occur during kill switch operations
#[derive(Debug)]
pub enum KillSwitchError {
    /// Failed to execute pf command
    CommandFailed(String),
    /// I/O error
    Io(io::Error),
    /// Not running as root
    NotRoot,
}

impl std::fmt::Display for KillSwitchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommandFailed(msg) => write!(f, "pf command failed: {msg}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::NotRoot => write!(f, "kill switch requires root privileges"),
        }
    }
}

impl std::error::Error for KillSwitchError {}

impl From<io::Error> for KillSwitchError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Generate pf rules that block all traffic except VPN
fn generate_pf_rules(vpn_interface: &str, vpn_server_ip: Option<&str>) -> String {
    let mut rules = format!(
        r"# Vortix Kill Switch Rules - Auto-generated
# DO NOT EDIT - Will be overwritten

# Default: block all
block all

# Allow loopback
pass quick on lo0 all

# Allow local network (RFC1918)
pass out quick to 192.168.0.0/16
pass in quick from 192.168.0.0/16
pass out quick to 10.0.0.0/8
pass in quick from 10.0.0.0/8
pass out quick to 172.16.0.0/12
pass in quick from 172.16.0.0/12

# Allow DHCP
pass out quick proto udp from any port 68 to any port 67
pass in quick proto udp from any port 67 to any port 68

# Allow all traffic on VPN interface
pass quick on {vpn_interface} all
"
    );

    // Allow VPN server IP if known (for reconnection)
    if let Some(ip) = vpn_server_ip {
        // Using writeln! to avoid clippy::write_with_newline and handling the result
        writeln!(
            rules,
            "\n# Allow VPN server for reconnection\npass out quick proto udp to {ip}\npass out quick proto tcp to {ip}"
        )
        .unwrap();
    }

    rules
}

/// Enable kill switch by loading restrictive pf rules.
///
/// # Arguments
///
/// * `vpn_interface` - The VPN tunnel interface (e.g., "utun3", "tun0")
/// * `vpn_server_ip` - Optional VPN server IP to allow for reconnection
///
/// # Errors
///
/// Returns error if not running as root or pf commands fail.
pub fn enable_blocking(vpn_interface: &str, vpn_server_ip: Option<&str>) -> Result<()> {
    logger::log(
        LogLevel::Info,
        "FIREWALL",
        format!(
            "Enabling kill switch on interface '{}'{}",
            vpn_interface,
            vpn_server_ip
                .map(|ip| format!(", server: {ip}"))
                .unwrap_or_default()
        ),
    );

    if !crate::utils::is_root() {
        logger::log(
            LogLevel::Error,
            "FIREWALL",
            "Kill switch requires root privileges",
        );
        return Err(KillSwitchError::NotRoot);
    }

    // Generate and write pf rules
    let rules = generate_pf_rules(vpn_interface, vpn_server_ip);
    let mut file = fs::File::create(PF_CONF_PATH)?;
    file.write_all(rules.as_bytes())?;
    logger::log(
        LogLevel::Debug,
        "FIREWALL",
        format!("Wrote pf rules to {PF_CONF_PATH}"),
    );

    // Load the rules
    let output = Command::new("pfctl").args(["-f", PF_CONF_PATH]).output()?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr).to_string();
        logger::log(
            LogLevel::Error,
            "FIREWALL",
            format!("pfctl -f failed: {err}"),
        );
        return Err(KillSwitchError::CommandFailed(err));
    }

    // Enable pf
    let output = Command::new("pfctl").args(["-e"]).output()?;

    // pfctl -e returns non-zero if already enabled, which is fine
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // "pf enabled" or "pf already enabled" are both OK
        if !stderr.contains("enabled") {
            logger::log(
                LogLevel::Error,
                "FIREWALL",
                format!("pfctl -e failed: {stderr}"),
            );
            return Err(KillSwitchError::CommandFailed(stderr.to_string()));
        }
    }

    logger::log(
        LogLevel::Info,
        "FIREWALL",
        "✓ Kill switch ACTIVE - blocking non-VPN traffic",
    );
    Ok(())
}

/// Disable kill switch by flushing pf rules.
///
/// # Errors
///
/// Returns error if not running as root or pf commands fail.
pub fn disable_blocking() -> Result<()> {
    logger::log(LogLevel::Info, "FIREWALL", "Disabling kill switch...");

    if !crate::utils::is_root() {
        logger::log(
            LogLevel::Error,
            "FIREWALL",
            "Disabling kill switch requires root privileges",
        );
        return Err(KillSwitchError::NotRoot);
    }

    // Flush all rules
    let output = Command::new("pfctl").args(["-F", "all"]).output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "pf not enabled" errors
        if !stderr.contains("not enabled") {
            logger::log(
                LogLevel::Error,
                "FIREWALL",
                format!("pfctl -F failed: {stderr}"),
            );
            return Err(KillSwitchError::CommandFailed(stderr.to_string()));
        }
    }

    // Disable pf
    let _ = Command::new("pfctl").args(["-d"]).output()?;

    // Clean up temp file
    let _ = fs::remove_file(PF_CONF_PATH);

    logger::log(
        LogLevel::Info,
        "FIREWALL",
        "✓ Kill switch DISABLED - normal traffic restored",
    );
    Ok(())
}

/// Get the state file path.
fn get_state_path() -> Option<PathBuf> {
    utils::home_dir().map(|h| h.join(".config").join("vortix").join(STATE_FILE))
}

/// Persistent state for recovery after crashes.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PersistedState {
    pub mode: KillSwitchMode,
    pub state: KillSwitchState,
    pub vpn_interface: Option<String>,
    pub vpn_server_ip: Option<String>,
}

/// Load kill switch state from persistence file.
#[must_use]
pub fn load_state() -> Option<PersistedState> {
    let path = get_state_path()?;
    let content = fs::read_to_string(&path).ok()?;
    match serde_json::from_str(&content) {
        Ok(state) => {
            logger::log(
                LogLevel::Debug,
                "FIREWALL",
                format!("Loaded persisted state from {}", path.display()),
            );
            Some(state)
        }
        Err(e) => {
            logger::log(
                LogLevel::Warning,
                "FIREWALL",
                format!("Failed to parse persisted state: {e}"),
            );
            None
        }
    }
}

/// Save kill switch state to persistence file.
pub fn save_state(
    mode: KillSwitchMode,
    state: KillSwitchState,
    vpn_interface: Option<&str>,
    vpn_server_ip: Option<&str>,
) -> Result<()> {
    let Some(path) = get_state_path() else {
        return Ok(()); // Silently skip if no home dir
    };

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let persisted = PersistedState {
        mode,
        state,
        vpn_interface: vpn_interface.map(String::from),
        vpn_server_ip: vpn_server_ip.map(String::from),
    };

    let content = serde_json::to_string_pretty(&persisted).map_err(io::Error::other)?;

    fs::write(path, content)?;
    Ok(())
}

/// Clear the persisted state file.
pub fn clear_state() {
    if let Some(path) = get_state_path() {
        let _ = fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_pf_rules_with_server() {
        let rules = generate_pf_rules("utun3", Some("1.2.3.4"));
        assert!(rules.contains("block all"));
        assert!(rules.contains("pass quick on lo0"));
        assert!(rules.contains("192.168.0.0/16"));
        assert!(rules.contains("pass out quick proto udp to 1.2.3.4"));
        assert!(rules.contains("pass quick on utun3"));
    }

    #[test]
    fn test_generate_pf_rules_without_server() {
        let rules = generate_pf_rules("utun3", None);
        assert!(rules.contains("block all"));
        assert!(rules.contains("pass quick on utun3"));
        assert!(!rules.contains("1.2.3.4"));
    }
}
