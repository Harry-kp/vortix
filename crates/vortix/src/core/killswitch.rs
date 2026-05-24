//! Kill switch firewall control module.
//!
//! Controls the system firewall to block non-VPN traffic when kill switch is active.
//! Uses platform-specific implementations:
//! - macOS: pf (Packet Filter) via pfctl
//! - Linux: iptables with custom `VORTIX_KILLSWITCH` chain
//!
//! # Safety
//!
//! This module modifies system firewall rules and requires root privileges.
//! Firewall rules are designed to:
//! - Always allow loopback traffic
//! - Always allow local network (RFC1918) traffic
//! - Allow VPN server IP for reconnection
//! - Allow all traffic on VPN interface

use crate::constants;
use crate::logger::{self, LogLevel};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use crate::platform::Firewall;
use crate::state::{KillSwitchMode, KillSwitchState};
use crate::utils;
use std::fs;
use std::io;
use std::path::PathBuf;

/// Result type for kill switch operations
pub type Result<T> = std::result::Result<T, KillSwitchError>;

/// Errors that can occur during kill switch operations
#[derive(Debug)]
pub enum KillSwitchError {
    /// Failed to execute firewall command
    CommandFailed(String),
    /// I/O error
    Io(io::Error),
    /// Not running as root
    NotRoot,
}

impl std::fmt::Display for KillSwitchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommandFailed(msg) => write!(f, "firewall command failed: {msg}"),
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

/// Enable kill switch by loading restrictive firewall rules.
///
/// Delegates to the platform-specific firewall implementation.
///
/// # Arguments
///
/// * `vpn_interface` - The VPN tunnel interface (e.g., "utun3" on macOS, "wg0" on Linux)
/// * `vpn_server_ip` - Optional VPN server IP to allow for reconnection
///
/// # Errors
///
/// Returns error if not running as root or firewall commands fail.
pub fn enable_blocking(vpn_interface: &str, vpn_server_ip: Option<&str>) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        crate::platform::macos::firewall::PfFirewall::enable_blocking(vpn_interface, vpn_server_ip)
    }
    #[cfg(target_os = "linux")]
    {
        crate::platform::linux::firewall::IptablesFirewall::enable_blocking(
            vpn_interface,
            vpn_server_ip,
        )
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (vpn_interface, vpn_server_ip);
        compile_error!("kill switch is only supported on macOS and Linux")
    }
}

/// Disable kill switch by flushing firewall rules.
///
/// # Errors
///
/// Returns error if not running as root or firewall commands fail.
pub fn disable_blocking() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        crate::platform::macos::firewall::PfFirewall::disable_blocking()
    }
    #[cfg(target_os = "linux")]
    {
        crate::platform::linux::firewall::IptablesFirewall::disable_blocking()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        compile_error!("kill switch is only supported on macOS and Linux")
    }
}

/// Get the state file path.
fn get_state_path() -> Option<PathBuf> {
    utils::get_app_config_dir()
        .ok()
        .map(|dir| dir.join(constants::KILLSWITCH_STATE_FILE))
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

    crate::utils::write_user_file(&path, content)?;
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

    // pf rules tests are now in platform/macos/firewall.rs

    #[test]
    fn test_persisted_state_serialization() {
        let state = PersistedState {
            mode: KillSwitchMode::Auto,
            state: KillSwitchState::Armed,
            vpn_interface: Some("utun3".to_string()),
            vpn_server_ip: Some("1.2.3.4".to_string()),
        };

        let json = serde_json::to_string_pretty(&state).unwrap();
        let deserialized: PersistedState = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.mode, KillSwitchMode::Auto);
        assert_eq!(deserialized.state, KillSwitchState::Armed);
        assert_eq!(deserialized.vpn_interface, Some("utun3".to_string()));
        assert_eq!(deserialized.vpn_server_ip, Some("1.2.3.4".to_string()));
    }

    #[test]
    fn test_persisted_state_deserialization_with_nulls() {
        let json = r#"{"mode":"Off","state":"Disabled","vpn_interface":null,"vpn_server_ip":null}"#;
        let state: PersistedState = serde_json::from_str(json).unwrap();
        assert_eq!(state.mode, KillSwitchMode::Off);
        assert_eq!(state.state, KillSwitchState::Disabled);
        assert!(state.vpn_interface.is_none());
        assert!(state.vpn_server_ip.is_none());
    }

    #[test]
    fn test_persisted_state_corrupted_json() {
        let json = r#"{"mode":"InvalidValue","state":"Disabled"}"#;
        let result: std::result::Result<PersistedState, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_persisted_state_empty_json() {
        let result: std::result::Result<PersistedState, _> = serde_json::from_str("{}");
        assert!(result.is_err());
    }
}
