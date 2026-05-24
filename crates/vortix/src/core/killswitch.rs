//! Kill switch firewall control — relocated trait now lives in `vortix-core`
//! (plan 003 U1). This module keeps the binary-crate-side state persistence
//! and the platform dispatch shim until plan 003 U7 swaps callers over to
//! the `Platform` aggregate.

use crate::constants;
use crate::logger::{self, LogLevel};
use crate::state::{KillSwitchMode, KillSwitchState};
use crate::utils;
use std::fs;
use std::io;
use std::path::PathBuf;

// Re-export the canonical types so existing `crate::core::killswitch::*`
// imports keep resolving.
pub use vortix_core::ports::killswitch::{KillswitchError, Result};

// Backwards-compat alias — the old name is `KillSwitchError`.
pub type KillSwitchError = KillswitchError;

/// Enable kill switch by loading restrictive firewall rules.
///
/// Routes through the process-global `Platform` aggregate (plan 003 U7);
/// the per-OS impl lives in `vortix-platform-{macos,linux}`.
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
    crate::platform::current_platform()
        .killswitch
        .enable_blocking(vpn_interface, vpn_server_ip)
}

/// Disable kill switch by flushing firewall rules.
///
/// # Errors
///
/// Returns error if not running as root or firewall commands fail.
pub fn disable_blocking() -> Result<()> {
    crate::platform::current_platform()
        .killswitch
        .disable_blocking()
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
///
/// # Errors
///
/// Returns [`KillswitchError::Io`] when the file cannot be written.
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
