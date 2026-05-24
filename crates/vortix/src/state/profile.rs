//! VPN profile and protocol types.

use std::path::PathBuf;
use std::time::SystemTime;

/// Supported VPN protocol types.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum Protocol {
    /// `WireGuard` VPN protocol.
    #[default]
    WireGuard,
    /// `OpenVPN` protocol.
    OpenVPN,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::WireGuard => write!(f, "WireGuard"),
            Protocol::OpenVPN => write!(f, "OpenVPN"),
        }
    }
}

/// VPN profile configuration.
///
/// Represents a saved VPN configuration file that can be used to establish connections.
#[derive(Clone, Debug)]
pub struct VpnProfile {
    /// Display name for the profile.
    pub name: String,
    /// VPN protocol type (`WireGuard` or `OpenVPN`).
    pub protocol: Protocol,
    /// Geographic location or server identifier.
    pub location: String,
    /// Path to the configuration file on disk.
    pub config_path: PathBuf,
    /// Last time this profile was used.
    pub last_used: Option<SystemTime>,
}
