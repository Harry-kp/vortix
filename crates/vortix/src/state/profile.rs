//! VPN profile and protocol types.

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use crate::vortix_core::profile::ProfileId;

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
    /// Stable identity loaded from the profile's sidecar.
    pub id: ProfileId,
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

/// Debounced observation of whether a known profile's config is present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfilePresence {
    Present(PathBuf),
    RenamePending { previous: PathBuf, since: Instant },
    Missing,
}

/// Tracks editor-style remove/create rename sequences without creating IDs.
#[derive(Debug, Clone)]
pub struct ProfilePresenceTracker {
    state: ProfilePresence,
    debounce: Duration,
}

impl ProfilePresenceTracker {
    #[must_use]
    pub fn new(path: PathBuf, debounce: Duration) -> Self {
        Self {
            state: ProfilePresence::Present(path),
            debounce,
        }
    }

    #[must_use]
    pub fn state(&self) -> &ProfilePresence {
        &self.state
    }

    pub fn observe_missing(&mut self, now: Instant) {
        if let ProfilePresence::Present(previous) = &self.state {
            self.state = ProfilePresence::RenamePending {
                previous: previous.clone(),
                since: now,
            };
        }
    }

    /// Associate a replacement path with the existing stable ID.
    pub fn observe_path(&mut self, path: PathBuf) {
        self.state = ProfilePresence::Present(path);
    }

    pub fn settle(&mut self, now: Instant) {
        if matches!(
            &self.state,
            ProfilePresence::RenamePending { since, .. }
                if now.saturating_duration_since(*since) >= self.debounce
        ) {
            self.state = ProfilePresence::Missing;
        }
    }
}
