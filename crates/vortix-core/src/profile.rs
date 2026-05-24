//! Unified profile identity shared across the workspace.
//!
//! Plan #004 introduces `Profile` and `ProfileId` as the Tunnel-trait input
//! vocabulary. The binary crate's richer `VpnProfile` (with on-disk path,
//! last-used timestamp, etc.) lives on alongside this type during plan #004;
//! plan #007 (config + secrets stack) reconciles them.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Stable identifier for a profile, derived from disk path + name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProfileId(String);

impl ProfileId {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProfileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which tunnel protocol a profile uses.
///
/// Mirrors `vortix::state::Protocol` — the binary-side type stays put until
/// plan #007 consolidates profile storage. Keeping a separate `ProtocolKind`
/// here lets `vortix-core` declare the Tunnel-trait vocabulary without
/// pulling in the richer profile types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ProtocolKind {
    WireGuard,
    OpenVpn,
}

impl std::fmt::Display for ProtocolKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WireGuard => f.write_str("WireGuard"),
            Self::OpenVpn => f.write_str("OpenVPN"),
        }
    }
}

/// Minimal profile vocabulary the `Tunnel` trait operates on.
///
/// The engine and app continue to hold the richer `VpnProfile`; they build a
/// `Profile` view of it when invoking the trait. Protocol-specific parsed
/// state lives in the per-protocol crate's `ParsedProfile` impl, attached
/// here via the per-protocol crate's `ParsedProfile` impl.
#[derive(Debug, Clone)]
pub struct Profile {
    pub id: ProfileId,
    pub display_name: String,
    pub protocol: ProtocolKind,
    /// Absolute path to the on-disk config (e.g., `.conf` or `.ovpn`).
    pub config_path: PathBuf,
}

impl Profile {
    /// Construct a minimal profile view from disk-side metadata.
    #[must_use]
    pub fn new(
        id: ProfileId,
        display_name: impl Into<String>,
        protocol: ProtocolKind,
        config_path: PathBuf,
    ) -> Self {
        Self {
            id,
            display_name: display_name.into(),
            protocol,
            config_path,
        }
    }
}
