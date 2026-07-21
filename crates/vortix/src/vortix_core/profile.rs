//! Unified profile identity shared across the workspace.
//!
//! Plan #004 introduces `Profile` and `ProfileId` as the Tunnel-trait input
//! vocabulary. The binary crate's richer `VpnProfile` (with on-disk path,
//! last-used timestamp, etc.) lives on alongside this type;
//! a config/secrets consolidation reconciles them.
use std::fmt::Write as _;
use std::fs::File;
use std::io::Read as _;
use std::path::PathBuf;

use serde::{Deserialize, Deserializer, Serialize};

/// Strip a profile name down to ASCII `[A-Za-z0-9_-]` for safe use in
/// daemon names, filenames, and process-match patterns.
#[must_use]
pub fn sanitize_profile_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Stable, opaque identifier for a profile.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ProfileId(String);

impl ProfileId {
    /// Number of lowercase hexadecimal characters in an on-disk profile ID.
    pub const HEX_LEN: usize = 64;

    /// Construct an unchecked ID for legacy fixtures.
    ///
    /// Production input boundaries must use [`Self::parse`] and newly imported
    /// profiles must use [`Self::generate`]. This constructor is retained only
    /// because integration fixtures compile the library without `cfg(test)`.
    #[doc(hidden)]
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Parse and validate an ID read from an untrusted sidecar or IPC frame.
    pub fn parse(value: impl Into<String>) -> Result<Self, ProfileIdError> {
        let value = value.into();
        if value.len() != Self::HEX_LEN
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ProfileIdError);
        }
        Ok(Self(value))
    }

    /// Generate a cryptographically opaque ID from the operating system RNG.
    pub fn generate() -> std::io::Result<Self> {
        let mut bytes = [0_u8; Self::HEX_LEN / 2];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        let mut value = String::with_capacity(Self::HEX_LEN);
        for byte in bytes {
            let _ = write!(value, "{byte:02x}");
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A profile ID did not match the canonical opaque on-disk format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileIdError;

impl std::fmt::Display for ProfileIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("profile ID must be 64 lowercase hexadecimal characters")
    }
}

impl std::error::Error for ProfileIdError {}

impl<'de> Deserialize<'de> for ProfileId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
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
/// profile storage is consolidated. Keeping a separate `ProtocolKind`
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

#[cfg(test)]
mod tests {
    use super::ProfileId;

    #[test]
    fn deserialize_profile_id_enforces_canonical_wire_format() {
        let valid = "a".repeat(ProfileId::HEX_LEN);
        let decoded: ProfileId = serde_json::from_str(&format!("\"{valid}\"")).unwrap();
        assert_eq!(decoded.as_str(), valid);

        for malformed in [
            "short".to_string(),
            "A".repeat(ProfileId::HEX_LEN),
            "g".repeat(ProfileId::HEX_LEN),
            "../etc/passwd".to_string(),
            format!("{}x", "a".repeat(ProfileId::HEX_LEN)),
        ] {
            assert!(
                serde_json::from_str::<ProfileId>(&format!("\"{malformed}\"")).is_err(),
                "accepted malformed profile ID {malformed:?}"
            );
        }
    }
}
