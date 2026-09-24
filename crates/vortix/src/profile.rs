//! Unified profile identity shared across the workspace.
//!
//! `Profile` is what a protocol needs to start a tunnel; the richer
//! `config::profiles::VpnProfile` is what the UI lists.
use std::fs::File;
use std::io::Read as _;
use std::net::IpAddr;
use std::path::PathBuf;

use serde::{Deserialize, Deserializer, Serialize};

/// Portable maximum for the interface name derived by `wg-quick` from a
/// `WireGuard` config filename.
pub const MAX_WIREGUARD_INTERFACE_NAME_BYTES: usize = 15;

/// Validate the one explicit `WireGuard` interface identity shared by profile
/// storage, protocol execution, observation, and teardown.
pub fn validate_wireguard_interface_name(name: &str) -> Result<(), String> {
    let valid = !name.is_empty()
        && name.len() <= MAX_WIREGUARD_INTERFACE_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_=+.-".contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(format!(
            "WireGuard name must be 1–{MAX_WIREGUARD_INTERFACE_NAME_BYTES} characters using only letters, numbers, _, =, +, ., or -"
        ))
    }
}

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

/// Return a legacy display name only when it is an unambiguous artifact key.
///
/// Older releases keyed some files by sanitized display name. Compatibility
/// readers may inspect the original name only when it is nonempty and already
/// canonical; otherwise multiple names could resolve to the same artifact.
#[must_use]
pub fn unambiguous_legacy_artifact_key(display_name: &str) -> Option<&str> {
    (!display_name.is_empty() && sanitize_profile_name(display_name) == display_name)
        .then_some(display_name)
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
        Ok(Self(hex(&bytes)))
    }

    /// The first `bytes` of SHA-256(id) in hex: a fixed-length,
    /// filesystem-safe key. Callers' lengths are persisted in file and socket
    /// names, so never change one.
    #[must_use]
    pub fn digest_key(&self, bytes: usize) -> String {
        use sha2::{Digest as _, Sha256};
        hex(&Sha256::digest(self.as_str().as_bytes())[..bytes])
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ProtocolKind {
    WireGuard,
    OpenVpn,
}

/// One DNS endpoint resolution bound to an exact profile body by the caller.
/// Protocol adapters consume this only when rendering their private managed
/// config; source profiles are never modified.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResolvedEndpoint {
    pub hostname: String,
    pub port: u16,
    pub address: IpAddr,
}

impl ResolvedEndpoint {
    #[must_use]
    pub fn new(hostname: impl Into<String>, port: u16, address: IpAddr) -> Self {
        Self {
            hostname: hostname.into(),
            port,
            address,
        }
    }
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
/// state lives in each protocol module's parser.
#[derive(Debug, Clone)]
pub struct Profile {
    pub id: ProfileId,
    pub display_name: String,
    pub protocol: ProtocolKind,
    /// Absolute path to the on-disk config (e.g., `.conf` or `.ovpn`).
    pub config_path: PathBuf,
    /// Exact endpoint substitutions captured while the profile body was
    /// authenticated and parsed. Empty means hostname startup must fail
    /// closed rather than ask DNS through a blocking firewall.
    pub endpoint_resolutions: Vec<ResolvedEndpoint>,
    /// Canonical requires every hostname to be replaced in the
    /// managed config. Legacy callers default to protocol-native DNS.
    pub require_managed_endpoint_resolution: bool,
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
            endpoint_resolutions: Vec::new(),
            require_managed_endpoint_resolution: false,
        }
    }

    #[must_use]
    pub fn require_managed_endpoint_resolution(mut self) -> Self {
        self.require_managed_endpoint_resolution = true;
        self
    }

    #[must_use]
    pub fn with_endpoint_resolutions(
        mut self,
        resolutions: impl IntoIterator<Item = ResolvedEndpoint>,
    ) -> Self {
        self.endpoint_resolutions = resolutions.into_iter().collect();
        self
    }

    /// Return one unambiguous exact host/port substitution.
    #[must_use]
    pub fn resolved_endpoint(&self, hostname: &str, port: u16) -> Option<IpAddr> {
        let mut matches = self
            .endpoint_resolutions
            .iter()
            .filter(|resolution| {
                resolution.port == port && resolution.hostname.eq_ignore_ascii_case(hostname)
            })
            .map(|resolution| resolution.address);
        let first = matches.next()?;
        matches.all(|address| address == first).then_some(first)
    }
}

/// Lowercase hex encoding.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// A `.conf` or `.ovpn` file: the only extensions a profile can have.
#[must_use]
pub fn has_profile_extension(path: &std::path::Path) -> bool {
    matches!(
        path.extension().and_then(std::ffi::OsStr::to_str),
        Some("conf" | "ovpn")
    )
}

/// What a `.conf` file's syntax says it is: `WireGuard` sections, `OpenVPN`
/// directives, or both (which nothing can connect, so it is refused).
/// A file with neither reads as `WireGuard`; its parser then names what is
/// missing.
///
/// # Errors
///
/// Returns a message when the file carries both syntaxes.
pub fn detect_conf_protocol(text: &str) -> Result<ProtocolKind, String> {
    let (mut wireguard, mut openvpn) = (false, false);
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if line.eq_ignore_ascii_case("[interface]") || line.eq_ignore_ascii_case("[peer]") {
            wireguard = true;
        }
        let directive = line.split_whitespace().next().unwrap_or_default();
        if matches!(
            directive.to_ascii_lowercase().as_str(),
            "client" | "dev" | "remote" | "proto" | "ca" | "cert" | "key" | "auth-user-pass"
        ) {
            openvpn = true;
        }
    }
    match (wireguard, openvpn) {
        (true, true) => Err("the file mixes WireGuard sections and OpenVPN directives".into()),
        (false, true) => Ok(ProtocolKind::OpenVpn),
        _ => Ok(ProtocolKind::WireGuard),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        detect_conf_protocol, hex, sanitize_profile_name, unambiguous_legacy_artifact_key,
        ProfileId, ProtocolKind,
    };

    #[test]
    fn digest_keys_are_stable_sha256_prefixes() {
        // Persisted file and socket names depend on these exact strings.
        let id = ProfileId::new("corp");
        assert_eq!(id.digest_key(16), "19f4c684a3ff4f2dfa73b8d9098257cf");
        assert_eq!(id.digest_key(12), "19f4c684a3ff4f2dfa73b8d9");
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
    }

    #[test]
    fn legacy_artifact_keys_are_nonempty_and_unchanged_by_sanitizing() {
        let cases = [
            ("", None),
            ("corp", Some("corp")),
            ("corp-vpn_2", Some("corp-vpn_2")),
            ("corp vpn", None),
            ("team/a", None),
            ("team?a", None),
            ("café", None),
            ("日本VPN", None),
        ];

        for (display_name, expected) in cases {
            assert_eq!(
                unambiguous_legacy_artifact_key(display_name),
                expected,
                "unexpected legacy artifact decision for {display_name:?}"
            );
        }
    }

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

    #[test]
    fn test_sanitize_profile_name_ascii() {
        assert_eq!(sanitize_profile_name("my-vpn_1"), "my-vpn_1");
    }

    #[test]
    fn test_sanitize_profile_name_spaces() {
        assert_eq!(sanitize_profile_name("my vpn server"), "my_vpn_server");
    }

    #[test]
    fn test_sanitize_profile_name_special_chars() {
        assert_eq!(sanitize_profile_name("vpn@home!#$"), "vpn_home___");
    }

    #[test]
    fn test_sanitize_profile_name_unicode_rejected() {
        assert_eq!(sanitize_profile_name("café-vpn"), "caf_-vpn");
        assert_eq!(sanitize_profile_name("München"), "M_nchen");
    }

    #[test]
    fn test_sanitize_profile_name_cjk() {
        assert_eq!(sanitize_profile_name("日本VPN"), "__VPN");
    }

    #[test]
    fn test_sanitize_profile_name_empty() {
        assert_eq!(sanitize_profile_name(""), "");
    }

    #[test]
    fn conf_protocol_follows_syntax_and_refuses_a_mix() {
        let wg = "[Interface]\nPrivateKey = x\n[Peer]\nPublicKey = y\n";
        let ovpn = "client\ndev tun\nremote vpn.example.com 1194\n";
        assert_eq!(detect_conf_protocol(wg), Ok(ProtocolKind::WireGuard));
        assert_eq!(detect_conf_protocol(ovpn), Ok(ProtocolKind::OpenVpn));
        assert_eq!(
            detect_conf_protocol("CLIENT\nRemote a 1\n"),
            Ok(ProtocolKind::OpenVpn)
        );
        assert_eq!(
            detect_conf_protocol("# only a comment\n"),
            Ok(ProtocolKind::WireGuard)
        );
        assert!(detect_conf_protocol(&format!("{wg}remote x 1\n")).is_err());
    }
}
