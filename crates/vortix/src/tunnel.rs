//! `TunnelKind` aggregate — runtime-selectable tunnel dispatcher (plan 004 U4).
//!
//! The engine routes `profile.protocol → TunnelKind` exactly once via
//! [`tunnel_for`]; everything downstream calls the trait without protocol
//! match arms.
//!
//! The aggregate lives in the binary (not `vortix-core`) for the same
//! Cargo-cycle reason as `Platform` (plan 003): the protocol crates already
//! depend on `vortix-core`.

use std::path::Path;

use vortix_core::ports::tunnel::{
    ParseError, ParsedProfile, Tunnel, TunnelCapabilities, TunnelError, TunnelHandle,
    TunnelKindTag, TunnelStatus,
};
use vortix_core::profile::{Profile, ProfileId, ProtocolKind};
use vortix_protocol_openvpn::OvpnTunnel;
use vortix_protocol_wireguard::WgTunnel;

use crate::state::{Protocol, VpnProfile};

/// Runtime-selectable carrier over the closed protocol set.
///
/// Mock variant uses `vortix_core::ports::tunnel::mock::MockTunnel` so tests
/// can substitute scripted behaviour without touching the real impls.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum TunnelKind {
    WireGuard(WgTunnel),
    OpenVpn(OvpnTunnel),
    Mock(vortix_core::ports::tunnel::mock::MockTunnel),
}

impl TunnelKind {
    pub fn up(&mut self, profile: &Profile) -> Result<TunnelHandle, TunnelError> {
        match self {
            Self::WireGuard(t) => t.up(profile),
            Self::OpenVpn(t) => t.up(profile),
            Self::Mock(t) => t.up(profile),
        }
    }

    pub fn down(&mut self, handle: TunnelHandle) -> Result<(), TunnelError> {
        match self {
            Self::WireGuard(t) => t.down(handle),
            Self::OpenVpn(t) => t.down(handle),
            Self::Mock(t) => t.down(handle),
        }
    }

    pub fn status(&self, handle: &TunnelHandle) -> Result<TunnelStatus, TunnelError> {
        match self {
            Self::WireGuard(t) => t.status(handle),
            Self::OpenVpn(t) => t.status(handle),
            Self::Mock(t) => t.status(handle),
        }
    }

    pub fn parse_profile(&self, raw: &[u8]) -> Result<Box<dyn ParsedProfile>, ParseError> {
        match self {
            Self::WireGuard(t) => t.parse_profile(raw),
            Self::OpenVpn(t) => t.parse_profile(raw),
            Self::Mock(t) => t.parse_profile(raw),
        }
    }

    #[must_use]
    pub fn capabilities(&self) -> TunnelCapabilities {
        match self {
            Self::WireGuard(t) => t.capabilities(),
            Self::OpenVpn(t) => t.capabilities(),
            Self::Mock(t) => t.capabilities(),
        }
    }

    #[must_use]
    pub fn kind_tag(&self) -> TunnelKindTag {
        match self {
            Self::WireGuard(t) => t.kind_tag(),
            Self::OpenVpn(t) => t.kind_tag(),
            Self::Mock(t) => t.kind_tag(),
        }
    }
}

// Implement the `Tunnel` trait by delegating to the inherent methods.
// Plan 005's `Engine<T: Tunnel>` requires this so the binary can construct
// `Engine<TunnelKind>` and drive the FSM with the existing dispatch.
impl vortix_core::ports::tunnel::Tunnel for TunnelKind {
    fn up(&mut self, profile: &Profile) -> Result<TunnelHandle, TunnelError> {
        TunnelKind::up(self, profile)
    }
    fn down(&mut self, handle: TunnelHandle) -> Result<(), TunnelError> {
        TunnelKind::down(self, handle)
    }
    fn status(&self, handle: &TunnelHandle) -> Result<TunnelStatus, TunnelError> {
        TunnelKind::status(self, handle)
    }
    fn parse_profile(&self, raw: &[u8]) -> Result<Box<dyn ParsedProfile>, ParseError> {
        TunnelKind::parse_profile(self, raw)
    }
    fn capabilities(&self) -> TunnelCapabilities {
        TunnelKind::capabilities(self)
    }
    fn kind_tag(&self) -> TunnelKindTag {
        TunnelKind::kind_tag(self)
    }
}

/// Extended variant of [`tunnel_for`] that wires the `SecretStore`-backed
/// auth provider onto the `OpenVPN` tunnel (plan 006 U5). The provider tries
/// the layered store at `<config_dir>/secrets.enc` keyed by
/// `creds/<profile_id>`; missing entries silently fall through to the
/// legacy `auth_dir` lookup inside the tunnel.
#[must_use]
pub fn tunnel_for_with_secrets(
    protocol: Protocol,
    config_dir: &Path,
    ovpn_verbosity: &str,
    connect_timeout_secs: u64,
) -> TunnelKind {
    let mut kind = tunnel_for(protocol, config_dir, ovpn_verbosity, connect_timeout_secs);
    if let TunnelKind::OpenVpn(ref mut ovpn) = kind {
        let store_dir = config_dir.to_path_buf();
        let provider: vortix_protocol_openvpn::SecretProvider =
            std::sync::Arc::new(move |profile_id: &str| {
                use vortix_config::secret_store::{
                    LayeredSecretStore, SecretBackendTag, SecretRef, SecretStore, SecretStoreConfig,
                };
                let store = LayeredSecretStore::new(SecretStoreConfig {
                    fallback_path: store_dir.join("secrets.enc"),
                    passphrase: None,
                    force_fallback: false,
                })
                .ok()?;
                let id = format!("creds/{profile_id}");
                for backend in [SecretBackendTag::Keyring, SecretBackendTag::EncryptedFile] {
                    let r = SecretRef::new(backend, &id);
                    if let Ok(s) = store.get(&r) {
                        return Some(s.as_bytes().to_vec());
                    }
                }
                None
            });
        let updated = ovpn.clone().with_secret_provider(provider);
        *ovpn = updated;
    }
    kind
}

/// THE single routing function: protocol → `TunnelKind`.
///
/// Engine and CLI call this once per connect/disconnect and never branch on
/// protocol again. Adding a third protocol means adding one variant here.
#[must_use]
pub fn tunnel_for(
    protocol: Protocol,
    config_dir: &Path,
    ovpn_verbosity: &str,
    connect_timeout_secs: u64,
) -> TunnelKind {
    match protocol {
        Protocol::WireGuard => TunnelKind::WireGuard(WgTunnel::new()),
        Protocol::OpenVPN => TunnelKind::OpenVpn(
            OvpnTunnel::new(config_dir.join(crate::constants::OPENVPN_RUN_DIR))
                .with_auth_dir(config_dir.join(crate::constants::OPENVPN_AUTH_DIR))
                .with_verbosity(ovpn_verbosity)
                .with_connect_timeout(connect_timeout_secs),
        ),
    }
}

/// Build a `vortix-core` [`Profile`] view from the binary-side `VpnProfile`.
///
/// Plan 007 reconciles the two profile types; until then the engine
/// translates at the trait boundary.
#[must_use]
pub fn profile_view(p: &VpnProfile) -> Profile {
    Profile::new(
        ProfileId::new(&p.name),
        &p.name,
        match p.protocol {
            Protocol::WireGuard => ProtocolKind::WireGuard,
            Protocol::OpenVPN => ProtocolKind::OpenVpn,
        },
        p.config_path.clone(),
    )
}
