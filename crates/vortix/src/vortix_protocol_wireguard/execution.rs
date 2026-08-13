//! Canonical helper-owned `WireGuard` runtime configuration.
//!
//! Only validated protocol plans and descriptor-backed key material reach
//! this renderer. It produces one private `wg-quick` file beneath the fixed
//! helper runtime identity; it never accepts hooks, scripts, paths, DNS, or
//! arbitrary `WireGuard` directives from the user profile.

use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use base64::engine::{general_purpose::STANDARD as BASE64, Engine as _};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::vortix_core::privileged::{ProtocolEndpoint, WireGuardPlan};

const KEY_BYTES: usize = 32;
const ENCODED_KEY_BYTES: usize = 44;

pub(crate) struct WireGuardMaterial<'a> {
    private_key: &'a [u8],
    preshared_keys: BTreeMap<[u8; 32], &'a [u8]>,
}

impl<'a> WireGuardMaterial<'a> {
    pub(crate) fn new(private_key: &'a [u8], preshared_keys: BTreeMap<[u8; 32], &'a [u8]>) -> Self {
        Self {
            private_key,
            preshared_keys,
        }
    }
}

pub(crate) struct WireGuardExecutionSpec {
    config_path: PathBuf,
    config: Zeroizing<String>,
}

impl Debug for WireGuardExecutionSpec {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireGuardExecutionSpec")
            .field("config_bytes", &self.config.len())
            .finish_non_exhaustive()
    }
}

impl WireGuardExecutionSpec {
    pub(crate) fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub(crate) fn config(&self) -> &[u8] {
        self.config.as_bytes()
    }
}

pub(crate) fn render_helper_execution(
    plan: &WireGuardPlan,
    config_path: &Path,
    materials: &WireGuardMaterial<'_>,
) -> Result<WireGuardExecutionSpec, WireGuardExecutionError> {
    if !config_path.is_absolute()
        || config_path.file_name().is_none()
        || config_path.extension().and_then(|value| value.to_str()) != Some("conf")
    {
        return Err(WireGuardExecutionError::UnsafeConfigPath);
    }
    let private_key = canonical_key(materials.private_key)?;
    let required_preshared = plan
        .peers()
        .iter()
        .filter_map(|peer| {
            peer.preshared_key()
                .map(crate::vortix_core::privileged::WireGuardPresharedKeyRef::peer_public_key)
        })
        .collect::<Vec<_>>();
    if required_preshared.len() != materials.preshared_keys.len()
        || required_preshared
            .iter()
            .any(|key| !materials.preshared_keys.contains_key(key))
    {
        return Err(WireGuardExecutionError::MaterialSetMismatch);
    }

    let mut config = Zeroizing::new(String::with_capacity(1024));
    config.push_str("[Interface]\nPrivateKey = ");
    config.push_str(private_key);
    config.push('\n');
    if !plan.addresses().is_empty() {
        config.push_str("Address = ");
        write_joined(&mut config, plan.addresses().iter())?;
        config.push('\n');
    }
    let options = plan.interface_options();
    if let Some(mtu) = options.mtu() {
        writeln!(config, "MTU = {mtu}").map_err(|_| WireGuardExecutionError::Render)?;
    }
    if let Some(port) = options.listen_port() {
        writeln!(config, "ListenPort = {port}").map_err(|_| WireGuardExecutionError::Render)?;
    }
    if let Some(mark) = options.fwmark() {
        writeln!(config, "FwMark = {mark}").map_err(|_| WireGuardExecutionError::Render)?;
    }

    for peer in plan.peers() {
        config.push_str("\n[Peer]\nPublicKey = ");
        config.push_str(&BASE64.encode(peer.public_key()));
        config.push('\n');
        if let Some(key_ref) = peer.preshared_key() {
            let value = materials
                .preshared_keys
                .get(&key_ref.peer_public_key())
                .ok_or(WireGuardExecutionError::MaterialSetMismatch)?;
            config.push_str("PresharedKey = ");
            config.push_str(canonical_key(value)?);
            config.push('\n');
        }
        if let Some(endpoint) = peer.endpoint() {
            config.push_str("Endpoint = ");
            write_endpoint(&mut config, endpoint)?;
            config.push('\n');
        }
        if !peer.allowed_routes().is_empty() {
            config.push_str("AllowedIPs = ");
            write_joined(&mut config, peer.allowed_routes().iter())?;
            config.push('\n');
        }
        if let Some(seconds) = peer.persistent_keepalive_seconds() {
            writeln!(config, "PersistentKeepalive = {seconds}")
                .map_err(|_| WireGuardExecutionError::Render)?;
        }
    }

    Ok(WireGuardExecutionSpec {
        config_path: config_path.to_owned(),
        config,
    })
}

fn canonical_key(bytes: &[u8]) -> Result<&str, WireGuardExecutionError> {
    let value = std::str::from_utf8(bytes)
        .map_err(|_| WireGuardExecutionError::InvalidKeyMaterial)?
        .trim_ascii();
    if value.len() != ENCODED_KEY_BYTES {
        return Err(WireGuardExecutionError::InvalidKeyMaterial);
    }
    let decoded = BASE64
        .decode(value)
        .map_err(|_| WireGuardExecutionError::InvalidKeyMaterial)?;
    if decoded.len() != KEY_BYTES || BASE64.encode(decoded) != value {
        return Err(WireGuardExecutionError::InvalidKeyMaterial);
    }
    Ok(value)
}

fn write_endpoint(
    output: &mut String,
    endpoint: &ProtocolEndpoint,
) -> Result<(), WireGuardExecutionError> {
    if let Some(address) = endpoint.socket_addr() {
        write!(output, "{}", CanonicalSocket(address)).map_err(|_| WireGuardExecutionError::Render)
    } else {
        let hostname = endpoint.hostname().ok_or(WireGuardExecutionError::Render)?;
        write!(output, "{}:{}", hostname.as_str(), endpoint.port())
            .map_err(|_| WireGuardExecutionError::Render)
    }
}

struct CanonicalSocket(SocketAddr);

impl std::fmt::Display for CanonicalSocket {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

fn write_joined<T: std::fmt::Display>(
    output: &mut String,
    values: impl Iterator<Item = T>,
) -> Result<(), WireGuardExecutionError> {
    for (index, value) in values.enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        write!(output, "{value}").map_err(|_| WireGuardExecutionError::Render)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum WireGuardExecutionError {
    #[error("WireGuard helper config path is unsafe")]
    UnsafeConfigPath,
    #[error("WireGuard key material is not one canonical 32-byte key")]
    InvalidKeyMaterial,
    #[error("WireGuard preshared-key material does not exactly match the plan")]
    MaterialSetMismatch,
    #[error("WireGuard helper configuration could not be rendered")]
    Render,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::cidr::Cidr;
    use crate::vortix_core::privileged::{
        ProtocolEndpoint, WireGuardInterfaceOptions, WireGuardPeerPlan, WireGuardPresharedKeyRef,
    };
    use crate::vortix_core::profile::ProfileId;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    fn id() -> ProfileId {
        ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap()
    }

    fn key(byte: u8) -> String {
        BASE64.encode([byte; 32])
    }

    fn plan(with_psk: bool) -> WireGuardPlan {
        let public = [2; 32];
        let endpoint =
            ProtocolEndpoint::ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 51820)).unwrap();
        let peer = if with_psk {
            WireGuardPeerPlan::with_preshared_key(
                public,
                Some(endpoint),
                vec![Cidr::new("0.0.0.0".parse().unwrap(), 0).unwrap()],
                Some(25),
                WireGuardPresharedKeyRef::for_peer(public).unwrap(),
            )
            .unwrap()
        } else {
            WireGuardPeerPlan::new(public, Some(endpoint), Vec::new(), None).unwrap()
        };
        WireGuardPlan::new(
            id(),
            4,
            vec![Cidr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 24).unwrap()],
            vec![peer],
            WireGuardInterfaceOptions::new(Some(1420), Some(51821), Some(42)).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn canonical_plan_renders_only_allowlisted_wg_quick_vocabulary() {
        let private = key(1);
        let psk = key(3);
        let material = WireGuardMaterial::new(
            private.as_bytes(),
            BTreeMap::from([([2; 32], psk.as_bytes())]),
        );
        let execution = render_helper_execution(
            &plan(true),
            Path::new("/run/vortix/resources/abc/vxabc.conf"),
            &material,
        )
        .unwrap();
        let rendered = std::str::from_utf8(execution.config()).unwrap();

        assert_eq!(
            rendered,
            format!(
                "[Interface]\nPrivateKey = {private}\nAddress = 10.0.0.2/24\nMTU = 1420\nListenPort = 51821\nFwMark = 42\n\n[Peer]\nPublicKey = {}\nPresharedKey = {psk}\nEndpoint = [::1]:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n",
                key(2)
            )
        );
        for forbidden in ["DNS", "PreUp", "PostUp", "PreDown", "PostDown", "Table"] {
            assert!(!rendered.contains(forbidden));
        }
    }

    #[test]
    fn material_set_and_key_encoding_are_exact() {
        let private = key(1);
        let missing = WireGuardMaterial::new(private.as_bytes(), BTreeMap::new());
        assert_eq!(
            render_helper_execution(
                &plan(true),
                Path::new("/run/vortix/resources/abc/vxabc.conf"),
                &missing,
            )
            .unwrap_err(),
            WireGuardExecutionError::MaterialSetMismatch
        );

        let invalid = WireGuardMaterial::new(b"not-a-key", BTreeMap::new());
        assert_eq!(
            render_helper_execution(
                &plan(false),
                Path::new("/run/vortix/resources/abc/vxabc.conf"),
                &invalid,
            )
            .unwrap_err(),
            WireGuardExecutionError::InvalidKeyMaterial
        );
    }

    #[test]
    fn relative_or_non_config_path_is_rejected() {
        let private = key(1);
        let material = WireGuardMaterial::new(private.as_bytes(), BTreeMap::new());
        for path in ["relative.conf", "/run/vortix/resources/abc/config.txt"] {
            assert_eq!(
                render_helper_execution(&plan(false), Path::new(path), &material).unwrap_err(),
                WireGuardExecutionError::UnsafeConfigPath
            );
        }
    }
}
