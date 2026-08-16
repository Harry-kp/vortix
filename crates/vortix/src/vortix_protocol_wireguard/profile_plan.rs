//! Unprivileged compilation of stored `WireGuard` profiles into helper plans.

use std::fmt::{Debug, Formatter};
use std::net::{IpAddr, SocketAddr};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::privileged::{
    ProtocolEndpoint, WireGuardInterfaceOptions, WireGuardPeerPlan, WireGuardPlan,
    WireGuardPresharedKeyRef,
};
use crate::vortix_core::profile::{Profile, ProtocolKind};

const MAX_FIELD_BYTES: usize = 4_096;

/// A typed public plan plus ordered, zeroizing descriptor payloads.
///
/// The key bytes are deliberately absent from `Debug`, serialization, and the
/// privileged plan. The daemon consumes this value immediately into anonymous
/// file descriptors ordered exactly like `WireGuardPlan::material_refs`.
pub(crate) struct PreparedWireGuardPlan {
    plan: WireGuardPlan,
    materials: Vec<Zeroizing<Vec<u8>>>,
}

impl Debug for PreparedWireGuardPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedWireGuardPlan")
            .field("profile_id", self.plan.profile_id())
            .field("generation", &self.plan.generation())
            .field("material_count", &self.materials.len())
            .finish_non_exhaustive()
    }
}

impl PreparedWireGuardPlan {
    pub(crate) fn into_parts(self) -> (WireGuardPlan, Vec<Zeroizing<Vec<u8>>>) {
        (self.plan, self.materials)
    }
}

#[derive(Default)]
struct InterfaceDraft {
    private_key: Option<Zeroizing<Vec<u8>>>,
    addresses: Vec<Cidr>,
    mtu: Option<u16>,
    listen_port: Option<u16>,
    listen_port_seen: bool,
    fwmark: Option<u32>,
    fwmark_seen: bool,
}

#[derive(Default)]
struct PeerDraft {
    public_key: Option<[u8; 32]>,
    preshared_key: Option<Zeroizing<Vec<u8>>>,
    endpoint: Option<ProtocolEndpoint>,
    allowed_routes: Vec<Cidr>,
    persistent_keepalive: Option<u16>,
    persistent_keepalive_seen: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Interface,
    Peer,
}

/// Compile one already-resolved profile body into the helper's strict
/// allowlisted `WireGuard` vocabulary.
pub(crate) fn compile_helper_plan(
    profile: &Profile,
    generation: u64,
    body: &[u8],
) -> Result<PreparedWireGuardPlan, WireGuardProfilePlanError> {
    if profile.protocol != ProtocolKind::WireGuard {
        return Err(WireGuardProfilePlanError::ProtocolMismatch);
    }
    if body.is_empty() || body.len() as u64 > crate::constants::MAX_CONFIG_SIZE_BYTES {
        return Err(WireGuardProfilePlanError::InvalidProfile);
    }
    let text = std::str::from_utf8(body).map_err(|_| WireGuardProfilePlanError::InvalidProfile)?;
    let mut interface = InterfaceDraft::default();
    let mut peers = Vec::new();
    let mut peer = None;
    let mut section = Section::None;
    let mut saw_interface = false;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(header) = line
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        {
            finish_peer(&mut peer, &mut peers)?;
            if header.trim().eq_ignore_ascii_case("Interface") {
                if saw_interface || !peers.is_empty() {
                    return Err(WireGuardProfilePlanError::InvalidSectionOrder);
                }
                saw_interface = true;
                section = Section::Interface;
            } else if header.trim().eq_ignore_ascii_case("Peer") {
                if !saw_interface {
                    return Err(WireGuardProfilePlanError::InvalidSectionOrder);
                }
                section = Section::Peer;
                peer = Some(PeerDraft::default());
            } else {
                return Err(WireGuardProfilePlanError::UnsupportedSection);
            }
            continue;
        }

        let (directive, raw_value) = line
            .split_once('=')
            .ok_or(WireGuardProfilePlanError::InvalidProfile)?;
        let directive = directive.trim();
        let value = strip_comment(raw_value).trim();
        if directive.is_empty()
            || value.is_empty()
            || directive.len() > MAX_FIELD_BYTES
            || value.len() > MAX_FIELD_BYTES
        {
            return Err(WireGuardProfilePlanError::InvalidProfile);
        }
        match section {
            Section::Interface => parse_interface(directive, value, &mut interface)?,
            Section::Peer => parse_peer(
                profile,
                directive,
                value,
                peer.as_mut()
                    .ok_or(WireGuardProfilePlanError::InvalidSectionOrder)?,
            )?,
            Section::None => return Err(WireGuardProfilePlanError::InvalidSectionOrder),
        }
    }
    finish_peer(&mut peer, &mut peers)?;

    finish_plan(profile, generation, interface, peers)
}

fn finish_plan(
    profile: &Profile,
    generation: u64,
    mut interface: InterfaceDraft,
    peers: Vec<PeerDraft>,
) -> Result<PreparedWireGuardPlan, WireGuardProfilePlanError> {
    let private_key = interface
        .private_key
        .take()
        .ok_or(WireGuardProfilePlanError::MissingPrivateKey)?;
    let options =
        WireGuardInterfaceOptions::new(interface.mtu, interface.listen_port, interface.fwmark)
            .map_err(|_| WireGuardProfilePlanError::InvalidInterfaceOption)?;
    let mut peer_plans = Vec::with_capacity(peers.len());
    let mut materials = Vec::with_capacity(1 + peers.len());
    materials.push(private_key);
    for mut draft in peers {
        let public_key = draft
            .public_key
            .ok_or(WireGuardProfilePlanError::MissingPeerPublicKey)?;
        let plan = match draft.preshared_key.take() {
            Some(material) => {
                let reference = WireGuardPresharedKeyRef::for_peer(public_key)
                    .map_err(|_| WireGuardProfilePlanError::InvalidKey)?;
                materials.push(material);
                WireGuardPeerPlan::with_preshared_key(
                    public_key,
                    draft.endpoint,
                    draft.allowed_routes,
                    draft.persistent_keepalive,
                    reference,
                )
            }
            None => WireGuardPeerPlan::new(
                public_key,
                draft.endpoint,
                draft.allowed_routes,
                draft.persistent_keepalive,
            ),
        }
        .map_err(|_| WireGuardProfilePlanError::InvalidPeer)?;
        peer_plans.push(plan);
    }
    let plan = WireGuardPlan::new(
        profile.id.clone(),
        generation,
        interface.addresses,
        peer_plans,
        options,
    )
    .map_err(|_| WireGuardProfilePlanError::InvalidProfile)?;
    if plan.material_refs().len() != materials.len() {
        return Err(WireGuardProfilePlanError::InvalidMaterialSet);
    }
    Ok(PreparedWireGuardPlan { plan, materials })
}

fn parse_interface(
    directive: &str,
    value: &str,
    draft: &mut InterfaceDraft,
) -> Result<(), WireGuardProfilePlanError> {
    if directive.eq_ignore_ascii_case("PrivateKey") {
        set_once(
            &mut draft.private_key,
            canonical_material(value)?,
            WireGuardProfilePlanError::DuplicateDirective,
        )
    } else if directive.eq_ignore_ascii_case("Address") {
        parse_cidrs(value, &mut draft.addresses)
    } else if directive.eq_ignore_ascii_case("MTU") {
        let mtu = value
            .parse::<u16>()
            .map_err(|_| WireGuardProfilePlanError::InvalidInterfaceOption)?;
        set_once(
            &mut draft.mtu,
            mtu,
            WireGuardProfilePlanError::DuplicateDirective,
        )
    } else if directive.eq_ignore_ascii_case("ListenPort") {
        if draft.listen_port_seen {
            return Err(WireGuardProfilePlanError::DuplicateDirective);
        }
        draft.listen_port_seen = true;
        let port = value
            .parse::<u16>()
            .map_err(|_| WireGuardProfilePlanError::InvalidInterfaceOption)?;
        draft.listen_port = (port != 0).then_some(port);
        Ok(())
    } else if directive.eq_ignore_ascii_case("FwMark") {
        if draft.fwmark_seen {
            return Err(WireGuardProfilePlanError::DuplicateDirective);
        }
        draft.fwmark_seen = true;
        let mark = parse_fwmark(value)?;
        draft.fwmark = mark;
        Ok(())
    } else if directive.eq_ignore_ascii_case("DNS") {
        Ok(())
    } else if ["PreUp", "PostUp", "PreDown", "PostDown"]
        .iter()
        .any(|candidate| directive.eq_ignore_ascii_case(candidate))
    {
        Err(WireGuardProfilePlanError::ExecutableDirective)
    } else {
        Err(WireGuardProfilePlanError::UnsupportedDirective)
    }
}

fn parse_peer(
    profile: &Profile,
    directive: &str,
    value: &str,
    draft: &mut PeerDraft,
) -> Result<(), WireGuardProfilePlanError> {
    if directive.eq_ignore_ascii_case("PublicKey") {
        let key = super::execution::decode_public_key(value)
            .map_err(|_| WireGuardProfilePlanError::InvalidKey)?;
        set_once(
            &mut draft.public_key,
            key,
            WireGuardProfilePlanError::DuplicateDirective,
        )
    } else if directive.eq_ignore_ascii_case("PresharedKey") {
        set_once(
            &mut draft.preshared_key,
            canonical_material(value)?,
            WireGuardProfilePlanError::DuplicateDirective,
        )
    } else if directive.eq_ignore_ascii_case("Endpoint") {
        let endpoint = parse_endpoint(profile, value)?;
        set_once(
            &mut draft.endpoint,
            endpoint,
            WireGuardProfilePlanError::DuplicateDirective,
        )
    } else if directive.eq_ignore_ascii_case("AllowedIPs") {
        parse_cidrs(value, &mut draft.allowed_routes)
    } else if directive.eq_ignore_ascii_case("PersistentKeepalive") {
        if draft.persistent_keepalive_seen {
            return Err(WireGuardProfilePlanError::DuplicateDirective);
        }
        draft.persistent_keepalive_seen = true;
        let seconds = if value.eq_ignore_ascii_case("off") || value == "0" {
            None
        } else {
            Some(
                value
                    .parse::<u16>()
                    .ok()
                    .filter(|value| *value != 0)
                    .ok_or(WireGuardProfilePlanError::InvalidPeer)?,
            )
        };
        draft.persistent_keepalive = seconds;
        Ok(())
    } else {
        Err(WireGuardProfilePlanError::UnsupportedDirective)
    }
}

fn finish_peer(
    current: &mut Option<PeerDraft>,
    peers: &mut Vec<PeerDraft>,
) -> Result<(), WireGuardProfilePlanError> {
    if let Some(peer) = current.take() {
        if peer.public_key.is_none() {
            return Err(WireGuardProfilePlanError::MissingPeerPublicKey);
        }
        peers.push(peer);
    }
    Ok(())
}

fn parse_cidrs(value: &str, output: &mut Vec<Cidr>) -> Result<(), WireGuardProfilePlanError> {
    for entry in value.split(',').map(str::trim) {
        if entry.is_empty() {
            return Err(WireGuardProfilePlanError::InvalidCidr);
        }
        output.push(
            entry
                .parse()
                .map_err(|_| WireGuardProfilePlanError::InvalidCidr)?,
        );
    }
    Ok(())
}

fn parse_endpoint(
    profile: &Profile,
    value: &str,
) -> Result<ProtocolEndpoint, WireGuardProfilePlanError> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        return ProtocolEndpoint::ip(address)
            .map_err(|_| WireGuardProfilePlanError::InvalidEndpoint);
    }
    let (host, port) = super::parser::parse_endpoint_host(value)
        .ok_or(WireGuardProfilePlanError::InvalidEndpoint)?;
    if let Ok(address) = host.parse::<IpAddr>() {
        return ProtocolEndpoint::ip(SocketAddr::new(address, port))
            .map_err(|_| WireGuardProfilePlanError::InvalidEndpoint);
    }
    if let Some(address) = profile.resolved_endpoint(&host, port) {
        return ProtocolEndpoint::ip(SocketAddr::new(address, port))
            .map_err(|_| WireGuardProfilePlanError::InvalidEndpoint);
    }
    if profile.require_managed_endpoint_resolution {
        return Err(WireGuardProfilePlanError::UnresolvedEndpoint);
    }
    ProtocolEndpoint::dns(&host, port).map_err(|_| WireGuardProfilePlanError::InvalidEndpoint)
}

fn canonical_material(value: &str) -> Result<Zeroizing<Vec<u8>>, WireGuardProfilePlanError> {
    super::execution::decode_public_key(value)
        .map_err(|_| WireGuardProfilePlanError::InvalidKey)?;
    Ok(Zeroizing::new(value.as_bytes().to_vec()))
}

fn parse_fwmark(value: &str) -> Result<Option<u32>, WireGuardProfilePlanError> {
    if value.eq_ignore_ascii_case("off") || value == "0" {
        return Ok(None);
    }
    let mark = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(|| value.parse::<u32>(), |hex| u32::from_str_radix(hex, 16))
        .map_err(|_| WireGuardProfilePlanError::InvalidInterfaceOption)?;
    Ok((mark != 0).then_some(mark))
}

fn strip_comment(value: &str) -> &str {
    value
        .find(['#', ';'])
        .map_or(value, |position| &value[..position])
}

fn set_once<T>(
    slot: &mut Option<T>,
    value: T,
    error: WireGuardProfilePlanError,
) -> Result<(), WireGuardProfilePlanError> {
    if slot.is_some() {
        Err(error)
    } else {
        *slot = Some(value);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum WireGuardProfilePlanError {
    #[error("profile protocol is not WireGuard")]
    ProtocolMismatch,
    #[error("WireGuard profile is empty, oversized, malformed, or incomplete")]
    InvalidProfile,
    #[error("WireGuard profile section order is invalid")]
    InvalidSectionOrder,
    #[error("WireGuard profile contains an unsupported section")]
    UnsupportedSection,
    #[error("WireGuard executable lifecycle directives are not supported by helper execution")]
    ExecutableDirective,
    #[error("WireGuard profile contains a directive not supported by helper execution")]
    UnsupportedDirective,
    #[error("WireGuard profile repeats a single-value directive")]
    DuplicateDirective,
    #[error("WireGuard profile has no private key")]
    MissingPrivateKey,
    #[error("WireGuard peer has no public key")]
    MissingPeerPublicKey,
    #[error("WireGuard profile contains invalid key material")]
    InvalidKey,
    #[error("WireGuard profile contains an invalid address or route")]
    InvalidCidr,
    #[error("WireGuard profile contains an invalid endpoint")]
    InvalidEndpoint,
    #[error("WireGuard hostname endpoint has no authenticated resolution")]
    UnresolvedEndpoint,
    #[error("WireGuard interface option cannot be represented safely")]
    InvalidInterfaceOption,
    #[error("WireGuard peer cannot be represented safely")]
    InvalidPeer,
    #[error("WireGuard material identities do not match the typed plan")]
    InvalidMaterialSet,
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use crate::vortix_core::profile::{Profile, ProfileId, ProtocolKind, ResolvedEndpoint};

    use super::{compile_helper_plan, WireGuardProfilePlanError};

    fn key(byte: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    }

    fn profile() -> Profile {
        Profile::new(
            ProfileId::parse("c".repeat(ProfileId::HEX_LEN)).unwrap(),
            "corp",
            ProtocolKind::WireGuard,
            "/profiles/corp.conf".into(),
        )
        .require_managed_endpoint_resolution()
    }

    #[test]
    fn managed_hostname_requires_exact_profile_bound_resolution() {
        let body = format!(
            "[Interface]\nPrivateKey = {}\n[Peer]\nPublicKey = {}\nEndpoint = vpn.example.test:51820\n",
            key(1),
            key(2),
        );
        assert_eq!(
            compile_helper_plan(&profile(), 1, body.as_bytes()).unwrap_err(),
            WireGuardProfilePlanError::UnresolvedEndpoint
        );

        let resolved = profile().with_endpoint_resolutions([ResolvedEndpoint::new(
            "vpn.example.test",
            51_820,
            "203.0.113.7".parse().unwrap(),
        )]);
        let prepared = compile_helper_plan(&resolved, 1, body.as_bytes()).unwrap();
        let (plan, _) = prepared.into_parts();
        assert_eq!(
            plan.peers()[0]
                .endpoint()
                .and_then(crate::vortix_core::privileged::ProtocolEndpoint::socket_addr)
                .unwrap()
                .ip(),
            "203.0.113.7".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn duplicate_zero_valued_directive_is_not_hidden_by_option_semantics() {
        let body = format!(
            "[Interface]\nPrivateKey = {}\nListenPort = 0\nListenPort = 0\n[Peer]\nPublicKey = {}\n",
            key(1),
            key(2),
        );

        assert_eq!(
            compile_helper_plan(&profile(), 1, body.as_bytes()).unwrap_err(),
            WireGuardProfilePlanError::DuplicateDirective
        );
    }

    #[test]
    fn debug_and_errors_never_echo_key_or_unknown_directive_text() {
        let secret = key(9);
        let body = format!(
            "[Interface]\nPrivateKey = {secret}\nSecretNamedDirective = sensitive-value\n[Peer]\nPublicKey = {}\n",
            key(2),
        );

        let error = compile_helper_plan(&profile(), 1, body.as_bytes()).unwrap_err();
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(&secret));
        assert!(!rendered.contains("SecretNamedDirective"));
        assert!(!rendered.contains("sensitive-value"));
    }
}
