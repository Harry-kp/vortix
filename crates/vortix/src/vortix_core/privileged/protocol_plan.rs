//! Canonical, allowlisted protocol plans accepted by privileged execution.
//!
//! Protocol adapters parse untrusted profile text and construct these values.
//! The plans intentionally contain no executable, path, environment, hook,
//! plugin, include, or arbitrary option vocabulary.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::privileged::{has_duplicates, invalid_unicast_ip, BoundedVec};
use crate::vortix_core::profile::{ProfileId, ProtocolKind};

const MAX_ADDRESSES: usize = 32;
const MAX_PEERS: usize = 256;
const MAX_ALLOWED_ROUTES: usize = 256;
const MAX_REMOTES: usize = 16;
const MAX_DNS_NAME_LEN: usize = 253;
const MAX_DNS_LABEL_LEN: usize = 63;

/// Canonical ASCII DNS hostname. Construction lowercases the name so DNS
/// case differences cannot produce different operation digests.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct DnsHostname(String);

impl DnsHostname {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ProtocolPlanError> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > MAX_DNS_NAME_LEN || !value.is_ascii() {
            return Err(ProtocolPlanError::InvalidHostname);
        }
        for label in value.split('.') {
            if label.is_empty()
                || label.len() > MAX_DNS_LABEL_LEN
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            {
                return Err(ProtocolPlanError::InvalidHostname);
            }
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for DnsHostname {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// A protocol endpoint is either an IP socket or a strictly validated DNS
/// hostname and port. It cannot carry URL schemes, paths, options, or shell
/// fragments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProtocolEndpoint {
    Ip { address: SocketAddr },
    Dns { hostname: DnsHostname, port: u16 },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ProtocolEndpointWire {
    Ip { address: SocketAddr },
    Dns { hostname: DnsHostname, port: u16 },
}

impl<'de> Deserialize<'de> for ProtocolEndpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match ProtocolEndpointWire::deserialize(deserializer)? {
            ProtocolEndpointWire::Ip { address } => Self::ip(address),
            ProtocolEndpointWire::Dns { hostname, port } => Self::dns(hostname.as_str(), port),
        }
        .map_err(serde::de::Error::custom)
    }
}

impl ProtocolEndpoint {
    pub fn ip(address: SocketAddr) -> Result<Self, ProtocolPlanError> {
        validate_socket_addr(address)?;
        Ok(Self::Ip { address })
    }

    pub fn dns(hostname: impl AsRef<str>, port: u16) -> Result<Self, ProtocolPlanError> {
        if port == 0 {
            return Err(ProtocolPlanError::InvalidEndpoint);
        }
        Ok(Self::Dns {
            hostname: DnsHostname::new(hostname)?,
            port,
        })
    }

    #[must_use]
    pub const fn hostname(&self) -> Option<&DnsHostname> {
        match self {
            Self::Ip { .. } => None,
            Self::Dns { hostname, .. } => Some(hostname),
        }
    }

    #[must_use]
    pub const fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Ip { address } => Some(*address),
            Self::Dns { .. } => None,
        }
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        match self {
            Self::Ip { address } => address.port(),
            Self::Dns { port, .. } => *port,
        }
    }

    fn validate(&self) -> Result<(), ProtocolPlanError> {
        match self {
            Self::Ip { address } => validate_socket_addr(*address),
            Self::Dns { port, .. } if *port == 0 => Err(ProtocolPlanError::InvalidEndpoint),
            Self::Dns { .. } => Ok(()),
        }
    }
}

/// A protocol-specific plan after unprivileged parsing and validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "protocol",
    content = "plan",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ProtocolPlan {
    WireGuard(WireGuardPlan),
    OpenVpn(OpenVpnPlan),
}

impl ProtocolPlan {
    #[must_use]
    pub const fn protocol(&self) -> ProtocolKind {
        match self {
            Self::WireGuard(_) => ProtocolKind::WireGuard,
            Self::OpenVpn(_) => ProtocolKind::OpenVpn,
        }
    }

    #[must_use]
    pub fn profile_id(&self) -> &ProfileId {
        match self {
            Self::WireGuard(plan) => &plan.profile_id,
            Self::OpenVpn(plan) => &plan.profile_id,
        }
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        match self {
            Self::WireGuard(plan) => plan.generation,
            Self::OpenVpn(plan) => plan.generation,
        }
    }

    #[must_use]
    pub fn material_refs(&self) -> Vec<ProfileMaterialRef> {
        match self {
            Self::WireGuard(plan) => plan.material_refs(),
            Self::OpenVpn(plan) => plan
                .materials
                .iter()
                .copied()
                .map(|slot| ProfileMaterialRef::ProfileSlot { slot })
                .collect(),
        }
    }

    /// Ordered descriptor identities for one tunnel start request.
    ///
    /// Profile material and one-shot runtime credentials share the local
    /// descriptor transport, but they are deliberately distinct identities:
    /// credentials are neither serialized in this plan nor persisted as
    /// profile material.
    #[must_use]
    pub(crate) fn descriptor_refs(&self) -> Vec<TunnelDescriptorRef> {
        let mut descriptors = Vec::with_capacity(self.descriptor_count());
        match self {
            Self::WireGuard(plan) => {
                descriptors.push(TunnelDescriptorRef::ProfileMaterial(
                    ProfileMaterialRef::ProfileSlot {
                        slot: plan.private_key,
                    },
                ));
                descriptors.extend(plan.peers.iter().filter_map(|peer| {
                    peer.preshared_key.map(|key| {
                        TunnelDescriptorRef::ProfileMaterial(
                            ProfileMaterialRef::WireGuardPresharedKey {
                                peer_public_key: key.peer_public_key,
                            },
                        )
                    })
                }));
            }
            Self::OpenVpn(plan) => {
                descriptors.extend(plan.materials.iter().copied().map(|slot| {
                    TunnelDescriptorRef::ProfileMaterial(ProfileMaterialRef::ProfileSlot { slot })
                }));
                if plan.authentication.uses_username_password() {
                    descriptors.push(TunnelDescriptorRef::OpenVpnCredentials);
                }
            }
        }
        descriptors
    }

    #[must_use]
    pub(crate) fn descriptor_count(&self) -> usize {
        match self {
            Self::WireGuard(plan) => {
                1 + plan
                    .peers
                    .iter()
                    .filter(|peer| peer.preshared_key.is_some())
                    .count()
            }
            Self::OpenVpn(plan) => {
                plan.materials.len() + usize::from(plan.authentication.uses_username_password())
            }
        }
    }
}

/// Canonical `WireGuard` interface and peer data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(try_from = "WireGuardPlanWire")]
pub struct WireGuardPlan {
    profile_id: ProfileId,
    generation: u64,
    addresses: Vec<Cidr>,
    peers: Vec<WireGuardPeerPlan>,
    interface_options: WireGuardInterfaceOptions,
    private_key: ProfileMaterialSlot,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireGuardPlanWire {
    profile_id: ProfileId,
    generation: u64,
    addresses: BoundedVec<Cidr, MAX_ADDRESSES>,
    peers: BoundedVec<WireGuardPeerPlan, MAX_PEERS>,
    interface_options: WireGuardInterfaceOptions,
    private_key: ProfileMaterialSlot,
}

impl TryFrom<WireGuardPlanWire> for WireGuardPlan {
    type Error = ProtocolPlanError;

    fn try_from(wire: WireGuardPlanWire) -> Result<Self, Self::Error> {
        Self::validate(
            wire.profile_id,
            wire.generation,
            wire.addresses.into_vec(),
            wire.peers.into_vec(),
            wire.interface_options,
            wire.private_key,
        )
    }
}

impl<'de> Deserialize<'de> for WireGuardPlan {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        WireGuardPlanWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

impl WireGuardPlan {
    pub fn new(
        profile_id: ProfileId,
        generation: u64,
        addresses: Vec<Cidr>,
        peers: Vec<WireGuardPeerPlan>,
        interface_options: WireGuardInterfaceOptions,
    ) -> Result<Self, ProtocolPlanError> {
        Self::validate(
            profile_id,
            generation,
            addresses,
            peers,
            interface_options,
            ProfileMaterialSlot::WireGuardPrivateKey,
        )
    }

    fn validate(
        profile_id: ProfileId,
        generation: u64,
        addresses: Vec<Cidr>,
        peers: Vec<WireGuardPeerPlan>,
        interface_options: WireGuardInterfaceOptions,
        private_key: ProfileMaterialSlot,
    ) -> Result<Self, ProtocolPlanError> {
        if generation == 0 {
            return Err(ProtocolPlanError::InvalidGeneration);
        }
        if private_key != ProfileMaterialSlot::WireGuardPrivateKey {
            return Err(ProtocolPlanError::InvalidMaterialSlots);
        }
        if addresses.iter().any(|cidr| !cidr.is_valid()) {
            return Err(ProtocolPlanError::InvalidCidr);
        }
        validate_count("WireGuard address", addresses.len(), 0, MAX_ADDRESSES)?;
        validate_count("WireGuard peer", peers.len(), 1, MAX_PEERS)?;
        if has_duplicates(peers.iter().map(|peer| &peer.public_key)) {
            return Err(ProtocolPlanError::DuplicatePublicKey);
        }
        Ok(Self {
            profile_id,
            generation,
            addresses,
            peers,
            interface_options,
            private_key,
        })
    }

    #[must_use]
    pub fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn addresses(&self) -> &[Cidr] {
        &self.addresses
    }

    #[must_use]
    pub fn peers(&self) -> &[WireGuardPeerPlan] {
        &self.peers
    }

    #[must_use]
    pub const fn interface_options(&self) -> WireGuardInterfaceOptions {
        self.interface_options
    }

    #[must_use]
    pub fn material_refs(&self) -> Vec<ProfileMaterialRef> {
        let mut refs = vec![ProfileMaterialRef::ProfileSlot {
            slot: self.private_key,
        }];
        refs.extend(self.peers.iter().filter_map(|peer| {
            peer.preshared_key
                .map(|key| ProfileMaterialRef::WireGuardPresharedKey {
                    peer_public_key: key.peer_public_key,
                })
        }));
        refs
    }
}

/// Fixed profile-owned material slots. During unprivileged parsing, embedded
/// material is normalized into storage keyed by `(profile_id, slot)`; the
/// helper resolves that key inside its fixed runtime root. No path or raw
/// material value crosses this contract. Per-peer `WireGuard` preshared keys
/// are additionally keyed by the typed peer public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileMaterialSlot {
    WireGuardPrivateKey,
    OpenVpnCaCertificate,
    OpenVpnClientCertificate,
    OpenVpnPrivateKey,
    OpenVpnTlsAuthKey,
    OpenVpnTlsCryptKey,
}

/// A material lookup that cannot lose per-peer identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProfileMaterialRef {
    ProfileSlot { slot: ProfileMaterialSlot },
    WireGuardPresharedKey { peer_public_key: [u8; 32] },
}

/// Identity of one descriptor accompanying a tunnel start request.
///
/// This type is derived locally from [`ProtocolPlan`] and intentionally has no
/// serde implementation. In particular, `OpenVpnCredentials` identifies a
/// one-shot secret channel; it never makes credential bytes part of the wire
/// plan or durable profile inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TunnelDescriptorRef {
    ProfileMaterial(ProfileMaterialRef),
    OpenVpnCredentials,
}

/// Bounded `WireGuard` interface options. `None` delegates to the platform
/// default; zero is never overloaded to mean "off" on this wire boundary.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(try_from = "WireGuardInterfaceOptionsWire")]
pub struct WireGuardInterfaceOptions {
    mtu: Option<u16>,
    listen_port: Option<u16>,
    fwmark: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireGuardInterfaceOptionsWire {
    mtu: Option<u16>,
    listen_port: Option<u16>,
    fwmark: Option<u32>,
}

impl TryFrom<WireGuardInterfaceOptionsWire> for WireGuardInterfaceOptions {
    type Error = ProtocolPlanError;

    fn try_from(wire: WireGuardInterfaceOptionsWire) -> Result<Self, Self::Error> {
        Self::new(wire.mtu, wire.listen_port, wire.fwmark)
    }
}

impl<'de> Deserialize<'de> for WireGuardInterfaceOptions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        WireGuardInterfaceOptionsWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

impl WireGuardInterfaceOptions {
    pub fn new(
        mtu: Option<u16>,
        listen_port: Option<u16>,
        fwmark: Option<u32>,
    ) -> Result<Self, ProtocolPlanError> {
        if matches!(mtu, Some(value) if value < 576) || listen_port == Some(0) || fwmark == Some(0)
        {
            return Err(ProtocolPlanError::InvalidInterfaceOptions);
        }
        Ok(Self {
            mtu,
            listen_port,
            fwmark,
        })
    }

    #[must_use]
    pub const fn mtu(self) -> Option<u16> {
        self.mtu
    }

    #[must_use]
    pub const fn listen_port(self) -> Option<u16> {
        self.listen_port
    }

    #[must_use]
    pub const fn fwmark(self) -> Option<u32> {
        self.fwmark
    }
}

/// Fixed material identity for one peer's preshared key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct WireGuardPresharedKeyRef {
    peer_public_key: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireGuardPresharedKeyRefWire {
    peer_public_key: [u8; 32],
}

impl<'de> Deserialize<'de> for WireGuardPresharedKeyRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = WireGuardPresharedKeyRefWire::deserialize(deserializer)?;
        Self::for_peer(wire.peer_public_key).map_err(serde::de::Error::custom)
    }
}

impl WireGuardPresharedKeyRef {
    pub fn for_peer(peer_public_key: [u8; 32]) -> Result<Self, ProtocolPlanError> {
        if peer_public_key == [0; 32] {
            Err(ProtocolPlanError::InvalidPublicKey)
        } else {
            Ok(Self { peer_public_key })
        }
    }

    #[must_use]
    pub const fn peer_public_key(self) -> [u8; 32] {
        self.peer_public_key
    }
}

/// One validated `WireGuard` peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(try_from = "WireGuardPeerPlanWire")]
pub struct WireGuardPeerPlan {
    public_key: [u8; 32],
    endpoint: Option<ProtocolEndpoint>,
    allowed_routes: Vec<Cidr>,
    persistent_keepalive_seconds: Option<u16>,
    preshared_key: Option<WireGuardPresharedKeyRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireGuardPeerPlanWire {
    public_key: [u8; 32],
    endpoint: Option<ProtocolEndpoint>,
    allowed_routes: BoundedVec<Cidr, MAX_ALLOWED_ROUTES>,
    persistent_keepalive_seconds: Option<u16>,
    preshared_key: Option<WireGuardPresharedKeyRef>,
}

impl TryFrom<WireGuardPeerPlanWire> for WireGuardPeerPlan {
    type Error = ProtocolPlanError;

    fn try_from(wire: WireGuardPeerPlanWire) -> Result<Self, Self::Error> {
        Self::validate(
            wire.public_key,
            wire.endpoint,
            wire.allowed_routes.into_vec(),
            wire.persistent_keepalive_seconds,
            wire.preshared_key,
        )
    }
}

impl<'de> Deserialize<'de> for WireGuardPeerPlan {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        WireGuardPeerPlanWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

impl WireGuardPeerPlan {
    pub fn new(
        public_key: [u8; 32],
        endpoint: Option<ProtocolEndpoint>,
        allowed_routes: Vec<Cidr>,
        persistent_keepalive_seconds: Option<u16>,
    ) -> Result<Self, ProtocolPlanError> {
        Self::validate(
            public_key,
            endpoint,
            allowed_routes,
            persistent_keepalive_seconds,
            None,
        )
    }

    pub fn with_preshared_key(
        public_key: [u8; 32],
        endpoint: Option<ProtocolEndpoint>,
        allowed_routes: Vec<Cidr>,
        persistent_keepalive_seconds: Option<u16>,
        preshared_key: WireGuardPresharedKeyRef,
    ) -> Result<Self, ProtocolPlanError> {
        Self::validate(
            public_key,
            endpoint,
            allowed_routes,
            persistent_keepalive_seconds,
            Some(preshared_key),
        )
    }

    fn validate(
        public_key: [u8; 32],
        endpoint: Option<ProtocolEndpoint>,
        allowed_routes: Vec<Cidr>,
        persistent_keepalive_seconds: Option<u16>,
        preshared_key: Option<WireGuardPresharedKeyRef>,
    ) -> Result<Self, ProtocolPlanError> {
        if public_key == [0; 32] {
            return Err(ProtocolPlanError::InvalidPublicKey);
        }
        if let Some(endpoint) = &endpoint {
            endpoint.validate()?;
        }
        validate_count(
            "WireGuard allowed route",
            allowed_routes.len(),
            0,
            MAX_ALLOWED_ROUTES,
        )?;
        if allowed_routes.iter().any(|cidr| !cidr.is_valid()) {
            return Err(ProtocolPlanError::InvalidCidr);
        }
        if persistent_keepalive_seconds == Some(0) {
            return Err(ProtocolPlanError::InvalidKeepalive);
        }
        if preshared_key.is_some_and(|key| key.peer_public_key != public_key) {
            return Err(ProtocolPlanError::PresharedKeyPeerMismatch);
        }
        Ok(Self {
            public_key,
            endpoint,
            allowed_routes,
            persistent_keepalive_seconds,
            preshared_key,
        })
    }

    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    #[must_use]
    pub const fn endpoint(&self) -> Option<&ProtocolEndpoint> {
        self.endpoint.as_ref()
    }

    #[must_use]
    pub fn allowed_routes(&self) -> &[Cidr] {
        &self.allowed_routes
    }

    #[must_use]
    pub const fn persistent_keepalive_seconds(&self) -> Option<u16> {
        self.persistent_keepalive_seconds
    }

    #[must_use]
    pub const fn preshared_key(&self) -> Option<WireGuardPresharedKeyRef> {
        self.preshared_key
    }
}

/// Canonical `OpenVPN` client plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(try_from = "OpenVpnPlanWire")]
pub struct OpenVpnPlan {
    profile_id: ProfileId,
    generation: u64,
    remotes: Vec<OpenVpnRemote>,
    remote_selection: OpenVpnRemoteSelection,
    authentication: OpenVpnAuthFactors,
    requested_routes: Vec<OpenVpnRoute>,
    #[serde(default, skip_serializing_if = "OpenVpnRouteDefaults::is_empty")]
    route_defaults: OpenVpnRouteDefaults,
    materials: BTreeSet<ProfileMaterialSlot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls_auth_direction: Option<OpenVpnKeyDirection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenVpnPlanWire {
    profile_id: ProfileId,
    generation: u64,
    remotes: BoundedVec<OpenVpnRemote, MAX_REMOTES>,
    remote_selection: OpenVpnRemoteSelection,
    authentication: OpenVpnAuthFactors,
    requested_routes: BoundedVec<OpenVpnRoute, MAX_ALLOWED_ROUTES>,
    #[serde(default)]
    route_defaults: OpenVpnRouteDefaults,
    materials: BoundedVec<ProfileMaterialSlot, 8>,
    #[serde(default)]
    tls_auth_direction: Option<OpenVpnKeyDirection>,
}

impl TryFrom<OpenVpnPlanWire> for OpenVpnPlan {
    type Error = ProtocolPlanError;

    fn try_from(wire: OpenVpnPlanWire) -> Result<Self, Self::Error> {
        let plan = Self::with_materials(
            wire.profile_id,
            wire.generation,
            wire.remotes.into_vec(),
            wire.remote_selection,
            wire.authentication,
            wire.requested_routes.into_vec(),
            wire.materials.into_vec().into_iter().collect(),
        )?;
        let plan = plan.with_route_defaults(wire.route_defaults);
        match wire.tls_auth_direction {
            Some(direction) => plan.with_tls_auth_direction(direction),
            None => Ok(plan),
        }
    }
}

impl<'de> Deserialize<'de> for OpenVpnPlan {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        OpenVpnPlanWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

impl OpenVpnPlan {
    pub fn new(
        profile_id: ProfileId,
        generation: u64,
        remotes: Vec<OpenVpnRemote>,
        remote_selection: OpenVpnRemoteSelection,
        authentication: OpenVpnAuthFactors,
        requested_routes: Vec<OpenVpnRoute>,
    ) -> Result<Self, ProtocolPlanError> {
        let materials = authentication.required_materials();
        Self::with_materials(
            profile_id,
            generation,
            remotes,
            remote_selection,
            authentication,
            requested_routes,
            materials,
        )
    }

    pub fn with_materials(
        profile_id: ProfileId,
        generation: u64,
        remotes: Vec<OpenVpnRemote>,
        remote_selection: OpenVpnRemoteSelection,
        authentication: OpenVpnAuthFactors,
        requested_routes: Vec<OpenVpnRoute>,
        materials: BTreeSet<ProfileMaterialSlot>,
    ) -> Result<Self, ProtocolPlanError> {
        if generation == 0 {
            return Err(ProtocolPlanError::InvalidGeneration);
        }
        validate_count("OpenVPN remote", remotes.len(), 1, MAX_REMOTES)?;
        validate_count(
            "OpenVPN requested route",
            requested_routes.len(),
            0,
            MAX_ALLOWED_ROUTES,
        )?;
        let required = authentication.required_materials();
        if !required.iter().all(|slot| materials.contains(slot))
            || materials.contains(&ProfileMaterialSlot::OpenVpnClientCertificate)
                != authentication.client_certificate
            || materials.contains(&ProfileMaterialSlot::OpenVpnPrivateKey)
                != authentication.client_certificate
            || materials.contains(&ProfileMaterialSlot::WireGuardPrivateKey)
            || (materials.contains(&ProfileMaterialSlot::OpenVpnTlsAuthKey)
                && materials.contains(&ProfileMaterialSlot::OpenVpnTlsCryptKey))
        {
            return Err(ProtocolPlanError::InvalidMaterialSlots);
        }
        Ok(Self {
            profile_id,
            generation,
            remotes,
            remote_selection,
            authentication,
            requested_routes,
            route_defaults: OpenVpnRouteDefaults::default(),
            materials,
            tls_auth_direction: None,
        })
    }

    pub fn with_tls_auth_direction(
        mut self,
        direction: OpenVpnKeyDirection,
    ) -> Result<Self, ProtocolPlanError> {
        if !self
            .materials
            .contains(&ProfileMaterialSlot::OpenVpnTlsAuthKey)
        {
            return Err(ProtocolPlanError::InvalidMaterialSlots);
        }
        self.tls_auth_direction = Some(direction);
        Ok(self)
    }

    #[must_use]
    pub const fn with_route_defaults(mut self, route_defaults: OpenVpnRouteDefaults) -> Self {
        self.route_defaults = route_defaults;
        self
    }

    #[must_use]
    pub fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn remotes(&self) -> &[OpenVpnRemote] {
        &self.remotes
    }

    #[must_use]
    pub const fn remote_selection(&self) -> OpenVpnRemoteSelection {
        self.remote_selection
    }

    #[must_use]
    pub const fn authentication(&self) -> OpenVpnAuthFactors {
        self.authentication
    }

    #[must_use]
    pub fn requested_routes(&self) -> &[OpenVpnRoute] {
        &self.requested_routes
    }

    #[must_use]
    pub const fn route_defaults(&self) -> OpenVpnRouteDefaults {
        self.route_defaults
    }

    #[must_use]
    pub const fn materials(&self) -> &BTreeSet<ProfileMaterialSlot> {
        &self.materials
    }

    #[must_use]
    pub const fn tls_auth_direction(&self) -> Option<OpenVpnKeyDirection> {
        self.tls_auth_direction
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenVpnRemote {
    endpoint: ProtocolEndpoint,
    transport: OpenVpnTransport,
}

impl OpenVpnRemote {
    pub fn new(
        endpoint: SocketAddr,
        transport: OpenVpnTransport,
    ) -> Result<Self, ProtocolPlanError> {
        Self::with_endpoint(ProtocolEndpoint::ip(endpoint)?, transport)
    }

    pub fn with_endpoint(
        endpoint: ProtocolEndpoint,
        transport: OpenVpnTransport,
    ) -> Result<Self, ProtocolPlanError> {
        endpoint.validate()?;
        Ok(Self {
            endpoint,
            transport,
        })
    }

    pub fn dns(
        hostname: impl AsRef<str>,
        port: u16,
        transport: OpenVpnTransport,
    ) -> Result<Self, ProtocolPlanError> {
        Self::with_endpoint(ProtocolEndpoint::dns(hostname, port)?, transport)
    }

    #[must_use]
    pub const fn endpoint(&self) -> &ProtocolEndpoint {
        &self.endpoint
    }

    #[must_use]
    pub const fn transport(&self) -> OpenVpnTransport {
        self.transport
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenVpnTransport {
    Udp,
    Tcp,
}

/// Optional direction paired with an `OpenVPN` `tls-auth` key. The numeric
/// values are protocol vocabulary, not caller-controlled argv.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenVpnKeyDirection {
    Zero,
    One,
}

impl OpenVpnKeyDirection {
    #[must_use]
    pub const fn as_openvpn_value(self) -> &'static str {
        match self {
            Self::Zero => "0",
            Self::One => "1",
        }
    }
}

/// Whether remotes are tried in profile order or randomized first, preserving
/// the `remote-random` semantic without losing each remote's transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenVpnRemoteSelection {
    Ordered,
    Randomized,
}

/// Supported challenge mechanisms. Challenge answers remain in the
/// memory-only credential channel and are not material references.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenVpnChallengeKind {
    Static,
    Remote,
}

/// Independent `OpenVPN` authentication factors. Certificate/key and
/// username/password may be combined; either challenge kind is valid only
/// alongside username/password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct OpenVpnAuthFactors {
    client_certificate: bool,
    username_password: bool,
    challenge: Option<OpenVpnChallengeKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenVpnAuthFactorsWire {
    client_certificate: bool,
    username_password: bool,
    challenge: Option<OpenVpnChallengeKind>,
}

impl<'de> Deserialize<'de> for OpenVpnAuthFactors {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = OpenVpnAuthFactorsWire::deserialize(deserializer)?;
        Self::new(
            wire.client_certificate,
            wire.username_password,
            wire.challenge,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl OpenVpnAuthFactors {
    pub const fn new(
        client_certificate: bool,
        username_password: bool,
        challenge: Option<OpenVpnChallengeKind>,
    ) -> Result<Self, ProtocolPlanError> {
        if !username_password && (!client_certificate || challenge.is_some()) {
            return Err(ProtocolPlanError::InvalidAuthentication);
        }
        Ok(Self {
            client_certificate,
            username_password,
            challenge,
        })
    }

    #[must_use]
    pub const fn certificate() -> Self {
        Self {
            client_certificate: true,
            username_password: false,
            challenge: None,
        }
    }

    #[must_use]
    pub const fn username_password() -> Self {
        Self {
            client_certificate: false,
            username_password: true,
            challenge: None,
        }
    }

    #[must_use]
    pub const fn certificate_and_username_password() -> Self {
        Self {
            client_certificate: true,
            username_password: true,
            challenge: None,
        }
    }

    pub const fn with_challenge(
        self,
        challenge: OpenVpnChallengeKind,
    ) -> Result<Self, ProtocolPlanError> {
        Self::new(
            self.client_certificate,
            self.username_password,
            Some(challenge),
        )
    }

    #[must_use]
    pub const fn uses_username_password(self) -> bool {
        self.username_password
    }

    #[must_use]
    pub const fn challenge(self) -> Option<OpenVpnChallengeKind> {
        self.challenge
    }

    fn required_materials(self) -> BTreeSet<ProfileMaterialSlot> {
        let mut materials = BTreeSet::from([ProfileMaterialSlot::OpenVpnCaCertificate]);
        if self.client_certificate {
            materials.insert(ProfileMaterialSlot::OpenVpnClientCertificate);
            materials.insert(ProfileMaterialSlot::OpenVpnPrivateKey);
        }
        materials
    }
}

/// Gateway semantics carried by one `OpenVPN` route directive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenVpnRouteGateway {
    /// The gateway assigned by the VPN server (`default`/`vpn_gateway`).
    VpnDefault,
    /// The pre-tunnel system gateway (`net_gateway`).
    NetGateway,
    /// The resolved remote-server gateway (`remote_host`).
    RemoteHost,
    /// One explicit gateway address.
    Address(IpAddr),
}

/// One explicit IPv4 `route-gateway` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenVpnDefaultGateway {
    /// A literal gateway address. Hostname resolution stays outside the helper
    /// contract because it cannot be authenticated as route truth.
    Address(IpAddr),
    /// Obtain the IPv4 gateway from the `OpenVPN` TAP DHCP negotiation.
    Dhcp,
}

/// Reviewed default gateway directives for one configured or pushed origin.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct OpenVpnDefaultGateways {
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv4: Option<OpenVpnDefaultGateway>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv6: Option<Ipv6Addr>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenVpnDefaultGatewaysWire {
    #[serde(default)]
    ipv4: Option<OpenVpnDefaultGateway>,
    #[serde(default)]
    ipv6: Option<Ipv6Addr>,
}

impl<'de> Deserialize<'de> for OpenVpnDefaultGateways {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = OpenVpnDefaultGatewaysWire::deserialize(deserializer)?;
        Self::new(wire.ipv4, wire.ipv6).map_err(serde::de::Error::custom)
    }
}

impl OpenVpnDefaultGateways {
    pub fn new(
        ipv4: Option<OpenVpnDefaultGateway>,
        ipv6: Option<Ipv6Addr>,
    ) -> Result<Self, ProtocolPlanError> {
        if matches!(ipv4, Some(OpenVpnDefaultGateway::Address(address)) if {
            !address.is_ipv4() || invalid_unicast_ip(&address)
        }) || ipv6.is_some_and(|address| invalid_unicast_ip(&IpAddr::V6(address)))
        {
            return Err(ProtocolPlanError::InvalidRouteGateway);
        }
        Ok(Self { ipv4, ipv6 })
    }

    #[must_use]
    pub const fn ipv4(self) -> Option<OpenVpnDefaultGateway> {
        self.ipv4
    }

    #[must_use]
    pub const fn ipv6(self) -> Option<Ipv6Addr> {
        self.ipv6
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.ipv4.is_none() && self.ipv6.is_none()
    }
}

/// Default gateway and metric values applied to `OpenVPN` routes that omit
/// an explicit value.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenVpnRouteDefaults {
    #[serde(default, skip_serializing_if = "OpenVpnDefaultGateways::is_empty")]
    gateways: OpenVpnDefaultGateways,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metric: Option<u32>,
}

impl OpenVpnRouteDefaults {
    #[must_use]
    pub const fn new(gateways: OpenVpnDefaultGateways, metric: Option<u32>) -> Self {
        Self { gateways, metric }
    }

    #[must_use]
    pub const fn gateways(self) -> OpenVpnDefaultGateways {
        self.gateways
    }

    #[must_use]
    pub const fn metric(self) -> Option<u32> {
        self.metric
    }

    #[must_use]
    pub fn merged(configured: Self, pushed: Self) -> Self {
        let configured_gateways = configured.gateways();
        let pushed_gateways = pushed.gateways();
        let gateways = OpenVpnDefaultGateways::new(
            pushed_gateways.ipv4().or(configured_gateways.ipv4()),
            pushed_gateways.ipv6().or(configured_gateways.ipv6()),
        )
        .expect("merging validated gateway families remains valid");
        Self::new(gateways, pushed.metric().or(configured.metric()))
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.gateways.is_empty() && self.metric.is_none()
    }
}

/// One reviewed `redirect-gateway` flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenVpnRedirectFlag {
    Local,
    AutoLocal,
    Def1,
    BypassDhcp,
    BypassDns,
    BlockLocal,
    Ipv6,
    DisableIpv4,
}

/// Exact reviewed flags from one `redirect-gateway` directive.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OpenVpnRedirectGateway(BTreeSet<OpenVpnRedirectFlag>);

impl OpenVpnRedirectGateway {
    pub fn new(flags: Vec<OpenVpnRedirectFlag>) -> Result<Self, ProtocolPlanError> {
        let count = flags.len();
        let flags = flags.into_iter().collect::<BTreeSet<_>>();
        if flags.len() != count {
            return Err(ProtocolPlanError::InvalidRouteGateway);
        }
        Ok(Self(flags))
    }

    #[must_use]
    pub fn flags(&self) -> &BTreeSet<OpenVpnRedirectFlag> {
        &self.0
    }

    #[must_use]
    pub fn ipv4(&self) -> bool {
        !self.0.contains(&OpenVpnRedirectFlag::DisableIpv4)
    }

    #[must_use]
    pub fn ipv6(&self) -> bool {
        self.0.contains(&OpenVpnRedirectFlag::Ipv6)
    }
}

/// One bounded `OpenVPN` route directive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct OpenVpnRoute {
    destination: Cidr,
    gateway: OpenVpnRouteGateway,
    metric: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenVpnRouteWire {
    destination: Cidr,
    gateway: OpenVpnRouteGatewayWire,
    metric: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
enum OpenVpnRouteGatewayWire {
    Current(OpenVpnRouteGateway),
    Legacy(Option<IpAddr>),
}

impl<'de> Deserialize<'de> for OpenVpnRoute {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = OpenVpnRouteWire::deserialize(deserializer)?;
        let gateway = match wire.gateway {
            OpenVpnRouteGatewayWire::Current(gateway) => gateway,
            OpenVpnRouteGatewayWire::Legacy(gateway) => gateway.map_or(
                OpenVpnRouteGateway::VpnDefault,
                OpenVpnRouteGateway::Address,
            ),
        };
        Self::with_gateway(wire.destination, gateway, wire.metric).map_err(serde::de::Error::custom)
    }
}

impl OpenVpnRoute {
    pub fn new(
        destination: Cidr,
        gateway: Option<IpAddr>,
        metric: Option<u32>,
    ) -> Result<Self, ProtocolPlanError> {
        Self::with_gateway(
            destination,
            gateway.map_or(
                OpenVpnRouteGateway::VpnDefault,
                OpenVpnRouteGateway::Address,
            ),
            metric,
        )
    }

    pub fn with_gateway(
        destination: Cidr,
        gateway: OpenVpnRouteGateway,
        metric: Option<u32>,
    ) -> Result<Self, ProtocolPlanError> {
        if !destination.is_valid()
            || matches!(gateway, OpenVpnRouteGateway::Address(address) if {
                invalid_unicast_ip(&address) || address.is_ipv4() != destination.addr.is_ipv4()
            })
        {
            if !destination.is_valid() {
                return Err(ProtocolPlanError::InvalidCidr);
            }
            return Err(ProtocolPlanError::InvalidRouteGateway);
        }
        Ok(Self {
            destination,
            gateway,
            metric,
        })
    }

    #[must_use]
    pub const fn destination(self) -> Cidr {
        self.destination
    }

    #[must_use]
    pub const fn gateway(self) -> OpenVpnRouteGateway {
        self.gateway
    }

    #[must_use]
    pub const fn metric(self) -> Option<u32> {
        self.metric
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolPlanError {
    #[error("protocol plan generation must be non-zero")]
    InvalidGeneration,
    #[error("{field} count {actual} is outside {min}..={max}")]
    InvalidCount {
        field: &'static str,
        actual: usize,
        min: usize,
        max: usize,
    },
    #[error("protocol endpoint must be a concrete unicast address and non-zero port")]
    InvalidEndpoint,
    #[error("DNS hostname is not a bounded ASCII hostname")]
    InvalidHostname,
    #[error("WireGuard public key must not be all zeroes")]
    InvalidPublicKey,
    #[error("WireGuard peer public keys must be unique within a plan")]
    DuplicatePublicKey,
    #[error("WireGuard keepalive must be non-zero when configured")]
    InvalidKeepalive,
    #[error("WireGuard interface options are outside the supported bounds")]
    InvalidInterfaceOptions,
    #[error("WireGuard preshared-key identity does not match its peer public key")]
    PresharedKeyPeerMismatch,
    #[error("OpenVPN requires at least one authentication factor and challenges require username/password")]
    InvalidAuthentication,
    #[error("OpenVPN route gateway must be a same-family unicast address")]
    InvalidRouteGateway,
    #[error("protocol material slots are incomplete or incompatible")]
    InvalidMaterialSlots,
    #[error("CIDR prefix exceeds its address-family width")]
    InvalidCidr,
}

fn validate_count(
    field: &'static str,
    actual: usize,
    min: usize,
    max: usize,
) -> Result<(), ProtocolPlanError> {
    if (min..=max).contains(&actual) {
        Ok(())
    } else {
        Err(ProtocolPlanError::InvalidCount {
            field,
            actual,
            min,
            max,
        })
    }
}

fn validate_socket_addr(endpoint: SocketAddr) -> Result<(), ProtocolPlanError> {
    if endpoint.port() == 0 || invalid_unicast_ip(&endpoint.ip()) {
        Err(ProtocolPlanError::InvalidEndpoint)
    } else {
        Ok(())
    }
}
