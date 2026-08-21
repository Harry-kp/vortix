//! Strict, versioned daemon-to-helper wire vocabulary.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::vortix_core::control::AuthorityEpoch;
use crate::vortix_core::ipc::frame::{decode_frame_bounded, encode_frame_bounded};
use crate::vortix_core::ipc::{CompatibilityRange, FrameError};
use crate::vortix_core::privileged::{
    has_duplicates, released_identity_set_is_invalid, AuthorityBinding, BoundedVec, HelperEpoch,
    HelperResourceState, LeaseId, PolicyDigest, PolicyPhase, PolicyPredecessor,
    PrivilegedOperation, PrivilegedRequest, RequestSequence, ResourceKind, ResourceTag,
    ServiceInstanceClaim, MAX_RESOURCE_ITEMS,
};

pub const HELPER_PROTOCOL_MIN: u16 = 1;
pub const HELPER_PROTOCOL_MAX: u16 = 1;
pub const HELPER_SCHEMA_MIN: u16 = 3;
pub const HELPER_SCHEMA_MAX: u16 = 13;
pub(crate) const MANAGED_OBSERVATION_SCHEMA_MIN: u16 = 5;
pub(crate) const FIREWALL_BASELINE_SCHEMA_MIN: u16 = 7;
pub(crate) const EXACT_RELEASE_SCHEMA_MIN: u16 = 8;
pub(crate) const POLICY_AUDIT_SCHEMA_MIN: u16 = 9;
pub(crate) const RELEASE_ACK_SCHEMA_MIN: u16 = 10;
pub(crate) const OPENVPN_GATEWAY_EVIDENCE_SCHEMA_MIN: u16 = 13;
pub const MAX_HELPER_FRAME_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperCapability {
    Handshake,
    Observe,
    TunnelLifecycle,
    NetworkPolicy,
    CleanupOwned,
}

pub const CONTRACT_CAPABILITIES: [HelperCapability; 5] = [
    HelperCapability::Handshake,
    HelperCapability::Observe,
    HelperCapability::TunnelLifecycle,
    HelperCapability::NetworkPolicy,
    HelperCapability::CleanupOwned,
];

pub const STAGED_CAPABILITIES: [HelperCapability; 1] = [HelperCapability::Handshake];

pub(crate) const fn capability_for_operation(operation: &PrivilegedOperation) -> HelperCapability {
    operation_contract(operation).0
}

pub(crate) fn minimum_schema_for_operation(operation: &PrivilegedOperation) -> u16 {
    match operation {
        PrivilegedOperation::StartTunnel(
            crate::vortix_core::privileged::ProtocolPlan::OpenVpn(_),
        ) => OPENVPN_GATEWAY_EVIDENCE_SCHEMA_MIN,
        PrivilegedOperation::ObserveManaged(targets)
            if targets.iter().any(|target| {
                target.protocol() == Some(crate::vortix_core::profile::ProtocolKind::OpenVpn)
            }) =>
        {
            OPENVPN_GATEWAY_EVIDENCE_SCHEMA_MIN
        }
        PrivilegedOperation::NetworkPolicy(
            crate::vortix_core::privileged::NetworkPolicyOperation::ApplyRoutes {
                routes,
                redirects,
                ..
            },
        ) if !redirects.is_empty()
            || routes.iter().any(|route| {
                route.origin() != crate::vortix_core::privileged::ScopedRouteOrigin::WireGuard
            }) =>
        {
            OPENVPN_GATEWAY_EVIDENCE_SCHEMA_MIN
        }
        _ => operation_contract(operation).1,
    }
}

const fn operation_contract(operation: &PrivilegedOperation) -> (HelperCapability, u16) {
    match operation {
        PrivilegedOperation::StartTunnel(_) | PrivilegedOperation::StopTunnel(_) => {
            (HelperCapability::TunnelLifecycle, HELPER_SCHEMA_MIN)
        }
        PrivilegedOperation::NetworkPolicy(
            crate::vortix_core::privileged::NetworkPolicyOperation::ReleaseObsolete {
                retained_state: crate::vortix_core::privileged::ObservationState::Absent,
                ..
            },
        ) => (HelperCapability::NetworkPolicy, EXACT_RELEASE_SCHEMA_MIN),
        PrivilegedOperation::NetworkPolicy(
            crate::vortix_core::privileged::NetworkPolicyOperation::EstablishFirewall { .. },
        ) => (
            HelperCapability::NetworkPolicy,
            FIREWALL_BASELINE_SCHEMA_MIN,
        ),
        PrivilegedOperation::NetworkPolicy(_) => {
            (HelperCapability::NetworkPolicy, HELPER_SCHEMA_MIN)
        }
        PrivilegedOperation::Observe(_) => (HelperCapability::Observe, HELPER_SCHEMA_MIN),
        PrivilegedOperation::ObserveManaged(_) => {
            (HelperCapability::Observe, MANAGED_OBSERVATION_SCHEMA_MIN)
        }
        PrivilegedOperation::ObserveManagedAbsence(_) => {
            (HelperCapability::Observe, EXACT_RELEASE_SCHEMA_MIN)
        }
        PrivilegedOperation::AcknowledgeReleased(_) => {
            (HelperCapability::Observe, RELEASE_ACK_SCHEMA_MIN)
        }
        PrivilegedOperation::AuditPolicy(_) => {
            (HelperCapability::NetworkPolicy, POLICY_AUDIT_SCHEMA_MIN)
        }
        PrivilegedOperation::CleanupOwned(_) => (HelperCapability::CleanupOwned, HELPER_SCHEMA_MIN),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperClientHello {
    pub product: String,
    pub product_version: String,
    pub protocol: CompatibilityRange,
    pub schema: CompatibilityRange,
    pub required_capabilities: Vec<HelperCapability>,
    pub owner_uid: u32,
    pub service: ServiceInstanceClaim,
}

impl HelperClientHello {
    #[must_use]
    pub fn current(
        owner_uid: u32,
        service: ServiceInstanceClaim,
        required_capabilities: Vec<HelperCapability>,
    ) -> Self {
        Self {
            product: "vortix".into(),
            product_version: env!("CARGO_PKG_VERSION").into(),
            protocol: CompatibilityRange {
                min: HELPER_PROTOCOL_MIN,
                max: HELPER_PROTOCOL_MAX,
            },
            schema: CompatibilityRange {
                min: HELPER_SCHEMA_MIN,
                max: HELPER_SCHEMA_MAX,
            },
            required_capabilities,
            owner_uid,
            service,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperAuthorityMode {
    Staged,
    Candidate,
    Enrolled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperServerHello {
    pub product: String,
    pub product_version: String,
    pub protocol: u16,
    pub schema: u16,
    pub authority_mode: HelperAuthorityMode,
    pub contract_capabilities: Vec<HelperCapability>,
    pub enabled_capabilities: Vec<HelperCapability>,
    pub session: Option<HelperSessionBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_inventory: Option<Box<HelperPolicyInventory>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_resources: Option<Box<HelperReleasedInventory>>,
}

/// Exact released tunnel identities retained by the root ledger. The daemon
/// uses this authenticated inventory to resume acknowledgement after a crash;
/// it is not live kernel evidence by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HelperReleasedInventory {
    resources: Vec<ResourceTag>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperReleasedInventoryWire {
    resources: BoundedVec<ResourceTag, MAX_RESOURCE_ITEMS>,
}

impl<'de> Deserialize<'de> for HelperReleasedInventory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = HelperReleasedInventoryWire::deserialize(deserializer)?;
        Self::new(wire.resources.into_vec()).map_err(serde::de::Error::custom)
    }
}

impl HelperReleasedInventory {
    pub(crate) fn new(resources: Vec<ResourceTag>) -> Result<Self, &'static str> {
        if resources.len() > MAX_RESOURCE_ITEMS
            || released_identity_set_is_invalid(&resources)
            || resources
                .iter()
                .any(|resource| resource.authority_epoch().is_some())
        {
            return Err("invalid released helper inventory");
        }
        Ok(Self { resources })
    }

    #[must_use]
    pub(crate) fn resources(&self) -> &[ResourceTag] {
        &self.resources
    }
}

/// Authenticated root-ledger policy state returned only by an enrolled
/// schema-6 helper. Projection digests let the daemon resume or compensate an
/// exact helper generation without exposing policy contents in the handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HelperPolicyInventory {
    current: Option<ResourceTag>,
    predecessor: Option<PolicyPredecessor>,
    resources: Vec<HelperPolicyResource>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperPolicyInventoryWire {
    current: Option<ResourceTag>,
    predecessor: Option<PolicyPredecessor>,
    resources: BoundedVec<HelperPolicyResource, MAX_RESOURCE_ITEMS>,
}

impl<'de> Deserialize<'de> for HelperPolicyInventory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = HelperPolicyInventoryWire::deserialize(deserializer)?;
        Self::new(wire.current, wire.predecessor, wire.resources.into_vec())
            .map_err(serde::de::Error::custom)
    }
}

impl HelperPolicyInventory {
    pub(crate) fn new(
        current: Option<ResourceTag>,
        predecessor: Option<PolicyPredecessor>,
        resources: Vec<HelperPolicyResource>,
    ) -> Result<Self, &'static str> {
        if resources.len() > MAX_RESOURCE_ITEMS
            || has_duplicates(resources.iter().map(HelperPolicyResource::resource))
            || resources.iter().any(|resource| !resource.is_valid())
            || predecessor.is_some_and(|value| !value.is_valid())
        {
            return Err("invalid helper policy inventory");
        }
        match (&current, predecessor) {
            (None, None) if resources.is_empty() => {}
            (Some(current), Some(predecessor))
                if current.authority_epoch().is_some()
                    && phase_matches_kind(predecessor.phase(), current.kind())
                    && resources
                        .iter()
                        .find(|resource| &resource.resource == current)
                        .is_some_and(|resource| {
                            cursor_state_matches(predecessor, resource.state)
                        }) => {}
            _ => return Err("invalid helper policy inventory cursor"),
        }
        Ok(Self {
            current,
            predecessor,
            resources,
        })
    }

    pub(crate) fn matches_authority(&self, authority: AuthorityEpoch) -> bool {
        self.current
            .as_ref()
            .is_none_or(|resource| resource.authority_epoch() == Some(authority))
            && self
                .resources
                .iter()
                .all(|resource| resource.resource.authority_epoch() == Some(authority))
    }

    #[allow(
        dead_code,
        reason = "daemon policy adapter consumes the authenticated inventory"
    )]
    #[must_use]
    pub(crate) const fn current(&self) -> Option<&ResourceTag> {
        self.current.as_ref()
    }

    #[allow(
        dead_code,
        reason = "daemon policy adapter consumes the authenticated inventory"
    )]
    #[must_use]
    pub(crate) const fn predecessor(&self) -> Option<PolicyPredecessor> {
        self.predecessor
    }

    #[allow(
        dead_code,
        reason = "daemon policy adapter consumes the authenticated inventory"
    )]
    #[must_use]
    pub(crate) fn resources(&self) -> &[HelperPolicyResource] {
        &self.resources
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperPolicyResource {
    resource: ResourceTag,
    state: HelperResourceState,
    intended: PolicyDigest,
    effective: Option<PolicyDigest>,
}

impl HelperPolicyResource {
    pub(crate) fn new(
        resource: ResourceTag,
        state: HelperResourceState,
        intended: PolicyDigest,
        effective: Option<PolicyDigest>,
    ) -> Result<Self, &'static str> {
        let candidate = Self {
            resource,
            state,
            intended,
            effective,
        };
        candidate
            .is_valid()
            .then_some(candidate)
            .ok_or("invalid helper policy resource")
    }

    fn is_valid(&self) -> bool {
        let topology_resource = matches!(
            self.resource.kind(),
            ResourceKind::Firewall | ResourceKind::Dns | ResourceKind::Routes
        ) && self.resource.authority_epoch().is_some();
        let settled_has_effective = !matches!(
            self.state,
            HelperResourceState::Owned | HelperResourceState::PendingRelease
        ) || self.effective.is_some();
        topology_resource
            && !self.intended.is_zero()
            && self.effective.is_none_or(|digest| !digest.is_zero())
            && settled_has_effective
    }

    #[allow(
        dead_code,
        reason = "daemon policy adapter consumes the authenticated inventory"
    )]
    #[must_use]
    pub(crate) const fn resource(&self) -> &ResourceTag {
        &self.resource
    }

    #[allow(
        dead_code,
        reason = "daemon policy adapter consumes the authenticated inventory"
    )]
    #[must_use]
    pub(crate) const fn state(&self) -> HelperResourceState {
        self.state
    }

    #[allow(
        dead_code,
        reason = "daemon policy adapter consumes the authenticated inventory"
    )]
    #[must_use]
    pub(crate) const fn intended(&self) -> PolicyDigest {
        self.intended
    }

    #[allow(
        dead_code,
        reason = "daemon policy adapter consumes the authenticated inventory"
    )]
    #[must_use]
    pub(crate) const fn effective(&self) -> Option<PolicyDigest> {
        self.effective
    }
}

fn phase_matches_kind(phase: PolicyPhase, kind: ResourceKind) -> bool {
    match phase {
        PolicyPhase::FirewallBaseline | PolicyPhase::Blocking | PolicyPhase::Firewall => {
            kind == ResourceKind::Firewall
        }
        PolicyPhase::Routes => kind == ResourceKind::Routes,
        PolicyPhase::Dns => kind == ResourceKind::Dns,
        PolicyPhase::Released => matches!(
            kind,
            ResourceKind::Firewall | ResourceKind::Dns | ResourceKind::Routes
        ),
    }
}

fn cursor_state_matches(predecessor: PolicyPredecessor, state: HelperResourceState) -> bool {
    match (predecessor.observed(), predecessor.phase()) {
        (true, _) | (false, PolicyPhase::Released) => state == HelperResourceState::Owned,
        (false, _) => state == HelperResourceState::PendingEffect,
    }
}

/// Authenticated incarnation expected on every enrolled receipt. The daemon
/// still treats these scalars as untrusted until the peer socket and installed
/// helper identity have been verified by the platform boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HelperSessionBinding {
    V4(HelperSessionBindingV4),
    V3(HelperSessionBindingV3),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperSessionBindingV3 {
    authority_epoch: AuthorityEpoch,
    lease_id: LeaseId,
    helper_epoch: HelperEpoch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperSessionBindingV4 {
    authority: AuthorityBinding,
    helper_epoch: HelperEpoch,
    next_sequence: RequestSequence,
}

impl HelperSessionBinding {
    pub(crate) const fn v3(
        authority_epoch: AuthorityEpoch,
        lease_id: LeaseId,
        helper_epoch: HelperEpoch,
    ) -> Self {
        Self::V3(HelperSessionBindingV3 {
            authority_epoch,
            lease_id,
            helper_epoch,
        })
    }

    pub(crate) const fn v4(
        authority: AuthorityBinding,
        helper_epoch: HelperEpoch,
        next_sequence: RequestSequence,
    ) -> Self {
        Self::V4(HelperSessionBindingV4 {
            authority,
            helper_epoch,
            next_sequence,
        })
    }

    fn negotiated(
        schema: u16,
        authority: AuthorityBinding,
        helper_epoch: HelperEpoch,
        next_sequence: RequestSequence,
    ) -> Self {
        match schema {
            3 => Self::v3(
                authority.authority_epoch(),
                authority.lease_id(),
                helper_epoch,
            ),
            4..=HELPER_SCHEMA_MAX => Self::v4(authority, helper_epoch, next_sequence),
            _ => unreachable!("negotiation accepts only supported helper schemas"),
        }
    }

    #[must_use]
    pub const fn authority(self) -> Option<AuthorityBinding> {
        match self {
            Self::V4(binding) => Some(binding.authority),
            Self::V3(_) => None,
        }
    }

    #[must_use]
    pub const fn authority_epoch(self) -> AuthorityEpoch {
        match self {
            Self::V4(binding) => binding.authority.authority_epoch(),
            Self::V3(binding) => binding.authority_epoch,
        }
    }

    #[must_use]
    pub const fn lease_id(self) -> LeaseId {
        match self {
            Self::V4(binding) => binding.authority.lease_id(),
            Self::V3(binding) => binding.lease_id,
        }
    }

    #[must_use]
    pub const fn helper_epoch(self) -> HelperEpoch {
        match self {
            Self::V4(binding) => binding.helper_epoch,
            Self::V3(binding) => binding.helper_epoch,
        }
    }

    #[must_use]
    pub const fn next_sequence(self) -> Option<RequestSequence> {
        match self {
            Self::V4(binding) => Some(binding.next_sequence),
            Self::V3(_) => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[allow(
    clippy::large_enum_variant,
    reason = "the bounded handshake occurs once per connection; boxing it would add heap churn and mechanical caller complexity"
)]
pub enum HelperOp {
    Handshake(HelperClientHello),
    Execute(Box<PrivilegedRequest>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperRequest {
    pub id: u64,
    pub op: HelperOp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperResponse {
    pub id: u64,
    pub result: Result<HelperResult, HelperError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum HelperResult {
    Handshake(HelperServerHello),
    /// A receipt remains an untrusted JSON value until the daemon decodes it
    /// as `UntrustedReceipt` and authenticates every binding field.
    Receipt(serde_json::Value),
    Staged,
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
#[serde(tag = "code", content = "detail", rename_all = "snake_case")]
pub enum HelperError {
    #[error("incompatible helper peer: {reason}")]
    Incompatible { reason: String },
    #[error("helper capability is unavailable: {capability:?}")]
    CapabilityUnavailable { capability: HelperCapability },
    #[error("helper authority is staged but not enrolled")]
    NotEnrolled,
    #[error("malformed helper request: {reason}")]
    Malformed { reason: String },
    #[error("helper frame is too large: {size} > {max}")]
    FrameTooLarge { size: usize, max: usize },
    #[error("helper peer did not authenticate as the enrolled daemon")]
    AuthenticationFailed,
    #[error("root replay ledger is unavailable; helper session is fail-closed")]
    LedgerUnavailable,
}

/// Negotiate the installed-but-unenrolled U11 helper contract.
pub fn negotiate_staged(hello: &HelperClientHello) -> Result<HelperServerHello, HelperError> {
    negotiate_common(hello, &STAGED_CAPABILITIES)
}

#[allow(
    dead_code,
    reason = "U12 execution slice remains unreachable until U13 enrollment gates it"
)]
pub(crate) fn negotiate_enrolled(
    hello: &HelperClientHello,
    authority: AuthorityBinding,
    helper_epoch: HelperEpoch,
    next_sequence: RequestSequence,
    enabled_capabilities: &[HelperCapability],
) -> Result<HelperServerHello, HelperError> {
    let mut negotiated = negotiate_common(hello, enabled_capabilities)?;
    negotiated.authority_mode = HelperAuthorityMode::Enrolled;
    negotiated.session = Some(HelperSessionBinding::negotiated(
        negotiated.schema,
        authority,
        helper_epoch,
        next_sequence,
    ));
    Ok(negotiated)
}

pub(crate) fn negotiate_candidate(
    hello: &HelperClientHello,
    authority: AuthorityBinding,
    helper_epoch: HelperEpoch,
) -> Result<HelperServerHello, HelperError> {
    let mut negotiated = negotiate_common(hello, &STAGED_CAPABILITIES)?;
    negotiated.authority_mode = HelperAuthorityMode::Candidate;
    negotiated.session = Some(HelperSessionBinding::negotiated(
        negotiated.schema,
        authority,
        helper_epoch,
        RequestSequence::new(1).expect("one is a valid request sequence"),
    ));
    Ok(negotiated)
}

#[allow(
    dead_code,
    reason = "U12 execution slice remains unreachable until U13 enrollment gates it"
)]
fn negotiate_common(
    hello: &HelperClientHello,
    enabled_capabilities: &[HelperCapability],
) -> Result<HelperServerHello, HelperError> {
    if hello.product != "vortix"
        || hello.product_version.is_empty()
        || hello.product_version.len() > 64
        || hello.owner_uid == 0
        || enabled_capabilities.is_empty()
        || !enabled_capabilities.contains(&HelperCapability::Handshake)
        || enabled_capabilities
            .iter()
            .enumerate()
            .any(|(index, capability)| enabled_capabilities[..index].contains(capability))
        || enabled_capabilities
            .iter()
            .any(|capability| !CONTRACT_CAPABILITIES.contains(capability))
    {
        return Err(HelperError::Incompatible {
            reason: "invalid product, owner, or enabled capability set".into(),
        });
    }
    if hello.required_capabilities.len() > CONTRACT_CAPABILITIES.len()
        || hello
            .required_capabilities
            .iter()
            .enumerate()
            .any(|(index, capability)| hello.required_capabilities[..index].contains(capability))
    {
        return Err(HelperError::Incompatible {
            reason: "required capabilities must be unique and bounded".into(),
        });
    }
    if !hello.protocol.is_valid() || !hello.schema.is_valid() {
        return Err(HelperError::Incompatible {
            reason: "invalid compatibility range".into(),
        });
    }
    let protocol = hello
        .protocol
        .highest_common(CompatibilityRange {
            min: HELPER_PROTOCOL_MIN,
            max: HELPER_PROTOCOL_MAX,
        })
        .ok_or_else(|| HelperError::Incompatible {
            reason: "helper protocol ranges do not overlap".into(),
        })?;
    let schema = hello
        .schema
        .highest_common(CompatibilityRange {
            min: HELPER_SCHEMA_MIN,
            max: HELPER_SCHEMA_MAX,
        })
        .ok_or_else(|| HelperError::Incompatible {
            reason: "helper schema ranges do not overlap".into(),
        })?;
    for capability in &hello.required_capabilities {
        if !enabled_capabilities.contains(capability) {
            return Err(HelperError::CapabilityUnavailable {
                capability: *capability,
            });
        }
    }
    Ok(HelperServerHello {
        product: "vortix-helper".into(),
        product_version: env!("CARGO_PKG_VERSION").into(),
        protocol,
        schema,
        authority_mode: HelperAuthorityMode::Staged,
        contract_capabilities: CONTRACT_CAPABILITIES.to_vec(),
        enabled_capabilities: enabled_capabilities.to_vec(),
        session: None,
        policy_inventory: None,
        released_resources: None,
    })
}

/// Allocation-bound and strictly decode one helper request body.
pub fn parse_request(bytes: &[u8]) -> Result<HelperRequest, HelperError> {
    if bytes.len() > MAX_HELPER_FRAME_BYTES {
        return Err(HelperError::FrameTooLarge {
            size: bytes.len(),
            max: MAX_HELPER_FRAME_BYTES,
        });
    }
    serde_json::from_slice(bytes).map_err(|error| HelperError::Malformed {
        reason: error.to_string(),
    })
}

/// Encode one daemon-to-helper request with the helper-specific frame cap.
pub fn encode_request_frame(request: &HelperRequest) -> Result<Vec<u8>, FrameError> {
    encode_frame_bounded::<_, MAX_HELPER_FRAME_BYTES>(request)
}

/// Decode at most one daemon-to-helper frame without allocating its declared
/// body until the 256 KiB helper limit has been checked.
pub fn decode_request_frame(bytes: &[u8]) -> Result<Option<(HelperRequest, usize)>, FrameError> {
    decode_frame_bounded::<_, MAX_HELPER_FRAME_BYTES>(bytes)
}

/// Encode one helper-to-daemon response with the same symmetric bound.
pub fn encode_response_frame(response: &HelperResponse) -> Result<Vec<u8>, FrameError> {
    encode_frame_bounded::<_, MAX_HELPER_FRAME_BYTES>(response)
}

/// Decode at most one helper-to-daemon response frame under the helper cap.
pub fn decode_response_frame(bytes: &[u8]) -> Result<Option<(HelperResponse, usize)>, FrameError> {
    decode_frame_bounded::<_, MAX_HELPER_FRAME_BYTES>(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::control::AuthorityEpoch;
    use crate::vortix_core::privileged::{
        BootScope, LeaseId, OperationDigest, ServiceInstanceClaim,
    };
    use crate::vortix_core::profile::{ProfileId, ProtocolKind};

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum V3HelperCapability {
        Handshake,
        Observe,
        TunnelLifecycle,
        NetworkPolicy,
        CleanupOwned,
    }

    const V3_CONTRACT_CAPABILITIES: [V3HelperCapability; 5] = [
        V3HelperCapability::Handshake,
        V3HelperCapability::Observe,
        V3HelperCapability::TunnelLifecycle,
        V3HelperCapability::NetworkPolicy,
        V3HelperCapability::CleanupOwned,
    ];

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct V3ClientHello {
        product: String,
        product_version: String,
        protocol: CompatibilityRange,
        schema: CompatibilityRange,
        required_capabilities: Vec<V3HelperCapability>,
        owner_uid: u32,
        service: ServiceInstanceClaim,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct V3SessionBinding {
        authority_epoch: AuthorityEpoch,
        lease_id: LeaseId,
        helper_epoch: HelperEpoch,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct V3ServerHello {
        product: String,
        product_version: String,
        protocol: u16,
        schema: u16,
        authority_mode: HelperAuthorityMode,
        contract_capabilities: Vec<V3HelperCapability>,
        enabled_capabilities: Vec<V3HelperCapability>,
        session: Option<V3SessionBinding>,
    }

    fn service() -> ServiceInstanceClaim {
        ServiceInstanceClaim::systemd(42, 9, OperationDigest::of_bytes(b"daemon"), [7; 32]).unwrap()
    }

    fn authority() -> AuthorityBinding {
        AuthorityBinding::for_service(
            AuthorityEpoch(3),
            BootScope::new([4; 16]),
            LeaseId::new([5; 32]),
            &service(),
        )
        .unwrap()
    }

    #[test]
    fn new_daemon_hello_is_strictly_decodable_by_v3_helper() {
        let hello = HelperClientHello::current(501, service(), vec![HelperCapability::Handshake]);
        let encoded = serde_json::to_vec(&hello).unwrap();
        let legacy: V3ClientHello = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(legacy.schema, CompatibilityRange { min: 3, max: 13 });
        assert!(!serde_json::to_value(hello)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("expected_authority"));

        let old_response = V3ServerHello {
            product: "vortix-helper".into(),
            product_version: env!("CARGO_PKG_VERSION").into(),
            protocol: 1,
            schema: 3,
            authority_mode: HelperAuthorityMode::Enrolled,
            contract_capabilities: V3_CONTRACT_CAPABILITIES.to_vec(),
            enabled_capabilities: vec![V3HelperCapability::Handshake, V3HelperCapability::Observe],
            session: Some(V3SessionBinding {
                authority_epoch: AuthorityEpoch(3),
                lease_id: LeaseId::new([5; 32]),
                helper_epoch: HelperEpoch::new(8).unwrap(),
            }),
        };
        let current: HelperServerHello =
            serde_json::from_slice(&serde_json::to_vec(&old_response).unwrap()).unwrap();
        assert!(matches!(current.session, Some(HelperSessionBinding::V3(_))));
    }

    #[test]
    fn old_daemon_and_new_helper_negotiate_exact_v3_binding_before_commands() {
        let old = V3ClientHello {
            product: "vortix".into(),
            product_version: env!("CARGO_PKG_VERSION").into(),
            protocol: CompatibilityRange { min: 1, max: 1 },
            schema: CompatibilityRange { min: 3, max: 3 },
            required_capabilities: vec![V3HelperCapability::Handshake],
            owner_uid: 501,
            service: service(),
        };
        let current: HelperClientHello =
            serde_json::from_slice(&serde_json::to_vec(&old).unwrap()).unwrap();
        let response =
            negotiate_candidate(&current, authority(), HelperEpoch::new(8).unwrap()).unwrap();
        assert_eq!(response.schema, 3);
        assert!(matches!(
            response.session,
            Some(HelperSessionBinding::V3(_))
        ));
        let legacy: V3ServerHello =
            serde_json::from_slice(&serde_json::to_vec(&response).unwrap()).unwrap();
        let session = legacy.session.unwrap();
        assert_eq!(session.authority_epoch, AuthorityEpoch(3));
        assert_eq!(session.lease_id, LeaseId::new([5; 32]));
        assert_eq!(session.helper_epoch, HelperEpoch::new(8).unwrap());
    }

    #[test]
    fn new_peers_negotiate_v13_full_authority_and_replay_cursor() {
        let hello = HelperClientHello::current(501, service(), vec![HelperCapability::Handshake]);
        let response = negotiate_enrolled(
            &hello,
            authority(),
            HelperEpoch::new(9).unwrap(),
            RequestSequence::new(17).unwrap(),
            &STAGED_CAPABILITIES,
        )
        .unwrap();
        assert_eq!(response.schema, 13);
        let encoded = serde_json::to_vec(&response).unwrap();
        let decoded: HelperServerHello = serde_json::from_slice(&encoded).unwrap();
        let binding = decoded.session.unwrap();
        assert_eq!(binding.authority(), Some(authority()));
        assert_eq!(binding.helper_epoch(), HelperEpoch::new(9).unwrap());
        assert_eq!(
            binding.next_sequence(),
            Some(RequestSequence::new(17).unwrap())
        );
        assert!(decoded.policy_inventory.is_none());
    }

    #[test]
    fn exact_nonblocking_baseline_and_exact_release_have_distinct_schema_floors() {
        let policy = ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Firewall).unwrap();
        let baseline = PrivilegedOperation::NetworkPolicy(
            crate::vortix_core::privileged::NetworkPolicyOperation::EstablishFirewall {
                policy: policy.clone(),
                mode: crate::vortix_core::state::killswitch::KillSwitchMode::Off,
                tunnels: Vec::new(),
            },
        );
        let blocking = PrivilegedOperation::NetworkPolicy(
            crate::vortix_core::privileged::NetworkPolicyOperation::EstablishBlocking {
                policy,
                tunnels: Vec::new(),
            },
        );
        let release = PrivilegedOperation::NetworkPolicy(
            crate::vortix_core::privileged::NetworkPolicyOperation::ReleaseObsolete {
                policy: ResourceTag::topology(AuthorityEpoch(3), 2, ResourceKind::Firewall)
                    .unwrap(),
                resources: vec![ResourceTag::topology(
                    AuthorityEpoch(3),
                    1,
                    ResourceKind::Firewall,
                )
                .unwrap()],
                predecessor: crate::vortix_core::privileged::PolicyPredecessor::for_test(
                    crate::vortix_core::privileged::PolicyDigest::for_test(
                        OperationDigest::of_bytes(b"policy"),
                    ),
                    crate::vortix_core::privileged::PolicyPhase::Firewall,
                ),
                retained_state: crate::vortix_core::privileged::ObservationState::Absent,
            },
        );
        let legacy_release = PrivilegedOperation::NetworkPolicy(
            crate::vortix_core::privileged::NetworkPolicyOperation::ReleaseObsolete {
                policy: ResourceTag::topology(AuthorityEpoch(3), 2, ResourceKind::Firewall)
                    .unwrap(),
                resources: vec![ResourceTag::topology(
                    AuthorityEpoch(3),
                    1,
                    ResourceKind::Firewall,
                )
                .unwrap()],
                predecessor: crate::vortix_core::privileged::PolicyPredecessor::for_test(
                    crate::vortix_core::privileged::PolicyDigest::for_test(
                        OperationDigest::of_bytes(b"legacy-policy"),
                    ),
                    crate::vortix_core::privileged::PolicyPhase::Firewall,
                ),
                retained_state: crate::vortix_core::privileged::ObservationState::Present,
            },
        );
        let audit = PrivilegedOperation::AuditPolicy(
            ResourceTag::topology(AuthorityEpoch(3), 2, ResourceKind::Routes).unwrap(),
        );

        assert_eq!(minimum_schema_for_operation(&baseline), 7);
        assert_eq!(minimum_schema_for_operation(&blocking), HELPER_SCHEMA_MIN);
        assert_eq!(minimum_schema_for_operation(&release), 8);
        assert_eq!(
            minimum_schema_for_operation(&legacy_release),
            HELPER_SCHEMA_MIN
        );
        assert_eq!(minimum_schema_for_operation(&audit), 9);
        let acknowledge = PrivilegedOperation::AcknowledgeReleased(vec![
            crate::vortix_core::privileged::ResourceObservationTarget::new(
                ResourceTag::tunnel(ProfileId::parse("a".repeat(64)).unwrap(), 1).unwrap(),
                Some(ProtocolKind::WireGuard),
            )
            .unwrap(),
        ]);
        assert_eq!(minimum_schema_for_operation(&acknowledge), 10);
        assert_eq!(HELPER_SCHEMA_MAX, 13);

        let PrivilegedOperation::NetworkPolicy(release) = release else {
            unreachable!();
        };
        let mut legacy_wire = serde_json::to_value(release).unwrap();
        legacy_wire
            .as_object_mut()
            .unwrap()
            .remove("retained_state");
        let decoded = serde_json::from_value::<
            crate::vortix_core::privileged::NetworkPolicyOperation,
        >(legacy_wire)
        .unwrap();
        assert!(matches!(
            decoded,
            crate::vortix_core::privileged::NetworkPolicyOperation::ReleaseObsolete {
                retained_state: crate::vortix_core::privileged::ObservationState::Present,
                ..
            }
        ));
    }

    #[test]
    fn semantic_openvpn_routes_require_schema_thirteen_without_narrowing_wireguard() {
        let route_policy =
            ResourceTag::topology(AuthorityEpoch(3), 2, ResourceKind::Routes).unwrap();
        let tunnel = ResourceTag::tunnel(ProfileId::parse("b".repeat(64)).unwrap(), 2).unwrap();
        let predecessor = crate::vortix_core::privileged::PolicyPredecessor::for_test(
            crate::vortix_core::privileged::PolicyDigest::for_test(OperationDigest::of_bytes(
                b"route-policy",
            )),
            crate::vortix_core::privileged::PolicyPhase::Blocking,
        );
        let legacy_wireguard_route = PrivilegedOperation::NetworkPolicy(
            crate::vortix_core::privileged::NetworkPolicyOperation::ApplyRoutes {
                policy: route_policy.clone(),
                routes: vec![crate::vortix_core::privileged::ScopedRoute::new(
                    "10.0.0.0/8".parse().unwrap(),
                    tunnel.clone(),
                )
                .unwrap()],
                redirects: Vec::new(),
                predecessor,
            },
        );
        let semantic_openvpn_route = PrivilegedOperation::NetworkPolicy(
            crate::vortix_core::privileged::NetworkPolicyOperation::ApplyRoutes {
                policy: route_policy,
                routes: vec![crate::vortix_core::privileged::ScopedRoute::openvpn(
                    crate::vortix_core::privileged::OpenVpnRoute::with_gateway(
                        "10.0.0.0/8".parse().unwrap(),
                        crate::vortix_core::privileged::OpenVpnRouteGateway::VpnDefault,
                        Some(7),
                    )
                    .unwrap(),
                    tunnel,
                    crate::vortix_core::privileged::ScopedRouteOrigin::OpenVpnPushed,
                    crate::vortix_core::privileged::OpenVpnRouteDefaults::default(),
                )
                .unwrap()],
                redirects: Vec::new(),
                predecessor,
            },
        );

        assert_eq!(
            minimum_schema_for_operation(&legacy_wireguard_route),
            HELPER_SCHEMA_MIN
        );
        assert_eq!(
            minimum_schema_for_operation(&semantic_openvpn_route),
            OPENVPN_GATEWAY_EVIDENCE_SCHEMA_MIN
        );
    }

    #[test]
    fn managed_openvpn_gateway_truth_requires_schema_thirteen() {
        let target = |seed: &str, protocol| {
            crate::vortix_core::privileged::ResourceObservationTarget::new(
                ResourceTag::tunnel(ProfileId::parse(seed.repeat(64)).unwrap(), 1).unwrap(),
                Some(protocol),
            )
            .unwrap()
        };
        let wireguard =
            PrivilegedOperation::ObserveManaged(vec![target("b", ProtocolKind::WireGuard)]);
        let openvpn = PrivilegedOperation::ObserveManaged(vec![target("c", ProtocolKind::OpenVpn)]);

        assert_eq!(
            minimum_schema_for_operation(&wireguard),
            MANAGED_OBSERVATION_SCHEMA_MIN
        );
        assert_eq!(
            minimum_schema_for_operation(&openvpn),
            OPENVPN_GATEWAY_EVIDENCE_SCHEMA_MIN
        );
    }

    #[test]
    fn policy_inventory_is_bounded_and_authority_scoped() {
        let firewall = ResourceTag::topology(AuthorityEpoch(3), 7, ResourceKind::Firewall).unwrap();
        let digest = PolicyDigest::for_test(OperationDigest::of_bytes(b"policy"));
        let predecessor = PolicyPredecessor::for_test(digest, PolicyPhase::Firewall);
        let record = HelperPolicyResource::new(
            firewall.clone(),
            HelperResourceState::Owned,
            digest,
            Some(digest),
        )
        .unwrap();
        let inventory =
            HelperPolicyInventory::new(Some(firewall.clone()), Some(predecessor), vec![record])
                .unwrap();
        assert!(inventory.matches_authority(AuthorityEpoch(3)));
        assert!(!inventory.matches_authority(AuthorityEpoch(4)));

        let mut encoded = serde_json::to_value(&inventory).unwrap();
        let resources = encoded["resources"].as_array_mut().unwrap();
        resources.extend((0..MAX_RESOURCE_ITEMS).map(|offset| {
            let generation = u64::try_from(offset).unwrap() + 8;
            let resource =
                ResourceTag::topology(AuthorityEpoch(3), generation, ResourceKind::Firewall)
                    .unwrap();
            serde_json::to_value(
                HelperPolicyResource::new(
                    resource,
                    HelperResourceState::Owned,
                    digest,
                    Some(digest),
                )
                .unwrap(),
            )
            .unwrap()
        }));
        assert!(serde_json::from_value::<HelperPolicyInventory>(encoded).is_err());
    }

    #[test]
    fn settled_policy_inventory_requires_effective_digest() {
        let firewall = ResourceTag::topology(AuthorityEpoch(3), 7, ResourceKind::Firewall).unwrap();
        let digest = PolicyDigest::for_test(OperationDigest::of_bytes(b"policy"));
        assert!(
            HelperPolicyResource::new(firewall, HelperResourceState::Owned, digest, None,).is_err()
        );
    }

    #[test]
    fn released_inventory_requires_a_closed_tunnel_identity_set() {
        let profile = ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap();
        let tunnel = ResourceTag::tunnel(profile.clone(), 4).unwrap();
        let group = ResourceTag::profile(profile, 4, ResourceKind::ProcessGroup).unwrap();
        let newer_tunnel = ResourceTag::tunnel(tunnel.profile_id().unwrap().clone(), 5).unwrap();

        assert!(HelperReleasedInventory::new(vec![group.clone()]).is_err());
        assert!(HelperReleasedInventory::new(vec![tunnel.clone(), group]).is_ok());
        assert!(HelperReleasedInventory::new(vec![tunnel.clone(), tunnel]).is_err());
        assert!(HelperReleasedInventory::new(vec![
            newer_tunnel,
            ResourceTag::tunnel(ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap(), 4,)
                .unwrap()
        ])
        .is_err());
    }

    #[test]
    fn policy_inventory_cursor_state_must_match_predecessor() {
        let firewall = ResourceTag::topology(AuthorityEpoch(3), 7, ResourceKind::Firewall).unwrap();
        let digest = PolicyDigest::for_test(OperationDigest::of_bytes(b"policy"));
        let predecessor = PolicyPredecessor::for_test(digest, PolicyPhase::Firewall);
        let record = HelperPolicyResource::new(
            firewall.clone(),
            HelperResourceState::Owned,
            digest,
            Some(digest),
        )
        .unwrap();
        let inventory =
            HelperPolicyInventory::new(Some(firewall), Some(predecessor), vec![record]).unwrap();

        let mut pending_resource = serde_json::to_value(&inventory).unwrap();
        pending_resource["resources"][0]["state"] = serde_json::json!("pending_effect");
        assert!(serde_json::from_value::<HelperPolicyInventory>(pending_resource).is_err());

        let mut unobserved_cursor = serde_json::to_value(&inventory).unwrap();
        unobserved_cursor["predecessor"]["observed"] = serde_json::json!(false);
        assert!(serde_json::from_value::<HelperPolicyInventory>(unobserved_cursor).is_err());

        let mut pending_effect = serde_json::to_value(&inventory).unwrap();
        pending_effect["predecessor"]["observed"] = serde_json::json!(false);
        pending_effect["resources"][0]["state"] = serde_json::json!("pending_effect");
        assert!(serde_json::from_value::<HelperPolicyInventory>(pending_effect).is_ok());

        let mut pending_release = serde_json::to_value(&inventory).unwrap();
        pending_release["predecessor"]["phase"] = serde_json::json!("released");
        pending_release["predecessor"]["observed"] = serde_json::json!(false);
        assert!(serde_json::from_value::<HelperPolicyInventory>(pending_release).is_ok());
    }
}
