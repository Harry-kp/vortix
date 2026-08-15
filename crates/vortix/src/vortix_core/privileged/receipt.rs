//! Strict untrusted receipt wire and authenticated helper-ledger receipts.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::control::AuthorityEpoch;
use crate::vortix_core::privileged::operation::{
    HelperEpoch, LeaseId, NetworkPolicyOperation, OperationDigest, PrivilegedOperation,
    PrivilegedOperationId, PrivilegedRequest, RequestSequence, RootAuthorityLedger,
    TrustedDaemonPrincipal,
};
use crate::vortix_core::privileged::resource::{
    ResourceKind, ResourceObservationTarget, ResourceTag,
};
use crate::vortix_core::privileged::{
    has_duplicates, BoundedVec, CONTRACT_SCHEMA_VERSION, MAX_RESOURCE_ITEMS,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmbiguousPhase {
    EffectMayHaveApplied,
    ReplyLost,
    HelperRestarted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionCode {
    StaleAuthority,
    Replay,
    InvalidResource,
    InvalidPlan,
    Overloaded,
    ExecutionFailed,
}

/// Root-ledger ownership fact. It is never accepted from deserialized wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResourceOwnership {
    resource: ResourceTag,
    authority_epoch: AuthorityEpoch,
    lease_id: LeaseId,
    acquired_sequence: RequestSequence,
}

impl ResourceOwnership {
    #[must_use]
    pub const fn resource(&self) -> &ResourceTag {
        &self.resource
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationState {
    Present,
    Absent,
    Drifted,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResourceObservation {
    resource: ResourceTag,
    state: ObservationState,
    observed_at_millis: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    wireguard_peers: Option<Vec<WireGuardPeerObservation>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceObservationWire {
    resource: ResourceTag,
    state: ObservationState,
    observed_at_millis: u64,
    #[serde(default)]
    wireguard_peers: Option<BoundedVec<WireGuardPeerObservation, MAX_RESOURCE_ITEMS>>,
}

impl<'de> Deserialize<'de> for ResourceObservation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ResourceObservationWire::deserialize(deserializer)?;
        Self::validate(
            wire.resource,
            wire.state,
            wire.observed_at_millis,
            wire.wireguard_peers.map(BoundedVec::into_vec),
        )
        .map_err(serde::de::Error::custom)
    }
}

impl ResourceObservation {
    pub fn new(
        resource: ResourceTag,
        state: ObservationState,
        observed_at_millis: u64,
    ) -> Result<Self, ReceiptError> {
        Self::validate(resource, state, observed_at_millis, None)
    }

    pub fn with_wireguard_peers(
        resource: ResourceTag,
        state: ObservationState,
        observed_at_millis: u64,
        peers: Vec<WireGuardPeerObservation>,
    ) -> Result<Self, ReceiptError> {
        Self::validate(resource, state, observed_at_millis, Some(peers))
    }

    fn validate(
        resource: ResourceTag,
        state: ObservationState,
        observed_at_millis: u64,
        wireguard_peers: Option<Vec<WireGuardPeerObservation>>,
    ) -> Result<Self, ReceiptError> {
        if observed_at_millis == 0 {
            return Err(ReceiptError::InvalidObservationTime);
        }
        if let Some(peers) = wireguard_peers.as_ref() {
            bounded(peers.len())?;
            let latest_allowed = observed_at_millis.saturating_add(5 * 60 * 1_000);
            if resource.kind() != ResourceKind::Tunnel
                || state != ObservationState::Present
                || has_duplicates(peers.iter().map(WireGuardPeerObservation::public_key_ref))
                || peers.iter().any(|peer| {
                    peer.latest_handshake_at_millis
                        .is_some_and(|handshake| handshake > latest_allowed)
                })
            {
                return Err(ReceiptError::InvalidPeerEvidence);
            }
        }
        Ok(Self {
            resource,
            state,
            observed_at_millis,
            wireguard_peers,
        })
    }

    #[must_use]
    pub const fn resource(&self) -> &ResourceTag {
        &self.resource
    }

    #[must_use]
    pub(crate) const fn state(&self) -> ObservationState {
        self.state
    }

    #[must_use]
    pub const fn observed_at_millis(&self) -> u64 {
        self.observed_at_millis
    }

    #[must_use]
    pub fn wireguard_peers(&self) -> Option<&[WireGuardPeerObservation]> {
        self.wireguard_peers.as_deref()
    }
}

/// One bounded, non-secret `wg show ... dump` peer fact authenticated by a
/// schema-5 managed observation receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WireGuardPeerObservation {
    public_key: [u8; 32],
    allowed_routes: Vec<Cidr>,
    latest_handshake_at_millis: Option<u64>,
    persistent_keepalive_seconds: Option<u16>,
    bytes_rx: u64,
    bytes_tx: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireGuardPeerObservationWire {
    public_key: [u8; 32],
    allowed_routes: BoundedVec<Cidr, MAX_RESOURCE_ITEMS>,
    latest_handshake_at_millis: Option<u64>,
    persistent_keepalive_seconds: Option<u16>,
    bytes_rx: u64,
    bytes_tx: u64,
}

impl<'de> Deserialize<'de> for WireGuardPeerObservation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = WireGuardPeerObservationWire::deserialize(deserializer)?;
        Self::new(
            wire.public_key,
            wire.allowed_routes.into_vec(),
            wire.latest_handshake_at_millis,
            wire.persistent_keepalive_seconds,
            wire.bytes_rx,
            wire.bytes_tx,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl WireGuardPeerObservation {
    pub fn new(
        public_key: [u8; 32],
        allowed_routes: Vec<Cidr>,
        latest_handshake_at_millis: Option<u64>,
        persistent_keepalive_seconds: Option<u16>,
        bytes_rx: u64,
        bytes_tx: u64,
    ) -> Result<Self, ReceiptError> {
        bounded(allowed_routes.len())?;
        if public_key == [0; 32]
            || latest_handshake_at_millis == Some(0)
            || persistent_keepalive_seconds == Some(0)
            || allowed_routes.iter().collect::<HashSet<_>>().len() != allowed_routes.len()
        {
            return Err(ReceiptError::InvalidPeerEvidence);
        }
        Ok(Self {
            public_key,
            allowed_routes,
            latest_handshake_at_millis,
            persistent_keepalive_seconds,
            bytes_rx,
            bytes_tx,
        })
    }

    const fn public_key_ref(&self) -> &[u8; 32] {
        &self.public_key
    }

    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    #[must_use]
    pub fn allowed_routes(&self) -> &[Cidr] {
        &self.allowed_routes
    }

    #[must_use]
    pub const fn latest_handshake_at_millis(&self) -> Option<u64> {
        self.latest_handshake_at_millis
    }

    #[must_use]
    pub const fn persistent_keepalive_seconds(&self) -> Option<u16> {
        self.persistent_keepalive_seconds
    }

    #[must_use]
    pub const fn bytes_rx(&self) -> u64 {
        self.bytes_rx
    }

    #[must_use]
    pub const fn bytes_tx(&self) -> u64 {
        self.bytes_tx
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", content = "detail", rename_all = "snake_case")]
pub enum ReceiptOutcome {
    Applied(Vec<ResourceOwnership>),
    Observed(Vec<ResourceObservation>),
    Rejected(RejectionCode),
    Ambiguous(AmbiguousPhase),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(
    tag = "outcome",
    content = "detail",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum UntrustedReceiptOutcome {
    Applied(BoundedVec<ResourceOwnershipWire, MAX_RESOURCE_ITEMS>),
    Observed(BoundedVec<ResourceObservation, MAX_RESOURCE_ITEMS>),
    Rejected(RejectionCode),
    Ambiguous(AmbiguousPhase),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceOwnershipWire {
    resource: ResourceTag,
    authority_epoch: AuthorityEpoch,
    lease_id: LeaseId,
    acquired_sequence: RequestSequence,
}

/// Strictly decoded but unauthenticated helper response. This type cannot be
/// used to commit policy or ownership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedReceipt {
    schema_version: u16,
    operation_id: PrivilegedOperationId,
    digest: OperationDigest,
    authority_epoch: AuthorityEpoch,
    helper_epoch: HelperEpoch,
    sequence: RequestSequence,
    outcome: UntrustedReceiptOutcome,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UntrustedReceiptWire {
    schema_version: u16,
    operation_id: PrivilegedOperationId,
    digest: OperationDigest,
    authority_epoch: AuthorityEpoch,
    helper_epoch: HelperEpoch,
    sequence: RequestSequence,
    outcome: UntrustedReceiptOutcome,
}

impl<'de> Deserialize<'de> for UntrustedReceipt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = UntrustedReceiptWire::deserialize(deserializer)?;
        if wire.schema_version != CONTRACT_SCHEMA_VERSION
            || wire.digest.as_bytes() == [0; 32]
            || wire.operation_id.authority_epoch() != wire.authority_epoch
            || wire.operation_id.sequence() != wire.sequence
        {
            return Err(serde::de::Error::custom("invalid privileged receipt wire"));
        }
        Ok(Self {
            schema_version: wire.schema_version,
            operation_id: wire.operation_id,
            digest: wire.digest,
            authority_epoch: wire.authority_epoch,
            helper_epoch: wire.helper_epoch,
            sequence: wire.sequence,
            outcome: wire.outcome,
        })
    }
}

/// Non-deserializable receipt authenticated by the root ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedReceipt {
    schema_version: u16,
    operation_id: PrivilegedOperationId,
    digest: OperationDigest,
    authority_epoch: AuthorityEpoch,
    helper_epoch: HelperEpoch,
    sequence: RequestSequence,
    outcome: ReceiptOutcome,
}

pub struct ReceiptLedger {
    authority_epoch: AuthorityEpoch,
    lease_id: LeaseId,
}

impl ReceiptLedger {
    pub fn new(
        root: &RootAuthorityLedger,
        principal: &TrustedDaemonPrincipal,
    ) -> Result<Self, ReceiptError> {
        if !root.matches_principal(principal) {
            return Err(ReceiptError::AuthorityMismatch);
        }
        Ok(Self {
            authority_epoch: root.authority_epoch(),
            lease_id: root.lease_id(),
        })
    }

    pub fn applied(
        &self,
        request: &PrivilegedRequest,
        resources: Vec<ResourceTag>,
    ) -> Result<VerifiedReceipt, ReceiptError> {
        self.validate_request(request)?;
        let ownership = resources
            .into_iter()
            .map(|resource| ResourceOwnership {
                resource,
                authority_epoch: self.authority_epoch,
                lease_id: self.lease_id,
                acquired_sequence: request.sequence(),
            })
            .collect();
        let receipt = VerifiedReceipt::new(request, ReceiptOutcome::Applied(ownership));
        receipt.validate_fields(request, self.authority_epoch, self.lease_id)?;
        Ok(receipt)
    }

    pub fn observed(
        &self,
        request: &PrivilegedRequest,
        resources: Vec<ResourceObservation>,
    ) -> Result<VerifiedReceipt, ReceiptError> {
        self.validate_request(request)?;
        let receipt = VerifiedReceipt::new(request, ReceiptOutcome::Observed(resources));
        receipt.validate_fields(request, self.authority_epoch, self.lease_id)?;
        Ok(receipt)
    }

    pub fn rejected(
        &self,
        request: &PrivilegedRequest,
        code: RejectionCode,
    ) -> Result<VerifiedReceipt, ReceiptError> {
        self.validate_request(request)?;
        Ok(VerifiedReceipt::new(
            request,
            ReceiptOutcome::Rejected(code),
        ))
    }

    pub fn ambiguous(
        &self,
        request: &PrivilegedRequest,
        phase: AmbiguousPhase,
    ) -> Result<VerifiedReceipt, ReceiptError> {
        self.validate_request(request)?;
        Ok(VerifiedReceipt::new(
            request,
            ReceiptOutcome::Ambiguous(phase),
        ))
    }
}

/// Daemon-side capability created only after U11 authenticates the helper
/// transport and binds it to one root-ledger lease and helper incarnation.
/// Merely decoding [`UntrustedReceipt`] never creates this capability.
#[allow(dead_code, reason = "U11 authenticated helper transport seam")]
pub(crate) struct AuthenticatedReceiptVerifier {
    authority_epoch: AuthorityEpoch,
    lease_id: LeaseId,
    helper_epoch: HelperEpoch,
}

#[allow(dead_code, reason = "U11 authenticated helper transport seam")]
impl AuthenticatedReceiptVerifier {
    pub(crate) const fn from_authenticated_helper(
        authority_epoch: AuthorityEpoch,
        lease_id: LeaseId,
        helper_epoch: HelperEpoch,
    ) -> Self {
        Self {
            authority_epoch,
            lease_id,
            helper_epoch,
        }
    }

    /// Authenticate a decoded wire response before it can affect state.
    pub(crate) fn verify(
        &self,
        request: &PrivilegedRequest,
        wire: UntrustedReceipt,
    ) -> Result<VerifiedReceipt, ReceiptError> {
        if request.authority_epoch() != self.authority_epoch
            || request.operation_id().lease_id() != self.lease_id
            || request.helper_epoch() != self.helper_epoch
        {
            return Err(ReceiptError::AuthorityMismatch);
        }
        if wire.schema_version != CONTRACT_SCHEMA_VERSION {
            return Err(ReceiptError::UnsupportedSchema);
        }
        let outcome = match wire.outcome {
            UntrustedReceiptOutcome::Applied(resources) => ReceiptOutcome::Applied(
                resources
                    .into_vec()
                    .into_iter()
                    .map(|resource| ResourceOwnership {
                        resource: resource.resource,
                        authority_epoch: resource.authority_epoch,
                        lease_id: resource.lease_id,
                        acquired_sequence: resource.acquired_sequence,
                    })
                    .collect(),
            ),
            UntrustedReceiptOutcome::Observed(resources) => {
                ReceiptOutcome::Observed(resources.into_vec())
            }
            UntrustedReceiptOutcome::Rejected(code) => ReceiptOutcome::Rejected(code),
            UntrustedReceiptOutcome::Ambiguous(phase) => ReceiptOutcome::Ambiguous(phase),
        };
        let verified = VerifiedReceipt {
            schema_version: wire.schema_version,
            operation_id: wire.operation_id,
            digest: wire.digest,
            authority_epoch: wire.authority_epoch,
            helper_epoch: wire.helper_epoch,
            sequence: wire.sequence,
            outcome,
        };
        verified.validate_fields(request, self.authority_epoch, self.lease_id)?;
        Ok(verified)
    }
}

impl ReceiptLedger {
    fn validate_request(&self, request: &PrivilegedRequest) -> Result<(), ReceiptError> {
        if request.authority_epoch() != self.authority_epoch
            || request.operation_id().lease_id() != self.lease_id
        {
            Err(ReceiptError::AuthorityMismatch)
        } else {
            Ok(())
        }
    }
}

impl VerifiedReceipt {
    fn new(request: &PrivilegedRequest, outcome: ReceiptOutcome) -> Self {
        Self {
            schema_version: CONTRACT_SCHEMA_VERSION,
            operation_id: request.operation_id().clone(),
            digest: *request.digest(),
            authority_epoch: request.authority_epoch(),
            helper_epoch: request.helper_epoch(),
            sequence: request.sequence(),
            outcome,
        }
    }

    pub fn validate_against(
        &self,
        request: &PrivilegedRequest,
        root: &RootAuthorityLedger,
    ) -> Result<(), ReceiptError> {
        self.validate_fields(request, root.authority_epoch(), root.lease_id())
    }

    fn validate_fields(
        &self,
        request: &PrivilegedRequest,
        authority_epoch: AuthorityEpoch,
        lease_id: LeaseId,
    ) -> Result<(), ReceiptError> {
        if self.schema_version != CONTRACT_SCHEMA_VERSION
            || self.operation_id != *request.operation_id()
            || self.digest != *request.digest()
            || self.authority_epoch != request.authority_epoch()
            || self.helper_epoch != request.helper_epoch()
            || self.sequence != request.sequence()
            || self.authority_epoch != authority_epoch
            || self.operation_id.lease_id() != lease_id
        {
            return Err(ReceiptError::AuthorityMismatch);
        }
        validate_outcome(
            request.operation(),
            &self.outcome,
            authority_epoch,
            lease_id,
            self.sequence,
        )
    }

    #[must_use]
    pub const fn operation_id(&self) -> &PrivilegedOperationId {
        &self.operation_id
    }

    #[must_use]
    pub const fn digest(&self) -> &OperationDigest {
        &self.digest
    }

    #[must_use]
    pub const fn is_ambiguous(&self) -> bool {
        matches!(self.outcome, ReceiptOutcome::Ambiguous(_))
    }

    #[cfg(test)]
    pub(crate) const fn is_rejected(&self) -> bool {
        matches!(self.outcome, ReceiptOutcome::Rejected(_))
    }

    pub(crate) fn observes(&self, resource: &ResourceTag, state: ObservationState) -> bool {
        matches!(&self.outcome, ReceiptOutcome::Observed(observations) if observations
            .iter().any(|observation| observation.resource == *resource && observation.state == state))
    }

    #[must_use]
    pub fn observation(&self, resource: &ResourceTag) -> Option<&ResourceObservation> {
        match &self.outcome {
            ReceiptOutcome::Observed(observations) => observations
                .iter()
                .find(|observation| observation.resource() == resource),
            ReceiptOutcome::Applied(_)
            | ReceiptOutcome::Rejected(_)
            | ReceiptOutcome::Ambiguous(_) => None,
        }
    }
}

fn validate_outcome(
    operation: &PrivilegedOperation,
    outcome: &ReceiptOutcome,
    authority: AuthorityEpoch,
    lease_id: LeaseId,
    sequence: RequestSequence,
) -> Result<(), ReceiptError> {
    match outcome {
        ReceiptOutcome::Rejected(_) | ReceiptOutcome::Ambiguous(_) => Ok(()),
        ReceiptOutcome::Applied(ownership) => {
            validate_applied(operation, ownership, authority, lease_id, sequence)
        }
        ReceiptOutcome::Observed(observations) => {
            bounded(observations.len())?;
            if observations.is_empty()
                || has_duplicates(observations.iter().map(ResourceObservation::resource))
                || observations.iter().any(|item| {
                    item.observed_at_millis == 0 || !operation.relates_to(&item.resource)
                })
            {
                return Err(ReceiptError::UnrelatedResource);
            }
            validate_observation_evidence(operation, observations)?;
            match operation {
                PrivilegedOperation::Observe(targets)
                | PrivilegedOperation::ObserveManaged(targets) => {
                    exact_target_observations(targets, observations)
                }
                PrivilegedOperation::StopTunnel(resource) => exact_observation_state(
                    std::slice::from_ref(resource),
                    observations,
                    ObservationState::Absent,
                ),
                PrivilegedOperation::CleanupOwned(resources) => {
                    exact_observation_state(resources, observations, ObservationState::Absent)
                }
                PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ObserveBarrier {
                    policy,
                    ..
                }) => exact_observations(std::slice::from_ref(policy), observations),
                PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ReleaseObsolete {
                    policy,
                    resources,
                    ..
                }) => {
                    if !observations.iter().any(|item| {
                        item.resource == *policy && item.state == ObservationState::Present
                    }) || resources.iter().any(|resource| {
                        !observations.iter().any(|item| {
                            item.resource == *resource && item.state == ObservationState::Absent
                        })
                    }) {
                        Err(ReceiptError::MissingRequiredResource)
                    } else {
                        Ok(())
                    }
                }
                _ => Err(ReceiptError::OutcomeMismatch),
            }
        }
    }
}

fn validate_observation_evidence(
    operation: &PrivilegedOperation,
    observations: &[ResourceObservation],
) -> Result<(), ReceiptError> {
    for observation in observations {
        let expected = if let PrivilegedOperation::ObserveManaged(targets) = operation {
            targets.iter().any(|target| {
                target.resource() == observation.resource()
                    && target.protocol()
                        == Some(crate::vortix_core::profile::ProtocolKind::WireGuard)
                    && observation.state() == ObservationState::Present
            })
        } else {
            false
        };
        if observation.wireguard_peers().is_some() != expected {
            return Err(ReceiptError::OutcomeMismatch);
        }
    }
    Ok(())
}

fn validate_applied(
    operation: &PrivilegedOperation,
    ownership: &[ResourceOwnership],
    authority: AuthorityEpoch,
    lease_id: LeaseId,
    sequence: RequestSequence,
) -> Result<(), ReceiptError> {
    bounded(ownership.len())?;
    if has_duplicates(ownership.iter().map(ResourceOwnership::resource))
        || ownership.iter().any(|item| {
            item.authority_epoch != authority
                || item.lease_id != lease_id
                || item.acquired_sequence != sequence
                || !operation.relates_to(&item.resource)
        })
    {
        return Err(ReceiptError::UnrelatedResource);
    }
    match operation {
        PrivilegedOperation::StartTunnel(plan) => {
            let tunnel = ResourceTag::tunnel(plan.profile_id().clone(), plan.generation())
                .map_err(|_| ReceiptError::UnrelatedResource)?;
            let group = ResourceTag::profile(
                plan.profile_id().clone(),
                plan.generation(),
                ResourceKind::ProcessGroup,
            )
            .map_err(|_| ReceiptError::UnrelatedResource)?;
            match plan {
                crate::vortix_core::privileged::ProtocolPlan::WireGuard(_) => {
                    if ownership.len() != 1 || ownership[0].resource != tunnel {
                        return Err(ReceiptError::MissingRequiredResource);
                    }
                }
                crate::vortix_core::privileged::ProtocolPlan::OpenVpn(_) => {
                    if ownership.len() != 2
                        || !ownership.iter().any(|item| item.resource == tunnel)
                        || !ownership.iter().any(|item| item.resource == group)
                    {
                        return Err(ReceiptError::MissingRequiredResource);
                    }
                }
            }
        }
        PrivilegedOperation::StopTunnel(_)
        | PrivilegedOperation::Observe(_)
        | PrivilegedOperation::ObserveManaged(_)
        | PrivilegedOperation::CleanupOwned(_) => return Err(ReceiptError::OutcomeMismatch),
        PrivilegedOperation::NetworkPolicy(policy) => {
            if ownership.len() != 1 || ownership[0].resource != *policy.policy_resource() {
                return Err(ReceiptError::OutcomeMismatch);
            }
        }
    }
    Ok(())
}

fn exact_observations(
    expected: &[ResourceTag],
    actual: &[ResourceObservation],
) -> Result<(), ReceiptError> {
    if expected.len() == actual.len()
        && expected
            .iter()
            .all(|resource| actual.iter().any(|item| &item.resource == resource))
    {
        Ok(())
    } else {
        Err(ReceiptError::MissingRequiredResource)
    }
}

fn exact_target_observations(
    expected: &[ResourceObservationTarget],
    actual: &[ResourceObservation],
) -> Result<(), ReceiptError> {
    if expected.len() == actual.len()
        && expected.iter().all(|target| {
            actual
                .iter()
                .any(|item| &item.resource == target.resource())
        })
    {
        Ok(())
    } else {
        Err(ReceiptError::MissingRequiredResource)
    }
}

fn exact_observation_state(
    expected: &[ResourceTag],
    actual: &[ResourceObservation],
    state: ObservationState,
) -> Result<(), ReceiptError> {
    exact_observations(expected, actual)?;
    if actual.iter().all(|item| item.state == state) {
        Ok(())
    } else {
        Err(ReceiptError::OutcomeMismatch)
    }
}

fn bounded(len: usize) -> Result<(), ReceiptError> {
    if len > MAX_RESOURCE_ITEMS {
        Err(ReceiptError::CollectionLimit)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ReceiptError {
    #[error("receipt does not match authenticated request authority")]
    AuthorityMismatch,
    #[error("receipt resource is unrelated to the requested operation")]
    UnrelatedResource,
    #[error("receipt is missing an exact required resource fact")]
    MissingRequiredResource,
    #[error("receipt outcome is not valid for the requested operation")]
    OutcomeMismatch,
    #[error("receipt resource collection exceeds its fixed bound")]
    CollectionLimit,
    #[error("resource observation timestamp must be non-zero")]
    InvalidObservationTime,
    #[error("WireGuard peer observation evidence is malformed or out of scope")]
    InvalidPeerEvidence,
    #[error("unsupported privileged contract schema version")]
    UnsupportedSchema,
}
