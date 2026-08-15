//! Privileged request vocabulary, trust roots, and replay/policy fences.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::control::AuthorityEpoch;
use crate::vortix_core::privileged::protocol_plan::{DnsHostname, ProtocolPlan};
use crate::vortix_core::privileged::receipt::{ObservationState, VerifiedReceipt};
use crate::vortix_core::privileged::resource::{
    ResourceKind, ResourceObservationTarget, ResourceTag,
};
use crate::vortix_core::privileged::{
    has_duplicates, invalid_unicast_ip, BoundedVec, CONTRACT_SCHEMA_VERSION, MAX_RESOURCE_ITEMS,
};
use crate::vortix_core::state::killswitch::KillSwitchMode;

const DIGEST_SCHEMA_VERSION: u16 = CONTRACT_SCHEMA_VERSION;
const MAX_DNS_SERVERS: usize = 16;
const MAX_DNS_DOMAINS: usize = 64;

macro_rules! nonzero_counter {
    ($name:ident, $message:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(u64);

        impl $name {
            pub const fn new(value: u64) -> Result<Self, OperationError> {
                if value == 0 {
                    Err(OperationError::InvalidCounter($message))
                } else {
                    Ok(Self(value))
                }
            }

            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                Self::new(u64::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

nonzero_counter!(HelperEpoch, "helper epoch must be non-zero");
nonzero_counter!(RequestSequence, "request sequence must be non-zero");

/// SHA-256 of a versioned, domain-separated canonical semantic encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OperationDigest([u8; 32]);

impl OperationDigest {
    /// Hash opaque root-owned evidence. Semantic operation hashing uses the
    /// private versioned encoder below instead.
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    #[must_use]
    pub(crate) const fn from_sha256(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    fn semantic<T: Serialize>(domain: &[u8], value: &T) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"vortix\0privileged-contract\0");
        hash.update(DIGEST_SCHEMA_VERSION.to_be_bytes());
        put_bytes(&mut hash, domain);
        encode_value(
            &mut hash,
            &serde_json::to_value(value).expect("privileged semantic serialization cannot fail"),
        );
        Self(hash.finalize().into())
    }

    fn of_request(payload: &RequestDigestPayload<'_>) -> Self {
        Self::semantic(b"request", payload)
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    fn is_zero(self) -> bool {
        self.0 == [0; 32]
    }
}

fn put_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(bytes);
}

/// Canonical binary encoding of serde's data model. Object keys are sorted by
/// `serde_json::Map`; every value and length is explicitly tagged, so JSON
/// whitespace/order/number formatting never participates in a digest.
fn encode_value(hash: &mut Sha256, value: &Value) {
    match value {
        Value::Null => hash.update([0]),
        Value::Bool(value) => hash.update([1, u8::from(*value)]),
        Value::Number(value) => {
            hash.update([2]);
            put_bytes(hash, value.to_string().as_bytes());
        }
        Value::String(value) => {
            hash.update([3]);
            put_bytes(hash, value.as_bytes());
        }
        Value::Array(values) => {
            hash.update([4]);
            hash.update(
                u64::try_from(values.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            for value in values {
                encode_value(hash, value);
            }
        }
        Value::Object(values) => {
            hash.update([5]);
            hash.update(
                u64::try_from(values.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            for (key, value) in entries {
                put_bytes(hash, key.as_bytes());
                encode_value(hash, value);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivilegedOperationId {
    authority_epoch: AuthorityEpoch,
    lease_id: LeaseId,
    sequence: RequestSequence,
}

impl PrivilegedOperationId {
    const fn new(
        authority_epoch: AuthorityEpoch,
        lease_id: LeaseId,
        sequence: RequestSequence,
    ) -> Self {
        Self {
            authority_epoch,
            lease_id,
            sequence,
        }
    }

    #[must_use]
    pub const fn authority_epoch(&self) -> AuthorityEpoch {
        self.authority_epoch
    }

    #[must_use]
    pub const fn lease_id(&self) -> LeaseId {
        self.lease_id
    }

    #[must_use]
    pub const fn sequence(&self) -> RequestSequence {
        self.sequence
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceManager {
    Systemd,
    Launchd,
}

/// Untrusted serialized claim received alongside peer credentials. It becomes
/// authority only after exact comparison with root-ledger OS-verified facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceInstanceClaim {
    manager: ServiceManager,
    pid: u32,
    process_start_token: u64,
    executable_digest: OperationDigest,
    manager_instance_nonce: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceInstanceClaimWire {
    manager: ServiceManager,
    pid: u32,
    process_start_token: u64,
    executable_digest: OperationDigest,
    manager_instance_nonce: [u8; 32],
}

impl<'de> Deserialize<'de> for ServiceInstanceClaim {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ServiceInstanceClaimWire::deserialize(deserializer)?;
        Self::new(
            wire.manager,
            wire.pid,
            wire.process_start_token,
            wire.executable_digest,
            wire.manager_instance_nonce,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl ServiceInstanceClaim {
    pub fn systemd(
        pid: u32,
        process_start_token: u64,
        executable_digest: OperationDigest,
        manager_instance_nonce: [u8; 32],
    ) -> Result<Self, OperationError> {
        Self::new(
            ServiceManager::Systemd,
            pid,
            process_start_token,
            executable_digest,
            manager_instance_nonce,
        )
    }

    pub fn launchd(
        pid: u32,
        process_start_token: u64,
        executable_digest: OperationDigest,
        manager_instance_nonce: [u8; 32],
    ) -> Result<Self, OperationError> {
        Self::new(
            ServiceManager::Launchd,
            pid,
            process_start_token,
            executable_digest,
            manager_instance_nonce,
        )
    }

    fn new(
        manager: ServiceManager,
        pid: u32,
        process_start_token: u64,
        executable_digest: OperationDigest,
        manager_instance_nonce: [u8; 32],
    ) -> Result<Self, OperationError> {
        if pid == 0
            || process_start_token == 0
            || executable_digest.is_zero()
            || manager_instance_nonce == [0; 32]
        {
            return Err(OperationError::InvalidServiceClaim);
        }
        Ok(Self {
            manager,
            pid,
            process_start_token,
            executable_digest,
            manager_instance_nonce,
        })
    }

    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    #[must_use]
    pub const fn process_start_token(&self) -> u64 {
        self.process_start_token
    }

    #[must_use]
    pub const fn executable_digest(&self) -> OperationDigest {
        self.executable_digest
    }

    #[must_use]
    pub const fn manager(&self) -> ServiceManager {
        self.manager
    }

    #[must_use]
    pub const fn manager_instance_nonce(&self) -> [u8; 32] {
        self.manager_instance_nonce
    }

    fn binding_digest(&self) -> OperationDigest {
        OperationDigest::semantic(b"service-instance", self)
    }
}

/// Untrusted peer credential claim. Scalar construction never grants trust;
/// U11 compares it to kernel facts before creating `PlatformVerifiedAuthority`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerProcessIdentity {
    uid: u32,
    pid: u32,
    process_start_token: u64,
}

impl PeerProcessIdentity {
    pub fn untrusted_claim(
        uid: u32,
        pid: u32,
        process_start_token: u64,
    ) -> Result<Self, OperationError> {
        if uid == 0 || pid == 0 || process_start_token == 0 {
            return Err(OperationError::InvalidPeerIdentity);
        }
        Ok(Self {
            uid,
            pid,
            process_start_token,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BootScope([u8; 16]);

impl BootScope {
    #[must_use]
    pub const fn new(value: [u8; 16]) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LeaseId([u8; 32]);

impl LeaseId {
    #[must_use]
    pub const fn new(value: [u8; 32]) -> Self {
        Self(value)
    }

    #[must_use]
    pub(crate) const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    fn is_zero(self) -> bool {
        self.0 == [0; 32]
    }
}

/// Non-secret cross-store identity for one enrolled authority generation.
/// The service-manager nonce is represented only by a domain-separated
/// digest; the root capability itself never enters user-owned state or IPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityBinding {
    authority_epoch: AuthorityEpoch,
    boot_scope: BootScope,
    lease_id: LeaseId,
    service_instance_digest: OperationDigest,
}

impl AuthorityBinding {
    pub fn new(
        authority_epoch: AuthorityEpoch,
        boot_scope: BootScope,
        lease_id: LeaseId,
        service_instance_digest: OperationDigest,
    ) -> Result<Self, OperationError> {
        if authority_epoch.0 == 0
            || boot_scope == BootScope::new([0; 16])
            || lease_id == LeaseId::new([0; 32])
            || service_instance_digest.is_zero()
        {
            return Err(OperationError::InvalidLease);
        }
        Ok(Self {
            authority_epoch,
            boot_scope,
            lease_id,
            service_instance_digest,
        })
    }

    #[must_use]
    pub const fn authority_epoch(self) -> AuthorityEpoch {
        self.authority_epoch
    }

    #[must_use]
    pub const fn boot_scope(self) -> BootScope {
        self.boot_scope
    }

    #[must_use]
    pub const fn lease_id(self) -> LeaseId {
        self.lease_id
    }

    #[must_use]
    pub const fn service_instance_digest(self) -> OperationDigest {
        self.service_instance_digest
    }
}

/// Opaque result of U11's platform verifier. Construction is crate-private so
/// no ordinary wire or public scalar API can bless daemon authority.
#[allow(dead_code, reason = "U11 platform verifier seam")]
pub(crate) struct PlatformVerifiedAuthority {
    owner_uid: u32,
    service: ServiceInstanceClaim,
}

/// Deliberately unconstructible production seam reserved for U11's
/// platform-specific OS verifier. U11 must add creation from OS-owned facts;
/// scalar request values are not an initializer.
#[allow(dead_code, reason = "U11 platform verifier seam")]
pub(crate) struct U11PlatformAuthorityVerifier {
    private: (),
}

#[allow(dead_code, reason = "U11 platform verifier seam")]
impl U11PlatformAuthorityVerifier {
    #[cfg(test)]
    const fn test_fixture() -> Self {
        Self { private: () }
    }

    fn verify(
        &self,
        owner_uid: u32,
        peer: PeerProcessIdentity,
        service: &ServiceInstanceClaim,
    ) -> Result<PlatformVerifiedAuthority, OperationError> {
        let () = self.private;
        PlatformVerifiedAuthority::from_platform_verifier(owner_uid, peer, service)
    }
}

#[allow(dead_code, reason = "U11 platform verifier seam")]
impl PlatformVerifiedAuthority {
    pub(crate) fn from_platform_verifier(
        owner_uid: u32,
        peer: PeerProcessIdentity,
        service: &ServiceInstanceClaim,
    ) -> Result<Self, OperationError> {
        if owner_uid == 0
            || peer.uid != owner_uid
            || peer.pid != service.pid
            || peer.process_start_token != service.process_start_token
        {
            return Err(OperationError::UntrustedDaemon);
        }
        Ok(Self {
            owner_uid,
            service: service.clone(),
        })
    }
}

/// Root-owned authority capability initialized only after the helper verifies the
/// service manager, cgroup/job identity, executable, PID start token, boot,
/// and peer credentials. U11 supplies that OS verifier and atomic storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootAuthorityLedger {
    owner_uid: u32,
    boot_scope: BootScope,
    authority_epoch: AuthorityEpoch,
    service: ServiceInstanceClaim,
    lease_id: LeaseId,
}

impl RootAuthorityLedger {
    /// U11 helper-side seam. Only a platform-verified opaque capability can
    /// initialize the root ledger.
    #[allow(dead_code, reason = "U11 platform verifier seam")]
    pub(crate) fn from_platform_verified(
        verified: PlatformVerifiedAuthority,
        boot_scope: BootScope,
        authority_epoch: AuthorityEpoch,
        lease_id: LeaseId,
    ) -> Result<Self, OperationError> {
        Self::validate(
            verified.owner_uid,
            boot_scope,
            authority_epoch,
            verified.service,
            lease_id,
        )
    }

    #[allow(dead_code, reason = "U11 platform verifier seam")]
    fn validate(
        owner_uid: u32,
        boot_scope: BootScope,
        authority_epoch: AuthorityEpoch,
        service: ServiceInstanceClaim,
        lease_id: LeaseId,
    ) -> Result<Self, OperationError> {
        if owner_uid == 0 || boot_scope.0 == [0; 16] || authority_epoch.0 == 0 || lease_id.is_zero()
        {
            return Err(OperationError::InvalidLease);
        }
        Ok(Self {
            owner_uid,
            boot_scope,
            authority_epoch,
            service,
            lease_id,
        })
    }

    #[allow(dead_code, reason = "U11 platform verifier seam")]
    pub(crate) fn principal(&self) -> TrustedDaemonPrincipal {
        TrustedDaemonPrincipal {
            owner_uid: self.owner_uid,
            authority_epoch: self.authority_epoch,
            boot_scope: self.boot_scope,
            lease_id: self.lease_id,
            service_binding: self.service.binding_digest(),
        }
    }

    #[must_use]
    pub const fn authority_epoch(&self) -> AuthorityEpoch {
        self.authority_epoch
    }

    #[must_use]
    pub const fn lease_id(&self) -> LeaseId {
        self.lease_id
    }

    #[allow(
        dead_code,
        reason = "U12 execution slice remains unreachable until U13 enrollment gates it"
    )]
    pub(crate) const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    #[allow(
        dead_code,
        reason = "U12 execution slice remains unreachable until U13 enrollment gates it"
    )]
    pub(crate) fn matches_service_claim(&self, claim: &ServiceInstanceClaim) -> bool {
        self.service == *claim
    }

    pub(crate) fn matches_principal(&self, principal: &TrustedDaemonPrincipal) -> bool {
        self.owner_uid == principal.owner_uid
            && self.authority_epoch == principal.authority_epoch
            && self.boot_scope == principal.boot_scope
            && self.lease_id == principal.lease_id
            && self.service.binding_digest() == principal.service_binding
    }

    #[allow(dead_code, reason = "U11 root replay-ledger seam")]
    pub(crate) fn unused_replay_baseline(
        &self,
        principal: &TrustedDaemonPrincipal,
        helper_epoch: HelperEpoch,
    ) -> Result<ReplayBaseline, OperationError> {
        if !self.matches_principal(principal) {
            return Err(OperationError::PrincipalMismatch);
        }
        Ok(ReplayBaseline(ReplayRecord::Unused(ReplayUnused {
            schema_version: CONTRACT_SCHEMA_VERSION,
            authority_epoch: self.authority_epoch,
            lease_id: self.lease_id,
            principal_binding: principal.binding_digest(),
            initial_helper_epoch: helper_epoch,
        })))
    }

    #[allow(dead_code, reason = "U11 root replay-ledger seam")]
    pub(crate) fn loaded_replay_baseline(
        &self,
        principal: &TrustedDaemonPrincipal,
        record: ReplayRecord,
    ) -> Result<ReplayBaseline, OperationError> {
        if !self.matches_principal(principal) {
            return Err(OperationError::PrincipalMismatch);
        }
        Ok(ReplayBaseline(record))
    }
}

/// Non-deserializable capability minted only by [`RootAuthorityLedger`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedDaemonPrincipal {
    owner_uid: u32,
    authority_epoch: AuthorityEpoch,
    boot_scope: BootScope,
    lease_id: LeaseId,
    service_binding: OperationDigest,
}

impl TrustedDaemonPrincipal {
    #[must_use]
    pub const fn authority_epoch(&self) -> AuthorityEpoch {
        self.authority_epoch
    }

    #[must_use]
    pub const fn lease_id(&self) -> LeaseId {
        self.lease_id
    }

    fn binding_digest(&self) -> OperationDigest {
        #[derive(Serialize)]
        struct Binding {
            owner_uid: u32,
            authority_epoch: AuthorityEpoch,
            boot_scope: BootScope,
            lease_id: LeaseId,
            service_digest: OperationDigest,
        }
        OperationDigest::semantic(
            b"trusted-principal",
            &Binding {
                owner_uid: self.owner_uid,
                authority_epoch: self.authority_epoch,
                boot_scope: self.boot_scope,
                lease_id: self.lease_id,
                service_digest: self.service_binding,
            },
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyDigest(OperationDigest);

impl PolicyDigest {
    fn of(operation: &NetworkPolicyOperation) -> Self {
        Self(OperationDigest::semantic(
            b"network-policy-transition",
            operation,
        ))
    }

    fn is_zero(self) -> bool {
        self.0.is_zero()
    }

    fn of_projection(projection: &PolicyProjection) -> Self {
        Self(OperationDigest::semantic(
            b"network-policy-projection",
            projection,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyPhase {
    Blocking,
    Routes,
    Dns,
    Firewall,
    Released,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPredecessor {
    digest: PolicyDigest,
    phase: PolicyPhase,
    observed: bool,
}

impl PolicyPredecessor {
    #[cfg(test)]
    pub(crate) const fn for_test(digest: PolicyDigest, phase: PolicyPhase) -> Self {
        Self {
            digest,
            phase,
            observed: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyCursor {
    authority_epoch: AuthorityEpoch,
    generation: u64,
    digest: PolicyDigest,
    phase: PolicyPhase,
    observed: bool,
    projection: PolicyProjection,
    previous: Option<PolicyRollback>,
    #[serde(deserialize_with = "deserialize_resource_vec")]
    pending_release: Vec<ResourceTag>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyRollback {
    authority_epoch: AuthorityEpoch,
    generation: u64,
    digest: PolicyDigest,
    phase: PolicyPhase,
    projection: PolicyProjection,
}

impl PolicyRollback {
    fn from_observed(cursor: &PolicyCursor) -> Option<Self> {
        (cursor.observed && cursor.previous.is_none() && cursor.pending_release.is_empty()).then(
            || Self {
                authority_epoch: cursor.authority_epoch,
                generation: cursor.generation,
                digest: cursor.digest,
                phase: cursor.phase,
                projection: cursor.projection.clone(),
            },
        )
    }

    fn into_cursor(self) -> PolicyCursor {
        PolicyCursor {
            authority_epoch: self.authority_epoch,
            generation: self.generation,
            digest: self.digest,
            phase: self.phase,
            observed: true,
            projection: self.projection,
            previous: None,
            pending_release: Vec::new(),
        }
    }
}

impl PolicyCursor {
    const fn predecessor(&self) -> PolicyPredecessor {
        PolicyPredecessor {
            digest: self.digest,
            phase: self.phase,
            observed: self.observed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrivilegedDnsScope {
    CatchAll,
    Scoped { domains: Vec<DnsHostname> },
    Suppressed,
}

/// Whether an admitted firewall subject already has a managed interface or
/// only needs its transport endpoints admitted during pre-tunnel blocking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegedFirewallRole {
    Primary,
    Secondary,
    PendingEndpoint,
}

/// Complete firewall inputs for one helper-derived tunnel identity. Physical
/// interface names remain authority-derived inside the helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrivilegedFirewallTunnel {
    tunnel: ResourceTag,
    endpoint_ips: Vec<IpAddr>,
    declared_cidrs: Vec<Cidr>,
    role: PrivilegedFirewallRole,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivilegedFirewallTunnelWire {
    tunnel: ResourceTag,
    endpoint_ips: BoundedVec<IpAddr, MAX_RESOURCE_ITEMS>,
    declared_cidrs: BoundedVec<Cidr, MAX_RESOURCE_ITEMS>,
    role: PrivilegedFirewallRole,
}

impl<'de> Deserialize<'de> for PrivilegedFirewallTunnel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = PrivilegedFirewallTunnelWire::deserialize(deserializer)?;
        Self::new(
            wire.tunnel,
            wire.endpoint_ips.into_vec(),
            wire.declared_cidrs.into_vec(),
            wire.role,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl PrivilegedFirewallTunnel {
    pub fn new(
        tunnel: ResourceTag,
        endpoint_ips: Vec<IpAddr>,
        declared_cidrs: Vec<Cidr>,
        role: PrivilegedFirewallRole,
    ) -> Result<Self, OperationError> {
        if tunnel.kind() != ResourceKind::Tunnel
            || endpoint_ips.len() > MAX_RESOURCE_ITEMS
            || endpoint_ips.iter().any(invalid_unicast_ip)
            || has_duplicates(&endpoint_ips)
            || declared_cidrs.len() > MAX_RESOURCE_ITEMS
            || declared_cidrs.iter().any(|cidr| !cidr.is_valid())
            || declared_cidrs
                .iter()
                .enumerate()
                .any(|(index, cidr)| declared_cidrs[..index].contains(cidr))
            || (role == PrivilegedFirewallRole::PendingEndpoint && endpoint_ips.is_empty())
        {
            return Err(OperationError::ResourceScopeMismatch);
        }
        Ok(Self {
            tunnel,
            endpoint_ips,
            declared_cidrs,
            role,
        })
    }

    #[must_use]
    pub const fn tunnel(&self) -> &ResourceTag {
        &self.tunnel
    }

    #[must_use]
    pub fn endpoint_ips(&self) -> &[IpAddr] {
        &self.endpoint_ips
    }

    #[must_use]
    pub fn declared_cidrs(&self) -> &[Cidr] {
        &self.declared_cidrs
    }

    #[must_use]
    pub const fn role(&self) -> PrivilegedFirewallRole {
        self.role
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum PrivilegedDnsScopeWire {
    CatchAll,
    Scoped {
        domains: BoundedVec<DnsHostname, MAX_DNS_DOMAINS>,
    },
    Suppressed,
}

impl<'de> Deserialize<'de> for PrivilegedDnsScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(match PrivilegedDnsScopeWire::deserialize(deserializer)? {
            PrivilegedDnsScopeWire::CatchAll => Self::CatchAll,
            PrivilegedDnsScopeWire::Scoped { domains } => Self::Scoped {
                domains: domains.into_vec(),
            },
            PrivilegedDnsScopeWire::Suppressed => Self::Suppressed,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrivilegedDnsAssignment {
    tunnel: ResourceTag,
    servers: Vec<IpAddr>,
    search_domains: Vec<DnsHostname>,
    scope: PrivilegedDnsScope,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivilegedDnsAssignmentWire {
    tunnel: ResourceTag,
    servers: BoundedVec<IpAddr, MAX_DNS_SERVERS>,
    search_domains: BoundedVec<DnsHostname, MAX_DNS_DOMAINS>,
    scope: PrivilegedDnsScope,
}

impl<'de> Deserialize<'de> for PrivilegedDnsAssignment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = PrivilegedDnsAssignmentWire::deserialize(deserializer)?;
        Self::new(
            wire.tunnel,
            wire.servers.into_vec(),
            wire.search_domains.into_vec(),
            wire.scope,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl PrivilegedDnsAssignment {
    pub fn new(
        tunnel: ResourceTag,
        servers: Vec<IpAddr>,
        search_domains: Vec<DnsHostname>,
        scope: PrivilegedDnsScope,
    ) -> Result<Self, OperationError> {
        let scoped_domains = match &scope {
            PrivilegedDnsScope::Scoped { domains } => domains,
            PrivilegedDnsScope::CatchAll | PrivilegedDnsScope::Suppressed => &Vec::new(),
        };
        if tunnel.kind() != ResourceKind::Tunnel
            || servers.is_empty()
            || servers.len() > MAX_DNS_SERVERS
            || servers.iter().any(invalid_unicast_ip)
            || search_domains.len() > MAX_DNS_DOMAINS
            || scoped_domains.is_empty() && matches!(scope, PrivilegedDnsScope::Scoped { .. })
            || scoped_domains.len() > MAX_DNS_DOMAINS
            || has_duplicates(&search_domains)
            || has_duplicates(scoped_domains)
        {
            return Err(OperationError::ResourceScopeMismatch);
        }
        Ok(Self {
            tunnel,
            servers,
            search_domains,
            scope,
        })
    }

    #[must_use]
    pub const fn tunnel(&self) -> &ResourceTag {
        &self.tunnel
    }

    #[must_use]
    pub fn servers(&self) -> &[IpAddr] {
        &self.servers
    }

    #[must_use]
    pub fn search_domains(&self) -> &[DnsHostname] {
        &self.search_domains
    }

    #[must_use]
    pub const fn scope(&self) -> &PrivilegedDnsScope {
        &self.scope
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum NetworkPolicyOperation {
    EstablishBlocking {
        policy: ResourceTag,
        #[serde(deserialize_with = "deserialize_firewall_tunnel_vec")]
        tunnels: Vec<PrivilegedFirewallTunnel>,
    },
    ApplyRoutes {
        policy: ResourceTag,
        #[serde(deserialize_with = "deserialize_route_vec")]
        routes: Vec<ScopedRoute>,
        predecessor: PolicyPredecessor,
    },
    ApplyDns {
        policy: ResourceTag,
        #[serde(deserialize_with = "deserialize_dns_assignment_vec")]
        assignments: Vec<PrivilegedDnsAssignment>,
        predecessor: PolicyPredecessor,
    },
    ApplyFirewall {
        policy: ResourceTag,
        #[serde(with = "crate::vortix_core::state::killswitch::serde_mode_slug")]
        mode: KillSwitchMode,
        #[serde(deserialize_with = "deserialize_firewall_tunnel_vec")]
        tunnels: Vec<PrivilegedFirewallTunnel>,
        predecessor: PolicyPredecessor,
    },
    ObserveBarrier {
        policy: ResourceTag,
        predecessor: PolicyPredecessor,
    },
    ReleaseObsolete {
        policy: ResourceTag,
        #[serde(deserialize_with = "deserialize_resource_vec")]
        resources: Vec<ResourceTag>,
        predecessor: PolicyPredecessor,
    },
}

impl NetworkPolicyOperation {
    fn validate(&self, authority: AuthorityEpoch) -> Result<(), OperationError> {
        let policy = self.policy();
        validate_policy_tag(policy, authority, self.expected_policy_kind())?;
        match self {
            Self::EstablishBlocking { tunnels, .. } => validate_firewall_tunnels(tunnels, true),
            Self::ApplyFirewall { mode, tunnels, .. } => {
                validate_firewall_tunnels(tunnels, matches!(mode, KillSwitchMode::AlwaysOn))
            }
            Self::ApplyRoutes { routes, .. } => validate_routes(routes),
            Self::ApplyDns { assignments, .. } => validate_dns_assignments(assignments),
            Self::ObserveBarrier { .. } => Ok(()),
            Self::ReleaseObsolete {
                policy, resources, ..
            } => {
                bounded(resources)?;
                if resources.is_empty()
                    || has_duplicates(resources)
                    || resources.iter().any(|resource| {
                        !matches!(
                            resource.kind(),
                            ResourceKind::Firewall | ResourceKind::Dns | ResourceKind::Routes
                        ) || resource.authority_epoch() != Some(authority)
                            || resource.generation() >= policy.generation()
                    })
                {
                    Err(OperationError::ResourceScopeMismatch)
                } else {
                    Ok(())
                }
            }
        }
    }

    const fn policy(&self) -> &ResourceTag {
        match self {
            Self::EstablishBlocking { policy, .. }
            | Self::ApplyRoutes { policy, .. }
            | Self::ApplyDns { policy, .. }
            | Self::ApplyFirewall { policy, .. }
            | Self::ObserveBarrier { policy, .. }
            | Self::ReleaseObsolete { policy, .. } => policy,
        }
    }

    pub(crate) const fn policy_resource(&self) -> &ResourceTag {
        self.policy()
    }

    const fn expected_policy_kind(&self) -> ResourceKind {
        match self {
            Self::EstablishBlocking { .. } | Self::ApplyFirewall { .. } => ResourceKind::Firewall,
            Self::ApplyRoutes { .. } => ResourceKind::Routes,
            Self::ApplyDns { .. } => ResourceKind::Dns,
            Self::ObserveBarrier { policy, .. } | Self::ReleaseObsolete { policy, .. } => {
                policy.kind()
            }
        }
    }

    const fn predecessor(&self) -> Option<PolicyPredecessor> {
        match self {
            Self::EstablishBlocking { .. } => None,
            Self::ApplyRoutes { predecessor, .. }
            | Self::ApplyDns { predecessor, .. }
            | Self::ApplyFirewall { predecessor, .. }
            | Self::ObserveBarrier { predecessor, .. }
            | Self::ReleaseObsolete { predecessor, .. } => Some(*predecessor),
        }
    }

    const fn target_phase(&self) -> PolicyPhase {
        match self {
            Self::EstablishBlocking { .. } => PolicyPhase::Blocking,
            Self::ApplyRoutes { .. } => PolicyPhase::Routes,
            Self::ApplyDns { .. } => PolicyPhase::Dns,
            Self::ApplyFirewall { .. } => PolicyPhase::Firewall,
            Self::ObserveBarrier { predecessor, .. } => predecessor.phase,
            Self::ReleaseObsolete { .. } => PolicyPhase::Released,
        }
    }

    const fn is_observation(&self) -> bool {
        matches!(self, Self::ObserveBarrier { .. })
    }
}

fn validate_policy_tag(
    policy: &ResourceTag,
    authority: AuthorityEpoch,
    kind: ResourceKind,
) -> Result<(), OperationError> {
    if policy.kind() == kind && policy.authority_epoch() == Some(authority) {
        Ok(())
    } else {
        Err(OperationError::ResourceScopeMismatch)
    }
}

fn validate_firewall_tunnels(
    tunnels: &[PrivilegedFirewallTunnel],
    endpoints_required: bool,
) -> Result<(), OperationError> {
    bounded(tunnels)?;
    if has_duplicates(tunnels.iter().map(PrivilegedFirewallTunnel::tunnel))
        || endpoints_required
            && tunnels
                .iter()
                .any(|tunnel| tunnel.endpoint_ips().is_empty())
    {
        Err(OperationError::ResourceScopeMismatch)
    } else {
        Ok(())
    }
}

fn validate_routes(routes: &[ScopedRoute]) -> Result<(), OperationError> {
    bounded(routes)?;
    if routes
        .iter()
        .any(|route| route.tunnel.kind() != ResourceKind::Tunnel)
    {
        Err(OperationError::ResourceScopeMismatch)
    } else {
        Ok(())
    }
}

fn validate_route_projection(
    routes: &[ScopedRoute],
    tunnels: &[PrivilegedFirewallTunnel],
) -> Result<(), OperationError> {
    validate_routes(routes)?;
    validate_firewall_tunnels(tunnels, true)?;
    if routes.iter().any(|route| {
        let Some(subject) = tunnels
            .iter()
            .find(|subject| subject.tunnel() == route.tunnel())
        else {
            return true;
        };
        !subject
            .declared_cidrs()
            .iter()
            .any(|declared| canonical_cidr(*declared) == canonical_cidr(route.destination()))
    }) {
        Err(OperationError::ResourceScopeMismatch)
    } else {
        Ok(())
    }
}

fn canonical_cidr(cidr: Cidr) -> Cidr {
    let addr = match cidr.addr {
        IpAddr::V4(address) => {
            let mask = u32::MAX
                .checked_shl(u32::from(32 - cidr.prefix_len))
                .unwrap_or(0);
            IpAddr::V4((u32::from(address) & mask).into())
        }
        IpAddr::V6(address) => {
            let mask = u128::MAX
                .checked_shl(u32::from(128 - cidr.prefix_len))
                .unwrap_or(0);
            IpAddr::V6((u128::from(address) & mask).into())
        }
    };
    Cidr {
        addr,
        prefix_len: cidr.prefix_len,
    }
}

fn validate_dns_assignments(assignments: &[PrivilegedDnsAssignment]) -> Result<(), OperationError> {
    bounded(assignments)?;
    if has_duplicates(assignments.iter().map(|assignment| &assignment.tunnel)) {
        Err(OperationError::ResourceScopeMismatch)
    } else {
        Ok(())
    }
}

fn bounded<T>(values: &[T]) -> Result<(), OperationError> {
    if values.len() > MAX_RESOURCE_ITEMS {
        Err(OperationError::CollectionLimit)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedRoute {
    destination: Cidr,
    tunnel: ResourceTag,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopedRouteWire {
    destination: Cidr,
    tunnel: ResourceTag,
}

impl<'de> Deserialize<'de> for ScopedRoute {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ScopedRouteWire::deserialize(deserializer)?;
        Self::new(wire.destination, wire.tunnel).map_err(serde::de::Error::custom)
    }
}

/// Exact typed projection persisted with the replay cursor before a policy
/// effect. Observation and release reuse this projection after helper restart
/// instead of reconstructing privileged intent from a digest or resource tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum PolicyProjection {
    Blocking {
        policy: ResourceTag,
        #[serde(deserialize_with = "deserialize_firewall_tunnel_vec")]
        tunnels: Vec<PrivilegedFirewallTunnel>,
    },
    Routes {
        policy: ResourceTag,
        #[serde(deserialize_with = "deserialize_route_vec")]
        routes: Vec<ScopedRoute>,
        #[serde(deserialize_with = "deserialize_firewall_tunnel_vec")]
        tunnels: Vec<PrivilegedFirewallTunnel>,
    },
    Dns {
        policy: ResourceTag,
        #[serde(deserialize_with = "deserialize_dns_assignment_vec")]
        assignments: Vec<PrivilegedDnsAssignment>,
    },
    Firewall {
        policy: ResourceTag,
        #[serde(with = "crate::vortix_core::state::killswitch::serde_mode_slug")]
        mode: KillSwitchMode,
        #[serde(deserialize_with = "deserialize_firewall_tunnel_vec")]
        tunnels: Vec<PrivilegedFirewallTunnel>,
    },
}

impl PolicyProjection {
    fn from_mutation(
        operation: &NetworkPolicyOperation,
        predecessor: Option<&Self>,
    ) -> Result<Option<Self>, OperationError> {
        Ok(match operation {
            NetworkPolicyOperation::EstablishBlocking { policy, tunnels } => Some(Self::Blocking {
                policy: policy.clone(),
                tunnels: tunnels.clone(),
            }),
            NetworkPolicyOperation::ApplyRoutes { policy, routes, .. } => {
                let Some(Self::Blocking { tunnels, .. }) = predecessor else {
                    return Err(OperationError::PolicyTransition);
                };
                validate_route_projection(routes, tunnels)?;
                Some(Self::Routes {
                    policy: policy.clone(),
                    routes: routes.clone(),
                    tunnels: tunnels.clone(),
                })
            }
            NetworkPolicyOperation::ApplyDns {
                policy,
                assignments,
                ..
            } => Some(Self::Dns {
                policy: policy.clone(),
                assignments: assignments.clone(),
            }),
            NetworkPolicyOperation::ApplyFirewall {
                policy,
                mode,
                tunnels,
                ..
            } => Some(Self::Firewall {
                policy: policy.clone(),
                mode: *mode,
                tunnels: tunnels.clone(),
            }),
            NetworkPolicyOperation::ObserveBarrier { .. }
            | NetworkPolicyOperation::ReleaseObsolete { .. } => None,
        })
    }

    pub(crate) const fn policy(&self) -> &ResourceTag {
        match self {
            Self::Blocking { policy, .. }
            | Self::Routes { policy, .. }
            | Self::Dns { policy, .. }
            | Self::Firewall { policy, .. } => policy,
        }
    }

    pub(crate) fn digest(&self) -> PolicyDigest {
        PolicyDigest::of_projection(self)
    }

    pub(crate) fn route_inputs(&self) -> Option<(&[ScopedRoute], &[PrivilegedFirewallTunnel])> {
        match self {
            Self::Routes {
                routes, tunnels, ..
            } => Some((routes, tunnels)),
            Self::Blocking { .. } | Self::Dns { .. } | Self::Firewall { .. } => None,
        }
    }

    /// Whether this projection requires a live helper-owned firewall
    /// resource. Non-firewall phases have no firewall disposition.
    pub(crate) const fn firewall_blocks(&self) -> Option<bool> {
        match self {
            Self::Blocking { .. } => Some(true),
            Self::Firewall { mode, .. } => Some(matches!(mode, KillSwitchMode::AlwaysOn)),
            Self::Routes { .. } | Self::Dns { .. } => None,
        }
    }

    const fn phase(&self) -> PolicyPhase {
        match self {
            Self::Blocking { .. } => PolicyPhase::Blocking,
            Self::Routes { .. } => PolicyPhase::Routes,
            Self::Dns { .. } => PolicyPhase::Dns,
            Self::Firewall { .. } => PolicyPhase::Firewall,
        }
    }

    pub(crate) fn is_valid(&self) -> bool {
        let (policy, expected_kind, payload) = match self {
            Self::Blocking { policy, tunnels } => (
                policy,
                ResourceKind::Firewall,
                validate_firewall_tunnels(tunnels, true),
            ),
            Self::Routes {
                policy,
                routes,
                tunnels,
            } => (
                policy,
                ResourceKind::Routes,
                validate_route_projection(routes, tunnels),
            ),
            Self::Dns {
                policy,
                assignments,
            } => (
                policy,
                ResourceKind::Dns,
                validate_dns_assignments(assignments),
            ),
            Self::Firewall {
                policy,
                mode,
                tunnels,
            } => (
                policy,
                ResourceKind::Firewall,
                validate_firewall_tunnels(tunnels, matches!(mode, KillSwitchMode::AlwaysOn)),
            ),
        };
        policy.authority_epoch().is_some_and(|authority| {
            validate_policy_tag(policy, authority, expected_kind).is_ok() && payload.is_ok()
        })
    }
}

impl ScopedRoute {
    pub fn new(destination: Cidr, tunnel: ResourceTag) -> Result<Self, OperationError> {
        if !destination.is_valid() || tunnel.kind() != ResourceKind::Tunnel {
            return Err(OperationError::ResourceScopeMismatch);
        }
        Ok(Self {
            destination: canonical_cidr(destination),
            tunnel,
        })
    }

    #[must_use]
    pub const fn destination(&self) -> Cidr {
        self.destination
    }

    #[must_use]
    pub const fn tunnel(&self) -> &ResourceTag {
        &self.tunnel
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum PrivilegedOperation {
    StartTunnel(ProtocolPlan),
    StopTunnel(ResourceTag),
    NetworkPolicy(NetworkPolicyOperation),
    Observe(
        #[serde(deserialize_with = "deserialize_observation_target_vec")]
        Vec<ResourceObservationTarget>,
    ),
    CleanupOwned(#[serde(deserialize_with = "deserialize_resource_vec")] Vec<ResourceTag>),
}

fn deserialize_resource_vec<'de, D>(deserializer: D) -> Result<Vec<ResourceTag>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    BoundedVec::<ResourceTag, MAX_RESOURCE_ITEMS>::deserialize(deserializer)
        .map(BoundedVec::into_vec)
}

fn deserialize_firewall_tunnel_vec<'de, D>(
    deserializer: D,
) -> Result<Vec<PrivilegedFirewallTunnel>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    BoundedVec::<PrivilegedFirewallTunnel, MAX_RESOURCE_ITEMS>::deserialize(deserializer)
        .map(BoundedVec::into_vec)
}

fn deserialize_observation_target_vec<'de, D>(
    deserializer: D,
) -> Result<Vec<ResourceObservationTarget>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    BoundedVec::<ResourceObservationTarget, MAX_RESOURCE_ITEMS>::deserialize(deserializer)
        .map(BoundedVec::into_vec)
}

fn deserialize_route_vec<'de, D>(deserializer: D) -> Result<Vec<ScopedRoute>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    BoundedVec::<ScopedRoute, MAX_RESOURCE_ITEMS>::deserialize(deserializer)
        .map(BoundedVec::into_vec)
}

fn deserialize_dns_assignment_vec<'de, D>(
    deserializer: D,
) -> Result<Vec<PrivilegedDnsAssignment>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    BoundedVec::<PrivilegedDnsAssignment, MAX_RESOURCE_ITEMS>::deserialize(deserializer)
        .map(BoundedVec::into_vec)
}

impl PrivilegedOperation {
    fn validate(&self, authority: AuthorityEpoch) -> Result<(), OperationError> {
        match self {
            Self::StartTunnel(_) => Ok(()),
            Self::StopTunnel(resource) => require_profile_kind(resource, ResourceKind::Tunnel),
            Self::NetworkPolicy(operation) => operation.validate(authority),
            Self::Observe(targets) => {
                bounded(targets)?;
                if has_duplicates(targets.iter().map(ResourceObservationTarget::resource))
                    || targets.iter().any(|target| {
                        let resource = target.resource();
                        resource.authority_epoch().is_some()
                            && resource.authority_epoch() != Some(authority)
                    })
                {
                    Err(OperationError::ResourceScopeMismatch)
                } else {
                    Ok(())
                }
            }
            Self::CleanupOwned(resources) => {
                bounded(resources)?;
                if has_duplicates(resources)
                    || resources.iter().any(|resource| {
                        !matches!(
                            resource.kind(),
                            ResourceKind::Tunnel
                                | ResourceKind::ProcessGroup
                                | ResourceKind::RuntimeSecret
                        )
                    })
                {
                    Err(OperationError::ResourceScopeMismatch)
                } else {
                    Ok(())
                }
            }
        }
    }

    pub(crate) fn relates_to(&self, resource: &ResourceTag) -> bool {
        match self {
            Self::StartTunnel(plan) => {
                resource.profile_id() == Some(plan.profile_id())
                    && resource.generation() == plan.generation()
                    && matches!(
                        resource.kind(),
                        ResourceKind::Tunnel
                            | ResourceKind::ProcessGroup
                            | ResourceKind::RuntimeSecret
                    )
            }
            Self::StopTunnel(expected) => resource == expected,
            Self::NetworkPolicy(operation) => {
                resource == operation.policy()
                    || matches!(operation, NetworkPolicyOperation::ReleaseObsolete { resources, .. } if resources.contains(resource))
            }
            Self::Observe(targets) => targets.iter().any(|target| target.resource() == resource),
            Self::CleanupOwned(resources) => resources.contains(resource),
        }
    }
}

fn require_profile_kind(resource: &ResourceTag, kind: ResourceKind) -> Result<(), OperationError> {
    if resource.kind() == kind && resource.authority_epoch().is_none() {
        Ok(())
    } else {
        Err(OperationError::ResourceScopeMismatch)
    }
}

#[derive(Serialize)]
struct RequestDigestPayload<'a> {
    authority_epoch: AuthorityEpoch,
    helper_epoch: HelperEpoch,
    lease_id: LeaseId,
    sequence: RequestSequence,
    principal_binding: OperationDigest,
    operation: &'a PrivilegedOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrivilegedRequest {
    schema_version: u16,
    operation_id: PrivilegedOperationId,
    authority_epoch: AuthorityEpoch,
    helper_epoch: HelperEpoch,
    sequence: RequestSequence,
    principal_binding: OperationDigest,
    digest: OperationDigest,
    operation: PrivilegedOperation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivilegedRequestWire {
    schema_version: u16,
    operation_id: PrivilegedOperationId,
    authority_epoch: AuthorityEpoch,
    helper_epoch: HelperEpoch,
    sequence: RequestSequence,
    principal_binding: OperationDigest,
    digest: OperationDigest,
    operation: PrivilegedOperation,
}

impl<'de> Deserialize<'de> for PrivilegedRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = PrivilegedRequestWire::deserialize(deserializer)?;
        wire.operation
            .validate(wire.authority_epoch)
            .map_err(serde::de::Error::custom)?;
        let expected_id = PrivilegedOperationId::new(
            wire.authority_epoch,
            wire.operation_id.lease_id,
            wire.sequence,
        );
        let expected_digest = OperationDigest::of_request(&RequestDigestPayload {
            authority_epoch: wire.authority_epoch,
            helper_epoch: wire.helper_epoch,
            lease_id: wire.operation_id.lease_id,
            sequence: wire.sequence,
            principal_binding: wire.principal_binding,
            operation: &wire.operation,
        });
        if wire.schema_version != CONTRACT_SCHEMA_VERSION
            || wire.authority_epoch.0 == 0
            || wire.operation_id.lease_id.is_zero()
            || wire.operation_id != expected_id
            || wire.digest != expected_digest
        {
            return Err(serde::de::Error::custom("inconsistent privileged request"));
        }
        Ok(Self {
            schema_version: wire.schema_version,
            operation_id: wire.operation_id,
            authority_epoch: wire.authority_epoch,
            helper_epoch: wire.helper_epoch,
            sequence: wire.sequence,
            principal_binding: wire.principal_binding,
            digest: wire.digest,
            operation: wire.operation,
        })
    }
}

impl PrivilegedRequest {
    pub fn new(
        principal: &TrustedDaemonPrincipal,
        helper_epoch: HelperEpoch,
        sequence: RequestSequence,
        operation: PrivilegedOperation,
    ) -> Result<Self, OperationError> {
        let authority_epoch = principal.authority_epoch;
        operation.validate(authority_epoch)?;
        let principal_binding = principal.binding_digest();
        let operation_id =
            PrivilegedOperationId::new(authority_epoch, principal.lease_id, sequence);
        let digest = OperationDigest::of_request(&RequestDigestPayload {
            authority_epoch,
            helper_epoch,
            lease_id: principal.lease_id,
            sequence,
            principal_binding,
            operation: &operation,
        });
        Ok(Self {
            schema_version: CONTRACT_SCHEMA_VERSION,
            operation_id,
            authority_epoch,
            helper_epoch,
            sequence,
            principal_binding,
            digest,
            operation,
        })
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
    pub const fn digest_schema_version(&self) -> u16 {
        DIGEST_SCHEMA_VERSION
    }

    #[must_use]
    pub const fn authority_epoch(&self) -> AuthorityEpoch {
        self.authority_epoch
    }

    #[must_use]
    pub const fn helper_epoch(&self) -> HelperEpoch {
        self.helper_epoch
    }

    #[must_use]
    pub const fn sequence(&self) -> RequestSequence {
        self.sequence
    }

    #[must_use]
    pub const fn operation(&self) -> &PrivilegedOperation {
        &self.operation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationAdmission {
    Fresh,
    Duplicate,
}

/// Constant-size state persisted atomically by the root-owned helper ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReplayHighWater {
    schema_version: u16,
    authority_epoch: AuthorityEpoch,
    lease_id: LeaseId,
    principal_binding: OperationDigest,
    helper_epoch: HelperEpoch,
    highest_id: PrivilegedOperationId,
    highest_digest: OperationDigest,
    policy: Option<PolicyCursor>,
}

/// Root-ledger proof that a lease has never admitted a request. Callers may
/// not substitute `None` and silently reset replay state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReplayUnused {
    schema_version: u16,
    authority_epoch: AuthorityEpoch,
    lease_id: LeaseId,
    principal_binding: OperationDigest,
    initial_helper_epoch: HelperEpoch,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayUnusedWire {
    schema_version: u16,
    authority_epoch: AuthorityEpoch,
    lease_id: LeaseId,
    principal_binding: OperationDigest,
    initial_helper_epoch: HelperEpoch,
}

impl<'de> Deserialize<'de> for ReplayUnused {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ReplayUnusedWire::deserialize(deserializer)?;
        if wire.schema_version != CONTRACT_SCHEMA_VERSION
            || wire.authority_epoch.0 == 0
            || wire.lease_id.is_zero()
            || wire.principal_binding.is_zero()
        {
            return Err(serde::de::Error::custom("invalid unused replay baseline"));
        }
        Ok(Self {
            schema_version: wire.schema_version,
            authority_epoch: wire.authority_epoch,
            lease_id: wire.lease_id,
            principal_binding: wire.principal_binding,
            initial_helper_epoch: wire.initial_helper_epoch,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ReplayRecord {
    Unused(ReplayUnused),
    HighWater(Box<ReplayHighWater>),
}

impl ReplayRecord {
    pub(super) const fn authority_epoch(&self) -> AuthorityEpoch {
        match self {
            Self::Unused(record) => record.authority_epoch,
            Self::HighWater(record) => record.authority_epoch,
        }
    }
}

/// Non-serializable replay capability authenticated by the root ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayBaseline(ReplayRecord);

impl ReplayBaseline {
    /// Consume the authenticated baseline for root-ledger persistence. This
    /// stays crate-private so wire callers cannot manufacture replay state.
    pub(crate) fn into_record(self) -> ReplayRecord {
        self.0
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayHighWaterWire {
    schema_version: u16,
    authority_epoch: AuthorityEpoch,
    lease_id: LeaseId,
    principal_binding: OperationDigest,
    helper_epoch: HelperEpoch,
    highest_id: PrivilegedOperationId,
    highest_digest: OperationDigest,
    policy: Option<PolicyCursor>,
}

impl<'de> Deserialize<'de> for ReplayHighWater {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ReplayHighWaterWire::deserialize(deserializer)?;
        if wire.schema_version != CONTRACT_SCHEMA_VERSION
            || wire.authority_epoch.0 == 0
            || wire.lease_id.is_zero()
            || wire.principal_binding.is_zero()
            || wire.highest_digest.is_zero()
            || wire.highest_id.authority_epoch != wire.authority_epoch
            || wire.highest_id.lease_id != wire.lease_id
            || wire.policy.as_ref().is_some_and(|policy| {
                policy.authority_epoch != wire.authority_epoch
                    || policy.generation == 0
                    || policy.digest.is_zero()
                    || !policy.projection.is_valid()
                    || policy.projection.policy().authority_epoch() != Some(policy.authority_epoch)
                    || policy.projection.policy().generation() != policy.generation
                    || (policy.phase != PolicyPhase::Released
                        && policy.projection.phase() != policy.phase)
                    || policy.previous.as_ref().is_some_and(|previous| {
                        previous.authority_epoch != policy.authority_epoch
                            || previous.generation > policy.generation
                            || previous.digest.is_zero()
                            || !previous.projection.is_valid()
                            || previous.projection.policy().authority_epoch()
                                != Some(previous.authority_epoch)
                            || previous.projection.policy().generation() != previous.generation
                            || previous.projection.phase() != previous.phase
                    })
                    || (policy.phase != PolicyPhase::Released && !policy.pending_release.is_empty())
                    || (policy.phase == PolicyPhase::Released
                        && !policy.observed
                        && policy.pending_release.is_empty())
            })
        {
            return Err(serde::de::Error::custom(
                "invalid root replay high-water state",
            ));
        }
        Ok(Self {
            schema_version: wire.schema_version,
            authority_epoch: wire.authority_epoch,
            lease_id: wire.lease_id,
            principal_binding: wire.principal_binding,
            helper_epoch: wire.helper_epoch,
            highest_id: wire.highest_id,
            highest_digest: wire.highest_digest,
            policy: wire.policy,
        })
    }
}

pub struct OperationGuard {
    principal_binding: OperationDigest,
    authority_epoch: AuthorityEpoch,
    lease_id: LeaseId,
    helper_epoch: HelperEpoch,
    highest: Option<ReplayHighWater>,
}

impl OperationGuard {
    pub fn resume(
        principal: &TrustedDaemonPrincipal,
        helper_epoch: HelperEpoch,
        baseline: ReplayBaseline,
    ) -> Result<Self, OperationError> {
        let principal_binding = principal.binding_digest();
        let high_water = match baseline.0 {
            ReplayRecord::Unused(unused) => {
                if unused.authority_epoch != principal.authority_epoch
                    || unused.lease_id != principal.lease_id
                    || unused.principal_binding != principal_binding
                    || unused.initial_helper_epoch != helper_epoch
                {
                    return Err(OperationError::InvalidReplayState);
                }
                None
            }
            ReplayRecord::HighWater(state) => {
                if state.authority_epoch != principal.authority_epoch
                    || state.lease_id != principal.lease_id
                    || state.principal_binding != principal_binding
                    || state.highest_id.authority_epoch != state.authority_epoch
                    || state.highest_id.lease_id != state.lease_id
                    || state.highest_digest.is_zero()
                    || helper_epoch <= state.helper_epoch
                {
                    return Err(OperationError::InvalidReplayState);
                }
                Some(*state)
            }
        };
        Ok(Self {
            principal_binding,
            authority_epoch: principal.authority_epoch,
            lease_id: principal.lease_id,
            helper_epoch,
            highest: high_water,
        })
    }

    #[must_use]
    pub fn checkpoint(&self) -> Option<ReplayRecord> {
        self.highest
            .clone()
            .map(Box::new)
            .map(ReplayRecord::HighWater)
    }

    #[must_use]
    pub fn policy_predecessor(&self) -> Option<PolicyPredecessor> {
        self.highest
            .as_ref()?
            .policy
            .as_ref()
            .map(PolicyCursor::predecessor)
    }

    /// Return the root-ledger-authenticated projection for the current policy
    /// phase. This is the only policy payload an executor may use for a
    /// barrier or post-restart release.
    pub(crate) fn policy_projection(&self) -> Option<&PolicyProjection> {
        self.highest
            .as_ref()?
            .policy
            .as_ref()
            .map(|policy| &policy.projection)
    }

    /// Restore the last observed cursor after an executor proves a fresh
    /// mutation failed before any external effect. The replay high-water mark
    /// remains advanced, so the rejected request cannot be replayed.
    pub(crate) fn rollback_policy_before_effect(
        &mut self,
        request: &PrivilegedRequest,
    ) -> Result<(), OperationError> {
        let Some(state) = &mut self.highest else {
            return Err(OperationError::PolicyTransition);
        };
        if state.highest_id != *request.operation_id() || state.highest_digest != *request.digest()
        {
            return Err(OperationError::PolicyTransition);
        }
        let Some(cursor) = &mut state.policy else {
            return Err(OperationError::PolicyTransition);
        };
        state.policy = cursor.previous.take().map(PolicyRollback::into_cursor);
        Ok(())
    }

    pub fn validate(
        &self,
        request: &PrivilegedRequest,
    ) -> Result<OperationAdmission, OperationError> {
        if request.principal_binding != self.principal_binding
            || request.authority_epoch != self.authority_epoch
            || request.operation_id.lease_id != self.lease_id
        {
            return Err(OperationError::PrincipalMismatch);
        }
        if request.helper_epoch != self.helper_epoch {
            return Err(OperationError::HelperEpochMismatch);
        }
        if let Some(highest) = &self.highest {
            if highest.highest_id == request.operation_id {
                return if highest.highest_digest == request.digest
                    && highest.helper_epoch == request.helper_epoch
                {
                    Ok(OperationAdmission::Duplicate)
                } else {
                    Err(OperationError::DuplicateDigestMismatch)
                };
            }
            if request.sequence <= highest.highest_id.sequence {
                return Err(OperationError::SequenceReplay);
            }
        }
        self.validate_policy_transition(request)?;
        Ok(OperationAdmission::Fresh)
    }

    fn validate_policy_transition(
        &self,
        request: &PrivilegedRequest,
    ) -> Result<(), OperationError> {
        let PrivilegedOperation::NetworkPolicy(operation) = &request.operation else {
            return Ok(());
        };
        let current = self
            .highest
            .as_ref()
            .and_then(|state| state.policy.as_ref());
        match (operation, current) {
            (NetworkPolicyOperation::EstablishBlocking { policy, .. }, None) => {
                if policy.generation() == 0 {
                    return Err(OperationError::PolicyTransition);
                }
            }
            (NetworkPolicyOperation::EstablishBlocking { policy, .. }, Some(cursor)) => {
                if policy.generation() <= cursor.generation || !cursor.observed {
                    return Err(OperationError::PolicyTransition);
                }
            }
            (_, Some(cursor)) => {
                if operation.policy().generation() != cursor.generation
                    || operation.policy().authority_epoch() != Some(cursor.authority_epoch)
                    || operation.predecessor() != Some(cursor.predecessor())
                {
                    return Err(OperationError::PolicyTransition);
                }
                if operation.is_observation() {
                    if cursor.observed
                        || operation.policy().kind() != policy_kind_for_phase(cursor.phase)
                    {
                        return Err(OperationError::PolicyTransition);
                    }
                } else {
                    if !cursor.observed {
                        return Err(OperationError::ObservationBarrierRequired);
                    }
                    if operation.target_phase() != PolicyPhase::Released
                        && phase_rank(operation.target_phase()) <= phase_rank(cursor.phase)
                    {
                        return Err(OperationError::PolicyTransition);
                    }
                }
            }
            (_, None) => return Err(OperationError::PolicyTransition),
        }
        Ok(())
    }

    pub fn admit(
        &mut self,
        request: &PrivilegedRequest,
    ) -> Result<OperationAdmission, OperationError> {
        let admission = self.validate(request)?;
        if admission == OperationAdmission::Fresh {
            let prior_policy = self.highest.as_ref().and_then(|state| state.policy.clone());
            let policy = match &request.operation {
                PrivilegedOperation::NetworkPolicy(operation) => {
                    let mutation_projection = PolicyProjection::from_mutation(
                        operation,
                        prior_policy.as_ref().map(|prior| &prior.projection),
                    )?;
                    let previous = if mutation_projection.is_some()
                        || matches!(operation, NetworkPolicyOperation::ReleaseObsolete { .. })
                    {
                        prior_policy
                            .as_ref()
                            .and_then(PolicyRollback::from_observed)
                    } else {
                        prior_policy
                            .as_ref()
                            .and_then(|prior| prior.previous.clone())
                    };
                    let projection = mutation_projection
                        .or_else(|| prior_policy.as_ref().map(|prior| prior.projection.clone()))
                        .ok_or(OperationError::PolicyTransition)?;
                    Some(PolicyCursor {
                        authority_epoch: request.authority_epoch,
                        generation: operation.policy().generation(),
                        digest: PolicyDigest::of(operation),
                        phase: operation.target_phase(),
                        observed: false,
                        projection,
                        previous,
                        pending_release: match operation {
                            NetworkPolicyOperation::ReleaseObsolete { resources, .. } => {
                                resources.clone()
                            }
                            _ => Vec::new(),
                        },
                    })
                }
                _ => prior_policy,
            };
            self.highest = Some(ReplayHighWater {
                schema_version: CONTRACT_SCHEMA_VERSION,
                authority_epoch: self.authority_epoch,
                lease_id: self.lease_id,
                principal_binding: self.principal_binding,
                helper_epoch: self.helper_epoch,
                highest_id: request.operation_id.clone(),
                highest_digest: request.digest,
                policy,
            });
        }
        Ok(admission)
    }

    /// Commit an observation barrier only after an authenticated receipt has
    /// proven that the helper actually observed the requested policy resource.
    pub fn confirm_observation(
        &mut self,
        request: &PrivilegedRequest,
        receipt: &VerifiedReceipt,
        root: &RootAuthorityLedger,
    ) -> Result<(), OperationError> {
        let PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ObserveBarrier {
            policy,
            ..
        }) = request.operation()
        else {
            return Err(OperationError::InvalidObservationReceipt);
        };
        let Some(state) = &mut self.highest else {
            return Err(OperationError::InvalidObservationReceipt);
        };
        if state.highest_id != *request.operation_id()
            || state.highest_digest != *request.digest()
            || receipt.validate_against(request, root).is_err()
            || !receipt.observes(policy, ObservationState::Present)
        {
            return Err(OperationError::InvalidObservationReceipt);
        }
        let Some(cursor) = &mut state.policy else {
            return Err(OperationError::InvalidObservationReceipt);
        };
        cursor.observed = true;
        cursor.previous = None;
        Ok(())
    }

    /// Finish a release only after one authenticated observation proves the
    /// current protection remains present and every exact obsolete resource
    /// retained in the persisted cursor is absent.
    pub fn confirm_release(
        &mut self,
        request: &PrivilegedRequest,
        receipt: &VerifiedReceipt,
        root: &RootAuthorityLedger,
    ) -> Result<(), OperationError> {
        let PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ReleaseObsolete {
            policy,
            resources,
            ..
        }) = request.operation()
        else {
            return Err(OperationError::InvalidObservationReceipt);
        };
        let Some(state) = &mut self.highest else {
            return Err(OperationError::InvalidObservationReceipt);
        };
        let Some(cursor) = &mut state.policy else {
            return Err(OperationError::InvalidObservationReceipt);
        };
        if state.highest_id != *request.operation_id()
            || state.highest_digest != *request.digest()
            || cursor.phase != PolicyPhase::Released
            || cursor.pending_release != *resources
            || receipt.validate_against(request, root).is_err()
            || !receipt.observes(policy, ObservationState::Present)
            || cursor
                .pending_release
                .iter()
                .any(|resource| !receipt.observes(resource, ObservationState::Absent))
        {
            return Err(OperationError::InvalidObservationReceipt);
        }
        cursor.observed = true;
        cursor.pending_release.clear();
        cursor.previous = None;
        Ok(())
    }
}

const fn phase_rank(phase: PolicyPhase) -> u8 {
    match phase {
        PolicyPhase::Blocking => 0,
        PolicyPhase::Routes => 1,
        PolicyPhase::Dns => 2,
        PolicyPhase::Firewall => 3,
        PolicyPhase::Released => 4,
    }
}

const fn policy_kind_for_phase(phase: PolicyPhase) -> ResourceKind {
    match phase {
        PolicyPhase::Blocking | PolicyPhase::Firewall | PolicyPhase::Released => {
            ResourceKind::Firewall
        }
        PolicyPhase::Routes => ResourceKind::Routes,
        PolicyPhase::Dns => ResourceKind::Dns,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OperationError {
    #[error("{0}")]
    InvalidCounter(&'static str),
    #[error("invalid OS service instance claim")]
    InvalidServiceClaim,
    #[error("invalid kernel-derived peer process identity")]
    InvalidPeerIdentity,
    #[error("invalid root-owned authority ledger")]
    InvalidLease,
    #[error("daemon is not the service instance bound by the root authority ledger")]
    UntrustedDaemon,
    #[error("daemon principal, lease, or authority epoch does not match")]
    PrincipalMismatch,
    #[error("helper epoch does not match")]
    HelperEpochMismatch,
    #[error("request sequence was already superseded")]
    SequenceReplay,
    #[error("operation ID was reused with a different digest or helper epoch")]
    DuplicateDigestMismatch,
    #[error("resource is not valid for this operation")]
    ResourceScopeMismatch,
    #[error("privileged operation collection exceeds its fixed bound")]
    CollectionLimit,
    #[error("root replay high-water state is inconsistent with current authority")]
    InvalidReplayState,
    #[error("network policy predecessor or generation does not match persisted state")]
    PolicyTransition,
    #[error("network policy mutation requires a persisted observation barrier")]
    ObservationBarrierRequired,
    #[error("network policy observation was not proven by an authenticated receipt")]
    InvalidObservationReceipt,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::privileged::protocol_plan::{
        OpenVpnAuthFactors, OpenVpnPlan, OpenVpnRemote, OpenVpnRemoteSelection, OpenVpnTransport,
        ProtocolEndpoint, WireGuardInterfaceOptions, WireGuardPeerPlan, WireGuardPlan,
    };
    use crate::vortix_core::privileged::receipt::{
        AuthenticatedReceiptVerifier, ReceiptError, ReceiptLedger, ResourceObservation,
    };
    use crate::vortix_core::profile::{ProfileId, ProtocolKind};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn profile(byte: char) -> ProfileId {
        ProfileId::parse(byte.to_string().repeat(ProfileId::HEX_LEN)).unwrap()
    }

    fn authority() -> (RootAuthorityLedger, TrustedDaemonPrincipal) {
        let service = ServiceInstanceClaim::systemd(
            42,
            99,
            OperationDigest::of_bytes(b"verified executable"),
            [3; 32],
        )
        .unwrap();
        let claim = PeerProcessIdentity::untrusted_claim(1000, 42, 99).unwrap();
        let verified = U11PlatformAuthorityVerifier::test_fixture()
            .verify(1000, claim, &service)
            .unwrap();
        let root = RootAuthorityLedger::from_platform_verified(
            verified,
            BootScope::new([1; 16]),
            AuthorityEpoch(7),
            LeaseId::new([2; 32]),
        )
        .unwrap();
        let principal = root.principal();
        (root, principal)
    }

    fn start_operation(generation: u64) -> PrivilegedOperation {
        let peer = WireGuardPeerPlan::new(
            [7; 32],
            Some(ProtocolEndpoint::ip(SocketAddr::from(([198, 51, 100, 7], 51820))).unwrap()),
            Vec::new(),
            None,
        )
        .unwrap();
        PrivilegedOperation::StartTunnel(ProtocolPlan::WireGuard(
            WireGuardPlan::new(
                profile('a'),
                generation,
                Vec::new(),
                vec![peer],
                WireGuardInterfaceOptions::default(),
            )
            .unwrap(),
        ))
    }

    fn openvpn_start_operation(generation: u64) -> PrivilegedOperation {
        PrivilegedOperation::StartTunnel(ProtocolPlan::OpenVpn(
            OpenVpnPlan::new(
                profile('a'),
                generation,
                vec![OpenVpnRemote::new(
                    SocketAddr::from(([203, 0, 113, 9], 1194)),
                    OpenVpnTransport::Udp,
                )
                .unwrap()],
                OpenVpnRemoteSelection::Ordered,
                OpenVpnAuthFactors::certificate(),
                Vec::new(),
            )
            .unwrap(),
        ))
    }

    #[test]
    fn public_scalar_claims_do_not_mint_authority() {
        let service = ServiceInstanceClaim::systemd(
            42,
            99,
            OperationDigest::of_bytes(b"verified executable"),
            [3; 32],
        )
        .unwrap();
        let wrong = PeerProcessIdentity::untrusted_claim(1000, 42, 100).unwrap();
        assert!(U11PlatformAuthorityVerifier::test_fixture()
            .verify(1000, wrong, &service)
            .is_err());
        assert!(serde_json::from_value::<ServiceInstanceClaim>(
            serde_json::to_value(service).unwrap()
        )
        .is_ok());
        // RootAuthorityLedger and TrustedDaemonPrincipal intentionally have no
        // Deserialize implementation; decoded claims remain data only.
    }

    #[test]
    fn replay_baseline_cannot_reset_or_reuse_helper_epoch() {
        let (root, principal) = authority();
        let helper3 = HelperEpoch::new(3).unwrap();
        let baseline = root.unused_replay_baseline(&principal, helper3).unwrap();
        let mut guard = OperationGuard::resume(&principal, helper3, baseline).unwrap();
        let ninth = PrivilegedRequest::new(
            &principal,
            helper3,
            RequestSequence::new(9).unwrap(),
            PrivilegedOperation::Observe(Vec::new()),
        )
        .unwrap();
        assert_eq!(guard.admit(&ninth).unwrap(), OperationAdmission::Fresh);
        assert_eq!(guard.admit(&ninth).unwrap(), OperationAdmission::Duplicate);
        let checkpoint = guard.checkpoint().unwrap();

        assert!(OperationGuard::resume(
            &principal,
            helper3,
            root.loaded_replay_baseline(&principal, checkpoint.clone())
                .unwrap()
        )
        .is_err());
        assert!(OperationGuard::resume(
            &principal,
            HelperEpoch::new(2).unwrap(),
            root.loaded_replay_baseline(&principal, checkpoint.clone())
                .unwrap()
        )
        .is_err());

        let helper4 = HelperEpoch::new(4).unwrap();
        let restarted_baseline = root.loaded_replay_baseline(&principal, checkpoint).unwrap();
        let mut restarted =
            OperationGuard::resume(&principal, helper4, restarted_baseline).unwrap();
        let replay = PrivilegedRequest::new(
            &principal,
            helper4,
            RequestSequence::new(9).unwrap(),
            PrivilegedOperation::Observe(Vec::new()),
        )
        .unwrap();
        assert_eq!(
            restarted.admit(&replay),
            Err(OperationError::DuplicateDigestMismatch)
        );
        let lower = PrivilegedRequest::new(
            &principal,
            helper4,
            RequestSequence::new(8).unwrap(),
            PrivilegedOperation::Observe(Vec::new()),
        )
        .unwrap();
        assert_eq!(restarted.admit(&lower), Err(OperationError::SequenceReplay));
        let next = PrivilegedRequest::new(
            &principal,
            helper4,
            RequestSequence::new(10).unwrap(),
            PrivilegedOperation::Observe(Vec::new()),
        )
        .unwrap();
        assert_eq!(restarted.admit(&next).unwrap(), OperationAdmission::Fresh);
    }

    #[test]
    fn schema_versions_are_explicit_and_unknown_versions_fail() {
        let (root, principal) = authority();
        let helper = HelperEpoch::new(3).unwrap();
        let request = PrivilegedRequest::new(
            &principal,
            helper,
            RequestSequence::new(1).unwrap(),
            PrivilegedOperation::Observe(Vec::new()),
        )
        .unwrap();
        let mut value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["schema_version"], 3);
        value["schema_version"] = serde_json::json!(4);
        assert!(serde_json::from_value::<PrivilegedRequest>(value).is_err());

        let mut oversized = serde_json::to_value(&request).unwrap();
        oversized["operation"]["payload"] = serde_json::Value::Array(
            (1..=257)
                .map(|generation| {
                    serde_json::to_value(
                        ResourceObservationTarget::new(
                            ResourceTag::tunnel(profile('a'), generation).unwrap(),
                            Some(ProtocolKind::WireGuard),
                        )
                        .unwrap(),
                    )
                    .unwrap()
                })
                .collect(),
        );
        assert!(serde_json::from_value::<PrivilegedRequest>(oversized).is_err());

        let baseline = root.unused_replay_baseline(&principal, helper).unwrap();
        let mut value = serde_json::to_value(baseline.0).unwrap();
        value["record"]["schema_version"] = serde_json::json!(0);
        assert!(serde_json::from_value::<ReplayRecord>(value).is_err());
    }

    #[test]
    fn observation_targets_are_unique_by_resource_not_protocol_label() {
        let (_root, principal) = authority();
        let tunnel = ResourceTag::tunnel(profile('a'), 4).unwrap();
        let targets = [ProtocolKind::WireGuard, ProtocolKind::OpenVpn]
            .map(|protocol| ResourceObservationTarget::new(tunnel.clone(), Some(protocol)).unwrap())
            .to_vec();

        assert_eq!(
            PrivilegedRequest::new(
                &principal,
                HelperEpoch::new(3).unwrap(),
                RequestSequence::new(1).unwrap(),
                PrivilegedOperation::Observe(targets),
            )
            .unwrap_err(),
            OperationError::ResourceScopeMismatch
        );
    }

    #[test]
    fn firewall_contract_requires_typed_endpoint_and_rejects_physical_names() {
        let (_root, principal) = authority();
        let tunnel = ResourceTag::tunnel(profile('a'), 4).unwrap();
        let empty_active = PrivilegedFirewallTunnel::new(
            tunnel.clone(),
            Vec::new(),
            Vec::new(),
            PrivilegedFirewallRole::Primary,
        )
        .unwrap();
        assert_eq!(
            PrivilegedRequest::new(
                &principal,
                HelperEpoch::new(3).unwrap(),
                RequestSequence::new(1).unwrap(),
                PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::EstablishBlocking {
                    policy: ResourceTag::topology(AuthorityEpoch(7), 1, ResourceKind::Firewall,)
                        .unwrap(),
                    tunnels: vec![empty_active],
                }),
            )
            .unwrap_err(),
            OperationError::ResourceScopeMismatch
        );

        let pending = PrivilegedFirewallTunnel::new(
            tunnel,
            vec!["198.51.100.1".parse().unwrap()],
            Vec::new(),
            PrivilegedFirewallRole::PendingEndpoint,
        )
        .unwrap();
        let request = PrivilegedRequest::new(
            &principal,
            HelperEpoch::new(3).unwrap(),
            RequestSequence::new(1).unwrap(),
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::EstablishBlocking {
                policy: ResourceTag::topology(AuthorityEpoch(7), 1, ResourceKind::Firewall)
                    .unwrap(),
                tunnels: vec![pending],
            }),
        )
        .unwrap();
        let mut wire = serde_json::to_value(request).unwrap();
        wire["operation"]["payload"]["tunnels"][0]["interface"] = serde_json::json!("foreign0");
        assert!(serde_json::from_value::<PrivilegedRequest>(wire).is_err());
    }

    #[test]
    fn firewall_mode_uses_the_canonical_kill_switch_slug() {
        let policy = ResourceTag::topology(AuthorityEpoch(7), 1, ResourceKind::Firewall).unwrap();
        let operation = NetworkPolicyOperation::ApplyFirewall {
            policy,
            mode: KillSwitchMode::Auto,
            tunnels: Vec::new(),
            predecessor: PolicyPredecessor {
                digest: PolicyDigest(OperationDigest::from_sha256([3; 32])),
                phase: PolicyPhase::Dns,
                observed: true,
            },
        };
        let mut wire = serde_json::to_value(&operation).unwrap();

        assert_eq!(wire["mode"], "block-on-drop");
        wire["mode"] = serde_json::json!("block_on_drop");
        assert!(serde_json::from_value::<NetworkPolicyOperation>(wire).is_err());
    }

    #[test]
    fn canonical_v3_digest_golden_and_deterministic_mutations() {
        let service = ServiceInstanceClaim::systemd(
            75,
            7_500,
            OperationDigest::of_bytes(b"root-owned-vortix"),
            [3; 32],
        )
        .unwrap();
        let verified = U11PlatformAuthorityVerifier::test_fixture()
            .verify(
                1000,
                PeerProcessIdentity::untrusted_claim(1000, 75, 7_500).unwrap(),
                &service,
            )
            .unwrap();
        let root = RootAuthorityLedger::from_platform_verified(
            verified,
            BootScope::new([1; 16]),
            AuthorityEpoch(7),
            LeaseId::new([2; 32]),
        )
        .unwrap();
        let principal = root.principal();
        let base = PrivilegedRequest::new(
            &principal,
            HelperEpoch::new(3).unwrap(),
            RequestSequence::new(1).unwrap(),
            PrivilegedOperation::Observe(Vec::new()),
        )
        .unwrap();
        assert_eq!(
            base.digest().as_bytes(),
            [
                7, 32, 90, 185, 156, 104, 54, 76, 120, 38, 196, 92, 44, 14, 207, 91, 116, 169, 218,
                47, 164, 203, 141, 178, 21, 220, 128, 177, 58, 190, 12, 157,
            ]
        );
        for mutated in [
            PrivilegedRequest::new(
                &principal,
                HelperEpoch::new(4).unwrap(),
                RequestSequence::new(1).unwrap(),
                PrivilegedOperation::Observe(Vec::new()),
            )
            .unwrap(),
            PrivilegedRequest::new(
                &principal,
                HelperEpoch::new(3).unwrap(),
                RequestSequence::new(2).unwrap(),
                PrivilegedOperation::Observe(Vec::new()),
            )
            .unwrap(),
            PrivilegedRequest::new(
                &principal,
                HelperEpoch::new(3).unwrap(),
                RequestSequence::new(1).unwrap(),
                PrivilegedOperation::CleanupOwned(Vec::new()),
            )
            .unwrap(),
        ] {
            assert_ne!(mutated.digest(), base.digest());
        }
    }

    #[test]
    fn wireguard_receipts_require_interface_only_and_authentication() {
        let (root, principal) = authority();
        let request = PrivilegedRequest::new(
            &principal,
            HelperEpoch::new(3).unwrap(),
            RequestSequence::new(1).unwrap(),
            start_operation(4),
        )
        .unwrap();
        let receipts = ReceiptLedger::new(&root, &principal).unwrap();
        let tunnel = ResourceTag::tunnel(profile('a'), 4).unwrap();
        let group = ResourceTag::profile(profile('a'), 4, ResourceKind::ProcessGroup).unwrap();
        assert_eq!(
            receipts.applied(&request, Vec::new()).unwrap_err(),
            ReceiptError::MissingRequiredResource
        );
        let verified_receipt = receipts.applied(&request, vec![tunnel.clone()]).unwrap();
        assert_eq!(
            receipts
                .applied(
                    &request,
                    vec![
                        tunnel.clone(),
                        group.clone(),
                        ResourceTag::profile(profile('b'), 4, ResourceKind::RuntimeSecret).unwrap(),
                    ],
                )
                .unwrap_err(),
            ReceiptError::UnrelatedResource
        );
        assert_eq!(
            receipts
                .applied(&request, vec![tunnel.clone(), group.clone()])
                .unwrap_err(),
            ReceiptError::MissingRequiredResource
        );

        let wire: crate::vortix_core::privileged::receipt::UntrustedReceipt =
            serde_json::from_value(serde_json::to_value(&verified_receipt).unwrap()).unwrap();
        let receipt_verifier = AuthenticatedReceiptVerifier::from_authenticated_helper(
            root.authority_epoch(),
            root.lease_id(),
            request.helper_epoch(),
        );
        receipt_verifier.verify(&request, wire).unwrap();

        let mut unsupported = serde_json::to_value(&verified_receipt).unwrap();
        unsupported["schema_version"] = serde_json::json!(4);
        assert!(
            serde_json::from_value::<crate::vortix_core::privileged::receipt::UntrustedReceipt>(
                unsupported
            )
            .is_err()
        );

        let mut forged = serde_json::to_value(&verified_receipt).unwrap();
        forged["digest"][0] = serde_json::json!(255);
        let forged = serde_json::from_value(forged).unwrap();
        assert_eq!(
            receipt_verifier.verify(&request, forged).unwrap_err(),
            ReceiptError::AuthorityMismatch
        );

        let mut oversized = serde_json::to_value(&verified_receipt).unwrap();
        oversized["outcome"]["detail"] = serde_json::Value::Array(
            (1..=257)
                .map(|generation| {
                    serde_json::json!({
                        "resource": ResourceTag::tunnel(profile('a'), generation).unwrap(),
                        "authority_epoch": 7,
                        "lease_id": vec![2; 32],
                        "acquired_sequence": 1,
                    })
                })
                .collect(),
        );
        assert!(
            serde_json::from_value::<crate::vortix_core::privileged::receipt::UntrustedReceipt>(
                oversized
            )
            .is_err()
        );

        let observe = PrivilegedRequest::new(
            &principal,
            HelperEpoch::new(3).unwrap(),
            RequestSequence::new(2).unwrap(),
            PrivilegedOperation::Observe(vec![ResourceObservationTarget::new(
                ResourceTag::tunnel(profile('a'), 4).unwrap(),
                Some(ProtocolKind::WireGuard),
            )
            .unwrap()]),
        )
        .unwrap();
        assert_eq!(
            receipts.applied(&observe, Vec::new()).unwrap_err(),
            ReceiptError::OutcomeMismatch
        );
    }

    #[test]
    fn openvpn_receipts_require_tunnel_and_foreground_group() {
        let (root, principal) = authority();
        let receipts = ReceiptLedger::new(&root, &principal).unwrap();
        let request = PrivilegedRequest::new(
            &principal,
            HelperEpoch::new(3).unwrap(),
            RequestSequence::new(1).unwrap(),
            openvpn_start_operation(5),
        )
        .unwrap();
        let tunnel = ResourceTag::tunnel(profile('a'), 5).unwrap();
        let group = ResourceTag::profile(profile('a'), 5, ResourceKind::ProcessGroup).unwrap();

        assert_eq!(
            receipts
                .applied(&request, vec![tunnel.clone()])
                .unwrap_err(),
            ReceiptError::MissingRequiredResource
        );
        receipts.applied(&request, vec![tunnel, group]).unwrap();
    }

    #[test]
    fn destructive_receipts_require_exact_absence_observations() {
        let (root, principal) = authority();
        let receipts = ReceiptLedger::new(&root, &principal).unwrap();
        let stopped = ResourceTag::tunnel(profile('a'), 4).unwrap();
        let stop = PrivilegedRequest::new(
            &principal,
            HelperEpoch::new(3).unwrap(),
            RequestSequence::new(1).unwrap(),
            PrivilegedOperation::StopTunnel(stopped.clone()),
        )
        .unwrap();
        assert_eq!(
            receipts.applied(&stop, Vec::new()).unwrap_err(),
            ReceiptError::OutcomeMismatch
        );
        assert_eq!(
            receipts
                .observed(
                    &stop,
                    vec![
                        ResourceObservation::new(stopped.clone(), ObservationState::Present, 1)
                            .unwrap(),
                    ],
                )
                .unwrap_err(),
            ReceiptError::OutcomeMismatch
        );
        receipts
            .observed(
                &stop,
                vec![
                    ResourceObservation::new(stopped.clone(), ObservationState::Absent, 1).unwrap(),
                ],
            )
            .unwrap();

        let group = ResourceTag::profile(profile('a'), 4, ResourceKind::ProcessGroup).unwrap();
        let cleanup = PrivilegedRequest::new(
            &principal,
            HelperEpoch::new(3).unwrap(),
            RequestSequence::new(2).unwrap(),
            PrivilegedOperation::CleanupOwned(vec![stopped.clone(), group.clone()]),
        )
        .unwrap();
        assert_eq!(
            receipts
                .observed(
                    &cleanup,
                    vec![
                        ResourceObservation::new(stopped.clone(), ObservationState::Absent, 1)
                            .unwrap(),
                        ResourceObservation::new(group.clone(), ObservationState::Present, 1)
                            .unwrap(),
                    ],
                )
                .unwrap_err(),
            ReceiptError::OutcomeMismatch
        );
        receipts
            .observed(
                &cleanup,
                vec![
                    ResourceObservation::new(stopped, ObservationState::Absent, 1).unwrap(),
                    ResourceObservation::new(group, ObservationState::Absent, 1).unwrap(),
                ],
            )
            .unwrap();
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one end-to-end release test retains the crash/restart proof chain"
    )]
    fn release_requires_current_protection_and_every_obsolete_resource_absent() {
        let (root, principal) = authority();
        let helper = HelperEpoch::new(3).unwrap();
        let mut guard = OperationGuard::resume(
            &principal,
            helper,
            root.unused_replay_baseline(&principal, helper).unwrap(),
        )
        .unwrap();
        let tunnel = ResourceTag::tunnel(profile('a'), 2).unwrap();
        let current = ResourceTag::topology(AuthorityEpoch(7), 2, ResourceKind::Firewall).unwrap();
        let obsolete_dns = ResourceTag::topology(AuthorityEpoch(7), 1, ResourceKind::Dns).unwrap();
        let obsolete_routes =
            ResourceTag::topology(AuthorityEpoch(7), 1, ResourceKind::Routes).unwrap();
        let establish = PrivilegedRequest::new(
            &principal,
            helper,
            RequestSequence::new(1).unwrap(),
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::EstablishBlocking {
                policy: current.clone(),
                tunnels: vec![PrivilegedFirewallTunnel::new(
                    tunnel,
                    vec!["198.51.100.1".parse().unwrap()],
                    Vec::new(),
                    PrivilegedFirewallRole::PendingEndpoint,
                )
                .unwrap()],
            }),
        )
        .unwrap();
        guard.admit(&establish).unwrap();
        let observe = PrivilegedRequest::new(
            &principal,
            helper,
            RequestSequence::new(2).unwrap(),
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ObserveBarrier {
                policy: current.clone(),
                predecessor: guard.policy_predecessor().unwrap(),
            }),
        )
        .unwrap();
        guard.admit(&observe).unwrap();
        let receipts = ReceiptLedger::new(&root, &principal).unwrap();
        let observed = receipts
            .observed(
                &observe,
                vec![
                    ResourceObservation::new(current.clone(), ObservationState::Present, 1)
                        .unwrap(),
                ],
            )
            .unwrap();
        guard
            .confirm_observation(&observe, &observed, &root)
            .unwrap();
        assert_eq!(
            PrivilegedRequest::new(
                &principal,
                helper,
                RequestSequence::new(3).unwrap(),
                PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ReleaseObsolete {
                    policy: current.clone(),
                    resources: Vec::new(),
                    predecessor: guard.policy_predecessor().unwrap(),
                }),
            )
            .unwrap_err(),
            OperationError::ResourceScopeMismatch
        );
        let release = PrivilegedRequest::new(
            &principal,
            helper,
            RequestSequence::new(3).unwrap(),
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ReleaseObsolete {
                policy: current.clone(),
                resources: vec![obsolete_dns.clone(), obsolete_routes.clone()],
                predecessor: guard.policy_predecessor().unwrap(),
            }),
        )
        .unwrap();
        guard.admit(&release).unwrap();
        let persisted = serde_json::to_value(guard.checkpoint().unwrap()).unwrap();
        let persisted_text = persisted.to_string();
        assert!(persisted_text.contains("projection"));
        assert!(persisted_text.contains("dns"));
        assert!(persisted_text.contains("routes"));
        let record: ReplayRecord = serde_json::from_value(persisted).unwrap();
        let baseline = root.loaded_replay_baseline(&principal, record).unwrap();
        let mut restarted =
            OperationGuard::resume(&principal, HelperEpoch::new(4).unwrap(), baseline).unwrap();
        assert!(restarted.policy_projection().is_some());
        assert_eq!(
            receipts
                .observed(
                    &release,
                    vec![
                        ResourceObservation::new(current.clone(), ObservationState::Present, 2)
                            .unwrap(),
                        ResourceObservation::new(
                            obsolete_dns.clone(),
                            ObservationState::Absent,
                            2,
                        )
                        .unwrap(),
                    ],
                )
                .unwrap_err(),
            ReceiptError::MissingRequiredResource
        );
        let proof = receipts
            .observed(
                &release,
                vec![
                    ResourceObservation::new(current, ObservationState::Present, 3).unwrap(),
                    ResourceObservation::new(obsolete_dns, ObservationState::Absent, 3).unwrap(),
                    ResourceObservation::new(obsolete_routes, ObservationState::Absent, 3).unwrap(),
                ],
            )
            .unwrap();
        restarted.confirm_release(&release, &proof, &root).unwrap();
    }

    #[test]
    fn invalid_public_cidr_literals_fail_every_privileged_constructor() {
        let invalid = Cidr {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 33,
        };
        let tunnel = ResourceTag::tunnel(profile('a'), 1).unwrap();
        assert!(ScopedRoute::new(invalid, tunnel).is_err());
        assert!(
            crate::vortix_core::privileged::protocol_plan::OpenVpnRoute::new(invalid, None, None)
                .is_err()
        );
        assert!(WireGuardPeerPlan::new([7; 32], None, vec![invalid], None).is_err());
        assert!(WireGuardPlan::new(
            profile('a'),
            1,
            vec![invalid],
            vec![WireGuardPeerPlan::new([7; 32], None, Vec::new(), None).unwrap()],
            WireGuardInterfaceOptions::default(),
        )
        .is_err());
    }

    #[test]
    fn route_projection_persists_and_validates_blocking_subjects() {
        let tunnel = ResourceTag::tunnel(profile('a'), 1).unwrap();
        let declared: Cidr = "10.0.0.0/8".parse().unwrap();
        let subjects = vec![PrivilegedFirewallTunnel::new(
            tunnel.clone(),
            vec!["198.51.100.7".parse().unwrap()],
            vec![declared],
            PrivilegedFirewallRole::PendingEndpoint,
        )
        .unwrap()];
        let blocking = PolicyProjection::Blocking {
            policy: ResourceTag::topology(AuthorityEpoch(7), 1, ResourceKind::Firewall).unwrap(),
            tunnels: subjects.clone(),
        };
        let routes = ResourceTag::topology(AuthorityEpoch(7), 1, ResourceKind::Routes).unwrap();
        let operation = NetworkPolicyOperation::ApplyRoutes {
            policy: routes.clone(),
            routes: vec![ScopedRoute::new(declared, tunnel.clone()).unwrap()],
            predecessor: PolicyPredecessor {
                digest: blocking.digest(),
                phase: PolicyPhase::Blocking,
                observed: true,
            },
        };

        let projection = PolicyProjection::from_mutation(&operation, Some(&blocking))
            .unwrap()
            .unwrap();
        assert_eq!(
            projection,
            PolicyProjection::Routes {
                policy: routes,
                routes: vec![ScopedRoute::new(declared, tunnel).unwrap()],
                tunnels: subjects,
            }
        );

        let foreign = ResourceTag::tunnel(profile('b'), 1).unwrap();
        let invalid = NetworkPolicyOperation::ApplyRoutes {
            policy: ResourceTag::topology(AuthorityEpoch(7), 1, ResourceKind::Routes).unwrap(),
            routes: vec![ScopedRoute::new(declared, foreign).unwrap()],
            predecessor: PolicyPredecessor {
                digest: blocking.digest(),
                phase: PolicyPhase::Blocking,
                observed: true,
            },
        };
        assert!(PolicyProjection::from_mutation(&invalid, Some(&blocking)).is_err());
    }

    #[test]
    fn scoped_route_canonicalizes_host_bits_at_construction_and_decode() {
        let tunnel = ResourceTag::tunnel(profile('a'), 1).unwrap();
        let noncanonical: Cidr = "10.2.3.4/8".parse().unwrap();
        let route = ScopedRoute::new(noncanonical, tunnel.clone()).unwrap();
        assert_eq!(route.destination(), "10.0.0.0/8".parse().unwrap());

        let encoded = serde_json::json!({
            "destination": { "addr": "10.2.3.4", "prefix_len": 8 },
            "tunnel": tunnel,
        });
        let decoded: ScopedRoute = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.destination(), "10.0.0.0/8".parse().unwrap());
    }
}
