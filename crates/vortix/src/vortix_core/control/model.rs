//! Canonical desired/observed/effective, operation, challenge, and event model.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::vortix_core::engine::registry::Conflict;
use crate::vortix_core::engine::state::{ConnectionHealth, DegradedReason, FailureReason};
use crate::vortix_core::privileged::OpenVpnRouteEvidence;
use crate::vortix_core::profile::{ProfileId, ProtocolKind};
use crate::vortix_core::state::killswitch::KillSwitchMode;
use crate::vortix_core::state::KillSwitchState;

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_PROTECTION_AGE_MILLIS: u64 = 5_000;

macro_rules! opaque_id {
    ($name:ident, $prefix:literal) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(u64);

        impl $name {
            pub(crate) const fn from_counter(value: u64) -> Self {
                Self(value)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, concat!($prefix, "-{:016x}"), self.0)
            }
        }
    };
}

opaque_id!(ChallengeId, "challenge");

/// Opaque operation identity scoped by the monotonic authority epoch.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct OperationId(String);

impl OperationId {
    #[must_use]
    pub fn parse(value: impl Into<String>) -> Option<Self> {
        let value = Self(value.into());
        value.sequence().map(|_| value)
    }

    pub(crate) fn from_parts(authority_epoch: AuthorityEpoch, sequence: u64) -> Self {
        Self(format!("op-{:016x}-{sequence:016x}", authority_epoch.0))
    }

    pub(crate) fn sequence(&self) -> Option<u64> {
        parse_scoped_id(&self.0, "op").map(|(_, sequence)| sequence)
    }

    pub(crate) fn authority_epoch(&self) -> Option<AuthorityEpoch> {
        parse_scoped_id(&self.0, "op").map(|(epoch, _)| AuthorityEpoch(epoch))
    }
}

impl<'de> Deserialize<'de> for OperationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Self(String::deserialize(deserializer)?);
        value
            .sequence()
            .map(|_| value)
            .ok_or_else(|| serde::de::Error::custom("invalid service-issued operation ID"))
    }
}

impl std::fmt::Display for OperationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ClientId(String);

impl ClientId {
    pub(crate) fn from_parts(authority_epoch: AuthorityEpoch, sequence: u64) -> Self {
        Self(format!("client-{:016x}-{sequence:016x}", authority_epoch.0))
    }

    pub(crate) fn is_valid(&self) -> bool {
        parse_scoped_id(&self.0, "client").is_some()
    }

    pub(crate) fn sequence(&self) -> Option<u64> {
        parse_scoped_id(&self.0, "client").map(|(_, sequence)| sequence)
    }

    pub(crate) fn authority_epoch(&self) -> Option<AuthorityEpoch> {
        parse_scoped_id(&self.0, "client").map(|(epoch, _)| AuthorityEpoch(epoch))
    }
}

fn parse_scoped_id(value: &str, prefix: &str) -> Option<(u64, u64)> {
    let rest = value.strip_prefix(prefix)?.strip_prefix('-')?;
    let (epoch, sequence) = rest.split_once('-')?;
    if epoch.len() != 16
        || sequence.len() != 16
        || !epoch.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !sequence.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some((
        u64::from_str_radix(epoch, 16).ok()?,
        u64::from_str_radix(sequence, 16).ok()?,
    ))
}

impl<'de> Deserialize<'de> for ClientId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Self(String::deserialize(deserializer)?);
        if value.is_valid() {
            Ok(value)
        } else {
            Err(serde::de::Error::custom("invalid service-issued client ID"))
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthorityEpoch(pub u64);

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyDigest(pub String);

impl PolicyDigest {
    #[must_use]
    pub(crate) fn sha256(bytes: &[u8]) -> Self {
        use sha2::Digest as _;

        let digest = sha2::Sha256::digest(bytes);
        let mut encoded = String::with_capacity(71);
        encoded.push_str("sha256:");
        for byte in digest {
            use std::fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").expect("String write");
        }
        Self(encoded)
    }

    pub(crate) fn is_valid(&self) -> bool {
        self.0.len() <= 128
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestedTunnelState {
    Connected,
    Disconnected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredState {
    pub generation: u64,
    pub tunnels: BTreeMap<ProfileId, RequestedTunnelState>,
    #[serde(with = "crate::vortix_core::state::killswitch::serde_mode_slug")]
    pub kill_switch: KillSwitchMode,
    pub authority_epoch: AuthorityEpoch,
    pub policy_digest: PolicyDigest,
    /// User-confirmed topology conflicts, keyed by the profile whose
    /// connection was admitted. The acknowledgement is durable so a
    /// supervised reconnect cannot silently lose the user's exact consent.
    #[serde(default)]
    pub conflict_acknowledgements: BTreeMap<ProfileId, Conflict>,
}

impl Default for DesiredState {
    fn default() -> Self {
        Self {
            generation: 0,
            tunnels: BTreeMap::new(),
            kill_switch: KillSwitchMode::Off,
            authority_epoch: AuthorityEpoch::default(),
            policy_digest: PolicyDigest::default(),
            conflict_acknowledgements: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionEvidence {
    pub desired_generation: u64,
    pub authority_epoch: AuthorityEpoch,
    pub policy_digest: PolicyDigest,
    pub observed_at_millis: u64,
    pub interface: GateEvidence,
    pub route: GateEvidence,
    pub dns: GateEvidence,
    pub firewall: GateEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateEvidence {
    Unverified,
    Verified,
}

impl ProtectionEvidence {
    #[must_use]
    pub const fn all_gates_verified(&self) -> bool {
        matches!(self.interface, GateEvidence::Verified)
            && matches!(self.route, GateEvidence::Verified)
            && matches!(self.dns, GateEvidence::Verified)
            && matches!(self.firewall, GateEvidence::Verified)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ObservedState {
    pub evidence: Option<ProtectionEvidence>,
    /// Authority-clock receipt time for the current protection evidence.
    pub evidence_received_at_millis: Option<u64>,
    /// Observer-owned tunnel facts. They never overwrite desired intent.
    pub tunnels: BTreeMap<ProfileId, ObservedTunnel>,
    /// Redacted, user-visible kernel/session metadata for renderer parity.
    /// Process ownership, teardown configuration, and DNS capabilities remain
    /// skipped by the reused engine details serde contract.
    #[serde(default)]
    pub tunnel_details: BTreeMap<ProfileId, ObservedTunnelDetails>,
    /// Latest kernel default-route observation used to derive one primary
    /// tunnel (or an explicit no-primary projection).
    #[serde(default)]
    pub default_route: Option<ObservedDefaultRoute>,
    /// Protocol-authoritative `WireGuard` evidence, fenced to the current
    /// desired generation. Scanner presence can never populate this map.
    #[serde(default)]
    pub wireguard_handshakes:
        BTreeMap<ProfileId, crate::vortix_core::ports::tunnel::HandshakeEvidence>,
    /// Per-peer probes issued by the exact successful protocol attempt.
    #[serde(default)]
    pub wireguard_probe_receipts:
        BTreeMap<ProfileId, Vec<crate::vortix_core::ports::tunnel::ProbeReceipt>>,
    /// Authenticated `OpenVPN` route truth fenced to the successful tunnel generation.
    #[serde(default)]
    pub openvpn_routes: BTreeMap<ProfileId, ObservedOpenVpnRoutes>,
    /// Ongoing typed health fenced to the successful desired generation.
    /// Snapshot subscribers consume this same record as CLI/TUI projections.
    #[serde(default)]
    pub connection_health: BTreeMap<ProfileId, ObservedConnectionHealth>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedOpenVpnRoutes {
    pub desired_generation: u64,
    pub evidence: OpenVpnRouteEvidence,
}

/// Generation-consistent ongoing health published by the control owner.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservedConnectionHealth {
    pub desired_generation: u64,
    pub health: ConnectionHealth,
    pub observed_at_millis: u64,
    pub received_at_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedTunnel {
    pub active: bool,
    pub interface_name: Option<String>,
    pub observed_at_millis: u64,
    /// Authority-clock receipt time. Observer clocks are never used for
    /// ordering or deadlines.
    pub received_at_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservedTunnelDetails {
    pub details: crate::vortix_core::engine::state::DetailedConnectionInfo,
    pub started_at: Option<SystemTime>,
    pub observed_at_millis: u64,
    pub received_at_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedDefaultRoute {
    pub interface_name: Option<String>,
    pub observed_at_millis: u64,
    pub received_at_millis: u64,
}

/// Protection gates invalidated by one atomic drift observation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // A gate bit-set is clearer than four ad-hoc variants.
pub struct DriftGates {
    pub interface: bool,
    pub route: bool,
    pub dns: bool,
    pub firewall: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionStatus {
    Unknown,
    Unprotected,
    Degraded,
    Protected,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Freshness {
    pub observed_at_millis: Option<u64>,
    pub age_millis: Option<u64>,
    pub ceiling_millis: u64,
    pub current: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveState {
    pub protection: ProtectionStatus,
    pub desired_generation: u64,
    pub authority_epoch: AuthorityEpoch,
    pub policy_digest: PolicyDigest,
    pub freshness: Freshness,
    /// Policy-owner truth for the effective kill-switch state. `None` means
    /// the authority has not yet produced enough evidence to make a claim;
    /// clients must not reinterpret generic protection as a firewall state.
    #[serde(default)]
    pub kill_switch: Option<KillSwitchState>,
}

impl Default for EffectiveState {
    fn default() -> Self {
        Self {
            protection: ProtectionStatus::Unknown,
            desired_generation: 0,
            authority_epoch: AuthorityEpoch::default(),
            policy_digest: PolicyDigest::default(),
            freshness: Freshness {
                ceiling_millis: MAX_PROTECTION_AGE_MILLIS,
                ..Freshness::default()
            },
            kill_switch: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Admitted,
    WaitingForObservation,
    Succeeded,
    Failed,
    Cancelled,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationFailure {
    Timeout,
    Rejected,
    /// A managed `WireGuard` attempt failed its cryptographic liveness gate
    /// after exact-attempt cleanup was confirmed.
    HandshakeFailed,
    ObservationFailed,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationResult {
    ObservedConvergence,
    ProfileMutationApplied,
    /// Storage committed after the admitted deadline. The operation remains
    /// expired, but callers must not mistake the durable side effect for an
    /// unapplied timeout and retry it blindly.
    ProfileMutationAppliedAfterDeadline,
    Failed(OperationFailure),
    Cancelled,
    Expired,
}

impl OperationStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::WaitingForObservation => "waiting_for_observation",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::Expired
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRecord {
    pub id: OperationId,
    pub idempotency_key: crate::vortix_core::control::command::IdempotencyKey,
    pub client_id: ClientId,
    /// Digest of the command's canonical semantic representation. Deadlines
    /// are intentionally excluded so a retry can extend its wait budget.
    pub command_digest: PolicyDigest,
    pub authority_epoch: AuthorityEpoch,
    pub desired_generation: u64,
    pub admitted_at_millis: u64,
    pub deadline_millis: u64,
    /// The bounded subset of desired state this operation requested. Older
    /// persisted records deserialize as generation-scoped so they can never
    /// be falsely completed by evidence for a later desired generation.
    #[serde(default)]
    pub intent: OperationIntent,
    pub status: OperationStatus,
    pub result: Option<OperationResult>,
}

/// Durable completion scope for an admitted operation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum OperationIntent {
    /// Backward-compatible scope for records written before intent was
    /// persisted. Only evidence for the record's own generation may satisfy
    /// it.
    #[default]
    GenerationScoped,
    /// The command-owned subset of desired state. Unmentioned profiles and
    /// policy fields may change without superseding this operation.
    DesiredSubset {
        #[serde(default)]
        tunnels: BTreeMap<ProfileId, RequestedTunnelState>,
        #[serde(default, with = "serde_optional_killswitch_slug")]
        kill_switch: Option<KillSwitchMode>,
    },
    /// Service-owned recovery after a canonically managed tunnel vanished.
    /// Persisting this distinction ensures a same-boot restart re-enters the
    /// pre-block phase instead of treating the operation as an ordinary
    /// reconnect.
    UnexpectedRecovery {
        profile_id: ProfileId,
        #[serde(default)]
        tunnels: BTreeMap<ProfileId, RequestedTunnelState>,
        #[serde(default, with = "serde_optional_killswitch_slug")]
        kill_switch: Option<KillSwitchMode>,
    },
    /// Filesystem/catalog mutation. The prepared import body remains in the
    /// injected executor and is never serialized here.
    ProfileMutation { profile_id: ProfileId },
}

mod serde_optional_killswitch_slug {
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

    use crate::vortix_core::state::killswitch::KillSwitchMode;

    #[allow(
        clippy::ref_option,
        clippy::trivially_copy_pass_by_ref,
        reason = "serde adapters receive a shared reference to the annotated field"
    )]
    pub fn serialize<S>(mode: &Option<KillSwitchMode>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match mode {
            Some(mode) => serializer.serialize_some(mode.cli_verb()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<KillSwitchMode>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|slug| {
                KillSwitchMode::from_cli_verb(&slug).ok_or_else(|| {
                    D::Error::custom(format_args!(
                        "invalid kill-switch mode `{slug}`; use off, block-on-drop, vpn-only"
                    ))
                })
            })
            .transpose()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionOutcome {
    /// Success backed by a fresh observation, never by dispatch alone.
    ObservedSuccess(ProtectionEvidence),
    Failed(OperationFailure),
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationCompletion {
    pub operation_id: OperationId,
    pub desired_generation: u64,
    pub outcome: CompletionOutcome,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Observation {
    Protection(ProtectionEvidence),
    Tunnel {
        profile_id: ProfileId,
        active: bool,
        interface_name: Option<String>,
        observed_at_millis: u64,
        /// Fresh, matching evidence supplied in the same owner transition can
        /// close gates invalidated by this tunnel change without a false
        /// protected publication between the two facts.
        protection: Option<ProtectionEvidence>,
    },
    /// Rich, redacted session metadata observed alongside tunnel presence.
    /// It can enrich a projection but can never create connection truth.
    TunnelDetails {
        profile_id: ProfileId,
        details: Box<crate::vortix_core::engine::state::DetailedConnectionInfo>,
        started_at: Option<SystemTime>,
        observed_at_millis: u64,
    },
    /// Kernel default-route interface observation used for canonical role
    /// projection. `None` is an explicit no-default-route observation.
    DefaultRoute {
        interface_name: Option<String>,
        observed_at_millis: u64,
    },
    Drift {
        profile_id: Option<ProfileId>,
        gates: DriftGates,
        observed_at_millis: u64,
        protection: Option<ProtectionEvidence>,
    },
    /// Typed ongoing tunnel health. It cannot create connection truth and is
    /// accepted only for the current desired generation.
    ConnectionHealth {
        profile_id: ProfileId,
        desired_generation: u64,
        health: ConnectionHealth,
        observed_at_millis: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    TwoFactorCode,
    Passphrase,
    Generic { label: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeRecord {
    pub id: ChallengeId,
    pub profile_id: ProfileId,
    pub operation_id: OperationId,
    pub kind: ChallengeKind,
    pub label: String,
    pub authorized_client: ClientId,
    pub created_at_millis: u64,
    pub expires_at_millis: u64,
}

/// Disposable notification vocabulary. Authoritative state is always the
/// watch snapshot; this enum contains no credential material.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ControlEvent {
    /// Committed lifecycle fact for asynchronous, unprivileged observers.
    Lifecycle {
        fact: crate::vortix_core::control::hooks::LifecycleFact,
    },
    OperationAdmitted {
        operation_id: OperationId,
        desired_generation: u64,
    },
    OperationCompleted {
        operation_id: OperationId,
        status: OperationStatus,
    },
    DesiredStateChanged {
        desired_generation: u64,
    },
    ChallengeIssued {
        challenge: ChallengeRecord,
    },
    ChallengeResolved {
        challenge_id: ChallengeId,
    },
    ChallengeExpired {
        challenge_id: ChallengeId,
    },
    ChallengeCancelled {
        challenge_id: ChallengeId,
    },
    ConnectAttemptStarted {
        profile_id: ProfileId,
        protocol: ProtocolKind,
        attempt: u32,
    },
    ConnectAttemptFailed {
        profile_id: ProfileId,
        attempt: u32,
        reason: FailureReason,
    },
    TunnelUp {
        profile_id: ProfileId,
        protocol: ProtocolKind,
        interface_name: String,
        pid: Option<u32>,
    },
    TunnelDown {
        profile_id: ProfileId,
        reason: TunnelDownReason,
    },
    HandshakeStale {
        profile_id: ProfileId,
        seconds_since_last_handshake: u64,
    },
    WireGuardHandshakeObserved {
        profile_id: ProfileId,
        desired_generation: u64,
        handshake_at_millis: u64,
        observed_at_millis: u64,
    },
    ConnectionHealthChanged {
        profile_id: ProfileId,
        old: ConnectionHealth,
        new: ConnectionHealth,
    },
    IpChanged {
        old: Option<String>,
        new: String,
    },
    KillswitchEngaged {
        reason: KillswitchEngageReason,
    },
    KillswitchDisengaged,
    RetryScheduled {
        profile_id: ProfileId,
        next_attempt: u32,
        delay: Duration,
        retry_budget_remaining: Duration,
    },
    RetryBudgetExhausted {
        profile_id: ProfileId,
        total_attempts: u32,
        elapsed: Duration,
    },
    NetworkLinkLost,
    NetworkLinkRestored {
        new_gateway: Option<String>,
    },
    ProfileRenamed {
        profile_id: ProfileId,
        old_display_name: String,
        new_display_name: String,
    },
    ProfileDeletionRequested {
        profile_id: ProfileId,
    },
    JournalRetentionApplied {
        deleted: u32,
    },
    DegradedReasonCleared {
        profile_id: ProfileId,
        reason: DegradedReason,
    },
    UserPromptRequested {
        profile_id: ProfileId,
        prompt_id: String,
        prompt_kind: ChallengeKind,
        prompt_text: String,
    },
    PrimaryTunnelChanged {
        from: Option<ProfileId>,
        to: Option<ProfileId>,
        via_interface: Option<String>,
        reason: PrimaryChangeReason,
    },
    ConnectAttemptBlockedByConflict {
        conflict: Conflict,
        profile_id: ProfileId,
    },
}

/// Disposable event paired with the snapshot generation produced by the same
/// owner transition. Consumers that lag can resynchronize to at least this
/// generation and safely deduplicate the subscription boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlEventEnvelope {
    pub snapshot_generation: u64,
    pub event: ControlEvent,
}

pub use ControlEvent as EngineEvent;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub schema_version: u32,
    pub timestamp: SystemTime,
    pub event: ControlEvent,
}

impl EventEnvelope {
    #[must_use]
    pub fn new(event: ControlEvent) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            timestamp: SystemTime::now(),
            event,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum PrimaryChangeReason {
    InitialConnect,
    PriorPrimaryDisconnected,
    ExternalRouteChange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum TunnelDownReason {
    UserDisconnect,
    NetworkLinkLost,
    DaemonExited,
    HandshakeFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum KillswitchEngageReason {
    UserRequest,
    AutoOnConnect,
    AlwaysOn,
    RecoveredFromCrash,
}

#[cfg(test)]
mod operation_id_tests {
    use super::OperationId;

    #[test]
    fn public_operation_id_parser_accepts_only_service_shape() {
        assert!(OperationId::parse("op-0000000000000001-0000000000000002").is_some());
        assert!(OperationId::parse("op-1-2").is_none());
        assert!(OperationId::parse("client-0000000000000001-0000000000000002").is_none());
    }
}
