//! Canonical desired/observed/effective, operation, challenge, and event model.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::vortix_core::engine::registry::Conflict;
use crate::vortix_core::engine::state::{ConnectionHealth, DegradedReason, FailureReason};
use crate::vortix_core::profile::{ProfileId, ProtocolKind};
use crate::vortix_core::state::killswitch::KillSwitchMode;

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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OperationId(String);

impl OperationId {
    pub(crate) fn from_parts(authority_epoch: AuthorityEpoch, sequence: u64) -> Self {
        Self(format!("op-{:016x}-{sequence:016x}", authority_epoch.0))
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
        let Some(rest) = self.0.strip_prefix("client-") else {
            return false;
        };
        let Some((epoch, sequence)) = rest.split_once('-') else {
            return false;
        };
        epoch.len() == 16
            && sequence.len() == 16
            && epoch.bytes().all(|byte| byte.is_ascii_hexdigit())
            && sequence.bytes().all(|byte| byte.is_ascii_hexdigit())
    }
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
}

impl Default for DesiredState {
    fn default() -> Self {
        Self {
            generation: 0,
            tunnels: BTreeMap::new(),
            kill_switch: KillSwitchMode::Off,
            authority_epoch: AuthorityEpoch::default(),
            policy_digest: PolicyDigest::default(),
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedState {
    pub evidence: Option<ProtectionEvidence>,
    /// Authority-clock receipt time for the current protection evidence.
    pub evidence_received_at_millis: Option<u64>,
    /// Observer-owned tunnel facts. They never overwrite desired intent.
    pub tunnels: BTreeMap<ProfileId, ObservedTunnel>,
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
    ObservationFailed,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationResult {
    ObservedConvergence,
    Failed(OperationFailure),
    Cancelled,
    Expired,
}

impl OperationStatus {
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
    pub status: OperationStatus,
    pub result: Option<OperationResult>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
    Drift {
        profile_id: Option<ProfileId>,
        gates: DriftGates,
        observed_at_millis: u64,
        protection: Option<ProtectionEvidence>,
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
