//! Bounded, side-effect-free canonical control owner.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use crate::vortix_core::control::command::{
    CommandRequest, Deadline, IdempotencyKey, Secret, UserCommand,
};
use crate::vortix_core::control::model::{
    AuthorityEpoch, ChallengeId, ChallengeKind, ChallengeRecord, ClientId, CompletionOutcome,
    ControlEvent, ControlEventEnvelope, DriftGates, EffectiveState, Freshness, GateEvidence,
    Observation, ObservedTunnel, OperationCompletion, OperationId, OperationRecord,
    OperationResult, OperationStatus, PolicyDigest, ProtectionEvidence, ProtectionStatus,
    RequestedTunnelState, MAX_PROTECTION_AGE_MILLIS,
};
use crate::vortix_core::control::reconcile::{
    plan_reconciliation, DisconnectTombstone, InFlightMutation, ObservationOwnership,
    ReconcileAction, ReconcileInput, ScanEvidence, TunnelObservation,
};
use crate::vortix_core::control::snapshot::{ControlSnapshot, ServiceReadiness};
use crate::vortix_core::control::supervisor::{PolicyVerification, SupervisedTruth, Supervisor};
use crate::vortix_core::control::worker::{
    ControlRevision, ProfileAdmission, RouteClaim, TopologyPolicy, TopologyState,
    TopologyTransitionKind, TunnelMutation, TunnelWork, WorkFailure,
};
use crate::vortix_core::profile::ProfileId;

/// Injectable authority-local service clock.
pub trait Clock: Send + Sync + 'static {
    fn now_millis(&self) -> u64;
}

#[derive(Debug, Default)]
pub struct RealClock;

impl Clock for RealClock {
    fn now_millis(&self) -> u64 {
        static START: OnceLock<Instant> = OnceLock::new();
        START
            .get_or_init(Instant::now)
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }
}

#[derive(Debug, Clone)]
pub struct ControlServiceConfig {
    pub command_capacity: usize,
    pub event_capacity: usize,
    pub max_operations: usize,
    pub max_idempotency_keys: usize,
    pub max_challenges: usize,
    pub max_observed_profiles: usize,
    pub known_profiles: BTreeSet<ProfileId>,
    /// Canonical resources parsed from real profiles before authority starts.
    pub profile_topologies: BTreeMap<ProfileId, ProfileTopology>,
    pub freshness_poll_interval: Duration,
    pub authority_epoch: AuthorityEpoch,
    pub reconciliation_complete: bool,
    pub authority_verified: bool,
}

/// Immutable profile resources used for admission and topology planning.
#[derive(Debug, Clone, Default)]
pub struct ProfileTopology {
    /// Protocol-authoritative interface, when it is known before connection.
    pub interface_name: Option<String>,
    /// Canonical CIDR claims requested by this profile.
    pub routes: BTreeSet<String>,
    /// Digest of the profile's complete DNS intent.
    pub dns_digest: PolicyDigest,
    /// Digest of the profile's firewall intent.
    pub firewall_digest: PolicyDigest,
    /// Durable resource ownership receipts available to compensation.
    pub ownership_receipts: BTreeSet<String>,
}

/// U6 execution is explicit so shipping the supervised seam cannot create a
/// second writer while U7/U8 still select the legacy authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionSelection {
    /// U5-compatible owner/model only. Legacy code remains the sole writer.
    LegacyAuthority,
    /// Run the pure planner for observability, but dispatch no effects.
    CanonicalShadow,
    /// Supervised canonical effects. Selected only by explicit construction.
    CanonicalAuthority,
}

impl Default for ControlServiceConfig {
    fn default() -> Self {
        Self {
            command_capacity: 64,
            event_capacity: 128,
            max_operations: 512,
            max_idempotency_keys: 512,
            max_challenges: 16,
            max_observed_profiles: 512,
            known_profiles: BTreeSet::new(),
            profile_topologies: BTreeMap::new(),
            freshness_poll_interval: Duration::from_millis(250),
            authority_epoch: AuthorityEpoch(0),
            reconciliation_complete: true,
            authority_verified: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmittedOperation {
    pub operation_id: OperationId,
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AdmissionError {
    #[error("control service is busy: command queue is saturated")]
    Busy,
    #[error("command deadline expired before admission")]
    DeadlineExpired,
    #[error("control service has not completed authority reconciliation")]
    NotReady,
    #[error("idempotency key was already used for a different command")]
    IdempotencyConflict,
    #[error("bounded operation or idempotency retention is full")]
    RetentionFull,
    #[error("invalid bounded control input: {reason}")]
    InvalidInput { reason: String },
    #[error("control service stopped")]
    Stopped,
    #[error("requested routes conflict with an admitted or active profile")]
    RouteConflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ObservationError {
    #[error("control service is busy")]
    Busy,
    #[error("observation is from the future")]
    FutureDated,
    #[error("observation is older than evidence already accepted for this scope")]
    Stale,
    #[error("observation names an unknown profile")]
    UnknownProfile,
    #[error("bounded observed-profile retention is full")]
    RetentionFull,
    #[error("protection evidence does not match current desired state")]
    MismatchedProtection,
    #[error("observation exceeds its bounded contract")]
    InvalidInput,
    #[error("control service stopped")]
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionResult {
    Terminal(OperationStatus),
    ProtectionIncomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CompletionError {
    #[error("control service is busy")]
    Busy,
    #[error("operation was not found")]
    NotFound,
    #[error("completion generation does not match the operation")]
    GenerationMismatch,
    #[error("operation deadline expired")]
    DeadlineExpired,
    #[error("success evidence is stale or does not match current desired state")]
    StaleSuccess,
    #[error("control service stopped")]
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReadinessError {
    #[error("authority epoch changed before readiness transition")]
    EpochMismatch,
    #[error("control service stopped")]
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ChallengeError {
    #[error("control service is busy")]
    Busy,
    #[error("challenge not found or already consumed")]
    NotFound,
    #[error("client is not authorized to answer this challenge")]
    Unauthorized,
    #[error("challenge expired")]
    Expired,
    #[error("challenge was cancelled")]
    Cancelled,
    #[error("challenge response is empty")]
    InvalidResponse,
    #[error("challenge metadata exceeds its bounded contract")]
    InvalidRequest,
    #[error("bounded challenge retention is full")]
    RetentionFull,
    #[error("issuing operation is not active")]
    OperationInactive,
    #[error("control service stopped")]
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ChallengeDeliveryError {
    #[error("challenge expired, was cancelled, or the service stopped")]
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EventReceiveError {
    #[error("event subscriber lagged; resynchronize from snapshot generation {newest_generation}")]
    ResyncRequired { newest_generation: u64 },
    #[error("control service stopped")]
    Stopped,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct IdempotencyScope {
    client_id: ClientId,
    authority_epoch: AuthorityEpoch,
    key: IdempotencyKey,
}

struct IdempotencyBinding {
    operation_id: OperationId,
    command_digest: PolicyDigest,
}

struct AdmissionState {
    next_operation: u64,
    next_challenge: u64,
    next_client: u64,
    retained_operations: usize,
    idempotency: BTreeMap<IdempotencyScope, IdempotencyBinding>,
    terminal_operations: BTreeSet<OperationId>,
    known_profiles: BTreeSet<ProfileId>,
    readiness: ServiceReadiness,
}

impl AdmissionState {
    fn new(readiness: ServiceReadiness, known_profiles: BTreeSet<ProfileId>) -> Self {
        Self {
            next_operation: 0,
            next_challenge: 0,
            next_client: 1,
            retained_operations: 0,
            idempotency: BTreeMap::new(),
            terminal_operations: BTreeSet::new(),
            known_profiles,
            readiness,
        }
    }

    fn compact_one(&mut self) -> Option<OperationId> {
        let operation_id = self.terminal_operations.pop_first()?;
        self.idempotency
            .retain(|_, binding| binding.operation_id != operation_id);
        self.retained_operations = self.retained_operations.saturating_sub(1);
        Some(operation_id)
    }
}

#[derive(Clone, Copy)]
enum ChallengeTerminal {
    Consumed,
    Expired,
    Cancelled,
}

enum Envelope {
    Mutate {
        request: CommandRequest,
        client_id: ClientId,
        command_digest: PolicyDigest,
        operation_id: OperationId,
        admitted_at: u64,
        evicted: Vec<OperationId>,
        work_admissions: Vec<(ProfileId, ProfileAdmission)>,
    },
    Observe {
        observation: Observation,
        reply: oneshot::Sender<Result<(), ObservationError>>,
    },
    Complete {
        completion: OperationCompletion,
        reply: oneshot::Sender<Result<CompletionResult, CompletionError>>,
    },
    IssueChallenge {
        record: ChallengeRecord,
        answer: oneshot::Sender<Secret>,
        reply: oneshot::Sender<Result<ChallengeRecord, ChallengeError>>,
    },
    RespondChallenge {
        challenge_id: ChallengeId,
        client_id: ClientId,
        answer: Secret,
        reply: oneshot::Sender<Result<(), ChallengeError>>,
    },
    CancelChallenge {
        challenge_id: ChallengeId,
        client_id: ClientId,
        reply: oneshot::Sender<Result<(), ChallengeError>>,
    },
    SetReadiness {
        expected_epoch: AuthorityEpoch,
        readiness: ServiceReadiness,
        reply: oneshot::Sender<Result<(), ReadinessError>>,
    },
    Refresh,
}

struct Shared {
    tx: mpsc::Sender<Envelope>,
    snapshots: watch::Receiver<ControlSnapshot>,
    events: broadcast::Sender<ControlEventEnvelope>,
    admission: Arc<Mutex<AdmissionState>>,
    clock: Arc<dyn Clock>,
    config: ControlServiceConfig,
    selection: ExecutionSelection,
    supervisor: Option<Arc<Supervisor>>,
}

/// Public mutation/subscription capability. It cannot forge observations,
/// completions, readiness, or worker challenges.
///
/// ```compile_fail
/// use vortix::vortix_core::control::{ControlHandle, Observation};
/// fn forge_observation(client: &ControlHandle, observation: Observation) {
///     client.observe(observation);
/// }
/// ```
///
/// ```compile_fail
/// use vortix::vortix_core::control::{ControlHandle, OperationCompletion};
/// fn forge_completion(client: &ControlHandle, completion: OperationCompletion) {
///     client.complete(completion);
/// }
/// ```
#[derive(Clone)]
pub struct ControlHandle {
    shared: Arc<Shared>,
    client_id: ClientId,
}

impl fmt::Debug for ControlHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlHandle").finish_non_exhaustive()
    }
}

/// Service-issued observer capability.
#[derive(Clone)]
pub struct ObserverHandle(Arc<Shared>);

/// Service-issued worker/completer capability.
#[derive(Clone)]
pub struct CompleterHandle(Arc<Shared>);

/// Root capability returned only at service construction.
pub struct ControlService {
    shared: Arc<Shared>,
    client: ControlHandle,
    observer: ObserverHandle,
    completer: CompleterHandle,
    supervisor: Option<Arc<Supervisor>>,
}

impl ControlService {
    #[must_use]
    pub fn start(config: ControlServiceConfig) -> Self {
        Self::start_with_clock(config, Arc::new(RealClock))
    }

    #[must_use]
    pub fn start_with_clock(config: ControlServiceConfig, clock: Arc<dyn Clock>) -> Self {
        Self::start_selected(config, clock, ExecutionSelection::LegacyAuthority, None)
    }

    /// Construct the canonical actor with an explicit supervision selection.
    /// Passing `CanonicalAuthority` requires a supervisor and is the only path
    /// that can dispatch effects.
    #[must_use]
    pub fn start_supervised(
        config: ControlServiceConfig,
        clock: Arc<dyn Clock>,
        selection: ExecutionSelection,
        supervisor: Arc<Supervisor>,
    ) -> Self {
        Self::start_selected(config, clock, selection, Some(supervisor))
    }

    fn start_selected(
        config: ControlServiceConfig,
        clock: Arc<dyn Clock>,
        selection: ExecutionSelection,
        supervisor: Option<Arc<Supervisor>>,
    ) -> Self {
        assert!(config.command_capacity > 0);
        assert!(config.event_capacity > 0);
        assert!(config.max_operations > 0);
        assert!(config.max_idempotency_keys > 0);
        assert!(config.max_challenges > 0);
        assert!(config.max_observed_profiles > 0);

        let readiness = ServiceReadiness {
            reconciliation_complete: config.reconciliation_complete,
            authority_verified: config.authority_verified,
        };
        let admission = Arc::new(Mutex::new(AdmissionState::new(
            readiness,
            config.known_profiles.clone(),
        )));
        let (tx, rx) = mpsc::channel(config.command_capacity);
        let mut initial = ControlSnapshot {
            readiness,
            ..ControlSnapshot::default()
        };
        initial.desired.authority_epoch = config.authority_epoch;
        recompute_policy_digest(&mut initial);
        derive_effective(
            &mut initial,
            clock.now_millis(),
            selection,
            supervisor.as_deref(),
        );
        let (snapshot_tx, snapshots) = watch::channel(initial.clone());
        let (events, _) = broadcast::channel(config.event_capacity);
        let shared = Arc::new(Shared {
            tx,
            snapshots,
            events: events.clone(),
            admission: Arc::clone(&admission),
            clock: Arc::clone(&clock),
            config: config.clone(),
            selection,
            supervisor: supervisor.clone(),
        });
        let client_id = ClientId::from_parts(config.authority_epoch, 1);
        tokio::spawn(run_service(
            rx,
            snapshot_tx,
            events,
            admission,
            clock,
            config,
            initial,
            selection,
            supervisor.clone(),
        ));
        Self {
            client: ControlHandle {
                shared: Arc::clone(&shared),
                client_id,
            },
            observer: ObserverHandle(Arc::clone(&shared)),
            completer: CompleterHandle(Arc::clone(&shared)),
            supervisor,
            shared,
        }
    }

    #[must_use]
    pub fn client(&self) -> ControlHandle {
        self.client.clone()
    }

    #[must_use]
    pub fn new_client(&self) -> ControlHandle {
        let client_id = {
            let mut admission = self
                .shared
                .admission
                .lock()
                .expect("admission mutex poisoned");
            admission.next_client = admission.next_client.saturating_add(1);
            ClientId::from_parts(self.shared.config.authority_epoch, admission.next_client)
        };
        ControlHandle {
            shared: Arc::clone(&self.shared),
            client_id,
        }
    }

    #[must_use]
    pub fn observer(&self) -> ObserverHandle {
        self.observer.clone()
    }

    #[must_use]
    pub fn completer(&self) -> CompleterHandle {
        self.completer.clone()
    }
}

impl Drop for ControlService {
    fn drop(&mut self) {
        if let Some(supervisor) = &self.supervisor {
            let _ = supervisor.shutdown_bounded(Duration::from_millis(250));
        }
    }
}

pub struct ControlSubscription {
    snapshots: watch::Receiver<ControlSnapshot>,
    events: broadcast::Receiver<ControlEventEnvelope>,
    minimum_generation: u64,
}

impl ControlSubscription {
    #[must_use]
    pub fn snapshot(&self) -> ControlSnapshot {
        self.snapshots.borrow().clone()
    }

    pub async fn changed(&mut self) -> Result<ControlSnapshot, EventReceiveError> {
        self.snapshots
            .changed()
            .await
            .map_err(|_| EventReceiveError::Stopped)?;
        let snapshot = self.snapshot();
        self.minimum_generation = self.minimum_generation.max(snapshot.generation);
        Ok(snapshot)
    }

    pub async fn recv_event(&mut self) -> Result<ControlEventEnvelope, EventReceiveError> {
        loop {
            match self.events.recv().await {
                Ok(event) if event.snapshot_generation > self.minimum_generation => {
                    return Ok(event);
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    let newest_generation = self.snapshots.borrow().generation;
                    self.minimum_generation = self.minimum_generation.max(newest_generation);
                    return Err(EventReceiveError::ResyncRequired { newest_generation });
                }
                Err(broadcast::error::RecvError::Closed) => return Err(EventReceiveError::Stopped),
            }
        }
    }
}

impl ControlHandle {
    #[must_use]
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    #[must_use]
    pub fn deadline_after(&self, duration: Duration) -> Deadline {
        let millis: u64 = duration.as_millis().try_into().unwrap_or(u64::MAX);
        Deadline(self.shared.clock.now_millis().saturating_add(millis))
    }

    #[allow(clippy::too_many_lines)] // Admission intentionally remains one lock/permit transaction.
    pub fn submit(&self, request: CommandRequest) -> Result<AdmittedOperation, AdmissionError> {
        if !request.idempotency_key.is_valid() {
            return Err(AdmissionError::InvalidInput {
                reason: "idempotency key must contain 1..=128 bytes".to_owned(),
            });
        }
        let command_digest = command_digest(&request.command);
        let scope = IdempotencyScope {
            client_id: self.client_id.clone(),
            authority_epoch: self.shared.config.authority_epoch,
            key: request.idempotency_key.clone(),
        };
        {
            let admission = self
                .shared
                .admission
                .lock()
                .expect("admission mutex poisoned");
            if !admission.readiness.reconciliation_complete
                || !admission.readiness.authority_verified
            {
                return Err(AdmissionError::NotReady);
            }
            if let Some(binding) = admission.idempotency.get(&scope) {
                return if binding.command_digest == command_digest {
                    Ok(AdmittedOperation {
                        operation_id: binding.operation_id.clone(),
                    })
                } else {
                    Err(AdmissionError::IdempotencyConflict)
                };
            }
        }
        if request.deadline.0 <= self.shared.clock.now_millis() {
            return Err(AdmissionError::DeadlineExpired);
        }
        let permit = self
            .shared
            .tx
            .clone()
            .try_reserve_owned()
            .map_err(|error| map_admission_reserve(&error))?;
        let now = self.shared.clock.now_millis();
        if request.deadline.0 <= now {
            return Err(AdmissionError::DeadlineExpired);
        }
        let mut admission = self
            .shared
            .admission
            .lock()
            .expect("admission mutex poisoned");
        if !admission.readiness.reconciliation_complete || !admission.readiness.authority_verified {
            return Err(AdmissionError::NotReady);
        }
        if let Some(binding) = admission.idempotency.get(&scope) {
            return if binding.command_digest == command_digest {
                Ok(AdmittedOperation {
                    operation_id: binding.operation_id.clone(),
                })
            } else {
                Err(AdmissionError::IdempotencyConflict)
            };
        }
        let admission_profiles = command_profiles(&request.command, &admission.known_profiles);
        let mut work_admissions = Vec::new();
        if self.shared.selection == ExecutionSelection::CanonicalAuthority {
            let supervisor = self
                .shared
                .supervisor
                .as_ref()
                .ok_or(AdmissionError::Stopped)?;
            for profile_id in admission_profiles {
                let routes = self
                    .shared
                    .config
                    .profile_topologies
                    .get(&profile_id)
                    .map(|topology| topology.routes.iter().cloned().collect::<Vec<_>>())
                    .unwrap_or_default();
                let reserved = supervisor
                    .reserve_tunnel(&profile_id, routes)
                    .map_err(|error| match error {
                        WorkFailure::RouteConflict => AdmissionError::RouteConflict,
                        WorkFailure::Stopped => AdmissionError::Stopped,
                        _ => AdmissionError::Busy,
                    })?;
                work_admissions.push((profile_id, reserved));
            }
        }
        if let Some(profile_id) = command_profile(&request.command) {
            if !admission.known_profiles.contains(profile_id)
                && admission.known_profiles.len() >= self.shared.config.max_observed_profiles
            {
                return Err(AdmissionError::InvalidInput {
                    reason: "known profile capacity is full".to_owned(),
                });
            }
            admission.known_profiles.insert(profile_id.clone());
        }
        let mut evicted = Vec::new();
        while admission.retained_operations >= self.shared.config.max_operations
            || admission.idempotency.len() >= self.shared.config.max_idempotency_keys
        {
            let Some(operation_id) = admission.compact_one() else {
                return Err(AdmissionError::RetentionFull);
            };
            evicted.push(operation_id);
        }
        admission.next_operation = admission.next_operation.saturating_add(1);
        admission.retained_operations = admission.retained_operations.saturating_add(1);
        let operation_id =
            OperationId::from_parts(self.shared.config.authority_epoch, admission.next_operation);
        admission.idempotency.insert(
            scope,
            IdempotencyBinding {
                operation_id: operation_id.clone(),
                command_digest: command_digest.clone(),
            },
        );
        drop(admission);
        permit.send(Envelope::Mutate {
            request,
            client_id: self.client_id.clone(),
            command_digest,
            operation_id: operation_id.clone(),
            admitted_at: now,
            evicted,
            work_admissions,
        });
        Ok(AdmittedOperation { operation_id })
    }

    pub async fn respond_challenge(
        &self,
        challenge_id: ChallengeId,
        answer: Secret,
    ) -> Result<(), ChallengeError> {
        if !answer.is_valid() {
            return Err(ChallengeError::InvalidResponse);
        }
        let permit = self
            .shared
            .tx
            .clone()
            .try_reserve_owned()
            .map_err(|error| map_challenge_reserve(&error))?;
        let (reply, receiver) = oneshot::channel();
        permit.send(Envelope::RespondChallenge {
            challenge_id,
            client_id: self.client_id.clone(),
            answer,
            reply,
        });
        receiver.await.map_err(|_| ChallengeError::Stopped)?
    }

    pub async fn cancel_challenge(&self, challenge_id: ChallengeId) -> Result<(), ChallengeError> {
        let permit = self
            .shared
            .tx
            .clone()
            .try_reserve_owned()
            .map_err(|error| map_challenge_reserve(&error))?;
        let (reply, receiver) = oneshot::channel();
        permit.send(Envelope::CancelChallenge {
            challenge_id,
            client_id: self.client_id.clone(),
            reply,
        });
        receiver.await.map_err(|_| ChallengeError::Stopped)?
    }

    pub fn refresh(&self) -> Result<(), AdmissionError> {
        self.shared.tx.try_send(Envelope::Refresh).map_err(|error| {
            if matches!(error, mpsc::error::TrySendError::Closed(_)) {
                AdmissionError::Stopped
            } else {
                AdmissionError::Busy
            }
        })
    }

    #[must_use]
    pub fn snapshot(&self) -> ControlSnapshot {
        self.shared.snapshots.borrow().clone()
    }

    #[must_use]
    pub fn subscribe(&self) -> ControlSubscription {
        // Subscribe to events first; any transition in the narrow boundary is
        // then either represented by the snapshot or buffered and deduplicated.
        let events = self.shared.events.subscribe();
        let snapshots = self.shared.snapshots.clone();
        let minimum_generation = snapshots.borrow().generation;
        ControlSubscription {
            snapshots,
            events,
            minimum_generation,
        }
    }
}

impl ObserverHandle {
    pub async fn observe(&self, observation: Observation) -> Result<(), ObservationError> {
        let invalid = matches!(
            &observation,
            Observation::Tunnel { interface_name: Some(name), .. } if name.len() > 256
        ) || observation_evidence(&observation)
            .is_some_and(|evidence| !evidence.policy_digest.is_valid());
        if invalid {
            return Err(ObservationError::InvalidInput);
        }
        let permit = self.0.tx.clone().try_reserve_owned().map_err(|error| {
            if matches!(error, mpsc::error::TrySendError::Closed(_)) {
                ObservationError::Stopped
            } else {
                ObservationError::Busy
            }
        })?;
        let (reply, receiver) = oneshot::channel();
        permit.send(Envelope::Observe { observation, reply });
        receiver.await.map_err(|_| ObservationError::Stopped)?
    }
}

impl CompleterHandle {
    pub async fn complete(
        &self,
        completion: OperationCompletion,
    ) -> Result<CompletionResult, CompletionError> {
        let permit = self.0.tx.clone().try_reserve_owned().map_err(|error| {
            if matches!(error, mpsc::error::TrySendError::Closed(_)) {
                CompletionError::Stopped
            } else {
                CompletionError::Busy
            }
        })?;
        let (reply, receiver) = oneshot::channel();
        permit.send(Envelope::Complete { completion, reply });
        receiver.await.map_err(|_| CompletionError::Stopped)?
    }

    pub async fn set_readiness(
        &self,
        expected_epoch: AuthorityEpoch,
        reconciliation_complete: bool,
        authority_verified: bool,
    ) -> Result<(), ReadinessError> {
        let permit = self
            .0
            .tx
            .clone()
            .reserve_owned()
            .await
            .map_err(|_| ReadinessError::Stopped)?;
        let (reply, receiver) = oneshot::channel();
        permit.send(Envelope::SetReadiness {
            expected_epoch,
            readiness: ServiceReadiness {
                reconciliation_complete,
                authority_verified,
            },
            reply,
        });
        receiver.await.map_err(|_| ReadinessError::Stopped)?
    }

    pub async fn issue_challenge(
        &self,
        operation_id: OperationId,
        profile_id: ProfileId,
        kind: ChallengeKind,
        label: impl Into<String>,
        expires_at_millis: u64,
    ) -> Result<IssuedChallenge, ChallengeError> {
        let permit = self
            .0
            .tx
            .clone()
            .try_reserve_owned()
            .map_err(|error| map_challenge_reserve(&error))?;
        let label = label.into();
        let generic_label_is_valid = !matches!(
            &kind,
            ChallengeKind::Generic { label } if label.is_empty() || label.len() > 256
        );
        if label.is_empty() || label.len() > 256 || !generic_label_is_valid {
            return Err(ChallengeError::InvalidRequest);
        }
        let now = self.0.clock.now_millis();
        if expires_at_millis <= now {
            return Err(ChallengeError::Expired);
        }
        let challenge_id = {
            let mut admission = self.0.admission.lock().expect("admission mutex poisoned");
            admission.next_challenge = admission.next_challenge.saturating_add(1);
            ChallengeId::from_counter(admission.next_challenge)
        };
        let authorized_client = {
            let snapshot = self.0.snapshots.borrow();
            snapshot
                .operations
                .get(&operation_id)
                .map(|record| record.client_id.clone())
        }
        .ok_or(ChallengeError::OperationInactive)?;
        let record = ChallengeRecord {
            id: challenge_id,
            profile_id,
            operation_id,
            kind,
            label,
            authorized_client,
            created_at_millis: now,
            expires_at_millis,
        };
        let (answer, response) = oneshot::channel();
        let (reply, receiver) = oneshot::channel();
        permit.send(Envelope::IssueChallenge {
            record,
            answer,
            reply,
        });
        let record = receiver.await.map_err(|_| ChallengeError::Stopped)??;
        Ok(IssuedChallenge {
            record,
            response: ChallengeAnswerReceiver(response),
        })
    }
}

/// Issuance result whose one-shot secret receiver belongs to the worker.
pub struct IssuedChallenge {
    pub record: ChallengeRecord,
    pub response: ChallengeAnswerReceiver,
}

pub struct ChallengeAnswerReceiver(oneshot::Receiver<Secret>);

impl ChallengeAnswerReceiver {
    pub async fn receive(self) -> Result<Secret, ChallengeDeliveryError> {
        self.0.await.map_err(|_| ChallengeDeliveryError::Closed)
    }
}

fn map_admission_reserve<T>(error: &mpsc::error::TrySendError<T>) -> AdmissionError {
    if matches!(error, mpsc::error::TrySendError::Closed(_)) {
        AdmissionError::Stopped
    } else {
        AdmissionError::Busy
    }
}

fn map_challenge_reserve<T>(error: &mpsc::error::TrySendError<T>) -> ChallengeError {
    if matches!(error, mpsc::error::TrySendError::Closed(_)) {
        ChallengeError::Stopped
    } else {
        ChallengeError::Busy
    }
}

struct OwnerState {
    challenge_terminals: BTreeMap<ChallengeId, ChallengeTerminal>,
    challenge_answers: BTreeMap<ChallengeId, oneshot::Sender<Secret>>,
    observation_clocks: BTreeMap<ObservationScope, u64>,
    work_admissions: BTreeMap<(OperationId, ProfileId), ProfileAdmission>,
    recovery_operations: BTreeSet<OperationId>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ObservationScope {
    Protection,
    Profile(ProfileId),
    Route,
    Dns,
    Firewall,
}

#[allow(clippy::too_many_arguments)] // One actor owns these bounded channels and authority state.
async fn run_service(
    mut rx: mpsc::Receiver<Envelope>,
    snapshot_tx: watch::Sender<ControlSnapshot>,
    events: broadcast::Sender<ControlEventEnvelope>,
    admission: Arc<Mutex<AdmissionState>>,
    clock: Arc<dyn Clock>,
    config: ControlServiceConfig,
    mut snapshot: ControlSnapshot,
    selection: ExecutionSelection,
    supervisor: Option<Arc<Supervisor>>,
) {
    let mut owner = OwnerState {
        challenge_terminals: BTreeMap::new(),
        challenge_answers: BTreeMap::new(),
        observation_clocks: BTreeMap::new(),
        work_admissions: BTreeMap::new(),
        recovery_operations: BTreeSet::new(),
    };
    let mut ticker = tokio::time::interval(config.freshness_poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            envelope = rx.recv() => {
                let Some(envelope) = envelope else { break };
                let mut pending = Vec::new();
                let now = clock.now_millis();
                expire_operations(&mut snapshot, &mut owner, &admission, now, &config, selection, &mut pending);
                expire_challenges(&mut snapshot, &mut owner, now, config.max_challenges, &mut pending);
                handle_envelope(envelope, &mut snapshot, &mut owner, &admission, now, &config, &mut pending);
                drive_supervision(selection, supervisor.as_deref(), &mut snapshot, &mut owner, &admission, now, &config, &mut pending);
                derive_effective(&mut snapshot, now, selection, supervisor.as_deref());
                publish_then_events(&mut snapshot, &snapshot_tx, &events, pending);
            }
            _ = ticker.tick() => {
                let before = snapshot.clone();
                let mut pending = Vec::new();
                let now = clock.now_millis();
                expire_operations(&mut snapshot, &mut owner, &admission, now, &config, selection, &mut pending);
                expire_challenges(&mut snapshot, &mut owner, now, config.max_challenges, &mut pending);
                drive_supervision(selection, supervisor.as_deref(), &mut snapshot, &mut owner, &admission, now, &config, &mut pending);
                derive_effective(&mut snapshot, now, selection, supervisor.as_deref());
                if snapshot != before || !pending.is_empty() {
                    publish_then_events(&mut snapshot, &snapshot_tx, &events, pending);
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn drive_supervision(
    selection: ExecutionSelection,
    supervisor: Option<&Supervisor>,
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    admission: &Arc<Mutex<AdmissionState>>,
    now: u64,
    config: &ControlServiceConfig,
    events: &mut Vec<ControlEvent>,
) {
    if selection == ExecutionSelection::LegacyAuthority {
        return;
    }
    let Some(supervisor) = supervisor else {
        return;
    };

    if supervisor.lost_results() > 0 {
        invalidate_gates(
            snapshot,
            DriftGates {
                interface: true,
                route: true,
                dns: true,
                firewall: true,
            },
            now,
            now,
        );
    }

    while let Some(result) = supervisor.poll_tunnel() {
        if result.result.is_err() {
            invalidate_gates(
                snapshot,
                DriftGates {
                    interface: true,
                    route: true,
                    dns: true,
                    firewall: true,
                },
                now,
                now,
            );
        }
    }
    while let Some(result) = supervisor.poll_policy() {
        if !matches!(
            result.outcome,
            crate::vortix_core::control::worker::PolicyOutcome::Applied
                | crate::vortix_core::control::worker::PolicyOutcome::Superseded
        ) {
            invalidate_gates(
                snapshot,
                DriftGates {
                    interface: true,
                    route: true,
                    dns: true,
                    firewall: true,
                },
                now,
                now,
            );
        }
    }

    let revision = ControlRevision {
        authority_epoch: snapshot.desired.authority_epoch,
        generation: snapshot.desired.generation,
        digest: snapshot.desired.policy_digest.clone(),
    };
    let evidence_is_exact_and_fresh = snapshot.observed.evidence.as_ref().is_some_and(|evidence| {
        evidence.desired_generation == revision.generation
            && evidence.authority_epoch == revision.authority_epoch
            && evidence.policy_digest == revision.digest
            && snapshot
                .observed
                .evidence_received_at_millis
                .is_some_and(|received| {
                    received <= now && now.saturating_sub(received) <= MAX_PROTECTION_AGE_MILLIS
                })
    });
    if evidence_is_exact_and_fresh {
        for (profile_id, fact) in &snapshot.observed.tunnels {
            if supervisor.profile_truth(profile_id).is_some_and(|entry| {
                entry.revision() == revision
                    && entry.truth == SupervisedTruth::WaitingForObservation
            }) {
                let _ = supervisor.confirm_tunnel(
                    profile_id,
                    &revision,
                    fact.active,
                    fact.interface_name.as_deref(),
                );
            }
        }
    }
    let supervised = supervisor.profiles();
    let tombstones = supervisor.tombstones();
    let desired_connected = snapshot
        .desired
        .tunnels
        .iter()
        .filter_map(|(profile, state)| {
            (*state == RequestedTunnelState::Connected).then_some(profile.clone())
        })
        .collect::<BTreeSet<_>>();
    let mut observations = snapshot
        .observed
        .tunnels
        .iter()
        .map(|(profile, fact)| {
            let supervision = supervised.get(profile);
            let managed = supervision.is_some_and(|entry| {
                entry.truth == SupervisedTruth::ObservedPresent && entry.adoption.is_some()
            });
            let managed_revision =
                managed.then(|| supervision.expect("managed supervision checked").revision());
            (
                profile.clone(),
                TunnelObservation {
                    evidence: if fact.active {
                        ScanEvidence::ConfirmedPresent
                    } else {
                        ScanEvidence::ConfirmedAbsent
                    },
                    interface_name: fact.interface_name.clone(),
                    ownership: if managed {
                        ObservationOwnership::Managed
                    } else {
                        ObservationOwnership::UnknownExternal
                    },
                    revision: managed_revision,
                    adoption: None,
                    observed_at_millis: fact.received_at_millis,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    for profile in tombstones.keys() {
        observations
            .entry(profile.clone())
            .or_insert(TunnelObservation {
                evidence: ScanEvidence::MissingPartial,
                interface_name: None,
                ownership: ObservationOwnership::Managed,
                revision: supervised
                    .get(profile)
                    .map(crate::vortix_core::control::supervisor::ProfileSupervision::revision),
                adoption: None,
                observed_at_millis: now,
            });
    }
    let in_flight = supervised
        .iter()
        .filter(|(profile, entry)| {
            !tombstones.contains_key(*profile)
                && matches!(
                    entry.truth,
                    SupervisedTruth::Reserved
                        | SupervisedTruth::WaitingForObservation
                        | SupervisedTruth::OutcomeUnknown
                )
        })
        .map(|(profile, entry)| {
            (
                profile.clone(),
                InFlightMutation {
                    revision: entry.revision(),
                    operation: entry.operation_id.clone(),
                },
            )
        })
        .collect();
    let disconnect_tombstones = tombstones
        .iter()
        .map(|(profile, entry)| {
            (
                profile.clone(),
                DisconnectTombstone {
                    revision: entry.revision(),
                    teardown_failed: matches!(
                        entry.truth,
                        SupervisedTruth::Degraded(_) | SupervisedTruth::OutcomeUnknown
                    ),
                },
            )
        })
        .collect();
    let plan = plan_reconciliation(&ReconcileInput {
        revision: revision.clone(),
        desired_connected,
        observations,
        in_flight,
        disconnect_tombstones,
    });
    if selection == ExecutionSelection::CanonicalShadow {
        return;
    }

    for action in &plan.actions {
        match action {
            ReconcileAction::ClearTombstone { profile_id } => {
                let _ = supervisor.confirm_tunnel(profile_id, &revision, false, None);
            }
            ReconcileAction::AdoptAttested {
                evidence,
                revision: adoption_revision,
                ..
            } => {
                if let Some(operation) =
                    operation_for_generation(snapshot, adoption_revision.generation)
                {
                    let _ = supervisor.adopt_attested(
                        evidence.clone(),
                        adoption_revision.clone(),
                        operation.id.clone(),
                    );
                }
            }
            ReconcileAction::Connect {
                profile_id,
                revision: action_revision,
            }
            | ReconcileAction::Disconnect {
                profile_id,
                revision: action_revision,
            }
            | ReconcileAction::CleanupStaleManaged {
                profile_id,
                target_revision: action_revision,
                ..
            } => {
                let Some(operation) =
                    operation_for_generation(snapshot, action_revision.generation)
                else {
                    continue;
                };
                let remaining = operation.deadline_millis.saturating_sub(now);
                let mutation = if matches!(action, ReconcileAction::Connect { .. }) {
                    TunnelMutation::Connect
                } else {
                    TunnelMutation::Disconnect
                };
                let work = TunnelWork {
                    profile_id: profile_id.clone(),
                    operation_id: operation.id.clone(),
                    generation: action_revision.generation,
                    authority_epoch: action_revision.authority_epoch,
                    policy_digest: action_revision.digest.clone(),
                    mutation,
                    deadline: Instant::now() + Duration::from_millis(remaining),
                };
                let key = (operation.id.clone(), profile_id.clone());
                let reserved = owner.work_admissions.remove(&key).or_else(|| {
                    if owner.recovery_operations.contains(&operation.id) {
                        let routes = config
                            .profile_topologies
                            .get(profile_id)
                            .map(|topology| topology.routes.iter().cloned().collect::<Vec<_>>())
                            .unwrap_or_default();
                        supervisor.reserve_tunnel(profile_id, routes).ok()
                    } else {
                        None
                    }
                });
                let Some(reserved) = reserved else {
                    invalidate_gates(
                        snapshot,
                        DriftGates {
                            interface: true,
                            route: true,
                            dns: true,
                            firewall: true,
                        },
                        now,
                        now,
                    );
                    continue;
                };
                if matches!(
                    supervisor.dispatch_reserved_tunnel(work, reserved),
                    Err(WorkFailure::Busy | WorkFailure::RouteConflict)
                ) {
                    invalidate_gates(
                        snapshot,
                        DriftGates {
                            interface: true,
                            route: true,
                            dns: true,
                            firewall: true,
                        },
                        now,
                        now,
                    );
                }
            }
            ReconcileAction::ObserveReadOnly { .. } => {}
        }
    }

    let tunnel_barrier_ready = plan.actions.is_empty()
        && snapshot.desired.tunnels.iter().all(|(profile, desired)| {
            let should_be_present = *desired == RequestedTunnelState::Connected;
            let observed = snapshot.observed.tunnels.get(profile);
            if should_be_present {
                supervisor.profile_truth(profile).is_some_and(|entry| {
                    entry.revision() == revision
                        && entry.truth == SupervisedTruth::ObservedPresent
                        && entry.adoption.is_some()
                }) && observed.is_some_and(|fact| {
                    fact.active
                        && fact.received_at_millis <= now
                        && now.saturating_sub(fact.received_at_millis) <= MAX_PROTECTION_AGE_MILLIS
                })
            } else {
                observed.is_none_or(|fact| !fact.active)
                    && supervisor.profile_truth(profile).is_none()
                    && !supervisor.is_tombstoned(profile)
            }
        });

    if tunnel_barrier_ready {
        if let Some(operation) = operation_for_generation(snapshot, revision.generation).cloned() {
            let target_profiles = snapshot
                .desired
                .tunnels
                .iter()
                .filter_map(|(profile, state)| {
                    (*state == RequestedTunnelState::Connected).then_some(profile.clone())
                })
                .collect();
            let prior_profiles = snapshot
                .observed
                .tunnels
                .iter()
                .filter_map(|(profile, fact)| fact.active.then_some(profile.clone()))
                .collect();
            let policy = TopologyPolicy {
                generation: revision.generation,
                authority_epoch: revision.authority_epoch,
                digest: revision.digest.clone(),
                operation_id: operation.id.clone(),
                deadline: Instant::now()
                    + Duration::from_millis(operation.deadline_millis.saturating_sub(now)),
                prior: supervisor.applied_topology().unwrap_or_else(|| {
                    build_topology_state(
                        prior_profiles,
                        &snapshot.observed.tunnels,
                        config,
                        crate::vortix_core::state::killswitch::KillSwitchMode::Off,
                    )
                }),
                target: build_topology_state(
                    target_profiles,
                    &snapshot.observed.tunnels,
                    config,
                    snapshot.desired.kill_switch,
                ),
                transition: transition_for_plan(&plan.actions),
                required_blocking: snapshot.desired.kill_switch
                    != crate::vortix_core::state::killswitch::KillSwitchMode::Off,
            };
            match supervisor.submit_policy(&policy) {
                Ok(()) | Err(WorkFailure::Stale) => {}
                Err(_) => invalidate_gates(
                    snapshot,
                    DriftGates {
                        interface: true,
                        route: true,
                        dns: true,
                        firewall: true,
                    },
                    now,
                    now,
                ),
            }
        }
    }

    if let (Some(evidence), Some((policy_revision, operation_id))) = (
        snapshot
            .observed
            .evidence
            .as_ref()
            .filter(|_| supervisor.lost_results() == 0),
        supervisor.latest_policy(),
    ) {
        let verification = PolicyVerification {
            revision: policy_revision.clone(),
            operation_id: operation_id.clone(),
            observed_at_millis: evidence.observed_at_millis,
            received_at_millis: snapshot.observed.evidence_received_at_millis.unwrap_or(now),
            interface_verified: evidence.interface == GateEvidence::Verified,
            route_verified: evidence.route == GateEvidence::Verified,
            dns_verified: evidence.dns == GateEvidence::Verified,
            firewall_verified: evidence.firewall == GateEvidence::Verified,
        };
        if evidence.desired_generation == policy_revision.generation
            && evidence.authority_epoch == policy_revision.authority_epoch
            && evidence.policy_digest == policy_revision.digest
            && supervisor.verify_policy(&verification, now).is_ok()
        {
            let converged =
                snapshot.desired.tunnels.iter().all(|(profile, state)| {
                    snapshot.observed.tunnels.get(profile).is_some_and(|fact| {
                        fact.active == (*state == RequestedTunnelState::Connected)
                    })
                });
            if converged {
                let completion_operation =
                    operation_for_generation(snapshot, policy_revision.generation)
                        .map(|operation| operation.id.clone())
                        .unwrap_or(operation_id);
                let _ = complete_operation(
                    OperationCompletion {
                        operation_id: completion_operation,
                        desired_generation: policy_revision.generation,
                        outcome: CompletionOutcome::ObservedSuccess(evidence.clone()),
                    },
                    snapshot,
                    owner,
                    admission,
                    now,
                    events,
                );
            }
        }
    }
}

fn operation_for_generation(
    snapshot: &ControlSnapshot,
    generation: u64,
) -> Option<&OperationRecord> {
    snapshot.operations.values().rev().find(|operation| {
        operation.desired_generation == generation && !operation.status.is_terminal()
    })
}

fn transition_for_plan(actions: &[ReconcileAction]) -> TopologyTransitionKind {
    let connects = actions
        .iter()
        .any(|action| matches!(action, ReconcileAction::Connect { .. }));
    let disconnects = actions
        .iter()
        .any(|action| matches!(action, ReconcileAction::Disconnect { .. }));
    match (connects, disconnects) {
        (true, true) => TopologyTransitionKind::Reconnect,
        (true, false) => TopologyTransitionKind::Connect,
        (false, true) => TopologyTransitionKind::Disconnect,
        (false, false) => TopologyTransitionKind::PolicyOnly,
    }
}

fn build_topology_state(
    profiles: BTreeSet<ProfileId>,
    observed: &BTreeMap<ProfileId, ObservedTunnel>,
    config: &ControlServiceConfig,
    kill_switch: crate::vortix_core::state::killswitch::KillSwitchMode,
) -> TopologyState {
    let mut interfaces = BTreeMap::new();
    let mut routes = BTreeMap::new();
    let mut ownership_receipts = BTreeSet::new();
    let mut dns_material = Vec::new();
    let mut firewall_material = Vec::new();
    for profile in &profiles {
        let configured = config.profile_topologies.get(profile);
        let interface = configured
            .and_then(|topology| topology.interface_name.clone())
            .or_else(|| {
                observed
                    .get(profile)
                    .and_then(|fact| fact.interface_name.clone())
            });
        if let Some(interface) = interface {
            interfaces.insert(profile.clone(), interface);
        }
        if let Some(topology) = configured {
            let claims = topology
                .routes
                .iter()
                .filter_map(|route| RouteClaim::parse(route).ok())
                .collect::<BTreeSet<_>>();
            routes.insert(profile.clone(), claims);
            dns_material.extend_from_slice(profile.as_str().as_bytes());
            dns_material.extend_from_slice(topology.dns_digest.0.as_bytes());
            firewall_material.extend_from_slice(profile.as_str().as_bytes());
            firewall_material.extend_from_slice(topology.firewall_digest.0.as_bytes());
            ownership_receipts.extend(topology.ownership_receipts.iter().cloned());
        }
    }
    TopologyState {
        profiles,
        interfaces,
        routes,
        dns_digest: PolicyDigest(encode_digest(&dns_material)),
        kill_switch,
        firewall_digest: PolicyDigest(encode_digest(&firewall_material)),
        ownership_receipts,
    }
}

#[allow(clippy::too_many_lines)] // Exhaustive owner-envelope dispatch is kept in one auditable match.
fn handle_envelope(
    envelope: Envelope,
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    admission: &Arc<Mutex<AdmissionState>>,
    now: u64,
    config: &ControlServiceConfig,
    events: &mut Vec<ControlEvent>,
) {
    match envelope {
        Envelope::Mutate {
            request,
            client_id,
            command_digest,
            operation_id,
            admitted_at,
            evicted,
            work_admissions,
        } => {
            for evicted_id in evicted {
                snapshot.operations.remove(&evicted_id);
            }
            let expired = request.deadline.0 <= now;
            let desired_generation = if expired {
                snapshot.desired.generation
            } else {
                apply_desired(&request.command, snapshot);
                snapshot.desired.generation
            };
            let status = if expired {
                OperationStatus::Expired
            } else {
                OperationStatus::WaitingForObservation
            };
            snapshot.operations.insert(
                operation_id.clone(),
                OperationRecord {
                    id: operation_id.clone(),
                    idempotency_key: request.idempotency_key,
                    client_id,
                    command_digest,
                    authority_epoch: snapshot.desired.authority_epoch,
                    desired_generation,
                    admitted_at_millis: admitted_at,
                    deadline_millis: request.deadline.0,
                    status,
                    result: expired.then_some(OperationResult::Expired),
                },
            );
            for (profile_id, reserved) in work_admissions {
                owner
                    .work_admissions
                    .insert((operation_id.clone(), profile_id), reserved);
            }
            events.push(ControlEvent::OperationAdmitted {
                operation_id: operation_id.clone(),
                desired_generation,
            });
            if expired {
                owner
                    .work_admissions
                    .retain(|(reserved_operation, _), _| reserved_operation != &operation_id);
                mark_terminal(admission, operation_id.clone());
                events.push(ControlEvent::OperationCompleted {
                    operation_id,
                    status,
                });
            } else {
                events.push(ControlEvent::DesiredStateChanged { desired_generation });
            }
        }
        Envelope::Observe { observation, reply } => {
            let result = apply_observation(observation, snapshot, owner, admission, now, config);
            let _ = reply.send(result);
        }
        Envelope::Complete { completion, reply } => {
            let result = complete_operation(completion, snapshot, owner, admission, now, events);
            let _ = reply.send(result);
        }
        Envelope::IssueChallenge {
            record,
            answer,
            reply,
        } => {
            let result = if record.expires_at_millis <= now {
                Err(ChallengeError::Expired)
            } else if snapshot.challenges.len() >= config.max_challenges {
                Err(ChallengeError::RetentionFull)
            } else if snapshot
                .operations
                .get(&record.operation_id)
                .is_none_or(|op| op.status.is_terminal())
            {
                Err(ChallengeError::OperationInactive)
            } else {
                snapshot.challenges.insert(record.id, record.clone());
                owner.challenge_answers.insert(record.id, answer);
                events.push(ControlEvent::ChallengeIssued {
                    challenge: record.clone(),
                });
                Ok(record)
            };
            let _ = reply.send(result);
        }
        Envelope::RespondChallenge {
            challenge_id,
            client_id,
            answer,
            reply,
        } => {
            let result = resolve_challenge(
                challenge_id,
                &client_id,
                answer,
                snapshot,
                owner,
                now,
                config.max_challenges,
                events,
            );
            let _ = reply.send(result);
        }
        Envelope::CancelChallenge {
            challenge_id,
            client_id,
            reply,
        } => {
            let result = cancel_challenge(
                challenge_id,
                &client_id,
                snapshot,
                owner,
                config.max_challenges,
                events,
            );
            let _ = reply.send(result);
        }
        Envelope::SetReadiness {
            expected_epoch,
            readiness,
            reply,
        } => {
            let result = if expected_epoch == snapshot.desired.authority_epoch {
                snapshot.readiness = readiness;
                admission
                    .lock()
                    .expect("admission mutex poisoned")
                    .readiness = readiness;
                Ok(())
            } else {
                Err(ReadinessError::EpochMismatch)
            };
            let _ = reply.send(result);
        }
        Envelope::Refresh => {}
    }
}

fn apply_desired(command: &UserCommand, snapshot: &mut ControlSnapshot) {
    snapshot.desired.generation = snapshot.desired.generation.saturating_add(1);
    match command {
        UserCommand::Connect { profile_id }
        | UserCommand::Reconnect {
            profile_id: Some(profile_id),
        } => {
            snapshot
                .desired
                .tunnels
                .insert(profile_id.clone(), RequestedTunnelState::Connected);
        }
        UserCommand::Disconnect {
            profile_id: Some(profile_id),
        }
        | UserCommand::ForceDisconnect {
            profile_id: Some(profile_id),
        } => {
            snapshot
                .desired
                .tunnels
                .insert(profile_id.clone(), RequestedTunnelState::Disconnected);
        }
        UserCommand::Disconnect { profile_id: None }
        | UserCommand::ForceDisconnect { profile_id: None } => snapshot
            .desired
            .tunnels
            .values_mut()
            .for_each(|state| *state = RequestedTunnelState::Disconnected),
        UserCommand::Reconnect { profile_id: None } => snapshot
            .desired
            .tunnels
            .values_mut()
            .for_each(|state| *state = RequestedTunnelState::Connected),
        UserCommand::SetKillSwitch { mode } => snapshot.desired.kill_switch = *mode,
    }
    recompute_policy_digest(snapshot);
    // Desired changes invalidate every prior protection claim immediately.
    if let Some(evidence) = snapshot.observed.evidence.as_mut() {
        evidence.interface = GateEvidence::Unverified;
        evidence.route = GateEvidence::Unverified;
        evidence.dns = GateEvidence::Unverified;
        evidence.firewall = GateEvidence::Unverified;
    }
}

fn command_digest(command: &UserCommand) -> PolicyDigest {
    let bytes = serde_json::to_vec(command).expect("commands are serializable");
    PolicyDigest(encode_digest(&bytes))
}

fn command_profile(command: &UserCommand) -> Option<&ProfileId> {
    match command {
        UserCommand::Connect { profile_id }
        | UserCommand::Disconnect {
            profile_id: Some(profile_id),
        }
        | UserCommand::Reconnect {
            profile_id: Some(profile_id),
        }
        | UserCommand::ForceDisconnect {
            profile_id: Some(profile_id),
        } => Some(profile_id),
        UserCommand::Disconnect { profile_id: None }
        | UserCommand::Reconnect { profile_id: None }
        | UserCommand::ForceDisconnect { profile_id: None }
        | UserCommand::SetKillSwitch { .. } => None,
    }
}

fn command_profiles(command: &UserCommand, known_profiles: &BTreeSet<ProfileId>) -> Vec<ProfileId> {
    if let Some(profile) = command_profile(command) {
        return vec![profile.clone()];
    }
    match command {
        UserCommand::Disconnect { profile_id: None }
        | UserCommand::Reconnect { profile_id: None }
        | UserCommand::ForceDisconnect { profile_id: None } => {
            known_profiles.iter().cloned().collect()
        }
        _ => Vec::new(),
    }
}

fn recompute_policy_digest(snapshot: &mut ControlSnapshot) {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(snapshot.desired.kill_switch.cli_verb().as_bytes());
    for (profile_id, state) in &snapshot.desired.tunnels {
        bytes.extend_from_slice(profile_id.as_str().as_bytes());
        bytes.extend_from_slice(match state {
            RequestedTunnelState::Connected => b"connected",
            RequestedTunnelState::Disconnected => b"disconnected",
        });
    }
    snapshot.desired.policy_digest = PolicyDigest(encode_digest(&bytes));
}

fn encode_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(71);
    encoded.push_str("sha256:");
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("String write");
    }
    encoded
}

fn observation_evidence(observation: &Observation) -> Option<&ProtectionEvidence> {
    match observation {
        Observation::Protection(evidence) => Some(evidence),
        Observation::Tunnel { protection, .. } | Observation::Drift { protection, .. } => {
            protection.as_ref()
        }
    }
}

fn evidence_matches(evidence: &ProtectionEvidence, snapshot: &ControlSnapshot, now: u64) -> bool {
    evidence.desired_generation == snapshot.desired.generation
        && evidence.authority_epoch == snapshot.desired.authority_epoch
        && evidence.policy_digest == snapshot.desired.policy_digest
        && evidence.observed_at_millis <= now
        && now.saturating_sub(evidence.observed_at_millis) <= MAX_PROTECTION_AGE_MILLIS
}

#[allow(clippy::too_many_lines)] // Validation and mutation must remain one atomic owner transition.
fn apply_observation(
    observation: Observation,
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    admission: &Arc<Mutex<AdmissionState>>,
    now: u64,
    config: &ControlServiceConfig,
) -> Result<(), ObservationError> {
    let timestamp = match &observation {
        Observation::Protection(evidence) => evidence.observed_at_millis,
        Observation::Tunnel {
            observed_at_millis, ..
        }
        | Observation::Drift {
            observed_at_millis, ..
        } => *observed_at_millis,
    };
    if timestamp > now {
        return Err(ObservationError::FutureDated);
    }
    if matches!(
        &observation,
        Observation::Tunnel {
            protection: Some(evidence),
            observed_at_millis,
            ..
        }
        | Observation::Drift {
            protection: Some(evidence),
            observed_at_millis,
            ..
        } if evidence.observed_at_millis != *observed_at_millis
    ) {
        return Err(ObservationError::InvalidInput);
    }
    if let Some(evidence) = observation_evidence(&observation) {
        if !evidence_matches(evidence, snapshot, now) {
            return Err(ObservationError::MismatchedProtection);
        }
    }
    let scopes = observation_scopes(&observation);
    if scopes.iter().any(|scope| {
        owner
            .observation_clocks
            .get(scope)
            .is_some_and(|last| timestamp < *last)
    }) {
        return Err(ObservationError::Stale);
    }
    match &observation {
        Observation::Tunnel { profile_id, .. } => {
            validate_observed_profile(profile_id, admission)?;
            if !snapshot.observed.tunnels.contains_key(profile_id)
                && snapshot.observed.tunnels.len() >= config.max_observed_profiles
            {
                return Err(ObservationError::RetentionFull);
            }
        }
        Observation::Drift {
            profile_id: Some(profile_id),
            ..
        } => validate_observed_profile(profile_id, admission)?,
        _ => {}
    }
    for scope in scopes {
        owner.observation_clocks.insert(scope, timestamp);
    }
    match observation {
        Observation::Protection(evidence) => {
            snapshot.observed.evidence = Some(evidence);
            snapshot.observed.evidence_received_at_millis = Some(now);
        }
        Observation::Tunnel {
            profile_id,
            active,
            interface_name,
            observed_at_millis,
            protection,
        } => {
            invalidate_gates(
                snapshot,
                DriftGates {
                    interface: true,
                    route: true,
                    dns: true,
                    firewall: true,
                },
                observed_at_millis,
                now,
            );
            snapshot.observed.tunnels.insert(
                profile_id,
                ObservedTunnel {
                    active,
                    interface_name,
                    observed_at_millis,
                    received_at_millis: now,
                },
            );
            if let Some(evidence) = protection {
                snapshot.observed.evidence = Some(evidence);
                snapshot.observed.evidence_received_at_millis = Some(now);
            }
        }
        Observation::Drift {
            gates,
            observed_at_millis,
            protection,
            ..
        } => {
            invalidate_gates(snapshot, gates, observed_at_millis, now);
            if let Some(evidence) = protection {
                snapshot.observed.evidence = Some(evidence);
                snapshot.observed.evidence_received_at_millis = Some(now);
            }
        }
    }
    Ok(())
}

fn validate_observed_profile(
    profile_id: &ProfileId,
    admission: &Arc<Mutex<AdmissionState>>,
) -> Result<(), ObservationError> {
    if admission
        .lock()
        .expect("admission mutex poisoned")
        .known_profiles
        .contains(profile_id)
    {
        Ok(())
    } else {
        Err(ObservationError::UnknownProfile)
    }
}

fn observation_scopes(observation: &Observation) -> Vec<ObservationScope> {
    let mut scopes = match observation {
        Observation::Protection(_) => vec![
            ObservationScope::Protection,
            ObservationScope::Route,
            ObservationScope::Dns,
            ObservationScope::Firewall,
        ],
        Observation::Tunnel {
            profile_id,
            protection,
            ..
        } => {
            let mut scopes = vec![ObservationScope::Profile(profile_id.clone())];
            if protection.is_some() {
                scopes.extend([
                    ObservationScope::Protection,
                    ObservationScope::Route,
                    ObservationScope::Dns,
                    ObservationScope::Firewall,
                ]);
            }
            scopes
        }
        Observation::Drift {
            profile_id,
            gates,
            protection,
            ..
        } => {
            let mut scopes = Vec::new();
            if let Some(profile_id) = profile_id {
                scopes.push(ObservationScope::Profile(profile_id.clone()));
            }
            if gates.route {
                scopes.push(ObservationScope::Route);
            }
            if gates.dns {
                scopes.push(ObservationScope::Dns);
            }
            if gates.firewall {
                scopes.push(ObservationScope::Firewall);
            }
            if gates.interface && profile_id.is_none() {
                scopes.push(ObservationScope::Protection);
            }
            if protection.is_some() {
                scopes.extend([
                    ObservationScope::Protection,
                    ObservationScope::Route,
                    ObservationScope::Dns,
                    ObservationScope::Firewall,
                ]);
            }
            scopes
        }
    };
    scopes.sort();
    scopes.dedup();
    scopes
}

fn invalidate_gates(
    snapshot: &mut ControlSnapshot,
    gates: DriftGates,
    observed_at: u64,
    received_at: u64,
) {
    let evidence = snapshot
        .observed
        .evidence
        .get_or_insert_with(|| ProtectionEvidence {
            desired_generation: snapshot.desired.generation,
            authority_epoch: snapshot.desired.authority_epoch,
            policy_digest: snapshot.desired.policy_digest.clone(),
            observed_at_millis: observed_at,
            interface: GateEvidence::Unverified,
            route: GateEvidence::Unverified,
            dns: GateEvidence::Unverified,
            firewall: GateEvidence::Unverified,
        });
    evidence.observed_at_millis = observed_at;
    if gates.interface {
        evidence.interface = GateEvidence::Unverified;
    }
    if gates.route {
        evidence.route = GateEvidence::Unverified;
    }
    if gates.dns {
        evidence.dns = GateEvidence::Unverified;
    }
    if gates.firewall {
        evidence.firewall = GateEvidence::Unverified;
    }
    snapshot.observed.evidence_received_at_millis = Some(received_at);
}

fn complete_operation(
    completion: OperationCompletion,
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    admission: &Arc<Mutex<AdmissionState>>,
    now: u64,
    events: &mut Vec<ControlEvent>,
) -> Result<CompletionResult, CompletionError> {
    let success_is_current = match &completion.outcome {
        CompletionOutcome::ObservedSuccess(evidence) => {
            completion.desired_generation == snapshot.desired.generation
                && evidence_matches(evidence, snapshot, now)
        }
        CompletionOutcome::Failed(_) | CompletionOutcome::Cancelled => true,
    };
    let Some(record) = snapshot.operations.get_mut(&completion.operation_id) else {
        return Err(CompletionError::NotFound);
    };
    if record.status.is_terminal() {
        return if record.status == OperationStatus::Expired {
            Err(CompletionError::DeadlineExpired)
        } else {
            Ok(CompletionResult::Terminal(record.status))
        };
    }
    if record.deadline_millis <= now {
        record.status = OperationStatus::Expired;
        record.result = Some(OperationResult::Expired);
        let was_recovery = owner.recovery_operations.remove(&completion.operation_id);
        owner
            .work_admissions
            .retain(|(operation, _), _| operation != &completion.operation_id);
        if was_recovery {
            snapshot.operations.remove(&completion.operation_id);
        } else {
            mark_terminal(admission, completion.operation_id.clone());
        }
        events.push(ControlEvent::OperationCompleted {
            operation_id: completion.operation_id,
            status: OperationStatus::Expired,
        });
        return Err(CompletionError::DeadlineExpired);
    }
    if completion.desired_generation != record.desired_generation {
        return Err(CompletionError::GenerationMismatch);
    }
    match completion.outcome {
        CompletionOutcome::ObservedSuccess(evidence) => {
            if !success_is_current {
                return Err(CompletionError::StaleSuccess);
            }
            snapshot.observed.evidence = Some(evidence.clone());
            snapshot.observed.evidence_received_at_millis = Some(now);
            if !evidence.all_gates_verified() {
                return Ok(CompletionResult::ProtectionIncomplete);
            }
            record.status = OperationStatus::Succeeded;
            record.result = Some(OperationResult::ObservedConvergence);
        }
        CompletionOutcome::Failed(reason) => {
            record.status = OperationStatus::Failed;
            record.result = Some(OperationResult::Failed(reason));
        }
        CompletionOutcome::Cancelled => {
            record.status = OperationStatus::Cancelled;
            record.result = Some(OperationResult::Cancelled);
        }
    }
    let status = record.status;
    owner
        .work_admissions
        .retain(|(operation, _), _| operation != &completion.operation_id);
    if owner.recovery_operations.remove(&completion.operation_id) {
        snapshot.operations.remove(&completion.operation_id);
    } else {
        mark_terminal(admission, completion.operation_id.clone());
    }
    events.push(ControlEvent::OperationCompleted {
        operation_id: completion.operation_id,
        status,
    });
    Ok(CompletionResult::Terminal(status))
}

fn expire_operations(
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    admission: &Arc<Mutex<AdmissionState>>,
    now: u64,
    _config: &ControlServiceConfig,
    selection: ExecutionSelection,
    events: &mut Vec<ControlEvent>,
) {
    let expired: Vec<_> = snapshot
        .operations
        .iter()
        .filter_map(|(id, record)| {
            (!record.status.is_terminal() && record.deadline_millis <= now).then_some(id.clone())
        })
        .collect();
    for id in expired {
        let expired_record = snapshot.operations.get(&id).cloned();
        let was_recovery = owner.recovery_operations.remove(&id);
        if let Some(record) = snapshot.operations.get_mut(&id) {
            record.status = OperationStatus::Expired;
            record.result = Some(OperationResult::Expired);
        }
        owner
            .work_admissions
            .retain(|(operation, _), _| operation != &id);
        if was_recovery {
            snapshot.operations.remove(&id);
        } else {
            mark_terminal(admission, id.clone());
        }
        events.push(ControlEvent::OperationCompleted {
            operation_id: id,
            status: OperationStatus::Expired,
        });
        let Some(expired_record) = expired_record else {
            continue;
        };
        if selection != ExecutionSelection::CanonicalAuthority
            || expired_record.desired_generation != snapshot.desired.generation
            || snapshot.operations.values().any(|operation| {
                operation.desired_generation == snapshot.desired.generation
                    && !operation.status.is_terminal()
            })
        {
            continue;
        }
        let recovery_id = {
            let mut state = admission.lock().expect("admission mutex poisoned");
            state.next_operation = state.next_operation.saturating_add(1);
            OperationId::from_parts(snapshot.desired.authority_epoch, state.next_operation)
        };
        let recovery_deadline = now.saturating_add(30_000);
        snapshot.operations.insert(
            recovery_id.clone(),
            OperationRecord {
                id: recovery_id.clone(),
                idempotency_key: IdempotencyKey::new(format!(
                    "service-recovery-{}-{now}",
                    snapshot.desired.generation
                )),
                client_id: ClientId::from_parts(snapshot.desired.authority_epoch, 0),
                command_digest: snapshot.desired.policy_digest.clone(),
                authority_epoch: snapshot.desired.authority_epoch,
                desired_generation: snapshot.desired.generation,
                admitted_at_millis: now,
                deadline_millis: recovery_deadline,
                status: OperationStatus::WaitingForObservation,
                result: None,
            },
        );
        owner.recovery_operations.insert(recovery_id.clone());
        events.push(ControlEvent::OperationAdmitted {
            operation_id: recovery_id,
            desired_generation: snapshot.desired.generation,
        });
    }
}

fn mark_terminal(admission: &Arc<Mutex<AdmissionState>>, operation_id: OperationId) {
    admission
        .lock()
        .expect("admission mutex poisoned")
        .terminal_operations
        .insert(operation_id);
}

#[allow(clippy::too_many_arguments)] // Challenge resolution is a single atomic owner transition.
fn resolve_challenge(
    challenge_id: ChallengeId,
    client_id: &ClientId,
    answer: Secret,
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    now: u64,
    max_terminals: usize,
    events: &mut Vec<ControlEvent>,
) -> Result<(), ChallengeError> {
    let Some(challenge) = snapshot.challenges.get(&challenge_id) else {
        return Err(challenge_terminal_error(owner, challenge_id));
    };
    if &challenge.authorized_client != client_id {
        return Err(ChallengeError::Unauthorized);
    }
    if challenge.expires_at_millis <= now {
        expire_one_challenge(challenge_id, snapshot, owner, max_terminals, events);
        return Err(ChallengeError::Expired);
    }
    snapshot.challenges.remove(&challenge_id);
    let Some(sender) = owner.challenge_answers.remove(&challenge_id) else {
        return Err(ChallengeError::NotFound);
    };
    record_challenge_terminal(
        &mut owner.challenge_terminals,
        challenge_id,
        ChallengeTerminal::Consumed,
        max_terminals,
    );
    let _ = sender.send(answer);
    events.push(ControlEvent::ChallengeResolved { challenge_id });
    Ok(())
}

fn cancel_challenge(
    challenge_id: ChallengeId,
    client_id: &ClientId,
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    max_terminals: usize,
    events: &mut Vec<ControlEvent>,
) -> Result<(), ChallengeError> {
    let Some(challenge) = snapshot.challenges.get(&challenge_id) else {
        return Err(challenge_terminal_error(owner, challenge_id));
    };
    if &challenge.authorized_client != client_id {
        return Err(ChallengeError::Unauthorized);
    }
    snapshot.challenges.remove(&challenge_id);
    owner.challenge_answers.remove(&challenge_id);
    record_challenge_terminal(
        &mut owner.challenge_terminals,
        challenge_id,
        ChallengeTerminal::Cancelled,
        max_terminals,
    );
    events.push(ControlEvent::ChallengeCancelled { challenge_id });
    Ok(())
}

fn challenge_terminal_error(owner: &OwnerState, id: ChallengeId) -> ChallengeError {
    match owner.challenge_terminals.get(&id) {
        Some(ChallengeTerminal::Expired) => ChallengeError::Expired,
        Some(ChallengeTerminal::Cancelled) => ChallengeError::Cancelled,
        Some(ChallengeTerminal::Consumed) | None => ChallengeError::NotFound,
    }
}

fn expire_challenges(
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    now: u64,
    max_terminals: usize,
    events: &mut Vec<ControlEvent>,
) {
    let expired: Vec<_> = snapshot
        .challenges
        .iter()
        .filter_map(|(id, challenge)| (challenge.expires_at_millis <= now).then_some(*id))
        .collect();
    for id in expired {
        expire_one_challenge(id, snapshot, owner, max_terminals, events);
    }
}

fn expire_one_challenge(
    id: ChallengeId,
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    max_terminals: usize,
    events: &mut Vec<ControlEvent>,
) {
    snapshot.challenges.remove(&id);
    owner.challenge_answers.remove(&id);
    record_challenge_terminal(
        &mut owner.challenge_terminals,
        id,
        ChallengeTerminal::Expired,
        max_terminals,
    );
    events.push(ControlEvent::ChallengeExpired { challenge_id: id });
}

fn record_challenge_terminal(
    terminals: &mut BTreeMap<ChallengeId, ChallengeTerminal>,
    id: ChallengeId,
    terminal: ChallengeTerminal,
    max: usize,
) {
    while terminals.len() >= max {
        let Some(oldest) = terminals.keys().next().copied() else {
            break;
        };
        terminals.remove(&oldest);
    }
    terminals.insert(id, terminal);
}

fn derive_effective(
    snapshot: &mut ControlSnapshot,
    now: u64,
    selection: ExecutionSelection,
    supervisor: Option<&Supervisor>,
) {
    let desired = &snapshot.desired;
    let Some(evidence) = snapshot.observed.evidence.as_ref() else {
        snapshot.effective = EffectiveState {
            protection: ProtectionStatus::Unknown,
            desired_generation: desired.generation,
            authority_epoch: desired.authority_epoch,
            policy_digest: desired.policy_digest.clone(),
            freshness: Freshness {
                ceiling_millis: MAX_PROTECTION_AGE_MILLIS,
                ..Freshness::default()
            },
        };
        return;
    };
    let age = now.saturating_sub(evidence.observed_at_millis);
    let current = evidence_matches(evidence, snapshot, now);
    let revision = ControlRevision {
        authority_epoch: desired.authority_epoch,
        generation: desired.generation,
        digest: desired.policy_digest.clone(),
    };
    let supervised_protection = selection != ExecutionSelection::CanonicalAuthority
        || supervisor.is_some_and(|supervisor| supervisor.protects(&revision, now));
    snapshot.effective = EffectiveState {
        protection: if current && evidence.all_gates_verified() && supervised_protection {
            ProtectionStatus::Protected
        } else {
            ProtectionStatus::Degraded
        },
        desired_generation: desired.generation,
        authority_epoch: desired.authority_epoch,
        policy_digest: desired.policy_digest.clone(),
        freshness: Freshness {
            observed_at_millis: Some(evidence.observed_at_millis),
            age_millis: Some(age),
            ceiling_millis: MAX_PROTECTION_AGE_MILLIS,
            current,
        },
    };
}

fn publish_then_events(
    snapshot: &mut ControlSnapshot,
    sender: &watch::Sender<ControlSnapshot>,
    events: &broadcast::Sender<ControlEventEnvelope>,
    pending: Vec<ControlEvent>,
) {
    snapshot.generation = snapshot.generation.saturating_add(1);
    sender.send_replace(snapshot.clone());
    for event in pending {
        let _ = events.send(ControlEventEnvelope {
            snapshot_generation: snapshot.generation,
            event,
        });
    }
}
