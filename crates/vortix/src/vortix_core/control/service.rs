//! Bounded, side-effect-free canonical control owner.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use crate::vortix_core::cidr::{claims_default_route_v4, claims_default_route_v6, Cidr};
use crate::vortix_core::control::command::{
    CommandRequest, Deadline, IdempotencyKey, Secret, UserCommand,
};
use crate::vortix_core::control::hooks::{HookEvent, HookEventId, LifecycleFact};
use crate::vortix_core::control::model::{
    AuthorityEpoch, ChallengeId, ChallengeKind, ChallengeRecord, ClientId, CompletionOutcome,
    ControlEvent, ControlEventEnvelope, DriftGates, EffectiveState, Freshness, GateEvidence,
    Observation, ObservedConnectionHealth, ObservedDefaultRoute, ObservedTunnel,
    ObservedTunnelDetails, OperationCompletion, OperationFailure, OperationId, OperationIntent,
    OperationRecord, OperationResult, OperationStatus, PolicyDigest, ProtectionEvidence,
    ProtectionStatus, RequestedTunnelState, MAX_PROTECTION_AGE_MILLIS,
};
use crate::vortix_core::control::persistence::{
    ControlStateStore, DurableControlState, PersistedTombstone, RequestedResources,
    RetentionMetadata, MAX_DURABLE_OPERATIONS,
};
use crate::vortix_core::control::reconcile::{
    plan_reconciliation, DisconnectTombstone, InFlightMutation, ObservationOwnership,
    ReconcileAction, ReconcileInput, ScanEvidence, TunnelObservation,
};
use crate::vortix_core::control::snapshot::{ControlSnapshot, ServiceReadiness};
use crate::vortix_core::control::supervisor::{PolicyVerification, SupervisedTruth, Supervisor};
use crate::vortix_core::control::worker::{
    ControlRevision, PolicyBarrier, PolicyOutcome, PolicyStage, ProfileAdmission, RouteClaim,
    TopologyPolicy, TopologyState, TopologyTransitionKind, TunnelMutation, TunnelRevision,
    TunnelWork, WorkFailure,
};
use crate::vortix_core::engine::registry::{Conflict, Role, TunnelSnapshot};
use crate::vortix_core::engine::state::{Connection, ConnectionHealth};
use crate::vortix_core::profile::ProfileId;

const MAX_OBSERVATIONS_PER_BATCH: usize = 1_025;

/// Injectable authority-local service clock.
pub trait Clock: Send + Sync + 'static {
    fn now_millis(&self) -> u64;
}

#[derive(Debug, Default)]
pub struct RealClock;

impl Clock for RealClock {
    fn now_millis(&self) -> u64 {
        static START: OnceLock<Instant> = OnceLock::new();
        if let Some(millis) = crate::utils::boot_elapsed_millis() {
            return millis;
        }
        // Unsupported targets retain the process-local fallback. Durable
        // persistence is unavailable there because boot_identity() is absent.
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
    /// Compatibility seed for activity recorded before canonical control
    /// became the single owner. Durable control state wins per profile when
    /// it contains a newer timestamp.
    pub initial_last_connected_at: BTreeMap<ProfileId, SystemTime>,
    /// Optional injected owner of crash-safe profile storage effects.
    pub profile_mutations: Option<Arc<dyn ProfileMutationExecutor>>,
    /// Explicit boot intent and prevalidated credential eligibility.
    pub boot_connections:
        BTreeMap<ProfileId, crate::vortix_core::control::persistence::BootConnection>,
    pub freshness_poll_interval: Duration,
    /// Wall-clock budget for automatic convergence after an unexpected drop.
    pub retry_budget: Duration,
    /// Initial reconnect backoff; subsequent failures double it within budget.
    pub retry_initial_backoff: Duration,
    pub authority_epoch: AuthorityEpoch,
    /// Compatibility seed used only when no durable control state exists.
    pub initial_kill_switch_mode: crate::vortix_core::state::killswitch::KillSwitchMode,
    pub reconciliation_complete: bool,
    pub authority_verified: bool,
    /// Optional user-owned durable intent. Presence forces scanner-first
    /// startup before any mutation or supervised effect is admitted.
    pub persistence: Option<ControlPersistenceConfig>,
}

#[derive(Debug, Clone)]
pub struct ControlPersistenceConfig {
    boot_id: String,
    store: Arc<dyn ControlStateStore>,
}

impl ControlPersistenceConfig {
    #[must_use]
    pub fn new(boot_id: impl Into<String>, store: Arc<dyn ControlStateStore>) -> Self {
        Self {
            boot_id: boot_id.into(),
            store,
        }
    }
}

/// Immutable profile resources used for admission and topology planning.
#[derive(Debug, Clone, Default)]
pub struct ProfileTopology {
    /// Protocol kind required for protocol-specific convergence gates.
    pub protocol: Option<crate::vortix_core::profile::ProtocolKind>,
    /// This profile requires a live client answer and can never be boot-eligible.
    pub interactive_credentials: bool,
    /// Owner-visible label allowed in lifecycle-hook environments.
    pub display_name: Option<String>,
    /// Protocol-authoritative interface, when it is known before connection.
    pub interface_name: Option<String>,
    /// Canonical CIDR claims requested by this profile.
    pub routes: BTreeSet<String>,
    /// Resolved VPN server IPs that must remain reachable while blocking.
    pub server_ips: BTreeSet<std::net::IpAddr>,
    /// Exact host/port substitutions for private managed protocol configs.
    pub resolved_endpoints: Vec<crate::vortix_core::profile::ResolvedEndpoint>,
    /// Complete protocol-neutral resolver request for this profile.
    pub dns_request: crate::vortix_core::ports::dns::DnsRequest,
    /// Digest of the profile's complete DNS intent.
    pub dns_digest: PolicyDigest,
    /// Digest of the profile's firewall intent.
    pub firewall_digest: PolicyDigest,
    /// Durable resource ownership receipts available to compensation.
    pub ownership_receipts: BTreeSet<String>,
}

/// Redacted profile mutation handed to an injected storage executor.
/// Imports reference a memory-only prepared payload by stable identity, so
/// private protocol configuration never enters durable operations or events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileMutation {
    Import {
        profile_id: ProfileId,
    },
    Rename {
        profile_id: ProfileId,
        new_display_name: String,
    },
    Delete {
        profile_id: ProfileId,
    },
}

impl ProfileMutation {
    #[must_use]
    pub fn profile_id(&self) -> &ProfileId {
        match self {
            Self::Import { profile_id }
            | Self::Rename { profile_id, .. }
            | Self::Delete { profile_id } => profile_id,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProfileMutationWork {
    pub operation_id: OperationId,
    pub deadline: Deadline,
    pub mutation: ProfileMutation,
}

#[derive(Debug, Clone)]
pub enum ProfileMutationApplied {
    Imported {
        profile_id: ProfileId,
        /// Missing means the profile was stored but canonical topology could
        /// not be derived; lifecycle admission must reject it until refresh.
        topology: Option<ProfileTopology>,
    },
    Renamed {
        profile_id: ProfileId,
        /// Missing preserves catalog mutation success while lifecycle
        /// admission remains fail-closed until topology can be rebuilt.
        topology: Option<ProfileTopology>,
    },
    Deleted {
        profile_id: ProfileId,
    },
}

impl ProfileMutationApplied {
    fn matches(&self, mutation: &ProfileMutation) -> bool {
        matches!(
            (self, mutation),
            (
                Self::Imported { profile_id: applied, .. },
                ProfileMutation::Import { profile_id: expected }
            ) | (
                Self::Renamed { profile_id: applied, .. },
                ProfileMutation::Rename { profile_id: expected, .. }
            ) | (
                Self::Deleted { profile_id: applied },
                ProfileMutation::Delete { profile_id: expected }
            ) if applied == expected
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileMutationFailure {
    NotFound,
    AlreadyExists,
    InvalidName,
    Busy,
    DeadlineExpired,
    Storage,
    Internal,
}

/// Blocking profile-storage boundary. Implementations run only on the
/// service's bounded mutation worker, never on the actor thread.
pub trait ProfileMutationExecutor: fmt::Debug + Send + Sync + 'static {
    fn execute(
        &self,
        work: ProfileMutationWork,
    ) -> Result<ProfileMutationApplied, ProfileMutationFailure>;
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
            max_operations: MAX_DURABLE_OPERATIONS,
            max_idempotency_keys: MAX_DURABLE_OPERATIONS,
            max_challenges: 16,
            max_observed_profiles: 512,
            known_profiles: BTreeSet::new(),
            profile_topologies: BTreeMap::new(),
            initial_last_connected_at: BTreeMap::new(),
            profile_mutations: None,
            boot_connections: BTreeMap::new(),
            freshness_poll_interval: Duration::from_millis(250),
            retry_budget: Duration::from_secs(300),
            retry_initial_backoff: Duration::from_secs(2),
            authority_epoch: AuthorityEpoch(0),
            initial_kill_switch_mode: crate::vortix_core::state::killswitch::KillSwitchMode::Off,
            reconciliation_complete: true,
            authority_verified: true,
            persistence: None,
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
    #[error("control identifier space is exhausted")]
    IdentifierExhausted,
    #[error("admitted operation could not be persisted")]
    Persistence,
    #[error("invalid bounded control input: {reason}")]
    InvalidInput { reason: String },
    #[error("control service stopped")]
    Stopped,
    #[error("requested routes conflict with an admitted or active profile")]
    RouteConflict,
    #[error("profile mutation executor is unavailable")]
    ProfileMutationUnavailable,
    #[error("profile is not in the canonical catalog")]
    ProfileNotFound,
    #[error("profile identity already exists in the canonical catalog")]
    ProfileAlreadyExists,
    #[error("profile is active; disconnect it before rename or delete")]
    ProfileActive,
    #[error("another operation already owns this profile")]
    ProfileBusy,
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
    #[error("terminal operation result could not be persisted")]
    Persistence,
    #[error("control service stopped")]
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReadinessError {
    #[error("authority epoch changed before readiness transition")]
    EpochMismatch,
    #[error("control service stopped")]
    Stopped,
    #[error("startup reconciliation could not be persisted")]
    Persistence,
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
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
    active_profile_operations: BTreeMap<ProfileId, BTreeMap<OperationId, ProfileOperationKind>>,
    readiness: ServiceReadiness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperationReservationError {
    RetentionFull,
    IdentifierExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileOperationKind {
    Lifecycle,
    Mutation,
}

impl AdmissionState {
    fn new(readiness: ServiceReadiness) -> Self {
        Self {
            next_operation: 0,
            next_challenge: 0,
            next_client: 0,
            retained_operations: 0,
            idempotency: BTreeMap::new(),
            terminal_operations: BTreeSet::new(),
            active_profile_operations: BTreeMap::new(),
            readiness,
        }
    }

    fn recover(
        readiness: ServiceReadiness,
        operations: &BTreeMap<OperationId, OperationRecord>,
    ) -> Self {
        let mut state = Self::new(readiness);
        for (operation_id, record) in operations {
            state.next_operation = state
                .next_operation
                .max(operation_id.sequence().unwrap_or_default());
            state.next_client = state
                .next_client
                .max(record.client_id.sequence().unwrap_or_default());
            state.idempotency.insert(
                IdempotencyScope {
                    client_id: record.client_id.clone(),
                    authority_epoch: record.authority_epoch,
                    key: record.idempotency_key.clone(),
                },
                IdempotencyBinding {
                    operation_id: operation_id.clone(),
                    command_digest: record.command_digest.clone(),
                },
            );
            if record.status.is_terminal() {
                state.terminal_operations.insert(operation_id.clone());
            } else {
                let kind = if matches!(record.intent, OperationIntent::ProfileMutation { .. }) {
                    ProfileOperationKind::Mutation
                } else {
                    ProfileOperationKind::Lifecycle
                };
                for profile_id in operation_intent_profiles(&record.intent) {
                    state
                        .active_profile_operations
                        .entry(profile_id)
                        .or_default()
                        .insert(operation_id.clone(), kind);
                }
            }
        }
        state.retained_operations = operations.len();
        state
    }

    fn compact_one(&mut self) -> Option<OperationId> {
        let operation_id = self.terminal_operations.pop_first()?;
        self.idempotency
            .retain(|_, binding| binding.operation_id != operation_id);
        self.retained_operations = self.retained_operations.saturating_sub(1);
        Some(operation_id)
    }

    fn compact_to_fit(
        &mut self,
        max_operations: usize,
        max_idempotency_keys: usize,
    ) -> Option<Vec<OperationId>> {
        let operation_slots = self
            .retained_operations
            .saturating_add(1)
            .saturating_sub(max_operations);
        let idempotency_slots = self
            .idempotency
            .len()
            .saturating_add(1)
            .saturating_sub(max_idempotency_keys);
        let required = operation_slots.max(idempotency_slots);
        (self.terminal_operations.len() >= required).then(|| {
            (0..required)
                .map(|_| {
                    self.compact_one()
                        .expect("terminal operation count was checked")
                })
                .collect()
        })
    }

    fn reserve_operation<'a>(
        &mut self,
        scope: IdempotencyScope,
        command_digest: PolicyDigest,
        active_profiles: impl IntoIterator<Item = &'a ProfileId>,
        operation_kind: ProfileOperationKind,
        config: &ControlServiceConfig,
    ) -> Result<(OperationId, Vec<OperationId>), OperationReservationError> {
        let sequence = self
            .next_operation
            .checked_add(1)
            .ok_or(OperationReservationError::IdentifierExhausted)?;
        let evicted = self
            .compact_to_fit(config.max_operations, config.max_idempotency_keys)
            .ok_or(OperationReservationError::RetentionFull)?;
        self.next_operation = sequence;
        let operation_id = OperationId::from_parts(scope.authority_epoch, sequence);
        self.retained_operations = self.retained_operations.saturating_add(1);
        self.idempotency.insert(
            scope,
            IdempotencyBinding {
                operation_id: operation_id.clone(),
                command_digest,
            },
        );
        for profile_id in active_profiles {
            self.active_profile_operations
                .entry(profile_id.clone())
                .or_default()
                .insert(operation_id.clone(), operation_kind);
        }
        Ok((operation_id, evicted))
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
        target_profiles: Vec<ProfileId>,
        lifecycle_profiles: Vec<ProfileId>,
        work_admissions: Vec<(ProfileId, ProfileAdmission)>,
        reply: oneshot::Sender<Result<AdmittedOperation, AdmissionError>>,
    },
    Observe {
        observation: Observation,
        reply: oneshot::Sender<Result<(), ObservationError>>,
    },
    ObserveBatch {
        observations: Vec<Observation>,
        reply: oneshot::Sender<Result<(), ObservationError>>,
    },
    Complete {
        completion: OperationCompletion,
        reply: oneshot::Sender<Result<CompletionResult, CompletionError>>,
    },
    IssueChallenge {
        record: ChallengeRecord,
        answer: std::sync::mpsc::SyncSender<Secret>,
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
    ProfileMutationCompleted {
        operation_id: OperationId,
        mutation: ProfileMutation,
        outcome: Result<ProfileMutationApplied, ProfileMutationFailure>,
        completed_after_deadline: bool,
    },
    Refresh,
}

struct ProfileMutationJob {
    work: ProfileMutationWork,
}

#[derive(Clone)]
struct ProfileMutationDispatcher(Arc<ProfileMutationDispatcherInner>);

struct ProfileMutationDispatcherInner {
    tx: Mutex<Option<std::sync::mpsc::SyncSender<ProfileMutationJob>>>,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    worker_done: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}

impl Drop for ProfileMutationDispatcherInner {
    fn drop(&mut self) {
        self.tx
            .lock()
            .expect("profile mutation sender mutex poisoned")
            .take();
        if let Some(worker) = self
            .worker
            .lock()
            .expect("profile mutation worker mutex poisoned")
            .take()
        {
            let finished = self
                .worker_done
                .lock()
                .expect("profile mutation completion mutex poisoned")
                .take()
                .is_some_and(|done| done.recv_timeout(Duration::from_millis(100)).is_ok());
            if finished {
                let _ = worker.join();
            }
            // A synchronous filesystem call cannot be force-cancelled safely.
            // Detach after the bounded grace instead of letting Drop defeat
            // the operation deadline and hang the CLI process indefinitely.
        }
    }
}

impl ProfileMutationDispatcher {
    fn start(
        executor: Arc<dyn ProfileMutationExecutor>,
        service_tx: &mpsc::Sender<Envelope>,
        clock: Arc<dyn Clock>,
        capacity: usize,
    ) -> Self {
        let service_tx = service_tx.downgrade();
        let (tx, rx) = std::sync::mpsc::sync_channel::<ProfileMutationJob>(capacity);
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("vortix-profile-mutations".to_owned())
            .spawn(move || {
                while let Ok(job) = rx.recv() {
                    let operation_id = job.work.operation_id.clone();
                    let deadline = job.work.deadline;
                    let mutation = job.work.mutation.clone();
                    let outcome = if deadline.0 <= clock.now_millis() {
                        Err(ProfileMutationFailure::DeadlineExpired)
                    } else {
                        executor.execute(job.work)
                    };
                    let completed_after_deadline = deadline.0 <= clock.now_millis();
                    let Some(service_tx) = service_tx.upgrade() else {
                        break;
                    };
                    if service_tx
                        .blocking_send(Envelope::ProfileMutationCompleted {
                            operation_id,
                            mutation,
                            outcome,
                            completed_after_deadline,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                let _ = done_tx.send(());
            })
            .expect("profile mutation worker must start");
        Self(Arc::new(ProfileMutationDispatcherInner {
            tx: Mutex::new(Some(tx)),
            worker: Mutex::new(Some(worker)),
            worker_done: Mutex::new(Some(done_rx)),
        }))
    }

    fn dispatch(&self, work: ProfileMutationWork) -> Result<(), ProfileMutationFailure> {
        self.0
            .tx
            .lock()
            .expect("profile mutation sender mutex poisoned")
            .as_ref()
            .ok_or(ProfileMutationFailure::Internal)?
            .try_send(ProfileMutationJob { work })
            .map_err(|error| match error {
                std::sync::mpsc::TrySendError::Full(_) => ProfileMutationFailure::Busy,
                std::sync::mpsc::TrySendError::Disconnected(_) => ProfileMutationFailure::Internal,
            })
    }
}

struct Shared {
    tx: mpsc::Sender<Envelope>,
    snapshots: watch::Receiver<ControlSnapshot>,
    events: broadcast::Sender<ControlEventEnvelope>,
    admission: Arc<Mutex<AdmissionState>>,
    clock: Arc<dyn Clock>,
    config: Arc<Mutex<ControlServiceConfig>>,
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
        mut config: ControlServiceConfig,
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
        if let Some(persistence) = &config.persistence {
            assert!(!persistence.boot_id.is_empty() && persistence.boot_id.len() <= 128);
        }
        enforce_interactive_boot_eligibility(&mut config);

        let readiness = ServiceReadiness {
            reconciliation_complete: config.persistence.is_none() && config.reconciliation_complete,
            authority_verified: config.authority_verified,
        };
        let (tx, rx) = mpsc::channel(config.command_capacity);
        let mut initial = ControlSnapshot {
            readiness,
            last_connected_at: config.initial_last_connected_at.clone(),
            ..ControlSnapshot::default()
        };
        initial.desired.authority_epoch = config.authority_epoch;
        initial.desired.kill_switch = config.initial_kill_switch_mode;
        let recovery = recover_control_state(&config, &mut initial);
        let mut durable = recovery.durable;
        let startup_persistence_fault = recovery.startup_persistence_fault;
        let recovered_control_state = recovery.recovered_control_state;
        durable.requested_resources = requested_resources(&config);
        recompute_policy_digest(&mut initial);
        durable.desired.clone_from(&initial.desired);
        if let Some(supervisor) = supervisor.as_deref() {
            if supervisor.restore_tombstones(&durable.tombstones).is_err() {
                durable.tombstones.clear();
            }
            restore_supervised_wireguard_evidence(&mut initial, supervisor);
        }
        let admission = Arc::new(Mutex::new(AdmissionState::recover(
            initial.readiness,
            &initial.operations,
        )));
        derive_effective(
            &mut initial,
            clock.now_millis(),
            selection,
            supervisor.as_deref(),
        );
        derive_tunnel_projections(&mut initial, None, &config);
        let (snapshot_tx, snapshots) = watch::channel(initial.clone());
        let (events, _) = broadcast::channel(config.event_capacity);
        let profile_mutations = config.profile_mutations.as_ref().map(|executor| {
            ProfileMutationDispatcher::start(
                Arc::clone(executor),
                &tx,
                Arc::clone(&clock),
                config.command_capacity,
            )
        });
        let shared_config = Arc::new(Mutex::new(config.clone()));
        let shared = Arc::new(Shared {
            tx,
            snapshots,
            events: events.clone(),
            admission: Arc::clone(&admission),
            clock: Arc::clone(&clock),
            config: Arc::clone(&shared_config),
            selection,
            supervisor: supervisor.clone(),
        });
        let client_id = {
            let mut state = admission.lock().expect("admission mutex poisoned");
            state.next_client = state
                .next_client
                .checked_add(1)
                .expect("recovered client identifier space must have capacity");
            ClientId::from_parts(initial.desired.authority_epoch, state.next_client)
        };
        tokio::spawn(run_service(
            rx,
            snapshot_tx,
            events,
            admission,
            clock,
            shared_config,
            initial,
            durable,
            startup_persistence_fault,
            recovered_control_state,
            selection,
            supervisor.clone(),
            profile_mutations,
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

    pub fn new_client(&self) -> Result<ControlHandle, AdmissionError> {
        let client_id = {
            let mut admission = self
                .shared
                .admission
                .lock()
                .expect("admission mutex poisoned");
            admission.next_client = admission
                .next_client
                .checked_add(1)
                .ok_or(AdmissionError::IdentifierExhausted)?;
            let authority_epoch = self
                .shared
                .config
                .lock()
                .expect("control config mutex poisoned")
                .authority_epoch;
            ClientId::from_parts(authority_epoch, admission.next_client)
        };
        Ok(ControlHandle {
            shared: Arc::clone(&self.shared),
            client_id,
        })
    }

    #[must_use]
    pub fn observer(&self) -> ObserverHandle {
        self.observer.clone()
    }

    #[must_use]
    pub fn completer(&self) -> CompleterHandle {
        self.completer.clone()
    }

    /// Cancel and join every supervised effect within the caller's process
    /// shutdown budget. Short-lived clients must call this before terminating
    /// so a recovery attempt cannot outlive its cleanup authority.
    #[must_use]
    pub fn shutdown_bounded(&self, timeout: Duration) -> bool {
        self.supervisor
            .as_ref()
            .is_none_or(|supervisor| supervisor.shutdown_bounded(timeout))
    }
}

fn enforce_interactive_boot_eligibility(config: &mut ControlServiceConfig) {
    for (profile_id, topology) in &config.profile_topologies {
        if topology.interactive_credentials {
            if let Some(connection) = config.boot_connections.get_mut(profile_id) {
                connection.eligibility =
                    crate::vortix_core::control::persistence::BootEligibility::InteractiveCredentials;
            }
        }
    }
}

impl Drop for ControlService {
    fn drop(&mut self) {
        let _ = self.shutdown_bounded(Duration::from_millis(250));
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

    /// Mark the latest publication as consumed and return it.
    #[must_use]
    pub fn current(&mut self) -> ControlSnapshot {
        let snapshot = self.snapshots.borrow_and_update().clone();
        self.minimum_generation = self.minimum_generation.max(snapshot.generation);
        snapshot
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

    /// Return a newer immutable publication without waiting or cloning when
    /// the watched generation is unchanged.
    pub fn take_changed(&mut self) -> Result<Option<ControlSnapshot>, EventReceiveError> {
        match self.snapshots.has_changed() {
            Ok(false) => Ok(None),
            Ok(true) => {
                let snapshot = self.snapshots.borrow_and_update().clone();
                self.minimum_generation = self.minimum_generation.max(snapshot.generation);
                Ok(Some(snapshot))
            }
            Err(_) => Err(EventReceiveError::Stopped),
        }
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
    pub async fn submit(
        &self,
        request: CommandRequest,
    ) -> Result<AdmittedOperation, AdmissionError> {
        if !request.idempotency_key.is_valid() {
            return Err(AdmissionError::InvalidInput {
                reason: "idempotency key must contain 1..=128 bytes".to_owned(),
            });
        }
        let config = self
            .shared
            .config
            .lock()
            .expect("control config mutex poisoned")
            .clone();
        let command_digest = command_digest(&request.command);
        let scope = IdempotencyScope {
            client_id: self.client_id.clone(),
            authority_epoch: config.authority_epoch,
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
        validate_profile_mutation_input(&request.command, &config)?;
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
        let (operation_id, evicted, target_profiles, lifecycle_profiles, work_admissions) = {
            // Catalog membership and topology must come from the same locked
            // snapshot. Profile-mutation completion updates this lock before
            // admission state, so lifecycle work can never reserve routes
            // from a stale topology for newly imported identity.
            let mut config = self
                .shared
                .config
                .lock()
                .expect("control config mutex poisoned");
            let mut admission = self
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
            validate_profile_mutation_input(&request.command, &config)?;
            let target_profiles = target_profiles_for_command(
                &request.command,
                &config.known_profiles,
                &self.shared.snapshots.borrow().desired.tunnels,
                self.shared.selection,
                self.shared.supervisor.as_deref(),
            )?;
            let operation_kind = if profile_mutation_for_command(&request.command).is_some() {
                ProfileOperationKind::Mutation
            } else {
                ProfileOperationKind::Lifecycle
            };
            if target_profiles.iter().any(|profile_id| {
                admission
                    .active_profile_operations
                    .get(profile_id)
                    .is_some_and(|operations| {
                        operation_kind == ProfileOperationKind::Mutation
                            || operations
                                .values()
                                .any(|kind| *kind == ProfileOperationKind::Mutation)
                    })
            }) {
                return Err(AdmissionError::ProfileBusy);
            }
            validate_profile_catalog_admission(
                &request.command,
                &config.known_profiles,
                &self.shared.snapshots.borrow(),
            )?;
            let conflict_acknowledgement = validate_topology_conflict_admission(
                &request.command,
                &self.shared.snapshots.borrow(),
                &config,
            )?;
            let lifecycle_profiles = lifecycle_profiles_for_command(
                &request.command,
                &target_profiles,
                self.shared.selection,
                self.shared.supervisor.as_deref(),
            )?;
            let mut work_admissions = Vec::new();
            if self.shared.selection == ExecutionSelection::CanonicalAuthority
                && profile_mutation_for_command(&request.command).is_none()
            {
                let supervisor = self
                    .shared
                    .supervisor
                    .as_ref()
                    .ok_or(AdmissionError::Stopped)?;
                for profile_id in &target_profiles {
                    // An exclusive switch reserves teardown capacity now, but
                    // deliberately reserves the target connect only after all
                    // competing tunnels are absent. That prevents the old
                    // routes from rejecting (or racing) the future target.
                    if matches!(
                        &request.command,
                        UserCommand::ConnectExclusive { profile_id: target }
                            if target == profile_id
                    ) {
                        continue;
                    }
                    let disconnecting = matches!(
                        request.command,
                        UserCommand::ConnectExclusive { .. }
                            | UserCommand::Disconnect { .. }
                            | UserCommand::ForceDisconnect { .. }
                    );
                    let reserved = if disconnecting {
                        supervisor.reserve_disconnect(profile_id)
                    } else {
                        let routes = config
                            .profile_topologies
                            .get(profile_id)
                            .map(|topology| topology.routes.iter().cloned().collect::<Vec<_>>())
                            .unwrap_or_default();
                        supervisor.reserve_tunnel_with_acknowledgement(
                            profile_id,
                            routes,
                            conflict_acknowledgement.as_ref(),
                        )
                    };
                    let reserved = reserved.map_err(|error| match error {
                        WorkFailure::RouteConflict => AdmissionError::RouteConflict,
                        WorkFailure::Stopped => AdmissionError::Stopped,
                        _ => AdmissionError::Busy,
                    })?;
                    work_admissions.push((profile_id.clone(), reserved));
                }
            }
            if let Some(profile_id) = command_profile(&request.command) {
                if !config.known_profiles.contains(profile_id)
                    && config.known_profiles.len() >= config.max_observed_profiles
                {
                    return Err(AdmissionError::InvalidInput {
                        reason: "known profile capacity is full".to_owned(),
                    });
                }
            }
            let (operation_id, evicted) = admission
                .reserve_operation(
                    scope,
                    command_digest.clone(),
                    &target_profiles,
                    operation_kind,
                    &config,
                )
                .map_err(|error| match error {
                    OperationReservationError::RetentionFull => AdmissionError::RetentionFull,
                    OperationReservationError::IdentifierExhausted => {
                        AdmissionError::IdentifierExhausted
                    }
                })?;
            if let Some(profile_id) = command_profile(&request.command) {
                if profile_mutation_for_command(&request.command).is_none() {
                    config.known_profiles.insert(profile_id.clone());
                }
            }
            (
                operation_id,
                evicted,
                target_profiles,
                lifecycle_profiles,
                work_admissions,
            )
        };
        let (reply, receiver) = oneshot::channel();
        permit.send(Envelope::Mutate {
            request,
            client_id: self.client_id.clone(),
            command_digest,
            operation_id: operation_id.clone(),
            admitted_at: now,
            evicted,
            target_profiles,
            lifecycle_profiles,
            work_admissions,
            reply,
        });
        receiver.await.map_err(|_| AdmissionError::Stopped)?
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
    /// Current authority-clock timestamp for observation receipts.
    #[must_use]
    pub fn now_millis(&self) -> u64 {
        self.0.clock.now_millis()
    }

    pub async fn observe(&self, observation: Observation) -> Result<(), ObservationError> {
        if observation_input_is_invalid(&observation) {
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

    /// Apply a bounded set of related observations in one actor transition.
    /// Validation is atomic: a rejected member publishes none of the batch.
    pub async fn observe_batch(
        &self,
        observations: Vec<Observation>,
    ) -> Result<(), ObservationError> {
        if observations.is_empty()
            || observations.len() > MAX_OBSERVATIONS_PER_BATCH
            || observations.iter().any(observation_input_is_invalid)
        {
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
        permit.send(Envelope::ObserveBatch {
            observations,
            reply,
        });
        receiver.await.map_err(|_| ObservationError::Stopped)?
    }
}

fn observation_input_is_invalid(observation: &Observation) -> bool {
    matches!(
        observation,
        Observation::Tunnel { interface_name: Some(name), .. }
            | Observation::DefaultRoute { interface_name: Some(name), .. }
            if name.len() > 256
    ) || matches!(
        observation,
        Observation::TunnelDetails { details, .. } if tunnel_details_exceed_bounds(details)
    ) || observation_evidence(observation)
        .is_some_and(|evidence| !evidence.policy_digest.is_valid())
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
            admission.next_challenge = admission
                .next_challenge
                .checked_add(1)
                .ok_or(ChallengeError::RetentionFull)?;
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
        let (answer, response) = std::sync::mpsc::sync_channel(1);
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

    /// Issue a challenge from a bounded protocol worker. Only that worker
    /// blocks; the service actor remains free to process the answer, expiry,
    /// cancellation, and observations.
    pub fn issue_challenge_blocking(
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
            admission.next_challenge = admission
                .next_challenge
                .checked_add(1)
                .ok_or(ChallengeError::RetentionFull)?;
            ChallengeId::from_counter(admission.next_challenge)
        };
        // Dispatch can start on its worker thread just before the actor
        // publishes the admission snapshot. Wait only for that bounded
        // publication boundary; never wait on the actor's command queue.
        let authorized_client = loop {
            if let Some(client) = self
                .0
                .snapshots
                .borrow()
                .operations
                .get(&operation_id)
                .filter(|record| !record.status.is_terminal())
                .map(|record| record.client_id.clone())
            {
                break client;
            }
            if self.0.clock.now_millis() >= expires_at_millis {
                return Err(ChallengeError::OperationInactive);
            }
            std::thread::sleep(Duration::from_millis(1));
        };
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
        let (answer, response) = std::sync::mpsc::sync_channel(1);
        let (reply, receiver) = oneshot::channel();
        permit.send(Envelope::IssueChallenge {
            record,
            answer,
            reply,
        });
        let record = receiver
            .blocking_recv()
            .map_err(|_| ChallengeError::Stopped)??;
        Ok(IssuedChallenge {
            record,
            response: ChallengeAnswerReceiver(response),
        })
    }

    #[must_use]
    pub fn now_millis(&self) -> u64 {
        self.0.clock.now_millis()
    }
}

/// Issuance result whose one-shot secret receiver belongs to the worker.
pub struct IssuedChallenge {
    pub record: ChallengeRecord,
    pub response: ChallengeAnswerReceiver,
}

pub struct ChallengeAnswerReceiver(std::sync::mpsc::Receiver<Secret>);

impl ChallengeAnswerReceiver {
    pub async fn receive(self) -> Result<Secret, ChallengeDeliveryError> {
        tokio::task::spawn_blocking(move || self.0.recv())
            .await
            .map_err(|_| ChallengeDeliveryError::Closed)?
            .map_err(|_| ChallengeDeliveryError::Closed)
    }

    pub fn receive_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Option<Secret>, ChallengeDeliveryError> {
        match self.0.recv_timeout(timeout) {
            Ok(secret) => Ok(Some(secret)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err(ChallengeDeliveryError::Closed)
            }
        }
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

#[derive(Default)]
struct OwnerState {
    challenge_terminals: BTreeMap<ChallengeId, ChallengeTerminal>,
    challenge_answers: BTreeMap<ChallengeId, std::sync::mpsc::SyncSender<Secret>>,
    observation_clocks: BTreeMap<ObservationScope, u64>,
    work_admissions: BTreeMap<(OperationId, ProfileId), ProfileAdmission>,
    reconnect_operations: BTreeMap<OperationId, ReconnectOperation>,
    exclusive_switch_operations: BTreeMap<OperationId, ExclusiveSwitchOperation>,
    tunnel_revisions: BTreeMap<ProfileId, TunnelRevision>,
    recovery_operations: BTreeSet<OperationId>,
    unexpected_recoveries: BTreeMap<OperationId, UnexpectedRecovery>,
    lifecycle_operations: BTreeMap<OperationId, LifecycleOperation>,
    topology_transaction: Option<TopologyTransaction>,
    next_lifecycle_event: u64,
    diagnostics: crate::vortix_core::control::DiagnosticBuffer,
}

impl OwnerState {
    fn release_operation_admission(&mut self, operation_id: &OperationId) {
        self.work_admissions
            .retain(|(operation, _), _| operation != operation_id);
        self.reconnect_operations.remove(operation_id);
        self.exclusive_switch_operations.remove(operation_id);
        self.unexpected_recoveries.remove(operation_id);
        if self
            .topology_transaction
            .as_ref()
            .is_some_and(|transaction| &transaction.pre_policy.operation_id == operation_id)
        {
            self.topology_transaction = None;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnexpectedRecoveryPhase {
    NeedsPreBlock,
    PreBlockPending,
    WaitingBackoff,
    AttemptInFlight,
}

#[derive(Debug)]
struct UnexpectedRecovery {
    profiles: BTreeSet<ProfileId>,
    phase: UnexpectedRecoveryPhase,
    next_attempt_millis: u64,
    backoff_millis: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TopologyTransactionPhase {
    NeedsPreBlock,
    PreBlockPending,
    TunnelsAllowed,
    FinalPending,
    FinalApplied,
}

#[derive(Debug, Clone)]
struct TopologyTransaction {
    /// Immutable safety policy captured before the first tunnel mutation.
    pre_policy: TopologyPolicy,
    /// Current-generation topology sealed once after tunnel observation.
    final_policy: Option<TopologyPolicy>,
    phase: TopologyTransactionPhase,
}

#[derive(Debug)]
struct ReconnectOperation {
    targets: BTreeSet<ProfileId>,
    teardown_dispatched: BTreeSet<ProfileId>,
}

#[derive(Debug)]
struct ExclusiveSwitchOperation {
    target: ProfileId,
    teardown: BTreeSet<ProfileId>,
}

impl ReconnectOperation {
    fn includes(&self, profile_id: &ProfileId) -> bool {
        self.targets.contains(profile_id)
    }

    fn can_reconnect(&self, profile_id: &ProfileId) -> bool {
        self.includes(profile_id) && self.teardown_dispatched.contains(profile_id)
    }
}

#[derive(Debug)]
struct LifecycleOperation {
    legs: Vec<LifecycleLeg>,
}

#[derive(Debug)]
struct LifecycleLeg {
    profiles: Vec<ProfileId>,
    success: HookEvent,
    failure: Option<HookEvent>,
}

struct LifecycleRegistration {
    operation: LifecycleOperation,
    started: Vec<(Vec<ProfileId>, HookEvent)>,
}

struct DeferredReadiness {
    reply: oneshot::Sender<Result<(), ReadinessError>>,
    readiness: ServiceReadiness,
}

enum DeferredDurability {
    Admission {
        operation_id: OperationId,
        reply: oneshot::Sender<Result<AdmittedOperation, AdmissionError>>,
    },
    Completion {
        result: Result<CompletionResult, CompletionError>,
        reply: oneshot::Sender<Result<CompletionResult, CompletionError>>,
    },
}

fn send_durability_reply(deferred: DeferredDurability, persisted: bool) {
    match deferred {
        DeferredDurability::Admission {
            operation_id,
            reply,
        } => {
            let result = if persisted {
                Ok(AdmittedOperation { operation_id })
            } else {
                Err(AdmissionError::Persistence)
            };
            let _ = reply.send(result);
        }
        DeferredDurability::Completion { result, reply } => {
            let result = match result {
                Ok(_) if !persisted => Err(CompletionError::Persistence),
                result => result,
            };
            let _ = reply.send(result);
        }
    }
}

struct ControlRuntime<'a> {
    config: &'a ControlServiceConfig,
    admission: &'a Arc<Mutex<AdmissionState>>,
    supervisor: Option<&'a Supervisor>,
    selection: ExecutionSelection,
    startup_persistence_fault: bool,
}

impl ControlRuntime<'_> {
    async fn advance(
        &self,
        before: &ControlSnapshot,
        snapshot: &mut ControlSnapshot,
        durable: &mut DurableControlState,
        owner: &mut OwnerState,
        now: u64,
        events: &mut Vec<ControlEvent>,
    ) -> bool {
        submit_emergency_pre_block_before_persistence(
            self.supervisor,
            snapshot,
            owner,
            self.admission,
            now,
            self.selection,
            self.config,
            events,
        );
        let persisted_before_effects = persist_control_state_if_changed(
            self.config,
            before,
            snapshot,
            durable,
            self.supervisor,
            self.admission,
            self.startup_persistence_fault,
        )
        .await;
        if persisted_before_effects {
            let before_supervision = snapshot.clone();
            drive_supervision(
                self.selection,
                self.supervisor,
                snapshot,
                owner,
                self.admission,
                now,
                self.config,
                events,
            );
            derive_effective(snapshot, now, self.selection, self.supervisor);
            let _ = persist_control_state_if_changed(
                self.config,
                &before_supervision,
                snapshot,
                durable,
                self.supervisor,
                self.admission,
                self.startup_persistence_fault,
            )
            .await;
        } else {
            derive_effective(snapshot, now, self.selection, self.supervisor);
        }
        let projection_inputs_changed = snapshot.desired != before.desired
            || snapshot.observed != before.observed
            || snapshot.operations != before.operations
            || snapshot.challenges != before.challenges;
        if projection_inputs_changed {
            derive_tunnel_projections(snapshot, Some(owner), self.config);
        } else {
            derive_dns_security_projection(snapshot, self.config);
        }
        persisted_before_effects
    }
}

#[allow(clippy::too_many_arguments)]
fn submit_emergency_pre_block_before_persistence(
    supervisor: Option<&Supervisor>,
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    admission: &Arc<Mutex<AdmissionState>>,
    now: u64,
    selection: ExecutionSelection,
    config: &ControlServiceConfig,
    events: &mut Vec<ControlEvent>,
) {
    let Some(supervisor) = supervisor else {
        return;
    };
    let is_unexpected_recovery = owner
        .topology_transaction
        .as_ref()
        .filter(|transaction| transaction.phase == TopologyTransactionPhase::NeedsPreBlock)
        .and_then(|transaction| {
            snapshot
                .operations
                .get(&transaction.pre_policy.operation_id)
        })
        .is_some_and(|operation| {
            matches!(operation.intent, OperationIntent::UnexpectedRecovery { .. })
        });
    if is_unexpected_recovery
        && snapshot.desired.kill_switch
            == crate::vortix_core::state::killswitch::KillSwitchMode::Auto
    {
        submit_required_pre_block(
            supervisor, snapshot, owner, admission, now, selection, config, events,
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ObservationScope {
    Protection,
    Profile(ProfileId),
    Route,
    Dns,
    Firewall,
}

struct RecoveryOutcome {
    durable: DurableControlState,
    startup_persistence_fault: bool,
    recovered_control_state: bool,
}

fn recover_control_state(
    config: &ControlServiceConfig,
    snapshot: &mut ControlSnapshot,
) -> RecoveryOutcome {
    let mut durable = durable_state(config, snapshot);
    let Some(persistence) = &config.persistence else {
        return RecoveryOutcome {
            durable,
            startup_persistence_fault: false,
            recovered_control_state: false,
        };
    };
    match persistence.store.load(&persistence.boot_id) {
        Ok(Some(recovered))
            if recovered.state.desired.authority_epoch == config.authority_epoch
                && recovered_identifiers_have_capacity(&recovered.state) =>
        {
            let same_boot = recovered.same_boot;
            durable = recovered.state;
            durable
                .boot_connections
                .clone_from(&config.boot_connections);
            if !same_boot {
                durable.prepare_for_reboot();
            }
            snapshot.desired.clone_from(&durable.desired);
            snapshot.operations.clone_from(&durable.operations);
            for (profile_id, connected_at) in &durable.last_connected_at {
                snapshot
                    .last_connected_at
                    .entry(profile_id.clone())
                    .and_modify(|current| *current = (*current).max(*connected_at))
                    .or_insert(*connected_at);
            }
            RecoveryOutcome {
                durable,
                startup_persistence_fault: false,
                recovered_control_state: true,
            }
        }
        Ok(None) => RecoveryOutcome {
            durable,
            startup_persistence_fault: false,
            recovered_control_state: false,
        },
        Ok(Some(_)) | Err(_) => {
            snapshot.readiness.authority_verified = false;
            RecoveryOutcome {
                durable,
                startup_persistence_fault: true,
                recovered_control_state: false,
            }
        }
    }
}

fn recovered_identifiers_have_capacity(state: &DurableControlState) -> bool {
    state.operations.iter().all(|(operation_id, operation)| {
        operation_id
            .sequence()
            .is_some_and(|sequence| sequence < u64::MAX)
            && operation
                .client_id
                .sequence()
                .is_some_and(|sequence| sequence < u64::MAX)
    })
}

fn durable_state(config: &ControlServiceConfig, snapshot: &ControlSnapshot) -> DurableControlState {
    DurableControlState {
        desired: snapshot.desired.clone(),
        operations: snapshot.operations.clone(),
        boot_connections: config.boot_connections.clone(),
        requested_resources: requested_resources(config),
        last_connected_at: snapshot.last_connected_at.clone(),
        tombstones: BTreeMap::new(),
        retention: RetentionMetadata::default(),
        reconciliation_required: !snapshot.readiness.reconciliation_complete,
    }
}

fn requested_resources(config: &ControlServiceConfig) -> BTreeMap<ProfileId, RequestedResources> {
    config
        .profile_topologies
        .iter()
        .map(|(profile_id, topology)| {
            (
                profile_id.clone(),
                RequestedResources {
                    routes: topology.routes.clone(),
                    dns_digest: topology.dns_digest.clone(),
                    firewall_digest: topology.firewall_digest.clone(),
                },
            )
        })
        .collect()
}

fn persisted_tombstones(
    supervisor: Option<&Supervisor>,
    policy_digest: &PolicyDigest,
) -> BTreeMap<ProfileId, PersistedTombstone> {
    supervisor
        .map(Supervisor::tombstones)
        .unwrap_or_default()
        .into_iter()
        .map(|(profile_id, tombstone)| {
            let teardown_failed = matches!(
                tombstone.truth,
                SupervisedTruth::Degraded(_) | SupervisedTruth::OutcomeUnknown
            );
            (
                profile_id,
                PersistedTombstone {
                    authority_epoch: tombstone.revision.authority_epoch,
                    generation: tombstone.revision.generation,
                    resource_generation: Some(tombstone.resource_revision.generation),
                    policy_digest: policy_digest.clone(),
                    operation_id: tombstone.operation_id,
                    teardown_failed,
                },
            )
        })
        .collect()
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one actor loop owns bounded channels, durability, and authority state"
)]
async fn run_service(
    mut rx: mpsc::Receiver<Envelope>,
    snapshot_tx: watch::Sender<ControlSnapshot>,
    events: broadcast::Sender<ControlEventEnvelope>,
    admission: Arc<Mutex<AdmissionState>>,
    clock: Arc<dyn Clock>,
    shared_config: Arc<Mutex<ControlServiceConfig>>,
    mut snapshot: ControlSnapshot,
    mut durable: DurableControlState,
    startup_persistence_fault: bool,
    recovered_control_state: bool,
    selection: ExecutionSelection,
    supervisor: Option<Arc<Supervisor>>,
    profile_mutations: Option<ProfileMutationDispatcher>,
) {
    let startup_now = clock.now_millis();
    let initial_config = shared_config
        .lock()
        .expect("control config mutex poisoned")
        .clone();
    let tunnel_revisions = initial_tunnel_revisions(&snapshot, supervisor.as_deref());
    let exclusive_switch_operations = recover_exclusive_switch_operations(&snapshot);
    let mut owner = OwnerState {
        challenge_terminals: BTreeMap::new(),
        challenge_answers: BTreeMap::new(),
        observation_clocks: BTreeMap::new(),
        work_admissions: BTreeMap::new(),
        reconnect_operations: BTreeMap::new(),
        exclusive_switch_operations,
        tunnel_revisions,
        recovery_operations: snapshot
            .operations
            .values()
            .filter(|operation| {
                !operation.status.is_terminal()
                    && operation.desired_generation == snapshot.desired.generation
            })
            .map(|operation| operation.id.clone())
            .collect(),
        unexpected_recoveries: restored_unexpected_recoveries(
            &snapshot,
            &initial_config,
            startup_now,
        ),
        lifecycle_operations: BTreeMap::new(),
        topology_transaction: None,
        next_lifecycle_event: 0,
        diagnostics: crate::vortix_core::control::DiagnosticBuffer::default(),
    };
    let mut ticker = tokio::time::interval(initial_config.freshness_poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            envelope = rx.recv() => {
                let Some(envelope) = envelope else { break };
                let before = snapshot.clone();
                let mut pending = Vec::new();
                let mut readiness_reply = None;
                let mut durability_reply = None;
                let now = clock.now_millis();
                let config = shared_config
                    .lock()
                    .expect("control config mutex poisoned")
                    .clone();
                expire_operations(&mut snapshot, &mut owner, &admission, now, &config, selection, &mut pending);
                expire_challenges(&mut snapshot, &mut owner, now, config.max_challenges, &mut pending);
                handle_envelope(envelope, &mut snapshot, &mut owner, &admission, now, &config, &shared_config, profile_mutations.as_ref(), startup_persistence_fault, &mut readiness_reply, &mut durability_reply, &mut pending);
                admit_unexpected_loss_recovery(
                    &before,
                    &mut snapshot,
                    &mut owner,
                    &admission,
                    now,
                    &config,
                    selection,
                    supervisor.as_deref(),
                    &mut pending,
                );
                if recovered_control_state
                    && !before.readiness.reconciliation_complete
                    && snapshot.readiness.reconciliation_complete
                {
                    let generation = snapshot.desired.generation;
                    start_recovery_operation(
                        &mut snapshot,
                        &mut owner,
                        &admission,
                        now,
                        selection,
                        generation,
                        &config,
                        &mut pending,
                    );
                }
                let config = shared_config
                    .lock()
                    .expect("control config mutex poisoned")
                    .clone();
                let runtime = ControlRuntime {
                    config: &config,
                    admission: &admission,
                    supervisor: supervisor.as_deref(),
                    selection,
                    startup_persistence_fault,
                };
                let persisted = runtime.advance(&before, &mut snapshot, &mut durable, &mut owner, now, &mut pending).await;
                if let Some(deferred) = readiness_reply {
                    let result = if snapshot.readiness == deferred.readiness {
                        admission
                            .lock()
                            .expect("admission mutex poisoned")
                            .readiness = deferred.readiness;
                        Ok(())
                    } else {
                        Err(ReadinessError::Persistence)
                    };
                    let _ = deferred.reply.send(result);
                }
                if let Some(deferred) = durability_reply {
                    send_durability_reply(deferred, persisted);
                }
                if snapshot != before || !pending.is_empty() {
                    publish_then_events(&mut snapshot, &mut owner, &snapshot_tx, &events, pending, now);
                }
            }
            _ = ticker.tick() => {
                let before = snapshot.clone();
                let mut pending = Vec::new();
                let now = clock.now_millis();
                let config = shared_config
                    .lock()
                    .expect("control config mutex poisoned")
                    .clone();
                expire_operations(&mut snapshot, &mut owner, &admission, now, &config, selection, &mut pending);
                expire_challenges(&mut snapshot, &mut owner, now, config.max_challenges, &mut pending);
                let runtime = ControlRuntime {
                    config: &config,
                    admission: &admission,
                    supervisor: supervisor.as_deref(),
                    selection,
                    startup_persistence_fault,
                };
                runtime.advance(&before, &mut snapshot, &mut durable, &mut owner, now, &mut pending).await;
                if snapshot != before || !pending.is_empty() {
                    publish_then_events(&mut snapshot, &mut owner, &snapshot_tx, &events, pending, now);
                }
            }
        }
    }
}

/// Rebuild the process-local ordering guard from the exact durable intent.
/// An exclusive switch is the only command whose subset contains one connect
/// and one or more disconnects in the current desired generation.
fn recover_exclusive_switch_operations(
    snapshot: &ControlSnapshot,
) -> BTreeMap<OperationId, ExclusiveSwitchOperation> {
    snapshot
        .operations
        .values()
        .filter(|operation| {
            !operation.status.is_terminal()
                && operation.desired_generation == snapshot.desired.generation
        })
        .filter_map(|operation| {
            let OperationIntent::DesiredSubset {
                tunnels,
                kill_switch: None,
            } = &operation.intent
            else {
                return None;
            };
            if tunnels != &snapshot.desired.tunnels {
                return None;
            }
            let mut connected = tunnels
                .iter()
                .filter(|(_, requested)| **requested == RequestedTunnelState::Connected)
                .map(|(profile_id, _)| profile_id.clone());
            let target = connected.next()?;
            if connected.next().is_some() {
                return None;
            }
            let teardown = tunnels
                .iter()
                .filter(|(_, requested)| **requested == RequestedTunnelState::Disconnected)
                .map(|(profile_id, _)| profile_id.clone())
                .collect::<BTreeSet<_>>();
            (!teardown.is_empty()).then(|| {
                (
                    operation.id.clone(),
                    ExclusiveSwitchOperation { target, teardown },
                )
            })
        })
        .collect()
}

fn initial_tunnel_revisions(
    snapshot: &ControlSnapshot,
    supervisor: Option<&Supervisor>,
) -> BTreeMap<ProfileId, TunnelRevision> {
    let recovered = TunnelRevision {
        authority_epoch: snapshot.desired.authority_epoch,
        generation: snapshot.desired.generation,
    };
    let mut revisions = snapshot
        .desired
        .tunnels
        .keys()
        .cloned()
        .map(|profile_id| (profile_id, recovered))
        .collect::<BTreeMap<_, _>>();
    if let Some(supervisor) = supervisor {
        revisions.extend(
            supervisor
                .profiles()
                .into_iter()
                .map(|(profile_id, state)| (profile_id, state.revision)),
        );
        revisions.extend(
            supervisor
                .tombstones()
                .into_iter()
                .map(|(profile_id, tombstone)| (profile_id, tombstone.revision)),
        );
    }
    revisions
}

async fn persist_control_state_if_changed(
    config: &ControlServiceConfig,
    before: &ControlSnapshot,
    snapshot: &mut ControlSnapshot,
    durable: &mut DurableControlState,
    supervisor: Option<&Supervisor>,
    admission: &Arc<Mutex<AdmissionState>>,
    startup_persistence_fault: bool,
) -> bool {
    let Some(persistence) = &config.persistence else {
        return true;
    };
    if startup_persistence_fault {
        return false;
    }
    let tombstones = persisted_tombstones(supervisor, &snapshot.desired.policy_digest);
    let requested_resources = requested_resources(config);
    if durable.desired == snapshot.desired
        && durable.operations == snapshot.operations
        && durable.reconciliation_required != snapshot.readiness.reconciliation_complete
        && durable.tombstones == tombstones
        && durable.last_connected_at == snapshot.last_connected_at
        && durable.requested_resources == requested_resources
    {
        return true;
    }
    let mut candidate = durable.clone();
    candidate.retention.compacted_operations =
        candidate.retention.compacted_operations.saturating_add(
            before
                .operations
                .keys()
                .filter(|operation_id| !snapshot.operations.contains_key(*operation_id))
                .count() as u64,
        );
    candidate.desired.clone_from(&snapshot.desired);
    candidate.operations.clone_from(&snapshot.operations);
    candidate.tombstones = tombstones;
    candidate
        .last_connected_at
        .clone_from(&snapshot.last_connected_at);
    candidate.requested_resources = requested_resources;
    candidate.reconciliation_required = !snapshot.readiness.reconciliation_complete;
    let store = Arc::clone(&persistence.store);
    let boot_id = persistence.boot_id.clone();
    let state = candidate.clone();
    let saved = match tokio::task::spawn_blocking(move || store.save(&boot_id, &state)).await {
        Ok(Ok(())) => true,
        Ok(Err(error)) => {
            tracing::error!(
                target: "vortix::control::persistence",
                %error,
                operation_count = candidate.operations.len(),
                max_operations = config.max_operations,
                "durable control state persistence failed"
            );
            false
        }
        Err(error) => {
            tracing::error!(
                target: "vortix::control::persistence",
                %error,
                operation_count = candidate.operations.len(),
                max_operations = config.max_operations,
                "durable control state persistence task failed"
            );
            false
        }
    };
    if saved {
        *durable = candidate;
        return true;
    }
    snapshot
        .last_connected_at
        .clone_from(&before.last_connected_at);
    snapshot.readiness.reconciliation_complete = false;
    admission
        .lock()
        .expect("admission mutex poisoned")
        .readiness
        .reconciliation_complete = false;
    false
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
    if selection == ExecutionSelection::LegacyAuthority
        || !snapshot.readiness.reconciliation_complete
        || !snapshot.readiness.authority_verified
    {
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
        if result.result.is_ok() {
            if result.mutation == TunnelMutation::Disconnect {
                // A successful disconnect is already an exact protocol-owned
                // absence receipt: OpenVPN proves the custodian receipt,
                // socket, and process group are gone; WireGuard proves the
                // interface is absent. Settle only the exact supervised
                // revision, and do not route this trusted receipt through the
                // scanner-drift reducer, which invalidates unrelated policy
                // gates.
                if supervisor
                    .confirm_tunnel(&result.profile_id, &result.revision, false, None)
                    .is_ok()
                {
                    snapshot.pending_route_conflicts.remove(&result.profile_id);
                    record_owned_disconnect(&result.profile_id, snapshot, owner, now);
                }
            } else {
                snapshot.pending_route_conflicts.remove(&result.profile_id);
            }
        }
        if let Some(routes) = result
            .openvpn_routes
            .as_ref()
            .filter(|_| result.result.is_ok())
        {
            snapshot.observed.openvpn_routes.insert(
                result.profile_id.clone(),
                crate::vortix_core::control::model::ObservedOpenVpnRoutes {
                    desired_generation: result.revision.generation,
                    evidence: routes.clone(),
                },
            );
        }
        if let Some(dns) = result
            .openvpn_dns
            .as_ref()
            .filter(|_| result.result.is_ok())
        {
            snapshot.observed.openvpn_dns.insert(
                result.profile_id.clone(),
                crate::vortix_core::control::model::ObservedOpenVpnDns {
                    desired_generation: result.revision.generation,
                    request: dns.clone(),
                },
            );
        }
        if let Some(handshake) = result.handshake.as_ref().filter(|handshake| {
            result.result.is_ok() && handshake.generation == result.revision.generation
        }) {
            snapshot
                .observed
                .wireguard_handshakes
                .insert(result.profile_id.clone(), handshake.clone());
            snapshot
                .observed
                .wireguard_probe_receipts
                .insert(result.profile_id.clone(), result.probe_receipts.clone());
            events.push(ControlEvent::WireGuardHandshakeObserved {
                profile_id: result.profile_id.clone(),
                desired_generation: result.revision.generation,
                handshake_at_millis: system_time_millis(handshake.handshake_at),
                observed_at_millis: system_time_millis(handshake.observed_at),
            });
        }
        if result.result.is_err() {
            let unexpected_retry = schedule_unexpected_recovery_backoff(
                owner,
                snapshot,
                &result.operation_id,
                &result.profile_id,
                now,
            );
            snapshot.observed.openvpn_routes.remove(&result.profile_id);
            snapshot.observed.openvpn_dns.remove(&result.profile_id);
            snapshot
                .observed
                .wireguard_handshakes
                .remove(&result.profile_id);
            snapshot
                .observed
                .wireguard_probe_receipts
                .remove(&result.profile_id);
            let wireguard_handshake_failure = result.result == Err(WorkFailure::HandshakeFailed)
                || (result.result == Err(WorkFailure::TimedOut)
                    && result.mutation == TunnelMutation::Connect
                    && config
                        .profile_topologies
                        .get(&result.profile_id)
                        .is_some_and(|topology| {
                            topology.protocol
                                == Some(crate::vortix_core::profile::ProtocolKind::WireGuard)
                        }));
            if let Some(conflict) = result
                .route_conflict
                .clone()
                .filter(|_| result.result == Err(WorkFailure::RouteConflict))
            {
                let retired = result.mutation == TunnelMutation::Connect
                    && supervisor
                        .retire_definitive_connect_failure(
                            &result.profile_id,
                            &result.revision,
                            &result.operation_id,
                        )
                        .is_ok();
                if retired {
                    let conflicted_operation_id =
                        operation_for_generation(snapshot, result.revision.generation).map_or_else(
                            || result.operation_id.clone(),
                            |operation| operation.id.clone(),
                        );
                    snapshot
                        .pending_route_conflicts
                        .insert(result.profile_id.clone(), conflict.clone());
                    events.push(ControlEvent::ConnectAttemptBlockedByConflict {
                        conflict,
                        profile_id: result.profile_id.clone(),
                    });
                    let completion = complete_operation(
                        OperationCompletion {
                            operation_id: conflicted_operation_id,
                            desired_generation: result.revision.generation,
                            outcome: CompletionOutcome::Failed(OperationFailure::Rejected),
                        },
                        snapshot,
                        owner,
                        admission,
                        now,
                        config,
                        events,
                    );
                    if matches!(completion, Ok(CompletionResult::Terminal(_))) {
                        rollback_connect_intent(
                            std::slice::from_ref(&result.profile_id),
                            result.revision.generation,
                            snapshot,
                            owner,
                            now,
                            events,
                        );
                    }
                }
            } else if unexpected_retry {
                if wireguard_handshake_failure {
                    events.push(ControlEvent::ConnectAttemptFailed {
                        profile_id: result.profile_id.clone(),
                        attempt: 1,
                        reason: crate::vortix_core::engine::state::FailureReason::HandshakeFailed(
                            "current-generation WireGuard peer evidence was not observed".into(),
                        ),
                    });
                }
            } else if matches!(
                result.result,
                Err(WorkFailure::AuthenticationFailed | WorkFailure::InvalidProfile)
            ) {
                let rollback_profiles = snapshot
                    .operations
                    .get(&result.operation_id)
                    .and_then(|operation| operation_intent_tunnels(&operation.intent))
                    .map_or_else(
                        || vec![result.profile_id.clone()],
                        |tunnels| {
                            tunnels
                                .iter()
                                .filter(|(_, requested)| {
                                    **requested == RequestedTunnelState::Connected
                                })
                                .map(|(profile_id, _)| profile_id.clone())
                                .collect::<Vec<_>>()
                        },
                    );
                let operation_failure = if result.result == Err(WorkFailure::AuthenticationFailed) {
                    OperationFailure::AuthenticationFailed
                } else {
                    OperationFailure::InvalidProfile
                };
                let retired = result.mutation == TunnelMutation::Connect
                    && supervisor
                        .retire_definitive_connect_failure(
                            &result.profile_id,
                            &result.revision,
                            &result.operation_id,
                        )
                        .is_ok();
                if retired {
                    let completion = complete_operation(
                        OperationCompletion {
                            operation_id: result.operation_id.clone(),
                            desired_generation: result.revision.generation,
                            outcome: CompletionOutcome::Failed(operation_failure),
                        },
                        snapshot,
                        owner,
                        admission,
                        now,
                        config,
                        events,
                    );
                    if matches!(completion, Ok(CompletionResult::Terminal(_))) {
                        rollback_connect_intent(
                            &rollback_profiles,
                            result.revision.generation,
                            snapshot,
                            owner,
                            now,
                            events,
                        );
                    }
                } else {
                    fail_tunnel_dispatch_operation(
                        &result.operation_id,
                        result.revision.generation,
                        result.result.expect_err("matched definitive failure"),
                        snapshot,
                        owner,
                        admission,
                        now,
                        selection,
                        config,
                        events,
                    );
                }
            } else if result.result == Err(WorkFailure::ChallengeFailed) {
                let rollback_profiles = snapshot
                    .operations
                    .get(&result.operation_id)
                    .and_then(|operation| match &operation.intent {
                        OperationIntent::DesiredSubset { tunnels, .. }
                        | OperationIntent::UnexpectedRecovery { tunnels, .. } => Some(
                            tunnels
                                .iter()
                                .filter(|(_, requested)| {
                                    **requested == RequestedTunnelState::Connected
                                })
                                .map(|(profile_id, _)| profile_id.clone())
                                .collect::<Vec<_>>(),
                        ),
                        OperationIntent::GenerationScoped
                        | OperationIntent::ProfileMutation { .. } => None,
                    })
                    .unwrap_or_else(|| vec![result.profile_id.clone()]);
                let completion = complete_operation(
                    OperationCompletion {
                        operation_id: result.operation_id.clone(),
                        desired_generation: result.revision.generation,
                        outcome: CompletionOutcome::Failed(OperationFailure::Rejected),
                    },
                    snapshot,
                    owner,
                    admission,
                    now,
                    config,
                    events,
                );
                if matches!(completion, Ok(CompletionResult::Terminal(_))) {
                    rollback_connect_intent(
                        &rollback_profiles,
                        result.revision.generation,
                        snapshot,
                        owner,
                        now,
                        events,
                    );
                }
            } else if wireguard_handshake_failure {
                let was_recovery = owner.recovery_operations.contains(&result.operation_id);
                let rollback_profiles = snapshot
                    .operations
                    .get(&result.operation_id)
                    .and_then(|operation| operation_intent_tunnels(&operation.intent))
                    .map_or_else(
                        || vec![result.profile_id.clone()],
                        |tunnels| {
                            tunnels
                                .iter()
                                .filter(|(_, requested)| {
                                    **requested == RequestedTunnelState::Connected
                                })
                                .map(|(profile_id, _)| profile_id.clone())
                                .collect::<Vec<_>>()
                        },
                    );
                events.push(ControlEvent::ConnectAttemptFailed {
                    profile_id: result.profile_id.clone(),
                    attempt: 1,
                    reason: crate::vortix_core::engine::state::FailureReason::HandshakeFailed(
                        "current-generation WireGuard peer evidence was not observed".into(),
                    ),
                });
                let retired = result.result == Err(WorkFailure::HandshakeFailed)
                    && result.mutation == TunnelMutation::Connect
                    && supervisor
                        .retire_definitive_connect_failure(
                            &result.profile_id,
                            &result.revision,
                            &result.operation_id,
                        )
                        .is_ok();
                let completion = complete_operation(
                    OperationCompletion {
                        operation_id: result.operation_id.clone(),
                        desired_generation: result.revision.generation,
                        outcome: CompletionOutcome::Failed(OperationFailure::HandshakeFailed),
                    },
                    snapshot,
                    owner,
                    admission,
                    now,
                    config,
                    events,
                );
                if matches!(
                    completion,
                    Ok(CompletionResult::Terminal(OperationStatus::Failed))
                ) {
                    if was_recovery && retired {
                        rollback_connect_intent(
                            &rollback_profiles,
                            result.revision.generation,
                            snapshot,
                            owner,
                            now,
                            events,
                        );
                    } else if !was_recovery {
                        start_recovery_operation(
                            snapshot,
                            owner,
                            admission,
                            now,
                            selection,
                            result.revision.generation,
                            config,
                            events,
                        );
                    }
                }
            } else if result.result == Err(WorkFailure::TimedOut) {
                fail_tunnel_dispatch_operation(
                    &result.operation_id,
                    result.revision.generation,
                    WorkFailure::TimedOut,
                    snapshot,
                    owner,
                    admission,
                    now,
                    selection,
                    config,
                    events,
                );
            } else if result.result == Err(WorkFailure::EffectFailed) {
                let rollback_profiles = snapshot
                    .operations
                    .get(&result.operation_id)
                    .map(|operation| interactive_connected_profiles(operation, config))
                    .unwrap_or_default();
                let retired = result.mutation == TunnelMutation::Connect
                    && !rollback_profiles.is_empty()
                    && supervisor
                        .retire_definitive_connect_failure(
                            &result.profile_id,
                            &result.revision,
                            &result.operation_id,
                        )
                        .is_ok();
                if retired {
                    let completion = complete_operation(
                        OperationCompletion {
                            operation_id: result.operation_id.clone(),
                            desired_generation: result.revision.generation,
                            outcome: CompletionOutcome::Failed(OperationFailure::Internal),
                        },
                        snapshot,
                        owner,
                        admission,
                        now,
                        config,
                        events,
                    );
                    if matches!(completion, Ok(CompletionResult::Terminal(_))) {
                        rollback_connect_intent(
                            &rollback_profiles,
                            result.revision.generation,
                            snapshot,
                            owner,
                            now,
                            events,
                        );
                    }
                }
            }
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
        let exact_transaction = owner
            .topology_transaction
            .as_ref()
            .is_some_and(|transaction| {
                let expected_stage = match transaction.phase {
                    TopologyTransactionPhase::PreBlockPending => {
                        Some(PolicyStage::PreTunnelBlocking)
                    }
                    TopologyTransactionPhase::FinalPending => Some(PolicyStage::Final),
                    _ => None,
                };
                transaction.pre_policy.authority_epoch == result.authority_epoch
                    && transaction.pre_policy.generation == result.generation
                    && transaction.pre_policy.digest == result.digest
                    && transaction.pre_policy.operation_id == result.operation_id
                    && expected_stage == Some(result.stage)
            });
        let mut effective_outcome = result.outcome;
        if exact_transaction
            && result.stage == PolicyStage::Final
            && result.outcome == PolicyOutcome::Applied
            && result.verification.is_some_and(|readback| {
                !accept_policy_readback(
                    supervisor,
                    snapshot,
                    owner,
                    ControlRevision {
                        authority_epoch: result.authority_epoch,
                        generation: result.generation,
                        digest: result.digest.clone(),
                    },
                    result.operation_id.clone(),
                    readback,
                    now,
                )
            })
        {
            effective_outcome = PolicyOutcome::Failed;
        }
        let failed_transaction = if exact_transaction {
            let transaction = owner
                .topology_transaction
                .as_mut()
                .expect("exact transaction checked");
            match (result.stage, effective_outcome, transaction.phase) {
                (
                    PolicyStage::PreTunnelBlocking,
                    PolicyOutcome::Applied,
                    TopologyTransactionPhase::PreBlockPending,
                ) => {
                    transaction.phase = TopologyTransactionPhase::TunnelsAllowed;
                    if let Some(recovery) =
                        owner.unexpected_recoveries.get_mut(&result.operation_id)
                    {
                        recovery.phase = UnexpectedRecoveryPhase::WaitingBackoff;
                    }
                    None
                }
                (
                    PolicyStage::Final,
                    PolicyOutcome::Applied,
                    TopologyTransactionPhase::FinalPending,
                ) => {
                    transaction.phase = TopologyTransactionPhase::FinalApplied;
                    None
                }
                (_, PolicyOutcome::Applied, _) => None,
                (_, outcome, _) => Some((
                    transaction.pre_policy.operation_id.clone(),
                    transaction.pre_policy.generation,
                    operation_failure_for_policy_result(outcome, result.failed_at),
                    result.failure_detail.clone(),
                    transaction.pre_policy.clone(),
                )),
            }
        } else {
            None
        };
        if let Some((operation_id, generation, failure, failure_detail, policy)) =
            failed_transaction
        {
            fail_policy_transaction(
                &operation_id,
                generation,
                failure,
                failure_detail,
                &policy,
                snapshot,
                owner,
                admission,
                now,
                selection,
                config,
                events,
            );
        }
        if !matches!(
            effective_outcome,
            PolicyOutcome::Applied | PolicyOutcome::Superseded
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

    while let Some(result) = supervisor.poll_policy_audit() {
        if let Ok(readback) = result.result {
            let _ = accept_policy_readback(
                supervisor,
                snapshot,
                owner,
                result.revision,
                result.operation_id,
                readback,
                now,
            );
        }
    }
    let _ = supervisor.submit_policy_audit_if_due(now);

    let revision = ControlRevision {
        authority_epoch: snapshot.desired.authority_epoch,
        generation: snapshot.desired.generation,
        digest: snapshot.desired.policy_digest.clone(),
    };
    // Tunnel truth is fenced by the supervisor's exact work receipt,
    // protocol-owned adoption/handshake, revision, and interface. Requiring
    // global policy evidence here would create a cycle: final route/DNS/
    // firewall read-back cannot run until the tunnel barrier has settled.
    for (profile_id, fact) in &snapshot.observed.tunnels {
        if let Some(tunnel_revision) = owner.tunnel_revisions.get(profile_id).filter(|revision| {
            supervisor.profile_truth(profile_id).is_some_and(|entry| {
                entry.revision == **revision
                    && entry.truth == SupervisedTruth::WaitingForObservation
            })
        }) {
            let _ = supervisor.confirm_tunnel(
                profile_id,
                tunnel_revision,
                fact.active,
                fact.interface_name.as_deref(),
            );
        }
    }
    let supervised = supervisor.profiles();
    let tombstones = supervisor.tombstones();
    let desired_connected = desired_connected_profiles(snapshot);
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
                managed.then(|| supervision.expect("managed supervision checked").revision);
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
                revision: supervised.get(profile).map(|entry| entry.revision),
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
                    revision: entry.revision,
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
                    revision: entry.revision,
                    resource_revision: entry.resource_revision,
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
        tunnel_revisions: owner.tunnel_revisions.clone(),
        desired_connected,
        observations,
        in_flight,
        disconnect_tombstones,
    });
    if selection == ExecutionSelection::CanonicalShadow {
        return;
    }

    let operation = operation_for_generation(snapshot, revision.generation).cloned();
    if let Some(operation) = operation {
        let transaction_is_current =
            owner
                .topology_transaction
                .as_ref()
                .is_some_and(|transaction| {
                    transaction.pre_policy.revision() == revision
                        && transaction.pre_policy.operation_id == operation.id
                });
        if !transaction_is_current {
            let transition = transition_for_plan(
                &plan.actions,
                owner.reconnect_operations.contains_key(&operation.id)
                    || owner
                        .exclusive_switch_operations
                        .contains_key(&operation.id),
                owner.recovery_operations.contains(&operation.id),
            );
            if let Some(policy) = capture_topology_policy(
                snapshot, owner, supervisor, config, &operation, transition, now,
            ) {
                let phase = if policy.required_blocking {
                    TopologyTransactionPhase::NeedsPreBlock
                } else {
                    TopologyTransactionPhase::TunnelsAllowed
                };
                owner.topology_transaction = Some(TopologyTransaction {
                    pre_policy: policy,
                    final_policy: None,
                    phase,
                });
            } else {
                invalidate_all_gates(snapshot, now);
            }
        }
    }

    submit_required_pre_block(
        supervisor, snapshot, owner, admission, now, selection, config, events,
    );

    let tunnel_action_operation = owner
        .topology_transaction
        .as_ref()
        .filter(|transaction| {
            transaction.pre_policy.revision() == revision
                && transaction.phase == TopologyTransactionPhase::TunnelsAllowed
        })
        .map(|transaction| transaction.pre_policy.operation_id.clone());
    let tunnel_actions_allowed = tunnel_action_operation
        .as_ref()
        .is_some_and(|operation_id| unexpected_recovery_actions_allowed(owner, operation_id, now));

    for action in plan.actions.iter().filter(|_| tunnel_actions_allowed) {
        match action {
            ReconcileAction::ClearTombstone {
                profile_id,
                revision,
            } => {
                let _ = supervisor.confirm_tombstone_absence(profile_id, revision);
            }
            ReconcileAction::AdoptAttested {
                evidence,
                revision: adoption_revision,
                ..
            } => {
                let Some(operation) =
                    operation_for_tunnel_action(snapshot, adoption_revision.generation)
                else {
                    invalidate_all_gates(snapshot, now);
                    continue;
                };
                if supervisor
                    .adopt_attested(evidence.clone(), *adoption_revision, operation.id.clone())
                    .is_err()
                {
                    invalidate_all_gates(snapshot, now);
                }
            }
            ReconcileAction::Connect {
                profile_id,
                revision: action_revision,
            }
            | ReconcileAction::Disconnect {
                profile_id,
                revision: action_revision,
                ..
            }
            | ReconcileAction::CleanupStaleManaged {
                profile_id,
                target_revision: action_revision,
                ..
            } => {
                if matches!(action, ReconcileAction::Connect { .. }) {
                    let exclusive_ready = owner
                        .exclusive_switch_operations
                        .values()
                        .find(|exclusive| &exclusive.target == profile_id)
                        .is_none_or(|exclusive| {
                            exclusive.teardown.iter().all(|teardown| {
                                snapshot
                                    .observed
                                    .tunnels
                                    .get(teardown)
                                    .is_none_or(|fact| !fact.active)
                                    && supervisor.profile_truth(teardown).is_none()
                                    && !supervisor.is_tombstoned(teardown)
                            })
                        });
                    if !exclusive_ready {
                        continue;
                    }
                }
                let Some(operation) =
                    operation_for_tunnel_action(snapshot, action_revision.generation).cloned()
                else {
                    invalidate_all_gates(snapshot, now);
                    continue;
                };
                let operation_id = operation.id.clone();
                let operation_generation = operation.desired_generation;
                let remaining = operation.deadline_millis.saturating_sub(now);
                let mutation = if matches!(action, ReconcileAction::Connect { .. }) {
                    TunnelMutation::Connect
                } else {
                    TunnelMutation::Disconnect
                };
                let resource_revision = match action {
                    ReconcileAction::Connect { revision, .. } => *revision,
                    ReconcileAction::Disconnect {
                        resource_revision, ..
                    } => *resource_revision,
                    ReconcileAction::CleanupStaleManaged {
                        stale_revision: Some(stale_revision),
                        ..
                    } => *stale_revision,
                    ReconcileAction::CleanupStaleManaged {
                        stale_revision: None,
                        ..
                    } => {
                        invalidate_all_gates(snapshot, now);
                        continue;
                    }
                    _ => unreachable!("matched tunnel effect action"),
                };
                let Some(deadline) = Instant::now().checked_add(Duration::from_millis(remaining))
                else {
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
                let work = TunnelWork {
                    profile_id: profile_id.clone(),
                    operation_id: operation_id.clone(),
                    revision: *action_revision,
                    resource_revision,
                    mutation,
                    protocol: config
                        .profile_topologies
                        .get(profile_id)
                        .and_then(|topology| topology.protocol)
                        .map_or(
                            crate::vortix_core::ports::tunnel::TunnelKindTag::Mock,
                            |protocol| match protocol {
                                crate::vortix_core::profile::ProtocolKind::WireGuard => {
                                    crate::vortix_core::ports::tunnel::TunnelKindTag::WireGuard
                                }
                                crate::vortix_core::profile::ProtocolKind::OpenVpn => {
                                    crate::vortix_core::ports::tunnel::TunnelKindTag::OpenVpn
                                }
                            },
                        ),
                    deadline,
                };
                let key = (operation_id.clone(), profile_id.clone());
                let reconnect_target = owner
                    .reconnect_operations
                    .get(&operation_id)
                    .is_some_and(|reconnect| reconnect.includes(profile_id));
                let reconnect_readmission = mutation == TunnelMutation::Connect
                    && owner
                        .reconnect_operations
                        .get(&operation_id)
                        .is_some_and(|reconnect| reconnect.can_reconnect(profile_id));
                let exclusive_readmission = mutation == TunnelMutation::Connect
                    && owner
                        .exclusive_switch_operations
                        .get(&operation_id)
                        .is_some_and(|exclusive| exclusive.target == *profile_id);
                let level_triggered_readmission =
                    operation_generation != action_revision.generation;
                let reserved = owner.work_admissions.remove(&key).map_or_else(
                    || {
                        if owner.recovery_operations.contains(&operation_id)
                            || reconnect_readmission
                            || exclusive_readmission
                            || level_triggered_readmission
                        {
                            let routes = config
                                .profile_topologies
                                .get(profile_id)
                                .map(|topology| topology.routes.iter().cloned().collect::<Vec<_>>())
                                .unwrap_or_default();
                            supervisor
                                .reserve_tunnel_with_acknowledgement(
                                    profile_id,
                                    routes,
                                    snapshot.desired.conflict_acknowledgements.get(profile_id),
                                )
                                .map(Some)
                        } else {
                            Ok(None)
                        }
                    },
                    |admission| Ok(Some(admission)),
                );
                let reserved = match reserved {
                    Ok(Some(reserved)) => reserved,
                    Ok(None) => {
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
                    }
                    Err(error) => {
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
                        if schedule_unexpected_recovery_backoff(
                            owner,
                            snapshot,
                            &operation_id,
                            profile_id,
                            now,
                        ) {
                            continue;
                        }
                        fail_tunnel_dispatch_operation(
                            &operation_id,
                            operation_generation,
                            error,
                            snapshot,
                            owner,
                            admission,
                            now,
                            selection,
                            config,
                            events,
                        );
                        continue;
                    }
                };
                match supervisor.dispatch_reserved_tunnel(work, reserved) {
                    Ok(_) => {
                        if reconnect_target && mutation == TunnelMutation::Disconnect {
                            owner
                                .reconnect_operations
                                .get_mut(&operation_id)
                                .expect("reconnect ownership checked")
                                .teardown_dispatched
                                .insert(profile_id.clone());
                        }
                    }
                    Err(error) => {
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
                        if schedule_unexpected_recovery_backoff(
                            owner,
                            snapshot,
                            &operation_id,
                            profile_id,
                            now,
                        ) {
                            continue;
                        }
                        fail_tunnel_dispatch_operation(
                            &operation_id,
                            operation_generation,
                            error,
                            snapshot,
                            owner,
                            admission,
                            now,
                            selection,
                            config,
                            events,
                        );
                    }
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
                owner.tunnel_revisions.get(profile).is_some_and(|revision| {
                    supervisor.profile_truth(profile).is_some_and(|entry| {
                        entry.revision == *revision
                            && entry.truth == SupervisedTruth::ObservedPresent
                            && entry.adoption.is_some()
                    })
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

    let final_submission = if tunnel_barrier_ready {
        owner
            .topology_transaction
            .as_mut()
            .filter(|transaction| {
                transaction.pre_policy.revision() == revision
                    && transaction.phase == TopologyTransactionPhase::TunnelsAllowed
            })
            .map(|transaction| {
                let pre_policy = &transaction.pre_policy;
                let policy = transaction
                    .final_policy
                    .get_or_insert_with(|| seal_final_topology_policy(pre_policy, snapshot));
                let result = supervisor.submit_policy(policy);
                let failure_context = result
                    .as_ref()
                    .err()
                    .filter(|failure| **failure != WorkFailure::Busy)
                    .map(|_| (policy.operation_id.clone(), policy.generation));
                (result, failure_context)
            })
    } else {
        None
    };
    if let Some((submission, failure_context)) = final_submission {
        match submission {
            Ok(()) => {
                if let Some(transaction) = owner.topology_transaction.as_mut() {
                    transaction.phase = TopologyTransactionPhase::FinalPending;
                }
            }
            Err(WorkFailure::Busy) => {}
            Err(failure) => {
                let (operation_id, generation) =
                    failure_context.expect("non-busy policy failure captured");
                fail_tunnel_dispatch_operation(
                    &operation_id,
                    generation,
                    failure,
                    snapshot,
                    owner,
                    admission,
                    now,
                    selection,
                    config,
                    events,
                );
                invalidate_all_gates(snapshot, now);
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
                let evidence = evidence.clone();
                let pending = snapshot
                    .operations
                    .values()
                    .filter(|operation| !operation.status.is_terminal())
                    .map(|operation| {
                        (
                            operation.id.clone(),
                            operation.desired_generation,
                            operation_intent_is_compatible(operation, snapshot),
                        )
                    })
                    .collect::<Vec<_>>();
                for (operation_id, desired_generation, compatible) in pending {
                    let outcome = if compatible {
                        CompletionOutcome::ObservedSuccess(evidence.clone())
                    } else {
                        CompletionOutcome::Cancelled
                    };
                    let _ = complete_operation(
                        OperationCompletion {
                            operation_id,
                            desired_generation,
                            outcome,
                        },
                        snapshot,
                        owner,
                        admission,
                        now,
                        config,
                        events,
                    );
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn submit_required_pre_block(
    supervisor: &Supervisor,
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    admission: &Arc<Mutex<AdmissionState>>,
    now: u64,
    selection: ExecutionSelection,
    config: &ControlServiceConfig,
    events: &mut Vec<ControlEvent>,
) {
    let pre_block_submission = owner.topology_transaction.as_ref().and_then(|transaction| {
        (transaction.phase == TopologyTransactionPhase::NeedsPreBlock).then(|| {
            let mut policy = transaction.pre_policy.clone();
            policy.stage = PolicyStage::PreTunnelBlocking;
            policy
        })
    });
    let Some(policy) = pre_block_submission else {
        return;
    };
    match supervisor.submit_policy(&policy) {
        Ok(()) => {
            if let Some(transaction) = owner.topology_transaction.as_mut() {
                transaction.phase = TopologyTransactionPhase::PreBlockPending;
            }
            if let Some(recovery) = owner.unexpected_recoveries.get_mut(&policy.operation_id) {
                recovery.phase = UnexpectedRecoveryPhase::PreBlockPending;
            }
        }
        Err(WorkFailure::Busy) => {}
        Err(failure) => {
            let operation_id = policy.operation_id.clone();
            fail_tunnel_dispatch_operation(
                &operation_id,
                policy.generation,
                failure,
                snapshot,
                owner,
                admission,
                now,
                selection,
                config,
                events,
            );
        }
    }
}

fn accept_policy_readback(
    supervisor: &Supervisor,
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    revision: ControlRevision,
    operation_id: OperationId,
    readback: crate::vortix_core::control::worker::PolicyExecutionEvidence,
    now: u64,
) -> bool {
    let verification = PolicyVerification {
        revision: revision.clone(),
        operation_id,
        observed_at_millis: readback.observed_at_millis,
        received_at_millis: now,
        interface_verified: readback.interface_verified,
        route_verified: readback.route_verified,
        dns_verified: readback.dns_verified,
        firewall_verified: readback.firewall_verified,
    };
    if supervisor.verify_policy(&verification, now).is_err() {
        return false;
    }
    snapshot.observed.evidence = Some(ProtectionEvidence {
        desired_generation: revision.generation,
        authority_epoch: revision.authority_epoch,
        policy_digest: revision.digest,
        observed_at_millis: readback.observed_at_millis,
        interface: GateEvidence::Verified,
        route: GateEvidence::Verified,
        dns: GateEvidence::Verified,
        firewall: GateEvidence::Verified,
    });
    snapshot.observed.evidence_received_at_millis = Some(now);
    for scope in [
        ObservationScope::Protection,
        ObservationScope::Route,
        ObservationScope::Dns,
        ObservationScope::Firewall,
    ] {
        owner
            .observation_clocks
            .insert(scope, readback.observed_at_millis);
    }
    true
}

fn rollback_connect_intent(
    profiles: &[ProfileId],
    expected_generation: u64,
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    now: u64,
    events: &mut Vec<ControlEvent>,
) {
    let expected_revision = TunnelRevision {
        authority_epoch: snapshot.desired.authority_epoch,
        generation: expected_generation,
    };
    let profiles = profiles
        .iter()
        .filter(|profile_id| {
            snapshot.desired.tunnels.get(*profile_id) == Some(&RequestedTunnelState::Connected)
                && owner.tunnel_revisions.get(*profile_id) == Some(&expected_revision)
        })
        .cloned()
        .collect::<Vec<_>>();
    if profiles.is_empty() {
        return;
    }
    snapshot.desired.generation = snapshot.desired.generation.saturating_add(1);
    let revision = TunnelRevision {
        authority_epoch: snapshot.desired.authority_epoch,
        generation: snapshot.desired.generation,
    };
    for profile_id in &profiles {
        snapshot
            .desired
            .tunnels
            .insert(profile_id.clone(), RequestedTunnelState::Disconnected);
        owner.tunnel_revisions.insert(profile_id.clone(), revision);
        snapshot
            .desired
            .conflict_acknowledgements
            .remove(profile_id);
    }
    recompute_policy_digest(snapshot);
    invalidate_all_gates(snapshot, now);
    events.push(ControlEvent::DesiredStateChanged {
        desired_generation: snapshot.desired.generation,
    });
}

fn system_time_millis(time: std::time::SystemTime) -> u64 {
    time.duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn operation_for_generation(
    snapshot: &ControlSnapshot,
    generation: u64,
) -> Option<&OperationRecord> {
    snapshot.operations.values().rev().find(|operation| {
        operation.desired_generation == generation && !operation.status.is_terminal()
    })
}

/// Tunnel revisions fence worker effects independently from global policy
/// generations. When a tunnel still needs level-triggered work after a later
/// command advanced global desired state, that current command (or its
/// recovery operation) is the dispatch vehicle while the worker retains the
/// profile's older exact revision.
fn operation_for_tunnel_action(
    snapshot: &ControlSnapshot,
    tunnel_generation: u64,
) -> Option<&OperationRecord> {
    let dispatch_generation = if tunnel_generation == snapshot.desired.generation {
        tunnel_generation
    } else {
        snapshot.desired.generation
    };
    operation_for_generation(snapshot, dispatch_generation)
}

fn operation_intent_is_compatible(operation: &OperationRecord, snapshot: &ControlSnapshot) -> bool {
    match &operation.intent {
        OperationIntent::GenerationScoped => {
            operation.desired_generation == snapshot.desired.generation
        }
        OperationIntent::DesiredSubset {
            tunnels,
            kill_switch,
        }
        | OperationIntent::UnexpectedRecovery {
            tunnels,
            kill_switch,
            ..
        } => {
            tunnels.iter().all(|(profile_id, requested)| {
                let desired = snapshot.desired.tunnels.get(profile_id);
                match requested {
                    RequestedTunnelState::Connected => {
                        desired == Some(&RequestedTunnelState::Connected)
                    }
                    RequestedTunnelState::Disconnected => {
                        desired != Some(&RequestedTunnelState::Connected)
                    }
                }
            }) && kill_switch.is_none_or(|mode| snapshot.desired.kill_switch == mode)
        }
        OperationIntent::ProfileMutation { .. } => false,
    }
}

fn invalidate_all_gates(snapshot: &mut ControlSnapshot, now: u64) {
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

fn schedule_unexpected_recovery_backoff(
    owner: &mut OwnerState,
    snapshot: &ControlSnapshot,
    operation_id: &OperationId,
    profile_id: &ProfileId,
    now: u64,
) -> bool {
    let Some(recovery) = owner
        .unexpected_recoveries
        .get_mut(operation_id)
        .filter(|recovery| recovery.profiles.contains(profile_id))
    else {
        return false;
    };
    let remaining = snapshot
        .operations
        .get(operation_id)
        .map_or(0, |operation| operation.deadline_millis.saturating_sub(now));
    let delay = recovery.backoff_millis.min(remaining);
    recovery.phase = UnexpectedRecoveryPhase::WaitingBackoff;
    recovery.next_attempt_millis = now.saturating_add(delay);
    recovery.backoff_millis = recovery.backoff_millis.saturating_mul(2).min(remaining);
    true
}

fn unexpected_recovery_actions_allowed(
    owner: &mut OwnerState,
    operation_id: &OperationId,
    now: u64,
) -> bool {
    let Some(recovery) = owner.unexpected_recoveries.get_mut(operation_id) else {
        return true;
    };
    match recovery.phase {
        UnexpectedRecoveryPhase::WaitingBackoff if now >= recovery.next_attempt_millis => {
            recovery.phase = UnexpectedRecoveryPhase::AttemptInFlight;
            true
        }
        UnexpectedRecoveryPhase::NeedsPreBlock
        | UnexpectedRecoveryPhase::PreBlockPending
        | UnexpectedRecoveryPhase::WaitingBackoff => false,
        UnexpectedRecoveryPhase::AttemptInFlight => true,
    }
}

#[allow(clippy::too_many_arguments)] // Failure closes one admitted effect and starts owned recovery.
fn fail_tunnel_dispatch_operation(
    operation_id: &OperationId,
    desired_generation: u64,
    failure: WorkFailure,
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    admission: &Arc<Mutex<AdmissionState>>,
    now: u64,
    selection: ExecutionSelection,
    config: &ControlServiceConfig,
    events: &mut Vec<ControlEvent>,
) {
    let was_recovery = owner.recovery_operations.contains(operation_id);
    let operation_failure = operation_failure_for_work(failure);
    let completion = complete_operation(
        OperationCompletion {
            operation_id: operation_id.clone(),
            desired_generation,
            outcome: CompletionOutcome::Failed(operation_failure),
        },
        snapshot,
        owner,
        admission,
        now,
        config,
        events,
    );
    if !was_recovery
        && matches!(
            completion,
            Ok(CompletionResult::Terminal(OperationStatus::Failed))
        )
    {
        start_recovery_operation(
            snapshot,
            owner,
            admission,
            now,
            selection,
            desired_generation,
            config,
            events,
        );
    }
}

const fn operation_failure_for_work(failure: WorkFailure) -> OperationFailure {
    match failure {
        WorkFailure::TimedOut => OperationFailure::Timeout,
        WorkFailure::Busy | WorkFailure::RouteConflict => OperationFailure::Rejected,
        WorkFailure::AuthenticationFailed => OperationFailure::AuthenticationFailed,
        WorkFailure::InvalidProfile => OperationFailure::InvalidProfile,
        WorkFailure::Cancelled
        | WorkFailure::Panicked
        | WorkFailure::EffectFailed
        | WorkFailure::HandshakeFailed
        | WorkFailure::ChallengeFailed
        | WorkFailure::OutcomeUnknown
        | WorkFailure::Stale
        | WorkFailure::Stopped => OperationFailure::Internal,
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "a failed policy atomically terminalizes its operation and restores prior topology"
)]
fn fail_policy_transaction(
    operation_id: &OperationId,
    desired_generation: u64,
    failure: OperationFailure,
    failure_detail: Option<String>,
    policy: &TopologyPolicy,
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    admission: &Arc<Mutex<AdmissionState>>,
    now: u64,
    selection: ExecutionSelection,
    config: &ControlServiceConfig,
    events: &mut Vec<ControlEvent>,
) {
    let was_recovery = owner.recovery_operations.contains(operation_id);
    let completion = complete_operation(
        OperationCompletion {
            operation_id: operation_id.clone(),
            desired_generation,
            outcome: CompletionOutcome::Failed(failure),
        },
        snapshot,
        owner,
        admission,
        now,
        config,
        events,
    );
    if matches!(
        &completion,
        Ok(CompletionResult::Terminal(OperationStatus::Failed))
    ) {
        if let Some(operation) = snapshot.operations.get_mut(operation_id) {
            operation.failure_detail = failure_detail;
        }
    }
    let restored = matches!(
        completion,
        Ok(CompletionResult::Terminal(OperationStatus::Failed))
    ) && restore_prior_topology_intent(policy, snapshot, owner, now, events);
    if !was_recovery && restored {
        start_recovery_operation(
            snapshot,
            owner,
            admission,
            now,
            selection,
            snapshot.desired.generation,
            config,
            events,
        );
    }
}

fn restore_prior_topology_intent(
    policy: &TopologyPolicy,
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    now: u64,
    events: &mut Vec<ControlEvent>,
) -> bool {
    if policy.revision()
        != (ControlRevision {
            authority_epoch: snapshot.desired.authority_epoch,
            generation: snapshot.desired.generation,
            digest: snapshot.desired.policy_digest.clone(),
        })
    {
        return false;
    }
    snapshot.desired.generation = snapshot.desired.generation.saturating_add(1);
    let revision = TunnelRevision {
        authority_epoch: snapshot.desired.authority_epoch,
        generation: snapshot.desired.generation,
    };
    let affected = policy
        .prior_tunnel_revisions
        .keys()
        .chain(policy.tunnel_revisions.keys())
        .filter(|profile_id| {
            policy.prior_tunnel_revisions.get(*profile_id)
                != policy.tunnel_revisions.get(*profile_id)
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    for profile_id in snapshot
        .desired
        .tunnels
        .keys()
        .chain(policy.prior.profiles.iter())
        .cloned()
        .collect::<BTreeSet<_>>()
    {
        let state = if policy.prior.profiles.contains(&profile_id) {
            RequestedTunnelState::Connected
        } else {
            RequestedTunnelState::Disconnected
        };
        snapshot.desired.tunnels.insert(profile_id, state);
    }
    for profile_id in affected {
        owner.tunnel_revisions.insert(profile_id.clone(), revision);
        snapshot
            .desired
            .conflict_acknowledgements
            .remove(&profile_id);
    }
    snapshot.desired.kill_switch = policy.prior.kill_switch;
    recompute_policy_digest(snapshot);
    invalidate_all_gates(snapshot, now);
    events.push(ControlEvent::DesiredStateChanged {
        desired_generation: snapshot.desired.generation,
    });
    true
}

const fn policy_outcome_failure(outcome: PolicyOutcome) -> WorkFailure {
    match outcome {
        PolicyOutcome::TimedOut => WorkFailure::TimedOut,
        PolicyOutcome::Cancelled => WorkFailure::Cancelled,
        PolicyOutcome::Panicked => WorkFailure::Panicked,
        PolicyOutcome::Superseded => WorkFailure::Stale,
        PolicyOutcome::Failed | PolicyOutcome::Applied => WorkFailure::EffectFailed,
    }
}

const fn operation_failure_for_policy_result(
    outcome: PolicyOutcome,
    failed_at: Option<PolicyBarrier>,
) -> OperationFailure {
    if matches!(outcome, PolicyOutcome::Failed) && matches!(failed_at, Some(PolicyBarrier::Dns)) {
        OperationFailure::DnsPolicyFailed
    } else {
        operation_failure_for_work(policy_outcome_failure(outcome))
    }
}

fn seal_final_topology_policy(
    pre_policy: &TopologyPolicy,
    snapshot: &ControlSnapshot,
) -> TopologyPolicy {
    let mut final_policy = pre_policy.clone();
    let mut dns_changed = false;
    final_policy.stage = PolicyStage::Final;
    for (profile_id, protocol) in &final_policy.target.protocols {
        if *protocol != crate::vortix_core::profile::ProtocolKind::OpenVpn {
            continue;
        }
        let Some(observed) = snapshot
            .observed
            .openvpn_routes
            .get(profile_id)
            .filter(|observed| observed.desired_generation == final_policy.generation)
        else {
            // Standard mode has no helper-authenticated negotiated evidence
            // yet, so its existing configured-route contract remains intact.
            continue;
        };
        final_policy
            .target
            .routes
            .entry(profile_id.clone())
            .or_default()
            .extend(crate::vortix_core::control::worker::openvpn_route_claims(
                &observed.evidence,
            ));
        final_policy
            .target
            .openvpn_routes
            .insert(profile_id.clone(), observed.evidence.clone());

        if let Some(observed_dns) = snapshot
            .observed
            .openvpn_dns
            .get(profile_id)
            .filter(|observed| observed.desired_generation == final_policy.generation)
        {
            final_policy
                .target
                .dns_requests
                .insert(profile_id.clone(), observed_dns.request.clone());
            dns_changed = true;
        }
    }
    if dns_changed {
        final_policy.target.dns_digest = topology_dns_digest(&final_policy.target.dns_requests);
    }
    final_policy
}

fn topology_dns_digest(
    requests: &BTreeMap<ProfileId, crate::vortix_core::ports::dns::DnsRequest>,
) -> PolicyDigest {
    let encoded = serde_json::to_vec(requests).expect("typed DNS requests serialize");
    PolicyDigest::sha256(&encoded)
}

#[allow(clippy::too_many_arguments)] // Captures one immutable cross-barrier transaction.
fn capture_topology_policy(
    snapshot: &ControlSnapshot,
    owner: &OwnerState,
    supervisor: &Supervisor,
    config: &ControlServiceConfig,
    operation: &OperationRecord,
    transition: TopologyTransitionKind,
    now: u64,
) -> Option<TopologyPolicy> {
    let revision = ControlRevision {
        authority_epoch: snapshot.desired.authority_epoch,
        generation: snapshot.desired.generation,
        digest: snapshot.desired.policy_digest.clone(),
    };
    let target_profiles = snapshot
        .desired
        .tunnels
        .iter()
        .filter_map(|(profile, state)| {
            (*state == RequestedTunnelState::Connected).then_some(profile.clone())
        })
        .collect::<BTreeSet<_>>();
    let prior_profiles = snapshot
        .observed
        .tunnels
        .iter()
        .filter_map(|(profile, fact)| fact.active.then_some(profile.clone()))
        .collect();
    let deadline = Instant::now().checked_add(Duration::from_millis(
        operation.deadline_millis.saturating_sub(now),
    ))?;
    let required_blocking = transition_requires_blocking(snapshot.desired.kill_switch, transition);
    let mut target = build_topology_state(
        target_profiles.clone(),
        &snapshot.observed.tunnels,
        config,
        snapshot.desired.kill_switch,
    );
    // `required_blocking` describes the temporary pre-tunnel safety barrier.
    // The final policy deliberately releases that barrier for block-on-drop;
    // only VPN-only retains a blocking firewall after successful publication.
    // `TopologyState::firewall_blocking` is effective final truth, so it must
    // not inherit the pre-barrier requirement.
    target.firewall_blocking = final_firewall_blocks(snapshot.desired.kill_switch);
    let prior = supervisor.applied_topology().unwrap_or_else(|| {
        // A fresh one-shot client has no supervisor history; its initial
        // mode is the persisted firewall baseline, never an implicit Off.
        build_topology_state(
            prior_profiles,
            &snapshot.observed.tunnels,
            config,
            config.initial_kill_switch_mode,
        )
    });
    let prior_tunnel_revisions = prior
        .profiles
        .iter()
        .filter_map(|profile| {
            supervisor
                .resource_revision(profile)
                .map(|revision| (profile.clone(), revision))
        })
        .collect();
    Some(TopologyPolicy {
        generation: revision.generation,
        authority_epoch: revision.authority_epoch,
        digest: revision.digest,
        operation_id: operation.id.clone(),
        deadline,
        prior,
        target,
        prior_tunnel_revisions,
        tunnel_revisions: target_profiles
            .iter()
            .filter_map(|profile| {
                owner
                    .tunnel_revisions
                    .get(profile)
                    .copied()
                    .map(|revision| (profile.clone(), revision))
            })
            .collect(),
        transition,
        required_blocking,
        stage: PolicyStage::Final,
    })
}

const fn final_firewall_blocks(
    mode: crate::vortix_core::state::killswitch::KillSwitchMode,
) -> bool {
    matches!(
        mode,
        crate::vortix_core::state::killswitch::KillSwitchMode::AlwaysOn
    )
}

fn transition_requires_blocking(
    kill_switch: crate::vortix_core::state::killswitch::KillSwitchMode,
    transition: TopologyTransitionKind,
) -> bool {
    use crate::vortix_core::state::killswitch::KillSwitchMode;

    match kill_switch {
        KillSwitchMode::Off => false,
        KillSwitchMode::AlwaysOn => true,
        KillSwitchMode::Auto => matches!(
            transition,
            TopologyTransitionKind::Reconnect
                | TopologyTransitionKind::PrimaryTransfer
                | TopologyTransitionKind::Recovery
        ),
    }
}

fn transition_for_plan(
    actions: &[ReconcileAction],
    reconnect: bool,
    recovery: bool,
) -> TopologyTransitionKind {
    if reconnect {
        return TopologyTransitionKind::Reconnect;
    }
    if recovery {
        return TopologyTransitionKind::Recovery;
    }
    let connects = actions
        .iter()
        .any(|action| matches!(action, ReconcileAction::Connect { .. }));
    let disconnects = actions.iter().any(|action| {
        matches!(
            action,
            ReconcileAction::Disconnect { .. } | ReconcileAction::CleanupStaleManaged { .. }
        )
    });
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
    let mut protocols = BTreeMap::new();
    let mut interfaces = BTreeMap::new();
    let mut routes = BTreeMap::new();
    let mut server_ips = BTreeMap::new();
    let mut dns_requests = BTreeMap::new();
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
            if let Some(protocol) = topology.protocol {
                protocols.insert(profile.clone(), protocol);
            }
            let claims = topology
                .routes
                .iter()
                .filter_map(|route| RouteClaim::parse(route).ok())
                .collect::<BTreeSet<_>>();
            routes.insert(profile.clone(), claims);
            server_ips.insert(profile.clone(), topology.server_ips.clone());
            dns_requests.insert(profile.clone(), topology.dns_request.clone());
            dns_material.extend_from_slice(profile.as_str().as_bytes());
            dns_material.extend_from_slice(topology.dns_digest.0.as_bytes());
            firewall_material.extend_from_slice(profile.as_str().as_bytes());
            firewall_material.extend_from_slice(topology.firewall_digest.0.as_bytes());
            ownership_receipts.extend(topology.ownership_receipts.iter().cloned());
        }
    }
    TopologyState {
        profiles,
        protocols,
        interfaces,
        routes,
        openvpn_routes: BTreeMap::new(),
        server_ips,
        dns_requests,
        dns_digest: PolicyDigest::sha256(&dns_material),
        kill_switch,
        firewall_blocking: false,
        firewall_digest: PolicyDigest::sha256(&firewall_material),
        ownership_receipts,
    }
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one owner transition carries snapshot, durable intent, admission, and events"
)]
fn handle_envelope(
    envelope: Envelope,
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    admission: &Arc<Mutex<AdmissionState>>,
    now: u64,
    config: &ControlServiceConfig,
    shared_config: &Arc<Mutex<ControlServiceConfig>>,
    profile_mutations: Option<&ProfileMutationDispatcher>,
    startup_persistence_fault: bool,
    readiness_reply: &mut Option<DeferredReadiness>,
    durability_reply: &mut Option<DeferredDurability>,
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
            target_profiles,
            lifecycle_profiles,
            work_admissions,
            reply,
        } => {
            let profile_mutation = profile_mutation_for_command(&request.command);
            for evicted_id in evicted {
                snapshot.operations.remove(&evicted_id);
                owner.release_operation_admission(&evicted_id);
            }
            let expired = request.deadline.0 <= now;
            let lifecycle = lifecycle_for_command(&request.command, &lifecycle_profiles, snapshot);
            let desired_generation = if expired {
                snapshot.desired.generation
            } else {
                apply_desired(&request.command, &target_profiles, snapshot, owner);
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
                    intent: intent_for_command(&request.command, &target_profiles),
                    status,
                    result: expired.then_some(OperationResult::Expired),
                    failure_detail: None,
                },
            );
            for (profile_id, reserved) in work_admissions {
                owner
                    .work_admissions
                    .insert((operation_id.clone(), profile_id), reserved);
            }
            if !expired && matches!(&request.command, UserCommand::Reconnect { .. }) {
                owner.reconnect_operations.insert(
                    operation_id.clone(),
                    ReconnectOperation {
                        targets: target_profiles.iter().cloned().collect(),
                        teardown_dispatched: BTreeSet::new(),
                    },
                );
            }
            if !expired {
                if let UserCommand::ConnectExclusive { profile_id } = &request.command {
                    owner.exclusive_switch_operations.insert(
                        operation_id.clone(),
                        ExclusiveSwitchOperation {
                            target: profile_id.clone(),
                            teardown: target_profiles
                                .iter()
                                .filter(|candidate| *candidate != profile_id)
                                .cloned()
                                .collect(),
                        },
                    );
                }
            }
            events.push(ControlEvent::OperationAdmitted {
                operation_id: operation_id.clone(),
                desired_generation,
            });
            if let Some(lifecycle) = lifecycle {
                for (profiles, event) in lifecycle.started {
                    emit_lifecycle_facts(owner, config, &profiles, event, now, events);
                }
                owner
                    .lifecycle_operations
                    .insert(operation_id.clone(), lifecycle.operation);
            }
            if expired {
                owner.release_operation_admission(&operation_id);
                mark_terminal(admission, &operation_id);
                events.push(ControlEvent::OperationCompleted {
                    operation_id: operation_id.clone(),
                    status,
                });
                finish_lifecycle_operation(owner, config, &operation_id, status, now, events);
            } else if profile_mutation.is_none() {
                events.push(ControlEvent::DesiredStateChanged { desired_generation });
            }
            if let Some(mutation) = profile_mutation {
                let dispatch = profile_mutations
                    .ok_or(ProfileMutationFailure::Internal)
                    .and_then(|dispatcher| {
                        dispatcher.dispatch(ProfileMutationWork {
                            operation_id: operation_id.clone(),
                            deadline: request.deadline,
                            mutation,
                        })
                    });
                if let Err(failure) = dispatch {
                    apply_profile_mutation_completion(
                        &operation_id,
                        Err(failure),
                        None,
                        false,
                        snapshot,
                        admission,
                        shared_config,
                        events,
                    );
                }
            }
            *durability_reply = Some(DeferredDurability::Admission {
                operation_id,
                reply,
            });
        }
        Envelope::Observe { observation, reply } => {
            let result = apply_observation(observation, snapshot, owner, now, config);
            let _ = reply.send(result);
        }
        Envelope::ObserveBatch {
            observations,
            reply,
        } => {
            let result = apply_observation_batch(observations, snapshot, owner, now, config);
            let _ = reply.send(result);
        }
        Envelope::Complete { completion, reply } => {
            let result =
                complete_operation(completion, snapshot, owner, admission, now, config, events);
            *durability_reply = Some(DeferredDurability::Completion { result, reply });
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
            if startup_persistence_fault {
                let _ = reply.send(Err(ReadinessError::Persistence));
            } else if expected_epoch == snapshot.desired.authority_epoch {
                snapshot.readiness = readiness;
                if !readiness.reconciliation_complete || !readiness.authority_verified {
                    admission
                        .lock()
                        .expect("admission mutex poisoned")
                        .readiness = readiness;
                }
                *readiness_reply = Some(DeferredReadiness { reply, readiness });
            } else {
                let _ = reply.send(Err(ReadinessError::EpochMismatch));
            }
        }
        Envelope::ProfileMutationCompleted {
            operation_id,
            mutation,
            outcome,
            completed_after_deadline,
        } => {
            apply_profile_mutation_completion(
                &operation_id,
                outcome,
                Some(&mutation),
                completed_after_deadline,
                snapshot,
                admission,
                shared_config,
                events,
            );
        }
        Envelope::Refresh => {}
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one atomic owner transition updates generation-fenced desired intent"
)]
fn apply_desired(
    command: &UserCommand,
    target_profiles: &[ProfileId],
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
) {
    if profile_mutation_for_command(command).is_some() {
        return;
    }
    snapshot.desired.generation = snapshot.desired.generation.saturating_add(1);
    let tunnel_revision = TunnelRevision {
        authority_epoch: snapshot.desired.authority_epoch,
        generation: snapshot.desired.generation,
    };
    for profile_id in target_profiles {
        owner
            .tunnel_revisions
            .insert(profile_id.clone(), tunnel_revision);
    }
    match command {
        UserCommand::Connect { profile_id, .. }
        | UserCommand::ConnectExclusive { profile_id }
        | UserCommand::Reconnect {
            profile_id: Some(profile_id),
        }
        | UserCommand::Disconnect {
            profile_id: Some(profile_id),
        }
        | UserCommand::ForceDisconnect {
            profile_id: Some(profile_id),
        } => {
            snapshot.observed.wireguard_handshakes.remove(profile_id);
            snapshot.observed.openvpn_routes.remove(profile_id);
            snapshot.observed.openvpn_dns.remove(profile_id);
            snapshot
                .observed
                .wireguard_probe_receipts
                .remove(profile_id);
            snapshot.observed.connection_health.remove(profile_id);
        }
        UserCommand::Disconnect { profile_id: None }
        | UserCommand::ForceDisconnect { profile_id: None } => {
            snapshot.observed.wireguard_handshakes.clear();
            snapshot.observed.openvpn_routes.clear();
            snapshot.observed.openvpn_dns.clear();
            snapshot.observed.wireguard_probe_receipts.clear();
            snapshot.observed.connection_health.clear();
        }
        UserCommand::Reconnect { profile_id: None } => {
            for profile_id in target_profiles {
                snapshot.observed.wireguard_handshakes.remove(profile_id);
                snapshot.observed.openvpn_routes.remove(profile_id);
                snapshot.observed.openvpn_dns.remove(profile_id);
                snapshot
                    .observed
                    .wireguard_probe_receipts
                    .remove(profile_id);
                snapshot.observed.connection_health.remove(profile_id);
            }
        }
        UserCommand::SetKillSwitch { .. }
        | UserCommand::ImportProfile { .. }
        | UserCommand::RenameProfile { .. }
        | UserCommand::DeleteProfile { .. } => {}
    }
    match command {
        UserCommand::Connect {
            profile_id,
            conflict_acknowledgement,
        } => {
            snapshot
                .desired
                .tunnels
                .insert(profile_id.clone(), RequestedTunnelState::Connected);
            match conflict_acknowledgement {
                Some(conflict) => {
                    snapshot
                        .desired
                        .conflict_acknowledgements
                        .insert(profile_id.clone(), conflict.clone());
                }
                None => {
                    snapshot
                        .desired
                        .conflict_acknowledgements
                        .remove(profile_id);
                }
            }
        }
        UserCommand::ConnectExclusive { profile_id } => {
            for candidate in target_profiles {
                snapshot
                    .desired
                    .tunnels
                    .insert(candidate.clone(), RequestedTunnelState::Disconnected);
            }
            snapshot
                .desired
                .tunnels
                .insert(profile_id.clone(), RequestedTunnelState::Connected);
            snapshot.desired.conflict_acknowledgements.clear();
        }
        UserCommand::Reconnect {
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
        UserCommand::Reconnect { profile_id: None } => {
            for profile_id in target_profiles {
                snapshot
                    .desired
                    .tunnels
                    .insert(profile_id.clone(), RequestedTunnelState::Connected);
            }
        }
        UserCommand::SetKillSwitch { mode } => snapshot.desired.kill_switch = *mode,
        UserCommand::ImportProfile { .. }
        | UserCommand::RenameProfile { .. }
        | UserCommand::DeleteProfile { .. } => {}
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

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one completion atomically reconciles disk, catalog, operation, and event truth"
)]
fn apply_profile_mutation_completion(
    operation_id: &OperationId,
    mut outcome: Result<ProfileMutationApplied, ProfileMutationFailure>,
    expected_mutation: Option<&ProfileMutation>,
    completed_after_deadline: bool,
    snapshot: &mut ControlSnapshot,
    admission: &Arc<Mutex<AdmissionState>>,
    shared_config: &Arc<Mutex<ControlServiceConfig>>,
    events: &mut Vec<ControlEvent>,
) {
    if let (Ok(applied), Some(expected)) = (&outcome, expected_mutation) {
        if !applied.matches(expected) {
            outcome = Err(ProfileMutationFailure::Internal);
        }
    }
    let mut old_display_name = None;
    if let Ok(applied) = &outcome {
        let mut config = shared_config.lock().expect("control config mutex poisoned");
        match applied {
            ProfileMutationApplied::Imported {
                profile_id,
                topology,
            } => {
                config.known_profiles.insert(profile_id.clone());
                if let Some(topology) = topology {
                    config
                        .profile_topologies
                        .insert(profile_id.clone(), topology.clone());
                } else {
                    config.profile_topologies.remove(profile_id);
                }
            }
            ProfileMutationApplied::Renamed {
                profile_id,
                topology,
            } => {
                old_display_name = config
                    .profile_topologies
                    .get(profile_id)
                    .and_then(|existing| existing.display_name.clone());
                config.known_profiles.insert(profile_id.clone());
                if let Some(topology) = topology {
                    config
                        .profile_topologies
                        .insert(profile_id.clone(), topology.clone());
                } else {
                    config.profile_topologies.remove(profile_id);
                }
            }
            ProfileMutationApplied::Deleted { profile_id } => {
                config.known_profiles.remove(profile_id);
                config.profile_topologies.remove(profile_id);
                config.boot_connections.remove(profile_id);
                snapshot.desired.tunnels.remove(profile_id);
                snapshot
                    .desired
                    .conflict_acknowledgements
                    .remove(profile_id);
                snapshot.observed.tunnels.remove(profile_id);
                snapshot.observed.tunnel_details.remove(profile_id);
                snapshot.observed.wireguard_handshakes.remove(profile_id);
                snapshot.observed.openvpn_routes.remove(profile_id);
                snapshot.observed.openvpn_dns.remove(profile_id);
                snapshot
                    .observed
                    .wireguard_probe_receipts
                    .remove(profile_id);
                snapshot.observed.connection_health.remove(profile_id);
                snapshot.last_connected_at.remove(profile_id);
                recompute_policy_digest(snapshot);
            }
        }
    }

    let Some(record) = snapshot.operations.get_mut(operation_id) else {
        return;
    };
    if record.status.is_terminal() {
        if completed_after_deadline && record.status == OperationStatus::Expired && outcome.is_ok()
        {
            // The deadline ticker can terminalize the record before the
            // non-cancellable filesystem worker reports that it committed.
            // Preserve the Expired status while replacing the ambiguous
            // result so clients know the mutation must not be retried.
            record.result = Some(OperationResult::ProfileMutationAppliedAfterDeadline);
        }
        return;
    }
    let status = if completed_after_deadline {
        record.result = Some(match outcome {
            Ok(_) => OperationResult::ProfileMutationAppliedAfterDeadline,
            Err(_) => OperationResult::Expired,
        });
        OperationStatus::Expired
    } else {
        match outcome {
            Ok(ProfileMutationApplied::Renamed {
                profile_id,
                topology,
            }) => {
                if let (Some(old_display_name), Some(new_display_name)) = (
                    old_display_name,
                    topology.and_then(|topology| topology.display_name),
                ) {
                    events.push(ControlEvent::ProfileRenamed {
                        profile_id,
                        old_display_name,
                        new_display_name,
                    });
                }
                record.result = Some(OperationResult::ProfileMutationApplied);
                OperationStatus::Succeeded
            }
            Ok(ProfileMutationApplied::Deleted { profile_id }) => {
                events.push(ControlEvent::ProfileDeletionRequested { profile_id });
                record.result = Some(OperationResult::ProfileMutationApplied);
                OperationStatus::Succeeded
            }
            Ok(ProfileMutationApplied::Imported { .. }) => {
                record.result = Some(OperationResult::ProfileMutationApplied);
                OperationStatus::Succeeded
            }
            Err(failure) => {
                let operation_failure = match failure {
                    ProfileMutationFailure::DeadlineExpired => OperationFailure::Timeout,
                    ProfileMutationFailure::NotFound
                    | ProfileMutationFailure::AlreadyExists
                    | ProfileMutationFailure::InvalidName
                    | ProfileMutationFailure::Busy => OperationFailure::Rejected,
                    ProfileMutationFailure::Storage | ProfileMutationFailure::Internal => {
                        OperationFailure::Internal
                    }
                };
                record.result = Some(OperationResult::Failed(operation_failure));
                OperationStatus::Failed
            }
        }
    };
    record.status = status;
    mark_terminal(admission, operation_id);
    events.push(ControlEvent::OperationCompleted {
        operation_id: operation_id.clone(),
        status,
    });
}

fn command_digest(command: &UserCommand) -> PolicyDigest {
    let bytes = serde_json::to_vec(command).expect("commands are serializable");
    PolicyDigest::sha256(&bytes)
}

fn intent_for_command(command: &UserCommand, target_profiles: &[ProfileId]) -> OperationIntent {
    let requested = match command {
        UserCommand::Connect { .. }
        | UserCommand::ConnectExclusive { .. }
        | UserCommand::Reconnect { .. } => Some(RequestedTunnelState::Connected),
        UserCommand::Disconnect { .. } | UserCommand::ForceDisconnect { .. } => {
            Some(RequestedTunnelState::Disconnected)
        }
        UserCommand::SetKillSwitch { .. }
        | UserCommand::ImportProfile { .. }
        | UserCommand::RenameProfile { .. }
        | UserCommand::DeleteProfile { .. } => None,
    };
    let tunnels = if let UserCommand::ConnectExclusive { profile_id } = command {
        target_profiles
            .iter()
            .cloned()
            .map(|candidate| {
                let state = if &candidate == profile_id {
                    RequestedTunnelState::Connected
                } else {
                    RequestedTunnelState::Disconnected
                };
                (candidate, state)
            })
            .collect()
    } else {
        requested.map_or_else(BTreeMap::new, |state| {
            target_profiles
                .iter()
                .cloned()
                .map(|profile_id| (profile_id, state))
                .collect()
        })
    };
    let kill_switch = match command {
        UserCommand::SetKillSwitch { mode } => Some(*mode),
        _ => None,
    };
    if let Some(mutation) = profile_mutation_for_command(command) {
        OperationIntent::ProfileMutation {
            profile_id: mutation.profile_id().clone(),
        }
    } else {
        OperationIntent::DesiredSubset {
            tunnels,
            kill_switch,
        }
    }
}

fn command_profile(command: &UserCommand) -> Option<&ProfileId> {
    match command {
        UserCommand::Connect { profile_id, .. }
        | UserCommand::ConnectExclusive { profile_id }
        | UserCommand::Disconnect {
            profile_id: Some(profile_id),
        }
        | UserCommand::Reconnect {
            profile_id: Some(profile_id),
        }
        | UserCommand::ForceDisconnect {
            profile_id: Some(profile_id),
        }
        | UserCommand::ImportProfile { profile_id }
        | UserCommand::RenameProfile { profile_id, .. }
        | UserCommand::DeleteProfile { profile_id } => Some(profile_id),
        UserCommand::Disconnect { profile_id: None }
        | UserCommand::Reconnect { profile_id: None }
        | UserCommand::ForceDisconnect { profile_id: None }
        | UserCommand::SetKillSwitch { .. } => None,
    }
}

fn command_profiles(command: &UserCommand, known_profiles: &BTreeSet<ProfileId>) -> Vec<ProfileId> {
    if matches!(command, UserCommand::ConnectExclusive { .. }) {
        return known_profiles.iter().cloned().collect();
    }
    if let Some(profile) = command_profile(command) {
        return vec![profile.clone()];
    }
    match command {
        UserCommand::Disconnect { profile_id: None }
        | UserCommand::ForceDisconnect { profile_id: None } => {
            known_profiles.iter().cloned().collect()
        }
        _ => Vec::new(),
    }
}

fn target_profiles_for_command(
    command: &UserCommand,
    known_profiles: &BTreeSet<ProfileId>,
    desired_tunnels: &BTreeMap<ProfileId, RequestedTunnelState>,
    selection: ExecutionSelection,
    supervisor: Option<&Supervisor>,
) -> Result<Vec<ProfileId>, AdmissionError> {
    if !matches!(command, UserCommand::Reconnect { profile_id: None }) {
        return Ok(command_profiles(command, known_profiles));
    }
    if selection == ExecutionSelection::CanonicalAuthority {
        return Ok(supervisor
            .ok_or(AdmissionError::Stopped)?
            .profiles()
            .into_iter()
            .filter_map(|(profile_id, supervision)| {
                (supervision.truth == SupervisedTruth::ObservedPresent
                    && supervision.adoption.is_some())
                .then_some(profile_id)
            })
            .collect());
    }
    Ok(desired_tunnels
        .iter()
        .filter_map(|(profile_id, state)| {
            (*state == RequestedTunnelState::Connected).then_some(profile_id.clone())
        })
        .collect())
}

fn lifecycle_profiles_for_command(
    command: &UserCommand,
    target_profiles: &[ProfileId],
    selection: ExecutionSelection,
    supervisor: Option<&Supervisor>,
) -> Result<Vec<ProfileId>, AdmissionError> {
    if selection != ExecutionSelection::CanonicalAuthority
        || !matches!(
            command,
            UserCommand::Disconnect { profile_id: None }
                | UserCommand::ForceDisconnect { profile_id: None }
        )
    {
        return Ok(target_profiles.to_vec());
    }
    let managed = supervisor
        .ok_or(AdmissionError::Stopped)?
        .profiles()
        .into_iter()
        .filter_map(|(profile_id, supervision)| {
            (supervision.truth == SupervisedTruth::ObservedPresent
                && supervision.adoption.is_some())
            .then_some(profile_id)
        })
        .collect::<BTreeSet<_>>();
    Ok(target_profiles
        .iter()
        .filter(|profile_id| managed.contains(*profile_id))
        .cloned()
        .collect())
}

fn lifecycle_for_command(
    command: &UserCommand,
    target_profiles: &[ProfileId],
    snapshot: &ControlSnapshot,
) -> Option<LifecycleRegistration> {
    if let UserCommand::ConnectExclusive { profile_id } = command {
        let teardown = target_profiles
            .iter()
            .filter(|candidate| *candidate != profile_id)
            .filter(|candidate| {
                snapshot.desired.tunnels.get(*candidate) == Some(&RequestedTunnelState::Connected)
                    || snapshot
                        .observed
                        .tunnels
                        .get(*candidate)
                        .is_some_and(|fact| fact.active)
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut legs = Vec::new();
        let mut started = Vec::new();
        if !teardown.is_empty() {
            started.push((teardown.clone(), HookEvent::DisconnectStarted));
            legs.push(LifecycleLeg {
                profiles: teardown,
                success: HookEvent::Disconnected,
                failure: None,
            });
        }
        started.push((vec![profile_id.clone()], HookEvent::ConnectStarted));
        legs.push(LifecycleLeg {
            profiles: vec![profile_id.clone()],
            success: HookEvent::Connected,
            failure: Some(HookEvent::ConnectFailed),
        });
        return Some(LifecycleRegistration {
            operation: LifecycleOperation { legs },
            started,
        });
    }
    let profiles = target_profiles.to_vec();
    if profiles.is_empty() {
        return None;
    }
    let (started, success, failure) = match command {
        UserCommand::Connect { .. } | UserCommand::ConnectExclusive { .. } => (
            HookEvent::ConnectStarted,
            HookEvent::Connected,
            Some(HookEvent::ConnectFailed),
        ),
        UserCommand::Reconnect { .. } => (
            HookEvent::Reconnecting,
            HookEvent::Connected,
            Some(HookEvent::ConnectFailed),
        ),
        UserCommand::Disconnect { .. } | UserCommand::ForceDisconnect { .. } => {
            (HookEvent::DisconnectStarted, HookEvent::Disconnected, None)
        }
        UserCommand::SetKillSwitch { .. }
        | UserCommand::ImportProfile { .. }
        | UserCommand::RenameProfile { .. }
        | UserCommand::DeleteProfile { .. } => return None,
    };
    Some(LifecycleRegistration {
        operation: LifecycleOperation {
            legs: vec![LifecycleLeg {
                profiles,
                success,
                failure,
            }],
        },
        started: vec![(target_profiles.to_vec(), started)],
    })
}

fn profile_mutation_for_command(command: &UserCommand) -> Option<ProfileMutation> {
    match command {
        UserCommand::ImportProfile { profile_id } => Some(ProfileMutation::Import {
            profile_id: profile_id.clone(),
        }),
        UserCommand::RenameProfile {
            profile_id,
            new_display_name,
        } => Some(ProfileMutation::Rename {
            profile_id: profile_id.clone(),
            new_display_name: new_display_name.clone(),
        }),
        UserCommand::DeleteProfile { profile_id } => Some(ProfileMutation::Delete {
            profile_id: profile_id.clone(),
        }),
        _ => None,
    }
}

fn validate_profile_mutation_input(
    command: &UserCommand,
    config: &ControlServiceConfig,
) -> Result<(), AdmissionError> {
    if let UserCommand::Connect { profile_id, .. }
    | UserCommand::ConnectExclusive { profile_id }
    | UserCommand::Reconnect {
        profile_id: Some(profile_id),
    } = command
    {
        if config.known_profiles.contains(profile_id)
            && !config.profile_topologies.contains_key(profile_id)
        {
            return Err(AdmissionError::InvalidInput {
                reason: "profile topology is unavailable".to_owned(),
            });
        }
    }
    let Some(mutation) = profile_mutation_for_command(command) else {
        return Ok(());
    };
    if config.profile_mutations.is_none() {
        return Err(AdmissionError::ProfileMutationUnavailable);
    }
    if let ProfileMutation::Rename {
        new_display_name, ..
    } = mutation
    {
        if new_display_name.len() > 256
            || new_display_name.trim() != new_display_name
            || new_display_name.is_empty()
            || new_display_name.starts_with('.')
            || new_display_name.contains('/')
            || new_display_name.contains('\\')
            || new_display_name.contains("..")
        {
            return Err(AdmissionError::InvalidInput {
                reason: "invalid profile display name".to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_topology_conflict_admission(
    command: &UserCommand,
    snapshot: &ControlSnapshot,
    _config: &ControlServiceConfig,
) -> Result<Option<Conflict>, AdmissionError> {
    let UserCommand::Connect {
        profile_id,
        conflict_acknowledgement,
    } = command
    else {
        return Ok(None);
    };
    let canonical = snapshot.topology_conflict(profile_id);
    match (&canonical, conflict_acknowledgement) {
        (None, None) => Ok(None),
        (Some(expected), Some(actual)) if expected == actual => Ok(canonical),
        (Some(_), None) => Err(AdmissionError::RouteConflict),
        (None | Some(_), Some(_)) => Err(AdmissionError::InvalidInput {
            reason: "topology conflict acknowledgement is stale or does not match canonical state"
                .to_owned(),
        }),
    }
}

fn validate_profile_catalog_admission(
    command: &UserCommand,
    known_profiles: &BTreeSet<ProfileId>,
    snapshot: &ControlSnapshot,
) -> Result<(), AdmissionError> {
    let Some(mutation) = profile_mutation_for_command(command) else {
        return Ok(());
    };
    let profile_id = mutation.profile_id();
    match mutation {
        ProfileMutation::Import { .. } if known_profiles.contains(profile_id) => {
            return Err(AdmissionError::ProfileAlreadyExists);
        }
        ProfileMutation::Rename { .. } | ProfileMutation::Delete { .. }
            if !known_profiles.contains(profile_id) =>
        {
            return Err(AdmissionError::ProfileNotFound);
        }
        _ => {}
    }
    if matches!(
        mutation,
        ProfileMutation::Rename { .. } | ProfileMutation::Delete { .. }
    ) && (snapshot
        .observed
        .tunnels
        .get(profile_id)
        .is_some_and(|tunnel| tunnel.active)
        || snapshot.desired.tunnels.get(profile_id) == Some(&RequestedTunnelState::Connected))
    {
        return Err(AdmissionError::ProfileActive);
    }
    Ok(())
}

fn emit_lifecycle_facts(
    owner: &mut OwnerState,
    config: &ControlServiceConfig,
    profiles: &[ProfileId],
    event: HookEvent,
    now: u64,
    events: &mut Vec<ControlEvent>,
) {
    for profile_id in profiles {
        let Some(topology) = config.profile_topologies.get(profile_id) else {
            continue;
        };
        let Some(protocol) = topology.protocol else {
            continue;
        };
        owner.next_lifecycle_event = owner.next_lifecycle_event.saturating_add(1);
        events.push(ControlEvent::Lifecycle {
            fact: LifecycleFact {
                event_id: HookEventId::from_parts(
                    config.authority_epoch.0,
                    owner.next_lifecycle_event,
                ),
                event,
                profile_id: profile_id.clone(),
                display_name: topology
                    .display_name
                    .clone()
                    .unwrap_or_else(|| profile_id.to_string()),
                protocol,
                occurred_at_millis: now,
            },
        });
    }
}

fn finish_lifecycle_operation(
    owner: &mut OwnerState,
    config: &ControlServiceConfig,
    operation_id: &OperationId,
    status: OperationStatus,
    now: u64,
    events: &mut Vec<ControlEvent>,
) {
    let Some(operation) = owner.lifecycle_operations.remove(operation_id) else {
        return;
    };
    for leg in operation.legs {
        let terminal = match status {
            OperationStatus::Succeeded => Some(leg.success),
            OperationStatus::Failed | OperationStatus::Expired => leg.failure,
            OperationStatus::Admitted
            | OperationStatus::WaitingForObservation
            | OperationStatus::Cancelled => None,
        };
        if let Some(event) = terminal {
            emit_lifecycle_facts(owner, config, &leg.profiles, event, now, events);
        }
    }
}

fn recompute_policy_digest(snapshot: &mut ControlSnapshot) {
    snapshot.desired.refresh_policy_digest();
}

fn observation_evidence(observation: &Observation) -> Option<&ProtectionEvidence> {
    match observation {
        Observation::Protection(evidence) => Some(evidence),
        Observation::Tunnel { protection, .. } | Observation::Drift { protection, .. } => {
            protection.as_ref()
        }
        Observation::ConnectionHealth { .. }
        | Observation::TunnelDetails { .. }
        | Observation::DefaultRoute { .. } => None,
    }
}

fn evidence_matches(evidence: &ProtectionEvidence, snapshot: &ControlSnapshot, now: u64) -> bool {
    evidence.desired_generation == snapshot.desired.generation
        && evidence.authority_epoch == snapshot.desired.authority_epoch
        && evidence.policy_digest == snapshot.desired.policy_digest
        && evidence.observed_at_millis <= now
        && now.saturating_sub(evidence.observed_at_millis) <= MAX_PROTECTION_AGE_MILLIS
}

fn apply_observation(
    observation: Observation,
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    now: u64,
    config: &ControlServiceConfig,
) -> Result<(), ObservationError> {
    apply_observation_to(
        observation,
        snapshot,
        &mut owner.observation_clocks,
        now,
        config,
    )
}

fn record_owned_disconnect(
    profile_id: &ProfileId,
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    now: u64,
) {
    owner
        .observation_clocks
        .insert(ObservationScope::Profile(profile_id.clone()), now);
    snapshot.observed.connection_health.remove(profile_id);
    snapshot.observed.tunnel_details.remove(profile_id);
    snapshot.observed.tunnels.insert(
        profile_id.clone(),
        ObservedTunnel {
            active: false,
            interface_name: None,
            observed_at_millis: now,
            received_at_millis: now,
        },
    );
}

fn apply_observation_batch(
    observations: Vec<Observation>,
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    now: u64,
    config: &ControlServiceConfig,
) -> Result<(), ObservationError> {
    let mut candidate = snapshot.clone();
    let mut clocks = owner.observation_clocks.clone();
    for observation in observations {
        apply_observation_to(observation, &mut candidate, &mut clocks, now, config)?;
    }
    *snapshot = candidate;
    owner.observation_clocks = clocks;
    Ok(())
}

#[allow(clippy::too_many_lines)] // Validation and mutation must remain one atomic owner transition.
fn apply_observation_to(
    observation: Observation,
    snapshot: &mut ControlSnapshot,
    observation_clocks: &mut BTreeMap<ObservationScope, u64>,
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
        }
        | Observation::ConnectionHealth {
            observed_at_millis, ..
        }
        | Observation::TunnelDetails {
            observed_at_millis, ..
        }
        | Observation::DefaultRoute {
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
        observation_clocks
            .get(scope)
            .is_some_and(|last| timestamp < *last)
    }) {
        return Err(ObservationError::Stale);
    }
    match &observation {
        Observation::Tunnel { profile_id, .. } => {
            validate_observed_profile(profile_id, config)?;
            if !snapshot.observed.tunnels.contains_key(profile_id)
                && snapshot.observed.tunnels.len() >= config.max_observed_profiles
            {
                return Err(ObservationError::RetentionFull);
            }
        }
        Observation::TunnelDetails { profile_id, .. } => {
            validate_observed_profile(profile_id, config)?;
            if !snapshot.observed.tunnel_details.contains_key(profile_id)
                && snapshot.observed.tunnel_details.len() >= config.max_observed_profiles
            {
                return Err(ObservationError::RetentionFull);
            }
        }
        Observation::Drift {
            profile_id: Some(profile_id),
            ..
        } => validate_observed_profile(profile_id, config)?,
        Observation::ConnectionHealth {
            profile_id,
            desired_generation,
            ..
        } => {
            validate_observed_profile(profile_id, config)?;
            if *desired_generation != snapshot.desired.generation {
                return Err(ObservationError::MismatchedProtection);
            }
        }
        _ => {}
    }
    for scope in scopes {
        observation_clocks.insert(scope, timestamp);
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
            if !active {
                snapshot.observed.connection_health.remove(&profile_id);
                snapshot.observed.tunnel_details.remove(&profile_id);
            }
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
        Observation::TunnelDetails {
            profile_id,
            details,
            started_at,
            observed_at_millis,
        } => {
            snapshot.observed.tunnel_details.insert(
                profile_id,
                ObservedTunnelDetails {
                    details: *details,
                    started_at,
                    observed_at_millis,
                    received_at_millis: now,
                },
            );
        }
        Observation::DefaultRoute {
            interface_name,
            observed_at_millis,
        } => {
            snapshot.observed.default_route = Some(ObservedDefaultRoute {
                interface_name,
                observed_at_millis,
                received_at_millis: now,
            });
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
        Observation::ConnectionHealth {
            profile_id,
            desired_generation,
            health,
            observed_at_millis,
        } => {
            snapshot.observed.connection_health.insert(
                profile_id,
                ObservedConnectionHealth {
                    desired_generation,
                    health,
                    observed_at_millis,
                    received_at_millis: now,
                },
            );
        }
    }
    Ok(())
}

fn validate_observed_profile(
    profile_id: &ProfileId,
    config: &ControlServiceConfig,
) -> Result<(), ObservationError> {
    if config.known_profiles.contains(profile_id) {
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
        Observation::ConnectionHealth { profile_id, .. }
        | Observation::TunnelDetails { profile_id, .. } => {
            vec![ObservationScope::Profile(profile_id.clone())]
        }
        Observation::DefaultRoute { .. } => vec![ObservationScope::Route],
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

#[allow(
    clippy::too_many_lines,
    reason = "one atomic terminal owner transition"
)]
fn complete_operation(
    completion: OperationCompletion,
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    admission: &Arc<Mutex<AdmissionState>>,
    now: u64,
    config: &ControlServiceConfig,
    events: &mut Vec<ControlEvent>,
) -> Result<CompletionResult, CompletionError> {
    let interactive_profiles = snapshot
        .operations
        .get(&completion.operation_id)
        .map_or_else(Vec::new, |operation| {
            interactive_connected_profiles(operation, config)
        });
    let success_is_current = match &completion.outcome {
        CompletionOutcome::ObservedSuccess(evidence) => evidence_matches(evidence, snapshot, now),
        CompletionOutcome::Failed(_) | CompletionOutcome::Cancelled => true,
    };
    let intent_is_compatible = snapshot
        .operations
        .get(&completion.operation_id)
        .is_some_and(|operation| operation_intent_is_compatible(operation, snapshot));
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
        cancel_operation_challenges(
            &completion.operation_id,
            snapshot,
            owner,
            config.max_challenges,
            events,
        );
        let was_recovery = owner.recovery_operations.remove(&completion.operation_id);
        owner.release_operation_admission(&completion.operation_id);
        if was_recovery {
            snapshot.operations.remove(&completion.operation_id);
            forget_operation(admission, &completion.operation_id);
        } else {
            mark_terminal(admission, &completion.operation_id);
        }
        let operation_id = completion.operation_id.clone();
        events.push(ControlEvent::OperationCompleted {
            operation_id: completion.operation_id,
            status: OperationStatus::Expired,
        });
        finish_lifecycle_operation(
            owner,
            config,
            &operation_id,
            OperationStatus::Expired,
            now,
            events,
        );
        rollback_connect_intent(
            &interactive_profiles,
            completion.desired_generation,
            snapshot,
            owner,
            now,
            events,
        );
        return Err(CompletionError::DeadlineExpired);
    }
    if completion.desired_generation != record.desired_generation {
        return Err(CompletionError::GenerationMismatch);
    }
    match completion.outcome {
        CompletionOutcome::ObservedSuccess(evidence) => {
            if !success_is_current || !intent_is_compatible {
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
    if status == OperationStatus::Succeeded {
        let connected_profiles = snapshot
            .operations
            .get(&completion.operation_id)
            .map_or_else(Vec::new, |operation| {
                successful_connection_times(operation, snapshot)
            });
        for (profile_id, connected_at) in connected_profiles {
            snapshot
                .last_connected_at
                .entry(profile_id)
                .and_modify(|current| *current = (*current).max(connected_at))
                .or_insert(connected_at);
        }
    }
    cancel_operation_challenges(
        &completion.operation_id,
        snapshot,
        owner,
        config.max_challenges,
        events,
    );
    owner.release_operation_admission(&completion.operation_id);
    if owner.recovery_operations.remove(&completion.operation_id) {
        snapshot.operations.remove(&completion.operation_id);
        forget_operation(admission, &completion.operation_id);
    } else {
        mark_terminal(admission, &completion.operation_id);
    }
    let operation_id = completion.operation_id.clone();
    events.push(ControlEvent::OperationCompleted {
        operation_id: completion.operation_id,
        status,
    });
    finish_lifecycle_operation(owner, config, &operation_id, status, now, events);
    Ok(CompletionResult::Terminal(status))
}

fn successful_connection_times(
    operation: &OperationRecord,
    snapshot: &ControlSnapshot,
) -> Vec<(ProfileId, SystemTime)> {
    let Some(tunnels) = operation_intent_tunnels(&operation.intent) else {
        return Vec::new();
    };
    tunnels
        .iter()
        .filter(|(_, requested)| **requested == RequestedTunnelState::Connected)
        .filter_map(|(profile_id, _)| {
            let active = snapshot
                .observed
                .tunnels
                .get(profile_id)
                .is_some_and(|tunnel| tunnel.active);
            active.then_some(())?;
            let connected_at = snapshot
                .observed
                .tunnel_details
                .get(profile_id)?
                .started_at?;
            Some((profile_id.clone(), connected_at))
        })
        .collect()
}

fn expire_operations(
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    admission: &Arc<Mutex<AdmissionState>>,
    now: u64,
    config: &ControlServiceConfig,
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
        cancel_operation_challenges(&id, snapshot, owner, config.max_challenges, events);
        owner.release_operation_admission(&id);
        if was_recovery {
            snapshot.operations.remove(&id);
            forget_operation(admission, &id);
        } else {
            mark_terminal(admission, &id);
        }
        let operation_id = id.clone();
        events.push(ControlEvent::OperationCompleted {
            operation_id: id,
            status: OperationStatus::Expired,
        });
        finish_lifecycle_operation(
            owner,
            config,
            &operation_id,
            OperationStatus::Expired,
            now,
            events,
        );
        let Some(expired_record) = expired_record else {
            continue;
        };
        let interactive_profiles = interactive_connected_profiles(&expired_record, config);
        if !interactive_profiles.is_empty() {
            rollback_connect_intent(
                &interactive_profiles,
                expired_record.desired_generation,
                snapshot,
                owner,
                now,
                events,
            );
            continue;
        }
        if selection != ExecutionSelection::CanonicalAuthority
            || expired_record.desired_generation != snapshot.desired.generation
            || snapshot.operations.values().any(|operation| {
                operation.desired_generation == snapshot.desired.generation
                    && !operation.status.is_terminal()
            })
        {
            continue;
        }
        let idempotency_key = IdempotencyKey::new(format!(
            "service-recovery-{}-{now}",
            snapshot.desired.generation
        ));
        let command_digest = snapshot.desired.policy_digest.clone();
        let Some(recovery_id) = reserve_service_operation(
            snapshot,
            owner,
            admission,
            config,
            &idempotency_key,
            &command_digest,
            None,
        ) else {
            mark_reconciliation_incomplete(snapshot, admission);
            return;
        };
        snapshot.operations.insert(
            recovery_id.clone(),
            OperationRecord {
                id: recovery_id.clone(),
                idempotency_key,
                client_id: ClientId::from_parts(snapshot.desired.authority_epoch, 0),
                command_digest,
                authority_epoch: snapshot.desired.authority_epoch,
                desired_generation: snapshot.desired.generation,
                admitted_at_millis: now,
                deadline_millis: now.saturating_add(30_000),
                intent: intent_for_desired_state(snapshot),
                status: OperationStatus::WaitingForObservation,
                result: None,
                failure_detail: None,
            },
        );
        owner.recovery_operations.insert(recovery_id.clone());
        events.push(ControlEvent::OperationAdmitted {
            operation_id: recovery_id.clone(),
            desired_generation: snapshot.desired.generation,
        });
        register_recovery_lifecycle(owner, snapshot, config, &recovery_id, now, events);
    }
}

fn interactive_connected_profiles(
    operation: &OperationRecord,
    config: &ControlServiceConfig,
) -> Vec<ProfileId> {
    let OperationIntent::DesiredSubset { tunnels, .. } = &operation.intent else {
        return Vec::new();
    };
    tunnels
        .iter()
        .filter(|(profile_id, requested)| {
            **requested == RequestedTunnelState::Connected
                && config
                    .profile_topologies
                    .get(*profile_id)
                    .is_some_and(|topology| topology.interactive_credentials)
        })
        .map(|(profile_id, _)| profile_id.clone())
        .collect()
}

fn reserve_service_operation(
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    admission: &Arc<Mutex<AdmissionState>>,
    config: &ControlServiceConfig,
    idempotency_key: &IdempotencyKey,
    command_digest: &PolicyDigest,
    active_profiles: Option<&BTreeSet<ProfileId>>,
) -> Option<OperationId> {
    let authority_epoch = snapshot.desired.authority_epoch;
    let client_id = ClientId::from_parts(authority_epoch, 0);
    let (operation_id, evicted) = {
        let mut state = admission.lock().expect("admission mutex poisoned");
        state
            .reserve_operation(
                IdempotencyScope {
                    client_id,
                    authority_epoch,
                    key: idempotency_key.clone(),
                },
                command_digest.clone(),
                active_profiles.into_iter().flatten(),
                ProfileOperationKind::Lifecycle,
                config,
            )
            .ok()?
    };
    for evicted_id in evicted {
        snapshot.operations.remove(&evicted_id);
        owner.release_operation_admission(&evicted_id);
    }
    Some(operation_id)
}

fn mark_reconciliation_incomplete(
    snapshot: &mut ControlSnapshot,
    admission: &Arc<Mutex<AdmissionState>>,
) {
    admission
        .lock()
        .expect("admission mutex poisoned")
        .readiness
        .reconciliation_complete = false;
    snapshot.readiness.reconciliation_complete = false;
}

/// Start a policy-owned retry only after the user-visible operation reached a
/// typed terminal. This keeps idempotent callers from waiting until expiry,
/// while preserving level-triggered convergence for unchanged desired state.
#[allow(clippy::too_many_arguments)] // Recovery is one owner transition across operation and hook facts.
fn start_recovery_operation(
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    admission: &Arc<Mutex<AdmissionState>>,
    now: u64,
    selection: ExecutionSelection,
    generation: u64,
    config: &ControlServiceConfig,
    events: &mut Vec<ControlEvent>,
) {
    if selection != ExecutionSelection::CanonicalAuthority
        || generation != snapshot.desired.generation
        || snapshot.operations.values().any(|operation| {
            operation.desired_generation == generation && !operation.status.is_terminal()
        })
    {
        return;
    }
    let idempotency_key = IdempotencyKey::new(format!("service-recovery-{generation}-{now}"));
    let command_digest = snapshot.desired.policy_digest.clone();
    let Some(recovery_id) = reserve_service_operation(
        snapshot,
        owner,
        admission,
        config,
        &idempotency_key,
        &command_digest,
        None,
    ) else {
        mark_reconciliation_incomplete(snapshot, admission);
        return;
    };
    snapshot.operations.insert(
        recovery_id.clone(),
        OperationRecord {
            id: recovery_id.clone(),
            idempotency_key,
            client_id: ClientId::from_parts(snapshot.desired.authority_epoch, 0),
            command_digest,
            authority_epoch: snapshot.desired.authority_epoch,
            desired_generation: generation,
            admitted_at_millis: now,
            deadline_millis: now.saturating_add(30_000),
            intent: intent_for_desired_state(snapshot),
            status: OperationStatus::WaitingForObservation,
            result: None,
            failure_detail: None,
        },
    );
    owner.recovery_operations.insert(recovery_id.clone());
    events.push(ControlEvent::OperationAdmitted {
        operation_id: recovery_id.clone(),
        desired_generation: generation,
    });
    register_recovery_lifecycle(owner, snapshot, config, &recovery_id, now, events);
}

#[allow(clippy::too_many_arguments)]
fn admit_unexpected_loss_recovery(
    before: &ControlSnapshot,
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    admission: &Arc<Mutex<AdmissionState>>,
    now: u64,
    config: &ControlServiceConfig,
    selection: ExecutionSelection,
    supervisor: Option<&Supervisor>,
    events: &mut Vec<ControlEvent>,
) {
    if selection != ExecutionSelection::CanonicalAuthority
        || snapshot.operations.values().any(|operation| {
            operation.desired_generation == snapshot.desired.generation
                && !operation.status.is_terminal()
        })
    {
        return;
    }
    let Some(supervisor) = supervisor else {
        return;
    };
    let dropped = snapshot
        .observed
        .tunnels
        .iter()
        .filter_map(|(profile_id, observed)| {
            let was_present = before
                .observed
                .tunnels
                .get(profile_id)
                .is_some_and(|prior| prior.active);
            let desired_connected =
                snapshot.desired.tunnels.get(profile_id) == Some(&RequestedTunnelState::Connected);
            let canonically_owned = supervisor.profile_truth(profile_id).is_some_and(|entry| {
                entry.truth == SupervisedTruth::ObservedPresent && entry.adoption.is_some()
            });
            (was_present && !observed.active && desired_connected && canonically_owned)
                .then_some(profile_id.clone())
        })
        .collect::<BTreeSet<_>>();
    let Some(profile_id) = dropped.first().cloned() else {
        return;
    };
    // The operation intent reconciles the complete desired topology. Own all
    // connected profiles for its lifetime so a later loss cannot race a user
    // command or escape the same level-triggered retry loop.
    let recovery_profiles = desired_connected_profiles(snapshot);

    let generation = snapshot.desired.generation;
    let idempotency_key = IdempotencyKey::new(format!(
        "unexpected-loss-recovery-{}-{generation}-{now}",
        profile_id.as_str()
    ));
    let command_digest = snapshot.desired.policy_digest.clone();
    let Some(recovery_id) = reserve_service_operation(
        snapshot,
        owner,
        admission,
        config,
        &idempotency_key,
        &command_digest,
        Some(&recovery_profiles),
    ) else {
        mark_reconciliation_incomplete(snapshot, admission);
        return;
    };
    let retry_budget = u64::try_from(config.retry_budget.as_millis()).unwrap_or(u64::MAX);
    let retry_backoff = u64::try_from(config.retry_initial_backoff.as_millis()).unwrap_or(u64::MAX);
    snapshot.operations.insert(
        recovery_id.clone(),
        OperationRecord {
            id: recovery_id.clone(),
            idempotency_key,
            client_id: ClientId::from_parts(snapshot.desired.authority_epoch, 0),
            command_digest,
            authority_epoch: snapshot.desired.authority_epoch,
            desired_generation: generation,
            admitted_at_millis: now,
            deadline_millis: now.saturating_add(retry_budget),
            intent: OperationIntent::UnexpectedRecovery {
                profile_id: profile_id.clone(),
                tunnels: snapshot.desired.tunnels.clone(),
                kill_switch: Some(snapshot.desired.kill_switch),
            },
            status: OperationStatus::WaitingForObservation,
            result: None,
            failure_detail: None,
        },
    );
    owner.recovery_operations.insert(recovery_id.clone());
    owner.unexpected_recoveries.insert(
        recovery_id.clone(),
        UnexpectedRecovery {
            profiles: recovery_profiles,
            phase: if snapshot.desired.kill_switch
                == crate::vortix_core::state::killswitch::KillSwitchMode::Auto
            {
                UnexpectedRecoveryPhase::NeedsPreBlock
            } else {
                UnexpectedRecoveryPhase::WaitingBackoff
            },
            next_attempt_millis: now.saturating_add(retry_backoff),
            backoff_millis: retry_backoff,
        },
    );
    events.push(ControlEvent::OperationAdmitted {
        operation_id: recovery_id.clone(),
        desired_generation: generation,
    });
    register_recovery_lifecycle(owner, snapshot, config, &recovery_id, now, events);

    prepare_unexpected_recovery_preblock(snapshot, owner, supervisor, config, &recovery_id, now);
}

fn prepare_unexpected_recovery_preblock(
    snapshot: &ControlSnapshot,
    owner: &mut OwnerState,
    supervisor: &Supervisor,
    config: &ControlServiceConfig,
    recovery_id: &OperationId,
    now: u64,
) {
    if snapshot.desired.kill_switch != crate::vortix_core::state::killswitch::KillSwitchMode::Auto {
        return;
    }
    let recovery_operation = snapshot
        .operations
        .get(recovery_id)
        .cloned()
        .expect("unexpected recovery operation was just inserted");
    if let Some(policy) = capture_topology_policy(
        snapshot,
        owner,
        supervisor,
        config,
        &recovery_operation,
        TopologyTransitionKind::Recovery,
        now,
    ) {
        owner.topology_transaction = Some(TopologyTransaction {
            pre_policy: policy,
            final_policy: None,
            phase: TopologyTransactionPhase::NeedsPreBlock,
        });
    }
}

fn restored_unexpected_recoveries(
    snapshot: &ControlSnapshot,
    config: &ControlServiceConfig,
    now: u64,
) -> BTreeMap<OperationId, UnexpectedRecovery> {
    let initial_backoff =
        u64::try_from(config.retry_initial_backoff.as_millis()).unwrap_or(u64::MAX);
    snapshot
        .operations
        .iter()
        .filter_map(|(operation_id, operation)| {
            if operation.status.is_terminal()
                || operation.desired_generation != snapshot.desired.generation
            {
                return None;
            }
            let OperationIntent::UnexpectedRecovery {
                profile_id,
                tunnels,
                ..
            } = &operation.intent
            else {
                return None;
            };
            let mut profiles = tunnels
                .iter()
                .filter(|(_, requested)| **requested == RequestedTunnelState::Connected)
                .map(|(profile_id, _)| profile_id.clone())
                .collect::<BTreeSet<_>>();
            if profiles.is_empty() {
                profiles.insert(profile_id.clone());
            }
            let remaining = operation.deadline_millis.saturating_sub(now);
            Some((
                operation_id.clone(),
                UnexpectedRecovery {
                    profiles,
                    phase: if snapshot.desired.kill_switch
                        == crate::vortix_core::state::killswitch::KillSwitchMode::Auto
                    {
                        UnexpectedRecoveryPhase::NeedsPreBlock
                    } else {
                        UnexpectedRecoveryPhase::WaitingBackoff
                    },
                    next_attempt_millis: now.saturating_add(initial_backoff.min(remaining)),
                    backoff_millis: initial_backoff.min(remaining),
                },
            ))
        })
        .collect()
}

fn intent_for_desired_state(snapshot: &ControlSnapshot) -> OperationIntent {
    OperationIntent::DesiredSubset {
        tunnels: snapshot.desired.tunnels.clone(),
        kill_switch: Some(snapshot.desired.kill_switch),
    }
}

fn register_recovery_lifecycle(
    owner: &mut OwnerState,
    snapshot: &ControlSnapshot,
    config: &ControlServiceConfig,
    recovery_id: &OperationId,
    now: u64,
    events: &mut Vec<ControlEvent>,
) {
    let profiles = snapshot
        .desired
        .tunnels
        .iter()
        .filter_map(|(profile, state)| {
            (*state == RequestedTunnelState::Connected).then_some(profile.clone())
        })
        .collect::<Vec<_>>();
    emit_lifecycle_facts(
        owner,
        config,
        &profiles,
        HookEvent::Reconnecting,
        now,
        events,
    );
    owner.lifecycle_operations.insert(
        recovery_id.clone(),
        LifecycleOperation {
            legs: vec![LifecycleLeg {
                profiles,
                success: HookEvent::Connected,
                failure: Some(HookEvent::ConnectFailed),
            }],
        },
    );
}

fn mark_terminal(admission: &Arc<Mutex<AdmissionState>>, operation_id: &OperationId) {
    let mut admission = admission.lock().expect("admission mutex poisoned");
    admission.terminal_operations.insert(operation_id.clone());
    release_profile_operation(&mut admission, operation_id);
}

fn forget_operation(admission: &Arc<Mutex<AdmissionState>>, operation_id: &OperationId) {
    let mut admission = admission.lock().expect("admission mutex poisoned");
    let was_retained = admission
        .idempotency
        .values()
        .any(|binding| &binding.operation_id == operation_id);
    admission
        .idempotency
        .retain(|_, binding| &binding.operation_id != operation_id);
    admission.terminal_operations.remove(operation_id);
    if was_retained {
        admission.retained_operations = admission.retained_operations.saturating_sub(1);
    }
    release_profile_operation(&mut admission, operation_id);
}

fn release_profile_operation(admission: &mut AdmissionState, operation_id: &OperationId) {
    admission.active_profile_operations.retain(|_, operations| {
        operations.remove(operation_id);
        !operations.is_empty()
    });
}

fn operation_intent_profiles(intent: &OperationIntent) -> Vec<ProfileId> {
    operation_intent_tunnels(intent).map_or_else(
        || match intent {
            OperationIntent::ProfileMutation { profile_id } => vec![profile_id.clone()],
            OperationIntent::GenerationScoped
            | OperationIntent::DesiredSubset { .. }
            | OperationIntent::UnexpectedRecovery { .. } => Vec::new(),
        },
        |tunnels| tunnels.keys().cloned().collect(),
    )
}

fn operation_intent_tunnels(
    intent: &OperationIntent,
) -> Option<&BTreeMap<ProfileId, RequestedTunnelState>> {
    match intent {
        OperationIntent::DesiredSubset { tunnels, .. }
        | OperationIntent::UnexpectedRecovery { tunnels, .. } => Some(tunnels),
        OperationIntent::GenerationScoped | OperationIntent::ProfileMutation { .. } => None,
    }
}

fn client_desired_tunnels(
    operation: &OperationRecord,
) -> Option<&BTreeMap<ProfileId, RequestedTunnelState>> {
    if operation.client_id.sequence()? == 0 {
        return None;
    }
    let OperationIntent::DesiredSubset { tunnels, .. } = &operation.intent else {
        return None;
    };
    Some(tunnels)
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

fn cancel_operation_challenges(
    operation_id: &OperationId,
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    max_terminals: usize,
    events: &mut Vec<ControlEvent>,
) {
    let ids = snapshot
        .challenges
        .iter()
        .filter_map(|(id, challenge)| (&challenge.operation_id == operation_id).then_some(*id))
        .collect::<Vec<_>>();
    for id in ids {
        snapshot.challenges.remove(&id);
        owner.challenge_answers.remove(&id);
        record_challenge_terminal(
            &mut owner.challenge_terminals,
            id,
            ChallengeTerminal::Cancelled,
            max_terminals,
        );
        events.push(ControlEvent::ChallengeCancelled { challenge_id: id });
    }
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

fn desired_connected_profiles(snapshot: &ControlSnapshot) -> BTreeSet<ProfileId> {
    snapshot
        .desired
        .tunnels
        .iter()
        .filter(|(_, requested)| **requested == RequestedTunnelState::Connected)
        .map(|(profile_id, _)| profile_id.clone())
        .collect()
}

fn tunnel_details_exceed_bounds(
    details: &crate::vortix_core::engine::state::DetailedConnectionInfo,
) -> bool {
    [
        &details.interface,
        &details.internal_ip,
        &details.endpoint,
        &details.mtu,
        &details.public_key,
        &details.listen_port,
        &details.transfer_rx,
        &details.transfer_tx,
        &details.latest_handshake,
    ]
    .into_iter()
    .any(|value| value.len() > 4_096)
}

fn topology_routes(
    snapshot: &ControlSnapshot,
    config: &ControlServiceConfig,
    profile_id: &ProfileId,
) -> Vec<Cidr> {
    let mut routes = config
        .profile_topologies
        .get(profile_id)
        .into_iter()
        .flat_map(|topology| &topology.routes)
        .filter_map(|route| RouteClaim::parse(route).ok())
        .collect::<BTreeSet<_>>();
    if let Some(observed) = snapshot
        .observed
        .openvpn_routes
        .get(profile_id)
        .filter(|observed| observed.desired_generation == snapshot.desired.generation)
    {
        routes.extend(crate::vortix_core::control::worker::openvpn_route_claims(
            &observed.evidence,
        ));
    }
    routes
        .into_iter()
        .filter_map(|route| Cidr::new(route.network(), route.prefix_len()))
        .collect()
}

fn projected_role(
    profile_id: &ProfileId,
    primary: Option<&ProfileId>,
    allowed_ips: Vec<Cidr>,
    interface_authoritative: bool,
) -> Role {
    if primary == Some(profile_id) {
        return Role::Primary { allowed_ips };
    }
    if !interface_authoritative {
        return Role::Addressable { allowed_ips };
    }
    let claims_default =
        claims_default_route_v4(&allowed_ips) || claims_default_route_v6(&allowed_ips);
    if claims_default && primary.is_some() {
        Role::AddressableSuppressed { allowed_ips }
    } else {
        Role::Addressable { allowed_ips }
    }
}

fn prior_started_at(
    previous: Option<&TunnelSnapshot>,
    same_phase: impl FnOnce(&Connection) -> bool,
) -> SystemTime {
    previous
        .filter(|snapshot| same_phase(&snapshot.state))
        .and_then(|snapshot| snapshot.started_at)
        .unwrap_or_else(SystemTime::now)
}

fn restore_supervised_wireguard_evidence(snapshot: &mut ControlSnapshot, supervisor: &Supervisor) {
    for (profile_id, state) in supervisor.profiles() {
        if state.truth != SupervisedTruth::ObservedPresent {
            continue;
        }
        let Some(handshake) = state
            .handshake
            .filter(|handshake| handshake.generation == state.revision.generation)
        else {
            continue;
        };
        snapshot
            .observed
            .wireguard_handshakes
            .insert(profile_id.clone(), handshake);
        snapshot
            .observed
            .wireguard_probe_receipts
            .insert(profile_id, state.probe_receipts);
    }
}

fn wireguard_connection_ready(
    snapshot: &ControlSnapshot,
    tunnel_revisions: Option<&BTreeMap<ProfileId, TunnelRevision>>,
    config: &ControlServiceConfig,
    profile_id: &ProfileId,
) -> bool {
    if config
        .profile_topologies
        .get(profile_id)
        .and_then(|topology| topology.protocol)
        != Some(crate::vortix_core::profile::ProtocolKind::WireGuard)
    {
        return true;
    }
    snapshot
        .observed
        .wireguard_handshakes
        .get(profile_id)
        .is_some_and(|handshake| {
            tunnel_revisions.is_none_or(|revisions| {
                revisions
                    .get(profile_id)
                    .is_some_and(|revision| revision.generation == handshake.generation)
            })
        })
}

/// Build the sole user-visible tunnel projection from canonical desired and
/// observed facts. This function performs no probing or protocol parsing.
#[allow(clippy::too_many_lines)]
fn derive_tunnel_projections(
    snapshot: &mut ControlSnapshot,
    owner: Option<&OwnerState>,
    config: &ControlServiceConfig,
) {
    let previous = std::mem::take(&mut snapshot.tunnels);
    let tunnel_revisions = owner.map(|owner| &owner.tunnel_revisions);
    let default_interface = snapshot
        .observed
        .default_route
        .as_ref()
        .and_then(|route| route.interface_name.as_deref());
    let primary = default_interface.and_then(|default_interface| {
        snapshot
            .observed
            .tunnels
            .iter()
            .find_map(|(profile_id, observed)| {
                if !observed.active {
                    return None;
                }
                if !wireguard_connection_ready(snapshot, tunnel_revisions, config, profile_id) {
                    return None;
                }
                let metadata = snapshot.observed.tunnel_details.get(profile_id)?;
                (metadata.details.interface_authoritative
                    && metadata.details.interface == default_interface)
                    .then(|| profile_id.clone())
            })
    });

    let mut profiles = config.known_profiles.clone();
    profiles.extend(snapshot.desired.tunnels.keys().cloned());
    profiles.extend(snapshot.observed.tunnels.keys().cloned());
    profiles.extend(
        snapshot
            .challenges
            .values()
            .map(|challenge| challenge.profile_id.clone()),
    );
    let routes_by_profile = profiles
        .iter()
        .map(|profile_id| {
            (
                profile_id.clone(),
                topology_routes(snapshot, config, profile_id),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let challenges_by_profile = snapshot
        .challenges
        .values()
        .map(|challenge| (challenge.profile_id.clone(), challenge))
        .collect::<BTreeMap<_, _>>();
    let reconnecting_profiles = owner
        .into_iter()
        .flat_map(|owner| owner.reconnect_operations.values())
        .flat_map(|reconnect| reconnect.targets.iter().cloned())
        .collect::<BTreeSet<_>>();
    let disconnecting_profiles = snapshot
        .operations
        .values()
        .filter(|operation| !operation.status.is_terminal())
        .filter_map(client_desired_tunnels)
        .flat_map(|tunnels| {
            tunnels
                .iter()
                .filter(|(_, requested)| **requested == RequestedTunnelState::Disconnected)
                .map(|(profile_id, _)| profile_id.clone())
        })
        .collect::<BTreeSet<_>>();

    let mut projections = BTreeMap::new();
    for profile_id in profiles {
        let observed = snapshot.observed.tunnels.get(&profile_id);
        let metadata = snapshot.observed.tunnel_details.get(&profile_id);
        let active = observed.is_some_and(|fact| fact.active);
        let connection_ready =
            active && wireguard_connection_ready(snapshot, tunnel_revisions, config, &profile_id);
        let requested = snapshot.desired.tunnels.get(&profile_id);
        let challenge = challenges_by_profile.get(&profile_id).copied();
        let reconnecting = reconnecting_profiles.contains(&profile_id);
        let old = previous.get(&profile_id);
        let allowed_ips = routes_by_profile
            .get(&profile_id)
            .cloned()
            .unwrap_or_default();
        let interface_authoritative =
            metadata.is_some_and(|metadata| metadata.details.interface_authoritative);
        let base_role = projected_role(
            &profile_id,
            primary.as_ref(),
            allowed_ips,
            interface_authoritative,
        );

        let (state, role, health, interface_name, started_at) = if let Some(challenge) = challenge {
            let since = prior_started_at(old, |state| {
                matches!(state, Connection::AwaitingUserInput { .. })
            });
            (
                Connection::AwaitingUserInput {
                    profile_id: profile_id.clone(),
                    prompt_id: challenge.id.to_string(),
                    prompt_kind: challenge.kind.clone(),
                    since,
                },
                Role::AwaitingInput,
                ConnectionHealth::Unknown,
                None,
                Some(since),
            )
        } else if reconnecting {
            let started = prior_started_at(old, |state| {
                matches!(state, Connection::Reconnecting { .. })
            });
            (
                Connection::Reconnecting {
                    profile_id: profile_id.clone(),
                    started_at: started,
                    attempt: 1,
                    retry_budget_remaining: Duration::ZERO,
                    last_error: None,
                },
                Role::Reconnecting {
                    prior_role: Box::new(base_role),
                },
                ConnectionHealth::Unknown,
                None,
                Some(started),
            )
        } else if matches!(requested, Some(RequestedTunnelState::Disconnected))
            && (active || disconnecting_profiles.contains(&profile_id))
        {
            let started = prior_started_at(old, |state| {
                matches!(state, Connection::Disconnecting { .. })
            });
            (
                Connection::Disconnecting {
                    profile_id: profile_id.clone(),
                    started_at: started,
                },
                base_role,
                ConnectionHealth::Unknown,
                metadata.and_then(|metadata| {
                    (!metadata.details.interface.is_empty())
                        .then(|| metadata.details.interface.clone())
                }),
                Some(started),
            )
        } else if connection_ready {
            let mut details = metadata
                .map(|metadata| metadata.details.clone())
                .unwrap_or_default();
            if details.interface.is_empty() {
                details.interface = observed
                    .and_then(|fact| fact.interface_name.clone())
                    .unwrap_or_default();
            }
            let health = snapshot
                .observed
                .connection_health
                .get(&profile_id)
                .filter(|health| health.desired_generation == snapshot.desired.generation)
                .map_or_else(
                    || details.health_hint.clone(),
                    |health| health.health.clone(),
                );
            details.health_hint = health.clone();
            let since = metadata
                .and_then(|metadata| metadata.started_at)
                .or_else(|| {
                    old.and_then(|snapshot| match snapshot.state {
                        Connection::Connected { since, .. } => Some(since),
                        _ => None,
                    })
                })
                .unwrap_or_else(SystemTime::now);
            let interface_name = (!details.interface.is_empty()).then(|| details.interface.clone());
            (
                Connection::Connected {
                    profile_id: profile_id.clone(),
                    since,
                    health: health.clone(),
                    details: Box::new(details),
                },
                base_role,
                health,
                interface_name,
                Some(since),
            )
        } else if (active && !connection_ready)
            || matches!(requested, Some(RequestedTunnelState::Connected))
        {
            let started =
                prior_started_at(old, |state| matches!(state, Connection::Connecting { .. }));
            (
                Connection::Connecting {
                    profile_id: profile_id.clone(),
                    started_at: started,
                    attempt: 1,
                    retry_budget_remaining: Duration::ZERO,
                },
                base_role,
                ConnectionHealth::Unknown,
                None,
                Some(started),
            )
        } else {
            continue;
        };

        projections.insert(
            profile_id.clone(),
            TunnelSnapshot {
                profile_id,
                state,
                role,
                health,
                interface_name,
                started_at,
            },
        );
    }
    snapshot.primary = primary;
    snapshot.tunnels = projections;
    snapshot.profile_routes = routes_by_profile;
    derive_dns_security_projection(snapshot, config);
}

fn derive_dns_security_projection(snapshot: &mut ControlSnapshot, config: &ControlServiceConfig) {
    use crate::vortix_core::control::{DnsSecurityProjection, DnsSecurityStatus};

    let Some(primary) = snapshot.primary.as_ref() else {
        snapshot.dns = DnsSecurityProjection::default();
        return;
    };
    let request = snapshot
        .observed
        .openvpn_dns
        .get(primary)
        .filter(|observed| observed.desired_generation == snapshot.desired.generation)
        .map(|observed| &observed.request)
        .or_else(|| {
            config
                .profile_topologies
                .get(primary)
                .map(|topology| &topology.dns_request)
        });
    let mut intended_servers = request
        .into_iter()
        .flat_map(|request| request.servers.iter().copied())
        .collect::<Vec<_>>();
    intended_servers.sort_unstable();
    intended_servers.dedup();
    if intended_servers.is_empty() {
        snapshot.dns = DnsSecurityProjection {
            intended_servers,
            status: DnsSecurityStatus::NotRequested,
        };
        return;
    }
    let verified = snapshot.observed.evidence.as_ref().is_some_and(|evidence| {
        evidence.desired_generation == snapshot.desired.generation
            && evidence.authority_epoch == snapshot.desired.authority_epoch
            && evidence.policy_digest == snapshot.desired.policy_digest
            && evidence.dns == GateEvidence::Verified
            && snapshot.effective.freshness.current
    });
    snapshot.dns = DnsSecurityProjection {
        intended_servers,
        status: if verified {
            DnsSecurityStatus::Protected
        } else {
            DnsSecurityStatus::Unverified
        },
    };
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
            kill_switch: (desired.kill_switch
                == crate::vortix_core::state::killswitch::KillSwitchMode::Off)
                .then_some(crate::vortix_core::state::killswitch::KillSwitchState::Disabled),
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
    let protection = if current && evidence.all_gates_verified() && supervised_protection {
        ProtectionStatus::Protected
    } else {
        ProtectionStatus::Degraded
    };
    let applied = supervisor.and_then(Supervisor::applied_topology);
    let kill_switch =
        derive_effective_kill_switch(desired.kill_switch, protection, applied.as_ref());
    snapshot.effective = EffectiveState {
        protection,
        desired_generation: desired.generation,
        authority_epoch: desired.authority_epoch,
        policy_digest: desired.policy_digest.clone(),
        freshness: Freshness {
            observed_at_millis: Some(evidence.observed_at_millis),
            age_millis: Some(age),
            ceiling_millis: MAX_PROTECTION_AGE_MILLIS,
            current,
        },
        kill_switch,
    };
}

fn derive_effective_kill_switch(
    mode: crate::vortix_core::state::killswitch::KillSwitchMode,
    protection: ProtectionStatus,
    applied: Option<&TopologyState>,
) -> Option<crate::vortix_core::state::killswitch::KillSwitchState> {
    match mode {
        crate::vortix_core::state::killswitch::KillSwitchMode::Off => {
            Some(crate::vortix_core::state::killswitch::KillSwitchState::Disabled)
        }
        _ if protection == ProtectionStatus::Degraded => {
            Some(crate::vortix_core::state::killswitch::KillSwitchState::Degraded)
        }
        crate::vortix_core::state::killswitch::KillSwitchMode::Auto => applied.map(|topology| {
            if topology.firewall_blocking {
                crate::vortix_core::state::killswitch::KillSwitchState::Blocking
            } else {
                crate::vortix_core::state::killswitch::KillSwitchState::Armed
            }
        }),
        crate::vortix_core::state::killswitch::KillSwitchMode::AlwaysOn => applied
            .filter(|topology| topology.firewall_blocking)
            .map(|_| crate::vortix_core::state::killswitch::KillSwitchState::Blocking),
    }
}

fn publish_then_events(
    snapshot: &mut ControlSnapshot,
    owner: &mut OwnerState,
    sender: &watch::Sender<ControlSnapshot>,
    events: &broadcast::Sender<ControlEventEnvelope>,
    pending: Vec<ControlEvent>,
    now_millis: u64,
) {
    for event in &pending {
        owner.diagnostics.push_control_event(now_millis, event);
    }
    snapshot.diagnostics = owner.diagnostics.view(now_millis);
    snapshot.generation = snapshot.generation.saturating_add(1);
    sender.send_replace(snapshot.clone());
    for event in pending {
        let _ = events.send(ControlEventEnvelope {
            snapshot_generation: snapshot.generation,
            event,
        });
    }
}

#[cfg(test)]
mod target_profiles_tests {
    use super::*;
    use crate::vortix_core::control::worker::{
        CancellationToken, PolicyBarrier, PolicyExecutor, TunnelExecutionReceipt, TunnelExecutor,
    };
    use crate::vortix_core::control::DnsSecurityStatus;
    use crate::vortix_core::state::{KillSwitchMode, KillSwitchState};

    #[test]
    fn stale_connect_failure_cannot_roll_back_newer_profile_intent() {
        let profile_id = ProfileId::new("newer-connect");
        let mut snapshot = ControlSnapshot::default();
        snapshot.desired.authority_epoch = AuthorityEpoch(7);
        snapshot.desired.generation = 12;
        snapshot
            .desired
            .tunnels
            .insert(profile_id.clone(), RequestedTunnelState::Connected);
        let mut owner = OwnerState::default();
        owner.tunnel_revisions.insert(
            profile_id.clone(),
            TunnelRevision {
                authority_epoch: AuthorityEpoch(7),
                generation: 12,
            },
        );
        let mut events = Vec::new();

        rollback_connect_intent(
            std::slice::from_ref(&profile_id),
            11,
            &mut snapshot,
            &mut owner,
            1,
            &mut events,
        );

        assert_eq!(snapshot.desired.generation, 12);
        assert_eq!(
            snapshot.desired.tunnels.get(&profile_id),
            Some(&RequestedTunnelState::Connected)
        );
        assert!(events.is_empty());

        rollback_connect_intent(
            std::slice::from_ref(&profile_id),
            12,
            &mut snapshot,
            &mut owner,
            2,
            &mut events,
        );

        assert_eq!(snapshot.desired.generation, 13);
        assert_eq!(
            snapshot.desired.tunnels.get(&profile_id),
            Some(&RequestedTunnelState::Disconnected)
        );
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn stale_policy_failure_cannot_restore_over_newer_desired_intent() {
        let profile_id = ProfileId::new("newer-policy-connect");
        let mut snapshot = ControlSnapshot::default();
        snapshot.desired.authority_epoch = AuthorityEpoch(7);
        snapshot.desired.generation = 12;
        snapshot.desired.policy_digest = PolicyDigest("newer-policy".into());
        snapshot
            .desired
            .tunnels
            .insert(profile_id.clone(), RequestedTunnelState::Connected);
        let mut owner = OwnerState::default();
        owner.tunnel_revisions.insert(
            profile_id.clone(),
            TunnelRevision {
                authority_epoch: AuthorityEpoch(7),
                generation: 12,
            },
        );
        let stale_policy = TopologyPolicy {
            generation: 11,
            authority_epoch: AuthorityEpoch(7),
            digest: PolicyDigest("stale-policy".into()),
            operation_id: OperationId::from_parts(AuthorityEpoch(7), 11),
            deadline: Instant::now() + Duration::from_secs(1),
            prior: TopologyState::default(),
            target: TopologyState {
                profiles: BTreeSet::from([profile_id.clone()]),
                ..TopologyState::default()
            },
            prior_tunnel_revisions: BTreeMap::new(),
            tunnel_revisions: BTreeMap::from([(
                profile_id.clone(),
                TunnelRevision {
                    authority_epoch: AuthorityEpoch(7),
                    generation: 11,
                },
            )]),
            transition: TopologyTransitionKind::Connect,
            required_blocking: true,
            stage: PolicyStage::Final,
        };
        let mut events = Vec::new();

        restore_prior_topology_intent(&stale_policy, &mut snapshot, &mut owner, 1, &mut events);

        assert_eq!(snapshot.desired.generation, 12);
        assert_eq!(snapshot.desired.policy_digest.0, "newer-policy");
        assert_eq!(
            snapshot.desired.tunnels.get(&profile_id),
            Some(&RequestedTunnelState::Connected)
        );
        assert_eq!(
            owner.tunnel_revisions.get(&profile_id),
            Some(&TunnelRevision {
                authority_epoch: AuthorityEpoch(7),
                generation: 12,
            })
        );
        assert!(events.is_empty());

        let current_policy = TopologyPolicy {
            generation: 12,
            digest: PolicyDigest("newer-policy".into()),
            operation_id: OperationId::from_parts(AuthorityEpoch(7), 12),
            tunnel_revisions: BTreeMap::from([(
                profile_id.clone(),
                TunnelRevision {
                    authority_epoch: AuthorityEpoch(7),
                    generation: 12,
                },
            )]),
            ..stale_policy
        };

        assert!(restore_prior_topology_intent(
            &current_policy,
            &mut snapshot,
            &mut owner,
            2,
            &mut events,
        ));
        assert_eq!(snapshot.desired.generation, 13);
        assert_eq!(
            snapshot.desired.tunnels.get(&profile_id),
            Some(&RequestedTunnelState::Disconnected)
        );
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn owned_disconnect_receipt_updates_only_the_profile_observation() {
        let profile_id = ProfileId::new("owned-disconnect");
        let mut snapshot = ControlSnapshot::default();
        snapshot.observed.tunnels.insert(
            profile_id.clone(),
            ObservedTunnel {
                active: true,
                interface_name: Some("wg-owned".into()),
                observed_at_millis: 4,
                received_at_millis: 4,
            },
        );
        snapshot.observed.evidence = Some(ProtectionEvidence {
            desired_generation: 3,
            authority_epoch: AuthorityEpoch(7),
            policy_digest: PolicyDigest("settled-policy".into()),
            observed_at_millis: 4,
            interface: GateEvidence::Verified,
            route: GateEvidence::Verified,
            dns: GateEvidence::Verified,
            firewall: GateEvidence::Verified,
        });
        let mut owner = OwnerState {
            observation_clocks: BTreeMap::from([
                (ObservationScope::Protection, 4),
                (ObservationScope::Route, 4),
                (ObservationScope::Dns, 4),
                (ObservationScope::Firewall, 4),
            ]),
            ..OwnerState::default()
        };

        record_owned_disconnect(&profile_id, &mut snapshot, &mut owner, 5);

        assert_eq!(
            snapshot.observed.tunnels.get(&profile_id),
            Some(&ObservedTunnel {
                active: false,
                interface_name: None,
                observed_at_millis: 5,
                received_at_millis: 5,
            })
        );
        let evidence = snapshot.observed.evidence.as_ref().unwrap();
        assert_eq!(evidence.interface, GateEvidence::Verified);
        assert_eq!(evidence.route, GateEvidence::Verified);
        assert_eq!(evidence.dns, GateEvidence::Verified);
        assert_eq!(evidence.firewall, GateEvidence::Verified);
        assert_eq!(
            owner.observation_clocks[&ObservationScope::Profile(profile_id)],
            5
        );
        assert_eq!(owner.observation_clocks[&ObservationScope::Route], 4);
        assert_eq!(owner.observation_clocks[&ObservationScope::Dns], 4);
        assert_eq!(owner.observation_clocks[&ObservationScope::Firewall], 4);
    }

    #[test]
    fn dns_projection_uses_primary_tunnel_intent_and_exact_policy_proof() {
        let profile_id = ProfileId::new("corp");
        let mut snapshot = ControlSnapshot {
            primary: Some(profile_id.clone()),
            ..ControlSnapshot::default()
        };
        snapshot.desired.generation = 9;
        snapshot.desired.authority_epoch = AuthorityEpoch(7);
        snapshot.desired.policy_digest = PolicyDigest("dns-policy".into());
        snapshot.effective.freshness.current = true;
        snapshot.observed.evidence = Some(ProtectionEvidence {
            desired_generation: 9,
            authority_epoch: AuthorityEpoch(7),
            policy_digest: PolicyDigest("dns-policy".into()),
            observed_at_millis: 1,
            interface: GateEvidence::Verified,
            route: GateEvidence::Verified,
            dns: GateEvidence::Verified,
            firewall: GateEvidence::Verified,
        });
        let config = ControlServiceConfig {
            known_profiles: BTreeSet::from([profile_id.clone()]),
            profile_topologies: BTreeMap::from([(
                profile_id,
                ProfileTopology {
                    dns_request: crate::vortix_core::ports::dns::DnsRequest {
                        servers: vec!["10.80.0.1".parse().unwrap()],
                        search_domains: Vec::new(),
                    },
                    ..ProfileTopology::default()
                },
            )]),
            ..ControlServiceConfig::default()
        };

        derive_dns_security_projection(&mut snapshot, &config);

        assert_eq!(
            snapshot.dns.intended_servers,
            vec!["10.80.0.1".parse::<std::net::IpAddr>().unwrap()]
        );
        assert_eq!(snapshot.dns.status, DnsSecurityStatus::Protected);

        snapshot.effective.freshness.current = false;
        derive_dns_security_projection(&mut snapshot, &config);

        assert_eq!(snapshot.dns.status, DnsSecurityStatus::Unverified);
    }

    #[test]
    fn primary_without_vpn_dns_never_claims_dns_protection() {
        let profile_id = ProfileId::new("corp");
        let mut snapshot = ControlSnapshot {
            primary: Some(profile_id.clone()),
            ..ControlSnapshot::default()
        };
        let config = ControlServiceConfig {
            known_profiles: BTreeSet::from([profile_id]),
            ..ControlServiceConfig::default()
        };

        derive_dns_security_projection(&mut snapshot, &config);

        assert_eq!(snapshot.dns.status, DnsSecurityStatus::NotRequested);
        assert!(snapshot.dns.intended_servers.is_empty());
    }

    #[test]
    fn authenticated_openvpn_dns_replaces_static_profile_intent_in_projection() {
        let profile_id = ProfileId::new("corp");
        let mut snapshot = ControlSnapshot {
            primary: Some(profile_id.clone()),
            ..ControlSnapshot::default()
        };
        snapshot.desired.generation = 11;
        snapshot.observed.openvpn_dns.insert(
            profile_id.clone(),
            crate::vortix_core::control::model::ObservedOpenVpnDns {
                desired_generation: 11,
                request: crate::vortix_core::ports::dns::DnsRequest {
                    servers: vec!["10.80.0.1".parse().unwrap()],
                    search_domains: Vec::new(),
                },
            },
        );
        let config = ControlServiceConfig {
            known_profiles: BTreeSet::from([profile_id.clone()]),
            profile_topologies: BTreeMap::from([(
                profile_id,
                ProfileTopology {
                    dns_request: crate::vortix_core::ports::dns::DnsRequest {
                        servers: vec!["1.1.1.1".parse().unwrap()],
                        search_domains: Vec::new(),
                    },
                    ..ProfileTopology::default()
                },
            )]),
            ..ControlServiceConfig::default()
        };

        derive_dns_security_projection(&mut snapshot, &config);

        assert_eq!(
            snapshot.dns.intended_servers,
            vec!["10.80.0.1".parse::<std::net::IpAddr>().unwrap()]
        );
        assert_eq!(snapshot.dns.status, DnsSecurityStatus::Unverified);
    }

    #[test]
    fn dns_barrier_failure_remains_actionable_at_the_operation_boundary() {
        assert_eq!(
            operation_failure_for_policy_result(PolicyOutcome::Failed, Some(PolicyBarrier::Dns),),
            OperationFailure::DnsPolicyFailed
        );
    }

    struct NoopTunnel;

    #[test]
    fn exclusive_switch_ordering_is_recovered_from_durable_intent() {
        let first = ProfileId::new("first");
        let target = ProfileId::new("target");
        let operation_id = OperationId::from_parts(AuthorityEpoch(7), 3);
        let tunnels = BTreeMap::from([
            (first.clone(), RequestedTunnelState::Disconnected),
            (target.clone(), RequestedTunnelState::Connected),
        ]);
        let mut snapshot = ControlSnapshot::default();
        snapshot.desired.generation = 9;
        snapshot.desired.tunnels.clone_from(&tunnels);
        snapshot.operations.insert(
            operation_id.clone(),
            OperationRecord {
                id: operation_id.clone(),
                idempotency_key: IdempotencyKey::new("exclusive-before-crash"),
                client_id: ClientId::from_parts(AuthorityEpoch(7), 1),
                command_digest: PolicyDigest::default(),
                authority_epoch: AuthorityEpoch(7),
                desired_generation: 9,
                admitted_at_millis: 1,
                deadline_millis: u64::MAX,
                intent: OperationIntent::DesiredSubset {
                    tunnels,
                    kill_switch: None,
                },
                status: OperationStatus::WaitingForObservation,
                result: None,
                failure_detail: None,
            },
        );

        let recovered = recover_exclusive_switch_operations(&snapshot);

        assert_eq!(recovered[&operation_id].target, target);
        assert_eq!(recovered[&operation_id].teardown, BTreeSet::from([first]));
    }

    #[test]
    fn absent_tunnel_remains_disconnecting_until_its_operation_is_terminal() {
        let profile_id = ProfileId::new("corp");
        let operation_id = OperationId::from_parts(AuthorityEpoch(7), 4);
        let mut snapshot = ControlSnapshot::default();
        snapshot.desired.generation = 9;
        snapshot
            .desired
            .tunnels
            .insert(profile_id.clone(), RequestedTunnelState::Disconnected);
        snapshot.operations.insert(
            operation_id.clone(),
            OperationRecord {
                id: operation_id,
                idempotency_key: IdempotencyKey::new("disconnect-corp"),
                client_id: ClientId::from_parts(AuthorityEpoch(7), 1),
                command_digest: PolicyDigest::default(),
                authority_epoch: AuthorityEpoch(7),
                desired_generation: 9,
                admitted_at_millis: 1,
                deadline_millis: u64::MAX,
                intent: OperationIntent::DesiredSubset {
                    tunnels: BTreeMap::from([(
                        profile_id.clone(),
                        RequestedTunnelState::Disconnected,
                    )]),
                    kill_switch: None,
                },
                status: OperationStatus::WaitingForObservation,
                result: None,
                failure_detail: None,
            },
        );
        let config = ControlServiceConfig {
            known_profiles: BTreeSet::from([profile_id.clone()]),
            ..ControlServiceConfig::default()
        };

        derive_tunnel_projections(&mut snapshot, None, &config);

        assert!(matches!(
            snapshot.tunnels[&profile_id].state,
            Connection::Disconnecting { .. }
        ));

        snapshot
            .operations
            .values_mut()
            .next()
            .expect("disconnect operation")
            .status = OperationStatus::Succeeded;
        derive_tunnel_projections(&mut snapshot, None, &config);

        assert!(!snapshot.tunnels.contains_key(&profile_id));

        let operation = snapshot
            .operations
            .values_mut()
            .next()
            .expect("disconnect operation");
        operation.status = OperationStatus::WaitingForObservation;
        operation.intent = OperationIntent::UnexpectedRecovery {
            profile_id: ProfileId::new("recovering"),
            tunnels: BTreeMap::from([(profile_id.clone(), RequestedTunnelState::Disconnected)]),
            kill_switch: None,
        };
        derive_tunnel_projections(&mut snapshot, None, &config);
        assert!(
            !snapshot.tunnels.contains_key(&profile_id),
            "recovery context is not a client disconnect request"
        );

        let operation = snapshot
            .operations
            .values_mut()
            .next()
            .expect("disconnect operation");
        operation.client_id = ClientId::from_parts(AuthorityEpoch(7), 0);
        operation.intent = OperationIntent::DesiredSubset {
            tunnels: BTreeMap::from([(profile_id.clone(), RequestedTunnelState::Disconnected)]),
            kill_switch: None,
        };
        derive_tunnel_projections(&mut snapshot, None, &config);
        assert!(
            !snapshot.tunnels.contains_key(&profile_id),
            "service recovery context is not a client disconnect request"
        );
    }

    #[test]
    fn wireguard_interface_presence_does_not_project_connected_without_handshake() {
        let profile_id = ProfileId::new("wg-no-handshake");
        let mut snapshot = ControlSnapshot::default();
        snapshot.desired.authority_epoch = AuthorityEpoch(7);
        snapshot.desired.generation = 9;
        snapshot
            .desired
            .tunnels
            .insert(profile_id.clone(), RequestedTunnelState::Connected);
        snapshot.observed.tunnels.insert(
            profile_id.clone(),
            ObservedTunnel {
                active: true,
                interface_name: Some("utun4".into()),
                observed_at_millis: 1,
                received_at_millis: 1,
            },
        );
        let config = ControlServiceConfig {
            known_profiles: BTreeSet::from([profile_id.clone()]),
            profile_topologies: BTreeMap::from([(
                profile_id.clone(),
                ProfileTopology {
                    protocol: Some(crate::vortix_core::profile::ProtocolKind::WireGuard),
                    ..ProfileTopology::default()
                },
            )]),
            ..ControlServiceConfig::default()
        };

        derive_tunnel_projections(&mut snapshot, None, &config);

        assert!(matches!(
            snapshot.tunnels[&profile_id].state,
            Connection::Connecting { .. }
        ));

        let revisions = BTreeMap::from([(
            profile_id.clone(),
            TunnelRevision {
                authority_epoch: AuthorityEpoch(7),
                generation: 9,
            },
        )]);
        snapshot.observed.wireguard_handshakes.insert(
            profile_id.clone(),
            crate::vortix_core::ports::tunnel::HandshakeEvidence {
                generation: 8,
                peer_public_key: "peer".into(),
                handshake_at: SystemTime::now(),
                observed_at: SystemTime::now(),
                allowed_routes: vec!["10.250.0.0/24".into()],
            },
        );
        assert!(!wireguard_connection_ready(
            &snapshot,
            Some(&revisions),
            &config,
            &profile_id
        ));
        snapshot
            .observed
            .wireguard_handshakes
            .get_mut(&profile_id)
            .expect("test handshake")
            .generation = 9;
        assert!(wireguard_connection_ready(
            &snapshot,
            Some(&revisions),
            &config,
            &profile_id
        ));

        snapshot.observed.wireguard_handshakes.clear();
        snapshot.desired.tunnels.clear();
        derive_tunnel_projections(&mut snapshot, None, &config);
        assert!(matches!(
            snapshot.tunnels[&profile_id].state,
            Connection::Connecting { .. }
        ));
        assert_ne!(snapshot.primary, Some(profile_id));
    }

    #[test]
    fn restored_wireguard_handshake_preserves_connected_projection() {
        let profile_id = ProfileId::new("wg-restored");
        let revision = TunnelRevision {
            authority_epoch: AuthorityEpoch(7),
            generation: 9,
        };
        let supervisor = Supervisor::new(
            AuthorityEpoch(7),
            Arc::new(NoopTunnel),
            Arc::new(NoopPolicy),
            1,
            2,
        );
        let receipt = TunnelExecutionReceipt::wireguard(
            profile_id.clone(),
            "utun4",
            "wg-restored-attestation",
            crate::vortix_core::ports::tunnel::HandshakeEvidence {
                generation: revision.generation,
                peer_public_key: "peer".into(),
                handshake_at: SystemTime::now(),
                observed_at: SystemTime::now(),
                allowed_routes: vec!["10.250.0.0/24".into()],
            },
        )
        .expect("valid WireGuard receipt");
        supervisor
            .restore_owned_tunnel(
                receipt.adoption.expect("adoption evidence"),
                receipt.handshake,
                receipt.probe_receipts,
                None,
                revision,
                OperationId::from_parts(AuthorityEpoch(7), 1),
            )
            .expect("valid restored ownership");

        let mut snapshot = ControlSnapshot::default();
        snapshot.desired.authority_epoch = AuthorityEpoch(7);
        snapshot.desired.generation = 9;
        snapshot
            .desired
            .tunnels
            .insert(profile_id.clone(), RequestedTunnelState::Connected);
        snapshot.observed.tunnels.insert(
            profile_id.clone(),
            ObservedTunnel {
                active: true,
                interface_name: Some("utun4".into()),
                observed_at_millis: 1,
                received_at_millis: 1,
            },
        );
        restore_supervised_wireguard_evidence(&mut snapshot, &supervisor);
        let config = ControlServiceConfig {
            known_profiles: BTreeSet::from([profile_id.clone()]),
            profile_topologies: BTreeMap::from([(
                profile_id.clone(),
                ProfileTopology {
                    protocol: Some(crate::vortix_core::profile::ProtocolKind::WireGuard),
                    ..ProfileTopology::default()
                },
            )]),
            ..ControlServiceConfig::default()
        };

        derive_tunnel_projections(&mut snapshot, None, &config);

        assert!(matches!(
            snapshot.tunnels[&profile_id].state,
            Connection::Connected { .. }
        ));
    }

    #[test]
    fn canonical_effective_killswitch_requires_explicit_policy_truth() {
        assert!(!final_firewall_blocks(KillSwitchMode::Off));
        assert!(!final_firewall_blocks(KillSwitchMode::Auto));
        assert!(final_firewall_blocks(KillSwitchMode::AlwaysOn));

        let armed = TopologyState {
            kill_switch: KillSwitchMode::Auto,
            ..TopologyState::default()
        };
        let blocking_auto = TopologyState {
            kill_switch: KillSwitchMode::Auto,
            firewall_blocking: true,
            ..TopologyState::default()
        };
        let blocking_always = TopologyState {
            kill_switch: KillSwitchMode::AlwaysOn,
            firewall_blocking: true,
            ..TopologyState::default()
        };

        assert_eq!(
            derive_effective_kill_switch(KillSwitchMode::Off, ProtectionStatus::Protected, None),
            Some(KillSwitchState::Disabled)
        );
        assert_eq!(
            derive_effective_kill_switch(
                KillSwitchMode::Auto,
                ProtectionStatus::Protected,
                Some(&armed)
            ),
            Some(KillSwitchState::Armed)
        );
        assert_eq!(
            derive_effective_kill_switch(
                KillSwitchMode::Auto,
                ProtectionStatus::Protected,
                Some(&blocking_auto)
            ),
            Some(KillSwitchState::Blocking)
        );
        assert_eq!(
            derive_effective_kill_switch(
                KillSwitchMode::AlwaysOn,
                ProtectionStatus::Protected,
                Some(&blocking_always)
            ),
            Some(KillSwitchState::Blocking)
        );
        assert_eq!(
            derive_effective_kill_switch(
                KillSwitchMode::Auto,
                ProtectionStatus::Degraded,
                Some(&armed)
            ),
            Some(KillSwitchState::Degraded)
        );
        assert_eq!(
            derive_effective_kill_switch(
                KillSwitchMode::AlwaysOn,
                ProtectionStatus::Protected,
                None
            ),
            None
        );
    }

    impl TunnelExecutor for NoopTunnel {
        fn execute(
            &self,
            _: &TunnelWork,
            _: &CancellationToken,
        ) -> Result<TunnelExecutionReceipt, String> {
            Ok(TunnelExecutionReceipt::default())
        }
    }

    struct NoopPolicy;

    impl PolicyExecutor for NoopPolicy {
        fn apply(&self, _: &TopologyPolicy, _: PolicyBarrier) -> Result<(), String> {
            Ok(())
        }

        fn compensate(&self, _: &TopologyPolicy, _: PolicyBarrier) -> Result<(), String> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct BlockingProfileMutation {
        entered: std::sync::mpsc::SyncSender<()>,
    }

    impl ProfileMutationExecutor for BlockingProfileMutation {
        fn execute(
            &self,
            work: ProfileMutationWork,
        ) -> Result<ProfileMutationApplied, ProfileMutationFailure> {
            let _ = self.entered.send(());
            std::thread::sleep(Duration::from_secs(1));
            Ok(ProfileMutationApplied::Deleted {
                profile_id: work.mutation.profile_id().clone(),
            })
        }
    }

    #[test]
    fn profile_mutation_dispatcher_shutdown_is_bounded() {
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (service_tx, _service_rx) = mpsc::channel(1);
        let dispatcher = ProfileMutationDispatcher::start(
            Arc::new(BlockingProfileMutation {
                entered: entered_tx,
            }),
            &service_tx,
            Arc::new(RealClock),
            1,
        );
        dispatcher
            .dispatch(ProfileMutationWork {
                operation_id: OperationId::from_parts(AuthorityEpoch(1), 1),
                deadline: Deadline(u64::MAX),
                mutation: ProfileMutation::Delete {
                    profile_id: ProfileId::new("corp"),
                },
            })
            .unwrap();
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let started = Instant::now();
        drop(dispatcher);

        assert!(
            started.elapsed() < Duration::from_millis(500),
            "dropping the service must not wait for an uninterruptible filesystem call"
        );
    }

    #[test]
    fn reconnect_all_uses_connected_desired_profiles_without_canonical_supervision() {
        let connected = ProfileId::new("connected");
        let disconnected = ProfileId::new("disconnected");
        let targets = target_profiles_for_command(
            &UserCommand::Reconnect { profile_id: None },
            &BTreeSet::from([connected.clone(), disconnected.clone()]),
            &BTreeMap::from([
                (connected.clone(), RequestedTunnelState::Connected),
                (disconnected, RequestedTunnelState::Disconnected),
            ]),
            ExecutionSelection::LegacyAuthority,
            None,
        )
        .unwrap();

        assert_eq!(targets, vec![connected]);
    }

    #[test]
    fn disconnect_all_lifecycle_targets_only_exact_managed_presence() {
        let connected = ProfileId::new("connected");
        let disconnected = ProfileId::new("disconnected");
        let supervisor = Supervisor::new(
            AuthorityEpoch(1),
            Arc::new(NoopTunnel),
            Arc::new(NoopPolicy),
            2,
            2,
        );
        let evidence = crate::vortix_core::ports::tunnel::AdoptionEvidence::attest(
            connected.clone(),
            "tun0",
            crate::vortix_core::ports::tunnel::TunnelKindTag::OpenVpn,
            Some(42),
            "authenticated-child-42",
        )
        .unwrap();
        supervisor
            .adopt_attested(
                evidence,
                TunnelRevision {
                    authority_epoch: AuthorityEpoch(1),
                    generation: 7,
                },
                OperationId::from_parts(AuthorityEpoch(1), 7),
            )
            .unwrap();
        let catalog = BTreeSet::from([connected.clone(), disconnected]);
        let targets = target_profiles_for_command(
            &UserCommand::Disconnect { profile_id: None },
            &catalog,
            &BTreeMap::new(),
            ExecutionSelection::CanonicalAuthority,
            Some(&supervisor),
        )
        .unwrap();
        let lifecycle = lifecycle_profiles_for_command(
            &UserCommand::Disconnect { profile_id: None },
            &targets,
            ExecutionSelection::CanonicalAuthority,
            Some(&supervisor),
        )
        .unwrap();

        assert_eq!(targets.len(), 2, "desired-state target remains the catalog");
        assert_eq!(lifecycle, vec![connected]);
    }

    #[test]
    fn interactive_profile_can_never_be_marked_boot_eligible() {
        use crate::vortix_core::control::persistence::{BootConnection, BootEligibility};

        let profile = ProfileId::new("interactive");
        let mut config = ControlServiceConfig {
            profile_topologies: BTreeMap::from([(
                profile.clone(),
                ProfileTopology {
                    interactive_credentials: true,
                    ..ProfileTopology::default()
                },
            )]),
            boot_connections: BTreeMap::from([(
                profile.clone(),
                BootConnection {
                    enabled: true,
                    eligibility: BootEligibility::Eligible,
                },
            )]),
            ..ControlServiceConfig::default()
        };

        enforce_interactive_boot_eligibility(&mut config);

        assert_eq!(
            config.boot_connections[&profile].eligibility,
            BootEligibility::InteractiveCredentials
        );
    }
}
