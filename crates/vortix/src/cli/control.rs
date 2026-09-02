//! Standard-mode CLI adapter for the canonical in-process control service.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::core::scanner::ActiveSession;
use crate::core::standard_tunnel_ownership::StandardTunnelOwnershipStore;
use crate::state::{Protocol, VpnProfile};
use crate::topology_policy::{
    topology_for_profile, CanonicalPolicyExecutor, EndpointResolutionCache,
};
use crate::tunnel::{CanonicalTunnelExecutor, CanonicalTunnelSettings};
use crate::vortix_config::control_state::FsControlStateStore;
pub use crate::vortix_config::openvpn_credentials::CredentialClearOutcome;
use crate::vortix_config::openvpn_credentials::{
    CredentialStoreError, FsOpenVpnCredentialStore, RememberedOpenVpnCredentials,
};
use crate::vortix_config::profile_store::{FsProfileStore, ProfileStore, ProfileStoreError};
use crate::vortix_core::control::worker::TunnelRevision;
use crate::vortix_core::control::{
    AdmissionError, AuthorityEpoch, CommandRequest, ControlPersistenceConfig, ControlService,
    ControlServiceConfig, ControlSnapshot, ControlStateStore, ControlSubscription,
    ExecutionSelection, IdempotencyKey, Observation, OperationId, OperationIntent, OperationRecord,
    OperationResult, OperationStatus, ProfileMutation, ProfileMutationApplied,
    ProfileMutationExecutor, ProfileMutationFailure, ProfileMutationWork, ProfileTopology,
    RealClock, RequestedTunnelState, UserCommand,
};
use crate::vortix_core::profile::{Profile, ProfileId};

const STANDARD_AUTHORITY_EPOCH: AuthorityEpoch = AuthorityEpoch(1);
const CONTROL_PROGRESS_INTERVAL: Duration = Duration::from_millis(50);
/// Full process/kernel scans are intentionally slower than control progress.
/// A completed scan can therefore be at most this old before another starts;
/// scans that take longer are followed immediately rather than queued.
const SCANNER_REFRESH_CEILING: Duration = Duration::from_millis(250);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
const SUPERVISED_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const HOOK_SHUTDOWN_GRACE: Duration = Duration::from_secs(1);
/// A recovered operation has a 30-second service-owned deadline. One-shot
/// commands wait for that prior authority work to settle before starting the
/// caller's own deadline, with a small publication margin.
const CLI_STARTUP_SETTLEMENT_TIMEOUT: Duration = Duration::from_secs(32);
const TUI_ADMISSION_CAPACITY: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartupSettlement {
    Wait,
    ContinueInBackground,
}

#[derive(Debug, Error)]
pub enum LocalControlError {
    #[error("cannot construct the local control runtime: {0}")]
    Runtime(String),
    #[error("cannot authenticate the Standard-mode configuration owner: {0}")]
    Owner(String),
    #[error("cannot parse profile '{profile}' for canonical control: {reason}")]
    Profile { profile: String, reason: String },
    #[error("{0}")]
    ProfileImport(String),
    #[error("cannot open durable local control state: {0}")]
    Persistence(String),
    #[error("cannot open Standard-mode tunnel ownership: {0}")]
    Ownership(String),
    #[error("cannot load remembered OpenVPN credentials: {0}")]
    CredentialLoad(#[source] CredentialStoreError),
    #[error("cannot remember OpenVPN credentials: {0}")]
    CredentialRemember(#[source] CredentialStoreError),
    #[error("cannot clear remembered OpenVPN credentials: {0}")]
    CredentialClear(#[source] CredentialStoreError),
    #[error("the credential change is visible, but disk durability could not be confirmed")]
    CredentialDurabilityUncertain,
    #[error(
        "remembered OpenVPN credential management is unavailable through this control session"
    )]
    CredentialManagementUnsupported,
    #[error("remembered OpenVPN credential authority is unavailable")]
    CredentialAuthorityUnavailable,
    #[error("cannot recover active profile '{profile}': {reason}")]
    Recovery { profile: String, reason: String },
    #[error("local control observation failed: {0}")]
    Observation(String),
    #[error("local control service refused the command: {0}")]
    Admission(AdmissionError),
    #[error("local control command queue is busy; wait for an earlier request to finish")]
    Busy,
    #[error("local control service stopped before the operation completed")]
    Stopped,
    #[error("interactive challenge was cancelled")]
    ChallengeCancelled,
    #[error("profile '{profile}' requires 2FA but stdin is not a tty")]
    ChallengeNonInteractive { profile: String },
    #[error("OTP required for 2FA profile '{profile}'")]
    ChallengeEmpty { profile: String },
    #[error("interactive challenge expired before it was answered")]
    ChallengeExpired,
    #[error("remote control failed: {0}")]
    Remote(#[from] crate::daemon::service::RemoteControlError),
}

fn map_challenge_response_error(
    error: crate::vortix_core::control::ChallengeError,
) -> LocalControlError {
    match error {
        crate::vortix_core::control::ChallengeError::Expired => LocalControlError::ChallengeExpired,
        crate::vortix_core::control::ChallengeError::Cancelled => {
            LocalControlError::ChallengeCancelled
        }
        error => LocalControlError::Observation(format!("challenge response failed: {error}")),
    }
}

/// Transport-neutral terminal command result consumed by CLI commands.
///
/// Keeping this shape at the CLI boundary means U13 can change only the
/// authority-selection constructor; command validation, challenge handling,
/// terminal rendering, and profile receipts do not depend on which client
/// transport was selected.
#[derive(Debug, Clone)]
pub struct ClientOperationOutcome {
    pub operation_id: OperationId,
    pub status: OperationStatus,
    pub result: Option<OperationResult>,
    pub snapshot: ControlSnapshot,
    pub profile_mutation: Option<Result<LocalProfileMutationReceipt, ProfileMutationFailure>>,
}

#[derive(Debug, Clone)]
pub enum LocalProfileMutationReceipt {
    Imported(VpnProfile),
    Renamed(VpnProfile),
    Deleted {
        profile_id: ProfileId,
        display_name: String,
    },
    /// Remote owner committed the catalog mutation; the client refreshes its
    /// local presentation catalog from the shared owner-private directory.
    RemoteApplied {
        display_name: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub(crate) enum LocalCatalogOutcome {
    Applied {
        operation_id: OperationId,
        receipt: LocalProfileMutationReceipt,
    },
    Failed {
        operation_id: OperationId,
        failure: ProfileMutationFailure,
    },
    /// No executor-private receipt is available, so preserve the canonical
    /// terminal fields for remote-private errors and pre-worker failures.
    Terminal {
        operation_id: OperationId,
        status: OperationStatus,
        result: Option<OperationResult>,
    },
}

#[derive(Debug)]
pub(crate) struct LocalCatalogUpdate {
    pub revision: u64,
    pub profiles: Option<Vec<VpnProfile>>,
    pub outcomes: Vec<LocalCatalogOutcome>,
}

pub(crate) enum TuiControlCompletion {
    Admission(Result<OperationId, LocalControlError>),
    ChallengeResponse {
        challenge_id: crate::vortix_core::control::ChallengeId,
        result: Result<(), LocalControlError>,
    },
    ChallengeCancellation {
        challenge_id: crate::vortix_core::control::ChallengeId,
        result: Result<(), LocalControlError>,
    },
}

/// A durable admission result produced off the terminal thread. The permit is
/// retained until the TUI drains this value, so queued, executing, and
/// completed-but-undrained requests share one strict capacity bound.
pub(crate) struct LocalTuiAdmissionResult {
    pub command: Option<UserCommand>,
    pub completion: TuiControlCompletion,
    pub import_display_name: Option<String>,
    pub import_request_key: Option<String>,
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

struct TuiAdmissionJob {
    request: CommandRequest,
    command: UserCommand,
    import: Option<(ProfileId, String, String)>,
    permit: tokio::sync::OwnedSemaphorePermit,
}

struct TuiAdmissionQueue {
    sender: tokio::sync::mpsc::Sender<TuiAdmissionJob>,
    results: RefCell<tokio::sync::mpsc::Receiver<LocalTuiAdmissionResult>>,
    permits: Arc<tokio::sync::Semaphore>,
}

fn start_tui_admission_queue(
    runtime: &tokio::runtime::Runtime,
    client: crate::vortix_core::control::ControlHandle,
    profile_mutations: Arc<StandardProfileMutationExecutor>,
) -> TuiAdmissionQueue {
    let (sender, mut receiver) =
        tokio::sync::mpsc::channel::<TuiAdmissionJob>(TUI_ADMISSION_CAPACITY);
    let (result_sender, results) = tokio::sync::mpsc::channel(TUI_ADMISSION_CAPACITY);
    runtime.spawn(async move {
        while let Some(job) = receiver.recv().await {
            let result = client
                .submit(job.request)
                .await
                .map(|admitted| admitted.operation_id)
                .map_err(LocalControlError::Admission);
            if result.is_err() {
                if let Some((profile_id, _, _)) = &job.import {
                    profile_mutations.discard_prepared_import(profile_id);
                }
            }
            let (import_display_name, import_request_key) = job
                .import
                .map_or((None, None), |(_, display_name, request_key)| {
                    (Some(display_name), Some(request_key))
                });
            if result_sender
                .send(LocalTuiAdmissionResult {
                    command: Some(job.command),
                    completion: TuiControlCompletion::Admission(result),
                    import_display_name,
                    import_request_key,
                    _permit: Some(job.permit),
                })
                .await
                .is_err()
            {
                break;
            }
        }
    });
    TuiAdmissionQueue {
        sender,
        results: RefCell::new(results),
        permits: Arc::new(tokio::sync::Semaphore::new(TUI_ADMISSION_CAPACITY)),
    }
}

#[derive(Debug, Clone, PartialEq)]
struct PublishedTunnelDetails {
    details: crate::vortix_core::engine::state::DetailedConnectionInfo,
    started_at: Option<std::time::SystemTime>,
}

impl From<&ActiveSession> for PublishedTunnelDetails {
    fn from(session: &ActiveSession) -> Self {
        Self {
            details: crate::vortix_core::engine::state::DetailedConnectionInfo {
                interface: session.interface.clone(),
                interface_authoritative: session.interface_authoritative,
                internal_ip: session.internal_ip.clone(),
                endpoint: session.endpoint.clone(),
                mtu: session.mtu.clone(),
                public_key: session.public_key.clone(),
                listen_port: session.listen_port.clone(),
                transfer_rx: session.transfer_rx.clone(),
                transfer_tx: session.transfer_tx.clone(),
                latest_handshake: session.latest_handshake.clone(),
                pid: session.pid,
                ..crate::vortix_core::engine::state::DetailedConnectionInfo::default()
            },
            started_at: session.started_at,
        }
    }
}

struct StandardProfileMutationExecutor {
    profiles_dir: std::path::PathBuf,
    profiles: Mutex<BTreeMap<ProfileId, VpnProfile>>,
    prepared_imports: Mutex<BTreeMap<ProfileId, PreparedImportState>>,
    topologies: Mutex<BTreeMap<ProfileId, ProfileTopology>>,
    results:
        Mutex<BTreeMap<OperationId, Result<LocalProfileMutationReceipt, ProfileMutationFailure>>>,
    catalog_revision: AtomicU64,
    #[cfg(test)]
    next_execution_delay: Mutex<Option<Duration>>,
}

struct PreparedImportState {
    prepared: crate::vpn::PreparedProfileImport,
    topology: Option<ProfileTopology>,
}

fn initial_last_connected_at(
    profiles: &[VpnProfile],
) -> BTreeMap<ProfileId, std::time::SystemTime> {
    profiles
        .iter()
        .filter_map(|profile| {
            profile
                .last_used
                .map(|connected_at| (profile.id.clone(), connected_at))
        })
        .collect()
}

impl std::fmt::Debug for StandardProfileMutationExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StandardProfileMutationExecutor")
            .field("profiles_dir", &self.profiles_dir)
            .field("prepared_imports", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl StandardProfileMutationExecutor {
    fn new(
        profiles_dir: std::path::PathBuf,
        profiles: &[VpnProfile],
        prepared_imports: Vec<PreparedImportState>,
        topologies: BTreeMap<ProfileId, ProfileTopology>,
    ) -> Self {
        Self {
            profiles_dir,
            profiles: Mutex::new(
                profiles
                    .iter()
                    .cloned()
                    .map(|profile| (profile.id.clone(), profile))
                    .collect(),
            ),
            prepared_imports: Mutex::new(
                prepared_imports
                    .into_iter()
                    .map(|state| (state.prepared.profile().id.clone(), state))
                    .collect(),
            ),
            topologies: Mutex::new(topologies),
            results: Mutex::new(BTreeMap::new()),
            catalog_revision: AtomicU64::new(0),
            #[cfg(test)]
            next_execution_delay: Mutex::new(None),
        }
    }

    fn profiles_snapshot(&self) -> Vec<VpnProfile> {
        self.profiles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }

    fn profile_snapshot(&self, profile_id: &ProfileId) -> Option<VpnProfile> {
        self.profiles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(profile_id)
            .cloned()
    }

    fn core_profile(&self, profile_id: &ProfileId) -> Option<Profile> {
        let profile = self
            .profiles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(profile_id)
            .cloned()?;
        let resolved = self
            .topologies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(profile_id)
            .map(|topology| topology.resolved_endpoints.clone())
            .unwrap_or_default();
        Some(
            crate::tunnel::profile_view(&profile)
                .with_endpoint_resolutions(resolved)
                .require_managed_endpoint_resolution(),
        )
    }

    fn profiles_and_core_snapshot(&self) -> (Vec<VpnProfile>, BTreeMap<ProfileId, Profile>) {
        let profiles = self
            .profiles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let topologies = self
            .topologies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let core = profiles
            .iter()
            .map(|(profile_id, profile)| {
                let resolved = topologies
                    .get(profile_id)
                    .map(|topology| topology.resolved_endpoints.clone())
                    .unwrap_or_default();
                let core = crate::tunnel::profile_view(profile)
                    .with_endpoint_resolutions(resolved)
                    .require_managed_endpoint_resolution();
                (profile_id.clone(), core)
            })
            .collect();
        (profiles.values().cloned().collect(), core)
    }

    fn take_result(
        &self,
        operation_id: &OperationId,
    ) -> Option<Result<LocalProfileMutationReceipt, ProfileMutationFailure>> {
        self.results
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(operation_id)
    }

    fn prepare_import(
        &self,
        prepared: crate::vpn::PreparedProfileImport,
        topology: Option<ProfileTopology>,
    ) -> ProfileId {
        let profile_id = prepared.profile().id.clone();
        self.prepared_imports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                profile_id.clone(),
                PreparedImportState { prepared, topology },
            );
        profile_id
    }

    fn discard_prepared_import(&self, profile_id: &ProfileId) {
        self.prepared_imports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(profile_id);
    }

    #[cfg(test)]
    fn prepared_import_count(&self) -> usize {
        self.prepared_imports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    #[cfg(test)]
    fn delay_next_execution(&self, delay: Duration) {
        self.next_execution_delay
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace(delay);
    }

    fn catalog_revision(&self) -> u64 {
        self.catalog_revision.load(Ordering::Acquire)
    }

    fn advance_catalog_revision(&self) {
        self.catalog_revision.fetch_add(1, Ordering::Release);
    }

    fn map_store_error(error: &ProfileStoreError) -> ProfileMutationFailure {
        match error {
            ProfileStoreError::NotFound(_) | ProfileStoreError::DisplayNameNotFound(_) => {
                ProfileMutationFailure::NotFound
            }
            ProfileStoreError::NameCollision { .. } | ProfileStoreError::DuplicateId { .. } => {
                ProfileMutationFailure::AlreadyExists
            }
            ProfileStoreError::InvalidName(_) | ProfileStoreError::InvalidId(_) => {
                ProfileMutationFailure::InvalidName
            }
            ProfileStoreError::LockBusy { .. } => ProfileMutationFailure::Busy,
            _ => ProfileMutationFailure::Storage,
        }
    }

    fn record(
        &self,
        operation_id: OperationId,
        result: Result<LocalProfileMutationReceipt, ProfileMutationFailure>,
    ) {
        self.results
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(operation_id, result);
    }
}

impl ProfileMutationExecutor for StandardProfileMutationExecutor {
    #[allow(
        clippy::too_many_lines,
        reason = "one serial executor keeps each crash-safe store commit and its catalog receipt adjacent"
    )]
    fn execute(
        &self,
        work: ProfileMutationWork,
    ) -> Result<ProfileMutationApplied, ProfileMutationFailure> {
        #[cfg(test)]
        if let Some(delay) = self
            .next_execution_delay
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            std::thread::sleep(delay);
        }
        let operation_id = work.operation_id.clone();
        let result = (|| match work.mutation {
            ProfileMutation::Import { profile_id } => {
                let state = self
                    .prepared_imports
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&profile_id)
                    .ok_or(ProfileMutationFailure::NotFound)?;
                let topology = state.topology;
                let profile = crate::vpn::commit_profile_import(state.prepared, &self.profiles_dir)
                    .map_err(|_| ProfileMutationFailure::Storage)?;
                self.profiles
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(profile_id.clone(), profile.clone());
                if let Some(topology) = &topology {
                    self.topologies
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(profile_id.clone(), topology.clone());
                }
                self.advance_catalog_revision();
                self.record(
                    operation_id.clone(),
                    Ok(LocalProfileMutationReceipt::Imported(profile)),
                );
                Ok(ProfileMutationApplied::Imported {
                    profile_id,
                    topology,
                })
            }
            ProfileMutation::Rename {
                profile_id,
                new_display_name,
            } => {
                let mut profile = self
                    .profiles
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&profile_id)
                    .cloned()
                    .ok_or(ProfileMutationFailure::NotFound)?;
                if profile.protocol == crate::state::Protocol::WireGuard
                    && crate::vortix_core::profile::validate_wireguard_interface_name(
                        &new_display_name,
                    )
                    .is_err()
                {
                    return Err(ProfileMutationFailure::InvalidName);
                }
                let mut topology = self
                    .topologies
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&profile_id)
                    .cloned();
                let store = FsProfileStore::new(self.profiles_dir.clone());
                let renamed = store
                    .rename(&profile_id, &new_display_name)
                    .map_err(|error| Self::map_store_error(&error))?;
                profile.name = renamed.display_name;
                profile.config_path = renamed.config_path;
                if let Some(topology) = &mut topology {
                    topology.display_name = Some(profile.name.clone());
                }
                self.profiles
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(profile_id.clone(), profile.clone());
                if let Some(topology) = &topology {
                    self.topologies
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(profile_id.clone(), topology.clone());
                }
                self.advance_catalog_revision();
                self.record(
                    operation_id.clone(),
                    Ok(LocalProfileMutationReceipt::Renamed(profile)),
                );
                Ok(ProfileMutationApplied::Renamed {
                    profile_id,
                    topology,
                })
            }
            ProfileMutation::Delete { profile_id } => {
                let profile = self
                    .profiles
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&profile_id)
                    .cloned()
                    .ok_or(ProfileMutationFailure::NotFound)?;
                FsProfileStore::new(self.profiles_dir.clone())
                    .delete(&profile_id)
                    .map_err(|error| Self::map_store_error(&error))?;
                self.profiles
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&profile_id);
                self.topologies
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&profile_id);
                if matches!(profile.protocol, Protocol::OpenVPN) {
                    crate::utils::cleanup_openvpn_run_files_compat(
                        profile_id.as_str(),
                        &profile.name,
                    );
                }
                self.advance_catalog_revision();
                self.record(
                    operation_id.clone(),
                    Ok(LocalProfileMutationReceipt::Deleted {
                        profile_id: profile_id.clone(),
                        display_name: profile.name,
                    }),
                );
                Ok(ProfileMutationApplied::Deleted { profile_id })
            }
        })();
        if let Err(failure) = result {
            self.record(operation_id, Err(failure));
        }
        result
    }
}

/// Read durable canonical intent without starting protocol or policy workers.
/// This keeps an already-disconnected `down` unprivileged while ensuring a
/// missing kernel tunnel cannot hide a still-connected desired state.
pub(crate) fn durable_disconnect_required(
    config_dir: &Path,
    target_profiles: &BTreeSet<ProfileId>,
) -> Result<bool, LocalControlError> {
    let boot_id = crate::utils::boot_identity()
        .ok_or_else(|| LocalControlError::Persistence("OS boot identity is unavailable".into()))?;
    let owner = config_owner(config_dir)?;
    let store = FsControlStateStore::for_owner(config_dir.join("control"), owner.0, owner.1);
    let recovered = store
        .load(&boot_id)
        .map_err(|error| LocalControlError::Persistence(error.to_string()))?;
    Ok(recovered.is_some_and(|recovered| {
        desired_disconnect_required(&recovered.state.desired.tunnels, target_profiles)
    }))
}

fn desired_disconnect_required(
    desired: &BTreeMap<ProfileId, RequestedTunnelState>,
    target_profiles: &BTreeSet<ProfileId>,
) -> bool {
    desired.iter().any(|(profile, state)| {
        *state == RequestedTunnelState::Connected
            && (target_profiles.is_empty() || target_profiles.contains(profile))
    })
}

fn honor_emergency_release_fence(
    active: bool,
    state_store: &dyn ControlStateStore,
    boot_id: &str,
    recovered: &mut Option<crate::vortix_core::control::RecoveredControlState>,
) -> Result<(), LocalControlError> {
    if !active {
        return Ok(());
    }
    let Some(recovered) = recovered else {
        return Ok(());
    };

    recovered.state.desired.kill_switch = crate::state::KillSwitchMode::Off;
    recovered.state.desired.generation = recovered.state.desired.generation.saturating_add(1);
    recovered.state.desired.refresh_policy_digest();
    recovered.state.reconciliation_required = true;

    // Replace both current and recovery copies before any tunnel or policy
    // restoration can observe the older blocking mode.
    state_store
        .save(boot_id, &recovered.state)
        .map_err(|error| LocalControlError::Persistence(error.to_string()))?;
    state_store
        .save(boot_id, &recovered.state)
        .map_err(|error| LocalControlError::Persistence(error.to_string()))
}

enum RemoteTuiWork {
    Command {
        command: UserCommand,
        wait: Duration,
        idempotency_key: String,
    },
    Import {
        path: std::path::PathBuf,
        wait: Duration,
        idempotency_key: String,
    },
    RespondChallenge {
        challenge_id: crate::vortix_core::control::ChallengeId,
        answer: crate::vortix_core::control::Secret,
    },
    CancelChallenge {
        challenge_id: crate::vortix_core::control::ChallengeId,
    },
}

struct RemoteTuiJob {
    work: RemoteTuiWork,
    permit: tokio::sync::OwnedSemaphorePermit,
}

struct RemoteTuiQueue {
    jobs: Option<std::sync::mpsc::SyncSender<RemoteTuiJob>>,
    results: RefCell<Option<std::sync::mpsc::Receiver<LocalTuiAdmissionResult>>>,
    permits: Arc<tokio::sync::Semaphore>,
    worker: Option<std::thread::JoinHandle<()>>,
    submitted_profile_operations: Arc<Mutex<BTreeMap<OperationId, RemoteProfileMutationContext>>>,
    staged_cli_profiles: Mutex<BTreeMap<ProfileId, String>>,
    pending_challenges:
        Arc<Mutex<std::collections::BTreeSet<crate::vortix_core::control::ChallengeId>>>,
    profiles_dir: Option<std::path::PathBuf>,
}

#[derive(Debug)]
struct RemoteProfileMutationContext {
    display_name: Option<String>,
}

impl RemoteTuiQueue {
    fn enqueue(&self, work: RemoteTuiWork) -> Result<(), LocalControlError> {
        let permit = Arc::clone(&self.permits)
            .try_acquire_owned()
            .map_err(|_| LocalControlError::Busy)?;
        self.jobs
            .as_ref()
            .ok_or(LocalControlError::Stopped)?
            .try_send(RemoteTuiJob { work, permit })
            .map_err(|error| match error {
                std::sync::mpsc::TrySendError::Full(_) => LocalControlError::Busy,
                std::sync::mpsc::TrySendError::Disconnected(_) => LocalControlError::Stopped,
            })
    }
}

fn remote_profile_mutation_context(
    command: &UserCommand,
    import_display_name: Option<&str>,
) -> Option<RemoteProfileMutationContext> {
    match command {
        UserCommand::ImportProfile { .. } => Some(RemoteProfileMutationContext {
            display_name: import_display_name.map(str::to_owned),
        }),
        UserCommand::RenameProfile {
            new_display_name, ..
        } => Some(RemoteProfileMutationContext {
            display_name: Some(new_display_name.clone()),
        }),
        UserCommand::DeleteProfile { .. } => {
            Some(RemoteProfileMutationContext { display_name: None })
        }
        _ => None,
    }
}

fn submit_remote_tui_command(
    session: &crate::daemon::service::RemoteControlSession,
    command: &UserCommand,
    wait: Duration,
    idempotency_key: String,
    import_display_name: Option<&str>,
    submitted_profile_operations: &Mutex<BTreeMap<OperationId, RemoteProfileMutationContext>>,
) -> Result<OperationId, LocalControlError> {
    let admitted = session
        .submit(command.clone(), wait, idempotency_key)
        .map_err(LocalControlError::Remote)?;
    if let Some(context) = remote_profile_mutation_context(command, import_display_name) {
        submitted_profile_operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(admitted.operation_id.clone(), context);
    }
    Ok(admitted.operation_id)
}

fn execute_remote_tui_work(
    session: &crate::daemon::service::RemoteControlSession,
    work: RemoteTuiWork,
    profile_operations: &Mutex<BTreeMap<OperationId, RemoteProfileMutationContext>>,
    pending_challenges: &Mutex<
        std::collections::BTreeSet<crate::vortix_core::control::ChallengeId>,
    >,
) -> (
    Option<UserCommand>,
    Option<String>,
    Option<String>,
    TuiControlCompletion,
) {
    match work {
        RemoteTuiWork::Command {
            command,
            wait,
            idempotency_key,
        } => {
            let operation_id = submit_remote_tui_command(
                session,
                &command,
                wait,
                idempotency_key,
                None,
                profile_operations,
            );
            (
                Some(command),
                None,
                None,
                TuiControlCompletion::Admission(operation_id),
            )
        }
        RemoteTuiWork::Import {
            path,
            wait,
            idempotency_key,
        } => {
            let import_request_key = idempotency_key.clone();
            match session.stage_profile_import(&path) {
                Ok((profile_id, display_name)) => {
                    let command = UserCommand::ImportProfile { profile_id };
                    let operation_id = submit_remote_tui_command(
                        session,
                        &command,
                        wait,
                        idempotency_key,
                        Some(&display_name),
                        profile_operations,
                    );
                    (
                        Some(command),
                        Some(display_name),
                        Some(import_request_key),
                        TuiControlCompletion::Admission(operation_id),
                    )
                }
                Err(error) => (
                    None,
                    path.file_stem()
                        .and_then(std::ffi::OsStr::to_str)
                        .map(str::to_owned),
                    Some(import_request_key),
                    TuiControlCompletion::Admission(Err(LocalControlError::Remote(error))),
                ),
            }
        }
        RemoteTuiWork::RespondChallenge {
            challenge_id,
            answer,
        } => {
            let result = session
                .respond_challenge(challenge_id, answer)
                .map_err(LocalControlError::Remote);
            if result.is_err() {
                pending_challenges
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&challenge_id);
            }
            (
                None,
                None,
                None,
                TuiControlCompletion::ChallengeResponse {
                    challenge_id,
                    result,
                },
            )
        }
        RemoteTuiWork::CancelChallenge { challenge_id } => {
            let result = session
                .cancel_challenge(challenge_id)
                .map_err(LocalControlError::Remote);
            if result.is_err() {
                pending_challenges
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&challenge_id);
            }
            (
                None,
                None,
                None,
                TuiControlCompletion::ChallengeCancellation {
                    challenge_id,
                    result,
                },
            )
        }
    }
}

fn start_remote_tui_worker(
    session: Arc<crate::daemon::service::RemoteControlSession>,
    receiver: std::sync::mpsc::Receiver<RemoteTuiJob>,
    result_sender: std::sync::mpsc::SyncSender<LocalTuiAdmissionResult>,
    profile_operations: Arc<Mutex<BTreeMap<OperationId, RemoteProfileMutationContext>>>,
    pending_challenges: Arc<
        Mutex<std::collections::BTreeSet<crate::vortix_core::control::ChallengeId>>,
    >,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("vortix-remote-control".into())
        .spawn(move || {
            while let Ok(job) = receiver.recv() {
                let (command, import_display_name, import_request_key, completion) =
                    execute_remote_tui_work(
                        &session,
                        job.work,
                        &profile_operations,
                        &pending_challenges,
                    );
                if result_sender
                    .send(LocalTuiAdmissionResult {
                        command,
                        completion,
                        import_display_name,
                        import_request_key,
                        _permit: Some(job.permit),
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .expect("remote control worker thread")
}

impl Drop for RemoteTuiQueue {
    fn drop(&mut self) {
        self.jobs.take();
        self.results.get_mut().take();
        if let Some(worker) = self.worker.take() {
            // A transport call has its own deadline, but terminal teardown
            // must never wait for a remote daemon. Join only when the worker
            // has already observed channel closure; otherwise detach it and
            // let its owned session expire at the transport boundary.
            if worker.is_finished() {
                let _ = worker.join();
            }
        }
    }
}

enum ClientControlSessionKind {
    StandardLifecycle(Box<LocalControlSession>),
    StandardProfile(LocalProfileMutationSession),
    Remote {
        session: Arc<crate::daemon::service::RemoteControlSession>,
        queue: RemoteTuiQueue,
    },
}

/// One CLI/TUI-facing client adapter. U19 prepares both transports behind
/// this facade while the production constructors remain Standard-only; U13
/// will change only the authority-selection seam after atomic enrollment.
pub struct ClientControlSession(ClientControlSessionKind);

impl ClientControlSession {
    #[must_use]
    pub fn standard(session: LocalControlSession) -> Self {
        Self(ClientControlSessionKind::StandardLifecycle(Box::new(
            session,
        )))
    }

    /// Production CLI authority-selection seam. U19 pins it explicitly to
    /// Standard mode and performs no daemon probe or fallback; U13 changes
    /// this one constructor only after atomic enrollment.
    pub fn start_production(
        config: &crate::config::AppConfig,
        config_dir: &Path,
        profiles: Vec<VpnProfile>,
    ) -> Result<Self, LocalControlError> {
        LocalControlSession::start(config, config_dir, profiles).map(Self::standard)
    }

    /// Profile-only production authority-selection seam. It is independently
    /// shaped because Standard imports carry prepared memory-only material,
    /// but it shares the same hard Standard pin until U13.
    pub(crate) fn start_production_profile(
        config_dir: &Path,
        profiles: &[VpnProfile],
        prepared_imports: Vec<crate::vpn::PreparedProfileImport>,
    ) -> Result<Self, LocalControlError> {
        LocalProfileMutationSession::start(config_dir, profiles, prepared_imports)
            .map(|session| Self(ClientControlSessionKind::StandardProfile(session)))
    }

    /// Profile-import authority-selection seam. The source path stays
    /// available at this boundary so U13 can replace Standard preparation
    /// with remote staging without changing the command handler.
    pub(crate) fn start_production_profile_import(
        config_dir: &Path,
        profiles: &[VpnProfile],
        path: &Path,
    ) -> Result<(Self, ProfileId), LocalControlError> {
        let profiles_dir = config_dir.join(crate::constants::PROFILES_DIR_NAME);
        let prepared = crate::vpn::prepare_profile_import(path, &profiles_dir)
            .map_err(LocalControlError::ProfileImport)?;
        let profile_id = prepared.profile().id.clone();
        let session = Self::start_production_profile(config_dir, profiles, vec![prepared])?;
        Ok((session, profile_id))
    }

    /// Closed production activation seam. It returns before connecting while
    /// U19's enrollment gate is disabled.
    pub fn connect_remote_production(
        socket_path: std::path::PathBuf,
    ) -> Result<Self, LocalControlError> {
        let transport: Arc<dyn crate::daemon::service::RemoteControlTransport> = Arc::new(
            crate::daemon::client::UnixRemoteControlTransport::new(socket_path),
        );
        let session = crate::daemon::service::RemoteControlSession::connect_production(
            crate::daemon::service::RemoteMutationGate::production(),
            transport,
        )?;
        Ok(Self::remote(session))
    }

    #[doc(hidden)]
    #[must_use]
    pub fn remote_for_parity(session: crate::daemon::service::RemoteControlSession) -> Self {
        Self::remote(session)
    }

    fn remote(session: crate::daemon::service::RemoteControlSession) -> Self {
        let session = Arc::new(session);
        let (jobs, receiver) =
            std::sync::mpsc::sync_channel::<RemoteTuiJob>(TUI_ADMISSION_CAPACITY);
        let (result_sender, results) = std::sync::mpsc::sync_channel(TUI_ADMISSION_CAPACITY);
        let permits = Arc::new(tokio::sync::Semaphore::new(TUI_ADMISSION_CAPACITY));
        let submitted_profile_operations = Arc::new(Mutex::new(BTreeMap::new()));
        let pending_challenges = Arc::new(Mutex::new(std::collections::BTreeSet::new()));
        let worker = start_remote_tui_worker(
            Arc::clone(&session),
            receiver,
            result_sender,
            Arc::clone(&submitted_profile_operations),
            Arc::clone(&pending_challenges),
        );
        Self(ClientControlSessionKind::Remote {
            session,
            queue: RemoteTuiQueue {
                jobs: Some(jobs),
                results: RefCell::new(Some(results)),
                permits,
                worker: Some(worker),
                submitted_profile_operations,
                staged_cli_profiles: Mutex::new(BTreeMap::new()),
                pending_challenges,
                profiles_dir: crate::vpn::get_profiles_dir().ok(),
            },
        })
    }

    pub fn progress(&self) -> Result<(), LocalControlError> {
        match &self.0 {
            ClientControlSessionKind::StandardLifecycle(session) => session.progress(),
            ClientControlSessionKind::StandardProfile(_)
            | ClientControlSessionKind::Remote { .. } => Ok(()),
        }
    }

    pub fn current_snapshot(&self) -> ControlSnapshot {
        match &self.0 {
            ClientControlSessionKind::StandardLifecycle(session) => session.current_snapshot(),
            ClientControlSessionKind::StandardProfile(session) => {
                session.service.client().snapshot()
            }
            ClientControlSessionKind::Remote { session, queue } => {
                project_remote_snapshot(session, queue, session.current_snapshot())
            }
        }
    }

    /// Validate through the selected client authority without constructing a
    /// second writer. Remote validation is deliberately limited to facts in
    /// the canonical snapshot; final admission remains daemon-owned.
    pub fn validate(&self, command: &UserCommand) -> Result<(), LocalControlError> {
        match &self.0 {
            ClientControlSessionKind::StandardLifecycle(session) => session.validate(command),
            ClientControlSessionKind::StandardProfile(_) => Ok(()),
            ClientControlSessionKind::Remote { session, queue } => {
                let snapshot = project_remote_snapshot(session, queue, session.current_snapshot());
                if !snapshot.readiness.reconciliation_complete
                    || !snapshot.readiness.authority_verified
                {
                    return Err(LocalControlError::Remote(
                        crate::daemon::service::RemoteControlError::Admission(
                            AdmissionError::NotReady,
                        ),
                    ));
                }
                if let UserCommand::Connect {
                    profile_id,
                    conflict_acknowledgement: None,
                } = command
                {
                    if snapshot.topology_conflict(profile_id).is_some() {
                        return Err(LocalControlError::Remote(
                            crate::daemon::service::RemoteControlError::Admission(
                                AdmissionError::RouteConflict,
                            ),
                        ));
                    }
                }
                Ok(())
            }
        }
    }

    /// Query canonical ownership through the selected transport. The remote
    /// branch consumes the daemon snapshot directly and never scans locally.
    #[must_use]
    pub fn is_canonically_owned_active(&self, profile_id: &ProfileId) -> bool {
        match &self.0 {
            ClientControlSessionKind::StandardLifecycle(session) => {
                session.is_canonically_owned_active(profile_id)
            }
            ClientControlSessionKind::StandardProfile(_) => false,
            ClientControlSessionKind::Remote { session, queue } => {
                let snapshot = project_remote_snapshot(session, queue, session.current_snapshot());
                snapshot.tunnels.get(profile_id).is_some_and(|tunnel| {
                    !matches!(
                        tunnel.state,
                        crate::vortix_core::engine::state::Connection::Disconnected { .. }
                    )
                })
            }
        }
    }

    /// Stage private profile material through the selected remote adapter.
    /// Production cannot reach this branch before the closed enrollment gate
    /// opens; Standard import continues to use its prepared in-process port.
    pub fn stage_profile_import(
        &self,
        path: &Path,
    ) -> Result<(ProfileId, String), LocalControlError> {
        let ClientControlSessionKind::Remote { session, queue } = &self.0 else {
            return Err(LocalControlError::Observation(
                "profile staging is only required by the remote client adapter".into(),
            ));
        };
        let (profile_id, display_name) = session
            .stage_profile_import(path)
            .map_err(LocalControlError::Remote)?;
        queue
            .staged_cli_profiles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(profile_id.clone(), display_name.clone());
        Ok((profile_id, display_name))
    }

    /// Run a one-shot CLI command through the selected client adapter.
    pub fn run(
        self,
        command: UserCommand,
        wait: Duration,
        idempotency_key: impl Into<String>,
    ) -> Result<ClientOperationOutcome, LocalControlError> {
        self.run_with_challenges(command, wait, idempotency_key, |challenge| {
            Err(LocalControlError::ChallengeNonInteractive {
                profile: challenge.profile_id.to_string(),
            })
        })
    }

    /// Run a one-shot CLI command and answer only challenges authorized for
    /// this selected client. Remote failures never fall back to Standard.
    pub fn run_with_challenges<F>(
        self,
        command: UserCommand,
        wait: Duration,
        idempotency_key: impl Into<String>,
        answer_challenge: F,
    ) -> Result<ClientOperationOutcome, LocalControlError>
    where
        F: FnMut(
                &crate::vortix_core::control::ChallengeRecord,
            ) -> Result<crate::vortix_core::control::Secret, LocalControlError>
            + Send
            + 'static,
    {
        let idempotency_key = idempotency_key.into();
        match self.0 {
            ClientControlSessionKind::StandardLifecycle(session) => {
                session.run_with_challenges(command, wait, idempotency_key, answer_challenge)
            }
            ClientControlSessionKind::StandardProfile(session) => {
                session.run(command, wait, idempotency_key)
            }
            ClientControlSessionKind::Remote { session, queue } => run_remote_cli_command(
                &session,
                &queue,
                &command,
                wait,
                idempotency_key,
                answer_challenge,
            ),
        }
    }

    pub fn enqueue_tui_command(
        &self,
        command: UserCommand,
        wait: Duration,
        idempotency_key: impl Into<String>,
    ) -> Result<(), LocalControlError> {
        match &self.0 {
            ClientControlSessionKind::StandardLifecycle(session) => {
                session.enqueue_tui_command(command, wait, idempotency_key)
            }
            ClientControlSessionKind::StandardProfile(_) => Err(LocalControlError::Observation(
                "profile-only Standard session cannot serve a TUI lifecycle request".into(),
            )),
            ClientControlSessionKind::Remote { queue, .. } => {
                queue.enqueue(RemoteTuiWork::Command {
                    command,
                    wait,
                    idempotency_key: idempotency_key.into(),
                })
            }
        }
    }

    pub fn enqueue_tui_profile_import(
        &self,
        path: &Path,
        wait: Duration,
        idempotency_key: impl Into<String>,
    ) -> Result<String, LocalControlError> {
        match &self.0 {
            ClientControlSessionKind::StandardLifecycle(session) => {
                session.enqueue_tui_profile_import(path, wait, idempotency_key)
            }
            ClientControlSessionKind::StandardProfile(_) => Err(LocalControlError::Observation(
                "profile-only Standard session cannot serve a TUI import request".into(),
            )),
            ClientControlSessionKind::Remote { queue, .. } => {
                // This is only a provisional queue label. The daemon parses
                // the body off-thread and its canonical display name is
                // returned in the admission completion and terminal receipt.
                let display_name = path
                    .file_stem()
                    .and_then(std::ffi::OsStr::to_str)
                    .filter(|name| !name.is_empty())
                    .ok_or_else(|| LocalControlError::Profile {
                        profile: path.display().to_string(),
                        reason: "invalid profile file name".into(),
                    })?
                    .to_owned();
                queue.enqueue(RemoteTuiWork::Import {
                    path: path.to_path_buf(),
                    wait,
                    idempotency_key: idempotency_key.into(),
                })?;
                Ok(display_name)
            }
        }
    }

    pub(crate) fn take_tui_admission_results(&self) -> Vec<LocalTuiAdmissionResult> {
        match &self.0 {
            ClientControlSessionKind::StandardLifecycle(session) => {
                session.take_tui_admission_results()
            }
            ClientControlSessionKind::StandardProfile(_) => Vec::new(),
            ClientControlSessionKind::Remote { queue, .. } => {
                let mut results = queue.results.borrow_mut();
                let Some(receiver) = results.as_mut() else {
                    return Vec::new();
                };
                std::iter::from_fn(|| receiver.try_recv().ok()).collect()
            }
        }
    }

    pub fn take_changed_snapshot(&self) -> Result<Option<ControlSnapshot>, LocalControlError> {
        match &self.0 {
            ClientControlSessionKind::StandardLifecycle(session) => session.take_changed_snapshot(),
            ClientControlSessionKind::StandardProfile(_) => Ok(None),
            ClientControlSessionKind::Remote { session, queue } => session
                .take_changed_snapshot()
                .map(|snapshot| {
                    snapshot.map(|snapshot| project_remote_snapshot(session, queue, snapshot))
                })
                .map_err(LocalControlError::Remote),
        }
    }

    pub(crate) fn take_catalog_update(
        &self,
        snapshot: &ControlSnapshot,
    ) -> Option<LocalCatalogUpdate> {
        match &self.0 {
            ClientControlSessionKind::StandardLifecycle(session) => {
                session.take_catalog_update(snapshot)
            }
            ClientControlSessionKind::StandardProfile(_) => None,
            ClientControlSessionKind::Remote { queue, .. } => {
                let mut outcomes = Vec::new();
                let mut submitted = queue
                    .submitted_profile_operations
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let terminal = submitted
                    .keys()
                    .filter_map(|operation_id| {
                        snapshot
                            .operations
                            .get(operation_id)
                            .filter(|operation| operation.status.is_terminal())
                            .map(|operation| (operation_id.clone(), operation.clone()))
                    })
                    .collect::<Vec<_>>();
                for (operation_id, operation) in terminal {
                    let context = submitted
                        .remove(&operation_id)
                        .expect("terminal operation came from the submitted map");
                    if matches!(
                        operation.result,
                        Some(
                            OperationResult::ProfileMutationApplied
                                | OperationResult::ProfileMutationAppliedAfterDeadline
                        )
                    ) {
                        outcomes.push(LocalCatalogOutcome::Applied {
                            operation_id,
                            receipt: LocalProfileMutationReceipt::RemoteApplied {
                                display_name: context.display_name,
                            },
                        });
                    } else {
                        outcomes.push(LocalCatalogOutcome::Terminal {
                            operation_id,
                            status: operation.status,
                            result: operation.result,
                        });
                    }
                }
                if outcomes.is_empty() {
                    return None;
                }
                Some(LocalCatalogUpdate {
                    revision: snapshot.generation,
                    profiles: queue
                        .profiles_dir
                        .as_deref()
                        .map(crate::vpn::load_profiles_from),
                    outcomes,
                })
            }
        }
    }

    pub fn respond_challenge(
        &self,
        challenge_id: crate::vortix_core::control::ChallengeId,
        answer: Vec<u8>,
    ) -> Result<(), LocalControlError> {
        match &self.0 {
            ClientControlSessionKind::StandardLifecycle(session) => {
                session.respond_challenge(challenge_id, answer)
            }
            ClientControlSessionKind::StandardProfile(_) => Err(LocalControlError::Observation(
                "profile-only Standard session cannot answer a challenge".into(),
            )),
            ClientControlSessionKind::Remote { queue, .. } => {
                if !queue
                    .pending_challenges
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(challenge_id)
                {
                    return Ok(());
                }
                let queued = queue.enqueue(RemoteTuiWork::RespondChallenge {
                    challenge_id,
                    answer: crate::vortix_core::control::Secret::new(answer),
                });
                if queued.is_err() {
                    queue
                        .pending_challenges
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&challenge_id);
                }
                queued
            }
        }
    }

    /// Load reusable `OpenVPN` credentials through the selected live
    /// authority. This operation is intentionally absent from `UserCommand`
    /// and every durable control projection.
    pub fn load_openvpn_credentials(
        &self,
        profile_id: &ProfileId,
        legacy_display_name: &str,
    ) -> Result<Option<RememberedOpenVpnCredentials>, LocalControlError> {
        match &self.0 {
            ClientControlSessionKind::StandardLifecycle(session) => {
                session.load_openvpn_credentials(profile_id, legacy_display_name)
            }
            ClientControlSessionKind::StandardProfile(_)
            | ClientControlSessionKind::Remote { .. } => {
                Err(LocalControlError::CredentialManagementUnsupported)
            }
        }
    }

    /// Atomically remember a reusable username/password pair for one stable
    /// profile identity through the selected live authority.
    pub fn remember_openvpn_credentials(
        &self,
        profile_id: &ProfileId,
        username: &str,
        password: &str,
    ) -> Result<(), LocalControlError> {
        match &self.0 {
            ClientControlSessionKind::StandardLifecycle(session) => {
                session.remember_openvpn_credentials(profile_id, username, password)
            }
            ClientControlSessionKind::StandardProfile(_)
            | ClientControlSessionKind::Remote { .. } => {
                Err(LocalControlError::CredentialManagementUnsupported)
            }
        }
    }

    /// Clear stable and unambiguous legacy credentials through the selected
    /// live authority.
    pub fn clear_openvpn_credentials(
        &self,
        profile_id: &ProfileId,
        legacy_display_name: &str,
    ) -> Result<CredentialClearOutcome, LocalControlError> {
        match &self.0 {
            ClientControlSessionKind::StandardLifecycle(session) => {
                session.clear_openvpn_credentials(profile_id, legacy_display_name)
            }
            ClientControlSessionKind::StandardProfile(_)
            | ClientControlSessionKind::Remote { .. } => {
                Err(LocalControlError::CredentialManagementUnsupported)
            }
        }
    }

    pub fn cancel_challenge(
        &self,
        challenge_id: crate::vortix_core::control::ChallengeId,
    ) -> Result<(), LocalControlError> {
        match &self.0 {
            ClientControlSessionKind::StandardLifecycle(session) => {
                session.cancel_challenge(challenge_id)
            }
            ClientControlSessionKind::StandardProfile(_) => Err(LocalControlError::Observation(
                "profile-only Standard session cannot cancel a challenge".into(),
            )),
            ClientControlSessionKind::Remote { queue, .. } => {
                if !queue
                    .pending_challenges
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(challenge_id)
                {
                    return Ok(());
                }
                let queued = queue.enqueue(RemoteTuiWork::CancelChallenge { challenge_id });
                if queued.is_err() {
                    queue
                        .pending_challenges
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&challenge_id);
                }
                queued
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn is_remote(&self) -> bool {
        matches!(self.0, ClientControlSessionKind::Remote { .. })
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the remote CLI loop keeps admission, authorized challenges, and terminal truth in one bounded flow"
)]
fn run_remote_cli_command<F>(
    session: &crate::daemon::service::RemoteControlSession,
    queue: &RemoteTuiQueue,
    command: &UserCommand,
    wait: Duration,
    idempotency_key: String,
    mut answer_challenge: F,
) -> Result<ClientOperationOutcome, LocalControlError>
where
    F: FnMut(
        &crate::vortix_core::control::ChallengeRecord,
    ) -> Result<crate::vortix_core::control::Secret, LocalControlError>,
{
    let admitted = session
        .submit(command.clone(), wait, idempotency_key)
        .map_err(LocalControlError::Remote)?;
    let wall_deadline = Instant::now() + wait + SHUTDOWN_GRACE;
    let mut handled = std::collections::BTreeSet::new();
    loop {
        let snapshot = session
            .take_changed_snapshot()
            .map_err(LocalControlError::Remote)?
            .unwrap_or_else(|| session.current_snapshot());
        let challenges = snapshot
            .challenges
            .values()
            .filter(|challenge| {
                challenge.operation_id == admitted.operation_id
                    && challenge.authorized_client == *session.client_id()
                    && !handled.contains(&challenge.id)
            })
            .cloned()
            .collect::<Vec<_>>();
        for challenge in challenges {
            handled.insert(challenge.id);
            match answer_challenge(&challenge) {
                Ok(answer) => session
                    .respond_challenge(challenge.id, answer)
                    .map_err(LocalControlError::Remote)?,
                Err(error) => {
                    let _ = session.cancel_challenge(challenge.id);
                    return Err(error);
                }
            }
        }
        if let Some(operation) = snapshot.operations.get(&admitted.operation_id) {
            if operation.status.is_terminal() {
                let profile_mutation = remote_profile_mutation_receipt(queue, command, operation);
                return Ok(ClientOperationOutcome {
                    operation_id: admitted.operation_id,
                    status: operation.status,
                    result: operation.result,
                    snapshot: project_remote_snapshot(session, queue, snapshot),
                    profile_mutation,
                });
            }
        }
        if Instant::now() >= wall_deadline {
            return Err(LocalControlError::Remote(
                crate::daemon::service::RemoteControlError::Protocol(format!(
                    "operation {} did not reach a terminal snapshot before the client deadline",
                    admitted.operation_id
                )),
            ));
        }
        std::thread::sleep(CONTROL_PROGRESS_INTERVAL);
    }
}

fn remote_profile_mutation_receipt(
    queue: &RemoteTuiQueue,
    command: &UserCommand,
    operation: &OperationRecord,
) -> Option<Result<LocalProfileMutationReceipt, ProfileMutationFailure>> {
    if !matches!(
        operation.result,
        Some(
            OperationResult::ProfileMutationApplied
                | OperationResult::ProfileMutationAppliedAfterDeadline
        )
    ) {
        return None;
    }
    let display_name = match command {
        UserCommand::ImportProfile { profile_id } => queue
            .staged_cli_profiles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(profile_id),
        UserCommand::RenameProfile {
            new_display_name, ..
        } => Some(new_display_name.clone()),
        UserCommand::DeleteProfile { .. } => None,
        _ => return None,
    };
    Some(Ok(LocalProfileMutationReceipt::RemoteApplied {
        display_name,
    }))
}

fn project_remote_snapshot(
    session: &crate::daemon::service::RemoteControlSession,
    queue: &RemoteTuiQueue,
    mut snapshot: ControlSnapshot,
) -> ControlSnapshot {
    snapshot
        .challenges
        .retain(|_, challenge| &challenge.authorized_client == session.client_id());
    let mut pending = queue
        .pending_challenges
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    pending.retain(|challenge_id| snapshot.challenges.contains_key(challenge_id));
    snapshot
        .challenges
        .retain(|challenge_id, _| !pending.contains(challenge_id));
    snapshot
}

impl From<LocalControlSession> for ClientControlSession {
    fn from(session: LocalControlSession) -> Self {
        Self::standard(session)
    }
}

/// One short-lived Standard-mode authority. It starts no idle daemon; only a
/// tunnel-scoped protocol custodian may outlive this process.
pub struct LocalControlSession {
    // Drop the service while its Tokio runtime is still alive.
    service: Option<ControlService>,
    // The executor holds only a Weak edge, avoiding a service/supervisor cycle.
    _challenge_issuer: Arc<crate::vortix_core::control::CompleterHandle>,
    openvpn_credentials: Arc<Mutex<FsOpenVpnCredentialStore>>,
    hooks: Option<crate::hooks::HookRunner>,
    runtime: Option<tokio::runtime::Runtime>,
    subscription: RefCell<ControlSubscription>,
    topology_errors: BTreeMap<ProfileId, String>,
    owned_active_profiles: std::collections::BTreeSet<ProfileId>,
    unowned_active_profiles: Vec<String>,
    sessions: Arc<Mutex<Vec<ActiveSession>>>,
    scanner_lifecycle_revision: Arc<AtomicU64>,
    published_observations: RefCell<BTreeMap<ProfileId, (bool, Option<String>)>>,
    published_default_route:
        RefCell<crate::vortix_core::ports::route_table::DefaultRouteObservation>,
    published_tunnel_details: RefCell<BTreeMap<ProfileId, PublishedTunnelDetails>>,
    profile_mutations: Arc<StandardProfileMutationExecutor>,
    tui_admission: TuiAdmissionQueue,
    last_catalog_revision: Cell<u64>,
    reported_profile_operations: RefCell<std::collections::BTreeSet<OperationId>>,
    pending_scan: RefCell<Option<PendingScanner>>,
    last_scan_started: Cell<Instant>,
}

struct PendingScanner {
    catalog_revision: u64,
    lifecycle_revision: u64,
    observed_at_millis: u64,
    task: tokio::task::JoinHandle<crate::core::scanner::ScannerResult>,
}

/// Lightweight Standard-mode authority for profile catalog mutations. It
/// deliberately constructs no tunnel/policy executor, so unprivileged import,
/// rename, and delete do not acquire protocol ownership or root capabilities.
pub(crate) struct LocalProfileMutationSession {
    service: ControlService,
    runtime: tokio::runtime::Runtime,
    profile_mutations: Arc<StandardProfileMutationExecutor>,
}

impl LocalProfileMutationSession {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn start(
        config_dir: &Path,
        profiles: &[VpnProfile],
        prepared_imports: Vec<crate::vpn::PreparedProfileImport>,
    ) -> Result<Self, LocalControlError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| LocalControlError::Runtime(error.to_string()))?;
        let _runtime_guard = runtime.enter();
        let owner = config_owner(config_dir)?;
        let boot_id = crate::utils::boot_identity().ok_or_else(|| {
            LocalControlError::Persistence("OS boot identity is unavailable".into())
        })?;
        let state_store = Arc::new(FsControlStateStore::for_owner(
            config_dir.join("control"),
            owner.0,
            owner.1,
        ));
        let cache_bytes = state_store
            .endpoint_resolution_cache()
            .map_err(|error| LocalControlError::Persistence(error.to_string()))?;
        let mut endpoint_cache = EndpointResolutionCache::decode(cache_bytes.as_deref())
            .map_err(LocalControlError::Persistence)?;
        endpoint_cache
            .retain_profiles(&profiles.iter().map(|profile| profile.id.clone()).collect());
        let (topologies, _) = load_profile_topologies(profiles, &mut endpoint_cache);
        let prepared_imports = prepared_imports
            .into_iter()
            .map(|prepared| {
                let profile = prepared.topology_profile();
                let topology = topology_for_profile(&profile, &mut endpoint_cache).ok();
                PreparedImportState { prepared, topology }
            })
            .collect();
        persist_endpoint_cache_if_changed(&state_store, cache_bytes.as_deref(), &endpoint_cache)?;
        let profile_mutations = Arc::new(StandardProfileMutationExecutor::new(
            config_dir.join(crate::constants::PROFILES_DIR_NAME),
            profiles,
            prepared_imports,
            topologies.clone(),
        ));
        let service = ControlService::start_with_clock(
            ControlServiceConfig {
                known_profiles: profiles.iter().map(|profile| profile.id.clone()).collect(),
                profile_topologies: topologies,
                initial_last_connected_at: initial_last_connected_at(profiles),
                profile_mutations: Some(profile_mutations.clone()),
                authority_epoch: STANDARD_AUTHORITY_EPOCH,
                persistence: Some(ControlPersistenceConfig::new(boot_id, state_store)),
                freshness_poll_interval: CONTROL_PROGRESS_INTERVAL,
                ..ControlServiceConfig::default()
            },
            Arc::new(RealClock),
        );
        let scan = crate::core::scanner::gather_system_state(profiles);
        if !scan.tunnel_observation_complete {
            return Err(LocalControlError::Observation(
                "tunnel observation failed; active-profile safety is unverified".into(),
            ));
        }
        let sessions = scan.sessions;
        runtime.block_on(async {
            let observer = service.observer();
            let observed_at_millis = observer.now_millis();
            for profile in profiles {
                let session = sessions.iter().find(|session| session.name == profile.name);
                observer
                    .observe(Observation::Tunnel {
                        profile_id: profile.id.clone(),
                        active: session.is_some(),
                        interface_name: session.map(|session| session.interface.clone()),
                        observed_at_millis,
                        protection: None,
                    })
                    .await
                    .map_err(|error| LocalControlError::Observation(error.to_string()))?;
            }
            service
                .completer()
                .set_readiness(STANDARD_AUTHORITY_EPOCH, true, true)
                .await
                .map_err(|error| LocalControlError::Persistence(error.to_string()))
        })?;
        Ok(Self {
            service,
            runtime,
            profile_mutations,
        })
    }

    pub(crate) fn run(
        self,
        command: UserCommand,
        wait: Duration,
        idempotency_key: impl Into<String>,
    ) -> Result<ClientOperationOutcome, LocalControlError> {
        let result = self.runtime.block_on(async {
            let client = self.service.client();
            let admitted = client
                .submit(CommandRequest {
                    command,
                    idempotency_key: IdempotencyKey::new(idempotency_key),
                    deadline: client.deadline_after(wait),
                })
                .await
                .map_err(LocalControlError::Admission)?;
            let mut subscription = client.subscribe();
            let wait_for_terminal = async {
                loop {
                    let snapshot = subscription.snapshot();
                    if let Some(operation) = snapshot.operations.get(&admitted.operation_id) {
                        if operation.status.is_terminal() {
                            return Ok(ClientOperationOutcome {
                                profile_mutation: self
                                    .profile_mutations
                                    .take_result(&admitted.operation_id),
                                operation_id: admitted.operation_id,
                                status: operation.status,
                                result: operation.result,
                                snapshot,
                            });
                        }
                    }
                    subscription
                        .changed()
                        .await
                        .map_err(|_| LocalControlError::Stopped)?;
                }
            };
            tokio::time::timeout(wait + SHUTDOWN_GRACE, wait_for_terminal)
                .await
                .map_err(|_| LocalControlError::Stopped)?
        });
        drop(self.service);
        self.runtime.shutdown_timeout(SHUTDOWN_GRACE);
        result
    }
}

async fn invoke_challenge_responder<F>(
    responder: Arc<Mutex<F>>,
    challenge: crate::vortix_core::control::ChallengeRecord,
) -> Result<crate::vortix_core::control::Secret, LocalControlError>
where
    F: FnMut(
            &crate::vortix_core::control::ChallengeRecord,
        ) -> Result<crate::vortix_core::control::Secret, LocalControlError>
        + Send
        + 'static,
{
    tokio::task::spawn_blocking(move || {
        responder.lock().map_err(|_| {
            LocalControlError::Observation("challenge responder mutex poisoned".into())
        })?(&challenge)
    })
    .await
    .map_err(|error| {
        LocalControlError::Observation(format!("challenge responder did not complete: {error}"))
    })?
}

impl LocalControlSession {
    fn service(&self) -> &ControlService {
        self.service
            .as_ref()
            .expect("local control service is available until bounded shutdown")
    }

    fn runtime(&self) -> &tokio::runtime::Runtime {
        self.runtime
            .as_ref()
            .expect("local control runtime is available until bounded shutdown")
    }

    #[cfg(test)]
    pub(crate) fn start_profile_test(
        config_dir: &Path,
        profiles: Vec<VpnProfile>,
    ) -> Result<Self, LocalControlError> {
        Self::start_profile_test_with_persistence(config_dir, profiles, None)
    }

    #[cfg(test)]
    fn start_profile_test_with_persistence(
        config_dir: &Path,
        profiles: Vec<VpnProfile>,
        persistence: Option<ControlPersistenceConfig>,
    ) -> Result<Self, LocalControlError> {
        Self::start_profile_test_with_persistence_and_clock(
            config_dir,
            profiles,
            persistence,
            Arc::new(RealClock),
        )
    }

    #[cfg(test)]
    fn start_profile_test_with_persistence_and_clock(
        config_dir: &Path,
        profiles: Vec<VpnProfile>,
        persistence: Option<ControlPersistenceConfig>,
        clock: Arc<dyn crate::vortix_core::control::Clock>,
    ) -> Result<Self, LocalControlError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("vortix-local-control-test")
            .enable_all()
            .build()
            .map_err(|error| LocalControlError::Runtime(error.to_string()))?;
        let owner = config_owner(config_dir)?;
        let openvpn_credentials = Arc::new(Mutex::new(
            FsOpenVpnCredentialStore::for_standard_owner(config_dir, owner.0, owner.1),
        ));
        let profiles = Arc::new(profiles);
        let mut cache = EndpointResolutionCache::default();
        let (topologies, topology_errors) = load_profile_topologies(&profiles, &mut cache);
        let profile_mutations = Arc::new(StandardProfileMutationExecutor::new(
            config_dir.join(crate::constants::PROFILES_DIR_NAME),
            &profiles,
            Vec::new(),
            topologies.clone(),
        ));
        let service = {
            let _runtime_guard = runtime.enter();
            ControlService::start_with_clock(
                ControlServiceConfig {
                    known_profiles: profiles.iter().map(|profile| profile.id.clone()).collect(),
                    profile_topologies: topologies,
                    initial_last_connected_at: initial_last_connected_at(&profiles),
                    profile_mutations: Some(profile_mutations.clone()),
                    authority_epoch: STANDARD_AUTHORITY_EPOCH,
                    freshness_poll_interval: CONTROL_PROGRESS_INTERVAL,
                    persistence,
                    ..ControlServiceConfig::default()
                },
                clock,
            )
        };
        let challenge_issuer = Arc::new(service.completer());
        runtime
            .block_on(
                service
                    .completer()
                    .set_readiness(STANDARD_AUTHORITY_EPOCH, true, true),
            )
            .map_err(|error| LocalControlError::Persistence(error.to_string()))?;
        let mut subscription = service.client().subscribe();
        runtime.block_on(async {
            while !subscription.snapshot().readiness.reconciliation_complete {
                subscription.changed().await.map_err(|error| {
                    LocalControlError::Observation(format!(
                        "test control readiness was not published: {error}"
                    ))
                })?;
            }
            Ok::<(), LocalControlError>(())
        })?;
        let tui_admission =
            start_tui_admission_queue(&runtime, service.client(), Arc::clone(&profile_mutations));
        Ok(Self {
            service: Some(service),
            _challenge_issuer: challenge_issuer,
            openvpn_credentials,
            hooks: None,
            runtime: Some(runtime),
            subscription: RefCell::new(subscription),
            topology_errors,
            owned_active_profiles: std::collections::BTreeSet::new(),
            unowned_active_profiles: Vec::new(),
            sessions: Arc::new(Mutex::new(Vec::new())),
            scanner_lifecycle_revision: Arc::new(AtomicU64::new(0)),
            published_observations: RefCell::new(BTreeMap::new()),
            published_default_route: RefCell::new(
                crate::vortix_core::ports::route_table::DefaultRouteObservation::ProbeFailed,
            ),
            published_tunnel_details: RefCell::new(BTreeMap::new()),
            profile_mutations,
            tui_admission,
            last_catalog_revision: Cell::new(0),
            reported_profile_operations: RefCell::new(std::collections::BTreeSet::new()),
            pending_scan: RefCell::new(None),
            last_scan_started: Cell::new(Instant::now()),
        })
    }

    #[allow(clippy::too_many_lines)]
    pub fn start(
        config: &crate::config::AppConfig,
        config_dir: &Path,
        profiles: Vec<VpnProfile>,
    ) -> Result<Self, LocalControlError> {
        Self::start_with_settlement(config, config_dir, profiles, StartupSettlement::Wait)
    }

    /// Start the interactive authority without withholding the session while
    /// recovered work settles. Admission and observation are ready at this
    /// boundary, so the TUI can display and cancel exact in-flight work.
    #[allow(clippy::too_many_lines)]
    pub fn start_tui(
        config: &crate::config::AppConfig,
        config_dir: &Path,
        profiles: Vec<VpnProfile>,
    ) -> Result<Self, LocalControlError> {
        Self::start_with_settlement(
            config,
            config_dir,
            profiles,
            StartupSettlement::ContinueInBackground,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn start_with_settlement(
        config: &crate::config::AppConfig,
        config_dir: &Path,
        profiles: Vec<VpnProfile>,
        startup_settlement: StartupSettlement,
    ) -> Result<Self, LocalControlError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("vortix-local-control")
            .enable_all()
            .build()
            .map_err(|error| LocalControlError::Runtime(error.to_string()))?;
        let _runtime_guard = runtime.enter();
        let profiles = Arc::new(profiles);
        let owner = config_owner(config_dir)?;
        let openvpn_credentials = Arc::new(Mutex::new(
            FsOpenVpnCredentialStore::for_standard_owner(config_dir, owner.0, owner.1),
        ));
        let boot_id = crate::utils::boot_identity().ok_or_else(|| {
            LocalControlError::Persistence("OS boot identity is unavailable".into())
        })?;
        let state_store = Arc::new(FsControlStateStore::for_owner(
            config_dir.join("control"),
            owner.0,
            owner.1,
        ));
        let persisted_kill_switch = crate::core::killswitch::load_state_checked().map_err(
            |error| {
                LocalControlError::Persistence(format!(
                    "kill-switch state is unavailable ({error}); run `sudo vortix release-killswitch` to restore networking safely"
                ))
            },
        )?;
        let mut recovered = state_store
            .load(&boot_id)
            .map_err(|error| LocalControlError::Persistence(error.to_string()))?;
        honor_emergency_release_fence(
            persisted_kill_switch
                .as_ref()
                .is_some_and(|state| state.emergency_release_fence),
            state_store.as_ref(),
            &boot_id,
            &mut recovered,
        )?;
        let ownership = Arc::new(
            StandardTunnelOwnershipStore::production(owner.0)
                .map_err(|error| LocalControlError::Ownership(error.to_string()))?,
        );
        let initial_scan = crate::core::scanner::gather_system_state(&profiles);
        if !initial_scan.tunnel_observation_complete {
            return Err(LocalControlError::Observation(
                "tunnel observation failed; tunnel absence is unverified".into(),
            ));
        }
        let initial_sessions = initial_scan.sessions.clone();
        let sessions = Arc::new(Mutex::new(initial_sessions.clone()));
        let scanner_lifecycle_revision = Arc::new(AtomicU64::new(0));

        let cache_bytes = state_store
            .endpoint_resolution_cache()
            .map_err(|error| LocalControlError::Persistence(error.to_string()))?;
        let mut endpoint_cache = EndpointResolutionCache::decode(cache_bytes.as_deref())
            .map_err(LocalControlError::Persistence)?;
        endpoint_cache
            .retain_profiles(&profiles.iter().map(|profile| profile.id.clone()).collect());
        let (topologies, topology_errors) = load_profile_topologies(&profiles, &mut endpoint_cache);
        persist_endpoint_cache_if_changed(&state_store, cache_bytes.as_deref(), &endpoint_cache)?;
        let profile_mutations = Arc::new(StandardProfileMutationExecutor::new(
            config_dir.join(crate::constants::PROFILES_DIR_NAME),
            &profiles,
            Vec::new(),
            topologies.clone(),
        ));
        let core_profiles = Arc::new(
            profiles
                .iter()
                .map(|profile| {
                    let resolved = topologies
                        .get(&profile.id)
                        .map(|topology| topology.resolved_endpoints.clone())
                        .unwrap_or_default();
                    let profile = crate::tunnel::profile_view(profile)
                        .with_endpoint_resolutions(resolved)
                        .require_managed_endpoint_resolution();
                    (profile.id.clone(), profile)
                })
                .collect::<BTreeMap<_, _>>(),
        );

        let executor_catalog = Arc::clone(&profile_mutations);
        let scanner_catalog = Arc::clone(&profile_mutations);
        let executor_sessions = Arc::clone(&sessions);
        let session_resolver = move |profile_id: &ProfileId| {
            let profile = scanner_catalog.profile_snapshot(profile_id)?;
            current_session(&profile, &executor_sessions)
        };
        let executor_credential_store = Arc::clone(&openvpn_credentials);
        let lifecycle_catalog = Arc::clone(&profile_mutations);
        let lifecycle_sessions = Arc::clone(&sessions);
        let lifecycle_revision = Arc::clone(&scanner_lifecycle_revision);
        let executor = Arc::new(
            CanonicalTunnelExecutor::new_standard(
                CanonicalTunnelSettings {
                    config_dir: config_dir.to_path_buf(),
                    openvpn_verbosity: config.openvpn_verbosity.clone(),
                    connect_timeout_secs: config.connect_timeout,
                    wireguard_handshake_timeout_secs: config.wireguard_handshake_timeout_secs,
                    wireguard_health_targets: config.ping_targets.clone(),
                },
                move |profile_id| executor_catalog.core_profile(profile_id),
                Arc::clone(&ownership),
                session_resolver,
            )
            .with_owned_lifecycle_observer(move |profile_id, active| {
                let disconnected_name = (!active)
                    .then(|| lifecycle_catalog.profile_snapshot(profile_id))
                    .flatten()
                    .map(|profile| profile.name);
                let mut sessions = lifecycle_sessions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                lifecycle_revision.fetch_add(1, Ordering::SeqCst);
                if let Some(name) = disconnected_name {
                    sessions.retain(|session| session.name != name);
                }
            })
            .with_remembered_openvpn_credentials(
                move |profile_id, legacy_display_name| {
                    let store = executor_credential_store.lock().map_err(|_| {
                        "remembered OpenVPN credential authority is unavailable".to_string()
                    })?;
                    // A rejected or unavailable remembered record is never consumed
                    // by tunnel execution. Fall back to the admitted memory-only
                    // challenge; the client-side load operation owns user-facing
                    // credential diagnostics.
                    Ok(store
                        .load(profile_id, legacy_display_name)
                        .ok()
                        .flatten()
                        .map(|credentials| {
                            crate::vortix_core::control::Secret::openvpn_credentials(
                                credentials.username(),
                                credentials.password(),
                                None,
                            )
                        }))
                },
            ),
        );

        let policy_profiles = Arc::clone(&profiles);
        let policy_catalog = Arc::clone(&profile_mutations);
        let policy_sessions = Arc::clone(&sessions);
        let policy_executor = Arc::clone(&executor);
        let external_catalog = Arc::clone(&profile_mutations);
        let external_ownership = Arc::clone(&ownership);
        let external_sessions = Arc::clone(&sessions);
        let external_executor = Arc::clone(&executor);
        let external_active_profiles = external_session_profiles(
            &initial_sessions,
            &policy_profiles,
            &core_profiles,
            &external_ownership,
            None,
        );
        let policy = Arc::new(CanonicalPolicyExecutor::new(
            config_dir.to_path_buf(),
            move |profile_id| {
                let profile = policy_catalog.profile_snapshot(profile_id)?;
                current_owned_session(&profile, &policy_sessions, &policy_executor)
            },
            move || {
                let sessions = external_sessions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let (profiles, core_profiles) = external_catalog.profiles_and_core_snapshot();
                external_session_profiles(
                    &sessions,
                    &profiles,
                    &core_profiles,
                    &external_ownership,
                    Some(&external_executor),
                )
                .len()
            },
        ));
        let supervisor = Arc::new(crate::vortix_core::control::supervisor::Supervisor::new(
            STANDARD_AUTHORITY_EPOCH,
            executor.clone(),
            policy,
            8,
            64,
        ));
        let empty_operations = BTreeMap::new();
        let operations = recovered
            .as_ref()
            .map_or(&empty_operations, |state| &state.state.operations);
        let owned_active_profiles = restore_owned_sessions(
            &profiles,
            &core_profiles,
            &ownership,
            &executor,
            &supervisor,
            operations,
            &initial_sessions,
        )?;
        let unowned_active_profiles = initial_sessions
            .iter()
            .filter_map(|session| {
                let profile = profiles
                    .iter()
                    .find(|profile| profile.name == session.name)?;
                (!owned_active_profiles.contains(&profile.id)).then(|| profile.name.clone())
            })
            .chain(external_active_profiles)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        let initial_kill_switch_mode =
            persisted_kill_switch.map_or(crate::state::KillSwitchMode::Off, |state| state.mode);
        let service = ControlService::start_supervised(
            ControlServiceConfig {
                known_profiles: profiles.iter().map(|profile| profile.id.clone()).collect(),
                profile_topologies: topologies,
                initial_last_connected_at: initial_last_connected_at(&profiles),
                profile_mutations: Some(profile_mutations.clone()),
                authority_epoch: STANDARD_AUTHORITY_EPOCH,
                initial_kill_switch_mode,
                freshness_poll_interval: CONTROL_PROGRESS_INTERVAL,
                persistence: Some(ControlPersistenceConfig::new(boot_id, state_store)),
                ..ControlServiceConfig::default()
            },
            Arc::new(RealClock),
            ExecutionSelection::CanonicalAuthority,
            supervisor,
        );
        let challenge_issuer = Arc::new(service.completer());
        executor
            .install_challenge_issuer(&challenge_issuer)
            .map_err(LocalControlError::Runtime)?;
        let hooks = crate::hooks::start_standard_control_hooks(config_dir, &service);
        let subscription = service.client().subscribe();
        let tui_admission =
            start_tui_admission_queue(&runtime, service.client(), Arc::clone(&profile_mutations));
        let session = Self {
            service: Some(service),
            _challenge_issuer: challenge_issuer,
            openvpn_credentials,
            hooks,
            runtime: Some(runtime),
            subscription: RefCell::new(subscription),
            topology_errors,
            owned_active_profiles,
            unowned_active_profiles,
            sessions,
            scanner_lifecycle_revision,
            published_observations: RefCell::new(BTreeMap::new()),
            published_default_route: RefCell::new(
                crate::vortix_core::ports::route_table::DefaultRouteObservation::ProbeFailed,
            ),
            published_tunnel_details: RefCell::new(BTreeMap::new()),
            profile_mutations,
            tui_admission,
            last_catalog_revision: Cell::new(0),
            reported_profile_operations: RefCell::new(std::collections::BTreeSet::new()),
            pending_scan: RefCell::new(None),
            last_scan_started: Cell::new(Instant::now()),
        };
        let startup_generation = session.current_snapshot().generation;
        let initial_observed_at_millis = session.service().observer().now_millis();
        session.runtime().block_on(async {
            session
                .publish_observations_from(initial_scan, initial_observed_at_millis)
                .await?;
            session
                .service()
                .completer()
                .set_readiness(STANDARD_AUTHORITY_EPOCH, true, true)
                .await
                .map_err(|error| LocalControlError::Persistence(error.to_string()))
        })?;
        if startup_settlement == StartupSettlement::Wait {
            session
                .wait_for_startup_settlement(startup_generation, CLI_STARTUP_SETTLEMENT_TIMEOUT)?;
        }
        Ok(session)
    }

    pub fn run(
        self,
        command: UserCommand,
        wait: Duration,
        idempotency_key: impl Into<String>,
    ) -> Result<ClientOperationOutcome, LocalControlError> {
        self.run_with_challenges(command, wait, idempotency_key, |_| {
            Err(LocalControlError::ChallengeNonInteractive {
                profile: "unknown".into(),
            })
        })
    }

    /// Admit one typed command without consuming the Standard-mode authority.
    /// The TUI calls this synchronously only for bounded in-memory admission;
    /// protocol and policy effects remain on supervised workers.
    pub fn submit(
        &self,
        command: UserCommand,
        wait: Duration,
        idempotency_key: impl Into<String>,
    ) -> Result<OperationId, LocalControlError> {
        self.validate(&command)?;
        self.runtime().block_on(async {
            let client = self.service().client();
            client
                .submit(CommandRequest {
                    command,
                    idempotency_key: IdempotencyKey::new(idempotency_key),
                    deadline: client.deadline_after(wait),
                })
                .await
                .map(|admitted| admitted.operation_id)
                .map_err(LocalControlError::Admission)
        })
    }

    /// Queue one TUI admission without waiting for durable state I/O. A
    /// successful return means only that bounded local capacity was acquired;
    /// the durable admission result is delivered by
    /// [`Self::take_tui_admission_results`].
    pub(crate) fn enqueue_tui_command(
        &self,
        command: UserCommand,
        wait: Duration,
        idempotency_key: impl Into<String>,
    ) -> Result<(), LocalControlError> {
        self.validate(&command)?;
        let permit = Arc::clone(&self.tui_admission.permits)
            .try_acquire_owned()
            .map_err(|_| LocalControlError::Busy)?;
        let client = self.service().client();
        let request = CommandRequest {
            command: command.clone(),
            idempotency_key: IdempotencyKey::new(idempotency_key),
            deadline: client.deadline_after(wait),
        };
        self.tui_admission
            .sender
            .try_send(TuiAdmissionJob {
                request,
                command,
                import: None,
                permit,
            })
            .map_err(|error| match error {
                tokio::sync::mpsc::error::TrySendError::Full(_) => LocalControlError::Busy,
                tokio::sync::mpsc::error::TrySendError::Closed(_) => LocalControlError::Stopped,
            })
    }

    /// Prepare and queue a TUI import. Prepared private material is discarded
    /// if the asynchronous durable admission is later refused.
    pub(crate) fn enqueue_tui_profile_import(
        &self,
        path: &Path,
        wait: Duration,
        idempotency_key: impl Into<String>,
    ) -> Result<String, LocalControlError> {
        let permit = Arc::clone(&self.tui_admission.permits)
            .try_acquire_owned()
            .map_err(|_| LocalControlError::Busy)?;
        let prepared =
            crate::vpn::prepare_profile_import(path, &self.profile_mutations.profiles_dir)
                .map_err(|reason| LocalControlError::Profile {
                    profile: path.display().to_string(),
                    reason,
                })?;
        let display_name = prepared.profile().name.clone();
        let mut cache = EndpointResolutionCache::default();
        let topology = topology_for_profile(&prepared.topology_profile(), &mut cache).ok();
        let profile_id = self.profile_mutations.prepare_import(prepared, topology);
        let command = UserCommand::ImportProfile {
            profile_id: profile_id.clone(),
        };
        let client = self.service().client();
        let idempotency_key = idempotency_key.into();
        let request = CommandRequest {
            command: command.clone(),
            idempotency_key: IdempotencyKey::new(idempotency_key.clone()),
            deadline: client.deadline_after(wait),
        };
        let queued = self.tui_admission.sender.try_send(TuiAdmissionJob {
            request,
            command,
            import: Some((profile_id.clone(), display_name.clone(), idempotency_key)),
            permit,
        });
        if let Err(error) = queued {
            self.profile_mutations.discard_prepared_import(&profile_id);
            return Err(match error {
                tokio::sync::mpsc::error::TrySendError::Full(_) => LocalControlError::Busy,
                tokio::sync::mpsc::error::TrySendError::Closed(_) => LocalControlError::Stopped,
            });
        }
        Ok(display_name)
    }

    pub(crate) fn take_tui_admission_results(&self) -> Vec<LocalTuiAdmissionResult> {
        let mut receiver = self.tui_admission.results.borrow_mut();
        std::iter::from_fn(|| receiver.try_recv().ok()).collect()
    }

    #[cfg(test)]
    fn prepared_import_count(&self) -> usize {
        self.profile_mutations.prepared_import_count()
    }

    /// Mark and return the latest publication when attaching a client.
    pub fn current_snapshot(&self) -> ControlSnapshot {
        let snapshot = self.subscription.borrow_mut().current();
        self.discard_terminal_prepared_imports(&snapshot);
        snapshot
    }

    /// Advance the local actor and its single bounded scanner. A slow scan
    /// never blocks the caller and snapshot delivery remains a separate step.
    pub fn progress(&self) -> Result<(), LocalControlError> {
        let completed = {
            let pending = self.pending_scan.borrow();
            pending.as_ref().is_some_and(|scan| scan.task.is_finished())
        }
        .then(|| self.pending_scan.borrow_mut().take())
        .flatten();
        if let Some(completed) = completed {
            let scan = self.runtime().block_on(completed.task).map_err(|error| {
                LocalControlError::Observation(format!("scanner worker did not complete: {error}"))
            })?;
            if completed.catalog_revision == self.profile_mutations.catalog_revision() {
                self.runtime()
                    .block_on(self.publish_observations_from_revision(
                        scan,
                        completed.observed_at_millis,
                        Some(completed.lifecycle_revision),
                    ))?;
            }
        }

        let now = Instant::now();
        if self.pending_scan.borrow().is_none()
            && scanner_refresh_due(self.last_scan_started.get(), now)
        {
            let profiles = self.profile_mutations.profiles_snapshot();
            let observed_at_millis = self.service().observer().now_millis();
            let scan = self
                .runtime()
                .handle()
                .spawn_blocking(move || crate::core::scanner::gather_system_state(&profiles));
            self.pending_scan.replace(Some(PendingScanner {
                catalog_revision: self.profile_mutations.catalog_revision(),
                lifecycle_revision: self.scanner_lifecycle_revision.load(Ordering::SeqCst),
                observed_at_millis,
                task: scan,
            }));
            self.last_scan_started.set(now);
        }
        self.runtime().block_on(tokio::task::yield_now());
        Ok(())
    }

    /// Let durable work recovered by this short-lived authority settle before
    /// a one-shot CLI command starts its own deadline. Interactive TUI startup
    /// deliberately skips this wait and renders the recovered state instead.
    fn wait_for_startup_settlement(
        &self,
        previous_generation: u64,
        limit: Duration,
    ) -> Result<(), LocalControlError> {
        let deadline = Instant::now()
            .checked_add(limit)
            .ok_or_else(|| LocalControlError::Observation("startup deadline overflowed".into()))?;
        loop {
            let snapshot = self.current_snapshot();
            if snapshot.generation > previous_generation
                && snapshot
                    .operations
                    .values()
                    .all(|operation| operation.status.is_terminal())
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(LocalControlError::Observation(
                    "recovered VPN work did not settle before a new command could start".into(),
                ));
            }
            self.progress()?;
            std::thread::sleep(CONTROL_PROGRESS_INTERVAL);
        }
    }

    /// Return a changed immutable publication without cloning on idle turns.
    pub fn take_changed_snapshot(&self) -> Result<Option<ControlSnapshot>, LocalControlError> {
        let snapshot = self
            .subscription
            .borrow_mut()
            .take_changed()
            .map_err(|_| LocalControlError::Stopped)?;
        if let Some(snapshot) = &snapshot {
            self.discard_terminal_prepared_imports(snapshot);
        }
        Ok(snapshot)
    }

    fn discard_terminal_prepared_imports(&self, snapshot: &ControlSnapshot) {
        for operation in snapshot.operations.values() {
            let OperationIntent::ProfileMutation { profile_id } = &operation.intent else {
                continue;
            };
            if operation.status.is_terminal() {
                // The executor removes successful imports before committing.
                // This idempotent cleanup covers all paths that become
                // terminal before `ProfileMutationExecutor::execute`, such as
                // queue expiry or dispatch failure.
                self.profile_mutations.discard_prepared_import(profile_id);
            }
        }
    }

    pub(crate) fn take_catalog_update(
        &self,
        snapshot: &ControlSnapshot,
    ) -> Option<LocalCatalogUpdate> {
        let mut outcomes = Vec::new();
        let mut reported = self.reported_profile_operations.borrow_mut();
        reported.retain(|operation_id| snapshot.operations.contains_key(operation_id));
        for (operation_id, operation) in &snapshot.operations {
            if !operation.status.is_terminal()
                || !matches!(operation.intent, OperationIntent::ProfileMutation { .. })
                || !reported.insert(operation_id.clone())
            {
                continue;
            }
            outcomes.push(
                if let Some(result) = self.profile_mutations.take_result(operation_id) {
                    match result {
                        Ok(receipt) => LocalCatalogOutcome::Applied {
                            operation_id: operation_id.clone(),
                            receipt,
                        },
                        Err(failure) => LocalCatalogOutcome::Failed {
                            operation_id: operation_id.clone(),
                            failure,
                        },
                    }
                } else {
                    LocalCatalogOutcome::Terminal {
                        operation_id: operation_id.clone(),
                        status: operation.status,
                        result: operation.result,
                    }
                },
            );
        }
        let revision = self.profile_mutations.catalog_revision();
        if revision == self.last_catalog_revision.get() && outcomes.is_empty() {
            return None;
        }
        self.last_catalog_revision.set(revision);
        Some(LocalCatalogUpdate {
            revision,
            profiles: Some(self.profile_mutations.profiles_snapshot()),
            outcomes,
        })
    }

    pub fn respond_challenge(
        &self,
        challenge_id: crate::vortix_core::control::ChallengeId,
        answer: Vec<u8>,
    ) -> Result<(), LocalControlError> {
        self.runtime()
            .block_on(self.service().client().respond_challenge(
                challenge_id,
                crate::vortix_core::control::Secret::new(answer),
            ))
            .map_err(map_challenge_response_error)
    }

    /// Resolve reusable credentials from the one owner-bound store retained
    /// by this Standard-mode session.
    pub fn load_openvpn_credentials(
        &self,
        profile_id: &ProfileId,
        legacy_display_name: &str,
    ) -> Result<Option<RememberedOpenVpnCredentials>, LocalControlError> {
        self.openvpn_credentials
            .lock()
            .map_err(|_| LocalControlError::CredentialAuthorityUnavailable)?
            .load(profile_id, legacy_display_name)
            .map_err(LocalControlError::CredentialLoad)
    }

    /// Replace the reusable username/password for one stable profile. The
    /// legacy name is accepted as part of the transport-neutral identity
    /// contract; new writes are always stable-ID keyed.
    pub fn remember_openvpn_credentials(
        &self,
        profile_id: &ProfileId,
        username: &str,
        password: &str,
    ) -> Result<(), LocalControlError> {
        let credentials = RememberedOpenVpnCredentials::new(username, password)
            .map_err(LocalControlError::CredentialRemember)?;
        self.openvpn_credentials
            .lock()
            .map_err(|_| LocalControlError::CredentialAuthorityUnavailable)?
            .replace(profile_id, &credentials)
            .map_err(|error| match error {
                CredentialStoreError::DurabilityUncertain => {
                    LocalControlError::CredentialDurabilityUncertain
                }
                other => LocalControlError::CredentialRemember(other),
            })
    }

    /// Clear stable and unambiguous legacy credentials for one profile.
    pub fn clear_openvpn_credentials(
        &self,
        profile_id: &ProfileId,
        legacy_display_name: &str,
    ) -> Result<CredentialClearOutcome, LocalControlError> {
        self.openvpn_credentials
            .lock()
            .map_err(|_| LocalControlError::CredentialAuthorityUnavailable)?
            .clear(profile_id, legacy_display_name)
            .map_err(|error| match error {
                CredentialStoreError::DurabilityUncertain => {
                    LocalControlError::CredentialDurabilityUncertain
                }
                other => LocalControlError::CredentialClear(other),
            })
    }

    pub fn cancel_challenge(
        &self,
        challenge_id: crate::vortix_core::control::ChallengeId,
    ) -> Result<(), LocalControlError> {
        self.runtime()
            .block_on(self.service().client().cancel_challenge(challenge_id))
            .map_err(map_challenge_response_error)
    }

    pub(crate) fn run_with_challenges<F>(
        mut self,
        command: UserCommand,
        wait: Duration,
        idempotency_key: impl Into<String>,
        answer_challenge: F,
    ) -> Result<ClientOperationOutcome, LocalControlError>
    where
        F: FnMut(
                &crate::vortix_core::control::ChallengeRecord,
            ) -> Result<crate::vortix_core::control::Secret, LocalControlError>
            + Send
            + 'static,
    {
        self.validate(&command)?;
        let client = self.service().client();
        let admitted = self
            .runtime()
            .block_on(client.submit(CommandRequest {
                command,
                idempotency_key: IdempotencyKey::new(idempotency_key),
                deadline: client.deadline_after(wait),
            }))
            .map_err(LocalControlError::Admission)?;
        let challenge_responder = Arc::new(Mutex::new(answer_challenge));
        let wall_deadline = Instant::now()
            .checked_add(wait + SHUTDOWN_GRACE)
            .ok_or_else(|| LocalControlError::Observation("command deadline overflowed".into()))?;
        // Drive one-shot commands through the same scanner, observation cache,
        // and subscription path used by the TUI. Presentation and blocking
        // policy differ between clients; canonical progress must not.
        self.last_scan_started.set(
            Instant::now()
                .checked_sub(SCANNER_REFRESH_CEILING)
                .unwrap_or_else(Instant::now),
        );
        let mut handled_challenges = std::collections::BTreeSet::new();
        let mut challenge_input_error = None;
        let result = loop {
            self.progress()?;
            let snapshot = self.current_snapshot();
            let pending_challenges = snapshot
                .challenges
                .values()
                .filter(|challenge| {
                    challenge.operation_id == admitted.operation_id
                        && challenge.authorized_client == *client.client_id()
                        && !handled_challenges.contains(&challenge.id)
                })
                .cloned()
                .collect::<Vec<_>>();
            let mut handled_challenge_this_tick = false;
            for challenge in &pending_challenges {
                handled_challenges.insert(challenge.id);
                handled_challenge_this_tick = true;
                let answer = self.runtime().block_on(invoke_challenge_responder(
                    Arc::clone(&challenge_responder),
                    challenge.clone(),
                ));
                match answer {
                    Ok(answer) => self.respond_challenge(challenge.id, answer.into_vec())?,
                    Err(error) => {
                        let _ = self.cancel_challenge(challenge.id);
                        if challenge_input_error.is_none() {
                            challenge_input_error = Some(error);
                        }
                    }
                }
            }
            if handled_challenge_this_tick {
                continue;
            }
            if let Some(operation) = snapshot.operations.get(&admitted.operation_id) {
                if operation.status.is_terminal() {
                    if let Some(error) = challenge_input_error {
                        break Err(error);
                    }
                    break Ok(ClientOperationOutcome {
                        profile_mutation: None,
                        operation_id: admitted.operation_id,
                        status: operation.status,
                        result: operation.result,
                        snapshot,
                    });
                }
            }
            if Instant::now() >= wall_deadline {
                break Err(LocalControlError::Stopped);
            }
            std::thread::sleep(CONTROL_PROGRESS_INTERVAL);
        };
        if let Some(hooks) = self.hooks.take() {
            self.runtime()
                .block_on(hooks.shutdown_bounded(HOOK_SHUTDOWN_GRACE));
        }
        // Tokio waits indefinitely for started `spawn_blocking` work when a
        // runtime is dropped. A scanner refresh may still be in flight after
        // the operation becomes terminal, so stop the service first and give
        // the runtime a finite drain window instead of extending CLI shutdown
        // to the duration of a slow platform probe.
        if let Some(service) = self.service.take() {
            let _ = service.shutdown_bounded(SUPERVISED_SHUTDOWN_GRACE);
        }
        self.runtime
            .take()
            .expect("local control runtime is present during shutdown")
            .shutdown_timeout(SHUTDOWN_GRACE);
        result
    }

    /// Reject a command that cannot be safely represented by this recovered
    /// local authority before prompting for or writing transient credentials.
    ///
    /// # Errors
    ///
    /// Returns the profile/recovery fault that makes the target unsafe.
    pub fn validate(&self, command: &UserCommand) -> Result<(), LocalControlError> {
        self.validate_command_target(command)?;
        if matches!(command, UserCommand::Reconnect { profile_id: None }) {
            if let Some((profile_id, reason)) = self
                .topology_errors
                .iter()
                .find(|(profile_id, _)| self.owned_active_profiles.contains(*profile_id))
            {
                let profiles = self.profile_mutations.profiles_snapshot();
                let profile = profiles
                    .iter()
                    .find(|profile| &profile.id == profile_id)
                    .map_or_else(|| profile_id.to_string(), |profile| profile.name.clone());
                return Err(LocalControlError::Profile {
                    profile,
                    reason: reason.clone(),
                });
            }
        }
        if matches!(command, UserCommand::Reconnect { profile_id: None })
            && !self.unowned_active_profiles.is_empty()
        {
            return Err(LocalControlError::Recovery {
                profile: self.unowned_active_profiles.join(", "),
                reason: "active tunnel is not owned by the canonical Standard-mode authority"
                    .into(),
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn is_canonically_owned_active(&self, profile_id: &ProfileId) -> bool {
        canonical_owned_active(
            &self.owned_active_profiles,
            &self.topology_errors,
            profile_id,
        )
    }

    fn validate_command_target(&self, command: &UserCommand) -> Result<(), LocalControlError> {
        validate_command_target(
            &self.profile_mutations.profiles_snapshot(),
            &self.topology_errors,
            &self.unowned_active_profiles,
            command,
        )
    }

    async fn publish_observations_from(
        &self,
        scan: crate::core::scanner::ScannerResult,
        observed_at_millis: u64,
    ) -> Result<(), LocalControlError> {
        self.publish_observations_from_revision(scan, observed_at_millis, None)
            .await
    }

    async fn publish_observations_from_revision(
        &self,
        scan: crate::core::scanner::ScannerResult,
        observed_at_millis: u64,
        expected_lifecycle_revision: Option<u64>,
    ) -> Result<(), LocalControlError> {
        if !scan.tunnel_observation_complete {
            return Err(LocalControlError::Observation(
                "tunnel observation failed; preserving the last verified tunnel state".into(),
            ));
        }
        let sessions = scan.sessions;
        let profiles = self.profile_mutations.profiles_snapshot();
        if !self.accept_scanner_sessions(&sessions, expected_lifecycle_revision) {
            return Ok(());
        }
        let observer = self.service().observer();
        let default_route = scan.default_route;
        let default_route_changed = !matches!(
            default_route,
            crate::vortix_core::ports::route_table::DefaultRouteObservation::ProbeFailed
        ) && *self.published_default_route.borrow() != default_route;
        let mut observations = Vec::new();
        if default_route_changed {
            let interface_name = match &default_route {
                crate::vortix_core::ports::route_table::DefaultRouteObservation::Interface(
                    interface_name,
                ) => Some(interface_name.clone()),
                crate::vortix_core::ports::route_table::DefaultRouteObservation::NoDefaultRoute => {
                    None
                }
                crate::vortix_core::ports::route_table::DefaultRouteObservation::ProbeFailed => {
                    unreachable!("probe failures are filtered before publication")
                }
            };
            observations.push(Observation::DefaultRoute {
                interface_name,
                observed_at_millis,
            });
        }
        let mut observed_detail_profiles = std::collections::BTreeSet::new();
        let mut detail_updates = Vec::new();
        for session in &sessions {
            let Some(profile) = profiles.iter().find(|profile| profile.name == session.name) else {
                continue;
            };
            observed_detail_profiles.insert(profile.id.clone());
            let published = PublishedTunnelDetails::from(session);
            let changed =
                self.published_tunnel_details.borrow().get(&profile.id) != Some(&published);
            if changed {
                observations.push(Observation::TunnelDetails {
                    profile_id: profile.id.clone(),
                    details: Box::new(published.details.clone()),
                    started_at: published.started_at,
                    observed_at_millis,
                });
                detail_updates.push((profile.id.clone(), published));
            }
        }
        let changed =
            observation_changes(&profiles, &sessions, &self.published_observations.borrow());
        observations.extend(
            changed
                .iter()
                .map(|(profile_id, state)| Observation::Tunnel {
                    profile_id: profile_id.clone(),
                    active: state.0,
                    interface_name: state.1.clone(),
                    observed_at_millis,
                    protection: None,
                }),
        );
        if !observations.is_empty() {
            observer
                .observe_batch(observations)
                .await
                .map_err(|error| LocalControlError::Observation(error.to_string()))?;
        }
        if default_route_changed {
            self.published_default_route.replace(default_route);
        }
        {
            let mut published = self.published_tunnel_details.borrow_mut();
            for (profile_id, details) in detail_updates {
                published.insert(profile_id, details);
            }
            published.retain(|profile_id, _| observed_detail_profiles.contains(profile_id));
        }
        for (profile_id, state) in changed {
            self.published_observations
                .borrow_mut()
                .insert(profile_id, state);
        }
        let profile_ids = profiles
            .iter()
            .map(|profile| &profile.id)
            .collect::<std::collections::BTreeSet<_>>();
        self.published_observations
            .borrow_mut()
            .retain(|profile_id, _| profile_ids.contains(profile_id));
        Ok(())
    }

    fn accept_scanner_sessions(
        &self,
        sessions: &[ActiveSession],
        expected_lifecycle_revision: Option<u64>,
    ) -> bool {
        let mut current = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if expected_lifecycle_revision.is_some_and(|expected| {
            self.scanner_lifecycle_revision.load(Ordering::SeqCst) != expected
        }) {
            return false;
        }
        current.clear();
        current.extend_from_slice(sessions);
        true
    }
}

impl Drop for LocalControlSession {
    fn drop(&mut self) {
        if let (Some(hooks), Some(runtime)) = (self.hooks.take(), self.runtime.as_ref()) {
            runtime.block_on(hooks.shutdown_bounded(HOOK_SHUTDOWN_GRACE));
        }
        // Service shutdown may need the executor. Keep the runtime alive for
        // that bounded teardown, then detach any stalled blocking probe.
        self.service.take();
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(SHUTDOWN_GRACE);
        }
    }
}

fn scanner_refresh_due(last_started: Instant, now: Instant) -> bool {
    now.saturating_duration_since(last_started) >= SCANNER_REFRESH_CEILING
}

fn canonical_owned_active(
    owned_active_profiles: &std::collections::BTreeSet<ProfileId>,
    topology_errors: &BTreeMap<ProfileId, String>,
    profile_id: &ProfileId,
) -> bool {
    owned_active_profiles.contains(profile_id) && !topology_errors.contains_key(profile_id)
}

fn persist_endpoint_cache_if_changed(
    state_store: &FsControlStateStore,
    previous: Option<&[u8]>,
    cache: &EndpointResolutionCache,
) -> Result<(), LocalControlError> {
    let encoded = cache.encode().map_err(LocalControlError::Persistence)?;
    if previous != Some(encoded.as_slice()) {
        state_store
            .save_endpoint_resolution_cache(&encoded)
            .map_err(|error| LocalControlError::Persistence(error.to_string()))?;
    }
    Ok(())
}

fn load_profile_topologies(
    profiles: &[VpnProfile],
    endpoint_cache: &mut EndpointResolutionCache,
) -> (
    BTreeMap<ProfileId, crate::vortix_core::control::ProfileTopology>,
    BTreeMap<ProfileId, String>,
) {
    let mut topologies = BTreeMap::new();
    let mut errors = BTreeMap::new();
    for profile in profiles {
        match topology_for_profile(profile, endpoint_cache) {
            Ok(topology) => {
                topologies.insert(profile.id.clone(), topology);
            }
            Err(reason) => {
                errors.insert(profile.id.clone(), reason);
            }
        }
    }
    (topologies, errors)
}

fn validate_command_target(
    profiles: &[VpnProfile],
    topology_errors: &BTreeMap<ProfileId, String>,
    unowned_active_profiles: &[String],
    command: &UserCommand,
) -> Result<(), LocalControlError> {
    let target = match command {
        UserCommand::Connect { profile_id, .. }
        | UserCommand::ConnectExclusive { profile_id }
        | UserCommand::Disconnect {
            profile_id: Some(profile_id),
        }
        | UserCommand::ForceDisconnect {
            profile_id: Some(profile_id),
        }
        | UserCommand::Reconnect {
            profile_id: Some(profile_id),
        } => Some(profile_id),
        UserCommand::Disconnect { profile_id: None }
        | UserCommand::ForceDisconnect { profile_id: None }
        | UserCommand::Reconnect { profile_id: None }
        | UserCommand::SetKillSwitch { .. }
        | UserCommand::ImportProfile { .. }
        | UserCommand::RenameProfile { .. }
        | UserCommand::DeleteProfile { .. } => None,
    };
    let Some(profile_id) = target else {
        return Ok(());
    };
    let starts_wireguard = matches!(
        command,
        UserCommand::Connect { .. }
            | UserCommand::ConnectExclusive { .. }
            | UserCommand::Reconnect {
                profile_id: Some(_)
            }
    );
    if starts_wireguard {
        if let Some(profile) = profiles.iter().find(|profile| &profile.id == profile_id) {
            if profile.protocol == crate::state::Protocol::WireGuard {
                let interface_name = profile
                    .config_path
                    .file_stem()
                    .and_then(std::ffi::OsStr::to_str)
                    .unwrap_or_default();
                if let Err(reason) =
                    crate::vortix_core::profile::validate_wireguard_interface_name(interface_name)
                {
                    return Err(LocalControlError::Profile {
                        profile: profile.name.clone(),
                        reason: format!(
                            "{reason}. Delete this profile, rename the original file (for example, to wg07.conf), and import it again"
                        ),
                    });
                }
            }
        }
    }
    if let Some(reason) = topology_errors.get(profile_id) {
        let profile = profiles
            .iter()
            .find(|profile| &profile.id == profile_id)
            .map_or_else(|| profile_id.to_string(), |profile| profile.name.clone());
        return Err(LocalControlError::Profile {
            profile,
            reason: reason.clone(),
        });
    }
    if matches!(command, UserCommand::Connect { .. })
        && profiles
            .iter()
            .find(|profile| &profile.id == profile_id)
            .is_some_and(|profile| unowned_active_profiles.contains(&profile.name))
    {
        return Err(LocalControlError::Recovery {
            profile: profile_id.to_string(),
            reason: "active tunnel is not owned by the canonical Standard-mode authority".into(),
        });
    }
    Ok(())
}

fn observation_changes(
    profiles: &[VpnProfile],
    sessions: &[ActiveSession],
    published: &BTreeMap<ProfileId, (bool, Option<String>)>,
) -> Vec<(ProfileId, (bool, Option<String>))> {
    profiles
        .iter()
        .filter_map(|profile| {
            let session = sessions.iter().find(|session| session.name == profile.name);
            let state = (
                session.is_some(),
                session.map(|session| session.interface.clone()),
            );
            (published.get(&profile.id) != Some(&state)).then(|| (profile.id.clone(), state))
        })
        .collect()
}

fn current_session(
    profile: &VpnProfile,
    sessions: &Mutex<Vec<ActiveSession>>,
) -> Option<ActiveSession> {
    sessions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|session| session.name == profile.name)
        .cloned()
}

fn current_owned_session(
    profile: &VpnProfile,
    sessions: &Mutex<Vec<ActiveSession>>,
    executor: &CanonicalTunnelExecutor,
) -> Option<ActiveSession> {
    let session = current_session(profile, sessions)?;
    executor
        .owns_live_session(&profile.id, &session)
        .ok()
        .filter(|owned| *owned)
        .map(|_| session)
}

fn external_session_profiles(
    sessions: &[ActiveSession],
    profiles: &[VpnProfile],
    canonical: &BTreeMap<ProfileId, Profile>,
    ownership: &StandardTunnelOwnershipStore,
    live_executor: Option<&CanonicalTunnelExecutor>,
) -> Vec<String> {
    sessions
        .iter()
        .filter(|session| {
            let Some(profile) = profiles.iter().find(|profile| profile.name == session.name) else {
                return true;
            };
            let Some(canonical) = canonical.get(&profile.id) else {
                return true;
            };
            if live_executor.is_some_and(|executor| {
                executor
                    .owns_live_session(&profile.id, session)
                    .unwrap_or(false)
            }) {
                return false;
            }
            match profile.protocol {
                Protocol::WireGuard => ownership.validate_wireguard(canonical, session).is_err(),
                Protocol::OpenVPN => crate::tunnel::standard_openvpn_owner(&profile.id, session)
                    .ok()
                    .flatten()
                    .is_none(),
            }
        })
        .map(|session| session.name.clone())
        .collect()
}

fn recovered_openvpn_operation(
    operations: &BTreeMap<OperationId, OperationRecord>,
    profile_id: &ProfileId,
    generation: u64,
    persisted: Option<&OperationId>,
) -> Option<OperationId> {
    persisted
        .cloned()
        .or_else(|| connected_operation(operations, profile_id, generation))
}

fn restore_owned_sessions(
    profiles: &[VpnProfile],
    canonical: &BTreeMap<ProfileId, Profile>,
    ownership: &StandardTunnelOwnershipStore,
    executor: &CanonicalTunnelExecutor,
    supervisor: &crate::vortix_core::control::supervisor::Supervisor,
    operations: &BTreeMap<OperationId, OperationRecord>,
    sessions: &[ActiveSession],
) -> Result<std::collections::BTreeSet<ProfileId>, LocalControlError> {
    let mut restored = std::collections::BTreeSet::new();
    for session in sessions {
        let Some(profile) = profiles.iter().find(|profile| profile.name == session.name) else {
            continue;
        };
        let Some(canonical) = canonical.get(&profile.id) else {
            continue;
        };
        let (generation, operation_id) = match profile.protocol {
            Protocol::WireGuard => {
                let Ok(owned) = ownership.validate_wireguard(canonical, session) else {
                    continue;
                };
                if owned.authority_epoch != STANDARD_AUTHORITY_EPOCH {
                    continue;
                }
                (owned.tunnel_generation, owned.operation_id)
            }
            Protocol::OpenVPN => {
                let Some(owner) = crate::tunnel::standard_openvpn_owner(&profile.id, session)
                    .map_err(|error| LocalControlError::Recovery {
                        profile: profile.name.clone(),
                        reason: error,
                    })?
                else {
                    continue;
                };
                let Some(operation_id) = recovered_openvpn_operation(
                    operations,
                    &profile.id,
                    owner.generation(),
                    owner.operation_id(),
                ) else {
                    continue;
                };
                (owner.generation(), operation_id)
            }
        };
        executor
            .restore_standard_profile(
                supervisor,
                &profile.id,
                TunnelRevision {
                    authority_epoch: STANDARD_AUTHORITY_EPOCH,
                    generation,
                },
                operation_id,
            )
            .map_err(|reason| LocalControlError::Recovery {
                profile: profile.name.clone(),
                reason,
            })?;
        restored.insert(profile.id.clone());
    }
    Ok(restored)
}

fn connected_operation(
    operations: &BTreeMap<OperationId, OperationRecord>,
    profile_id: &ProfileId,
    generation: u64,
) -> Option<OperationId> {
    operations.values().rev().find_map(|operation| {
        let OperationIntent::DesiredSubset { tunnels, .. } = &operation.intent else {
            return None;
        };
        (operation.desired_generation == generation
            && tunnels.get(profile_id) == Some(&RequestedTunnelState::Connected))
        .then(|| operation.id.clone())
    })
}

#[cfg(unix)]
pub(crate) fn config_owner(config_dir: &Path) -> Result<(u32, u32), LocalControlError> {
    crate::config::config_owner(config_dir).map_err(LocalControlError::Owner)
}

#[cfg(not(unix))]
pub(crate) fn config_owner(_config_dir: &Path) -> Result<(u32, u32), LocalControlError> {
    crate::config::config_owner(_config_dir).map_err(LocalControlError::Owner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emergency_release_fence_replaces_both_recovery_copies_before_startup() {
        let temp = tempfile::tempdir().unwrap();
        let control_dir = temp.path().join("control");
        let store = FsControlStateStore::new(&control_dir);
        let boot_id = crate::utils::boot_identity()
            .unwrap_or_else(|| "emergency-release-fence-test".to_string());
        let mut durable = crate::vortix_core::control::DurableControlState {
            desired: crate::vortix_core::control::DesiredState::default(),
            operations: BTreeMap::new(),
            boot_connections: BTreeMap::new(),
            requested_resources: BTreeMap::new(),
            last_connected_at: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            retention: crate::vortix_core::control::RetentionMetadata::default(),
            reconciliation_required: false,
        };
        durable.desired.kill_switch = crate::state::KillSwitchMode::AlwaysOn;
        durable.desired.refresh_policy_digest();
        let mut recovered = Some(crate::vortix_core::control::RecoveredControlState {
            state: durable,
            same_boot: true,
        });

        honor_emergency_release_fence(true, &store, &boot_id, &mut recovered).unwrap();

        let current = store.load(&boot_id).unwrap().unwrap();
        assert_eq!(
            current.state.desired.kill_switch,
            crate::state::KillSwitchMode::Off
        );
        assert!(current.state.reconciliation_required);
        std::fs::write(control_dir.join("control-state.json"), b"corrupt").unwrap();
        let recovery = store.load(&boot_id).unwrap().unwrap();
        assert_eq!(
            recovery.state.desired.kill_switch,
            crate::state::KillSwitchMode::Off
        );
    }

    #[derive(Debug)]
    struct FrozenClock(u64);

    impl crate::vortix_core::control::Clock for FrozenClock {
        fn now_millis(&self) -> u64 {
            self.0
        }
    }

    #[derive(Debug, Default)]
    struct BlockingNextSaveStore {
        armed: std::sync::atomic::AtomicBool,
        entered: (Mutex<bool>, std::sync::Condvar),
        released: (Mutex<bool>, std::sync::Condvar),
    }

    impl BlockingNextSaveStore {
        fn arm(&self) {
            self.armed.store(true, Ordering::SeqCst);
            *self.entered.0.lock().unwrap() = false;
            *self.released.0.lock().unwrap() = false;
        }

        fn wait_until_blocked(&self) {
            let entered = self.entered.0.lock().unwrap();
            let (entered, timeout) = self
                .entered
                .1
                .wait_timeout_while(entered, Duration::from_secs(1), |entered| !*entered)
                .unwrap();
            assert!(*entered && !timeout.timed_out(), "state save did not block");
        }

        fn release(&self) {
            *self.released.0.lock().unwrap() = true;
            self.released.1.notify_all();
        }
    }

    impl ControlStateStore for BlockingNextSaveStore {
        fn load(
            &self,
            _current_boot_id: &str,
        ) -> Result<
            Option<crate::vortix_core::control::RecoveredControlState>,
            crate::vortix_core::control::ControlStateStoreError,
        > {
            Ok(None)
        }

        fn save(
            &self,
            _current_boot_id: &str,
            _state: &crate::vortix_core::control::DurableControlState,
        ) -> Result<(), crate::vortix_core::control::ControlStateStoreError> {
            if self.armed.swap(false, Ordering::SeqCst) {
                *self.entered.0.lock().unwrap() = true;
                self.entered.1.notify_all();
                let released = self.released.0.lock().unwrap();
                drop(
                    self.released
                        .1
                        .wait_while(released, |released| !*released)
                        .unwrap(),
                );
            }
            Ok(())
        }
    }

    fn profile_id(seed: char) -> ProfileId {
        ProfileId::parse(seed.to_string().repeat(ProfileId::HEX_LEN)).unwrap()
    }

    fn client_id(sequence: u64) -> crate::vortix_core::control::ClientId {
        serde_json::from_str(&format!("\"client-0000000000000001-{sequence:016x}\"")).unwrap()
    }

    fn operation_id(sequence: u64) -> OperationId {
        OperationId::parse(format!("op-0000000000000001-{sequence:016x}")).unwrap()
    }

    struct EmptyRemoteSubscription;

    impl crate::daemon::service::RemoteControlSubscription for EmptyRemoteSubscription {
        fn try_recv(
            &mut self,
        ) -> Result<
            Option<crate::daemon::service::RemoteControlUpdate>,
            crate::daemon::service::RemoteControlError,
        > {
            Ok(None)
        }
    }

    struct SnapshotRemoteTransport {
        next_client: AtomicU64,
        snapshot: ControlSnapshot,
    }

    impl SnapshotRemoteTransport {
        fn new(snapshot: ControlSnapshot) -> Self {
            Self {
                next_client: AtomicU64::new(0),
                snapshot,
            }
        }
    }

    impl crate::daemon::service::RemoteControlTransport for SnapshotRemoteTransport {
        fn exchange(
            &self,
            op: crate::vortix_core::ipc::IpcOp,
        ) -> Result<crate::vortix_core::ipc::IpcResult, crate::daemon::service::RemoteControlError>
        {
            if !matches!(op, crate::vortix_core::ipc::IpcOp::ControlOpen) {
                return Err(crate::daemon::service::RemoteControlError::Protocol(
                    format!("unexpected projection operation: {op:?}"),
                ));
            }
            let sequence = self.next_client.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(crate::vortix_core::ipc::IpcResult::ControlOpened {
                session_id: crate::vortix_core::ipc::RemoteSessionId::parse(format!(
                    "session-{sequence:032x}"
                ))
                .unwrap(),
                client_id: client_id(sequence),
            })
        }

        fn subscribe(
            &self,
            _session_id: &crate::vortix_core::ipc::RemoteSessionId,
        ) -> Result<
            (
                Box<dyn crate::daemon::service::RemoteControlSubscription>,
                ControlSnapshot,
            ),
            crate::daemon::service::RemoteControlError,
        > {
            Ok((Box::new(EmptyRemoteSubscription), self.snapshot.clone()))
        }
    }

    #[derive(Default)]
    struct AdmissionRemoteTransport {
        next_operation: AtomicU64,
    }

    impl crate::daemon::service::RemoteControlTransport for AdmissionRemoteTransport {
        fn exchange(
            &self,
            op: crate::vortix_core::ipc::IpcOp,
        ) -> Result<crate::vortix_core::ipc::IpcResult, crate::daemon::service::RemoteControlError>
        {
            match op {
                crate::vortix_core::ipc::IpcOp::ControlOpen => {
                    Ok(crate::vortix_core::ipc::IpcResult::ControlOpened {
                        session_id: crate::vortix_core::ipc::RemoteSessionId::parse(format!(
                            "session-{}",
                            "a".repeat(32)
                        ))
                        .unwrap(),
                        client_id: client_id(1),
                    })
                }
                crate::vortix_core::ipc::IpcOp::ControlSubmit { .. } => {
                    let sequence = self.next_operation.fetch_add(1, Ordering::SeqCst) + 1;
                    Ok(crate::vortix_core::ipc::IpcResult::ControlAccepted {
                        admitted: crate::vortix_core::control::AdmittedOperation {
                            operation_id: operation_id(sequence),
                        },
                    })
                }
                crate::vortix_core::ipc::IpcOp::ControlStageProfileImport {
                    final_chunk: true,
                    ..
                } => Ok(
                    crate::vortix_core::ipc::IpcResult::ControlProfileImportStaged {
                        profile_id: profile_id('d'),
                        display_name: "daemon-canonical".into(),
                    },
                ),
                other => Err(crate::daemon::service::RemoteControlError::Protocol(
                    format!("unexpected admission operation: {other:?}"),
                )),
            }
        }

        fn subscribe(
            &self,
            _session_id: &crate::vortix_core::ipc::RemoteSessionId,
        ) -> Result<
            (
                Box<dyn crate::daemon::service::RemoteControlSubscription>,
                ControlSnapshot,
            ),
            crate::daemon::service::RemoteControlError,
        > {
            Ok((
                Box::new(EmptyRemoteSubscription),
                ControlSnapshot::default(),
            ))
        }
    }

    #[derive(Default)]
    struct BlockingChallengeTransport {
        entered: (Mutex<bool>, std::sync::Condvar),
        released: (Mutex<bool>, std::sync::Condvar),
        responses: AtomicU64,
    }

    impl BlockingChallengeTransport {
        fn wait_until_blocked(&self) {
            let entered = self.entered.0.lock().unwrap();
            let (entered, timeout) = self
                .entered
                .1
                .wait_timeout_while(entered, Duration::from_secs(1), |entered| !*entered)
                .unwrap();
            assert!(
                *entered && !timeout.timed_out(),
                "challenge call did not block"
            );
        }

        fn release(&self) {
            *self.released.0.lock().unwrap() = true;
            self.released.1.notify_all();
        }
    }

    impl crate::daemon::service::RemoteControlTransport for BlockingChallengeTransport {
        fn exchange(
            &self,
            op: crate::vortix_core::ipc::IpcOp,
        ) -> Result<crate::vortix_core::ipc::IpcResult, crate::daemon::service::RemoteControlError>
        {
            match op {
                crate::vortix_core::ipc::IpcOp::ControlOpen => {
                    Ok(crate::vortix_core::ipc::IpcResult::ControlOpened {
                        session_id: crate::vortix_core::ipc::RemoteSessionId::parse(format!(
                            "session-{}",
                            "b".repeat(32)
                        ))
                        .unwrap(),
                        client_id: client_id(1),
                    })
                }
                crate::vortix_core::ipc::IpcOp::ControlRespondChallenge { .. } => {
                    self.responses.fetch_add(1, Ordering::SeqCst);
                    *self.entered.0.lock().unwrap() = true;
                    self.entered.1.notify_all();
                    let released = self.released.0.lock().unwrap();
                    drop(
                        self.released
                            .1
                            .wait_while(released, |released| !*released)
                            .unwrap(),
                    );
                    Ok(crate::vortix_core::ipc::IpcResult::ChallengeAccepted)
                }
                other => Err(crate::daemon::service::RemoteControlError::Protocol(
                    format!("unexpected challenge operation: {other:?}"),
                )),
            }
        }

        fn subscribe(
            &self,
            _session_id: &crate::vortix_core::ipc::RemoteSessionId,
        ) -> Result<
            (
                Box<dyn crate::daemon::service::RemoteControlSubscription>,
                ControlSnapshot,
            ),
            crate::daemon::service::RemoteControlError,
        > {
            Ok((
                Box::new(EmptyRemoteSubscription),
                ControlSnapshot::default(),
            ))
        }
    }

    fn profile_operation(
        id: OperationId,
        profile_id: ProfileId,
        status: OperationStatus,
        result: Option<OperationResult>,
    ) -> OperationRecord {
        OperationRecord {
            id,
            idempotency_key: IdempotencyKey::new("remote-profile-test"),
            client_id: client_id(1),
            command_digest: crate::vortix_core::control::PolicyDigest("test".into()),
            authority_epoch: AuthorityEpoch(1),
            desired_generation: 1,
            admitted_at_millis: 1,
            deadline_millis: 10,
            intent: OperationIntent::ProfileMutation { profile_id },
            status,
            result,
            failure_detail: None,
        }
    }

    #[test]
    fn remote_snapshot_projects_challenges_to_each_session_client() {
        let challenge_id = serde_json::from_str("1").unwrap();
        let mut snapshot = ControlSnapshot::default();
        snapshot.challenges.insert(
            challenge_id,
            crate::vortix_core::control::ChallengeRecord {
                id: challenge_id,
                profile_id: profile_id('a'),
                operation_id: operation_id(1),
                kind: crate::vortix_core::control::ChallengeKind::TwoFactorCode,
                label: "OTP".into(),
                authorized_client: client_id(1),
                created_at_millis: 1,
                expires_at_millis: 10,
            },
        );
        let transport = Arc::new(SnapshotRemoteTransport::new(snapshot));
        let first = ClientControlSession::remote_for_parity(
            crate::daemon::service::RemoteControlSession::open_for_parity(transport.clone())
                .unwrap(),
        );
        let second = ClientControlSession::remote_for_parity(
            crate::daemon::service::RemoteControlSession::open_for_parity(transport).unwrap(),
        );

        assert!(first
            .current_snapshot()
            .challenges
            .contains_key(&challenge_id));
        assert!(second.current_snapshot().challenges.is_empty());
    }

    #[test]
    fn remote_catalog_reports_only_submitted_profile_terminal_truth() {
        let transport = Arc::new(AdmissionRemoteTransport::default());
        let session = ClientControlSession::remote_for_parity(
            crate::daemon::service::RemoteControlSession::open_for_parity(transport).unwrap(),
        );
        let target = profile_id('b');
        session
            .enqueue_tui_command(
                UserCommand::RenameProfile {
                    profile_id: target.clone(),
                    new_display_name: "canonical-name".into(),
                },
                Duration::from_secs(1),
                "rename",
            )
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let submitted_id = loop {
            if let Some(result) = session.take_tui_admission_results().into_iter().next() {
                let TuiControlCompletion::Admission(Ok(operation_id)) = result.completion else {
                    panic!("remote rename was not admitted");
                };
                break operation_id;
            }
            assert!(Instant::now() < deadline, "remote rename did not settle");
            std::thread::yield_now();
        };

        let historical_id = operation_id(99);
        let mut snapshot = ControlSnapshot::default();
        snapshot.operations.insert(
            historical_id.clone(),
            profile_operation(
                historical_id,
                profile_id('c'),
                OperationStatus::Succeeded,
                Some(OperationResult::ProfileMutationApplied),
            ),
        );
        snapshot.operations.insert(
            submitted_id.clone(),
            profile_operation(
                submitted_id,
                target,
                OperationStatus::Failed,
                Some(OperationResult::Failed(
                    crate::vortix_core::control::OperationFailure::Rejected,
                )),
            ),
        );

        let update = session.take_catalog_update(&snapshot).unwrap();
        assert_eq!(update.outcomes.len(), 1);
        assert!(matches!(
            update.outcomes.as_slice(),
            [LocalCatalogOutcome::Terminal {
                operation_id: _,
                status: OperationStatus::Failed,
                result: Some(OperationResult::Failed(
                    crate::vortix_core::control::OperationFailure::Rejected
                )),
            }]
        ));
        assert!(session.take_catalog_update(&snapshot).is_none());
    }

    #[test]
    fn remote_import_reconciles_provisional_file_name_to_daemon_name() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("upload.conf");
        write_test_wireguard_config(&source);
        let session = ClientControlSession::remote_for_parity(
            crate::daemon::service::RemoteControlSession::open_for_parity(Arc::new(
                AdmissionRemoteTransport::default(),
            ))
            .unwrap(),
        );
        assert_eq!(
            session
                .enqueue_tui_profile_import(&source, Duration::from_secs(1), "import")
                .unwrap(),
            "upload"
        );
        let deadline = Instant::now() + Duration::from_secs(1);
        let submitted_id = loop {
            if let Some(result) = session.take_tui_admission_results().into_iter().next() {
                assert_eq!(
                    result.import_display_name.as_deref(),
                    Some("daemon-canonical")
                );
                let TuiControlCompletion::Admission(Ok(operation_id)) = result.completion else {
                    panic!("remote import was not admitted");
                };
                break operation_id;
            }
            assert!(Instant::now() < deadline, "remote import did not settle");
            std::thread::yield_now();
        };
        let mut snapshot = ControlSnapshot::default();
        snapshot.operations.insert(
            submitted_id.clone(),
            profile_operation(
                submitted_id,
                profile_id('d'),
                OperationStatus::Succeeded,
                Some(OperationResult::ProfileMutationApplied),
            ),
        );

        let update = session.take_catalog_update(&snapshot).unwrap();
        assert!(matches!(
            update.outcomes.as_slice(),
            [LocalCatalogOutcome::Applied {
                operation_id: _,
                receipt: LocalProfileMutationReceipt::RemoteApplied {
                    display_name: Some(display_name),
                },
            }] if display_name == "daemon-canonical"
        ));
    }

    #[test]
    fn remote_import_validation_failure_is_delivered_after_nonblocking_enqueue() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing.conf");
        let session = ClientControlSession::remote_for_parity(
            crate::daemon::service::RemoteControlSession::open_for_parity(Arc::new(
                AdmissionRemoteTransport::default(),
            ))
            .unwrap(),
        );
        let started = Instant::now();
        assert_eq!(
            session
                .enqueue_tui_profile_import(&missing, Duration::from_secs(1), "missing")
                .unwrap(),
            "missing"
        );
        assert!(started.elapsed() < Duration::from_millis(50));

        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(result) = session.take_tui_admission_results().into_iter().next() {
                assert_eq!(result.import_display_name.as_deref(), Some("missing"));
                assert!(matches!(
                    result.completion,
                    TuiControlCompletion::Admission(Err(LocalControlError::Remote(
                        crate::daemon::service::RemoteControlError::Protocol(_)
                    )))
                ));
                break;
            }
            assert!(
                Instant::now() < deadline,
                "remote import failure did not settle"
            );
            std::thread::yield_now();
        }
    }

    #[test]
    fn remote_challenge_response_uses_bounded_background_queue() {
        let transport = Arc::new(BlockingChallengeTransport::default());
        let session = ClientControlSession::remote_for_parity(
            crate::daemon::service::RemoteControlSession::open_for_parity(transport.clone())
                .unwrap(),
        );
        let challenge_id = serde_json::from_str("1").unwrap();
        let started = Instant::now();
        session
            .respond_challenge(challenge_id, b"123456".to_vec())
            .unwrap();
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "terminal thread waited for remote challenge I/O"
        );
        transport.wait_until_blocked();
        assert!(session.take_tui_admission_results().is_empty());
        session
            .respond_challenge(challenge_id, b"duplicate".to_vec())
            .unwrap();

        transport.release();
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(result) = session.take_tui_admission_results().into_iter().next() {
                assert!(matches!(
                    result.completion,
                    TuiControlCompletion::ChallengeResponse {
                        challenge_id: completed,
                        result: Ok(()),
                    } if completed == challenge_id
                ));
                break;
            }
            assert!(Instant::now() < deadline, "challenge result did not settle");
            std::thread::yield_now();
        }
        assert_eq!(transport.responses.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn scanner_refresh_is_bounded_independently_of_fast_control_ticks() {
        let started = Instant::now();
        assert!(!scanner_refresh_due(
            started,
            started + CONTROL_PROGRESS_INTERVAL
        ));
        assert!(!scanner_refresh_due(
            started,
            started
                + SCANNER_REFRESH_CEILING
                    .checked_sub(Duration::from_millis(1))
                    .unwrap()
        ));
        assert!(scanner_refresh_due(
            started,
            started + SCANNER_REFRESH_CEILING
        ));
        assert!(SCANNER_REFRESH_CEILING > CONTROL_PROGRESS_INTERVAL);
    }

    #[test]
    fn inactive_down_still_requires_control_when_durable_intent_is_connected() {
        let connected = profile_id('a');
        let disconnected = profile_id('b');
        let desired = BTreeMap::from([
            (connected.clone(), RequestedTunnelState::Connected),
            (disconnected.clone(), RequestedTunnelState::Disconnected),
        ]);

        assert!(desired_disconnect_required(&desired, &BTreeSet::new()));
        assert!(desired_disconnect_required(
            &desired,
            &BTreeSet::from([connected])
        ));
        assert!(!desired_disconnect_required(
            &desired,
            &BTreeSet::from([disconnected])
        ));
    }

    #[test]
    fn scanner_cache_publishes_only_presence_or_interface_changes() {
        let profile = VpnProfile {
            id: profile_id('a'),
            name: "corp".into(),
            protocol: Protocol::WireGuard,
            location: String::new(),
            config_path: "/tmp/corp.conf".into(),
            last_used: None,
        };
        let session = ActiveSession {
            name: "corp".into(),
            interface: "wg0".into(),
            ..ActiveSession::default()
        };
        let initial = observation_changes(
            std::slice::from_ref(&profile),
            std::slice::from_ref(&session),
            &BTreeMap::new(),
        );
        assert_eq!(
            initial,
            vec![(profile.id.clone(), (true, Some("wg0".into())))]
        );

        let published = BTreeMap::from_iter(initial);
        assert!(observation_changes(
            std::slice::from_ref(&profile),
            std::slice::from_ref(&session),
            &published,
        )
        .is_empty());

        let changed = ActiveSession {
            interface: "wg1".into(),
            ..session
        };
        assert_eq!(
            observation_changes(&[profile], &[changed], &published),
            vec![(profile_id('a'), (true, Some("wg1".into())))]
        );
    }

    #[test]
    fn unchanged_local_session_has_no_snapshot_delivery() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join(crate::constants::PROFILES_DIR_NAME)).unwrap();
        let session = LocalControlSession::start_profile_test(temp.path(), Vec::new()).unwrap();

        assert!(session.take_changed_snapshot().unwrap().is_none());
        assert!(session.take_changed_snapshot().unwrap().is_none());
    }

    #[test]
    fn standard_session_manages_credentials_outside_durable_control_shapes() {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;

        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join(crate::constants::PROFILES_DIR_NAME)).unwrap();
        let profile_id = profile_id('a');
        let session = LocalControlSession::start_profile_test(temp.path(), Vec::new()).unwrap();

        session
            .remember_openvpn_credentials(
                &profile_id,
                "u2-session-marker-user",
                "u2-session-marker-password",
            )
            .unwrap();
        let loaded = session
            .load_openvpn_credentials(&profile_id, "renamed-corp")
            .unwrap()
            .unwrap();
        assert_eq!(loaded.username(), "u2-session-marker-user");
        assert_eq!(loaded.password(), "u2-session-marker-password");

        let command = serde_json::to_vec(&UserCommand::Connect {
            profile_id: profile_id.clone(),
            conflict_acknowledgement: None,
        })
        .unwrap();
        let snapshot = serde_json::to_vec(&session.current_snapshot()).unwrap();
        for durable in [&command[..], &snapshot[..]] {
            assert!(!durable
                .windows(b"u2-session-marker-user".len())
                .any(|window| window == b"u2-session-marker-user"));
            assert!(!durable
                .windows(b"u2-session-marker-password".len())
                .any(|window| window == b"u2-session-marker-password"));
        }

        let auth_path = temp
            .path()
            .join(crate::constants::OPENVPN_AUTH_DIR)
            .join(format!("{}.auth", profile_id.as_str()));
        #[cfg(unix)]
        {
            let owner = config_owner(temp.path()).unwrap();
            let metadata = std::fs::metadata(&auth_path).unwrap();
            assert_eq!((metadata.uid(), metadata.gid()), owner);
        }

        session
            .clear_openvpn_credentials(&profile_id, "renamed-corp")
            .unwrap();
        assert!(session
            .load_openvpn_credentials(&profile_id, "renamed-corp")
            .unwrap()
            .is_none());
    }

    #[test]
    fn remote_credential_management_is_explicitly_unsupported_without_local_fallback() {
        let session = ClientControlSession::remote_for_parity(
            crate::daemon::service::RemoteControlSession::open_for_parity(Arc::new(
                SnapshotRemoteTransport::new(ControlSnapshot::default()),
            ))
            .unwrap(),
        );
        let profile_id = profile_id('a');

        assert!(matches!(
            session.load_openvpn_credentials(&profile_id, "corp"),
            Err(LocalControlError::CredentialManagementUnsupported)
        ));
        assert!(matches!(
            session.remember_openvpn_credentials(&profile_id, "alice", "secret"),
            Err(LocalControlError::CredentialManagementUnsupported)
        ));
        assert!(matches!(
            session.clear_openvpn_credentials(&profile_id, "corp"),
            Err(LocalControlError::CredentialManagementUnsupported)
        ));
    }

    #[test]
    fn tui_enqueue_stays_prompt_while_durable_admission_is_blocked() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join(crate::constants::PROFILES_DIR_NAME)).unwrap();
        let store = Arc::new(BlockingNextSaveStore::default());
        let persistence = ControlPersistenceConfig::new(
            "test-boot",
            Arc::clone(&store) as Arc<dyn ControlStateStore>,
        );
        let session = LocalControlSession::start_profile_test_with_persistence(
            temp.path(),
            Vec::new(),
            Some(persistence),
        )
        .unwrap();
        store.arm();

        let started = Instant::now();
        session
            .enqueue_tui_command(
                UserCommand::SetKillSwitch {
                    mode: crate::state::KillSwitchMode::Off,
                },
                Duration::from_secs(1),
                "async-durable",
            )
            .unwrap();
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "TUI enqueue waited for durable state I/O"
        );
        store.wait_until_blocked();
        assert!(session.take_tui_admission_results().is_empty());

        store.release();
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let results = session.take_tui_admission_results();
            if let Some(result) = results.into_iter().next() {
                assert!(matches!(
                    result.completion,
                    TuiControlCompletion::Admission(Ok(_))
                ));
                break;
            }
            assert!(
                Instant::now() < deadline,
                "durable result was not delivered"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn tui_admission_capacity_includes_undrained_results() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join(crate::constants::PROFILES_DIR_NAME)).unwrap();
        let session = LocalControlSession::start_profile_test(temp.path(), Vec::new()).unwrap();
        for sequence in 0..TUI_ADMISSION_CAPACITY {
            session
                .enqueue_tui_command(
                    UserCommand::SetKillSwitch {
                        mode: crate::state::KillSwitchMode::Off,
                    },
                    Duration::from_secs(1),
                    format!("capacity-{sequence}"),
                )
                .unwrap();
        }
        assert!(matches!(
            session.enqueue_tui_command(
                UserCommand::SetKillSwitch {
                    mode: crate::state::KillSwitchMode::Off,
                },
                Duration::from_secs(1),
                "capacity-overflow",
            ),
            Err(LocalControlError::Busy)
        ));

        let deadline = Instant::now() + Duration::from_secs(1);
        let mut settled = 0;
        loop {
            settled += session.take_tui_admission_results().len();
            if settled == TUI_ADMISSION_CAPACITY {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "admission results did not settle: received {settled}/{TUI_ADMISSION_CAPACITY}"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(session
            .enqueue_tui_command(
                UserCommand::SetKillSwitch {
                    mode: crate::state::KillSwitchMode::Off,
                },
                Duration::from_secs(1),
                "capacity-released",
            )
            .is_ok());
    }

    #[test]
    fn local_service_deadlines_progress_while_ui_is_idle() {
        let temp = tempfile::tempdir().unwrap();
        let profiles_dir = temp.path().join(crate::constants::PROFILES_DIR_NAME);
        std::fs::create_dir(&profiles_dir).unwrap();
        let config_path = profiles_dir.join("corp.conf");
        write_test_wireguard_config(&config_path);
        let profile = VpnProfile {
            id: profile_id('b'),
            name: "corp".into(),
            protocol: Protocol::WireGuard,
            location: String::new(),
            config_path,
            last_used: None,
        };
        let session =
            LocalControlSession::start_profile_test(temp.path(), vec![profile.clone()]).unwrap();
        let operation_id = session
            .submit(
                UserCommand::Connect {
                    profile_id: profile.id,
                    conflict_acknowledgement: None,
                },
                Duration::from_millis(20),
                "idle-deadline",
            )
            .unwrap();

        // Deliberately do not call `progress`: the service ticker belongs to
        // its own runtime workers rather than the terminal event loop.
        std::thread::sleep(Duration::from_millis(150));
        let snapshot = session.current_snapshot();
        let operation = snapshot.operations.get(&operation_id).unwrap();
        assert!(operation.status.is_terminal());
        assert_eq!(operation.result, Some(OperationResult::Expired));
    }

    #[test]
    fn cli_startup_settlement_waits_for_recovered_work_before_new_deadline() {
        let temp = tempfile::tempdir().unwrap();
        let profiles_dir = temp.path().join(crate::constants::PROFILES_DIR_NAME);
        std::fs::create_dir(&profiles_dir).unwrap();
        let config_path = profiles_dir.join("corp.conf");
        write_test_wireguard_config(&config_path);
        let profile = VpnProfile {
            id: profile_id('b'),
            name: "corp".into(),
            protocol: Protocol::WireGuard,
            location: String::new(),
            config_path,
            last_used: None,
        };
        let session =
            LocalControlSession::start_profile_test(temp.path(), vec![profile.clone()]).unwrap();
        let before_generation = session.current_snapshot().generation;
        let recovered_operation = session
            .submit(
                UserCommand::Connect {
                    profile_id: profile.id,
                    conflict_acknowledgement: None,
                },
                Duration::from_millis(20),
                "recovered-before-cli",
            )
            .unwrap();

        session
            .wait_for_startup_settlement(before_generation, Duration::from_secs(1))
            .unwrap();

        let snapshot = session.current_snapshot();
        assert!(snapshot
            .operations
            .get(&recovered_operation)
            .is_some_and(|operation| operation.status.is_terminal()));
    }

    #[test]
    fn unchanged_scanner_payload_does_not_publish_again() {
        let temp = tempfile::tempdir().unwrap();
        let profiles_dir = temp.path().join(crate::constants::PROFILES_DIR_NAME);
        std::fs::create_dir(&profiles_dir).unwrap();
        let config_path = profiles_dir.join("corp.conf");
        std::fs::write(
            &config_path,
            b"[Interface]\nPrivateKey = abc=\nAddress = 10.0.0.1/24\n\n[Peer]\nPublicKey = xyz=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n",
        )
        .unwrap();
        let profile = VpnProfile {
            id: profile_id('c'),
            name: "corp".into(),
            protocol: Protocol::WireGuard,
            location: String::new(),
            config_path,
            last_used: None,
        };
        // Snapshot generation is the assertion subject here. Freeze the
        // service clock so independent freshness ticks cannot create a second
        // publication while the scanner batch is being observed.
        let session = LocalControlSession::start_profile_test_with_persistence_and_clock(
            temp.path(),
            vec![profile],
            None,
            Arc::new(FrozenClock(1)),
        )
        .unwrap();
        let scan = || crate::core::scanner::ScannerResult {
            sessions: vec![ActiveSession {
                name: "corp".into(),
                interface: "wg0".into(),
                interface_authoritative: true,
                endpoint: "1.2.3.4:51820".into(),
                ..ActiveSession::default()
            }],
            default_route:
                crate::vortix_core::ports::route_table::DefaultRouteObservation::Interface(
                    "wg0".into(),
                ),
            tunnel_observation_complete: true,
        };
        let profile_id = profile_id('c');
        let baseline_generation = session.current_snapshot().generation;
        session
            .runtime()
            .block_on(session.publish_observations_from(scan(), 1))
            .unwrap();
        // `observe` acknowledges actor receipt before the final publication,
        // so consume snapshots until all three semantic facts from the first
        // scan are visible. A generation count can be satisfied by unrelated
        // actor publications and would leave a scan publication in flight.
        let settle_deadline = Instant::now() + Duration::from_secs(1);
        let settled_generation = loop {
            let snapshot = session.current_snapshot();
            let route_visible = snapshot
                .observed
                .default_route
                .as_ref()
                .is_some_and(|route| route.interface_name.as_deref() == Some("wg0"));
            let details_visible = snapshot.observed.tunnel_details.contains_key(&profile_id);
            let tunnel_visible = snapshot
                .observed
                .tunnels
                .get(&profile_id)
                .is_some_and(|tunnel| {
                    tunnel.active && tunnel.interface_name.as_deref() == Some("wg0")
                });
            if route_visible && details_visible && tunnel_visible {
                break snapshot.generation;
            }
            assert!(
                Instant::now() < settle_deadline,
                "first scanner publication did not settle"
            );
            std::thread::sleep(Duration::from_millis(1));
        };
        assert_eq!(
            settled_generation,
            baseline_generation + 1,
            "one scanner result must publish one atomic control snapshot"
        );
        while session.take_changed_snapshot().unwrap().is_some() {}
        let published_default_route = session.published_default_route.borrow().clone();
        let published_tunnel_details = session.published_tunnel_details.borrow().clone();
        let published_observations = session.published_observations.borrow().clone();

        session
            .runtime()
            .block_on(session.publish_observations_from(scan(), 1))
            .unwrap();
        assert_eq!(
            *session.published_default_route.borrow(),
            published_default_route
        );
        assert_eq!(
            *session.published_tunnel_details.borrow(),
            published_tunnel_details
        );
        assert_eq!(
            *session.published_observations.borrow(),
            published_observations
        );
    }

    #[test]
    fn scan_captured_before_owned_absence_cannot_restore_stale_presence() {
        let temp = tempfile::tempdir().unwrap();
        let profiles_dir = temp.path().join(crate::constants::PROFILES_DIR_NAME);
        std::fs::create_dir(&profiles_dir).unwrap();
        let config_path = profiles_dir.join("corp.conf");
        write_test_wireguard_config(&config_path);
        let profile = VpnProfile {
            id: profile_id('d'),
            name: "corp".into(),
            protocol: Protocol::WireGuard,
            location: String::new(),
            config_path,
            last_used: None,
        };
        let session =
            LocalControlSession::start_profile_test(temp.path(), vec![profile.clone()]).unwrap();
        let observer = session.service().observer();
        let absence_at = observer.now_millis();
        session
            .runtime()
            .block_on(observer.observe(Observation::Tunnel {
                profile_id: profile.id.clone(),
                active: false,
                interface_name: None,
                observed_at_millis: absence_at,
                protection: None,
            }))
            .unwrap();
        let scan_lifecycle_revision = session.scanner_lifecycle_revision.load(Ordering::SeqCst);
        session
            .scanner_lifecycle_revision
            .fetch_add(1, Ordering::SeqCst);

        session
            .runtime()
            .block_on(session.publish_observations_from_revision(
                crate::core::scanner::ScannerResult {
                    sessions: vec![ActiveSession {
                        name: profile.name,
                        interface: "wg0".into(),
                        ..ActiveSession::default()
                    }],
                    default_route:
                        crate::vortix_core::ports::route_table::DefaultRouteObservation::ProbeFailed,
                    tunnel_observation_complete: true,
                },
                absence_at.saturating_sub(1),
                Some(scan_lifecycle_revision),
            ))
            .unwrap();

        assert!(session.sessions.lock().unwrap().is_empty());
        assert!(!session
            .current_snapshot()
            .observed
            .tunnels
            .get(&profile.id)
            .is_some_and(|tunnel| tunnel.active));
    }

    #[test]
    fn stale_scanner_session_is_not_policy_authority_after_owned_teardown() {
        let temp = tempfile::tempdir().unwrap();
        let profile = VpnProfile {
            id: profile_id('d'),
            name: "corp".into(),
            protocol: Protocol::WireGuard,
            location: String::new(),
            config_path: temp.path().join("corp.conf"),
            last_used: None,
        };
        let sessions = Mutex::new(vec![ActiveSession {
            name: profile.name.clone(),
            interface: "wg0".into(),
            interface_authoritative: true,
            ..ActiveSession::default()
        }]);
        let executor = CanonicalTunnelExecutor::new(
            CanonicalTunnelSettings {
                config_dir: temp.path().to_path_buf(),
                openvpn_verbosity: "3".into(),
                connect_timeout_secs: 1,
                wireguard_handshake_timeout_secs: 1,
                wireguard_health_targets: Vec::new(),
            },
            |_| None,
        );

        assert!(current_owned_session(&profile, &sessions, &executor).is_none());
    }

    #[test]
    fn local_session_prunes_compacted_operations_and_deleted_profile_observations() {
        let temp = tempfile::tempdir().unwrap();
        let session = LocalControlSession::start_profile_test(temp.path(), Vec::new()).unwrap();
        let stale_operation = operation_id(99);
        session
            .reported_profile_operations
            .borrow_mut()
            .insert(stale_operation);
        session
            .published_observations
            .borrow_mut()
            .insert(profile_id('e'), (true, Some("wg9".into())));

        assert!(session
            .take_catalog_update(&ControlSnapshot::default())
            .is_none());
        session
            .runtime()
            .block_on(session.publish_observations_from(
                crate::core::scanner::ScannerResult {
                    sessions: Vec::new(),
                    default_route:
                        crate::vortix_core::ports::route_table::DefaultRouteObservation::ProbeFailed,
                    tunnel_observation_complete: true,
                },
                0,
            ))
            .unwrap();

        assert!(session.reported_profile_operations.borrow().is_empty());
        assert!(session.published_observations.borrow().is_empty());
    }

    #[test]
    fn failed_wireguard_sweep_never_publishes_absence() {
        let temp = tempfile::tempdir().unwrap();
        let session = LocalControlSession::start_profile_test(temp.path(), Vec::new()).unwrap();
        let profile = profile_id('f');
        session
            .published_observations
            .borrow_mut()
            .insert(profile.clone(), (true, Some("wg0".into())));

        let error = session
            .runtime()
            .block_on(session.publish_observations_from(
                crate::core::scanner::ScannerResult {
                    sessions: Vec::new(),
                    default_route:
                        crate::vortix_core::ports::route_table::DefaultRouteObservation::ProbeFailed,
                    tunnel_observation_complete: false,
                },
                0,
            ))
            .unwrap_err();

        assert!(matches!(error, LocalControlError::Observation(_)));
        assert_eq!(
            session.published_observations.borrow().get(&profile),
            Some(&(true, Some("wg0".into())))
        );
    }

    #[test]
    fn admitted_import_expiry_discards_prepared_body_and_topology() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join(crate::constants::PROFILES_DIR_NAME)).unwrap();
        let first_source = temp.path().join("first.conf");
        let expiring_source = temp.path().join("expiring.conf");
        write_test_wireguard_config(&first_source);
        write_test_wireguard_config(&expiring_source);
        let session = LocalControlSession::start_profile_test(temp.path(), Vec::new()).unwrap();
        session
            .profile_mutations
            .delay_next_execution(Duration::from_millis(250));
        session
            .enqueue_tui_profile_import(&first_source, Duration::from_secs(1), "first")
            .unwrap();
        session
            .enqueue_tui_profile_import(
                &expiring_source,
                Duration::from_millis(50),
                "expires-in-queue",
            )
            .unwrap();
        let admission_deadline = Instant::now() + Duration::from_secs(1);
        let mut expiring_id = None;
        while expiring_id.is_none() {
            for result in session.take_tui_admission_results() {
                if result.import_display_name.as_deref() == Some("expiring") {
                    let TuiControlCompletion::Admission(Ok(operation_id)) = result.completion
                    else {
                        panic!("expiring import was not admitted");
                    };
                    expiring_id = Some(operation_id);
                }
            }
            assert!(
                Instant::now() < admission_deadline,
                "import admissions did not settle"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        let expiring_id = expiring_id.unwrap();
        assert_eq!(session.prepared_import_count(), 2);

        std::thread::sleep(Duration::from_millis(400));
        let snapshot = session.current_snapshot();
        let operation = snapshot.operations.get(&expiring_id).unwrap();
        assert!(operation.status.is_terminal());
        assert_eq!(operation.result, Some(OperationResult::Expired));
        assert_eq!(session.prepared_import_count(), 0);
        assert!(session
            .profile_mutations
            .prepared_imports
            .lock()
            .unwrap()
            .is_empty());
        let catalog = session.take_catalog_update(&snapshot).unwrap();
        assert!(catalog.outcomes.iter().any(|outcome| matches!(
            outcome,
            LocalCatalogOutcome::Terminal {
                operation_id,
                status: OperationStatus::Expired,
                result: Some(OperationResult::Expired),
            } if operation_id == &expiring_id
        )));
    }

    #[test]
    fn async_import_admission_failure_discards_prepared_private_body() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join(crate::constants::PROFILES_DIR_NAME)).unwrap();
        let source = temp.path().join("corp.conf");
        write_test_wireguard_config(&source);
        let session = LocalControlSession::start_profile_test(temp.path(), Vec::new()).unwrap();
        session
            .submit(
                UserCommand::SetKillSwitch {
                    mode: crate::state::KillSwitchMode::Off,
                },
                Duration::from_secs(1),
                "collision",
            )
            .unwrap();
        session
            .enqueue_tui_profile_import(&source, Duration::from_secs(1), "collision")
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(result) = session.take_tui_admission_results().into_iter().next() {
                assert!(matches!(
                    result.completion,
                    TuiControlCompletion::Admission(Err(_))
                ));
                break;
            }
            assert!(
                Instant::now() < deadline,
                "admission failure was not delivered"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(session.prepared_import_count(), 0);
    }

    fn write_test_wireguard_config(path: &Path) {
        std::fs::write(
            path,
            b"[Interface]\nPrivateKey = abc=\nAddress = 10.0.0.1/24\n\n[Peer]\nPublicKey = xyz=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n",
        )
        .unwrap();
    }

    #[test]
    fn restored_openvpn_operation_is_generation_and_profile_exact() {
        let target = profile_id('a');
        let other = profile_id('b');
        let operation_id: OperationId =
            serde_json::from_str("\"op-0000000000000001-0000000000000001\"").unwrap();
        let operation = OperationRecord {
            id: operation_id.clone(),
            idempotency_key: IdempotencyKey::new("restore"),
            client_id: serde_json::from_str("\"client-0000000000000001-0000000000000001\"")
                .unwrap(),
            command_digest: crate::vortix_core::control::PolicyDigest("digest".into()),
            authority_epoch: STANDARD_AUTHORITY_EPOCH,
            desired_generation: 7,
            admitted_at_millis: 1,
            deadline_millis: 2,
            intent: OperationIntent::DesiredSubset {
                tunnels: BTreeMap::from([(target.clone(), RequestedTunnelState::Connected)]),
                kill_switch: None,
            },
            status: OperationStatus::Succeeded,
            result: Some(OperationResult::ObservedConvergence),
            failure_detail: None,
        };
        let operations = BTreeMap::from([(operation_id.clone(), operation)]);
        assert_eq!(
            connected_operation(&operations, &target, 7),
            Some(operation_id)
        );
        assert_eq!(connected_operation(&operations, &target, 8), None);
        assert_eq!(connected_operation(&operations, &other, 7), None);
    }

    #[test]
    fn openvpn_recovery_uses_receipt_operation_after_history_eviction() {
        let operation: OperationId =
            serde_json::from_str("\"op-0000000000000001-0000000000000001\"").unwrap();
        assert_eq!(
            recovered_openvpn_operation(&BTreeMap::new(), &profile_id('a'), 7, Some(&operation),),
            Some(operation),
        );
    }

    #[test]
    fn malformed_profile_blocks_only_commands_that_target_it() {
        let broken = VpnProfile {
            id: profile_id('a'),
            name: "broken".into(),
            protocol: Protocol::WireGuard,
            location: String::new(),
            config_path: "/missing.conf".into(),
            last_used: None,
        };
        let errors = BTreeMap::from([(broken.id.clone(), "profile parse failed".into())]);
        assert!(matches!(
            validate_command_target(
                std::slice::from_ref(&broken),
                &errors,
                &[],
                &UserCommand::Connect {
                    profile_id: broken.id.clone(),
                    conflict_acknowledgement: None,
                },
            ),
            Err(LocalControlError::Profile { .. })
        ));
        assert!(validate_command_target(
            &[broken],
            &errors,
            &[],
            &UserCommand::SetKillSwitch {
                mode: crate::state::KillSwitchMode::Off,
            },
        )
        .is_ok());
    }

    #[test]
    fn invalid_wireguard_filename_is_rejected_before_control_admission() {
        let profile = VpnProfile {
            id: profile_id('a'),
            name: "07-wireguard-split-ip".into(),
            protocol: Protocol::WireGuard,
            location: String::new(),
            config_path: "/profiles/07-wireguard-split-ip.conf".into(),
            last_used: None,
        };

        let error = validate_command_target(
            std::slice::from_ref(&profile),
            &BTreeMap::new(),
            &[],
            &UserCommand::Connect {
                profile_id: profile.id.clone(),
                conflict_acknowledgement: None,
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("1–15 characters"));
        assert!(error.to_string().contains("import it again"));
        assert!(validate_command_target(
            &[profile],
            &BTreeMap::new(),
            &[],
            &UserCommand::Disconnect {
                profile_id: Some(profile_id('a')),
            },
        )
        .is_ok());
    }

    #[test]
    fn topology_loading_retains_healthy_profiles_and_records_broken_ones() {
        let temp = tempfile::tempdir().unwrap();
        let healthy_path = temp.path().join("healthy.conf");
        std::fs::write(
            &healthy_path,
            "[Interface]\nPrivateKey = AAAA\n[Peer]\nPublicKey = BBBB\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.7:51820\n",
        )
        .unwrap();
        let healthy = VpnProfile {
            id: profile_id('a'),
            name: "healthy".into(),
            protocol: Protocol::WireGuard,
            location: String::new(),
            config_path: healthy_path,
            last_used: None,
        };
        let broken = VpnProfile {
            id: profile_id('b'),
            name: "broken".into(),
            protocol: Protocol::WireGuard,
            location: String::new(),
            config_path: temp.path().join("missing.conf"),
            last_used: None,
        };

        let (topologies, errors) = load_profile_topologies(
            &[healthy.clone(), broken.clone()],
            &mut EndpointResolutionCache::default(),
        );

        assert!(topologies.contains_key(&healthy.id));
        assert!(!topologies.contains_key(&broken.id));
        assert!(errors.contains_key(&broken.id));
        assert!(!errors.contains_key(&healthy.id));
        assert!(!canonical_owned_active(
            &std::collections::BTreeSet::from([broken.id.clone()]),
            &errors,
            &broken.id,
        ));
    }

    #[test]
    fn unowned_scanner_lookalike_cannot_make_connect_idempotently_succeed() {
        let profile = VpnProfile {
            id: profile_id('a'),
            name: "lookalike".into(),
            protocol: Protocol::OpenVPN,
            location: String::new(),
            config_path: "/lookalike.ovpn".into(),
            last_used: None,
        };
        assert!(matches!(
            validate_command_target(
                std::slice::from_ref(&profile),
                &BTreeMap::new(),
                std::slice::from_ref(&profile.name),
                &UserCommand::Connect {
                    profile_id: profile.id.clone(),
                    conflict_acknowledgement: None,
                },
            ),
            Err(LocalControlError::Recovery { .. })
        ));
        assert!(!canonical_owned_active(
            &std::collections::BTreeSet::new(),
            &BTreeMap::new(),
            &profile.id,
        ));
        assert!(canonical_owned_active(
            &std::collections::BTreeSet::from([profile.id.clone()]),
            &BTreeMap::new(),
            &profile.id,
        ));
    }

    #[test]
    fn challenge_response_errors_preserve_terminal_categories() {
        assert!(matches!(
            map_challenge_response_error(crate::vortix_core::control::ChallengeError::Expired),
            LocalControlError::ChallengeExpired
        ));
        assert!(matches!(
            map_challenge_response_error(crate::vortix_core::control::ChallengeError::Cancelled),
            LocalControlError::ChallengeCancelled
        ));
        assert!(matches!(
            map_challenge_response_error(crate::vortix_core::control::ChallengeError::Unauthorized),
            LocalControlError::Observation(message)
                if message.contains("client is not authorized")
        ));
    }

    #[tokio::test]
    async fn blocking_challenge_prompt_does_not_freeze_current_thread_runtime() {
        let challenge = crate::vortix_core::control::ChallengeRecord {
            id: serde_json::from_str("1").unwrap(),
            profile_id: profile_id('a'),
            operation_id: serde_json::from_str("\"op-0000000000000001-0000000000000001\"").unwrap(),
            kind: crate::vortix_core::control::ChallengeKind::TwoFactorCode,
            label: "OTP".into(),
            authorized_client: serde_json::from_str("\"client-0000000000000001-0000000000000001\"")
                .unwrap(),
            created_at_millis: 1,
            expires_at_millis: u64::MAX,
        };
        let responder = Arc::new(Mutex::new(
            |_challenge: &crate::vortix_core::control::ChallengeRecord| {
                std::thread::sleep(Duration::from_millis(40));
                Ok(crate::vortix_core::control::Secret::new(b"123456".to_vec()))
            },
        ));
        let response = tokio::spawn(invoke_challenge_responder(responder, challenge));

        tokio::time::timeout(Duration::from_millis(20), async {
            tokio::time::sleep(Duration::from_millis(5)).await;
        })
        .await
        .expect("runtime timer must progress while terminal input blocks");
        response.await.expect("responder task").expect("answer");
    }
}
