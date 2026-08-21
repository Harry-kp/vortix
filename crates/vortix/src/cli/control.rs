//! Standard-mode CLI adapter for the canonical in-process control service.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
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
const TUI_ADMISSION_CAPACITY: usize = 8;

#[derive(Debug, Error)]
pub enum LocalControlError {
    #[error("cannot construct the local control runtime: {0}")]
    Runtime(String),
    #[error("cannot authenticate the Standard-mode configuration owner: {0}")]
    Owner(String),
    #[error("cannot parse profile '{profile}' for canonical control: {reason}")]
    Profile { profile: String, reason: String },
    #[error("cannot open durable local control state: {0}")]
    Persistence(String),
    #[error("cannot open Standard-mode tunnel ownership: {0}")]
    Ownership(String),
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

#[derive(Debug, Clone)]
pub struct LocalOperationOutcome {
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
}

#[derive(Debug)]
pub(crate) struct LocalCatalogUpdate {
    pub revision: u64,
    pub profiles: Vec<VpnProfile>,
    pub outcomes: Vec<Result<LocalProfileMutationReceipt, ProfileMutationFailure>>,
}

/// A durable admission result produced off the terminal thread. The permit is
/// retained until the TUI drains this value, so queued, executing, and
/// completed-but-undrained requests share one strict capacity bound.
pub(crate) struct LocalTuiAdmissionResult {
    pub command: UserCommand,
    pub operation_id: Result<OperationId, LocalControlError>,
    pub import_display_name: Option<String>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

struct TuiAdmissionJob {
    request: CommandRequest,
    command: UserCommand,
    import: Option<(ProfileId, String)>,
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
                if let Some((profile_id, _)) = &job.import {
                    profile_mutations.discard_prepared_import(profile_id);
                }
            }
            let import_display_name = job.import.map(|(_, display_name)| display_name);
            if result_sender
                .send(LocalTuiAdmissionResult {
                    command: job.command,
                    operation_id: result,
                    import_display_name,
                    _permit: job.permit,
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

struct StandardProfileMutationExecutor {
    profiles_dir: std::path::PathBuf,
    profiles: Mutex<BTreeMap<ProfileId, VpnProfile>>,
    prepared_imports: Mutex<BTreeMap<ProfileId, crate::vpn::PreparedProfileImport>>,
    topologies: Mutex<BTreeMap<ProfileId, ProfileTopology>>,
    prepared_topologies: Mutex<BTreeMap<ProfileId, Option<ProfileTopology>>>,
    results:
        Mutex<BTreeMap<OperationId, Result<LocalProfileMutationReceipt, ProfileMutationFailure>>>,
    catalog_revision: AtomicU64,
    #[cfg(test)]
    next_execution_delay: Mutex<Option<Duration>>,
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
        prepared_imports: Vec<crate::vpn::PreparedProfileImport>,
        topologies: BTreeMap<ProfileId, ProfileTopology>,
        prepared_topologies: BTreeMap<ProfileId, Option<ProfileTopology>>,
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
                    .map(|prepared| (prepared.profile().id.clone(), prepared))
                    .collect(),
            ),
            topologies: Mutex::new(topologies),
            prepared_topologies: Mutex::new(prepared_topologies),
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

    fn core_profiles_snapshot(&self) -> BTreeMap<ProfileId, Profile> {
        self.profiles_snapshot()
            .into_iter()
            .filter_map(|profile| {
                let profile_id = profile.id.clone();
                self.core_profile(&profile_id)
                    .map(|core| (profile_id, core))
            })
            .collect()
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
            .insert(profile_id.clone(), prepared);
        self.prepared_topologies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(profile_id.clone(), topology);
        profile_id
    }

    fn discard_prepared_import(&self, profile_id: &ProfileId) {
        self.prepared_imports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(profile_id);
        self.prepared_topologies
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
                let prepared = self
                    .prepared_imports
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&profile_id)
                    .ok_or(ProfileMutationFailure::NotFound)?;
                let topology = self
                    .prepared_topologies
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&profile_id)
                    .ok_or(ProfileMutationFailure::Internal)?;
                let profile = crate::vpn::commit_profile_import(prepared, &self.profiles_dir)
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
                let mut topology = self
                    .topologies
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&profile_id)
                    .cloned()
                    .ok_or(ProfileMutationFailure::Internal)?;
                let store = FsProfileStore::new(self.profiles_dir.clone());
                let renamed = store
                    .rename(&profile_id, &new_display_name)
                    .map_err(|error| Self::map_store_error(&error))?;
                profile.name = renamed.display_name;
                profile.config_path = renamed.config_path;
                topology.display_name = Some(profile.name.clone());
                self.profiles
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(profile_id.clone(), profile.clone());
                self.topologies
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(profile_id.clone(), topology.clone());
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

/// One short-lived Standard-mode authority. It starts no idle daemon; only a
/// tunnel-scoped protocol custodian may outlive this process.
pub struct LocalControlSession {
    // Drop the service while its Tokio runtime is still alive.
    service: Option<ControlService>,
    // The executor holds only a Weak edge, avoiding a service/supervisor cycle.
    _challenge_issuer: Arc<crate::vortix_core::control::CompleterHandle>,
    hooks: Option<crate::hooks::HookRunner>,
    runtime: Option<tokio::runtime::Runtime>,
    subscription: RefCell<ControlSubscription>,
    topology_errors: BTreeMap<ProfileId, String>,
    owned_active_profiles: std::collections::BTreeSet<ProfileId>,
    unowned_active_profiles: Vec<String>,
    sessions: Arc<Mutex<Vec<ActiveSession>>>,
    published_observations: RefCell<BTreeMap<ProfileId, (bool, Option<String>)>>,
    published_default_route:
        RefCell<crate::vortix_core::ports::route_table::DefaultRouteObservation>,
    published_tunnel_details: RefCell<BTreeMap<ProfileId, PublishedTunnelDetails>>,
    profile_mutations: Arc<StandardProfileMutationExecutor>,
    tui_admission: TuiAdmissionQueue,
    last_catalog_revision: Cell<u64>,
    reported_profile_operations: RefCell<std::collections::BTreeSet<OperationId>>,
    pending_scan: RefCell<
        Option<(
            u64,
            tokio::task::JoinHandle<crate::core::scanner::ScannerResult>,
        )>,
    >,
    last_scan_started: Cell<Instant>,
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
        let prepared_topologies = prepared_imports
            .iter()
            .map(|prepared| {
                let profile = prepared.topology_profile();
                let topology = topology_for_profile(&profile, &mut endpoint_cache).ok();
                (profile.id, topology)
            })
            .collect();
        persist_endpoint_cache_if_changed(&state_store, cache_bytes.as_deref(), &endpoint_cache)?;
        let profile_mutations = Arc::new(StandardProfileMutationExecutor::new(
            config_dir.join(crate::constants::PROFILES_DIR_NAME),
            profiles,
            prepared_imports,
            topologies.clone(),
            prepared_topologies,
        ));
        let service = ControlService::start_with_clock(
            ControlServiceConfig {
                known_profiles: profiles.iter().map(|profile| profile.id.clone()).collect(),
                profile_topologies: topologies,
                profile_mutations: Some(profile_mutations.clone()),
                authority_epoch: STANDARD_AUTHORITY_EPOCH,
                persistence: Some(ControlPersistenceConfig::new(boot_id, state_store)),
                freshness_poll_interval: CONTROL_PROGRESS_INTERVAL,
                ..ControlServiceConfig::default()
            },
            Arc::new(RealClock),
        );
        let sessions = crate::core::scanner::get_active_profiles(profiles);
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
    ) -> Result<LocalOperationOutcome, LocalControlError> {
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
                            return Ok(LocalOperationOutcome {
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
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("vortix-local-control-test")
            .enable_all()
            .build()
            .map_err(|error| LocalControlError::Runtime(error.to_string()))?;
        let profiles = Arc::new(profiles);
        let mut cache = EndpointResolutionCache::default();
        let (topologies, topology_errors) = load_profile_topologies(&profiles, &mut cache);
        let profile_mutations = Arc::new(StandardProfileMutationExecutor::new(
            config_dir.join(crate::constants::PROFILES_DIR_NAME),
            &profiles,
            Vec::new(),
            topologies.clone(),
            BTreeMap::new(),
        ));
        let service = {
            let _runtime_guard = runtime.enter();
            ControlService::start_with_clock(
                ControlServiceConfig {
                    known_profiles: profiles.iter().map(|profile| profile.id.clone()).collect(),
                    profile_topologies: topologies,
                    profile_mutations: Some(profile_mutations.clone()),
                    authority_epoch: STANDARD_AUTHORITY_EPOCH,
                    freshness_poll_interval: CONTROL_PROGRESS_INTERVAL,
                    persistence,
                    ..ControlServiceConfig::default()
                },
                Arc::new(RealClock),
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
        let subscription = service.client().subscribe();
        let tui_admission =
            start_tui_admission_queue(&runtime, service.client(), Arc::clone(&profile_mutations));
        Ok(Self {
            service: Some(service),
            _challenge_issuer: challenge_issuer,
            hooks: None,
            runtime: Some(runtime),
            subscription: RefCell::new(subscription),
            topology_errors,
            owned_active_profiles: std::collections::BTreeSet::new(),
            unowned_active_profiles: Vec::new(),
            sessions: Arc::new(Mutex::new(Vec::new())),
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
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("vortix-local-control")
            .enable_all()
            .build()
            .map_err(|error| LocalControlError::Runtime(error.to_string()))?;
        let _runtime_guard = runtime.enter();
        let profiles = Arc::new(profiles);
        let owner = config_owner(config_dir)?;
        let boot_id = crate::utils::boot_identity().ok_or_else(|| {
            LocalControlError::Persistence("OS boot identity is unavailable".into())
        })?;
        let state_store = Arc::new(FsControlStateStore::for_owner(
            config_dir.join("control"),
            owner.0,
            owner.1,
        ));
        let recovered = state_store
            .load(&boot_id)
            .map_err(|error| LocalControlError::Persistence(error.to_string()))?;
        let ownership = Arc::new(
            StandardTunnelOwnershipStore::production(owner.0)
                .map_err(|error| LocalControlError::Ownership(error.to_string()))?,
        );
        let initial_scan = crate::core::scanner::gather_system_state(&profiles);
        let initial_sessions = initial_scan.sessions.clone();
        let sessions = Arc::new(Mutex::new(initial_sessions.clone()));

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
            BTreeMap::new(),
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
            current_session(
                &scanner_catalog.profiles_snapshot(),
                &executor_sessions,
                profile_id,
            )
        };
        let executor = Arc::new(CanonicalTunnelExecutor::new_standard(
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
        ));

        let policy_profiles = Arc::clone(&profiles);
        let policy_catalog = Arc::clone(&profile_mutations);
        let policy_sessions = Arc::clone(&sessions);
        let external_catalog = Arc::clone(&profile_mutations);
        let external_ownership = Arc::clone(&ownership);
        let external_sessions = Arc::clone(&sessions);
        let external_active_profiles = external_session_profiles(
            &initial_sessions,
            &policy_profiles,
            &core_profiles,
            &external_ownership,
        );
        let policy = Arc::new(CanonicalPolicyExecutor::new(
            config_dir.to_path_buf(),
            move |profile_id| {
                current_session(
                    &policy_catalog.profiles_snapshot(),
                    &policy_sessions,
                    profile_id,
                )
            },
            move || {
                let sessions = external_sessions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let profiles = external_catalog.profiles_snapshot();
                let core_profiles = external_catalog.core_profiles_snapshot();
                external_session_profiles(&sessions, &profiles, &core_profiles, &external_ownership)
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

        let initial_kill_switch_mode = crate::core::killswitch::load_state()
            .map_or(crate::state::KillSwitchMode::Off, |state| state.mode);
        let service = ControlService::start_supervised(
            ControlServiceConfig {
                known_profiles: profiles.iter().map(|profile| profile.id.clone()).collect(),
                profile_topologies: topologies,
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
            hooks,
            runtime: Some(runtime),
            subscription: RefCell::new(subscription),
            topology_errors,
            owned_active_profiles,
            unowned_active_profiles,
            sessions,
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
        session.runtime().block_on(async {
            session.publish_observations_from(initial_scan).await?;
            session
                .service()
                .completer()
                .set_readiness(STANDARD_AUTHORITY_EPOCH, true, true)
                .await
                .map_err(|error| LocalControlError::Persistence(error.to_string()))
        })?;
        Ok(session)
    }

    pub fn run(
        self,
        command: UserCommand,
        wait: Duration,
        idempotency_key: impl Into<String>,
    ) -> Result<LocalOperationOutcome, LocalControlError> {
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
        let request = CommandRequest {
            command: command.clone(),
            idempotency_key: IdempotencyKey::new(idempotency_key),
            deadline: client.deadline_after(wait),
        };
        let queued = self.tui_admission.sender.try_send(TuiAdmissionJob {
            request,
            command,
            import: Some((profile_id.clone(), display_name.clone())),
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
            pending.as_ref().is_some_and(|(_, scan)| scan.is_finished())
        }
        .then(|| self.pending_scan.borrow_mut().take())
        .flatten();
        if let Some((catalog_revision, completed)) = completed {
            let scan = self.runtime().block_on(completed).map_err(|error| {
                LocalControlError::Observation(format!("scanner worker did not complete: {error}"))
            })?;
            if catalog_revision == self.profile_mutations.catalog_revision() {
                self.runtime()
                    .block_on(self.publish_observations_from(scan))?;
            }
        }

        let now = Instant::now();
        if self.pending_scan.borrow().is_none()
            && scanner_refresh_due(self.last_scan_started.get(), now)
        {
            let profiles = self.profile_mutations.profiles_snapshot();
            let scan = self
                .runtime()
                .handle()
                .spawn_blocking(move || crate::core::scanner::gather_system_state(&profiles));
            self.pending_scan
                .replace(Some((self.profile_mutations.catalog_revision(), scan)));
            self.last_scan_started.set(now);
        }
        self.runtime().block_on(tokio::task::yield_now());
        Ok(())
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
        for (operation_id, operation) in &snapshot.operations {
            if !operation.status.is_terminal()
                || !matches!(operation.intent, OperationIntent::ProfileMutation { .. })
                || !reported.insert(operation_id.clone())
            {
                continue;
            }
            if let Some(result) = self.profile_mutations.take_result(operation_id) {
                outcomes.push(result);
            }
        }
        let revision = self.profile_mutations.catalog_revision();
        if revision == self.last_catalog_revision.get() && outcomes.is_empty() {
            return None;
        }
        self.last_catalog_revision.set(revision);
        Some(LocalCatalogUpdate {
            revision,
            profiles: self.profile_mutations.profiles_snapshot(),
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

    pub fn cancel_challenge(
        &self,
        challenge_id: crate::vortix_core::control::ChallengeId,
    ) -> Result<(), LocalControlError> {
        self.runtime()
            .block_on(self.service().client().cancel_challenge(challenge_id))
            .map_err(map_challenge_response_error)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one bounded admission/challenge/observation wait loop"
    )]
    pub(crate) fn run_with_challenges<F>(
        mut self,
        command: UserCommand,
        wait: Duration,
        idempotency_key: impl Into<String>,
        answer_challenge: F,
    ) -> Result<LocalOperationOutcome, LocalControlError>
    where
        F: FnMut(
                &crate::vortix_core::control::ChallengeRecord,
            ) -> Result<crate::vortix_core::control::Secret, LocalControlError>
            + Send
            + 'static,
    {
        self.validate(&command)?;
        let challenge_responder = Arc::new(Mutex::new(answer_challenge));
        let result = self.runtime().block_on(async {
            let client = self.service().client();
            let admitted = client
                .submit(CommandRequest {
                    command,
                    idempotency_key: IdempotencyKey::new(idempotency_key),
                    deadline: client.deadline_after(wait),
                })
                .await
                .map_err(LocalControlError::Admission)?;
            let wall_deadline = Instant::now() + wait + SHUTDOWN_GRACE;
            // Startup already performed and published one immediate scan.
            // Start the first post-admission refresh immediately so a fast
            // tunnel effect is observed without waiting for a cadence tick.
            let mut last_scan_started = Instant::now()
                .checked_sub(SCANNER_REFRESH_CEILING)
                .unwrap_or_else(Instant::now);
            let mut pending_scan = None;
            let mut handled_challenges = std::collections::BTreeSet::new();
            let mut challenge_input_error = None;
            loop {
                if pending_scan
                    .as_ref()
                    .is_some_and(tokio::task::JoinHandle::is_finished)
                {
                    let completed = pending_scan.take().expect("finished scan checked");
                    let scan = completed.await.map_err(|error| {
                        LocalControlError::Observation(format!(
                            "scanner worker did not complete: {error}"
                        ))
                    })?;
                    self.publish_observations_from(scan).await?;
                }
                let snapshot = client.snapshot();
                let pending_challenges = snapshot
                    .challenges
                    .values()
                    .filter(|challenge| {
                        challenge.operation_id == admitted.operation_id
                            && &challenge.authorized_client == client.client_id()
                            && !handled_challenges.contains(&challenge.id)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                let mut handled_challenge_this_tick = false;
                for challenge in &pending_challenges {
                    handled_challenges.insert(challenge.id);
                    handled_challenge_this_tick = true;
                    let answer = invoke_challenge_responder(
                        Arc::clone(&challenge_responder),
                        challenge.clone(),
                    )
                    .await;
                    match answer {
                        Ok(answer) => client
                            .respond_challenge(challenge.id, answer)
                            .await
                            .map_err(map_challenge_response_error)?,
                        Err(error) => {
                            let _ = client.cancel_challenge(challenge.id).await;
                            if challenge_input_error.is_none() {
                                challenge_input_error = Some(error);
                            }
                        }
                    }
                }
                if handled_challenge_this_tick {
                    // `respond_challenge` acknowledges inside the actor before
                    // the resulting snapshot publication. Never decide from
                    // the older snapshot captured above.
                    tokio::task::yield_now().await;
                    continue;
                }
                if let Some(operation) = snapshot.operations.get(&admitted.operation_id) {
                    if operation.status.is_terminal() {
                        if let Some(error) = challenge_input_error {
                            return Err(error);
                        }
                        return Ok(LocalOperationOutcome {
                            profile_mutation: None,
                            operation_id: admitted.operation_id,
                            status: operation.status,
                            result: operation.result,
                            snapshot,
                        });
                    }
                }
                if Instant::now() >= wall_deadline {
                    return Err(LocalControlError::Stopped);
                }
                let now = Instant::now();
                if pending_scan.is_none() && scanner_refresh_due(last_scan_started, now) {
                    let profiles = self.profile_mutations.profiles_snapshot();
                    pending_scan = Some(tokio::task::spawn_blocking(move || {
                        crate::core::scanner::gather_system_state(&profiles)
                    }));
                    last_scan_started = now;
                }
                tokio::time::sleep(CONTROL_PROGRESS_INTERVAL).await;
            }
        });
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
    ) -> Result<(), LocalControlError> {
        let sessions = scan.sessions;
        let profiles = self.profile_mutations.profiles_snapshot();
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone_from(&sessions);
        let observer = self.service().observer();
        let observed_at_millis = observer.now_millis();
        let default_route = scan.default_route;
        let default_route_changed = !matches!(
            default_route,
            crate::vortix_core::ports::route_table::DefaultRouteObservation::ProbeFailed
        ) && *self.published_default_route.borrow() != default_route;
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
            observer
                .observe(Observation::DefaultRoute {
                    interface_name,
                    observed_at_millis,
                })
                .await
                .map_err(|error| LocalControlError::Observation(error.to_string()))?;
            self.published_default_route.replace(default_route);
        }
        let mut observed_detail_profiles = std::collections::BTreeSet::new();
        for session in &sessions {
            let Some(profile) = profiles.iter().find(|profile| profile.name == session.name) else {
                continue;
            };
            observed_detail_profiles.insert(profile.id.clone());
            let published = PublishedTunnelDetails {
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
            };
            let changed =
                self.published_tunnel_details.borrow().get(&profile.id) != Some(&published);
            if changed {
                observer
                    .observe(Observation::TunnelDetails {
                        profile_id: profile.id.clone(),
                        details: Box::new(published.details.clone()),
                        started_at: published.started_at,
                        observed_at_millis,
                    })
                    .await
                    .map_err(|error| LocalControlError::Observation(error.to_string()))?;
                self.published_tunnel_details
                    .borrow_mut()
                    .insert(profile.id.clone(), published);
            }
        }
        self.published_tunnel_details
            .borrow_mut()
            .retain(|profile_id, _| observed_detail_profiles.contains(profile_id));
        let changed =
            observation_changes(&profiles, &sessions, &self.published_observations.borrow());
        for (profile_id, state) in changed {
            observer
                .observe(Observation::Tunnel {
                    profile_id: profile_id.clone(),
                    active: state.0,
                    interface_name: state.1.clone(),
                    observed_at_millis,
                    protection: None,
                })
                .await
                .map_err(|error| LocalControlError::Observation(error.to_string()))?;
            self.published_observations
                .borrow_mut()
                .insert(profile_id, state);
        }
        Ok(())
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
    profiles: &[VpnProfile],
    sessions: &Mutex<Vec<ActiveSession>>,
    profile_id: &ProfileId,
) -> Option<ActiveSession> {
    let profile = profiles.iter().find(|profile| &profile.id == profile_id)?;
    sessions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|session| session.name == profile.name)
        .cloned()
}

fn external_session_profiles(
    sessions: &[ActiveSession],
    profiles: &[VpnProfile],
    canonical: &BTreeMap<ProfileId, Profile>,
    ownership: &StandardTunnelOwnershipStore,
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
    use std::os::unix::fs::MetadataExt as _;
    let metadata = std::fs::symlink_metadata(config_dir)
        .map_err(|error| LocalControlError::Owner(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LocalControlError::Owner(
            "configuration path is not a real directory".into(),
        ));
    }
    let effective = crate::utils::effective_user_group_ids();
    if effective.0 != 0 {
        return (metadata.uid() == effective.0)
            .then_some(effective)
            .ok_or_else(|| LocalControlError::Owner("configuration owner mismatch".into()));
    }
    let uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(metadata.uid());
    let gid = std::env::var("SUDO_GID")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(metadata.gid());
    (metadata.uid() == uid)
        .then_some((uid, gid))
        .ok_or_else(|| LocalControlError::Owner("sudo owner does not own configuration".into()))
}

#[cfg(not(unix))]
pub(crate) fn config_owner(_config_dir: &Path) -> Result<(u32, u32), LocalControlError> {
    Err(LocalControlError::Owner(
        "Standard-mode canonical control is unsupported on this platform".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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
                assert!(result.operation_id.is_ok());
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
        let session = LocalControlSession::start_profile_test(temp.path(), vec![profile]).unwrap();
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
        };
        let profile_id = profile_id('c');
        session.current_snapshot();
        session
            .runtime()
            .block_on(session.publish_observations_from(scan()))
            .unwrap();
        // `observe` acknowledges actor receipt before the final publication,
        // so consume snapshots until all three semantic facts from the first
        // scan are visible. A generation count can be satisfied by unrelated
        // actor publications and would leave a scan publication in flight.
        let settle_deadline = Instant::now() + Duration::from_secs(1);
        loop {
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
                break;
            }
            assert!(
                Instant::now() < settle_deadline,
                "first scanner publication did not settle"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        while session.take_changed_snapshot().unwrap().is_some() {}
        let published_default_route = session.published_default_route.borrow().clone();
        let published_tunnel_details = session.published_tunnel_details.borrow().clone();
        let published_observations = session.published_observations.borrow().clone();

        session
            .runtime()
            .block_on(session.publish_observations_from(scan()))
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
                    expiring_id = Some(result.operation_id.unwrap());
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
            .prepared_topologies
            .lock()
            .unwrap()
            .is_empty());
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
                assert!(result.operation_id.is_err());
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
    fn openvpn_recovery_rejects_a_scanner_pid_that_is_not_the_custodian_child() {
        let session = ActiveSession {
            pid: Some(43),
            interface: "tun0".into(),
            interface_authoritative: true,
            ..ActiveSession::default()
        };
        assert!(!crate::tunnel::standard_openvpn_scanner_pid_matches(
            session.pid,
            42,
        ));
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
