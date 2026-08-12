//! Standard-mode CLI adapter for the canonical in-process control service.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;
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
    ControlServiceConfig, ControlSnapshot, ControlStateStore, ExecutionSelection, IdempotencyKey,
    Observation, OperationId, OperationIntent, OperationRecord, OperationResult, OperationStatus,
    ProfileMutation, ProfileMutationApplied, ProfileMutationExecutor, ProfileMutationFailure,
    ProfileMutationWork, ProfileTopology, RealClock, RequestedTunnelState, UserCommand,
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

struct StandardProfileMutationExecutor {
    profiles_dir: std::path::PathBuf,
    profiles: Mutex<BTreeMap<ProfileId, VpnProfile>>,
    prepared_imports: Mutex<BTreeMap<ProfileId, crate::vpn::PreparedProfileImport>>,
    topologies: Mutex<BTreeMap<ProfileId, ProfileTopology>>,
    prepared_topologies: Mutex<BTreeMap<ProfileId, Option<ProfileTopology>>>,
    results:
        Mutex<BTreeMap<OperationId, Result<LocalProfileMutationReceipt, ProfileMutationFailure>>>,
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
        }
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
    service: ControlService,
    // The executor holds only a Weak edge, avoiding a service/supervisor cycle.
    challenge_issuer: Arc<crate::vortix_core::control::CompleterHandle>,
    hooks: Option<crate::hooks::HookRunner>,
    runtime: tokio::runtime::Runtime,
    profiles: Arc<Vec<VpnProfile>>,
    topology_errors: BTreeMap<ProfileId, String>,
    owned_active_profiles: std::collections::BTreeSet<ProfileId>,
    unowned_active_profiles: Vec<String>,
    sessions: Arc<Mutex<Vec<ActiveSession>>>,
    published_observations: RefCell<BTreeMap<ProfileId, (bool, Option<String>)>>,
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
    #[allow(clippy::too_many_lines)]
    pub fn start(
        config: &crate::config::AppConfig,
        config_dir: &Path,
        profiles: Vec<VpnProfile>,
    ) -> Result<Self, LocalControlError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
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
        let initial_sessions = crate::core::scanner::get_active_profiles(&profiles);
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

        let executor_profiles = Arc::clone(&core_profiles);
        let scanner_profiles = Arc::clone(&profiles);
        let executor_sessions = Arc::clone(&sessions);
        let session_resolver = move |profile_id: &ProfileId| {
            current_session(&scanner_profiles, &executor_sessions, profile_id)
        };
        let executor = Arc::new(CanonicalTunnelExecutor::new_standard(
            CanonicalTunnelSettings {
                config_dir: config_dir.to_path_buf(),
                openvpn_verbosity: config.openvpn_verbosity.clone(),
                connect_timeout_secs: config.connect_timeout,
                wireguard_handshake_timeout_secs: config.wireguard_handshake_timeout_secs,
                wireguard_health_targets: config.ping_targets.clone(),
            },
            move |profile_id| executor_profiles.get(profile_id).cloned(),
            Arc::clone(&ownership),
            session_resolver,
        ));

        let policy_profiles = Arc::clone(&profiles);
        let policy_session_profiles = Arc::clone(&profiles);
        let policy_sessions = Arc::clone(&sessions);
        let external_profiles = Arc::clone(&core_profiles);
        let external_ownership = Arc::clone(&ownership);
        let external_sessions = Arc::clone(&sessions);
        let external_active_profiles = external_session_profiles(
            &initial_sessions,
            &policy_profiles,
            &external_profiles,
            &external_ownership,
        );
        let policy = Arc::new(CanonicalPolicyExecutor::new(
            config_dir.to_path_buf(),
            move |profile_id| {
                current_session(&policy_session_profiles, &policy_sessions, profile_id)
            },
            move || {
                let sessions = external_sessions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                external_session_profiles(
                    &sessions,
                    &policy_profiles,
                    &external_profiles,
                    &external_ownership,
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

        let initial_kill_switch_mode = crate::core::killswitch::load_state()
            .map_or(crate::state::KillSwitchMode::Off, |state| state.mode);
        let service = ControlService::start_supervised(
            ControlServiceConfig {
                known_profiles: profiles.iter().map(|profile| profile.id.clone()).collect(),
                profile_topologies: topologies,
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
        let session = Self {
            service,
            challenge_issuer,
            hooks,
            runtime,
            profiles,
            topology_errors,
            owned_active_profiles,
            unowned_active_profiles,
            sessions,
            published_observations: RefCell::new(BTreeMap::new()),
        };
        session.runtime.block_on(async {
            session.publish_observations_from(initial_sessions).await?;
            session
                .service
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
                    let sessions = completed.await.map_err(|error| {
                        LocalControlError::Observation(format!(
                            "scanner worker did not complete: {error}"
                        ))
                    })?;
                    self.publish_observations_from(sessions).await?;
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
                    let profiles = Arc::clone(&self.profiles);
                    pending_scan = Some(tokio::task::spawn_blocking(move || {
                        crate::core::scanner::get_active_profiles(&profiles)
                    }));
                    last_scan_started = now;
                }
                tokio::time::sleep(CONTROL_PROGRESS_INTERVAL).await;
            }
        });
        if let Some(hooks) = self.hooks.take() {
            self.runtime
                .block_on(hooks.shutdown_bounded(HOOK_SHUTDOWN_GRACE));
        }
        // Tokio waits indefinitely for started `spawn_blocking` work when a
        // runtime is dropped. A scanner refresh may still be in flight after
        // the operation becomes terminal, so stop the service first and give
        // the runtime a finite drain window instead of extending CLI shutdown
        // to the duration of a slow platform probe.
        let _ = self.service.shutdown_bounded(SUPERVISED_SHUTDOWN_GRACE);
        drop(self.service);
        drop(self.challenge_issuer);
        self.runtime.shutdown_timeout(SHUTDOWN_GRACE);
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
                let profile = self
                    .profiles
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
            &self.profiles,
            &self.topology_errors,
            &self.unowned_active_profiles,
            command,
        )
    }

    async fn publish_observations_from(
        &self,
        sessions: Vec<ActiveSession>,
    ) -> Result<(), LocalControlError> {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone_from(&sessions);
        let observer = self.service.observer();
        let observed_at_millis = observer.now_millis();
        let changed = observation_changes(
            &self.profiles,
            &sessions,
            &self.published_observations.borrow(),
        );
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
        UserCommand::Connect { profile_id }
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
