use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tempfile::tempdir;
use vortix::vortix_config::control_state::FsControlStateStore;
use vortix::vortix_core::control::supervisor::Supervisor;
use vortix::vortix_core::control::worker::{
    CancellationToken, PolicyBarrier, PolicyExecutor, PolicyStage, TopologyPolicy,
    TunnelExecutionReceipt, TunnelExecutor, TunnelWork,
};
use vortix::vortix_core::control::{
    AdmissionError, AuthorityEpoch, BootConnection, BootEligibility, CommandRequest,
    CompletionError, CompletionOutcome, ControlPersistenceConfig, ControlService,
    ControlServiceConfig, ControlStateStore, ControlStateStoreError, Deadline, DesiredState,
    DurableControlState, ExecutionSelection, GateEvidence, IdempotencyKey, Observation,
    OperationCompletion, OperationFailure, OperationId, OperationIntent, OperationRecord,
    OperationResult, OperationStatus, PolicyDigest, ProfileMutation, ProfileMutationApplied,
    ProfileMutationExecutor, ProfileMutationFailure, ProfileMutationWork, ProfileTopology,
    ProtectionEvidence, ReadinessError, RecoveredControlState, RequestedTunnelState,
    RetentionMetadata, UserCommand,
};
use vortix::vortix_core::ports::tunnel::TunnelKindTag;
use vortix::vortix_core::profile::ProfileId;

fn topology_catalog(profile_id: &ProfileId) -> BTreeMap<ProfileId, ProfileTopology> {
    BTreeMap::from([(profile_id.clone(), ProfileTopology::default())])
}

fn retained_terminal_operation(
    authority_epoch: AuthorityEpoch,
    desired_generation: u64,
    command_digest: &PolicyDigest,
    sequence: u64,
) -> (OperationId, OperationRecord) {
    let operation_id =
        OperationId::parse(format!("op-{:016x}-{sequence:016x}", authority_epoch.0)).unwrap();
    let client_id = serde_json::from_str(&format!(
        "\"client-{:016x}-{sequence:016x}\"",
        authority_epoch.0
    ))
    .unwrap();
    (
        operation_id.clone(),
        OperationRecord {
            id: operation_id,
            idempotency_key: IdempotencyKey::new(format!("retained-{sequence}")),
            client_id,
            command_digest: command_digest.clone(),
            authority_epoch,
            desired_generation,
            admitted_at_millis: 0,
            deadline_millis: u64::MAX,
            intent: OperationIntent::GenerationScoped,
            status: OperationStatus::Succeeded,
            result: Some(OperationResult::ObservedConvergence),
            failure_detail: None,
        },
    )
}

#[derive(Debug, Default)]
struct RecordingStore {
    saves: AtomicUsize,
    fail: AtomicBool,
    state: Mutex<Option<DurableControlState>>,
}

#[derive(Debug)]
struct SlowStore {
    entered: Arc<AtomicBool>,
}

impl ControlStateStore for SlowStore {
    fn load(
        &self,
        _current_boot_id: &str,
    ) -> Result<Option<RecoveredControlState>, ControlStateStoreError> {
        Ok(None)
    }

    fn save(
        &self,
        _current_boot_id: &str,
        _state: &DurableControlState,
    ) -> Result<(), ControlStateStoreError> {
        self.entered.store(true, Ordering::Release);
        std::thread::sleep(Duration::from_millis(100));
        Ok(())
    }
}

impl ControlStateStore for RecordingStore {
    fn load(
        &self,
        _current_boot_id: &str,
    ) -> Result<Option<RecoveredControlState>, ControlStateStoreError> {
        Ok(self
            .state
            .lock()
            .expect("recording store mutex poisoned")
            .clone()
            .map(|state| RecoveredControlState {
                state,
                same_boot: true,
            }))
    }

    fn save(
        &self,
        _current_boot_id: &str,
        state: &DurableControlState,
    ) -> Result<(), ControlStateStoreError> {
        if self.fail.load(Ordering::Acquire) {
            Err(ControlStateStoreError::Io("injected disk failure".into()))
        } else {
            self.saves.fetch_add(1, Ordering::AcqRel);
            self.state
                .lock()
                .expect("recording store mutex poisoned")
                .replace(state.clone());
            Ok(())
        }
    }
}

struct SaveOrderedExecutor {
    store: Arc<RecordingStore>,
    ran_after_save: Arc<AtomicBool>,
}

struct CountingExecutor(Arc<AtomicUsize>);

impl TunnelExecutor for CountingExecutor {
    fn execute(
        &self,
        work: &TunnelWork,
        _cancel: &CancellationToken,
    ) -> Result<TunnelExecutionReceipt, String> {
        self.0.fetch_add(1, Ordering::AcqRel);
        TunnelExecutionReceipt::attested(
            work.profile_id.clone(),
            "tun-restarted",
            TunnelKindTag::Mock,
            None,
            "restart-attestation-1",
        )
    }
}

impl TunnelExecutor for SaveOrderedExecutor {
    fn execute(
        &self,
        work: &TunnelWork,
        _cancel: &CancellationToken,
    ) -> Result<TunnelExecutionReceipt, String> {
        self.ran_after_save.store(
            self.store.saves.load(Ordering::Acquire) > 0,
            Ordering::Release,
        );
        TunnelExecutionReceipt::attested(
            work.profile_id.clone(),
            "tun-recovered",
            TunnelKindTag::Mock,
            None,
            "recovery-attestation-1",
        )
    }
}

struct OkPolicy;

#[derive(Debug)]
struct DeleteProfile;

impl ProfileMutationExecutor for DeleteProfile {
    fn execute(
        &self,
        work: ProfileMutationWork,
    ) -> Result<ProfileMutationApplied, ProfileMutationFailure> {
        let ProfileMutation::Delete { profile_id } = work.mutation else {
            return Err(ProfileMutationFailure::Internal);
        };
        Ok(ProfileMutationApplied::Deleted { profile_id })
    }
}

impl PolicyExecutor for OkPolicy {
    fn apply(&self, _policy: &TopologyPolicy, _barrier: PolicyBarrier) -> Result<(), String> {
        Ok(())
    }

    fn compensate(&self, _policy: &TopologyPolicy, _barrier: PolicyBarrier) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Default)]
struct RestartOrder(Mutex<Vec<&'static str>>);

impl TunnelExecutor for RestartOrder {
    fn execute(
        &self,
        work: &TunnelWork,
        _cancel: &CancellationToken,
    ) -> Result<TunnelExecutionReceipt, String> {
        self.0.lock().unwrap().push("tunnel");
        TunnelExecutionReceipt::attested(
            work.profile_id.clone(),
            "tun-restarted-recovery",
            TunnelKindTag::Mock,
            None,
            "restart-recovery-attestation-1",
        )
    }
}

impl PolicyExecutor for RestartOrder {
    fn apply(&self, policy: &TopologyPolicy, barrier: PolicyBarrier) -> Result<(), String> {
        if policy.stage == PolicyStage::PreTunnelBlocking && barrier == PolicyBarrier::Blocking {
            self.0.lock().unwrap().push("preblock");
        }
        Ok(())
    }

    fn compensate(&self, _policy: &TopologyPolicy, _barrier: PolicyBarrier) -> Result<(), String> {
        Ok(())
    }
}

#[tokio::test]
async fn same_boot_unexpected_recovery_reconstructs_preblock_before_reconnect() {
    let profile_id = ProfileId::parse("d".repeat(ProfileId::HEX_LEN)).unwrap();
    let operation_id: OperationId =
        serde_json::from_str("\"op-000000000000000b-0000000000000001\"").unwrap();
    let desired = DesiredState {
        generation: 7,
        tunnels: BTreeMap::from([(profile_id.clone(), RequestedTunnelState::Connected)]),
        conflict_acknowledgements: BTreeMap::new(),
        kill_switch: vortix::vortix_core::state::killswitch::KillSwitchMode::Auto,
        authority_epoch: AuthorityEpoch(11),
        policy_digest: PolicyDigest("restart-recovery-policy".into()),
    };
    let operation = OperationRecord {
        id: operation_id.clone(),
        idempotency_key: IdempotencyKey::new("persisted-unexpected-recovery"),
        client_id: serde_json::from_str("\"client-000000000000000b-0000000000000001\"").unwrap(),
        command_digest: desired.policy_digest.clone(),
        authority_epoch: AuthorityEpoch(11),
        desired_generation: desired.generation,
        admitted_at_millis: 0,
        deadline_millis: u64::MAX,
        intent: OperationIntent::UnexpectedRecovery {
            profile_id: profile_id.clone(),
            tunnels: desired.tunnels.clone(),
            kill_switch: Some(desired.kill_switch),
        },
        status: OperationStatus::WaitingForObservation,
        result: None,
        failure_detail: None,
    };
    let store = Arc::new(RecordingStore {
        state: Mutex::new(Some(DurableControlState {
            desired,
            operations: BTreeMap::from([(operation_id, operation)]),
            boot_connections: BTreeMap::new(),
            requested_resources: BTreeMap::new(),
            last_connected_at: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            retention: RetentionMetadata::default(),
            reconciliation_required: true,
        })),
        ..RecordingStore::default()
    });
    let order = Arc::new(RestartOrder::default());
    let service = ControlService::start_supervised(
        ControlServiceConfig {
            authority_epoch: AuthorityEpoch(11),
            known_profiles: BTreeSet::from([profile_id.clone()]),
            profile_topologies: topology_catalog(&profile_id),
            persistence: Some(ControlPersistenceConfig::new("boot-a", store)),
            retry_initial_backoff: Duration::ZERO,
            freshness_poll_interval: Duration::from_millis(5),
            ..ControlServiceConfig::default()
        },
        Arc::new(vortix::vortix_core::control::RealClock),
        ExecutionSelection::CanonicalAuthority,
        Arc::new(Supervisor::new(
            AuthorityEpoch(11),
            order.clone(),
            order.clone(),
            1,
            4,
        )),
    );
    service
        .observer()
        .observe(Observation::Tunnel {
            profile_id,
            active: false,
            interface_name: None,
            observed_at_millis: 0,
            protection: None,
        })
        .await
        .unwrap();
    service
        .completer()
        .set_readiness(AuthorityEpoch(11), true, true)
        .await
        .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while order.0.lock().unwrap().len() < 2 {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::task::yield_now().await;
    }
    assert_eq!(&*order.0.lock().unwrap(), &["preblock", "tunnel"]);
}

#[tokio::test]
async fn restart_restores_canonical_last_connected_time() {
    let profile_id = ProfileId::new("last-connected-recovery");
    let connected_at = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(9_876);
    let desired = DesiredState {
        authority_epoch: AuthorityEpoch(15),
        ..DesiredState::default()
    };
    let store = Arc::new(RecordingStore {
        state: Mutex::new(Some(DurableControlState {
            desired,
            operations: BTreeMap::new(),
            boot_connections: BTreeMap::new(),
            requested_resources: BTreeMap::new(),
            last_connected_at: BTreeMap::from([(profile_id.clone(), connected_at)]),
            tombstones: BTreeMap::new(),
            retention: RetentionMetadata::default(),
            reconciliation_required: true,
        })),
        ..RecordingStore::default()
    });

    let service = ControlService::start(ControlServiceConfig {
        authority_epoch: AuthorityEpoch(15),
        known_profiles: BTreeSet::from([profile_id.clone()]),
        profile_topologies: topology_catalog(&profile_id),
        persistence: Some(ControlPersistenceConfig::new("boot-a", store)),
        ..ControlServiceConfig::default()
    });

    assert_eq!(
        service.client().snapshot().last_connected_at[&profile_id],
        connected_at
    );
}

#[tokio::test]
async fn persistence_failure_keeps_startup_non_admitting() {
    let store = Arc::new(RecordingStore::default());
    store.fail.store(true, Ordering::Release);
    let service = ControlService::start(ControlServiceConfig {
        authority_epoch: AuthorityEpoch(4),
        persistence: Some(ControlPersistenceConfig::new("boot-a", store)),
        ..ControlServiceConfig::default()
    });

    assert_eq!(
        service
            .completer()
            .set_readiness(AuthorityEpoch(4), true, true)
            .await
            .unwrap_err(),
        ReadinessError::Persistence
    );
    assert!(
        !service
            .client()
            .snapshot()
            .readiness
            .reconciliation_complete
    );
    assert_eq!(
        service
            .client()
            .submit(CommandRequest {
                command: UserCommand::Disconnect { profile_id: None },
                idempotency_key: IdempotencyKey::new("must-not-admit"),
                deadline: service.client().deadline_after(Duration::from_secs(1)),
            })
            .await
            .unwrap_err(),
        AdmissionError::NotReady
    );
}

#[tokio::test]
async fn full_durable_history_compacts_before_startup_recovery_is_persisted() {
    let directory = tempdir().unwrap();
    let store = Arc::new(FsControlStateStore::new(directory.path().join("control")));
    let authority_epoch = AuthorityEpoch(19);
    let desired = DesiredState {
        generation: 1,
        authority_epoch,
        policy_digest: PolicyDigest(format!("sha256:{}", "a".repeat(64))),
        ..DesiredState::default()
    };
    let oldest_operation_id = OperationId::parse("op-0000000000000013-0000000000000001").unwrap();
    let live_operation_id = OperationId::parse("op-0000000000000013-0000000000000200").unwrap();
    let mut operations: BTreeMap<OperationId, OperationRecord> = (1_u64..=511)
        .map(|sequence| {
            retained_terminal_operation(
                authority_epoch,
                desired.generation,
                &desired.policy_digest,
                sequence,
            )
        })
        .collect();
    operations.insert(
        live_operation_id.clone(),
        OperationRecord {
            id: live_operation_id.clone(),
            idempotency_key: IdempotencyKey::new("live-operation"),
            client_id: serde_json::from_str("\"client-0000000000000013-0000000000000200\"")
                .unwrap(),
            command_digest: desired.policy_digest.clone(),
            authority_epoch,
            desired_generation: 0,
            admitted_at_millis: 0,
            deadline_millis: u64::MAX,
            intent: OperationIntent::GenerationScoped,
            status: OperationStatus::WaitingForObservation,
            result: None,
            failure_detail: None,
        },
    );
    store
        .save(
            "boot-a",
            &DurableControlState {
                desired,
                operations,
                boot_connections: BTreeMap::new(),
                requested_resources: BTreeMap::new(),
                last_connected_at: BTreeMap::new(),
                tombstones: BTreeMap::new(),
                retention: RetentionMetadata::default(),
                reconciliation_required: true,
            },
        )
        .unwrap();
    let service = ControlService::start_supervised(
        ControlServiceConfig {
            authority_epoch,
            persistence: Some(ControlPersistenceConfig::new("boot-a", store.clone())),
            ..ControlServiceConfig::default()
        },
        Arc::new(vortix::vortix_core::control::RealClock),
        ExecutionSelection::CanonicalAuthority,
        Arc::new(Supervisor::new(
            authority_epoch,
            Arc::new(CountingExecutor(Arc::new(AtomicUsize::new(0)))),
            Arc::new(OkPolicy),
            1,
            4,
        )),
    );

    service
        .completer()
        .set_readiness(authority_epoch, true, true)
        .await
        .expect("startup recovery must compact terminal history before persisting");
    let snapshot = service.client().snapshot();
    assert_eq!(snapshot.operations.len(), 512);
    assert!(!snapshot.operations.contains_key(&oldest_operation_id));
    assert!(snapshot.operations.contains_key(&live_operation_id));
    let recovered = store.load("boot-a").unwrap().unwrap();
    assert_eq!(recovered.state.operations.len(), 512);
    assert_eq!(recovered.state.retention.compacted_operations, 1);
}

#[tokio::test]
async fn unchanged_readiness_does_not_rewrite_durable_state() {
    let store = Arc::new(RecordingStore::default());
    let service = ControlService::start(ControlServiceConfig {
        authority_epoch: AuthorityEpoch(5),
        persistence: Some(ControlPersistenceConfig::new("boot-a", store.clone())),
        ..ControlServiceConfig::default()
    });
    service
        .completer()
        .set_readiness(AuthorityEpoch(5), true, true)
        .await
        .unwrap();
    let writes = store.saves.load(Ordering::Acquire);
    service
        .completer()
        .set_readiness(AuthorityEpoch(5), true, true)
        .await
        .unwrap();
    assert_eq!(store.saves.load(Ordering::Acquire), writes);
}

#[tokio::test(flavor = "current_thread")]
async fn durable_fsync_does_not_block_the_control_runtime_thread() {
    let entered = Arc::new(AtomicBool::new(false));
    let service = ControlService::start(ControlServiceConfig {
        authority_epoch: AuthorityEpoch(6),
        persistence: Some(ControlPersistenceConfig::new(
            "boot-a",
            Arc::new(SlowStore {
                entered: entered.clone(),
            }),
        )),
        ..ControlServiceConfig::default()
    });
    let completer = service.completer();
    let readiness =
        tokio::spawn(async move { completer.set_readiness(AuthorityEpoch(6), true, true).await });
    while !entered.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(!readiness.is_finished());
    readiness.await.unwrap().unwrap();
}

#[tokio::test]
async fn desired_intent_is_saved_before_supervised_effect_dispatch() {
    let store = Arc::new(RecordingStore::default());
    let ran_after_save = Arc::new(AtomicBool::new(false));
    let profile_id = ProfileId::new("persist-before-effect");
    let supervisor = Arc::new(Supervisor::new(
        AuthorityEpoch(8),
        Arc::new(SaveOrderedExecutor {
            store: store.clone(),
            ran_after_save: ran_after_save.clone(),
        }),
        Arc::new(OkPolicy),
        1,
        4,
    ));
    let service = ControlService::start_supervised(
        ControlServiceConfig {
            authority_epoch: AuthorityEpoch(8),
            known_profiles: BTreeSet::from([profile_id.clone()]),
            profile_topologies: topology_catalog(&profile_id),
            persistence: Some(ControlPersistenceConfig::new("boot-a", store.clone())),
            freshness_poll_interval: Duration::from_millis(5),
            ..ControlServiceConfig::default()
        },
        Arc::new(vortix::vortix_core::control::RealClock),
        ExecutionSelection::CanonicalAuthority,
        supervisor,
    );
    service
        .completer()
        .set_readiness(AuthorityEpoch(8), true, true)
        .await
        .unwrap();
    store.saves.store(0, Ordering::Release);

    service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Connect {
                profile_id: profile_id.clone(),
                conflict_acknowledgement: None,
            },
            idempotency_key: IdempotencyKey::new("save-before-connect"),
            deadline: Deadline(u64::MAX),
        })
        .await
        .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while !ran_after_save.load(Ordering::Acquire) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "supervised effect did not observe a prior durable save"
        );
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn failed_mutation_save_is_retried_before_effect_dispatch() {
    let store = Arc::new(RecordingStore::default());
    let executions = Arc::new(AtomicUsize::new(0));
    let profile_id = ProfileId::new("retry-persistence-before-effect");
    let service = ControlService::start_supervised(
        ControlServiceConfig {
            authority_epoch: AuthorityEpoch(11),
            known_profiles: BTreeSet::from([profile_id.clone()]),
            profile_topologies: topology_catalog(&profile_id),
            persistence: Some(ControlPersistenceConfig::new("boot-a", store.clone())),
            freshness_poll_interval: Duration::from_millis(5),
            ..ControlServiceConfig::default()
        },
        Arc::new(vortix::vortix_core::control::RealClock),
        ExecutionSelection::CanonicalAuthority,
        Arc::new(Supervisor::new(
            AuthorityEpoch(11),
            Arc::new(CountingExecutor(executions.clone())),
            Arc::new(OkPolicy),
            1,
            4,
        )),
    );
    service
        .completer()
        .set_readiness(AuthorityEpoch(11), true, true)
        .await
        .unwrap();
    store.fail.store(true, Ordering::Release);

    assert_eq!(
        service
            .client()
            .submit(CommandRequest {
                command: UserCommand::Connect {
                    profile_id: profile_id.clone(),
                    conflict_acknowledgement: None,
                },
                idempotency_key: IdempotencyKey::new("retry-after-disk-failure"),
                deadline: Deadline(u64::MAX),
            })
            .await,
        Err(AdmissionError::Persistence)
    );
    assert_eq!(executions.load(Ordering::Acquire), 0);
    assert!(
        !service
            .client()
            .snapshot()
            .readiness
            .reconciliation_complete
    );

    store.fail.store(false, Ordering::Release);
    service
        .completer()
        .set_readiness(AuthorityEpoch(11), true, true)
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while executions.load(Ordering::Acquire) == 0 {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::task::yield_now().await;
    }
    assert_eq!(executions.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn terminal_reply_waits_for_durable_operation_result() {
    let store = Arc::new(RecordingStore::default());
    let profile_id = ProfileId::new("durable-terminal-reply");
    let service = ControlService::start(ControlServiceConfig {
        authority_epoch: AuthorityEpoch(12),
        known_profiles: BTreeSet::from([profile_id.clone()]),
        profile_topologies: topology_catalog(&profile_id),
        persistence: Some(ControlPersistenceConfig::new("boot-a", store.clone())),
        ..ControlServiceConfig::default()
    });
    service
        .completer()
        .set_readiness(AuthorityEpoch(12), true, true)
        .await
        .unwrap();
    let admitted = service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Connect {
                profile_id,
                conflict_acknowledgement: None,
            },
            idempotency_key: IdempotencyKey::new("terminal-durability"),
            deadline: Deadline(u64::MAX),
        })
        .await
        .unwrap();
    store.fail.store(true, Ordering::Release);

    assert_eq!(
        service
            .completer()
            .complete(OperationCompletion {
                operation_id: admitted.operation_id.clone(),
                desired_generation: 1,
                outcome: CompletionOutcome::Failed(OperationFailure::ObservationFailed),
            })
            .await,
        Err(CompletionError::Persistence)
    );
    assert_eq!(
        store.state.lock().unwrap().as_ref().unwrap().operations[&admitted.operation_id].status,
        OperationStatus::WaitingForObservation
    );
}

#[tokio::test]
async fn failed_terminal_persistence_does_not_publish_last_connected_activity() {
    let store = Arc::new(RecordingStore::default());
    let profile_id = ProfileId::new("failed-activity-persistence");
    let service = ControlService::start(ControlServiceConfig {
        authority_epoch: AuthorityEpoch(16),
        known_profiles: BTreeSet::from([profile_id.clone()]),
        profile_topologies: topology_catalog(&profile_id),
        persistence: Some(ControlPersistenceConfig::new("boot-a", store.clone())),
        ..ControlServiceConfig::default()
    });
    service
        .completer()
        .set_readiness(AuthorityEpoch(16), true, true)
        .await
        .unwrap();
    let admitted = service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Connect {
                profile_id: profile_id.clone(),
                conflict_acknowledgement: None,
            },
            idempotency_key: IdempotencyKey::new("activity-persistence-failure"),
            deadline: Deadline(u64::MAX),
        })
        .await
        .unwrap();
    let connected_at = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(123);
    let observed_at_millis = service.observer().now_millis();
    service
        .observer()
        .observe_batch(vec![
            Observation::TunnelDetails {
                profile_id: profile_id.clone(),
                details: Box::default(),
                started_at: Some(connected_at),
                observed_at_millis,
            },
            Observation::Tunnel {
                profile_id: profile_id.clone(),
                active: true,
                interface_name: Some("utun9".into()),
                observed_at_millis,
                protection: None,
            },
        ])
        .await
        .unwrap();
    let desired = service.client().snapshot().desired;
    store.fail.store(true, Ordering::Release);

    assert_eq!(
        service
            .completer()
            .complete(OperationCompletion {
                operation_id: admitted.operation_id,
                desired_generation: desired.generation,
                outcome: CompletionOutcome::ObservedSuccess(ProtectionEvidence {
                    desired_generation: desired.generation,
                    authority_epoch: desired.authority_epoch,
                    policy_digest: desired.policy_digest,
                    observed_at_millis,
                    interface: GateEvidence::Verified,
                    route: GateEvidence::Verified,
                    dns: GateEvidence::Verified,
                    firewall: GateEvidence::Verified,
                }),
            })
            .await,
        Err(CompletionError::Persistence)
    );
    assert!(
        !service
            .client()
            .snapshot()
            .last_connected_at
            .contains_key(&profile_id),
        "activity must not become visible when its durable transaction fails"
    );
}

#[tokio::test]
async fn same_boot_restart_scans_before_resuming_one_nonterminal_operation() {
    let store = Arc::new(RecordingStore::default());
    let profile_id = ProfileId::new("same-boot-recovery");
    let config = ControlServiceConfig {
        authority_epoch: AuthorityEpoch(9),
        known_profiles: BTreeSet::from([profile_id.clone()]),
        profile_topologies: topology_catalog(&profile_id),
        persistence: Some(ControlPersistenceConfig::new("boot-a", store.clone())),
        freshness_poll_interval: Duration::from_millis(5),
        ..ControlServiceConfig::default()
    };

    let original_operation = {
        let service = ControlService::start(config.clone());
        service
            .completer()
            .set_readiness(AuthorityEpoch(9), true, true)
            .await
            .unwrap();
        let admitted = service
            .client()
            .submit(CommandRequest {
                command: UserCommand::Connect {
                    profile_id: profile_id.clone(),
                    conflict_acknowledgement: None,
                },
                idempotency_key: IdempotencyKey::new("survive-restart"),
                deadline: Deadline(u64::MAX),
            })
            .await
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while store
            .state
            .lock()
            .unwrap()
            .as_ref()
            .is_none_or(|state| !state.operations.contains_key(&admitted.operation_id))
        {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::task::yield_now().await;
        }
        admitted.operation_id
    };

    let executions = Arc::new(AtomicUsize::new(0));
    let restarted = ControlService::start_supervised(
        config,
        Arc::new(vortix::vortix_core::control::RealClock),
        ExecutionSelection::CanonicalAuthority,
        Arc::new(Supervisor::new(
            AuthorityEpoch(9),
            Arc::new(CountingExecutor(executions.clone())),
            Arc::new(OkPolicy),
            1,
            4,
        )),
    );
    assert_eq!(executions.load(Ordering::Acquire), 0);
    assert!(
        !restarted
            .client()
            .snapshot()
            .readiness
            .reconciliation_complete
    );
    restarted
        .observer()
        .observe(Observation::Tunnel {
            profile_id: profile_id.clone(),
            active: false,
            interface_name: None,
            observed_at_millis: 0,
            protection: None,
        })
        .await
        .unwrap();
    assert_eq!(executions.load(Ordering::Acquire), 0);
    restarted
        .completer()
        .set_readiness(AuthorityEpoch(9), true, true)
        .await
        .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while executions.load(Ordering::Acquire) == 0 {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::task::yield_now().await;
    }
    assert_eq!(executions.load(Ordering::Acquire), 1);
    assert!(restarted
        .client()
        .snapshot()
        .operations
        .contains_key(&original_operation));
}

#[tokio::test]
async fn admitted_connect_does_not_wait_for_deadline_when_dispatch_stops() {
    let profile_id = ProfileId::new("dispatch-stopped-connect");
    let save_entered = Arc::new(AtomicBool::new(false));
    let store = Arc::new(SlowStore {
        entered: save_entered.clone(),
    });
    let supervisor = Arc::new(Supervisor::new(
        AuthorityEpoch(17),
        Arc::new(CountingExecutor(Arc::new(AtomicUsize::new(0)))),
        Arc::new(OkPolicy),
        1,
        4,
    ));
    let service = ControlService::start_supervised(
        ControlServiceConfig {
            authority_epoch: AuthorityEpoch(17),
            known_profiles: BTreeSet::from([profile_id.clone()]),
            profile_topologies: topology_catalog(&profile_id),
            persistence: Some(ControlPersistenceConfig::new("boot-a", store)),
            freshness_poll_interval: Duration::from_millis(5),
            ..ControlServiceConfig::default()
        },
        Arc::new(vortix::vortix_core::control::RealClock),
        ExecutionSelection::CanonicalAuthority,
        supervisor.clone(),
    );
    service
        .observer()
        .observe(Observation::Tunnel {
            profile_id: profile_id.clone(),
            active: false,
            interface_name: None,
            observed_at_millis: service.observer().now_millis(),
            protection: None,
        })
        .await
        .unwrap();
    service
        .completer()
        .set_readiness(AuthorityEpoch(17), true, true)
        .await
        .unwrap();
    save_entered.store(false, Ordering::Release);

    let client = service.client();
    let submit = tokio::spawn(async move {
        client
            .submit(CommandRequest {
                command: UserCommand::Connect {
                    profile_id,
                    conflict_acknowledgement: None,
                },
                idempotency_key: IdempotencyKey::new("dispatch-stopped-connect"),
                deadline: client.deadline_after(Duration::from_secs(10)),
            })
            .await
    });
    let save_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while !save_entered.load(Ordering::Acquire) {
        assert!(
            tokio::time::Instant::now() < save_deadline,
            "connect intent was not persisted before dispatch"
        );
        tokio::task::yield_now().await;
    }
    supervisor.shutdown();

    let admitted = submit.await.unwrap().unwrap();
    let terminal_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    loop {
        let operation = service
            .client()
            .snapshot()
            .operations
            .get(&admitted.operation_id)
            .cloned()
            .expect("admitted operation remains retained");
        if operation.status.is_terminal() {
            assert_eq!(operation.status, OperationStatus::Failed);
            assert_eq!(
                operation.result,
                Some(vortix::vortix_core::control::OperationResult::Failed(
                    OperationFailure::Internal,
                ))
            );
            break;
        }
        assert!(
            tokio::time::Instant::now() < terminal_deadline,
            "dispatch failure left the admitted connect waiting for its deadline"
        );
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn completed_restarted_disconnect_releases_profile_for_deletion() {
    let store = Arc::new(RecordingStore::default());
    let profile_id = ProfileId::new("restart-disconnect-release");
    let operation_id: OperationId =
        serde_json::from_str("\"op-0000000000000009-0000000000000001\"").unwrap();
    let desired = DesiredState {
        generation: 1,
        tunnels: BTreeMap::from([(profile_id.clone(), RequestedTunnelState::Disconnected)]),
        conflict_acknowledgements: BTreeMap::new(),
        kill_switch: vortix::vortix_core::state::killswitch::KillSwitchMode::Off,
        authority_epoch: AuthorityEpoch(9),
        policy_digest: PolicyDigest("restart-disconnect-policy".into()),
    };
    store.state.lock().unwrap().replace(DurableControlState {
        desired: desired.clone(),
        operations: BTreeMap::from([(
            operation_id.clone(),
            OperationRecord {
                id: operation_id.clone(),
                idempotency_key: IdempotencyKey::new("restart-disconnect"),
                client_id: serde_json::from_str("\"client-0000000000000009-0000000000000001\"")
                    .unwrap(),
                command_digest: desired.policy_digest.clone(),
                authority_epoch: AuthorityEpoch(9),
                desired_generation: desired.generation,
                admitted_at_millis: 0,
                deadline_millis: u64::MAX,
                intent: OperationIntent::DesiredSubset {
                    tunnels: desired.tunnels.clone(),
                    kill_switch: None,
                },
                status: OperationStatus::WaitingForObservation,
                result: None,
                failure_detail: None,
            },
        )]),
        boot_connections: BTreeMap::new(),
        requested_resources: BTreeMap::new(),
        last_connected_at: BTreeMap::new(),
        tombstones: BTreeMap::new(),
        retention: RetentionMetadata::default(),
        reconciliation_required: true,
    });
    let service = ControlService::start(ControlServiceConfig {
        authority_epoch: AuthorityEpoch(9),
        known_profiles: BTreeSet::from([profile_id.clone()]),
        profile_topologies: topology_catalog(&profile_id),
        persistence: Some(ControlPersistenceConfig::new("boot-a", store)),
        profile_mutations: Some(Arc::new(DeleteProfile)),
        ..ControlServiceConfig::default()
    });
    service
        .completer()
        .set_readiness(AuthorityEpoch(9), true, true)
        .await
        .unwrap();

    service
        .completer()
        .complete(OperationCompletion {
            operation_id: operation_id.clone(),
            desired_generation: desired.generation,
            outcome: CompletionOutcome::Failed(OperationFailure::ObservationFailed),
        })
        .await
        .expect("restarted disconnect terminalized");
    assert!(!service
        .client()
        .snapshot()
        .operations
        .contains_key(&operation_id));

    let deletion = service
        .client()
        .submit(CommandRequest {
            command: UserCommand::DeleteProfile {
                profile_id: profile_id.clone(),
            },
            idempotency_key: IdempotencyKey::new("delete-after-restart-disconnect"),
            deadline: Deadline(u64::MAX),
        })
        .await;
    assert!(
        deletion.is_ok(),
        "completed recovery must release {profile_id} for deletion: {deletion:?}"
    );
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one recovery scenario verifies both eligible and ineligible boot intent"
)]
async fn new_boot_creates_one_recovery_operation_only_for_eligible_intent() {
    let directory = tempdir().unwrap();
    let store = Arc::new(FsControlStateStore::new(directory.path()));
    let profile_id = ProfileId::parse("b".repeat(ProfileId::HEX_LEN)).unwrap();
    let base_config = ControlServiceConfig {
        authority_epoch: AuthorityEpoch(10),
        known_profiles: BTreeSet::from([profile_id.clone()]),
        profile_topologies: topology_catalog(&profile_id),
        boot_connections: std::collections::BTreeMap::from([(
            profile_id.clone(),
            BootConnection {
                enabled: true,
                eligibility: BootEligibility::Eligible,
            },
        )]),
        freshness_poll_interval: Duration::from_millis(5),
        ..ControlServiceConfig::default()
    };
    let prior_operation = {
        let mut config = base_config.clone();
        config.persistence = Some(ControlPersistenceConfig::new("boot-a", store.clone()));
        let service = ControlService::start(config);
        service
            .completer()
            .set_readiness(AuthorityEpoch(10), true, true)
            .await
            .unwrap();
        let admitted = service
            .client()
            .submit(CommandRequest {
                command: UserCommand::Connect {
                    profile_id: profile_id.clone(),
                    conflict_acknowledgement: None,
                },
                idempotency_key: IdempotencyKey::new("boot-connect"),
                deadline: Deadline(u64::MAX),
            })
            .await
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while !service
            .client()
            .snapshot()
            .operations
            .contains_key(&admitted.operation_id)
        {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::task::yield_now().await;
        }
        admitted.operation_id
    };
    tokio::time::sleep(Duration::from_millis(20)).await;

    let executions = Arc::new(AtomicUsize::new(0));
    let mut rebooted_config = base_config;
    rebooted_config.persistence = Some(ControlPersistenceConfig::new("boot-b", store));
    let rebooted = ControlService::start_supervised(
        rebooted_config,
        Arc::new(vortix::vortix_core::control::RealClock),
        ExecutionSelection::CanonicalAuthority,
        Arc::new(Supervisor::new(
            AuthorityEpoch(10),
            Arc::new(CountingExecutor(executions.clone())),
            Arc::new(OkPolicy),
            1,
            4,
        )),
    );
    let rebooted_generation = rebooted.client().snapshot().desired.generation;
    assert_eq!(
        rebooted.client().snapshot().operations[&prior_operation].status,
        OperationStatus::Cancelled
    );
    rebooted
        .observer()
        .observe(Observation::Tunnel {
            profile_id,
            active: false,
            interface_name: None,
            observed_at_millis: 0,
            protection: None,
        })
        .await
        .unwrap();
    rebooted
        .completer()
        .set_readiness(AuthorityEpoch(10), true, true)
        .await
        .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while executions.load(Ordering::Acquire) == 0 {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::task::yield_now().await;
    }
    assert_eq!(executions.load(Ordering::Acquire), 1);
    assert!(rebooted
        .client()
        .snapshot()
        .operations
        .values()
        .any(|operation| {
            operation.desired_generation == rebooted_generation && !operation.status.is_terminal()
        }));
}

#[tokio::test]
async fn reboot_uses_current_boot_policy_instead_of_persisted_eligibility() {
    let directory = tempdir().unwrap();
    let store = Arc::new(FsControlStateStore::new(directory.path()));
    let profile_id = ProfileId::parse("c".repeat(ProfileId::HEX_LEN)).unwrap();
    let enabled = BootConnection {
        enabled: true,
        eligibility: BootEligibility::Eligible,
    };
    let base = ControlServiceConfig {
        authority_epoch: AuthorityEpoch(13),
        known_profiles: BTreeSet::from([profile_id.clone()]),
        profile_topologies: topology_catalog(&profile_id),
        boot_connections: std::collections::BTreeMap::from([(profile_id.clone(), enabled)]),
        persistence: Some(ControlPersistenceConfig::new("boot-a", store.clone())),
        ..ControlServiceConfig::default()
    };
    {
        let service = ControlService::start(base);
        service
            .completer()
            .set_readiness(AuthorityEpoch(13), true, true)
            .await
            .unwrap();
        service
            .client()
            .submit(CommandRequest {
                command: UserCommand::Connect {
                    profile_id: profile_id.clone(),
                    conflict_acknowledgement: None,
                },
                idempotency_key: IdempotencyKey::new("persisted-boot-policy"),
                deadline: Deadline(u64::MAX),
            })
            .await
            .unwrap();
    }

    let rebooted = ControlService::start(ControlServiceConfig {
        authority_epoch: AuthorityEpoch(13),
        known_profiles: BTreeSet::from([profile_id.clone()]),
        profile_topologies: topology_catalog(&profile_id),
        boot_connections: std::collections::BTreeMap::from([(
            profile_id.clone(),
            BootConnection {
                enabled: false,
                eligibility: BootEligibility::Eligible,
            },
        )]),
        persistence: Some(ControlPersistenceConfig::new("boot-b", store)),
        ..ControlServiceConfig::default()
    });

    assert_eq!(
        rebooted.client().snapshot().desired.tunnels[&profile_id],
        RequestedTunnelState::Disconnected
    );
}

#[test]
fn persisted_operation_ids_reject_malformed_values() {
    for malformed in ["op-1-1", "bad", "op-0000000000000001-zzzzzzzzzzzzzzzz"] {
        assert!(
            serde_json::from_value::<vortix::vortix_core::control::OperationId>(serde_json::json!(
                malformed
            ))
            .is_err()
        );
    }
}
