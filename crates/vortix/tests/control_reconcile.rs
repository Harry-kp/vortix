use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::time::{Duration, Instant};

use vortix::vortix_core::control::model::{AuthorityEpoch, OperationId, PolicyDigest};
use vortix::vortix_core::control::reconcile::{
    merge_observation, plan_reconciliation, DisconnectTombstone, InFlightMutation,
    ObservationOwnership, ReconcileAction, ReconcileInput, ScanEvidence, TunnelObservation,
};
use vortix::vortix_core::control::supervisor::{PolicyVerification, SupervisedTruth, Supervisor};
use vortix::vortix_core::control::worker::{
    wait_until, CancellationToken, ControlRevision, PolicyBarrier, PolicyExecutionEvidence,
    PolicyExecutor, PolicyOutcome, PolicyStage, PolicyWorker, ProfileWorkerPool, TopologyPolicy,
    TopologyState, TopologyTransitionKind, TunnelExecutionReceipt, TunnelExecutor, TunnelMutation,
    TunnelRevision, TunnelWork, WorkFailure,
};
use vortix::vortix_core::control::{
    Clock, CommandRequest, CompletionOutcome, CompletionResult, ControlEvent, ControlService,
    ControlServiceConfig, Deadline, ExecutionSelection, GateEvidence, HookEvent, IdempotencyKey,
    Observation, OperationCompletion, OperationStatus, PersistedTombstone, ProfileTopology,
    ProtectionEvidence, ProtectionStatus, RequestedTunnelState, UserCommand,
};
use vortix::vortix_core::ports::tunnel::{HandshakeEvidence, TunnelKindTag};
use vortix::vortix_core::profile::{ProfileId, ProtocolKind};

fn profile(value: &str) -> ProfileId {
    ProfileId::new(value)
}
fn operation(value: u64) -> OperationId {
    serde_json::from_str(&format!("\"op-0000000000000001-{value:016x}\"")).unwrap()
}
fn revision(generation: u64, digest: &str) -> ControlRevision {
    ControlRevision {
        authority_epoch: AuthorityEpoch(1),
        generation,
        digest: PolicyDigest(digest.into()),
    }
}
fn tunnel_revision(generation: u64) -> TunnelRevision {
    TunnelRevision {
        authority_epoch: AuthorityEpoch(1),
        generation,
    }
}
fn work(
    profile_id: ProfileId,
    generation: u64,
    operation_value: u64,
    mutation: TunnelMutation,
) -> TunnelWork {
    TunnelWork {
        profile_id,
        operation_id: operation(operation_value),
        revision: tunnel_revision(generation),
        mutation,
        protocol: TunnelKindTag::Mock,
        deadline: Instant::now() + Duration::from_secs(2),
    }
}

fn execution_receipt(work: &TunnelWork) -> TunnelExecutionReceipt {
    if work.mutation == TunnelMutation::Disconnect {
        TunnelExecutionReceipt::default()
    } else {
        TunnelExecutionReceipt::attested(
            work.profile_id.clone(),
            format!("tun-{}", work.profile_id.as_str()),
            TunnelKindTag::Mock,
            None,
            "test-attestation-0001",
        )
        .unwrap()
    }
}

#[test]
fn restart_restores_only_disconnect_tombstone_fences() {
    let target = profile("recovery-tombstone");
    let supervisor = Supervisor::new(
        AuthorityEpoch(1),
        Arc::new(OkExecutor),
        Arc::new(OkPolicy),
        1,
        4,
    );
    supervisor
        .restore_tombstones(&BTreeMap::from([(
            target.clone(),
            PersistedTombstone {
                authority_epoch: AuthorityEpoch(1),
                generation: 4,
                policy_digest: PolicyDigest("persisted-policy".into()),
                operation_id: operation(9),
                teardown_failed: true,
            },
        )]))
        .unwrap();

    let restored = supervisor.tombstones().remove(&target).unwrap();
    assert_eq!(restored.revision.generation, 4);
    assert!(restored.adoption.is_none());
    assert!(restored.handshake.is_none());
    assert!(restored.probe_receipts.is_empty());
    assert_eq!(restored.truth, SupervisedTruth::OutcomeUnknown);
}

struct BarrierExecutor {
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}
impl TunnelExecutor for BarrierExecutor {
    fn execute(
        &self,
        work: &TunnelWork,
        _: &CancellationToken,
    ) -> Result<TunnelExecutionReceipt, String> {
        self.entered.wait();
        self.release.wait();
        Ok(execution_receipt(work))
    }
}
struct OkExecutor;
impl TunnelExecutor for OkExecutor {
    fn execute(
        &self,
        work: &TunnelWork,
        _: &CancellationToken,
    ) -> Result<TunnelExecutionReceipt, String> {
        Ok(execution_receipt(work))
    }
}
struct OkPolicy;
impl PolicyExecutor for OkPolicy {
    fn apply(&self, _: &TopologyPolicy, _: PolicyBarrier) -> Result<(), String> {
        Ok(())
    }
    fn compensate(&self, _: &TopologyPolicy, _: PolicyBarrier) {}
}

#[tokio::test]
async fn disconnect_all_does_not_reserve_connect_routes() {
    let first = profile("disconnect-overlap-first");
    let second = profile("disconnect-overlap-second");
    let supervisor = Arc::new(Supervisor::new(
        AuthorityEpoch(1),
        Arc::new(OkExecutor),
        Arc::new(OkPolicy),
        2,
        8,
    ));
    let overlapping = BTreeSet::from(["0.0.0.0/0".into()]);
    let service = ControlService::start_supervised(
        ControlServiceConfig {
            authority_epoch: AuthorityEpoch(1),
            known_profiles: BTreeSet::from([first.clone(), second.clone()]),
            profile_topologies: BTreeMap::from([
                (
                    first,
                    ProfileTopology {
                        routes: overlapping.clone(),
                        ..ProfileTopology::default()
                    },
                ),
                (
                    second,
                    ProfileTopology {
                        routes: overlapping,
                        ..ProfileTopology::default()
                    },
                ),
            ]),
            ..ControlServiceConfig::default()
        },
        Arc::new(TestClock::default()),
        ExecutionSelection::CanonicalAuthority,
        supervisor,
    );

    service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Disconnect { profile_id: None },
            idempotency_key: IdempotencyKey::new("disconnect-overlap-all"),
            deadline: Deadline(1_000),
        })
        .await
        .expect("disconnect admission must not claim routes used only by connect");
}

#[test]
fn supervisor_restores_only_protocol_correct_owned_tunnels() {
    let wg_profile = profile("restored-wg");
    let wg_revision = tunnel_revision(7);
    let supervisor = Supervisor::new(
        AuthorityEpoch(1),
        Arc::new(OkExecutor),
        Arc::new(OkPolicy),
        1,
        4,
    );
    let adoption = TunnelExecutionReceipt::wireguard(
        wg_profile.clone(),
        "wg0",
        "wg-recovery-attestation-0001",
        HandshakeEvidence {
            generation: 7,
            peer_public_key: "peer".into(),
            handshake_at: std::time::SystemTime::now(),
            observed_at: std::time::SystemTime::now(),
            allowed_routes: vec!["10.0.0.0/24".into()],
        },
    )
    .unwrap();
    supervisor
        .restore_owned_tunnel(
            adoption.adoption.unwrap(),
            adoption.handshake,
            Vec::new(),
            None,
            wg_revision,
            operation(41),
        )
        .unwrap();
    assert_eq!(
        supervisor.profile_truth(&wg_profile).unwrap().truth,
        SupervisedTruth::ObservedPresent
    );

    let wrong_generation = TunnelExecutionReceipt::wireguard(
        profile("wrong-generation"),
        "wg1",
        "wg-recovery-attestation-0002",
        HandshakeEvidence {
            generation: 6,
            peer_public_key: "peer".into(),
            handshake_at: std::time::SystemTime::now(),
            observed_at: std::time::SystemTime::now(),
            allowed_routes: vec!["10.1.0.0/24".into()],
        },
    )
    .unwrap();
    assert_eq!(
        supervisor.restore_owned_tunnel(
            wrong_generation.adoption.unwrap(),
            wrong_generation.handshake,
            Vec::new(),
            None,
            tunnel_revision(7),
            operation(42),
        ),
        Err(WorkFailure::EffectFailed)
    );
}

#[test]
fn supervisor_requires_matching_openvpn_custodian_capability() {
    use vortix::vortix_core::ports::process::ManagedProcessId;

    let target = profile("restored-ovpn");
    let supervisor = Supervisor::new(
        AuthorityEpoch(1),
        Arc::new(OkExecutor),
        Arc::new(OkPolicy),
        1,
        4,
    );
    let receipt = TunnelExecutionReceipt::attested(
        target.clone(),
        "tun0",
        TunnelKindTag::OpenVpn,
        Some(123),
        "openvpn-custodian-attestation",
    )
    .unwrap();
    let adoption = receipt.adoption.unwrap();
    let wrong_owner = ManagedProcessId {
        profile_id: profile("other-ovpn"),
        generation: 9,
        ownership_token: "a".repeat(64),
    };
    assert_eq!(
        supervisor.restore_owned_tunnel(
            adoption.clone(),
            None,
            Vec::new(),
            Some(&wrong_owner),
            tunnel_revision(7),
            operation(43),
        ),
        Err(WorkFailure::EffectFailed)
    );

    let wrong_generation = ManagedProcessId {
        profile_id: target,
        generation: 6,
        ownership_token: "b".repeat(64),
    };
    assert_eq!(
        supervisor.restore_owned_tunnel(
            adoption,
            None,
            Vec::new(),
            Some(&wrong_generation),
            tunnel_revision(7),
            operation(44),
        ),
        Err(WorkFailure::EffectFailed)
    );
}

#[test]
fn independent_profiles_progress_and_same_profile_serializes() {
    let entered = Arc::new(Barrier::new(3));
    let release = Arc::new(Barrier::new(3));
    let pool = ProfileWorkerPool::with_limits(
        Arc::new(BarrierExecutor {
            entered: entered.clone(),
            release: release.clone(),
        }),
        2,
        4,
        4,
        Duration::from_secs(10),
    );
    pool.dispatch(
        work(profile("a"), 1, 1, TunnelMutation::Connect),
        ["10.0.0.0/24".into()],
    )
    .unwrap();
    pool.dispatch(
        work(profile("b"), 1, 2, TunnelMutation::Connect),
        ["10.1.0.0/24".into()],
    )
    .unwrap();
    entered.wait();
    assert!(pool.reservations().is_reserved(&profile("a")));
    release.wait();
    assert!(wait_until(Duration::from_secs(1), || pool.try_result()).is_some());
    assert!(wait_until(Duration::from_secs(1), || pool.try_result()).is_some());
}

#[test]
fn cidr_overlap_is_normalized_and_active_lease_lives_until_disconnect() {
    let pool = ProfileWorkerPool::new(Arc::new(OkExecutor), 2, 8);
    pool.dispatch(
        work(profile("a"), 1, 1, TunnelMutation::Connect),
        ["10.0.0.7/24".into()],
    )
    .unwrap();
    assert!(wait_until(Duration::from_secs(1), || pool.try_result())
        .unwrap()
        .result
        .is_ok());
    assert!(pool.reservations().active_lease(&profile("a")).is_some());
    assert_eq!(
        pool.dispatch(
            work(profile("b"), 2, 2, TunnelMutation::Connect),
            ["10.0.0.128/25".into()]
        )
        .unwrap_err(),
        WorkFailure::RouteConflict
    );
    pool.dispatch(
        work(profile("a"), 2, 3, TunnelMutation::Disconnect),
        ["10.0.0.0/24".into()],
    )
    .unwrap();
    assert!(wait_until(Duration::from_secs(1), || pool.try_result())
        .unwrap()
        .result
        .is_ok());
    assert!(!pool.reservations().is_reserved(&profile("a")));
}

#[test]
fn cooperative_effect_is_cancelled_and_joined_without_abandoning_a_thread() {
    struct Cooperative;
    impl TunnelExecutor for Cooperative {
        fn execute(
            &self,
            _: &TunnelWork,
            cancellation: &CancellationToken,
        ) -> Result<TunnelExecutionReceipt, String> {
            while !cancellation.is_cancelled() {
                std::thread::yield_now();
            }
            Err("cancelled".into())
        }
    }
    let pool =
        ProfileWorkerPool::with_limits(Arc::new(Cooperative), 1, 1, 1, Duration::from_secs(10));
    let mut item = work(profile("hung"), 1, 1, TunnelMutation::Connect);
    item.deadline = Instant::now() + Duration::from_millis(20);
    pool.dispatch(item, Vec::new()).unwrap();
    let started = Instant::now();
    assert!(pool.shutdown_bounded(Duration::from_millis(250)));
    assert!(started.elapsed() < Duration::from_millis(250));
}

#[test]
fn supervisor_gives_tunnel_compensation_the_callers_full_shutdown_budget() {
    struct SlowCancellation {
        entered: Arc<Barrier>,
    }
    impl TunnelExecutor for SlowCancellation {
        fn execute(
            &self,
            _: &TunnelWork,
            cancellation: &CancellationToken,
        ) -> Result<TunnelExecutionReceipt, String> {
            self.entered.wait();
            while !cancellation.is_cancelled() {
                std::thread::yield_now();
            }
            // Longer than half the caller's shutdown budget, so this still
            // catches the former budget-splitting implementation. Keep ample
            // headroom below the full budget for loaded CI runners.
            std::thread::sleep(Duration::from_millis(500));
            Err("cancelled after owned cleanup".into())
        }
    }

    let entered = Arc::new(Barrier::new(2));
    let supervisor = Supervisor::new(
        AuthorityEpoch(1),
        Arc::new(SlowCancellation {
            entered: Arc::clone(&entered),
        }),
        Arc::new(OkPolicy),
        1,
        4,
    );
    supervisor
        .dispatch_tunnel(
            work(profile("shutdown-budget"), 1, 1, TunnelMutation::Connect),
            Vec::new(),
        )
        .unwrap();
    entered.wait();

    assert!(supervisor.shutdown_bounded(Duration::from_millis(800)));
}

fn observation(
    evidence: ScanEvidence,
    ownership: ObservationOwnership,
    revision: Option<TunnelRevision>,
) -> TunnelObservation {
    TunnelObservation {
        evidence,
        interface_name: Some("tun0".into()),
        ownership,
        revision,
        adoption: None,
        observed_at_millis: 10,
    }
}

#[test]
fn stale_tunnel_generation_never_converges() {
    let id = profile("corp");
    let target = revision(4, "new");
    let stale = tunnel_revision(3);
    let plan = plan_reconciliation(&ReconcileInput {
        revision: target,
        tunnel_revisions: BTreeMap::from([(id.clone(), tunnel_revision(4))]),
        desired_connected: BTreeSet::from([id.clone()]),
        observations: BTreeMap::from([(
            id.clone(),
            observation(
                ScanEvidence::ConfirmedPresent,
                ObservationOwnership::Managed,
                Some(stale),
            ),
        )]),
        in_flight: BTreeMap::new(),
        disconnect_tombstones: BTreeMap::new(),
    });
    assert!(
        matches!(plan.actions.as_slice(), [ReconcileAction::CleanupStaleManaged { stale_revision: Some(found), .. }] if found == &stale)
    );
}

#[test]
fn wireguard_interface_attestation_alone_remains_read_only() {
    let target = revision(4, "digest-4");
    let profile_id = profile("corp");
    let receipt = TunnelExecutionReceipt::wireguard(
        profile_id.clone(),
        "wg0",
        "wireguard-test-attestation",
        HandshakeEvidence {
            generation: 3,
            peer_public_key: "peer".into(),
            handshake_at: std::time::SystemTime::now(),
            observed_at: std::time::SystemTime::now(),
            allowed_routes: vec!["10.0.0.0/24".into()],
        },
    )
    .unwrap();
    let plan = plan_reconciliation(&ReconcileInput {
        revision: target,
        tunnel_revisions: BTreeMap::from([(profile_id.clone(), tunnel_revision(4))]),
        desired_connected: BTreeSet::from([profile_id.clone()]),
        observations: BTreeMap::from([(
            profile_id.clone(),
            TunnelObservation {
                evidence: ScanEvidence::ConfirmedPresent,
                interface_name: Some("wg0".into()),
                ownership: ObservationOwnership::ExternalUnambiguous,
                revision: None,
                adoption: receipt.adoption,
                observed_at_millis: 10,
            },
        )]),
        in_flight: BTreeMap::new(),
        disconnect_tombstones: BTreeMap::new(),
    });
    assert!(matches!(
        plan.actions.as_slice(),
        [ReconcileAction::ObserveReadOnly { profile_id: found, .. }] if found == &profile_id
    ));
}

#[test]
fn failed_teardown_retries_and_probe_failure_does_not_clear_tombstone() {
    let id = profile("corp");
    let rev = revision(5, "digest");
    let tunnel_rev = tunnel_revision(5);
    let input = ReconcileInput {
        revision: rev.clone(),
        tunnel_revisions: BTreeMap::from([(id.clone(), tunnel_rev)]),
        desired_connected: BTreeSet::new(),
        observations: BTreeMap::from([(
            id.clone(),
            observation(
                ScanEvidence::ProbeFailed,
                ObservationOwnership::Managed,
                Some(tunnel_rev),
            ),
        )]),
        in_flight: BTreeMap::new(),
        disconnect_tombstones: BTreeMap::from([(
            id.clone(),
            DisconnectTombstone {
                revision: tunnel_rev,
                teardown_failed: true,
            },
        )]),
    };
    assert!(matches!(
        plan_reconciliation(&input).actions.as_slice(),
        [ReconcileAction::Disconnect { .. }]
    ));
    let absent = ReconcileInput {
        observations: BTreeMap::from([(
            id.clone(),
            observation(
                ScanEvidence::ConfirmedAbsent,
                ObservationOwnership::Managed,
                Some(tunnel_rev),
            ),
        )]),
        ..input
    };
    assert!(matches!(
        plan_reconciliation(&absent).actions.as_slice(),
        [ReconcileAction::ClearTombstone { .. }]
    ));
}

#[test]
fn scanner_never_overwrites_inflight_protocol_identity() {
    let rev = tunnel_revision(7);
    let mut current = observation(
        ScanEvidence::ConfirmedAbsent,
        ObservationOwnership::Managed,
        Some(rev),
    );
    current.interface_name = Some("tun-authoritative".into());
    let mut scanner = observation(
        ScanEvidence::ConfirmedPresent,
        ObservationOwnership::UnknownExternal,
        None,
    );
    scanner.interface_name = Some("utun-guess".into());
    merge_observation(&mut current, scanner, Some(&rev));
    assert_eq!(current.interface_name.as_deref(), Some("tun-authoritative"));
    assert_eq!(current.revision, Some(rev));
}

#[derive(Default)]
struct PolicyRecorder {
    calls: Mutex<Vec<(u64, PolicyBarrier)>>,
    fail_at: Mutex<Option<PolicyBarrier>>,
    compensations: Mutex<Vec<PolicyBarrier>>,
    panic_compensation: Mutex<bool>,
}
impl PolicyExecutor for PolicyRecorder {
    fn apply(&self, policy: &TopologyPolicy, barrier: PolicyBarrier) -> Result<(), String> {
        self.calls
            .lock()
            .unwrap()
            .push((policy.generation, barrier));
        if *self.fail_at.lock().unwrap() == Some(barrier) {
            Err("injected".into())
        } else {
            Ok(())
        }
    }
    fn compensate(&self, _: &TopologyPolicy, barrier: PolicyBarrier) {
        self.compensations.lock().unwrap().push(barrier);
        assert!(
            !*self.panic_compensation.lock().unwrap(),
            "injected compensation panic"
        );
    }
}
fn policy(generation: u64, digest: &str) -> TopologyPolicy {
    TopologyPolicy {
        generation,
        authority_epoch: AuthorityEpoch(1),
        digest: PolicyDigest(digest.into()),
        operation_id: operation(generation),
        deadline: Instant::now() + Duration::from_secs(2),
        prior: TopologyState::default(),
        target: TopologyState {
            profiles: BTreeSet::from([profile("corp")]),
            ..TopologyState::default()
        },
        tunnel_revisions: BTreeMap::from([(profile("corp"), tunnel_revision(generation))]),
        transition: TopologyTransitionKind::Connect,
        required_blocking: true,
        stage: PolicyStage::Final,
    }
}

#[test]
fn required_final_failure_compensates_without_touching_pre_block() {
    let recorder = Arc::new(PolicyRecorder::default());
    *recorder.fail_at.lock().unwrap() = Some(PolicyBarrier::Dns);
    let worker = PolicyWorker::start(recorder.clone(), 4);
    worker.submit(policy(1, "one")).unwrap();
    let result = wait_until(Duration::from_secs(1), || worker.try_result()).unwrap();
    assert_eq!(result.outcome, PolicyOutcome::Failed);
    assert_eq!(
        recorder.compensations.lock().unwrap().first(),
        Some(&PolicyBarrier::Dns)
    );
    assert!(result
        .receipts
        .iter()
        .all(|receipt| receipt.barrier != PolicyBarrier::Blocking));
    assert!(!recorder
        .compensations
        .lock()
        .unwrap()
        .contains(&PolicyBarrier::Blocking));
}

#[test]
fn pre_tunnel_policy_runs_only_the_blocking_barrier() {
    let recorder = Arc::new(PolicyRecorder::default());
    let worker = PolicyWorker::start(recorder.clone(), 4);
    let mut pre = policy(1, "one");
    pre.stage = PolicyStage::PreTunnelBlocking;
    worker.submit(pre).unwrap();
    let result = wait_until(Duration::from_secs(1), || worker.try_result()).unwrap();
    assert_eq!(result.outcome, PolicyOutcome::Applied);
    assert_eq!(result.stage, PolicyStage::PreTunnelBlocking);
    assert_eq!(
        recorder.calls.lock().unwrap().as_slice(),
        &[(1, PolicyBarrier::Blocking)]
    );
}

#[test]
fn failed_pre_tunnel_policy_compensates_a_possibly_partial_blocking_apply() {
    let recorder = Arc::new(PolicyRecorder::default());
    *recorder.fail_at.lock().unwrap() = Some(PolicyBarrier::Blocking);
    let worker = PolicyWorker::start(recorder.clone(), 4);
    let mut pre = policy(1, "failed-pre");
    pre.stage = PolicyStage::PreTunnelBlocking;
    worker.submit(pre).unwrap();
    let result = wait_until(Duration::from_secs(1), || worker.try_result()).unwrap();
    assert_eq!(result.outcome, PolicyOutcome::Failed);
    assert!(result.receipts.iter().any(|receipt| {
        receipt.barrier == PolicyBarrier::Blocking
            && !receipt.preserved_for_safety
            && receipt.compensated
    }));
    assert_eq!(
        recorder.compensations.lock().unwrap().as_slice(),
        &[PolicyBarrier::Blocking]
    );
}

#[test]
fn compensation_panic_is_a_structured_policy_result() {
    let recorder = Arc::new(PolicyRecorder::default());
    *recorder.fail_at.lock().unwrap() = Some(PolicyBarrier::Route);
    *recorder.panic_compensation.lock().unwrap() = true;
    let worker = PolicyWorker::start(recorder, 4);
    worker.submit(policy(1, "one")).unwrap();
    assert_eq!(
        wait_until(Duration::from_secs(1), || worker.try_result())
            .unwrap()
            .outcome,
        PolicyOutcome::Panicked
    );
}

#[test]
fn cooperative_policy_apply_is_cancelled_and_joined() {
    struct CooperativePolicy;
    impl PolicyExecutor for CooperativePolicy {
        fn apply(&self, _: &TopologyPolicy, _: PolicyBarrier) -> Result<(), String> {
            Ok(())
        }
        fn compensate(&self, _: &TopologyPolicy, _: PolicyBarrier) {}
        fn apply_cancellable(
            &self,
            _: &TopologyPolicy,
            _: PolicyBarrier,
            cancellation: &CancellationToken,
        ) -> Result<(), String> {
            while !cancellation.is_cancelled() {
                std::thread::yield_now();
            }
            Err("cancelled".into())
        }
    }
    let worker = PolicyWorker::start(Arc::new(CooperativePolicy), 2);
    worker.submit(policy(1, "hung-policy")).unwrap();
    let started = Instant::now();
    assert!(worker.shutdown_bounded(Duration::from_millis(100)));
    assert!(started.elapsed() < Duration::from_millis(250));
}

#[test]
fn timed_out_policy_shutdown_retains_the_owned_join_for_a_later_drain() {
    struct SlowPolicyCancellation {
        entered: Arc<Barrier>,
    }
    impl PolicyExecutor for SlowPolicyCancellation {
        fn apply(&self, _: &TopologyPolicy, _: PolicyBarrier) -> Result<(), String> {
            Ok(())
        }
        fn compensate(&self, _: &TopologyPolicy, _: PolicyBarrier) {}
        fn apply_cancellable(
            &self,
            _: &TopologyPolicy,
            _: PolicyBarrier,
            cancellation: &CancellationToken,
        ) -> Result<(), String> {
            self.entered.wait();
            while !cancellation.is_cancelled() {
                std::thread::yield_now();
            }
            std::thread::sleep(Duration::from_millis(100));
            Err("cancelled after policy cleanup".into())
        }
    }

    let entered = Arc::new(Barrier::new(2));
    let worker = PolicyWorker::start(
        Arc::new(SlowPolicyCancellation {
            entered: Arc::clone(&entered),
        }),
        2,
    );
    worker.submit(policy(1, "slow-policy-shutdown")).unwrap();
    entered.wait();

    assert!(!worker.shutdown_bounded(Duration::from_millis(10)));
    assert!(worker.shutdown_bounded(Duration::from_millis(250)));
}

#[test]
fn pending_coalescing_emits_superseded_receipt() {
    struct Gate {
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
    }
    impl PolicyExecutor for Gate {
        fn apply(&self, _: &TopologyPolicy, barrier: PolicyBarrier) -> Result<(), String> {
            if barrier == PolicyBarrier::Blocking {
                self.entered.wait();
                self.release.wait();
            }
            Ok(())
        }
        fn compensate(&self, _: &TopologyPolicy, _: PolicyBarrier) {}
    }
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let worker = PolicyWorker::start(
        Arc::new(Gate {
            entered: entered.clone(),
            release: release.clone(),
        }),
        8,
    );
    let mut first = policy(1, "one");
    first.stage = PolicyStage::PreTunnelBlocking;
    worker.submit(first).unwrap();
    entered.wait();
    worker.submit(policy(2, "two")).unwrap();
    worker.submit(policy(3, "three")).unwrap();
    let superseded = worker
        .try_result()
        .expect("pending generation superseded synchronously");
    assert_eq!(superseded.outcome, PolicyOutcome::Superseded);
    assert_eq!(superseded.generation, 2);
    assert_eq!(superseded.superseded_by.unwrap().generation, 3);
    release.wait();
}

#[test]
fn supervisor_rejects_same_generation_different_digest_verification() {
    let supervisor = Supervisor::new(
        AuthorityEpoch(1),
        Arc::new(OkExecutor),
        Arc::new(OkPolicy),
        2,
        4,
    );
    let mut policy_only = policy(7, "expected");
    policy_only.target.profiles.clear();
    policy_only.required_blocking = false;
    supervisor.submit_policy(&policy_only).unwrap();
    let premature = PolicyVerification {
        revision: revision(7, "expected"),
        operation_id: operation(7),
        observed_at_millis: 10,
        received_at_millis: 10,
        interface_verified: true,
        route_verified: true,
        dns_verified: true,
        firewall_verified: true,
    };
    assert_eq!(
        supervisor.verify_policy(&premature, 10),
        Err(WorkFailure::Stale),
        "submission is not application proof"
    );
    let result = wait_until(Duration::from_secs(1), || supervisor.poll_policy()).unwrap();
    assert_eq!(result.outcome, PolicyOutcome::Applied);
    assert_eq!(supervisor.protected_generation(), None);
    let evidence = PolicyVerification {
        revision: revision(7, "racing"),
        operation_id: operation(7),
        observed_at_millis: 10,
        received_at_millis: 10,
        interface_verified: true,
        route_verified: true,
        dns_verified: true,
        firewall_verified: true,
    };
    assert_eq!(
        supervisor.verify_policy(&evidence, 10),
        Err(WorkFailure::Stale)
    );
    assert_eq!(supervisor.protected_generation(), None);

    let stale_source = PolicyVerification {
        revision: revision(7, "expected"),
        operation_id: operation(7),
        observed_at_millis: 0,
        received_at_millis: 10,
        interface_verified: true,
        route_verified: true,
        dns_verified: true,
        firewall_verified: true,
    };
    assert_eq!(
        supervisor.verify_policy(&stale_source, 5_001),
        Err(WorkFailure::EffectFailed)
    );
    let verified = PolicyVerification {
        observed_at_millis: 10,
        ..stale_source
    };
    supervisor.verify_policy(&verified, 10).unwrap();
    assert_eq!(supervisor.protected_generation(), Some(7));
    let incomplete = PolicyVerification {
        dns_verified: false,
        ..verified
    };
    assert_eq!(
        supervisor.verify_policy(&incomplete, 10),
        Err(WorkFailure::EffectFailed)
    );
    assert_eq!(supervisor.protected_generation(), None);
}

#[test]
fn supervisor_does_not_reuse_pre_block_for_another_operation() {
    let supervisor = Supervisor::new(
        AuthorityEpoch(1),
        Arc::new(OkExecutor),
        Arc::new(OkPolicy),
        2,
        4,
    );
    let mut pre = policy(8, "operation-bound-pre");
    pre.stage = PolicyStage::PreTunnelBlocking;
    supervisor.submit_policy(&pre).unwrap();
    let result = wait_until(Duration::from_secs(1), || supervisor.poll_policy()).unwrap();
    assert_eq!(result.outcome, PolicyOutcome::Applied);

    let mut wrong_operation = policy(8, "operation-bound-pre");
    wrong_operation.operation_id = operation(9);
    assert_eq!(
        supervisor.submit_policy(&wrong_operation),
        Err(WorkFailure::Busy)
    );
    supervisor
        .submit_policy(&policy(8, "operation-bound-pre"))
        .unwrap();
}

#[test]
fn bounded_profile_cardinality_returns_busy_before_dispatch() {
    struct Park(Arc<Barrier>);
    impl TunnelExecutor for Park {
        fn execute(
            &self,
            work: &TunnelWork,
            _: &CancellationToken,
        ) -> Result<TunnelExecutionReceipt, String> {
            self.0.wait();
            Ok(execution_receipt(work))
        }
    }
    let barrier = Arc::new(Barrier::new(2));
    let pool = ProfileWorkerPool::with_limits(
        Arc::new(Park(barrier.clone())),
        1,
        2,
        1,
        Duration::from_secs(10),
    );
    pool.dispatch(
        work(profile("a"), 1, 1, TunnelMutation::Connect),
        Vec::new(),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(10));
    assert_eq!(
        pool.dispatch(
            work(profile("b"), 1, 2, TunnelMutation::Connect),
            Vec::new()
        )
        .unwrap_err(),
        WorkFailure::Busy
    );
    barrier.wait();
}

#[test]
fn stale_inflight_tuple_plans_cleanup_not_convergence() {
    let id = profile("corp");
    let input = ReconcileInput {
        revision: revision(2, "new"),
        tunnel_revisions: BTreeMap::from([(id.clone(), tunnel_revision(2))]),
        desired_connected: BTreeSet::from([id.clone()]),
        observations: BTreeMap::new(),
        in_flight: BTreeMap::from([(
            id.clone(),
            InFlightMutation {
                revision: tunnel_revision(1),
                operation: operation(1),
            },
        )]),
        disconnect_tombstones: BTreeMap::new(),
    };
    assert!(matches!(
        plan_reconciliation(&input).actions.as_slice(),
        [ReconcileAction::CleanupStaleManaged { .. }]
    ));
}

#[test]
fn result_saturation_retains_latest_profile_terminal_without_drop() {
    let pool =
        ProfileWorkerPool::with_limits(Arc::new(OkExecutor), 1, 1, 2, Duration::from_secs(10));
    pool.dispatch(
        work(profile("a"), 1, 1, TunnelMutation::Connect),
        Vec::new(),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(20));
    pool.dispatch(
        work(profile("a"), 2, 2, TunnelMutation::Connect),
        Vec::new(),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let latest = pool.try_result().expect("latest result retained");
    assert_eq!(latest.profile_id, profile("a"));
    assert_eq!(latest.revision.generation, 2);
    assert_eq!(pool.dropped_results(), 0);
}

#[derive(Default)]
struct TestClock(AtomicU64);

impl Clock for TestClock {
    fn now_millis(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}

#[tokio::test]
async fn restarted_local_service_dispatches_down_for_restored_owned_tunnel() {
    struct DisconnectCapture(Arc<AtomicBool>);
    impl TunnelExecutor for DisconnectCapture {
        fn execute(
            &self,
            work: &TunnelWork,
            _: &CancellationToken,
        ) -> Result<TunnelExecutionReceipt, String> {
            if work.mutation == TunnelMutation::Disconnect {
                self.0.store(true, Ordering::SeqCst);
            }
            Ok(TunnelExecutionReceipt::default())
        }
    }

    let target = profile("restart-owned-wg");
    let dispatched = Arc::new(AtomicBool::new(false));
    let supervisor = Arc::new(Supervisor::new(
        AuthorityEpoch(1),
        Arc::new(DisconnectCapture(dispatched.clone())),
        Arc::new(OkPolicy),
        2,
        8,
    ));
    let receipt = TunnelExecutionReceipt::wireguard(
        target.clone(),
        "wg0",
        "restart-owned-attestation",
        HandshakeEvidence {
            generation: 7,
            peer_public_key: "peer".into(),
            handshake_at: std::time::SystemTime::now(),
            observed_at: std::time::SystemTime::now(),
            allowed_routes: vec!["10.0.0.0/24".into()],
        },
    )
    .unwrap();
    supervisor
        .restore_owned_tunnel(
            receipt.adoption.unwrap(),
            receipt.handshake,
            Vec::new(),
            None,
            tunnel_revision(7),
            operation(9),
        )
        .unwrap();
    let clock = Arc::new(TestClock::default());
    let service = ControlService::start_supervised(
        ControlServiceConfig {
            authority_epoch: AuthorityEpoch(1),
            known_profiles: BTreeSet::from([target.clone()]),
            profile_topologies: BTreeMap::from([(
                target.clone(),
                ProfileTopology {
                    protocol: Some(ProtocolKind::WireGuard),
                    ..ProfileTopology::default()
                },
            )]),
            freshness_poll_interval: Duration::from_millis(5),
            ..ControlServiceConfig::default()
        },
        clock,
        ExecutionSelection::CanonicalAuthority,
        supervisor,
    );
    service
        .observer()
        .observe(Observation::Tunnel {
            profile_id: target.clone(),
            active: true,
            interface_name: Some("wg0".into()),
            observed_at_millis: 0,
            protection: None,
        })
        .await
        .unwrap();
    service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Disconnect {
                profile_id: Some(target),
            },
            idempotency_key: IdempotencyKey::new("restart-down"),
            deadline: Deadline(1_000),
        })
        .await
        .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while !dispatched.load(Ordering::SeqCst) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "restored owned tunnel was not dispatched for teardown"
        );
        tokio::task::yield_now().await;
    }
}

#[derive(Default)]
struct PreBlockGate {
    held_generation: Option<u64>,
    entered: BTreeSet<u64>,
    released: BTreeSet<u64>,
    failed: BTreeSet<u64>,
}

#[derive(Default)]
struct TopologyCapture {
    tunnel_calls: Mutex<Vec<(ProfileId, TunnelMutation, u64)>>,
    policies: Mutex<Vec<TopologyPolicy>>,
    pre_block: (Mutex<PreBlockGate>, Condvar),
    failed_final: Mutex<BTreeSet<u64>>,
    publish_readback: AtomicBool,
}

impl TopologyCapture {
    fn hold_pre_block(&self, generation: u64) {
        self.pre_block.0.lock().unwrap().held_generation = Some(generation);
    }

    fn release_pre_block(&self, generation: u64) {
        let (state, wake) = &self.pre_block;
        state.lock().unwrap().released.insert(generation);
        wake.notify_all();
    }

    fn fail_pre_block(&self, generation: u64) {
        self.pre_block.0.lock().unwrap().failed.insert(generation);
    }

    fn pre_block_entered(&self, generation: u64) -> bool {
        self.pre_block
            .0
            .lock()
            .unwrap()
            .entered
            .contains(&generation)
    }

    fn fail_final(&self, generation: u64) {
        self.failed_final.lock().unwrap().insert(generation);
    }

    fn publish_readback(&self) {
        self.publish_readback.store(true, Ordering::SeqCst);
    }
}

impl TunnelExecutor for TopologyCapture {
    fn execute(
        &self,
        work: &TunnelWork,
        _: &CancellationToken,
    ) -> Result<TunnelExecutionReceipt, String> {
        self.tunnel_calls.lock().unwrap().push((
            work.profile_id.clone(),
            work.mutation,
            work.revision.generation,
        ));
        Ok(execution_receipt(work))
    }
}

impl PolicyExecutor for TopologyCapture {
    fn apply(&self, policy: &TopologyPolicy, barrier: PolicyBarrier) -> Result<(), String> {
        let first_for_stage = match policy.stage {
            PolicyStage::Final if policy.required_blocking => PolicyBarrier::Tunnel,
            PolicyStage::PreTunnelBlocking | PolicyStage::Final => PolicyBarrier::Blocking,
        };
        if barrier == first_for_stage {
            self.policies.lock().unwrap().push(policy.clone());
            if policy.stage == PolicyStage::Final
                && self
                    .failed_final
                    .lock()
                    .unwrap()
                    .contains(&policy.generation)
            {
                return Err("injected final policy failure".into());
            }
        }
        if policy.stage == PolicyStage::PreTunnelBlocking && barrier == PolicyBarrier::Blocking {
            let (state, wake) = &self.pre_block;
            let mut state = state.lock().unwrap();
            state.entered.insert(policy.generation);
            if state.failed.contains(&policy.generation) {
                return Err("injected pre-block failure".into());
            }
            while state.held_generation == Some(policy.generation)
                && !state.released.contains(&policy.generation)
            {
                state = wake.wait(state).unwrap();
            }
        }
        Ok(())
    }

    fn compensate(&self, _: &TopologyPolicy, _: PolicyBarrier) {}

    fn verification(&self, policy: &TopologyPolicy) -> Option<PolicyExecutionEvidence> {
        (policy.stage == PolicyStage::Final && self.publish_readback.load(Ordering::SeqCst))
            .then_some(PolicyExecutionEvidence {
                observed_at_millis: 0,
                interface_verified: true,
                route_verified: true,
                dns_verified: true,
                firewall_verified: true,
            })
    }
}

async fn wait_for_condition(mut condition: impl FnMut() -> bool, message: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while !condition() {
        assert!(tokio::time::Instant::now() < deadline, "{message}");
        tokio::task::yield_now().await;
    }
}

async fn observe_connected(service: &ControlService, profile_id: &ProfileId, interface_name: &str) {
    let desired = service.client().snapshot().desired;
    service
        .observer()
        .observe(Observation::Tunnel {
            profile_id: profile_id.clone(),
            active: true,
            interface_name: Some(interface_name.into()),
            observed_at_millis: 0,
            protection: Some(ProtectionEvidence {
                desired_generation: desired.generation,
                authority_epoch: desired.authority_epoch,
                policy_digest: desired.policy_digest,
                observed_at_millis: 0,
                interface: GateEvidence::Verified,
                route: GateEvidence::Verified,
                dns: GateEvidence::Verified,
                firewall: GateEvidence::Verified,
            }),
        })
        .await
        .expect("managed tunnel observation accepted");
}

async fn observe_disconnected(service: &ControlService, profile_id: &ProfileId) {
    let desired = service.client().snapshot().desired;
    service
        .observer()
        .observe(Observation::Tunnel {
            profile_id: profile_id.clone(),
            active: false,
            interface_name: None,
            observed_at_millis: 0,
            protection: Some(ProtectionEvidence {
                desired_generation: desired.generation,
                authority_epoch: desired.authority_epoch,
                policy_digest: desired.policy_digest,
                observed_at_millis: 0,
                interface: GateEvidence::Verified,
                route: GateEvidence::Verified,
                dns: GateEvidence::Verified,
                firewall: GateEvidence::Verified,
            }),
        })
        .await
        .expect("managed tunnel absence accepted");
}

async fn set_killswitch_and_settle(
    service: &ControlService,
    capture: &TopologyCapture,
    mode: vortix::vortix_core::state::killswitch::KillSwitchMode,
    key: &str,
) {
    let admitted = service
        .client()
        .submit(CommandRequest {
            command: UserCommand::SetKillSwitch { mode },
            idempotency_key: IdempotencyKey::new(key),
            deadline: Deadline(1_000),
        })
        .await
        .expect("kill-switch change admitted");
    let desired = service.client().snapshot().desired;
    service
        .observer()
        .observe(Observation::Protection(ProtectionEvidence {
            desired_generation: desired.generation,
            authority_epoch: desired.authority_epoch,
            policy_digest: desired.policy_digest,
            observed_at_millis: 0,
            interface: GateEvidence::Verified,
            route: GateEvidence::Verified,
            dns: GateEvidence::Verified,
            firewall: GateEvidence::Verified,
        }))
        .await
        .expect("kill-switch protection evidence accepted");
    wait_for_condition(
        || {
            capture.policies.lock().unwrap().iter().any(|policy| {
                policy.generation == desired.generation && policy.stage == PolicyStage::Final
            }) && service.client().snapshot().operations[&admitted.operation_id].status
                == OperationStatus::Succeeded
        },
        "kill-switch policy did not settle",
    )
    .await;
}

fn topology_service(
    profiles: BTreeSet<ProfileId>,
) -> (ControlService, Arc<Supervisor>, Arc<TopologyCapture>) {
    let capture = Arc::new(TopologyCapture::default());
    let supervisor = Arc::new(Supervisor::new(
        AuthorityEpoch(1),
        capture.clone(),
        capture.clone(),
        profiles.len().max(1),
        8,
    ));
    let profile_topologies = profiles
        .iter()
        .cloned()
        .map(|profile_id| (profile_id, ProfileTopology::default()))
        .collect();
    let service = ControlService::start_supervised(
        ControlServiceConfig {
            authority_epoch: AuthorityEpoch(1),
            known_profiles: profiles,
            profile_topologies,
            freshness_poll_interval: Duration::from_millis(5),
            ..ControlServiceConfig::default()
        },
        Arc::new(TestClock::default()),
        ExecutionSelection::CanonicalAuthority,
        supervisor.clone(),
    );
    (service, supervisor, capture)
}

#[tokio::test]
async fn exact_policy_readback_publishes_protection_without_external_proof() {
    let target = profile("internal-policy-readback");
    let (service, supervisor, capture) = topology_service(BTreeSet::from([target.clone()]));
    capture.publish_readback();
    let admitted = service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Connect {
                profile_id: target.clone(),
            },
            idempotency_key: IdempotencyKey::new("internal-policy-readback"),
            deadline: Deadline(1_000),
        })
        .await
        .unwrap();
    wait_for_condition(
        || !capture.tunnel_calls.lock().unwrap().is_empty(),
        "connect did not dispatch",
    )
    .await;
    wait_for_condition(
        || {
            supervisor
                .profile_truth(&target)
                .is_some_and(|entry| entry.truth == SupervisedTruth::WaitingForObservation)
        },
        "connect receipt did not reach observation gate",
    )
    .await;
    service
        .observer()
        .observe(Observation::Tunnel {
            profile_id: target.clone(),
            active: true,
            interface_name: Some("tun-internal-policy-readback".into()),
            observed_at_millis: 0,
            protection: None,
        })
        .await
        .unwrap();
    wait_for_condition(
        || {
            supervisor
                .profile_truth(&target)
                .is_some_and(|entry| entry.truth == SupervisedTruth::ObservedPresent)
        },
        "tunnel did not settle before policy readback",
    )
    .await;
    wait_for_condition(
        || {
            let snapshot = service.client().snapshot();
            snapshot.operations[&admitted.operation_id].status == OperationStatus::Succeeded
                && snapshot.effective.protection
                    == vortix::vortix_core::control::ProtectionStatus::Protected
        },
        "typed policy readback was not published",
    )
    .await;
}

async fn connect_and_settle(
    service: &ControlService,
    supervisor: &Supervisor,
    capture: &TopologyCapture,
    profile_id: &ProfileId,
    key: &str,
) {
    service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Connect {
                profile_id: profile_id.clone(),
            },
            idempotency_key: IdempotencyKey::new(key),
            deadline: Deadline(1_000),
        })
        .await
        .expect("connect admitted");
    wait_for_condition(
        || {
            capture
                .tunnel_calls
                .lock()
                .unwrap()
                .iter()
                .any(|(called, mutation, _)| {
                    called == profile_id && *mutation == TunnelMutation::Connect
                })
        },
        "tunnel effect was not dispatched",
    )
    .await;
    observe_connected(service, profile_id, &format!("tun-{profile_id}")).await;
    wait_for_condition(
        || {
            supervisor
                .profile_truth(profile_id)
                .is_some_and(|entry| entry.truth == SupervisedTruth::ObservedPresent)
        },
        "tunnel did not settle",
    )
    .await;
}

async fn connect_then_enable_required_blocking(
    service: &ControlService,
    supervisor: &Supervisor,
    capture: &TopologyCapture,
    profile_id: &ProfileId,
    key: &str,
) {
    connect_and_settle(service, supervisor, capture, profile_id, key).await;
    set_killswitch_and_settle(
        service,
        capture,
        vortix::vortix_core::state::killswitch::KillSwitchMode::Auto,
        &format!("{key}-blocking"),
    )
    .await;
}

#[tokio::test]
async fn disconnect_waits_for_exact_pre_block_and_keeps_transition_at_final_stage() {
    let target = profile("preblocked-disconnect");
    let (service, supervisor, capture) = topology_service(BTreeSet::from([target.clone()]));
    connect_then_enable_required_blocking(
        &service,
        &supervisor,
        &capture,
        &target,
        "prepare-disconnect",
    )
    .await;
    set_killswitch_and_settle(
        &service,
        &capture,
        vortix::vortix_core::state::killswitch::KillSwitchMode::AlwaysOn,
        "disconnect-vpn-only",
    )
    .await;
    let baseline = capture.tunnel_calls.lock().unwrap().len();
    let generation = service
        .client()
        .snapshot()
        .desired
        .generation
        .saturating_add(1);
    capture.hold_pre_block(generation);
    service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Disconnect {
                profile_id: Some(target.clone()),
            },
            idempotency_key: IdempotencyKey::new("preblocked-disconnect"),
            deadline: Deadline(1_000),
        })
        .await
        .expect("disconnect admitted");

    wait_for_condition(
        || capture.pre_block_entered(generation),
        "disconnect pre-block did not enter",
    )
    .await;
    assert_eq!(
        capture.tunnel_calls.lock().unwrap().len(),
        baseline,
        "teardown executed before the pre-block receipt"
    );

    capture.release_pre_block(generation);
    wait_for_condition(
        || capture.tunnel_calls.lock().unwrap().len() > baseline,
        "disconnect did not execute after the pre-block receipt",
    )
    .await;
    observe_disconnected(&service, &target).await;
    wait_for_condition(
        || {
            capture.policies.lock().unwrap().iter().any(|policy| {
                policy.generation == generation
                    && policy.stage == PolicyStage::Final
                    && policy.transition == TopologyTransitionKind::Disconnect
            })
        },
        "disconnect final policy lost its captured transition",
    )
    .await;
}

#[tokio::test]
async fn reconnect_teardown_waits_for_pre_block_and_final_policy_waits_for_observation() {
    let target = profile("preblocked-reconnect");
    let (service, supervisor, capture) = topology_service(BTreeSet::from([target.clone()]));
    connect_then_enable_required_blocking(
        &service,
        &supervisor,
        &capture,
        &target,
        "prepare-reconnect",
    )
    .await;
    let baseline = capture.tunnel_calls.lock().unwrap().len();
    let generation = service
        .client()
        .snapshot()
        .desired
        .generation
        .saturating_add(1);
    capture.hold_pre_block(generation);
    service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Reconnect {
                profile_id: Some(target.clone()),
            },
            idempotency_key: IdempotencyKey::new("preblocked-reconnect"),
            deadline: Deadline(1_000),
        })
        .await
        .expect("reconnect admitted");

    wait_for_condition(
        || capture.pre_block_entered(generation),
        "reconnect pre-block did not enter",
    )
    .await;
    assert_eq!(capture.tunnel_calls.lock().unwrap().len(), baseline);
    capture.release_pre_block(generation);
    wait_for_condition(
        || {
            capture.tunnel_calls.lock().unwrap().iter().any(
                |(profile_id, mutation, call_generation)| {
                    profile_id == &target
                        && *mutation == TunnelMutation::Disconnect
                        && *call_generation == generation
                },
            )
        },
        "reconnect teardown did not execute after pre-block",
    )
    .await;
    assert!(!capture
        .policies
        .lock()
        .unwrap()
        .iter()
        .any(|policy| { policy.generation == generation && policy.stage == PolicyStage::Final }));

    observe_disconnected(&service, &target).await;
    wait_for_condition(
        || {
            capture.tunnel_calls.lock().unwrap().iter().any(
                |(profile_id, mutation, call_generation)| {
                    profile_id == &target
                        && *mutation == TunnelMutation::Connect
                        && *call_generation == generation
                },
            )
        },
        "reconnect bring-up did not execute after teardown observation",
    )
    .await;
    assert!(!capture
        .policies
        .lock()
        .unwrap()
        .iter()
        .any(|policy| { policy.generation == generation && policy.stage == PolicyStage::Final }));
    observe_connected(&service, &target, "tun-preblocked-reconnect").await;
    wait_for_condition(
        || {
            capture.policies.lock().unwrap().iter().any(|policy| {
                policy.generation == generation
                    && policy.stage == PolicyStage::Final
                    && policy.transition == TopologyTransitionKind::Reconnect
            })
        },
        "reconnect final policy did not wait for the connected observation",
    )
    .await;
}

#[tokio::test]
async fn failed_pre_block_terminalizes_without_dispatching_teardown() {
    let target = profile("failed-preblock");
    let (service, supervisor, capture) = topology_service(BTreeSet::from([target.clone()]));
    connect_then_enable_required_blocking(
        &service,
        &supervisor,
        &capture,
        &target,
        "prepare-failed-preblock",
    )
    .await;
    set_killswitch_and_settle(
        &service,
        &capture,
        vortix::vortix_core::state::killswitch::KillSwitchMode::AlwaysOn,
        "failed-preblock-vpn-only",
    )
    .await;
    let baseline = capture.tunnel_calls.lock().unwrap().len();
    let generation = service
        .client()
        .snapshot()
        .desired
        .generation
        .saturating_add(1);
    capture.fail_pre_block(generation);
    let admitted = service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Disconnect {
                profile_id: Some(target),
            },
            idempotency_key: IdempotencyKey::new("failed-preblock"),
            deadline: Deadline(1_000),
        })
        .await
        .expect("disconnect admitted");
    wait_for_condition(
        || {
            service.client().snapshot().operations[&admitted.operation_id].status
                == OperationStatus::Failed
        },
        "pre-block failure did not terminalize the operation",
    )
    .await;
    assert_eq!(
        capture.tunnel_calls.lock().unwrap().len(),
        baseline,
        "failed pre-block allowed teardown"
    );
}

#[tokio::test]
async fn failed_final_policy_never_publishes_terminal_success() {
    let target = profile("failed-final-policy");
    let (service, supervisor, capture) = topology_service(BTreeSet::from([target.clone()]));
    connect_then_enable_required_blocking(
        &service,
        &supervisor,
        &capture,
        &target,
        "prepare-failed-final",
    )
    .await;
    let generation = service
        .client()
        .snapshot()
        .desired
        .generation
        .saturating_add(1);
    capture.fail_final(generation);
    let admitted = service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Reconnect {
                profile_id: Some(target.clone()),
            },
            idempotency_key: IdempotencyKey::new("failed-final-policy"),
            deadline: Deadline(1_000),
        })
        .await
        .expect("reconnect admitted");
    wait_for_condition(
        || capture.pre_block_entered(generation),
        "reconnect pre-block did not apply",
    )
    .await;
    wait_for_condition(
        || {
            capture.tunnel_calls.lock().unwrap().iter().any(
                |(profile_id, mutation, call_generation)| {
                    profile_id == &target
                        && *mutation == TunnelMutation::Disconnect
                        && *call_generation == generation
                },
            )
        },
        "reconnect teardown did not dispatch",
    )
    .await;
    observe_disconnected(&service, &target).await;
    wait_for_condition(
        || {
            capture.tunnel_calls.lock().unwrap().iter().any(
                |(profile_id, mutation, call_generation)| {
                    profile_id == &target
                        && *mutation == TunnelMutation::Connect
                        && *call_generation == generation
                },
            )
        },
        "reconnect bring-up did not dispatch",
    )
    .await;
    observe_connected(&service, &target, "tun-failed-final-policy").await;
    wait_for_condition(
        || {
            service.client().snapshot().operations[&admitted.operation_id].status
                == OperationStatus::Failed
        },
        "final policy failure did not terminalize visibly",
    )
    .await;
    assert_ne!(
        service.client().snapshot().operations[&admitted.operation_id].status,
        OperationStatus::Succeeded
    );
}

#[tokio::test]
async fn nonblocking_connect_dispatches_before_final_policy_and_final_waits_for_observation() {
    let target = profile("nonblocking-connect");
    let (service, _, capture) = topology_service(BTreeSet::from([target.clone()]));
    let admitted = service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Connect {
                profile_id: target.clone(),
            },
            idempotency_key: IdempotencyKey::new("nonblocking-connect"),
            deadline: Deadline(1_000),
        })
        .await
        .expect("connect admitted");
    let generation = service.client().snapshot().desired.generation;
    wait_for_condition(
        || !capture.tunnel_calls.lock().unwrap().is_empty(),
        "non-blocking connect was not dispatched",
    )
    .await;
    assert!(capture
        .policies
        .lock()
        .unwrap()
        .iter()
        .all(|policy| { policy.generation != generation || policy.stage != PolicyStage::Final }));
    observe_connected(&service, &target, "tun-nonblocking-connect").await;
    wait_for_condition(
        || {
            capture.policies.lock().unwrap().iter().any(|policy| {
                policy.generation == generation
                    && policy.stage == PolicyStage::Final
                    && policy.transition == TopologyTransitionKind::Connect
            })
        },
        "final connect policy did not follow tunnel observation",
    )
    .await;
    assert_ne!(
        service.client().snapshot().operations[&admitted.operation_id].status,
        OperationStatus::Failed
    );
}

#[tokio::test]
async fn block_on_drop_skips_pre_block_for_normal_connect_and_intentional_disconnect() {
    let target = profile("auto-normal-lifecycle");
    let (service, supervisor, capture) = topology_service(BTreeSet::from([target.clone()]));
    set_killswitch_and_settle(
        &service,
        &capture,
        vortix::vortix_core::state::killswitch::KillSwitchMode::Auto,
        "auto-before-connect",
    )
    .await;

    let connect_generation = service
        .client()
        .snapshot()
        .desired
        .generation
        .saturating_add(1);
    capture.hold_pre_block(connect_generation);
    connect_and_settle(
        &service,
        &supervisor,
        &capture,
        &target,
        "auto-normal-connect",
    )
    .await;
    assert!(!capture.pre_block_entered(connect_generation));

    let baseline = capture.tunnel_calls.lock().unwrap().len();
    let disconnect_generation = service
        .client()
        .snapshot()
        .desired
        .generation
        .saturating_add(1);
    capture.hold_pre_block(disconnect_generation);
    service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Disconnect {
                profile_id: Some(target.clone()),
            },
            idempotency_key: IdempotencyKey::new("auto-normal-disconnect"),
            deadline: Deadline(1_000),
        })
        .await
        .expect("disconnect admitted");
    wait_for_condition(
        || capture.tunnel_calls.lock().unwrap().len() > baseline,
        "intentional block-on-drop disconnect did not dispatch",
    )
    .await;
    assert!(!capture.pre_block_entered(disconnect_generation));
    observe_disconnected(&service, &target).await;
}

#[tokio::test]
async fn connecting_second_profile_preserves_settled_first_tunnel_revision() {
    let first = profile("stable-first");
    let second = profile("new-second");
    let (service, supervisor, capture) =
        topology_service(BTreeSet::from([first.clone(), second.clone()]));
    connect_and_settle(
        &service,
        &supervisor,
        &capture,
        &first,
        "connect-stable-first",
    )
    .await;
    let first_calls = capture.tunnel_calls.lock().unwrap().len();

    connect_and_settle(
        &service,
        &supervisor,
        &capture,
        &second,
        "connect-new-second",
    )
    .await;
    let second_generation = service.client().snapshot().desired.generation;
    wait_for_condition(
        || {
            capture.policies.lock().unwrap().iter().any(|policy| {
                policy.generation == second_generation
                    && policy.target.profiles == BTreeSet::from([first.clone(), second.clone()])
            })
        },
        "two-tunnel topology did not reach the policy worker",
    )
    .await;

    assert_eq!(
        capture
            .tunnel_calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(profile_id, _, _)| profile_id == &first)
            .count(),
        first_calls,
        "adding a profile must not mutate an already-settled tunnel"
    );
}

#[tokio::test]
async fn kill_switch_change_preserves_settled_tunnel_revision() {
    let target = profile("stable-policy");
    let (service, supervisor, capture) = topology_service(BTreeSet::from([target.clone()]));
    connect_and_settle(
        &service,
        &supervisor,
        &capture,
        &target,
        "connect-stable-policy",
    )
    .await;
    let tunnel_calls_before = capture.tunnel_calls.lock().unwrap().len();

    service
        .client()
        .submit(CommandRequest {
            command: UserCommand::SetKillSwitch {
                mode: vortix::vortix_core::state::killswitch::KillSwitchMode::Auto,
            },
            idempotency_key: IdempotencyKey::new("change-policy-only"),
            deadline: Deadline(1_000),
        })
        .await
        .expect("kill-switch change admitted");
    let desired = service.client().snapshot().desired;
    let policy_generation = desired.generation;
    service
        .observer()
        .observe(Observation::Protection(ProtectionEvidence {
            desired_generation: desired.generation,
            authority_epoch: desired.authority_epoch,
            policy_digest: desired.policy_digest,
            observed_at_millis: 0,
            interface: GateEvidence::Verified,
            route: GateEvidence::Verified,
            dns: GateEvidence::Verified,
            firewall: GateEvidence::Verified,
        }))
        .await
        .expect("policy evidence accepted");
    wait_for_condition(
        || {
            capture.policies.lock().unwrap().iter().any(|policy| {
                policy.generation == policy_generation
                    && policy.target.kill_switch
                        == vortix::vortix_core::state::killswitch::KillSwitchMode::Auto
            })
        },
        "kill-switch-only topology did not reach the policy worker",
    )
    .await;

    assert_eq!(
        capture.tunnel_calls.lock().unwrap().len(),
        tunnel_calls_before,
        "policy-only changes must not mutate settled tunnels"
    );
}

#[tokio::test]
async fn first_policy_after_restart_uses_initial_firewall_mode_as_rollback_baseline() {
    use vortix::vortix_core::state::killswitch::KillSwitchMode;

    let capture = Arc::new(TopologyCapture::default());
    let supervisor = Arc::new(Supervisor::new(
        AuthorityEpoch(1),
        capture.clone(),
        capture.clone(),
        1,
        8,
    ));
    let service = ControlService::start_supervised(
        ControlServiceConfig {
            authority_epoch: AuthorityEpoch(1),
            initial_kill_switch_mode: KillSwitchMode::AlwaysOn,
            freshness_poll_interval: Duration::from_millis(5),
            ..ControlServiceConfig::default()
        },
        Arc::new(TestClock::default()),
        ExecutionSelection::CanonicalAuthority,
        supervisor,
    );

    service
        .client()
        .submit(CommandRequest {
            command: UserCommand::SetKillSwitch {
                mode: KillSwitchMode::AlwaysOn,
            },
            idempotency_key: IdempotencyKey::new("restart-vpn-only"),
            deadline: Deadline(1_000),
        })
        .await
        .expect("persisted kill-switch intent is admitted");
    wait_for_condition(
        || !capture.policies.lock().unwrap().is_empty(),
        "restart policy did not reach the worker",
    )
    .await;

    let policy = capture.policies.lock().unwrap()[0].clone();
    assert_eq!(policy.stage, PolicyStage::PreTunnelBlocking);
    assert_eq!(policy.prior.kill_switch, KillSwitchMode::AlwaysOn);
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One end-to-end stale-revision retry and convergence assertion.
async fn later_policy_command_drives_retry_for_older_tunnel_revision() {
    #[derive(Default)]
    struct FailFirstCapture {
        calls: Mutex<Vec<(ProfileId, OperationId, TunnelRevision)>>,
        policies: Mutex<Vec<TopologyPolicy>>,
    }
    impl TunnelExecutor for FailFirstCapture {
        fn execute(
            &self,
            work: &TunnelWork,
            _: &CancellationToken,
        ) -> Result<TunnelExecutionReceipt, String> {
            let mut calls = self.calls.lock().unwrap();
            calls.push((
                work.profile_id.clone(),
                work.operation_id.clone(),
                work.revision,
            ));
            if calls.len() == 1 {
                Err("first attempt failed".into())
            } else {
                Ok(execution_receipt(work))
            }
        }
    }
    impl PolicyExecutor for FailFirstCapture {
        fn apply(&self, policy: &TopologyPolicy, barrier: PolicyBarrier) -> Result<(), String> {
            if barrier == PolicyBarrier::Blocking {
                self.policies.lock().unwrap().push(policy.clone());
            }
            Ok(())
        }

        fn compensate(&self, _: &TopologyPolicy, _: PolicyBarrier) {}
    }

    let target = profile("retry-after-policy");
    let capture = Arc::new(FailFirstCapture::default());
    let supervisor = Arc::new(Supervisor::new(
        AuthorityEpoch(1),
        capture.clone(),
        capture.clone(),
        2,
        4,
    ));
    let service = ControlService::start_supervised(
        ControlServiceConfig {
            authority_epoch: AuthorityEpoch(1),
            known_profiles: BTreeSet::from([target.clone()]),
            profile_topologies: BTreeMap::from([(target.clone(), ProfileTopology::default())]),
            freshness_poll_interval: Duration::from_millis(5),
            ..ControlServiceConfig::default()
        },
        Arc::new(TestClock::default()),
        ExecutionSelection::CanonicalAuthority,
        supervisor.clone(),
    );
    let connect = service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Connect {
                profile_id: target.clone(),
            },
            idempotency_key: IdempotencyKey::new("retry-connect"),
            deadline: Deadline(1_000),
        })
        .await
        .unwrap();
    wait_for_condition(
        || {
            supervisor
                .profile_truth(&target)
                .is_some_and(|entry| matches!(entry.truth, SupervisedTruth::Degraded(_)))
        },
        "failed tunnel attempt was not recorded",
    )
    .await;

    let policy = service
        .client()
        .submit(CommandRequest {
            command: UserCommand::SetKillSwitch {
                mode: vortix::vortix_core::state::killswitch::KillSwitchMode::Auto,
            },
            idempotency_key: IdempotencyKey::new("retry-policy"),
            deadline: Deadline(1_000),
        })
        .await
        .unwrap();
    wait_for_condition(
        || capture.calls.lock().unwrap().len() >= 2,
        "current policy operation did not drive the stale tunnel retry",
    )
    .await;
    let calls = capture.calls.lock().unwrap().clone();
    assert_eq!(calls[1].1, policy.operation_id);
    assert_eq!(calls[1].2.generation, 1);
    drop(calls);

    observe_connected(&service, &target, "tun-retry-after-policy").await;
    wait_for_condition(
        || {
            let snapshot = service.client().snapshot();
            snapshot.operations[&connect.operation_id].status == OperationStatus::Succeeded
                && snapshot.operations[&policy.operation_id].status == OperationStatus::Succeeded
        },
        "fresh policy evidence did not complete compatible operations",
    )
    .await;
}

#[tokio::test]
async fn disjoint_connect_operations_complete_from_shared_current_evidence() {
    let first = profile("pending-first");
    let second = profile("pending-second");
    let (service, _, capture) = topology_service(BTreeSet::from([first.clone(), second.clone()]));
    let first_operation = service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Connect {
                profile_id: first.clone(),
            },
            idempotency_key: IdempotencyKey::new("pending-first"),
            deadline: Deadline(1_000),
        })
        .await
        .unwrap();
    let second_operation = service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Connect {
                profile_id: second.clone(),
            },
            idempotency_key: IdempotencyKey::new("pending-second"),
            deadline: Deadline(1_000),
        })
        .await
        .unwrap();
    wait_for_condition(
        || capture.tunnel_calls.lock().unwrap().len() == 2,
        "both disjoint tunnel effects were not dispatched",
    )
    .await;

    observe_connected(&service, &first, "tun-pending-first").await;
    observe_connected(&service, &second, "tun-pending-second").await;
    wait_for_condition(
        || {
            let snapshot = service.client().snapshot();
            snapshot.operations[&first_operation.operation_id].status == OperationStatus::Succeeded
                && snapshot.operations[&second_operation.operation_id].status
                    == OperationStatus::Succeeded
        },
        "shared current policy evidence did not complete both connects",
    )
    .await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One held-policy race proves superseded intent is cancelled.
async fn opposite_profile_intent_cancels_older_pending_operation() {
    #[derive(Default)]
    struct HeldFirstPolicy {
        entered: Mutex<bool>,
        release: (Mutex<bool>, Condvar),
    }
    impl PolicyExecutor for HeldFirstPolicy {
        fn apply(&self, policy: &TopologyPolicy, barrier: PolicyBarrier) -> Result<(), String> {
            if barrier == PolicyBarrier::Blocking && policy.generation == 1 {
                *self.entered.lock().unwrap() = true;
                let (released, wake) = &self.release;
                let mut released = released.lock().unwrap();
                while !*released {
                    released = wake.wait(released).unwrap();
                }
            }
            Ok(())
        }

        fn compensate(&self, _: &TopologyPolicy, _: PolicyBarrier) {}
    }

    let target = profile("opposite-intent");
    let policy = Arc::new(HeldFirstPolicy::default());
    let capture = Arc::new(TopologyCapture::default());
    let supervisor = Arc::new(Supervisor::new(
        AuthorityEpoch(1),
        capture.clone(),
        policy.clone(),
        2,
        4,
    ));
    let service = ControlService::start_supervised(
        ControlServiceConfig {
            authority_epoch: AuthorityEpoch(1),
            known_profiles: BTreeSet::from([target.clone()]),
            profile_topologies: BTreeMap::from([(target.clone(), ProfileTopology::default())]),
            freshness_poll_interval: Duration::from_millis(5),
            ..ControlServiceConfig::default()
        },
        Arc::new(TestClock::default()),
        ExecutionSelection::CanonicalAuthority,
        supervisor.clone(),
    );
    let connect = service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Connect {
                profile_id: target.clone(),
            },
            idempotency_key: IdempotencyKey::new("opposite-connect"),
            deadline: Deadline(1_000),
        })
        .await
        .unwrap();
    wait_for_condition(
        || !capture.tunnel_calls.lock().unwrap().is_empty(),
        "connect was not dispatched",
    )
    .await;
    observe_connected(&service, &target, "tun-opposite-intent").await;
    wait_for_condition(
        || *policy.entered.lock().unwrap(),
        "first-generation policy did not enter the held worker",
    )
    .await;

    let disconnect = service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Disconnect {
                profile_id: Some(target.clone()),
            },
            idempotency_key: IdempotencyKey::new("opposite-disconnect"),
            deadline: Deadline(1_000),
        })
        .await
        .unwrap();
    wait_for_condition(
        || {
            capture
                .tunnel_calls
                .lock()
                .unwrap()
                .iter()
                .any(|(profile_id, mutation, _)| {
                    profile_id == &target && *mutation == TunnelMutation::Disconnect
                })
        },
        "opposite disconnect was not dispatched",
    )
    .await;
    {
        let (released, wake) = &policy.release;
        *released.lock().unwrap() = true;
        wake.notify_all();
    }
    wait_for_condition(
        || {
            supervisor.profile_truth(&target).is_some_and(|entry| {
                entry.mutation == TunnelMutation::Disconnect
                    && entry.truth == SupervisedTruth::WaitingForObservation
            })
        },
        "disconnect did not reach its observation barrier",
    )
    .await;
    let desired = service.client().snapshot().desired;
    service
        .observer()
        .observe(Observation::Tunnel {
            profile_id: target,
            active: false,
            interface_name: None,
            observed_at_millis: 0,
            protection: Some(ProtectionEvidence {
                desired_generation: desired.generation,
                authority_epoch: desired.authority_epoch,
                policy_digest: desired.policy_digest,
                observed_at_millis: 0,
                interface: GateEvidence::Verified,
                route: GateEvidence::Verified,
                dns: GateEvidence::Verified,
                firewall: GateEvidence::Verified,
            }),
        })
        .await
        .unwrap();
    wait_for_condition(
        || {
            let snapshot = service.client().snapshot();
            snapshot.operations[&connect.operation_id].status == OperationStatus::Cancelled
                && snapshot.operations[&disconnect.operation_id].status
                    == OperationStatus::Succeeded
        },
        "opposite intent did not cancel the superseded operation",
    )
    .await;
}

#[tokio::test]
async fn canonical_service_dispatches_admitted_mutation_without_blocking_snapshots() {
    struct CountingExecutor(Mutex<Vec<TunnelMutation>>);
    impl TunnelExecutor for CountingExecutor {
        fn execute(
            &self,
            work: &TunnelWork,
            _: &CancellationToken,
        ) -> Result<TunnelExecutionReceipt, String> {
            self.0.lock().unwrap().push(work.mutation);
            Ok(execution_receipt(work))
        }
    }

    let target = profile("canonical");
    let executor = Arc::new(CountingExecutor(Mutex::new(Vec::new())));
    let supervisor = Arc::new(Supervisor::new(
        AuthorityEpoch(1),
        executor.clone(),
        Arc::new(OkPolicy),
        2,
        4,
    ));
    let service = ControlService::start_supervised(
        ControlServiceConfig {
            authority_epoch: AuthorityEpoch(1),
            known_profiles: BTreeSet::from([target.clone()]),
            profile_topologies: BTreeMap::from([(target.clone(), ProfileTopology::default())]),
            freshness_poll_interval: Duration::from_millis(5),
            ..ControlServiceConfig::default()
        },
        Arc::new(TestClock::default()),
        ExecutionSelection::CanonicalAuthority,
        supervisor,
    );
    let client = service.client();
    client
        .submit(CommandRequest {
            command: UserCommand::Connect {
                profile_id: target.clone(),
            },
            idempotency_key: IdempotencyKey::new("canonical-connect"),
            deadline: Deadline(1_000),
        })
        .await
        .expect("canonical operation admitted");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while executor.0.lock().unwrap().is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "effect was not dispatched"
        );
        assert_eq!(client.snapshot().desired.authority_epoch, AuthorityEpoch(1));
        tokio::task::yield_now().await;
    }

    let desired = client.snapshot().desired;
    service
        .observer()
        .observe(Observation::Tunnel {
            profile_id: target.clone(),
            active: true,
            interface_name: Some("tun-canonical".into()),
            observed_at_millis: 0,
            protection: Some(ProtectionEvidence {
                desired_generation: desired.generation,
                authority_epoch: desired.authority_epoch,
                policy_digest: desired.policy_digest,
                observed_at_millis: 0,
                interface: GateEvidence::Verified,
                route: GateEvidence::Verified,
                dns: GateEvidence::Verified,
                firewall: GateEvidence::Verified,
            }),
        })
        .await
        .expect("fresh managed observation accepted");
    client
        .submit(CommandRequest {
            command: UserCommand::Disconnect {
                profile_id: Some(target),
            },
            idempotency_key: IdempotencyKey::new("canonical-disconnect"),
            deadline: Deadline(1_000),
        })
        .await
        .expect("disconnect admitted after connect observation");
    while !executor
        .0
        .lock()
        .unwrap()
        .contains(&TunnelMutation::Disconnect)
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "stale managed generation was not cleaned up"
        );
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn unanswered_interactive_challenge_fails_closed_without_recovery_connect() {
    struct ChallengeFailure;
    impl TunnelExecutor for ChallengeFailure {
        fn execute(
            &self,
            _: &TunnelWork,
            _: &CancellationToken,
        ) -> Result<TunnelExecutionReceipt, String> {
            Err("interactive challenge was cancelled or expired".into())
        }

        fn classify_failure(&self, _: &str) -> WorkFailure {
            WorkFailure::ChallengeFailed
        }
    }

    let target = profile("challenge-profile");
    let supervisor = Arc::new(Supervisor::new(
        AuthorityEpoch(1),
        Arc::new(ChallengeFailure),
        Arc::new(OkPolicy),
        2,
        4,
    ));
    let service = ControlService::start_supervised(
        ControlServiceConfig {
            authority_epoch: AuthorityEpoch(1),
            known_profiles: BTreeSet::from([target.clone()]),
            profile_topologies: BTreeMap::from([(target.clone(), ProfileTopology::default())]),
            freshness_poll_interval: Duration::from_millis(5),
            ..ControlServiceConfig::default()
        },
        Arc::new(TestClock::default()),
        ExecutionSelection::CanonicalAuthority,
        supervisor,
    );
    let client = service.client();
    let admitted = client
        .submit(CommandRequest {
            command: UserCommand::Connect {
                profile_id: target.clone(),
            },
            idempotency_key: IdempotencyKey::new("challenge-fails-closed"),
            deadline: Deadline(1_000),
        })
        .await
        .expect("connect admitted");

    wait_for_condition(
        || {
            let snapshot = client.snapshot();
            snapshot.operations[&admitted.operation_id].status == OperationStatus::Failed
                && snapshot.desired.tunnels.get(&target)
                    == Some(&RequestedTunnelState::Disconnected)
                && snapshot
                    .operations
                    .values()
                    .all(|operation| operation.status.is_terminal())
        },
        "challenge failure did not roll back connected intent",
    )
    .await;
}

#[tokio::test]
async fn interactive_operation_expiry_rolls_back_without_service_recovery() {
    struct WaitingExecutor;
    impl TunnelExecutor for WaitingExecutor {
        fn execute(
            &self,
            _: &TunnelWork,
            cancellation: &CancellationToken,
        ) -> Result<TunnelExecutionReceipt, String> {
            while !cancellation.is_cancelled() {
                std::thread::yield_now();
            }
            Err("cancelled".into())
        }
    }

    let target = profile("interactive-expiry");
    let clock = Arc::new(TestClock::default());
    let supervisor = Arc::new(Supervisor::new(
        AuthorityEpoch(1),
        Arc::new(WaitingExecutor),
        Arc::new(OkPolicy),
        2,
        4,
    ));
    let service = ControlService::start_supervised(
        ControlServiceConfig {
            authority_epoch: AuthorityEpoch(1),
            known_profiles: BTreeSet::from([target.clone()]),
            profile_topologies: BTreeMap::from([(
                target.clone(),
                ProfileTopology {
                    interactive_credentials: true,
                    ..ProfileTopology::default()
                },
            )]),
            freshness_poll_interval: Duration::from_millis(5),
            ..ControlServiceConfig::default()
        },
        clock.clone(),
        ExecutionSelection::CanonicalAuthority,
        supervisor,
    );
    let client = service.client();
    let admitted = client
        .submit(CommandRequest {
            command: UserCommand::Connect {
                profile_id: target.clone(),
            },
            idempotency_key: IdempotencyKey::new("interactive-expiry"),
            deadline: Deadline(10),
        })
        .await
        .expect("connect admitted");
    clock.0.store(10, Ordering::Release);
    client.refresh().expect("expiry refresh");

    wait_for_condition(
        || {
            let snapshot = client.snapshot();
            snapshot.operations[&admitted.operation_id].status == OperationStatus::Expired
                && snapshot.desired.tunnels.get(&target)
                    == Some(&RequestedTunnelState::Disconnected)
                && snapshot.operations.len() == 1
        },
        "interactive expiry retained connected intent or started recovery",
    )
    .await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One end-to-end admission, effect, and hook assertion.
async fn reconnect_all_targets_only_currently_managed_profiles() {
    #[derive(Default)]
    struct Capture(Mutex<Vec<(ProfileId, OperationId, TunnelRevision, TunnelMutation)>>);
    impl TunnelExecutor for Capture {
        fn execute(
            &self,
            work: &TunnelWork,
            _: &CancellationToken,
        ) -> Result<TunnelExecutionReceipt, String> {
            self.0.lock().unwrap().push((
                work.profile_id.clone(),
                work.operation_id.clone(),
                work.revision,
                work.mutation,
            ));
            Ok(execution_receipt(work))
        }
    }

    let connected = profile("connected");
    let disconnected = profile("disconnected");
    let executor = Arc::new(Capture::default());
    let supervisor = Arc::new(Supervisor::new(
        AuthorityEpoch(1),
        executor.clone(),
        Arc::new(OkPolicy),
        4,
        8,
    ));
    let service = ControlService::start_supervised(
        ControlServiceConfig {
            authority_epoch: AuthorityEpoch(1),
            known_profiles: BTreeSet::from([connected.clone(), disconnected.clone()]),
            profile_topologies: BTreeMap::from([
                (
                    connected.clone(),
                    ProfileTopology {
                        protocol: Some(ProtocolKind::OpenVpn),
                        ..ProfileTopology::default()
                    },
                ),
                (
                    disconnected.clone(),
                    ProfileTopology {
                        protocol: Some(ProtocolKind::OpenVpn),
                        ..ProfileTopology::default()
                    },
                ),
            ]),
            freshness_poll_interval: Duration::from_millis(5),
            ..ControlServiceConfig::default()
        },
        Arc::new(TestClock::default()),
        ExecutionSelection::CanonicalAuthority,
        supervisor.clone(),
    );
    let client = service.client();

    client
        .submit(CommandRequest {
            command: UserCommand::Disconnect {
                profile_id: Some(disconnected.clone()),
            },
            idempotency_key: IdempotencyKey::new("keep-disconnected"),
            deadline: Deadline(1_000),
        })
        .await
        .expect("explicit disconnected intent admitted");
    assert_eq!(
        client.snapshot().desired.tunnels.get(&disconnected),
        Some(&RequestedTunnelState::Disconnected)
    );

    client
        .submit(CommandRequest {
            command: UserCommand::Connect {
                profile_id: connected.clone(),
            },
            idempotency_key: IdempotencyKey::new("connect-managed"),
            deadline: Deadline(1_000),
        })
        .await
        .expect("managed connect admitted");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while !executor
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|(profile_id, _, _, mutation)| {
            profile_id == &connected && *mutation == TunnelMutation::Connect
        })
    {
        assert!(tokio::time::Instant::now() < deadline, "connect dispatched");
        tokio::task::yield_now().await;
    }
    let desired = client.snapshot().desired;
    service
        .observer()
        .observe(Observation::Tunnel {
            profile_id: connected.clone(),
            active: true,
            interface_name: Some("tun-connected".into()),
            observed_at_millis: 0,
            protection: Some(ProtectionEvidence {
                desired_generation: desired.generation,
                authority_epoch: desired.authority_epoch,
                policy_digest: desired.policy_digest,
                observed_at_millis: 0,
                interface: GateEvidence::Verified,
                route: GateEvidence::Verified,
                dns: GateEvidence::Verified,
                firewall: GateEvidence::Verified,
            }),
        })
        .await
        .expect("managed connection observed");
    while supervisor
        .profile_truth(&connected)
        .is_none_or(|entry| entry.truth != SupervisedTruth::ObservedPresent)
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "managed connection promoted"
        );
        tokio::task::yield_now().await;
    }

    let mut events = client.subscribe();
    let executions_before = executor.0.lock().unwrap().len();
    let reconnect = client
        .submit(CommandRequest {
            command: UserCommand::Reconnect { profile_id: None },
            idempotency_key: IdempotencyKey::new("reconnect-managed-only"),
            deadline: Deadline(1_000),
        })
        .await
        .expect("reconnect-all admitted for the managed target only");

    let mut reconnecting = Vec::new();
    let mut command_seen = false;
    loop {
        let event = tokio::time::timeout(Duration::from_secs(1), events.recv_event())
            .await
            .expect("control event timeout")
            .expect("control service remains live")
            .event;
        match event {
            ControlEvent::OperationAdmitted { operation_id, .. }
                if operation_id == reconnect.operation_id =>
            {
                command_seen = true;
            }
            ControlEvent::Lifecycle { fact }
                if command_seen && fact.event == HookEvent::Reconnecting =>
            {
                reconnecting.push(fact.profile_id);
            }
            ControlEvent::DesiredStateChanged { .. } if command_seen => break,
            _ => {}
        }
    }
    assert_eq!(reconnecting, vec![connected.clone()]);
    assert_eq!(
        client.snapshot().desired.tunnels.get(&disconnected),
        Some(&RequestedTunnelState::Disconnected)
    );
    let reconnect_revision = tunnel_revision(client.snapshot().desired.generation);
    wait_for_condition(
        || {
            executor.0.lock().unwrap()[executions_before..].iter().any(
                |(profile_id, operation_id, revision, mutation)| {
                    profile_id == &connected
                        && operation_id == &reconnect.operation_id
                        && revision == &reconnect_revision
                        && *mutation == TunnelMutation::Disconnect
                },
            )
        },
        "reconnect teardown was not dispatched",
    )
    .await;
    assert!(executor.0.lock().unwrap()[executions_before..]
        .iter()
        .all(|(profile_id, _, _, _)| profile_id == &connected));

    wait_for_condition(
        || {
            supervisor.profile_truth(&connected).is_some_and(|entry| {
                entry.operation_id == reconnect.operation_id
                    && entry.revision == reconnect_revision
                    && entry.mutation == TunnelMutation::Disconnect
                    && entry.truth == SupervisedTruth::WaitingForObservation
            })
        },
        "reconnect teardown did not reach its observation barrier",
    )
    .await;
    let desired = client.snapshot().desired;
    service
        .observer()
        .observe(Observation::Tunnel {
            profile_id: connected.clone(),
            active: false,
            interface_name: None,
            observed_at_millis: 0,
            protection: Some(ProtectionEvidence {
                desired_generation: desired.generation,
                authority_epoch: desired.authority_epoch,
                policy_digest: desired.policy_digest.clone(),
                observed_at_millis: 0,
                interface: GateEvidence::Verified,
                route: GateEvidence::Verified,
                dns: GateEvidence::Verified,
                firewall: GateEvidence::Verified,
            }),
        })
        .await
        .expect("reconnect absence observed");

    wait_for_condition(
        || {
            executor.0.lock().unwrap()[executions_before..].iter().any(
                |(profile_id, operation_id, revision, mutation)| {
                    profile_id == &connected
                        && operation_id == &reconnect.operation_id
                        && revision == &reconnect_revision
                        && *mutation == TunnelMutation::Connect
                },
            )
        },
        "reconnect did not dispatch its second-phase connect",
    )
    .await;
    wait_for_condition(
        || {
            supervisor.profile_truth(&connected).is_some_and(|entry| {
                entry.operation_id == reconnect.operation_id
                    && entry.revision == reconnect_revision
                    && entry.mutation == TunnelMutation::Connect
                    && entry.truth == SupervisedTruth::WaitingForObservation
            })
        },
        "reconnect connect did not reach its observation barrier",
    )
    .await;
    service
        .observer()
        .observe(Observation::Tunnel {
            profile_id: connected.clone(),
            active: true,
            interface_name: Some("tun-connected".into()),
            observed_at_millis: 0,
            protection: Some(ProtectionEvidence {
                desired_generation: desired.generation,
                authority_epoch: desired.authority_epoch,
                policy_digest: desired.policy_digest.clone(),
                observed_at_millis: 0,
                interface: GateEvidence::Verified,
                route: GateEvidence::Verified,
                dns: GateEvidence::Verified,
                firewall: GateEvidence::Verified,
            }),
        })
        .await
        .expect("reconnect presence observed");
    wait_for_condition(
        || {
            supervisor.profile_truth(&connected).is_some_and(|entry| {
                entry.operation_id == reconnect.operation_id
                    && entry.revision == reconnect_revision
                    && entry.truth == SupervisedTruth::ObservedPresent
            })
        },
        "reconnect presence did not settle",
    )
    .await;
    assert_eq!(
        service
            .completer()
            .complete(OperationCompletion {
                operation_id: reconnect.operation_id.clone(),
                desired_generation: desired.generation,
                outcome: CompletionOutcome::ObservedSuccess(ProtectionEvidence {
                    desired_generation: desired.generation,
                    authority_epoch: desired.authority_epoch,
                    policy_digest: desired.policy_digest,
                    observed_at_millis: 0,
                    interface: GateEvidence::Verified,
                    route: GateEvidence::Verified,
                    dns: GateEvidence::Verified,
                    firewall: GateEvidence::Verified,
                }),
            })
            .await,
        Ok(CompletionResult::Terminal(OperationStatus::Succeeded))
    );
    wait_for_condition(
        || {
            client.snapshot().operations[&reconnect.operation_id].status
                == OperationStatus::Succeeded
        },
        "reconnect operation did not converge",
    )
    .await;
}

#[tokio::test]
async fn canonical_profile_limit_returns_busy_before_operation_admission() {
    let occupied = profile("occupied");
    let rejected = profile("rejected");
    let supervisor = Arc::new(Supervisor::new(
        AuthorityEpoch(1),
        Arc::new(OkExecutor),
        Arc::new(OkPolicy),
        1,
        1,
    ));
    supervisor
        .dispatch_tunnel(
            work(occupied.clone(), 1, 1, TunnelMutation::Connect),
            Vec::new(),
        )
        .unwrap();
    let service = ControlService::start_supervised(
        ControlServiceConfig {
            authority_epoch: AuthorityEpoch(1),
            known_profiles: BTreeSet::from([occupied.clone(), rejected.clone()]),
            profile_topologies: BTreeMap::from([
                (occupied, ProfileTopology::default()),
                (rejected.clone(), ProfileTopology::default()),
            ]),
            ..ControlServiceConfig::default()
        },
        Arc::new(TestClock::default()),
        ExecutionSelection::CanonicalAuthority,
        supervisor,
    );
    let result = service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Connect {
                profile_id: rejected,
            },
            idempotency_key: IdempotencyKey::new("bounded-profile"),
            deadline: Deadline(1_000),
        })
        .await;
    assert_eq!(
        result,
        Err(vortix::vortix_core::control::AdmissionError::Busy)
    );
    assert!(service.client().snapshot().operations.is_empty());
}

#[test]
fn scanner_confirmation_requires_exact_successful_protocol_receipt() {
    let target = profile("receipt");
    let supervisor = Supervisor::new(
        AuthorityEpoch(1),
        Arc::new(OkExecutor),
        Arc::new(OkPolicy),
        2,
        4,
    );
    let item = work(target.clone(), 1, 1, TunnelMutation::Connect);
    let revision = item.revision;
    supervisor.dispatch_tunnel(item, Vec::new()).unwrap();
    assert_eq!(
        supervisor.confirm_tunnel(&target, &revision, true, Some("tun-receipt")),
        Err(WorkFailure::Busy),
        "Reserved work cannot be promoted from scanner presence"
    );
    wait_until(Duration::from_secs(1), || supervisor.poll_tunnel()).expect("typed worker receipt");
    assert_eq!(
        supervisor.confirm_tunnel(&target, &revision, true, Some("wrong-interface")),
        Err(WorkFailure::EffectFailed)
    );
    supervisor
        .confirm_tunnel(&target, &revision, true, Some("tun-receipt"))
        .unwrap();
    assert_eq!(
        supervisor.profile_truth(&target).unwrap().truth,
        vortix::vortix_core::control::supervisor::SupervisedTruth::ObservedPresent
    );
}

#[tokio::test]
async fn admission_reserves_normalized_routes_before_desired_mutation() {
    let first = profile("route-a");
    let second = profile("route-b");
    let supervisor = Arc::new(Supervisor::new(
        AuthorityEpoch(1),
        Arc::new(OkExecutor),
        Arc::new(OkPolicy),
        2,
        4,
    ));
    let service = ControlService::start_supervised(
        ControlServiceConfig {
            authority_epoch: AuthorityEpoch(1),
            known_profiles: BTreeSet::from([first.clone(), second.clone()]),
            profile_topologies: BTreeMap::from([
                (
                    first.clone(),
                    ProfileTopology {
                        routes: BTreeSet::from(["10.44.0.9/24".into()]),
                        ..ProfileTopology::default()
                    },
                ),
                (
                    second.clone(),
                    ProfileTopology {
                        routes: BTreeSet::from(["10.44.0.200/24".into()]),
                        ..ProfileTopology::default()
                    },
                ),
            ]),
            ..ControlServiceConfig::default()
        },
        Arc::new(TestClock::default()),
        ExecutionSelection::CanonicalAuthority,
        supervisor,
    );
    service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Connect { profile_id: first },
            idempotency_key: IdempotencyKey::new("route-a"),
            deadline: Deadline(1_000),
        })
        .await
        .unwrap();
    let rejected = service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Connect {
                profile_id: second.clone(),
            },
            idempotency_key: IdempotencyKey::new("route-b"),
            deadline: Deadline(1_000),
        })
        .await;
    assert_eq!(
        rejected,
        Err(vortix::vortix_core::control::AdmissionError::RouteConflict)
    );
    assert!(!service
        .client()
        .snapshot()
        .desired
        .tunnels
        .contains_key(&second));
}

#[tokio::test]
async fn policy_waits_for_attested_tunnel_and_carries_complete_topology() {
    #[derive(Default)]
    struct Capture(Mutex<Vec<TopologyPolicy>>);
    impl PolicyExecutor for Capture {
        fn apply(&self, policy: &TopologyPolicy, barrier: PolicyBarrier) -> Result<(), String> {
            if barrier == PolicyBarrier::Blocking {
                self.0.lock().unwrap().push(policy.clone());
            }
            Ok(())
        }
        fn compensate(&self, _: &TopologyPolicy, _: PolicyBarrier) {}
    }
    let target = profile("complete-policy");
    let capture = Arc::new(Capture::default());
    let supervisor = Arc::new(Supervisor::new(
        AuthorityEpoch(1),
        Arc::new(OkExecutor),
        capture.clone(),
        2,
        4,
    ));
    let service = ControlService::start_supervised(
        ControlServiceConfig {
            authority_epoch: AuthorityEpoch(1),
            known_profiles: BTreeSet::from([target.clone()]),
            profile_topologies: BTreeMap::from([(
                target.clone(),
                ProfileTopology {
                    interface_name: Some("tun-complete-policy".into()),
                    routes: BTreeSet::from(["10.55.0.9/24".into()]),
                    dns_digest: PolicyDigest("dns-v1".into()),
                    firewall_digest: PolicyDigest("firewall-v1".into()),
                    ownership_receipts: BTreeSet::from(["receipt-v1".into()]),
                    ..ProfileTopology::default()
                },
            )]),
            freshness_poll_interval: Duration::from_millis(5),
            ..ControlServiceConfig::default()
        },
        Arc::new(TestClock::default()),
        ExecutionSelection::CanonicalAuthority,
        supervisor,
    );
    let client = service.client();
    client
        .submit(CommandRequest {
            command: UserCommand::Connect {
                profile_id: target.clone(),
            },
            idempotency_key: IdempotencyKey::new("complete-policy"),
            deadline: Deadline(1_000),
        })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(capture.0.lock().unwrap().is_empty());
    let desired = client.snapshot().desired;
    service
        .observer()
        .observe(Observation::Tunnel {
            profile_id: target.clone(),
            active: true,
            interface_name: Some("tun-complete-policy".into()),
            observed_at_millis: 0,
            protection: Some(ProtectionEvidence {
                desired_generation: desired.generation,
                authority_epoch: desired.authority_epoch,
                policy_digest: desired.policy_digest,
                observed_at_millis: 0,
                interface: GateEvidence::Verified,
                route: GateEvidence::Verified,
                dns: GateEvidence::Verified,
                firewall: GateEvidence::Verified,
            }),
        })
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while capture.0.lock().unwrap().is_empty() {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::task::yield_now().await;
    }
    let policy = capture.0.lock().unwrap()[0].clone();
    assert_eq!(
        policy.target.interfaces.get(&target).map(String::as_str),
        Some("tun-complete-policy")
    );
    let route = policy.target.routes[&target].iter().next().unwrap();
    assert_eq!(route.to_string(), "10.55.0.0/24");
    assert!(!policy.target.dns_digest.0.is_empty());
    assert!(!policy.target.firewall_digest.0.is_empty());
    assert!(policy.target.ownership_receipts.contains("receipt-v1"));
    while client.snapshot().effective.protection != ProtectionStatus::Protected {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn expired_client_operation_leaves_queryable_record_and_starts_recovery() {
    let clock = Arc::new(TestClock::default());
    let target = profile("recovery");
    let service = ControlService::start_supervised(
        ControlServiceConfig {
            authority_epoch: AuthorityEpoch(1),
            known_profiles: BTreeSet::from([target.clone()]),
            profile_topologies: BTreeMap::from([(target.clone(), ProfileTopology::default())]),
            freshness_poll_interval: Duration::from_millis(5),
            ..ControlServiceConfig::default()
        },
        clock.clone(),
        ExecutionSelection::CanonicalAuthority,
        Arc::new(Supervisor::new(
            AuthorityEpoch(1),
            Arc::new(OkExecutor),
            Arc::new(OkPolicy),
            2,
            4,
        )),
    );
    let admitted = service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Connect { profile_id: target },
            idempotency_key: IdempotencyKey::new("expires"),
            deadline: Deadline(5),
        })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    clock.0.store(6, Ordering::Release);
    service.client().refresh().unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let snapshot = service.client().snapshot();
    assert_eq!(
        snapshot.operations[&admitted.operation_id].status,
        vortix::vortix_core::control::OperationStatus::Expired
    );
    assert!(snapshot.operations.values().any(|operation| {
        operation.id != admitted.operation_id
            && operation.desired_generation == snapshot.desired.generation
            && !operation.status.is_terminal()
    }));
}

#[tokio::test]
async fn cleaned_handshake_failure_terminalizes_original_before_policy_retry() {
    struct MissingHandshake;
    impl TunnelExecutor for MissingHandshake {
        fn execute(
            &self,
            work: &TunnelWork,
            _: &CancellationToken,
        ) -> Result<TunnelExecutionReceipt, String> {
            TunnelExecutionReceipt::attested(
                work.profile_id.clone(),
                "wg-cleaned",
                TunnelKindTag::WireGuard,
                None,
                "wg-missing-handshake",
            )
        }

        fn compensate_uncertain(&self, _: &TunnelWork) -> Result<(), String> {
            // Models the protocol adapter's exact-attempt teardown plus fresh
            // absence observation.
            Ok(())
        }
    }

    let target = profile("handshake-terminal");
    let service = ControlService::start_supervised(
        ControlServiceConfig {
            authority_epoch: AuthorityEpoch(1),
            known_profiles: BTreeSet::from([target.clone()]),
            profile_topologies: BTreeMap::from([(
                target.clone(),
                ProfileTopology {
                    protocol: Some(vortix::vortix_core::profile::ProtocolKind::WireGuard),
                    ..ProfileTopology::default()
                },
            )]),
            freshness_poll_interval: Duration::from_millis(5),
            ..ControlServiceConfig::default()
        },
        Arc::new(TestClock::default()),
        ExecutionSelection::CanonicalAuthority,
        Arc::new(Supervisor::new(
            AuthorityEpoch(1),
            Arc::new(MissingHandshake),
            Arc::new(OkPolicy),
            2,
            4,
        )),
    );
    let admitted = service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Connect { profile_id: target },
            idempotency_key: IdempotencyKey::new("handshake-terminal"),
            deadline: Deadline(1_000),
        })
        .await
        .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    loop {
        let snapshot = service.client().snapshot();
        if snapshot
            .operations
            .get(&admitted.operation_id)
            .is_some_and(|operation| {
                operation.status == vortix::vortix_core::control::OperationStatus::Failed
            })
        {
            assert_eq!(
                snapshot.operations[&admitted.operation_id].result,
                Some(vortix::vortix_core::control::OperationResult::Failed(
                    vortix::vortix_core::control::OperationFailure::HandshakeFailed
                ))
            );
            assert!(snapshot.operations.values().any(|operation| {
                operation.id != admitted.operation_id
                    && operation.desired_generation == snapshot.desired.generation
            }));
            break;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn cleaned_wireguard_connect_timeout_is_a_terminal_handshake_failure() {
    struct CleanedTimeout;
    impl TunnelExecutor for CleanedTimeout {
        fn execute(
            &self,
            _: &TunnelWork,
            _: &CancellationToken,
        ) -> Result<TunnelExecutionReceipt, String> {
            Err("bounded WireGuard connect timed out after exact cleanup".into())
        }

        fn classify_failure(&self, _: &str) -> WorkFailure {
            WorkFailure::TimedOut
        }
    }

    let target = profile("handshake-timeout-terminal");
    let service = ControlService::start_supervised(
        ControlServiceConfig {
            authority_epoch: AuthorityEpoch(1),
            known_profiles: BTreeSet::from([target.clone()]),
            profile_topologies: BTreeMap::from([(
                target.clone(),
                ProfileTopology {
                    protocol: Some(vortix::vortix_core::profile::ProtocolKind::WireGuard),
                    ..ProfileTopology::default()
                },
            )]),
            freshness_poll_interval: Duration::from_millis(5),
            ..ControlServiceConfig::default()
        },
        Arc::new(TestClock::default()),
        ExecutionSelection::CanonicalAuthority,
        Arc::new(Supervisor::new(
            AuthorityEpoch(1),
            Arc::new(CleanedTimeout),
            Arc::new(OkPolicy),
            2,
            4,
        )),
    );
    let admitted = service
        .client()
        .submit(CommandRequest {
            command: UserCommand::Connect { profile_id: target },
            idempotency_key: IdempotencyKey::new("handshake-timeout-terminal"),
            deadline: Deadline(1_000),
        })
        .await
        .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    loop {
        let snapshot = service.client().snapshot();
        let operation = &snapshot.operations[&admitted.operation_id];
        if operation.status.is_terminal() {
            assert_eq!(
                operation.result,
                Some(vortix::vortix_core::control::OperationResult::Failed(
                    vortix::vortix_core::control::OperationFailure::HandshakeFailed
                ))
            );
            break;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::task::yield_now().await;
    }
}
