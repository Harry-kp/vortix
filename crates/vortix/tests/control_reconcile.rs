use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

use vortix::vortix_core::control::model::{AuthorityEpoch, OperationId, PolicyDigest};
use vortix::vortix_core::control::reconcile::{
    merge_observation, plan_reconciliation, DisconnectTombstone, InFlightMutation,
    ObservationOwnership, ReconcileAction, ReconcileInput, ScanEvidence, TunnelObservation,
};
use vortix::vortix_core::control::supervisor::{PolicyVerification, Supervisor};
use vortix::vortix_core::control::worker::{
    wait_until, CancellationToken, ControlRevision, PolicyBarrier, PolicyExecutor, PolicyOutcome,
    PolicyWorker, ProfileWorkerPool, TopologyPolicy, TopologyState, TopologyTransitionKind,
    TunnelExecutionReceipt, TunnelExecutor, TunnelMutation, TunnelWork, WorkFailure,
};
use vortix::vortix_core::control::{
    Clock, CommandRequest, ControlService, ControlServiceConfig, Deadline, ExecutionSelection,
    GateEvidence, IdempotencyKey, Observation, ProfileTopology, ProtectionEvidence,
    ProtectionStatus, UserCommand,
};
use vortix::vortix_core::ports::tunnel::{HandshakeEvidence, TunnelKindTag};
use vortix::vortix_core::profile::ProfileId;

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
fn work(
    profile_id: ProfileId,
    generation: u64,
    operation_value: u64,
    mutation: TunnelMutation,
) -> TunnelWork {
    TunnelWork {
        profile_id,
        operation_id: operation(operation_value),
        generation,
        authority_epoch: AuthorityEpoch(1),
        policy_digest: PolicyDigest(format!("digest-{generation}")),
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

fn observation(
    evidence: ScanEvidence,
    ownership: ObservationOwnership,
    revision: Option<ControlRevision>,
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
fn stale_generation_and_same_generation_digest_never_converge() {
    let id = profile("corp");
    let target = revision(4, "new");
    for stale in [revision(3, "old"), revision(4, "other-digest")] {
        let plan = plan_reconciliation(&ReconcileInput {
            revision: target.clone(),
            desired_connected: BTreeSet::from([id.clone()]),
            observations: BTreeMap::from([(
                id.clone(),
                observation(
                    ScanEvidence::ConfirmedPresent,
                    ObservationOwnership::Managed,
                    Some(stale.clone()),
                ),
            )]),
            in_flight: BTreeMap::new(),
            disconnect_tombstones: BTreeMap::new(),
        });
        assert!(
            matches!(plan.actions.as_slice(), [ReconcileAction::CleanupStaleManaged { stale_revision: Some(found), .. }] if found == &stale)
        );
    }
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
    let input = ReconcileInput {
        revision: rev.clone(),
        desired_connected: BTreeSet::new(),
        observations: BTreeMap::from([(
            id.clone(),
            observation(
                ScanEvidence::ProbeFailed,
                ObservationOwnership::Managed,
                Some(rev.clone()),
            ),
        )]),
        in_flight: BTreeMap::new(),
        disconnect_tombstones: BTreeMap::from([(
            id.clone(),
            DisconnectTombstone {
                revision: rev.clone(),
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
                Some(rev.clone()),
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
    let rev = revision(7, "digest");
    let mut current = observation(
        ScanEvidence::ConfirmedAbsent,
        ObservationOwnership::Managed,
        Some(rev.clone()),
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
        transition: TopologyTransitionKind::Connect,
        required_blocking: true,
    }
}

#[test]
fn partial_barrier_failure_compensates_failed_receipt_first_and_preserves_blocking() {
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
        .any(|receipt| receipt.barrier == PolicyBarrier::Blocking
            && receipt.preserved_for_safety
            && !receipt.compensated));
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
    worker.submit(policy(1, "one")).unwrap();
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
        desired_connected: BTreeSet::from([id.clone()]),
        observations: BTreeMap::new(),
        in_flight: BTreeMap::from([(
            id.clone(),
            InFlightMutation {
                revision: revision(2, "old"),
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
    assert_eq!(latest.generation, 2);
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
            known_profiles: BTreeSet::from([occupied, rejected.clone()]),
            ..ControlServiceConfig::default()
        },
        Arc::new(TestClock::default()),
        ExecutionSelection::CanonicalAuthority,
        supervisor,
    );
    let result = service.client().submit(CommandRequest {
        command: UserCommand::Connect {
            profile_id: rejected,
        },
        idempotency_key: IdempotencyKey::new("bounded-profile"),
        deadline: Deadline(1_000),
    });
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
    let revision = item.revision();
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
        .unwrap();
    let rejected = service.client().submit(CommandRequest {
        command: UserCommand::Connect {
            profile_id: second.clone(),
        },
        idempotency_key: IdempotencyKey::new("route-b"),
        deadline: Deadline(1_000),
    });
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
    assert_eq!(
        policy.target.routes[&target]
            .iter()
            .next()
            .unwrap()
            .to_string(),
        "10.55.0.0/24"
    );
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
