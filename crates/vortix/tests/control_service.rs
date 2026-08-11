use std::future::{poll_fn, Future as _};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use vortix::vortix_core::control::{
    AdmissionError, AuthorityEpoch, ChallengeError, Clock, CommandRequest, CompletionError,
    CompletionOutcome, CompletionResult, ControlEvent, ControlHandle, ControlService,
    ControlServiceConfig, Deadline, DriftGates, EventReceiveError, GateEvidence, IdempotencyKey,
    Observation, ObservationError, OperationCompletion, OperationFailure, OperationStatus,
    ProfileMutation, ProfileMutationApplied, ProfileMutationExecutor, ProfileMutationFailure,
    ProfileMutationWork, ProfileTopology, ProtectionEvidence, ProtectionStatus, ReadinessError,
    Secret, UserCommand,
};
use vortix::vortix_core::engine::state::{ConnectionHealth, DegradedReason};
use vortix::vortix_core::profile::ProfileId;

#[derive(Debug, Default)]
struct FakeClock(AtomicU64);

impl FakeClock {
    fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now_millis(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn profile(seed: char) -> ProfileId {
    ProfileId::parse(seed.to_string().repeat(ProfileId::HEX_LEN)).expect("profile id")
}

fn request(key: &str, profile_id: ProfileId, deadline: u64) -> CommandRequest {
    CommandRequest {
        command: UserCommand::Connect {
            profile_id,
            conflict_acknowledgement: None,
        },
        idempotency_key: IdempotencyKey::new(key),
        deadline: Deadline(deadline),
    }
}

#[tokio::test]
async fn exclusive_connect_replaces_multi_tunnel_desire_atomically() {
    let first = profile('a');
    let target = profile('b');
    let untouched = profile('c');
    let service = ControlService::start(ControlServiceConfig {
        known_profiles: [first.clone(), target.clone(), untouched.clone()]
            .into_iter()
            .collect(),
        profile_topologies: [
            (first.clone(), ProfileTopology::default()),
            (target.clone(), ProfileTopology::default()),
            (untouched.clone(), ProfileTopology::default()),
        ]
        .into_iter()
        .collect(),
        ..config()
    });
    let client = service.client();
    for (key, profile_id) in [
        ("connect-first", first.clone()),
        ("connect-target", target.clone()),
    ] {
        client
            .submit(request(key, profile_id, u64::MAX))
            .await
            .unwrap();
    }
    let before = client.subscribe().snapshot();
    assert_eq!(
        before.desired.tunnels.get(&first),
        Some(&vortix::vortix_core::control::RequestedTunnelState::Connected)
    );
    assert_eq!(
        before.desired.tunnels.get(&target),
        Some(&vortix::vortix_core::control::RequestedTunnelState::Connected)
    );

    let admitted = client
        .submit(CommandRequest {
            command: UserCommand::ConnectExclusive {
                profile_id: target.clone(),
            },
            idempotency_key: IdempotencyKey::new("exclusive-target"),
            deadline: Deadline(u64::MAX),
        })
        .await
        .unwrap();
    let after = client.subscribe().snapshot();
    assert_eq!(after.desired.generation, before.desired.generation + 1);
    assert_eq!(
        after.desired.tunnels.get(&first),
        Some(&vortix::vortix_core::control::RequestedTunnelState::Disconnected)
    );
    assert_eq!(
        after.desired.tunnels.get(&target),
        Some(&vortix::vortix_core::control::RequestedTunnelState::Connected)
    );
    assert_eq!(
        after.desired.tunnels.get(&untouched),
        Some(&vortix::vortix_core::control::RequestedTunnelState::Disconnected),
        "the atomic subset must explicitly include untouched catalog profiles"
    );
    let operation = after.operations.get(&admitted.operation_id).unwrap();
    let vortix::vortix_core::control::OperationIntent::DesiredSubset { tunnels, .. } =
        &operation.intent
    else {
        panic!("exclusive switch must retain its exact desired subset");
    };
    assert_eq!(tunnels, &after.desired.tunnels);
}

fn config() -> ControlServiceConfig {
    ControlServiceConfig {
        freshness_poll_interval: Duration::from_secs(60),
        ..ControlServiceConfig::default()
    }
}

#[derive(Debug)]
struct FakeProfileMutations {
    delay: Duration,
    import_has_topology: bool,
    calls: Mutex<Vec<ProfileMutation>>,
}

impl ProfileMutationExecutor for FakeProfileMutations {
    fn execute(
        &self,
        work: ProfileMutationWork,
    ) -> Result<ProfileMutationApplied, ProfileMutationFailure> {
        std::thread::sleep(self.delay);
        self.calls.lock().unwrap().push(work.mutation.clone());
        Ok(match work.mutation {
            ProfileMutation::Import { profile_id } => ProfileMutationApplied::Imported {
                profile_id,
                topology: self.import_has_topology.then(ProfileTopology::default),
            },
            ProfileMutation::Rename {
                profile_id,
                new_display_name,
            } => ProfileMutationApplied::Renamed {
                profile_id,
                topology: ProfileTopology {
                    display_name: Some(new_display_name),
                    ..ProfileTopology::default()
                },
            },
            ProfileMutation::Delete { profile_id } => {
                ProfileMutationApplied::Deleted { profile_id }
            }
        })
    }
}

async fn wait_for_terminal(
    handle: &ControlHandle,
    operation_id: &vortix::vortix_core::control::OperationId,
) {
    let mut subscription = handle.subscribe();
    loop {
        let snapshot = subscription.snapshot();
        if snapshot
            .operations
            .get(operation_id)
            .is_some_and(|operation| operation.status.is_terminal())
        {
            return;
        }
        subscription.changed().await.expect("service remains live");
    }
}

#[tokio::test]
async fn typed_profile_import_updates_the_single_service_catalog() {
    let mutations = Arc::new(FakeProfileMutations {
        delay: Duration::ZERO,
        import_has_topology: true,
        calls: Mutex::new(Vec::new()),
    });
    let imported = profile('e');
    let service = ControlService::start(ControlServiceConfig {
        profile_mutations: Some(mutations.clone()),
        ..config()
    });
    let client = service.client();
    let operation = client
        .submit(CommandRequest {
            command: UserCommand::ImportProfile {
                profile_id: imported.clone(),
            },
            idempotency_key: IdempotencyKey::new("profile-import"),
            deadline: Deadline(u64::MAX),
        })
        .await
        .expect("typed import admitted");
    wait_for_terminal(&client, &operation.operation_id).await;
    assert_eq!(
        client.snapshot().operations[&operation.operation_id].status,
        OperationStatus::Succeeded
    );

    client
        .submit(request("connect-imported", imported, u64::MAX))
        .await
        .expect("the same dynamic catalog admits the imported identity");
    assert_eq!(mutations.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn profile_mutation_fences_racing_lifecycle_and_rejects_active_profiles() {
    let mutations = Arc::new(FakeProfileMutations {
        delay: Duration::from_millis(50),
        import_has_topology: true,
        calls: Mutex::new(Vec::new()),
    });
    let existing = profile('d');
    let service = ControlService::start(ControlServiceConfig {
        known_profiles: [existing.clone()].into_iter().collect(),
        profile_topologies: [(existing.clone(), ProfileTopology::default())]
            .into_iter()
            .collect(),
        profile_mutations: Some(mutations),
        ..config()
    });
    let client = service.client();
    let rename = client
        .submit(CommandRequest {
            command: UserCommand::RenameProfile {
                profile_id: existing.clone(),
                new_display_name: "work".to_owned(),
            },
            idempotency_key: IdempotencyKey::new("profile-rename"),
            deadline: Deadline(u64::MAX),
        })
        .await
        .expect("rename admitted");
    assert_eq!(
        client
            .submit(request("racing-connect", existing.clone(), u64::MAX))
            .await,
        Err(AdmissionError::ProfileBusy)
    );
    wait_for_terminal(&client, &rename.operation_id).await;

    let observer = service.observer();
    let observed_at_millis = observer.now_millis();
    observer
        .observe(Observation::Tunnel {
            profile_id: existing.clone(),
            active: true,
            interface_name: Some("tun0".to_owned()),
            observed_at_millis,
            protection: None,
        })
        .await
        .expect("active observation accepted");
    assert_eq!(
        client
            .submit(CommandRequest {
                command: UserCommand::DeleteProfile {
                    profile_id: existing,
                },
                idempotency_key: IdempotencyKey::new("profile-delete"),
                deadline: Deadline(u64::MAX),
            })
            .await,
        Err(AdmissionError::ProfileActive)
    );
}

#[tokio::test]
async fn imported_profile_without_topology_is_known_but_cannot_connect() {
    let mutations = Arc::new(FakeProfileMutations {
        delay: Duration::ZERO,
        import_has_topology: false,
        calls: Mutex::new(Vec::new()),
    });
    let imported = profile('f');
    let service = ControlService::start(ControlServiceConfig {
        profile_mutations: Some(mutations),
        ..config()
    });
    let client = service.client();
    let operation = client
        .submit(CommandRequest {
            command: UserCommand::ImportProfile {
                profile_id: imported.clone(),
            },
            idempotency_key: IdempotencyKey::new("profile-import-no-topology"),
            deadline: Deadline(u64::MAX),
        })
        .await
        .expect("storage mutation remains truthful");
    wait_for_terminal(&client, &operation.operation_id).await;

    assert_eq!(
        client
            .submit(request("unsafe-connect", imported, u64::MAX))
            .await,
        Err(AdmissionError::InvalidInput {
            reason: "profile topology is unavailable".to_owned(),
        })
    );
}

#[derive(Debug)]
struct LateProfileMutation {
    clock: Arc<FakeClock>,
}

impl ProfileMutationExecutor for LateProfileMutation {
    fn execute(
        &self,
        work: ProfileMutationWork,
    ) -> Result<ProfileMutationApplied, ProfileMutationFailure> {
        self.clock.set(work.deadline.0.saturating_add(1));
        Ok(ProfileMutationApplied::Imported {
            profile_id: work.mutation.profile_id().clone(),
            topology: Some(ProfileTopology::default()),
        })
    }
}

#[derive(Debug)]
struct MismatchedProfileMutation;

impl ProfileMutationExecutor for MismatchedProfileMutation {
    fn execute(
        &self,
        work: ProfileMutationWork,
    ) -> Result<ProfileMutationApplied, ProfileMutationFailure> {
        Ok(ProfileMutationApplied::Deleted {
            profile_id: work.mutation.profile_id().clone(),
        })
    }
}

#[tokio::test]
async fn mismatched_profile_storage_result_cannot_mutate_the_catalog() {
    let imported = profile('8');
    let service = ControlService::start(ControlServiceConfig {
        profile_mutations: Some(Arc::new(MismatchedProfileMutation)),
        ..config()
    });
    let client = service.client();
    let operation = client
        .submit(CommandRequest {
            command: UserCommand::ImportProfile {
                profile_id: imported.clone(),
            },
            idempotency_key: IdempotencyKey::new("mismatched-profile-import"),
            deadline: Deadline(u64::MAX),
        })
        .await
        .expect("typed import admitted");
    wait_for_terminal(&client, &operation.operation_id).await;
    let snapshot = client.snapshot();
    assert_eq!(
        snapshot.operations[&operation.operation_id].status,
        OperationStatus::Failed
    );
    assert_eq!(
        snapshot.operations[&operation.operation_id].result,
        Some(vortix::vortix_core::control::OperationResult::Failed(
            OperationFailure::Internal
        ))
    );

    client
        .submit(CommandRequest {
            command: UserCommand::ImportProfile {
                profile_id: imported,
            },
            idempotency_key: IdempotencyKey::new("mismatched-profile-import-retry"),
            deadline: Deadline(u64::MAX),
        })
        .await
        .expect("mismatched result neither catalogs nor leaves the profile fenced");
}

#[tokio::test]
async fn late_profile_storage_is_reconciled_but_never_reported_as_timely_success() {
    let clock = Arc::new(FakeClock::default());
    let imported = profile('9');
    let service = ControlService::start_with_clock(
        ControlServiceConfig {
            profile_mutations: Some(Arc::new(LateProfileMutation {
                clock: clock.clone(),
            })),
            ..config()
        },
        clock,
    );
    let client = service.client();
    let operation = client
        .submit(CommandRequest {
            command: UserCommand::ImportProfile {
                profile_id: imported.clone(),
            },
            idempotency_key: IdempotencyKey::new("late-profile-import"),
            deadline: Deadline(10),
        })
        .await
        .expect("work admitted before its deadline");
    wait_for_terminal(&client, &operation.operation_id).await;
    assert_eq!(
        client.snapshot().operations[&operation.operation_id].status,
        OperationStatus::Expired
    );
    assert_eq!(
        client.snapshot().operations[&operation.operation_id].result,
        Some(vortix::vortix_core::control::OperationResult::ProfileMutationAppliedAfterDeadline)
    );

    client
        .submit(request("connect-late-import", imported, u64::MAX))
        .await
        .expect("committed storage result was reconciled into the catalog");
}

#[tokio::test]
async fn fresh_local_service_imports_existing_kill_switch_intent() {
    let service = ControlService::start(ControlServiceConfig {
        initial_kill_switch_mode: vortix::vortix_core::state::killswitch::KillSwitchMode::AlwaysOn,
        ..config()
    });
    assert_eq!(
        service.client().snapshot().desired.kill_switch,
        vortix::vortix_core::state::killswitch::KillSwitchMode::AlwaysOn
    );
}

async fn wait_for_generation(handle: &ControlHandle, desired_generation: u64) {
    let mut subscription = handle.subscribe();
    while subscription.snapshot().desired.generation < desired_generation {
        subscription.changed().await.expect("service remains live");
    }
}

fn current_evidence(handle: &ControlHandle, observed_at_millis: u64) -> ProtectionEvidence {
    let desired = handle.snapshot().desired;
    ProtectionEvidence {
        desired_generation: desired.generation,
        authority_epoch: desired.authority_epoch,
        policy_digest: desired.policy_digest,
        observed_at_millis,
        interface: GateEvidence::Verified,
        route: GateEvidence::Verified,
        dns: GateEvidence::Verified,
        firewall: GateEvidence::Verified,
    }
}

#[tokio::test]
async fn idempotency_is_scoped_to_service_client_epoch_and_semantic_command() {
    let clock = Arc::new(FakeClock::default());
    let service = ControlService::start_with_clock(config(), clock.clone());
    let client = service.client();
    let first_request = request("same", profile('a'), 100);
    let first = client
        .submit(first_request.clone())
        .await
        .expect("admitted");
    wait_for_generation(&client, 1).await;

    let retry = client
        .submit(CommandRequest {
            deadline: Deadline(200),
            ..first_request
        })
        .await
        .expect("same semantic retry with a different transport deadline");
    assert_eq!(first.operation_id, retry.operation_id);
    assert_eq!(client.snapshot().desired.generation, 1);

    assert_eq!(
        client.submit(request("same", profile('b'), 100)).await,
        Err(AdmissionError::IdempotencyConflict)
    );

    let other_client = service.new_client().expect("client identifier available");
    let independent = other_client
        .submit(request("same", profile('b'), 100))
        .await
        .expect("key is scoped to service-created client identity");
    assert_ne!(first.operation_id, independent.operation_id);
}

#[tokio::test(flavor = "current_thread")]
async fn saturation_and_expiry_happen_before_execution() {
    let clock = Arc::new(FakeClock::default());
    let service = ControlService::start_with_clock(
        ControlServiceConfig {
            command_capacity: 1,
            ..config()
        },
        clock.clone(),
    );
    let client = service.client();
    let mut reserved = Box::pin(client.submit(request("reserved", profile('a'), 10)));
    poll_fn(|context| {
        assert!(reserved.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(
        client.submit(request("busy", profile('b'), 10)).await,
        Err(AdmissionError::Busy)
    );
    clock.set(10);
    let admitted = reserved.await.expect("reserved");
    tokio::task::yield_now().await;
    let snapshot = client.snapshot();
    assert_eq!(snapshot.desired.generation, 0);
    assert_eq!(
        snapshot.operations[&admitted.operation_id].status,
        OperationStatus::Expired
    );
}

#[tokio::test]
async fn public_client_and_trusted_roles_have_distinct_capabilities() {
    let service = ControlService::start(config());
    let client = service.client();
    let observer = service.observer();
    let completer = service.completer();
    let admitted = client
        .submit(request("roles", profile('a'), u64::MAX))
        .await
        .expect("admitted");
    wait_for_generation(&client, 1).await;

    observer
        .observe(Observation::Protection(current_evidence(
            &client,
            observer.now_millis(),
        )))
        .await
        .expect("observer has observation capability");
    assert_eq!(
        completer
            .complete(OperationCompletion {
                operation_id: admitted.operation_id,
                desired_generation: 1,
                outcome: CompletionOutcome::Cancelled,
            })
            .await,
        Ok(CompletionResult::Terminal(OperationStatus::Cancelled))
    );
}

#[tokio::test]
async fn observations_use_owner_receipt_time_and_reject_future_or_older_evidence() {
    let clock = Arc::new(FakeClock::default());
    clock.set(10);
    let service = ControlService::start_with_clock(config(), clock.clone());
    let client = service.client();
    let observer = service.observer();
    client
        .submit(request("known", profile('a'), 100))
        .await
        .expect("admitted");
    wait_for_generation(&client, 1).await;

    assert_eq!(
        observer
            .observe(Observation::Tunnel {
                profile_id: profile('a'),
                active: true,
                interface_name: Some("wg0".to_owned()),
                observed_at_millis: 11,
                protection: None,
            })
            .await,
        Err(ObservationError::FutureDated)
    );
    observer
        .observe(Observation::Tunnel {
            profile_id: profile('a'),
            active: true,
            interface_name: Some("wg0".to_owned()),
            observed_at_millis: 9,
            protection: None,
        })
        .await
        .expect("current observation");
    assert_eq!(
        client.snapshot().observed.tunnels[&profile('a')].received_at_millis,
        10
    );
    assert_eq!(
        observer
            .observe(Observation::Tunnel {
                profile_id: profile('a'),
                active: false,
                interface_name: None,
                observed_at_millis: 8,
                protection: None,
            })
            .await,
        Err(ObservationError::Stale)
    );
}

#[tokio::test]
async fn connection_health_is_generation_fenced_and_published_to_snapshot_subscribers() {
    let clock = Arc::new(FakeClock::default());
    clock.set(10);
    let service = ControlService::start_with_clock(config(), clock);
    let client = service.client();
    let observer = service.observer();
    client
        .submit(request("health", profile('a'), 100))
        .await
        .expect("admitted");
    wait_for_generation(&client, 1).await;

    assert_eq!(
        observer
            .observe(Observation::ConnectionHealth {
                profile_id: profile('a'),
                desired_generation: 0,
                health: ConnectionHealth::Healthy,
                observed_at_millis: 9,
            })
            .await,
        Err(ObservationError::MismatchedProtection)
    );

    let mut subscription = client.subscribe();
    let stale = ConnectionHealth::Degraded {
        reason: DegradedReason::WireGuardPeerStale {
            peer_public_key: "peer-a".into(),
            allowed_routes: vec!["0.0.0.0/0".into()],
            seconds_since_last_handshake: 181,
        },
    };
    observer
        .observe(Observation::ConnectionHealth {
            profile_id: profile('a'),
            desired_generation: 1,
            health: stale.clone(),
            observed_at_millis: 9,
        })
        .await
        .expect("stale health accepted");
    let snapshot = subscription.changed().await.expect("stale publication");
    assert_eq!(
        snapshot.observed.connection_health[&profile('a')].health,
        stale
    );

    observer
        .observe(Observation::ConnectionHealth {
            profile_id: profile('a'),
            desired_generation: 1,
            health: ConnectionHealth::Healthy,
            observed_at_millis: 10,
        })
        .await
        .expect("recovery accepted");
    let snapshot = subscription.changed().await.expect("recovery publication");
    assert_eq!(
        snapshot.observed.connection_health[&profile('a')].health,
        ConnectionHealth::Healthy
    );
}

#[tokio::test]
async fn drift_invalidates_gates_atomically_and_same_message_can_reverify() {
    let clock = Arc::new(FakeClock::default());
    clock.set(10);
    let service = ControlService::start_with_clock(config(), clock);
    let client = service.client();
    let observer = service.observer();
    client
        .submit(request("drift", profile('a'), 100))
        .await
        .expect("admitted");
    wait_for_generation(&client, 1).await;
    observer
        .observe(Observation::Protection(current_evidence(&client, 9)))
        .await
        .expect("protected");
    assert_eq!(
        client.snapshot().effective.protection,
        ProtectionStatus::Protected
    );

    observer
        .observe(Observation::Drift {
            profile_id: Some(profile('a')),
            gates: DriftGates {
                dns: true,
                ..DriftGates::default()
            },
            observed_at_millis: 10,
            protection: None,
        })
        .await
        .expect("drift accepted");
    let drifted = client.snapshot();
    assert_eq!(drifted.effective.protection, ProtectionStatus::Degraded);
    let evidence = drifted.observed.evidence.expect("gate evidence remains");
    assert_eq!(evidence.interface, GateEvidence::Verified);
    assert_eq!(evidence.route, GateEvidence::Verified);
    assert_eq!(evidence.dns, GateEvidence::Unverified);
    assert_eq!(evidence.firewall, GateEvidence::Verified);

    observer
        .observe(Observation::Drift {
            profile_id: Some(profile('a')),
            gates: DriftGates {
                route: true,
                ..DriftGates::default()
            },
            observed_at_millis: 10,
            protection: Some(current_evidence(&client, 10)),
        })
        .await
        .expect("atomic re-verification");
    assert_eq!(
        client.snapshot().effective.protection,
        ProtectionStatus::Protected
    );
}

#[tokio::test]
async fn success_requires_every_gate_and_accepts_compatible_newer_evidence() {
    let clock = Arc::new(FakeClock::default());
    let service = ControlService::start_with_clock(config(), clock);
    let client = service.client();
    let completer = service.completer();
    let first = client
        .submit(request("first", profile('a'), 100))
        .await
        .expect("first");
    wait_for_generation(&client, 1).await;
    let second = client
        .submit(request("second", profile('b'), 100))
        .await
        .expect("second");
    wait_for_generation(&client, 2).await;

    assert_eq!(
        completer
            .complete(OperationCompletion {
                operation_id: first.operation_id.clone(),
                desired_generation: 1,
                outcome: CompletionOutcome::Failed(OperationFailure::ObservationFailed),
            })
            .await,
        Ok(CompletionResult::Terminal(OperationStatus::Failed))
    );
    assert_eq!(
        client.snapshot().operations[&first.operation_id].status,
        OperationStatus::Failed
    );

    let mut partial = current_evidence(&client, 0);
    partial.dns = GateEvidence::Unverified;
    assert_eq!(
        completer
            .complete(OperationCompletion {
                operation_id: second.operation_id.clone(),
                desired_generation: 2,
                outcome: CompletionOutcome::ObservedSuccess(partial),
            })
            .await,
        Ok(CompletionResult::ProtectionIncomplete)
    );
    let snapshot = client.snapshot();
    assert_eq!(
        snapshot.operations[&second.operation_id].status,
        OperationStatus::WaitingForObservation
    );
    assert_eq!(snapshot.effective.protection, ProtectionStatus::Degraded);

    let third = client
        .submit(request("third", profile('c'), 100))
        .await
        .expect("newer desired generation");
    wait_for_generation(&client, 3).await;
    assert_eq!(
        completer
            .complete(OperationCompletion {
                operation_id: second.operation_id.clone(),
                desired_generation: 2,
                outcome: CompletionOutcome::ObservedSuccess(current_evidence(&client, 0)),
            })
            .await,
        Ok(CompletionResult::Terminal(OperationStatus::Succeeded))
    );
    assert_eq!(
        client.snapshot().operations[&second.operation_id].status,
        OperationStatus::Succeeded
    );
    assert_eq!(
        client.snapshot().operations[&third.operation_id].status,
        OperationStatus::WaitingForObservation
    );
}

#[tokio::test]
async fn admitted_deadlines_and_terminal_compaction_are_owner_enforced() {
    let clock = Arc::new(FakeClock::default());
    let service = ControlService::start_with_clock(
        ControlServiceConfig {
            max_operations: 1,
            max_idempotency_keys: 1,
            ..config()
        },
        clock.clone(),
    );
    let client = service.client();
    let completer = service.completer();
    let first = client
        .submit(request("first", profile('a'), 10))
        .await
        .expect("first");
    wait_for_generation(&client, 1).await;
    assert_eq!(
        client
            .submit(request("active-cannot-evict", profile('b'), 10))
            .await,
        Err(AdmissionError::RetentionFull)
    );
    completer
        .complete(OperationCompletion {
            operation_id: first.operation_id.clone(),
            desired_generation: 1,
            outcome: CompletionOutcome::Cancelled,
        })
        .await
        .expect("terminal");
    let second = client
        .submit(request("second", profile('b'), 10))
        .await
        .expect("terminal record compacted");
    wait_for_generation(&client, 2).await;
    assert!(!client
        .snapshot()
        .operations
        .contains_key(&first.operation_id));

    clock.set(10);
    assert_eq!(
        completer
            .complete(OperationCompletion {
                operation_id: second.operation_id.clone(),
                desired_generation: 2,
                outcome: CompletionOutcome::Cancelled,
            })
            .await,
        Err(CompletionError::DeadlineExpired)
    );
    assert_eq!(
        client.snapshot().operations[&second.operation_id].status,
        OperationStatus::Expired
    );
}

#[tokio::test]
async fn challenges_deliver_secret_once_and_expiry_wins_over_cancel() {
    let clock = Arc::new(FakeClock::default());
    let service = ControlService::start_with_clock(config(), clock.clone());
    let client = service.client();
    let completer = service.completer();
    let operation = client
        .submit(request("challenge", profile('a'), 100))
        .await
        .expect("operation");
    wait_for_generation(&client, 1).await;
    let issued = completer
        .issue_challenge(
            operation.operation_id.clone(),
            profile('a'),
            vortix::vortix_core::control::ChallengeKind::TwoFactorCode,
            "OTP",
            50,
        )
        .await
        .expect("issued");
    let id = issued.record.id;
    client
        .respond_challenge(id, Secret::new(b"123456".to_vec()))
        .await
        .expect("delivered");
    issued
        .response
        .receive()
        .await
        .expect("worker receives secret");
    assert_eq!(
        client
            .respond_challenge(id, Secret::new(b"again".to_vec()))
            .await,
        Err(ChallengeError::NotFound)
    );

    let expiring = completer
        .issue_challenge(
            operation.operation_id.clone(),
            profile('a'),
            vortix::vortix_core::control::ChallengeKind::Passphrase,
            "Passphrase",
            80,
        )
        .await
        .expect("issued");
    clock.set(80);
    assert_eq!(
        client.cancel_challenge(expiring.record.id).await,
        Err(ChallengeError::Expired)
    );
    assert!(expiring.response.receive().await.is_err());

    clock.set(81);
    let cancelled = completer
        .issue_challenge(
            operation.operation_id,
            profile('a'),
            vortix::vortix_core::control::ChallengeKind::Passphrase,
            "Passphrase",
            100,
        )
        .await
        .expect("issued");
    client
        .cancel_challenge(cancelled.record.id)
        .await
        .expect("cancelled");
    assert!(cancelled.response.receive().await.is_err());

    let serialized = serde_json::to_string(&client.snapshot()).expect("snapshot serializes");
    assert!(!serialized.contains("123456"));
}

#[tokio::test]
async fn challenge_authorization_comes_from_issuing_operation_client() {
    let service = ControlService::start(config());
    let owner = service.client();
    let other = service.new_client().expect("client identifier available");
    let completer = service.completer();
    let operation = owner
        .submit(request("owned", profile('a'), u64::MAX))
        .await
        .expect("operation");
    wait_for_generation(&owner, 1).await;
    let issued = completer
        .issue_challenge(
            operation.operation_id,
            profile('a'),
            vortix::vortix_core::control::ChallengeKind::TwoFactorCode,
            "OTP",
            u64::MAX,
        )
        .await
        .expect("issued");
    assert_eq!(
        other
            .respond_challenge(issued.record.id, Secret::new(b"stolen".to_vec()))
            .await,
        Err(ChallengeError::Unauthorized)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocking_worker_challenge_keeps_actor_live_and_is_one_shot() {
    let service = ControlService::start(config());
    let client = service.client();
    let operation = client
        .submit(request("blocking-challenge", profile('a'), u64::MAX))
        .await
        .expect("operation");
    wait_for_generation(&client, 1).await;

    let completer = service.completer();
    let operation_id = operation.operation_id.clone();
    let issuance = tokio::task::spawn_blocking(move || {
        completer.issue_challenge_blocking(
            operation_id,
            profile('a'),
            vortix::vortix_core::control::ChallengeKind::TwoFactorCode,
            "OTP",
            u64::MAX,
        )
    });

    let challenge_id = loop {
        if let Some(id) = client.snapshot().challenges.keys().next().copied() {
            break id;
        }
        tokio::task::yield_now().await;
    };
    client
        .refresh()
        .expect("actor accepts progress while worker waits");
    let issued = issuance
        .await
        .expect("worker task")
        .expect("challenge issued");
    assert_eq!(issued.record.id, challenge_id);

    client
        .respond_challenge(challenge_id, Secret::new(b"123456".to_vec()))
        .await
        .expect("authorized answer");
    assert!(issued
        .response
        .receive_timeout(Duration::from_secs(1))
        .expect("receiver remains live")
        .is_some());
    assert_eq!(
        client
            .respond_challenge(challenge_id, Secret::new(b"again".to_vec()))
            .await,
        Err(ChallengeError::NotFound)
    );
}

#[tokio::test]
async fn no_op_refresh_preserves_snapshot_generation_and_does_not_wake_subscribers() {
    let service = ControlService::start(config());
    let client = service.client();
    let mut subscription = client.subscribe();
    let generation = subscription.snapshot().generation;

    client.refresh().expect("refresh accepted");
    assert!(
        tokio::time::timeout(Duration::from_millis(25), subscription.changed())
            .await
            .is_err(),
        "a no-op refresh must preserve the watch channel's no-change signal"
    );
    assert_eq!(client.snapshot().generation, generation);
}

#[tokio::test]
async fn terminal_operation_cancels_its_unanswered_challenge() {
    let service = ControlService::start(config());
    let client = service.client();
    let completer = service.completer();
    let operation = client
        .submit(request("terminal-challenge", profile('a'), u64::MAX))
        .await
        .expect("operation");
    wait_for_generation(&client, 1).await;
    let issued = completer
        .issue_challenge(
            operation.operation_id.clone(),
            profile('a'),
            vortix::vortix_core::control::ChallengeKind::TwoFactorCode,
            "OTP",
            u64::MAX,
        )
        .await
        .expect("challenge");
    let id = issued.record.id;

    completer
        .complete(OperationCompletion {
            operation_id: operation.operation_id,
            desired_generation: 1,
            outcome: CompletionOutcome::Cancelled,
        })
        .await
        .expect("terminal completion");
    assert!(issued.response.receive().await.is_err());
    assert!(!client.snapshot().challenges.contains_key(&id));
    assert_eq!(
        client.cancel_challenge(id).await,
        Err(ChallengeError::Cancelled)
    );
}

#[tokio::test]
async fn snapshot_is_published_before_generation_stamped_events_and_boundary_deduplicates() {
    let service = ControlService::start(config());
    let client = service.client();
    let mut subscriber = client.subscribe();
    client
        .submit(request("event", profile('a'), u64::MAX))
        .await
        .expect("admitted");
    let event = subscriber.recv_event().await.expect("event");
    assert!(subscriber.snapshot().generation >= event.snapshot_generation);

    wait_for_generation(&client, 1).await;
    let mut boundary = client.subscribe();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), boundary.recv_event())
            .await
            .is_err(),
        "subscription must not replay events represented by its initial snapshot"
    );
    client
        .submit(request("event-2", profile('b'), u64::MAX))
        .await
        .expect("admitted");
    let next = boundary.recv_event().await.expect("new event");
    assert!(next.snapshot_generation > event.snapshot_generation);
}

#[tokio::test]
async fn lag_requires_resync_to_at_least_event_generation() {
    let service = ControlService::start(ControlServiceConfig {
        event_capacity: 2,
        ..config()
    });
    let client = service.client();
    let mut slow = client.subscribe();
    for (index, seed) in ['a', 'b', 'c', 'd'].into_iter().enumerate() {
        client
            .submit(request(&format!("lag-{index}"), profile(seed), u64::MAX))
            .await
            .expect("admitted");
    }
    wait_for_generation(&client, 4).await;
    let EventReceiveError::ResyncRequired { newest_generation } =
        slow.recv_event().await.expect_err("lagged")
    else {
        panic!("expected resync");
    };
    assert!(slow.snapshot().generation >= newest_generation);
}

#[tokio::test]
async fn readiness_is_live_epoch_checked_owner_state() {
    let service = ControlService::start(ControlServiceConfig {
        authority_epoch: AuthorityEpoch(7),
        reconciliation_complete: false,
        authority_verified: false,
        ..config()
    });
    let client = service.client();
    let completer = service.completer();
    assert_eq!(
        client
            .submit(request("closed", profile('a'), u64::MAX))
            .await,
        Err(AdmissionError::NotReady)
    );
    assert_eq!(
        completer.set_readiness(AuthorityEpoch(6), true, true).await,
        Err(ReadinessError::EpochMismatch)
    );
    completer
        .set_readiness(AuthorityEpoch(7), true, true)
        .await
        .expect("reconciled authority opens same service");
    assert!(client.snapshot().readiness.reconciliation_complete);
    client
        .submit(request("open", profile('a'), u64::MAX))
        .await
        .expect("same handle admitted after readiness transition");
}

#[tokio::test]
async fn observations_are_bounded_to_known_profiles_and_capacity() {
    let clock = Arc::new(FakeClock::default());
    clock.set(10);
    let service = ControlService::start_with_clock(
        ControlServiceConfig {
            max_observed_profiles: 1,
            known_profiles: [profile('a'), profile('b')].into_iter().collect(),
            ..config()
        },
        clock,
    );
    let observer = service.observer();
    assert_eq!(
        observer
            .observe(Observation::Tunnel {
                profile_id: profile('c'),
                active: true,
                interface_name: None,
                observed_at_millis: 1,
                protection: None,
            })
            .await,
        Err(ObservationError::UnknownProfile)
    );
    observer
        .observe(Observation::Tunnel {
            profile_id: profile('a'),
            active: true,
            interface_name: None,
            observed_at_millis: 2,
            protection: None,
        })
        .await
        .expect("first retained");
    assert_eq!(
        observer
            .observe(Observation::Tunnel {
                profile_id: profile('b'),
                active: true,
                interface_name: None,
                observed_at_millis: 3,
                protection: None,
            })
            .await,
        Err(ObservationError::RetentionFull)
    );
}

#[test]
fn compatibility_paths_and_public_error_shapes_remain_stable() {
    let json = serde_json::to_string(&AdmissionError::Busy).expect("typed error serializes");
    assert_eq!(json, r#"{"kind":"busy"}"#);
    let event = ControlEvent::DesiredStateChanged {
        desired_generation: 7,
    };
    assert!(serde_json::to_string(&event)
        .expect("event serializes")
        .contains(r#""kind":"desired_state_changed""#));
}

#[test]
fn canonical_command_rejects_legacy_secret_answer_shape() {
    let legacy = r#"{"UserAnswered":{"prompt_id":"prompt-7","answer":"never-journal-me"}}"#;
    assert!(serde_json::from_str::<UserCommand>(legacy).is_err());
}

#[test]
fn control_kill_switch_json_uses_only_canonical_slugs() {
    let command = UserCommand::SetKillSwitch {
        mode: vortix::state::KillSwitchMode::Auto,
    };
    assert_eq!(
        serde_json::to_string(&command).expect("serialize command"),
        r#"{"SetKillSwitch":{"mode":"block-on-drop"}}"#
    );

    let desired = vortix::vortix_core::control::DesiredState {
        kill_switch: vortix::state::KillSwitchMode::AlwaysOn,
        ..vortix::vortix_core::control::DesiredState::default()
    };
    let json = serde_json::to_value(&desired).expect("serialize desired state");
    assert_eq!(json["kill_switch"], "vpn-only");
    assert!(!json.to_string().contains("AlwaysOn"));

    let decoded: vortix::vortix_core::control::DesiredState =
        serde_json::from_value(json).expect("deserialize desired state");
    assert_eq!(decoded.kill_switch, vortix::state::KillSwitchMode::AlwaysOn);
    assert!(serde_json::from_str::<UserCommand>(r#"{"SetKillSwitch":{"mode":"Auto"}}"#).is_err());
}

#[tokio::test]
async fn canonical_tunnel_projection_carries_kernel_role_details_and_health() {
    use std::collections::BTreeSet;
    use std::time::{Duration, SystemTime};

    use vortix::vortix_core::engine::registry::Role;
    use vortix::vortix_core::engine::state::{Connection, DetailedConnectionInfo};

    let profile_id = profile('a');
    let clock = Arc::new(FakeClock::default());
    clock.set(100);
    let service = ControlService::start_with_clock(
        ControlServiceConfig {
            known_profiles: [profile_id.clone()].into_iter().collect(),
            profile_topologies: [(
                profile_id.clone(),
                ProfileTopology {
                    routes: BTreeSet::from(["0.0.0.0/0".to_string()]),
                    ..ProfileTopology::default()
                },
            )]
            .into_iter()
            .collect(),
            ..config()
        },
        clock,
    );
    let client = service.client();
    client
        .submit(request("project", profile_id.clone(), u64::MAX))
        .await
        .expect("connect admitted");

    let started_at = SystemTime::UNIX_EPOCH + Duration::from_secs(80);
    let mut details = DetailedConnectionInfo {
        interface: "wg7".to_string(),
        interface_authoritative: true,
        endpoint: "198.51.100.7:51820".to_string(),
        mtu: "1420".to_string(),
        ..DetailedConnectionInfo::default()
    };
    details.health_hint = ConnectionHealth::Healthy;
    service
        .observer()
        .observe(Observation::TunnelDetails {
            profile_id: profile_id.clone(),
            details: Box::new(details),
            started_at: Some(started_at),
            observed_at_millis: 90,
        })
        .await
        .expect("details accepted");
    service
        .observer()
        .observe(Observation::DefaultRoute {
            interface_name: Some("wg7".to_string()),
            observed_at_millis: 90,
        })
        .await
        .expect("route accepted");
    service
        .observer()
        .observe(Observation::Tunnel {
            profile_id: profile_id.clone(),
            active: true,
            interface_name: Some("wg7".to_string()),
            observed_at_millis: 90,
            protection: None,
        })
        .await
        .expect("presence accepted");

    let snapshot = client.snapshot();
    assert_eq!(snapshot.primary.as_ref(), Some(&profile_id));
    let projected = snapshot
        .tunnels
        .get(&profile_id)
        .expect("canonical projection");
    assert!(matches!(projected.role, Role::Primary { .. }));
    assert_eq!(projected.health, ConnectionHealth::Healthy);
    assert_eq!(projected.started_at, Some(started_at));
    let Connection::Connected { details, .. } = &projected.state else {
        panic!("active observed tunnel must project as connected");
    };
    assert_eq!(details.interface, "wg7");
    assert_eq!(details.endpoint, "198.51.100.7:51820");
    assert_eq!(details.mtu, "1420");
}
