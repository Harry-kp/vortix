use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use vortix::vortix_core::control::{
    AdmissionError, AuthorityEpoch, ChallengeError, Clock, CommandRequest, CompletionError,
    CompletionOutcome, CompletionResult, ControlEvent, ControlHandle, ControlService,
    ControlServiceConfig, Deadline, DriftGates, EventReceiveError, GateEvidence, IdempotencyKey,
    Observation, ObservationError, OperationCompletion, OperationFailure, OperationStatus,
    ProtectionEvidence, ProtectionStatus, ReadinessError, Secret, UserCommand,
};
use vortix::vortix_core::profile::ProfileId;

#[derive(Default)]
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
        command: UserCommand::Connect { profile_id },
        idempotency_key: IdempotencyKey::new(key),
        deadline: Deadline(deadline),
    }
}

fn config() -> ControlServiceConfig {
    ControlServiceConfig {
        freshness_poll_interval: Duration::from_secs(60),
        ..ControlServiceConfig::default()
    }
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
    let first = client.submit(first_request.clone()).expect("admitted");
    wait_for_generation(&client, 1).await;

    let retry = client
        .submit(CommandRequest {
            deadline: Deadline(200),
            ..first_request
        })
        .expect("same semantic retry with a different transport deadline");
    assert_eq!(first.operation_id, retry.operation_id);
    assert_eq!(client.snapshot().desired.generation, 1);

    assert_eq!(
        client.submit(request("same", profile('b'), 100)),
        Err(AdmissionError::IdempotencyConflict)
    );

    let other_client = service.new_client();
    let independent = other_client
        .submit(request("same", profile('b'), 100))
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
    let admitted = client
        .submit(request("reserved", profile('a'), 10))
        .expect("reserved");
    assert_eq!(
        client.submit(request("busy", profile('b'), 10)),
        Err(AdmissionError::Busy)
    );
    clock.set(10);
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
        .expect("admitted");
    wait_for_generation(&client, 1).await;

    observer
        .observe(Observation::Protection(current_evidence(&client, 0)))
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
async fn drift_invalidates_gates_atomically_and_same_message_can_reverify() {
    let clock = Arc::new(FakeClock::default());
    clock.set(10);
    let service = ControlService::start_with_clock(config(), clock);
    let client = service.client();
    let observer = service.observer();
    client
        .submit(request("drift", profile('a'), 100))
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
async fn success_requires_every_gate_while_failure_can_finish_superseded_operation() {
    let clock = Arc::new(FakeClock::default());
    let service = ControlService::start_with_clock(config(), clock);
    let client = service.client();
    let completer = service.completer();
    let first = client
        .submit(request("first", profile('a'), 100))
        .expect("first");
    wait_for_generation(&client, 1).await;
    let second = client
        .submit(request("second", profile('b'), 100))
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
        Err(CompletionError::StaleSuccess)
    );
    assert_eq!(
        completer
            .complete(OperationCompletion {
                operation_id: second.operation_id.clone(),
                desired_generation: 2,
                outcome: CompletionOutcome::Cancelled,
            })
            .await,
        Ok(CompletionResult::Terminal(OperationStatus::Cancelled))
    );
    assert_eq!(
        client.snapshot().operations[&second.operation_id].status,
        OperationStatus::Cancelled
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
        .expect("first");
    wait_for_generation(&client, 1).await;
    assert_eq!(
        client.submit(request("active-cannot-evict", profile('b'), 10)),
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
    let other = service.new_client();
    let completer = service.completer();
    let operation = owner
        .submit(request("owned", profile('a'), u64::MAX))
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

#[tokio::test]
async fn snapshot_is_published_before_generation_stamped_events_and_boundary_deduplicates() {
    let service = ControlService::start(config());
    let client = service.client();
    let mut subscriber = client.subscribe();
    client
        .submit(request("event", profile('a'), u64::MAX))
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
        client.submit(request("closed", profile('a'), u64::MAX)),
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
