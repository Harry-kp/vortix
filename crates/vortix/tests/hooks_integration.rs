use std::collections::{BTreeMap, BTreeSet};
use std::future::{poll_fn, Future as _};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use vortix::vortix_core::control::{
    AuthorityEpoch, Clock, CommandRequest, CompletionOutcome, ControlEvent, ControlHandle,
    ControlService, ControlServiceConfig, Deadline, GateEvidence, HookEvent, IdempotencyKey,
    OperationCompletion, ProfileTopology, ProtectionEvidence, UserCommand,
};
use vortix::vortix_core::profile::{ProfileId, ProtocolKind};

fn profile_id() -> ProfileId {
    ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap()
}

fn config() -> ControlServiceConfig {
    let profile_id = profile_id();
    ControlServiceConfig {
        authority_epoch: AuthorityEpoch(7),
        known_profiles: BTreeSet::from([profile_id.clone()]),
        profile_topologies: BTreeMap::from([(
            profile_id,
            ProfileTopology {
                protocol: Some(ProtocolKind::WireGuard),
                display_name: Some("Corporate VPN".into()),
                ..ProfileTopology::default()
            },
        )]),
        freshness_poll_interval: Duration::from_secs(60),
        ..ControlServiceConfig::default()
    }
}

#[derive(Default)]
struct TestClock(AtomicU64);

impl Clock for TestClock {
    fn now_millis(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn current_evidence(client: &ControlHandle) -> ProtectionEvidence {
    let desired = client.snapshot().desired;
    ProtectionEvidence {
        desired_generation: desired.generation,
        authority_epoch: desired.authority_epoch,
        policy_digest: desired.policy_digest,
        observed_at_millis: client.deadline_after(Duration::ZERO).0,
        interface: GateEvidence::Verified,
        route: GateEvidence::Verified,
        dns: GateEvidence::Verified,
        firewall: GateEvidence::Verified,
    }
}

async fn next_lifecycle(
    subscription: &mut vortix::vortix_core::control::ControlSubscription,
) -> vortix::vortix_core::control::LifecycleFact {
    loop {
        let envelope = tokio::time::timeout(Duration::from_secs(1), subscription.recv_event())
            .await
            .expect("lifecycle event timeout")
            .expect("control service remains live");
        if let ControlEvent::Lifecycle { fact } = envelope.event {
            assert!(
                subscription.snapshot().generation >= envelope.snapshot_generation,
                "fact is published only after its snapshot commit"
            );
            return fact;
        }
    }
}

async fn next_event(
    subscription: &mut vortix::vortix_core::control::ControlSubscription,
) -> ControlEvent {
    tokio::time::timeout(Duration::from_secs(1), subscription.recv_event())
        .await
        .expect("control event timeout")
        .expect("control service remains live")
        .event
}

#[tokio::test]
async fn committed_connect_lifecycle_has_stable_ordered_event_ids() {
    let service = ControlService::start(config());
    let client = service.client();
    let completer = service.completer();
    let mut subscription = client.subscribe();
    let admitted = client
        .submit(CommandRequest {
            command: UserCommand::Connect {
                profile_id: profile_id(),
            },
            idempotency_key: IdempotencyKey::new("hook-connect"),
            deadline: Deadline(u64::MAX),
        })
        .await
        .unwrap();

    assert!(matches!(
        next_event(&mut subscription).await,
        ControlEvent::OperationAdmitted { .. }
    ));
    let ControlEvent::Lifecycle { fact: started } = next_event(&mut subscription).await else {
        panic!("lifecycle fact must follow operation admission");
    };
    assert_eq!(started.event, HookEvent::ConnectStarted);
    assert_eq!(started.display_name, "Corporate VPN");
    assert_eq!(started.protocol, ProtocolKind::WireGuard);
    assert!(matches!(
        next_event(&mut subscription).await,
        ControlEvent::DesiredStateChanged { .. }
    ));

    let evidence = current_evidence(&client);
    completer
        .complete(OperationCompletion {
            operation_id: admitted.operation_id,
            desired_generation: evidence.desired_generation,
            outcome: CompletionOutcome::ObservedSuccess(evidence),
        })
        .await
        .unwrap();

    assert!(matches!(
        next_event(&mut subscription).await,
        ControlEvent::OperationCompleted { .. }
    ));
    let ControlEvent::Lifecycle { fact: connected } = next_event(&mut subscription).await else {
        panic!("terminal lifecycle fact must follow operation completion");
    };
    assert_eq!(connected.event, HookEvent::Connected);
    assert_ne!(connected.event_id, started.event_id);
    assert!(connected
        .event_id
        .as_str()
        .starts_with("hook-0000000000000007-"));
}

#[tokio::test]
async fn reconnect_and_disconnect_use_their_distinct_lifecycle_vocabulary() {
    let reconnect_service = ControlService::start(config());
    let reconnect = reconnect_service.client();
    let mut reconnect_events = reconnect.subscribe();
    reconnect
        .submit(CommandRequest {
            command: UserCommand::Reconnect {
                profile_id: Some(profile_id()),
            },
            idempotency_key: IdempotencyKey::new("hook-reconnect"),
            deadline: Deadline(u64::MAX),
        })
        .await
        .unwrap();
    assert_eq!(
        next_lifecycle(&mut reconnect_events).await.event,
        HookEvent::Reconnecting
    );

    let disconnect_service = ControlService::start(config());
    let disconnect = disconnect_service.client();
    let completer = disconnect_service.completer();
    let mut disconnect_events = disconnect.subscribe();
    let admitted = disconnect
        .submit(CommandRequest {
            command: UserCommand::Disconnect {
                profile_id: Some(profile_id()),
            },
            idempotency_key: IdempotencyKey::new("hook-disconnect"),
            deadline: Deadline(u64::MAX),
        })
        .await
        .unwrap();
    assert_eq!(
        next_lifecycle(&mut disconnect_events).await.event,
        HookEvent::DisconnectStarted
    );
    let evidence = current_evidence(&disconnect);
    completer
        .complete(OperationCompletion {
            operation_id: admitted.operation_id,
            desired_generation: evidence.desired_generation,
            outcome: CompletionOutcome::ObservedSuccess(evidence),
        })
        .await
        .unwrap();
    assert_eq!(
        next_lifecycle(&mut disconnect_events).await.event,
        HookEvent::Disconnected
    );
}

#[tokio::test(flavor = "current_thread")]
async fn expiry_after_queue_admission_keeps_start_and_failure_facts_ordered() {
    let clock = Arc::new(TestClock::default());
    let service = ControlService::start_with_clock(config(), clock.clone());
    let client = service.client();
    let mut events = client.subscribe();
    let mut admission = Box::pin(client.submit(CommandRequest {
        command: UserCommand::Connect {
            profile_id: profile_id(),
        },
        idempotency_key: IdempotencyKey::new("hook-expired-in-queue"),
        deadline: Deadline(1),
    }));
    poll_fn(|context| {
        assert!(admission.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    clock.0.store(2, Ordering::SeqCst);
    admission.await.unwrap();

    assert!(matches!(
        next_event(&mut events).await,
        ControlEvent::OperationAdmitted { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        ControlEvent::Lifecycle {
            fact: vortix::vortix_core::control::LifecycleFact {
                event: HookEvent::ConnectStarted,
                ..
            }
        }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        ControlEvent::OperationCompleted { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        ControlEvent::Lifecycle {
            fact: vortix::vortix_core::control::LifecycleFact {
                event: HookEvent::ConnectFailed,
                ..
            }
        }
    ));
}

#[tokio::test]
async fn connect_failure_is_observational_and_keeps_operation_terminal() {
    use vortix::vortix_core::control::{OperationFailure, OperationStatus};

    let service = ControlService::start(config());
    let client = service.client();
    let completer = service.completer();
    let mut subscription = client.subscribe();
    let admitted = client
        .submit(CommandRequest {
            command: UserCommand::Connect {
                profile_id: profile_id(),
            },
            idempotency_key: IdempotencyKey::new("hook-failure"),
            deadline: Deadline(u64::MAX),
        })
        .await
        .unwrap();
    assert_eq!(
        next_lifecycle(&mut subscription).await.event,
        HookEvent::ConnectStarted
    );
    completer
        .complete(OperationCompletion {
            operation_id: admitted.operation_id.clone(),
            desired_generation: client.snapshot().desired.generation,
            outcome: CompletionOutcome::Failed(OperationFailure::Rejected),
        })
        .await
        .unwrap();
    assert_eq!(
        next_lifecycle(&mut subscription).await.event,
        HookEvent::ConnectFailed
    );
    assert_eq!(
        client.snapshot().operations[&admitted.operation_id].status,
        OperationStatus::Failed
    );
}
