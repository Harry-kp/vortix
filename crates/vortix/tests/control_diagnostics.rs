#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use vortix::daemon::client;
use vortix::daemon::diagnostics::{DiagnosticHub, FallbackStore};
use vortix::daemon::DaemonServer;
use vortix::vortix_core::control::{ControlEvent, OperationStatus};
use vortix::vortix_core::control::{
    DiagnosticBuffer, DiagnosticCode, DiagnosticComponent, DiagnosticFields, DiagnosticSeverity,
    DiagnosticSource, DiagnosticStatus,
};
use vortix::vortix_core::profile::ProfileId;

#[test]
fn arbitrary_event_strings_never_enter_diagnostic_json() {
    let secrets = [
        "otp-739201",
        "private-profile-name",
        "vpn.example.invalid:1194",
        "203.0.113.9",
        "10.0.0.53",
        "/Users/alice/private/client.ovpn",
        "--auth-user-pass /tmp/secret",
        "AUTH_FAILED: password=secret",
    ];
    let profile_id = ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap();
    let events = vec![
        ControlEvent::TunnelUp {
            profile_id: profile_id.clone(),
            protocol: vortix::vortix_core::profile::ProtocolKind::OpenVpn,
            interface_name: secrets[2].into(),
            pid: Some(4242),
        },
        ControlEvent::IpChanged {
            old: Some(secrets[3].into()),
            new: secrets[4].into(),
        },
        ControlEvent::ProfileRenamed {
            profile_id: profile_id.clone(),
            old_display_name: secrets[0].into(),
            new_display_name: secrets[1].into(),
        },
        ControlEvent::UserPromptRequested {
            profile_id,
            prompt_id: secrets[5].into(),
            prompt_kind: vortix::vortix_core::control::ChallengeKind::Generic {
                label: secrets[6].into(),
            },
            prompt_text: secrets[7].into(),
        },
    ];
    let mut buffer = DiagnosticBuffer::default();
    for event in &events {
        buffer.push_control_event(10, event);
    }
    let json = serde_json::to_string(&buffer.view(20)).unwrap();
    for secret in secrets {
        assert!(!json.contains(secret), "diagnostics leaked {secret}");
    }
    assert!(!json.contains("4242"));
}

#[test]
fn flood_stays_within_exact_record_and_byte_limits() {
    let mut buffer = DiagnosticBuffer::default();
    for generation in 0..20_000 {
        buffer.push(
            generation,
            DiagnosticComponent::Queue,
            DiagnosticSeverity::Warning,
            DiagnosticCode::QueueSaturated,
            DiagnosticFields::Queue {
                depth: u16::MAX,
                capacity: u16::MAX,
            },
        );
    }
    let snapshot = buffer.snapshot(20_000, 20_000, DiagnosticStatus::default());
    assert!(snapshot.records.len() <= 512);
    assert!(serde_json::to_vec(&snapshot.records).unwrap().len() <= 1024 * 1024);
    assert_eq!(snapshot.records[0].code, DiagnosticCode::RecordsDropped);

    let fallback = buffer.fallback_snapshot(20_000, 20_000, DiagnosticStatus::default());
    assert!(fallback.records.len() <= 256);
    assert!(serde_json::to_vec(&fallback).unwrap().len() <= 512 * 1024);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_diagnostics_follow_and_disk_fallback_remains_advisory() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("vortix.sock");
    let fallback_path = directory.path().join("diagnostics.json");
    vortix::daemon::diagnostics::prepare_fallback_directory(directory.path()).unwrap();
    let hub = Arc::new(DiagnosticHub::start(Some(fallback_path.clone())).unwrap());
    hub.set_status(DiagnosticStatus {
        authority_verified: true,
        reconciliation_complete: true,
        helper: vortix::vortix_core::control::HelperDiagnosticState::EnrolledHealthy,
        ..DiagnosticStatus::default()
    });
    let server = DaemonServer::bind(socket.clone())
        .unwrap()
        .with_diagnostic_provider(hub.clone());
    let server_task = tokio::spawn(server.run());

    let one_shot_socket = socket.clone();
    let live = tokio::task::spawn_blocking(move || client::diagnostics(&one_shot_socket))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(live.source, DiagnosticSource::AuthenticatedLive);
    assert!(!live.may_establish_authority());

    let subscription_socket = socket.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let subscription = tokio::task::spawn_blocking(move || {
        let mut subscription = client::subscribe_diagnostics(&subscription_socket).unwrap();
        ready_tx
            .send(subscription.initial().snapshot.generation)
            .unwrap();
        subscription.recv().unwrap()
    });
    let boundary = ready_rx.await.unwrap();
    hub.record(
        DiagnosticComponent::Helper,
        DiagnosticSeverity::Warning,
        DiagnosticCode::HelperHealthChanged,
        DiagnosticFields::HelperCounters {
            accepted: 5,
            rejected: 1,
            ambiguous: 1,
        },
    );
    let next = tokio::time::timeout(Duration::from_secs(2), subscription)
        .await
        .unwrap()
        .unwrap();
    assert!(next.snapshot.generation > boundary);
    assert_eq!(next.source, DiagnosticSource::AuthenticatedLive);

    for _ in 0..100 {
        if fallback_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let fallback = FallbackStore::new(fallback_path.clone())
        .read(u64::MAX)
        .unwrap();
    assert_eq!(
        fallback.source,
        DiagnosticSource::UnauthenticatedAdvisoryFallback
    );
    assert!(fallback.stale);
    assert!(!fallback.may_establish_authority());
    assert!(!fallback.may_authorize_cleanup());
    assert!(!fallback.may_claim_protection());

    let shutdown_socket = socket.clone();
    tokio::task::spawn_blocking(move || {
        client::request(&shutdown_socket, vortix::vortix_core::ipc::IpcOp::Shutdown)
    })
    .await
    .unwrap()
    .unwrap();
    tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let unavailable = client::diagnostics_or_fallback(&socket, &fallback_path, u64::MAX).unwrap();
    assert_eq!(
        unavailable.source,
        DiagnosticSource::UnauthenticatedAdvisoryFallback
    );
    assert!(unavailable.stale);
    assert!(!unavailable.may_establish_authority());
}

#[test]
fn stable_outcome_code_does_not_include_operation_identity() {
    let mut buffer = DiagnosticBuffer::default();
    buffer.push_control_event(
        1,
        &ControlEvent::OperationCompleted {
            operation_id: vortix::vortix_core::control::OperationId::parse(
                "op-0000000000000009-0000000000000777",
            )
            .unwrap(),
            status: OperationStatus::Succeeded,
        },
    );
    let json = serde_json::to_string(&buffer.view(1)).unwrap();
    assert!(json.contains("operation_succeeded"));
    assert!(!json.contains("777"));
}

#[tokio::test]
async fn canonical_service_publishes_allowlisted_control_diagnostics() {
    let service = vortix::vortix_core::control::ControlService::start(
        vortix::vortix_core::control::ControlServiceConfig::default(),
    );
    let client = service.client();
    client
        .submit(vortix::vortix_core::control::CommandRequest {
            command: vortix::vortix_core::control::UserCommand::Disconnect { profile_id: None },
            idempotency_key: vortix::vortix_core::control::IdempotencyKey::new(
                "diagnostic-service-test",
            ),
            deadline: vortix::vortix_core::control::Deadline(u64::MAX),
        })
        .await
        .unwrap();
    let snapshot = client.snapshot();
    assert!(snapshot.diagnostics.generation > 0);
    assert!(snapshot
        .diagnostics
        .records
        .iter()
        .any(|record| record.code == DiagnosticCode::OperationAdmitted));
    let json = serde_json::to_string(&snapshot.diagnostics).unwrap();
    assert!(!json.contains("diagnostic-service-test"));
}
