use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use vortix::vortix_core::control::model::{AuthorityEpoch, OperationId};
use vortix::vortix_core::control::snapshot::ControlSnapshot;
use vortix::vortix_core::control::worker::{
    wait_until, CancellationToken, ProfileWorkerPool, TunnelExecutionReceipt, TunnelExecutor,
    TunnelMutation, TunnelRevision, TunnelWork, WorkFailure,
};
use vortix::vortix_core::ports::dns::DnsRequest;
use vortix::vortix_core::ports::tunnel::{
    classify_peer_handshake_health, HandshakeAttempt, HandshakeEvidence, PeerHandshakeHealth,
    PeerTrafficExpectation, ProbeReceipt, ProtocolStatus, TunnelHandle, TunnelKindTag,
    TunnelPeerStatus, TunnelStatus,
};
use vortix::vortix_core::profile::ProfileId;
use vortix::vortix_protocol_wireguard::parser::parse_wg_conf;
use vortix::vortix_protocol_wireguard::tunnel::{parse_wg_dump, select_health_probe};

#[derive(Debug)]
struct Detail;
impl ProtocolStatus for Detail {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn peer(key: &str, generation: u64, handshake: Option<SystemTime>) -> TunnelPeerStatus {
    TunnelPeerStatus {
        public_key: key.into(),
        endpoint: None,
        allowed_routes: vec!["10.0.0.0/24".into()],
        latest_handshake: handshake,
        evidence_observed_at: at(250),
        evidence_generation: generation,
        persistent_keepalive: None,
        bytes_rx: 0,
        bytes_tx: 0,
    }
}

fn status(generation: u64, peers: Vec<TunnelPeerStatus>) -> TunnelStatus {
    TunnelStatus {
        handle: TunnelHandle {
            profile_id: ProfileId::new("corp"),
            display_name: "corp".into(),
            interface_name: "wg0".into(),
            pid: None,
            started_at: at(200),
            kind: TunnelKindTag::WireGuard,
            generation,
            handshake: None,
            probe_receipts: Vec::new(),
            process_ownership: None,
            teardown_config: None,
            dns_request: DnsRequest::default(),
            openvpn_routes: None,
        },
        bytes_rx: 0,
        bytes_tx: 0,
        last_handshake: peers.iter().filter_map(|peer| peer.latest_handshake).max(),
        observed_at: at(250),
        peers,
        detail: Box::new(Detail),
    }
}

fn attempt(generation: u64) -> HandshakeAttempt {
    HandshakeAttempt {
        generation,
        started_at: at(200),
        expected_peers: BTreeSet::from(["expected".into()]),
        baseline: BTreeMap::from([("expected".into(), Some(at(190)))]),
    }
}

#[test]
fn unreachable_interface_never_becomes_connected_without_handshake() {
    assert!(attempt(7)
        .evaluate(&status(7, vec![peer("expected", 7, None)]))
        .is_none());
}

#[test]
fn only_fresh_expected_current_generation_peer_completes_attempt() {
    let gate = attempt(7);
    assert!(gate
        .evaluate(&status(7, vec![peer("expected", 7, Some(at(201)))]))
        .is_some());
    assert!(gate
        .evaluate(&status(7, vec![peer("expected", 7, Some(at(190)))]))
        .is_none());
    assert!(gate
        .evaluate(&status(7, vec![peer("wrong", 7, Some(at(201)))]))
        .is_none());
    assert!(gate
        .evaluate(&status(7, vec![peer("expected", 6, Some(at(201)))]))
        .is_none());

    let exact = ProfileWorkerPool::new(
        Arc::new(HandshakeReceipt {
            generation_offset: 0,
        }),
        1,
        1,
    );
    exact.dispatch(wg_work(), ["10.0.0.0/24".into()]).unwrap();
    assert!(wait_until(Duration::from_secs(1), || exact.try_result())
        .unwrap()
        .result
        .is_ok());

    let stale = ProfileWorkerPool::new(
        Arc::new(HandshakeReceipt {
            generation_offset: -1,
        }),
        1,
        1,
    );
    stale.dispatch(wg_work(), ["10.0.0.0/24".into()]).unwrap();
    assert_eq!(
        wait_until(Duration::from_secs(1), || stale.try_result())
            .unwrap()
            .result,
        Err(WorkFailure::HandshakeFailed)
    );
}

struct MissingHandshake;
impl TunnelExecutor for MissingHandshake {
    fn execute(
        &self,
        work: &TunnelWork,
        _: &CancellationToken,
    ) -> Result<TunnelExecutionReceipt, String> {
        TunnelExecutionReceipt::attested(
            work.profile_id.clone(),
            "wg0",
            TunnelKindTag::WireGuard,
            None,
            "wireguard-test-attestation",
        )
    }
}

struct PanicBeforeReceipt;
impl TunnelExecutor for PanicBeforeReceipt {
    fn execute(
        &self,
        _: &TunnelWork,
        _: &CancellationToken,
    ) -> Result<TunnelExecutionReceipt, String> {
        panic!("simulated worker crash before handshake receipt");
    }
}

struct HandshakeReceipt {
    generation_offset: i64,
}

struct LateCancellation {
    compensated: Arc<AtomicBool>,
}

impl TunnelExecutor for LateCancellation {
    fn execute(
        &self,
        work: &TunnelWork,
        cancellation: &CancellationToken,
    ) -> Result<TunnelExecutionReceipt, String> {
        let receipt = TunnelExecutionReceipt::wireguard(
            work.profile_id.clone(),
            "wg0",
            "wireguard-late-cancel-attestation",
            HandshakeEvidence {
                generation: work.revision.generation,
                peer_public_key: "expected".into(),
                handshake_at: at(201),
                observed_at: at(202),
                allowed_routes: vec!["10.0.0.0/24".into()],
            },
        );
        cancellation.cancel();
        receipt
    }

    fn compensate_unaccepted_success(&self, _: &TunnelWork) -> Result<(), String> {
        self.compensated.store(true, Ordering::Release);
        Ok(())
    }
}
impl TunnelExecutor for HandshakeReceipt {
    fn execute(
        &self,
        work: &TunnelWork,
        _: &CancellationToken,
    ) -> Result<TunnelExecutionReceipt, String> {
        let generation = work
            .revision
            .generation
            .saturating_add_signed(self.generation_offset);
        TunnelExecutionReceipt::wireguard(
            work.profile_id.clone(),
            "wg0",
            "wireguard-test-attestation",
            HandshakeEvidence {
                generation,
                peer_public_key: "expected".into(),
                handshake_at: at(201),
                observed_at: at(202),
                allowed_routes: vec!["10.0.0.0/24".into()],
            },
        )
    }

    fn compensate_uncertain(&self, _: &TunnelWork) -> Result<(), String> {
        Ok(())
    }
}

fn operation() -> OperationId {
    serde_json::from_str("\"op-0000000000000001-0000000000000001\"").unwrap()
}

fn wg_work() -> TunnelWork {
    TunnelWork {
        profile_id: ProfileId::new("corp"),
        operation_id: operation(),
        revision: TunnelRevision {
            authority_epoch: AuthorityEpoch(1),
            generation: 9,
        },
        resource_revision: TunnelRevision {
            authority_epoch: AuthorityEpoch(1),
            generation: 9,
        },
        mutation: TunnelMutation::Connect,
        protocol: TunnelKindTag::WireGuard,
        deadline: Instant::now() + Duration::from_secs(1),
    }
}

#[test]
fn missing_or_panicked_receipt_fences_retry_until_absence_is_confirmed() {
    let pool = ProfileWorkerPool::new(Arc::new(MissingHandshake), 1, 2);
    pool.dispatch(wg_work(), ["10.0.0.0/24".into()]).unwrap();
    let result = wait_until(Duration::from_secs(1), || pool.try_result()).unwrap();
    assert_eq!(result.result, Err(WorkFailure::OutcomeUnknown));
    assert!(pool.reservations().is_reserved(&ProfileId::new("corp")));
    assert!(matches!(
        pool.dispatch(wg_work(), ["10.0.0.0/24".into()]),
        Err(WorkFailure::Busy)
    ));

    let crashed = ProfileWorkerPool::new(Arc::new(PanicBeforeReceipt), 1, 1);
    crashed.dispatch(wg_work(), ["10.0.0.0/24".into()]).unwrap();
    assert_eq!(
        wait_until(Duration::from_secs(1), || crashed.try_result())
            .unwrap()
            .result,
        Err(WorkFailure::OutcomeUnknown)
    );
    assert!(crashed.reservations().is_reserved(&ProfileId::new("corp")));
    crashed.confirm_absence(&ProfileId::new("corp"));
    assert!(!crashed.reservations().is_reserved(&ProfileId::new("corp")));
}

#[test]
fn cancellation_after_effect_compensates_before_typed_terminal_result() {
    let compensated = Arc::new(AtomicBool::new(false));
    let pool = ProfileWorkerPool::new(
        Arc::new(LateCancellation {
            compensated: Arc::clone(&compensated),
        }),
        1,
        1,
    );
    pool.dispatch(wg_work(), ["10.0.0.0/24".into()]).unwrap();
    let result = wait_until(Duration::from_secs(1), || pool.try_result()).unwrap();
    assert_eq!(result.result, Err(WorkFailure::Cancelled));
    assert!(compensated.load(Ordering::Acquire));
    assert!(!pool.reservations().is_reserved(&ProfileId::new("corp")));
}

#[test]
fn multi_peer_health_is_attributed_per_peer_and_route() {
    let now = at(1_000);
    let healthy = peer("healthy", 3, Some(at(990)));
    let mut stale = peer("stale", 3, Some(at(700)));
    stale.allowed_routes = vec!["192.168.0.0/16".into()];
    stale.persistent_keepalive = Some(Duration::from_secs(25));
    assert!(matches!(
        classify_peer_handshake_health(
            &healthy,
            now,
            &PeerTrafficExpectation::RoutedTraffic,
            Duration::from_secs(180)
        ),
        PeerHandshakeHealth::Healthy { .. }
    ));
    assert!(matches!(
        classify_peer_handshake_health(
            &stale,
            now,
            &PeerTrafficExpectation::PersistentKeepalive,
            Duration::from_secs(180)
        ),
        PeerHandshakeHealth::Stale { .. }
    ));
    assert_eq!(stale.allowed_routes, vec!["192.168.0.0/16"]);
}

#[test]
fn idle_peer_is_informational_but_expected_traffic_can_be_stale() {
    let stale = peer("idle", 3, Some(at(700)));
    assert!(matches!(
        classify_peer_handshake_health(
            &stale,
            at(1_000),
            &PeerTrafficExpectation::Idle,
            Duration::from_secs(180)
        ),
        PeerHandshakeHealth::InformationalIdle { .. }
    ));
    assert!(matches!(
        classify_peer_handshake_health(
            &stale,
            at(1_000),
            &PeerTrafficExpectation::ConfiguredProbe {
                target: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
            },
            Duration::from_secs(180)
        ),
        PeerHandshakeHealth::Stale { .. }
    ));
}

#[test]
fn fresh_handshake_clears_stale_health() {
    let mut observed = peer("expected", 11, Some(at(700)));
    observed.persistent_keepalive = Some(Duration::from_secs(25));
    assert!(matches!(
        classify_peer_handshake_health(
            &observed,
            at(1_000),
            &PeerTrafficExpectation::PersistentKeepalive,
            Duration::from_secs(180)
        ),
        PeerHandshakeHealth::Stale { .. }
    ));
    observed.latest_handshake = Some(at(999));
    assert!(matches!(
        classify_peer_handshake_health(
            &observed,
            at(1_000),
            &PeerTrafficExpectation::PersistentKeepalive,
            Duration::from_secs(180)
        ),
        PeerHandshakeHealth::Healthy { .. }
    ));
}

#[test]
fn machine_dump_and_snapshot_keep_one_generation_consistent_evidence() {
    let dump = "private\tinterface-public\t51820\toff\npeer-key\t(none)\t198.51.100.1:51820\t10.0.0.0/24\t201\t12\t34\t25\n";
    let parsed = parse_wg_dump("wg0", dump, at(202), 42).unwrap();
    assert_eq!(parsed.peers[0].public_key, "peer-key");
    assert_eq!(parsed.peers[0].evidence_generation, 42);
    assert_eq!(parsed.peers[0].allowed_routes, vec!["10.0.0.0/24"]);

    let evidence = HandshakeEvidence {
        generation: 42,
        peer_public_key: "peer-key".into(),
        handshake_at: at(201),
        observed_at: at(202),
        allowed_routes: vec!["10.0.0.0/24".into()],
    };
    let mut snapshot = ControlSnapshot::default();
    snapshot
        .observed
        .wireguard_handshakes
        .insert(ProfileId::new("corp"), evidence);
    snapshot.observed.wireguard_probe_receipts.insert(
        ProfileId::new("corp"),
        vec![ProbeReceipt {
            peer_public_key: "peer-key".into(),
            target: "10.0.0.1".parse().unwrap(),
            allowed_routes: vec!["10.0.0.0/24".into()],
            issued_at: at(200),
        }],
    );
    let json = serde_json::to_value(snapshot).unwrap();
    assert_eq!(
        json["observed"]["wireguard_handshakes"]["corp"]["generation"],
        42
    );
    assert_eq!(
        json["observed"]["wireguard_probe_receipts"]["corp"][0]["peer_public_key"],
        "peer-key"
    );
}

#[test]
fn split_tunnel_requires_covered_target_before_side_effects() {
    let parsed = parse_wg_conf(
        "[Interface]\nPrivateKey = private\n[Peer]\nPublicKey = peer\nAllowedIPs = 10.0.0.0/24\n",
    )
    .unwrap();
    assert_eq!(
        select_health_probe(&parsed, &[IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]),
        None
    );
    assert_eq!(
        select_health_probe(&parsed, &[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))]),
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)))
    );
}
