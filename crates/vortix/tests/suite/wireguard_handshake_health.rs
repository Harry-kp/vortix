use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vortix::core::ports::dns::DnsRequest;
use vortix::core::ports::tunnel::{
    classify_peer_handshake_health, HandshakeAttempt, PeerHandshakeHealth, PeerTrafficExpectation,
    TunnelHandle, TunnelKindTag, TunnelPeerStatus, TunnelStatus,
};
use vortix::core::profile::ProfileId;
use vortix::wireguard::tunnel::parse_wg_dump;

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
}

#[test]
fn machine_dump_keeps_one_generation_consistent_evidence() {
    let dump = "private\tinterface-public\t51820\toff\npeer-key\t(none)\t198.51.100.1:51820\t10.0.0.0/24\t201\t12\t34\t25\n";
    let parsed = parse_wg_dump("wg0", dump, at(202), 42).unwrap();
    assert_eq!(parsed.peers[0].public_key, "peer-key");
    assert_eq!(parsed.peers[0].evidence_generation, 42);
    assert_eq!(parsed.peers[0].allowed_routes, vec!["10.0.0.0/24"]);
}
