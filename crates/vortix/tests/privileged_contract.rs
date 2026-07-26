use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use serde::Deserialize;
use serde_json::json;
use vortix::vortix_core::cidr::Cidr;
use vortix::vortix_core::control::AuthorityEpoch;
use vortix::vortix_core::privileged::{
    ChildObservation, ChildOwner, ContainmentId, CustodianAction, DnsHostname, HelperEpoch,
    ObservedChildIdentity, OpenVpnAuthFactors, OpenVpnChallengeKind, OpenVpnPlan, OpenVpnRemote,
    OpenVpnRemoteSelection, OpenVpnRoute, OpenVpnTransport, OperationDigest,
    PrivilegedDnsAssignment, PrivilegedDnsScope, ProfileMaterialRef, ProfileMaterialSlot,
    ProtocolEndpoint, ProtocolPlan, ProtocolPlanError, ResourceKind, ResourceTag,
    ServiceInstanceClaim, StandardCustodianContract, WireGuardInterfaceOptions, WireGuardPeerPlan,
    WireGuardPlan, WireGuardPresharedKeyRef,
};
use vortix::vortix_core::profile::ProfileId;

fn profile(byte: char) -> ProfileId {
    ProfileId::parse(byte.to_string().repeat(ProfileId::HEX_LEN)).unwrap()
}

fn cidr(octet: u8) -> Cidr {
    Cidr::new(IpAddr::V4(Ipv4Addr::new(10, octet, 0, 0)), 16).unwrap()
}

fn wireguard_plan(generation: u64) -> ProtocolPlan {
    let peer = WireGuardPeerPlan::new(
        [7; 32],
        Some(ProtocolEndpoint::ip(SocketAddr::from(([198, 51, 100, 7], 51820))).unwrap()),
        vec![cidr(7)],
        Some(25),
    )
    .unwrap();
    ProtocolPlan::WireGuard(
        WireGuardPlan::new(
            profile('a'),
            generation,
            vec![cidr(1)],
            vec![peer],
            WireGuardInterfaceOptions::new(Some(1420), Some(51820), Some(7)).unwrap(),
        )
        .unwrap(),
    )
}

fn openvpn_plan(generation: u64) -> ProtocolPlan {
    ProtocolPlan::OpenVpn(
        OpenVpnPlan::new(
            profile('b'),
            generation,
            vec![OpenVpnRemote::new(
                SocketAddr::from(([203, 0, 113, 9], 1194)),
                OpenVpnTransport::Udp,
            )
            .unwrap()],
            OpenVpnRemoteSelection::Ordered,
            OpenVpnAuthFactors::certificate(),
            vec![OpenVpnRoute::new(cidr(2), None, None).unwrap()],
        )
        .unwrap(),
    )
}

#[test]
fn protocol_plans_are_strict_allowlists_without_execution_escape_hatches() {
    for plan in [wireguard_plan(1), openvpn_plan(1)] {
        let encoded = serde_json::to_value(&plan).unwrap();
        let text = encoded.to_string();
        for forbidden in [
            "raw_profile",
            "hook",
            "plugin",
            "include",
            "path",
            "command",
            "executable",
            "argument",
            "environment",
        ] {
            assert!(
                !text.contains(forbidden),
                "plan exposed {forbidden}: {text}"
            );
        }
        let mut injected = encoded.clone();
        injected["plan"]["command"] = json!("/bin/sh");
        assert!(serde_json::from_value::<ProtocolPlan>(injected).is_err());
        assert_eq!(
            serde_json::from_value::<ProtocolPlan>(encoded).unwrap(),
            plan
        );
    }
}

#[test]
fn protocol_semantics_preserve_composite_openvpn_and_sparse_wireguard() {
    let auth = OpenVpnAuthFactors::certificate_and_username_password()
        .with_challenge(OpenVpnChallengeKind::Remote)
        .unwrap();
    let openvpn = ProtocolPlan::OpenVpn(
        OpenVpnPlan::new(
            profile('b'),
            4,
            vec![
                OpenVpnRemote::dns("udp.example.com", 1194, OpenVpnTransport::Udp).unwrap(),
                OpenVpnRemote::dns("tcp.example.com", 443, OpenVpnTransport::Tcp).unwrap(),
            ],
            OpenVpnRemoteSelection::Randomized,
            auth,
            vec![OpenVpnRoute::new(
                cidr(4),
                Some(IpAddr::V4(Ipv4Addr::new(10, 4, 0, 1))),
                Some(5),
            )
            .unwrap()],
        )
        .unwrap(),
    );
    let encoded = serde_json::to_value(&openvpn).unwrap();
    assert_eq!(encoded["plan"]["remote_selection"], json!("randomized"));
    assert_eq!(encoded["plan"]["remotes"][0]["transport"], json!("udp"));
    assert_eq!(encoded["plan"]["remotes"][1]["transport"], json!("tcp"));

    let public_key = [9; 32];
    let peer = WireGuardPeerPlan::with_preshared_key(
        public_key,
        None,
        Vec::new(),
        None,
        WireGuardPresharedKeyRef::for_peer(public_key).unwrap(),
    )
    .unwrap();
    let wireguard = ProtocolPlan::WireGuard(
        WireGuardPlan::new(
            profile('a'),
            4,
            Vec::new(),
            vec![peer.clone()],
            WireGuardInterfaceOptions::default(),
        )
        .unwrap(),
    );
    assert!(wireguard
        .material_refs()
        .contains(&ProfileMaterialRef::WireGuardPresharedKey {
            peer_public_key: public_key
        }));
    assert!(WireGuardPlan::new(
        profile('a'),
        4,
        Vec::new(),
        vec![peer.clone(), peer],
        WireGuardInterfaceOptions::default(),
    )
    .is_err());
}

#[test]
fn fixed_material_slots_and_dns_names_carry_no_paths() {
    assert_eq!(
        wireguard_plan(1).material_refs(),
        vec![ProfileMaterialRef::ProfileSlot {
            slot: ProfileMaterialSlot::WireGuardPrivateKey,
        }]
    );
    assert!(DnsHostname::new("vpn-1.example.com").is_ok());
    for malformed in [
        "",
        ".example.com",
        "example.com.",
        "-vpn.example.com",
        "vpn_name.example.com",
        "vpn..example.com",
    ] {
        assert!(
            DnsHostname::new(malformed).is_err(),
            "accepted {malformed:?}"
        );
    }
    assert!(ProtocolEndpoint::dns("vpn.example.com", 0).is_err());
}

#[test]
fn public_invalid_cidr_literals_are_rejected_at_every_privileged_boundary() {
    let invalid = Cidr {
        addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 33,
    };
    assert!(!invalid.is_valid());
    assert!(OpenVpnRoute::new(invalid, None, None).is_err());
    assert!(WireGuardPeerPlan::new([7; 32], None, vec![invalid], None).is_err());
    assert!(WireGuardPlan::new(
        profile('a'),
        1,
        vec![invalid],
        vec![WireGuardPeerPlan::new([7; 32], None, Vec::new(), None).unwrap()],
        WireGuardInterfaceOptions::default(),
    )
    .is_err());
    assert!(serde_json::from_value::<Cidr>(json!({
        "addr": "10.0.0.0",
        "prefix_len": 33
    }))
    .is_err());
}

#[test]
fn allocation_bounded_wire_rejects_oversized_distinct_sequences() {
    let mut plan = serde_json::to_value(wireguard_plan(1)).unwrap();
    let template = plan["plan"]["peers"][0].clone();
    let peers = plan["plan"]["peers"].as_array_mut().unwrap();
    peers.clear();
    for index in 0..257_u16 {
        let mut peer = template.clone();
        peer["public_key"][0] = json!(u8::try_from(index % 255 + 1).unwrap());
        peer["persistent_keepalive_seconds"] = json!(index + 1);
        peers.push(peer);
    }
    let json = serde_json::to_string(&plan).unwrap();
    let mut stream = serde_json::Deserializer::from_str(&json);
    assert!(ProtocolPlan::deserialize(&mut stream).is_err());

    let mut openvpn = serde_json::to_value(openvpn_plan(1)).unwrap();
    let remote = openvpn["plan"]["remotes"][0].clone();
    let remotes = openvpn["plan"]["remotes"].as_array_mut().unwrap();
    remotes.clear();
    for port in 1..=17_u16 {
        let mut item = remote.clone();
        item["endpoint"]["address"] = json!(format!("203.0.113.9:{port}"));
        remotes.push(item);
    }
    assert!(serde_json::from_value::<ProtocolPlan>(openvpn).is_err());
}

#[test]
fn observations_and_untrusted_claims_never_become_capabilities() {
    let tunnel = ResourceTag::tunnel(profile('b'), 8).unwrap();
    let identity =
        ObservedChildIdentity::new(tunnel.clone(), 4_242, 90_001, ContainmentId::new([8; 32]))
            .unwrap();
    let decoded = serde_json::from_value(serde_json::to_value(&identity).unwrap()).unwrap();
    let observation = ChildObservation::from_identity(&decoded);
    assert!(observation
        .claim_after_restart(ChildOwner::BackgroundHelper(HelperEpoch::new(3).unwrap()))
        .is_err());

    let claim = ServiceInstanceClaim::systemd(
        42,
        99,
        OperationDigest::of_bytes(b"untrusted executable claim"),
        [3; 32],
    )
    .unwrap();
    assert!(
        serde_json::from_value::<ServiceInstanceClaim>(serde_json::to_value(claim).unwrap())
            .is_ok()
    );
    // There is intentionally no public API from this claim to a root ledger
    // or TrustedDaemonPrincipal.
}

#[test]
fn standard_custodian_remains_exactly_tunnel_scoped() {
    let tunnel = ResourceTag::tunnel(profile('a'), 1).unwrap();
    let contract = StandardCustodianContract::new(tunnel.clone()).unwrap();
    for action in [
        CustodianAction::start(wireguard_plan(1)).unwrap(),
        CustodianAction::status(tunnel.clone()).unwrap(),
        CustodianAction::stop(tunnel).unwrap(),
    ] {
        contract.authorize(&action).unwrap();
    }
    let foreign = CustodianAction::status(ResourceTag::tunnel(profile('b'), 1).unwrap()).unwrap();
    assert!(contract.authorize(&foreign).is_err());
    let topology = ResourceTag::topology(AuthorityEpoch(7), 1, ResourceKind::Dns).unwrap();
    assert!(CustodianAction::status(topology).is_err());
}

#[test]
fn dns_policy_preserves_tunnel_scope_without_interface_escape_hatch() {
    let assignment = PrivilegedDnsAssignment::new(
        ResourceTag::tunnel(profile('a'), 3).unwrap(),
        vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
        vec![DnsHostname::new("corp.example").unwrap()],
        PrivilegedDnsScope::Scoped {
            domains: vec![DnsHostname::new("corp.example").unwrap()],
        },
    )
    .unwrap();
    let encoded = serde_json::to_value(&assignment).unwrap();
    assert_eq!(encoded["scope"]["kind"], json!("scoped"));
    assert!(encoded.get("interface").is_none());
}

#[test]
fn protocol_generation_and_authentication_are_validated() {
    assert!(matches!(
        WireGuardPlan::new(
            profile('a'),
            0,
            Vec::new(),
            Vec::new(),
            WireGuardInterfaceOptions::default(),
        ),
        Err(ProtocolPlanError::InvalidGeneration)
    ));
    assert!(OpenVpnAuthFactors::new(false, false, None).is_err());
    assert!(OpenVpnAuthFactors::new(false, false, Some(OpenVpnChallengeKind::Static)).is_err());
}
