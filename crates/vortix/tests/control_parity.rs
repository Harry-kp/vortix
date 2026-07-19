//! State/topology characterization shared by future local and remote adapters.

#[path = "support/control_scenarios.rs"]
mod control_scenarios;

use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;

use vortix::vortix_core::cidr::Cidr;
use vortix::vortix_core::engine::state::DetailedConnectionInfo;
use vortix::vortix_core::engine::{Conflict, Engine, Role, TunnelRegistry};
use vortix::vortix_core::ports::tunnel::mock::MockTunnel;
use vortix::vortix_core::profile::ProfileId;

fn cidr(address: [u8; 4], prefix: u8) -> Cidr {
    Cidr::new(IpAddr::V4(Ipv4Addr::from(address)), prefix).unwrap()
}

fn insert_connected(
    registry: &mut TunnelRegistry<MockTunnel>,
    name: &str,
    interface: &str,
    allowed_ips: Vec<Cidr>,
) {
    registry.set_connected(
        ProfileId::new(name),
        allowed_ips,
        DetailedConnectionInfo {
            interface: interface.to_string(),
            interface_authoritative: true,
            ..Default::default()
        },
        SystemTime::UNIX_EPOCH,
        || Engine::new(MockTunnel::new(), |_| None),
    );
}

#[test]
fn one_and_two_tunnel_primary_and_secondary_roles_are_stable() {
    let mut registry = TunnelRegistry::new();
    insert_connected(&mut registry, "corp", "wg0", vec![cidr([0, 0, 0, 0], 0)]);
    registry.feed_default_route_interface(Some("wg0".to_string()));
    registry.refresh_primary();

    assert_eq!(registry.primary(), Some(&ProfileId::new("corp")));
    assert!(matches!(
        registry.snapshot(&ProfileId::new("corp")).unwrap().role,
        Role::Primary { .. }
    ));

    insert_connected(&mut registry, "lab", "wg1", vec![cidr([10, 0, 0, 0], 8)]);
    let snapshots = registry.snapshot_all();
    assert_eq!(snapshots.len(), 2);
    assert!(matches!(snapshots[1].role, Role::Addressable { .. }));
}

#[test]
fn split_only_topology_keeps_no_primary_and_preserves_route_scope() {
    let mut registry = TunnelRegistry::new();
    let split = cidr([10, 0, 0, 0], 8);
    insert_connected(&mut registry, "lab", "wg1", vec![split]);
    registry.feed_default_route_interface(None);
    registry.refresh_primary();

    assert!(registry.primary().is_none());
    let snapshot = registry.snapshot(&ProfileId::new("lab")).unwrap();
    let Role::Addressable { allowed_ips } = snapshot.role else {
        panic!("split-only tunnel must remain addressable");
    };
    assert_eq!(allowed_ips, vec![split]);
    assert!(split.intersects(&cidr([10, 2, 3, 4], 32)));
    assert!(!split.intersects(&cidr([8, 8, 8, 8], 32)));
}

#[test]
fn second_default_route_is_a_typed_conflict_without_kernel_mutation() {
    let mut registry = TunnelRegistry::new();
    let default = cidr([0, 0, 0, 0], 0);
    insert_connected(&mut registry, "corp", "wg0", vec![default]);

    let conflict = registry
        .detect_conflict(&ProfileId::new("home"), &[default])
        .expect("second default route must conflict");
    assert_eq!(
        conflict,
        Conflict::DefaultRouteTakeover {
            current: ProfileId::new("corp"),
            new: ProfileId::new("home"),
        }
    );
}
