//! System-DNS path verification for the Security Guard.
//!
//! Resolver configuration readback proves which servers the operating system
//! intends to use. This module adds the second half of that proof: every
//! active resolver address must resolve through the tunnel interface that owns
//! its DNS assignment. It intentionally makes no claim about application-owned
//! encrypted DNS such as browser `DoH`.

use std::net::IpAddr;
use std::time::Instant;

use crate::vortix_core::control::worker::TopologyState;
use crate::vortix_core::ports::dns::{
    DnsPlatformCapabilities, DnsPolicy, DnsScope, DnsTunnelIntent, DnsTunnelRole,
};
use crate::vortix_core::ports::route_table::DefaultRouteObservation;

const MAX_DNS_ROUTE_PROBES: usize = 256;

pub(crate) fn verify_dns_routes(policy: &DnsPolicy, deadline: Instant) -> Result<(), String> {
    verify_dns_routes_with(policy, deadline, |server| {
        crate::platform::current_platform()
            .route_table
            .route_interface_for(server)
    })
}

fn verify_dns_routes_with(
    policy: &DnsPolicy,
    deadline: Instant,
    mut observe: impl FnMut(IpAddr) -> DefaultRouteObservation,
) -> Result<(), String> {
    // Every interface vortix currently assigns DNS to is a tunnel it manages.
    // A resolver that egresses through any of them is still inside a VPN — not a
    // leak — even if it is not the specific interface it was assigned to. This
    // is the normal split+full case: a split tunnel's public resolver rides the
    // primary full tunnel that owns the default route. Only egress through an
    // interface vortix does NOT manage (a physical link) is a real DNS leak.
    let vpn_interfaces = policy
        .assignments
        .iter()
        .filter(|assignment| !matches!(assignment.scope, DnsScope::Suppressed))
        .map(|assignment| assignment.interface.as_str())
        .collect::<Vec<_>>();
    let mut probes = policy
        .assignments
        .iter()
        .filter(|assignment| !matches!(assignment.scope, DnsScope::Suppressed))
        .flat_map(|assignment| {
            assignment
                .servers
                .iter()
                .copied()
                .map(move |server| (server, assignment.interface.as_str()))
        })
        .collect::<Vec<_>>();
    probes.sort_unstable();
    probes.dedup();
    if probes.len() > MAX_DNS_ROUTE_PROBES {
        return Err(format!(
            "DNS verification requires more than {MAX_DNS_ROUTE_PROBES} distinct route probes"
        ));
    }
    let total = probes.len();
    for (index, (server, expected_interface)) in probes.into_iter().enumerate() {
        if Instant::now() >= deadline {
            return Err(format!(
                "DNS route verification deadline expired after {index} of {total} probes"
            ));
        }
        let observation = observe(server);
        if Instant::now() >= deadline {
            return Err(format!(
                "DNS route verification deadline expired during probe {} of {total}",
                index + 1
            ));
        }
        if let DefaultRouteObservation::Interface(interface) = &observation {
            if interface == expected_interface || vpn_interfaces.contains(&interface.as_str()) {
                continue;
            }
            return Err(format!(
                "DNS resolver {server} currently routes through {interface}, which is not a Vortix VPN interface. Another VPN or network service may own that route. Check active VPN apps, then run `{}`.",
                route_diagnostic_command(server)
            ));
        }
        return Err(format!(
            "DNS resolver {server} could not be verified through this VPN ({expected_interface}): {observation:?}"
        ));
    }
    Ok(())
}

fn route_diagnostic_command(server: IpAddr) -> String {
    match std::env::consts::OS {
        "macos" => {
            let family = if server.is_ipv4() { "-inet" } else { "-inet6" };
            format!("route -n get {family} {server}")
        }
        "linux" => format!("ip route get {server}"),
        _ => format!("inspect the system route to {server}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::ports::dns::{DnsAssignment, DnsScope};
    use crate::vortix_core::profile::ProfileId;
    use std::time::Duration;

    fn policy(server: &str, interface: &str) -> DnsPolicy {
        DnsPolicy {
            generation: 7,
            assignments: vec![DnsAssignment {
                profile_id: ProfileId::new("corp"),
                interface: interface.into(),
                servers: vec![server.parse().unwrap()],
                search_domains: Vec::new(),
                scope: DnsScope::CatchAll,
            }],
        }
    }

    #[test]
    fn resolver_route_must_use_its_owned_tunnel_interface() {
        let error = verify_dns_routes_with(
            &policy("192.168.1.100", "utun4"),
            Instant::now() + Duration::from_secs(1),
            |_| DefaultRouteObservation::Interface("en0".into()),
        )
        .unwrap_err();

        assert!(error.contains("192.168.1.100"));
        assert!(error.contains("currently routes through en0, which is not a Vortix VPN interface"));
        assert!(error.contains("Another VPN or network service may own that route"));
        assert!(error.contains(&route_diagnostic_command("192.168.1.100".parse().unwrap())));
    }

    #[test]
    fn resolver_riding_another_vortix_tunnel_is_not_a_leak() {
        // Split + full: the split tunnel (utun4) pushes a public resolver, but a
        // full tunnel (utun5) owns the default route, so the resolver egresses
        // through utun5. That is still inside a Vortix VPN — accept it, don't
        // reject the split tunnel's connect.
        let policy = DnsPolicy {
            generation: 7,
            assignments: vec![
                DnsAssignment {
                    profile_id: ProfileId::new("split"),
                    interface: "utun4".into(),
                    servers: vec!["1.0.0.1".parse().unwrap()],
                    search_domains: Vec::new(),
                    scope: DnsScope::CatchAll,
                },
                DnsAssignment {
                    profile_id: ProfileId::new("full"),
                    interface: "utun5".into(),
                    servers: vec!["1.1.1.1".parse().unwrap()],
                    search_domains: Vec::new(),
                    scope: DnsScope::CatchAll,
                },
            ],
        };
        verify_dns_routes_with(&policy, Instant::now() + Duration::from_secs(1), |_| {
            DefaultRouteObservation::Interface("utun5".into())
        })
        .unwrap();
    }

    #[test]
    fn resolver_route_is_protected_only_on_the_exact_tunnel() {
        verify_dns_routes_with(
            &policy("10.80.0.1", "utun4"),
            Instant::now() + Duration::from_secs(1),
            |_| DefaultRouteObservation::Interface("utun4".into()),
        )
        .unwrap();
    }

    #[test]
    fn suppressed_secondary_dns_does_not_claim_a_route() {
        let mut policy = policy("192.168.1.100", "utun4");
        policy.assignments[0].scope = DnsScope::Suppressed;
        verify_dns_routes_with(&policy, Instant::now() + Duration::from_secs(1), |_| {
            panic!("suppressed DNS must not be probed")
        })
        .unwrap();
    }
}
