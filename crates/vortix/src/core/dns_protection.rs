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

pub(crate) fn policy_for_topology(
    generation: u64,
    state: &TopologyState,
    capabilities: DnsPlatformCapabilities,
) -> Result<DnsPolicy, String> {
    let intents = state
        .profiles
        .iter()
        .filter_map(|profile| {
            state
                .dns_requests
                .get(profile)
                .filter(|request| !request.is_empty())
                .map(|request| (profile, request))
        })
        .map(|(profile, request)| {
            let interface =
                state.interfaces.get(profile).cloned().ok_or_else(|| {
                    format!("profile {profile} has no authoritative DNS interface")
                })?;
            let role = if state
                .routes
                .get(profile)
                .is_some_and(|routes| routes.iter().any(|route| route.is_default()))
            {
                DnsTunnelRole::Primary
            } else {
                DnsTunnelRole::Secondary
            };
            Ok(DnsTunnelIntent {
                profile_id: profile.clone(),
                interface,
                role,
                request: request.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    DnsPolicy::compute(generation, &intents, capabilities).map_err(|error| error.to_string())
}

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
            if interface == expected_interface {
                continue;
            }
            return Err(format!(
                "DNS resolver {server} currently routes through {interface} instead of this VPN ({expected_interface}). Another VPN or network service may own that route. Check active VPN apps, then run `{}`.",
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
        assert!(error.contains("currently routes through en0 instead of this VPN (utun4)"));
        assert!(error.contains("Another VPN or network service may own that route"));
        assert!(error.contains(&route_diagnostic_command("192.168.1.100".parse().unwrap())));
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
