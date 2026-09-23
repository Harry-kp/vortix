//! Pure network plan: the routes, DNS roles and firewall allowances the host
//! should carry for a set of live tunnels.
//!
//! The plan depends only on which tunnels are up, never on the order of the
//! commands that produced them, so every path to the same tunnel set lands on
//! the same host state.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::ports::dns::{DnsRequest, DnsTunnelIntent, DnsTunnelRole};
use crate::vortix_core::ports::killswitch::ActiveTunnelInfo;
use crate::vortix_core::profile::ProfileId;

/// One live tunnel as the planner sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanTunnel {
    pub profile_id: ProfileId,
    pub interface: String,
    pub routes: BTreeSet<Cidr>,
    pub server_ips: BTreeSet<IpAddr>,
    pub dns: DnsRequest,
    /// Larger is newer. The newest full tunnel owns the default route.
    pub rank: u64,
}

impl PlanTunnel {
    fn claims_default(&self, v4: bool) -> bool {
        self.routes
            .iter()
            .any(|cidr| cidr.prefix_len == 0 && cidr.addr.is_ipv4() == v4)
    }

    fn is_full(&self) -> bool {
        self.claims_default(true) || self.claims_default(false)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkPlan {
    /// Owner of the IPv4 default route.
    pub primary: Option<ProfileId>,
    /// Kernel routes: CIDR → interface. A default claim becomes its two `/1`
    /// halves, which outrank the physical `/0` without replacing it.
    pub routes: BTreeMap<Cidr, String>,
    /// Server addresses pinned to the physical gateway so a full tunnel's own
    /// transport never loops into a tunnel.
    pub host_routes: BTreeSet<IpAddr>,
    pub dns: Vec<DnsTunnelIntent>,
    pub firewall: Vec<ActiveTunnelInfo>,
}

impl NetworkPlan {
    /// Address whose kernel route lookup proves `cidr` is bound, avoiding any
    /// address a host route pins elsewhere.
    #[must_use]
    pub fn probe_address(&self, cidr: Cidr) -> Option<IpAddr> {
        let probe = match cidr.addr {
            IpAddr::V4(addr) if addr.is_unspecified() => IpAddr::from([1, 1, 1, 1]),
            IpAddr::V6(addr) if addr.is_unspecified() => {
                "2606:4700:4700::1111".parse().expect("fixed IPv6 address")
            }
            IpAddr::V4(addr) if cidr.prefix_len < 32 => {
                IpAddr::V4(u32::from(addr).saturating_add(1).into())
            }
            IpAddr::V6(addr) if cidr.prefix_len < 128 => {
                IpAddr::V6(u128::from(addr).saturating_add(1).into())
            }
            addr => addr,
        };
        (!self.host_routes.contains(&probe)).then_some(probe)
    }
}

fn default_halves(v4: bool) -> [Cidr; 2] {
    let parse = |value: &str| value.parse::<Cidr>().expect("fixed default half");
    if v4 {
        [parse("0.0.0.0/1"), parse("128.0.0.0/1")]
    } else {
        [parse("::/1"), parse("8000::/1")]
    }
}

fn newest(tunnels: &[PlanTunnel], pick: impl Fn(&PlanTunnel) -> bool) -> Option<&PlanTunnel> {
    tunnels.iter().filter(|tunnel| pick(tunnel)).max_by(|a, b| {
        a.rank
            .cmp(&b.rank)
            .then_with(|| b.profile_id.cmp(&a.profile_id))
    })
}

#[must_use]
pub fn plan(tunnels: &[PlanTunnel]) -> NetworkPlan {
    let primary = newest(tunnels, |tunnel| tunnel.claims_default(true));
    let primary_v6 = newest(tunnels, |tunnel| tunnel.claims_default(false));

    let mut owners = BTreeMap::<Cidr, &PlanTunnel>::new();
    for tunnel in tunnels {
        for cidr in tunnel.routes.iter().filter(|cidr| cidr.prefix_len != 0) {
            let cidr = cidr.canonical_network();
            let owner = owners.entry(cidr).or_insert(tunnel);
            if (tunnel.rank, &owner.profile_id) > (owner.rank, &tunnel.profile_id) {
                *owner = tunnel;
            }
        }
    }
    let mut routes = owners
        .into_iter()
        .map(|(cidr, owner)| (cidr, owner.interface.clone()))
        .collect::<BTreeMap<_, _>>();
    for (owner, v4) in [(primary, true), (primary_v6, false)] {
        if let Some(owner) = owner {
            for half in default_halves(v4) {
                routes.insert(half, owner.interface.clone());
            }
        }
    }

    let host_routes = tunnels
        .iter()
        .filter(|tunnel| tunnel.is_full())
        .flat_map(|tunnel| tunnel.server_ips.iter().copied())
        .collect();

    let dns = tunnels
        .iter()
        .filter(|tunnel| !tunnel.dns.is_empty())
        .map(|tunnel| DnsTunnelIntent {
            profile_id: tunnel.profile_id.clone(),
            interface: tunnel.interface.clone(),
            role: if primary.is_some_and(|primary| primary.profile_id == tunnel.profile_id) {
                DnsTunnelRole::Primary
            } else {
                DnsTunnelRole::Secondary
            },
            request: tunnel.dns.clone(),
        })
        .collect();

    let firewall = tunnels
        .iter()
        .map(|tunnel| ActiveTunnelInfo {
            interface: tunnel.interface.clone(),
            server_ips: tunnel.server_ips.iter().copied().collect(),
            declared_cidrs: tunnel.routes.iter().copied().collect(),
            is_primary: tunnel.is_full(),
        })
        .collect();

    NetworkPlan {
        primary: primary.map(|tunnel| tunnel.profile_id.clone()),
        routes,
        host_routes,
        dns,
        firewall,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = "0.0.0.0/0";
    const SPLIT: &str = "10.250.0.0/24";

    fn tunnel(id: &str, iface: &str, route: &str, rank: u64) -> PlanTunnel {
        PlanTunnel {
            profile_id: ProfileId::new(id),
            interface: iface.into(),
            routes: BTreeSet::from([route.parse().unwrap()]),
            server_ips: BTreeSet::from([IpAddr::from([203, 0, 113, u8::try_from(rank).unwrap()])]),
            dns: DnsRequest {
                servers: vec![IpAddr::from([10, 8, 0, 1])],
                search_domains: Vec::new(),
            },
            rank,
        }
    }

    fn cidr(value: &str) -> Cidr {
        value.parse().unwrap()
    }

    /// Invariants every plan must hold, whatever tunnels are up.
    fn assert_invariants(tunnels: &[PlanTunnel], plan: &NetworkPlan) {
        let primaries = plan
            .dns
            .iter()
            .filter(|intent| intent.role == DnsTunnelRole::Primary)
            .count();
        assert!(primaries <= 1, "at most one DNS primary: {plan:?}");
        let full = tunnels
            .iter()
            .filter(|tunnel| tunnel.claims_default(true))
            .collect::<Vec<_>>();
        if let Some(owner) = newest(tunnels, |tunnel| tunnel.claims_default(true)) {
            assert_eq!(plan.primary.as_ref(), Some(&owner.profile_id));
            for half in default_halves(true) {
                assert_eq!(plan.routes.get(&half), Some(&owner.interface));
            }
            assert_eq!(primaries, usize::from(!owner.dns.is_empty()));
        } else {
            assert!(full.is_empty());
            assert_eq!(plan.primary, None);
            assert!(!plan.routes.contains_key(&cidr("0.0.0.0/1")));
            assert_eq!(primaries, 0);
        }
        for tunnel in &full {
            for ip in &tunnel.server_ips {
                assert!(
                    plan.host_routes.contains(ip),
                    "full tunnel keeps its escape route"
                );
            }
        }
        let interfaces = tunnels
            .iter()
            .map(|tunnel| tunnel.interface.as_str())
            .collect::<BTreeSet<_>>();
        assert!(
            plan.routes
                .values()
                .all(|iface| interfaces.contains(iface.as_str())),
            "no route points at a tunnel that is down"
        );
        assert_eq!(plan.firewall.len(), tunnels.len());
    }

    #[test]
    fn newest_full_tunnel_owns_the_default_route_and_dns() {
        let tunnels = [
            tunnel("01", "utun4", FULL, 1),
            tunnel("03", "utun6", FULL, 3),
        ];
        let plan = plan(&tunnels);
        assert_eq!(plan.primary, Some(ProfileId::new("03")));
        assert_eq!(plan.routes[&cidr("0.0.0.0/1")], "utun6");
        assert_invariants(&tunnels, &plan);
    }

    #[test]
    fn split_tunnel_keeps_its_prefix_beside_a_full_tunnel() {
        let tunnels = [
            tunnel("01", "utun4", FULL, 1),
            tunnel("02", "utun5", SPLIT, 2),
        ];
        let plan = plan(&tunnels);
        assert_eq!(plan.routes[&cidr(SPLIT)], "utun5");
        assert_eq!(plan.primary, Some(ProfileId::new("01")));
        assert_invariants(&tunnels, &plan);
    }

    #[test]
    fn a_default_probe_never_lands_on_a_pinned_server() {
        let mut full = tunnel("01", "utun4", FULL, 1);
        full.server_ips = BTreeSet::from([IpAddr::from([1, 1, 1, 1])]);
        let plan = plan(&[full]);
        assert_eq!(plan.probe_address(cidr("0.0.0.0/1")), None);
        assert_eq!(
            plan.probe_address(cidr("128.0.0.0/1")),
            Some(IpAddr::from([128, 0, 0, 1]))
        );
    }

    /// Every connect/disconnect sequence over three full and split profiles:
    /// the plan after each step depends only on the live set, and holds every
    /// invariant.
    #[test]
    fn every_command_sequence_converges_to_the_same_plan_for_the_same_live_set() {
        let catalog = [
            ("01", "utun4", FULL),
            ("02", "utun5", SPLIT),
            ("03", "utun6", FULL),
        ];
        let mut seen = BTreeMap::<Vec<(String, u64)>, NetworkPlan>::new();
        let steps = catalog.len() * 2;
        for sequence in 0..(steps.pow(5)) {
            let mut live = Vec::<PlanTunnel>::new();
            let mut clock = 0;
            let mut rest = sequence;
            for _ in 0..5 {
                let step = rest % steps;
                rest /= steps;
                let (id, iface, route) = catalog[step / 2];
                live.retain(|tunnel| tunnel.profile_id.as_str() != id);
                if step % 2 == 0 {
                    clock += 1;
                    live.push(tunnel(id, iface, route, clock));
                }
                let plan = plan(&live);
                assert_invariants(&live, &plan);
                let mut order = live
                    .iter()
                    .map(|tunnel| (tunnel.profile_id.as_str().to_owned(), tunnel.rank))
                    .collect::<Vec<_>>();
                order.sort_by_key(|(_, rank)| *rank);
                let key = order
                    .iter()
                    .enumerate()
                    .map(|(position, (id, _))| (id.clone(), position as u64))
                    .collect::<Vec<_>>();
                let mut normalized = plan.clone();
                normalized.host_routes.clear();
                normalized.firewall.clear();
                if let Some(previous) = seen.get(&key) {
                    assert_eq!(previous, &normalized, "same live set, same plan");
                } else {
                    seen.insert(key, normalized);
                }
            }
        }
    }
}
