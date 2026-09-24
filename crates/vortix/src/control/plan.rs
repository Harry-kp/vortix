//! What the host network should look like for a set of tunnels.
//!
//! Pure: the plan depends only on which tunnels exist and the kill switch
//! mode, never on the commands that produced them, so every path to the same
//! tunnel set lands on the same routes, DNS and firewall.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::core::cidr::Cidr;
use crate::core::ports::dns::{DnsRequest, DnsTunnelIntent, DnsTunnelRole};
use crate::core::ports::killswitch::ActiveTunnelInfo;
use crate::core::profile::ProfileId;
use crate::core::state::killswitch::{KillSwitchMode, KillSwitchState};

/// One tunnel whose interface is up and carrying traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveTunnel {
    pub profile_id: ProfileId,
    pub interface: String,
    pub routes: BTreeSet<Cidr>,
    pub server_ips: BTreeSet<IpAddr>,
    pub dns: DnsRequest,
    /// Larger is newer. The newest full tunnel owns the default route.
    pub rank: u64,
}

impl LiveTunnel {
    fn claims_default(&self, v4: bool) -> bool {
        self.routes
            .iter()
            .any(|cidr| cidr.prefix_len == 0 && cidr.addr.is_ipv4() == v4)
    }

    #[must_use]
    pub fn is_full(&self) -> bool {
        self.claims_default(true) || self.claims_default(false)
    }
}

/// Everything the planner needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanInput {
    pub live: Vec<LiveTunnel>,
    /// Servers of tunnels still starting or recovering. The firewall must let
    /// their transport out before an interface exists.
    pub pending_endpoints: BTreeSet<IpAddr>,
    /// A tunnel dropped without being asked to.
    pub dropped: bool,
    pub kill_switch: KillSwitchMode,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Firewall {
    #[default]
    Open,
    /// Default-drop egress except through these tunnels and endpoints.
    Block(Vec<ActiveTunnelInfo>),
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
    pub firewall: Firewall,
    pub kill_switch_state: KillSwitchState,
}

impl NetworkPlan {
    /// Address whose kernel route lookup proves `cidr` is bound, avoiding any
    /// address a host route pins elsewhere.
    #[must_use]
    pub fn probe_address(&self, cidr: Cidr) -> Option<IpAddr> {
        let probe = match cidr.addr {
            IpAddr::V4(addr) if addr.is_unspecified() => IpAddr::from([1, 1, 1, 1]),
            IpAddr::V6(addr) if addr.is_unspecified() => {
                IpAddr::from([0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111])
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

fn newest(tunnels: &[LiveTunnel], pick: impl Fn(&LiveTunnel) -> bool) -> Option<&LiveTunnel> {
    tunnels.iter().filter(|tunnel| pick(tunnel)).max_by(|a, b| {
        a.rank
            .cmp(&b.rank)
            .then_with(|| b.profile_id.cmp(&a.profile_id))
    })
}

#[must_use]
pub fn plan(input: &PlanInput) -> NetworkPlan {
    let tunnels = input.live.as_slice();
    let primary = newest(tunnels, |tunnel| tunnel.claims_default(true));
    let primary_v6 = newest(tunnels, |tunnel| tunnel.claims_default(false));

    let mut owners = BTreeMap::<Cidr, &LiveTunnel>::new();
    for tunnel in tunnels {
        for cidr in tunnel.routes.iter().filter(|cidr| cidr.prefix_len != 0) {
            let owner = owners.entry(cidr.canonical_network()).or_insert(tunnel);
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

    let (firewall, kill_switch_state) = firewall(input);

    NetworkPlan {
        primary: primary.map(|tunnel| tunnel.profile_id.clone()),
        routes,
        host_routes,
        dns,
        firewall,
        kill_switch_state,
    }
}

fn firewall(input: &PlanInput) -> (Firewall, KillSwitchState) {
    let blocking = match input.kill_switch {
        KillSwitchMode::Off => return (Firewall::Open, KillSwitchState::Disabled),
        KillSwitchMode::AlwaysOn => true,
        KillSwitchMode::Auto => input.dropped,
    };
    if !blocking {
        return (Firewall::Open, KillSwitchState::Armed);
    }
    let mut allow = input
        .live
        .iter()
        .map(|tunnel| ActiveTunnelInfo {
            interface: tunnel.interface.clone(),
            server_ips: tunnel.server_ips.iter().copied().collect(),
            declared_cidrs: tunnel.routes.iter().copied().collect(),
            is_primary: tunnel.is_full(),
        })
        .collect::<Vec<_>>();
    let covered = allow
        .iter()
        .flat_map(|tunnel| tunnel.server_ips.iter().copied())
        .collect::<BTreeSet<_>>();
    let pending = input
        .pending_endpoints
        .difference(&covered)
        .copied()
        .collect::<Vec<_>>();
    if !pending.is_empty() {
        allow.push(ActiveTunnelInfo::endpoint_allowlist(pending));
    }
    (Firewall::Block(allow), KillSwitchState::Blocking)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const FULL: &str = "0.0.0.0/0";
    pub const SPLIT: &str = "10.250.0.0/24";

    pub fn live(id: &str, iface: &str, route: &str, rank: u64) -> LiveTunnel {
        LiveTunnel {
            profile_id: ProfileId::new(id),
            interface: iface.into(),
            routes: BTreeSet::from([route.parse().unwrap()]),
            server_ips: BTreeSet::from([IpAddr::from([203, 0, 113, id.as_bytes()[0]])]),
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

    fn input(live: Vec<LiveTunnel>) -> PlanInput {
        PlanInput {
            live,
            ..PlanInput::default()
        }
    }

    /// Invariants every plan must hold, whatever the input.
    pub fn assert_invariants(input: &PlanInput, plan: &NetworkPlan) {
        let tunnels = &input.live;
        let primaries = plan
            .dns
            .iter()
            .filter(|intent| intent.role == DnsTunnelRole::Primary)
            .count();
        assert!(primaries <= 1, "at most one DNS primary: {plan:?}");
        if let Some(owner) = newest(tunnels, |tunnel| tunnel.claims_default(true)) {
            assert_eq!(plan.primary.as_ref(), Some(&owner.profile_id));
            for half in default_halves(true) {
                assert_eq!(plan.routes.get(&half), Some(&owner.interface));
            }
            assert_eq!(primaries, usize::from(!owner.dns.is_empty()));
        } else {
            assert_eq!(plan.primary, None);
            assert!(!plan.routes.contains_key(&cidr("0.0.0.0/1")));
            assert_eq!(primaries, 0);
        }
        for tunnel in tunnels.iter().filter(|tunnel| tunnel.is_full()) {
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
        let blocks = matches!(plan.firewall, Firewall::Block(_));
        match input.kill_switch {
            KillSwitchMode::Off => assert!(!blocks),
            KillSwitchMode::AlwaysOn => assert!(blocks),
            KillSwitchMode::Auto => assert_eq!(blocks, input.dropped),
        }
        if let Firewall::Block(allow) = &plan.firewall {
            let allowed = allow
                .iter()
                .flat_map(|rule| rule.server_ips.iter())
                .collect::<BTreeSet<_>>();
            for endpoint in &input.pending_endpoints {
                assert!(
                    allowed.contains(endpoint),
                    "a starting tunnel can reach its server"
                );
            }
        }
    }

    #[test]
    fn newest_full_tunnel_owns_the_default_route_and_dns() {
        let input = input(vec![
            live("01", "utun4", FULL, 1),
            live("03", "utun6", FULL, 3),
        ]);
        let plan = plan(&input);
        assert_eq!(plan.primary, Some(ProfileId::new("03")));
        assert_eq!(plan.routes[&cidr("0.0.0.0/1")], "utun6");
        assert_invariants(&input, &plan);
    }

    #[test]
    fn split_tunnel_keeps_its_prefix_beside_a_full_tunnel() {
        let input = input(vec![
            live("01", "utun4", FULL, 1),
            live("02", "utun5", SPLIT, 2),
        ]);
        let plan = plan(&input);
        assert_eq!(plan.routes[&cidr(SPLIT)], "utun5");
        assert_eq!(plan.primary, Some(ProfileId::new("01")));
        assert_invariants(&input, &plan);
    }

    #[test]
    fn a_default_probe_never_lands_on_a_pinned_server() {
        let mut full = live("01", "utun4", FULL, 1);
        full.server_ips = BTreeSet::from([IpAddr::from([1, 1, 1, 1])]);
        let plan = plan(&input(vec![full]));
        assert_eq!(plan.probe_address(cidr("0.0.0.0/1")), None);
        assert_eq!(
            plan.probe_address(cidr("128.0.0.0/1")),
            Some(IpAddr::from([128, 0, 0, 1]))
        );
    }

    #[test]
    fn block_on_drop_blocks_only_after_a_drop() {
        let mut input = input(vec![live("01", "utun4", FULL, 1)]);
        input.kill_switch = KillSwitchMode::Auto;
        assert_eq!(plan(&input).kill_switch_state, KillSwitchState::Armed);
        input.live.clear();
        input.dropped = true;
        input.pending_endpoints = BTreeSet::from([IpAddr::from([203, 0, 113, 2])]);
        let plan = plan(&input);
        assert_eq!(plan.kill_switch_state, KillSwitchState::Blocking);
        assert_invariants(&input, &plan);
    }
}
