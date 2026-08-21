//! Fixed-vocabulary Linux route-selection read-back for the root helper.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use crate::platform::fixed_root_command::{self, FixedCommandError};
use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::ports::owned_routes::{
    canonical_route_destination, OwnedRouteBackend, OwnedRouteError, OwnedRoutes, RouteEntry,
    RouteMutationError,
};

const IP_CANDIDATES: &[&str] = &["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"];
const VORTIX_ROUTE_PROTOCOL: &str = "196";
const VORTIX_ROUTE_TABLE: &str = "196";
const VORTIX_BYPASS_RULE_PRIORITY: &str = "19599";
const VORTIX_TABLE_RULE_PRIORITY: &str = "19600";

pub(crate) struct LinuxOwnedRoutes;

impl LinuxOwnedRoutes {
    fn mutate(route: &RouteEntry, action: RouteMutation) -> Result<(), RouteMutationError> {
        let arguments = linux_route_arguments(action, route);
        let borrowed = arguments.iter().map(String::as_str).collect::<Vec<_>>();
        let output = fixed_root_command::run(IP_CANDIDATES, &borrowed, None, 0)
            .map_err(map_mutation_error)?;
        if output.status.success() {
            Ok(())
        } else {
            Err(RouteMutationError::FailedBeforeEffect)
        }
    }

    fn policy_rules(ipv4: bool) -> Result<LinuxPolicyRules, OwnedRouteError> {
        let family = if ipv4 { "-4" } else { "-6" };
        let output = fixed_root_command::run(IP_CANDIDATES, &[family, "rule", "show"], None, 0)
            .map_err(|_| OwnedRouteError::Unknown)?;
        if !output.status.success() {
            return Err(OwnedRouteError::Unknown);
        }
        parse_linux_policy_rules(&output.stdout, ipv4).ok_or(OwnedRouteError::Unknown)
    }

    fn mutate_rule(arguments: &[String]) -> Result<(), RouteMutationError> {
        let borrowed = arguments.iter().map(String::as_str).collect::<Vec<_>>();
        let output = fixed_root_command::run(IP_CANDIDATES, &borrowed, None, 0)
            .map_err(map_mutation_error)?;
        if output.status.success() {
            Ok(())
        } else {
            Err(RouteMutationError::FailedBeforeEffect)
        }
    }

    fn mutate_route_domain(action: RuleMutation) -> Result<(), RouteMutationError> {
        let first = linux_table_rule_arguments(true, action);
        Self::mutate_rule(&first)?;
        let second = linux_table_rule_arguments(false, action);
        if let Err(error) = Self::mutate_rule(&second) {
            let rollback = linux_table_rule_arguments(true, action.inverse());
            if Self::mutate_rule(&rollback).is_ok()
                && matches!(
                    (Self::policy_rules(true), Self::policy_rules(false)),
                    (Ok(ipv4), Ok(ipv6)) if ipv4.domain_active == action.inverse().is_add()
                        && ipv6.domain_active == action.inverse().is_add()
                )
            {
                return Err(RouteMutationError::FailedBeforeEffect);
            }
            return Err(match error {
                RouteMutationError::FailedBeforeEffect
                | RouteMutationError::EffectMayHaveApplied => {
                    RouteMutationError::EffectMayHaveApplied
                }
            });
        }
        Ok(())
    }
}

impl OwnedRoutes for LinuxOwnedRoutes {
    fn backend(&self) -> OwnedRouteBackend {
        OwnedRouteBackend::LinuxPolicyV1
    }

    fn route_interface_for(&mut self, target: IpAddr) -> Result<String, OwnedRouteError> {
        let target = target.to_string();
        let output =
            fixed_root_command::run(IP_CANDIDATES, &["route", "get", target.as_str()], None, 0)
                .map_err(|_| OwnedRouteError::Unknown)?;
        if !output.status.success() {
            return Err(OwnedRouteError::Unknown);
        }
        super::route_table::parse_interface(&output.stdout).ok_or(OwnedRouteError::Unknown)
    }

    fn exact_route_interfaces(
        &mut self,
        destination: Cidr,
    ) -> Result<Vec<String>, OwnedRouteError> {
        let destination = canonical_route_destination(destination);
        let family = if destination.is_v4() { "-4" } else { "-6" };
        let destination = destination.to_string();
        let output = fixed_root_command::run(
            IP_CANDIDATES,
            &[
                family,
                "route",
                "show",
                "table",
                "all",
                "exact",
                destination.as_str(),
            ],
            None,
            0,
        )
        .map_err(|_| OwnedRouteError::Unknown)?;
        if !output.status.success() {
            return Err(OwnedRouteError::Unknown);
        }
        parse_exact_route_interfaces(&output.stdout, destination.as_str())
            .ok_or(OwnedRouteError::Unknown)
    }

    fn exact_route_entries(
        &mut self,
        destination: Cidr,
    ) -> Result<Vec<RouteEntry>, OwnedRouteError> {
        self.exact_route_entries_batch(&[destination])?
            .pop()
            .ok_or(OwnedRouteError::Unknown)
    }

    fn exact_route_entries_batch(
        &mut self,
        destinations: &[Cidr],
    ) -> Result<Vec<Vec<RouteEntry>>, OwnedRouteError> {
        let destinations = destinations
            .iter()
            .copied()
            .map(canonical_route_destination)
            .collect::<Vec<_>>();
        let mut observed = HashMap::<Cidr, Vec<RouteEntry>>::new();
        for (ipv4, family) in [(true, "-4"), (false, "-6")] {
            let requested = destinations
                .iter()
                .copied()
                .filter(|destination| destination.is_v4() == ipv4)
                .collect::<Vec<_>>();
            if requested.is_empty() {
                continue;
            }
            let output = fixed_root_command::run(
                IP_CANDIDATES,
                &[family, "route", "show", "table", VORTIX_ROUTE_TABLE],
                None,
                0,
            )
            .map_err(|_| OwnedRouteError::Unknown)?;
            if !output.status.success() {
                return Err(OwnedRouteError::Unknown);
            }
            observed.extend(
                parse_exact_route_entries_batch(&output.stdout, &requested)
                    .ok_or(OwnedRouteError::Unknown)?,
            );
        }
        destinations
            .into_iter()
            .map(|destination| {
                observed
                    .remove(&destination)
                    .ok_or(OwnedRouteError::Unknown)
            })
            .collect()
    }

    fn add_route(&mut self, route: &RouteEntry) -> Result<(), RouteMutationError> {
        Self::mutate(route, RouteMutation::Add)
    }

    fn remove_route(&mut self, route: &RouteEntry) -> Result<(), RouteMutationError> {
        Self::mutate(route, RouteMutation::Delete)
    }

    fn exact_transport_bypass_targets(&mut self) -> Result<Vec<IpAddr>, OwnedRouteError> {
        let ipv4 = Self::policy_rules(true)?;
        let ipv6 = Self::policy_rules(false)?;
        Ok(ipv4
            .bypass_targets
            .into_iter()
            .chain(ipv6.bypass_targets)
            .collect())
    }

    fn add_transport_bypass(&mut self, target: IpAddr) -> Result<(), RouteMutationError> {
        Self::mutate_rule(&linux_bypass_rule_arguments(target, RuleMutation::Add))
    }

    fn remove_transport_bypass(&mut self, target: IpAddr) -> Result<(), RouteMutationError> {
        Self::mutate_rule(&linux_bypass_rule_arguments(target, RuleMutation::Delete))
    }

    fn resolve_net_gateway(&mut self, destination: Cidr) -> Result<RouteEntry, OwnedRouteError> {
        let family = if destination.is_v4() { "-4" } else { "-6" };
        let output = fixed_root_command::run(
            IP_CANDIDATES,
            &[family, "route", "show", "table", "main", "default"],
            None,
            0,
        )
        .map_err(|_| OwnedRouteError::Unknown)?;
        if !output.status.success() {
            return Err(OwnedRouteError::Unknown);
        }
        parse_linux_default_gateway(&output.stdout, destination).ok_or(OwnedRouteError::Unknown)
    }

    fn route_domain_active(&mut self) -> Result<bool, OwnedRouteError> {
        let ipv4 = Self::policy_rules(true)?.domain_active;
        let ipv6 = Self::policy_rules(false)?.domain_active;
        (ipv4 == ipv6)
            .then_some(ipv4)
            .ok_or(OwnedRouteError::Unknown)
    }

    fn activate_route_domain(&mut self) -> Result<(), RouteMutationError> {
        Self::mutate_route_domain(RuleMutation::Add)
    }

    fn deactivate_route_domain(&mut self) -> Result<(), RouteMutationError> {
        Self::mutate_route_domain(RuleMutation::Delete)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteMutation {
    Add,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleMutation {
    Add,
    Delete,
}

impl RuleMutation {
    const fn verb(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Delete => "del",
        }
    }

    const fn inverse(self) -> Self {
        match self {
            Self::Add => Self::Delete,
            Self::Delete => Self::Add,
        }
    }

    const fn is_add(self) -> bool {
        matches!(self, Self::Add)
    }
}

impl RouteMutation {
    const fn verb(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Delete => "del",
        }
    }
}

fn linux_route_arguments(action: RouteMutation, route: &RouteEntry) -> Vec<String> {
    let mut arguments = vec![
        if route.destination().is_v4() {
            "-4"
        } else {
            "-6"
        }
        .into(),
        "route".into(),
        action.verb().into(),
        route.destination().to_string(),
    ];
    if let Some(gateway) = route.gateway() {
        arguments.extend(["via".into(), gateway.to_string()]);
    }
    arguments.extend(["dev".into(), route.interface().into()]);
    if let Some(metric) = route.metric() {
        arguments.extend(["metric".into(), metric.to_string()]);
    }
    arguments.extend(["proto".into(), VORTIX_ROUTE_PROTOCOL.into()]);
    arguments.extend(["table".into(), VORTIX_ROUTE_TABLE.into()]);
    arguments
}

fn parse_linux_default_gateway(output: &str, destination: Cidr) -> Option<RouteEntry> {
    let mut lines = output.lines().filter(|line| !line.trim().is_empty());
    let tokens = lines.next()?.split_whitespace().collect::<Vec<_>>();
    if lines.next().is_some() || tokens.first() != Some(&"default") || tokens.contains(&"nexthop") {
        return None;
    }
    let gateway = unique_value(&tokens, "via")?.parse::<IpAddr>().ok()?;
    let interface = unique_value(&tokens, "dev")?.to_owned();
    RouteEntry::new(destination, interface, Some(gateway), None).ok()
}

fn linux_bypass_rule_arguments(target: IpAddr, action: RuleMutation) -> Vec<String> {
    let prefix = if target.is_ipv4() { 32 } else { 128 };
    vec![
        if target.is_ipv4() { "-4" } else { "-6" }.into(),
        "rule".into(),
        action.verb().into(),
        "priority".into(),
        VORTIX_BYPASS_RULE_PRIORITY.into(),
        "to".into(),
        format!("{target}/{prefix}"),
        "lookup".into(),
        "main".into(),
        "protocol".into(),
        VORTIX_ROUTE_PROTOCOL.into(),
    ]
}

fn linux_table_rule_arguments(ipv4: bool, action: RuleMutation) -> Vec<String> {
    vec![
        if ipv4 { "-4" } else { "-6" }.into(),
        "rule".into(),
        action.verb().into(),
        "priority".into(),
        VORTIX_TABLE_RULE_PRIORITY.into(),
        "lookup".into(),
        VORTIX_ROUTE_TABLE.into(),
        "protocol".into(),
        VORTIX_ROUTE_PROTOCOL.into(),
    ]
}

const fn map_mutation_error(error: FixedCommandError) -> RouteMutationError {
    match error {
        FixedCommandError::FailedBeforeSpawn => RouteMutationError::FailedBeforeEffect,
        FixedCommandError::OutcomeUnknown => RouteMutationError::EffectMayHaveApplied,
    }
}

fn parse_exact_route_interfaces(output: &str, destination: &str) -> Option<Vec<String>> {
    let default = destination.ends_with("/0");
    let mut interfaces = Vec::new();
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        let first = *tokens.first()?;
        let route_destination = if matches!(
            first,
            "unicast"
                | "local"
                | "broadcast"
                | "multicast"
                | "throw"
                | "unreachable"
                | "prohibit"
                | "blackhole"
                | "nat"
                | "anycast"
        ) {
            *tokens.get(1)?
        } else {
            first
        };
        if route_destination != destination && !(default && route_destination == "default") {
            return None;
        }
        let Some(index) = tokens.iter().position(|token| *token == "dev") else {
            continue;
        };
        let interface = (*tokens.get(index + 1)?).to_string();
        if !interfaces.contains(&interface) {
            interfaces.push(interface);
        }
    }
    Some(interfaces)
}

fn parse_exact_route_entries_batch(
    output: &str,
    destinations: &[Cidr],
) -> Option<HashMap<Cidr, Vec<RouteEntry>>> {
    let mut routes = destinations
        .iter()
        .copied()
        .map(|destination| (destination, Vec::new()))
        .collect::<HashMap<_, _>>();
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        let route_kind = *tokens.first()?;
        let offset = usize::from(route_kind == "unicast");
        let destination =
            parse_linux_route_destination(tokens.get(offset)?, destinations[0].is_v4())?;
        let Some(destination_routes) = routes.get_mut(&destination) else {
            continue;
        };
        if tokens.contains(&"nexthop")
            || (offset == 0
                && matches!(
                    route_kind,
                    "local"
                        | "broadcast"
                        | "multicast"
                        | "throw"
                        | "unreachable"
                        | "prohibit"
                        | "blackhole"
                        | "nat"
                        | "anycast"
                ))
        {
            return None;
        }
        if unique_value(&tokens, "proto")? != VORTIX_ROUTE_PROTOCOL {
            return None;
        }
        let interface = unique_value(&tokens, "dev")?.to_owned();
        let gateway = optional_unique_value(&tokens, "via")
            .ok()?
            .map(str::parse::<IpAddr>)
            .transpose()
            .ok()?;
        let metric = optional_unique_value(&tokens, "metric")
            .ok()?
            .map(str::parse::<u32>)
            .transpose()
            .ok()?;
        destination_routes.push(RouteEntry::new(destination, interface, gateway, metric).ok()?);
    }
    Some(routes)
}

fn parse_linux_route_destination(token: &str, ipv4: bool) -> Option<Cidr> {
    if token == "default" {
        return if ipv4 {
            "0.0.0.0/0".parse().ok()
        } else {
            "::/0".parse().ok()
        };
    }
    if token.contains('/') {
        return token.parse::<Cidr>().ok().map(Cidr::canonical_network);
    }
    let prefix = if ipv4 { 32 } else { 128 };
    format!("{token}/{prefix}").parse().ok()
}

#[derive(Debug, PartialEq, Eq)]
struct LinuxPolicyRules {
    bypass_targets: BTreeSet<IpAddr>,
    domain_active: bool,
}

fn parse_linux_policy_rules(output: &str, ipv4: bool) -> Option<LinuxPolicyRules> {
    let mut bypass_targets = BTreeSet::new();
    let mut domain_active = false;
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        let priority = tokens.first()?.strip_suffix(':')?;
        match priority {
            VORTIX_BYPASS_RULE_PRIORITY => {
                if tokens.len() != 9
                    || tokens[1..4] != ["from", "all", "to"]
                    || tokens[5..] != ["lookup", "main", "proto", VORTIX_ROUTE_PROTOCOL]
                {
                    return None;
                }
                let target = parse_host_rule_target(tokens[4], ipv4)?;
                if !bypass_targets.insert(target) {
                    return None;
                }
            }
            VORTIX_TABLE_RULE_PRIORITY => {
                if domain_active
                    || tokens[1..]
                        != [
                            "from",
                            "all",
                            "lookup",
                            VORTIX_ROUTE_TABLE,
                            "proto",
                            VORTIX_ROUTE_PROTOCOL,
                        ]
                {
                    return None;
                }
                domain_active = true;
            }
            _ => {}
        }
    }
    Some(LinuxPolicyRules {
        bypass_targets,
        domain_active,
    })
}

fn parse_host_rule_target(value: &str, ipv4: bool) -> Option<IpAddr> {
    if let Ok(target) = value.parse::<IpAddr>() {
        return (target.is_ipv4() == ipv4).then_some(target);
    }
    let cidr = value.parse::<Cidr>().ok()?.canonical_network();
    let host_prefix = if ipv4 { 32 } else { 128 };
    (cidr.is_v4() == ipv4 && cidr.prefix_len == host_prefix).then_some(cidr.addr)
}

fn unique_value<'a>(tokens: &'a [&str], key: &str) -> Option<&'a str> {
    let mut values = tokens
        .windows(2)
        .filter_map(|pair| (pair[0] == key).then_some(pair[1]));
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

fn optional_unique_value<'a>(tokens: &'a [&str], key: &str) -> Result<Option<&'a str>, ()> {
    let mut values = tokens
        .windows(2)
        .filter_map(|pair| (pair[0] == key).then_some(pair[1]));
    let value = values.next();
    if values.next().is_some() {
        Err(())
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_linux_routes_without_accepting_other_destinations() {
        assert_eq!(
            parse_exact_route_interfaces(
                "10.0.0.0/8 dev vxabc proto static\n10.0.0.0/8 dev vxdef metric 2\n",
                "10.0.0.0/8"
            ),
            Some(vec!["vxabc".into(), "vxdef".into()])
        );
        assert_eq!(
            parse_exact_route_interfaces("10.0.0.0/9 dev vxabc\n", "10.0.0.0/8"),
            None
        );
    }

    #[test]
    fn parses_default_and_empty_exact_route_results() {
        assert_eq!(
            parse_exact_route_interfaces("default dev vxabc\n", "0.0.0.0/0"),
            Some(vec!["vxabc".into()])
        );
        assert_eq!(
            parse_exact_route_interfaces("", "2001:db8::/32"),
            Some(Vec::new())
        );
    }

    #[test]
    fn parses_exact_linux_route_identity() {
        let destination = "10.0.0.0/8".parse().unwrap();
        assert_eq!(
            parse_exact_route_entries_batch(
                "10.0.0.0/8 via 10.1.0.1 dev vxroute0 proto 196 metric 7\n",
                &[destination],
            ),
            Some(HashMap::from([(
                destination,
                vec![RouteEntry::new(
                    destination,
                    "vxroute0".into(),
                    Some("10.1.0.1".parse().unwrap()),
                    Some(7),
                )
                .unwrap()]
            )]))
        );
        assert!(parse_exact_route_entries_batch(
            "10.0.0.0/8 nexthop via 10.1.0.1 dev vxroute0 nexthop via 10.2.0.1 dev vxroute1\n",
            &[destination],
        )
        .is_none());
        assert!(parse_exact_route_entries_batch(
            "10.0.0.0/8 via 10.1.0.1 dev vxroute0 proto static metric 7\n",
            &[destination],
        )
        .is_none());
        for malformed in [
            "10.0.0.0/8 via invalid dev vxroute0 proto 196 metric 7\n",
            "10.0.0.0/8 via 10.1.0.1 dev vxroute0 proto 196 metric invalid\n",
            "10.0.0.0/8 via 10.1.0.1 via 10.2.0.1 dev vxroute0 proto 196\n",
            "10.0.0.0/8 dev vxroute0 proto 196 metric 7 metric 8\n",
        ] {
            assert!(parse_exact_route_entries_batch(malformed, &[destination]).is_none());
        }
    }

    #[test]
    fn parses_one_linux_snapshot_for_multiple_exact_destinations() {
        let first = "10.0.0.0/8".parse().unwrap();
        let second = "192.168.0.0/16".parse().unwrap();
        let parsed = parse_exact_route_entries_batch(
            "default via 192.0.2.1 dev en0\n10.0.0.0/8 dev vx0 proto 196\n192.168.0.0/16 via 192.168.1.1 dev vx1 proto 196 metric 4\n",
            &[first, second],
        )
        .unwrap();
        assert_eq!(parsed[&first][0].interface(), "vx0");
        assert_eq!(parsed[&second][0].interface(), "vx1");
    }

    #[test]
    fn renders_fixed_linux_route_mutation_vocabulary() {
        assert_eq!(LinuxOwnedRoutes.backend(), OwnedRouteBackend::LinuxPolicyV1);
        let route = RouteEntry::new(
            "2001:db8::/32".parse().unwrap(),
            "vxroute0".into(),
            Some("2001:db8::1".parse().unwrap()),
            Some(9),
        )
        .unwrap();
        assert_eq!(
            linux_route_arguments(RouteMutation::Add, &route),
            [
                "-6",
                "route",
                "add",
                "2001:db8::/32",
                "via",
                "2001:db8::1",
                "dev",
                "vxroute0",
                "metric",
                "9",
                "proto",
                "196",
                "table",
                "196",
            ]
        );
    }

    #[test]
    fn resolves_one_exact_linux_main_default_gateway() {
        let destination = "10.20.0.0/16".parse().unwrap();
        assert_eq!(
            parse_linux_default_gateway(
                "default via 192.0.2.1 dev en0 proto dhcp metric 600\n",
                destination,
            ),
            Some(
                RouteEntry::new(
                    destination,
                    "en0".into(),
                    Some("192.0.2.1".parse().unwrap()),
                    None,
                )
                .unwrap()
            )
        );
        assert!(parse_linux_default_gateway(
            "default via 192.0.2.1 dev en0\ndefault via 198.51.100.1 dev en1\n",
            destination,
        )
        .is_none());
        assert!(parse_linux_default_gateway(
            "default nexthop via 192.0.2.1 dev en0 nexthop via 198.51.100.1 dev en1\n",
            destination,
        )
        .is_none());
    }

    #[test]
    fn renders_fixed_linux_policy_rule_vocabulary() {
        assert_eq!(
            linux_bypass_rule_arguments("198.51.100.7".parse().unwrap(), RuleMutation::Add),
            [
                "-4",
                "rule",
                "add",
                "priority",
                "19599",
                "to",
                "198.51.100.7/32",
                "lookup",
                "main",
                "protocol",
                "196",
            ]
        );
        assert_eq!(
            linux_table_rule_arguments(false, RuleMutation::Delete),
            ["-6", "rule", "del", "priority", "19600", "lookup", "196", "protocol", "196",]
        );
    }

    #[test]
    fn parses_only_the_exact_owned_linux_policy_rules() {
        assert_eq!(
            parse_linux_policy_rules(
                "0: from all lookup local\n19599: from all to 198.51.100.7 lookup main proto 196\n19600: from all lookup 196 proto 196\n32766: from all lookup main\n",
                true,
            ),
            Some(LinuxPolicyRules {
                bypass_targets: BTreeSet::from(["198.51.100.7".parse().unwrap()]),
                domain_active: true,
            })
        );
        assert_eq!(
            parse_linux_policy_rules(
                "19599: from all to 2001:db8::7/128 lookup main proto 196\n",
                false,
            ),
            Some(LinuxPolicyRules {
                bypass_targets: BTreeSet::from(["2001:db8::7".parse().unwrap()]),
                domain_active: false,
            })
        );
        assert!(parse_linux_policy_rules(
            "19599: from all to 198.51.100.7 lookup main proto static\n",
            true,
        )
        .is_none());
        assert!(
            parse_linux_policy_rules("19600: from all lookup 197 proto 196\n", true,).is_none()
        );
        assert!(parse_linux_policy_rules(
            "19599: from all to 198.51.100.0/24 lookup main proto 196\n",
            true,
        )
        .is_none());
    }
}
