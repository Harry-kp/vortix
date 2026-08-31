//! Fixed-vocabulary macOS route-selection read-back for the root helper.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::platform::fixed_root_command::{self, FixedCommandError};
use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::ports::owned_routes::{
    canonical_route_destination, OwnedRouteBackend, OwnedRouteError, OwnedRoutes, RouteEntry,
    RouteMutationError,
};

const ROUTE_CANDIDATES: &[&str] = &["/sbin/route", "/usr/sbin/route"];
const NETSTAT_CANDIDATES: &[&str] = &["/usr/sbin/netstat", "/usr/bin/netstat"];

pub(crate) struct MacOsOwnedRoutes;

impl MacOsOwnedRoutes {
    fn mutate(route: &RouteEntry, action: RouteMutation) -> Result<(), RouteMutationError> {
        let arguments = macos_route_arguments(action, route)?;
        let borrowed = arguments.iter().map(String::as_str).collect::<Vec<_>>();
        let output = fixed_root_command::run(ROUTE_CANDIDATES, &borrowed, None, 0)
            .map_err(map_mutation_error)?;
        if output.status.success() {
            Ok(())
        } else {
            Err(RouteMutationError::FailedBeforeEffect)
        }
    }
}

impl OwnedRoutes for MacOsOwnedRoutes {
    fn backend(&self) -> OwnedRouteBackend {
        OwnedRouteBackend::MacOsScopedV1
    }

    fn route_interface_for(&mut self, target: IpAddr) -> Result<String, OwnedRouteError> {
        let arguments = super::route_table::route_get_args(target);
        let borrowed = arguments.iter().map(String::as_str).collect::<Vec<_>>();
        let output = fixed_root_command::run(ROUTE_CANDIDATES, &borrowed, None, 0)
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
        let family = if destination.is_v4() { "inet" } else { "inet6" };
        let output = fixed_root_command::run(NETSTAT_CANDIDATES, &["-rn", "-f", family], None, 0)
            .map_err(|_| OwnedRouteError::Unknown)?;
        if !output.status.success() {
            return Err(OwnedRouteError::Unknown);
        }
        parse_exact_route_interfaces(&output.stdout, destination).ok_or(OwnedRouteError::Unknown)
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
        let mut results = vec![None; destinations.len()];
        for (ipv4, family) in [(true, "inet"), (false, "inet6")] {
            let indexes = destinations
                .iter()
                .enumerate()
                .filter_map(|(index, destination)| (destination.is_v4() == ipv4).then_some(index))
                .collect::<Vec<_>>();
            if indexes.is_empty() {
                continue;
            }
            let output =
                fixed_root_command::run(NETSTAT_CANDIDATES, &["-rn", "-f", family], None, 0)
                    .map_err(|_| OwnedRouteError::Unknown)?;
            if !output.status.success() {
                return Err(OwnedRouteError::Unknown);
            }
            let requested = indexes
                .iter()
                .map(|index| destinations[*index])
                .collect::<Vec<_>>();
            let mut parsed = parse_exact_route_entries_batch(&output.stdout, &requested, ipv4)
                .ok_or(OwnedRouteError::Unknown)?;
            for index in indexes {
                results[index] = Some(
                    parsed
                        .remove(&canonical_route_destination(destinations[index]))
                        .ok_or(OwnedRouteError::Unknown)?,
                );
            }
        }
        results
            .into_iter()
            .map(|result| result.ok_or(OwnedRouteError::Unknown))
            .collect()
    }

    fn add_route(&mut self, route: &RouteEntry) -> Result<(), RouteMutationError> {
        Self::mutate(route, RouteMutation::Add)
    }

    fn remove_route(&mut self, route: &RouteEntry) -> Result<(), RouteMutationError> {
        Self::mutate(route, RouteMutation::Delete)
    }

    fn resolve_transport_bypass(&mut self, target: IpAddr) -> Result<RouteEntry, OwnedRouteError> {
        let arguments = super::route_table::route_get_args(target);
        let borrowed = arguments.iter().map(String::as_str).collect::<Vec<_>>();
        let output = fixed_root_command::run(ROUTE_CANDIDATES, &borrowed, None, 0)
            .map_err(|_| OwnedRouteError::Unknown)?;
        if !output.status.success() {
            return Err(OwnedRouteError::Unknown);
        }
        parse_route_get_bypass(&output.stdout, target).ok_or(OwnedRouteError::Unknown)
    }

    fn resolve_net_gateway(&mut self, destination: Cidr) -> Result<RouteEntry, OwnedRouteError> {
        let family = if destination.is_v4() {
            "-inet"
        } else {
            "-inet6"
        };
        let output =
            fixed_root_command::run(ROUTE_CANDIDATES, &["-n", "get", family, "default"], None, 0)
                .map_err(|_| OwnedRouteError::Unknown)?;
        if !output.status.success() {
            return Err(OwnedRouteError::Unknown);
        }
        parse_route_get_gateway(&output.stdout, destination).ok_or(OwnedRouteError::Unknown)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteMutation {
    Add,
    Delete,
}

impl RouteMutation {
    const fn verb(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Delete => "delete",
        }
    }
}

fn macos_route_arguments(
    action: RouteMutation,
    route: &RouteEntry,
) -> Result<Vec<String>, RouteMutationError> {
    if route.metric().is_some() {
        return Err(RouteMutationError::FailedBeforeEffect);
    }
    let mut arguments = vec![
        "-n".into(),
        action.verb().into(),
        if route.destination().is_v4() {
            "-inet"
        } else {
            "-inet6"
        }
        .into(),
        "-net".into(),
        "-proto2".into(),
    ];
    if let Some(gateway) = route.gateway() {
        arguments.extend([
            "-ifscope".into(),
            route.interface().into(),
            route.destination().to_string(),
            gateway.to_string(),
        ]);
    } else {
        arguments.extend([
            "-interface".into(),
            route.destination().to_string(),
            route.interface().into(),
        ]);
    }
    Ok(arguments)
}

const fn map_mutation_error(error: FixedCommandError) -> RouteMutationError {
    match error {
        FixedCommandError::FailedBeforeSpawn => RouteMutationError::FailedBeforeEffect,
        FixedCommandError::OutcomeUnknown => RouteMutationError::EffectMayHaveApplied,
    }
}

fn parse_exact_route_interfaces(output: &str, destination: Cidr) -> Option<Vec<String>> {
    let destination = canonical_route_destination(destination);
    let mut netif_column = None;
    let mut interfaces = Vec::new();
    for line in output.lines() {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if tokens.first() == Some(&"Destination") {
            netif_column = tokens.iter().position(|token| *token == "Netif");
            continue;
        }
        let Some(netif_column) = netif_column else {
            continue;
        };
        let Some(route_destination) = tokens
            .first()
            .and_then(|token| parse_netstat_destination(token, destination.is_v4()))
        else {
            continue;
        };
        if canonical_route_destination(route_destination) != destination {
            continue;
        }
        let interface = (*tokens.get(netif_column)?).to_string();
        if !interfaces.contains(&interface) {
            interfaces.push(interface);
        }
    }
    netif_column.map(|_| interfaces)
}

fn parse_exact_route_entries_batch(
    output: &str,
    destinations: &[Cidr],
    ipv4: bool,
) -> Option<HashMap<Cidr, Vec<RouteEntry>>> {
    let mut routes = destinations
        .iter()
        .copied()
        .map(canonical_route_destination)
        .map(|destination| (destination, Vec::new()))
        .collect::<HashMap<_, _>>();
    let mut gateway_column = None;
    let mut flags_column = None;
    let mut netif_column = None;
    for line in output.lines() {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if tokens.first() == Some(&"Destination") {
            gateway_column = tokens.iter().position(|token| *token == "Gateway");
            flags_column = tokens.iter().position(|token| *token == "Flags");
            netif_column = tokens.iter().position(|token| *token == "Netif");
            continue;
        }
        let (Some(gateway_column), Some(flags_column), Some(netif_column)) =
            (gateway_column, flags_column, netif_column)
        else {
            continue;
        };
        let Some(route_destination) = tokens
            .first()
            .and_then(|token| parse_netstat_destination(token, ipv4))
        else {
            continue;
        };
        let destination = canonical_route_destination(route_destination);
        let Some(destination_routes) = routes.get_mut(&destination) else {
            continue;
        };
        if !tokens.get(flags_column)?.contains('2') {
            continue;
        }
        let interface = (*tokens.get(netif_column)?).to_owned();
        let gateway_text = *tokens.get(gateway_column)?;
        let gateway = if gateway_text.starts_with("link#") || gateway_text == interface {
            None
        } else {
            Some(gateway_text.split('%').next()?.parse::<IpAddr>().ok()?)
        };
        destination_routes.push(RouteEntry::new(destination, interface, gateway, None).ok()?);
    }
    gateway_column
        .zip(flags_column)
        .zip(netif_column)
        .map(|_| routes)
}

fn parse_netstat_destination(token: &str, ipv4: bool) -> Option<Cidr> {
    if token == "default" {
        return if ipv4 {
            "0.0.0.0/0".parse().ok()
        } else {
            "::/0".parse().ok()
        };
    }
    if !ipv4 {
        let token = token.split('%').next()?;
        return if token.contains('/') {
            token.parse().ok()
        } else {
            format!("{token}/128").parse().ok()
        };
    }
    let (address, prefix) = token
        .split_once('/')
        .map_or((token, None), |(address, prefix)| {
            (address, prefix.parse::<u8>().ok())
        });
    let components = address.split('.').collect::<Vec<_>>();
    if components.is_empty() || components.len() > 4 {
        return None;
    }
    let mut octets = [0_u8; 4];
    for (index, component) in components.iter().enumerate() {
        octets[index] = component.parse().ok()?;
    }
    let prefix = prefix.unwrap_or(u8::try_from(components.len() * 8).ok()?);
    Cidr::new(std::net::Ipv4Addr::from(octets).into(), prefix)
}

fn parse_route_get_bypass(output: &str, target: IpAddr) -> Option<RouteEntry> {
    if output.lines().any(|line| {
        line.trim_start()
            .strip_prefix("flags:")
            .is_some_and(|flags| {
                flags
                    .split([',', '<', '>'])
                    .any(|flag| flag.trim() == "PROTO2")
            })
    }) {
        return None;
    }
    let interface = unique_labeled_value(output, "interface:")?.to_owned();
    let gateway = match unique_labeled_value(output, "gateway:") {
        Some(value) if value == interface || value.starts_with("link#") => None,
        Some(value) => Some(value.split('%').next()?.parse::<IpAddr>().ok()?),
        None => None,
    };
    let prefix = if target.is_ipv4() { 32 } else { 128 };
    RouteEntry::new(Cidr::new(target, prefix)?, interface, gateway, None).ok()
}

fn parse_route_get_gateway(output: &str, destination: Cidr) -> Option<RouteEntry> {
    if output.lines().any(|line| {
        line.trim_start()
            .strip_prefix("flags:")
            .is_some_and(|flags| {
                flags
                    .split([',', '<', '>'])
                    .any(|flag| flag.trim() == "PROTO2")
            })
    }) {
        return None;
    }
    let interface = unique_labeled_value(output, "interface:")?.to_owned();
    let gateway = unique_labeled_value(output, "gateway:")?
        .split('%')
        .next()?
        .parse::<IpAddr>()
        .ok()?;
    RouteEntry::new(destination, interface, Some(gateway), None).ok()
}

fn unique_labeled_value<'a>(output: &'a str, label: &str) -> Option<&'a str> {
    let mut values = output.lines().filter_map(|line| {
        line.trim_start()
            .strip_prefix(label)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    });
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_macos_ipv4_routes_and_abbreviated_networks() {
        let output = "Routing tables\n\nInternet:\nDestination Gateway Flags Netif Expire\ndefault 192.0.2.1 UGSc en0\n10/8 10.0.0.1 UGSc vxabc\n10.0/16 10.0.0.1 UGSc vxdef\n";
        assert_eq!(
            parse_exact_route_interfaces(output, "10.0.0.0/8".parse().unwrap()),
            Some(vec!["vxabc".into()])
        );
        assert_eq!(
            parse_exact_route_interfaces(output, "0.0.0.0/0".parse().unwrap()),
            Some(vec!["en0".into()])
        );
    }

    #[test]
    fn parses_exact_macos_ipv6_routes_and_empty_tables() {
        let output = "Internet6:\nDestination Gateway Flags Netif Expire\n2001:db8::/32 fe80::1 UGSc vxabc\n";
        assert_eq!(
            parse_exact_route_interfaces(output, "2001:db8::/32".parse().unwrap()),
            Some(vec!["vxabc".into()])
        );
        assert_eq!(
            parse_exact_route_interfaces(
                "Internet:\nDestination Gateway Flags Netif Expire\n",
                "10.0.0.0/8".parse().unwrap()
            ),
            Some(Vec::new())
        );
    }

    #[test]
    fn parses_exact_macos_route_identity() {
        let output = "Internet:\nDestination Gateway Flags Netif Expire\n10/8 10.0.0.1 UGS2c vxroute0\n192.168/16 vxroute1 UC2S vxroute1\n172.16/12 172.16.0.1 UGSc vxforeign\n";
        let first = "10.0.0.0/8".parse().unwrap();
        let second = "192.168.0.0/16".parse().unwrap();
        let routes = parse_exact_route_entries_batch(output, &[first, second], true).unwrap();
        assert_eq!(
            routes[&first],
            vec![RouteEntry::new(
                first,
                "vxroute0".into(),
                Some("10.0.0.1".parse().unwrap()),
                None,
            )
            .unwrap()]
        );
        assert_eq!(
            routes[&second],
            vec![RouteEntry::new(second, "vxroute1".into(), None, None,).unwrap()]
        );
    }

    #[test]
    fn renders_fixed_macos_route_vocabulary_and_rejects_metrics() {
        assert_eq!(MacOsOwnedRoutes.backend(), OwnedRouteBackend::MacOsScopedV1);
        let route = RouteEntry::new(
            "10.0.0.0/8".parse().unwrap(),
            "vxroute0".into(),
            Some("10.0.0.1".parse().unwrap()),
            None,
        )
        .unwrap();
        assert_eq!(
            macos_route_arguments(RouteMutation::Add, &route).unwrap(),
            [
                "-n",
                "add",
                "-inet",
                "-net",
                "-proto2",
                "-ifscope",
                "vxroute0",
                "10.0.0.0/8",
                "10.0.0.1",
            ]
        );
        let with_metric = RouteEntry::new(
            "10.0.0.0/8".parse().unwrap(),
            "vxroute0".into(),
            None,
            Some(1),
        )
        .unwrap();
        assert_eq!(
            macos_route_arguments(RouteMutation::Add, &with_metric),
            Err(RouteMutationError::FailedBeforeEffect)
        );
    }

    #[test]
    fn resolves_a_non_vortix_endpoint_route_to_an_exact_host_entry() {
        let output = "   route to: 198.51.100.7\ndestination: 198.51.100.7\n    gateway: 192.0.2.1\n  interface: en0\n      flags: <UP,GATEWAY,HOST,DONE,STATIC>\n";
        assert_eq!(
            parse_route_get_bypass(output, "198.51.100.7".parse().unwrap()),
            Some(
                RouteEntry::new(
                    "198.51.100.7/32".parse().unwrap(),
                    "en0".into(),
                    Some("192.0.2.1".parse().unwrap()),
                    None,
                )
                .unwrap()
            )
        );
        assert!(parse_route_get_bypass(
            &output.replace("STATIC>", "STATIC,PROTO2>"),
            "198.51.100.7".parse().unwrap(),
        )
        .is_none());
    }

    #[test]
    fn resolves_one_exact_macos_default_gateway() {
        let output = "   route to: default\ndestination: default\n    gateway: 192.0.2.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC>\n";
        let destination = "10.20.0.0/16".parse().unwrap();
        assert_eq!(
            parse_route_get_gateway(output, destination),
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
        assert!(
            parse_route_get_gateway(&output.replace("STATIC>", "STATIC,PROTO2>"), destination,)
                .is_none()
        );
    }
}
