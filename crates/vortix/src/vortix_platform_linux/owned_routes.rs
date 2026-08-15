//! Fixed-vocabulary Linux route-selection read-back for the root helper.

use std::net::IpAddr;

use crate::platform::fixed_root_command;
use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::ports::owned_routes::{
    canonical_route_destination, OwnedRouteError, OwnedRoutes,
};

const IP_CANDIDATES: &[&str] = &["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"];

pub(crate) struct LinuxOwnedRoutes;

impl OwnedRoutes for LinuxOwnedRoutes {
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

#[cfg(test)]
mod tests {
    use super::parse_exact_route_interfaces;

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
}
