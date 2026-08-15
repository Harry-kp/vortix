//! Fixed-vocabulary macOS route-selection read-back for the root helper.

use std::net::IpAddr;

use crate::platform::fixed_root_command;
use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::ports::owned_routes::{
    canonical_route_destination, OwnedRouteError, OwnedRoutes,
};

const ROUTE_CANDIDATES: &[&str] = &["/sbin/route", "/usr/sbin/route"];
const NETSTAT_CANDIDATES: &[&str] = &["/usr/sbin/netstat", "/usr/bin/netstat"];

pub(crate) struct MacOsOwnedRoutes;

impl OwnedRoutes for MacOsOwnedRoutes {
    fn route_interface_for(&mut self, target: IpAddr) -> Result<String, OwnedRouteError> {
        let target = target.to_string();
        let output =
            fixed_root_command::run(ROUTE_CANDIDATES, &["-n", "get", target.as_str()], None, 0)
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

#[cfg(test)]
mod tests {
    use super::parse_exact_route_interfaces;

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
}
