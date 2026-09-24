//! macOS routing-table inspection via `route -n get 8.8.8.8`.
//!
//! Why a specific target instead of `default`: `OpenVPN`'s standard
//! `push "redirect-gateway def1"` does NOT replace the kernel's default
//! route. Instead it inserts two more-specific /1 routes (0.0.0.0/1 and
//! 128.0.0.0/1) that together cover all of IPv4 and out-prioritise the
//! original default. `route get default` reports the kernel's default-
//! route slot — which `def1` deliberately leaves on the original
//! interface (`en0`) — even though actual internet-bound packets flow
//! through `utun*`. Querying a public-internet target makes the kernel
//! actually do the longest-prefix match it would do for a real packet,
//! returning the interface that owns internet egress (the /1 routes win
//! when the VPN is up; the default wins when it's not).
//!
//! Hardcoded target choice (8.8.8.8, Google DNS): any well-known public
//! IP in 0.0.0.0/1 works. Users with a static-route exception for
//! 8.8.8.8 specifically (DNS-leak-prevention setups) will see this
//! probe return their physical interface even while the VPN is up; that
//! case is rare enough to accept as a known limitation.

use std::net::IpAddr;
use std::time::Duration;

use crate::platform::route_probe::{ProbeOutcome, RouteProbe};
use crate::platform::DefaultRouteObservation;
use crate::process::CommandSpec;

/// Upper bound on the `route get default` subprocess. The query goes
/// through the kernel's routing socket (`rtmsg`), which can take many
/// seconds when the route table is mid-transition — e.g., right after a
/// new VPN tunnel claims the default route. Without this cap, an
/// uncapped query freezes the entire `rtmsg` retry budget (30s on
/// macOS).
const ROUTE_QUERY_TIMEOUT: Duration = Duration::from_secs(1);

/// Process-wide backoff for the route-default probe. Without this,
/// the scanner thread and network-monitor thread each call this
/// subprocess every 1-2 seconds; on a broken VPN both hit the 1s
/// timeout, burning two tokio runtime workers continuously even though
/// neither call yields useful data. Backoff reduces background churn
/// and prevents the scanner's per-tick budget from being eaten by
/// hopeless probes, which is what makes the UI feel stuttery (the
/// scanner ticks at 1Hz so state updates land slow).
static ROUTE_PROBE: RouteProbe = RouteProbe::new();

/// macOS routing-table reader using `route -n get <target>`.
pub struct MacRouteTable;

impl MacRouteTable {
    /// The physical default gateway for one address family; an IPv6 one
    /// keeps its zone (`fe80::1%en0`).
    #[must_use]
    pub fn default_gateway(v4: bool) -> Option<String> {
        // Read the literal default (/0) row, NOT `route get default`. That query
        // resolves the destination 0.0.0.0, which longest-prefix-matches our own
        // `0.0.0.0/1 -> utunN` once it is installed — so it answers with the
        // tunnel's link (`index: N utunN`) instead of the physical gateway, and
        // the VPN-server escape route built from it then points into the very
        // tunnel it exists to bypass. The /0 slot is what `def1` deliberately
        // leaves on the physical link, so it is the reliable source here.
        match ROUTE_PROBE.run(
            // xtask:allow-shell-regression: `netstat -rn` is the supported macOS read of the literal default-route slot; `route get` cannot express "the /0 entry".
            CommandSpec::oneshot(
                "netstat",
                vec![
                    "-rn".into(),
                    "-f".into(),
                    if v4 { "inet" } else { "inet6" }.into(),
                ],
            )
            .timeout(ROUTE_QUERY_TIMEOUT)
            .output_limit(256 * 1024),
        ) {
            ProbeOutcome::Success(stdout) => {
                let gateway = parse_default_slot_gateway(&stdout);
                if gateway.is_none() {
                    let default_rows = stdout
                        .lines()
                        .filter(|line| line.starts_with("default"))
                        .collect::<Vec<_>>();
                    tracing::warn!(
                        target: "vortix::macos::route_table",
                        ?default_rows,
                        "no IP gateway on the default (/0) row"
                    );
                }
                gateway
            }
            ProbeOutcome::BackedOff => None,
            ProbeOutcome::Failed {
                consecutive_failures,
                cooldown,
            } => {
                if consecutive_failures == 1 || cooldown >= Duration::from_secs(5) {
                    tracing::warn!(
                        target: "vortix::macos::route_table",
                        consecutive_fails = consecutive_failures,
                        cooldown_secs = cooldown.as_secs(),
                        "default-route slot read failed; backing off to spare the tokio runtime"
                    );
                }
                None
            }
        }
    }

    #[must_use]
    pub fn default_route_observation() -> DefaultRouteObservation {
        Self::route_interface_for(crate::platform::INTERNET_ROUTE_PROBE)
    }

    pub fn bind_route(cidr: &str, interface: &str) -> Result<(), String> {
        if add_or_change(|verb| bind_route_args(verb, cidr, interface)) {
            Ok(())
        } else {
            Err(format!("route {cidr} could not be bound to {interface}"))
        }
    }

    pub fn bind_host_route(destination: IpAddr, gateway: &str) -> Result<(), String> {
        let ran = add_or_change(|verb| bind_host_route_args(verb, destination, gateway));
        if ran
            && selected_gateway(destination)
                .is_some_and(|selected| same_gateway(&selected, gateway))
        {
            Ok(())
        } else {
            Err(format!(
                "host route for {destination} via {gateway} could not be installed"
            ))
        }
    }

    pub fn unbind_route(cidr: &str, interface: &str) -> Result<(), String> {
        run_route_delete(unbind_route_args(cidr, interface), &format!("route {cidr}"))
    }

    pub fn unbind_host_route(destination: IpAddr) -> Result<(), String> {
        run_route_delete(
            unbind_host_route_args(destination),
            &format!("host route for {destination}"),
        )
    }

    #[must_use]
    pub fn route_interface_for(target: IpAddr) -> DefaultRouteObservation {
        let Some(text) = route_get(target) else {
            return DefaultRouteObservation::ProbeFailed;
        };
        parse_interface(&text).map_or(
            DefaultRouteObservation::NoDefaultRoute,
            DefaultRouteObservation::Interface,
        )
    }
}

/// `add` the route; `change` it only when `add` reports that exact route already
/// exists. Never `change` first: on a missing route, `route change` rewrites
/// whatever it longest-prefix-matches — for `0.0.0.0/1` that is the default
/// route itself, which hijacked the physical default onto the tunnel and left
/// no default at all once the tunnel went away.
fn add_or_change(args: impl Fn(&str) -> Vec<String>) -> bool {
    let run = |verb| {
        crate::process::run(
            CommandSpec::oneshot("route", args(verb))
                .timeout(ROUTE_QUERY_TIMEOUT)
                .output_limit(64 * 1024),
        )
    };
    match run("add") {
        Ok(output) if String::from_utf8_lossy(&output.stderr).contains("File exists") => {
            run("change").is_ok_and(|output| output.success())
        }
        Ok(output) => output.success(),
        Err(_) => false,
    }
}

fn run_route_delete(args: Vec<String>, description: &str) -> Result<(), String> {
    let spec = CommandSpec::oneshot("route", args)
        .timeout(ROUTE_QUERY_TIMEOUT)
        .output_limit(64 * 1024);
    let output =
        crate::process::run(spec).map_err(|_| format!("{description} could not be removed"))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.success() || stderr.contains("not in table") {
        Ok(())
    } else {
        Err(format!("{description} could not be removed"))
    }
}

/// `route get <target>` output, or `None` when the query fails.
fn route_get(target: IpAddr) -> Option<String> {
    let spec = CommandSpec::oneshot("route", route_get_args(target))
        .timeout(ROUTE_QUERY_TIMEOUT)
        .output_limit(64 * 1024);
    let output = crate::process::run(spec).ok()?;
    output
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn selected_gateway(target: IpAddr) -> Option<String> {
    parse_gateway(&route_get(target)?)
}

pub(crate) fn route_get_args(target: IpAddr) -> Vec<String> {
    let family = if target.is_ipv4() { "-inet" } else { "-inet6" };
    vec!["-n".into(), "get".into(), family.into(), target.to_string()]
}

/// Argv for `route -n <verb> -net <cidr> -interface <iface>`: an
/// interface-scoped route that binds to the named utun regardless of gateway.
pub(crate) fn bind_route_args(verb: &str, cidr: &str, interface: &str) -> Vec<String> {
    let mut args = vec!["-n".into(), verb.into()];
    // `route` does not infer IPv6 from the address; it answers "bad address".
    if cidr.contains(':') {
        args.push("-inet6".into());
    }
    args.extend([
        "-net".into(),
        cidr.into(),
        "-interface".into(),
        interface.into(),
    ]);
    args
}

pub(crate) fn bind_host_route_args(verb: &str, destination: IpAddr, gateway: &str) -> Vec<String> {
    vec![
        "-n".into(),
        verb.into(),
        if destination.is_ipv4() {
            "-inet"
        } else {
            "-inet6"
        }
        .into(),
        "-host".into(),
        destination.to_string(),
        gateway.into(),
    ]
}

pub(crate) fn unbind_route_args(cidr: &str, interface: &str) -> Vec<String> {
    bind_route_args("delete", cidr, interface)
}

pub(crate) fn unbind_host_route_args(destination: IpAddr) -> Vec<String> {
    vec![
        "-n".into(),
        "delete".into(),
        if destination.is_ipv4() {
            "-inet"
        } else {
            "-inet6"
        }
        .into(),
        "-host".into(),
        destination.to_string(),
    ]
}

/// Gateway of the literal `default` (/0) row in `netstat -rn` output.
///
/// Only a real IP on a physical interface counts: an interface-scoped route
/// renders its gateway as a link (`index: 20 utun4`), and macOS lists its own
/// utun tunnels as IPv6 defaults. An IPv6 gateway keeps its `%zone`.
pub(crate) fn parse_default_slot_gateway(text: &str) -> Option<String> {
    text.lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let (destination, gateway) = (*fields.first()?, *fields.get(1)?);
            let on_tunnel = fields.get(3).is_some_and(|netif| netif.starts_with("utun"));
            (destination == "default" && !on_tunnel).then_some(gateway)
        })
        .find(|gateway| address_part(gateway).parse::<IpAddr>().is_ok())
        .map(ToOwned::to_owned)
}

fn address_part(gateway: &str) -> &str {
    gateway.split('%').next().unwrap_or(gateway)
}

/// `route get` may print a link-local gateway with or without its zone.
fn same_gateway(selected: &str, gateway: &str) -> bool {
    address_part(selected) == address_part(gateway)
}

/// Extract the `gateway:` line from `route get <target>` output.
fn parse_gateway(text: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(gw) = trimmed.strip_prefix("gateway:") {
            let gw = gw.trim();
            if !gw.is_empty() {
                return Some(gw.to_string());
            }
        }
    }
    None
}

/// Extract the `interface:` line from `route get default` output.
///
/// macOS formats the line as `   interface: en0` (leading whitespace
/// varies). We trim and look for the `interface:` prefix, then take the
/// first whitespace-delimited token as the interface name. Returns `None`
/// if no such line exists or the name is empty.
pub(crate) fn parse_interface(text: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("interface:") {
            let name = rest.split_whitespace().next()?;
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_WIFI: &str = "\
   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
";

    const SAMPLE_VPN: &str = "\
   route to: default
destination: default
    gateway: 10.0.0.1
  interface: utun3
      flags: <UP,GATEWAY,DONE,STATIC>
";

    #[test]
    fn parse_interface_extracts_en0_on_wifi() {
        assert_eq!(parse_interface(SAMPLE_WIFI), Some("en0".into()));
    }

    #[test]
    fn parse_interface_extracts_utun3_on_vpn() {
        assert_eq!(parse_interface(SAMPLE_VPN), Some("utun3".into()));
    }

    #[test]
    fn parse_interface_returns_none_when_no_interface_line() {
        let text = "   route to: default\n    gateway: 192.168.1.1\n";
        assert_eq!(parse_interface(text), None);
    }

    #[test]
    fn parse_interface_returns_none_on_empty_input() {
        assert_eq!(parse_interface(""), None);
    }

    #[test]
    fn parse_interface_ignores_empty_name() {
        let text = "  interface:   \n";
        assert_eq!(parse_interface(text), None);
    }

    #[test]
    fn parse_interface_tolerates_macos14_style_extra_whitespace() {
        // Defensive: any reasonable amount of whitespace before/after the
        // colon and around the name should still match.
        let text = "    interface:\t  en5  \n";
        assert_eq!(parse_interface(text), Some("en5".into()));
    }

    #[test]
    fn physical_gateway_comes_from_the_default_slot_not_our_own_half_route() {
        // `route get default` resolves 0.0.0.0, which longest-prefix-matches the
        // `0.0.0.0/1 -> utunN` we install ourselves and answers with the tunnel's
        // link — the escape route built from that points into the tunnel it is
        // meant to bypass. Reading the literal default row keeps the physical gw.
        let netstat = "\
Destination        Gateway            Flags               Netif Expire
0/1                utun4              UScg                utun4
default            192.168.1.1        UGScg                 en0
128.0/1            utun4              USc                 utun4
";
        assert_eq!(
            parse_default_slot_gateway(netstat),
            Some("192.168.1.1".to_owned())
        );
    }

    /// `route` does not infer the family from an IPv6 `-net`: without
    /// `-inet6` it answers "bad address", so every IPv6 default half failed.
    #[test]
    fn ipv6_routes_name_their_family() {
        assert_eq!(
            bind_route_args("add", "::/1", "utun4"),
            ["-n", "add", "-inet6", "-net", "::/1", "-interface", "utun4"]
        );
        assert_eq!(
            unbind_route_args("8000::/1", "utun4"),
            [
                "-n",
                "delete",
                "-inet6",
                "-net",
                "8000::/1",
                "-interface",
                "utun4"
            ]
        );
        assert_eq!(
            bind_route_args("add", "0.0.0.0/1", "utun4"),
            ["-n", "add", "-net", "0.0.0.0/1", "-interface", "utun4"]
        );
    }

    /// macOS lists Apple's own utun tunnels as IPv6 defaults; only a row on
    /// a physical interface is the escape gateway, zone included.
    #[test]
    fn the_ipv6_physical_gateway_keeps_its_zone_and_skips_tunnels() {
        let netstat = "\
Destination                             Gateway                                 Flags               Netif Expire
default                                 fe80::%utun0                            UGcIg               utun0
default                                 fe80::1%en0                             UGcg                  en0
";
        assert_eq!(
            parse_default_slot_gateway(netstat),
            Some("fe80::1%en0".to_owned())
        );
        assert_eq!(
            parse_default_slot_gateway(
                "default   fe80::%utun0   UGcIg   utun0\ndefault   fe80::%utun1   UGcIg   utun1\n"
            ),
            None
        );
    }

    #[test]
    fn a_link_gateway_is_never_reported_as_the_physical_gateway() {
        // An interface-scoped default renders its gateway as a link, which is
        // not routable as an escape-route gateway.
        assert_eq!(
            parse_default_slot_gateway("default            utun4              UGScg    utun4\n"),
            None
        );
    }

    #[test]
    fn parse_gateway_still_works_on_sample() {
        assert_eq!(parse_gateway(SAMPLE_WIFI), Some("192.168.1.1".into()));
        assert_eq!(parse_gateway(SAMPLE_VPN), Some("10.0.0.1".into()));
    }

    #[test]
    fn route_lookup_selects_the_explicit_address_family() {
        assert_eq!(
            route_get_args("1.1.1.1".parse().unwrap()),
            ["-n", "get", "-inet", "1.1.1.1"]
        );
        assert_eq!(
            route_get_args("2606:4700:4700::1111".parse().unwrap()),
            ["-n", "get", "-inet6", "2606:4700:4700::1111"]
        );
    }

    #[test]
    fn bind_route_is_interface_scoped_not_gateway_scoped() {
        // `-interface utunN` (not a gateway) is the whole point: it binds the
        // route to the named tunnel regardless of how a gateway would resolve.
        assert_eq!(
            bind_route_args("change", "10.250.0.0/24", "utun5"),
            [
                "-n",
                "change",
                "-net",
                "10.250.0.0/24",
                "-interface",
                "utun5"
            ]
        );
    }

    #[test]
    fn host_route_keeps_the_openvpn_server_on_the_physical_gateway() {
        assert_eq!(
            bind_host_route_args("change", "198.51.100.7".parse().unwrap(), "192.168.1.1"),
            [
                "-n",
                "change",
                "-inet",
                "-host",
                "198.51.100.7",
                "192.168.1.1"
            ]
        );
    }

    #[test]
    fn teardown_deletes_only_the_owned_route_shapes() {
        assert_eq!(
            unbind_route_args("0.0.0.0/1", "utun5"),
            ["-n", "delete", "-net", "0.0.0.0/1", "-interface", "utun5"]
        );
        assert_eq!(
            unbind_host_route_args("198.51.100.7".parse().unwrap()),
            ["-n", "delete", "-inet", "-host", "198.51.100.7"]
        );
    }
}
