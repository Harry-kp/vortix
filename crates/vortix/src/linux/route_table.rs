//! Linux routing-table inspection via `ip route get 8.8.8.8`.
//!
//! Why a specific target instead of `ip route show default`: `OpenVPN`'s
//! standard `push "redirect-gateway def1"` does NOT replace the
//! kernel's default-route entry; it inserts two more-specific /1 routes
//! (0.0.0.0/1 and 128.0.0.0/1) that out-prioritise the original
//! default. `ip route show default` reports the kernel's default-route
//! slot — which `def1` deliberately leaves on the original interface
//! (`wlan0`/`eth0`/...) — even though actual internet-bound packets
//! flow through `tun0`. Asking `ip route get <internet IP>` makes the
//! kernel do the longest-prefix match it would do for a real packet,
//! returning the interface that actually owns internet egress.
//!
//! See `macos/route_table.rs` for the cross-platform
//! rationale and the choice of 8.8.8.8 as the probe target.

use std::net::IpAddr;
use std::time::Duration;

use crate::platform::route_probe::{ProbeOutcome, RouteProbe};
use crate::platform::DefaultRouteObservation;
use crate::process::CommandSpec;

/// Upper bound on the `ip route show default` subprocess. Netlink is
/// usually instant on Linux, but pathological cases (heavy
/// routing-policy rules, contention during a tunnel transition) can
/// stall the query. 1s is generous for any healthy run.
const ROUTE_QUERY_TIMEOUT: Duration = Duration::from_secs(1);

/// Process-wide backoff for the route-default probe. See the macOS
/// `route_table.rs` for the full rationale; same shape applies here so
/// a broken Linux network state doesn't keep the scanner thread + the
/// network-monitor thread both spinning on a doomed `ip route` call
/// every couple of seconds.
static ROUTE_PROBE: RouteProbe = RouteProbe::new();

/// Linux routing-table reader using `ip route get <target>`.
pub struct LinuxRouteTable;

impl LinuxRouteTable {
    /// The physical default gateway for one address family; an IPv6 one
    /// carries its device (`fe80::1%wlp3s0`).
    #[must_use]
    pub fn default_gateway(v4: bool) -> Option<String> {
        let text = run_ip_route_show_default(v4)?;
        parse_default_gateway(&text)
    }

    pub fn bind_route(cidr: &str, interface: &str) -> Result<(), String> {
        // xtask:allow-shell-regression: `ip route replace ... dev` is the native Linux route mutation interface; the process layer provides bounded execution.
        let spec = CommandSpec::oneshot("ip", bind_route_args(cidr, interface))
            .timeout(ROUTE_QUERY_TIMEOUT)
            .output_limit(64 * 1024);
        match crate::process::run(spec) {
            Ok(output) if output.success() => Ok(()),
            _ => Err(format!("route {cidr} could not be bound to {interface}")),
        }
    }

    pub fn bind_host_route(destination: IpAddr, gateway: &str) -> Result<(), String> {
        // xtask:allow-shell-regression: `ip route replace ... via` is the native Linux route mutation interface; the process layer provides bounded execution.
        let spec = CommandSpec::oneshot("ip", bind_host_route_args(destination, gateway))
            .timeout(ROUTE_QUERY_TIMEOUT)
            .output_limit(64 * 1024);
        match crate::process::run(spec) {
            Ok(output)
                if output.success()
                    && selected_gateway(destination).as_deref() == gateway.split('%').next() =>
            {
                Ok(())
            }
            _ => Err(format!(
                "host route for {destination} via {gateway} could not be installed"
            )),
        }
    }

    pub fn unbind_route(cidr: &str, interface: &str) -> Result<(), String> {
        run_ip_route_delete(unbind_route_args(cidr, interface), &format!("route {cidr}"))
    }

    pub fn unbind_host_route(destination: IpAddr) -> Result<(), String> {
        run_ip_route_delete(
            unbind_host_route_args(destination),
            &format!("host route for {destination}"),
        )
    }

    #[must_use]
    pub fn default_route_observation() -> DefaultRouteObservation {
        Self::route_interface_for(crate::platform::INTERNET_ROUTE_PROBE)
    }

    /// [`Self::route_interface_for`] for each target; `ip route get` is fast
    /// enough here (337 routes connect in 5 s).
    #[must_use]
    pub fn route_interfaces_for(targets: &[IpAddr]) -> Vec<DefaultRouteObservation> {
        targets
            .iter()
            .map(|target| Self::route_interface_for(*target))
            .collect()
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

fn run_ip_route_delete(args: Vec<String>, description: &str) -> Result<(), String> {
    // xtask:allow-shell-regression: `ip route del` is the native Linux route teardown interface; the process layer provides bounded execution.
    let spec = CommandSpec::oneshot("ip", args)
        .timeout(ROUTE_QUERY_TIMEOUT)
        .output_limit(64 * 1024);
    let output =
        crate::process::run(spec).map_err(|_| format!("{description} could not be removed"))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.success() || stderr.contains("No such process") {
        Ok(())
    } else {
        Err(format!("{description} could not be removed"))
    }
}

/// `ip route get <target>` output, or `None` when the query fails.
fn route_get(target: IpAddr) -> Option<String> {
    // xtask:allow-shell-regression: `ip route get <target>` is the supported Linux route-selection proof; no existing libc port exposes policy-routing resolution.
    let spec = CommandSpec::oneshot("ip", vec!["route".into(), "get".into(), target.to_string()])
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

pub(crate) fn bind_route_args(cidr: &str, interface: &str) -> Vec<String> {
    vec![
        "route".into(),
        "replace".into(),
        cidr.into(),
        "dev".into(),
        interface.into(),
    ]
}

pub(crate) fn bind_host_route_args(destination: IpAddr, gateway: &str) -> Vec<String> {
    let mut args = vec![
        "route".into(),
        "replace".into(),
        crate::cidr::Cidr::host(destination).to_string(),
        "via".into(),
    ];
    match gateway.split_once('%') {
        Some((address, device)) => args.extend([address.into(), "dev".into(), device.into()]),
        None => args.push(gateway.into()),
    }
    args
}

pub(crate) fn unbind_route_args(cidr: &str, interface: &str) -> Vec<String> {
    vec![
        "route".into(),
        "del".into(),
        cidr.into(),
        "dev".into(),
        interface.into(),
    ]
}

pub(crate) fn unbind_host_route_args(destination: IpAddr) -> Vec<String> {
    vec![
        "route".into(),
        "del".into(),
        crate::cidr::Cidr::host(destination).to_string(),
    ]
}

/// Read the literal default-route slot. `def1` leaves this on the physical
/// network, which is the gateway needed for VPN server escape routes.
///
/// Returns `None` if the subprocess fails so callers can degrade gracefully.
fn run_ip_route_show_default(v4: bool) -> Option<String> {
    let family = if v4 { "-4" } else { "-6" };
    match ROUTE_PROBE.run(
        // xtask:allow-shell-regression: `ip route show default` is the canonical Linux default-gateway inspection.
        CommandSpec::oneshot(
            "ip",
            vec![
                family.into(),
                "route".into(),
                "show".into(),
                "default".into(),
            ],
        )
        .timeout(ROUTE_QUERY_TIMEOUT),
    ) {
        ProbeOutcome::Success(stdout) => Some(stdout),
        ProbeOutcome::BackedOff => None,
        ProbeOutcome::Failed {
            consecutive_failures,
            cooldown,
        } => {
            if consecutive_failures == 1 || cooldown >= Duration::from_secs(5) {
                tracing::warn!(
                    target: "vortix::linux::route_table",
                    consecutive_fails = consecutive_failures,
                    cooldown_secs = cooldown.as_secs(),
                    "`ip route get` probe failed; backing off to spare the tokio runtime"
                );
            }
            None
        }
    }
}

/// The `via` gateway of a default route; an IPv6 one gets `%<dev>`, since a
/// link-local next hop means nothing without its device.
fn parse_default_gateway(text: &str) -> Option<String> {
    let gateway = parse_gateway(text)?;
    let device = text
        .split_whitespace()
        .skip_while(|token| *token != "dev")
        .nth(1);
    match device {
        Some(device) if gateway.parse::<std::net::Ipv6Addr>().is_ok() => {
            Some(format!("{gateway}%{device}"))
        }
        _ => Some(gateway),
    }
}

/// Extract the gateway IP from any line containing `via <ip>`.
///
/// `ip route get 8.8.8.8` produces lines like
/// `8.8.8.8 via 192.168.1.1 dev wlan0 src ... uid ...` (line starts
/// with the queried IP, not `default`). `ip route show default` would
/// produce `default via 192.168.1.1 dev wlan0 ...`. We accept either
/// shape by scanning all tokens for `via <next>` rather than asserting
/// the line's first token.
fn parse_gateway(text: &str) -> Option<String> {
    for line in text.lines() {
        let mut iter = line.split_whitespace();
        while let Some(tok) = iter.next() {
            if tok == "via" {
                if let Some(gw) = iter.next() {
                    if !gw.is_empty() {
                        return Some(gw.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Extract the interface name from any line containing `dev <name>`.
///
/// Same shape rationale as [`parse_gateway`]: `ip route get <ip>` and
/// `ip route show default` differ in their line prefix but share the
/// `dev <name>` token pair somewhere in the line.
pub(crate) fn parse_interface(text: &str) -> Option<String> {
    for line in text.lines() {
        let mut iter = line.split_whitespace();
        while let Some(tok) = iter.next() {
            if tok == "dev" {
                if let Some(name) = iter.next() {
                    if !name.is_empty() {
                        return Some(name.to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_interface_extracts_wlan0_on_typical_dhcp_output() {
        let text = "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n";
        assert_eq!(parse_interface(text), Some("wlan0".into()));
    }

    #[test]
    fn parse_interface_extracts_utun3_when_vpn_owns_default() {
        let text = "default via 10.0.0.1 dev utun3\n";
        assert_eq!(parse_interface(text), Some("utun3".into()));
    }

    #[test]
    fn parse_interface_extracts_dev_at_unusual_position() {
        // `dev` may appear later than usual on some configurations; the
        // parser must still pick it up.
        let text = "default via 192.168.1.1 proto static metric 100 dev eth0\n";
        assert_eq!(parse_interface(text), Some("eth0".into()));
    }

    #[test]
    fn parse_interface_returns_none_on_empty_input() {
        assert_eq!(parse_interface(""), None);
    }

    #[test]
    fn parse_interface_extracts_dev_from_ip_route_get_output() {
        // `ip route get 8.8.8.8` returns a line that starts with the
        // queried IP, not `default`. The shape-based parser must still
        // pick up `dev <name>`.
        let text = "8.8.8.8 via 192.168.1.1 dev wlan0 src 192.168.1.42 uid 1000\n    cache\n";
        assert_eq!(parse_interface(text), Some("wlan0".into()));
    }

    #[test]
    fn parse_interface_extracts_tun_when_vpn_redirects_via_def1() {
        // When `OpenVPN`'s redirect-gateway def1 is active, the kernel
        // routes 8.8.8.8 through the VPN's /1 routes — `ip route get`
        // returns `dev tun0` even though `ip route show default`
        // would still say `dev wlan0`.
        let text = "8.8.8.8 via 10.9.0.1 dev tun0 src 10.9.0.2 uid 1000\n    cache\n";
        assert_eq!(parse_interface(text), Some("tun0".into()));
    }

    #[test]
    fn parse_interface_returns_none_when_dev_has_no_value() {
        let text = "8.8.8.8 via 192.168.1.1 dev\n";
        assert_eq!(parse_interface(text), None);
    }

    #[test]
    fn parse_gateway_still_works_on_sample() {
        let text = "default via 192.168.1.1 dev wlan0 proto dhcp\n";
        assert_eq!(parse_gateway(text), Some("192.168.1.1".into()));
    }

    #[test]
    fn bind_route_replaces_the_prefix_on_the_tunnel_device() {
        assert_eq!(
            bind_route_args("10.250.0.0/24", "tun5"),
            ["route", "replace", "10.250.0.0/24", "dev", "tun5"]
        );
    }

    #[test]
    fn host_route_keeps_the_openvpn_server_on_the_physical_gateway() {
        assert_eq!(
            bind_host_route_args("198.51.100.7".parse().unwrap(), "192.168.1.1"),
            ["route", "replace", "198.51.100.7/32", "via", "192.168.1.1"]
        );
    }

    /// An IPv6 default gateway is link-local, so the host route needs the
    /// device it lives on.
    #[test]
    fn an_ipv6_server_is_pinned_via_the_link_local_gateway_and_its_device() {
        let gateway =
            parse_default_gateway("default via fe80::1 dev wlp3s0 proto ra metric 600 pref low\n");
        assert_eq!(gateway.as_deref(), Some("fe80::1%wlp3s0"));
        assert_eq!(
            bind_host_route_args("2001:db8::7".parse().unwrap(), "fe80::1%wlp3s0"),
            [
                "route",
                "replace",
                "2001:db8::7/128",
                "via",
                "fe80::1",
                "dev",
                "wlp3s0"
            ]
        );
        assert_eq!(
            parse_default_gateway("default via 192.168.1.1 dev wlp3s0 proto dhcp\n").as_deref(),
            Some("192.168.1.1")
        );
    }

    #[test]
    fn teardown_deletes_only_the_owned_route_shapes() {
        assert_eq!(
            unbind_route_args("0.0.0.0/1", "tun5"),
            ["route", "del", "0.0.0.0/1", "dev", "tun5"]
        );
        assert_eq!(
            unbind_host_route_args("198.51.100.7".parse().unwrap()),
            ["route", "del", "198.51.100.7/32"]
        );
    }
}
