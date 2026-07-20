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
//! See `vortix_platform_macos/route_table.rs` for the cross-platform
//! rationale and the choice of 8.8.8.8 as the probe target.

use std::time::Duration;

use crate::platform::route_probe::{ProbeOutcome, RouteProbe};
use crate::vortix_core::ports::route_table::{DefaultRouteObservation, RouteTable};
use crate::vortix_process::CommandSpec;

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

/// Public-internet probe target. See module-level docs for why this is
/// preferred over `ip route show default`.
const ROUTE_PROBE_TARGET: &str = "8.8.8.8";

/// Linux routing-table reader using `ip route get <target>`.
pub struct LinuxRouteTable;

impl RouteTable for LinuxRouteTable {
    fn default_gateway() -> Option<String> {
        let text = run_ip_route_show_default()?;
        parse_gateway(&text)
    }

    fn default_route_observation() -> DefaultRouteObservation {
        let Some(text) = run_ip_route_show_default() else {
            return DefaultRouteObservation::ProbeFailed;
        };
        parse_interface(&text).map_or(
            DefaultRouteObservation::NoDefaultRoute,
            DefaultRouteObservation::Interface,
        )
    }
}

/// Run `ip route get <ROUTE_PROBE_TARGET>` and return stdout as UTF-8
/// (lossy).
///
/// Returns `None` if the subprocess fails so callers can degrade gracefully.
fn run_ip_route_show_default() -> Option<String> {
    match ROUTE_PROBE.run(
        // xtask:allow-shell-regression: `ip route get <ip>` is the canonical Linux routing-table inspection — no libc equivalent that returns the chosen egress dev without rolling our own netlink RTNETLINK parser.
        CommandSpec::oneshot(
            "ip",
            vec!["route".into(), "get".into(), ROUTE_PROBE_TARGET.into()],
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
                    target: "vortix::vortix_platform_linux::route_table",
                    consecutive_fails = consecutive_failures,
                    cooldown_secs = cooldown.as_secs(),
                    "`ip route get` probe failed; backing off to spare the tokio runtime"
                );
            }
            None
        }
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
fn parse_interface(text: &str) -> Option<String> {
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
}
