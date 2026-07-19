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

use std::time::Duration;

use crate::platform::route_probe::{ProbeOutcome, RouteProbe};
use crate::vortix_core::ports::route_table::RouteTable;
use crate::vortix_process::CommandSpec;

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

/// Public-internet probe target. See module-level docs for why this is
/// preferred over `route get default`.
const ROUTE_PROBE_TARGET: &str = "8.8.8.8";

/// macOS routing-table reader using `route -n get <target>`.
pub struct MacRouteTable;

impl RouteTable for MacRouteTable {
    fn default_gateway() -> Option<String> {
        let text = run_route_get_default()?;
        parse_gateway(&text)
    }

    fn default_route_interface() -> Option<String> {
        let text = run_route_get_default()?;
        parse_interface(&text)
    }
}

/// Run `route -n get <ROUTE_PROBE_TARGET>` and return its stdout as
/// UTF-8 (lossy).
///
/// Returns `None` if the subprocess fails (binary missing, non-zero exit,
/// I/O error) so callers can degrade gracefully without panicking.
fn run_route_get_default() -> Option<String> {
    match ROUTE_PROBE.run(
        CommandSpec::oneshot(
            "route",
            vec!["-n".into(), "get".into(), ROUTE_PROBE_TARGET.into()],
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
                    target: "vortix::vortix_platform_macos::route_table",
                    consecutive_fails = consecutive_failures,
                    cooldown_secs = cooldown.as_secs(),
                    "`route get default` probe failed; backing off to spare the tokio runtime"
                );
            }
            None
        }
    }
}

/// Extract the `gateway:` line from `route get default` output.
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
fn parse_interface(text: &str) -> Option<String> {
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
    fn parse_gateway_still_works_on_sample() {
        assert_eq!(parse_gateway(SAMPLE_WIFI), Some("192.168.1.1".into()));
        assert_eq!(parse_gateway(SAMPLE_VPN), Some("10.0.0.1".into()));
    }
}
