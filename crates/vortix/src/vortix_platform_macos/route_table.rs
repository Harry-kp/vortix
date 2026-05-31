//! macOS routing-table inspection via `route get default`.

use std::time::Duration;

use crate::vortix_core::ports::route_table::RouteTable;
use crate::vortix_process::CommandSpec;

/// Upper bound on the `route get default` subprocess. The query goes
/// through the kernel's routing socket (`rtmsg`), which can take many
/// seconds when the route table is mid-transition — e.g., right after a
/// new VPN tunnel claims the default route. Called inline from
/// `TunnelRegistry::recompute_primary` on the UI thread (via
/// `set_connected` → success path of `handle_connect_result`), so an
/// uncapped query freezes the TUI for the entire transition window
/// (observed: 30s after an `OpenVPN` connect, exactly `rtmsg`'s retry
/// timeout). With this cap, `route` is killed at 1s, we return [`None`],
/// and the primary stays unset until the scanner's next tick — by which
/// time the kernel has settled and the query returns instantly.
const ROUTE_QUERY_TIMEOUT: Duration = Duration::from_secs(1);

/// macOS routing-table reader using `route get default`.
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

/// Run `route get default` and return its stdout as UTF-8 (lossy).
///
/// Returns `None` if the subprocess fails (binary missing, non-zero exit,
/// I/O error) so callers can degrade gracefully without panicking.
fn run_route_get_default() -> Option<String> {
    let output = crate::vortix_process::run_to_output(
        CommandSpec::oneshot("route", vec!["get".into(), "default".into()])
            .timeout(ROUTE_QUERY_TIMEOUT),
    )
    .ok()?;
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
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
