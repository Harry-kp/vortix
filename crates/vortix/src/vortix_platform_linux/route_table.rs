//! Linux routing-table inspection via `ip route`.

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::vortix_core::ports::route_table::RouteTable;
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
struct ProbeBackoff {
    consecutive_fails: u32,
    next_allowed: Instant,
}

fn backoff_state() -> &'static Mutex<ProbeBackoff> {
    static STATE: OnceLock<Mutex<ProbeBackoff>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(ProbeBackoff {
            consecutive_fails: 0,
            next_allowed: Instant::now(),
        })
    })
}

fn cooldown_for_fails(fails: u32) -> Duration {
    let secs = match fails {
        0..=2 => 0,
        3..=5 => 5,
        6..=10 => 15,
        _ => 60,
    };
    Duration::from_secs(secs)
}

/// Linux routing-table reader using `ip route show default`.
pub struct LinuxRouteTable;

impl RouteTable for LinuxRouteTable {
    fn default_gateway() -> Option<String> {
        let text = run_ip_route_show_default()?;
        parse_gateway(&text)
    }

    fn default_route_interface() -> Option<String> {
        let text = run_ip_route_show_default()?;
        parse_interface(&text)
    }
}

/// Run `ip route show default` and return stdout as UTF-8 (lossy).
///
/// Returns `None` if the subprocess fails so callers can degrade gracefully.
fn run_ip_route_show_default() -> Option<String> {
    {
        let state = backoff_state()
            .lock()
            .expect("backoff state mutex poisoned");
        if Instant::now() < state.next_allowed {
            return None;
        }
    }

    let result = crate::vortix_process::run_to_output(
        // xtask:allow-shell-regression: `ip route show default` is the canonical Linux routing-table inspection — no libc equivalent that returns the default-route dev without rolling our own netlink RTNETLINK parser. Pre-existing shell-out; this change only adds a timeout.
        CommandSpec::oneshot("ip", vec!["route".into(), "show".into(), "default".into()])
            .timeout(ROUTE_QUERY_TIMEOUT),
    );

    let mut state = backoff_state()
        .lock()
        .expect("backoff state mutex poisoned");
    if let Ok(output) = result {
        state.consecutive_fails = 0;
        state.next_allowed = Instant::now();
        return Some(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    state.consecutive_fails = state.consecutive_fails.saturating_add(1);
    let cooldown = cooldown_for_fails(state.consecutive_fails);
    state.next_allowed = Instant::now() + cooldown;
    if state.consecutive_fails == 1 || cooldown >= Duration::from_secs(5) {
        tracing::warn!(
            target: "vortix::vortix_platform_linux::route_table",
            consecutive_fails = state.consecutive_fails,
            cooldown_secs = cooldown.as_secs(),
            "`ip route show default` probe failed; backing off to spare the tokio runtime"
        );
    }
    None
}

/// Extract the gateway IP from `default via <ip> dev <name> ...` lines.
fn parse_gateway(text: &str) -> Option<String> {
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "default" && parts[1] == "via" {
            return Some(parts[2].to_string());
        }
    }
    None
}

/// Extract the interface name from `default ... dev <name> ...` lines.
///
/// `iproute2` formats default routes with `dev <name>` somewhere in the
/// token sequence — its position is not fixed (e.g. it may appear after
/// `proto`, `metric`, etc. on unusual systems). Walk all tokens and return
/// the one immediately following `dev`.
fn parse_interface(text: &str) -> Option<String> {
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.first() != Some(&"default") {
            continue;
        }
        let mut iter = parts.iter().copied();
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
    fn parse_interface_returns_none_when_no_default_line() {
        let text = "10.0.0.0/8 via 192.168.1.1 dev wlan0\n";
        assert_eq!(parse_interface(text), None);
    }

    #[test]
    fn parse_interface_returns_none_when_dev_has_no_value() {
        let text = "default via 192.168.1.1 dev\n";
        assert_eq!(parse_interface(text), None);
    }

    #[test]
    fn parse_gateway_still_works_on_sample() {
        let text = "default via 192.168.1.1 dev wlan0 proto dhcp\n";
        assert_eq!(parse_gateway(text), Some("192.168.1.1".into()));
    }
}
