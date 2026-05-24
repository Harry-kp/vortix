//! Linux routing-table inspection via `ip route`.

use vortix_core::ports::route_table::RouteTable;
use vortix_process::CommandSpec;

/// Linux routing-table reader using `ip route show default`.
pub struct LinuxRouteTable;

impl RouteTable for LinuxRouteTable {
    fn default_gateway() -> Option<String> {
        let output = vortix_process::run_to_output(CommandSpec::oneshot(
            "ip",
            vec!["route".into(), "show".into(), "default".into()],
        ))
        .ok()?;

        let text = String::from_utf8_lossy(&output.stdout);
        // Format: "default via 192.168.1.1 dev wlan0 ..."
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[0] == "default" && parts[1] == "via" {
                return Some(parts[2].to_string());
            }
        }
        None
    }
}
