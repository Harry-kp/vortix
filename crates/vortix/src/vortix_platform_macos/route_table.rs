//! macOS routing-table inspection via `route get default`.

use crate::vortix_core::ports::route_table::RouteTable;
use crate::vortix_process::CommandSpec;

/// macOS routing-table reader using `route get default`.
pub struct MacRouteTable;

impl RouteTable for MacRouteTable {
    fn default_gateway() -> Option<String> {
        let output = crate::vortix_process::run_to_output(CommandSpec::oneshot(
            "route",
            vec!["get".into(), "default".into()],
        ))
        .ok()?;

        let text = String::from_utf8_lossy(&output.stdout);
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
}
