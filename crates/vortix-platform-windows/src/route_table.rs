//! Windows route table stub (plan 008 U4).
//!
//! Real impl would call `Get-NetRoute` or `GetIpForwardTable` from IP
//! Helper. Today returns `None` (no known default gateway).

use vortix_core::ports::route_table::RouteTable;

#[derive(Debug, Clone, Default)]
pub struct WindowsRouteTable;

impl RouteTable for WindowsRouteTable {
    fn default_gateway() -> Option<String> {
        None
    }
}
