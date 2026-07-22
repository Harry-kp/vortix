//! Windows route table stub.
//!
//! Real impl would call `Get-NetRoute` or `GetIpForwardTable` from IP
//! Helper. Today returns `None` (no known default gateway).

use crate::vortix_core::ports::route_table::{DefaultRouteObservation, RouteTable};

#[derive(Debug, Clone, Default)]
pub struct WindowsRouteTable;

impl RouteTable for WindowsRouteTable {
    fn default_gateway() -> Option<String> {
        None
    }

    fn default_route_observation() -> DefaultRouteObservation {
        // Windows is out of scope for v1 multi-connection
        // routing primitives. Real impl would call `Get-NetRoute` /
        // `GetIpForwardTable2` and read `InterfaceAlias` / `InterfaceLuid`.
        DefaultRouteObservation::ProbeFailed
    }

    fn route_interface_for(_target: std::net::IpAddr) -> DefaultRouteObservation {
        DefaultRouteObservation::ProbeFailed
    }
}
