//! Exact route-selection read-back owned by the privileged helper.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnedRouteError {
    Unknown,
}

/// Read one concrete kernel route decision without accepting a caller-chosen
/// command, interface name, table, or route handle.
pub(crate) trait OwnedRoutes: Send {
    fn route_interface_for(&mut self, target: IpAddr) -> Result<String, OwnedRouteError>;
}
