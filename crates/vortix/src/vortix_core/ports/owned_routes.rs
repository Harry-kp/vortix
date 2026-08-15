//! Exact route-selection read-back owned by the privileged helper.

use std::net::IpAddr;

use crate::vortix_core::cidr::Cidr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnedRouteError {
    Unknown,
}

/// Read one concrete kernel route decision without accepting a caller-chosen
/// command, interface name, table, or route handle.
pub(crate) trait OwnedRoutes: Send {
    fn route_interface_for(&mut self, target: IpAddr) -> Result<String, OwnedRouteError>;

    /// Return every interface attached to an exact kernel route entry for
    /// `destination`. An empty vector proves that exact entry is absent; it
    /// must not be inferred from a longest-prefix route decision.
    fn exact_route_interfaces(&mut self, destination: Cidr)
        -> Result<Vec<String>, OwnedRouteError>;
}

pub(crate) fn canonical_route_destination(destination: Cidr) -> Cidr {
    let addr = match destination.addr {
        IpAddr::V4(address) => {
            let mask = u32::MAX
                .checked_shl(u32::from(32 - destination.prefix_len))
                .unwrap_or(0);
            IpAddr::V4((u32::from(address) & mask).into())
        }
        IpAddr::V6(address) => {
            let mask = u128::MAX
                .checked_shl(u32::from(128 - destination.prefix_len))
                .unwrap_or(0);
            IpAddr::V6((u128::from(address) & mask).into())
        }
    };
    Cidr {
        addr,
        prefix_len: destination.prefix_len,
    }
}
