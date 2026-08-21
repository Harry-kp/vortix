//! Exact route-selection read-back owned by the privileged helper.

use std::net::IpAddr;

use crate::vortix_core::cidr::Cidr;
pub(crate) use crate::vortix_core::privileged::{
    PhysicalRouteBackend as OwnedRouteBackend, PhysicalRouteEntry as RouteEntry,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnedRouteError {
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteMutationError {
    FailedBeforeEffect,
    EffectMayHaveApplied,
}

/// Read one concrete kernel route decision without accepting a caller-chosen
/// command, interface name, table, or route handle.
pub(crate) trait OwnedRoutes: Send {
    fn backend(&self) -> OwnedRouteBackend;

    fn route_interface_for(&mut self, target: IpAddr) -> Result<String, OwnedRouteError>;

    /// Return every interface attached to an exact kernel route entry for
    /// `destination`. An empty vector proves that exact entry is absent; it
    /// must not be inferred from a longest-prefix route decision.
    fn exact_route_interfaces(&mut self, destination: Cidr)
        -> Result<Vec<String>, OwnedRouteError>;

    /// Return every exactly representable entry for `destination` in the
    /// platform table the helper will mutate. Unsupported or incomplete
    /// kernel vocabulary fails closed rather than being treated as absence.
    fn exact_route_entries(
        &mut self,
        _destination: Cidr,
    ) -> Result<Vec<RouteEntry>, OwnedRouteError> {
        Err(OwnedRouteError::Unknown)
    }

    fn exact_route_entries_batch(
        &mut self,
        destinations: &[Cidr],
    ) -> Result<Vec<Vec<RouteEntry>>, OwnedRouteError>;

    fn add_route(&mut self, _route: &RouteEntry) -> Result<(), RouteMutationError> {
        Err(RouteMutationError::FailedBeforeEffect)
    }

    fn remove_route(&mut self, _route: &RouteEntry) -> Result<(), RouteMutationError> {
        Err(RouteMutationError::FailedBeforeEffect)
    }

    fn exact_transport_bypass_targets(&mut self) -> Result<Vec<IpAddr>, OwnedRouteError> {
        Err(OwnedRouteError::Unknown)
    }

    fn add_transport_bypass(&mut self, _target: IpAddr) -> Result<(), RouteMutationError> {
        Err(RouteMutationError::FailedBeforeEffect)
    }

    fn remove_transport_bypass(&mut self, _target: IpAddr) -> Result<(), RouteMutationError> {
        Err(RouteMutationError::FailedBeforeEffect)
    }

    /// Resolve one endpoint escape route entirely inside the privileged
    /// platform adapter. The caller supplies only the authenticated endpoint;
    /// gateway and interface identity come from current kernel truth.
    fn resolve_transport_bypass(&mut self, _target: IpAddr) -> Result<RouteEntry, OwnedRouteError> {
        Err(OwnedRouteError::Unknown)
    }

    /// Resolve `OpenVPN`'s `net_gateway` against the pre-tunnel system default
    /// route. The adapter supplies the gateway and interface from kernel
    /// truth; the caller supplies only the authenticated route destination.
    fn resolve_net_gateway(&mut self, _destination: Cidr) -> Result<RouteEntry, OwnedRouteError> {
        Err(OwnedRouteError::Unknown)
    }

    fn route_domain_active(&mut self) -> Result<bool, OwnedRouteError> {
        Err(OwnedRouteError::Unknown)
    }

    fn activate_route_domain(&mut self) -> Result<(), RouteMutationError> {
        Err(RouteMutationError::FailedBeforeEffect)
    }

    fn deactivate_route_domain(&mut self) -> Result<(), RouteMutationError> {
        Err(RouteMutationError::FailedBeforeEffect)
    }
}

pub(crate) fn canonical_route_destination(destination: Cidr) -> Cidr {
    destination.canonical_network()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_entry_requires_canonical_bounded_platform_values() {
        assert!(RouteEntry::new(
            "10.0.0.0/8".parse().unwrap(),
            "vxroute0".into(),
            Some("10.0.0.1".parse().unwrap()),
            Some(20),
        )
        .is_ok());
        assert!(
            RouteEntry::new("10.1.2.3/8".parse().unwrap(), "vxroute0".into(), None, None,).is_err()
        );
        assert!(RouteEntry::new(
            "10.0.0.0/8".parse().unwrap(),
            "not/an/interface".into(),
            None,
            None,
        )
        .is_err());
        assert!(RouteEntry::new(
            "10.0.0.0/8".parse().unwrap(),
            "vxroute0".into(),
            Some("2001:db8::1".parse().unwrap()),
            None,
        )
        .is_err());
    }
}
