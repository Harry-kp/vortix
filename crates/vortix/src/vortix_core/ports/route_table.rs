//! `RouteTable` port — system route inspection and exact scoped writes.

use std::net::IpAddr;

/// Result of probing the route used for public-internet traffic.
///
/// `NoDefaultRoute` is an observed kernel state. `ProbeFailed` means the
/// observation is unknown and consumers must retain their last known route
/// instead of interpreting the failure as a topology change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum DefaultRouteObservation {
    Interface(String),
    NoDefaultRoute,
    #[default]
    ProbeFailed,
}

impl DefaultRouteObservation {
    #[must_use]
    pub fn interface(&self) -> Option<&str> {
        match self {
            Self::Interface(interface) => Some(interface),
            Self::NoDefaultRoute | Self::ProbeFailed => None,
        }
    }
}

/// Read-only access to the host's routing table.
pub trait RouteTable {
    /// IP address of the current default gateway, if any.
    fn default_gateway() -> Option<String>;

    /// Name of the network interface carrying the current default route, if
    /// any (e.g. `en0`, `wlan0`, `utun3`). Used by the tunnel registry to
    /// detect which physical/virtual interface owns the default route so it
    /// can identify primary tunnels and reason about VPN-over-VPN topologies
    ///.
    fn default_route_observation() -> DefaultRouteObservation;

    /// Observe the exact kernel route selected for `target`.
    ///
    /// Protocol probes use this before emitting traffic so a configured
    /// split-tunnel destination cannot silently escape over a physical link.
    fn route_interface_for(target: IpAddr) -> DefaultRouteObservation;

    /// Bind `cidr` to `interface`, regardless of how a gateway would resolve.
    ///
    /// macOS `OpenVPN` installs a pushed split route via its gateway; when a full
    /// tunnel already owns `0.0.0.0/1` that gateway resolves through the full
    /// tunnel, so the split route lands on the wrong interface. Re-scoping it to
    /// the named interface fixes it. Linux already installs device-scoped, so
    /// its implementation is a no-op.
    fn bind_route(cidr: &str, interface: &str) -> Result<(), String>;

    /// Keep a VPN server reachable through the pre-tunnel gateway before a
    /// default-route claim is transferred to that VPN.
    fn bind_host_route(destination: IpAddr, gateway: &str) -> Result<(), String>;

    /// Remove an interface-scoped route previously installed by Vortix.
    fn unbind_route(cidr: &str, interface: &str) -> Result<(), String>;

    /// Remove a VPN-server escape route previously installed by Vortix.
    fn unbind_host_route(destination: IpAddr) -> Result<(), String>;
}
