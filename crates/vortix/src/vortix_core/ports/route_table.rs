//! `RouteTable` port — system routing inspection.
//!
//! Today vortix only reads the default gateway. The port shape leaves room
//! for `list`/`add`/`remove` once split-tunnelling and route manipulation
//! land (deliberately deferred).

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
}
