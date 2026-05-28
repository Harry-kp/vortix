//! `RouteTable` port — system routing inspection.
//!
//! Today vortix only reads the default gateway. The port shape leaves room
//! for `list`/`add`/`remove` once split-tunnelling and route manipulation
//! land (deferred per plan #003 Scope Boundaries).

/// Read-only access to the host's routing table.
pub trait RouteTable {
    /// IP address of the current default gateway, if any.
    fn default_gateway() -> Option<String>;

    /// Name of the network interface carrying the current default route, if
    /// any (e.g. `en0`, `wlan0`, `utun3`). Used by the tunnel registry to
    /// detect which physical/virtual interface owns the default route so it
    /// can identify primary tunnels and reason about VPN-over-VPN topologies
    /// (plan #001 U4, R2).
    fn default_route_interface() -> Option<String>;
}
