//! `RouteTable` port — system routing inspection.
//!
//! Today vortix only reads the default gateway. The port shape leaves room
//! for `list`/`add`/`remove` once split-tunnelling and route manipulation
//! land (deferred per plan #003 Scope Boundaries).

/// Read-only access to the host's routing table.
pub trait RouteTable {
    /// IP address of the current default gateway, if any.
    fn default_gateway() -> Option<String>;
}
