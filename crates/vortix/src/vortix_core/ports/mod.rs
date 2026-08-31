//! Capability ports: traits that adapter crates implement to provide subprocess execution,
//! per-OS platform operations, VPN protocol drivers, etc.
//!
//! - `process` — `CommandRunner`
//! - `killswitch`, `dns`, `interface`, `network_stats`, `route_table` — capability ports
//! - `tunnel` — `Tunnel` trait

pub mod dns;
pub mod interface;
pub mod killswitch;
pub mod network_stats;
pub(crate) mod owned_dns;
pub(crate) mod owned_firewall;
pub(crate) mod owned_routes;
pub mod process;
pub mod route_table;
pub mod socket_audit;
pub mod tunnel;
