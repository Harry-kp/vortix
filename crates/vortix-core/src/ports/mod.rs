//! Capability ports: traits that adapter crates implement to provide subprocess execution,
//! per-OS platform operations, VPN protocol drivers, etc.
//!
//! - `process` — `CommandRunner` (plan 002, this module)
//! - `killswitch`, `dns`, `interface`, `network_stats`, `route_table` — capability ports (plan 003)
//! - `tunnel` — `Tunnel` trait (plan 004)

pub mod dns;
pub mod interface;
pub mod killswitch;
pub mod network_stats;
pub mod process;
pub mod route_table;
pub mod socket_audit;
pub mod tunnel;
