//! `vortix-platform-macos`: macOS platform adapters.
//!
//! Implements the capability ports defined in `vortix-core::ports::*`:
//! - `Killswitch` via pf (`pfctl`).
//! - `DnsResolver` via `scutil --dns` → `networksetup`.
//! - `Interface` via `ifconfig` + `lsof`.
//! - `NetworkStats` via `netstat -ib`.
//! - `RouteTable` via `route get default`.

#![allow(clippy::missing_errors_doc)]

pub mod dns;
pub mod firewall;
pub mod interface;
pub mod network_stats;
pub mod route_table;
pub mod socket_audit;

pub use dns::MacDns;
pub use firewall::PfFirewall;
pub use interface::MacInterface;
pub use network_stats::MacNetworkStats;
pub use route_table::MacRouteTable;
pub use socket_audit::LsofSocketAudit;
