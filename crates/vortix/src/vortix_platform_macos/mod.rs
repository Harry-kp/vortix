//! `vortix-platform-macos`: macOS platform adapters.
//!
//! Implements the capability ports defined in `vortix-core::ports::*`:
//! - `Killswitch` via pf (`pfctl`).
//! - `DnsResolver` via `SCDynamicStore` (plan 002 U7).
//! - `Interface` via `libc::getifaddrs` + libproc FFI (plan 002 U6/U7).
//! - `NetworkStats` via `libc::getifaddrs` + BSD `if_data` (plan 002 U7).
//! - `RouteTable` via `route get default`.
//! - `SocketAudit` via hand-rolled libproc FFI (plan 002 U7).

#![allow(clippy::missing_errors_doc)]

pub mod dns;
pub mod firewall;
pub mod interface;
pub mod interface_list;
mod libproc_ffi;
pub mod network_stats;
pub mod route_table;
pub mod socket_audit;

pub use dns::MacDns;
pub use firewall::PfFirewall;
pub use interface::MacInterface;
pub use network_stats::MacNetworkStats;
pub use route_table::MacRouteTable;
pub use socket_audit::LsofSocketAudit;
