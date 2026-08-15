//! `vortix-platform-macos`: macOS platform adapters.
//!
//! Implements the capability ports defined in `vortix-core::ports::*`:
//! - `Killswitch` via pf (`pfctl`).
//! - `DnsResolver` via `SCDynamicStore`.
//! - `Interface` via `libc::getifaddrs` + libproc FFI.
//! - `NetworkStats` via `libc::getifaddrs` + BSD `if_data`.
//! - `RouteTable` via `route get default`.
//! - `SocketAudit` via hand-rolled libproc FFI.

#![allow(clippy::missing_errors_doc)]

pub mod dns;
pub mod firewall;
pub mod interface;
pub mod interface_list;
mod libproc_ffi;
pub mod network_stats;
pub(crate) mod owned_firewall;
pub mod process_identity;
pub mod route_table;
pub mod socket_audit;

pub use dns::MacDns;
pub use firewall::PfFirewall;
pub use interface::MacInterface;
pub use network_stats::MacNetworkStats;
pub use route_table::MacRouteTable;
pub use socket_audit::LsofSocketAudit;
