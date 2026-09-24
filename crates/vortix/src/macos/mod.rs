//! macOS adapters:
//! - firewall via pf (`pfctl`).
//! - DNS via `SCDynamicStore`.
//! - interfaces via `libc::getifaddrs` + libproc FFI.
//! - byte counters via `libc::getifaddrs` + BSD `if_data`.
//! - routes via `route get default`.
//! - socket audit via hand-rolled libproc FFI.

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
