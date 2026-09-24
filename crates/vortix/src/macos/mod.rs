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
mod libproc;
pub mod route_table;

pub use dns::MacDns;
pub use firewall::PfFirewall;
pub use interface::MacInterface;
pub use interface::MacNetworkStats;
pub use libproc::LsofSocketAudit;
pub use route_table::MacRouteTable;
