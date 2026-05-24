//! `vortix-platform-windows`: Windows platform adapters (plan 008 U4 stub).
//!
//! This crate exists to prove the `Platform` aggregate admits a third
//! OS without surprises. Every port impl currently returns "not
//! supported" — no Windows functionality ships in v0.3.0.
//!
//! The goal of the stub is to surface latent `cfg(unix)` leaks in the
//! workspace *now*, while the architectural context is fresh, rather
//! than when someone first tries to build vortix on Windows (issue #17).
//!
//! When real Windows support lands, fill each impl in place. The
//! Platform aggregate's match arm in `crates/vortix/src/platform/`
//! already routes here.

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::unused_self)]

pub mod dns;
pub mod firewall;
pub mod interface;
pub mod network_stats;
pub mod route_table;
pub mod socket_audit;

pub use dns::WindowsDns;
pub use firewall::WindowsFirewall;
pub use interface::WindowsInterface;
pub use network_stats::WindowsNetworkStats;
pub use route_table::WindowsRouteTable;
pub use socket_audit::WindowsSocketAudit;
