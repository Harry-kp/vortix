//! `vortix-platform-macos`: macOS platform adapters.
//!
//! Implements the capability ports defined in `vortix-core::ports::*` against
//! macOS-native tooling: pf (Packet Filter) via `pfctl` for the kill switch.
//! Plan 003 U2 adds the remaining four ports (DNS, interface, network-stats,
//! route-table).

#![allow(clippy::missing_errors_doc)]

pub mod firewall;

pub use firewall::PfFirewall;
