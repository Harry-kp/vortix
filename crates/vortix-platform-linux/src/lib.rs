//! `vortix-platform-linux`: Linux platform adapters.
//!
//! Implements the capability ports defined in `vortix-core::ports::*` against
//! Linux-native tooling: iptables / nftables for the kill switch (preference
//! iptables → nft). Plan 003 U2 adds the remaining four ports (DNS, interface,
//! network-stats, route-table).

#![allow(clippy::missing_errors_doc)]

pub mod firewall;

pub use firewall::IptablesFirewall;
