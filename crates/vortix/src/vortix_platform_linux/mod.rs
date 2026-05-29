//! `vortix-platform-linux`: Linux platform adapters.
//!
//! Implements the capability ports defined in `vortix-core::ports::*`:
//! - `Killswitch` via iptables (preferred) → nftables fallback.
//! - `DnsResolver` via resolvectl → nmcli → /etc/resolv.conf.
//! - `Interface` via `ip addr` + `wg show`.
//! - `NetworkStats` via /proc/net/dev.
//! - `RouteTable` via `ip route show default`.

#![allow(clippy::missing_errors_doc)]

pub mod dns;
pub mod firewall;
pub mod interface;
pub mod interface_list;
pub mod network_stats;
pub mod route_table;
pub mod socket_audit;

pub use dns::LinuxDns;
pub use firewall::IptablesFirewall;
pub use interface::LinuxInterface;
pub use network_stats::LinuxNetworkStats;
pub use route_table::LinuxRouteTable;
pub use socket_audit::ProcSocketAudit;
