//! Linux adapters:
//! - firewall via one atomic nftables `inet` transaction.
//! - DNS via resolvectl → nmcli → /etc/resolv.conf.
//! - interfaces via direct kernel/sysfs observation.
//! - byte counters via /proc/net/dev.
//! - routes via `ip route show default`.

#![allow(clippy::missing_errors_doc)]

pub mod dns;
pub mod firewall;
pub mod interface;
pub mod process_identity;
pub mod route_table;
pub mod socket_audit;

pub use dns::LinuxDns;
pub use firewall::NftFirewall;
pub use interface::LinuxInterface;
pub use interface::LinuxNetworkStats;
pub use route_table::LinuxRouteTable;
pub use socket_audit::ProcSocketAudit;

const POLICY_COMMENT_PREFIX: &str = "vortix-policy:";
