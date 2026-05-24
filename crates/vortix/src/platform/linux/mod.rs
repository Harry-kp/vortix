//! Linux platform implementations.
//!
//! Uses iptables/nftables, /proc/net/dev, ip addr, and resolvectl.

pub mod dns;
pub mod interface;
pub mod network;

// Killswitch firewall impl now lives in `vortix-platform-linux::firewall`
// (plan 003 U1).
pub use vortix_platform_linux::firewall;
