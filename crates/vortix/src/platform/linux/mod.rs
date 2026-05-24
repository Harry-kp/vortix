//! Linux platform implementations.
//!
//! Uses iptables/nftables, /proc/net/dev, ip addr, and resolvectl.

pub mod dns;
pub mod firewall;
pub mod interface;
pub mod network;
