//! macOS platform implementations.
//!
//! Uses pf (Packet Filter), netstat -ib, ifconfig, and scutil/networksetup.

pub mod dns;
pub mod firewall;
pub mod interface;
pub mod network;
