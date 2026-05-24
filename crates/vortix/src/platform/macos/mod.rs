//! macOS platform implementations.
//!
//! Uses pf (Packet Filter), netstat -ib, ifconfig, and scutil/networksetup.

pub mod dns;
pub mod interface;
pub mod network;

// Killswitch firewall impl now lives in `vortix-platform-macos::firewall`
// (plan 003 U1).
pub use vortix_platform_macos::firewall;
