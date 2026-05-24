//! `Interface` port — VPN interface detection.

/// Detect and inspect VPN interfaces on the host.
///
/// Implementations resolve the platform-specific mapping between a profile
/// name and the actual kernel/userspace interface, query process state, and
/// extract IP/MTU information.
pub trait Interface {
    /// Check whether a `WireGuard` interface exists for the given profile name.
    fn check_wireguard_interface(name: &str) -> bool;

    /// Resolve the real interface name for a `WireGuard` profile.
    fn resolve_wireguard_interface(name: &str) -> Option<String>;

    /// PID of the `WireGuard` user-space process managing an interface (if any).
    fn get_wireguard_pid(interface: &str) -> Option<u32>;

    /// `(ip, mtu)` for an interface; empty strings if unavailable.
    fn get_interface_info(interface: &str) -> (String, String);
}
