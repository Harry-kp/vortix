//! Platform abstraction layer for OS-specific functionality.
//!
//! This module provides trait-based abstractions for platform-specific operations,
//! with compile-time selection via `#[cfg]` conditional compilation.
//!
//! Supported platforms:
//! - macOS: pf firewall, netstat -ib, ifconfig, scutil/networksetup
//! - Linux: iptables/nftables, /proc/net/dev, ip addr, resolvectl

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("Vortix currently only supports macOS and Linux");

use crate::core::killswitch::Result as KsResult;

// Re-export platform constants from the centralized constants module for convenience.
pub use crate::constants::DEFAULT_VPN_INTERFACE;
pub use crate::constants::KILLSWITCH_EMERGENCY_MSG;

// === Platform Trait Definitions ===

/// Firewall control for the kill switch.
///
/// Implementations block all non-VPN traffic when enabled.
pub trait Firewall {
    /// Enable kill switch by loading restrictive firewall rules.
    fn enable_blocking(vpn_interface: &str, vpn_server_ip: Option<&str>) -> KsResult<()>;

    /// Disable kill switch by flushing firewall rules.
    fn disable_blocking() -> KsResult<()>;
}

/// Network statistics collection.
///
/// Implementations read per-interface byte counters to calculate throughput.
pub trait NetworkStatsProvider {
    /// Get total bytes (in, out) across all non-loopback interfaces.
    fn get_total_bytes() -> (u64, u64);
}

/// VPN interface detection.
///
/// Implementations detect active `WireGuard` and `OpenVPN` interfaces.
pub trait InterfaceDetector {
    /// Check if a `WireGuard` interface exists by profile name.
    fn check_wireguard_interface(name: &str) -> bool;

    /// Get the real interface name for a `WireGuard` profile.
    fn resolve_wireguard_interface(name: &str) -> Option<String>;

    /// Get the PID of the `WireGuard` process managing an interface.
    fn get_wireguard_pid(interface: &str) -> Option<u32>;

    /// Get IP and MTU for an interface.
    fn get_interface_info(interface: &str) -> (String, String);
}

/// DNS resolver information.
///
/// Implementations query the system for the active DNS server.
pub trait DnsResolver {
    /// Get the current system DNS server address.
    fn get_dns_server() -> Option<String>;
}

/// Platform-appropriate install hint for a package.
#[cfg(target_os = "macos")]
#[must_use]
pub fn install_hint(pkg: &str) -> String {
    format!("brew install {pkg}")
}

#[cfg(target_os = "linux")]
#[must_use]
pub fn install_hint(pkg: &str) -> String {
    match pkg {
        // systemd-resolved is managing DNS — need the systemd-provided shim.
        // `openresolv` will NOT work here (causes "signature mismatch").
        "resolvconf (systemd)" => "\
sudo apt install systemd-resolved  # Debian/Ubuntu (provides resolvconf shim)\n\
sudo pacman -S systemd-resolvconf  # Arch\n\
sudo dnf install systemd-resolved  # Fedora"
            .to_string(),
        // Non-systemd system — standalone openresolv works fine.
        "resolvconf" => "\
sudo apt install openresolv  # Debian/Ubuntu\n\
sudo pacman -S openresolv    # Arch\n\
sudo dnf install openresolv  # Fedora"
            .to_string(),
        // WireGuard binaries are shipped by the wireguard-tools package.
        "wg" | "wg-quick" => "\
sudo apt install wireguard-tools  # Debian/Ubuntu\n\
sudo pacman -S wireguard-tools    # Arch\n\
sudo dnf install wireguard-tools  # Fedora"
            .to_string(),
        _ => format!("sudo apt install {pkg}  # or: sudo dnf install {pkg}"),
    }
}
