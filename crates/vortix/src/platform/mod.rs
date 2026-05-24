//! Platform abstraction layer — thin re-exports.
//!
//! Plan 003 moves capability-port traits and impls into `vortix-core::ports::*`
//! and the `vortix-platform-{linux,macos}` crates. This module keeps the
//! legacy trait/impl path aliases working until plan 003 U7 swaps consumers
//! over to the `Platform` aggregate.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("Vortix currently only supports macOS and Linux");

// Re-export platform constants from the centralized constants module for convenience.
pub use crate::constants::DEFAULT_VPN_INTERFACE;
pub use crate::constants::KILLSWITCH_EMERGENCY_MSG;

// Capability ports now live in `vortix-core::ports::*` (plan 003 U1/U2).
// Keep the legacy trait names as aliases so existing call sites keep working.
pub use vortix_core::ports::dns::DnsResolver;
pub use vortix_core::ports::interface::Interface as InterfaceDetector;
pub use vortix_core::ports::killswitch::Killswitch as Firewall;
pub use vortix_core::ports::network_stats::NetworkStats as NetworkStatsProvider;
pub use vortix_core::ports::route_table::RouteTable;

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
