//! Platform abstraction layer — thin re-exports.
//!
//! Plan 003 moves capability-port traits and impls into `vortix-core::ports::*`
//! and the `vortix-platform-{linux,macos}` crates. This module keeps the
//! legacy trait/impl path aliases working until a later sweep swaps consumers
//! over to the `Platform` aggregate.

pub mod aggregate;
pub(crate) mod fixed_root_command;
pub(crate) mod route_probe;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;

pub use aggregate::{
    DnsResolverKind, InterfaceKind, KillswitchKind, MockDns, MockInterface, MockKillswitch,
    MockNetworkStats, MockRouteTable, NetworkStatsKind, Platform, RouteTableKind,
};

#[allow(
    dead_code,
    reason = "the opposite family is constructed on its target OS"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlatformFamily {
    Linux,
    MacOs,
}

use crate::vortix_core::ports::owned_dns::OwnedDns;
use crate::vortix_core::ports::owned_firewall::OwnedFirewall;

#[cfg(target_os = "linux")]
pub(crate) const fn current_platform_family() -> PlatformFamily {
    PlatformFamily::Linux
}

#[cfg(target_os = "macos")]
pub(crate) const fn current_platform_family() -> PlatformFamily {
    PlatformFamily::MacOs
}

pub(crate) fn helper_owned_firewall() -> Box<dyn OwnedFirewall> {
    #[cfg(target_os = "linux")]
    {
        Box::new(crate::vortix_platform_linux::owned_firewall::LinuxOwnedFirewall::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(crate::vortix_platform_macos::owned_firewall::MacOsOwnedFirewall::new())
    }
}

pub(crate) fn helper_owned_dns() -> Box<dyn OwnedDns> {
    #[cfg(target_os = "linux")]
    {
        Box::new(crate::vortix_platform_linux::owned_dns::LinuxOwnedDns::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(crate::vortix_platform_macos::dns::MacDnsPolicy::system())
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Process-global platform — the consumer-migration seam.
//
// Plan #003 originally threaded the Platform aggregate through every consumer.
// We instead install a process-wide singleton, matching the runner's
// `crate::vortix_process::global_runner()` pattern. `main.rs` initialises it once at
// startup; consumers reach for `current_platform()` instead of branching on
// `cfg(target_os)`. The async engine refactor swaps this back to
// explicit dependency injection.
// ───────────────────────────────────────────────────────────────────────────

use std::sync::OnceLock;

static GLOBAL_PLATFORM: OnceLock<Platform> = OnceLock::new();

/// Install the process-wide platform aggregate. First call wins.
///
/// `main()` calls this with `Platform::detect_current()`. Tests can call it
/// earlier with `Platform::for_test()` to redirect platform-port calls.
pub fn set_global_platform(platform: Platform) {
    let _ = GLOBAL_PLATFORM.set(platform);
}

/// Get the process-wide platform aggregate. Lazily initialises with
/// `Platform::for_test()` (all-mock variants) when no explicit platform has
/// been installed — the right behaviour for tests that don't touch
/// platform-port paths.
#[must_use]
pub fn current_platform() -> &'static Platform {
    GLOBAL_PLATFORM.get_or_init(Platform::for_test)
}

pub(crate) fn observe_process_identity(
    pid: u32,
) -> std::io::Result<Option<crate::vortix_core::ports::process::KernelProcessIdentity>> {
    #[cfg(target_os = "linux")]
    {
        crate::vortix_platform_linux::process_identity::observe(pid)
    }
    #[cfg(target_os = "macos")]
    {
        crate::vortix_platform_macos::process_identity::observe(pid)
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn process_group_has_live_members(group_id: u32) -> std::io::Result<Option<bool>> {
    crate::vortix_platform_linux::process_identity::process_group_has_live_members(group_id)
}

#[cfg(target_os = "macos")]
#[allow(
    clippy::unnecessary_wraps,
    reason = "matches the Linux platform probe so the process layer stays OS-agnostic"
)]
pub(crate) fn process_group_has_live_members(_group_id: u32) -> std::io::Result<Option<bool>> {
    Ok(None)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("Vortix currently only supports macOS and Linux");

// Re-export platform constants from the centralized constants module for convenience.
pub use crate::constants::DEFAULT_VPN_INTERFACE;
pub use crate::constants::KILLSWITCH_EMERGENCY_MSG;

// Capability ports now live in `vortix-core::ports::*`.
// Keep the legacy trait names as aliases so existing call sites keep working.
pub use crate::vortix_core::ports::dns::DnsResolver;
pub use crate::vortix_core::ports::interface::Interface as InterfaceDetector;
pub use crate::vortix_core::ports::killswitch::Killswitch as Firewall;
pub use crate::vortix_core::ports::network_stats::NetworkStats as NetworkStatsProvider;
pub use crate::vortix_core::ports::route_table::RouteTable;

fn syscall_result(result: libc::c_int) -> std::io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Replace the current process's supplementary groups on macOS.
///
/// This is called from a `pre_exec` closure, so it performs only bounded
/// scalar conversion and the async-signal-safe `setgroups` syscall.
#[cfg(target_os = "macos")]
pub(crate) fn set_process_supplementary_groups(groups: &[u32]) -> std::io::Result<()> {
    let count =
        i32::try_from(groups.len()).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: `groups` remains valid for the duration of the syscall.
    #[allow(unsafe_code)]
    let result = unsafe { libc::setgroups(count, groups.as_ptr()) };
    syscall_result(result)
}

/// Linux variant of [`set_process_supplementary_groups`].
#[cfg(target_os = "linux")]
pub(crate) fn set_process_supplementary_groups(groups: &[u32]) -> std::io::Result<()> {
    // SAFETY: `groups` remains valid for the duration of the syscall.
    #[allow(unsafe_code)]
    let result = unsafe { libc::setgroups(groups.len(), groups.as_ptr()) };
    syscall_result(result)
}

/// Resolve a user's complete OS group list without invoking an external
/// command. The libc signature differs between macOS and Linux, so the
/// normalization belongs at this platform boundary.
#[cfg(target_os = "macos")]
pub(crate) fn supplementary_groups_for_user(
    user: &std::ffi::CStr,
    gid: u32,
    max_groups: usize,
) -> Option<Vec<u32>> {
    let base_group = i32::try_from(gid).ok()?;
    let mut group_count = i32::try_from(max_groups).ok()?;
    let mut groups = vec![0_i32; max_groups];
    // SAFETY: the call uses the stable C string and a buffer whose length is
    // supplied through `group_count`.
    #[allow(unsafe_code)]
    unsafe {
        if libc::getgrouplist(
            user.as_ptr(),
            base_group,
            groups.as_mut_ptr(),
            &raw mut group_count,
        ) < 0
        {
            return None;
        }
        groups.truncate(usize::try_from(group_count).ok()?);
        if groups.is_empty() {
            return None;
        }
        groups
            .into_iter()
            .map(|group| u32::try_from(group).ok())
            .collect()
    }
}

/// Linux variant of [`supplementary_groups_for_user`].
#[cfg(target_os = "linux")]
pub(crate) fn supplementary_groups_for_user(
    user: &std::ffi::CStr,
    gid: u32,
    max_groups: usize,
) -> Option<Vec<u32>> {
    let mut group_count = i32::try_from(max_groups).ok()?;
    let mut groups = vec![0_u32; max_groups];
    // SAFETY: the call uses the stable C string and a buffer whose length is
    // supplied through `group_count`.
    #[allow(unsafe_code)]
    unsafe {
        if libc::getgrouplist(
            user.as_ptr(),
            gid,
            groups.as_mut_ptr(),
            &raw mut group_count,
        ) < 0
        {
            return None;
        }
        groups.truncate(usize::try_from(group_count).ok()?);
        if groups.is_empty() {
            return None;
        }
        Some(groups)
    }
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
        // Not a package (#242) — the fix is a sysctl, boot-param, or profile edit.
        "host IPv6 (kernel disabled)" => "\
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0\n\
# if that reports 'unknown oid': remove ipv6.disable=1 from the kernel cmdline\n\
# or: remove the IPv6 entry from the profile's Address line"
            .to_string(),
        // WireGuard binaries (wg, wg-quick) and the package itself all
        // share the same install hint — both binaries ship in the
        // wireguard-tools package on every supported distro.
        "wg" | "wg-quick" | "wireguard-tools" => "\
sudo apt install wireguard-tools  # Debian/Ubuntu\n\
sudo pacman -S wireguard-tools    # Arch\n\
sudo dnf install wireguard-tools  # Fedora"
            .to_string(),
        // OpenVPN ships under its eponymous package everywhere.
        "openvpn" => "\
sudo apt install openvpn  # Debian/Ubuntu\n\
sudo pacman -S openvpn    # Arch\n\
sudo dnf install openvpn  # Fedora"
            .to_string(),
        // Unknown package: best-effort generic hint (the calling code
        // should add a specific case above before relying on this).
        _ => format!(
            "\
sudo apt install {pkg}  # Debian/Ubuntu\n\
sudo pacman -S {pkg}    # Arch\n\
sudo dnf install {pkg}  # Fedora"
        ),
    }
}
