//! The OS adapters for this build, and small per-OS helpers.

#[cfg(target_os = "linux")]
pub use crate::linux::{
    LinuxDns as Dns, LinuxInterface as Interface, LinuxNetworkStats as NetworkStats,
    LinuxRouteTable as Routes, NftFirewall as Firewall, ProcSocketAudit as SocketAudit,
};
#[cfg(target_os = "macos")]
pub use crate::macos::{
    LsofSocketAudit as SocketAudit, MacDns as Dns, MacInterface as Interface,
    MacNetworkStats as NetworkStats, MacRouteTable as Routes, PfFirewall as Firewall,
};

/// Live network-interface names; empty when enumeration fails, which
/// callers must read as "unknown", not "none present".
#[must_use]
pub fn available_network_interfaces() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        crate::linux::interface_list::available_network_interfaces()
    }
    #[cfg(target_os = "macos")]
    {
        crate::macos::interface_list::available_network_interfaces()
    }
}

pub(crate) mod route_probe {
    //! Shared failure backoff for platform route-table probes.

    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    use crate::process::CommandSpec;

    pub(crate) enum ProbeOutcome {
        BackedOff,
        Success(String),
        Failed {
            consecutive_failures: u32,
            cooldown: Duration,
        },
    }

    struct ProbeBackoff {
        consecutive_failures: u32,
        next_allowed: Instant,
    }

    /// Process-wide state for one platform route probe.
    pub(crate) struct RouteProbe {
        state: OnceLock<Mutex<ProbeBackoff>>,
    }

    impl RouteProbe {
        pub(crate) const fn new() -> Self {
            Self {
                state: OnceLock::new(),
            }
        }

        pub(crate) fn run(&self, spec: CommandSpec) -> ProbeOutcome {
            let state = self.state.get_or_init(|| {
                Mutex::new(ProbeBackoff {
                    consecutive_failures: 0,
                    next_allowed: Instant::now(),
                })
            });

            {
                let state = state.lock().expect("backoff state mutex poisoned");
                if Instant::now() < state.next_allowed {
                    return ProbeOutcome::BackedOff;
                }
            }

            let result = crate::process::run_to_output(spec);
            let mut state = state.lock().expect("backoff state mutex poisoned");
            if let Ok(output) = result {
                state.consecutive_failures = 0;
                state.next_allowed = Instant::now();
                return ProbeOutcome::Success(String::from_utf8_lossy(&output.stdout).into_owned());
            }

            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            let cooldown = cooldown_for_failures(state.consecutive_failures);
            state.next_allowed = Instant::now() + cooldown;
            ProbeOutcome::Failed {
                consecutive_failures: state.consecutive_failures,
                cooldown,
            }
        }
    }

    fn cooldown_for_failures(failures: u32) -> Duration {
        Duration::from_secs(match failures {
            0..=2 => 0,
            3..=5 => 5,
            6..=10 => 15,
            _ => 60,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn cooldown_ladder_escalates_then_caps() {
            assert_eq!(cooldown_for_failures(0), Duration::ZERO);
            assert_eq!(cooldown_for_failures(2), Duration::ZERO);
            assert_eq!(cooldown_for_failures(3), Duration::from_secs(5));
            assert_eq!(cooldown_for_failures(5), Duration::from_secs(5));
            assert_eq!(cooldown_for_failures(6), Duration::from_secs(15));
            assert_eq!(cooldown_for_failures(10), Duration::from_secs(15));
            assert_eq!(cooldown_for_failures(11), Duration::from_secs(60));
            assert_eq!(cooldown_for_failures(1_000_000), Duration::from_secs(60));
        }
    }
}

/// Directory a confined `wg-quick` is permitted to read configs from, when
/// the platform confines it at all.
///
/// Debian and Ubuntu ship an `AppArmor` profile for wg-quick granting no read
/// access outside `/etc/wireguard`, so a lifecycle copy staged anywhere else
/// is refused by the kernel before wg-quick even runs. The profile's rule is
/// `file rw @{etc_rw}/wireguard/{,**}` — the `{,**}` covers the tree
/// recursively, so Vortix takes its own subdirectory rather than writing
/// beside configs the user manages. Nothing there is ever theirs, so there is
/// no file to avoid clobbering and none of its contents outlive a teardown.
///
/// `None` means the platform does not confine wg-quick and the caller may
/// stage wherever it likes.
pub(crate) fn wireguard_staging_dir() -> Option<&'static std::path::Path> {
    #[cfg(target_os = "linux")] // xtask:allow-platform-cfg: AppArmor confines wg-quick on Linux only
    const STAGING_DIR: Option<&str> = Some("/etc/wireguard/vortix");
    #[cfg(not(target_os = "linux"))] // xtask:allow-platform-cfg: see above
    const STAGING_DIR: Option<&str> = None;

    STAGING_DIR.map(std::path::Path::new)
}

#[cfg(target_os = "linux")]
pub(crate) fn process_group_has_live_members(group_id: u32) -> std::io::Result<Option<bool>> {
    crate::linux::process_identity::process_group_has_live_members(group_id)
}

#[cfg(target_os = "macos")]
#[allow(
    clippy::unnecessary_wraps,
    reason = "matches the Linux platform probe so the process layer stays OS-agnostic"
)]
pub(crate) fn process_group_has_live_members(_group_id: u32) -> std::io::Result<Option<bool>> {
    Ok(None)
}

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

/// The command that shows this platform's Vortix-owned firewall rules, so a
/// reader who is told Vortix cannot confirm them can look for themselves.
#[cfg(target_os = "macos")]
#[must_use]
pub fn firewall_inspect_hint() -> &'static str {
    "sudo pfctl -a com.apple/vortix.killswitch -sr"
}

#[cfg(target_os = "linux")]
#[must_use]
pub fn firewall_inspect_hint() -> &'static str {
    "sudo nft list table inet vortix_killswitch"
}

/// Platform-appropriate install hint for a package.
#[cfg(target_os = "macos")]
#[must_use]
pub fn install_hint(pkg: &str) -> String {
    format!("brew install {pkg}")
}

/// The install command for this machine's package manager.
///
/// Read from `/etc/os-release`: `ID` first, then `ID_LIKE`, so derivatives
/// resolve to the family they are built on -- `CachyOS` and `EndeavourOS` report
/// `ID_LIKE=arch`, Nobara reports `fedora`, Mint reports `debian`. A distro
/// that matches nothing falls back to listing every family, which is what
/// this function used to print unconditionally.
#[cfg(target_os = "linux")]
fn install_command(pkg: &str) -> Option<String> {
    let release = std::fs::read_to_string("/etc/os-release").ok()?;
    let field = |key: &str| -> Option<String> {
        release.lines().find_map(|line| {
            let value = line.strip_prefix(key)?.strip_prefix('=')?;
            Some(value.trim_matches('"').to_lowercase())
        })
    };
    let ids = [field("ID"), field("ID_LIKE")];
    let families = ids.iter().flatten().flat_map(|v| {
        v.split_whitespace()
            .map(std::borrow::ToOwned::to_owned)
            .collect::<Vec<_>>()
    });
    for family in families {
        match family.as_str() {
            "debian" | "ubuntu" => return Some(format!("sudo apt install {pkg}")),
            "arch" | "archlinux" | "cachyos" | "manjaro" => {
                return Some(format!("sudo pacman -S {pkg}"))
            }
            "fedora" | "rhel" | "centos" => return Some(format!("sudo dnf install {pkg}")),
            _ => {}
        }
    }
    None
}

#[cfg(target_os = "linux")]
#[must_use]
pub fn install_hint(pkg: &str) -> String {
    // A package whose name differs per family, or which is not a package at
    // all, keeps its hand-written block below.
    let uniform = matches!(pkg, "wg" | "wg-quick" | "wireguard-tools" | "openvpn");
    if uniform {
        let package = if pkg == "openvpn" {
            "openvpn"
        } else {
            "wireguard-tools"
        };
        if let Some(command) = install_command(package) {
            return command;
        }
    }
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

/// Check if required binaries are available for a given protocol.
///
/// Shared between TUI and CLI so both surfaces refuse the same
/// missing-dep set (and run the same `OpenVPN` 2.4+ probe — older
/// builds silently drop `--pull-filter`, breaking multi-tunnel DNS
/// scoping).
#[must_use]
pub fn check_dependencies(
    protocol: crate::profile::ProtocolKind,
    config_path: &std::path::Path,
) -> Vec<String> {
    let mut missing = Vec::new();
    match protocol {
        crate::profile::ProtocolKind::WireGuard => {
            // Both `wg` and `wg-quick` ship in the wireguard-tools
            // package on every supported distro — report them under
            // a single label so the install hint isn't duplicated.
            if !crate::utils::binary_exists("wg-quick") || !crate::utils::binary_exists("wg") {
                missing.push("wireguard-tools".to_string());
            }
            // On Linux, wg-quick uses `resolvconf` to set DNS when the
            // config contains a DNS directive. Two escape hatches:
            //   1. systemd-resolved + working `resolvectl` →
            //      `WgTunnel::up` takes over per-link DNS via
            //      `resolvectl` itself; no resolvconf shim needed.
            //   2. A working `resolvconf` (openresolv on non-resolved
            //      hosts; systemd-resolvconf shim on resolved hosts).
            //
            // Otherwise emit the missing-dep label with a hint at
            // which shim the user actually needs.
            #[cfg(target_os = "linux")]
            // xtask:allow-platform-cfg: the gates below are Linux-only
            let parsed = std::fs::read_to_string(config_path)
                .ok()
                .and_then(|text| crate::wireguard::parser::parse_wg_conf(&text).ok());
            #[cfg(target_os = "linux")]
            // xtask:allow-platform-cfg: resolvconf check is Linux-only DNS plumbing
            if let Some(label) = wireguard_dns_missing_dep(WireguardDnsGateInputs {
                has_dns_directive: parsed
                    .as_ref()
                    .is_some_and(crate::wireguard::parser::WgParsedProfile::has_dns),
                resolvectl_path_available: crate::utils::use_resolvectl_path(),
                resolvconf_works: crate::utils::resolvconf_works(),
                is_systemd_resolved: crate::utils::is_systemd_resolved(),
            }) {
                missing.push(label);
            }
            #[cfg(target_os = "linux")]
            // xtask:allow-platform-cfg: /proc sysctl gate is Linux-only (issue #242)
            if let Some(label) = wireguard_ipv6_missing_dep(
                parsed
                    .as_ref()
                    .is_some_and(crate::wireguard::parser::WgParsedProfile::has_ipv6_address),
                crate::utils::host_ipv6_disabled,
            ) {
                missing.push(label);
            }
            #[cfg(not(target_os = "linux"))]
            let _ = config_path; // suppress unused warning on non-Linux
        }
        crate::profile::ProtocolKind::OpenVpn => {
            if crate::utils::binary_exists("openvpn") {
                // Assert OpenVPN ≥ 2.4 so `--pull-filter` (multi-tunnel
                // DNS scoping) is available. Older builds silently
                // ignore the flag and leak pushed DNS into the primary
                // tunnel's resolver. Unparseable probe = fail-open with
                // a tracing warning so vendor-patched or sandboxed
                // environments aren't blocked.
                use crate::openvpn::version::OvpnVersionProbe;
                match crate::openvpn::version::probe_openvpn_version() {
                    OvpnVersionProbe::Parsed(v) if v.supports_multi_tunnel_dns() => {}
                    OvpnVersionProbe::Parsed(v) => {
                        missing.push(format!(
                            "openvpn 2.4+ required for multi-tunnel DNS scoping (found {v})"
                        ));
                    }
                    OvpnVersionProbe::HelpFallbackOk => {}
                    OvpnVersionProbe::Unparseable => {
                        tracing::warn!(
                            target: "vortix::platform",
                            "openvpn version could not be determined; \
                             multi-tunnel DNS scoping may not work if the \
                             installed binary is older than 2.4"
                        );
                    }
                }
            } else {
                missing.push("openvpn".to_string());
            }
        }
    }
    missing
}

/// Inputs to the `WireGuard` DNS-shim missing-dep decision. Wrapping the
/// four booleans in a struct keeps the call-site readable (named fields)
/// and dodges the `fn_params_excessive_bools` lint while staying purely
/// declarative — no behavior moves into the struct itself.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_excessive_bools)] // intentional flag record; mirrors TunnelCapabilities
#[cfg(target_os = "linux")] // xtask:allow-platform-cfg: WG DNS-shim gate is Linux-only
pub(crate) struct WireguardDnsGateInputs {
    pub has_dns_directive: bool,
    pub resolvectl_path_available: bool,
    pub resolvconf_works: bool,
    pub is_systemd_resolved: bool,
}

/// Pure decision logic for the `WireGuard` DNS-shim missing-dep label on Linux.
///
/// Returns `Some(label)` when the user must install a DNS-management shim,
/// `None` when the connect can proceed. Split out so the four-quadrant
/// gate can be unit-tested without depending on host state (each input
/// helper — `is_systemd_resolved`, `resolvconf_works`, `resolvectl_works`
/// — probes real OS state and would make these tests host-dependent).
#[must_use]
#[cfg(target_os = "linux")] // xtask:allow-platform-cfg: gate decision is Linux-only DNS plumbing
pub(crate) fn wireguard_dns_missing_dep(inputs: WireguardDnsGateInputs) -> Option<String> {
    if !inputs.has_dns_directive {
        return None;
    }
    if inputs.resolvectl_path_available {
        return None;
    }
    if inputs.resolvconf_works {
        return None;
    }
    Some(
        if inputs.is_systemd_resolved {
            "resolvconf (systemd)"
        } else {
            "resolvconf"
        }
        .to_string(),
    )
}

/// Pure decision logic for the host-IPv6 pre-flight gate on Linux (#242).
///
/// `wg-quick` runs `ip -6 address add` for each IPv6 entry on the
/// profile's `Address =` line, which aborts the whole bring-up when
/// kernel IPv6 is disabled. Refuse up front instead of surfacing raw
/// wg-quick stderr; never silently strip the user's IPv6 entry.
///
/// The host probe is a closure so its `/proc` reads only happen for
/// profiles that actually declare an IPv6 address.
#[must_use]
#[cfg(target_os = "linux")] // xtask:allow-platform-cfg: gate decision is Linux-only (issue #242)
pub(crate) fn wireguard_ipv6_missing_dep(
    profile_has_ipv6_address: bool,
    host_ipv6_disabled: impl FnOnce() -> bool,
) -> Option<String> {
    (profile_has_ipv6_address && host_ipv6_disabled())
        .then(|| "host IPv6 (kernel disabled)".to_string())
}

#[cfg(all(test, target_os = "linux"))]
mod dns_gate_tests {
    use super::{wireguard_dns_missing_dep, WireguardDnsGateInputs};

    #[allow(clippy::fn_params_excessive_bools)] // test fixture mirrors the WireguardDnsGateInputs shape
    fn inputs(
        has_dns_directive: bool,
        resolvectl_path_available: bool,
        resolvconf_works: bool,
        is_systemd_resolved: bool,
    ) -> WireguardDnsGateInputs {
        WireguardDnsGateInputs {
            has_dns_directive,
            resolvectl_path_available,
            resolvconf_works,
            is_systemd_resolved,
        }
    }

    #[test]
    fn no_dns_directive_returns_none_regardless_of_host_state() {
        // Every host-state combination with `has_dns = false` must return None.
        for resolvectl in [false, true] {
            for resolvconf in [false, true] {
                for resolved in [false, true] {
                    assert_eq!(
                        wireguard_dns_missing_dep(inputs(false, resolvectl, resolvconf, resolved)),
                        None,
                        "has_dns=false resolvectl={resolvectl} resolvconf={resolvconf} resolved={resolved}"
                    );
                }
            }
        }
    }

    #[test]
    fn resolved_with_resolvectl_returns_none() {
        // The headline behaviour change: a resolved host with a working
        // resolvectl no longer needs a resolvconf shim, even when the
        // .conf carries `DNS = ...`.
        assert_eq!(
            wireguard_dns_missing_dep(inputs(true, true, false, true)),
            None
        );
    }

    #[test]
    fn resolved_without_resolvectl_falls_back_to_systemd_label() {
        // Edge case: resolved is detected but resolvectl probe fails
        // (service crashed, broken systemd install). The user genuinely
        // needs the `systemd-resolvconf` shim; emit the resolved-flavoured
        // missing-dep label.
        assert_eq!(
            wireguard_dns_missing_dep(inputs(true, false, false, true)),
            Some("resolvconf (systemd)".to_string())
        );
    }

    #[test]
    fn non_resolved_without_resolvconf_returns_plain_label() {
        // Classic missing-resolvconf on a non-resolved Linux host.
        assert_eq!(
            wireguard_dns_missing_dep(inputs(true, false, false, false)),
            Some("resolvconf".to_string())
        );
    }

    #[test]
    fn non_resolved_with_resolvconf_returns_none() {
        // Ubuntu / Debian-shaped happy path: resolvconf is installed and
        // the host doesn't use systemd-resolved. Unchanged from today.
        assert_eq!(
            wireguard_dns_missing_dep(inputs(true, false, true, false)),
            None
        );
    }

    #[test]
    fn resolved_with_both_paths_prefers_resolvectl_over_resolvconf() {
        // Belt-and-braces: even if resolvconf is also installed, the
        // resolvectl path takes precedence. This avoids double-management
        // surprises and matches the WgTunnel::up wiring (which always
        // uses resolvectl when use_resolvectl_path() is true).
        assert_eq!(
            wireguard_dns_missing_dep(inputs(true, true, true, true)),
            None
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod ipv6_gate_tests {
    use super::wireguard_ipv6_missing_dep;

    #[test]
    fn fires_only_when_profile_declares_v6_and_host_disabled() {
        assert_eq!(
            wireguard_ipv6_missing_dep(true, || true),
            Some("host IPv6 (kernel disabled)".to_string())
        );
    }

    #[test]
    fn silent_when_profile_is_v4_only() {
        assert_eq!(wireguard_ipv6_missing_dep(false, || true), None);
    }

    #[test]
    fn silent_when_host_ipv6_enabled() {
        assert_eq!(wireguard_ipv6_missing_dep(true, || false), None);
    }

    #[test]
    fn silent_when_neither() {
        assert_eq!(wireguard_ipv6_missing_dep(false, || false), None);
    }

    #[test]
    fn host_probe_not_evaluated_for_v4_only_profiles() {
        let called = std::cell::Cell::new(false);
        let result = wireguard_ipv6_missing_dep(false, || {
            called.set(true);
            true
        });
        assert_eq!(result, None);
        assert!(!called.get(), "host probe ran for a v4-only profile");
    }

    #[test]
    fn label_maps_to_the_sysctl_hint_not_the_generic_package_fallback() {
        // The label lives here; the hint arm lives in platform::install_hint.
        // Pin the pair so a rename on either side fails loudly instead of
        // rendering "sudo apt install host IPv6 (kernel disabled)".
        let label = wireguard_ipv6_missing_dep(true, || true).unwrap();
        let hint = crate::platform::install_hint(&label);
        assert!(
            hint.contains("sysctl"),
            "hint fell back to generic package install: {hint}"
        );
    }
}

/// Result of probing the route used for public-internet traffic.
///
/// `NoDefaultRoute` is an observed kernel state. `ProbeFailed` means the
/// observation is unknown and consumers must retain their last known route
/// instead of interpreting the failure as a topology change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum DefaultRouteObservation {
    Interface(String),
    NoDefaultRoute,
    #[default]
    ProbeFailed,
}

impl DefaultRouteObservation {
    #[must_use]
    pub fn interface(&self) -> Option<&str> {
        match self {
            Self::Interface(interface) => Some(interface),
            Self::NoDefaultRoute | Self::ProbeFailed => None,
        }
    }
}

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The IP transport protocol of a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum SocketProtocol {
    Tcp,
    Udp,
    Tcp6,
    Udp6,
}

impl std::fmt::Display for SocketProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Tcp6 => "tcp6",
            Self::Udp6 => "udp6",
        };
        f.write_str(s)
    }
}

/// One socket as observed at snapshot time.
///
/// The vortix engine and audit CLI consume `Vec<SocketSnapshot>` from
/// the `SocketAudit::snapshot()` call. The shape is intentionally
/// simple — no continuous streaming, no diffing; future requirements
/// can extend the port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketSnapshot {
    /// Owning process id (or `0` when the impl can't resolve it,
    /// e.g. without root on Linux or when the socket belongs to
    /// another user).
    pub pid: u32,
    /// `comm` (Linux) or process name (macOS). Empty string when
    /// unknown.
    pub command: String,
    /// Local endpoint.
    pub local: SocketAddr,
    /// Remote endpoint. `None` for listening sockets.
    pub remote: Option<SocketAddr>,
    /// Transport protocol.
    pub protocol: SocketProtocol,
    /// Routing interface (e.g. `en0`, `wg0`, `tun0`). `None` when the
    /// platform impl can't resolve it for this socket; the audit CLI
    /// renders this as a useful hint for "is this traffic going
    /// through the tunnel?"
    pub interface: Option<String>,
}

/// Errors produced by a socket-audit snapshot.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SocketAuditError {
    /// The platform impl is a stub (Windows in v0.3.0). The CLI
    /// surfaces this as "socket audit not available on this platform"
    /// without a panic.
    #[error("socket audit is not available on this platform")]
    Unsupported,
    /// The underlying tool (`ps`, `lsof`, file read) failed.
    #[error("socket audit command failed: {0}")]
    CommandFailed(String),
    /// Parsing the tool's output failed midway. The CLI surfaces this
    /// with the parser's diagnostic so a future contributor can
    /// reproduce.
    #[error("socket audit parse failed: {0}")]
    ParseFailed(String),
    /// I/O error reading `/proc` or running a command.
    #[error("socket audit I/O: {0}")]
    Io(#[from] std::io::Error),
}

/// Result alias for socket-audit operations.
pub type SocketAuditResult<T> = std::result::Result<T, SocketAuditError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_protocol_round_trips_through_json() {
        for proto in [
            SocketProtocol::Tcp,
            SocketProtocol::Udp,
            SocketProtocol::Tcp6,
            SocketProtocol::Udp6,
        ] {
            let json = serde_json::to_string(&proto).unwrap();
            let back: SocketProtocol = serde_json::from_str(&json).unwrap();
            assert_eq!(proto, back);
        }
    }

    #[test]
    fn socket_protocol_display() {
        assert_eq!(format!("{}", SocketProtocol::Tcp), "tcp");
        assert_eq!(format!("{}", SocketProtocol::Udp6), "udp6");
    }

    #[test]
    fn socket_snapshot_round_trips() {
        let snap = SocketSnapshot {
            pid: 1234,
            command: "curl".into(),
            local: "127.0.0.1:54321".parse().unwrap(),
            remote: Some("8.8.8.8:443".parse().unwrap()),
            protocol: SocketProtocol::Tcp,
            interface: Some("en0".into()),
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: SocketSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn listening_socket_has_no_remote() {
        let snap = SocketSnapshot {
            pid: 5678,
            command: "nc".into(),
            local: "0.0.0.0:8080".parse().unwrap(),
            remote: None,
            protocol: SocketProtocol::Tcp,
            interface: None,
        };
        let json = serde_json::to_string(&snap).unwrap();
        // Listening sockets serialize remote as null
        assert!(json.contains("\"remote\":null"));
    }
}
