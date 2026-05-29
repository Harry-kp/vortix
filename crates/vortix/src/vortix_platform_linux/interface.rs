//! Linux VPN interface detection via `libc::getifaddrs` + `/sys/class/net` + `wg show`.
//!
//! Plan 002 U4: replaced the `ip addr show <iface>` shell-out with a direct
//! `libc::getifaddrs` walk for IPv4 address discovery and a `/sys/class/net/<iface>/mtu`
//! read for MTU. No more parsing of human-formatted `ip` output; no PATH dependency
//! on iproute2 for read-only interface inspection.

use crate::vortix_core::ports::interface::Interface;
use crate::vortix_process::CommandSpec;

/// Run a command and return its output.
///
/// No timeout — called from the scanner's background thread, cannot block the UI.
/// All commands are read-only inspections that run unprivileged.
fn cmd_output(program: &str, args: &[&str]) -> Option<std::process::Output> {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    crate::vortix_process::run_to_output(CommandSpec::oneshot(program, owned)).ok()
}

/// Linux interface detection using `libc::getifaddrs`, `/sys/class/net`, and `wg show`.
pub struct LinuxInterface;

impl Interface for LinuxInterface {
    fn check_wireguard_interface(name: &str) -> bool {
        // On Linux, WireGuard creates interfaces directly (wg0, wg1, etc.)
        // Also check using `wg show` which works for kernel and userspace WireGuard.
        // `wg` stays a shell-out (it's the irreducible WireGuard tool).
        check_wg_interface_exists(name)
    }

    fn resolve_wireguard_interface(name: &str) -> Option<String> {
        // Linux doesn't use /var/run/wireguard/*.name mapping files
        // The interface name IS the WireGuard interface
        if check_wg_interface_exists(name) {
            return Some(name.to_string());
        }

        // Fallback: try to find any active WireGuard interface via `wg show`
        // and match against the profile name
        if let Some(output) = cmd_output("wg", &["show"]) {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.starts_with("interface: ") {
                    let iface = line.trim_start_matches("interface: ").trim();
                    if iface == name {
                        return Some(iface.to_string());
                    }
                }
            }
        }

        None
    }

    fn get_wireguard_pid(interface: &str) -> Option<u32> {
        // Plan 002 U6: walk /proc directly instead of shelling to `ps`.
        // Kernel WG has no userspace PID (returns None); wireguard-go has
        // a process whose cmdline contains both "wireguard" and the
        // interface name.
        find_pid_with_cmdline_substrings(&["wireguard", interface])
    }

    fn get_interface_info(interface: &str) -> (String, String) {
        // Plan 002 U4: IPv4 address from libc::getifaddrs; MTU from sysfs.
        // Used to shell to `ip addr show <iface>` and parse the human-
        // formatted output — both are direct kernel reads now.
        let ip = get_interface_ipv4(interface).unwrap_or_default();
        let mtu = read_sysfs_mtu(interface).unwrap_or_default();
        (ip, mtu)
    }
}

fn check_wg_interface_exists(name: &str) -> bool {
    cmd_output("wg", &["show", name, "public-key"]).is_some_and(|o| o.status.success())
}

/// Walk `/proc/[pid]/cmdline` and return the first PID whose cmdline
/// contains ALL of the given substring needles (case-insensitive).
///
/// Replaces the `ps -eo pid,args` shell-out used for finding userspace
/// `WireGuard` processes (wireguard-go). Pure stdlib; no PATH dependency
/// on procps.
///
/// Plan 002 U6.
pub(crate) fn find_pid_with_cmdline_substrings(needles: &[&str]) -> Option<u32> {
    let needles_lower: Vec<String> = needles.iter().map(|n| n.to_lowercase()).collect();

    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        // Skip non-PID entries (those are numeric).
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        // cmdline is null-separated; replace with spaces for substring
        // matching against the legacy `ps args` format.
        let cmdline_path = format!("/proc/{pid}/cmdline");
        let Ok(raw) = std::fs::read(&cmdline_path) else {
            continue; // PID disappeared between readdir and read — fine
        };
        let cmdline = String::from_utf8_lossy(&raw)
            .replace('\0', " ")
            .to_lowercase();
        if needles_lower.iter().all(|n| cmdline.contains(n)) {
            return Some(pid);
        }
    }
    None
}

/// Walk `/proc/[pid]/cmdline` and return EVERY PID whose cmdline contains
/// the given substring needle (case-insensitive).
///
/// Used by the OVPN tunnel teardown to replace `pkill -f`. Same /proc
/// walk as the single-PID variant but collects all matches.
///
/// Plan 002 U6.
pub(crate) fn find_all_pids_with_cmdline_substring(needle: &str) -> Vec<u32> {
    let needle_lower = needle.to_lowercase();
    let mut matches = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return matches;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let cmdline_path = format!("/proc/{pid}/cmdline");
        let Ok(raw) = std::fs::read(&cmdline_path) else {
            continue;
        };
        let cmdline = String::from_utf8_lossy(&raw)
            .replace('\0', " ")
            .to_lowercase();
        if cmdline.contains(&needle_lower) {
            matches.push(pid);
        }
    }
    matches
}

/// Read the IPv4 address assigned to `interface` from `libc::getifaddrs`.
///
/// Returns the first `AF_INET` address encountered for the named interface,
/// matching the prior parser's behavior (it picked the first `inet ` line
/// out of `ip addr show` output). Returns `None` when the interface has
/// no IPv4 address, doesn't exist, or `getifaddrs` itself fails.
///
/// Plan 002 U4.
fn get_interface_ipv4(interface: &str) -> Option<String> {
    // SAFETY: libc::getifaddrs writes a *mut *mut ifaddrs into `ifap`.
    // We pass a stack-rooted null pointer; on success the kernel
    // allocates a linked list we MUST release via freeifaddrs.
    // Returns 0 on success, -1 on error (no allocation done on error).
    #[allow(unsafe_code)]
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&raw mut ifap) != 0 {
            return None;
        }

        let mut result: Option<String> = None;
        let mut current = ifap;
        while !current.is_null() {
            let entry = &*current;
            if !entry.ifa_name.is_null() {
                let name_cstr = std::ffi::CStr::from_ptr(entry.ifa_name);
                if name_cstr.to_bytes() == interface.as_bytes() && !entry.ifa_addr.is_null() {
                    let addr = &*entry.ifa_addr;
                    if i32::from(addr.sa_family) == libc::AF_INET {
                        // Cast to sockaddr_in; extract the 4-byte network-
                        // order address; format as dotted-decimal.
                        // sockaddr_in alignment (4) is stricter than sockaddr (2 on
                        // Linux), but getifaddrs guarantees alignment when sa_family
                        // is AF_INET. The cast is safe in this branch.
                        #[allow(clippy::cast_ptr_alignment)]
                        let sin = entry.ifa_addr.cast::<libc::sockaddr_in>();
                        let bytes = (*sin).sin_addr.s_addr.to_ne_bytes();
                        result = Some(format!(
                            "{}.{}.{}.{}",
                            bytes[0], bytes[1], bytes[2], bytes[3]
                        ));
                        break;
                    }
                }
            }
            current = entry.ifa_next;
        }

        libc::freeifaddrs(ifap);
        result
    }
}

/// Read the MTU value for `interface` from `/sys/class/net/<iface>/mtu`.
///
/// Returns the MTU as a String (e.g. `"1420"`), trimmed of trailing
/// newline. Returns `None` when the sysfs file is unreadable (interface
/// doesn't exist, no permission, or kernel without sysfs).
///
/// Plan 002 U4.
fn read_sysfs_mtu(interface: &str) -> Option<String> {
    let path = format!("/sys/class/net/{interface}/mtu");
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Plan 002 U4: the previous `parse_ip_addr_output` tests asserted
    // string-parsing of human-formatted `ip addr show` output. That
    // parser is gone; tests are obsolete. The new implementation
    // exercises libc::getifaddrs + sysfs reads, which depend on real
    // kernel state — those go in the integration suite, not here.

    #[test]
    fn get_interface_ipv4_returns_none_for_nonexistent_interface() {
        let result = get_interface_ipv4("vortix-nonexistent-test-iface-xyz");
        assert!(result.is_none());
    }

    #[test]
    fn read_sysfs_mtu_returns_none_for_nonexistent_interface() {
        let result = read_sysfs_mtu("vortix-nonexistent-test-iface-xyz");
        assert!(result.is_none());
    }

    #[test]
    fn get_interface_info_for_loopback_returns_known_values() {
        // `lo` exists in every Linux environment + every macOS env where
        // this file might be compiled. On Linux it's named `lo`; the
        // file is cfg-gated to Linux at the module level so the test
        // assumes Linux.
        let (ip, mtu) = LinuxInterface::get_interface_info("lo");
        assert_eq!(ip, "127.0.0.1", "loopback IPv4 should be 127.0.0.1");
        assert!(
            mtu.parse::<u32>().is_ok(),
            "loopback MTU should be a parseable integer; got: {mtu}"
        );
    }
}
