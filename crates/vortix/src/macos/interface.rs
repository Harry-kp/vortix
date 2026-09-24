//! macOS VPN interface detection via `libc::getifaddrs` + `/var/run/wireguard` +
//! `libc::proc_listpids` + hand-rolled libproc FFI.
//!
//! Replaced `ifconfig <iface>`, `ps -ax -o pid,command`,
//! and `lsof -t <socket>` shell-outs with direct libc / libproc calls.

use std::path::{Path, PathBuf};

use super::libproc::{self, SocketView};

/// macOS interface detection using libc + /var/run/wireguard/*.name files.
pub struct MacInterface;

impl MacInterface {
    #[must_use]
    pub fn resolve_wireguard_interface(name: &str) -> Option<String> {
        let pid_file =
            PathBuf::from(crate::constants::WIREGUARD_RUN_DIR).join(format!("{name}.name"));
        if pid_file.exists() {
            Some(
                std::fs::read_to_string(&pid_file)
                    .map_or_else(|_| name.to_string(), |s| s.trim().to_string()),
            )
        } else if interface_exists(name) {
            Some(name.to_string())
        } else {
            None
        }
    }

    #[must_use]
    pub fn get_wireguard_pid(interface: &str) -> Option<u32> {
        let sock_path =
            PathBuf::from(crate::constants::WIREGUARD_RUN_DIR).join(format!("{interface}.sock"));

        // primary path is libproc — walk every PID's socket
        // FDs and match the bound unix-socket path against `sock_path`.
        // Replaces the prior `lsof -t <sock_path>` shell-out.
        if let Some(pid) = find_pid_holding_unix_socket(&sock_path) {
            return Some(pid);
        }

        // fallback search via libc::proc_listpids + proc_pidpath
        // (was `ps -ax -o pid,command`). Walks the live PID list and
        // filters by binary path containing "wireguard" + interface name.
        find_pid_with_cmdline_substring("wireguard", Some(interface))
    }

    #[must_use]
    pub fn get_interface_info(interface: &str) -> (String, String) {
        // Per-interface (vs the interface listing):
        // ifconfig <iface> replaced with libc::getifaddrs walk for the
        // named interface. Same data, no PATH dependency.
        let (ip, mtu) = get_interface_addr_and_mtu(interface);
        (ip.unwrap_or_default(), mtu.unwrap_or_default())
    }
}

fn interface_exists(name: &str) -> bool {
    let (address, mtu) = get_interface_addr_and_mtu(name);
    address.is_some() || mtu.is_some()
}

/// Read both IPv4 address and MTU for `interface` from `libc::getifaddrs`.
///
/// Single getifaddrs walk extracts both fields:
///   - IPv4 address: from `ifa_addr` cast to `sockaddr_in`
///   - MTU: from `ifa_data` cast to `if_data` (BSD-specific; macOS-supported)
///
/// On Linux `ifa_data` has a different shape, so this helper is macOS-only;
/// Linux uses `/sys/class/net/<iface>/mtu` instead (see `linux`).
fn get_interface_addr_and_mtu(interface: &str) -> (Option<String>, Option<String>) {
    // SAFETY: standard getifaddrs allocation/free pairing. Returns -1 on
    // error with no allocation done.
    #[allow(unsafe_code)]
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&raw mut ifap) != 0 {
            return (None, None);
        }

        let mut ip: Option<String> = None;
        let mut mtu: Option<String> = None;
        let mut current = ifap;
        while !current.is_null() {
            let entry = &*current;
            if !entry.ifa_name.is_null() {
                let name_cstr = std::ffi::CStr::from_ptr(entry.ifa_name);
                if name_cstr.to_bytes() == interface.as_bytes() {
                    // IPv4 address — match first AF_INET entry.
                    if ip.is_none() && !entry.ifa_addr.is_null() {
                        let addr = &*entry.ifa_addr;
                        if i32::from(addr.sa_family) == libc::AF_INET {
                            // sockaddr → sockaddr_in cast: getifaddrs
                            // returns properly aligned sockaddr_in when
                            // sa_family == AF_INET. Alignment-safe.
                            #[allow(clippy::cast_ptr_alignment)]
                            let sin = entry.ifa_addr.cast::<libc::sockaddr_in>();
                            let bytes = (*sin).sin_addr.s_addr.to_ne_bytes();
                            ip = Some(format!(
                                "{}.{}.{}.{}",
                                bytes[0], bytes[1], bytes[2], bytes[3]
                            ));
                        }
                    }
                    // MTU — `ifa_data` is a pointer to `if_data` on BSD/macOS.
                    // The first AF_LINK entry for each interface populates
                    // `ifa_data`; entries for AF_INET / AF_INET6 typically
                    // have NULL `ifa_data`. We extract from the first
                    // non-null one we encounter.
                    if mtu.is_none() && !entry.ifa_data.is_null() {
                        let data = entry.ifa_data.cast::<libc::if_data>();
                        mtu = Some((*data).ifi_mtu.to_string());
                    }
                    if ip.is_some() && mtu.is_some() {
                        break;
                    }
                }
            }
            current = entry.ifa_next;
        }

        libc::freeifaddrs(ifap);
        (ip, mtu)
    }
}

/// find a process whose binary path contains the given
/// substring (and optionally a second substring). Walks the live process
/// list via `libc::proc_listpids` and inspects each PID's path via
/// `libc::proc_pidpath`.
///
/// Returns the first matching PID, or None. Substring match is
/// case-insensitive — matches the prior `ps` parser's behavior.
pub(crate) fn find_pid_with_cmdline_substring(needle: &str, also: Option<&str>) -> Option<u32> {
    let needles: Vec<&str> = std::iter::once(needle).chain(also).collect();
    matching_pids(&needles, Some(1)).into_iter().next()
}

fn matching_pids(needles: &[&str], limit: Option<usize>) -> Vec<u32> {
    let needles: Vec<String> = needles.iter().map(|needle| needle.to_lowercase()).collect();
    let mut matches = Vec::new();
    for pid in libproc::list_all_pids() {
        let Some(path_lower) = libproc::pid_path(pid).map(|path| path.to_lowercase()) else {
            continue;
        };
        if needles.iter().all(|needle| path_lower.contains(needle)) {
            let Ok(pid) = u32::try_from(pid) else {
                continue;
            };
            matches.push(pid);
            if limit.is_some_and(|limit| matches.len() == limit) {
                break;
            }
        }
    }
    matches
}

/// find the PID with `sock_path` open as a unix domain
/// socket. Walks every PID's socket FDs via `libproc::iter_all_sockets`
/// and matches `unsi_addr.ua_sun.sun_path` (or `unsi_caddr.ua_sun.sun_path`)
/// against the target. Replaces the prior `lsof -t <sock_path>`
/// shell-out.
fn find_pid_holding_unix_socket(sock_path: &Path) -> Option<u32> {
    for (pid, _fd, view) in libproc::iter_all_sockets() {
        let SocketView::Unix { path } = view else {
            continue;
        };
        if path == sock_path {
            return u32::try_from(pid).ok();
        }
    }
    None
}

/// Return the list of network interface names currently visible to the
/// kernel.
///
/// Walks `libc::getifaddrs` and collects unique interface names. On
/// macOS each interface appears once per address family in the
/// `getifaddrs` list (e.g. en0 may appear for `AF_INET` + `AF_INET6` + `AF_LINK`);
/// dedupe via a `HashSet` before returning.
///
/// On any failure (getifaddrs syscall error) returns an empty vector.
#[must_use]
pub fn available_network_interfaces() -> Vec<String> {
    use std::collections::HashSet;

    // SAFETY: libc::getifaddrs writes a *mut *mut ifaddrs into the
    // pointer we pass. Stack-rooted null on entry; on success the
    // kernel allocates a linked list we MUST release via freeifaddrs.
    // Returns 0 on success, -1 on error (no allocation done on error).
    #[allow(unsafe_code)]
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&raw mut ifap) != 0 {
            return Vec::new();
        }

        let mut names: HashSet<String> = HashSet::new();
        let mut current = ifap;
        while !current.is_null() {
            let entry = &*current;
            if !entry.ifa_name.is_null() {
                let name_cstr = std::ffi::CStr::from_ptr(entry.ifa_name);
                if let Ok(name) = name_cstr.to_str() {
                    names.insert(name.to_string());
                }
            }
            current = entry.ifa_next;
        }

        libc::freeifaddrs(ifap);

        let mut result: Vec<String> = names.into_iter().collect();
        result.sort(); // deterministic ordering for tests + diff stability
        result
    }
}

/// macOS network stats via `getifaddrs` + BSD `if_data`.
pub struct MacNetworkStats;

impl MacNetworkStats {
    #[must_use]
    pub fn get_total_bytes() -> (u64, u64) {
        get_total_bytes_via_getifaddrs().unwrap_or((0, 0))
    }
}

/// Walk every interface returned by `getifaddrs` and accumulate
/// `ifi_ibytes` / `ifi_obytes` from each non-loopback `ifa_data`.
///
/// macOS surfaces an entry per address family per interface; only the
/// `AF_LINK` entry carries a non-null `ifa_data`. Filtering by non-null
/// `ifa_data` therefore naturally dedupes — we count each interface once.
fn get_total_bytes_via_getifaddrs() -> Option<(u64, u64)> {
    // SAFETY: standard getifaddrs allocation pairing. Returns -1 on error
    // with no allocation done; we drop the list via freeifaddrs on every
    // exit path.
    #[allow(unsafe_code)]
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&raw mut ifap) != 0 {
            return None;
        }

        let mut total_in: u64 = 0;
        let mut total_out: u64 = 0;
        let mut current = ifap;
        while !current.is_null() {
            let entry = &*current;
            if let Some(name_cstr) = entry
                .ifa_name
                .as_ref()
                .map(|p| std::ffi::CStr::from_ptr(std::ptr::from_ref(p).cast()))
            {
                if !entry.ifa_data.is_null() && !is_loopback(name_cstr.to_bytes()) {
                    let data = entry.ifa_data.cast::<libc::if_data>();
                    total_in += u64::from((*data).ifi_ibytes);
                    total_out += u64::from((*data).ifi_obytes);
                }
            }
            current = entry.ifa_next;
        }

        libc::freeifaddrs(ifap);
        Some((total_in, total_out))
    }
}

fn is_loopback(name: &[u8]) -> bool {
    name.starts_with(b"lo")
}

#[cfg(test)]
mod interface_list_tests {
    use super::*;

    #[test]
    fn lists_at_least_one_interface_on_macos() {
        // On any macOS host, `lo0` is always present. The list also
        // contains en0/en1/etc depending on hardware; we just assert
        // it's non-empty and well-formed.
        let ifaces = available_network_interfaces();
        assert!(!ifaces.is_empty(), "expected at least one interface");
        for name in &ifaces {
            assert!(!name.is_empty(), "interface name must be non-empty");
            assert!(
                !name.chars().any(char::is_whitespace),
                "interface name must not contain whitespace: {name:?}"
            );
        }
    }

    #[test]
    fn dedupes_repeated_interface_entries() {
        // getifaddrs lists each interface once per address family; the
        // returned list must dedupe. Verified indirectly via uniqueness
        // check on a real call.
        let ifaces = available_network_interfaces();
        let unique: std::collections::HashSet<_> = ifaces.iter().collect();
        assert_eq!(
            ifaces.len(),
            unique.len(),
            "available_network_interfaces must return unique names"
        );
    }

    #[test]
    fn loopback_interface_present_on_macos() {
        let ifaces = available_network_interfaces();
        assert!(
            ifaces.iter().any(|n| n == "lo0"),
            "lo0 should always be present on macOS; got: {ifaces:?}"
        );
    }
}

#[cfg(test)]
mod network_stats_tests {
    use super::*;

    #[test]
    fn loopback_filter_matches_old_parser() {
        assert!(is_loopback(b"lo0"));
        assert!(is_loopback(b"lo"));
        assert!(!is_loopback(b"en0"));
        assert!(!is_loopback(b"utun3"));
        assert!(!is_loopback(b"awdl0"));
    }

    #[test]
    fn snapshot_is_monotonic_across_calls() {
        // The counters are u32 wrap-prone but two reads back-to-back on a
        // healthy interface must be non-decreasing. This also exercises the
        // FFI path end-to-end.
        let (a_in, a_out) = MacNetworkStats::get_total_bytes();
        let (b_in, b_out) = MacNetworkStats::get_total_bytes();
        assert!(b_in >= a_in, "ibytes regressed: {a_in} -> {b_in}");
        assert!(b_out >= a_out, "obytes regressed: {a_out} -> {b_out}");
    }
}
