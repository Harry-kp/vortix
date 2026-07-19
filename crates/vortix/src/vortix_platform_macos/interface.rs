//! macOS VPN interface detection via `libc::getifaddrs` + `/var/run/wireguard` +
//! `libc::proc_listpids` + hand-rolled libproc FFI.
//!
//! Replaced `ifconfig <iface>`, `ps -ax -o pid,command`,
//! and `lsof -t <socket>` shell-outs with direct libc / libproc calls.

use crate::vortix_core::ports::interface::Interface;
use crate::vortix_process::simple_output as cmd_output;
use std::path::{Path, PathBuf};

use super::libproc_ffi::{self, SocketView};

const WIREGUARD_RUN_DIR: &str = "/var/run/wireguard";

/// macOS interface detection using libc + /var/run/wireguard/*.name files.
pub struct MacInterface;

impl Interface for MacInterface {
    fn resolve_wireguard_interface(name: &str) -> Option<String> {
        let pid_file = PathBuf::from(WIREGUARD_RUN_DIR).join(format!("{name}.name"));
        if pid_file.exists() {
            Some(
                std::fs::read_to_string(&pid_file)
                    .map_or_else(|_| name.to_string(), |s| s.trim().to_string()),
            )
        } else if check_wg_interface_exists(name) {
            Some(name.to_string())
        } else {
            None
        }
    }

    fn get_wireguard_pid(interface: &str) -> Option<u32> {
        let sock_path = PathBuf::from(WIREGUARD_RUN_DIR).join(format!("{interface}.sock"));

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

    fn get_interface_info(interface: &str) -> (String, String) {
        // Per-interface (vs the interface listing):
        // ifconfig <iface> replaced with libc::getifaddrs walk for the
        // named interface. Same data, no PATH dependency.
        let (ip, mtu) = get_interface_addr_and_mtu(interface);
        (ip.unwrap_or_default(), mtu.unwrap_or_default())
    }
}

fn check_wg_interface_exists(name: &str) -> bool {
    cmd_output("wg", &["show", name, "public-key"]).is_some_and(|o| o.status.success())
}

/// Read both IPv4 address and MTU for `interface` from `libc::getifaddrs`.
///
/// Single getifaddrs walk extracts both fields:
///   - IPv4 address: from `ifa_addr` cast to `sockaddr_in`
///   - MTU: from `ifa_data` cast to `if_data` (BSD-specific; macOS-supported)
///
/// On Linux `ifa_data` has a different shape, so this helper is macOS-only;
/// Linux uses `/sys/class/net/<iface>/mtu` instead (see `vortix_platform_linux`).
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

/// find ALL processes whose binary path contains the given
/// substring. Used by the OVPN tunnel teardown to replace `pkill -f`.
pub(crate) fn find_all_pids_with_cmdline_substring(needle: &str) -> Vec<u32> {
    matching_pids(&[needle], None)
}

fn matching_pids(needles: &[&str], limit: Option<usize>) -> Vec<u32> {
    let needles: Vec<String> = needles.iter().map(|needle| needle.to_lowercase()).collect();
    let mut matches = Vec::new();
    for pid in libproc_ffi::list_all_pids() {
        let Some(path_lower) = libproc_ffi::pid_path(pid).map(|path| path.to_lowercase()) else {
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
/// socket. Walks every PID's socket FDs via `libproc_ffi::iter_all_sockets`
/// and matches `unsi_addr.ua_sun.sun_path` (or `unsi_caddr.ua_sun.sun_path`)
/// against the target. Replaces the prior `lsof -t <sock_path>`
/// shell-out.
fn find_pid_holding_unix_socket(sock_path: &Path) -> Option<u32> {
    for (pid, _fd, view) in libproc_ffi::iter_all_sockets() {
        let SocketView::Unix { path } = view else {
            continue;
        };
        if path == sock_path {
            return u32::try_from(pid).ok();
        }
    }
    None
}
