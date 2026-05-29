//! macOS VPN interface detection via `libc::getifaddrs` + `/var/run/wireguard` +
//! `libc::proc_listpids` + hand-rolled libproc FFI.
//!
//! Plan 002 U5/U6/U7: replaced `ifconfig <iface>`, `ps -ax -o pid,command`,
//! and `lsof -t <socket>` shell-outs with direct libc / libproc calls.

use crate::vortix_core::ports::interface::Interface;
use crate::vortix_process::CommandSpec;
use std::path::{Path, PathBuf};

use super::libproc_ffi::{self, SocketView};

const WIREGUARD_RUN_DIR: &str = "/var/run/wireguard";

/// Run a command and return its output.
///
/// No timeout — called from the scanner's background thread, cannot block the UI.
/// All commands here are read-only inspections that run unprivileged.
fn cmd_output(program: &str, args: &[&str]) -> Option<std::process::Output> {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    crate::vortix_process::run_to_output(CommandSpec::oneshot(program, owned)).ok()
}

/// macOS interface detection using libc + /var/run/wireguard/*.name files.
pub struct MacInterface;

impl Interface for MacInterface {
    fn check_wireguard_interface(name: &str) -> bool {
        let pid_file = PathBuf::from(WIREGUARD_RUN_DIR).join(format!("{name}.name"));
        pid_file.exists() || check_wg_interface_exists(name)
    }

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

        // Plan 002 U7: primary path is libproc — walk every PID's socket
        // FDs and match the bound unix-socket path against `sock_path`.
        // Replaces the prior `lsof -t <sock_path>` shell-out.
        if let Some(pid) = find_pid_holding_unix_socket(&sock_path) {
            return Some(pid);
        }

        // Plan 002 U6: fallback search via libc::proc_listpids + proc_pidpath
        // (was `ps -ax -o pid,command`). Walks the live PID list and
        // filters by binary path containing "wireguard" + interface name.
        find_pid_with_cmdline_substring("wireguard", Some(interface))
    }

    fn get_interface_info(interface: &str) -> (String, String) {
        // Plan 002 U6 (per-interface, vs U5's interface listing):
        // ifconfig <iface> replaced with libc::getifaddrs walk for the
        // named interface. Same data, no PATH dependency.
        let ip = get_interface_ipv4(interface).unwrap_or_default();
        let mtu = get_interface_mtu(interface).unwrap_or_default();
        (ip, mtu)
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

fn get_interface_ipv4(interface: &str) -> Option<String> {
    get_interface_addr_and_mtu(interface).0
}

fn get_interface_mtu(interface: &str) -> Option<String> {
    get_interface_addr_and_mtu(interface).1
}

// `PROC_ALL_PIDS` is not re-exported by the libc crate as of 0.2.x —
// define it locally from Apple's <sys/proc_info.h>. Value is `1`.
const PROC_ALL_PIDS: u32 = 1;

/// Plan 002 U6: find a process whose binary path contains the given
/// substring (and optionally a second substring). Walks the live process
/// list via `libc::proc_listpids` and inspects each PID's path via
/// `libc::proc_pidpath`.
///
/// Returns the first matching PID, or None. Substring match is
/// case-insensitive — matches the prior `ps` parser's behavior.
pub(crate) fn find_pid_with_cmdline_substring(needle: &str, also: Option<&str>) -> Option<u32> {
    let pids = list_all_pids()?;
    let needle_lower = needle.to_lowercase();
    let also_lower = also.map(str::to_lowercase);
    for pid in pids {
        let Some(path_lower) = pid_path_lower(pid) else {
            continue;
        };
        if !path_lower.contains(&needle_lower) {
            continue;
        }
        if let Some(ref a) = also_lower {
            if !path_lower.contains(a) {
                continue;
            }
        }
        if let Ok(pid_u32) = u32::try_from(pid) {
            return Some(pid_u32);
        }
    }
    None
}

/// Plan 002 U6: find ALL processes whose binary path contains the given
/// substring. Used by the OVPN tunnel teardown to replace `pkill -f`.
pub(crate) fn find_all_pids_with_cmdline_substring(needle: &str) -> Vec<u32> {
    let Some(pids) = list_all_pids() else {
        return Vec::new();
    };
    let needle_lower = needle.to_lowercase();
    let mut matches = Vec::new();
    for pid in pids {
        let Some(path_lower) = pid_path_lower(pid) else {
            continue;
        };
        if path_lower.contains(&needle_lower) {
            if let Ok(pid_u32) = u32::try_from(pid) {
                matches.push(pid_u32);
            }
        }
    }
    matches
}

/// Enumerate every live PID via `libc::proc_listpids(PROC_ALL_PIDS)`.
/// Returns `None` if the syscall fails.
fn list_all_pids() -> Option<Vec<libc::pid_t>> {
    // SAFETY: sizing call (NULL buf) returns required bytes. Then
    // allocate and call again. Returns -1 on error.
    #[allow(unsafe_code)]
    unsafe {
        let needed = libc::proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0);
        // `needed > 0` is the only case yielding usable buffer size info.
        let needed_usize = usize::try_from(needed).ok().filter(|&n| n > 0)?;
        let count_hint = needed_usize / std::mem::size_of::<libc::pid_t>();
        let mut pids: Vec<libc::pid_t> = vec![0; count_hint + 16]; // headroom
        let buf_bytes = pids.len() * std::mem::size_of::<libc::pid_t>();
        let Ok(buf_bytes_i32) = libc::c_int::try_from(buf_bytes) else {
            return None;
        };
        let written = libc::proc_listpids(
            PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr().cast::<libc::c_void>(),
            buf_bytes_i32,
        );
        let written_usize = usize::try_from(written).ok().filter(|&n| n > 0)?;
        let actual = written_usize / std::mem::size_of::<libc::pid_t>();
        pids.truncate(actual);
        Some(pids)
    }
}

/// Read a PID's binary path via `libc::proc_pidpath` and return it
/// lowercased for case-insensitive substring matching.
fn pid_path_lower(pid: libc::pid_t) -> Option<String> {
    if pid <= 0 {
        return None;
    }
    let mut path_buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: proc_pidpath writes into a buffer we provide; we pass the
    // exact buffer size.
    #[allow(unsafe_code)]
    unsafe {
        let Ok(buf_size_u32) = u32::try_from(path_buf.len()) else {
            return None;
        };
        let len = libc::proc_pidpath(
            pid,
            path_buf.as_mut_ptr().cast::<libc::c_void>(),
            buf_size_u32,
        );
        let len_usize = usize::try_from(len).ok().filter(|&n| n > 0)?;
        path_buf.truncate(len_usize);
    }
    String::from_utf8(path_buf).ok().map(|s| s.to_lowercase())
}

/// Plan 002 U7: find the PID with `sock_path` open as a unix domain
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
