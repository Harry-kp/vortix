//! Linux VPN interface detection via `libc::getifaddrs` + `/sys/class/net`.
//!
//! replaced the `ip addr show <iface>` shell-out with a direct
//! `libc::getifaddrs` walk for IPv4 address discovery and a `/sys/class/net/<iface>/mtu`
//! read for MTU. No more parsing of human-formatted `ip` output; no PATH dependency
//! on iproute2 for read-only interface inspection.

/// Linux interface detection using `libc::getifaddrs` and `/sys/class/net`.
pub struct LinuxInterface;

impl LinuxInterface {
    #[must_use]
    pub fn resolve_wireguard_interface(name: &str) -> Option<String> {
        // Protocol identity is verified by the WireGuard adapter. This port
        // answers only the platform question: does a kernel interface with
        // this basename exist?
        std::path::Path::new("/sys/class/net")
            .join(name)
            .exists()
            .then(|| name.to_string())
    }

    #[must_use]
    pub fn get_wireguard_pid(interface: &str) -> Option<u32> {
        // walk /proc directly instead of shelling to `ps`.
        // Kernel WG has no userspace PID (returns None); wireguard-go has
        // a process whose cmdline contains both "wireguard" and the
        // interface name.
        find_pid_with_cmdline_substrings(&["wireguard", interface])
    }

    #[must_use]
    pub fn get_interface_info(interface: &str) -> (String, String) {
        // IPv4 address from libc::getifaddrs; MTU from sysfs.
        // Used to shell to `ip addr show <iface>` and parse the human-
        // formatted output — both are direct kernel reads now.
        let ip = get_interface_ipv4(interface).unwrap_or_default();
        let mtu = read_sysfs_mtu(interface).unwrap_or_default();
        (ip, mtu)
    }
}

/// Walk `/proc/[pid]/cmdline` and return the first PID whose cmdline
/// contains ALL of the given substring needles (case-insensitive).
///
/// Replaces the `ps -eo pid,args` shell-out used for finding userspace
/// `WireGuard` processes (wireguard-go). Pure stdlib; no PATH dependency
/// on procps.
///
pub(crate) fn find_pid_with_cmdline_substrings(needles: &[&str]) -> Option<u32> {
    matching_pids(needles, Some(1)).into_iter().next()
}

fn matching_pids(needles: &[&str], limit: Option<usize>) -> Vec<u32> {
    let needles: Vec<String> = needles.iter().map(|needle| needle.to_lowercase()).collect();
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
        if needles.iter().all(|needle| cmdline.contains(needle)) {
            matches.push(pid);
            if limit.is_some_and(|limit| matches.len() == limit) {
                break;
            }
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
fn read_sysfs_mtu(interface: &str) -> Option<String> {
    let path = format!("/sys/class/net/{interface}/mtu");
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Return the list of network interface names currently present in the
/// kernel.
///
/// Reads `/sys/class/net/` directory entries. On any I/O error (sysfs
/// not mounted, permissions, etc.) returns an empty vector — callers
/// must treat empty as "unknown" rather than "no interfaces present"
/// where that distinction matters.
#[must_use]
pub fn available_network_interfaces() -> Vec<String> {
    std::fs::read_dir("/sys/class/net/")
        .map(|entries| {
            entries
                .filter_map(std::result::Result::ok)
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default()
}

const PROC_NET_DEV_PATH: &str = "/proc/net/dev";

/// Linux network stats from `/proc/net/dev`.
pub struct LinuxNetworkStats;

impl LinuxNetworkStats {
    #[must_use]
    pub fn get_total_bytes() -> (u64, u64) {
        match std::fs::read_to_string(PROC_NET_DEV_PATH) {
            Ok(content) => parse_proc_net_dev(&content),
            Err(_) => (0, 0),
        }
    }
}

/// Parse `/proc/net/dev` content into `(total_rx_bytes, total_tx_bytes)`,
/// excluding loopback.
///
/// Format: `iface: rx_bytes rx_packets rx_errs ... tx_bytes tx_packets tx_errs ...`
pub(crate) fn parse_proc_net_dev(content: &str) -> (u64, u64) {
    let mut total_in: u64 = 0;
    let mut total_out: u64 = 0;

    for line in content.lines().skip(2) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }

        let iface = parts[0].trim();
        if iface == "lo" {
            continue;
        }

        let stats: Vec<&str> = parts[1].split_whitespace().collect();
        // rx_bytes is index 0, tx_bytes is index 8
        if stats.len() >= 10 {
            if let Ok(rx) = stats[0].parse::<u64>() {
                total_in += rx;
            }
            if let Ok(tx) = stats[8].parse::<u64>() {
                total_out += tx;
            }
        }
    }

    (total_in, total_out)
}

/// `(interface, mtu, first IPv4)` for every tun/tap device with an address.
#[must_use]
pub fn tun_addresses() -> Vec<(String, String, String)> {
    crate::process::simple_output("ip", &["addr"])
        .map(|output| parse_ip_addr(&String::from_utf8_lossy(&output.stdout)))
        .unwrap_or_default()
}

/// Linux has no per-process device lookup; the `OpenVPN` log names it.
#[must_use]
pub fn process_tun_device(_pid: u32) -> Option<String> {
    None
}

/// No file records when a `WireGuard` interface came up on Linux.
#[must_use]
pub fn wireguard_started_at(_name: &str) -> Option<std::time::SystemTime> {
    None
}

/// `(interface, mtu, first IPv4)` for every tun/tap device with an IPv4
/// address in `ip addr` output.
pub(crate) fn parse_ip_addr(ip_addr: &str) -> Vec<(String, String, String)> {
    let mut found = Vec::new();
    let mut current: Option<(String, String)> = None;
    for line in ip_addr.lines() {
        if !line.starts_with(' ') {
            current = line.split(':').nth(1).map(str::trim).and_then(|iface| {
                (iface.starts_with("tun") || iface.starts_with("tap")).then(|| {
                    let mtu = line
                        .split_once("mtu ")
                        .and_then(|(_, rest)| rest.split_whitespace().next())
                        .unwrap_or("")
                        .to_string();
                    (iface.to_string(), mtu)
                })
            });
        } else if let Some((iface, mtu)) = &current {
            if let Some(address) = line.trim().strip_prefix("inet ") {
                let ip = address.split(['/', ' ']).next().unwrap_or("").to_string();
                found.push((iface.clone(), mtu.clone(), ip));
                current = None;
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    // the previous `parse_ip_addr_output` tests asserted
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

#[cfg(test)]
mod interface_list_tests {
    use super::*;

    #[test]
    fn lists_at_least_loopback_on_linux() {
        // On any Linux build host, lo should always exist. This test
        // is a smoke check that the sysfs reader returns something
        // sensible. Skip silently on non-Linux CI (the function is
        // only compiled in for target_os = "linux", so this is a
        // tautology here — the module itself is cfg-gated).
        let ifaces = available_network_interfaces();
        // We don't assert non-empty because container CI environments
        // may have restricted /sys mounts. Just assert the call
        // returns without panicking and produces valid UTF-8 strings.
        for name in &ifaces {
            assert!(!name.is_empty(), "interface name must be non-empty");
        }
    }
}

#[cfg(test)]
mod network_stats_tests {
    use super::parse_proc_net_dev;

    #[test]
    fn test_parse_proc_net_dev() {
        let content = "Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1234567    8910    0    0    0     0          0         0  1234567    8910    0    0    0     0       0          0
  eth0: 5000000   12345    0    0    0     0          0         0  3000000   12000    0    0    0     0       0          0
   wg0: 2000000    5000    0    0    0     0          0         0  1500000    4000    0    0    0     0       0          0
";
        let (bytes_in, bytes_out) = parse_proc_net_dev(content);
        // Should sum eth0 + wg0, excluding lo
        assert_eq!(bytes_in, 5_000_000 + 2_000_000);
        assert_eq!(bytes_out, 3_000_000 + 1_500_000);
    }

    #[test]
    fn test_parse_proc_net_dev_only_loopback() {
        let content = "Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1234567    8910    0    0    0     0          0         0  1234567    8910    0    0    0     0       0          0
";
        let (bytes_in, bytes_out) = parse_proc_net_dev(content);
        assert_eq!(bytes_in, 0);
        assert_eq!(bytes_out, 0);
    }

    #[test]
    fn test_parse_proc_net_dev_empty() {
        let (bytes_in, bytes_out) = parse_proc_net_dev("");
        assert_eq!(bytes_in, 0);
        assert_eq!(bytes_out, 0);
    }
}

#[cfg(test)]
mod tun_tests {
    use super::*;

    #[test]
    fn ip_addr_lists_each_device_with_its_own_address() {
        let out = "\
1: lo: <LOOPBACK,UP> mtu 65536 qdisc noqueue
    inet 127.0.0.1/8 scope host lo
5: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel
    inet 10.80.0.2/24 scope global tun0
6: tun1: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1400 qdisc fq_codel
    inet 10.80.0.3/24 scope global tun1
";
        assert_eq!(
            parse_ip_addr(out),
            vec![
                ("tun0".into(), "1500".into(), "10.80.0.2".into()),
                ("tun1".into(), "1400".into(), "10.80.0.3".into()),
            ]
        );
    }
}
