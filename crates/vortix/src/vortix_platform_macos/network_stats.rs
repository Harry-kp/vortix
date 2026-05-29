//! macOS network statistics via `libc::getifaddrs` (BSD `if_data`).
//!
//! Plan 002 U7: replaced `netstat -ib` shell-out + stdout parsing with a
//! direct `getifaddrs` walk. `ifa_data` on macOS points at a `struct
//! if_data` whose `ifi_ibytes` / `ifi_obytes` fields are the same
//! counters `netstat -ib` reports. Behavior parity: counters are the
//! 32-bit wrap-prone variants — same as the prior shell-out's column.
//! Loopback interfaces are skipped to match the old parser's `lo*`
//! filter.

use crate::vortix_core::ports::network_stats::NetworkStats;

/// macOS network stats via `getifaddrs` + BSD `if_data`.
pub struct MacNetworkStats;

impl NetworkStats for MacNetworkStats {
    fn get_total_bytes() -> (u64, u64) {
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
                .map(|p| std::ffi::CStr::from_ptr(p as *const _))
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
mod tests {
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
