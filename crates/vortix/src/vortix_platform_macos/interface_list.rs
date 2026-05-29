//! Live kernel interface enumeration via `libc::getifaddrs` (plan
//! multi-connection U11; refactored by plan 002 U5).
//!
//! Used by the killswitch `PersistedState` V2 migration to drop phantom
//! tunnel entries whose interface no longer exists in the kernel after a
//! reboot or interface teardown.
//!
//! Plan 002 U5: replaced the `ifconfig -l` shell-out with a direct
//! `libc::getifaddrs` walk. Same data; faster; no PATH dependency on
//! ifconfig (which most macOS installs have, but consistency with the
//! Linux side's libc-based interface listing matters).

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

#[cfg(test)]
mod tests {
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
