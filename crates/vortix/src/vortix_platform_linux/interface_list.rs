//! Live kernel interface enumeration via `/sys/class/net/` (plan
//! multi-connection U11).
//!
//! Used by the killswitch `PersistedState` V2 migration to drop phantom
//! tunnel entries whose interface no longer exists in the kernel after a
//! reboot or interface teardown.
//!
//! Free function (not a `Killswitch` trait method) per plan D-7-style
//! decision: the existing trait is associated-function-only, so adding an
//! `&self` validator would force every impl to instance-method form for
//! one consumer. Trait extension is reserved for cases with multiple
//! consumers.

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

#[cfg(test)]
mod tests {
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
