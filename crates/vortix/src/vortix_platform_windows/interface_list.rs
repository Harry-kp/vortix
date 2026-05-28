//! Windows stub for `available_network_interfaces` (plan
//! multi-connection U11). Real enumeration (via `GetAdaptersAddresses`
//! or `netsh`) lands when Windows support is implemented.

/// Stub — returns an empty list on Windows. The killswitch V2 migration
/// treats an empty list as "unknown" and skips phantom-interface
/// filtering, so persisted state is preserved as-is on Windows until a
/// real implementation lands.
#[must_use]
pub fn available_network_interfaces() -> Vec<String> {
    Vec::new()
}
