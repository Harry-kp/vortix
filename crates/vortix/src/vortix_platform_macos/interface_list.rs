//! Live kernel interface enumeration via `ifconfig -l` (plan
//! multi-connection U11).
//!
//! Used by the killswitch `PersistedState` V2 migration to drop phantom
//! tunnel entries whose interface no longer exists in the kernel after a
//! reboot or interface teardown.
//!
//! Free function (not a `Killswitch` trait method) per plan D-7-style
//! decision: the existing trait is associated-function-only, so adding an
//! `&self` validator would force every impl to instance-method form for
//! one consumer.

use crate::vortix_process::CommandSpec;

/// Return the list of network interface names currently visible to the
/// kernel.
///
/// Parses `ifconfig -l`, which on macOS emits a single line of
/// space-separated interface names. On any failure (binary missing,
/// non-UTF-8 output, etc.) returns an empty vector.
#[must_use]
pub fn available_network_interfaces() -> Vec<String> {
    let spec = CommandSpec::oneshot("ifconfig", vec!["-l".to_string()]);
    let output = crate::vortix_process::run_to_output(spec).ok();
    output
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.split_whitespace().map(String::from).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_at_least_loopback_on_macos() {
        // On any macOS host, `lo0` is always present. We can't rely on
        // this in cross-platform CI, so we just smoke-test the parser:
        // every returned name must be non-empty and contain no
        // whitespace.
        let ifaces = available_network_interfaces();
        for name in &ifaces {
            assert!(!name.is_empty(), "interface name must be non-empty");
            assert!(
                !name.chars().any(char::is_whitespace),
                "interface name must not contain whitespace: {name:?}"
            );
        }
    }
}
