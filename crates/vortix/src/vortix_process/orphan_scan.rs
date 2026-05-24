//! Startup orphan-daemon scan (plan 008 U5).
//!
//! When vortix starts, check for leftover `wg-quick`, `openvpn`, or
//! `wireguard-go` processes that might be orphans from a previous
//! crashed vortix run. Warn-only — no automatic adoption or killing.
//! The user follows up with `sudo kill <pid>` or
//! `sudo vortix down --force`.
//!
//! Implementation notes:
//! - Pulls process list via `ps -eo pid,comm` (Unix). Windows path is
//!   a no-op for v0.3.0 since this scenario is Unix-specific.
//! - Does not use the global `CommandRunner` so it works before main's
//!   runtime initialisation. Falls through silently if `ps` is missing
//!   or fails — orphan scan is best-effort observability, not load-
//!   bearing.
//! - Returns the list so callers can choose how to surface it (stderr
//!   line, journal event, etc.).

use std::process::Command;

/// Names of binaries we treat as candidate orphan VPN daemons.
const ORPHAN_BINARIES: &[&str] = &["wg-quick", "openvpn", "wireguard-go"];

/// One process matched by [`scan_orphans`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanProcess {
    /// OS process id.
    pub pid: u32,
    /// Command name (`comm`-style — base name, no args).
    pub command: String,
}

/// Scan the OS process list for likely orphan VPN daemons.
///
/// Returns an empty list when:
/// - The platform isn't Unix
/// - `ps` is missing or fails
/// - No matching processes exist
///
/// Never panics. Callers should treat the result as advisory.
#[must_use]
pub fn scan_orphans() -> Vec<OrphanProcess> {
    if cfg!(not(unix)) {
        return Vec::new();
    }

    let Ok(output) = Command::new("ps").args(["-eo", "pid=,comm="]).output() else {
        return Vec::new();
    };

    if !output.status.success() {
        return Vec::new();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_ps_output(&stdout)
}

fn parse_ps_output(stdout: &str) -> Vec<OrphanProcess> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let Some(pid_str) = parts.next() else {
            continue;
        };
        let Some(comm_str) = parts.next() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        // `comm` may be a path like `/usr/sbin/openvpn`; match on base name.
        let base = comm_str
            .trim()
            .rsplit('/')
            .next()
            .unwrap_or("")
            .trim_start_matches('-');
        if ORPHAN_BINARIES.contains(&base) {
            out.push(OrphanProcess {
                pid,
                command: base.to_string(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_ps_output_returns_empty() {
        assert_eq!(parse_ps_output(""), Vec::new());
    }

    #[test]
    fn parses_simple_ps_format() {
        let input = "  123 wg-quick\n  456 openvpn\n  789 firefox\n";
        let got = parse_ps_output(input);
        assert_eq!(
            got,
            vec![
                OrphanProcess {
                    pid: 123,
                    command: "wg-quick".into()
                },
                OrphanProcess {
                    pid: 456,
                    command: "openvpn".into()
                },
            ]
        );
    }

    #[test]
    fn handles_path_prefixed_commands() {
        let input = " 1001 /usr/sbin/openvpn\n 1002 /opt/wireguard/wireguard-go\n";
        let got = parse_ps_output(input);
        assert_eq!(
            got,
            vec![
                OrphanProcess {
                    pid: 1001,
                    command: "openvpn".into()
                },
                OrphanProcess {
                    pid: 1002,
                    command: "wireguard-go".into()
                },
            ]
        );
    }

    #[test]
    fn skips_unrelated_processes() {
        let input = "1 init\n2 kthreadd\n3 ssh-agent\n4 zsh\n";
        assert_eq!(parse_ps_output(input), Vec::new());
    }

    #[test]
    fn skips_malformed_lines() {
        let input = "  not-a-pid wg-quick\n   \n  555 openvpn\n";
        let got = parse_ps_output(input);
        assert_eq!(
            got,
            vec![OrphanProcess {
                pid: 555,
                command: "openvpn".into()
            }]
        );
    }

    #[test]
    fn scan_orphans_does_not_panic_on_any_platform() {
        // Live OS call. We only assert that it returns *something* —
        // empty Vec is a perfectly valid outcome (no orphans, no `ps`,
        // ps returned an error, etc.). The test's job is to lock in
        // the no-panic contract that main.rs depends on.
        let _ = scan_orphans();
    }
}
