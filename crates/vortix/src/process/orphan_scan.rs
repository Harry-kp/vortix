//! Startup orphan-daemon scan.
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

/// Names of binaries we treat as candidate orphan VPN daemons. A process
/// counts only when its arguments name a Vortix path: `openvpn` always gets
/// `--writepid <config dir>/run/…`, `wg-quick` a Vortix-staged config.
/// `wireguard-go` carries no path, so Vortix's own is known by its receipt.
const ORPHAN_BINARIES: &[&str] = &["wg-quick", "openvpn"];

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
pub fn scan_orphans(vortix_paths: &[&std::path::Path]) -> Vec<OrphanProcess> {
    if cfg!(not(unix)) {
        return Vec::new();
    }

    let Ok(output) = Command::new("ps").args(["-eo", "pid=,args="]).output() else {
        return Vec::new();
    };

    if !output.status.success() {
        return Vec::new();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_ps_output(&stdout, vortix_paths)
}

/// Drop scanned processes whose PID is tracked by a live vortix session
/// (e.g. an `openvpn --daemon` recorded in a profile's `run/<name>.pid`).
/// Without this filter every vortix invocation flags its own active
/// tunnel as an orphan — the daemon reparents to init, so a bare process
/// scan cannot tell "mine" from "leftover".
#[must_use]
pub fn filter_untracked(orphans: Vec<OrphanProcess>, tracked_pids: &[u32]) -> Vec<OrphanProcess> {
    orphans
        .into_iter()
        .filter(|o| !tracked_pids.contains(&o.pid))
        .collect()
}

fn parse_ps_output(stdout: &str, vortix_paths: &[&std::path::Path]) -> Vec<OrphanProcess> {
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
        let Some(args) = parts.next() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        // The program may be a path like `/usr/sbin/openvpn`; match on base name.
        let program = args.split_whitespace().next().unwrap_or("");
        let base = program
            .rsplit('/')
            .next()
            .unwrap_or("")
            .trim_start_matches('-');
        let from_vortix = vortix_paths
            .iter()
            .any(|path| args.contains(path.to_string_lossy().as_ref()));
        if ORPHAN_BINARIES.contains(&base) && from_vortix {
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
        assert_eq!(parse_ps_output("", &[]), Vec::new());
    }

    #[test]
    fn parses_simple_ps_format() {
        let input = "  123 wg-quick up /v/wg0.conf\n  456 openvpn --writepid /v/run/a.pid\n  789 firefox /v\n";
        let got = parse_ps_output(input, &[std::path::Path::new("/v")]);
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
        let input = " 1001 /usr/sbin/openvpn --writepid /v/run/a.pid\n 1002 /usr/bin/wg-quick up /v/wg0.conf\n";
        let got = parse_ps_output(input, &[std::path::Path::new("/v")]);
        assert_eq!(
            got,
            vec![
                OrphanProcess {
                    pid: 1001,
                    command: "openvpn".into()
                },
                OrphanProcess {
                    pid: 1002,
                    command: "wg-quick".into()
                },
            ]
        );
    }

    #[test]
    fn skips_unrelated_processes() {
        let input = "1 init\n2 kthreadd\n3 ssh-agent\n4 zsh\n";
        assert_eq!(parse_ps_output(input, &[]), Vec::new());
    }

    #[test]
    fn skips_malformed_lines() {
        let input = "  not-a-pid wg-quick /v\n   \n  555 openvpn /v/run/a.pid\n";
        let got = parse_ps_output(input, &[std::path::Path::new("/v")]);
        assert_eq!(
            got,
            vec![OrphanProcess {
                pid: 555,
                command: "openvpn".into()
            }]
        );
    }

    /// A user's own `OpenVPN` server or the `NetworkManager` client is not a
    /// leftover from a Vortix crash, and must not be flagged for `kill`.
    #[test]
    fn only_processes_started_from_vortix_paths_are_candidates() {
        let marker = std::path::Path::new("/home/u/.config/vortix");
        let input = " 10 /usr/sbin/openvpn --config /etc/openvpn/server.conf --daemon\n\
                     11 /usr/sbin/openvpn --config /home/u/.config/vortix/profiles/corp.ovpn --writepid /home/u/.config/vortix/run/a.pid\n\
                     12 wireguard-go utun\n";
        assert_eq!(
            parse_ps_output(input, &[marker]),
            vec![OrphanProcess {
                pid: 11,
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
        let _ = scan_orphans(&[]);
    }

    fn orphan(pid: u32) -> OrphanProcess {
        OrphanProcess {
            pid,
            command: "openvpn".into(),
        }
    }

    #[test]
    fn filter_untracked_drops_tracked_pids() {
        let got = filter_untracked(vec![orphan(100), orphan(200), orphan(300)], &[200]);
        assert_eq!(got, vec![orphan(100), orphan(300)]);
    }

    #[test]
    fn filter_untracked_keeps_all_when_nothing_tracked() {
        let got = filter_untracked(vec![orphan(100)], &[]);
        assert_eq!(got, vec![orphan(100)]);
    }

    #[test]
    fn filter_untracked_empty_when_all_tracked() {
        let got = filter_untracked(vec![orphan(100), orphan(200)], &[100, 200]);
        assert_eq!(got, Vec::new());
    }
}
