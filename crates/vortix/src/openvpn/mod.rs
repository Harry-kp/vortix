//! `OpenVPN`.
//!
//! Runs the `openvpn` binary as a custodian-owned foreground child and watches the
//! `--log` file for `Initialization Sequence Completed` to declare the
//! tunnel established.

#![allow(clippy::missing_errors_doc)]

pub mod parser;
pub mod tunnel;

pub(crate) mod management;
pub(crate) mod push;
pub mod routes;

pub use tunnel::{OvpnDnsEvidence, OvpnTunnel};

pub mod version {
    //! `OpenVPN` version detection + the multi-tunnel `--pull-filter` baseline
    //! probe.
    //!
    //! Both the TUI and the CLI need to assert `OpenVPN` ≥ 2.4 before a
    //! connect can proceed — older builds silently
    //! ignore `--pull-filter` and leak pushed DNS into the primary tunnel's
    //! resolver. The probe lives here so both surfaces resolve through the
    //! same `platform::check_dependencies` call site instead of one
    //! running the gate (TUI) and the other skipping it (CLI).

    use std::sync::OnceLock;
    use std::time::Duration;

    use crate::process::{self, CommandSpec};

    /// Semantic version of an installed `openvpn` binary, as reported by
    /// `openvpn --version`. Used by `check_dependencies` to assert the
    /// `--pull-filter` multi-tunnel-DNS-suppression baseline.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub struct OvpnVersion {
        pub major: u32,
        pub minor: u32,
        pub patch: u32,
    }

    impl OvpnVersion {
        /// Minimum `OpenVPN` release supporting `--pull-filter` reliably. Anything
        /// older fails multi-tunnel's DNS-scoping precondition.
        const MIN_MULTI_TUNNEL: Self = Self {
            major: 2,
            minor: 4,
            patch: 0,
        };

        #[must_use]
        pub fn supports_multi_tunnel_dns(self) -> bool {
            self >= Self::MIN_MULTI_TUNNEL
        }
    }

    impl std::fmt::Display for OvpnVersion {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        }
    }

    /// Outcome of probing `openvpn --version`.
    #[derive(Debug, Clone)]
    pub enum OvpnVersionProbe {
        /// Parsed a usable semantic version from `--version` stdout.
        Parsed(OvpnVersion),
        /// `--version` ran but its first line did not contain a parseable
        /// `OpenVPN <X.Y.Z>` token. The `--help` fallback was consulted and
        /// confirmed `--pull-filter` is present.
        HelpFallbackOk,
        /// Both `--version` parsing and the `--help` fallback failed — we cannot
        /// confirm the binary supports `--pull-filter`. Treated as a missing
        /// dependency for multi-tunnel.
        Unparseable,
    }

    /// Parse the `OpenVPN` semantic version from the first line of `openvpn --version`.
    ///
    /// The stable format across `OpenVPN` 2.x / 3.x releases is:
    /// `OpenVPN <major>.<minor>.<patch>[<suffix>] ...`. Vendor-patched builds
    /// occasionally prefix the line (e.g. `Vendor-OpenVPN 2.5.8 ...`) — we scan
    /// for the `OpenVPN ` token rather than anchoring to the start so those still
    /// parse.
    #[must_use]
    pub fn parse_openvpn_version(stdout: &str) -> Option<OvpnVersion> {
        let first_line = stdout.lines().next()?;
        let after = first_line.find("OpenVPN ").map(|i| i + "OpenVPN ".len())?;
        let rest = &first_line[after..];
        let token = rest.split_whitespace().next()?;
        let core: String = token
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        let mut parts = core.split('.');
        let major = parts.next()?.parse::<u32>().ok()?;
        let minor = parts.next()?.parse::<u32>().ok()?;
        let patch = parts.next().unwrap_or("0").parse::<u32>().unwrap_or(0);
        Some(OvpnVersion {
            major,
            minor,
            patch,
        })
    }

    /// Cached outcome of probing `openvpn --version`. The subprocess
    /// runs at most once per process lifetime; subsequent dependency checks reuse
    /// the cached value.
    static OVPN_VERSION_PROBE: OnceLock<OvpnVersionProbe> = OnceLock::new();

    /// Probe the installed `openvpn` for its version, falling back to a `--help`
    /// grep when `--version` is unparseable. Cached for the process lifetime.
    #[must_use]
    pub fn probe_openvpn_version() -> OvpnVersionProbe {
        OVPN_VERSION_PROBE
            .get_or_init(probe_openvpn_version_uncached)
            .clone()
    }

    /// Upper bound on the version-probe subprocess. The probe runs on the UI
    /// thread (via `check_dependencies` on every connect attempt), so a slow or
    /// hung `openvpn --version` would freeze the TUI. 10 seconds is generous
    /// for a first-run launch (Gatekeeper / antivirus / Spotlight on macOS;
    /// cold cache on Linux) and short enough that the user notices a UX bug
    /// rather than concluding vortix is broken. On timeout we fall through to
    /// `Unparseable` (fail-open with a tracing warning) — same as if `openvpn`
    /// returned malformed output.
    const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

    fn probe_openvpn_version_uncached() -> OvpnVersionProbe {
        // xtask:allow-protocol-leak: dependency-version probe runs before any tunnel exists; pre-flight gate
        let version_output = process::run(
            CommandSpec::oneshot("openvpn", vec!["--version".into()]).timeout(PROBE_TIMEOUT),
        );
        if let Ok(out) = version_output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if let Some(v) = parse_openvpn_version(&stdout) {
                return OvpnVersionProbe::Parsed(v);
            }
            let stderr = String::from_utf8_lossy(&out.stderr);
            if let Some(v) = parse_openvpn_version(&stderr) {
                return OvpnVersionProbe::Parsed(v);
            }
        }

        // xtask:allow-protocol-leak: dependency-feature probe runs before any tunnel exists; pre-flight gate
        let help_output = process::run(
            CommandSpec::oneshot("openvpn", vec!["--help".into()]).timeout(PROBE_TIMEOUT),
        );
        if let Ok(out) = help_output {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            );
            if combined.contains("--pull-filter") {
                return OvpnVersionProbe::HelpFallbackOk;
            }
        }

        OvpnVersionProbe::Unparseable
    }

    #[cfg(test)]
    mod tests {
        //! Tests for the `OpenVPN` `--version` parsing and the 2.4+
        //! precondition assertion. The parse helper is pure so we can cover the
        //! happy path, the major-bump edge case, and the malformed-output
        //! fallback without spawning a subprocess.
        use super::{parse_openvpn_version, OvpnVersion};

        #[test]
        fn parses_standard_first_line() {
            let stdout =
            "OpenVPN 2.5.8 [git:release/2.5/...] x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4]";
            let v = parse_openvpn_version(stdout).expect("should parse");
            assert_eq!(
                v,
                OvpnVersion {
                    major: 2,
                    minor: 5,
                    patch: 8
                }
            );
            assert!(v.supports_multi_tunnel_dns());
        }

        #[test]
        fn parses_exact_2_4_0_as_passing() {
            let v = parse_openvpn_version("OpenVPN 2.4.0 amd64-pc-linux").expect("should parse");
            assert_eq!(
                v,
                OvpnVersion {
                    major: 2,
                    minor: 4,
                    patch: 0
                }
            );
            assert!(v.supports_multi_tunnel_dns());
        }

        #[test]
        fn rejects_2_3_18_below_baseline() {
            let v = parse_openvpn_version("OpenVPN 2.3.18 x86_64").expect("should parse");
            assert_eq!(
                v,
                OvpnVersion {
                    major: 2,
                    minor: 3,
                    patch: 18
                }
            );
            assert!(!v.supports_multi_tunnel_dns());
        }

        #[test]
        fn accepts_major_version_3() {
            let v = parse_openvpn_version("OpenVPN 3.0.0 something").expect("should parse");
            assert_eq!(
                v,
                OvpnVersion {
                    major: 3,
                    minor: 0,
                    patch: 0
                }
            );
            assert!(v.supports_multi_tunnel_dns());
        }

        #[test]
        fn handles_vendor_prefix_via_token_scan() {
            let v =
                parse_openvpn_version("vendor-patched OpenVPN 2.6.10 abc").expect("should parse");
            assert_eq!(
                v,
                OvpnVersion {
                    major: 2,
                    minor: 6,
                    patch: 10
                }
            );
        }

        #[test]
        fn strips_trailing_non_numeric_suffix() {
            let v = parse_openvpn_version("OpenVPN 2.5.8-git build").expect("should parse");
            assert_eq!(
                v,
                OvpnVersion {
                    major: 2,
                    minor: 5,
                    patch: 8
                }
            );
        }

        #[test]
        fn returns_none_on_malformed_output() {
            // No `OpenVPN ` marker → unparseable → caller's `--help` fallback fires.
            assert!(parse_openvpn_version("Custom-VPN-Tool 1.2.3").is_none());
            assert!(parse_openvpn_version("").is_none());
            assert!(parse_openvpn_version("OpenVPN notaversion").is_none());
        }

        #[test]
        fn major_minor_only_accepts_with_zero_patch() {
            // Some banners only emit major.minor — accept with implicit .0 patch.
            let v = parse_openvpn_version("OpenVPN 2.5 something").expect("should parse");
            assert_eq!(
                v,
                OvpnVersion {
                    major: 2,
                    minor: 5,
                    patch: 0
                }
            );
        }

        #[test]
        fn ordering_is_semver_like() {
            let a = OvpnVersion {
                major: 2,
                minor: 4,
                patch: 0,
            };
            let b = OvpnVersion {
                major: 2,
                minor: 3,
                patch: 99,
            };
            assert!(a > b);
            let c = OvpnVersion {
                major: 3,
                minor: 0,
                patch: 0,
            };
            assert!(c > a);
        }
    }
}

pub(crate) fn validate_openvpn_artifact_key(key: &str) -> std::io::Result<()> {
    if !key.is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "OpenVPN artifact key contains unsafe characters",
        ))
    }
}

/// `<run_dir>/<key>.<ext>`: the daemon's `pid` and `log` files.
pub(crate) fn run_file(run_dir: &std::path::Path, key: &str, ext: &str) -> std::path::PathBuf {
    run_dir.join(format!("{key}.{ext}"))
}

/// The management socket, named by a digest so the path stays short.
pub(crate) fn management_socket_path(run_dir: &std::path::Path, key: &str) -> std::path::PathBuf {
    use sha2::Digest as _;
    let key = crate::profile::hex(&sha2::Sha256::digest(key.as_bytes())[..16]);
    run_dir.join(format!("{key}.mgmt.sock"))
}

/// The keys a profile's run files may use: its id, then its legacy
/// display-name key when that is unambiguous and different.
fn run_file_keys<'a>(profile_id: &'a str, display_name: &'a str) -> Vec<&'a str> {
    let mut keys = vec![profile_id];
    keys.extend(
        crate::profile::unambiguous_legacy_artifact_key(display_name)
            .filter(|legacy| *legacy != profile_id),
    );
    keys
}

/// The log the daemon is writing: the id-keyed one, else the legacy one.
pub(crate) fn runtime_log_path(
    run_dir: &std::path::Path,
    profile_id: &str,
    display_name: &str,
) -> std::path::PathBuf {
    run_file_keys(profile_id, display_name)
        .into_iter()
        .map(|key| run_file(run_dir, key, "log"))
        .find(|path| path.exists())
        .unwrap_or_else(|| run_file(run_dir, profile_id, "log"))
}

/// Remove a profile's pid, log and management socket under every key it
/// may use. Ambiguous legacy names are left for manual cleanup rather than
/// risk another profile's live daemon.
pub(crate) fn remove_run_files(run_dir: &std::path::Path, profile_id: &str, display_name: &str) {
    for key in run_file_keys(profile_id, display_name) {
        let _ = std::fs::remove_file(run_file(run_dir, key, "pid"));
        let _ = std::fs::remove_file(run_file(run_dir, key, "log"));
        let _ = std::fs::remove_file(management_socket_path(run_dir, key));
    }
}

/// PIDs recorded in `<config_dir>/run/*.pid` — the `OpenVPN` daemons a
/// vortix session is tracking. Reads only the run dir (no profile
/// parsing), so it's cheap enough for the startup orphan scan.
#[must_use]
pub fn tracked_openvpn_pids() -> Vec<u32> {
    let Ok(root) = crate::config::get_config_dir() else {
        return Vec::new();
    };
    let run_dir = root.join(crate::constants::OPENVPN_RUN_DIR);
    let Ok(entries) = std::fs::read_dir(run_dir) else {
        return Vec::new();
    };
    entries
        .filter_map(std::result::Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "pid"))
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .filter_map(|content| content.trim().parse::<u32>().ok())
        .collect()
}

/// Remove a profile's run files from the config directory's run dir.
pub fn cleanup_openvpn_run_files_compat(profile_id: &str, legacy_display_name: &str) {
    if let Ok(root) = crate::config::get_config_dir() {
        let run_dir = root.join(crate::constants::OPENVPN_RUN_DIR);
        remove_run_files(&run_dir, profile_id, legacy_display_name);
    }
}

/// Scan the `OpenVPN` auth directory and delete any leftover transient
/// `<safe>.scrv1.auth` credentials bundle.
///
/// The bundle is a 3-line `user\npass\notp\n` file the submit handler
/// writes for the protocol layer to consume at the start of a
/// static-challenge connect. The protocol layer deletes the file
/// immediately on read; if it's still on disk at vortix startup,
/// something crashed mid-connect and the file is now an orphaned
/// plaintext OTP that should never persist. The OTP would also be
/// stale (TOTP expires in 30s), so the only correct cleanup is
/// deletion — the user re-enters credentials on the next connect.
///
/// Silently skips files it can't read or delete — the scrubber must
/// not block app startup. Each deletion is logged at warn level with
/// the file name (NOT the file contents).
pub fn scrub_stale_scrv1_auth_files() {
    let Ok(root) = crate::config::get_config_dir() else {
        return;
    };
    let auth_dir = root.join(crate::constants::OPENVPN_AUTH_DIR);
    let Ok(entries) = std::fs::read_dir(&auth_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if name.to_ascii_lowercase().ends_with(".scrv1.auth") {
            tracing::warn!(
                file = %name,
                "AUTH: stale credentials bundle — clearing"
            );
            let _ = std::fs::remove_file(&path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_no_op_when_auth_dir_missing() {
        // Set a temp config dir with no `auth/` subdir created. The scrub
        // must not panic or error.
        let _tmp = crate::config::set_temp_config_dir();
        scrub_stale_scrv1_auth_files();
        // No assertion needed — the test passes by not panicking.
    }

    #[test]
    fn removing_run_files_takes_the_management_socket_too() {
        let run_dir = tempfile::tempdir().unwrap();
        let id = "a".repeat(64);
        let files = [
            run_file(run_dir.path(), &id, "pid"),
            run_file(run_dir.path(), &id, "log"),
            management_socket_path(run_dir.path(), &id),
        ];
        for file in &files {
            std::fs::write(file, b"x").unwrap();
        }
        remove_run_files(run_dir.path(), &id, "corp");
        assert!(files.iter().all(|file| !file.exists()));
    }
}
