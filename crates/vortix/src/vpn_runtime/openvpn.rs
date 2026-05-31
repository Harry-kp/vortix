//! `OpenVPN` version detection + the multi-tunnel `--pull-filter` baseline
//! probe.
//!
//! Both the TUI and the CLI need to assert `OpenVPN` ≥ 2.4 before a
//! connect can proceed (plan 001 U14 / R13) — older builds silently
//! ignore `--pull-filter` and leak pushed DNS into the primary tunnel's
//! resolver. The probe lives here so both surfaces resolve through the
//! same `VpnRuntime::check_dependencies` call site instead of one
//! running the gate (TUI) and the other skipping it (CLI).

use std::sync::OnceLock;
use std::time::Duration;

use crate::vortix_process::{self, CommandSpec};

/// Semantic version of an installed `openvpn` binary, as reported by
/// `openvpn --version`. Used by `check_dependencies` to assert the
/// `--pull-filter` multi-tunnel-DNS-suppression baseline (plan 001 U14, R13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OvpnVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl OvpnVersion {
    /// Minimum `OpenVPN` release supporting `--pull-filter` reliably. Anything
    /// older fails multi-tunnel's DNS-scoping precondition (R13).
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

/// Cached outcome of probing `openvpn --version` (plan 001 U14). The subprocess
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
    // xtask:allow-protocol-leak: dependency-version probe runs before any tunnel exists; pre-flight gate (R13)
    let version_output = vortix_process::run_to_output(
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

    // xtask:allow-protocol-leak: dependency-feature probe runs before any tunnel exists; pre-flight gate (R13)
    let help_output = vortix_process::run_to_output(
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
    //! Tests for plan 001 U14 — `OpenVPN` `--version` parsing and the 2.4+
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
        let v = parse_openvpn_version("vendor-patched OpenVPN 2.6.10 abc").expect("should parse");
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
