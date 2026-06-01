//! `OvpnTunnel` — `OpenVPN` impl of the `Tunnel` port.
//!
//! Spawns the daemon with `--daemon --writepid --log --auth-user-pass`, then
//! polls the log file for `Initialization Sequence Completed` (success) or
//! one of the known error patterns. Behaviour matches the existing engine
//! invocation byte-for-byte.

use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::vortix_core::ports::tunnel::{
    ParseError, ParsedProfile, ProtocolStatus, Tunnel, TunnelCapabilities, TunnelError,
    TunnelHandle, TunnelKindTag, TunnelStatus,
};
use crate::vortix_core::profile::Profile;
use crate::vortix_process::{CommandSpec, PrivilegeReq};
use tracing::{debug, info, warn};

use crate::vortix_protocol_openvpn::parser::parse_ovpn_conf;

/// Log line indicating successful tunnel establishment.
pub const OVPN_LOG_SUCCESS: &str = "Initialization Sequence Completed";

/// Log patterns indicating definitive failure.
pub const OVPN_LOG_ERRORS: &[&str] = &[
    "AUTH_FAILED",
    "TLS Error",
    "TLS handshake failed",
    "FATAL",
    "Cannot open TUN/TAP",
    "ERROR:",
    "Exiting due to fatal error",
    "Options error",
];

/// Polling interval for the daemon's log file.
pub const OVPN_LOG_POLL_MS: u64 = 500;
/// Delay between daemon fork and chowning the pid/log files to the real user.
pub const OVPN_CHOWN_DELAY_MS: u64 = 200;
/// How long to wait before checking if the daemon is still alive.
pub const OVPN_HEALTH_CHECK_DELAY_SECS: u64 = 2;
/// How long to wait for the pid file to appear before declaring failure.
pub const OVPN_PID_FILE_TIMEOUT_SECS: u64 = 3;
/// Number of trailing log lines to include in error messages.
pub const OVPN_ERROR_LOG_TAIL_LINES: usize = 5;
/// Default `--verb` level.
pub const DEFAULT_OVPN_VERBOSITY: &str = "3";

/// `OpenVPN` tunnel implementation.
///
/// Construct with the run-files directory (where the protocol writes
/// `<profile>.pid` / `<profile>.log`) and optional auth directory. The engine
/// passes resolved paths in based on the app config.
#[derive(Clone)]
pub struct OvpnTunnel {
    /// Directory where `<safe_name>.pid` and `<safe_name>.log` are written.
    pub run_dir: PathBuf,
    /// Optional auth file directory (`<safe_name>.auth`); absent when the
    /// profile uses other auth mechanisms.
    pub auth_dir: Option<PathBuf>,
    /// `--verb N` value passed to the daemon.
    pub verbosity: String,
    /// Overall connect timeout in seconds.
    pub connect_timeout_secs: u64,
    /// True when this tunnel is being brought up as a secondary in a
    /// multi-tunnel session (plan 001 U14). When true, `up()` appends
    /// `--pull-filter ignore "dhcp-option DNS"` to the openvpn argv so the
    /// server's pushed DNS does not clobber the primary's resolver. Defaults
    /// to `false` — single-tunnel callers see unchanged behaviour. The
    /// `TunnelRegistry` (plan 001 U5) sets this on the tunnel before invoking
    /// `up()`; until U5 lands no production callsite flips this.
    pub is_secondary: bool,
}

impl std::fmt::Debug for OvpnTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OvpnTunnel")
            .field("run_dir", &self.run_dir)
            .field("auth_dir", &self.auth_dir)
            .field("verbosity", &self.verbosity)
            .field("connect_timeout_secs", &self.connect_timeout_secs)
            .field("is_secondary", &self.is_secondary)
            .finish()
    }
}

impl Default for OvpnTunnel {
    fn default() -> Self {
        Self {
            run_dir: PathBuf::from("/tmp/vortix-ovpn"),
            auth_dir: None,
            verbosity: DEFAULT_OVPN_VERBOSITY.to_string(),
            connect_timeout_secs: 30,
            is_secondary: false,
        }
    }
}

impl OvpnTunnel {
    #[must_use]
    pub fn new(run_dir: PathBuf) -> Self {
        Self {
            run_dir,
            ..Default::default()
        }
    }

    /// Builder: set the auth file directory.
    #[must_use]
    pub fn with_auth_dir(mut self, auth_dir: PathBuf) -> Self {
        self.auth_dir = Some(auth_dir);
        self
    }

    /// Builder: set the `--verb` value.
    #[must_use]
    pub fn with_verbosity(mut self, verbosity: impl Into<String>) -> Self {
        self.verbosity = verbosity.into();
        self
    }

    /// Builder: set the connect timeout (seconds).
    #[must_use]
    pub fn with_connect_timeout(mut self, secs: u64) -> Self {
        self.connect_timeout_secs = secs;
        self
    }

    /// Builder: mark this tunnel as a secondary in a multi-tunnel session
    /// (plan 001 U14). When set to `true`, `up()` appends
    /// `--pull-filter ignore "dhcp-option DNS"` to the openvpn argv,
    /// suppressing server-pushed DNS so the primary tunnel's resolver
    /// stays authoritative.
    ///
    /// Defaults to `false`. The `TunnelRegistry` (plan 001 U5) toggles this
    /// before calling `up()` once it lands; until then no production callsite
    /// flips the flag and the existing single-tunnel argv is preserved.
    ///
    /// Requires `OpenVPN` >= 2.4 — version assertion lives in the
    /// shared dependency probe at `VpnRuntime::check_dependencies`
    /// (uses `vpn_runtime::openvpn::probe_openvpn_version`).
    #[must_use]
    pub fn with_secondary(mut self, is_secondary: bool) -> Self {
        self.is_secondary = is_secondary;
        self
    }

    fn pid_path(&self, safe_name: &str) -> PathBuf {
        self.run_dir.join(format!("{safe_name}.pid"))
    }

    fn log_path(&self, safe_name: &str) -> PathBuf {
        self.run_dir.join(format!("{safe_name}.log"))
    }

    fn auth_path(&self, safe_name: &str) -> Option<PathBuf> {
        self.auth_dir
            .as_ref()
            .map(|d| d.join(format!("{safe_name}.auth")))
    }
}

/// `OpenVPN`-specific status (placeholder; richer parsing arrives with plan #005).
#[derive(Debug, Default)]
pub struct OvpnStatus {
    pub pid: Option<u32>,
}

impl ProtocolStatus for OvpnStatus {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Filesystem-safe version of a profile name (matches the binary-side
/// `utils::sanitize_profile_name` rules).
fn sanitize_profile_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[allow(clippy::too_many_lines)]
/// Anchor phrases `OpenVPN` writes to its log when it brings the kernel
/// interface up. The device name immediately follows the anchor and is
/// extracted as a single whitespace-delimited token.
///
/// Each entry is `(prefix, suffix)`:
/// - `prefix` is what we split on; the device name is the first token after.
/// - `suffix` is what must appear after the device name on the same line, or
///   the empty string if the device name is the line's terminal token.
///
/// Pattern coverage:
/// - macOS: `Opened utun device utun4` — utun kernel control device
/// - Linux/BSD legacy: `TUN/TAP device tun0 opened` — works for `tap0` too
/// - Linux modern (iproute2 path, `OpenVPN` >= 2.5): `net_iface_up: set wg-corp up`
///
/// The contract here is "trust the anchor phrase, not the device name."
/// The anchor is `OpenVPN`'s log format (stable across releases); the
/// device name is whatever the kernel reports — `utun4`, `tun0`, `tap0`,
/// or a user-chosen name like `corp-vpn` (when the profile sets `dev`
/// to a custom string on Linux). Hardcoding a `tun`/`utun` prefix would
/// miss those cases.
///
/// Windows is not yet covered. The `OpenVPN`-Windows log format and the
/// TAP-Windows / wintun adapter naming model are different enough
/// (`Local Area Connection 3`, GUIDs) that this needs a separate
/// extractor — track via `vortix_platform_windows` when Windows lands.
const OVPN_IFACE_ANCHORS: &[(&str, &str)] = &[
    ("Opened utun device ", ""),
    ("TUN/TAP device ", " opened"),
    ("net_iface_up: set ", " up"),
];

/// Parse the kernel-visible interface name from `OpenVPN`'s log output.
///
/// The returned name MUST equal the kernel-visible interface name; the
/// registry's primary-election compares it byte-for-byte against
/// `route get default` / `ip route show default` output. The legacy
/// synthetic `openvpn-{name}` was the source of the "always Split tunnel"
/// bug — see [`OVPN_IFACE_ANCHORS`] for the patterns we accept.
pub(crate) fn parse_kernel_interface(log: &str) -> Option<String> {
    for line in log.lines() {
        for (prefix, suffix) in OVPN_IFACE_ANCHORS {
            let Some((_, after_prefix)) = line.split_once(prefix) else {
                continue;
            };
            let name = after_prefix.split_whitespace().next()?;
            // `suffix.is_empty()` covers the "name is the terminal token"
            // case (macOS). Otherwise the suffix must follow on the same
            // line to confirm we matched the right log message.
            if suffix.is_empty() || after_prefix[name.len()..].starts_with(suffix) {
                return Some(name.to_string());
            }
        }
    }
    None
}

fn poll_log_until_ready(
    log_path: &std::path::Path,
    pid_path: &std::path::Path,
    timeout_secs: u64,
) -> Result<(u32, Option<String>), TunnelError> {
    let timeout = Duration::from_secs(timeout_secs);
    let poll_interval = Duration::from_millis(OVPN_LOG_POLL_MS);
    let start = Instant::now();

    loop {
        thread::sleep(poll_interval);

        // After OVPN_HEALTH_CHECK_DELAY_SECS, check whether the daemon is
        // still alive — if the pid file appeared and the process is gone,
        // bail with the tail of the log.
        if start.elapsed() > Duration::from_secs(OVPN_HEALTH_CHECK_DELAY_SECS) {
            if let Ok(content) = std::fs::read_to_string(pid_path) {
                if let Ok(pid) = content.trim().parse::<u32>() {
                    let alive = crate::vortix_process::run_to_output(CommandSpec::oneshot(
                        "kill",
                        vec!["-0".into(), pid.to_string()],
                    ))
                    .is_ok_and(|o| o.status.success());
                    if !alive {
                        let log = std::fs::read_to_string(log_path).unwrap_or_default();
                        let last_lines = tail_lines(&log, OVPN_ERROR_LOG_TAIL_LINES);
                        return Err(TunnelError::DaemonExited(format!(
                            "OpenVPN daemon exited:\n{last_lines}"
                        )));
                    }
                }
            } else if start.elapsed() > Duration::from_secs(OVPN_PID_FILE_TIMEOUT_SECS) {
                let log = std::fs::read_to_string(log_path)
                    .unwrap_or_else(|_| "No log output".to_string());
                return Err(TunnelError::DaemonExited(format!(
                    "OpenVPN: no PID file. Log:\n{log}"
                )));
            }
        }

        if let Ok(log_content) = std::fs::read_to_string(log_path) {
            if log_content.contains(OVPN_LOG_SUCCESS) {
                let pid = std::fs::read_to_string(pid_path)
                    .ok()
                    .and_then(|s| s.trim().parse::<u32>().ok())
                    .ok_or_else(|| {
                        TunnelError::DaemonExited(
                            "OpenVPN initialised but PID file is missing".into(),
                        )
                    })?;
                let iface = parse_kernel_interface(&log_content);
                return Ok((pid, iface));
            }

            for pattern in OVPN_LOG_ERRORS {
                if log_content.contains(pattern) {
                    let error_line = log_content
                        .lines()
                        .find(|l| l.contains(pattern))
                        .unwrap_or(pattern);
                    if pattern == &"AUTH_FAILED" {
                        return Err(TunnelError::AuthFailed(error_line.to_string()));
                    }
                    return Err(TunnelError::DaemonExited(format!("OpenVPN: {error_line}")));
                }
            }
        }

        if start.elapsed() >= timeout {
            return Err(TunnelError::Timeout(timeout));
        }
    }
}

/// Build the openvpn daemon argv for a given profile. Pure helper extracted
/// so the secondary-DNS-suppression branch (plan 001 U14) is unit-testable
/// without spawning a subprocess. The caller appends `--auth-user-pass <path>`
/// afterwards when an auth file is available.
fn build_ovpn_args(
    config_path: &std::path::Path,
    safe_name: &str,
    pid_path: &std::path::Path,
    log_path: &std::path::Path,
    verbosity: &str,
    is_secondary: bool,
) -> Vec<String> {
    let mut args = vec![
        "--config".to_string(),
        config_path.to_string_lossy().into_owned(),
        "--daemon".to_string(),
        format!("vortix-{safe_name}"),
        "--writepid".to_string(),
        pid_path.to_string_lossy().into_owned(),
        "--log".to_string(),
        log_path.to_string_lossy().into_owned(),
        "--verb".to_string(),
        verbosity.to_string(),
    ];

    // Plan 001 U14: when this tunnel is a secondary, suppress server-pushed
    // DNS so the primary's resolver stays authoritative. Requires OpenVPN
    // >= 2.4 — gated upstream by `VpnRuntime::check_dependencies`.
    if is_secondary {
        args.push("--pull-filter".to_string());
        args.push("ignore".to_string());
        args.push("dhcp-option DNS".to_string());
    }

    args
}

fn tail_lines(content: &str, n: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

impl Tunnel for OvpnTunnel {
    #[allow(clippy::too_many_lines)] // single linear sequence of pid/log/auth setup + daemon spawn + log-poll; splitting would obscure the connect flow without simplifying it
    fn up(&mut self, profile: &Profile) -> Result<TunnelHandle, TunnelError> {
        let safe_name = sanitize_profile_name(&profile.display_name);
        let pid_path = self.pid_path(&safe_name);
        let log_path = self.log_path(&safe_name);

        if let Some(parent) = pid_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Stale-file cleanup from any previous run.
        let _ = std::fs::remove_file(&pid_path);
        let _ = std::fs::remove_file(&log_path);

        info!(
            target: "vortix::tunnel::openvpn",
            profile = %profile.id,
            config = %profile.config_path.display(),
            pid_path = %pid_path.display(),
            log_path = %log_path.display(),
            "ovpn.up"
        );

        let mut args = build_ovpn_args(
            &profile.config_path,
            &safe_name,
            &pid_path,
            &log_path,
            &self.verbosity,
            self.is_secondary,
        );
        if self.is_secondary {
            debug!(
                target: "vortix::tunnel::openvpn",
                profile = %profile.id,
                "ovpn.up: secondary tunnel, suppressing pushed DNS via --pull-filter"
            );
        }

        if let Some(auth) = self.auth_path(&safe_name).filter(|p| p.exists()) {
            args.push("--auth-user-pass".to_string());
            args.push(auth.to_string_lossy().into_owned());
        }

        // `openvpn --daemon` forks and detaches — the grandchild inherits
        // any piped stdout/stderr fds from the parent, so without
        // `.daemonizes()` the runner's `wait_with_output()` would hang
        // forever waiting for pipe EOF that never comes. The daemon writes
        // diagnostics to `--log <log_path>` (read via `tail_lines` on the
        // error path below), so dropping pipe capture costs no signal.
        let output = crate::vortix_process::run_to_output(
            CommandSpec::oneshot("openvpn", args)
                .privilege(PrivilegeReq::Root)
                .daemonizes(),
        )
        .map_err(|e| TunnelError::Subprocess(format!("openvpn: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let detail = if stderr.trim().is_empty() {
                std::fs::read_to_string(&log_path)
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .map_or_else(
                        || "unknown error (no stderr or log output)".to_string(),
                        |log| tail_lines(&log, OVPN_ERROR_LOG_TAIL_LINES),
                    )
            } else {
                stderr.trim().to_string()
            };
            return Err(TunnelError::DaemonExited(format!("OpenVPN: {detail}")));
        }

        // Give the daemon a moment to drop privileges and chown its files,
        // then wait for the success marker in the log.
        thread::sleep(Duration::from_millis(OVPN_CHOWN_DELAY_MS));
        debug!(target: "vortix::tunnel::openvpn", "polling log for ready");
        let (pid, kernel_iface) =
            poll_log_until_ready(&log_path, &pid_path, self.connect_timeout_secs)?;

        // The kernel interface name must come from the log scrape. The
        // multi-tunnel state-authority contract (R1, R5 of
        // docs/brainstorms/2026-06-01-multi-tunnel-state-authority-
        // requirements.md) requires `details.interface` to be byte-
        // comparable with `route get`'s output. A synthetic label like
        // `openvpn-{safe_name}` would silently disable primary-election
        // for this profile and silently break per-tunnel killswitch
        // ACCEPT rules (firewall.rs reads details.interface to build
        // PF/iptables rules — wrong iface = silent leak).
        //
        // If the log shows the success marker but no anchor phrase
        // (e.g., `Opened utun device utunN` / `TUN/TAP device tunN
        // opened` / `net_iface_up: set X up` — see OVPN_IFACE_ANCHORS),
        // bail with a typed error so the FSM routes to
        // `handle_connect_failure` (which then runs the orphan cleanup
        // path against the still-running daemon via PID).
        let Some(interface_name) = kernel_iface else {
            warn!(
                target: "vortix::tunnel::openvpn",
                profile = %profile.id,
                pid = pid,
                "ovpn.up: success marker logged but kernel interface name not found in log; refusing to track this tunnel"
            );
            return Err(TunnelError::DaemonExited(format!(
                "OpenVPN reported initialization success but no kernel interface was logged \
                 (expected one of: `Opened utun device <name>`, `TUN/TAP device <name> opened`, \
                 `net_iface_up: set <name> up`). Pid {pid} is being terminated."
            )));
        };

        Ok(TunnelHandle {
            profile_id: profile.id.clone(),
            interface_name,
            pid: Some(pid),
            started_at: SystemTime::now(),
            kind: TunnelKindTag::OpenVpn,
        })
    }

    fn down(&mut self, handle: TunnelHandle) -> Result<(), TunnelError> {
        info!(
            target: "vortix::tunnel::openvpn",
            profile = %handle.profile_id,
            pid = ?handle.pid,
            "ovpn.down"
        );

        let safe_name = sanitize_profile_name(handle.profile_id.as_str());

        if let Some(pid) = handle.pid {
            // Plan 002 U2: direct PID signal via libc::kill instead of
            // shelling to `/usr/bin/kill`. SIGTERM (15) gives the OVPN
            // daemon a chance to clean up before pkill (below) fires the
            // pattern-matched fallback.
            //
            // SAFETY: libc::kill is a thin syscall wrapper with no buffer
            // or memory invariants. Returns 0 on success or -1 with errno
            // set. We map non-zero to a warn() log, matching the prior
            // shell-out's behavior (it also fell through to pkill).
            //
            // PID conversion: TunnelHandle stores pid as u32; libc::pid_t
            // is i32 on every supported platform. Real PIDs never exceed
            // i32::MAX (kernel caps are well below 2^31), but use
            // try_from so any future overflow surfaces as an explicit
            // error rather than silent wrap.
            match libc::pid_t::try_from(pid) {
                Ok(libc_pid) => {
                    #[allow(unsafe_code)]
                    let rc = unsafe { libc::kill(libc_pid, libc::SIGTERM) };
                    if rc != 0 {
                        let err = std::io::Error::last_os_error();
                        warn!(
                            target: "vortix::tunnel::openvpn",
                            pid = pid,
                            error = %err,
                            "libc::kill(SIGTERM) returned non-zero; falling back to pkill"
                        );
                    }
                }
                Err(_) => {
                    warn!(
                        target: "vortix::tunnel::openvpn",
                        pid = pid,
                        "PID exceeds libc::pid_t range; cannot send SIGTERM directly, falling back to pkill"
                    );
                }
            }
        }

        // Plan 002 U6: fallback pattern-matched kill via process
        // enumeration + libc::kill, replacing the prior `pkill -f` shell-out.
        // Substring-match "openvpn" + "vortix-<safe_name>" against each
        // PID's cmdline. Catches the daemon even when the captured PID
        // is stale (process re-spawned, exec'd, etc.).
        //
        // Note: this imports from a platform module directly, which is
        // a controlled cross-layer reach. The alternative — adding a
        // `ProcessEnumerate` port to vortix_core — is heavier for one
        // caller. Revisit if a second protocol module needs this.
        let needle = format!("vortix-{safe_name}");

        #[cfg(target_os = "linux")]
        // xtask:allow-platform-cfg: process enumeration is OS-specific (Linux /proc walk)
        let stale_pids =
            crate::vortix_platform_linux::interface::find_all_pids_with_cmdline_substring(&needle);
        #[cfg(target_os = "macos")]
        // xtask:allow-platform-cfg: process enumeration is OS-specific (macOS proc_listpids)
        let stale_pids =
            crate::vortix_platform_macos::interface::find_all_pids_with_cmdline_substring(&needle);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        // xtask:allow-platform-cfg: Windows / other OS fallback (NG per origin)
        let stale_pids: Vec<u32> = Vec::new();

        for stale_pid in stale_pids {
            if let Ok(libc_pid) = libc::pid_t::try_from(stale_pid) {
                // SAFETY: thin syscall wrapper; see U2 for the full
                // invariant analysis. Errors are best-effort warn-only —
                // the prior `pkill` also ignored failures.
                #[allow(unsafe_code)]
                let rc = unsafe { libc::kill(libc_pid, libc::SIGTERM) };
                if rc != 0 {
                    let err = std::io::Error::last_os_error();
                    debug!(
                        target: "vortix::tunnel::openvpn",
                        pid = stale_pid,
                        error = %err,
                        "libc::kill(SIGTERM) on stale-pattern-match PID failed"
                    );
                }
            }
        }

        // Cleanup run files.
        let _ = std::fs::remove_file(self.pid_path(&safe_name));
        let _ = std::fs::remove_file(self.log_path(&safe_name));

        Ok(())
    }

    fn status(&self, handle: &TunnelHandle) -> Result<TunnelStatus, TunnelError> {
        Ok(TunnelStatus {
            handle: handle.clone(),
            bytes_rx: 0,
            bytes_tx: 0,
            last_handshake: None,
            observed_at: SystemTime::now(),
            detail: Box::new(OvpnStatus { pid: handle.pid }),
        })
    }

    fn parse_profile(&self, raw: &[u8]) -> Result<Box<dyn ParsedProfile>, ParseError> {
        let text = std::str::from_utf8(raw)
            .map_err(|e| ParseError::Encoding(format!("OpenVPN .ovpn must be UTF-8: {e}")))?;
        let parsed = parse_ovpn_conf(text)?;
        Ok(Box::new(parsed))
    }

    fn capabilities(&self) -> TunnelCapabilities {
        TunnelCapabilities {
            supports_split_tunnel: false,
            supports_ipv6: true,
            mtu_configurable: false,
            supports_reconnect_without_disconnect: false,
            requires_root: true,
            userspace: false,
        }
    }

    fn kind_tag(&self) -> TunnelKindTag {
        TunnelKindTag::OpenVpn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_match_openvpn() {
        let caps = OvpnTunnel::default().capabilities();
        assert!(caps.requires_root);
        assert!(!caps.userspace);
        assert!(!caps.supports_reconnect_without_disconnect);
    }

    #[test]
    fn sanitize_replaces_unsafe_chars() {
        assert_eq!(sanitize_profile_name("hello world"), "hello_world");
        assert_eq!(sanitize_profile_name("a/b.c"), "a_b_c");
        assert_eq!(sanitize_profile_name("safe-name_1"), "safe-name_1");
    }

    #[test]
    fn tail_lines_handles_short_input() {
        assert_eq!(tail_lines("a\nb\nc", 5), "a\nb\nc");
        assert_eq!(tail_lines("a\nb\nc\nd\ne", 2), "d\ne");
    }

    #[test]
    fn parse_kernel_interface_extracts_macos_utun() {
        let log = "Mon Jun 01 00:00:01 2026 OpenVPN 2.6.10 starting\n\
                   Mon Jun 01 00:00:02 2026 Opened utun device utun4\n\
                   Mon Jun 01 00:00:03 2026 Initialization Sequence Completed\n";
        assert_eq!(parse_kernel_interface(log), Some("utun4".to_string()));
    }

    #[test]
    fn parse_kernel_interface_extracts_linux_tun_legacy_format() {
        let log = "Mon Jun 01 00:00:01 2026 OpenVPN 2.6.10 starting\n\
                   Mon Jun 01 00:00:02 2026 TUN/TAP device tun0 opened\n\
                   Mon Jun 01 00:00:03 2026 Initialization Sequence Completed\n";
        assert_eq!(parse_kernel_interface(log), Some("tun0".to_string()));
    }

    #[test]
    fn parse_kernel_interface_extracts_tap_device() {
        // OpenVPN TAP (layer-2) mode produces `tap0`, not `tun0`.
        let log = "TUN/TAP device tap0 opened\n";
        assert_eq!(parse_kernel_interface(log), Some("tap0".to_string()));
    }

    #[test]
    fn parse_kernel_interface_extracts_renamed_linux_device() {
        // Linux profile with `dev mycorp` produces a kernel iface named
        // `mycorp` — nothing to do with `tun`/`utun`. The pattern-based
        // matcher catches this; the prior prefix-based one missed it.
        let log = "net_iface_up: set mycorp up\n";
        assert_eq!(parse_kernel_interface(log), Some("mycorp".to_string()));
    }

    #[test]
    fn parse_kernel_interface_extracts_linux_modern_format() {
        let log = "Mon Jun 01 net_iface_up: set tun3 up\n\
                   Mon Jun 01 Initialization Sequence Completed\n";
        assert_eq!(parse_kernel_interface(log), Some("tun3".to_string()));
    }

    #[test]
    fn parse_kernel_interface_returns_none_for_empty_log() {
        assert_eq!(parse_kernel_interface(""), None);
        assert_eq!(parse_kernel_interface("no device reference here\n"), None);
    }

    #[test]
    fn parse_kernel_interface_requires_anchor_suffix_when_present() {
        // Bare "tun0" mention without the anchor suffix must NOT match
        // — otherwise log noise like `setting MTU on tun0` would pick up
        // names from non-up-event lines.
        let log = "setting MTU on tun0\n";
        assert_eq!(parse_kernel_interface(log), None);
    }

    // Plan 001 U14: argv-building behaviour for primary vs. secondary tunnels.
    // The argv builder is pure so we can assert against it without spawning a
    // subprocess; the secondary branch must inject the `--pull-filter` triple
    // and the primary branch must not.

    #[test]
    fn build_ovpn_args_primary_omits_pull_filter() {
        let args = build_ovpn_args(
            std::path::Path::new("/etc/vortix/corp.ovpn"),
            "corp",
            std::path::Path::new("/run/vortix/corp.pid"),
            std::path::Path::new("/run/vortix/corp.log"),
            "3",
            false,
        );
        assert!(
            !args.iter().any(|a| a == "--pull-filter"),
            "primary argv must not contain --pull-filter; got: {args:?}"
        );
        assert!(args.contains(&"--config".to_string()));
        assert!(args.contains(&"--daemon".to_string()));
    }

    #[test]
    fn build_ovpn_args_secondary_injects_pull_filter() {
        let args = build_ovpn_args(
            std::path::Path::new("/etc/vortix/lab.ovpn"),
            "lab",
            std::path::Path::new("/run/vortix/lab.pid"),
            std::path::Path::new("/run/vortix/lab.log"),
            "3",
            true,
        );
        // The three flag tokens must appear in order: `--pull-filter`,
        // `ignore`, `dhcp-option DNS`.
        let pf_idx = args
            .iter()
            .position(|a| a == "--pull-filter")
            .expect("secondary argv must contain --pull-filter");
        assert_eq!(args.get(pf_idx + 1).map(String::as_str), Some("ignore"));
        assert_eq!(
            args.get(pf_idx + 2).map(String::as_str),
            Some("dhcp-option DNS")
        );
    }

    #[test]
    fn with_secondary_flips_field_and_default_is_false() {
        let primary = OvpnTunnel::default();
        assert!(!primary.is_secondary);
        let secondary = OvpnTunnel::default().with_secondary(true);
        assert!(secondary.is_secondary);
        // Toggle back.
        let toggled = secondary.with_secondary(false);
        assert!(!toggled.is_secondary);
    }
}
