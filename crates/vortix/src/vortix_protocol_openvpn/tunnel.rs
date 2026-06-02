//! `OvpnTunnel` — `OpenVPN` impl of the `Tunnel` port.
//!
//! Spawns the daemon with `--daemon --writepid --log --auth-user-pass`, then
//! polls the log file for `Initialization Sequence Completed` (success) or
//! one of the known error patterns. Behaviour matches the existing engine
//! invocation byte-for-byte.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use base64::engine::{general_purpose::STANDARD as BASE64, Engine as _};

use crate::vortix_core::ports::tunnel::{
    ParseError, ParsedProfile, ProtocolStatus, Tunnel, TunnelCapabilities, TunnelError,
    TunnelHandle, TunnelKindTag, TunnelStatus,
};
use crate::vortix_core::profile::Profile;
use crate::vortix_process::{CommandSpec, PrivilegeReq};
use tracing::{debug, info, warn};

use crate::vortix_protocol_openvpn::parser::parse_ovpn_conf;

/// Maximum wall-clock to wait for openvpn to create the unix
/// management socket after spawn (plan 2026-06-02-001, #191,
/// Approach B-minimal). Typical macOS spawn takes <200ms; 5s gives
/// loaded systems ample headroom while still surfacing
/// catastrophic-spawn-failure within the user's attention span.
const OVPN_MGMT_SOCKET_TIMEOUT_MS: u64 = 5000;

/// Read the credentials bundle file written by the TUI/CLI auth flow
/// (plan 2026-06-02-001 U3/U4, #191, Approach B-minimal). Returns
/// `Ok(Some((user, pass, otp)))` when the file exists and has the
/// expected 3-line shape, `Ok(None)` when the file is absent
/// (non-MFA connect path), `Err` when the file exists but is
/// malformed.
fn read_mgmt_credentials_bundle(path: &Path) -> std::io::Result<Option<(String, String, String)>> {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let mut lines = content.lines();
            let user = lines.next().unwrap_or("").to_string();
            let pass = lines.next().unwrap_or("").to_string();
            let otp = lines.next().unwrap_or("").to_string();
            // Best-effort delete: keep the credentials surface tiny.
            // If delete fails the startup scrub catches the residue.
            let _ = std::fs::remove_file(path);
            if user.is_empty() || pass.is_empty() || otp.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "mgmt credentials bundle: empty field(s)",
                ));
            }
            Ok(Some((user, pass, otp)))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Drive `OpenVPN`'s management protocol auth dance over a unix socket
/// (plan 2026-06-02-001, #191, Approach B-minimal). Implements only
/// the static-challenge-inline path used by `ovpn-totp`-shaped
/// profiles: release the hold, respond to `>PASSWORD:Need 'Auth' SC:
/// 1,<prompt>` with username + SCRV1 envelope. Returns `Ok(())` when
/// `>STATE:<ts>,CONNECTED,...` is observed; returns `Err` on
/// `>FATAL:`, `>PASSWORD:Verification Failed`, or socket error.
///
/// Dynamic CRV1, passphrase, and push MFA are deferred to a future
/// brainstorm — when encountered, this function returns a
/// `TunnelError::AuthFailed` describing the unhandled event so the
/// failure is loud rather than a hang.
fn drive_mgmt_auth(
    stream: UnixStream,
    user: &str,
    pass: &str,
    otp: &str,
    profile_id: &str,
    connect_timeout_secs: u64,
) -> Result<(), TunnelError> {
    // Per-recv read timeout. Aligned with the configured overall
    // connect_timeout so a slow MFA handshake (TLS + auth-pam fork +
    // sequential PAM modules + PUSH_REPLY) doesn't trip the socket
    // budget before the outer connect-timeout would. In the normal
    // path events arrive continuously (HOLD -> PASSWORD prompt ->
    // SUCCESS -> multiple STATE events) and no single recv takes
    // more than ~1-2s; this timeout only fires when openvpn hangs.
    stream
        .set_read_timeout(Some(Duration::from_secs(connect_timeout_secs)))
        .map_err(|e| TunnelError::Subprocess(format!("mgmt: set_read_timeout: {e}")))?;
    let mut writer = stream
        .try_clone()
        .map_err(|e| TunnelError::Subprocess(format!("mgmt: try_clone: {e}")))?;
    let mut reader = BufReader::new(stream);

    let send = |w: &mut UnixStream, line: &str| -> Result<(), TunnelError> {
        // No log emit of the line content — credentials cannot
        // appear in tracing spans (plan 2026-06-02-001 PF-8).
        w.write_all(line.as_bytes())
            .and_then(|()| w.write_all(b"\n"))
            .and_then(|()| w.flush())
            .map_err(|e| TunnelError::Subprocess(format!("mgmt: write: {e}")))
    };

    let mut line = String::new();
    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| TunnelError::Subprocess(format!("mgmt: read_line: {e}")))?;
        if n == 0 {
            return Err(TunnelError::Subprocess(
                "mgmt: socket closed before CONNECTED state".into(),
            ));
        }
        let trimmed = line.trim();
        debug!(
            target: "vortix::tunnel::openvpn::mgmt",
            profile = %profile_id,
            event = %trimmed,
            "mgmt event"
        );

        if trimmed.starts_with(">HOLD:") {
            // Subscribe to STATE events BEFORE releasing the hold.
            // OpenVPN's management protocol does NOT send `>STATE:...`
            // real-time messages by default; without `state on` the
            // socket goes silent after the password handshake and
            // drive_mgmt_auth sits on read_timeout waiting for a
            // `>STATE:CONNECTED` event that will never arrive --
            // even when the tunnel is actually up and routing
            // traffic. The handshake-success path needs explicit
            // subscription. (Management-notes.txt: "STATE (when
            // state is on)" -- not in the default-enabled list.)
            send(&mut writer, "state on")?;
            send(&mut writer, "hold release")?;
        } else if trimmed.starts_with(">PASSWORD:Need 'Auth'") && trimmed.contains(" SC:") {
            // Static-challenge inline. The prompt CAN come in two
            // observed shapes from OpenVPN:
            //   ">PASSWORD:Need 'Auth' SC:1,Enter TOTP code"
            //   ">PASSWORD:Need 'Auth' username/password SC:1,Enter TOTP code"
            // (OpenVPN 2.6.19 server uses the second form; earlier
            // versions used the first. The `username/password` token
            // appears when the server asks for both creds in one
            // round-trip alongside the static-challenge.)
            // We don't parse echo/prompt -- vortix already showed the
            // overlay; here we just send the SCRV1 envelope.
            send(
                &mut writer,
                &format!("username \"Auth\" \"{}\"", escape_mgmt(user)),
            )?;
            let pw_b64 = BASE64.encode(pass);
            let otp_b64 = BASE64.encode(otp);
            let password_cmd = format!("password \"Auth\" \"SCRV1:{pw_b64}:{otp_b64}\"");
            send(&mut writer, &password_cmd)?;
        } else if trimmed.starts_with(">PASSWORD:Need 'Auth'") {
            // Non-static-challenge auth-user-pass query — plain creds.
            send(
                &mut writer,
                &format!("username \"Auth\" \"{}\"", escape_mgmt(user)),
            )?;
            send(
                &mut writer,
                &format!("password \"Auth\" \"{}\"", escape_mgmt(pass)),
            )?;
        } else if trimmed.starts_with(">PASSWORD:Verification Failed") {
            return Err(TunnelError::AuthFailed(trimmed.to_string()));
        } else if trimmed.starts_with(">PASSWORD:Need 'Private Key'") {
            return Err(TunnelError::AuthFailed(
                "OpenVPN requested a private-key passphrase; this profile shape is not yet supported (deferred to next brainstorm).".into(),
            ));
        } else if trimmed.starts_with(">FATAL:") {
            return Err(TunnelError::DaemonExited(trimmed.to_string()));
        } else if let Some(state) = trimmed.strip_prefix(">STATE:") {
            // `>STATE:<ts>,<state>,...` — we only care about CONNECTED
            // (success) and EXITING (early failure).
            let mut fields = state.splitn(3, ',');
            let _ts = fields.next();
            if let Some(state_name) = fields.next() {
                if state_name == "CONNECTED" {
                    return Ok(());
                }
                if state_name == "EXITING" {
                    return Err(TunnelError::DaemonExited(format!(
                        "OpenVPN entered EXITING state mid-auth: {trimmed}"
                    )));
                }
            }
        }
        // Other events (>INFO:, >LOG:, >BYTECOUNT:, etc.) are
        // ignored — the auth dance only cares about HOLD, PASSWORD,
        // STATE, FATAL.
    }
}

/// Escape a value for the `OpenVPN` management protocol's quoted-string
/// form. Per `management-notes.txt`: backslash and double-quote are
/// the only characters that need escaping inside `"..."`.
fn escape_mgmt(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(ch),
        }
    }
    out
}

/// Wait for openvpn to create the management unix socket. Returns
/// `Ok(())` when the path becomes a socket, `Err` on timeout.
fn wait_for_mgmt_socket(path: &Path, timeout: Duration) -> Result<(), TunnelError> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(TunnelError::Subprocess(format!(
        "openvpn management socket did not appear within {}ms at {}",
        timeout.as_millis(),
        path.display()
    )))
}

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

    /// Path used by the static-challenge SCRV1 envelope (plan
    /// 2026-06-02-001 U3 / PF-2, #191). The connect path writes the
    /// envelope to this sibling of the canonical auth file, hands it
    /// to openvpn via `--auth-user-pass`, and deletes it immediately
    /// after the daemon fork returns — keeping the canonical
    /// `<safe>.auth` plain at all times, with no race window for the
    /// async TUI worker thread to lose against.
    fn scrv1_auth_path(&self, safe_name: &str) -> Option<PathBuf> {
        self.auth_dir
            .as_ref()
            .map(|d| d.join(format!("{safe_name}.scrv1.auth")))
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

        // Plan 2026-06-02-001, #191, Approach B-minimal: if the
        // credentials bundle file is present, this is a
        // static-challenge connect. Read user/pass/otp out of the
        // bundle (the file is consumed/deleted on read), spawn
        // openvpn with `--management <sock> unix --management-hold
        // --management-query-passwords --daemon`, and drive the auth
        // dance over the socket on a worker thread while
        // run_to_output waits for the parent to daemonize.
        //
        // Non-MFA profiles take the existing --auth-user-pass file
        // path unchanged.
        let bundle_path = self.scrv1_auth_path(&safe_name);
        let mgmt_creds = if let Some(p) = &bundle_path {
            read_mgmt_credentials_bundle(p)
                .map_err(|e| TunnelError::Subprocess(format!("mgmt creds bundle: {e}")))?
        } else {
            None
        };

        let mgmt_sock_path = if mgmt_creds.is_some() {
            let path = self.run_dir.join(format!("{safe_name}.mgmt.sock"));
            // Stale socket from a prior crash — delete before spawn
            // so openvpn can bind cleanly.
            let _ = std::fs::remove_file(&path);
            args.push("--management".to_string());
            args.push(path.to_string_lossy().into_owned());
            args.push("unix".to_string());
            args.push("--management-hold".to_string());
            args.push("--management-query-passwords".to_string());
            Some(path)
        } else {
            None
        };

        // Non-MFA: legacy `--auth-user-pass <file>` flow.
        if mgmt_creds.is_none() {
            if let Some(auth) = self.auth_path(&safe_name).filter(|p| p.exists()) {
                args.push("--auth-user-pass".to_string());
                args.push(auth.to_string_lossy().into_owned());
            }
        }

        // `openvpn --daemon` forks and detaches — the grandchild inherits
        // any piped stdout/stderr fds from the parent, so without
        // `.daemonizes()` the runner's `wait_with_output()` would hang
        // forever waiting for pipe EOF that never comes. The daemon writes
        // diagnostics to `--log <log_path>` (read via `tail_lines` on the
        // error path below), so dropping pipe capture costs no signal.
        //
        // For the management-socket flow, the parent does NOT fork
        // until auth completes successfully — so we spawn openvpn on
        // a worker thread and drive the management dance on the main
        // thread while run_to_output blocks on the parent.
        let output = if let (Some(creds), Some(sock_path)) = (mgmt_creds, mgmt_sock_path) {
            let (user, pass, otp) = creds;
            let profile_id_for_log = profile.id.to_string();
            let mgmt_timeout = self.connect_timeout_secs;
            let spawn_thread = thread::spawn(move || {
                crate::vortix_process::run_to_output(
                    CommandSpec::oneshot("openvpn", args)
                        .privilege(PrivilegeReq::Root)
                        .daemonizes(),
                )
            });

            // Wait for openvpn to bind its management socket, then
            // connect and drive the auth dance. If anything fails,
            // we still need to join the spawn thread to avoid leaks.
            let mgmt_result = (|| -> Result<(), TunnelError> {
                wait_for_mgmt_socket(
                    &sock_path,
                    Duration::from_millis(OVPN_MGMT_SOCKET_TIMEOUT_MS),
                )?;
                let stream = UnixStream::connect(&sock_path).map_err(|e| {
                    TunnelError::Subprocess(format!("mgmt: connect {}: {e}", sock_path.display()))
                })?;
                drive_mgmt_auth(
                    stream,
                    &user,
                    &pass,
                    &otp,
                    &profile_id_for_log,
                    mgmt_timeout,
                )
            })();

            // Always join. If mgmt failed, openvpn is probably about
            // to exit anyway (we never released the hold or the
            // SCRV1 was rejected). The join returns whatever the
            // parent gave us.
            let spawn_result = spawn_thread
                .join()
                .map_err(|_| TunnelError::Subprocess("openvpn spawn thread panicked".into()))?;

            // Best-effort cleanup of the management socket file.
            let _ = std::fs::remove_file(&sock_path);

            // Bubble up the most informative error.
            mgmt_result?;
            spawn_result.map_err(|e| TunnelError::Subprocess(format!("openvpn: {e}")))?
        } else {
            crate::vortix_process::run_to_output(
                CommandSpec::oneshot("openvpn", args)
                    .privilege(PrivilegeReq::Root)
                    .daemonizes(),
            )
            .map_err(|e| TunnelError::Subprocess(format!("openvpn: {e}")))?
        };

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
