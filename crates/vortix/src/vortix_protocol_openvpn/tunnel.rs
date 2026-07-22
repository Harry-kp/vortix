//! `OvpnTunnel` — `OpenVPN` impl of the `Tunnel` port.
//!
//! Spawns `OpenVPN` as a foreground child owned by the Standard-mode lifecycle
//! custodian, then polls the log for protocol readiness. `OpenVPN` never
//! self-daemonizes, so Vortix retains a reapable process-group owner.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use base64::engine::{general_purpose::STANDARD as BASE64, Engine as _};

use crate::vortix_core::ports::process::ManagedProcessId;
use crate::vortix_core::ports::tunnel::{
    ParseError, ParsedProfile, ProtocolStatus, Tunnel, TunnelCapabilities, TunnelError,
    TunnelHandle, TunnelKindTag, TunnelStatus,
};
use crate::vortix_core::profile::Profile;
use crate::vortix_process::{CommandSpec, PrivilegeReq};
use tracing::{debug, info, warn};

use crate::vortix_protocol_openvpn::parser::parse_ovpn_conf;

/// Quality of the DNS intent recovered from an `OpenVPN` session log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OvpnDnsEvidence {
    /// A complete negotiation contained pushed DNS settings.
    Observed(crate::vortix_core::ports::dns::DnsRequest),
    /// A complete negotiation contained no pushed DNS settings. Statically
    /// configured settings, if any, remain in the request.
    ExplicitlyEmpty(crate::vortix_core::ports::dns::DnsRequest),
    /// The runtime log was missing or did not prove a completed negotiation.
    /// The configured request is returned separately from runtime evidence.
    Unavailable {
        configured: crate::vortix_core::ports::dns::DnsRequest,
        reason: String,
    },
}

/// Maximum wall-clock to wait for openvpn to create the unix
/// management socket after spawn. Typical macOS spawn takes <200ms; 5s gives
/// loaded systems ample headroom while still surfacing
/// catastrophic-spawn-failure within the user's attention span.
const OVPN_MGMT_SOCKET_TIMEOUT_MS: u64 = 5000;
const MANAGED_CONFIG_MARKER: &str = "# managed-by: vortix openvpn custodian";

#[derive(Debug, thiserror::Error)]
#[error(
    "OpenVPN `{directive}` directives are not allowed in managed profiles: Vortix never runs profile commands as root; migrate lifecycle automation to a global hook using an absolute executable plus argv"
)]
struct ManagedConfigViolation {
    directive: String,
}

fn unambiguous_legacy_key(display_name: &str) -> Option<&str> {
    (!display_name.is_empty()
        && crate::vortix_core::profile::sanitize_profile_name(display_name) == display_name)
        .then_some(display_name)
}

fn sanitize_managed_config(text: &str) -> Result<String, TunnelError> {
    let mut output = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let directive = line.split(['#', ';']).next().unwrap_or_default();
        let mut tokens = directive.split_whitespace();
        let first = tokens.next().map(|value| value.trim_start_matches('-'));
        if let Some(value) = first {
            validate_managed_directive(value)
                .map_err(|error| TunnelError::Subprocess(error.to_string()))?;
        }
        let is_dns = matches!(first, Some(value) if value.eq_ignore_ascii_case("dhcp-option"))
            && matches!(tokens.next(), Some(value) if value.eq_ignore_ascii_case("DNS")
                || value.eq_ignore_ascii_case("DOMAIN")
                || value.eq_ignore_ascii_case("DOMAIN-SEARCH"));
        if !is_dns {
            output.push_str(line);
        }
    }
    Ok(output)
}

fn validate_managed_directive(directive: &str) -> Result<(), ManagedConfigViolation> {
    const FORBIDDEN: &[&str] = &[
        "daemon",
        "config",
        "include",
        "plugin",
        "up",
        "down",
        "route-up",
        "route-pre-down",
        "ipchange",
        "client-connect",
        "client-connect-deferred",
        "client-disconnect",
        "learn-address",
        "tls-verify",
        "tls-crypt-v2-verify",
        "auth-user-pass-verify",
        "iproute",
    ];
    if FORBIDDEN
        .iter()
        .any(|forbidden| directive.eq_ignore_ascii_case(forbidden))
    {
        return Err(ManagedConfigViolation {
            directive: directive.to_ascii_lowercase(),
        });
    }
    Ok(())
}

fn validate_managed_config(path: &Path) -> Result<String, TunnelError> {
    let body = std::fs::read_to_string(path)?;
    sanitize_managed_config(&body)
}

#[cfg(test)]
fn managed_config(profile: &Profile, identity: &ManagedProcessId) -> Result<PathBuf, TunnelError> {
    let stripped = validate_managed_config(&profile.config_path)?;
    write_managed_config(profile, identity, &stripped)
}

fn write_managed_config(
    profile: &Profile,
    identity: &ManagedProcessId,
    stripped: &str,
) -> Result<PathBuf, TunnelError> {
    // Keep the managed copy beside the source profile so relative CA, cert,
    // key, tls-auth, and script paths retain OpenVPN's established behavior.
    // The unpredictable ownership suffix plus O_NOFOLLOW secret-file writer
    // prevents a foreign file from being silently replaced.
    let parent = profile
        .config_path
        .parent()
        .ok_or_else(|| TunnelError::Subprocess("OpenVPN config has no parent directory".into()))?;
    let path = parent.join(format!(
        ".vortix-{}-{:016x}-{}.ovpn",
        profile.id,
        identity.generation,
        &identity.ownership_token[..16]
    ));
    let managed_body = format!(
        "{MANAGED_CONFIG_MARKER}\n# profile-id: {}\n# ownership-token: {}\n{stripped}",
        profile.id, identity.ownership_token
    );
    crate::vortix_core::secret_file::write_secret_file(&path, managed_body.as_bytes()).map_err(
        |error| TunnelError::Subprocess(format!("write managed OpenVPN config: {error}")),
    )?;
    Ok(path)
}

/// Read the credentials bundle file written by the TUI/CLI auth flow
///. Returns
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
///. Implements only
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
        // appear in tracing spans.
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
    /// Directory where `<profile_id>.pid` and `<profile_id>.log` are written.
    pub run_dir: PathBuf,
    /// Optional auth file directory (`<profile_id>.auth`); absent when the
    /// profile uses other auth mechanisms.
    pub auth_dir: Option<PathBuf>,
    /// `--verb N` value passed to the daemon.
    pub verbosity: String,
    /// Overall connect timeout in seconds.
    pub connect_timeout_secs: u64,
}

impl std::fmt::Debug for OvpnTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OvpnTunnel")
            .field("run_dir", &self.run_dir)
            .field("auth_dir", &self.auth_dir)
            .field("verbosity", &self.verbosity)
            .field("connect_timeout_secs", &self.connect_timeout_secs)
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

    /// Recover configured and negotiated DNS intent without conflating an
    /// unreadable/truncated log with a completed negotiation that pushed no
    /// DNS options.
    pub fn requested_dns_evidence(
        &self,
        profile: &Profile,
    ) -> Result<OvpnDnsEvidence, TunnelError> {
        let profile_text = std::fs::read_to_string(&profile.config_path).map_err(|error| {
            TunnelError::Subprocess(format!("read OpenVPN profile for DNS intent: {error}"))
        })?;
        let configured = parse_ovpn_conf(&profile_text)
            .map_err(|error| TunnelError::Subprocess(format!("parse OpenVPN DNS intent: {error}")))?
            .dns_request();
        let canonical_log = self.log_path(profile.id.as_str());
        let log_path = if canonical_log.exists() {
            canonical_log
        } else if let Some(legacy_key) = unambiguous_legacy_key(&profile.display_name) {
            self.log_path(legacy_key)
        } else {
            canonical_log
        };
        let log = match std::fs::read_to_string(&log_path) {
            Ok(log) => log,
            Err(error) => {
                return Ok(OvpnDnsEvidence::Unavailable {
                    configured,
                    reason: format!("read {}: {error}", log_path.display()),
                });
            }
        };
        Ok(pushed_dns_evidence(configured, &log))
    }

    fn pid_path(&self, profile_id: &str) -> PathBuf {
        self.run_dir.join(format!("{profile_id}.pid"))
    }

    fn log_path(&self, profile_id: &str) -> PathBuf {
        self.run_dir.join(format!("{profile_id}.log"))
    }

    fn auth_path(&self, profile_id: &str) -> Option<PathBuf> {
        self.auth_dir
            .as_ref()
            .map(|d| d.join(format!("{profile_id}.auth")))
    }

    /// Path used by the static-challenge SCRV1 envelope. The connect path writes the
    /// envelope to this sibling of the canonical auth file, hands it
    /// to openvpn via `--auth-user-pass`, and deletes it immediately
    /// after the daemon fork returns — keeping the canonical
    /// `<safe>.auth` plain at all times, with no race window for the
    /// async TUI worker thread to lose against.
    fn scrv1_auth_path(&self, profile_id: &str) -> Option<PathBuf> {
        self.auth_dir
            .as_ref()
            .map(|d| d.join(format!("{profile_id}.scrv1.auth")))
    }

    fn management_socket_path(&self, profile_id: &str) -> PathBuf {
        self.run_dir.join(format!("{profile_id}.mgmt.sock"))
    }

    fn cleanup_run_artifacts(&self, handle: &TunnelHandle) {
        let artifact_key = handle.profile_id.as_str();
        let _ = std::fs::remove_file(self.pid_path(artifact_key));
        let _ = std::fs::remove_file(self.log_path(artifact_key));
        let _ = std::fs::remove_file(self.management_socket_path(artifact_key));
        if let Some(legacy_key) = unambiguous_legacy_key(&handle.display_name) {
            if legacy_key != artifact_key {
                let _ = std::fs::remove_file(self.pid_path(legacy_key));
                let _ = std::fs::remove_file(self.log_path(legacy_key));
                let _ = std::fs::remove_file(self.management_socket_path(legacy_key));
            }
        }
    }

    fn existing_auth_path(&self, profile: &Profile) -> Option<PathBuf> {
        self.auth_path(profile.id.as_str())
            .filter(|path| path.exists())
            .or_else(|| {
                unambiguous_legacy_key(&profile.display_name)
                    .and_then(|legacy_key| self.auth_path(legacy_key))
                    .filter(|path| path.exists())
            })
    }

    fn existing_scrv1_auth_path(&self, profile: &Profile) -> Option<PathBuf> {
        self.scrv1_auth_path(profile.id.as_str())
            .filter(|path| path.exists())
            .or_else(|| {
                unambiguous_legacy_key(&profile.display_name)
                    .and_then(|legacy_key| self.scrv1_auth_path(legacy_key))
                    .filter(|path| path.exists())
            })
    }
}

/// `OpenVPN`-specific status (placeholder; richer parsing planned).
#[derive(Debug, Default)]
pub struct OvpnStatus {
    pub pid: Option<u32>,
}

impl ProtocolStatus for OvpnStatus {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
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

/// Build the foreground `OpenVPN` argv for a given profile. DNS mutations are
/// always suppressed here and applied later by the global coordinator.
fn build_ovpn_args(
    config_path: &std::path::Path,
    pid_path: &std::path::Path,
    log_path: &std::path::Path,
    verbosity: &str,
) -> Vec<String> {
    let mut args = vec![
        "--config".to_string(),
        config_path.to_string_lossy().into_owned(),
        "--writepid".to_string(),
        pid_path.to_string_lossy().into_owned(),
        "--log".to_string(),
        log_path.to_string_lossy().into_owned(),
        "--verb".to_string(),
        verbosity.to_string(),
    ];

    for option in [
        "dhcp-option DNS",
        "dhcp-option DOMAIN",
        "dhcp-option DOMAIN-SEARCH",
    ] {
        args.push("--pull-filter".to_string());
        args.push("ignore".to_string());
        args.push(option.to_string());
    }

    args
}

fn tail_lines(content: &str, n: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

fn process_exists(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return true;
    };
    // SAFETY: signal zero only probes existence/permission.
    #[allow(unsafe_code)]
    let status = unsafe { libc::kill(pid, 0) };
    status == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Parse DNS options from the latest completed `OpenVPN` negotiation.
/// Missing, incomplete, or malformed runtime evidence is never interpreted
/// as an authoritative empty request. The corresponding options are filtered
/// from `OpenVPN` itself, so this is intent capture only.
fn pushed_dns_evidence(
    mut request: crate::vortix_core::ports::dns::DnsRequest,
    log: &str,
) -> OvpnDnsEvidence {
    const COMPLETED: &str = "Initialization Sequence Completed";
    let Some(completed_at) = log.rfind(COMPLETED) else {
        return OvpnDnsEvidence::Unavailable {
            configured: request,
            reason: "OpenVPN log has no completed negotiation marker".into(),
        };
    };
    if log[completed_at + COMPLETED.len()..].contains("PUSH_REPLY") {
        return OvpnDnsEvidence::Unavailable {
            configured: request,
            reason: "OpenVPN log contains a newer incomplete negotiation".into(),
        };
    }
    let completed_log = &log[..completed_at];
    let session_start = completed_log
        .rfind(COMPLETED)
        .map_or(0, |previous| previous + COMPLETED.len());
    let session_log = &completed_log[session_start..];
    let Some(push_at) = session_log.rfind("PUSH_REPLY") else {
        return OvpnDnsEvidence::ExplicitlyEmpty(request);
    };

    let push_reply = session_log[push_at + "PUSH_REPLY".len()..]
        .lines()
        .next()
        .unwrap_or_default();
    let mut observed = false;
    for option in push_reply.split(',') {
        let option = option.trim().trim_matches('\'');
        let mut tokens = option.split_whitespace();
        if !matches!(tokens.next(), Some(prefix) if prefix.eq_ignore_ascii_case("dhcp-option")) {
            continue;
        }
        match tokens.next() {
            Some(kind) if kind.eq_ignore_ascii_case("DNS") => {
                let Some(server) = tokens.next().and_then(|value| value.parse().ok()) else {
                    return OvpnDnsEvidence::Unavailable {
                        configured: request,
                        reason: "OpenVPN PUSH_REPLY contained malformed DNS evidence".into(),
                    };
                };
                observed = true;
                if !request.servers.contains(&server) {
                    request.servers.push(server);
                }
            }
            Some(kind)
                if kind.eq_ignore_ascii_case("DOMAIN")
                    || kind.eq_ignore_ascii_case("DOMAIN-SEARCH") =>
            {
                let domains = tokens.collect::<Vec<_>>();
                if domains.is_empty() {
                    return OvpnDnsEvidence::Unavailable {
                        configured: request,
                        reason: "OpenVPN PUSH_REPLY contained malformed domain evidence".into(),
                    };
                }
                observed = true;
                for domain in domains {
                    if !request.search_domains.iter().any(|item| item == domain) {
                        request.search_domains.push(domain.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    if observed {
        OvpnDnsEvidence::Observed(request)
    } else {
        OvpnDnsEvidence::ExplicitlyEmpty(request)
    }
}

impl Tunnel for OvpnTunnel {
    #[allow(clippy::too_many_lines)] // single linear sequence of pid/log/auth setup + daemon spawn + log-poll; splitting would obscure the connect flow without simplifying it
    fn up(&mut self, profile: &Profile) -> Result<TunnelHandle, TunnelError> {
        let artifact_key = profile.id.as_str();
        let pid_path = self.pid_path(artifact_key);
        let log_path = self.log_path(artifact_key);

        // Reject recursive configuration and executable hooks before creating
        // runtime artifacts or spawning any privileged process.
        let validated_config = validate_managed_config(&profile.config_path)?;

        if let Some(parent) = pid_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Refuse double-up: if the pidfile records a live daemon, a second
        // spawn would orphan it (--writepid last-write-wins clobbers the
        // record `down` uses for teardown). Dead-pid files fall through to
        // the stale cleanup below.
        #[cfg(unix)]
        if let Ok(content) = std::fs::read_to_string(&pid_path) {
            if let Some(existing_pid) = content
                .trim()
                .parse::<u32>()
                .ok()
                .and_then(|p| libc::pid_t::try_from(p).ok())
            {
                // SAFETY: kill(pid, 0) is a pure existence probe — no signal
                // delivered, no buffers. Same invariant analysis as the
                // SIGTERM teardown below. EPERM means the process exists but
                // is owned elsewhere — treat as alive (refuse the spawn).
                #[allow(unsafe_code)]
                let rc = unsafe { libc::kill(existing_pid, 0) };
                let alive =
                    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
                if alive {
                    return Err(TunnelError::Subprocess(format!(
                        "OpenVPN for '{}' is already running (pid {existing_pid}) — \
                         disconnect it first with `vortix down`",
                        profile.display_name
                    )));
                }
            }
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

        let ownership_id = ManagedProcessId::generate(profile.id.clone()).map_err(|error| {
            TunnelError::Subprocess(format!("allocate OpenVPN ownership token: {error}"))
        })?;
        let effective_config = write_managed_config(profile, &ownership_id, &validated_config)?;
        let mut args = build_ovpn_args(&effective_config, &pid_path, &log_path, &self.verbosity);
        debug!(
            target: "vortix::tunnel::openvpn",
            profile = %profile.id,
            "ovpn.up: DNS mutation suppressed for coordinator-owned policy"
        );

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
        let bundle_path = self.existing_scrv1_auth_path(profile);
        let mgmt_creds = if let Some(p) = &bundle_path {
            read_mgmt_credentials_bundle(p)
                .map_err(|e| TunnelError::Subprocess(format!("mgmt creds bundle: {e}")))?
        } else {
            None
        };

        let mgmt_sock_path = if mgmt_creds.is_some() {
            let path = self.management_socket_path(artifact_key);
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
            if let Some(auth) = self.existing_auth_path(profile) {
                args.push("--auth-user-pass".to_string());
                args.push(auth.to_string_lossy().into_owned());
            }
        }

        let handshake = crate::vortix_process::start_managed_foreground(
            ownership_id.clone(),
            CommandSpec::oneshot("openvpn", args).privilege(PrivilegeReq::Root),
            vec![
                effective_config.clone(),
                self.management_socket_path(artifact_key),
            ],
        );
        let handshake = match handshake {
            Ok(handshake) => handshake,
            Err(error) => {
                let _ = std::fs::remove_file(&effective_config);
                return Err(TunnelError::Subprocess(format!("openvpn custody: {error}")));
            }
        };

        if let (Some(creds), Some(sock_path)) = (mgmt_creds, mgmt_sock_path) {
            let (user, pass, otp) = creds;
            let profile_id_for_log = profile.id.to_string();
            let mgmt_timeout = self.connect_timeout_secs;
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
            let _ = std::fs::remove_file(&sock_path);
            if let Err(error) = mgmt_result {
                return Err(cleanup_startup_failure(&ownership_id, error));
            }
        }

        let startup = (|| -> Result<TunnelHandle, TunnelError> {
            // Give the child a moment to drop privileges and chown its files,
            // then wait for the success marker in the log.
            thread::sleep(Duration::from_millis(OVPN_CHOWN_DELAY_MS));
            debug!(target: "vortix::tunnel::openvpn", "polling log for ready");
            let (pid, kernel_iface) =
                poll_log_until_ready(&log_path, &pid_path, self.connect_timeout_secs)?;

            // The kernel interface name must come from the log scrape. The
            // multi-tunnel state-authority contract requires `details.interface` to be byte-
            // comparable with `route get`'s output. A synthetic label like
            // a synthetic daemon label would silently disable primary-election
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

            let dns_request = match self.requested_dns_evidence(profile)? {
                OvpnDnsEvidence::Observed(request) | OvpnDnsEvidence::ExplicitlyEmpty(request) => {
                    request
                }
                OvpnDnsEvidence::Unavailable { reason, .. } => {
                    return Err(TunnelError::DaemonExited(format!(
                        "OpenVPN connected but DNS negotiation evidence is unavailable: {reason}"
                    )));
                }
            };

            Ok(TunnelHandle {
                profile_id: profile.id.clone(),
                display_name: profile.display_name.clone(),
                interface_name,
                pid: Some(pid),
                started_at: SystemTime::now(),
                kind: TunnelKindTag::OpenVpn,
                generation: 0,
                handshake: None,
                probe_receipts: Vec::new(),
                process_ownership: Some(handshake.identity),
                teardown_config: None,
                dns_request,
            })
        })();
        startup.map_err(|error| cleanup_startup_failure(&ownership_id, error))
    }

    fn down(&mut self, handle: TunnelHandle) -> Result<(), TunnelError> {
        info!(
            target: "vortix::tunnel::openvpn",
            profile = %handle.profile_id,
            pid = ?handle.pid,
            "ovpn.down"
        );

        let identity = match handle.process_ownership.clone() {
            Some(identity) => Some(identity),
            None => crate::vortix_process::managed_identity_for_profile(&handle.profile_id)
                .map_err(|error| TunnelError::Subprocess(format!("OpenVPN ownership: {error}")))?,
        };
        if let Some(identity) = identity {
            crate::vortix_process::stop_managed_foreground(&identity).map_err(|error| {
                TunnelError::Subprocess(format!(
                    "OpenVPN owned teardown was not confirmed for generation {}: {error}",
                    identity.generation
                ))
            })?;
            self.cleanup_run_artifacts(&handle);
            return Ok(());
        }

        // Compatibility state without an authenticated receipt is
        // observation-only. Never signal a bare PID or substring match: PID
        // reuse and command-line collisions can target an unrelated process.
        if handle.pid.is_some_and(process_exists) {
            return Err(TunnelError::Subprocess(
                "OpenVPN process is live but no authenticated Vortix ownership receipt exists; refusing ambiguous PID teardown"
                    .into(),
            ));
        }
        self.cleanup_run_artifacts(&handle);
        Ok(())
    }

    fn status(&self, handle: &TunnelHandle) -> Result<TunnelStatus, TunnelError> {
        if let Some(identity) = handle.process_ownership.as_ref() {
            let alive =
                crate::vortix_process::status_managed_foreground(identity).map_err(|error| {
                    TunnelError::Subprocess(format!("OpenVPN custody status: {error}"))
                })?;
            if !alive {
                return Err(TunnelError::DaemonExited(
                    "OpenVPN custodian reports that the owned child exited".into(),
                ));
            }
        }
        Ok(TunnelStatus {
            handle: handle.clone(),
            bytes_rx: 0,
            bytes_tx: 0,
            last_handshake: None,
            observed_at: SystemTime::now(),
            peers: Vec::new(),
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

fn cleanup_startup_failure(identity: &ManagedProcessId, startup: TunnelError) -> TunnelError {
    match crate::vortix_process::stop_managed_foreground(identity) {
        Ok(()) => startup,
        Err(teardown) => TunnelError::Subprocess(format!(
            "{startup}; OpenVPN startup teardown is ambiguous-owned for generation {}: {teardown}",
            identity.generation
        )),
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
        assert_eq!(
            crate::vortix_core::profile::sanitize_profile_name("hello world"),
            "hello_world"
        );
    }

    #[test]
    fn colliding_display_names_have_isolated_openvpn_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let auth = temp.path().join("auth");
        let tunnel = OvpnTunnel::new(temp.path().to_path_buf()).with_auth_dir(auth);
        let first = "1".repeat(crate::vortix_core::profile::ProfileId::HEX_LEN);
        let second = "2".repeat(crate::vortix_core::profile::ProfileId::HEX_LEN);

        assert_eq!(
            crate::vortix_core::profile::sanitize_profile_name("team/a"),
            crate::vortix_core::profile::sanitize_profile_name("team?a")
        );
        assert_ne!(tunnel.pid_path(&first), tunnel.pid_path(&second));
        assert_ne!(tunnel.log_path(&first), tunnel.log_path(&second));
        assert_ne!(tunnel.auth_path(&first), tunnel.auth_path(&second));
        assert_ne!(
            tunnel.scrv1_auth_path(&first),
            tunnel.scrv1_auth_path(&second)
        );
        assert_ne!(
            tunnel.management_socket_path(&first),
            tunnel.management_socket_path(&second)
        );

        let first_args = build_ovpn_args(
            std::path::Path::new("/tmp/one.ovpn"),
            &tunnel.pid_path(&first),
            &tunnel.log_path(&first),
            "3",
        );
        let second_args = build_ovpn_args(
            std::path::Path::new("/tmp/two.ovpn"),
            &tunnel.pid_path(&second),
            &tunnel.log_path(&second),
            "3",
        );
        assert!(first_args.contains(&tunnel.pid_path(&first).to_string_lossy().into_owned()));
        assert!(second_args.contains(&tunnel.pid_path(&second).to_string_lossy().into_owned()));
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

    #[test]
    fn build_ovpn_args_always_suppresses_protocol_dns_mutation() {
        let args = build_ovpn_args(
            std::path::Path::new("/etc/vortix/lab.ovpn"),
            std::path::Path::new("/run/vortix/lab.pid"),
            std::path::Path::new("/run/vortix/lab.log"),
            "3",
        );
        // The three flag tokens must appear in order: `--pull-filter`,
        // `ignore`, `dhcp-option DNS`.
        let pf_idx = args
            .iter()
            .position(|a| a == "--pull-filter")
            .expect("argv must contain DNS pull-filter");
        assert_eq!(args.get(pf_idx + 1).map(String::as_str), Some("ignore"));
        assert_eq!(
            args.get(pf_idx + 2).map(String::as_str),
            Some("dhcp-option DNS")
        );
        assert_eq!(
            args.iter()
                .filter(|arg| arg.as_str() == "--pull-filter")
                .count(),
            3
        );
        assert!(args
            .windows(3)
            .any(|window| { window == ["--pull-filter", "ignore", "dhcp-option DOMAIN-SEARCH"] }));
        assert!(!args.iter().any(|arg| arg == "--daemon"));
    }

    #[test]
    fn managed_config_strips_local_dns_but_preserves_other_options() {
        let input = "client\ndhcp-option DNS 1.1.1.1\ndhcp-option DOMAIN corp.example\ndhcp-option NTP 10.0.0.1\nremote vpn.example 1194\n";
        let output = sanitize_managed_config(input).unwrap();
        assert!(!output.contains("dhcp-option DNS"));
        assert!(!output.contains("dhcp-option DOMAIN"));
        assert!(output.contains("dhcp-option NTP 10.0.0.1"));
        assert!(output.contains("remote vpn.example 1194"));
    }

    #[test]
    fn managed_config_preserves_relative_path_base_and_recovery_identity() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("corp.ovpn");
        std::fs::write(&path, "client\ndhcp-option DNS 1.1.1.1\n").unwrap();
        let profile = Profile::new(
            crate::vortix_core::profile::ProfileId::new("corp"),
            "corp",
            crate::vortix_core::profile::ProtocolKind::OpenVpn,
            path,
        );
        let identity = ManagedProcessId {
            profile_id: profile.id.clone(),
            generation: 7,
            ownership_token: "a".repeat(64),
        };
        let managed = managed_config(&profile, &identity).unwrap();
        assert_eq!(managed.parent(), Some(temp.path()));
        let body = std::fs::read_to_string(&managed).unwrap();
        assert!(!body.contains("dhcp-option DNS"));
        assert!(body.contains("# profile-id: corp"));
        assert!(body.contains(&format!("# ownership-token: {}", "a".repeat(64))));
    }

    #[test]
    fn managed_config_rejects_daemon_directive() {
        let error = sanitize_managed_config("client\ndaemon sneaky\nremote vpn 1194\n")
            .expect_err("daemon would escape foreground custody");
        assert!(error.to_string().contains("daemon"));
        assert!(sanitize_managed_config("client\n--DaEmOn\n").is_err());
        assert_eq!(
            sanitize_managed_config("client\n# daemon\n; --daemon\n").unwrap(),
            "client\n# daemon\n; --daemon\n"
        );
    }

    #[test]
    fn managed_config_rejects_recursive_configs_plugins_and_script_hooks() {
        for directive in [
            "config nested.ovpn",
            "--include nested.ovpn",
            "plugin malicious.so",
            "up ./up.sh",
            "down ./down.sh",
            "route-up ./route.sh",
            "route-pre-down ./route-down.sh",
            "ipchange ./changed.sh",
            "client-connect ./connect.sh",
            "client-disconnect ./disconnect.sh",
            "learn-address ./learn.sh",
            "tls-verify ./verify.sh",
            "tls-crypt-v2-verify ./verify-key.sh",
            "auth-user-pass-verify ./auth.sh via-file",
            "iproute ./custom-ip",
        ] {
            let error = sanitize_managed_config(&format!("client\n{directive}\nremote vpn 1194\n"))
                .expect_err("managed config must be data-only");
            assert!(
                error.to_string().contains(
                    directive
                        .split_whitespace()
                        .next()
                        .unwrap()
                        .trim_start_matches('-')
                ),
                "unexpected error for {directive}: {error}"
            );
        }
    }

    #[test]
    fn nested_daemon_escape_is_rejected_at_the_include_boundary() {
        let error = sanitize_managed_config("client\nconfig nested-daemon.ovpn\n")
            .expect_err("recursive config could hide a daemon directive");
        assert!(error.to_string().contains("config"));
    }

    #[test]
    fn pushed_dns_is_captured_without_platform_mutation() {
        let evidence = pushed_dns_evidence(
            crate::vortix_core::ports::dns::DnsRequest::default(),
            "PUSH: Received control message: 'PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN corp.example'\nInitialization Sequence Completed\n",
        );
        let OvpnDnsEvidence::Observed(request) = evidence else {
            panic!("complete pushed DNS must be observed");
        };
        assert_eq!(
            request.servers,
            vec!["10.8.0.1".parse::<std::net::IpAddr>().unwrap()]
        );
        assert_eq!(request.search_domains, vec!["corp.example"]);
    }

    #[test]
    fn dns_evidence_recovers_push_reply_from_existing_log() {
        let temp = tempfile::tempdir().unwrap();
        let profile_path = temp.path().join("corp.ovpn");
        std::fs::write(&profile_path, "client\ndhcp-option DNS 1.1.1.1\n").unwrap();
        let profile = Profile::new(
            crate::vortix_core::profile::ProfileId::new("corp"),
            "corp",
            crate::vortix_core::profile::ProtocolKind::OpenVpn,
            profile_path,
        );
        std::fs::write(
            temp.path().join(format!("{}.log", profile.id)),
            "PUSH_REPLY,dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN corp.example\nInitialization Sequence Completed\n",
        )
        .unwrap();
        let evidence = OvpnTunnel::new(temp.path().to_path_buf())
            .requested_dns_evidence(&profile)
            .unwrap();
        let OvpnDnsEvidence::Observed(request) = evidence else {
            panic!("complete pushed DNS must be observed");
        };
        assert_eq!(request.servers.len(), 2);
        assert_eq!(request.search_domains, vec!["corp.example"]);
    }

    #[test]
    fn completed_negotiation_without_pushed_dns_is_explicitly_empty() {
        let configured = crate::vortix_core::ports::dns::DnsRequest {
            servers: vec!["1.1.1.1".parse().unwrap()],
            search_domains: Vec::new(),
        };
        let evidence = pushed_dns_evidence(
            configured.clone(),
            "PUSH_REPLY,redirect-gateway def1,ping 10\nInitialization Sequence Completed\n",
        );
        assert_eq!(evidence, OvpnDnsEvidence::ExplicitlyEmpty(configured));
    }

    #[test]
    fn truncated_negotiation_is_unavailable_not_explicitly_empty() {
        let configured = crate::vortix_core::ports::dns::DnsRequest::default();
        let evidence = pushed_dns_evidence(
            configured.clone(),
            "PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 10.8.0.1\n",
        );
        assert!(matches!(
            evidence,
            OvpnDnsEvidence::Unavailable {
                configured: actual,
                ..
            } if actual == configured
        ));
    }

    #[test]
    fn newer_incomplete_negotiation_does_not_reuse_old_pushed_dns() {
        let evidence = pushed_dns_evidence(
            crate::vortix_core::ports::dns::DnsRequest::default(),
            "PUSH_REPLY,dhcp-option DNS 10.8.0.1\nInitialization Sequence Completed\nPUSH_REPLY,redirect-gateway def1\n",
        );
        assert!(matches!(evidence, OvpnDnsEvidence::Unavailable { .. }));
    }

    #[test]
    fn latest_completed_negotiation_replaces_older_pushed_dns() {
        let evidence = pushed_dns_evidence(
            crate::vortix_core::ports::dns::DnsRequest::default(),
            "PUSH_REPLY,dhcp-option DNS 10.8.0.1\nInitialization Sequence Completed\nPUSH_REPLY,dhcp-option DNS 10.9.0.1\nInitialization Sequence Completed\n",
        );
        let OvpnDnsEvidence::Observed(request) = evidence else {
            panic!("latest completed negotiation must be observed");
        };
        assert_eq!(
            request.servers,
            vec!["10.9.0.1".parse::<std::net::IpAddr>().unwrap()]
        );
    }

    #[test]
    fn malformed_pushed_dns_is_unavailable_not_explicitly_empty() {
        let configured = crate::vortix_core::ports::dns::DnsRequest::default();
        let evidence = pushed_dns_evidence(
            configured,
            "PUSH_REPLY,dhcp-option DNS not-an-address\nInitialization Sequence Completed\n",
        );
        assert!(matches!(evidence, OvpnDnsEvidence::Unavailable { .. }));
    }

    #[test]
    fn missing_runtime_log_is_unavailable() {
        let temp = tempfile::tempdir().unwrap();
        let profile_path = temp.path().join("corp.ovpn");
        std::fs::write(&profile_path, "client\ndhcp-option DNS 1.1.1.1\n").unwrap();
        let profile = Profile::new(
            crate::vortix_core::profile::ProfileId::new("corp"),
            "corp",
            crate::vortix_core::profile::ProtocolKind::OpenVpn,
            profile_path,
        );

        let evidence = OvpnTunnel::new(temp.path().to_path_buf())
            .requested_dns_evidence(&profile)
            .unwrap();
        assert!(matches!(
            evidence,
            OvpnDnsEvidence::Unavailable { configured, .. }
                if configured.servers == vec!["1.1.1.1".parse::<std::net::IpAddr>().unwrap()]
        ));
    }
}
