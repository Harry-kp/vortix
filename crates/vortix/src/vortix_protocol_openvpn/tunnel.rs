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

/// Callback that materialises auth bytes from a `SecretStore` (plan 006 U5).
///
/// `Fn(profile_id) -> Option<Vec<u8>>`. When set on `OvpnTunnel`, `up()`
/// asks the closure for the profile's auth bytes; on `Some`, writes them
/// to an ephemeral file with mode 0600, points `openvpn --auth-user-pass`
/// at it, and deletes the file after spawn.
pub type SecretProvider = std::sync::Arc<dyn Fn(&str) -> Option<Vec<u8>> + Send + Sync>;

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
    /// Optional `SecretStore`-backed auth materialisation hook (plan 006 U5).
    /// When set, takes precedence over the on-disk `auth_dir` lookup.
    pub secret_provider: Option<SecretProvider>,
}

impl std::fmt::Debug for OvpnTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OvpnTunnel")
            .field("run_dir", &self.run_dir)
            .field("auth_dir", &self.auth_dir)
            .field("verbosity", &self.verbosity)
            .field("connect_timeout_secs", &self.connect_timeout_secs)
            .field("secret_provider", &self.secret_provider.is_some())
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
            secret_provider: None,
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

    /// Builder: install a `SecretStore`-backed auth-bytes provider
    /// (plan 006 U5). When set, `up()` materialises an ephemeral auth
    /// file from `provider(profile_id)` instead of reading from
    /// `<auth_dir>/<safe_name>.auth`.
    #[must_use]
    pub fn with_secret_provider(mut self, provider: SecretProvider) -> Self {
        self.secret_provider = Some(provider);
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
fn poll_log_until_ready(
    log_path: &std::path::Path,
    pid_path: &std::path::Path,
    timeout_secs: u64,
) -> Result<u32, TunnelError> {
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
                return Ok(pid);
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

/// Write `bytes` to `path` with mode 0600 (Unix; best-effort on other OSes).
/// Used by the SecretStore-backed auth flow (plan 006 U5).
fn write_ephemeral_auth(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.flush()?;
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::File::create(path)?;
        f.write_all(bytes)?;
        f.flush()?;
    }
    Ok(())
}

fn tail_lines(content: &str, n: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

impl Tunnel for OvpnTunnel {
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

        let mut args = vec![
            "--config".to_string(),
            profile.config_path.to_string_lossy().into_owned(),
            "--daemon".to_string(),
            format!("vortix-{safe_name}"),
            "--writepid".to_string(),
            pid_path.to_string_lossy().into_owned(),
            "--log".to_string(),
            log_path.to_string_lossy().into_owned(),
            "--verb".to_string(),
            self.verbosity.clone(),
        ];

        // Plan 006 U5: SecretStore-backed auth takes precedence. When a
        // secret_provider is installed and returns bytes for this profile,
        // materialise them into an ephemeral 0600 file under `run_dir`,
        // point `--auth-user-pass` at it, and remember the path for
        // cleanup. Otherwise fall back to the legacy `<auth_dir>/<name>.auth`.
        let ephemeral_auth = if let Some(provider) = &self.secret_provider {
            if let Some(bytes) = provider(profile.id.as_str()) {
                let path = self.run_dir.join(format!("{safe_name}.auth.ephemeral"));
                let written = write_ephemeral_auth(&path, &bytes);
                if let Err(e) = &written {
                    tracing::warn!(
                        target: "vortix::tunnel::openvpn",
                        error = %e,
                        "failed to materialise ephemeral auth file; falling back to auth_dir"
                    );
                }
                written.ok().map(|()| path)
            } else {
                None
            }
        } else {
            None
        };

        let auth_to_use = ephemeral_auth
            .clone()
            .or_else(|| self.auth_path(&safe_name).filter(|p| p.exists()));
        if let Some(auth) = auth_to_use {
            args.push("--auth-user-pass".to_string());
            args.push(auth.to_string_lossy().into_owned());
        }

        let output_result = crate::vortix_process::run_to_output(
            CommandSpec::oneshot("openvpn", args).privilege(PrivilegeReq::Root),
        );

        // Plan 006 U5: the daemon has forked + read the auth file by now.
        // Remove the ephemeral copy before propagating the spawn result so
        // the secret bytes don't linger on disk if the call fails.
        if let Some(path) = &ephemeral_auth {
            let _ = std::fs::remove_file(path);
        }

        let output = output_result.map_err(|e| TunnelError::Subprocess(format!("openvpn: {e}")))?;

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
        let pid = poll_log_until_ready(&log_path, &pid_path, self.connect_timeout_secs)?;

        Ok(TunnelHandle {
            profile_id: profile.id.clone(),
            interface_name: format!("openvpn-{safe_name}"),
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
            let output = crate::vortix_process::run_to_output(
                CommandSpec::oneshot("kill", vec!["-15".into(), pid.to_string()])
                    .privilege(PrivilegeReq::Root),
            )
            .map_err(|e| TunnelError::Subprocess(format!("kill openvpn pid: {e}")))?;
            if !output.status.success() {
                warn!(
                    target: "vortix::tunnel::openvpn",
                    pid = pid,
                    "kill -15 returned non-zero; falling back to pkill"
                );
            }
        }

        // Fall back to pkill in case the pid was stale.
        let _ = crate::vortix_process::run_to_output(
            CommandSpec::oneshot(
                "pkill",
                vec![
                    "-15".into(),
                    "-f".into(),
                    format!("openvpn.*--daemon vortix-{safe_name}"),
                ],
            )
            .privilege(PrivilegeReq::Root),
        );

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
}
