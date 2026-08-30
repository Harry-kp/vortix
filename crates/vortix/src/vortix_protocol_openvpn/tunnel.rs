//! `OvpnTunnel` — `OpenVPN` impl of the `Tunnel` port.
//!
//! Spawns `OpenVPN` as a foreground child owned by the Standard-mode lifecycle
//! custodian, then polls the log for protocol readiness. `OpenVPN` never
//! self-daemonizes, so Vortix retains a reapable process-group owner.

use std::fmt::Write as FmtWrite;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::vortix_core::control::{OperationId, Secret};
use crate::vortix_core::ports::process::ManagedProcessId;
use crate::vortix_core::ports::tunnel::{
    ParseError, ParsedProfile, ProtocolStatus, Tunnel, TunnelCapabilities, TunnelError,
    TunnelHandle, TunnelKindTag, TunnelStatus,
};
use crate::vortix_core::profile::{unambiguous_legacy_artifact_key, Profile, ProfileId};
use crate::vortix_process::{CommandSpec, PrivilegeReq};
use tracing::{debug, info, warn};

use crate::vortix_protocol_openvpn::parser::{forbidden_effective_directive, parse_ovpn_conf};
use crate::vortix_protocol_openvpn::push::{latest_completed_push_reply, PushReplySelectionError};

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

/// DNS and route truth parsed from one profile and one completed runtime-log
/// snapshot, so a renegotiation cannot mix evidence from different sessions.
pub(crate) struct OvpnRuntimeEvidence {
    pub(crate) dns: OvpnDnsEvidence,
    pub(crate) routes: crate::vortix_core::privileged::OpenVpnRouteEvidence,
}

/// Maximum wall-clock to wait for openvpn to create the unix
/// management socket after spawn. Typical macOS spawn takes <200ms; 5s gives
/// loaded systems ample headroom while still surfacing
/// catastrophic-spawn-failure within the user's attention span.
const OVPN_MGMT_SOCKET_TIMEOUT_MS: u64 = 5000;
const MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES: usize = 103;
const MANAGED_CONFIG_MARKER: &str = "# managed-by: vortix openvpn custodian";

#[derive(Debug, thiserror::Error)]
#[error(
    "OpenVPN `{directive}` directives are not allowed in managed profiles: Vortix never runs profile commands as root; migrate lifecycle automation to a global hook using an absolute executable plus argv"
)]
struct ManagedConfigViolation {
    directive: String,
}

fn sanitize_managed_config(text: &str) -> Result<String, TunnelError> {
    let mut output = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        validate_managed_line(line).map_err(|error| TunnelError::Subprocess(error.to_string()))?;
        let directive = line.split(['#', ';']).next().unwrap_or_default();
        let mut tokens = directive.split_whitespace();
        let first = tokens.next().map(|value| value.trim_start_matches('-'));
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

fn validate_managed_line(line: &str) -> Result<(), ManagedConfigViolation> {
    if let Some(directive) = forbidden_effective_directive(line) {
        return Err(ManagedConfigViolation { directive });
    }
    Ok(())
}

fn validate_managed_config(path: &Path) -> Result<String, TunnelError> {
    let body = std::fs::read_to_string(path)?;
    sanitize_managed_config(&body)
}

fn resolve_managed_endpoints(profile: &Profile, text: &str) -> Result<String, TunnelError> {
    if !profile.require_managed_endpoint_resolution {
        return Ok(text.to_owned());
    }
    let mut output = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let directive = line.split(['#', ';']).next().unwrap_or_default();
        let mut tokens = directive.split_whitespace();
        if !matches!(tokens.next(), Some(value) if value.eq_ignore_ascii_case("remote")) {
            output.push_str(line);
            continue;
        }
        let Some(host) = tokens.next() else {
            return Err(TunnelError::Subprocess(
                "managed OpenVPN remote is malformed".into(),
            ));
        };
        if host.parse::<std::net::IpAddr>().is_ok() {
            output.push_str(line);
            continue;
        }
        let port = tokens
            .next()
            .map_or(Ok(1194_u16), str::parse)
            .map_err(|_| {
                TunnelError::Subprocess("managed OpenVPN remote port is invalid".into())
            })?;
        let transport = tokens.next();
        let Some(address) = profile.resolved_endpoint(host, port) else {
            return Err(TunnelError::Subprocess(format!(
                "managed OpenVPN endpoint {host}:{port} has no unambiguous profile-bound resolution"
            )));
        };
        write!(output, "remote {address} {port}").expect("writing to String cannot fail");
        if let Some(transport) = transport {
            write!(output, " {transport}").expect("writing to String cannot fail");
        }
        if line.ends_with('\n') {
            output.push('\n');
        }
    }
    Ok(output)
}

fn prepare_managed_config(profile: &Profile) -> Result<String, TunnelError> {
    let sanitized = validate_managed_config(&profile.config_path)?;
    resolve_managed_endpoints(profile, &sanitized)
}

#[cfg(test)]
fn managed_config(profile: &Profile, identity: &ManagedProcessId) -> Result<PathBuf, TunnelError> {
    let stripped = prepare_managed_config(profile)?;
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

/// Adapt the shared bounded management driver to the Standard-mode tunnel
/// error vocabulary. A non-empty answer selects the supported SCRV1 static
/// challenge; every other interactive challenge remains fail-closed.
fn drive_mgmt_auth(
    stream: UnixStream,
    user: &str,
    pass: &str,
    answer: &[u8],
    connect_timeout_secs: u64,
) -> Result<(), TunnelError> {
    let challenge = (!answer.is_empty())
        .then_some(crate::vortix_core::privileged::OpenVpnChallengeKind::Static);
    crate::vortix_protocol_openvpn::management::authenticate(
        stream,
        user,
        pass,
        answer,
        challenge,
        Duration::from_secs(connect_timeout_secs),
    )
    .map_err(|error| match error {
        crate::vortix_protocol_openvpn::management::ManagementAuthError::AuthenticationRejected
        | crate::vortix_protocol_openvpn::management::ManagementAuthError::UnsupportedChallenge
        | crate::vortix_protocol_openvpn::management::ManagementAuthError::InvalidCredentials => {
            TunnelError::AuthFailed(error.to_string())
        }
        crate::vortix_protocol_openvpn::management::ManagementAuthError::DaemonExited => {
            TunnelError::DaemonExited(error.to_string())
        }
        _ => TunnelError::Subprocess(error.to_string()),
    })
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

/// One-shot in-memory credentials for a service-owned static challenge.
/// Debug, clone, and serde are deliberately unavailable.
pub struct OpenVpnStaticChallengeCredentials {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
    answer: Secret,
}

impl OpenVpnStaticChallengeCredentials {
    #[must_use]
    pub fn new(username: String, password: String, answer: Secret) -> Self {
        Self {
            username: Zeroizing::new(username),
            password: Zeroizing::new(password),
            answer,
        }
    }

    #[cfg(test)]
    pub(crate) fn username_password_for_test(&self) -> (&str, &str) {
        (&self.username, &self.password)
    }
}

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
    /// Canonical control revision assigned before the custodian capability is
    /// created. Legacy callers leave this unset and retain a random attempt
    /// generation.
    generation: Option<u64>,
    /// Canonical connect operation persisted into the custodian receipt.
    /// Legacy engine/TUI callers leave this unset.
    operation_id: Option<OperationId>,
    /// Shared only to preserve the tunnel carrier's historical `Clone`
    /// contract; the credential value itself can be taken exactly once.
    static_challenge_credentials:
        Option<std::sync::Arc<std::sync::Mutex<Option<OpenVpnStaticChallengeCredentials>>>>,
}

impl std::fmt::Debug for OvpnTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OvpnTunnel")
            .field("run_dir", &self.run_dir)
            .field("auth_dir", &self.auth_dir)
            .field("verbosity", &self.verbosity)
            .field("connect_timeout_secs", &self.connect_timeout_secs)
            .field("generation", &self.generation)
            .field("operation_id", &self.operation_id)
            .field(
                "static_challenge_credentials",
                &self
                    .static_challenge_credentials
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
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
            generation: None,
            operation_id: None,
            static_challenge_credentials: None,
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

    /// Fence the Standard-mode custodian capability to one control revision.
    #[must_use]
    pub fn for_generation(mut self, generation: u64) -> Self {
        self.generation = Some(generation);
        self
    }

    /// Bind the managed child to the canonical operation that created it.
    #[must_use]
    pub fn for_operation(mut self, operation_id: OperationId) -> Self {
        self.operation_id = Some(operation_id);
        self
    }

    /// Supply the exact one-shot answer delivered by the canonical service.
    #[must_use]
    pub fn with_static_challenge_credentials(
        mut self,
        credentials: OpenVpnStaticChallengeCredentials,
    ) -> Self {
        self.static_challenge_credentials = Some(std::sync::Arc::new(std::sync::Mutex::new(Some(
            credentials,
        ))));
        self
    }

    fn ownership_id(&self, profile_id: &ProfileId) -> Result<ManagedProcessId, TunnelError> {
        let mut ownership_id = ManagedProcessId::generate(profile_id.clone()).map_err(|error| {
            TunnelError::Subprocess(format!("allocate OpenVPN ownership token: {error}"))
        })?;
        if let Some(generation) = self.generation {
            if generation == 0 {
                return Err(TunnelError::Other(
                    "canonical OpenVPN generation must be non-zero".into(),
                ));
            }
            ownership_id.generation = generation;
        }
        Ok(ownership_id)
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
        let log_path = self.runtime_log_path(profile);
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

    fn runtime_log_path(&self, profile: &Profile) -> PathBuf {
        let canonical_log = self.log_path(profile.id.as_str());
        if canonical_log.exists() {
            canonical_log
        } else if let Some(legacy_key) = unambiguous_legacy_artifact_key(&profile.display_name) {
            self.log_path(legacy_key)
        } else {
            canonical_log
        }
    }

    pub(crate) fn requested_runtime_evidence(
        &self,
        profile: &Profile,
    ) -> Result<OvpnRuntimeEvidence, TunnelError> {
        let profile_text = std::fs::read_to_string(&profile.config_path).map_err(|error| {
            TunnelError::Subprocess(format!("read OpenVPN profile runtime intent: {error}"))
        })?;
        let parsed = parse_ovpn_conf(&profile_text).map_err(|error| {
            TunnelError::Subprocess(format!("parse OpenVPN runtime intent: {error}"))
        })?;
        let log_path = self.runtime_log_path(profile);
        let log = std::fs::read_to_string(&log_path).map_err(|error| {
            TunnelError::Subprocess(format!(
                "read OpenVPN runtime evidence from {}: {error}",
                log_path.display()
            ))
        })?;
        let dns = pushed_dns_evidence(parsed.dns_request(), &log);
        let routes =
            crate::vortix_protocol_openvpn::push::openvpn_route_evidence(&parsed, &log, false)
                .map_err(|error| {
                    TunnelError::Subprocess(format!("validate OpenVPN route evidence: {error}"))
                })?;
        Ok(OvpnRuntimeEvidence { dns, routes })
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
        let digest = Sha256::digest(profile_id.as_bytes());
        let key = digest
            .iter()
            .take(16)
            .fold(String::with_capacity(32), |mut encoded, byte| {
                let _ = write!(encoded, "{byte:02x}");
                encoded
            });
        self.run_dir.join(format!("{key}.mgmt.sock"))
    }

    fn validate_management_socket_path(path: &Path) -> Result<(), TunnelError> {
        if path.as_os_str().as_encoded_bytes().len() > MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES {
            return Err(TunnelError::Subprocess(format!(
                "OpenVPN runtime directory is too long for a portable Unix management socket: {}",
                path.display()
            )));
        }
        Ok(())
    }

    fn cleanup_run_artifacts(&self, handle: &TunnelHandle) {
        let artifact_key = handle.profile_id.as_str();
        let _ = std::fs::remove_file(self.pid_path(artifact_key));
        let _ = std::fs::remove_file(self.log_path(artifact_key));
        let _ = std::fs::remove_file(self.management_socket_path(artifact_key));
        if let Some(legacy_key) = unambiguous_legacy_artifact_key(&handle.display_name) {
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
                unambiguous_legacy_artifact_key(&profile.display_name)
                    .and_then(|legacy_key| self.auth_path(legacy_key))
                    .filter(|path| path.exists())
            })
    }

    fn existing_scrv1_auth_path(&self, profile: &Profile) -> Option<PathBuf> {
        self.scrv1_auth_path(profile.id.as_str())
            .filter(|path| path.exists())
            .or_else(|| {
                unambiguous_legacy_artifact_key(&profile.display_name)
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

fn resolve_standard_openvpn_binary() -> Result<PathBuf, TunnelError> {
    // Standard mode deliberately accepts the owner's full client and package
    // installation as root-trusted input (including Homebrew). Canonicalizing
    // the existing PATH result prevents a second lookup inside the privileged
    // child; package-owned identity/digest verification belongs to U12's
    // Background-mode helper boundary.
    let candidate = crate::utils::find_binary_path("openvpn").ok_or_else(|| {
        TunnelError::Subprocess("OpenVPN executable was not found on PATH".into())
    })?;
    candidate.canonicalize().map_err(|error| {
        TunnelError::Subprocess(format!(
            "resolve OpenVPN executable {}: {error}",
            candidate.display()
        ))
    })
}

fn privileged_openvpn_command(program: &Path, args: Vec<String>) -> CommandSpec {
    let mut command =
        CommandSpec::oneshot(program.to_string_lossy(), args).privilege(PrivilegeReq::Root);
    // The daemon may inherit caller-controlled OpenSSL provider and dynamic
    // loader variables. Resolve the executable before this boundary, then
    // launch it with an empty environment so the child never searches PATH or
    // consumes provider/loader configuration from its caller.
    command.env_clear = true;
    command
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
    let push_reply = match latest_completed_push_reply(log) {
        Ok(Some(push_reply)) => push_reply,
        Ok(None) => return OvpnDnsEvidence::ExplicitlyEmpty(request),
        Err(PushReplySelectionError::NoCompletedNegotiation) => {
            return OvpnDnsEvidence::Unavailable {
                configured: request,
                reason: "OpenVPN log has no completed negotiation marker".into(),
            };
        }
        Err(PushReplySelectionError::NewerIncompleteNegotiation) => {
            return OvpnDnsEvidence::Unavailable {
                configured: request,
                reason: "OpenVPN log contains a newer incomplete negotiation".into(),
            };
        }
    };
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
        let validated_config = prepare_managed_config(profile)?;
        let openvpn_binary = resolve_standard_openvpn_binary()?;

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

        let ownership_id = self.ownership_id(&profile.id)?;
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
        let service_creds = self
            .static_challenge_credentials
            .as_ref()
            .map(|slot| {
                slot.lock()
                    .map_err(|_| {
                        TunnelError::Subprocess(
                            "static-challenge credential slot was poisoned".into(),
                        )
                    })?
                    .take()
                    .ok_or_else(|| {
                        TunnelError::Subprocess(
                            "static-challenge credentials were already consumed".into(),
                        )
                    })
            })
            .transpose()?;
        let bundle_path = service_creds
            .is_none()
            .then(|| self.existing_scrv1_auth_path(profile))
            .flatten();
        let file_creds = if let Some(p) = &bundle_path {
            read_mgmt_credentials_bundle(p)
                .map_err(|e| TunnelError::Subprocess(format!("mgmt creds bundle: {e}")))?
        } else {
            None
        };
        let mgmt_creds = service_creds.or_else(|| {
            file_creds.map(|(username, password, answer)| {
                OpenVpnStaticChallengeCredentials::new(
                    username,
                    password,
                    Secret::new(answer.into_bytes()),
                )
            })
        });

        let mgmt_sock_path = if mgmt_creds.is_some() {
            let path = self.management_socket_path(artifact_key);
            Self::validate_management_socket_path(&path)?;
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

        let cleanup_paths = vec![
            effective_config.clone(),
            self.management_socket_path(artifact_key),
        ];
        let command = privileged_openvpn_command(&openvpn_binary, args);
        let handshake = match self.operation_id.clone() {
            Some(operation_id) => crate::vortix_process::start_managed_foreground_for_operation(
                ownership_id.clone(),
                command,
                cleanup_paths,
                operation_id,
            ),
            None => crate::vortix_process::start_managed_foreground(
                ownership_id.clone(),
                command,
                cleanup_paths,
            ),
        };
        let handshake = match handshake {
            Ok(handshake) => handshake,
            Err(error) => {
                let _ = std::fs::remove_file(&effective_config);
                return Err(TunnelError::Subprocess(format!("openvpn custody: {error}")));
            }
        };

        if let (Some(creds), Some(sock_path)) = (mgmt_creds, mgmt_sock_path) {
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
                    creds.username.as_str(),
                    creds.password.as_str(),
                    creds.answer.expose(),
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

            let runtime_evidence = self.requested_runtime_evidence(profile)?;
            let dns_request = match runtime_evidence.dns {
                OvpnDnsEvidence::Observed(request) | OvpnDnsEvidence::ExplicitlyEmpty(request) => {
                    request
                }
                OvpnDnsEvidence::Unavailable { reason, .. } => {
                    return Err(TunnelError::DaemonExited(format!(
                        "OpenVPN connected but DNS negotiation evidence is unavailable: {reason}"
                    )));
                }
            };
            let openvpn_routes = Some(runtime_evidence.routes);

            Ok(TunnelHandle {
                profile_id: profile.id.clone(),
                display_name: profile.display_name.clone(),
                interface_name,
                pid: Some(pid),
                started_at: SystemTime::now(),
                kind: TunnelKindTag::OpenVpn,
                generation: ownership_id.generation,
                handshake: None,
                probe_receipts: Vec::new(),
                process_ownership: Some(handshake.identity),
                teardown_config: None,
                dns_request,
                openvpn_routes,
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
            "{startup}; OpenVPN startup teardown failed and ownership is ambiguous for generation {}: {teardown}",
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
    fn canonical_generation_and_operation_fence_standard_custodian_identity() {
        let operation: OperationId =
            serde_json::from_str("\"op-0000000000000001-0000000000000001\"").unwrap();
        let tunnel = OvpnTunnel::default()
            .for_generation(41)
            .for_operation(operation.clone());
        assert_eq!(tunnel.generation, Some(41));
        assert_eq!(tunnel.operation_id, Some(operation));
        assert_eq!(
            tunnel
                .ownership_id(&ProfileId::new("corp"))
                .unwrap()
                .generation,
            41
        );
        assert!(OvpnTunnel::default()
            .for_generation(0)
            .ownership_id(&ProfileId::new("corp"))
            .is_err());
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
    fn canonical_profile_id_keeps_management_socket_within_unix_path_limit() {
        let tunnel = OvpnTunnel::new(PathBuf::from("/Users/vortix/.config/vortix/run"));
        let profile_id = "a".repeat(crate::vortix_core::profile::ProfileId::HEX_LEN);
        let socket = tunnel.management_socket_path(&profile_id);

        assert!(
            socket.as_os_str().as_encoded_bytes().len() <= 103,
            "management socket path exceeds macOS sockaddr_un.sun_path: {}",
            socket.display()
        );
    }

    #[test]
    fn in_memory_static_challenge_is_redacted_from_debug() {
        let tunnel = OvpnTunnel::new(PathBuf::from("/tmp/vortix-test"))
            .with_static_challenge_credentials(OpenVpnStaticChallengeCredentials::new(
                "secret-user".into(),
                "secret-password".into(),
                Secret::new(b"654321".to_vec()),
            ));

        let debug = format!("{tunnel:?}");
        for secret in ["secret-user", "secret-password", "654321"] {
            assert!(!debug.contains(secret));
        }
        assert!(debug.contains("[REDACTED]"));
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
    fn privileged_openvpn_spawn_uses_an_allowlisted_environment() {
        let command = privileged_openvpn_command(
            std::path::Path::new("/usr/sbin/openvpn"),
            vec!["--version".into()],
        );
        assert_eq!(command.requires_privilege, PrivilegeReq::Root);
        assert!(std::path::Path::new(&command.program).is_absolute());
        assert!(command.env_clear);
        assert!(command.env.is_empty());
        for unsafe_name in [
            "OPENSSL_CONF",
            "OPENSSL_MODULES",
            "OPENSSL_ENGINES",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "DYLD_FRAMEWORK_PATH",
        ] {
            assert!(!command.env.contains_key(unsafe_name));
        }
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
    fn managed_config_rewrites_cached_remote_without_dns() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("corp.ovpn");
        std::fs::write(&path, "client\nremote vpn.example 1194 udp\n").unwrap();
        let profile = Profile::new(
            crate::vortix_core::profile::ProfileId::new("corp"),
            "corp",
            crate::vortix_core::profile::ProtocolKind::OpenVpn,
            path,
        )
        .with_endpoint_resolutions([crate::vortix_core::profile::ResolvedEndpoint::new(
            "vpn.example",
            1194,
            "203.0.113.19".parse().unwrap(),
        )])
        .require_managed_endpoint_resolution();
        let identity = ManagedProcessId {
            profile_id: profile.id.clone(),
            generation: 7,
            ownership_token: "a".repeat(64),
        };
        let managed = managed_config(&profile, &identity).unwrap();
        let body = std::fs::read_to_string(&managed).unwrap();
        assert!(body.contains("remote 203.0.113.19 1194 udp"));
        assert!(!body.contains("vpn.example"));
    }

    #[test]
    fn managed_config_refuses_unresolved_hostname_remote() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("corp.ovpn");
        std::fs::write(&path, "client\nremote vpn.example 1194 udp\n").unwrap();
        let profile = Profile::new(
            crate::vortix_core::profile::ProfileId::new("corp"),
            "corp",
            crate::vortix_core::profile::ProtocolKind::OpenVpn,
            path,
        )
        .require_managed_endpoint_resolution();
        let identity = ManagedProcessId {
            profile_id: profile.id.clone(),
            generation: 7,
            ownership_token: "a".repeat(64),
        };
        let error =
            managed_config(&profile, &identity).expect_err("missing cache must fail closed");
        assert!(error.to_string().contains("vpn.example:1194"));
    }

    #[test]
    fn cached_profile_resolution_reaches_openvpn_managed_config_without_dns() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("corp.ovpn");
        let body = "client\nremote endpoint.invalid 1194 udp\n";
        std::fs::write(&path, body).unwrap();
        let vpn_profile = crate::state::VpnProfile {
            id: crate::vortix_core::profile::ProfileId::new("corp"),
            name: "Corporate".into(),
            protocol: crate::state::Protocol::OpenVPN,
            location: String::new(),
            config_path: path,
            last_used: None,
        };
        let digest = crate::vortix_core::control::PolicyDigest::sha256(body.as_bytes()).0;
        let cache_json = serde_json::json!({
            "schema_version": 1,
            "profiles": {
                "corp": {
                    "profile_digest": digest,
                    "endpoints": [{
                        "hostname": "endpoint.invalid",
                        "port": 1194,
                        "address": "203.0.113.19"
                    }]
                }
            }
        });
        let encoded = serde_json::to_vec(&cache_json).unwrap();
        let mut cache =
            crate::topology_policy::EndpointResolutionCache::decode(Some(&encoded)).unwrap();
        let topology = crate::topology_policy::topology_for_profile(&vpn_profile, &mut cache)
            .expect("exact cache entry resolves topology without DNS");
        let profile = crate::tunnel::profile_view(&vpn_profile)
            .with_endpoint_resolutions(topology.resolved_endpoints)
            .require_managed_endpoint_resolution();
        let identity = ManagedProcessId {
            profile_id: profile.id.clone(),
            generation: 7,
            ownership_token: "a".repeat(64),
        };
        let managed = managed_config(&profile, &identity).unwrap();
        let managed_body = std::fs::read_to_string(managed).unwrap();
        assert!(managed_body.contains("remote 203.0.113.19 1194 udp"));
        assert!(!managed_body.contains("endpoint.invalid"));
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
    fn managed_config_rejects_external_crypto_providers() {
        for directive in [
            "providers legacy default",
            "--EnGiNe pkcs11",
            "pkcs11-providers /tmp/evil.so",
        ] {
            let error = sanitize_managed_config(&format!("client\n{directive}\n"))
                .expect_err("provider-loading directives must not reach privileged OpenVPN");
            assert!(
                error.to_string().contains(
                    directive
                        .split_whitespace()
                        .next()
                        .unwrap()
                        .trim_start_matches('-')
                        .to_ascii_lowercase()
                        .as_str()
                ),
                "unexpected error for {directive}: {error}"
            );
        }
    }

    #[test]
    fn managed_config_rejects_effective_privileged_aliases() {
        for directive in [
            "setenv opt plugin malicious.so",
            "--setenv opt up ./up.sh",
            "SeTeNv OpT providers legacy default",
            "setenv opt --config nested.ovpn",
            "\"up\" ./up.sh",
        ] {
            let error = sanitize_managed_config(&format!("client\n{directive}\n"))
                .expect_err("effective privileged aliases must not reach root OpenVPN");
            assert!(
                error.to_string().contains("not allowed"),
                "unexpected error for {directive}: {error}"
            );
        }

        let safe = "client\nsetenv opt block-outside-dns\n";
        assert_eq!(sanitize_managed_config(safe).unwrap(), safe);
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
    fn route_evidence_recovers_pushed_default_from_existing_log() {
        let temp = tempfile::tempdir().unwrap();
        let profile_path = temp.path().join("corp.ovpn");
        std::fs::write(
            &profile_path,
            "client\nremote 198.51.100.7 1194 udp\nroute 10.20.0.0 255.255.0.0\n",
        )
        .unwrap();
        let profile = Profile::new(
            crate::vortix_core::profile::ProfileId::new("corp"),
            "corp",
            crate::vortix_core::profile::ProtocolKind::OpenVpn,
            profile_path,
        );
        std::fs::write(
            temp.path().join(format!("{}.log", profile.id)),
            "UDPv4 link remote: [AF_INET]198.51.100.7:1194\n\
             PUSH_REPLY,redirect-gateway def1 bypass-dhcp,dhcp-option DNS 1.1.1.1\n\
             Initialization Sequence Completed\n",
        )
        .unwrap();

        let evidence = OvpnTunnel::new(temp.path().to_path_buf())
            .requested_runtime_evidence(&profile)
            .unwrap();

        assert_eq!(evidence.routes.configured().routes().len(), 1);
        let redirect = evidence.routes.pushed().redirect_gateway().unwrap();
        assert!(redirect.ipv4());
        assert!(redirect
            .flags()
            .contains(&crate::vortix_core::privileged::OpenVpnRedirectFlag::Def1));
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
