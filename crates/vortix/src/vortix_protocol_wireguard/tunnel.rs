//! `WgTunnel` — `WireGuard` impl of the `Tunnel` port.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::vortix_core::ports::tunnel::{
    HandshakeAttempt, ParseError, ParsedProfile, ProbeReceipt, ProtocolStatus, Tunnel,
    TunnelCapabilities, TunnelError, TunnelExecutionContext, TunnelHandle, TunnelKindTag,
    TunnelPeerStatus, TunnelStatus, TunnelTeardownConfig,
};
use crate::vortix_core::profile::Profile;
use crate::vortix_process::{CommandSpec, PrivilegeReq};
use tracing::info;
// `warn!` is only used by the macOS-only diagnostic at line ~227.
// Gate the import so Linux clippy doesn't flag it as unused.
#[cfg(target_os = "macos")] // xtask:allow-platform-cfg: import for macOS-only warn! call
use tracing::warn;

use crate::vortix_protocol_wireguard::parser::parse_wg_conf;

/// `wg-quick`-based `WireGuard` tunnel.
///
/// Plan #004 v1 supports kernel `WireGuard` only — `wireguard-go`/`boringtun`
/// user-space backends land with idea 5's daemon work.
///
/// DNS directives are always removed from the `wg-quick` input. The parsed
/// request is returned on [`TunnelHandle`] for the protocol-neutral policy
/// coordinator; `wg-quick` never mutates resolver state itself.
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const DEFAULT_STATUS_POLL: Duration = Duration::from_millis(250);
const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const MIN_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(300);
const MIN_STATUS_POLL: Duration = Duration::from_millis(10);
const MAX_STATUS_POLL: Duration = Duration::from_secs(5);
const MAX_PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HEALTH_TARGETS: usize = 64;
const MAX_WG_DUMP_BYTES: usize = 1024 * 1024;
const MAX_WG_PEERS: usize = 256;
const MAX_ROUTES_PER_PEER: usize = 256;
const MAX_WG_FIELD_BYTES: usize = 4096;
const MAX_WG_PROFILE_BYTES: usize = 1024 * 1024;
const HANDSHAKE_FUTURE_TOLERANCE: Duration = Duration::from_secs(300);
static NEXT_ATTEMPT_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct WgTunnel {
    handshake_timeout: Duration,
    status_poll: Duration,
    probe_timeout: Duration,
    health_targets: Vec<IpAddr>,
    generation_override: Option<u64>,
    execution_context: Option<TunnelExecutionContext>,
    /// Exact attempt capability retained across unwinding until `up` returns
    /// a trustworthy handle or proves absence.
    inflight: Option<Box<WgInflightAttempt>>,
}

#[derive(Debug, Clone)]
struct WgInflightAttempt {
    profile_id: crate::vortix_core::profile::ProfileId,
    display_name: String,
    interface_basename: String,
    started_at: SystemTime,
    generation: u64,
    temp_path: PathBuf,
}

impl Default for WgTunnel {
    fn default() -> Self {
        Self {
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            status_poll: DEFAULT_STATUS_POLL,
            probe_timeout: DEFAULT_PROBE_TIMEOUT,
            health_targets: crate::constants::DEFAULT_PING_TARGETS
                .iter()
                .filter_map(|target| target.parse().ok())
                .collect(),
            generation_override: None,
            execution_context: None,
            inflight: None,
        }
    }
}

impl WgTunnel {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_handshake_policy(
        mut self,
        timeout: Duration,
        health_targets: impl IntoIterator<Item = IpAddr>,
    ) -> Self {
        self.handshake_timeout = timeout;
        self.health_targets = health_targets.into_iter().collect();
        self
    }

    /// Fence the next connect to the canonical worker's desired generation.
    #[must_use]
    pub fn for_generation(mut self, generation: u64) -> Self {
        self.generation_override = Some(generation);
        self
    }

    /// Bind cancellation and the canonical operation deadline to this effect.
    #[must_use]
    pub fn with_execution_context(mut self, context: TunnelExecutionContext) -> Self {
        self.execution_context = Some(context);
        self
    }

    fn validate_settings(&self) -> Result<(), TunnelError> {
        if self.generation_override == Some(0) {
            return Err(TunnelError::Other(
                "WireGuard canonical generation must be non-zero".into(),
            ));
        }
        if !(MIN_HANDSHAKE_TIMEOUT..=MAX_HANDSHAKE_TIMEOUT).contains(&self.handshake_timeout) {
            return Err(TunnelError::Other(format!(
                "WireGuard handshake timeout must be between {} and {} seconds",
                MIN_HANDSHAKE_TIMEOUT.as_secs(),
                MAX_HANDSHAKE_TIMEOUT.as_secs()
            )));
        }
        if !(MIN_STATUS_POLL..=MAX_STATUS_POLL).contains(&self.status_poll) {
            return Err(TunnelError::Other(
                "WireGuard status poll interval is outside the supported range".into(),
            ));
        }
        if self.probe_timeout.is_zero() || self.probe_timeout > MAX_PROBE_TIMEOUT {
            return Err(TunnelError::Other(
                "WireGuard probe timeout must be non-zero and at most 10 seconds".into(),
            ));
        }
        if self.health_targets.len() > MAX_HEALTH_TARGETS {
            return Err(TunnelError::Other(format!(
                "WireGuard health target count exceeds {MAX_HEALTH_TARGETS}"
            )));
        }
        if self
            .execution_context
            .as_ref()
            .is_some_and(|context| context.deadline <= Instant::now())
        {
            return Err(TunnelError::Timeout(Duration::ZERO));
        }
        Ok(())
    }

    fn cancellation_requested(&self) -> bool {
        self.execution_context
            .as_ref()
            .is_some_and(|context| context.cancellation.is_cancelled())
    }

    /// Parse requested DNS without applying platform state.
    pub fn requested_dns(
        &self,
        profile: &Profile,
    ) -> Result<crate::vortix_core::ports::dns::DnsRequest, TunnelError> {
        let body = read_bounded_profile(&profile.config_path)?;
        parse_wg_conf(&body)
            .map(|parsed| parsed.dns_request())
            .map_err(|error| {
                TunnelError::Subprocess(format!("parse WireGuard DNS intent: {error}"))
            })
    }
}

fn read_bounded_profile(path: &Path) -> Result<String, TunnelError> {
    let file = std::fs::File::open(path).map_err(|error| {
        TunnelError::Subprocess(format!("read WG config {}: {error}", path.display()))
    })?;
    let mut bytes = Vec::with_capacity(8192);
    file.take((MAX_WG_PROFILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            TunnelError::Subprocess(format!("read WG config {}: {error}", path.display()))
        })?;
    if bytes.len() > MAX_WG_PROFILE_BYTES {
        return Err(TunnelError::ResourceLimit {
            resource: "WireGuard profile bytes",
            limit: MAX_WG_PROFILE_BYTES,
        });
    }
    String::from_utf8(bytes)
        .map_err(|error| TunnelError::MalformedStatus(format!("profile UTF-8: {error}")))
}

/// Strip `DNS = …` lines from a `WireGuard` `.conf` body.
///
/// Protocol parsing captures the request separately; this helper only keeps
/// `wg-quick` from mutating resolver state.
#[must_use]
pub(crate) fn strip_dns_directive(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        // Match "DNS" (case-insensitive) followed (after optional
        // whitespace) by '='. Anything else starting with "dns" (e.g. a
        // comment that mentions DNS, or a `dns_search = …` directive) is
        // kept verbatim.
        let after_dns = trimmed
            .strip_prefix(|c: char| c == 'D' || c == 'd')
            .and_then(|r| r.strip_prefix(|c: char| c == 'N' || c == 'n'))
            .and_then(|r| r.strip_prefix(|c: char| c == 'S' || c == 's'));
        let is_dns = after_dns.is_some_and(|rest| rest.trim_start().starts_with('='));
        if !is_dns {
            out.push_str(line);
        }
    }
    out
}

/// Resolve the current `session_id` from the global journal, or fall back to
/// a pid-derived stable value when the journal is disabled (tests, or
/// `[journal] disk = false`). The fallback is deterministic within a process
/// so repeated calls within one run yield the same subdir.
fn resolve_session_id() -> String {
    crate::vortix_core::journal::global_journal()
        .and_then(crate::vortix_core::journal::Journal::session_id)
        .unwrap_or_else(|| format!("nojournal-{}", std::process::id()))
}

/// Inner helper: write the sanitized body to `${session_dir}/${basename}` at
/// mode `0o600`. The basename is preserved verbatim so wg-quick's
/// `interface = basename(filename)` derivation produces the same interface
/// name as the user's original profile (relevant for `%i` substitution in
/// `PostUp`/`PreDown` hooks).
///
/// If a stale leaf with the same basename exists in the session subdir (very
/// fast disconnect-reconnect within one session), it is unlinked first —
/// `write_secret_file` refuses to overwrite.
///
/// Separated from [`write_managed_temp_config`] so tests can exercise the
/// file-writing logic against a per-test tempdir without depending on the
/// process-global `config_dir` set by `set_config_dir` (a `OnceLock` shared
/// across the test binary).
fn write_managed_temp_config_at(
    session_dir: &Path,
    user_conf_path: &Path,
    stripped_body: &[u8],
) -> Result<PathBuf, TunnelError> {
    use crate::vortix_core::secret_file::{write_secret_file, SecretFileError};

    let basename = user_conf_path
        .file_name()
        .ok_or_else(|| TunnelError::Subprocess("WG config has no basename".into()))?;

    let temp_path = session_dir.join(basename);

    // Best-effort unlink of any stale leaf from a same-session reconnect.
    // Ignore all errors — NotFound is the happy path and any other error is
    // surfaced by the subsequent write_secret_file attempt.
    let _ = std::fs::remove_file(&temp_path);

    write_secret_file(&temp_path, stripped_body).map_err(|e| match e {
        SecretFileError::Io(io) => {
            TunnelError::Subprocess(format!("write managed WG temp config: {io}"))
        }
        other => TunnelError::Subprocess(format!("write managed WG temp config: {other}")),
    })?;

    Ok(temp_path)
}

/// Public wrapper used by `up()`: resolves the per-session tmp dir from the
/// global journal `session_id`, then delegates to
/// [`write_managed_temp_config_at`].
fn write_managed_temp_config(
    user_conf_path: &Path,
    stripped_body: &[u8],
) -> Result<PathBuf, TunnelError> {
    let session_id = resolve_session_id();
    let session_root = crate::utils::get_tmp_config_dir(&session_id).map_err(|e| {
        TunnelError::Subprocess(format!("failed to create per-session tmp dir: {e}"))
    })?;
    let lifecycle_dir = create_lifecycle_dir(&session_root)?;
    match write_managed_temp_config_at(&lifecycle_dir, user_conf_path, stripped_body) {
        Ok(path) => Ok(path),
        Err(error) => {
            let _ = std::fs::remove_dir(&lifecycle_dir);
            Err(error)
        }
    }
}

fn create_lifecycle_dir(session_root: &Path) -> Result<PathBuf, TunnelError> {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_LIFECYCLE: AtomicU64 = AtomicU64::new(0);
    for _ in 0..16 {
        let sequence = NEXT_LIFECYCLE.fetch_add(1, Ordering::Relaxed);
        let path = session_root.join(format!("wg-{}-{sequence}", std::process::id()));
        #[cfg(unix)]
        let result = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700).create(&path)
        };
        #[cfg(not(unix))]
        let result = std::fs::create_dir(&path);

        match result {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(TunnelError::Subprocess(format!(
                    "create managed WG lifecycle dir: {error}"
                )));
            }
        }
    }
    Err(TunnelError::Subprocess(
        "could not allocate a unique managed WG lifecycle dir".into(),
    ))
}

/// Remove the per-session temp file written by [`write_managed_temp_config`]
/// and, if the per-session subdir is now empty, remove that too. Errors are
/// swallowed: at disconnect time the tunnel is already down, so a residual
/// temp file is harmless and the startup sweep will collect it on the next
/// run.
fn cleanup_managed_temp_config(temp_path: &Path) {
    let _ = std::fs::remove_file(temp_path);
    if let Some(parent) = temp_path.parent() {
        // `remove_dir` only succeeds when the dir is empty — exactly the
        // condition we want. Other secondaries in the same session keep
        // their own leaf and the dir survives.
        let removed_lifecycle = std::fs::remove_dir(parent).is_ok()
            && parent
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|name| name.starts_with("wg-"));
        if removed_lifecycle {
            if let Some(session_root) = parent.parent() {
                let _ = std::fs::remove_dir(session_root);
            }
        }
    }
}

/// Typed `wg show <iface> dump` observation.
#[derive(Debug, Default, Clone)]
pub struct WgStatus {
    pub interface_name: String,
    pub interface_public_key: String,
    pub listen_port: Option<u16>,
    pub peers: Vec<TunnelPeerStatus>,
}

impl ProtocolStatus for WgStatus {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn parse_unix_timestamp(
    value: &str,
    observed_at: SystemTime,
) -> Result<Option<SystemTime>, TunnelError> {
    let seconds = value
        .parse::<u64>()
        .map_err(|_| TunnelError::MalformedStatus("handshake timestamp".into()))?;
    if seconds == 0 {
        return Ok(None);
    }
    let timestamp = UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or_else(|| TunnelError::MalformedStatus("handshake timestamp overflow".into()))?;
    let latest_allowed = observed_at
        .checked_add(HANDSHAKE_FUTURE_TOLERANCE)
        .ok_or_else(|| TunnelError::MalformedStatus("observation clock overflow".into()))?;
    if timestamp > latest_allowed {
        return Err(TunnelError::MalformedStatus(
            "handshake timestamp is implausibly far in the future".into(),
        ));
    }
    Ok(Some(timestamp))
}

/// Parse the stable tab-separated `WireGuard` dump format.
pub fn parse_wg_dump(
    interface_name: &str,
    dump: &str,
    observed_at: SystemTime,
    generation: u64,
) -> Result<WgStatus, TunnelError> {
    if dump.len() > MAX_WG_DUMP_BYTES {
        return Err(TunnelError::ResourceLimit {
            resource: "WireGuard status bytes",
            limit: MAX_WG_DUMP_BYTES,
        });
    }
    let mut lines = dump.lines();
    let interface = lines
        .next()
        .ok_or_else(|| TunnelError::MalformedStatus("WireGuard dump was empty".into()))?;
    let fields = interface.split('\t').collect::<Vec<_>>();
    if fields.len() != 4 || fields.iter().any(|field| field.len() > MAX_WG_FIELD_BYTES) {
        return Err(TunnelError::MalformedStatus(
            "WireGuard interface dump shape".into(),
        ));
    }
    let listen_port = fields[2]
        .parse::<u16>()
        .map_err(|_| TunnelError::MalformedStatus("WireGuard listen port".into()))?;
    let fwmark_valid = fields[3].eq_ignore_ascii_case("off")
        || fields[3].parse::<u32>().is_ok()
        || fields[3]
            .strip_prefix("0x")
            .and_then(|value| u32::from_str_radix(value, 16).ok())
            .is_some();
    if !fwmark_valid {
        return Err(TunnelError::MalformedStatus("WireGuard fwmark".into()));
    }
    let mut status = WgStatus {
        interface_name: interface_name.to_string(),
        interface_public_key: fields[1].to_string(),
        listen_port: Some(listen_port),
        peers: Vec::new(),
    };
    for line in lines {
        if status.peers.len() >= MAX_WG_PEERS {
            return Err(TunnelError::ResourceLimit {
                resource: "WireGuard peers",
                limit: MAX_WG_PEERS,
            });
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 8 || fields.iter().any(|field| field.len() > MAX_WG_FIELD_BYTES) {
            return Err(TunnelError::MalformedStatus(
                "WireGuard peer dump shape".into(),
            ));
        }
        let allowed_routes = fields[3]
            .split(',')
            .map(str::trim)
            .filter(|route| !route.is_empty())
            .map(|route| {
                route
                    .parse::<crate::vortix_core::cidr::Cidr>()
                    .map(|_| route.to_string())
                    .map_err(|_| TunnelError::MalformedStatus("WireGuard AllowedIPs".into()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if allowed_routes.len() > MAX_ROUTES_PER_PEER {
            return Err(TunnelError::ResourceLimit {
                resource: "WireGuard peer routes",
                limit: MAX_ROUTES_PER_PEER,
            });
        }
        let bytes_rx = fields[5]
            .parse()
            .map_err(|_| TunnelError::MalformedStatus("WireGuard receive counter".into()))?;
        let bytes_tx = fields[6]
            .parse()
            .map_err(|_| TunnelError::MalformedStatus("WireGuard transmit counter".into()))?;
        let keepalive = fields[7]
            .parse::<u64>()
            .map_err(|_| TunnelError::MalformedStatus("WireGuard keepalive interval".into()))?;
        let endpoint = if fields[2] == "(none)" {
            None
        } else {
            fields[2]
                .parse::<SocketAddr>()
                .map_err(|_| TunnelError::MalformedStatus("WireGuard peer endpoint".into()))?;
            Some(fields[2].to_string())
        };
        status.peers.push(TunnelPeerStatus {
            public_key: fields[0].to_string(),
            endpoint,
            allowed_routes,
            latest_handshake: parse_unix_timestamp(fields[4], observed_at)?,
            evidence_observed_at: observed_at,
            evidence_generation: generation,
            bytes_rx,
            bytes_tx,
            persistent_keepalive: (keepalive > 0).then(|| Duration::from_secs(keepalive)),
        });
    }
    Ok(status)
}

fn observe_interface_with_generation(
    interface_name: &str,
    generation: u64,
    timeout: Duration,
) -> Result<WgStatus, TunnelError> {
    if timeout.is_zero() {
        return Err(TunnelError::Timeout(Duration::ZERO));
    }
    let output = crate::vortix_process::run_to_output(
        CommandSpec::oneshot(
            "wg",
            vec!["show".into(), interface_name.into(), "dump".into()],
        )
        .timeout(timeout.min(Duration::from_secs(2)))
        .output_limit(MAX_WG_DUMP_BYTES),
    )
    .map_err(|error| TunnelError::Subprocess(format!("wg show {interface_name} dump: {error}")))?;
    if !output.status.success() {
        return Err(TunnelError::Subprocess(format!(
            "wg show {interface_name} dump: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let observed_at = SystemTime::now();
    let dump = std::str::from_utf8(&output.stdout)
        .map_err(|error| TunnelError::Other(format!("WireGuard status was not UTF-8: {error}")))?;
    parse_wg_dump(interface_name, dump, observed_at, generation)
}

impl WgTunnel {
    /// Protocol-owned read-only observation used by the scanner.
    pub fn observe_interface(interface_name: &str) -> Result<WgStatus, TunnelError> {
        observe_interface_with_generation(interface_name, 0, Duration::from_secs(2))
    }

    #[must_use]
    pub fn interface_exists(interface_name: &str) -> bool {
        Self::observe_interface(interface_name).is_ok()
    }

    /// Compensate an attempt interrupted by unwinding before a receipt was
    /// returned. Absence is observed before the capability is forgotten.
    pub fn compensate_inflight(&mut self) -> Result<(), TunnelError> {
        let Some(attempt) = self.inflight.take() else {
            return Err(TunnelError::OutcomeUnknown(
                "no exact WireGuard attempt capability was retained".into(),
            ));
        };
        let interface_name = resolve_kernel_iface(
            &attempt.interface_basename,
            crate::platform::current_platform()
                .interface
                .resolve_wireguard_interface(&attempt.interface_basename),
            &attempt.profile_id,
        );
        if !Self::interface_exists(&interface_name) {
            cleanup_managed_temp_config(&attempt.temp_path);
            return Ok(());
        }
        let handle = TunnelHandle {
            profile_id: attempt.profile_id,
            display_name: attempt.display_name,
            interface_name: interface_name.clone(),
            pid: None,
            started_at: attempt.started_at,
            kind: TunnelKindTag::WireGuard,
            generation: attempt.generation,
            handshake: None,
            probe_receipts: Vec::new(),
            process_ownership: None,
            teardown_config: Some(TunnelTeardownConfig {
                path: attempt.temp_path,
                managed: true,
            }),
            dns_request: crate::vortix_core::ports::dns::DnsRequest::default(),
        };
        self.down(handle)?;
        if wait_for_interface_absence(&interface_name, Duration::from_secs(2)) {
            Ok(())
        } else {
            Err(TunnelError::OutcomeUnknown(format!(
                "WireGuard interface {interface_name} remained after panic compensation"
            )))
        }
    }

    fn handshake_plan(
        &self,
        parsed: &crate::vortix_protocol_wireguard::parser::WgParsedProfile,
    ) -> Result<HandshakePlan, TunnelError> {
        let expected = parsed
            .peers
            .iter()
            .filter(|peer| !peer.public_key.is_empty())
            .map(|peer| peer.public_key.clone())
            .collect::<BTreeSet<_>>();
        if expected.is_empty() {
            return Err(TunnelError::HandshakeFailed(
                "WireGuard profile has no peer public key".into(),
            ));
        }
        let mut probes = Vec::new();
        for peer in &parsed.peers {
            if peer.public_key.is_empty() || peer.persistent_keepalive.is_some() {
                continue;
            }
            let target = self
                .health_targets
                .iter()
                .copied()
                .find(|target| peer_covers_target(peer, *target))
                .ok_or_else(|| {
                    TunnelError::HandshakeFailed(format!(
                        "WireGuard peer {} has no PersistentKeepalive and no configured health target covered by its AllowedIPs; add a covered ping_target",
                        peer.public_key
                    ))
                })?;
            probes.push(ProbePlan {
                peer_public_key: peer.public_key.clone(),
                target,
                allowed_routes: peer
                    .allowed_ips
                    .iter()
                    .map(|route| format!("{}/{}", route.addr, route.prefix_len))
                    .collect(),
            });
        }
        Ok(HandshakePlan { expected, probes })
    }

    fn await_handshake(
        &self,
        handle: &TunnelHandle,
        attempt: &HandshakeAttempt,
        probes: &[ProbePlan],
    ) -> Result<
        (
            crate::vortix_core::ports::tunnel::HandshakeEvidence,
            Vec<ProbeReceipt>,
        ),
        TunnelError,
    > {
        let local_deadline = Instant::now()
            .checked_add(self.handshake_timeout)
            .ok_or_else(|| TunnelError::Other("WireGuard deadline overflowed".into()))?;
        let deadline = self
            .execution_context
            .as_ref()
            .map_or(local_deadline, |context| {
                local_deadline.min(context.deadline)
            });
        let mut receipts = Vec::with_capacity(probes.len());
        for probe in probes {
            if self.cancellation_requested() {
                return Err(TunnelError::Cancelled);
            }
            Self::ensure_probe_route(probe.target, &handle.interface_name)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(TunnelError::Timeout(self.handshake_timeout));
            }
            send_handshake_probe(probe.target, self.probe_timeout.min(remaining)).map_err(
                |error| TunnelError::Other(format!("WireGuard handshake probe failed: {error}")),
            )?;
            receipts.push(ProbeReceipt {
                peer_public_key: probe.peer_public_key.clone(),
                target: probe.target,
                allowed_routes: probe.allowed_routes.clone(),
                issued_at: SystemTime::now(),
            });
        }
        loop {
            if self.cancellation_requested() {
                return Err(TunnelError::Cancelled);
            }
            if let Ok(status) = self.status(handle) {
                if let Some(evidence) = attempt.evaluate(&status) {
                    return Ok((evidence, receipts));
                }
            }
            if Instant::now() >= deadline {
                return Err(TunnelError::HandshakeFailed(format!(
                    "no current-generation peer handshake within {} seconds",
                    self.handshake_timeout.as_secs()
                )));
            }
            std::thread::sleep(
                self.status_poll
                    .min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }

    fn ensure_probe_route(target: IpAddr, owned_interface: &str) -> Result<(), TunnelError> {
        let observation = crate::platform::current_platform()
            .route_table
            .route_interface_for(target);
        verify_probe_route(observation, target, owned_interface)
    }

    /// Fence a failed `wg-quick up` against the exact interface derived from
    /// this attempt. A runner error or non-zero status can happen after
    /// partial kernel creation, so the managed config remains available until
    /// teardown and a fresh absence observation both succeed.
    fn settle_failed_up(
        &mut self,
        profile: &Profile,
        temp_path: PathBuf,
        generation: u64,
        started_at: SystemTime,
        dns_request: crate::vortix_core::ports::dns::DnsRequest,
        original: TunnelError,
    ) -> TunnelError {
        let basename = interface_from_path(&temp_path);
        let interface_name = resolve_kernel_iface(
            &basename,
            crate::platform::current_platform()
                .interface
                .resolve_wireguard_interface(&basename),
            &profile.id,
        );
        let initially_exists = Self::interface_exists(&interface_name);
        let cleanup_path = temp_path.clone();
        let handle = TunnelHandle {
            profile_id: profile.id.clone(),
            display_name: profile.display_name.clone(),
            interface_name: interface_name.clone(),
            pid: None,
            started_at,
            kind: TunnelKindTag::WireGuard,
            generation,
            handshake: None,
            probe_receipts: Vec::new(),
            process_ownership: None,
            teardown_config: Some(TunnelTeardownConfig {
                path: temp_path,
                managed: true,
            }),
            dns_request,
        };
        settle_failed_attempt(
            original,
            &interface_name,
            initially_exists,
            || cleanup_managed_temp_config(&cleanup_path),
            || self.down(handle),
            || wait_for_interface_absence(&interface_name, Duration::from_secs(2)),
        )
    }
}

fn settle_failed_attempt(
    original: TunnelError,
    interface_name: &str,
    initially_exists: bool,
    cleanup_absent: impl FnOnce(),
    teardown: impl FnOnce() -> Result<(), TunnelError>,
    confirm_absence: impl FnOnce() -> bool,
) -> TunnelError {
    if !initially_exists {
        cleanup_absent();
        return original;
    }
    match teardown() {
        Ok(()) if confirm_absence() => original,
        Ok(()) => TunnelError::OutcomeUnknown(format!(
            "{original}; attempt-owned interface {interface_name} remained after cleanup"
        )),
        Err(cleanup) => TunnelError::OutcomeUnknown(format!(
            "{original}; attempt-owned interface {interface_name} cleanup failed: {cleanup}"
        )),
    }
}

fn verify_probe_route(
    observation: crate::vortix_core::ports::route_table::DefaultRouteObservation,
    target: IpAddr,
    owned_interface: &str,
) -> Result<(), TunnelError> {
    use crate::vortix_core::ports::route_table::DefaultRouteObservation;
    match observation {
            DefaultRouteObservation::Interface(interface) if interface == owned_interface => Ok(()),
            DefaultRouteObservation::Interface(interface) => Err(TunnelError::HandshakeFailed(
                format!(
                    "WireGuard probe target {target} routes through {interface}, not owned interface {owned_interface}; check Table/AllowedIPs policy"
                ),
            )),
            DefaultRouteObservation::NoDefaultRoute => Err(TunnelError::HandshakeFailed(format!(
                "WireGuard probe target {target} has no kernel route"
            ))),
            DefaultRouteObservation::ProbeFailed => Err(TunnelError::OutcomeUnknown(format!(
                "kernel route for WireGuard probe target {target} could not be verified"
            ))),
    }
}

#[derive(Debug)]
struct HandshakePlan {
    expected: BTreeSet<String>,
    probes: Vec<ProbePlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProbePlan {
    peer_public_key: String,
    target: IpAddr,
    allowed_routes: Vec<String>,
}

fn peer_covers_target(
    peer: &crate::vortix_protocol_wireguard::parser::WgPeer,
    target: IpAddr,
) -> bool {
    peer.allowed_ips.iter().any(|route| {
        crate::vortix_core::cidr::Cidr::new(route.addr, route.prefix_len).is_some_and(|route| {
            let target_prefix = if target.is_ipv4() { 32 } else { 128 };
            crate::vortix_core::cidr::Cidr::new(target, target_prefix)
                .is_some_and(|target| route.intersects(&target))
        })
    })
}

fn send_handshake_probe(target: IpAddr, timeout: Duration) -> std::io::Result<()> {
    let bind_addr = match target {
        IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        IpAddr::V6(_) => SocketAddr::from(([0_u16; 8], 0)),
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_write_timeout(Some(timeout))?;
    socket.connect(SocketAddr::new(target, 9))?;
    // Discard service: one byte is sufficient to cause route lookup and a
    // WireGuard handshake; no application response is read or interpreted.
    socket.send(&[0]).map(|_| ())
}

fn wait_for_interface_absence(interface_name: &str, timeout: Duration) -> bool {
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return false;
    };
    loop {
        if !WgTunnel::interface_exists(interface_name) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Select the first configured target covered by a peer route. Selection is
/// deterministic and side-effect-free so split-tunnel preflight runs before
/// `wg-quick up`.
#[must_use]
pub fn select_health_probe(
    parsed: &crate::vortix_protocol_wireguard::parser::WgParsedProfile,
    health_targets: &[IpAddr],
) -> Option<IpAddr> {
    parsed.peers.iter().find_map(|peer| {
        health_targets
            .iter()
            .copied()
            .find(|target| peer_covers_target(peer, *target))
    })
}

/// Decide the kernel-visible interface name for a `WireGuard` tunnel
/// based on the config basename and the platform port's
/// `resolve_wireguard_interface` result.
///
/// Platform behaviour:
/// - **Linux / BSD**: `wg-quick` names the kernel interface after the
///   config basename (the file passed to `wg-quick up`). The platform
///   port's `resolve_wireguard_interface` returns `None`, and the
///   basename is the correct value to store.
/// - **macOS**: `wg-quick` creates a `utunN` kernel device via
///   wireguard-go and writes the config-basename → `utunN` mapping to
///   `/var/run/wireguard/<basename>.name`. The platform port returns
///   `Some("utun7")` (or similar). The registry needs `utun7` stored
///   to match `route -n get`'s output.
///
/// Falling back to the basename when the port returns `None` is the
/// correct behaviour on Linux. On macOS, reaching the fallback path
/// post-`wg-quick up` indicates the `.name` file is missing — an
/// anomalous wg-quick install / permission state worth logging.
///
/// `profile_id` is plumbed through purely so the macOS-side warning
/// can attribute the anomaly to a profile.
fn resolve_kernel_iface(
    basename: &str,
    port_result: Option<String>,
    profile_id: &crate::vortix_core::profile::ProfileId,
) -> String {
    if let Some(iface) = port_result {
        return iface;
    }
    #[cfg(target_os = "macos")] // xtask:allow-platform-cfg: warn-only diagnostic for an anomalous wg-quick state on macOS
    warn!(
        target: "vortix::tunnel::wireguard",
        profile = %profile_id,
        basename = %basename,
        "wg.up: resolve_wireguard_interface returned None on macOS; falling back to basename. \
         Expected /var/run/wireguard/<basename>.name to exist post-`wg-quick up` — check wg-quick install / permissions."
    );
    let _ = profile_id;
    basename.to_string()
}

fn interface_from_path(path: &std::path::Path) -> String {
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("wg0")
        .to_string()
}

struct PreparedDownTarget {
    target: String,
    cleanup_after_attempt: Option<PathBuf>,
    cleanup_after_success: Option<PathBuf>,
}

fn looks_like_config_path(value: &str) -> bool {
    Path::new(value)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("conf"))
        || Path::new(value).components().count() > 1
}

/// Resolve a teardown-safe `wg-quick down` target.
///
/// Managed configs were sanitized during `up` and must stay alive until the
/// matching `down`. Source configs are sanitized into a fresh managed copy
/// here when needed, covering synthetic handles built after a restart or a
/// scanner adoption. Interface-only handles never involve a config file.
fn prepare_down_target_with(
    handle: &TunnelHandle,
    write_managed: impl FnOnce(&Path, &[u8]) -> Result<PathBuf, TunnelError>,
) -> Result<PreparedDownTarget, TunnelError> {
    let config = handle.teardown_config.clone().or_else(|| {
        looks_like_config_path(&handle.interface_name).then(|| TunnelTeardownConfig {
            path: PathBuf::from(&handle.interface_name),
            managed: false,
        })
    });

    let Some(config) = config else {
        return Ok(PreparedDownTarget {
            target: handle.interface_name.clone(),
            cleanup_after_attempt: None,
            cleanup_after_success: None,
        });
    };

    if config.managed {
        return Ok(PreparedDownTarget {
            target: config.path.to_string_lossy().into_owned(),
            cleanup_after_attempt: None,
            cleanup_after_success: Some(config.path),
        });
    }

    let body = read_bounded_profile(&config.path)?;
    parse_wg_conf(&body).map_err(|error| {
        TunnelError::Subprocess(format!("validate WireGuard teardown profile: {error}"))
    })?;
    let stripped = strip_dns_directive(&body);
    if stripped == body {
        return Ok(PreparedDownTarget {
            target: config.path.to_string_lossy().into_owned(),
            cleanup_after_attempt: None,
            cleanup_after_success: None,
        });
    }

    let temp_path = write_managed(&config.path, stripped.as_bytes())?;
    Ok(PreparedDownTarget {
        target: temp_path.to_string_lossy().into_owned(),
        cleanup_after_attempt: Some(temp_path),
        cleanup_after_success: None,
    })
}

fn prepare_down_target(handle: &TunnelHandle) -> Result<PreparedDownTarget, TunnelError> {
    prepare_down_target_with(handle, write_managed_temp_config)
}

fn wg_quick_down_spec(target: String) -> CommandSpec {
    CommandSpec::oneshot("wg-quick", vec!["down".into(), target]).privilege(PrivilegeReq::Root)
}

impl Tunnel for WgTunnel {
    #[allow(clippy::too_many_lines)]
    fn up(&mut self, profile: &Profile) -> Result<TunnelHandle, TunnelError> {
        self.validate_settings()?;
        if self.cancellation_requested() {
            return Err(TunnelError::Cancelled);
        }
        let user_body = read_bounded_profile(&profile.config_path)?;
        let parsed = parse_wg_conf(&user_body).map_err(|error| {
            TunnelError::Subprocess(format!("validate WireGuard profile: {error}"))
        })?;
        let dns_request = parsed.dns_request();
        let plan = self.handshake_plan(&parsed)?;
        let generation = self
            .generation_override
            .take()
            .unwrap_or_else(|| NEXT_ATTEMPT_GENERATION.fetch_add(1, Ordering::Relaxed));
        let source_basename = interface_from_path(&profile.config_path);
        let baseline_timeout = self
            .execution_context
            .as_ref()
            .map_or(Duration::from_secs(2), |context| {
                context.deadline.saturating_duration_since(Instant::now())
            });
        let baseline_status =
            observe_interface_with_generation(&source_basename, generation, baseline_timeout).ok();
        let baseline = plan
            .expected
            .iter()
            .map(|peer| {
                let timestamp = baseline_status.as_ref().and_then(|status| {
                    status
                        .peers
                        .iter()
                        .find(|observed| &observed.public_key == peer)
                        .and_then(|observed| observed.latest_handshake)
                });
                (peer.clone(), timestamp)
            })
            .collect::<BTreeMap<_, _>>();
        let attempt_started = SystemTime::now();
        let stripped = strip_dns_directive(&user_body);
        if self.cancellation_requested() {
            return Err(TunnelError::Cancelled);
        }
        if self
            .execution_context
            .as_ref()
            .is_some_and(|context| context.deadline <= Instant::now())
        {
            return Err(TunnelError::Timeout(self.handshake_timeout));
        }
        // Keep one private lifecycle copy even when the source has no DNS.
        // `wg-quick down` needs the same routes/hooks as `up`, and arbitrary
        // imported profiles are not discoverable through `/etc/wireguard` by
        // interface name alone.
        let temp_path = write_managed_temp_config(&profile.config_path, stripped.as_bytes())?;
        let effective_path = temp_path.clone();

        self.inflight = Some(Box::new(WgInflightAttempt {
            profile_id: profile.id.clone(),
            display_name: profile.display_name.clone(),
            interface_basename: interface_from_path(&effective_path),
            started_at: attempt_started,
            generation,
            temp_path: temp_path.clone(),
        }));

        let path_str = effective_path.to_string_lossy().into_owned();
        info!(
            target: "vortix::tunnel::wireguard",
            profile = %profile.id,
            config = %path_str,
            "wg.up"
        );

        let command_timeout = self
            .execution_context
            .as_ref()
            .map_or(self.handshake_timeout, |context| {
                context.deadline.saturating_duration_since(Instant::now())
            });
        if command_timeout.is_zero() || self.cancellation_requested() {
            self.inflight = None;
            cleanup_managed_temp_config(&temp_path);
            return Err(if self.cancellation_requested() {
                TunnelError::Cancelled
            } else {
                TunnelError::Timeout(Duration::ZERO)
            });
        }
        let output = crate::vortix_process::run_to_output(
            CommandSpec::oneshot("wg-quick", vec!["up".into(), path_str.clone()])
                .privilege(PrivilegeReq::Root)
                .timeout(command_timeout),
        );
        let output = match output {
            Ok(output) => output,
            Err(error) => {
                self.inflight = None;
                return Err(self.settle_failed_up(
                    profile,
                    temp_path,
                    generation,
                    attempt_started,
                    dns_request,
                    TunnelError::Subprocess(format!("wg-quick up: {error}")),
                ));
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            self.inflight = None;
            return Err(self.settle_failed_up(
                profile,
                temp_path,
                generation,
                attempt_started,
                dns_request,
                TunnelError::Subprocess(format!("wg-quick up: {stderr}")),
            ));
        }

        let basename = interface_from_path(&effective_path);
        let interface_name = resolve_kernel_iface(
            &basename,
            crate::platform::current_platform()
                .interface
                .resolve_wireguard_interface(&basename),
            &profile.id,
        );

        let mut handle = TunnelHandle {
            profile_id: profile.id.clone(),
            display_name: profile.display_name.clone(),
            interface_name,
            pid: None,
            started_at: attempt_started,
            kind: TunnelKindTag::WireGuard,
            generation,
            handshake: None,
            probe_receipts: Vec::new(),
            process_ownership: None,
            teardown_config: Some(TunnelTeardownConfig {
                path: temp_path,
                managed: true,
            }),
            dns_request,
        };
        let attempt = HandshakeAttempt {
            generation,
            started_at: attempt_started,
            expected_peers: plan.expected,
            baseline,
        };
        let awaited = panic::catch_unwind(AssertUnwindSafe(|| {
            self.await_handshake(&handle, &attempt, &plan.probes)
        }));
        match awaited {
            Ok(Ok((evidence, receipts))) => {
                handle.handshake = Some(evidence);
                handle.probe_receipts = receipts;
                self.inflight = None;
            }
            Ok(Err(error)) => {
                self.inflight = None;
                let cleanup = self.down(handle.clone());
                return Err(match cleanup {
                    Ok(())
                        if wait_for_interface_absence(
                            &handle.interface_name,
                            Duration::from_secs(2),
                        ) =>
                    {
                        error
                    }
                    Ok(()) => TunnelError::OutcomeUnknown(format!(
                        "{error}; attempt-owned interface still exists after teardown"
                    )),
                    Err(cleanup) => TunnelError::OutcomeUnknown(format!(
                        "{error}; attempt-owned interface cleanup failed: {cleanup}"
                    )),
                });
            }
            Err(_) => {
                self.inflight = None;
                let cleanup = self.down(handle.clone());
                return Err(match cleanup {
                    Ok(()) if wait_for_interface_absence(&handle.interface_name, Duration::from_secs(2)) => {
                        TunnelError::Other("WireGuard handshake worker panicked; attempt was cleaned up".into())
                    }
                    Ok(()) => TunnelError::OutcomeUnknown(
                        "WireGuard handshake worker panicked and interface absence was not verified".into(),
                    ),
                    Err(error) => TunnelError::OutcomeUnknown(format!(
                        "WireGuard handshake worker panicked and cleanup failed: {error}"
                    )),
                });
            }
        }
        Ok(handle)
    }

    fn down(&mut self, handle: TunnelHandle) -> Result<(), TunnelError> {
        info!(
            target: "vortix::tunnel::wireguard",
            profile = %handle.profile_id,
            interface = %handle.interface_name,
            "wg.down"
        );

        // Teardown is idempotent only after platform-observed absence. This
        // lets the caller safely reconcile a handshake-timeout cleanup without
        // replaying `wg-quick down` against an already-removed interface.
        if !looks_like_config_path(&handle.interface_name)
            && !Self::interface_exists(&handle.interface_name)
        {
            if let Some(config) = &handle.teardown_config {
                if config.managed {
                    cleanup_managed_temp_config(&config.path);
                }
            }
            return Ok(());
        }

        let prepared = prepare_down_target(&handle)?;
        let output = crate::vortix_process::run_to_output(wg_quick_down_spec(prepared.target));

        if let Some(path) = &prepared.cleanup_after_attempt {
            cleanup_managed_temp_config(path);
        }

        let output = output.map_err(|e| TunnelError::Subprocess(format!("wg-quick down: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(TunnelError::Subprocess(format!("WireGuard down: {stderr}")));
        }

        if wait_for_interface_absence(&handle.interface_name, Duration::from_secs(2)) {
            if let Some(path) = &prepared.cleanup_after_success {
                cleanup_managed_temp_config(path);
            }
            Ok(())
        } else {
            Err(TunnelError::OutcomeUnknown(format!(
                "WireGuard interface {} remained after teardown",
                handle.interface_name
            )))
        }
    }

    fn status(&self, handle: &TunnelHandle) -> Result<TunnelStatus, TunnelError> {
        if self.cancellation_requested() {
            return Err(TunnelError::Cancelled);
        }
        let timeout = self
            .execution_context
            .as_ref()
            .map_or(Duration::from_secs(2), |context| {
                context.deadline.saturating_duration_since(Instant::now())
            });
        let detail =
            observe_interface_with_generation(&handle.interface_name, handle.generation, timeout)?;
        let observed_at = detail
            .peers
            .first()
            .map_or_else(SystemTime::now, |peer| peer.evidence_observed_at);
        let bytes_rx = detail.peers.iter().map(|peer| peer.bytes_rx).sum();
        let bytes_tx = detail.peers.iter().map(|peer| peer.bytes_tx).sum();
        let last_handshake = detail
            .peers
            .iter()
            .filter_map(|peer| peer.latest_handshake)
            .max();
        let peers = detail.peers.clone();
        Ok(TunnelStatus {
            handle: handle.clone(),
            bytes_rx,
            bytes_tx,
            last_handshake,
            observed_at,
            peers,
            detail: Box::new(detail),
        })
    }

    fn parse_profile(&self, raw: &[u8]) -> Result<Box<dyn ParsedProfile>, ParseError> {
        let text = std::str::from_utf8(raw)
            .map_err(|e| ParseError::Encoding(format!("WireGuard .conf must be UTF-8: {e}")))?;
        let parsed = parse_wg_conf(text)?;
        Ok(Box::new(parsed))
    }

    fn capabilities(&self) -> TunnelCapabilities {
        TunnelCapabilities {
            supports_split_tunnel: false,
            supports_ipv6: true,
            mtu_configurable: true,
            supports_reconnect_without_disconnect: true,
            requires_root: true,
            userspace: false,
        }
    }

    fn kind_tag(&self) -> TunnelKindTag {
        TunnelKindTag::WireGuard
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_match_kernel_wireguard() {
        let caps = WgTunnel::new().capabilities();
        assert!(caps.requires_root);
        assert!(caps.supports_ipv6);
        assert!(!caps.userspace);
    }

    #[test]
    fn interface_from_path_uses_stem() {
        let p = std::path::PathBuf::from("/etc/wireguard/corp.conf");
        assert_eq!(interface_from_path(&p), "corp");
    }

    // --- resolve_kernel_iface contract ---

    #[test]
    fn resolve_kernel_iface_uses_port_result_when_present() {
        // macOS-shape: platform port returns the underlying utun device.
        // This is the value the registry must store to match `route get`'s
        // output byte-for-byte.
        let profile_id = crate::vortix_core::profile::ProfileId::new("corp");
        let resolved = resolve_kernel_iface("corp", Some("utun7".to_string()), &profile_id);
        assert_eq!(resolved, "utun7");
    }

    #[test]
    fn resolve_kernel_iface_falls_back_to_basename_when_port_returns_none() {
        // Linux-shape: platform port returns None because the kernel
        // device name IS the config basename. The fallback is the
        // correct value to store.
        let profile_id = crate::vortix_core::profile::ProfileId::new("corp");
        let resolved = resolve_kernel_iface("corp", None, &profile_id);
        assert_eq!(resolved, "corp");
    }

    #[test]
    fn resolve_kernel_iface_preserves_port_result_even_when_equal_to_basename() {
        // Edge: Mock variant returns `Some(name)` for `wg_present=true`
        // (the legacy default before the override existed). This MUST
        // be preserved verbatim — the helper has no business stripping
        // the port's answer just because it happens to equal the
        // basename.
        let profile_id = crate::vortix_core::profile::ProfileId::new("corp");
        let resolved = resolve_kernel_iface("corp", Some("corp".to_string()), &profile_id);
        assert_eq!(resolved, "corp");
    }

    // --- DNS extraction and protocol-side suppression ---

    #[test]
    fn strip_dns_removes_directive_with_equals() {
        let body = "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/24\nDNS = 1.1.1.1\nMTU = 1420\n\n[Peer]\nPublicKey = xyz\n";
        let out = strip_dns_directive(body);
        assert!(!out.contains("DNS"));
        assert!(out.contains("PrivateKey = abc"));
        assert!(out.contains("MTU = 1420"));
        assert!(out.contains("[Peer]"));
    }

    #[test]
    fn strip_dns_is_case_insensitive() {
        let body =
            "[Interface]\nPrivateKey = abc\ndns = 8.8.8.8\nDns=4.4.4.4\nAddress = 10.0.0.2/24\n";
        let out = strip_dns_directive(body);
        assert!(!out.to_lowercase().contains("dns ="));
        assert!(!out.to_lowercase().contains("dns="));
        assert!(out.contains("Address = 10.0.0.2/24"));
    }

    #[test]
    fn strip_dns_tolerates_leading_whitespace() {
        let body = "[Interface]\n  DNS  =  1.1.1.1, 8.8.8.8\nAddress = 10.0.0.2/24\n";
        let out = strip_dns_directive(body);
        assert!(!out.contains("1.1.1.1"));
        assert!(out.contains("Address = 10.0.0.2/24"));
    }

    #[test]
    fn strip_dns_preserves_non_directive_lines_starting_with_dns() {
        // A comment that *mentions* DNS but doesn't have "DNS = ..." must
        // survive — wg-quick only treats "DNS =" as the directive.
        let body = "[Interface]\n# Custom DNS overrides below\nPrivateKey = abc\n";
        let out = strip_dns_directive(body);
        assert!(out.contains("# Custom DNS overrides below"));
        assert!(out.contains("PrivateKey = abc"));
    }

    #[test]
    fn strip_dns_no_op_when_directive_absent() {
        let body =
            "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/24\n\n[Peer]\nPublicKey = xyz\n";
        assert_eq!(strip_dns_directive(body), body);
    }

    fn wg_handle(
        interface_name: &str,
        teardown_config: Option<TunnelTeardownConfig>,
    ) -> TunnelHandle {
        TunnelHandle {
            profile_id: crate::vortix_core::profile::ProfileId::new("corp"),
            display_name: "corp".to_string(),
            interface_name: interface_name.to_string(),
            pid: None,
            started_at: SystemTime::now(),
            kind: TunnelKindTag::WireGuard,
            generation: 0,
            handshake: None,
            probe_receipts: Vec::new(),
            process_ownership: None,
            teardown_config,
            dns_request: crate::vortix_core::ports::dns::DnsRequest::default(),
        }
    }

    #[test]
    fn synthetic_down_command_uses_dns_free_managed_copy() {
        let (_root, session) = fresh_session_dir();
        let scratch = tempfile::tempdir().unwrap();
        let source = scratch.path().join("corp.conf");
        std::fs::write(
            &source,
            "[Interface]\nPrivateKey = SECRET\nDNS = 1.1.1.1\nAddress = 10.0.0.2/24\n",
        )
        .unwrap();
        let handle = wg_handle(
            "corp",
            Some(TunnelTeardownConfig {
                path: source.clone(),
                managed: false,
            }),
        );

        let prepared = prepare_down_target_with(&handle, |path, body| {
            write_managed_temp_config_at(&session, path, body)
        })
        .unwrap();
        let spec = wg_quick_down_spec(prepared.target.clone());

        assert_eq!(spec.program, "wg-quick");
        assert_eq!(spec.args, vec!["down", prepared.target.as_str()]);
        assert_ne!(prepared.target, source.to_string_lossy());
        let command_body = std::fs::read_to_string(&prepared.target).unwrap();
        assert!(!command_body.contains("DNS ="));
        assert!(command_body.contains("PrivateKey = SECRET"));
    }

    #[test]
    fn real_handle_down_command_keeps_managed_config_until_success() {
        let scratch = tempfile::tempdir().unwrap();
        let managed = scratch.path().join("corp.conf");
        std::fs::write(&managed, "[Interface]\nPrivateKey = SECRET\n").unwrap();
        let handle = wg_handle(
            "wg0",
            Some(TunnelTeardownConfig {
                path: managed.clone(),
                managed: true,
            }),
        );

        let prepared = prepare_down_target_with(&handle, |_path, _body| {
            panic!("managed config must not be rewritten")
        })
        .unwrap();
        let spec = wg_quick_down_spec(prepared.target);

        assert_eq!(spec.args, vec!["down", managed.to_string_lossy().as_ref()]);
        assert!(prepared.cleanup_after_attempt.is_none());
        assert_eq!(
            prepared.cleanup_after_success.as_deref(),
            Some(managed.as_path())
        );
        assert!(
            managed.exists(),
            "managed config must survive until down succeeds"
        );
    }

    #[test]
    fn partial_creation_timeout_retains_config_when_absence_is_unproved() {
        let scratch = tempfile::tempdir().unwrap();
        let managed = scratch.path().join("corp.conf");
        std::fs::write(&managed, "managed-attempt").unwrap();
        let error = settle_failed_attempt(
            TunnelError::Timeout(Duration::from_secs(1)),
            "wg0",
            true,
            || panic!("present attempt must be torn down"),
            || Err(TunnelError::Subprocess("down timed out".into())),
            || false,
        );
        assert!(matches!(error, TunnelError::OutcomeUnknown(_)));
        assert!(managed.exists(), "ambiguous attempt must retain its config");
    }

    #[test]
    fn nonzero_up_cleans_config_only_after_exact_absence() {
        let scratch = tempfile::tempdir().unwrap();
        let managed = scratch.path().join("corp.conf");
        std::fs::write(&managed, "managed-attempt").unwrap();
        let cleanup_path = managed.clone();
        let error = settle_failed_attempt(
            TunnelError::Subprocess("wg-quick up exited 1".into()),
            "wg0",
            true,
            || panic!("present attempt must be torn down"),
            || {
                std::fs::remove_file(cleanup_path).unwrap();
                Ok(())
            },
            || true,
        );
        assert!(matches!(error, TunnelError::Subprocess(_)));
        assert!(!managed.exists());
    }

    #[test]
    fn adopted_interface_down_command_never_uses_a_profile_path() {
        let handle = wg_handle("utun7", None);
        let prepared = prepare_down_target_with(&handle, |_path, _body| {
            panic!("interface-only teardown must not create a config")
        })
        .unwrap();
        let spec = wg_quick_down_spec(prepared.target);

        assert_eq!(spec.args, vec!["down", "utun7"]);
    }

    /// Per-test isolation: build a fresh session-style subdir at mode `0o700`
    /// under a tempdir. Avoids touching the process-global `config_dir`
    /// (`OnceLock` → first-write-wins → races across tests when set in each).
    #[cfg(unix)]
    fn fresh_session_dir() -> (tempfile::TempDir, std::path::PathBuf) {
        use std::os::unix::fs::DirBuilderExt;

        let root = tempfile::Builder::new()
            .prefix("vortix_wg_tunnel_test_")
            .tempdir()
            .unwrap();
        let session = root.path().join("tmp").join("sid-test");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&session)
            .unwrap();
        (root, session)
    }

    #[cfg(not(unix))]
    fn fresh_session_dir() -> (tempfile::TempDir, std::path::PathBuf) {
        let root = tempfile::Builder::new()
            .prefix("vortix_wg_tunnel_test_")
            .tempdir()
            .unwrap();
        let session = root.path().join("tmp").join("sid-test");
        std::fs::create_dir_all(&session).unwrap();
        (root, session)
    }

    #[cfg(unix)]
    #[test]
    fn fresh_session_dir_is_0700() {
        // Sanity-check the test fixture mirrors the production permission
        // contract (so the "verify 0o700" property below isn't tautological
        // against a 0o755 default umask).
        use std::os::unix::fs::PermissionsExt;
        let (_root, session) = fresh_session_dir();
        let perms = std::fs::metadata(&session).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o700);
    }

    #[test]
    fn managed_temp_config_strips_dns_and_preserves_basename() {
        let (_root, session) = fresh_session_dir();
        let scratch = tempfile::tempdir().unwrap();
        let user_conf = scratch.path().join("corp.conf");
        std::fs::write(
            &user_conf,
            "[Interface]\nPrivateKey = SECRET\nAddress = 10.0.0.2/24\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = PUBKEY\n",
        )
        .unwrap();
        let body = std::fs::read_to_string(&user_conf).unwrap();
        let stripped = strip_dns_directive(&body);

        let temp = write_managed_temp_config_at(&session, &user_conf, stripped.as_bytes()).unwrap();
        // Basename matches the original — wg-quick will derive interface
        // "corp" from this path, identical to the user's original.
        assert_eq!(temp.file_name().unwrap(), "corp.conf");

        let written = std::fs::read_to_string(&temp).unwrap();
        assert!(!written.contains("DNS"));
        assert!(written.contains("PrivateKey = SECRET"));
        assert!(written.contains("[Peer]"));
    }

    #[cfg(unix)]
    #[test]
    fn managed_temp_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;

        let (_root, session) = fresh_session_dir();
        let scratch = tempfile::tempdir().unwrap();
        let user_conf = scratch.path().join("wg0.conf");
        std::fs::write(
            &user_conf,
            "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/24\n",
        )
        .unwrap();

        let temp =
            write_managed_temp_config_at(&session, &user_conf, b"[Interface]\nPrivateKey = abc\n")
                .unwrap();
        let perms = std::fs::metadata(&temp).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[test]
    fn write_managed_overwrites_stale_same_session_leaf() {
        let (_root, session) = fresh_session_dir();
        let scratch = tempfile::tempdir().unwrap();
        let user_conf = scratch.path().join("vpn.conf");
        std::fs::write(&user_conf, "[Interface]\nPrivateKey = a\n").unwrap();

        // First write — leaf does not exist yet.
        let t1 = write_managed_temp_config_at(&session, &user_conf, b"first").unwrap();
        // Second write within same session — stale leaf is unlinked first
        // (write_secret_file would otherwise refuse with FileExists).
        let t2 = write_managed_temp_config_at(&session, &user_conf, b"second").unwrap();
        assert_eq!(t1, t2);
        assert_eq!(std::fs::read_to_string(&t2).unwrap(), "second");
    }

    #[test]
    fn lifecycle_directories_do_not_overwrite_an_active_teardown_config() {
        let (_root, session) = fresh_session_dir();
        let first_dir = create_lifecycle_dir(&session).unwrap();
        let second_dir = create_lifecycle_dir(&session).unwrap();
        let source = session.join("corp.conf");

        let first = write_managed_temp_config_at(&first_dir, &source, b"first").unwrap();
        let second = write_managed_temp_config_at(&second_dir, &source, b"second").unwrap();

        assert_ne!(first, second);
        assert_eq!(std::fs::read_to_string(first).unwrap(), "first");
        assert_eq!(std::fs::read_to_string(second).unwrap(), "second");
    }

    #[test]
    fn cleanup_removes_leaf_and_empty_session_dir() {
        let (_root, session) = fresh_session_dir();
        let scratch = tempfile::tempdir().unwrap();
        let user_conf = scratch.path().join("only.conf");
        std::fs::write(&user_conf, "[Interface]\nPrivateKey = a\n").unwrap();

        let temp = write_managed_temp_config_at(&session, &user_conf, b"body").unwrap();
        assert!(temp.exists());
        assert!(session.exists());

        cleanup_managed_temp_config(&temp);
        assert!(!temp.exists());
        assert!(!session.exists(), "empty session dir should be removed");
    }

    #[test]
    fn cleanup_keeps_session_dir_when_other_leaves_remain() {
        let (_root, session) = fresh_session_dir();
        let scratch = tempfile::tempdir().unwrap();
        let conf_a = scratch.path().join("a.conf");
        let conf_b = scratch.path().join("b.conf");
        std::fs::write(&conf_a, "x").unwrap();
        std::fs::write(&conf_b, "y").unwrap();

        let temp_a = write_managed_temp_config_at(&session, &conf_a, b"a-body").unwrap();
        let temp_b = write_managed_temp_config_at(&session, &conf_b, b"b-body").unwrap();
        assert_eq!(session, temp_a.parent().unwrap());
        assert_eq!(session, temp_b.parent().unwrap());

        cleanup_managed_temp_config(&temp_a);
        assert!(!temp_a.exists());
        assert!(temp_b.exists(), "sibling managed leaf must survive");
        assert!(session.exists(), "session dir must survive while non-empty");

        cleanup_managed_temp_config(&temp_b);
        assert!(!session.exists());
    }

    /// Mirror of the production helper at
    /// `crates/vortix/src/main.rs::sweep_orphan_temp_configs` so we can
    /// exercise it without invoking `main()`.
    fn sweep_orphan_temp_configs(config_dir: &std::path::Path, current_session_id: &str) {
        let tmp_dir = config_dir.join(crate::constants::TMP_CONFIG_DIR);
        if !tmp_dir.exists() {
            return;
        }
        let Ok(entries) = std::fs::read_dir(&tmp_dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if name == current_session_id {
                continue;
            }
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }

    #[test]
    fn sweep_removes_prior_session_subdirs() {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path();
        let prior = config_dir.join("tmp").join("2025-01-01T000000Z-9999");
        let current = config_dir.join("tmp").join("2026-05-28T120000Z-1234");
        std::fs::create_dir_all(&prior).unwrap();
        std::fs::create_dir_all(&current).unwrap();
        std::fs::write(prior.join("corp.conf"), "stale").unwrap();
        std::fs::write(current.join("vpn.conf"), "live").unwrap();

        sweep_orphan_temp_configs(config_dir, "2026-05-28T120000Z-1234");

        assert!(!prior.exists(), "orphan session subdir must be removed");
        assert!(current.exists(), "current session subdir must survive");
        assert!(current.join("vpn.conf").exists());
    }

    #[test]
    fn sweep_is_noop_when_tmp_dir_missing() {
        let tmp = tempfile::tempdir().unwrap();
        // No tmp/ created. Sweep must not panic and must not create anything.
        sweep_orphan_temp_configs(tmp.path(), "sid");
        assert!(!tmp.path().join("tmp").exists());
    }

    #[test]
    fn persistent_keepalive_peer_needs_no_probe_target() {
        let parsed = parse_wg_conf(
            "[Peer]\nPublicKey = peer\nAllowedIPs = 10.0.0.0/24\nPersistentKeepalive = 25\n",
        )
        .unwrap();
        let tunnel = WgTunnel::new().with_handshake_policy(Duration::from_secs(20), []);
        let plan = tunnel.handshake_plan(&parsed).unwrap();
        assert_eq!(plan.expected, BTreeSet::from(["peer".to_string()]));
        assert!(plan.probes.is_empty());
    }

    #[test]
    fn every_non_keepalive_peer_requires_its_own_covered_target() {
        let parsed = parse_wg_conf(
            "[Peer]\nPublicKey = keepalive\nAllowedIPs = 10.0.0.0/24\nPersistentKeepalive = 25\n\
             [Peer]\nPublicKey = active\nAllowedIPs = 192.168.0.0/16\n",
        )
        .unwrap();
        let covered = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 7));
        let plan = WgTunnel::new()
            .with_handshake_policy(Duration::from_secs(20), [covered])
            .handshake_plan(&parsed)
            .unwrap();
        assert_eq!(plan.probes.len(), 1);
        assert_eq!(plan.probes[0].peer_public_key, "active");
        assert_eq!(plan.probes[0].target, covered);
        assert_eq!(plan.probes[0].allowed_routes, vec!["192.168.0.0/16"]);

        let error = WgTunnel::new()
            .with_handshake_policy(
                Duration::from_secs(20),
                [IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))],
            )
            .handshake_plan(&parsed)
            .unwrap_err();
        assert!(error.to_string().contains("active"));
    }

    #[test]
    fn probe_route_must_resolve_to_exact_owned_interface() {
        use crate::vortix_core::ports::route_table::DefaultRouteObservation;
        let target = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 7));
        assert!(verify_probe_route(
            DefaultRouteObservation::Interface("wg0".into()),
            target,
            "wg0"
        )
        .is_ok());
        assert!(verify_probe_route(
            DefaultRouteObservation::Interface("en0".into()),
            target,
            "wg0"
        )
        .is_err());
        assert!(
            verify_probe_route(DefaultRouteObservation::ProbeFailed, target, "wg0")
                .unwrap_err()
                .to_string()
                .contains("ambiguous")
        );
    }

    #[test]
    fn dump_parser_rejects_extra_fields_oversize_and_future_timestamps() {
        let observed = UNIX_EPOCH + Duration::from_secs(1_000);
        let extra = "private\tpublic\t51820\toff\textra\n";
        assert!(parse_wg_dump("wg0", extra, observed, 1).is_err());

        let future =
            "private\tpublic\t51820\toff\npeer\t(none)\t(none)\t10.0.0.0/24\t2000\t0\t0\t0\n";
        assert!(parse_wg_dump("wg0", future, observed, 1).is_err());

        let oversized = "x".repeat(MAX_WG_DUMP_BYTES + 1);
        assert!(parse_wg_dump("wg0", &oversized, observed, 1).is_err());
    }

    #[test]
    fn dump_parser_bounds_peer_and_route_cardinality() {
        let observed = UNIX_EPOCH + Duration::from_secs(1_000);
        let routes = std::iter::repeat_n("10.0.0.0/24", MAX_ROUTES_PER_PEER + 1)
            .collect::<Vec<_>>()
            .join(",");
        let dump =
            format!("private\tpublic\t51820\toff\npeer\t(none)\t(none)\t{routes}\t900\t0\t0\t0\n");
        assert!(parse_wg_dump("wg0", &dump, observed, 1).is_err());

        let peer = "peer\t(none)\t(none)\t10.0.0.0/24\t900\t0\t0\t0\n";
        let dump = format!(
            "private\tpublic\t51820\toff\n{}",
            peer.repeat(MAX_WG_PEERS + 1)
        );
        assert!(parse_wg_dump("wg0", &dump, observed, 1).is_err());
    }

    #[test]
    fn invalid_or_cancelled_policy_fails_before_profile_io() {
        let profile = Profile::new(
            crate::vortix_core::profile::ProfileId::new("missing"),
            "missing",
            crate::vortix_core::profile::ProtocolKind::WireGuard,
            PathBuf::from("/definitely/missing.conf"),
        );
        let mut invalid = WgTunnel::new().with_handshake_policy(Duration::ZERO, []);
        assert!(matches!(invalid.up(&profile), Err(TunnelError::Other(_))));
        let mut zero_generation = WgTunnel::new().for_generation(0);
        assert!(matches!(
            zero_generation.up(&profile),
            Err(TunnelError::Other(_))
        ));

        let cancellation = crate::vortix_core::ports::tunnel::TunnelCancellation::default();
        cancellation.cancel();
        let mut cancelled = WgTunnel::new().with_execution_context(TunnelExecutionContext {
            cancellation,
            deadline: Instant::now() + Duration::from_secs(1),
        });
        assert!(matches!(
            cancelled.up(&profile),
            Err(TunnelError::Cancelled)
        ));
    }
}
