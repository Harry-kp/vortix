//! `WgTunnel` — `WireGuard` impl of the `Tunnel` port.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::process::{CommandSpec, PrivilegeReq};
use crate::profile::Profile;
use crate::tunnel::{
    HandshakeAttempt, ProbeReceipt, TunnelError, TunnelExecutionContext, TunnelHandle,
    TunnelKindTag, TunnelPeerStatus, TunnelStatus, TunnelTeardownConfig,
};
use tracing::{debug, info, warn};

use crate::wireguard::parser::parse_wg_conf;

/// `wg-quick`-based `WireGuard` tunnel.
///
/// Kernel `WireGuard` only; user-space backends are not supported.
///
/// DNS directives are always removed from the `wg-quick` input. The parsed
/// request is returned on [`TunnelHandle`] for the protocol-neutral policy
/// coordinator; `wg-quick` never mutates resolver state itself.
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
/// A wedged teardown must not hold the engine thread forever.
const WG_QUICK_DOWN_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_STATUS_POLL: Duration = Duration::from_millis(250);
const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const MIN_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(300);
const MIN_STATUS_POLL: Duration = Duration::from_millis(10);
const MAX_STATUS_POLL: Duration = Duration::from_secs(5);
const MAX_PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HEALTH_TARGETS: usize = 64;
const MAX_WG_DUMP_BYTES: usize = 1024 * 1024;
const MAX_WG_INTERFACES: usize = 512;
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
    profile_id: crate::profile::ProfileId,
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

fn managed_up_body(text: &str, profile: &Profile) -> Result<String, TunnelError> {
    let stripped = strip_dns_directive(text);
    if !profile.require_managed_endpoint_resolution {
        return Ok(stripped);
    }
    let mut output = String::with_capacity(stripped.len());
    for line in stripped.split_inclusive('\n') {
        let Some((left, right)) = line.split_once('=') else {
            output.push_str(line);
            continue;
        };
        if !left.trim().eq_ignore_ascii_case("Endpoint") {
            output.push_str(line);
            continue;
        }
        let endpoint = right.split(['#', ';']).next().unwrap_or_default().trim();
        let Some((host, port)) = crate::wireguard::parser::parse_endpoint_host(endpoint) else {
            return Err(TunnelError::Subprocess(
                "managed WireGuard endpoint is malformed".into(),
            ));
        };
        if host.parse::<IpAddr>().is_ok() {
            output.push_str(line);
            continue;
        }
        let Some(address) = profile.resolved_endpoint(&host, port) else {
            return Err(TunnelError::Subprocess(format!(
                "managed WireGuard endpoint {host}:{port} has no unambiguous profile-bound resolution"
            )));
        };
        let formatted = match address {
            IpAddr::V4(address) => format!("{address}:{port}"),
            IpAddr::V6(address) => format!("[{address}]:{port}"),
        };
        let newline = if line.ends_with('\n') { "\n" } else { "" };
        output.push_str(left);
        output.push_str("= ");
        output.push_str(&formatted);
        output.push_str(newline);
    }
    Ok(output)
}

/// Resolve the current `session_id` from the global journal, or fall back to
/// a pid-derived stable value when the journal is disabled (tests, or
/// `[journal] disk = false`). The fallback is deterministic within a process
/// so repeated calls within one run yield the same subdir.
fn resolve_session_id() -> String {
    crate::wireguard::tunnel::temp_session_id()
}

/// Validate the interface name that `wg-quick` derives from a config basename.
///
/// Linux limits interface names to 15 bytes and `wg-quick` applies this same
/// portable contract on macOS. Keeping the name explicit avoids a second,
/// hidden identity between profile storage, observation, and teardown.
/// Return and validate the exact interface name derived from a config path.
pub(crate) fn interface_name_from_path(path: &Path) -> Result<String, TunnelError> {
    let name = path
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| TunnelError::Subprocess("WireGuard config has no valid name".into()))?;
    crate::profile::validate_wireguard_interface_name(name).map_err(TunnelError::Subprocess)?;
    Ok(name.to_owned())
}

/// Inner helper: write the sanitized body to `${session_dir}/${basename}` at
/// mode `0o600`. The basename is preserved verbatim so every lifecycle layer
/// uses the same explicit `wg-quick` interface identity.
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
    use crate::config::secret::{write_secret_file, SecretFileError};

    interface_name_from_path(user_conf_path)?;
    let basename = user_conf_path
        .file_name()
        .ok_or_else(|| TunnelError::Subprocess("WireGuard config has no basename".into()))?;
    let temp_path = session_dir.join(basename);

    // Best-effort unlink of any stale leaf from a same-session reconnect.
    // Ignore all errors — NotFound is the happy path and any other error is
    // surfaced by the subsequent write_secret_file attempt.
    let _ = std::fs::remove_file(&temp_path);

    write_secret_file(&temp_path, stripped_body).map_err(|e| match e {
        SecretFileError::Io(io) => {
            TunnelError::Subprocess(format!("write managed WG config: {io}"))
        }
        other => TunnelError::Subprocess(format!("write managed WG config: {other}")),
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
    // Debian and Ubuntu ship an AppArmor profile for wg-quick that permits no
    // config path outside /etc/wireguard. Staging under the session tmp dir
    // made the kernel deny the read — `apparmor="DENIED" operation="open"
    // profile="wg-quick"` — and every WireGuard connect timed out with nothing
    // in Vortix's own logs to explain it. The canonical directory is the only
    // location a confined wg-quick can read, so on Linux that is where the
    // lifecycle copy goes.
    if let Some(directory) = crate::platform::wireguard_staging_dir() {
        return write_managed_config_in_wireguard_dir(directory, user_conf_path, stripped_body);
    }
    write_managed_temp_config_unconfined(user_conf_path, stripped_body)
}

/// Stage the lifecycle copy inside the directory a confined `wg-quick` may
/// read.
///
/// The platform hands back a Vortix-owned subdirectory, so nothing here
/// belongs to the user and the write needs no ownership arbitration.
fn write_managed_config_in_wireguard_dir(
    directory: &Path,
    user_conf_path: &Path,
    stripped_body: &[u8],
) -> Result<PathBuf, TunnelError> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .map_err(|error| {
            TunnelError::Subprocess(format!(
                "create {}: {error}. WireGuard needs this directory because wg-quick is confined to it.",
                directory.display()
            ))
        })?;
    write_managed_temp_config_at(directory, user_conf_path, stripped_body)
}

/// Original staging behaviour, retained where `wg-quick` is unconfined.
fn write_managed_temp_config_unconfined(
    user_conf_path: &Path,
    stripped_body: &[u8],
) -> Result<PathBuf, TunnelError> {
    let session_id = resolve_session_id();
    let session_root = crate::wireguard::tunnel::get_tmp_config_dir(&session_id).map_err(|e| {
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
        let result = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700).create(&path)
        };

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
        // their own leaf and the dir survives. The name check gates only the
        // session-root removal below, so an empty session dir is still
        // collected here.
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
                    .parse::<crate::cidr::Cidr>()
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

/// Parse the stable `wg show all dump` format into exact per-interface facts.
/// The all-interface form prefixes every interface and peer line with the
/// interface name; converting each bounded block through [`parse_wg_dump`]
/// keeps the single-interface parser as the one validation authority.
///
/// A foreign interface (`NetBird`, `Tailscale`, a corporate mesh — all
/// `WireGuard` underneath) can carry a peer table too large for the per-interface
/// caps; skip an interface whose block fails to parse rather than failing the
/// whole observation, which would report every tunnel unverifiable and refuse
/// startup.
pub fn parse_wg_all_dump(
    dump: &str,
    observed_at: SystemTime,
    generation: u64,
) -> Result<BTreeMap<String, WgStatus>, TunnelError> {
    if dump.len() > MAX_WG_DUMP_BYTES {
        return Err(TunnelError::ResourceLimit {
            resource: "WireGuard status bytes",
            limit: MAX_WG_DUMP_BYTES,
        });
    }
    let mut blocks = BTreeMap::<String, String>::new();
    let mut current_interface: Option<String> = None;
    for line in dump.lines() {
        let fields = line.split('\t').collect::<Vec<_>>();
        // Oversized fields are caught per-block by parse_wg_dump, which skips
        // just that interface.
        match fields.as_slice() {
            [interface, private_key, public_key, listen_port, fwmark] => {
                if blocks.len() >= MAX_WG_INTERFACES || blocks.contains_key(*interface) {
                    return Err(TunnelError::ResourceLimit {
                        resource: "WireGuard interfaces",
                        limit: MAX_WG_INTERFACES,
                    });
                }
                let block = format!("{private_key}\t{public_key}\t{listen_port}\t{fwmark}\n");
                blocks.insert((*interface).to_owned(), block);
                current_interface = Some((*interface).to_owned());
            }
            [interface, peer @ ..] if peer.len() == 8 => {
                if current_interface.as_deref() != Some(*interface) {
                    return Err(TunnelError::MalformedStatus(
                        "WireGuard peer appeared outside its interface block".into(),
                    ));
                }
                let block = blocks.get_mut(*interface).ok_or_else(|| {
                    TunnelError::MalformedStatus("WireGuard peer without interface".into())
                })?;
                block.push_str(&peer.join("\t"));
                block.push('\n');
            }
            _ => {
                return Err(TunnelError::MalformedStatus(
                    "WireGuard all-interface dump shape".into(),
                ));
            }
        }
    }
    Ok(blocks
        .into_iter()
        .filter_map(|(interface, block)| {
            match parse_wg_dump(&interface, &block, observed_at, generation) {
                Ok(status) => Some((interface, status)),
                Err(error) => {
                    debug!(
                        target: "vortix::registry",
                        interface = %interface,
                        %error,
                        "skipping unparseable WireGuard interface during all-interface observation"
                    );
                    None
                }
            }
        })
        .collect())
}

fn observe_all_interfaces_with(
    mut execute: impl FnMut(&CommandSpec) -> Result<Vec<u8>, TunnelError>,
) -> Result<BTreeMap<String, WgStatus>, TunnelError> {
    let spec = CommandSpec::oneshot("wg", vec!["show".into(), "all".into(), "dump".into()])
        .timeout(Duration::from_secs(2))
        .output_limit(MAX_WG_DUMP_BYTES);
    let stdout = execute(&spec)?;
    let observed_at = SystemTime::now();
    let dump = std::str::from_utf8(&stdout)
        .map_err(|error| TunnelError::Other(format!("WireGuard status was not UTF-8: {error}")))?;
    parse_wg_all_dump(dump, observed_at, 0)
}

fn observe_interface_with_generation(
    interface_name: &str,
    generation: u64,
    timeout: Duration,
) -> Result<WgStatus, TunnelError> {
    if timeout.is_zero() {
        return Err(TunnelError::Timeout(Duration::ZERO));
    }
    let output = crate::process::run(
        CommandSpec::oneshot(
            "wg",
            vec!["show".into(), interface_name.into(), "dump".into()],
        )
        .timeout(timeout.min(Duration::from_secs(2)))
        .output_limit(MAX_WG_DUMP_BYTES),
    )
    .map_err(|error| TunnelError::Subprocess(format!("wg show {interface_name} dump: {error}")))?;
    if !output.success() {
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
    /// One protocol-owned, bounded observation for every `WireGuard` interface.
    pub fn observe_all_interfaces() -> Result<BTreeMap<String, WgStatus>, TunnelError> {
        observe_all_interfaces_with(|spec| {
            let output = crate::process::run(spec.clone())
                .map_err(|error| TunnelError::Subprocess(format!("wg show all dump: {error}")))?;
            if !output.success() {
                return Err(TunnelError::Subprocess(format!(
                    "wg show all dump: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
            Ok(output.stdout)
        })
    }

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
            crate::platform::Interface::resolve_wireguard_interface(&attempt.interface_basename),
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
                wg_quick_interface: Some(attempt.interface_basename),
            }),
            dns_request: crate::control::dns::DnsRequest::default(),
            openvpn_routes: None,
        };
        self.down(&handle)?;
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
        parsed: &crate::wireguard::parser::WgParsedProfile,
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
                        "WireGuard peer {} has no PersistentKeepalive and no health target inside its AllowedIPs; add PersistentKeepalive = 25 to the peer, or an address inside its AllowedIPs to wireguard_health_targets under [engine] in settings.toml",
                        peer.public_key
                    ))
                })?;
            probes.push(ProbePlan {
                peer_public_key: peer.public_key.clone(),
                target,
                allowed_routes: peer.allowed_ips.iter().map(ToString::to_string).collect(),
            });
        }
        Ok(HandshakePlan { expected, probes })
    }

    fn await_handshake(
        &self,
        handle: &TunnelHandle,
        attempt: &HandshakeAttempt,
        probes: &[ProbePlan],
    ) -> Result<(crate::tunnel::HandshakeEvidence, Vec<ProbeReceipt>), TunnelError> {
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
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(TunnelError::Timeout(self.handshake_timeout));
            }
            let issued_at = issue_handshake_probe(
                probe.target,
                &handle.interface_name,
                self.probe_timeout.min(remaining),
            )?;
            receipts.push(ProbeReceipt {
                peer_public_key: probe.peer_public_key.clone(),
                target: probe.target,
                allowed_routes: probe.allowed_routes.clone(),
                issued_at,
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
        let observation = crate::platform::Routes::route_interface_for(target);
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
        dns_request: crate::control::dns::DnsRequest,
        original: TunnelError,
    ) -> TunnelError {
        let basename = interface_from_path(&temp_path);
        let interface_name = resolve_kernel_iface(
            &basename,
            crate::platform::Interface::resolve_wireguard_interface(&basename),
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
                wg_quick_interface: Some(basename),
            }),
            dns_request,
            openvpn_routes: None,
        };
        settle_failed_attempt(
            original,
            &interface_name,
            initially_exists,
            || cleanup_managed_temp_config(&cleanup_path),
            || self.down(&handle),
            || wait_for_interface_absence(&interface_name, Duration::from_secs(2)),
            || wait_for_interface_presence(&interface_name, Duration::from_secs(2)),
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
    settle_presence: impl FnOnce() -> bool,
) -> TunnelError {
    // "Absent right now" is not "never created": the daemon behind the
    // interface may still be starting after its launcher was killed. Give it
    // a bounded moment before concluding there is nothing to tear down.
    if !initially_exists && !settle_presence() {
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
    observation: crate::platform::DefaultRouteObservation,
    target: IpAddr,
    owned_interface: &str,
) -> Result<(), TunnelError> {
    use crate::platform::DefaultRouteObservation;
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

fn peer_covers_target(peer: &crate::wireguard::parser::WgPeer, target: IpAddr) -> bool {
    peer.allowed_ips
        .iter()
        .any(|route| route_covers_target(*route, target))
}

fn route_covers_target(route: crate::cidr::Cidr, target: IpAddr) -> bool {
    route.intersects(&crate::cidr::Cidr::host(target))
}

/// Verify that a configured health target is currently routed through the
/// exact owned `WireGuard` interface, then issue one UDP packet to elicit a
/// handshake. The route proof and packet emission stay inside the protocol
/// adapter even when lifecycle execution is delegated to the root helper.
pub(crate) fn issue_handshake_probe(
    target: IpAddr,
    owned_interface: &str,
    timeout: Duration,
) -> Result<SystemTime, TunnelError> {
    WgTunnel::ensure_probe_route(target, owned_interface)?;
    send_handshake_probe(target, timeout).map_err(|error| {
        TunnelError::Other(format!("WireGuard handshake probe failed: {error}"))
    })?;
    Ok(SystemTime::now())
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

/// Wait briefly for an interface that may still be coming up.
///
/// `wg-quick` spawns `wireguard-go` and returns; killing `wg-quick` on a
/// deadline does not kill that daemon. A failed attempt that probes for its
/// interface the instant the command dies can therefore see nothing, skip
/// teardown, and leave the daemon to finish starting — owning a `utun` with
/// whatever routes it had installed, with no owner left to remove it.
fn wait_for_interface_presence(interface_name: &str, timeout: Duration) -> bool {
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return false;
    };
    loop {
        if WgTunnel::interface_exists(interface_name) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
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
///   `Some("utun7")` (or similar). The engine snapshot needs `utun7` stored
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
    profile_id: &crate::profile::ProfileId,
) -> String {
    if let Some(iface) = port_result {
        return iface;
    }
    #[cfg(target_os = "macos")] // xtask:allow-platform-cfg: warn-only diagnostic for an anomalous wg-quick state on macOS
    warn!(
        target: "vortix::control::tunnels::wireguard",
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
            wg_quick_interface: None,
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
        let wg_quick_interface = config
            .wg_quick_interface
            .as_deref()
            .unwrap_or(&handle.interface_name);
        crate::profile::validate_wireguard_interface_name(wg_quick_interface)
            .map_err(TunnelError::Subprocess)?;
        if interface_from_path(&config.path) != wg_quick_interface {
            if Path::new(wg_quick_interface).components().count() != 1 {
                return Err(TunnelError::Subprocess(
                    "managed WireGuard alias is not a safe basename".into(),
                ));
            }
            let body = read_bounded_profile(&config.path)?;
            parse_wg_conf(&body).map_err(|error| {
                TunnelError::Subprocess(format!(
                    "validate recovered WireGuard teardown profile: {error}"
                ))
            })?;
            let interface_config = PathBuf::from(format!("{wg_quick_interface}.conf"));
            let temp_path = write_managed(&interface_config, body.as_bytes())?;
            return Ok(PreparedDownTarget {
                target: temp_path.to_string_lossy().into_owned(),
                cleanup_after_attempt: Some(temp_path),
                cleanup_after_success: Some(config.path),
            });
        }
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
    CommandSpec::oneshot("wg-quick", vec!["down".into(), target])
        .privilege(PrivilegeReq::Root)
        .timeout(WG_QUICK_DOWN_TIMEOUT)
}

impl WgTunnel {
    #[allow(clippy::too_many_lines)]
    pub fn up(&mut self, profile: &Profile) -> Result<TunnelHandle, TunnelError> {
        self.validate_settings()?;
        // Reject legacy or externally-created invalid names before reading
        // secrets, spawning `wg-quick`, or entering a Handshaking UI state.
        let explicit_interface_name = interface_name_from_path(&profile.config_path)?;
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
        let stripped = managed_up_body(&user_body, profile)?;
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
        let interface_basename = interface_from_path(&effective_path);
        debug_assert_eq!(interface_basename, explicit_interface_name);

        self.inflight = Some(Box::new(WgInflightAttempt {
            profile_id: profile.id.clone(),
            display_name: profile.display_name.clone(),
            interface_basename,
            started_at: attempt_started,
            generation,
            temp_path: temp_path.clone(),
        }));

        let path_str = effective_path.to_string_lossy().into_owned();
        info!(
            target: "vortix::control::tunnels::wireguard",
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
        let output = crate::process::run(
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

        if !output.success() {
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
            crate::platform::Interface::resolve_wireguard_interface(&basename),
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
                wg_quick_interface: Some(explicit_interface_name),
            }),
            dns_request,
            openvpn_routes: None,
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
                let cleanup = self.down(&handle);
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
                let cleanup = self.down(&handle);
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

    pub fn down(&mut self, handle: &TunnelHandle) -> Result<(), TunnelError> {
        info!(
            target: "vortix::control::tunnels::wireguard",
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

        let prepared = prepare_down_target(handle)?;
        let output = crate::process::run(wg_quick_down_spec(prepared.target));

        if let Some(path) = &prepared.cleanup_after_attempt {
            cleanup_managed_temp_config(path);
        }

        let output = output.map_err(|e| TunnelError::Subprocess(format!("wg-quick down: {e}")))?;

        if !output.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            // `wg-quick` prints commands and paths here, never the private-key
            // values from its input. Preserve this diagnostic because a
            // failed exact-attempt teardown intentionally leaves ownership
            // ambiguous and the caller must not pretend it was cleaned up.
            warn!(
                target: "vortix::control::tunnels::wireguard",
                profile = %handle.profile_id,
                interface = %handle.interface_name,
                stderr = %stderr.trim(),
                "wg.down.failed"
            );
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

    pub fn status(&self, handle: &TunnelHandle) -> Result<TunnelStatus, TunnelError> {
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
        let peers = detail.peers;
        Ok(TunnelStatus {
            handle: handle.clone(),
            bytes_rx,
            bytes_tx,
            last_handshake,
            observed_at,
            peers,
        })
    }
}

/// Returns the per-session temp config directory `${config_dir}/tmp/${session_id}/`.
///
/// Both the `tmp/` parent and the per-session subdir are forced to mode
/// `0o700` — the default umask would yield `0o755`, allowing any local
/// process to enumerate active session IDs by listing the parent. Used by
/// `WireGuard` secondary connect-time DNS scoping: the
/// secondary's rewritten `.conf` (with `DNS =` stripped) is written under
/// this subdir so crashed disconnects leave isolated orphans that the
/// startup sweep cleans only after acquiring their process-lifetime lease.
///
/// The subdir name matches the journal's `session_id` (`{ISO}-{pid}`), so a
/// new Vortix process is guaranteed a fresh namespace without mistaking a
/// concurrently running session for a crash orphan.
///
/// # Errors
///
/// Returns an error if the config directory cannot be resolved or if the
/// per-session subdirectory cannot be created at the required mode.
pub fn get_tmp_config_dir(session_id: &str) -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::fs::DirBuilderExt;

    let root = crate::config::get_config_dir()?;
    let tmp_root = root.join(crate::constants::TMP_CONFIG_DIR);

    // Create `tmp/` and the per-session subdir at 0o700 explicitly.
    // `recursive(true)` is idempotent on existing dirs but does NOT re-chmod
    // them, so on first creation we set the mode through DirBuilder; on
    // existing dirs we leave the mode alone (the only writer is this
    // process's prior call, which used the same mode).
    if !tmp_root.exists() {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&tmp_root)?;
        crate::config::fix_ownership(&tmp_root);
    }

    let session_dir = tmp_root.join(session_id);
    if !session_dir.exists() {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&session_dir)?;
        crate::config::fix_ownership(&session_dir);
    }

    Ok(session_dir)
}

/// Process-lifetime lease for one per-session scratch directory.
///
/// The kernel releases the advisory lock on every process exit path,
/// including crashes and [`std::process::exit`]. Keeping this value alive is
/// what distinguishes a concurrently running Vortix session from a crash
/// orphan; a different journal session ID alone is not proof of death.
#[derive(Debug)]
pub struct TempSessionLease {
    _file: std::fs::File,
}

/// Resolve the scratch-session identity used by protocol-owned temporary
/// files, including when journal disk persistence is disabled.
#[must_use]
pub fn temp_session_id() -> String {
    crate::journal::global_journal()
        .and_then(crate::journal::Journal::session_id)
        .unwrap_or_else(|| format!("nojournal-{}", std::process::id()))
}

/// Create and exclusively lease this process's scratch-session directory.
///
/// # Errors
///
/// Returns an I/O error when the private directory or its no-follow lease
/// file cannot be created, or when another process already holds the same
/// session identity.
pub fn acquire_temp_session_lease(
    config_dir: &std::path::Path,
    session_id: &str,
) -> std::io::Result<TempSessionLease> {
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
    use std::os::unix::io::AsRawFd as _;

    let tmp_root = config_dir.join(crate::constants::TMP_CONFIG_DIR);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(&tmp_root)?;
    let session_dir = tmp_root.join(session_id);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(&session_dir)?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(session_dir.join(".lease"))?;
    // SAFETY: `file` owns a valid descriptor for the lifetime of the lease;
    // flock changes only the kernel lock associated with that descriptor.
    #[allow(unsafe_code)]
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    crate::config::fix_ownership(&tmp_root);
    crate::config::fix_ownership(&session_dir);
    crate::config::fix_ownership(&session_dir.join(".lease"));
    Ok(TempSessionLease { _file: file })
}

fn legacy_temp_session_process_is_live(session_id: &str) -> bool {
    let Some(pid) = session_id
        .rsplit_once('-')
        .and_then(|(_, pid)| pid.parse::<i32>().ok())
        .filter(|pid| *pid > 0)
    else {
        return false;
    };
    // SAFETY: signal zero is a side-effect-free existence probe. Permission
    // denial also proves that a process currently owns the PID.
    #[allow(unsafe_code)]
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// Remove only scratch sessions proven not to have a live process lease.
///
/// Directories from older Vortix releases have no `.lease`; during the
/// upgrade window their PID suffix remains a conservative liveness fallback.
/// Unknown or inaccessible entries are retained rather than risking deletion
/// of a live tunnel's teardown capability.
pub fn sweep_orphan_temp_configs(config_dir: &std::path::Path, current_session_id: &str) {
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::io::AsRawFd as _;

    let tmp_dir = config_dir.join(crate::constants::TMP_CONFIG_DIR);
    let Ok(entries) = std::fs::read_dir(&tmp_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name == current_session_id || !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let lease = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(entry.path().join(".lease"));
        match lease {
            Ok(file) => {
                // SAFETY: `file` is an owned valid descriptor. A refused
                // nonblocking lock means a live process still owns it.
                //
                // Only a refusal means that. `flock` can also fail with EINTR
                // when a signal lands mid-call, which says nothing about
                // ownership, and treating it as ownership silently abandons a
                // real orphan. The test for this sweep failed intermittently
                // under a loaded parallel run for exactly that reason. Retry an
                // interrupt; treat anything else as owned and leave it alone.
                let refused = loop {
                    #[allow(unsafe_code)]
                    let result =
                        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
                    if result == 0 {
                        break false;
                    }
                    if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    break true;
                };
                if refused {
                    continue;
                }
                remove_swept_session(&entry.path());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !legacy_temp_session_process_is_live(&name) {
                    remove_swept_session(&entry.path());
                }
            }
            Err(error) => {
                // Anything other than a missing lease is unexpected, and
                // skipping in silence leaves scratch configuration behind with
                // no trace of why -- the same gap `remove_swept_session`
                // already closes for removal failures.
                tracing::warn!(
                    target: "vortix::process",
                    session = %name,
                    %error,
                    "could not read an orphan session lease; leaving it alone"
                );
            }
        }
    }
}

/// Remove one scratch session, saying so when it cannot be removed.
///
/// These directories hold rendered tunnel configuration. Discarding the error
/// let them accumulate with no trace of why.
fn remove_swept_session(path: &std::path::Path) {
    if let Err(error) = std::fs::remove_dir_all(path) {
        tracing::warn!(
            target: "vortix::process",
            path = %path.display(),
            %error,
            "could not remove an orphaned tunnel scratch directory"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn managed_profile(
        resolutions: impl IntoIterator<Item = crate::profile::ResolvedEndpoint>,
    ) -> Profile {
        Profile::new(
            crate::profile::ProfileId::new("managed-test"),
            "managed-test",
            crate::profile::ProtocolKind::WireGuard,
            PathBuf::from("managed-test.conf"),
        )
        .with_endpoint_resolutions(resolutions)
        .require_managed_endpoint_resolution()
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
        // This is the value the engine snapshot must store to match `route get`'s
        // output byte-for-byte.
        let profile_id = crate::profile::ProfileId::new("corp");
        let resolved = resolve_kernel_iface("corp", Some("utun7".to_string()), &profile_id);
        assert_eq!(resolved, "utun7");
    }

    #[test]
    fn resolve_kernel_iface_falls_back_to_basename_when_port_returns_none() {
        // Linux-shape: platform port returns None because the kernel
        // device name IS the config basename. The fallback is the
        // correct value to store.
        let profile_id = crate::profile::ProfileId::new("corp");
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
        let profile_id = crate::profile::ProfileId::new("corp");
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

    #[test]
    fn managed_up_config_rewrites_cached_hostname_without_dns() {
        let input = "[Interface]\nPrivateKey = abc\nDNS = 10.0.0.53\n[Peer]\nPublicKey = xyz\nEndpoint = vpn.example:51820\nAllowedIPs = 0.0.0.0/0\n";
        let resolution = crate::profile::ResolvedEndpoint::new(
            "vpn.example",
            51820,
            "203.0.113.19".parse().unwrap(),
        );
        let managed = managed_up_body(input, &managed_profile([resolution])).unwrap();
        assert!(!managed.contains("DNS ="));
        assert!(managed.contains("Endpoint = 203.0.113.19:51820"));
        assert!(!managed.contains("vpn.example"));

        let error = managed_up_body(input, &managed_profile([]))
            .expect_err("missing cache must fail closed");
        assert!(error.to_string().contains("vpn.example:51820"));
    }

    #[test]
    fn managed_up_config_preserves_ipv6_endpoint_family_and_port() {
        let input = "[Interface]\nPrivateKey = abc\n[Peer]\nPublicKey = xyz\nEndpoint = vpn.example:51820\n";
        let resolution = crate::profile::ResolvedEndpoint::new(
            "vpn.example",
            51820,
            "2001:db8::19".parse().unwrap(),
        );
        let managed = managed_up_body(input, &managed_profile([resolution])).unwrap();
        assert!(managed.contains("Endpoint = [2001:db8::19]:51820"));
    }

    fn wg_handle(
        interface_name: &str,
        teardown_config: Option<TunnelTeardownConfig>,
    ) -> TunnelHandle {
        TunnelHandle {
            profile_id: crate::profile::ProfileId::new("corp"),
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
            dns_request: crate::control::dns::DnsRequest::default(),
            openvpn_routes: None,
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
                wg_quick_interface: Some("corp".into()),
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
            "corp",
            Some(TunnelTeardownConfig {
                path: managed.clone(),
                managed: true,
                wg_quick_interface: Some("corp".into()),
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
    fn recovered_macos_down_uses_wg_quick_alias_not_kernel_interface() {
        let (_root, session) = fresh_session_dir();
        let scratch = tempfile::tempdir().unwrap();
        let persisted = scratch.path().join("ownership-record-hash.conf");
        std::fs::write(&persisted, "[Interface]\nPrivateKey = SECRET\n").unwrap();
        let handle = wg_handle(
            "utun4",
            Some(TunnelTeardownConfig {
                path: persisted.clone(),
                managed: true,
                wg_quick_interface: Some("wg07".into()),
            }),
        );

        let prepared = prepare_down_target_with(&handle, |path, body| {
            write_managed_temp_config_at(&session, path, body)
        })
        .unwrap();

        assert_eq!(
            std::path::Path::new(&prepared.target)
                .file_name()
                .and_then(std::ffi::OsStr::to_str),
            Some("wg07.conf"),
            "wg-quick must receive the alias recorded in /var/run/wireguard/wg07.name"
        );
        assert_eq!(
            prepared.cleanup_after_attempt.as_deref(),
            Some(std::path::Path::new(&prepared.target))
        );
        assert_eq!(
            prepared.cleanup_after_success.as_deref(),
            Some(persisted.as_path())
        );
        assert!(
            persisted.exists(),
            "durable recovery config stays until success"
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
            || panic!("a present interface must not wait for presence"),
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
            || panic!("a present interface must not wait for presence"),
        );
        assert!(matches!(error, TunnelError::Subprocess(_)));
        assert!(!managed.exists());
    }

    #[test]
    fn an_interface_that_appears_after_the_probe_is_still_torn_down() {
        // `wg-quick` spawns `wireguard-go` and returns; killing `wg-quick` on a
        // deadline leaves that daemon starting. Probing once the instant the
        // command dies saw no interface, skipped teardown, and let the daemon
        // finish — owning a utun with its routes and nothing left to remove it,
        // which took a laptop off the network.
        let scratch = tempfile::tempdir().unwrap();
        let managed = scratch.path().join("corp.conf");
        std::fs::write(&managed, "managed-attempt").unwrap();
        let torn_down = std::cell::Cell::new(false);

        let error = settle_failed_attempt(
            TunnelError::Timeout(Duration::from_secs(1)),
            "utun4",
            false, // the probe at kill time saw nothing
            || panic!("an interface that appeared must not be written off as absent"),
            || {
                torn_down.set(true);
                Ok(())
            },
            || true,
            || true, // …but it came up a moment later
        );

        assert!(torn_down.get(), "the late interface must be torn down");
        assert!(matches!(error, TunnelError::Timeout(_)));
    }

    #[test]
    fn nothing_created_still_skips_teardown() {
        let scratch = tempfile::tempdir().unwrap();
        let managed = scratch.path().join("corp.conf");
        std::fs::write(&managed, "managed-attempt").unwrap();
        let cleanup_path = managed.clone();

        let error = settle_failed_attempt(
            TunnelError::Timeout(Duration::from_secs(1)),
            "utun4",
            false,
            || std::fs::remove_file(cleanup_path).unwrap(),
            || panic!("an attempt that created nothing must not run teardown"),
            || true,
            || false, // never appeared
        );

        assert!(matches!(error, TunnelError::Timeout(_)));
        assert!(!managed.exists(), "its scratch config is still cleaned up");
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

    #[test]
    fn managed_temp_config_rejects_a_wg_quick_invalid_basename() {
        let (_root, session) = fresh_session_dir();
        let scratch = tempfile::tempdir().unwrap();
        let user_conf = scratch.path().join("07-wireguard-split-ip.conf");
        let body = b"[Interface]\nPrivateKey = SECRET\n";

        let error = write_managed_temp_config_at(&session, &user_conf, body).unwrap_err();
        assert!(error.to_string().contains("1–15 characters"));
        assert!(std::fs::read_dir(&session).unwrap().next().is_none());
    }

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

    #[test]
    fn sweep_removes_prior_session_subdirs() {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path();
        let prior_id = "2025-01-01T000000Z-9999";
        let prior = config_dir.join("tmp").join(prior_id);
        let current = config_dir.join("tmp").join("2026-05-28T120000Z-1234");
        // A session whose process died leaves its directory and an unlocked
        // `.lease` behind -- that is what the sweep exists to collect. Taking a
        // real lease and dropping it models the same end state but depends on
        // this process's own `flock` being visible as released to the `flock`
        // the sweep takes moments later, and under a loaded parallel run it
        // intermittently was not, which failed the assertion below rather than
        // any behaviour. Write the file the dead session would have left.
        std::fs::create_dir_all(&prior).unwrap();
        std::fs::write(prior.join(".lease"), b"").unwrap();
        std::fs::create_dir_all(&current).unwrap();
        std::fs::write(prior.join("corp.conf"), "stale").unwrap();
        std::fs::write(current.join("vpn.conf"), "live").unwrap();

        crate::wireguard::tunnel::sweep_orphan_temp_configs(config_dir, "2026-05-28T120000Z-1234");

        assert!(!prior.exists(), "orphan session subdir must be removed");
        assert!(current.exists(), "current session subdir must survive");
        assert!(current.join("vpn.conf").exists());
    }

    #[test]
    fn sweep_is_noop_when_tmp_dir_missing() {
        let tmp = tempfile::tempdir().unwrap();
        // No tmp/ created. Sweep must not panic and must not create anything.
        crate::wireguard::tunnel::sweep_orphan_temp_configs(tmp.path(), "sid");
        assert!(!tmp.path().join("tmp").exists());
    }

    #[test]
    fn sweep_preserves_a_different_live_session_lease() {
        let tmp = tempfile::tempdir().unwrap();
        let live_id = "2026-05-28T120000Z-4321";
        let live = tmp.path().join("tmp").join(live_id);
        let _lease =
            crate::wireguard::tunnel::acquire_temp_session_lease(tmp.path(), live_id).unwrap();
        std::fs::write(live.join("corp.conf"), "live teardown capability").unwrap();

        crate::wireguard::tunnel::sweep_orphan_temp_configs(tmp.path(), "another-session-1234");

        assert!(live.join("corp.conf").exists());
    }

    #[test]
    fn sweep_preserves_a_live_legacy_session_during_upgrade() {
        let tmp = tempfile::tempdir().unwrap();
        let live_id = format!("legacy-{}", std::process::id());
        let live = tmp.path().join("tmp").join(&live_id);
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(live.join("corp.conf"), "pre-lease live capability").unwrap();

        crate::wireguard::tunnel::sweep_orphan_temp_configs(tmp.path(), "another-session-1234");

        assert!(live.join("corp.conf").exists());
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
        use crate::platform::DefaultRouteObservation;
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
    fn all_dump_maps_exact_interfaces_and_uses_one_command() {
        let dump = concat!(
            "wg0\tprivate0\tpublic0\t51820\toff\n",
            "wg0\tpeer0\t(none)\t1.2.3.4:51820\t0.0.0.0/0\t900\t10\t20\t0\n",
            "wg1\tprivate1\tpublic1\t51821\t0x1\n",
            "wg1\tpeer1\t(none)\t(none)\t10.0.0.0/8\t0\t30\t40\t25\n",
        );
        let mut calls = 0;
        let statuses = observe_all_interfaces_with(|spec| {
            calls += 1;
            assert_eq!(spec.program, "wg");
            assert_eq!(spec.args, ["show", "all", "dump"]);
            Ok(dump.as_bytes().to_vec())
        })
        .unwrap();

        assert_eq!(calls, 1);
        assert_eq!(statuses.len(), 2);
        assert_eq!(statuses["wg0"].interface_public_key, "public0");
        assert_eq!(statuses["wg0"].peers[0].bytes_tx, 20);
        assert_eq!(statuses["wg1"].interface_public_key, "public1");
        assert_eq!(statuses["wg1"].peers[0].bytes_rx, 30);
    }

    #[test]
    fn all_dump_rejects_cross_interface_peer_attribution() {
        let dump = concat!(
            "wg0\tprivate0\tpublic0\t51820\toff\n",
            "wg1\tpeer1\t(none)\t(none)\t10.0.0.0/8\t0\t30\t40\t25\n",
        );
        assert!(parse_wg_all_dump(dump, SystemTime::now(), 0).is_err());
    }

    #[test]
    fn all_dump_skips_foreign_interface_with_oversized_peer_table() {
        // NetBird, Tailscale and corporate meshes are WireGuard underneath and
        // surface in `wg show all dump` with peer tables far larger than any
        // vortix tunnel. Such an interface must be skipped, not fail the whole
        // observation — which would report every real vortix tunnel
        // unverifiable and refuse startup.
        let huge_routes = "10.0.0.0/8,".repeat(600);
        let dump = format!(
            concat!(
                "wg0\tprivate0\tpublic0\t51820\toff\n",
                "wg0\tpeer0\t(none)\t1.2.3.4:51820\t0.0.0.0/0\t900\t10\t20\t0\n",
                "utun100\tprivbird\tpubbird\t51820\toff\n",
                "utun100\tpeerbird\t(none)\t(none)\t{routes}\t0\t0\t0\t25\n",
            ),
            routes = huge_routes,
        );
        let statuses =
            parse_wg_all_dump(&dump, SystemTime::now(), 0).expect("observation stays complete");
        assert_eq!(statuses.len(), 1);
        assert!(statuses.contains_key("wg0"));
        assert!(!statuses.contains_key("utun100"));
    }

    #[test]
    fn invalid_or_cancelled_policy_fails_before_profile_io() {
        let profile = Profile::new(
            crate::profile::ProfileId::new("missing"),
            "missing",
            crate::profile::ProtocolKind::WireGuard,
            PathBuf::from("/definitely/missing.conf"),
        );
        let mut invalid = WgTunnel::new().with_handshake_policy(Duration::ZERO, []);
        assert!(matches!(invalid.up(&profile), Err(TunnelError::Other(_))));
        let mut zero_generation = WgTunnel::new().for_generation(0);
        assert!(matches!(
            zero_generation.up(&profile),
            Err(TunnelError::Other(_))
        ));

        let cancellation = crate::tunnel::TunnelCancellation::default();
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

    #[test]
    fn test_get_tmp_config_dir_creates_session_subdir_at_0700() {
        use std::os::unix::fs::PermissionsExt;

        // `set_temp_config_dir` writes via `set_config_dir`'s `OnceLock` —
        // first writer wins across the whole test binary. Sibling tests are
        // unaffected because each test passes a unique session_id; subdirs
        // therefore can't collide even when they share a `tmp/` root.
        let _tmp = crate::config::set_temp_config_dir();
        let sid = format!("session-{}-{}", std::process::id(), line!());
        let session_dir = get_tmp_config_dir(&sid).unwrap();
        assert!(session_dir.ends_with(format!("tmp/{sid}")));

        let leaf_perms = std::fs::metadata(&session_dir).unwrap().permissions();
        assert_eq!(leaf_perms.mode() & 0o777, 0o700);

        // `tmp/` root is tightened to 0o700 — default umask would produce
        // 0o755 and leak session IDs via readdir.
        let tmp_root = session_dir.parent().unwrap();
        let root_perms = std::fs::metadata(tmp_root).unwrap().permissions();
        assert_eq!(root_perms.mode() & 0o777, 0o700);
    }

    #[test]
    fn test_get_tmp_config_dir_is_idempotent() {
        let _tmp = crate::config::set_temp_config_dir();
        let sid = format!("idempotent-{}-{}", std::process::id(), line!());
        let a = get_tmp_config_dir(&sid).unwrap();
        let b = get_tmp_config_dir(&sid).unwrap();
        assert_eq!(a, b);
        assert!(a.exists());
    }
}
