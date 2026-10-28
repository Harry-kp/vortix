//! `NetBird` mesh networks, run by Vortix through the `netbird` binary.
//!
//! Each `.netbird` profile gets its own daemon (`netbird service run`) under a
//! Vortix custodian, with its identity in a private state directory and a
//! private control socket, so it never meets `NetBird`'s own system service.
//! The daemon installs its own routes, DNS and firewall tables; Vortix plans
//! none for it.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::process::{CommandSpec, ManagedProcessId, PrivilegeReq};
use crate::profile::{Profile, ProfileId};
use crate::tunnel::{TunnelError, TunnelExecutionContext, TunnelHandle, TunnelKindTag};

/// `NetBird`'s own default, pinned so every connect listens on the same port.
const WIREGUARD_PORT: u16 = 51820;
/// Root-only, like `NetBird`'s own `/var/lib/netbird`: it holds each network's identity.
const STATE_ROOT: &str = "/var/lib/vortix/netbird";
const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Where the `NetBird` app keeps its identity, on macOS and Linux alike.
pub const APP_STATE_DIR: &str = "/var/lib/netbird";
/// The `NetBird` app's daemon socket; present while its service runs.
const APP_SOCKET: &str = "/var/run/netbird.sock";

/// What a `.netbird` profile file holds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetBirdProfile {
    pub management_url: String,
    /// Registers this device on first connect; unused once it has an identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_key: Option<String>,
    /// The `NetBird` app's identity file, copied in on first connect so this
    /// device stays the same peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<PathBuf>,
}

impl NetBirdProfile {
    pub fn parse(content: &str) -> Result<Self, String> {
        let profile: Self = toml::from_str(content).map_err(|error: toml::de::Error| {
            // The error's own text quotes the line, which may hold the setup key.
            let line = error
                .span()
                .map_or(0, |span| content[..span.start].matches('\n').count() + 1);
            format!("Invalid NetBird profile (line {line}): {}", error.message())
        })?;
        profile.management_host()?;
        Ok(profile)
    }

    /// Host and port of the management server.
    pub fn management_host(&self) -> Result<(String, u16), String> {
        let url = &self.management_url;
        let (rest, default_port) = url
            .strip_prefix("https://")
            .map(|rest| (rest, 443))
            .or_else(|| url.strip_prefix("http://").map(|rest| (rest, 80)))
            .ok_or("management_url must start with https:// or http://")?;
        let authority = rest.split('/').next().unwrap_or_default();
        let (host, port) = match authority.strip_prefix('[') {
            Some(v6) => v6.split_once(']').unwrap_or((v6, "")),
            None => authority.split_once(':').unwrap_or((authority, "")),
        };
        let port = match port.trim_start_matches(':') {
            "" => default_port,
            port => port
                .parse()
                .map_err(|_| format!("management_url has a bad port: {port}"))?,
        };
        if host.is_empty() {
            return Err("management_url has no host".into());
        }
        Ok((host.to_string(), port))
    }
}

/// The `NetBird` app's state directory: its active profile becomes a `.netbird`
/// profile that takes over that identity.
#[must_use]
pub fn is_app_state_dir(dir: &Path) -> bool {
    dir.join("default.json").is_file()
}

/// The `.netbird` profile that moves the `NetBird` app's active network here.
pub fn profile_from_app(dir: &Path) -> Result<String, String> {
    #[derive(Deserialize)]
    struct Active {
        name: String,
        #[serde(default)]
        username: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Url {
        scheme: String,
        host: String,
    }
    #[derive(Deserialize)]
    struct Config {
        #[serde(rename = "ManagementURL")]
        management_url: Url,
    }
    let read = |path: &Path| {
        std::fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
    };
    let active_path = dir.join("active_profile.json");
    let active = match std::fs::read(&active_path) {
        Ok(bytes) => serde_json::from_slice::<Active>(&bytes)
            .map_err(|error| format!("NetBird's active profile is unreadable: {error}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Active {
            name: "default".into(),
            username: String::new(),
        },
        Err(error) => return Err(format!("cannot read {}: {error}", active_path.display())),
    };
    let safe = |part: &str| !part.contains('/') && !part.contains("..");
    let identity = if active.name == "default" {
        dir.join("default.json")
    } else if safe(&active.name) && safe(&active.username) {
        dir.join(&active.username)
            .join(format!("{}.json", active.name))
    } else {
        return Err(format!(
            "NetBird's active profile has a bad name: {}",
            active.name
        ));
    };
    let config: Config = serde_json::from_slice(&read(&identity)?)
        .map_err(|error| format!("{} is not a NetBird profile: {error}", identity.display()))?;
    let profile = NetBirdProfile {
        management_url: format!(
            "{}://{}",
            config.management_url.scheme, config.management_url.host
        ),
        setup_key: None,
        identity: Some(identity),
    };
    profile.management_host()?;
    toml::to_string(&profile).map_err(|error| error.to_string())
}

/// The part of `netbird status --json` Vortix reads.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Status {
    pub daemon_status: String,
    pub netbird_ip: String,
    pub management: Server,
    pub peers: Peers,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Server {
    pub url: String,
    pub error: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Peers {
    #[serde(deserialize_with = "null_as_empty")]
    pub details: Vec<Peer>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Peer {
    pub fqdn: String,
    pub netbird_ip: String,
    pub status: String,
    pub connection_type: String,
    pub transfer_received: u64,
    pub transfer_sent: u64,
    /// Nanoseconds.
    pub latency: u64,
}

/// Go encodes an empty list as `null`.
fn null_as_empty<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

impl Status {
    pub fn parse(json: &[u8]) -> Result<Self, TunnelError> {
        serde_json::from_slice(json)
            .map_err(|error| TunnelError::MalformedStatus(format!("netbird status: {error}")))
    }

    #[must_use]
    pub fn connected(&self) -> bool {
        self.daemon_status == "Connected"
    }

    /// The daemon has no identity, or the network refused the one it has.
    #[must_use]
    pub fn needs_login(&self) -> bool {
        matches!(
            self.daemon_status.as_str(),
            "NeedsLogin" | "LoginFailed" | "SessionExpired"
        )
    }

    /// The session the scanner reports for a running network.
    fn session(&self) -> crate::control::scanner::ActiveSession {
        let peers = &self.peers.details;
        let mut details = crate::tunnel::DetailedConnectionInfo {
            internal_ip: self.netbird_ip.clone(),
            endpoint: self
                .management
                .url
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .to_string(),
            transfer_rx: peers
                .iter()
                .map(|peer| peer.transfer_received)
                .sum::<u64>()
                .to_string(),
            transfer_tx: peers
                .iter()
                .map(|peer| peer.transfer_sent)
                .sum::<u64>()
                .to_string(),
            ..Default::default()
        };
        details.peers = peers
            .iter()
            .map(|peer| crate::tunnel::MeshPeer {
                name: peer
                    .fqdn
                    .split('.')
                    .next()
                    .filter(|name| !name.is_empty())
                    .unwrap_or(&peer.netbird_ip)
                    .to_string(),
                address: peer.netbird_ip.clone(),
                connected: peer.status == "Connected",
                relayed: peer.connection_type == "Relayed",
                latency: (peer.latency > 0).then(|| Duration::from_nanos(peer.latency)),
            })
            .collect();
        crate::control::scanner::ActiveSession {
            details,
            ..Default::default()
        }
    }
}

/// The `NetBird` transport for one connect or disconnect.
#[derive(Debug, Clone)]
pub struct NbTunnel {
    connect_timeout: Duration,
    generation: Option<u64>,
    execution_context: Option<TunnelExecutionContext>,
}

impl NbTunnel {
    #[must_use]
    pub fn new(connect_timeout_secs: u64) -> Self {
        Self {
            connect_timeout: Duration::from_secs(connect_timeout_secs),
            generation: None,
            execution_context: None,
        }
    }

    #[must_use]
    pub fn for_generation(mut self, generation: u64) -> Self {
        self.generation = Some(generation);
        self
    }

    #[must_use]
    pub fn with_execution_context(mut self, context: TunnelExecutionContext) -> Self {
        self.execution_context = Some(context);
        self
    }

    fn remaining(&self) -> Result<Duration, TunnelError> {
        let Some(context) = &self.execution_context else {
            return Ok(self.connect_timeout);
        };
        if context.cancellation.is_cancelled() {
            return Err(TunnelError::Cancelled);
        }
        let remaining = self
            .connect_timeout
            .min(context.deadline.saturating_duration_since(Instant::now()));
        if remaining.is_zero() {
            return Err(TunnelError::Timeout(self.connect_timeout));
        }
        Ok(remaining)
    }

    pub fn up(&mut self, profile: &Profile) -> Result<TunnelHandle, TunnelError> {
        self.remaining()?;
        let content = std::fs::read_to_string(&profile.config_path)?;
        let settings = NetBirdProfile::parse(&content).map_err(TunnelError::Other)?;
        let binary = binary()?;
        if answers(Path::new(APP_SOCKET)) {
            return Err(TunnelError::Other(
                "the NetBird app's service is running, and only one NetBird can run at a time: \
                 stop it with `sudo netbird service stop` (and `sudo netbird service uninstall` \
                 so it stays stopped after a reboot)"
                    .into(),
            ));
        }
        let socket = socket_path(&profile.id);
        if other_network_running(&socket) {
            return Err(TunnelError::Other(
                "another NetBird network is connected, and only one NetBird can run at a time: \
                 disconnect it first"
                    .into(),
            ));
        }
        let state_dir = Path::new(STATE_ROOT).join(profile.id.digest_key(8));
        create_private_dir(&state_dir)?;
        let own_identity = state_dir.join("default.json");
        if let (Some(identity), false) = (&settings.identity, own_identity.exists()) {
            write_private(&own_identity, &read_app_identity(identity)?)?;
        }
        let _ = std::fs::remove_file(&socket);

        let mut identity = ManagedProcessId::generate(profile.id.clone())
            .map_err(|error| TunnelError::Subprocess(format!("allocate ownership: {error}")))?;
        if let Some(generation) = self.generation {
            identity.generation = generation;
        }
        let mut daemon = command(
            &binary,
            &socket,
            [
                "service",
                "run",
                "--log-file",
                &state_dir.join("netbird.log").to_string_lossy(),
            ],
        );
        daemon
            .env
            .insert("NB_STATE_DIR".into(), state_dir.to_string_lossy().into());
        // Kernel WireGuard sends from a socket with no group, which the kill
        // switch could not tell apart; userspace keeps it all in the daemon.
        daemon
            .env
            .insert("NB_WG_KERNEL_DISABLED".into(), "true".into());
        daemon.firewall_group = Some(crate::control::killswitch::TRANSPORT_GROUP);
        let custody = crate::process::custodian::spawn_custodian(
            identity.clone(),
            daemon,
            vec![socket.clone()],
            None,
        )
        .map_err(|error| TunnelError::Subprocess(format!("netbird custody: {error}")))?;

        let started = self.connect(profile, &settings, &binary, &socket, &state_dir);
        if let Err(error) = started {
            return Err(
                match crate::process::custodian::remote_stop_after_startup(&custody) {
                    Ok(()) => error,
                    Err(stop) => TunnelError::Subprocess(format!(
                        "{error}; stopping the NetBird daemon also failed: {stop}"
                    )),
                },
            );
        }
        Ok(TunnelHandle {
            profile_id: profile.id.clone(),
            display_name: profile.display_name.clone(),
            interface_name: crate::platform::NETBIRD_INTERFACE.into(),
            pid: Some(custody.pid),
            started_at: SystemTime::now(),
            kind: TunnelKindTag::NetBird,
            generation: identity.generation,
            handshake: None,
            probe_receipts: Vec::new(),
            process_ownership: Some(identity),
            teardown_config: None,
            dns_request: crate::control::dns::DnsRequest::default(),
            openvpn_routes: None,
        })
    }

    /// Bring the network up through a running daemon.
    fn connect(
        &self,
        profile: &Profile,
        settings: &NetBirdProfile,
        binary: &Path,
        socket: &Path,
        state_dir: &Path,
    ) -> Result<(), TunnelError> {
        wait_for(socket, self.remaining()?)?;
        // A fresh daemon reports Idle, not NeedsLogin, so the key goes with
        // every connect; NetBird logs a registered peer in by its own key.
        let key_file = settings
            .setup_key
            .as_deref()
            .map(|key| write_key_file(state_dir, key))
            .transpose()?;
        let mut args = vec![
            "up".to_string(),
            "--management-url".into(),
            settings.management_url.clone(),
            "--interface-name".into(),
            crate::platform::NETBIRD_INTERFACE.into(),
            "--wireguard-port".into(),
            WIREGUARD_PORT.to_string(),
        ];
        match &key_file {
            Some(key_file) => {
                args.push("--setup-key-file".into());
                args.push(key_file.to_string_lossy().into());
            }
            // Without a key, a device that must log in prints a link and waits.
            None => args.push("--no-browser".into()),
        }
        let mut up = command(binary, socket, args);
        let timeout = self.remaining()?;
        up.timeout = Some(timeout);
        let (lines, printed) = std::sync::mpsc::channel();
        up.stdout_lines = Some(lines);
        let progress = self
            .execution_context
            .as_ref()
            .and_then(|context| context.progress.as_ref());
        let done = std::sync::atomic::AtomicBool::new(false);
        let outcome = std::thread::scope(|scope| {
            scope.spawn(|| {
                for line in printed {
                    if let (Some(text), Some(progress)) = (
                        login_notice(&line, &profile.display_name, timeout),
                        progress,
                    ) {
                        let _ = progress.send(text);
                    }
                }
            });
            // A disconnect must not wait out a login nobody will finish.
            if let Some(context) = &self.execution_context {
                let done = &done;
                scope.spawn(move || {
                    while !done.load(std::sync::atomic::Ordering::Acquire) {
                        if context.cancellation.is_cancelled() {
                            let mut down = command(binary, socket, ["down"]);
                            down.timeout = Some(Duration::from_secs(10));
                            let _ = crate::process::run(down);
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(200));
                    }
                });
            }
            let outcome = crate::process::run(up);
            done.store(true, std::sync::atomic::Ordering::Release);
            outcome
        });
        if let Some(key_file) = &key_file {
            let _ = std::fs::remove_file(key_file);
        }
        let outcome = outcome.map_err(|error| TunnelError::Subprocess(error.to_string()))?;
        let after = status(binary, socket)?;
        if !outcome.success() || !after.connected() {
            return Err(up_failure(
                &after,
                &String::from_utf8_lossy(&outcome.stderr),
            ));
        }
        Ok(())
    }

    pub fn down(&mut self, handle: &TunnelHandle) -> Result<(), TunnelError> {
        let identity = match handle.process_ownership.clone() {
            Some(identity) => Some(identity),
            None => crate::process::custodian::load_identity(&handle.profile_id)
                .map_err(|error| TunnelError::Subprocess(format!("NetBird ownership: {error}")))?,
        };
        let Some(identity) = identity else {
            return Ok(());
        };
        // Stopping the daemon also takes the network down; `down` first
        // makes that quick enough for the custodian's grace period.
        if let Ok(binary) = binary() {
            let mut down = command(&binary, &socket_path(&handle.profile_id), ["down"]);
            down.timeout = Some(Duration::from_secs(10));
            let _ = crate::process::run(down);
        }
        crate::process::custodian::remote_stop(&identity).map_err(|error| {
            TunnelError::Subprocess(format!("NetBird daemon did not stop: {error}"))
        })
    }
}

/// A running network as the scanner reports it. Without its status (a reader
/// that is not root cannot ask the daemon) the session still shows, unfilled.
#[must_use]
pub fn observe(profile_id: &ProfileId) -> Option<crate::control::scanner::ActiveSession> {
    let custody = running_owner(profile_id)?;
    let socket = socket_path(profile_id);
    let binary = binary().ok();
    let mut session = binary
        .as_ref()
        .and_then(|binary| status(binary, &socket).ok())
        .map(|status| status.session())
        .unwrap_or_default();
    if let Some(binary) = &binary {
        let mut list = command(binary, &socket, ["networks", "list"]);
        list.timeout = Some(Duration::from_secs(10));
        if let Some(listed) = crate::process::run(list)
            .ok()
            .filter(crate::process::CommandOutcome::success)
        {
            session.details.networks = parse_networks(&listed.stdout_lossy());
        }
    }
    session.details.interface = crate::platform::NETBIRD_INTERFACE.into();
    session.details.interface_authoritative = true;
    session.details.pid = Some(custody.pid);
    Some(session)
}

/// `netbird networks list` has no JSON: blocks of `- ID:`, then `Network:` or
/// `Domains:`, then `Status:`.
fn parse_networks(text: &str) -> Vec<crate::tunnel::RoutedNetwork> {
    let mut networks: Vec<crate::tunnel::RoutedNetwork> = Vec::new();
    for line in text.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix("- ID: ") {
            networks.push(crate::tunnel::RoutedNetwork {
                name: name.to_string(),
                ..Default::default()
            });
        } else if let Some(network) = networks.last_mut() {
            if let Some(range) = line
                .strip_prefix("Network: ")
                .or_else(|| line.strip_prefix("Domains: "))
            {
                network.range = range.to_string();
            } else if let Some(status) = line.strip_prefix("Status: ") {
                network.selected = status == "Selected";
            }
        }
    }
    networks
}

/// The custodian's receipt for a daemon Vortix started earlier, if it is still
/// running.
#[must_use]
pub fn running_owner(profile_id: &ProfileId) -> Option<crate::process::CustodianHandshake> {
    let custody = crate::process::custodian::load_handshake(profile_id).ok()??;
    crate::process::custodian::remote_status(&custody.identity)
        .unwrap_or(false)
        .then_some(custody)
}

/// One socket per profile, outside `/var/run/netbird/`, where the `netbird`
/// CLI looks for a daemon on its own.
fn socket_path(profile_id: &ProfileId) -> PathBuf {
    PathBuf::from(format!(
        "/var/run/vortix-netbird-{}.sock",
        profile_id.digest_key(8)
    ))
}

/// A daemon listens on this socket; a file left by a crash does not count.
fn answers(socket: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(socket).is_ok()
}

/// Another network's daemon that Vortix started is running.
fn other_network_running(own: &Path) -> bool {
    std::fs::read_dir("/var/run").is_ok_and(|entries| {
        entries.flatten().map(|entry| entry.path()).any(|path| {
            path != own
                && path
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .is_some_and(|name| name.starts_with("vortix-netbird-"))
                && answers(&path)
        })
    })
}

fn binary() -> Result<PathBuf, TunnelError> {
    crate::platform::find_binary_path("netbird")
        .ok_or_else(|| {
            TunnelError::Subprocess(
                "netbird was not found on PATH (install it: https://docs.netbird.io/get-started/install)"
                    .into(),
            )
        })?
        .canonicalize()
        .map_err(TunnelError::Io)
}

fn command<I, S>(binary: &Path, socket: &Path, args: I) -> CommandSpec
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter().map(Into::into).collect::<Vec<String>>();
    args.push("--daemon-addr".into());
    args.push(format!("unix://{}", socket.display()));
    let mut spec =
        CommandSpec::oneshot(binary.to_string_lossy(), args).privilege(PrivilegeReq::Root);
    spec.env_clear = true;
    spec.env.insert("PATH".into(), PATH.into());
    spec
}

fn status(binary: &Path, socket: &Path) -> Result<Status, TunnelError> {
    let mut spec = command(binary, socket, ["status", "--json"]);
    spec.timeout = Some(Duration::from_secs(10));
    let outcome =
        crate::process::run(spec).map_err(|error| TunnelError::Subprocess(error.to_string()))?;
    if !outcome.success() {
        return Err(TunnelError::Subprocess(format!(
            "netbird status: {}",
            String::from_utf8_lossy(&outcome.stderr).trim()
        )));
    }
    Status::parse(&outcome.stdout)
}

/// What to tell the user when `netbird up` prints its login link.
fn login_notice(line: &str, name: &str, timeout: Duration) -> Option<String> {
    let line = line.trim();
    line.starts_with("https://").then(|| {
        format!(
            "Log in to '{name}' within {}s: open {line}",
            timeout.as_secs()
        )
    })
}

fn up_failure(status: &Status, stderr: &str) -> TunnelError {
    if status.needs_login() {
        return TunnelError::AuthFailed(format!(
            "NetBird refused this device ({})",
            status.daemon_status
        ));
    }
    if !status.management.error.is_empty() {
        return TunnelError::Subprocess(format!(
            "NetBird management server: {}",
            status.management.error
        ));
    }
    let detail = stderr.trim();
    TunnelError::Subprocess(if detail.is_empty() {
        format!("NetBird did not connect ({})", status.daemon_status)
    } else {
        format!("netbird up: {detail}")
    })
}

fn wait_for(socket: &Path, timeout: Duration) -> Result<(), TunnelError> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if socket.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(TunnelError::Timeout(timeout))
}

fn create_private_dir(dir: &Path) -> Result<(), TunnelError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// The profile file is user-editable but read as root, so only a root-owned
/// `.json` file inside the `NetBird` app's state directory is accepted.
fn read_app_identity(path: &Path) -> Result<Vec<u8>, TunnelError> {
    use std::os::unix::fs::MetadataExt as _;
    let refuse = |why: &str| {
        TunnelError::Other(format!(
            "cannot use {} as the NetBird app's identity: {why}",
            path.display()
        ))
    };
    let real = path
        .canonicalize()
        .map_err(|error| refuse(&error.to_string()))?;
    let root = Path::new(APP_STATE_DIR)
        .canonicalize()
        .map_err(|error| refuse(&error.to_string()))?;
    let meta = std::fs::metadata(&real).map_err(|error| refuse(&error.to_string()))?;
    if !real.starts_with(&root)
        || real.extension().and_then(std::ffi::OsStr::to_str) != Some("json")
        || !meta.is_file()
        || meta.uid() != 0
    {
        return Err(refuse(&format!(
            "it must be a root-owned .json file in {APP_STATE_DIR}"
        )));
    }
    std::fs::read(&real).map_err(|error| refuse(&error.to_string()))
}

/// Root-only, and never over an existing file.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), TunnelError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(bytes)?;
    Ok(())
}

fn write_key_file(state_dir: &Path, key: &str) -> Result<PathBuf, TunnelError> {
    let path = state_dir.join("setup-key");
    let _ = std::fs::remove_file(&path);
    write_private(&path, key.trim().as_bytes())?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONNECTED: &str = r#"{
        "peers": {"total": 2, "connected": 1, "details": [
            {"fqdn": "db.netbird.cloud", "netbirdIp": "100.90.1.2", "publicKey": "a=",
             "status": "Connected", "connectionType": "P2P", "transferReceived": 10,
             "transferSent": 20, "latency": 3000000, "networks": ["10.0.0.0/24"]},
            {"fqdn": "", "netbirdIp": "100.90.1.3", "publicKey": "b=", "status": "Idle"}
        ]},
        "daemonStatus": "Connected", "netbirdIp": "100.90.1.1/16",
        "management": {"url": "https://api.netbird.io:443", "connected": true, "error": ""},
        "unknownFutureField": {"x": 1}
    }"#;

    #[test]
    fn status_reads_a_connected_daemon() {
        let status = Status::parse(CONNECTED.as_bytes()).unwrap();
        assert!(status.connected());
        assert!(!status.needs_login());
    }

    /// The scanner's session: one short name per peer, direct or relayed, and
    /// the management server as the tunnel's server.
    #[test]
    fn status_becomes_the_scanned_session() {
        let session = Status::parse(CONNECTED.as_bytes()).unwrap().session();
        let details = &session.details;
        assert_eq!(details.internal_ip, "100.90.1.1/16");
        assert_eq!(details.endpoint, "api.netbird.io:443");
        assert_eq!(
            (details.transfer_rx.as_str(), details.transfer_tx.as_str()),
            ("10", "20")
        );
        assert_eq!(details.peers[0].name, "db");
        assert!(details.peers[0].connected && !details.peers[0].relayed);
        assert_eq!(details.peers[0].latency, Some(Duration::from_millis(3)));
        assert_eq!(details.peers[1].name, "100.90.1.3");
        assert!(!details.peers[1].connected);
        assert_eq!(
            crate::ui::helpers::peers_summary(&details.peers),
            "1/2 connected"
        );
    }

    #[test]
    fn networks_are_read_from_the_plain_list() {
        let text = "Available Networks:\n\n  - ID: office\n    Network: 10.20.0.0/16\n    Status: Selected\n\n  - ID: exit\n    Network: 0.0.0.0/0\n    Status: Not Selected\n\n  - ID: wiki\n    Domains: wiki.corp.example, git.corp.example\n    Status: Selected\n    Resolved IPs:\n      [wiki.corp.example]: 10.1.1.1\n";
        let networks = parse_networks(text);
        assert_eq!(networks.len(), 3);
        assert_eq!(
            (networks[0].name.as_str(), networks[0].range.as_str()),
            ("office", "10.20.0.0/16")
        );
        assert!(networks[0].selected && !networks[0].is_exit_node());
        assert!(!networks[1].selected && networks[1].is_exit_node());
        assert_eq!(networks[2].range, "wiki.corp.example, git.corp.example");
        assert!(parse_networks("No networks available.").is_empty());
    }

    #[test]
    fn status_names_every_login_state() {
        for state in ["NeedsLogin", "LoginFailed", "SessionExpired"] {
            let json = format!(r#"{{"daemonStatus": "{state}"}}"#);
            let status = Status::parse(json.as_bytes()).unwrap();
            assert!(status.needs_login() && !status.connected(), "{state}");
            assert!(matches!(
                up_failure(&status, ""),
                TunnelError::AuthFailed(_)
            ));
        }
        let idle =
            Status::parse(br#"{"daemonStatus": "Idle", "peers": {"details": null}}"#).unwrap();
        assert!(idle.peers.details.is_empty());
        assert!(!idle.needs_login());
        assert!(Status::parse(b"not json").is_err());
    }

    #[test]
    fn only_the_login_link_becomes_a_notice() {
        let notice = |line| login_notice(line, "work", Duration::from_secs(60));
        assert_eq!(
            notice("https://idp.example/device?code=AB12 and enter the code AB12 to authenticate."),
            Some(
                "Log in to 'work' within 60s: open https://idp.example/device?code=AB12 \
                 and enter the code AB12 to authenticate."
                    .into()
            )
        );
        for other in ["Use this URL to log in:", "", "Connected", "http://plain"] {
            assert_eq!(notice(other), None, "{other}");
        }
    }

    #[test]
    fn up_failure_prefers_the_management_error() {
        let status = Status::parse(
            br#"{"daemonStatus": "Connecting", "management": {"error": "dial tcp: refused"}}"#,
        )
        .unwrap();
        assert!(up_failure(&status, "ignored")
            .to_string()
            .contains("dial tcp: refused"));
        let status = Status::parse(br#"{"daemonStatus": "Connecting"}"#).unwrap();
        assert!(up_failure(&status, "context deadline exceeded\n")
            .to_string()
            .ends_with("netbird up: context deadline exceeded"));
    }

    const APP_CONFIG: &str = r#"{"PrivateKey": "secret", "ManagementURL":
        {"Scheme": "https", "Host": "nb.corp.example:443", "Path": ""}}"#;

    #[test]
    fn the_app_default_profile_becomes_a_netbird_profile() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("default.json"), APP_CONFIG).unwrap();
        assert!(is_app_state_dir(dir.path()));
        let profile = NetBirdProfile::parse(&profile_from_app(dir.path()).unwrap()).unwrap();
        assert_eq!(profile.management_url, "https://nb.corp.example:443");
        assert_eq!(profile.identity, Some(dir.path().join("default.json")));
        assert_eq!(profile.setup_key, None);
    }

    #[test]
    fn the_app_active_user_profile_is_the_one_moved() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("default.json"), "{}").unwrap();
        std::fs::create_dir(dir.path().join("alice")).unwrap();
        std::fs::write(dir.path().join("alice/work.json"), APP_CONFIG).unwrap();
        let active = |json: &str| {
            std::fs::write(dir.path().join("active_profile.json"), json).unwrap();
            profile_from_app(dir.path())
        };
        let profile =
            NetBirdProfile::parse(&active(r#"{"name": "work", "username": "alice"}"#).unwrap())
                .unwrap();
        assert_eq!(profile.identity, Some(dir.path().join("alice/work.json")));
        assert!(active(r#"{"name": "../work", "username": "alice"}"#).is_err());
        assert!(active(r#"{"name": "default", "username": ""}"#)
            .unwrap_err()
            .contains("is not a NetBird profile"));
        assert!(!is_app_state_dir(&dir.path().join("alice")));
    }

    /// The profile is user-editable but read as root: an identity outside the
    /// app's state directory is refused, never copied.
    #[test]
    fn an_identity_outside_the_app_state_dir_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("default.json");
        std::fs::write(&elsewhere, APP_CONFIG).unwrap();
        assert!(read_app_identity(&elsewhere).is_err());
        assert!(read_app_identity(Path::new("/etc/passwd")).is_err());
    }

    /// toml quotes the offending line in its message; the setup key must not
    /// reach a log or the CLI that way.
    #[test]
    fn a_bad_profile_line_is_not_quoted_back() {
        for text in [
            "management_url = \"https://a\"\nsetupkey = \"SECRET-KEY-123\"",
            "management_url = \"https://a\"\nsetup_key = SECRET-KEY-123",
        ] {
            let error = NetBirdProfile::parse(text).unwrap_err();
            assert!(!error.contains("SECRET"), "{error}");
            assert!(error.contains("line 2"), "{error}");
        }
    }

    #[test]
    fn profile_parses_management_host_and_port() {
        let host = |url: &str| {
            NetBirdProfile::parse(&format!("management_url = \"{url}\""))
                .and_then(|profile| profile.management_host())
        };
        assert_eq!(
            host("https://api.netbird.io").unwrap(),
            ("api.netbird.io".into(), 443)
        );
        assert_eq!(
            host("https://nb.corp:33073/x").unwrap(),
            ("nb.corp".into(), 33073)
        );
        assert_eq!(host("http://10.0.0.5").unwrap(), ("10.0.0.5".into(), 80));
        assert_eq!(
            host("https://[fd00::1]:8443").unwrap(),
            ("fd00::1".into(), 8443)
        );
        assert!(host("ftp://x").is_err());
        assert!(host("https://").is_err());
        assert!(host("https://nb.corp:port").is_err());
        assert!(NetBirdProfile::parse("management_url = \"https://a\"\nsetupkey = \"x\"").is_err());
        let keyed =
            NetBirdProfile::parse("management_url = \"https://a\"\nsetup_key = \"K\"").unwrap();
        assert_eq!(keyed.setup_key.as_deref(), Some("K"));
    }
}
