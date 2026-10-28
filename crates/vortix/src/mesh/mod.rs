//! Mesh networks (`NetBird`, and the next ones like it), run by Vortix through
//! the vendor's own client.
//!
//! Everything here is the kind: each profile gets its own daemon under a
//! Vortix custodian, with its identity in a private state directory and a
//! private control socket, so it never meets the vendor app's own service; the
//! daemon runs under the kill switch's transport group and installs its own
//! routes, DNS and firewall tables. A vendor is a [`MeshDriver`]: its commands,
//! output formats, paths and labels, in a file of its own.

mod netbird;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::process::{CommandSpec, ManagedProcessId, PrivilegeReq};
use crate::profile::{Profile, ProfileId};
use crate::tunnel::{
    MeshPeer, RoutedNetwork, TunnelError, TunnelExecutionContext, TunnelHandle, TunnelKindTag,
};

/// Root-only, like a vendor's own state directory: it holds each network's identity.
const STATE_ROOT: &str = "/var/lib/vortix";
const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// A mesh network vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum MeshDriver {
    NetBird,
}

impl MeshDriver {
    pub const ALL: [Self; 1] = [Self::NetBird];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NetBird => "NetBird",
        }
    }

    /// Two letters for the sidebar and header.
    #[must_use]
    pub const fn short(self) -> &'static str {
        match self {
            Self::NetBird => "NB",
        }
    }

    /// Its CLI binary, profile file extension, hook value and the stem of its
    /// state and socket names.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::NetBird => "netbird",
        }
    }

    /// Every driver's profile extension, for messages: `.netbird`.
    #[must_use]
    pub fn extensions() -> String {
        Self::ALL
            .iter()
            .map(|driver| format!(".{}", driver.slug()))
            .collect::<Vec<_>>()
            .join(", ")
    }

    #[must_use]
    pub fn from_extension(extension: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|driver| driver.slug() == extension)
    }

    /// Where its own app keeps its identity: importing this folder moves the
    /// app's network to Vortix.
    #[must_use]
    pub const fn app_state_dir(self) -> &'static str {
        self.app().state_dir
    }

    /// Every driver's name, for counts: `NetBird`.
    #[must_use]
    pub fn names() -> String {
        Self::ALL.map(Self::name).join("/")
    }

    /// The interface its daemon is told to create.
    #[must_use]
    pub const fn interface(self) -> &'static str {
        match self {
            Self::NetBird => crate::platform::NETBIRD_INTERFACE,
        }
    }

    const fn app(self) -> AppInstall {
        match self {
            Self::NetBird => netbird::APP,
        }
    }

    fn daemon(self, state_dir: &Path) -> Launch {
        match self {
            Self::NetBird => netbird::daemon(state_dir),
        }
    }

    fn control(self, socket: &Path) -> Vec<String> {
        match self {
            Self::NetBird => netbird::control(socket),
        }
    }

    fn up(self, profile: &MeshProfile, key_file: Option<&Path>) -> Vec<String> {
        match self {
            Self::NetBird => netbird::up(profile, key_file, self.interface()),
        }
    }

    const fn down(self) -> &'static [&'static str] {
        match self {
            Self::NetBird => netbird::DOWN,
        }
    }

    const fn status(self) -> &'static [&'static str] {
        match self {
            Self::NetBird => netbird::STATUS,
        }
    }

    const fn networks(self) -> &'static [&'static str] {
        match self {
            Self::NetBird => netbird::NETWORKS,
        }
    }

    fn parse_status(self, json: &[u8]) -> Result<MeshStatus, String> {
        match self {
            Self::NetBird => netbird::parse_status(json),
        }
    }

    fn parse_networks(self, text: &str) -> Vec<RoutedNetwork> {
        match self {
            Self::NetBird => netbird::parse_networks(text),
        }
    }

    fn profile_from_app(self, dir: &Path) -> Result<MeshProfile, String> {
        match self {
            Self::NetBird => netbird::profile_from_app(dir),
        }
    }

    fn state_dir(self, profile_id: &ProfileId) -> PathBuf {
        Path::new(STATE_ROOT)
            .join(self.slug())
            .join(profile_id.digest_key(8))
    }

    /// One socket per profile, outside wherever the vendor's CLI looks for a
    /// daemon on its own.
    fn socket(self, profile_id: &ProfileId) -> PathBuf {
        PathBuf::from(format!(
            "/var/run/vortix-{}-{}.sock",
            self.slug(),
            profile_id.digest_key(8)
        ))
    }
}

impl std::fmt::Display for MeshDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// How the vendor's own app is installed, for moving from it.
struct AppInstall {
    state_dir: &'static str,
    /// Present and answering while its service runs.
    socket: &'static str,
    /// The file in its state directory (and in Vortix's) that holds the identity.
    identity: &'static str,
    /// Stop its service, then keep it stopped after a reboot.
    stop: [&'static str; 2],
}

/// The daemon's program, arguments and environment.
struct Launch {
    program: &'static str,
    args: Vec<String>,
    env: Vec<(&'static str, String)>,
}

/// What a mesh profile file holds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeshProfile {
    /// The network's control server (`NetBird`'s management URL).
    pub server_url: String,
    /// Registers this device on first connect; unused once it has an identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_key: Option<String>,
    /// The vendor app's identity file, copied in on first connect so this
    /// device stays the same peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<PathBuf>,
}

impl MeshProfile {
    pub fn parse(content: &str) -> Result<Self, String> {
        let profile: Self = toml::from_str(content).map_err(|error: toml::de::Error| {
            // The error's own text quotes the line, which may hold the key.
            let line = error
                .span()
                .map_or(0, |span| content[..span.start].matches('\n').count() + 1);
            format!("Invalid profile (line {line}): {}", error.message())
        })?;
        profile.server()?;
        Ok(profile)
    }

    /// Host and port of the control server.
    pub fn server(&self) -> Result<(String, u16), String> {
        let url = &self.server_url;
        let (rest, default_port) = url
            .strip_prefix("https://")
            .map(|rest| (rest, 443))
            .or_else(|| url.strip_prefix("http://").map(|rest| (rest, 80)))
            .ok_or("server_url must start with https:// or http://")?;
        let authority = rest.split('/').next().unwrap_or_default();
        let (host, port) = match authority.strip_prefix('[') {
            Some(v6) => v6.split_once(']').unwrap_or((v6, "")),
            None => authority.split_once(':').unwrap_or((authority, "")),
        };
        let port = match port.trim_start_matches(':') {
            "" => default_port,
            port => port
                .parse()
                .map_err(|_| format!("server_url has a bad port: {port}"))?,
        };
        if host.is_empty() {
            return Err("server_url has no host".into());
        }
        Ok((host.to_string(), port))
    }
}

/// The vendor app's state directory, if `dir` is one: its active network
/// becomes a profile that takes over that identity.
#[must_use]
pub fn app_driver(dir: &Path) -> Option<MeshDriver> {
    MeshDriver::ALL
        .into_iter()
        .find(|driver| dir.join(driver.app().identity).is_file())
}

/// The profile file that moves the vendor app's active network here.
pub fn profile_from_app(driver: MeshDriver, dir: &Path) -> Result<String, String> {
    let profile = driver.profile_from_app(dir)?;
    profile.server()?;
    toml::to_string(&profile).map_err(|error| error.to_string())
}

/// A daemon's state, in the terms every mesh network shares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MeshStatus {
    pub state: MeshState,
    /// This device's address in the network.
    pub address: String,
    /// The control server, `host:port`.
    pub server: String,
    /// Why the control server cannot be reached, when it cannot.
    pub error: String,
    pub rx: u64,
    pub tx: u64,
    pub peers: Vec<MeshPeer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshState {
    Connected,
    /// No identity, or the network refused the one it has; the vendor's word.
    NeedsLogin(String),
    Other(String),
}

impl Default for MeshState {
    fn default() -> Self {
        Self::Other(String::new())
    }
}

impl MeshStatus {
    /// The session the scanner reports for a running network.
    fn session(self) -> crate::control::scanner::ActiveSession {
        crate::control::scanner::ActiveSession {
            details: crate::tunnel::DetailedConnectionInfo {
                internal_ip: self.address,
                endpoint: self.server,
                transfer_rx: self.rx.to_string(),
                transfer_tx: self.tx.to_string(),
                peers: self.peers,
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

/// The mesh transport for one connect or disconnect.
#[derive(Debug, Clone)]
pub struct MeshTunnel {
    driver: MeshDriver,
    connect_timeout: Duration,
    generation: Option<u64>,
    execution_context: Option<TunnelExecutionContext>,
}

impl MeshTunnel {
    #[must_use]
    pub fn new(driver: MeshDriver, connect_timeout_secs: u64) -> Self {
        Self {
            driver,
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
        let driver = self.driver;
        let name = driver.name();
        let content = std::fs::read_to_string(&profile.config_path)?;
        let settings = MeshProfile::parse(&content).map_err(TunnelError::Other)?;
        let cli = binary(driver.slug())?;
        let app = driver.app();
        if answers(Path::new(app.socket)) {
            return Err(TunnelError::Other(format!(
                "the {name} app's service is running, and only one {name} can run at a time: \
                 stop it with `{}` (and `{}` so it stays stopped after a reboot)",
                app.stop[0], app.stop[1]
            )));
        }
        let socket = driver.socket(&profile.id);
        if other_network_running(driver, &socket) {
            return Err(TunnelError::Other(format!(
                "another {name} network is connected, and only one {name} can run at a time: \
                 disconnect it first"
            )));
        }
        let state_dir = driver.state_dir(&profile.id);
        create_private_dir(&state_dir)?;
        let own_identity = state_dir.join(app.identity);
        if let (Some(identity), false) = (&settings.identity, own_identity.exists()) {
            write_private(&own_identity, &read_app_identity(&app, identity)?)?;
        }
        let _ = std::fs::remove_file(&socket);

        let mut identity = ManagedProcessId::generate(profile.id.clone())
            .map_err(|error| TunnelError::Subprocess(format!("allocate ownership: {error}")))?;
        if let Some(generation) = self.generation {
            identity.generation = generation;
        }
        let launch = driver.daemon(&state_dir);
        let mut daemon = command(
            &binary(launch.program)?,
            driver.control(&socket),
            launch.args,
        );
        daemon.env.extend(
            launch
                .env
                .into_iter()
                .map(|(key, value)| (key.into(), value)),
        );
        daemon.firewall_group = Some(crate::control::killswitch::TRANSPORT_GROUP);
        let custody = crate::process::custodian::spawn_custodian(
            identity.clone(),
            daemon,
            vec![socket.clone()],
            None,
        )
        .map_err(|error| TunnelError::Subprocess(format!("{name} custody: {error}")))?;

        let started = self.connect(profile, &settings, &cli, &socket, &state_dir);
        if let Err(error) = started {
            return Err(
                match crate::process::custodian::remote_stop_after_startup(&custody) {
                    Ok(()) => error,
                    Err(stop) => TunnelError::Subprocess(format!(
                        "{error}; stopping the {name} daemon also failed: {stop}"
                    )),
                },
            );
        }
        Ok(TunnelHandle {
            profile_id: profile.id.clone(),
            display_name: profile.display_name.clone(),
            interface_name: driver.interface().into(),
            pid: Some(custody.pid),
            started_at: SystemTime::now(),
            kind: TunnelKindTag::Mesh,
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
        settings: &MeshProfile,
        cli: &Path,
        socket: &Path,
        state_dir: &Path,
    ) -> Result<(), TunnelError> {
        let driver = self.driver;
        wait_for(socket, self.remaining()?)?;
        // A fresh daemon may not report that it needs a login, so the key goes
        // with every connect; a registered device logs in by its own key.
        let key_file = settings
            .auth_key
            .as_deref()
            .map(|key| write_key_file(state_dir, key))
            .transpose()?;
        let mut up = command(
            cli,
            driver.control(socket),
            driver.up(settings, key_file.as_deref()),
        );
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
                            let _ = run(driver, cli, socket, driver.down());
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
        let after = status(driver, cli, socket)?;
        if !outcome.success() || after.state != MeshState::Connected {
            return Err(up_failure(
                driver,
                &after,
                &String::from_utf8_lossy(&outcome.stderr),
            ));
        }
        Ok(())
    }

    pub fn down(&mut self, handle: &TunnelHandle) -> Result<(), TunnelError> {
        let name = self.driver.name();
        let identity = match handle.process_ownership.clone() {
            Some(identity) => Some(identity),
            None => crate::process::custodian::load_identity(&handle.profile_id)
                .map_err(|error| TunnelError::Subprocess(format!("{name} ownership: {error}")))?,
        };
        let Some(identity) = identity else {
            return Ok(());
        };
        // Stopping the daemon also takes the network down; `down` first
        // makes that quick enough for the custodian's grace period.
        if let Ok(cli) = binary(self.driver.slug()) {
            let socket = self.driver.socket(&handle.profile_id);
            let _ = run(self.driver, &cli, &socket, self.driver.down());
        }
        crate::process::custodian::remote_stop(&identity).map_err(|error| {
            TunnelError::Subprocess(format!("{name} daemon did not stop: {error}"))
        })
    }
}

/// A running network as the scanner reports it. Without its status (a reader
/// that is not root cannot ask the daemon) the session still shows, unfilled.
#[must_use]
pub fn observe(
    driver: MeshDriver,
    profile_id: &ProfileId,
) -> Option<crate::control::scanner::ActiveSession> {
    let custody = running_owner(profile_id)?;
    let socket = driver.socket(profile_id);
    let cli = binary(driver.slug()).ok();
    let mut session = cli
        .as_ref()
        .and_then(|cli| status(driver, cli, &socket).ok())
        .map(MeshStatus::session)
        .unwrap_or_default();
    if let Some(listed) = cli
        .as_ref()
        .and_then(|cli| run(driver, cli, &socket, driver.networks()).ok())
        .filter(crate::process::CommandOutcome::success)
    {
        session.details.networks = driver.parse_networks(&listed.stdout_lossy());
    }
    session.details.interface = driver.interface().into();
    session.details.interface_authoritative = true;
    session.details.pid = Some(custody.pid);
    Some(session)
}

/// Remove a deleted profile's state: its identity must not outlive it.
pub fn forget(driver: MeshDriver, profile_id: &ProfileId) -> std::io::Result<()> {
    match std::fs::remove_dir_all(driver.state_dir(profile_id)) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
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

/// A daemon listens on this socket; a file left by a crash does not count.
fn answers(socket: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(socket).is_ok()
}

/// Another network of this vendor that Vortix started is running: its daemons
/// share one interface and port.
fn other_network_running(driver: MeshDriver, own: &Path) -> bool {
    let prefix = format!("vortix-{}-", driver.slug());
    std::fs::read_dir("/var/run").is_ok_and(|entries| {
        entries.flatten().map(|entry| entry.path()).any(|path| {
            path != own
                && path
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .is_some_and(|name| name.starts_with(&prefix))
                && answers(&path)
        })
    })
}

fn binary(name: &str) -> Result<PathBuf, TunnelError> {
    crate::platform::find_binary_path(name)
        .ok_or_else(|| {
            TunnelError::Subprocess(format!(
                "{name} was not found on PATH (install it: {})",
                crate::platform::install_hint(name)
            ))
        })?
        .canonicalize()
        .map_err(TunnelError::Io)
}

fn command(program: &Path, control: Vec<String>, args: Vec<String>) -> CommandSpec {
    let mut spec = CommandSpec::oneshot(
        program.to_string_lossy(),
        args.into_iter().chain(control).collect(),
    )
    .privilege(PrivilegeReq::Root);
    spec.env_clear = true;
    spec.env.insert("PATH".into(), PATH.into());
    spec
}

/// One short command against a running daemon.
fn run(
    driver: MeshDriver,
    cli: &Path,
    socket: &Path,
    args: &[&str],
) -> Result<crate::process::CommandOutcome, TunnelError> {
    let mut spec = command(
        cli,
        driver.control(socket),
        args.iter().map(ToString::to_string).collect(),
    );
    spec.timeout = Some(Duration::from_secs(10));
    crate::process::run(spec).map_err(|error| TunnelError::Subprocess(error.to_string()))
}

fn status(driver: MeshDriver, cli: &Path, socket: &Path) -> Result<MeshStatus, TunnelError> {
    let outcome = run(driver, cli, socket, driver.status())?;
    if !outcome.success() {
        return Err(TunnelError::Subprocess(format!(
            "{} status: {}",
            driver.slug(),
            String::from_utf8_lossy(&outcome.stderr).trim()
        )));
    }
    driver
        .parse_status(&outcome.stdout)
        .map_err(|error| TunnelError::MalformedStatus(format!("{} status: {error}", driver.slug())))
}

/// What to tell the user when the client prints its login link.
fn login_notice(line: &str, name: &str, timeout: Duration) -> Option<String> {
    let line = line.trim();
    line.starts_with("https://").then(|| {
        format!(
            "Log in to '{name}' within {}s: open {line}",
            timeout.as_secs()
        )
    })
}

fn up_failure(driver: MeshDriver, status: &MeshStatus, stderr: &str) -> TunnelError {
    let name = driver.name();
    match &status.state {
        MeshState::NeedsLogin(why) => {
            return TunnelError::AuthFailed(format!("{name} refused this device ({why})"));
        }
        _ if !status.error.is_empty() => {
            return TunnelError::Subprocess(format!("{name} server: {}", status.error));
        }
        _ => {}
    }
    let detail = stderr.trim();
    TunnelError::Subprocess(if detail.is_empty() {
        format!("{name} did not connect ({:?})", status.state)
    } else {
        format!("{} up: {detail}", driver.slug())
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
/// `.json` file inside the vendor app's state directory is accepted.
fn read_app_identity(app: &AppInstall, path: &Path) -> Result<Vec<u8>, TunnelError> {
    use std::os::unix::fs::MetadataExt as _;
    let refuse = |why: &str| {
        TunnelError::Other(format!(
            "cannot use {} as the app's identity: {why}",
            path.display()
        ))
    };
    let real = path
        .canonicalize()
        .map_err(|error| refuse(&error.to_string()))?;
    let root = Path::new(app.state_dir)
        .canonicalize()
        .map_err(|error| refuse(&error.to_string()))?;
    let meta = std::fs::metadata(&real).map_err(|error| refuse(&error.to_string()))?;
    if !real.starts_with(&root)
        || real.extension().and_then(std::ffi::OsStr::to_str) != Some("json")
        || !meta.is_file()
        || meta.uid() != 0
    {
        return Err(refuse(&format!(
            "it must be a root-owned .json file in {}",
            app.state_dir
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
    let path = state_dir.join("auth-key");
    let _ = std::fs::remove_file(&path);
    write_private(&path, key.trim().as_bytes())?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_driver_is_found_by_its_extension_only() {
        for driver in MeshDriver::ALL {
            assert_eq!(MeshDriver::from_extension(driver.slug()), Some(driver));
        }
        assert_eq!(MeshDriver::from_extension("conf"), None);
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
    fn up_failure_names_the_refusal_then_the_server_then_the_client() {
        let failure = |state, error: &str, stderr| {
            up_failure(
                MeshDriver::NetBird,
                &MeshStatus {
                    state,
                    error: error.into(),
                    ..MeshStatus::default()
                },
                stderr,
            )
        };
        assert!(matches!(
            failure(MeshState::NeedsLogin("SessionExpired".into()), "", ""),
            TunnelError::AuthFailed(_)
        ));
        assert!(
            failure(MeshState::default(), "dial tcp: refused", "ignored")
                .to_string()
                .contains("dial tcp: refused")
        );
        assert!(
            failure(MeshState::default(), "", "context deadline exceeded\n")
                .to_string()
                .ends_with("netbird up: context deadline exceeded")
        );
    }

    /// The moved profile points at the app's identity, so the device stays the
    /// same peer, and parses back as a profile.
    #[test]
    fn the_app_state_dir_becomes_a_profile() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(app_driver(dir.path()), None);
        std::fs::write(
            dir.path().join("default.json"),
            r#"{"ManagementURL": {"Scheme": "https", "Host": "nb.corp.example:443"}}"#,
        )
        .unwrap();
        assert_eq!(app_driver(dir.path()), Some(MeshDriver::NetBird));
        let profile =
            MeshProfile::parse(&profile_from_app(MeshDriver::NetBird, dir.path()).unwrap())
                .unwrap();
        assert_eq!(profile.server_url, "https://nb.corp.example:443");
        assert_eq!(profile.identity, Some(dir.path().join("default.json")));
    }

    /// The profile is user-editable but read as root: an identity outside the
    /// app's state directory is refused, never copied.
    #[test]
    fn an_identity_outside_the_app_state_dir_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("default.json");
        std::fs::write(&elsewhere, "{}").unwrap();
        let app = MeshDriver::NetBird.app();
        assert!(read_app_identity(&app, &elsewhere).is_err());
        assert!(read_app_identity(&app, Path::new("/etc/passwd")).is_err());
    }

    /// toml quotes the offending line in its message; the key must not reach
    /// a log or the CLI that way.
    #[test]
    fn a_bad_profile_line_is_not_quoted_back() {
        for text in [
            "server_url = \"https://a\"\nauthkey = \"SECRET-KEY-123\"",
            "server_url = \"https://a\"\nauth_key = SECRET-KEY-123",
        ] {
            let error = MeshProfile::parse(text).unwrap_err();
            assert!(!error.contains("SECRET"), "{error}");
            assert!(error.contains("line 2"), "{error}");
        }
    }

    #[test]
    fn profile_parses_server_host_and_port() {
        let host = |url: &str| {
            MeshProfile::parse(&format!("server_url = \"{url}\"")).and_then(|p| p.server())
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
        let keyed = MeshProfile::parse("server_url = \"https://a\"\nauth_key = \"K\"").unwrap();
        assert_eq!(keyed.auth_key.as_deref(), Some("K"));
    }
}
