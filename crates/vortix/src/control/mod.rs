//! The connection engine: one owner thread, one tunnel list, one planner.
//!
//! Callers send [`Command`]s and read [`Snapshot`]s. The engine thread owns
//! the tunnel list ([`state`]), starts and stops protocol processes
//! ([`tunnels`]), and after every change moves the host to
//! [`plan::plan`]'s answer through [`net`].

pub mod dns;
pub mod dns_policy;
mod engine;
pub mod killswitch;
pub mod net;
pub mod plan;
pub mod profiles;
pub mod scanner;
pub mod state;
pub mod tunnels;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use crate::app::registry::{classify_route_conflict, Conflict};
use crate::cidr::Cidr;
use crate::config::openvpn_credentials::{
    CredentialClearOutcome, FsOpenVpnCredentialStore, RememberedOpenVpnCredentials,
};
use crate::config::profiles::VpnProfile;
use crate::control::killswitch::{KillSwitchMode, KillSwitchState};
use crate::profile::ProfileId;
use crate::tunnel::DetailedConnectionInfo;

pub use state::Phase;

#[derive(Debug, Clone)]
pub enum Command {
    /// Bring a profile up next to whatever is running.
    Connect(ProfileId),
    /// Bring a profile up, then stop the tunnels it conflicts with.
    Switch(ProfileId),
    Disconnect(ProfileId),
    DisconnectAll,
    Reconnect(ProfileId),
    SetKillSwitch(KillSwitchMode),
    /// The profile catalog changed on disk.
    Profiles(Vec<VpnProfile>),
}

/// Answer to a credential prompt.
#[derive(Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub otp: Option<String>,
    pub remember: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    pub id: u64,
    pub profile_id: ProfileId,
    pub name: String,
    /// The server's one-time-code challenge text, when it asks for one.
    pub otp_label: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Success,
    Warning,
    Error,
}

/// Something the user should hear about. Clients show each once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub seq: u64,
    pub level: Level,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Pending,
    Done,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct TunnelView {
    pub profile_id: ProfileId,
    pub name: String,
    pub phase: Phase,
    pub interface: Option<String>,
    pub since: SystemTime,
    pub routes: Vec<Cidr>,
    pub dns: Vec<IpAddr>,
    pub details: DetailedConnectionInfo,
    pub health: crate::tunnel::ConnectionHealth,
}

impl TunnelView {
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.routes.iter().any(|route| route.prefix_len == 0)
    }
}

/// Whether system DNS is going through the primary tunnel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DnsSecurityStatus {
    /// No tunnel owns the default route.
    #[default]
    NotActive,
    /// The primary tunnel asked for no resolvers.
    NotRequested,
    /// Resolvers are intended but could not be applied.
    Unverified,
    Protected,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsView {
    pub intended_servers: Vec<IpAddr>,
    pub status: DnsSecurityStatus,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Snapshot {
    pub version: u64,
    pub tunnels: Vec<TunnelView>,
    /// Owner of the default route.
    pub primary: Option<ProfileId>,
    pub kill_switch: KillSwitchMode,
    pub kill_switch_state: KillSwitchState,
    pub dns: DnsView,
    pub default_route: Option<String>,
    pub prompts: Vec<Prompt>,
    pub outcomes: BTreeMap<u64, Outcome>,
    pub notices: Vec<Notice>,
    /// Routes every known profile claims, for conflict previews.
    pub routes: BTreeMap<ProfileId, Vec<Cidr>>,
    /// Profiles running outside Vortix's control.
    pub external: Vec<String>,
    pub last_connected: BTreeMap<ProfileId, SystemTime>,
}

impl Snapshot {
    #[must_use]
    pub fn tunnel(&self, profile_id: &ProfileId) -> Option<&TunnelView> {
        self.tunnels
            .iter()
            .find(|tunnel| &tunnel.profile_id == profile_id)
    }

    /// Running tunnels that cannot coexist with `profile_id`.
    #[must_use]
    pub fn conflicts(&self, profile_id: &ProfileId) -> Vec<Conflict> {
        let requested = self.routes.get(profile_id).cloned().unwrap_or_default();
        self.tunnels
            .iter()
            .filter(|tunnel| &tunnel.profile_id != profile_id && tunnel.phase != Phase::Stopping)
            .filter_map(|tunnel| {
                classify_route_conflict(&requested, &tunnel.routes, &tunnel.profile_id, profile_id)
            })
            .collect()
    }
}

/// Engine configuration read once at start.
#[derive(Debug, Clone)]
pub struct Config {
    pub config_dir: PathBuf,
    pub tunnels: tunnels::Settings,
    pub openvpn_timeout: Duration,
    pub wireguard_timeout: Duration,
    pub auto_reconnect: bool,
    pub reconnect_delay: Duration,
    pub max_retries: u32,
    pub retry_base: Duration,
    pub retry_max: Duration,
    pub wireguard_stale_after: Duration,
}

impl Config {
    #[must_use]
    pub fn from_app(config: &crate::config::AppConfig, config_dir: &Path) -> Self {
        use crate::profile::ProtocolKind;
        Self {
            config_dir: config_dir.to_path_buf(),
            tunnels: tunnels::Settings {
                config_dir: config_dir.to_path_buf(),
                openvpn_verbosity: config.openvpn_verbosity.clone(),
                connect_timeout_secs: config.connect_timeout,
                wireguard_handshake_timeout_secs: config.wireguard_handshake_timeout_secs,
                wireguard_health_targets: config.ping_targets.clone(),
            },
            openvpn_timeout: Duration::from_secs(
                config.connect_operation_timeout_secs(ProtocolKind::OpenVpn),
            ),
            wireguard_stale_after: Duration::from_secs(config.wireguard_handshake_stale_secs),
            wireguard_timeout: Duration::from_secs(
                config.connect_operation_timeout_secs(ProtocolKind::WireGuard),
            ),
            auto_reconnect: config.auto_reconnect,
            reconnect_delay: Duration::from_secs(config.auto_reconnect_delay_secs),
            max_retries: config.connect_max_retries,
            retry_base: Duration::from_secs(config.connect_retry_base_delay_secs.max(1)),
            retry_max: Duration::from_secs(config.connect_retry_max_delay_secs.max(1)),
        }
    }

    #[must_use]
    pub const fn connect_timeout(&self, protocol: crate::profile::ProtocolKind) -> Duration {
        match protocol {
            crate::profile::ProtocolKind::OpenVpn => self.openvpn_timeout,
            crate::profile::ProtocolKind::WireGuard => self.wireguard_timeout,
        }
    }
}

enum Msg {
    Command(u64, Command),
    Answer(u64, Option<Credentials>),
    Event(Box<engine::Event>),
    Shutdown,
}

/// Handle to the engine thread.
pub struct Control {
    tx: mpsc::Sender<Msg>,
    snapshot: Arc<Mutex<Arc<Snapshot>>>,
    seen: std::cell::Cell<u64>,
    next_ticket: std::sync::atomic::AtomicU64,
    credentials: Arc<Mutex<FsOpenVpnCredentialStore>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Control {
    /// Adopt running tunnels, apply the plan once, and start the engine.
    pub fn start(
        config: &crate::config::AppConfig,
        config_dir: &Path,
        profiles: Vec<VpnProfile>,
    ) -> Result<Self, String> {
        let (uid, gid) = crate::config::config_owner(config_dir)?;
        let credentials = Arc::new(Mutex::new(FsOpenVpnCredentialStore::for_standard_owner(
            config_dir, uid, gid,
        )));
        let (tx, rx) = mpsc::channel();
        let snapshot = Arc::new(Mutex::new(Arc::new(Snapshot::default())));
        let engine = engine::Engine::start(
            Config::from_app(config, config_dir),
            uid,
            profiles,
            Arc::clone(&credentials),
            tx.clone(),
            Arc::clone(&snapshot),
        )?;
        let thread = std::thread::Builder::new()
            .name("vortix-engine".into())
            .spawn(move || engine.run(&rx))
            .map_err(|error| error.to_string())?;
        Ok(Self {
            tx,
            snapshot,
            seen: std::cell::Cell::new(0),
            next_ticket: std::sync::atomic::AtomicU64::new(1),
            credentials,
            thread: Some(thread),
        })
    }

    /// Queue a command. The returned ticket appears in [`Snapshot::outcomes`].
    pub fn send(&self, command: Command) -> u64 {
        let ticket = self
            .next_ticket
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let _ = self.tx.send(Msg::Command(ticket, command));
        ticket
    }

    pub fn answer(&self, prompt: u64, credentials: Option<Credentials>) {
        let _ = self.tx.send(Msg::Answer(prompt, credentials));
    }

    #[must_use]
    pub fn snapshot(&self) -> Arc<Snapshot> {
        Arc::clone(
            &self
                .snapshot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// The latest snapshot, if it changed since the last call.
    #[must_use]
    pub fn changed(&self) -> Option<Arc<Snapshot>> {
        let snapshot = self.snapshot();
        (snapshot.version != self.seen.replace(snapshot.version)).then_some(snapshot)
    }

    /// Block until `ticket` settles, answering prompts with `prompt`.
    pub fn wait(
        &self,
        ticket: u64,
        timeout: Duration,
        mut prompt: impl FnMut(&Prompt) -> Option<Credentials>,
    ) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        let mut answered = std::collections::BTreeSet::new();
        loop {
            let snapshot = self.snapshot();
            for pending in &snapshot.prompts {
                if answered.insert(pending.id) {
                    self.answer(pending.id, prompt(pending));
                }
            }
            match snapshot.outcomes.get(&ticket) {
                Some(Outcome::Done) => return Ok(()),
                Some(Outcome::Failed(reason)) => return Err(reason.clone()),
                _ => {}
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for the VPN".into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn load_credentials(
        &self,
        profile_id: &ProfileId,
        name: &str,
    ) -> Result<Option<RememberedOpenVpnCredentials>, String> {
        self.store()?
            .load(profile_id, name)
            .map_err(|error| error.to_string())
    }

    pub fn remember_credentials(
        &self,
        profile_id: &ProfileId,
        username: &str,
        password: &str,
    ) -> Result<(), String> {
        let credentials = RememberedOpenVpnCredentials::new(username, password)
            .map_err(|error| error.to_string())?;
        self.store()?
            .replace(profile_id, &credentials)
            .map_err(|error| error.to_string())
    }

    pub fn clear_credentials(
        &self,
        profile_id: &ProfileId,
        name: &str,
    ) -> Result<CredentialClearOutcome, String> {
        self.store()?
            .clear(profile_id, name)
            .map_err(|error| error.to_string())
    }

    fn store(&self) -> Result<std::sync::MutexGuard<'_, FsOpenVpnCredentialStore>, String> {
        self.credentials
            .lock()
            .map_err(|_| "credential store is unavailable".to_string())
    }
}

impl Drop for Control {
    /// Stop the engine; tunnels keep running and the next start adopts them.
    fn drop(&mut self) {
        let _ = self.tx.send(Msg::Shutdown);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
