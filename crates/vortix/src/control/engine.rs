//! The engine thread: turns commands and protocol results into tunnel-list
//! transitions, then moves the host to the new plan.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use crate::config::openvpn_credentials::{FsOpenVpnCredentialStore, RememberedOpenVpnCredentials};
use crate::config::secret::Secret;
use crate::control::killswitch::{KillSwitchMode, KillSwitchState};
use crate::control::scanner::{ActiveSession, ScannerResult};
use crate::control::Conflict;
use crate::hooks::{HookEvent, HookEventId, LifecycleFact};
use crate::openvpn::tunnel::OpenVpnStaticChallengeCredentials;
use crate::platform::DefaultRouteObservation;
use crate::profile::{ProfileId, ProtocolKind};
use crate::tunnel::TunnelCancellation;
use crate::wireguard::ownership::StandardTunnelOwnershipStore;

use super::net::Net;
use super::plan::{plan, NetworkPlan};
use super::profiles::{self, Entry};
use super::state::{Phase, Refusal, State};
use super::tunnels::{self, Live, StartError};
use super::{
    Command, Config, Credentials, Level, Msg, Notice, Outcome, Prompt, Snapshot, TunnelView,
};

const SCAN_EVERY: Duration = Duration::from_secs(1);
const APPLY_RETRY: Duration = Duration::from_secs(2);
const KEPT_NOTICES: usize = 64;
const KEPT_OUTCOMES: usize = 256;

pub(super) enum Event {
    Started {
        profile_id: ProfileId,
        result: Result<Live, StartError>,
        remember: Option<(String, String)>,
        used_saved: bool,
    },
    Stopped {
        profile_id: ProfileId,
        result: Result<(), (Live, String)>,
    },
    Scanned {
        result: ScannerResult,
        started: Instant,
    },
}

enum Wait {
    Up(ProfileId),
    Gone(BTreeSet<ProfileId>),
    Net,
}

/// Credentials a start attempt needs before it can run.
enum Need {
    Ready {
        credentials: Option<OpenVpnStaticChallengeCredentials>,
        used_saved: bool,
    },
    Prompt(Option<String>),
}

pub(super) struct Engine {
    config: Config,
    state: State,
    entries: BTreeMap<ProfileId, Entry>,
    live: BTreeMap<ProfileId, Live>,
    up_at: BTreeMap<ProfileId, Instant>,
    cancel: BTreeMap<ProfileId, TunnelCancellation>,
    errors: BTreeMap<ProfileId, String>,
    prompts: BTreeMap<u64, Prompt>,
    waits: BTreeMap<u64, Wait>,
    outcomes: BTreeMap<u64, Outcome>,
    notices: VecDeque<Notice>,
    seq: u64,
    net: Net,
    applied: Option<NetworkPlan>,
    apply_error: Option<String>,
    applied_at: Instant,
    ownership: Arc<StandardTunnelOwnershipStore>,
    credentials: Arc<Mutex<FsOpenVpnCredentialStore>>,
    tx: mpsc::Sender<Msg>,
    shared: Arc<Mutex<Arc<Snapshot>>>,
    published: Snapshot,
    scan: Option<ScannerResult>,
    scanning: bool,
    next_scan: Instant,
    external: Vec<String>,
    last_connected: BTreeMap<ProfileId, SystemTime>,
    last_generation: u64,
    hooks: Option<(tokio::runtime::Runtime, crate::hooks::HookRunner)>,
    health: BTreeMap<
        ProfileId,
        (
            crate::tunnel::ConnectionHealth,
            crate::wireguard::receipt::PeerActivity,
        ),
    >,
}

impl Engine {
    pub(super) fn start(
        config: Config,
        uid: u32,
        profiles: Vec<crate::config::profiles::VpnProfile>,
        credentials: Arc<Mutex<FsOpenVpnCredentialStore>>,
        tx: mpsc::Sender<Msg>,
        shared: Arc<Mutex<Arc<Snapshot>>>,
    ) -> Result<Self, String> {
        let last_connected = profiles
            .iter()
            .filter_map(|profile| Some((profile.id.clone(), profile.last_used?)))
            .collect();
        let entries = profiles::load(&config.config_dir, profiles);
        let ownership = Arc::new(
            StandardTunnelOwnershipStore::production(uid).map_err(|error| error.to_string())?,
        );
        let kill_switch = crate::control::killswitch::load_state_checked()
            .map_err(|error| {
                format!(
                    "kill switch state is unreadable ({error}); run `sudo vortix release-killswitch`"
                )
            })?
            .map_or(KillSwitchMode::Off, |state| state.mode);
        let catalog = entries
            .values()
            .map(|entry| entry.profile.clone())
            .collect::<Vec<_>>();
        let scan = crate::control::scanner::gather_system_state(&catalog);
        if !scan.tunnel_observation_complete {
            return Err("could not list running tunnels".into());
        }

        let mut engine = Self {
            net: Net::new(config.config_dir.clone(), NetworkPlan::default()),
            hooks: start_hooks(&config.config_dir),
            health: BTreeMap::new(),
            config,
            state: State::new(kill_switch),
            entries,
            live: BTreeMap::new(),
            up_at: BTreeMap::new(),
            cancel: BTreeMap::new(),
            errors: BTreeMap::new(),
            prompts: BTreeMap::new(),
            waits: BTreeMap::new(),
            outcomes: BTreeMap::new(),
            notices: VecDeque::new(),
            seq: 0,
            applied: None,
            apply_error: None,
            applied_at: Instant::now(),
            ownership,
            credentials,
            tx,
            shared,
            published: Snapshot::default(),
            scan: None,
            scanning: false,
            next_scan: Instant::now() + SCAN_EVERY,
            external: Vec::new(),
            last_connected,
            last_generation: 0,
        };
        engine.adopt(&scan.sessions);
        engine.net = Net::new(
            engine.config.config_dir.clone(),
            plan(&engine.state.plan_input()),
        );
        engine.scan = Some(scan);
        engine.reconcile();
        engine.publish();
        Ok(engine)
    }

    pub(super) fn run(mut self, rx: &mpsc::Receiver<Msg>) {
        loop {
            let wait = self.next_wake().saturating_duration_since(Instant::now());
            match rx.recv_timeout(wait) {
                Ok(Msg::Shutdown) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Ok(message) => self.handle(message),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            let mut shutdown = false;
            while let Ok(message) = rx.try_recv() {
                if matches!(message, Msg::Shutdown) {
                    shutdown = true;
                } else {
                    self.handle(message);
                }
            }
            self.tick();
            self.reconcile();
            self.settle();
            self.publish();
            if shutdown {
                break;
            }
        }
        if let Some((runtime, hooks)) = self.hooks.take() {
            runtime.block_on(hooks.shutdown_bounded(Duration::from_secs(2)));
        }
    }

    fn handle(&mut self, message: Msg) {
        match message {
            Msg::Command(ticket, command) => self.command(ticket, command),
            Msg::Answer(prompt, credentials) => self.answer(prompt, credentials),
            Msg::Event(event) => match *event {
                Event::Started {
                    profile_id,
                    result,
                    remember,
                    used_saved,
                } => self.started(&profile_id, result, remember, used_saved),
                Event::Stopped { profile_id, result } => self.stopped(&profile_id, result),
                Event::Scanned { result, started } => self.scanned(result, started),
            },
            Msg::Shutdown => {}
        }
    }

    // ── commands ────────────────────────────────────────────────────────

    fn command(&mut self, ticket: u64, command: Command) {
        self.outcomes.insert(ticket, Outcome::Pending);
        match command {
            Command::Connect(profile_id) => self.connect(ticket, profile_id, false),
            Command::Switch(profile_id) => self.connect(ticket, profile_id, true),
            Command::Disconnect(profile_id) => {
                if self.state.get(&profile_id).is_some() {
                    self.waits
                        .insert(ticket, Wait::Gone(BTreeSet::from([profile_id.clone()])));
                    self.stop(&profile_id);
                } else {
                    self.outcomes.insert(ticket, Outcome::Done);
                }
            }
            Command::DisconnectAll => {
                let all = self
                    .state
                    .tunnels()
                    .map(|tunnel| tunnel.spec.profile_id.clone())
                    .collect::<BTreeSet<_>>();
                for profile_id in &all {
                    self.stop(profile_id);
                }
                self.waits.insert(ticket, Wait::Gone(all));
            }
            Command::Reconnect(profile_id) => {
                if self.state.restart(&profile_id) {
                    self.waits.insert(ticket, Wait::Up(profile_id.clone()));
                    self.hook(HookEvent::Reconnecting, &profile_id);
                    self.begin_stop(&profile_id);
                } else {
                    self.connect(ticket, profile_id, false);
                }
            }
            Command::SetKillSwitch(mode) => {
                self.state.kill_switch = mode;
                self.applied = None;
                self.waits.insert(ticket, Wait::Net);
            }
            Command::Profiles(profiles) => {
                self.entries = profiles::load(&self.config.config_dir, profiles);
                self.outcomes.insert(ticket, Outcome::Done);
            }
        }
    }

    fn connect(&mut self, ticket: u64, profile_id: ProfileId, switch: bool) {
        let Some(entry) = self.entries.get(&profile_id) else {
            self.outcomes
                .insert(ticket, Outcome::Failed("unknown profile".into()));
            return;
        };
        let spec = match &entry.spec {
            Ok(spec) => spec.clone(),
            Err(error) => {
                let text = format!("'{}' cannot be used: {error}", entry.profile.name);
                self.notice(Level::Error, text.clone());
                self.outcomes.insert(ticket, Outcome::Failed(text));
                return;
            }
        };
        let replaces = if switch {
            // A running tunnel knows the routes its server pushed.
            let known = self
                .state
                .get(&profile_id)
                .map_or_else(|| spec.clone(), |tunnel| tunnel.spec.clone());
            self.state
                .conflicts(&known)
                .into_iter()
                .map(|conflict| match conflict {
                    Conflict::DefaultRouteTakeover { current, .. } => current,
                    Conflict::RouteOverlap { with, .. } => with,
                })
                .collect()
        } else {
            BTreeSet::new()
        };
        let need = self.need(&profile_id);
        let rank = self.next_generation();
        let replaces_again = replaces.clone();
        match self
            .state
            .begin(spec, rank, replaces, matches!(need, Need::Prompt(_)))
        {
            Ok(()) => {}
            Err(Refusal::Active) => {
                // Switching to a tunnel that is already up stops what it conflicts with.
                for peer in replaces_again {
                    self.stop(&peer);
                }
                self.outcomes.insert(ticket, Outcome::Done);
                return;
            }
            Err(Refusal::Busy) => {
                self.outcomes.insert(
                    ticket,
                    Outcome::Failed("still disconnecting; try again in a moment".into()),
                );
                return;
            }
        }
        self.errors.remove(&profile_id);
        self.waits.insert(ticket, Wait::Up(profile_id.clone()));
        self.hook(HookEvent::ConnectStarted, &profile_id);
        match need {
            Need::Ready {
                credentials,
                used_saved,
            } => self.spawn_start(&profile_id, credentials, None, used_saved),
            Need::Prompt(otp_label) => {
                self.seq += 1;
                let name = self.name(&profile_id);
                self.prompts.insert(
                    self.seq,
                    Prompt {
                        id: self.seq,
                        profile_id,
                        name,
                        otp_label,
                    },
                );
            }
        }
    }

    fn answer(&mut self, prompt: u64, credentials: Option<Credentials>) {
        let Some(prompt) = self.prompts.remove(&prompt) else {
            return;
        };
        let profile_id = prompt.profile_id;
        match credentials {
            Some(credentials) if self.state.credentials_given(&profile_id) => {
                let remember = credentials
                    .remember
                    .then(|| (credentials.username.clone(), credentials.password.clone()));
                let secret = Secret::new(credentials.otp.unwrap_or_default().into_bytes());
                self.spawn_start(
                    &profile_id,
                    Some(OpenVpnStaticChallengeCredentials::new(
                        credentials.username,
                        credentials.password,
                        secret,
                    )),
                    remember,
                    false,
                );
            }
            _ => {
                self.errors.insert(profile_id.clone(), "cancelled".into());
                self.stop(&profile_id);
            }
        }
    }

    // ── protocol results ────────────────────────────────────────────────

    fn started(
        &mut self,
        profile_id: &ProfileId,
        result: Result<Live, StartError>,
        remember: Option<(String, String)>,
        used_saved: bool,
    ) {
        self.cancel.remove(profile_id);
        let phase = self.state.get(profile_id).map(|tunnel| tunnel.phase);
        let name = self.name(profile_id);
        match result {
            Ok(live) if phase == Some(Phase::Starting) => {
                let replaced = self.state.came_up(
                    profile_id,
                    live.handle.interface_name.clone(),
                    live.pushed_routes(),
                    live.pushed_servers(),
                    live.dns(),
                );
                self.live.insert(profile_id.clone(), live);
                self.up_at.insert(profile_id.clone(), Instant::now());
                self.last_connected
                    .insert(profile_id.clone(), SystemTime::now());
                let store = crate::config::profile_store::FsProfileStore::new(
                    self.config
                        .config_dir
                        .join(crate::constants::PROFILES_DIR_NAME),
                );
                if let Err(error) = store.touch(profile_id) {
                    tracing::warn!(%error, "could not record last-used time");
                }
                for peer in replaced {
                    self.begin_stop(&peer);
                }
                if let Some((username, password)) = remember {
                    self.remember_credentials(profile_id, &username, &password);
                }
                self.notice(Level::Success, format!("Connected '{name}'"));
                self.warn_late_takeover(profile_id);
                self.hook(HookEvent::Connected, profile_id);
            }
            Ok(live) => self.spawn_stop(profile_id, live),
            Err(error) => {
                if error == StartError::AuthFailed && used_saved {
                    if let Ok(store) = self.credentials.lock() {
                        let _ = store.clear(profile_id, &name);
                    }
                    self.notice(
                        Level::Warning,
                        format!("Saved credentials for '{name}' were rejected and removed"),
                    );
                }
                if phase == Some(Phase::Stopping) {
                    self.finish_stop(profile_id);
                    return;
                }
                let attempt = self
                    .state
                    .get(profile_id)
                    .and_then(|tunnel| tunnel.recovering);
                let retry_at = attempt
                    .filter(|attempt| *attempt < self.config.max_retries)
                    .map(|attempt| Instant::now() + self.backoff(attempt));
                let text = format!("Could not connect '{name}': {error}");
                self.errors.insert(profile_id.clone(), text.clone());
                self.state.start_failed(profile_id, retry_at);
                self.notice(Level::Error, text);
                if attempt.is_some() && retry_at.is_none() {
                    self.notice(
                        Level::Warning,
                        format!("Gave up reconnecting '{name}'. Disconnect or reconnect it."),
                    );
                }
                self.hook(HookEvent::ConnectFailed, profile_id);
            }
        }
    }

    fn stopped(&mut self, profile_id: &ProfileId, result: Result<(), (Live, String)>) {
        match result {
            Ok(()) => self.finish_stop(profile_id),
            Err((live, error)) => {
                let name = self.name(profile_id);
                self.live.insert(profile_id.clone(), live);
                self.state.stop_failed(profile_id);
                self.errors.insert(profile_id.clone(), error.clone());
                self.notice(
                    Level::Error,
                    format!("Could not disconnect '{name}': {error}"),
                );
            }
        }
    }

    fn scanned(&mut self, result: ScannerResult, started: Instant) {
        self.scanning = false;
        self.next_scan = Instant::now() + SCAN_EVERY;
        if result.tunnel_observation_complete {
            let lost = self
                .state
                .tunnels()
                .filter(|tunnel| tunnel.phase == Phase::Up)
                .filter(|tunnel| {
                    self.up_at
                        .get(&tunnel.spec.profile_id)
                        .is_some_and(|up| *up < started)
                })
                .filter(|tunnel| session(&result.sessions, &tunnel.spec.name).is_none())
                .map(|tunnel| tunnel.spec.profile_id.clone())
                .collect::<Vec<_>>();
            for profile_id in lost {
                self.lost(&profile_id);
            }
            self.external = result
                .sessions
                .iter()
                .filter(|session| {
                    !self
                        .state
                        .tunnels()
                        .any(|tunnel| tunnel.spec.name == session.name)
                })
                .map(|session| session.name.clone())
                .collect();
            self.observe_wireguard_health(&result.sessions);
        }
        self.scan = Some(result);
    }

    /// Track handshake health of each up `WireGuard` tunnel Vortix manages,
    /// recording changes in its receipt and the journal.
    fn observe_wireguard_health(&mut self, sessions: &[ActiveSession]) {
        let up = self
            .state
            .tunnels()
            .filter(|tunnel| {
                tunnel.phase == Phase::Up && tunnel.spec.protocol == ProtocolKind::WireGuard
            })
            .map(|tunnel| (tunnel.spec.profile_id.clone(), tunnel.spec.name.clone()))
            .collect::<Vec<_>>();
        self.health
            .retain(|profile_id, _| up.iter().any(|(id, _)| id == profile_id));
        for (profile_id, name) in up {
            let Some(session) = session(sessions, &name) else {
                continue;
            };
            let Some(mut receipt) =
                crate::wireguard::receipt::load(&self.config.config_dir, &profile_id)
                    .filter(|receipt| receipt.validates(&profile_id, session))
            else {
                continue;
            };
            let (health, activity) = self.health.entry(profile_id.clone()).or_default();
            let current = crate::wireguard::receipt::health_from_peers(
                &session.wireguard_peers,
                activity,
                &receipt.probe_receipts,
                self.config.wireguard_stale_after,
            );
            if let Ok(Some(old)) = crate::wireguard::receipt::update_health(
                &self.config.config_dir,
                &mut receipt,
                current.clone(),
            ) {
                if let Some(journal) = crate::journal::global_journal() {
                    let _ = journal.append(crate::journal::JournalEvent::ConnectionHealthChanged {
                        profile_id: profile_id.clone(),
                        old,
                        new: current.clone(),
                    });
                }
            }
            *health = current;
        }
    }

    fn lost(&mut self, profile_id: &ProfileId) {
        let name = self.name(profile_id);
        if let Some(live) = self.live.remove(profile_id) {
            let settings = self.config.tunnels.clone();
            let ownership = Arc::clone(&self.ownership);
            std::thread::spawn(move || {
                let _ = tunnels::stop(&settings, &ownership, live);
            });
        }
        self.up_at.remove(profile_id);
        let retry_at = (self.config.auto_reconnect && self.config.max_retries > 0)
            .then(|| Instant::now() + self.config.reconnect_delay);
        self.state.lost(profile_id, retry_at);
        self.notice(
            Level::Warning,
            if retry_at.is_some() {
                format!("'{name}' dropped; reconnecting")
            } else {
                format!("'{name}' dropped. Reconnect or disconnect it.")
            },
        );
        self.hook(HookEvent::Reconnecting, profile_id);
    }

    // ── stopping ────────────────────────────────────────────────────────

    fn stop(&mut self, profile_id: &ProfileId) {
        if self.state.stop(profile_id) {
            self.hook(HookEvent::DisconnectStarted, profile_id);
            self.begin_stop(profile_id);
        }
    }

    /// Undo whatever is running for a tunnel already marked stopping.
    fn begin_stop(&mut self, profile_id: &ProfileId) {
        self.prompts
            .retain(|_, prompt| &prompt.profile_id != profile_id);
        if let Some(cancel) = self.cancel.get(profile_id) {
            // The start result arrives next and finishes the stop.
            cancel.cancel();
        } else if let Some(live) = self.live.remove(profile_id) {
            self.spawn_stop(profile_id, live);
        } else {
            self.finish_stop(profile_id);
        }
    }

    fn finish_stop(&mut self, profile_id: &ProfileId) {
        self.up_at.remove(profile_id);
        let name = self.name(profile_id);
        let restart = self.state.stopped(profile_id);
        self.hook(HookEvent::Disconnected, profile_id);
        if restart.is_some() {
            let need = self.need(profile_id);
            let spec = self
                .entries
                .get(profile_id)
                .and_then(|entry| entry.spec.clone().ok());
            let rank = self.next_generation();
            if let Some(spec) = spec {
                if self
                    .state
                    .begin(spec, rank, BTreeSet::new(), matches!(need, Need::Prompt(_)))
                    .is_ok()
                {
                    if restart.as_ref().is_some_and(|old| old.recovering.is_some()) {
                        self.state.resume_recovery(profile_id);
                    }
                    match need {
                        Need::Ready {
                            credentials,
                            used_saved,
                        } => self.spawn_start(profile_id, credentials, None, used_saved),
                        Need::Prompt(otp_label) => {
                            self.seq += 1;
                            self.prompts.insert(
                                self.seq,
                                Prompt {
                                    id: self.seq,
                                    profile_id: profile_id.clone(),
                                    name,
                                    otp_label,
                                },
                            );
                        }
                    }
                }
            }
        } else if !self.errors.contains_key(profile_id) {
            self.notice(Level::Info, format!("Disconnected '{name}'"));
        }
    }

    // ── workers ─────────────────────────────────────────────────────────

    fn spawn_start(
        &mut self,
        profile_id: &ProfileId,
        credentials: Option<OpenVpnStaticChallengeCredentials>,
        remember: Option<(String, String)>,
        used_saved: bool,
    ) {
        let Some(entry) = self.entries.get(profile_id) else {
            self.state.start_failed(profile_id, None);
            return;
        };
        let profile = entry.core_profile();
        let timeout = self.config.connect_timeout(profile.protocol);
        let generation = self.next_generation();
        let cancel = TunnelCancellation::default();
        self.cancel.insert(profile_id.clone(), cancel.clone());
        let settings = self.config.tunnels.clone();
        let ownership = Arc::clone(&self.ownership);
        let tx = self.tx.clone();
        let profile_id = profile_id.clone();
        std::thread::spawn(move || {
            let result = tunnels::start(
                &settings,
                &ownership,
                &profile,
                generation,
                credentials,
                cancel,
                timeout,
            );
            let _ = tx.send(Msg::Event(Box::new(Event::Started {
                profile_id,
                result,
                remember,
                used_saved,
            })));
        });
    }

    fn spawn_stop(&self, profile_id: &ProfileId, live: Live) {
        let settings = self.config.tunnels.clone();
        let ownership = Arc::clone(&self.ownership);
        let tx = self.tx.clone();
        let profile_id = profile_id.clone();
        std::thread::spawn(move || {
            let backup = Live {
                kind: live.kind.clone(),
                handle: live.handle.clone(),
            };
            let result =
                tunnels::stop(&settings, &ownership, live).map_err(|error| (backup, error));
            let _ = tx.send(Msg::Event(Box::new(Event::Stopped { profile_id, result })));
        });
    }

    // ── loop steps ──────────────────────────────────────────────────────

    fn tick(&mut self) {
        let now = Instant::now();
        let due = self
            .state
            .tunnels()
            .filter(
                |tunnel| matches!(tunnel.phase, Phase::Waiting { retry_at: Some(at) } if at <= now),
            )
            .map(|tunnel| tunnel.spec.profile_id.clone())
            .collect::<Vec<_>>();
        for profile_id in due {
            if self.state.retry(&profile_id).is_none() {
                continue;
            }
            match self.need(&profile_id) {
                Need::Ready {
                    credentials,
                    used_saved,
                } => self.spawn_start(&profile_id, credentials, None, used_saved),
                // A recovery cannot stop to ask; it waits for the user.
                Need::Prompt(_) => {
                    self.state.start_failed(&profile_id, None);
                }
            }
        }
        if !self.scanning && now >= self.next_scan {
            self.scanning = true;
            let catalog = self
                .entries
                .values()
                .map(|entry| entry.profile.clone())
                .collect::<Vec<_>>();
            let tx = self.tx.clone();
            std::thread::spawn(move || {
                let started = Instant::now();
                let result = crate::control::scanner::gather_system_state(&catalog);
                let _ = tx.send(Msg::Event(Box::new(Event::Scanned { result, started })));
            });
        }
    }

    fn reconcile(&mut self) {
        let target = plan(&self.state.plan_input());
        let unchanged = self.applied.as_ref() == Some(&target);
        if unchanged && (self.apply_error.is_none() || self.applied_at.elapsed() < APPLY_RETRY) {
            return;
        }
        let result = self.net.apply(&target, self.state.kill_switch);
        self.applied_at = Instant::now();
        self.applied = Some(target);
        let settled = match result {
            Ok(()) => {
                if self.apply_error.take().is_some() {
                    self.notice(Level::Success, "Network settings applied".into());
                }
                Outcome::Done
            }
            Err(error) => {
                tracing::warn!(target: "vortix::engine", %error, "network apply failed");
                if self.apply_error.as_ref() != Some(&error) {
                    self.notice(
                        Level::Error,
                        format!("Network settings not applied: {error}"),
                    );
                }
                self.apply_error = Some(error.clone());
                Outcome::Failed(error)
            }
        };
        let waiting = self
            .waits
            .iter()
            .filter(|(_, wait)| matches!(wait, Wait::Net))
            .map(|(ticket, _)| *ticket)
            .collect::<Vec<_>>();
        for ticket in waiting {
            self.waits.remove(&ticket);
            self.outcomes.insert(ticket, settled.clone());
        }
    }

    /// Resolve tickets whose condition now holds.
    fn settle(&mut self) {
        let mut done = Vec::new();
        for (ticket, wait) in &self.waits {
            let outcome = match wait {
                Wait::Up(profile_id) => match self.state.get(profile_id).map(|tunnel| tunnel.phase)
                {
                    Some(Phase::Up) => Some(Outcome::Done),
                    None | Some(Phase::Waiting { .. }) => Some(Outcome::Failed(
                        self.errors
                            .get(profile_id)
                            .cloned()
                            .unwrap_or_else(|| "cancelled".into()),
                    )),
                    _ => None,
                },
                Wait::Gone(profiles) => {
                    let remaining = profiles
                        .iter()
                        .filter(|profile_id| self.state.get(profile_id).is_some())
                        .collect::<Vec<_>>();
                    if remaining.is_empty() {
                        Some(Outcome::Done)
                    } else {
                        remaining
                            .iter()
                            .find(|profile_id| {
                                self.state
                                    .get(profile_id)
                                    .is_some_and(|tunnel| tunnel.phase != Phase::Stopping)
                            })
                            .map(|profile_id| {
                                Outcome::Failed(
                                    self.errors
                                        .get(*profile_id)
                                        .cloned()
                                        .unwrap_or_else(|| "disconnect failed".into()),
                                )
                            })
                    }
                }
                Wait::Net => None,
            };
            if let Some(outcome) = outcome {
                done.push((*ticket, outcome));
            }
        }
        for (ticket, outcome) in done {
            self.waits.remove(&ticket);
            self.outcomes.insert(ticket, outcome);
        }
        while self.outcomes.len() > KEPT_OUTCOMES {
            self.outcomes.pop_first();
        }
    }

    fn publish(&mut self) {
        let target = self.applied.clone().unwrap_or_default();
        let scan = self.scan.as_ref();
        let tunnels = self
            .state
            .tunnels()
            .map(|tunnel| TunnelView {
                profile_id: tunnel.spec.profile_id.clone(),
                name: tunnel.spec.name.clone(),
                phase: tunnel.phase,
                interface: tunnel.interface.clone(),
                since: tunnel.since,
                routes: tunnel.spec.routes.iter().copied().collect(),
                dns: tunnel.spec.dns.servers.clone(),
                details: scan
                    .and_then(|scan| session(&scan.sessions, &tunnel.spec.name))
                    .map(|session| session.details.clone())
                    .unwrap_or_default(),
                health: self
                    .health
                    .get(&tunnel.spec.profile_id)
                    .map(|(health, _)| health.clone())
                    .unwrap_or_default(),
            })
            .collect::<Vec<_>>();
        let intended_servers = target
            .primary
            .as_ref()
            .and_then(|primary| tunnels.iter().find(|tunnel| &tunnel.profile_id == primary))
            .map(|tunnel| tunnel.dns.clone())
            .unwrap_or_default();
        let dns = super::DnsView {
            status: if target.primary.is_none() {
                super::DnsSecurityStatus::NotActive
            } else if intended_servers.is_empty() {
                super::DnsSecurityStatus::NotRequested
            } else if self.apply_error.is_some() {
                super::DnsSecurityStatus::Unverified
            } else {
                super::DnsSecurityStatus::Protected
            },
            intended_servers,
        };
        let kill_switch_state =
            if self.apply_error.is_some() && self.state.kill_switch != KillSwitchMode::Off {
                KillSwitchState::Degraded
            } else {
                target.kill_switch_state
            };
        let mut routes = self
            .entries
            .iter()
            .filter_map(|(profile_id, entry)| {
                let spec = entry.spec.as_ref().ok()?;
                Some((profile_id.clone(), spec.routes.iter().copied().collect()))
            })
            .collect::<BTreeMap<_, Vec<_>>>();
        for tunnel in &tunnels {
            routes.insert(tunnel.profile_id.clone(), tunnel.routes.clone());
        }
        let next = Snapshot {
            version: self.published.version,
            tunnels,
            primary: target.primary.clone(),
            kill_switch: self.state.kill_switch,
            kill_switch_state,
            dns,
            default_route: scan.and_then(|scan| match &scan.default_route {
                DefaultRouteObservation::Interface(interface) => Some(interface.clone()),
                _ => None,
            }),
            prompts: self.prompts.values().cloned().collect(),
            outcomes: self.outcomes.clone(),
            notices: self.notices.iter().cloned().collect(),
            routes,
            external: self.external.clone(),
            last_connected: self.last_connected.clone(),
        };
        if next == self.published {
            return;
        }
        self.published = next;
        self.published.version += 1;
        *self
            .shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(self.published.clone());
    }

    fn next_wake(&self) -> Instant {
        let mut wake = self.next_scan;
        for tunnel in self.state.tunnels() {
            if let Phase::Waiting { retry_at: Some(at) } = tunnel.phase {
                wake = wake.min(at);
            }
        }
        if self.apply_error.is_some() {
            wake = wake.min(self.applied_at + APPLY_RETRY);
        }
        wake
    }

    // ── helpers ─────────────────────────────────────────────────────────

    fn adopt(&mut self, sessions: &[ActiveSession]) {
        for session in sessions {
            let Some(entry) = self
                .entries
                .values()
                .find(|entry| entry.profile.name == session.name)
            else {
                continue;
            };
            let Ok(spec) = entry.spec.clone() else {
                self.external.push(session.name.clone());
                continue;
            };
            match tunnels::adopt(
                &self.config.tunnels,
                &self.ownership,
                &entry.core_profile(),
                session,
            ) {
                Ok(Some(live)) => {
                    let mut spec = spec;
                    spec.routes.extend(live.pushed_routes());
                    spec.server_ips.extend(live.pushed_servers());
                    if let Some(dns) = live.dns() {
                        spec.dns = dns;
                    }
                    let profile_id = spec.profile_id.clone();
                    self.last_generation = self.last_generation.max(live.handle.generation);
                    self.state.adopt(
                        spec,
                        live.handle.interface_name.clone(),
                        live.handle.generation,
                        live.handle.started_at,
                    );
                    self.up_at.insert(profile_id.clone(), Instant::now());
                    self.live.insert(profile_id, live);
                }
                Ok(None) => self.external.push(session.name.clone()),
                Err(error) => {
                    tracing::warn!(target: "vortix::engine", profile = %session.name, %error, "adoption refused");
                    self.external.push(session.name.clone());
                }
            }
        }
    }

    fn need(&self, profile_id: &ProfileId) -> Need {
        let ready = Need::Ready {
            credentials: None,
            used_saved: false,
        };
        let Some(entry) = self.entries.get(profile_id) else {
            return ready;
        };
        let path = &entry.profile.config_path;
        if entry.profile.protocol != ProtocolKind::OpenVpn
            || !crate::openvpn::parser::needs_credentials(path)
        {
            return ready;
        }
        let otp_label = crate::openvpn::parser::static_challenge_prompt(path);
        let saved = self
            .credentials
            .lock()
            .ok()
            .and_then(|store| store.load(profile_id, &entry.profile.name).ok().flatten());
        match (otp_label, saved) {
            (None, Some(saved)) => Need::Ready {
                credentials: Some(OpenVpnStaticChallengeCredentials::new(
                    saved.username().to_owned(),
                    saved.password().to_owned(),
                    Secret::new(Vec::new()),
                )),
                used_saved: true,
            },
            (otp_label, _) => Need::Prompt(otp_label),
        }
    }

    fn remember_credentials(&mut self, profile_id: &ProfileId, username: &str, password: &str) {
        let saved = RememberedOpenVpnCredentials::new(username, password)
            .map_err(|error| error.to_string())
            .and_then(|credentials| {
                self.credentials
                    .lock()
                    .map_err(|_| "credential store is unavailable".to_string())?
                    .replace(profile_id, &credentials)
                    .map_err(|error| error.to_string())
            });
        if let Err(error) = saved {
            let name = self.name(profile_id);
            self.notice(
                Level::Warning,
                format!("Connected '{name}', but its credentials were not saved: {error}"),
            );
        }
    }

    fn warn_late_takeover(&mut self, profile_id: &ProfileId) {
        let Some(tunnel) = self.state.get(profile_id) else {
            return;
        };
        let spec = tunnel.spec.clone();
        let holders = self
            .state
            .conflicts(&spec)
            .into_iter()
            .filter_map(|conflict| match conflict {
                Conflict::DefaultRouteTakeover { current, .. } => Some(current),
                Conflict::RouteOverlap { .. } => None,
            })
            .collect::<Vec<_>>();
        for holder in holders {
            let holder = self.name(&holder);
            self.notice(
                Level::Warning,
                format!(
                    "'{}' also routes all traffic and now carries it. '{holder}' is still connected.",
                    spec.name
                ),
            );
        }
    }

    fn backoff(&self, attempt: u32) -> Duration {
        let factor = 2u32.saturating_pow(attempt.saturating_sub(1));
        self.config
            .retry_base
            .saturating_mul(factor)
            .min(self.config.retry_max)
    }

    fn next_generation(&mut self) -> u64 {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            });
        self.last_generation = now.max(self.last_generation + 1);
        self.last_generation
    }

    fn name(&self, profile_id: &ProfileId) -> String {
        self.entries.get(profile_id).map_or_else(
            || profile_id.to_string(),
            |entry| entry.profile.name.clone(),
        )
    }

    fn notice(&mut self, level: Level, text: String) {
        tracing::info!(target: "vortix::engine", ?level, %text);
        if let Some(journal) = crate::journal::global_journal() {
            let _ = journal.append(crate::journal::JournalEvent::Notice {
                level: format!("{level:?}").to_ascii_lowercase(),
                text: text.clone(),
            });
        }
        self.seq += 1;
        self.notices.push_back(Notice {
            seq: self.seq,
            level,
            text,
        });
        while self.notices.len() > KEPT_NOTICES {
            self.notices.pop_front();
        }
    }

    fn hook(&mut self, event: HookEvent, profile_id: &ProfileId) {
        let Some((_, hooks)) = &self.hooks else {
            return;
        };
        let Some(entry) = self.entries.get(profile_id) else {
            return;
        };
        self.seq += 1;
        hooks.dispatcher().dispatch(&LifecycleFact {
            event_id: HookEventId::from_parts(1, self.seq),
            event,
            profile_id: profile_id.clone(),
            display_name: entry.profile.name.clone(),
            protocol: entry.profile.protocol,
            occurred_at_millis: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |elapsed| {
                    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
                }),
        });
    }
}

fn session<'a>(sessions: &'a [ActiveSession], name: &str) -> Option<&'a ActiveSession> {
    sessions.iter().find(|session| session.name == name)
}

fn start_hooks(
    config_dir: &std::path::Path,
) -> Option<(tokio::runtime::Runtime, crate::hooks::HookRunner)> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("vortix-hooks")
        .enable_all()
        .build()
        .ok()?;
    let runner = {
        let _guard = runtime.enter();
        crate::hooks::start(config_dir)?
    };
    Some((runtime, runner))
}
