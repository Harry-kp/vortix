//! Headless VPN runtime — owns telemetry, profiles, config, and worker channels.
//!
//! `VpnRuntime` holds connection-state mirror (CLI-only — TUI consults
//! `TunnelRegistry`), profiles, telemetry data, kill switch state, retry
//! logic, and background worker channels. It has **zero** ratatui
//! dependencies, making it usable from both the TUI ([`crate::app::App`])
//! and the CLI without pulling in any terminal rendering code.
//!
//! The TUI embeds `VpnRuntime` as `App.runtime` (no `Deref`); field
//! accesses go through `self.runtime.X` or `app.runtime.X` explicitly.

pub mod connection;
pub mod connection_state;
pub mod openvpn;

pub use connection_state::{ConnectionState, DetailedConnectionInfo};

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Instant;

use crate::config::AppConfig;
use crate::constants;
use crate::core::network_monitor::NetworkEvent;
use crate::core::telemetry::{self, TelemetryUpdate};
use crate::logger;
use crate::message::Message;
use crate::state::{
    KillSwitchMode, KillSwitchState, ProfileSortOrder, Protocol, RetryState, VpnProfile,
};

fn effective_killswitch_state(
    requested: KillSwitchState,
    firewall_result: Option<bool>,
) -> KillSwitchState {
    match firewall_result {
        Some(false) => KillSwitchState::Degraded,
        Some(true) | None => requested,
    }
}

fn needs_firewall_release(old: KillSwitchState, requested: KillSwitchState) -> bool {
    !requested.is_blocking() && matches!(old, KillSwitchState::Blocking | KillSwitchState::Degraded)
}

fn current_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

use crate::utils;
use crate::vortix_core::profile::ProfileId;

type DnsObservation = (ProfileId, String, bool);
type DnsSchedule = (Vec<DnsObservation>, usize, Instant);

/// Core VPN engine — all VPN-related state, no UI dependencies.
///
/// Created by [`VpnRuntime::new`] for TUI use (spawns background workers) or
/// [`VpnRuntime::new_headless`] for CLI one-shot commands (no background threads).
#[allow(clippy::struct_excessive_bools)]
pub struct VpnRuntime {
    // === VPN State ===
    pub profiles: Vec<VpnProfile>,
    /// Debounced filesystem observation keyed by stable identity. It never
    /// allocates or rekeys a profile when an editor moves a config.
    pub profile_presence: HashMap<ProfileId, crate::state::ProfilePresenceTracker>,
    pub session_start: Option<Instant>,

    // === Network Telemetry ===
    pub down_history: VecDeque<f64>,
    pub up_history: VecDeque<f64>,
    pub current_down: u64,
    pub current_up: u64,
    pub latency_ms: u64,
    pub packet_loss: f32,
    pub jitter_ms: u64,
    pub location: String,
    pub isp: String,
    pub dns_server: String,
    pub dns_leak: crate::core::dns_leak::DnsLeakStatus,

    // === System Info ===
    pub public_ip: String,
    pub real_ip: Option<String>,
    pub public_ipv6: Option<String>,
    pub real_ipv6: Option<String>,
    pub last_security_check: Option<Instant>,
    pub ip_unchanged_warned: bool,
    pub last_connected_profile: Option<String>,

    /// True once the scanner has completed at least one
    /// `Message::SyncSystemState` tick. Until then we don't know
    /// whether the kernel has any active VPN interfaces, so the
    /// real-IP cache gate must withhold trust on the first
    /// telemetry sample. Without this flag, vortix opened while a
    /// VPN is already up races: telemetry returns the VPN's exit
    /// IP, the registry is briefly empty (adoption hasn't run
    /// yet), and the wrong IP gets cached as `real_ip`.
    pub scanner_first_tick_done: bool,

    /// Number of kernel-visible VPN sessions observed at the most
    /// recent scanner tick. Reading raw kernel state (not the
    /// registry) catches tunnels that have not yet been adopted —
    /// e.g. an OVPN process running outside vortix on macOS where
    /// adoption needs the lsof Method A probe to attribute the
    /// iface to the PID. Real-IP caching requires this to be zero.
    pub last_kernel_session_count: usize,

    // === Configuration ===
    pub config: AppConfig,
    pub config_dir: PathBuf,
    pub is_root: bool,

    // === Connection Management ===
    pub connection_drops: u32,
    pub pending_connect: Option<usize>,
    pub sort_order: ProfileSortOrder,

    // === Kill Switch ===
    pub killswitch_mode: KillSwitchMode,
    pub killswitch_state: KillSwitchState,
    /// Fresh platform read-back proof for the current Blocking state.
    pub killswitch_verification: Option<crate::core::killswitch::FirewallVerification>,
    /// Bounds retries after a persistent platform mutation/read-back failure.
    killswitch_last_verification_attempt_ms: Option<u64>,

    /// Full desired/effective resolver policy owned by the global network
    /// policy path. Protocol adapters only populate `dns_requests`.
    pub dns_policy: crate::vortix_core::ports::dns::DnsPolicyCoordinator,
    dns_requests: HashMap<ProfileId, crate::vortix_core::ports::dns::DnsRequest>,
    persist_dns_policy: bool,
    dns_policy_worker: Option<crate::core::dns_policy::DnsPolicyWorker>,
    dns_policy_revision: u64,
    dns_policy_completed_revision: u64,
    dns_last_scheduled: Option<DnsSchedule>,
    /// Scanner-visible sessions for which this process has no protocol handle.
    pub dns_external_sessions: usize,
    /// False after a route probe failure; the prior registry primary is retained.
    pub route_observation_fresh: bool,

    // === Connection Retry & Auto-Reconnect ===
    /// Per-profile retry / auto-reconnect bookkeeping.
    /// Replaces the single-slot retry triple. Each profile retries
    /// independently — a failed connect on A no longer blocks or
    /// overwrites an in-flight retry on B.
    pub retry_state: HashMap<ProfileId, RetryState>,

    // === Async Communication ===
    pub(crate) telemetry_rx: Option<mpsc::Receiver<TelemetryUpdate>>,
    pub telemetry_nudge: Option<mpsc::Sender<()>>,
    pub(crate) cmd_tx: mpsc::Sender<Message>,
    pub(crate) cmd_rx: mpsc::Receiver<Message>,
    pub(crate) scanner_rx: Option<mpsc::Receiver<crate::core::scanner::ScannerResult>>,
    pub(crate) netmon_rx: Option<mpsc::Receiver<NetworkEvent>>,
    pub(crate) netstats_rx: Option<mpsc::Receiver<(u64, u64)>>,
    pub(crate) last_bytes_in: u64,
    pub(crate) last_bytes_out: u64,
}

impl VpnRuntime {
    /// Create an engine with background workers (telemetry, scanner, network monitor).
    ///
    /// Use this constructor when the engine will be long-lived (TUI mode).
    #[must_use]
    pub fn new(config: AppConfig, config_dir: PathBuf) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel::<Message>();
        let history_size = constants::NETWORK_HISTORY_SIZE;

        let mut engine = Self {
            profiles: Vec::new(),
            profile_presence: HashMap::new(),
            session_start: None,

            down_history: VecDeque::from(vec![0.0; history_size]),
            up_history: VecDeque::from(vec![0.0; history_size]),
            current_down: 0,
            current_up: 0,
            latency_ms: 0,
            packet_loss: 0.0,
            jitter_ms: 0,
            location: constants::MSG_DETECTING.to_string(),
            isp: constants::MSG_DETECTING.to_string(),
            dns_server: constants::MSG_DETECTING.to_string(),
            dns_leak: crate::core::dns_leak::DnsLeakStatus::Unknown,

            public_ip: constants::MSG_DETECTING.to_string(),
            real_ip: None,
            public_ipv6: None,
            real_ipv6: None,
            last_security_check: None,
            ip_unchanged_warned: false,
            last_connected_profile: None,
            scanner_first_tick_done: false,
            last_kernel_session_count: 0,

            config,
            config_dir,
            is_root: utils::is_root(),

            connection_drops: 0,
            pending_connect: None,
            sort_order: ProfileSortOrder::default(),

            killswitch_mode: KillSwitchMode::default(),
            killswitch_state: KillSwitchState::default(),
            killswitch_verification: None,
            killswitch_last_verification_attempt_ms: None,
            dns_policy: crate::vortix_core::ports::dns::DnsPolicyCoordinator::default(),
            dns_requests: HashMap::new(),
            persist_dns_policy: true,
            dns_policy_worker: None,
            dns_policy_revision: 0,
            dns_policy_completed_revision: 0,
            dns_last_scheduled: None,
            dns_external_sessions: 0,
            route_observation_fresh: false,

            retry_state: HashMap::new(),

            telemetry_rx: None,
            telemetry_nudge: None,
            cmd_tx,
            cmd_rx,
            scanner_rx: None,
            netmon_rx: None,
            netstats_rx: None,
            last_bytes_in: 0,
            last_bytes_out: 0,
        };

        // Recover kill switch state from crash
        if let Some(persisted) = crate::core::killswitch::load_state() {
            engine.killswitch_mode = persisted.mode;
            if persisted.state == KillSwitchState::Blocking {
                // A persisted blocking request is not fresh proof, but its
                // kernel policy may still be the only fail-closed barrier.
                // Keep it in place and report unverified/watching until the
                // next synchronization applies and reads back the policy.
                engine.killswitch_state = KillSwitchState::Degraded;
            } else {
                engine.killswitch_state = persisted.state;
            }
        }
        if let Some(persisted) = crate::core::dns_policy::load(&engine.config_dir) {
            engine.dns_policy = persisted;
        }

        // Restore the cached real IPv4 / IPv6 / DNS — handles launch-with-VPN-up.
        if let Some(cached) = crate::core::real_ip_cache::load(&engine.config_dir) {
            engine.real_ip = Some(cached.ip);
        }
        if let Some(cached) = crate::core::real_ip_cache::load_ipv6(&engine.config_dir) {
            engine.real_ipv6 = Some(cached.ip);
        }

        // Load profiles
        engine.profiles = crate::vpn::load_profiles();

        // Start background workers
        engine.start_background_workers();

        engine
    }

    /// Create a lightweight engine without background workers.
    ///
    /// Use this for CLI one-shot commands (status, list, import, etc.) where
    /// you don't need continuous telemetry or scanner polling.
    #[must_use]
    pub fn new_headless(config: AppConfig, config_dir: PathBuf) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel::<Message>();
        let history_size = constants::NETWORK_HISTORY_SIZE;

        let mut engine = Self {
            profiles: Vec::new(),
            profile_presence: HashMap::new(),
            session_start: None,

            down_history: VecDeque::from(vec![0.0; history_size]),
            up_history: VecDeque::from(vec![0.0; history_size]),
            current_down: 0,
            current_up: 0,
            latency_ms: 0,
            packet_loss: 0.0,
            jitter_ms: 0,
            location: String::new(),
            isp: String::new(),
            dns_server: String::new(),
            dns_leak: crate::core::dns_leak::DnsLeakStatus::Unknown,

            public_ip: String::new(),
            real_ip: None,
            public_ipv6: None,
            real_ipv6: None,
            last_security_check: None,
            ip_unchanged_warned: false,
            last_connected_profile: None,
            scanner_first_tick_done: false,
            last_kernel_session_count: 0,

            config,
            config_dir,
            is_root: utils::is_root(),

            connection_drops: 0,
            pending_connect: None,
            sort_order: ProfileSortOrder::default(),

            killswitch_mode: KillSwitchMode::default(),
            killswitch_state: KillSwitchState::default(),
            killswitch_verification: None,
            killswitch_last_verification_attempt_ms: None,
            dns_policy: crate::vortix_core::ports::dns::DnsPolicyCoordinator::default(),
            dns_requests: HashMap::new(),
            persist_dns_policy: true,
            dns_policy_worker: None,
            dns_policy_revision: 0,
            dns_policy_completed_revision: 0,
            dns_last_scheduled: None,
            dns_external_sessions: 0,
            route_observation_fresh: false,

            retry_state: HashMap::new(),

            telemetry_rx: None,
            telemetry_nudge: None,
            cmd_tx,
            cmd_rx,
            scanner_rx: None,
            netmon_rx: None,
            netstats_rx: None,
            last_bytes_in: 0,
            last_bytes_out: 0,
        };

        // Recover kill switch state
        if let Some(persisted) = crate::core::killswitch::load_state() {
            engine.killswitch_mode = persisted.mode;
            if persisted.state == KillSwitchState::Blocking {
                engine.killswitch_state = KillSwitchState::Degraded;
            } else {
                engine.killswitch_state = persisted.state;
            }
        }
        if let Some(persisted) = crate::core::dns_policy::load(&engine.config_dir) {
            engine.dns_policy = persisted;
        }

        engine.profiles = crate::vpn::load_profiles();

        engine
    }

    /// Lightweight constructor for testing — no background threads, no disk I/O.
    #[must_use]
    pub fn new_test() -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel::<Message>();
        let history_size = constants::NETWORK_HISTORY_SIZE;
        Self {
            profiles: Vec::new(),
            profile_presence: HashMap::new(),
            session_start: None,
            down_history: VecDeque::from(vec![0.0; history_size]),
            up_history: VecDeque::from(vec![0.0; history_size]),
            current_down: 0,
            current_up: 0,
            latency_ms: 0,
            packet_loss: 0.0,
            jitter_ms: 0,
            location: String::new(),
            isp: String::new(),
            dns_server: String::new(),
            dns_leak: crate::core::dns_leak::DnsLeakStatus::Unknown,
            public_ip: String::new(),
            real_ip: None,
            public_ipv6: None,
            real_ipv6: None,
            last_security_check: None,
            ip_unchanged_warned: false,
            last_connected_profile: None,
            scanner_first_tick_done: false,
            last_kernel_session_count: 0,
            config: AppConfig::default(),
            config_dir: std::env::temp_dir().join("vortix_test"),
            is_root: false,
            connection_drops: 0,
            pending_connect: None,
            sort_order: ProfileSortOrder::default(),
            killswitch_mode: KillSwitchMode::Off,
            killswitch_state: KillSwitchState::Disabled,
            killswitch_verification: None,
            killswitch_last_verification_attempt_ms: None,
            dns_policy: crate::vortix_core::ports::dns::DnsPolicyCoordinator::default(),
            dns_requests: HashMap::new(),
            persist_dns_policy: false,
            dns_policy_worker: None,
            dns_policy_revision: 0,
            dns_policy_completed_revision: 0,
            dns_last_scheduled: None,
            dns_external_sessions: 0,
            route_observation_fresh: false,
            retry_state: HashMap::new(),
            telemetry_rx: None,
            telemetry_nudge: None,
            cmd_tx,
            cmd_rx,
            scanner_rx: None,
            netmon_rx: None,
            netstats_rx: None,
            last_bytes_in: 0,
            last_bytes_out: 0,
        }
    }

    /// Start background workers for telemetry, scanning, and network monitoring.
    pub fn start_background_workers(&mut self) {
        let telemetry_config = telemetry::TelemetryConfig::from(&self.config);
        let (telem_rx, telem_nudge) = telemetry::spawn_telemetry_worker(telemetry_config);
        self.telemetry_rx = Some(telem_rx);
        self.telemetry_nudge = Some(telem_nudge);

        let netmon_rx = crate::core::network_monitor::spawn_network_monitor(
            std::time::Duration::from_secs(constants::NETWORK_MONITOR_POLL_SECS),
        );
        self.netmon_rx = Some(netmon_rx);
        self.start_dns_policy_worker();
    }

    fn start_dns_policy_worker(&mut self) {
        if self.dns_policy_worker.is_none() {
            self.dns_policy_worker = Some(crate::core::dns_policy::DnsPolicyWorker::spawn(
                self.dns_policy.clone(),
                self.cmd_tx.clone(),
            ));
        }
    }

    #[cfg(test)]
    pub(crate) fn start_dns_policy_worker_for_test(&mut self) {
        self.start_dns_policy_worker();
    }

    /// Wake the telemetry worker so it refreshes IP/ISP/latency immediately.
    pub fn refresh_telemetry(&self) {
        if let Some(nudge) = &self.telemetry_nudge {
            let _ = nudge.send(());
        }
    }

    pub fn remember_dns_request(
        &mut self,
        profile_name: &str,
        request: crate::vortix_core::ports::dns::DnsRequest,
    ) {
        if let Some(profile) = self
            .profiles
            .iter()
            .find(|profile| profile.name == profile_name)
        {
            self.dns_requests.insert(profile.id.clone(), request);
        }
    }

    pub fn forget_dns_request(&mut self, profile_name: &str) {
        if let Some(profile) = self
            .profiles
            .iter()
            .find(|profile| profile.name == profile_name)
        {
            self.dns_requests.remove(&profile.id);
        }
    }

    #[must_use]
    pub fn owns_dns_session(&self, profile_id: &ProfileId) -> bool {
        self.dns_requests.contains_key(profile_id)
    }

    fn dns_intents(
        &self,
        observations: &[DnsObservation],
    ) -> Vec<crate::vortix_core::ports::dns::DnsTunnelIntent> {
        use crate::vortix_core::ports::dns::{DnsTunnelIntent, DnsTunnelRole};

        observations
            .iter()
            .filter_map(|(profile_id, interface, is_primary)| {
                // A scanner match or a persisted profile is not ownership.
                // Only a live protocol-layer success in this process installs
                // a request and authorizes platform DNS mutation.
                let request = self.dns_requests.get(profile_id)?.clone();
                Some(DnsTunnelIntent {
                    profile_id: profile_id.clone(),
                    interface: interface.clone(),
                    role: if *is_primary {
                        DnsTunnelRole::Primary
                    } else {
                        DnsTunnelRole::Secondary
                    },
                    request,
                })
            })
            .collect()
    }

    /// Recompute one complete policy from kernel-derived roles. The tuple is
    /// `(profile name, kernel interface, is primary)`.
    pub fn reconcile_dns_observations(
        &mut self,
        observations: &[DnsObservation],
    ) -> crate::vortix_core::ports::dns::DnsEffectiveState {
        let intents = self.dns_intents(observations);
        let _lock = match crate::core::dns_policy::acquire_policy_lock(&self.config_dir) {
            Ok(lock) => lock,
            Err(error) => {
                self.dns_policy
                    .invalidate_effective(format!("DNS policy lock failed: {error}"));
                tracing::error!(target: "vortix::dns", error = %error, "DNS policy lock failed");
                return self.dns_policy.effective().clone();
            }
        };
        let adapter = &crate::platform::current_platform().dns;
        let result = if self.persist_dns_policy {
            let config_dir = self.config_dir.clone();
            self.dns_policy
                .reconcile_durable(&intents, adapter, |coordinator| {
                    crate::core::dns_policy::save(&config_dir, coordinator)
                })
        } else {
            self.dns_policy.reconcile(&intents, adapter)
        };
        if let Err(error) = result {
            tracing::error!(target: "vortix::dns", error = %error, "DNS policy rejected");
        }
        self.dns_policy.effective().clone()
    }

    /// Queue a latest-wins reconciliation for the long-lived TUI. Returns
    /// immediately; platform probes, lock waits and persistence happen on the
    /// single DNS policy worker.
    pub fn schedule_dns_observations(
        &mut self,
        observations: &[DnsObservation],
        external_sessions: usize,
    ) -> Result<u64, String> {
        let same_topology = self.dns_last_scheduled.as_ref().is_some_and(
            |(previous, previous_external, scheduled_at)| {
                previous == observations
                    && *previous_external == external_sessions
                    && (self.dns_policy.effective().status
                        == crate::vortix_core::ports::dns::DnsEffectiveStatus::Degraded
                        || scheduled_at.elapsed() < std::time::Duration::from_secs(5))
            },
        );
        if same_topology {
            return Ok(self.dns_policy_revision);
        }
        let intents = self.dns_intents(observations);
        self.dns_policy_revision = self.dns_policy_revision.saturating_add(1);
        let revision = self.dns_policy_revision;
        let Some(worker) = &self.dns_policy_worker else {
            return Err("DNS policy worker is unavailable".into());
        };
        worker.schedule(crate::core::dns_policy::DnsPolicyWork {
            revision,
            intents,
            external_sessions,
            config_dir: self.config_dir.clone(),
            persist: self.persist_dns_policy,
        })?;
        self.dns_last_scheduled = Some((observations.to_vec(), external_sessions, Instant::now()));
        Ok(revision)
    }

    /// Accept a worker completion unless it predates one already applied.
    pub fn complete_dns_policy(
        &mut self,
        revision: u64,
        coordinator: crate::vortix_core::ports::dns::DnsPolicyCoordinator,
        external_sessions: usize,
    ) -> bool {
        if revision < self.dns_policy_completed_revision {
            return false;
        }
        self.dns_policy_completed_revision = revision;
        self.dns_policy = coordinator;
        self.dns_external_sessions = external_sessions;
        true
    }

    /// Headless CLI reconciliation uses the same scanner route truth as the
    /// kill-switch path; no CLI-local primary heuristic is retained.
    pub fn reconcile_dns_from_scanner(
        &mut self,
    ) -> crate::vortix_core::ports::dns::DnsEffectiveState {
        let scan = crate::core::scanner::gather_system_state(&self.profiles);
        let route_interface = match scan.default_route {
            crate::vortix_core::ports::route_table::DefaultRouteObservation::Interface(
                interface,
            ) => Some(interface),
            crate::vortix_core::ports::route_table::DefaultRouteObservation::NoDefaultRoute => None,
            crate::vortix_core::ports::route_table::DefaultRouteObservation::ProbeFailed => {
                self.route_observation_fresh = false;
                self.dns_policy.invalidate_effective(
                    "default-route probe failed; retaining prior DNS topology",
                );
                return self.dns_policy.effective().clone();
            }
        };
        self.route_observation_fresh = true;
        let external_sessions = scan
            .sessions
            .iter()
            .filter(|session| {
                self.profiles
                    .iter()
                    .find(|profile| profile.name == session.name)
                    .is_none_or(|profile| !self.owns_dns_session(&profile.id))
            })
            .count();
        let observations = scan
            .sessions
            .into_iter()
            .filter_map(|session| {
                let profile_id = self
                    .profiles
                    .iter()
                    .find(|profile| profile.name == session.name)?
                    .id
                    .clone();
                let primary = route_interface.as_deref() == Some(session.interface.as_str());
                Some((profile_id, session.interface, primary))
            })
            .collect::<Vec<_>>();
        self.dns_external_sessions = external_sessions;
        if external_sessions > 0 {
            self.dns_policy
                .invalidate_effective("external VPN session observed; DNS ownership is unknown");
            return self.dns_policy.effective().clone();
        }
        self.reconcile_dns_observations(&observations)
    }

    /// Find a profile by name, returning its index.
    #[must_use]
    pub fn find_profile(&self, name: &str) -> Option<usize> {
        self.profiles.iter().position(|p| p.name == name)
    }

    /// Sort profiles according to the current `sort_order`.
    pub fn sort_profiles(&mut self) {
        match self.sort_order {
            ProfileSortOrder::NameAsc => {
                self.profiles.sort_by(|a, b| a.name.cmp(&b.name));
            }
            ProfileSortOrder::NameDesc => {
                self.profiles.sort_by(|a, b| b.name.cmp(&a.name));
            }
            ProfileSortOrder::LastUsed => {
                self.profiles.sort_by(|a, b| {
                    b.last_used
                        .unwrap_or(std::time::UNIX_EPOCH)
                        .cmp(&a.last_used.unwrap_or(std::time::UNIX_EPOCH))
                });
            }
            ProfileSortOrder::Protocol => {
                fn proto_rank(p: Protocol) -> u8 {
                    match p {
                        Protocol::WireGuard => 0,
                        Protocol::OpenVPN => 1,
                    }
                }
                self.profiles.sort_by(|a, b| {
                    proto_rank(a.protocol)
                        .cmp(&proto_rank(b.protocol))
                        .then_with(|| a.name.cmp(&b.name))
                });
            }
        }
    }

    /// Load profile metadata (`last_used` timestamps) from disk.
    pub fn load_metadata(&mut self) {
        if let Ok(metadata) = utils::load_profile_metadata() {
            for profile in &mut self.profiles {
                let key = profile.config_path.to_string_lossy().to_string();
                if let Some(meta) = metadata.get(&key) {
                    profile.last_used = meta.last_used;
                }
            }
        }
    }

    /// Save profile metadata to disk.
    pub fn save_metadata(&self) {
        use std::collections::HashMap;

        let mut metadata = HashMap::new();
        for profile in &self.profiles {
            let key = profile.config_path.to_string_lossy().to_string();
            metadata.insert(
                key,
                utils::ProfileMetadata {
                    last_used: profile.last_used,
                },
            );
        }

        let _ = utils::save_profile_metadata(&metadata);
    }

    /// Kill any running VPN process and remove run files for a profile.
    ///
    /// dispatch routes through the `TunnelKind` aggregate.
    pub fn cleanup_vpn_resources(
        &self,
        profile_name: &str,
    ) -> Result<(), crate::vortix_core::ports::tunnel::TunnelError> {
        let Some(profile) = self.profiles.iter().find(|p| p.name == profile_name) else {
            return Ok(());
        };
        let config_dir =
            utils::get_app_config_dir().unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));
        let mut tunnel = crate::tunnel::tunnel_for(profile.protocol, &config_dir, "3", 30);
        self.cleanup_vpn_resources_with(profile_name, &mut tunnel)
    }

    fn cleanup_vpn_resources_with(
        &self,
        profile_name: &str,
        tunnel: &mut crate::tunnel::TunnelKind,
    ) -> Result<(), crate::vortix_core::ports::tunnel::TunnelError> {
        use crate::vortix_core::ports::tunnel::{TunnelHandle, TunnelKindTag};
        if let Some(profile) = self.profiles.iter().find(|p| p.name == profile_name) {
            let iface = match profile.protocol {
                Protocol::WireGuard => profile
                    .config_path
                    .file_stem()
                    .and_then(std::ffi::OsStr::to_str)
                    .unwrap_or("wg0")
                    .to_string(),
                Protocol::OpenVPN => {
                    format!("openvpn-{}", utils::sanitize_profile_name(profile_name))
                }
            };
            let pid = match profile.protocol {
                Protocol::OpenVPN => {
                    utils::read_openvpn_pid_compat(profile.id.as_str(), profile_name)
                }
                Protocol::WireGuard => None,
            };
            let handle = TunnelHandle {
                profile_id: profile.id.clone(),
                display_name: profile.name.clone(),
                interface_name: iface,
                pid,
                started_at: std::time::SystemTime::now(),
                kind: match profile.protocol {
                    Protocol::WireGuard => TunnelKindTag::WireGuard,
                    Protocol::OpenVPN => TunnelKindTag::OpenVpn,
                },
                process_ownership: None,
                teardown_config: matches!(profile.protocol, Protocol::WireGuard).then(|| {
                    crate::vortix_core::ports::tunnel::TunnelTeardownConfig {
                        path: profile.config_path.clone(),
                        managed: false,
                    }
                }),
                dns_request: crate::vortix_core::ports::dns::DnsRequest::default(),
            };

            tunnel.down(handle)?;

            if matches!(profile.protocol, Protocol::OpenVPN) {
                utils::cleanup_openvpn_run_files_compat(profile.id.as_str(), profile_name);
            }
        }
        Ok(())
    }

    /// Build the `(is_connected, active_tunnels)` pair from the
    /// scanner's view of the kernel — every kernel-visible tunnel
    /// contributes one entry, regardless of which surface (TUI or
    /// CLI) initiated it. CLI-side callers feed this into
    /// `sync_killswitch` so the persisted slice always reflects every
    /// active tunnel, not just the one the current CLI invocation
    /// touched.
    ///
    /// Marks every entry as `is_primary: true` because the headless
    /// CLI has no registry-derived primary; the killswitch's
    /// firewall rules treat each Connected interface as a tunnel
    /// that must allow its server IP and DNS through. The TUI
    /// computes a multi-tunnel slice (`App::active_tunnels_for_killswitch`)
    /// with proper primary marking from registry state.
    #[must_use]
    pub fn killswitch_view_from_scanner(
        &self,
    ) -> (bool, Vec<crate::core::killswitch::ActiveTunnelInfo>) {
        let sessions = crate::core::scanner::get_active_profiles(&self.profiles);
        let is_connected = !sessions.is_empty();
        let active_tunnels = sessions
            .iter()
            .map(|s| crate::core::killswitch::ActiveTunnelInfo {
                interface: s.interface.clone(),
                server_ips: s
                    .endpoint
                    .split(':')
                    .next()
                    .and_then(|h| h.parse().ok())
                    .into_iter()
                    .collect(),
                declared_cidrs: Vec::new(),
                is_primary: true,
            })
            .collect();
        (is_connected, active_tunnels)
    }

    /// Synchronizes the kill switch state with the current mode and
    /// connection status.
    ///
    /// Plan P5d: callers compute `is_connected` and `active_tunnels`
    /// from their own state. App-side callers derive both from
    /// `app.registry`; CLI-side callers use
    /// [`Self::killswitch_view_from_scanner`] so every CLI lifecycle
    /// helper persists the full multi-tunnel slice, not a synthesised
    /// single-tunnel view that would clobber the on-disk state when
    /// another tunnel is still up.
    pub fn sync_killswitch(
        &mut self,
        is_connected: bool,
        active_tunnels: &[crate::core::killswitch::ActiveTunnelInfo],
    ) -> bool {
        let old_state = self.killswitch_state;

        // Pure mode → state decision lives on `KillSwitchMode` so it
        // can be unit-tested without firewall side effects. AlwaysOn
        // always resolves to Blocking — the firewall stays engaged
        // whether the VPN is up or down (canonical Linux killswitch
        // shape; see `tests/integration/killswitch.sh`).
        let mut requested_state = self.killswitch_mode.desired_state(old_state, is_connected);

        if requested_state.is_blocking() && !self.is_root {
            requested_state = KillSwitchState::Armed;
        }

        let mut firewall_result = None;
        if requested_state != old_state || requested_state == KillSwitchState::Blocking {
            self.killswitch_last_verification_attempt_ms = Some(current_unix_ms());
            if requested_state.is_blocking() {
                match crate::core::killswitch::enable_blocking_multi(active_tunnels) {
                    Ok(()) => firewall_result = Some(true),
                    Err(e) => {
                        firewall_result = Some(false);
                        logger::log(
                            logger::LogLevel::Warning,
                            "SEC",
                            format!(
                                "Kill switch policy was not verified; protection degraded: {e}"
                            ),
                        );
                    }
                }
            } else if needs_firewall_release(old_state, requested_state) {
                match crate::core::killswitch::disable_blocking() {
                    Ok(()) => firewall_result = Some(true),
                    Err(e) => {
                        firewall_result = Some(false);
                        logger::log(
                            logger::LogLevel::Warning,
                            "SEC",
                            format!("Kill switch release was not verified; state degraded: {e}"),
                        );
                    }
                }
            }
        }
        self.killswitch_state = effective_killswitch_state(requested_state, firewall_result);

        let persisted_tunnels = crate::core::killswitch::persisted_from_active(active_tunnels);
        let verification = (self.killswitch_state == KillSwitchState::Blocking
            && firewall_result == Some(true))
        .then(|| crate::core::killswitch::local_verification(active_tunnels));
        self.killswitch_verification.clone_from(&verification);
        if let Err(e) = crate::core::killswitch::save_state_with_verification(
            self.killswitch_mode,
            self.killswitch_state,
            persisted_tunnels,
            verification,
        ) {
            logger::log(
                logger::LogLevel::Warning,
                "SEC",
                format!("Failed to persist kill switch state: {e}"),
            );
        }
        firewall_result != Some(false)
    }

    /// Whether Blocking truth needs a new platform observation. Degraded
    /// state also retries so a transient apply/read-back failure can recover.
    #[must_use]
    pub fn killswitch_verification_needs_refresh(&self) -> bool {
        if !matches!(
            self.killswitch_state,
            KillSwitchState::Blocking | KillSwitchState::Degraded
        ) {
            return false;
        }
        let now_ms = current_unix_ms();
        if self
            .killswitch_last_verification_attempt_ms
            .is_some_and(|attempt| now_ms < attempt.saturating_add(5_000))
        {
            return false;
        }
        if self.killswitch_state == KillSwitchState::Degraded {
            return true;
        }
        self.killswitch_verification
            .as_ref()
            .is_none_or(|proof| proof.fresh_until_unix_ms <= now_ms)
    }

    /// Check if required binaries are available for a given protocol.
    ///
    /// Shared between TUI and CLI so both surfaces refuse the same
    /// missing-dep set (and run the same `OpenVPN` 2.4+ probe — older
    /// builds silently drop `--pull-filter`, breaking multi-tunnel DNS
    /// scoping).
    #[must_use]
    pub fn check_dependencies(protocol: Protocol, config_path: &std::path::Path) -> Vec<String> {
        let mut missing = Vec::new();
        match protocol {
            Protocol::WireGuard => {
                // Both `wg` and `wg-quick` ship in the wireguard-tools
                // package on every supported distro — report them under
                // a single label so the install hint isn't duplicated.
                if !utils::binary_exists("wg-quick") || !utils::binary_exists("wg") {
                    missing.push("wireguard-tools".to_string());
                }
                // On Linux, wg-quick uses `resolvconf` to set DNS when the
                // config contains a DNS directive. Two escape hatches:
                //   1. systemd-resolved + working `resolvectl` →
                //      `WgTunnel::up` takes over per-link DNS via
                //      `resolvectl` itself; no resolvconf shim needed.
                //   2. A working `resolvconf` (openresolv on non-resolved
                //      hosts; systemd-resolvconf shim on resolved hosts).
                //
                // Otherwise emit the missing-dep label with a hint at
                // which shim the user actually needs.
                #[cfg(target_os = "linux")]
                // xtask:allow-platform-cfg: resolvconf check is Linux-only DNS plumbing
                if let Some(label) = wireguard_dns_missing_dep(WireguardDnsGateInputs {
                    has_dns_directive: utils::wireguard_config_has_dns(config_path),
                    resolvectl_path_available: utils::use_resolvectl_path(),
                    resolvconf_works: utils::resolvconf_works(),
                    is_systemd_resolved: utils::is_systemd_resolved(),
                }) {
                    missing.push(label);
                }
                #[cfg(target_os = "linux")]
                // xtask:allow-platform-cfg: /proc sysctl gate is Linux-only (issue #242)
                if let Some(label) = wireguard_ipv6_missing_dep(
                    utils::wireguard_config_has_ipv6_address(config_path),
                    utils::host_ipv6_disabled,
                ) {
                    missing.push(label);
                }
                #[cfg(not(target_os = "linux"))]
                let _ = config_path; // suppress unused warning on non-Linux
            }
            Protocol::OpenVPN => {
                if utils::binary_exists("openvpn") {
                    // Assert OpenVPN ≥ 2.4 so `--pull-filter` (multi-tunnel
                    // DNS scoping) is available. Older builds silently
                    // ignore the flag and leak pushed DNS into the primary
                    // tunnel's resolver. Unparseable probe = fail-open with
                    // a tracing warning so vendor-patched or sandboxed
                    // environments aren't blocked.
                    use openvpn::OvpnVersionProbe;
                    match openvpn::probe_openvpn_version() {
                        OvpnVersionProbe::Parsed(v) if v.supports_multi_tunnel_dns() => {}
                        OvpnVersionProbe::Parsed(v) => {
                            missing.push(format!(
                                "openvpn 2.4+ required for multi-tunnel DNS scoping (found {v})"
                            ));
                        }
                        OvpnVersionProbe::HelpFallbackOk => {}
                        OvpnVersionProbe::Unparseable => {
                            tracing::warn!(
                                target: "vortix::vpn_runtime",
                                "openvpn version could not be determined; \
                                 multi-tunnel DNS scoping may not work if the \
                                 installed binary is older than 2.4"
                            );
                        }
                    }
                } else {
                    missing.push("openvpn".to_string());
                }
            }
        }
        missing
    }
}

/// Inputs to the `WireGuard` DNS-shim missing-dep decision. Wrapping the
/// four booleans in a struct keeps the call-site readable (named fields)
/// and dodges the `fn_params_excessive_bools` lint while staying purely
/// declarative — no behavior moves into the struct itself.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_excessive_bools)] // intentional flag record; mirrors TunnelCapabilities
#[cfg(target_os = "linux")] // xtask:allow-platform-cfg: WG DNS-shim gate is Linux-only
pub(crate) struct WireguardDnsGateInputs {
    pub has_dns_directive: bool,
    pub resolvectl_path_available: bool,
    pub resolvconf_works: bool,
    pub is_systemd_resolved: bool,
}

/// Pure decision logic for the `WireGuard` DNS-shim missing-dep label on Linux.
///
/// Returns `Some(label)` when the user must install a DNS-management shim,
/// `None` when the connect can proceed. Split out so the four-quadrant
/// gate can be unit-tested without depending on host state (each input
/// helper — `is_systemd_resolved`, `resolvconf_works`, `resolvectl_works`
/// — probes real OS state and would make these tests host-dependent).
#[must_use]
#[cfg(target_os = "linux")] // xtask:allow-platform-cfg: gate decision is Linux-only DNS plumbing
pub(crate) fn wireguard_dns_missing_dep(inputs: WireguardDnsGateInputs) -> Option<String> {
    if !inputs.has_dns_directive {
        return None;
    }
    if inputs.resolvectl_path_available {
        return None;
    }
    if inputs.resolvconf_works {
        return None;
    }
    Some(
        if inputs.is_systemd_resolved {
            "resolvconf (systemd)"
        } else {
            "resolvconf"
        }
        .to_string(),
    )
}

/// Pure decision logic for the host-IPv6 pre-flight gate on Linux (#242).
///
/// `wg-quick` runs `ip -6 address add` for each IPv6 entry on the
/// profile's `Address =` line, which aborts the whole bring-up when
/// kernel IPv6 is disabled. Refuse up front instead of surfacing raw
/// wg-quick stderr; never silently strip the user's IPv6 entry.
///
/// The host probe is a closure so its `/proc` reads only happen for
/// profiles that actually declare an IPv6 address.
#[must_use]
#[cfg(target_os = "linux")] // xtask:allow-platform-cfg: gate decision is Linux-only (issue #242)
pub(crate) fn wireguard_ipv6_missing_dep(
    profile_has_ipv6_address: bool,
    host_ipv6_disabled: impl FnOnce() -> bool,
) -> Option<String> {
    (profile_has_ipv6_address && host_ipv6_disabled())
        .then(|| "host IPv6 (kernel disabled)".to_string())
}

impl Drop for VpnRuntime {
    fn drop(&mut self) {
        // VPN connections are independent OS processes (wg-quick, openvpn) that
        // should survive UI process exit. Only explicit user actions (disconnect
        // button, `vortix down`) should tear them down. This matches the TUI's
        // confirm dialog: "VPN connection may still be active. Quit anyway?"
        //
        // Kill switch firewall rules also persist — the next launch recovers
        // them via `load_state()`.
    }
}

#[cfg(test)]
mod killswitch_truth_tests {
    use super::{effective_killswitch_state, needs_firewall_release, KillSwitchState};

    #[test]
    fn failed_apply_or_readback_never_retains_blocking_truth() {
        assert_eq!(
            effective_killswitch_state(KillSwitchState::Blocking, Some(false)),
            KillSwitchState::Degraded
        );
    }

    #[test]
    fn verified_and_noop_transitions_keep_the_requested_state() {
        assert_eq!(
            effective_killswitch_state(KillSwitchState::Blocking, Some(true)),
            KillSwitchState::Blocking
        );
        assert_eq!(
            effective_killswitch_state(KillSwitchState::Disabled, None),
            KillSwitchState::Disabled
        );
    }

    #[test]
    fn degraded_prior_policy_retries_release_until_verified() {
        assert!(needs_firewall_release(
            KillSwitchState::Degraded,
            KillSwitchState::Disabled
        ));
        assert!(needs_firewall_release(
            KillSwitchState::Degraded,
            KillSwitchState::Armed
        ));
        assert!(!needs_firewall_release(
            KillSwitchState::Degraded,
            KillSwitchState::Blocking
        ));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod dns_gate_tests {
    use super::{wireguard_dns_missing_dep, WireguardDnsGateInputs};

    #[allow(clippy::fn_params_excessive_bools)] // test fixture mirrors the WireguardDnsGateInputs shape
    fn inputs(
        has_dns_directive: bool,
        resolvectl_path_available: bool,
        resolvconf_works: bool,
        is_systemd_resolved: bool,
    ) -> WireguardDnsGateInputs {
        WireguardDnsGateInputs {
            has_dns_directive,
            resolvectl_path_available,
            resolvconf_works,
            is_systemd_resolved,
        }
    }

    #[test]
    fn no_dns_directive_returns_none_regardless_of_host_state() {
        // Every host-state combination with `has_dns = false` must return None.
        for resolvectl in [false, true] {
            for resolvconf in [false, true] {
                for resolved in [false, true] {
                    assert_eq!(
                        wireguard_dns_missing_dep(inputs(false, resolvectl, resolvconf, resolved)),
                        None,
                        "has_dns=false resolvectl={resolvectl} resolvconf={resolvconf} resolved={resolved}"
                    );
                }
            }
        }
    }

    #[test]
    fn resolved_with_resolvectl_returns_none() {
        // The headline behaviour change: a resolved host with a working
        // resolvectl no longer needs a resolvconf shim, even when the
        // .conf carries `DNS = ...`.
        assert_eq!(
            wireguard_dns_missing_dep(inputs(true, true, false, true)),
            None
        );
    }

    #[test]
    fn resolved_without_resolvectl_falls_back_to_systemd_label() {
        // Edge case: resolved is detected but resolvectl probe fails
        // (service crashed, broken systemd install). The user genuinely
        // needs the `systemd-resolvconf` shim; emit the resolved-flavoured
        // missing-dep label.
        assert_eq!(
            wireguard_dns_missing_dep(inputs(true, false, false, true)),
            Some("resolvconf (systemd)".to_string())
        );
    }

    #[test]
    fn non_resolved_without_resolvconf_returns_plain_label() {
        // Classic missing-resolvconf on a non-resolved Linux host.
        assert_eq!(
            wireguard_dns_missing_dep(inputs(true, false, false, false)),
            Some("resolvconf".to_string())
        );
    }

    #[test]
    fn non_resolved_with_resolvconf_returns_none() {
        // Ubuntu / Debian-shaped happy path: resolvconf is installed and
        // the host doesn't use systemd-resolved. Unchanged from today.
        assert_eq!(
            wireguard_dns_missing_dep(inputs(true, false, true, false)),
            None
        );
    }

    #[test]
    fn resolved_with_both_paths_prefers_resolvectl_over_resolvconf() {
        // Belt-and-braces: even if resolvconf is also installed, the
        // resolvectl path takes precedence. This avoids double-management
        // surprises and matches the WgTunnel::up wiring (which always
        // uses resolvectl when use_resolvectl_path() is true).
        assert_eq!(
            wireguard_dns_missing_dep(inputs(true, true, true, true)),
            None
        );
    }
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    use crate::vortix_core::ports::tunnel::mock::{MockTunnel, ScriptedTunnelOutcome};

    #[test]
    fn cleanup_propagates_teardown_failure_instead_of_claiming_disconnect() {
        let mut runtime = VpnRuntime::new_test();
        runtime.profiles.push(crate::state::VpnProfile {
            id: crate::vortix_core::profile::ProfileId::new("cleanup-failure"),
            name: "cleanup-failure".into(),
            protocol: Protocol::WireGuard,
            config_path: "/tmp/cleanup-failure.conf".into(),
            location: "Test".into(),
            last_used: None,
        });
        let mock = MockTunnel::new();
        mock.script_down(ScriptedTunnelOutcome::Failure(
            "injected teardown failure".into(),
        ));
        let calls = mock.invocations();
        let mut tunnel = crate::tunnel::TunnelKind::Mock(mock);

        let error = runtime
            .cleanup_vpn_resources_with("cleanup-failure", &mut tunnel)
            .expect_err("teardown failure must remain observable");

        assert!(error.to_string().contains("injected teardown failure"));
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert_eq!(calls.lock().unwrap()[0].method, "down");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod ipv6_gate_tests {
    use super::wireguard_ipv6_missing_dep;

    #[test]
    fn fires_only_when_profile_declares_v6_and_host_disabled() {
        assert_eq!(
            wireguard_ipv6_missing_dep(true, || true),
            Some("host IPv6 (kernel disabled)".to_string())
        );
    }

    #[test]
    fn silent_when_profile_is_v4_only() {
        assert_eq!(wireguard_ipv6_missing_dep(false, || true), None);
    }

    #[test]
    fn silent_when_host_ipv6_enabled() {
        assert_eq!(wireguard_ipv6_missing_dep(true, || false), None);
    }

    #[test]
    fn silent_when_neither() {
        assert_eq!(wireguard_ipv6_missing_dep(false, || false), None);
    }

    #[test]
    fn host_probe_not_evaluated_for_v4_only_profiles() {
        let called = std::cell::Cell::new(false);
        let result = wireguard_ipv6_missing_dep(false, || {
            called.set(true);
            true
        });
        assert_eq!(result, None);
        assert!(!called.get(), "host probe ran for a v4-only profile");
    }

    #[test]
    fn label_maps_to_the_sysctl_hint_not_the_generic_package_fallback() {
        // The label lives here; the hint arm lives in platform::install_hint.
        // Pin the pair so a rename on either side fails loudly instead of
        // rendering "sudo apt install host IPv6 (kernel disabled)".
        let label = wireguard_ipv6_missing_dep(true, || true).unwrap();
        let hint = crate::platform::install_hint(&label);
        assert!(
            hint.contains("sysctl"),
            "hint fell back to generic package install: {hint}"
        );
    }
}
