//! Headless VPN engine — owns all VPN state and operations.
//!
//! `VpnEngine` holds connection lifecycle, profiles, telemetry data, kill switch
//! state, retry logic, and background worker channels. It has **zero** ratatui
//! dependencies, making it usable from both the TUI ([`crate::app::App`]) and
//! the CLI without pulling in any terminal rendering code.
//!
//! The TUI embeds `VpnEngine` inside `App` via `Deref`/`DerefMut`, so all
//! existing field accesses (`self.profiles`, `app.connection_state`, …) resolve
//! transparently through the engine.

pub mod connection;

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Instant;

use crate::config::AppConfig;
use crate::constants;
use crate::core::network_monitor::NetworkEvent;
use crate::core::scanner::ActiveSession;
use crate::core::telemetry::{self, TelemetryUpdate};
use crate::logger;
use crate::message::Message;
use crate::state::{
    ConnectionState, KillSwitchMode, KillSwitchState, ProfileSortOrder, Protocol, VpnProfile,
};
use crate::utils;

/// Core VPN engine — all VPN-related state, no UI dependencies.
///
/// Created by [`VpnEngine::new`] for TUI use (spawns background workers) or
/// [`VpnEngine::new_headless`] for CLI one-shot commands (no background threads).
#[allow(clippy::struct_excessive_bools)]
pub struct VpnEngine {
    // === VPN State ===
    pub connection_state: ConnectionState,
    pub profiles: Vec<VpnProfile>,
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
    pub ipv6_leak: bool,

    // === System Info ===
    pub public_ip: String,
    pub real_ip: Option<String>,
    pub real_dns: Option<String>,
    pub last_security_check: Option<Instant>,
    pub ip_unchanged_warned: bool,
    pub last_connected_profile: Option<String>,

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

    // === Connection Retry & Auto-Reconnect ===
    pub retry_count: u32,
    pub retry_profile_idx: Option<usize>,
    pub auto_reconnect_profile: Option<usize>,

    // === Async Communication ===
    pub(crate) telemetry_rx: Option<mpsc::Receiver<TelemetryUpdate>>,
    pub(crate) telemetry_nudge: Option<mpsc::Sender<()>>,
    pub(crate) cmd_tx: mpsc::Sender<Message>,
    pub(crate) cmd_rx: mpsc::Receiver<Message>,
    pub(crate) scanner_rx: Option<mpsc::Receiver<Vec<ActiveSession>>>,
    pub(crate) netmon_rx: Option<mpsc::Receiver<NetworkEvent>>,
    pub(crate) netstats_rx: Option<mpsc::Receiver<(u64, u64)>>,
    pub(crate) last_bytes_in: u64,
    pub(crate) last_bytes_out: u64,
}

impl VpnEngine {
    /// Create an engine with background workers (telemetry, scanner, network monitor).
    ///
    /// Use this constructor when the engine will be long-lived (TUI mode).
    #[must_use]
    pub fn new(config: AppConfig, config_dir: PathBuf) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel::<Message>();
        let history_size = constants::NETWORK_HISTORY_SIZE;

        let mut engine = Self {
            connection_state: ConnectionState::Disconnected,
            profiles: Vec::new(),
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
            ipv6_leak: false,

            public_ip: constants::MSG_DETECTING.to_string(),
            real_ip: None,
            real_dns: None,
            last_security_check: None,
            ip_unchanged_warned: false,
            last_connected_profile: None,

            config,
            config_dir,
            is_root: utils::is_root(),

            connection_drops: 0,
            pending_connect: None,
            sort_order: ProfileSortOrder::default(),

            killswitch_mode: KillSwitchMode::default(),
            killswitch_state: KillSwitchState::default(),

            retry_count: 0,
            retry_profile_idx: None,
            auto_reconnect_profile: None,

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
                let _ = crate::core::killswitch::disable_blocking();
                engine.killswitch_state = KillSwitchState::Disabled;
                crate::core::killswitch::clear_state();
            } else {
                engine.killswitch_state = persisted.state;
            }
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
            connection_state: ConnectionState::Disconnected,
            profiles: Vec::new(),
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
            ipv6_leak: false,

            public_ip: String::new(),
            real_ip: None,
            real_dns: None,
            last_security_check: None,
            ip_unchanged_warned: false,
            last_connected_profile: None,

            config,
            config_dir,
            is_root: utils::is_root(),

            connection_drops: 0,
            pending_connect: None,
            sort_order: ProfileSortOrder::default(),

            killswitch_mode: KillSwitchMode::default(),
            killswitch_state: KillSwitchState::default(),

            retry_count: 0,
            retry_profile_idx: None,
            auto_reconnect_profile: None,

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
                let _ = crate::core::killswitch::disable_blocking();
                engine.killswitch_state = KillSwitchState::Disabled;
                crate::core::killswitch::clear_state();
            } else {
                engine.killswitch_state = persisted.state;
            }
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
            connection_state: ConnectionState::Disconnected,
            profiles: Vec::new(),
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
            ipv6_leak: false,
            public_ip: String::new(),
            real_ip: None,
            real_dns: None,
            last_security_check: None,
            ip_unchanged_warned: false,
            last_connected_profile: None,
            config: AppConfig::default(),
            config_dir: std::env::temp_dir().join("vortix_test"),
            is_root: false,
            connection_drops: 0,
            pending_connect: None,
            sort_order: ProfileSortOrder::default(),
            killswitch_mode: KillSwitchMode::Off,
            killswitch_state: KillSwitchState::Disabled,
            retry_count: 0,
            retry_profile_idx: None,
            auto_reconnect_profile: None,
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
    }

    /// Wake the telemetry worker so it refreshes IP/ISP/latency immediately.
    pub fn refresh_telemetry(&self) {
        if let Some(nudge) = &self.telemetry_nudge {
            let _ = nudge.send(());
        }
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
    pub fn cleanup_vpn_resources(&self, profile_name: &str) {
        if let Some(profile) = self.profiles.iter().find(|p| p.name == profile_name) {
            match profile.protocol {
                Protocol::OpenVPN => {
                    if let Some(pid) = utils::read_openvpn_pid(profile_name) {
                        let _ = std::process::Command::new("kill")
                            .arg(pid.to_string())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .output();
                    }
                    utils::cleanup_openvpn_run_files(profile_name);
                }
                Protocol::WireGuard => {
                    let _ = std::process::Command::new("wg-quick")
                        .args(["down", profile.config_path.to_str().unwrap_or("")])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .output();
                }
            }
        }
    }

    /// Synchronizes the kill switch state with the current mode and connection status.
    pub fn sync_killswitch(&mut self) {
        let old_state = self.killswitch_state;

        self.killswitch_state = match self.killswitch_mode {
            KillSwitchMode::Off => KillSwitchState::Disabled,
            KillSwitchMode::Auto => {
                if matches!(self.connection_state, ConnectionState::Connected { .. }) {
                    KillSwitchState::Armed
                } else if old_state == KillSwitchState::Blocking {
                    KillSwitchState::Blocking
                } else {
                    KillSwitchState::Armed
                }
            }
            KillSwitchMode::AlwaysOn => {
                if matches!(self.connection_state, ConnectionState::Connected { .. }) {
                    KillSwitchState::Armed
                } else {
                    KillSwitchState::Blocking
                }
            }
        };

        if self.killswitch_state.is_blocking() && !self.is_root {
            self.killswitch_state = KillSwitchState::Armed;
        }

        if self.killswitch_state != old_state || self.killswitch_state == KillSwitchState::Blocking
        {
            if self.killswitch_state.is_blocking() {
                let (interface, server_ip) = match &self.connection_state {
                    ConnectionState::Connected { details, .. } => (
                        details.interface.as_str(),
                        Some(details.endpoint.split(':').next().unwrap_or("")),
                    ),
                    _ => (crate::platform::DEFAULT_VPN_INTERFACE, None),
                };

                if let Err(e) = crate::core::killswitch::enable_blocking(interface, server_ip) {
                    logger::log(
                        logger::LogLevel::Warning,
                        "SEC",
                        format!("Failed to enable kill switch: {e}"),
                    );
                }
            } else if old_state.is_blocking() {
                if let Err(e) = crate::core::killswitch::disable_blocking() {
                    logger::log(
                        logger::LogLevel::Warning,
                        "SEC",
                        format!("Failed to release kill switch: {e}"),
                    );
                }
            }
        }

        let _ = crate::core::killswitch::save_state(
            self.killswitch_mode,
            self.killswitch_state,
            None,
            None,
        );
    }

    /// Check if required binaries are available for a given protocol.
    #[must_use]
    pub fn check_dependencies(protocol: Protocol, config_path: &std::path::Path) -> Vec<String> {
        let mut missing = Vec::new();
        match protocol {
            Protocol::WireGuard => {
                if !utils::binary_exists("wg-quick") {
                    missing.push("wg-quick".to_string());
                }
                if !utils::binary_exists("wg") {
                    missing.push("wireguard-tools".to_string());
                }
                // On Linux, wg-quick uses `resolvconf` to set DNS when the
                // config contains a DNS directive.  We must verify that a
                // working resolvconf is present — `openresolv` installed on
                // a systemd-resolved system will exist but fail at runtime
                // with "signature mismatch".
                #[cfg(target_os = "linux")]
                if utils::wireguard_config_has_dns(config_path) && !utils::resolvconf_works() {
                    if utils::is_systemd_resolved() {
                        missing.push("resolvconf (systemd)".to_string());
                    } else {
                        missing.push("resolvconf".to_string());
                    }
                }
                #[cfg(not(target_os = "linux"))]
                let _ = config_path; // suppress unused warning on non-Linux
            }
            Protocol::OpenVPN => {
                if !utils::binary_exists("openvpn") {
                    missing.push("openvpn".to_string());
                }
            }
        }
        missing
    }
}

impl Drop for VpnEngine {
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
