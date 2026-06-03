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
use crate::utils;
use crate::vortix_core::profile::ProfileId;

/// Core VPN engine — all VPN-related state, no UI dependencies.
///
/// Created by [`VpnRuntime::new`] for TUI use (spawns background workers) or
/// [`VpnRuntime::new_headless`] for CLI one-shot commands (no background threads).
#[allow(clippy::struct_excessive_bools)]
pub struct VpnRuntime {
    // === VPN State ===
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

    // === Connection Retry & Auto-Reconnect ===
    /// Per-profile retry / auto-reconnect bookkeeping (plan P5b U-P5b-1).
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
                let _ = crate::core::killswitch::disable_blocking();
                engine.killswitch_state = KillSwitchState::Disabled;
                crate::core::killswitch::clear_state();
            } else {
                engine.killswitch_state = persisted.state;
            }
        }

        // Restore real_ip from the on-disk cache. Handles the
        // "launch vortix with VPN already up" case where the
        // current process has no disconnected window to learn the
        // real IP from telemetry. Stale loads are acceptable — a
        // fresh disconnected sample will overwrite the cache the
        // moment the user disconnects.
        if let Some(cached) = crate::core::real_ip_cache::load(&engine.config_dir) {
            engine.real_ip = Some(cached.ip);
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
    ///
    /// Plan #004 U4: dispatch routes through the `TunnelKind` aggregate.
    pub fn cleanup_vpn_resources(&self, profile_name: &str) {
        use crate::vortix_core::ports::tunnel::{TunnelHandle, TunnelKindTag};
        use crate::vortix_core::profile::ProfileId;

        if let Some(profile) = self.profiles.iter().find(|p| p.name == profile_name) {
            let iface = match profile.protocol {
                Protocol::WireGuard => profile.config_path.to_string_lossy().into_owned(),
                Protocol::OpenVPN => {
                    format!("openvpn-{}", utils::sanitize_profile_name(profile_name))
                }
            };
            let pid = match profile.protocol {
                Protocol::OpenVPN => utils::read_openvpn_pid(profile_name),
                Protocol::WireGuard => None,
            };
            let handle = TunnelHandle {
                profile_id: ProfileId::new(profile_name),
                interface_name: iface,
                pid,
                started_at: std::time::SystemTime::now(),
                kind: match profile.protocol {
                    Protocol::WireGuard => TunnelKindTag::WireGuard,
                    Protocol::OpenVPN => TunnelKindTag::OpenVpn,
                },
            };

            let config_dir =
                utils::get_app_config_dir().unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));
            let mut tunnel = crate::tunnel::tunnel_for(profile.protocol, &config_dir, "3", 30);
            let _ = tunnel.down(handle);

            if matches!(profile.protocol, Protocol::OpenVPN) {
                utils::cleanup_openvpn_run_files(profile_name);
            }
        }
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
    ) {
        let old_state = self.killswitch_state;

        // Pure mode → state decision lives on `KillSwitchMode` so it
        // can be unit-tested without firewall side effects. AlwaysOn
        // always resolves to Blocking — the firewall stays engaged
        // whether the VPN is up or down (canonical Linux killswitch
        // shape; see `tests/integration/killswitch.sh`).
        self.killswitch_state = self.killswitch_mode.desired_state(old_state, is_connected);

        if self.killswitch_state.is_blocking() && !self.is_root {
            self.killswitch_state = KillSwitchState::Armed;
        }

        if self.killswitch_state != old_state || self.killswitch_state == KillSwitchState::Blocking
        {
            if self.killswitch_state.is_blocking() {
                if let Err(e) = crate::core::killswitch::enable_blocking_multi(active_tunnels) {
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

        let persisted_tunnels = crate::core::killswitch::persisted_from_active(active_tunnels);
        let _ = crate::core::killswitch::save_state(
            self.killswitch_mode,
            self.killswitch_state,
            persisted_tunnels,
        );
    }

    /// Check if required binaries are available for a given protocol.
    ///
    /// Shared between TUI and CLI so both surfaces refuse the same
    /// missing-dep set (and run the same `OpenVPN` 2.4+ probe — older
    /// builds silently drop `--pull-filter`, breaking multi-tunnel DNS
    /// scoping per plan 001 U14 / R13).
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
