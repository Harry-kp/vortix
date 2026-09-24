//! The TUI's telemetry, profile list and worker channels.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::App;
use crate::app::state::ProfileSortOrder;
use crate::config::profiles::VpnProfile;
use crate::config::AppConfig;
use crate::constants;
use crate::message::Message;
use crate::profile::ProtocolKind;
use crate::telemetry::{self, TelemetryUpdate};

/// Telemetry, profiles and worker channels behind the TUI.
#[allow(clippy::struct_excessive_bools)]
pub struct VpnRuntime {
    // === VPN State ===
    pub profiles: Vec<VpnProfile>,

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

    // === System Info ===
    pub public_ip: String,
    pub real_ip: Option<String>,
    pub public_ipv6: Option<String>,
    pub real_ipv6: Option<String>,
    /// True while `real_ip` is only the address the cache remembers, with no
    /// unprotected observation in this session to confirm it. The Security
    /// Guard must not present such a value as a current fact.
    pub real_ip_from_cache: bool,
    /// Same, for `real_ipv6`.
    pub real_ipv6_from_cache: bool,
    pub last_ipv6_check: Option<Instant>,
    /// When the public-address probe last landed — the observation behind
    /// `public_ip`, `isp` and `location`.
    pub last_egress_check: Option<Instant>,
    /// When the resolver read last landed — the observation behind
    /// `dns_server`.
    pub last_dns_check: Option<Instant>,
    /// Most recent of any telemetry observation. Useful as "something is
    /// alive"; never as the age of a particular field, because each field is
    /// refreshed by its own probe on its own schedule.
    pub last_security_check: Option<Instant>,
    pub ip_unchanged_warned: bool,

    /// True once the scanner has completed at least one
    /// `Message::SyncSystemState` tick. Until then we don't know
    /// whether the kernel has any active VPN interfaces, so the
    /// real-IP cache gate must withhold trust on the first
    /// telemetry sample. Without this flag, vortix opened while a
    /// VPN is already up races: telemetry returns the VPN's exit
    /// IP, the engine snapshot is briefly empty (adoption hasn't run
    /// yet), and the wrong IP gets cached as `real_ip`.
    pub scanner_first_tick_done: bool,

    /// Number of kernel-visible VPN sessions observed at the most
    /// recent scanner tick. Reading raw kernel state (not the
    /// engine snapshot) catches tunnels that have not yet been adopted —
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
    pub sort_order: ProfileSortOrder,

    // === Async Communication ===
    pub(crate) telemetry_rx: Option<mpsc::Receiver<(u64, TelemetryUpdate)>>,
    pub telemetry_nudge: Option<mpsc::Sender<u64>>,
    /// Bumped whenever the tunnel set changes; telemetry started before the
    /// bump describes an egress path that may no longer exist.
    pub telemetry_epoch: u64,
    pub(crate) cmd_tx: mpsc::Sender<Message>,
    pub(crate) cmd_rx: mpsc::Receiver<Message>,
    pub(crate) netstats_rx: Option<mpsc::Receiver<(u64, u64)>>,
    pub(crate) last_bytes_in: u64,
    pub(crate) last_bytes_out: u64,
}

/// The real addresses Vortix remembers from an earlier unprotected session.
///
/// A record older than the cache ceiling describes a network the host may
/// have left days ago. Restoring it would put a stale address in the leak
/// indicator, so an expired record is not restored at all — the field reads
/// unknown until a live observation replaces it.
fn remembered_real_addresses(config_dir: &std::path::Path) -> (Option<String>, Option<String>) {
    let max_age = Duration::from_secs(constants::REAL_IP_CACHE_MAX_AGE_SECS);
    (
        crate::telemetry::ip_cache::load_recent(config_dir, max_age).map(|cached| cached.ip),
        crate::telemetry::ip_cache::load_recent_ipv6(config_dir, max_age).map(|cached| cached.ip),
    )
}
impl VpnRuntime {
    /// Every field, with nothing detected and no background work started.
    ///
    /// The three public constructors differ by a handful of fields and what
    /// they do afterwards, so they share this and apply their own deltas. A
    /// new field is added here once instead of in three literals that have to
    /// be kept in step.
    fn blank(config: AppConfig, config_dir: PathBuf) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel::<Message>();
        let history_size = constants::NETWORK_HISTORY_SIZE;
        Self {
            profiles: Vec::new(),

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

            public_ip: String::new(),
            real_ip: None,
            public_ipv6: None,
            real_ipv6: None,
            real_ip_from_cache: false,
            real_ipv6_from_cache: false,
            last_ipv6_check: None,
            last_egress_check: None,
            last_dns_check: None,
            last_security_check: None,
            ip_unchanged_warned: false,
            scanner_first_tick_done: false,
            last_kernel_session_count: 0,

            config,
            config_dir,
            is_root: crate::platform::is_root(),

            connection_drops: 0,
            sort_order: ProfileSortOrder::default(),

            telemetry_rx: None,
            telemetry_nudge: None,
            telemetry_epoch: 0,
            cmd_tx,
            cmd_rx,
            netstats_rx: None,
            last_bytes_in: 0,
            last_bytes_out: 0,
        }
    }

    /// Long-lived engine for the TUI: detects telemetry and runs background workers.
    #[must_use]
    pub fn new(config: AppConfig, config_dir: PathBuf) -> Self {
        let mut engine = Self::blank(config, config_dir);
        engine.location = constants::MSG_DETECTING.to_string();
        engine.isp = constants::MSG_DETECTING.to_string();
        engine.dns_server = constants::MSG_DETECTING.to_string();
        engine.public_ip = constants::MSG_DETECTING.to_string();

        // Remembered only until reconfirmed, so launch-with-VPN-up still shows a real IP.
        let (remembered_ipv4, remembered_ipv6) = remembered_real_addresses(&engine.config_dir);
        if let Some(ip) = remembered_ipv4 {
            engine.real_ip = Some(ip);
            engine.real_ip_from_cache = true;
        }
        if let Some(ip) = remembered_ipv6 {
            engine.real_ipv6 = Some(ip);
            engine.real_ipv6_from_cache = true;
        }

        engine.profiles = crate::config::profiles::load_profiles();
        engine.start_background_workers();
        engine
    }

    /// Lightweight constructor for testing — no background threads, no disk I/O.
    #[must_use]
    pub fn new_test() -> Self {
        let mut engine = Self::blank(
            AppConfig::default(),
            std::env::temp_dir().join("vortix_test"),
        );
        engine.is_root = false;
        engine
    }

    /// Start presentation-only telemetry workers.
    pub fn start_background_workers(&mut self) {
        let telemetry_config = telemetry::TelemetryConfig::from(&self.config);
        let (telem_rx, telem_nudge) = telemetry::spawn_telemetry_worker(telemetry_config);
        self.telemetry_rx = Some(telem_rx);
        self.telemetry_nudge = Some(telem_nudge);
    }

    /// Find a profile by name, returning its index.
    #[must_use]
    pub fn find_profile(&self, name: &str) -> Option<usize> {
        self.profiles.iter().position(|p| p.name == name)
    }

    /// Sort profiles according to the current `sort_order`.
    pub fn sort_profiles(&mut self) {
        self.sort_order.sort(&mut self.profiles);
    }
}

impl crate::app::state::ProfileSortOrder {
    /// Order `profiles` in place.
    pub fn sort(self, profiles: &mut [VpnProfile]) {
        match self {
            ProfileSortOrder::NameAsc => {
                profiles.sort_by(|a, b| a.name.cmp(&b.name));
            }
            ProfileSortOrder::NameDesc => {
                profiles.sort_by(|a, b| b.name.cmp(&a.name));
            }
            ProfileSortOrder::LastUsed => {
                profiles.sort_by(|a, b| {
                    b.last_used
                        .unwrap_or(std::time::UNIX_EPOCH)
                        .cmp(&a.last_used.unwrap_or(std::time::UNIX_EPOCH))
                });
            }
            ProfileSortOrder::Protocol => {
                fn proto_rank(p: ProtocolKind) -> u8 {
                    match p {
                        ProtocolKind::WireGuard => 0,
                        ProtocolKind::OpenVpn => 1,
                    }
                }
                profiles.sort_by(|a, b| {
                    proto_rank(a.protocol)
                        .cmp(&proto_rank(b.protocol))
                        .then_with(|| a.name.cmp(&b.name))
                });
            }
        }
    }
}

impl App {
    /// Processes pending telemetry updates from the background worker.
    /// Called frequently to ensure logs appear immediately.
    pub(crate) fn process_telemetry(&mut self) {
        let updates: Vec<_> = if let Some(rx) = &self.runtime.telemetry_rx {
            rx.try_iter().collect()
        } else {
            return;
        };

        for (epoch, update) in updates {
            if epoch == self.runtime.telemetry_epoch
                || matches!(update, crate::telemetry::TelemetryUpdate::Log(..))
            {
                self.handle_message(Message::Telemetry(update));
            }
        }
    }

    /// Wake the telemetry worker so it refreshes IP/ISP/latency immediately.
    pub(crate) fn refresh_telemetry(&mut self) {
        // The route changed, so the last exit is no longer the exit: show it
        // as pending rather than as a fresh reading of the old path.
        let detecting = crate::constants::MSG_DETECTING.to_string();
        self.runtime.public_ip.clone_from(&detecting);
        self.runtime.isp.clone_from(&detecting);
        self.runtime.location = detecting;
        self.runtime.public_ipv6 = None;
        self.runtime.last_egress_check = None;
        self.runtime.telemetry_epoch += 1;
        if let Some(nudge) = &self.runtime.telemetry_nudge {
            let _ = nudge.send(self.runtime.telemetry_epoch);
        }
    }
    /// Poll the network stats channel and kick off a new fetch if idle.
    ///
    /// The background thread just reads raw byte totals from the OS.
    /// Delta calculation (bytes/sec) stays here in the App, keeping state local.
    pub(crate) fn poll_network_stats(&mut self) {
        // 1. Try to collect a result from the previous fetch
        if let Some(rx) = &self.runtime.netstats_rx {
            match rx.try_recv() {
                Ok((total_in, total_out)) => {
                    if self.runtime.last_bytes_in > 0 {
                        self.runtime.current_down =
                            total_in.saturating_sub(self.runtime.last_bytes_in);
                        self.runtime.current_up =
                            total_out.saturating_sub(self.runtime.last_bytes_out);
                    }
                    self.runtime.last_bytes_in = total_in;
                    self.runtime.last_bytes_out = total_out;
                    self.runtime.netstats_rx = None;
                }
                Err(mpsc::TryRecvError::Empty) => {
                    return;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.runtime.netstats_rx = None;
                }
            }
        }

        // 2. Kick off a new fetch via the platform aggregate.
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let totals = crate::platform::NetworkStats::get_total_bytes();
            let _ = tx.send(totals);
        });
        self.runtime.netstats_rx = Some(rx);
    }
}

#[cfg(test)]
mod remembered_address_tests {
    use super::*;
    use crate::constants::{REAL_IPV6_CACHE_FILE, REAL_IP_CACHE_FILE};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vortix-remembered-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn seconds_ago(seconds: u64) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs()
            - seconds
    }

    /// Startup must go through the age-checked load. Reading the raw record
    /// would put an address the host has not seen for days into the leak
    /// indicator, presented as the real address it is being compared against.
    #[test]
    fn an_expired_cache_record_is_not_remembered_at_startup() {
        let dir = scratch("expired");
        let stale = seconds_ago(constants::REAL_IP_CACHE_MAX_AGE_SECS + 60 * 60);
        std::fs::write(
            dir.join(REAL_IP_CACHE_FILE),
            format!("203.0.113.5\n{stale}\n"),
        )
        .expect("write v4 record");
        std::fs::write(
            dir.join(REAL_IPV6_CACHE_FILE),
            format!("2001:db8::1\n{stale}\n"),
        )
        .expect("write v6 record");

        assert!(
            crate::telemetry::ip_cache::load(&dir).is_some(),
            "the record is on disk; the point is that startup declines it"
        );
        assert_eq!(
            remembered_real_addresses(&dir),
            (None, None),
            "an expired record must not be restored as a remembered address"
        );
    }

    #[test]
    fn a_recent_cache_record_is_remembered_at_startup() {
        let dir = scratch("recent");
        crate::telemetry::ip_cache::save(&dir, "203.0.113.5");
        crate::telemetry::ip_cache::save_ipv6(&dir, "2001:db8::1");

        assert_eq!(
            remembered_real_addresses(&dir),
            (
                Some("203.0.113.5".to_string()),
                Some("2001:db8::1".to_string())
            )
        );
    }
}
