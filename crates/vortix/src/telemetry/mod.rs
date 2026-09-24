//! Background telemetry collection service.
//!
//! This module handles asynchronous collection of network telemetry data
//! including public IP address, ISP information, latency measurements,
//! DNS configuration, and IPv6 leak detection.
//!
//! The telemetry worker runs in a background thread and communicates
//! updates via an MPSC channel to the main application.

pub mod icmp;
pub mod ip_cache;

use std::collections::VecDeque;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use crate::constants;
use crate::logger::LogLevel;
use serde::Deserialize;

const MAX_CACHED_EGRESS_IDENTITIES: usize = 8;

/// Configuration subset needed by the telemetry worker thread.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// Telemetry polling interval.
    pub poll_rate: Duration,
    /// HTTP API timeout in seconds.
    pub api_timeout: u64,
    /// Ping command timeout in seconds.
    pub ping_timeout: u64,
    /// Ping targets for latency measurement.
    pub ping_targets: Vec<String>,
    /// IPv6 leak detection endpoints.
    pub ipv6_check_apis: Vec<String>,
    /// Primary API endpoint for IP lookup.
    pub ip_api_primary: String,
    /// Fallback API endpoints for IP lookup followed by geolocation.
    pub ip_api_fallbacks: Vec<String>,
    /// Fallback API endpoint for metadata about an exact public IP.
    pub geolocation_api_fallback: String,
}

impl From<&crate::config::AppConfig> for TelemetryConfig {
    fn from(config: &crate::config::AppConfig) -> Self {
        Self {
            poll_rate: Duration::from_secs(config.telemetry_poll_rate),
            api_timeout: config.api_timeout,
            ping_timeout: config.ping_timeout,
            ping_targets: config.ping_targets.clone(),
            ipv6_check_apis: config.ipv6_check_apis.clone(),
            ip_api_primary: config.ip_api_primary.clone(),
            ip_api_fallbacks: config.ip_api_fallbacks.clone(),
            geolocation_api_fallback: config.geolocation_api_fallback.clone(),
        }
    }
}

/// Sends updates tagged with the tunnel-topology epoch the probe started in,
/// so the app can drop a sample taken through a tunnel that has since gone.
#[derive(Clone)]
struct Tx {
    inner: mpsc::Sender<(u64, TelemetryUpdate)>,
    epoch: u64,
}

impl Tx {
    fn send(&self, update: TelemetryUpdate) -> Result<(), mpsc::SendError<(u64, TelemetryUpdate)>> {
        self.inner.send((self.epoch, update))
    }
}

/// Telemetry update messages sent from background workers to the main application.
#[derive(Debug, Clone)]
pub enum TelemetryUpdate {
    /// One coherent observation of the current public egress identity.
    /// Optional metadata is absent for IP-only fallback providers.
    EgressIdentity(EgressIdentity),
    /// Every bounded public-egress provider failed.
    EgressUnavailable,
    /// One coherent network-quality sample. Keeping the related measurements
    /// together prevents consumers from classifying a mixture of old and new
    /// values while the three fields are delivered.
    NetworkQuality {
        /// Round-trip latency in milliseconds.
        latency_ms: u64,
        /// Packet loss percentage (0.0-100.0).
        packet_loss: f32,
        /// Latency standard deviation in milliseconds.
        jitter_ms: u64,
    },
    /// Updated DNS server address.
    Dns(String),
    /// Public IPv6 observed by the probe, `None` if unreachable.
    PublicIpv6(Option<String>),
    /// Log message with level for production logging (uses centralized logger)
    Log(LogLevel, String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressIdentity {
    pub public_ip: String,
    pub isp: Option<String>,
    pub location: Option<String>,
}

#[derive(Default)]
struct IpSuccessLog {
    last_identity: Option<EgressIdentity>,
}

#[derive(Default)]
struct EgressIdentityState {
    located: VecDeque<EgressIdentity>,
    primary_retry_at: Option<Instant>,
    /// Whether the "no public-egress provider answered" line has already
    /// been emitted for the failure episode currently in progress.
    egress_unavailable_announced: bool,
    /// Same, for the primary location provider's own failure episode.
    primary_unavailable_announced: bool,
}

impl EgressIdentityState {
    fn complete_for(&self, public_ip: &str) -> Option<&EgressIdentity> {
        self.located
            .iter()
            .find(|identity| identity.public_ip == public_ip)
    }

    fn remember(&mut self, identity: EgressIdentity) {
        if identity.is_location_capable() {
            self.located
                .retain(|cached| cached.public_ip != identity.public_ip);
            self.located.push_front(identity);
            self.located.truncate(MAX_CACHED_EGRESS_IDENTITIES);
        }
    }

    fn primary_is_available(&self, now: Instant) -> bool {
        self.primary_retry_at.is_none_or(|retry_at| now >= retry_at)
    }

    fn suppress_rate_limited_primary(&mut self, now: Instant) {
        self.primary_retry_at = now.checked_add(RATE_LIMITED_PRIMARY_PAUSE);
    }

    /// Pause a primary provider that keeps failing for reasons other than a
    /// quota. Retrying it every poll costs two request timeouts on the
    /// coordinator thread, which is what pushes a whole poll past its own
    /// interval and leaves every field a cycle behind.
    fn suppress_unavailable_primary(&mut self, now: Instant) {
        self.primary_retry_at = now.checked_add(UNAVAILABLE_PRIMARY_PAUSE);
    }

    /// Log a state transition, never a per-poll repetition.
    fn announce_once(flag: &mut bool, tx: &Tx, level: LogLevel, message: &str) {
        if *flag {
            let _ = tx.send(TelemetryUpdate::Log(LogLevel::Debug, message.to_string()));
            return;
        }
        if tx
            .send(TelemetryUpdate::Log(level, message.to_string()))
            .is_ok()
        {
            *flag = true;
        }
    }

    fn announce_egress_unavailable(&mut self, tx: &Tx) {
        Self::announce_once(
            &mut self.egress_unavailable_announced,
            tx,
            LogLevel::Error,
            "No public-address service answered; check network, VPN routing, or firewall rules",
        );
    }

    fn announce_egress_recovered(&mut self, tx: &Tx) {
        if !self.egress_unavailable_announced {
            return;
        }
        self.egress_unavailable_announced = false;
        let _ = tx.send(TelemetryUpdate::Log(
            LogLevel::Info,
            "Public-address service reachable again".to_string(),
        ));
    }

    fn announce_primary_unavailable(&mut self, tx: &Tx) {
        Self::announce_once(
            &mut self.primary_unavailable_announced,
            tx,
            LogLevel::Warning,
            "Location service unreachable; using the backup service",
        );
    }

    fn announce_primary_recovered(&mut self) {
        self.primary_unavailable_announced = false;
    }
}

/// How long a quota-exhausted primary location provider stays paused. A
/// daily quota only resets on the provider's clock, so retrying inside the
/// day cannot succeed.
const RATE_LIMITED_PRIMARY_PAUSE: Duration = Duration::from_secs(24 * 60 * 60);

/// How long a primary location provider stays paused after a non-quota
/// failure episode. Long enough that a persistent outage stops costing
/// every poll two request timeouts; short enough that a transient one
/// self-heals without a restart.
const UNAVAILABLE_PRIMARY_PAUSE: Duration = Duration::from_secs(5 * 60);

impl EgressIdentity {
    fn is_location_capable(&self) -> bool {
        self.location.is_some()
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PrimaryLookup {
    Found(EgressIdentity),
    RateLimited,
    Unavailable,
}

impl IpSuccessLog {
    fn publish(&mut self, tx: &Tx, identity: &EgressIdentity) {
        if self.last_identity.as_ref() == Some(identity) {
            return;
        }
        let message = format!(
            "✓ Public address: IP={}, network={}, location={}",
            identity.public_ip,
            identity.isp.as_deref().unwrap_or("Unknown"),
            identity.location.as_deref().unwrap_or("Unknown")
        );
        if tx
            .send(TelemetryUpdate::Log(LogLevel::Info, message))
            .is_ok()
        {
            self.last_identity = Some(identity.clone());
        }
    }

    fn reset(&mut self) {
        self.last_identity = None;
    }
}

/// Spawns a background telemetry worker that periodically fetches network information.
///
/// # Returns
///
/// A tuple of:
/// - a receiver of updates, each tagged with the topology epoch its probe
///   started under
/// - a sender that triggers an immediate refresh under a new epoch
///
/// # Panics
///
/// This function does not panic. All errors in background threads are silently handled.
#[must_use]
pub fn spawn_telemetry_worker(
    config: TelemetryConfig,
) -> (Receiver<(u64, TelemetryUpdate)>, mpsc::Sender<u64>) {
    let (sender, rx) = mpsc::channel();
    let (nudge_tx, nudge_rx) = mpsc::channel::<u64>();
    let mut epoch = 0;
    let config = std::sync::Arc::new(config);
    let mut ip_success_log = IpSuccessLog::default();
    let mut identity_state = EgressIdentityState::default();

    thread::spawn(move || loop {
        let tx = Tx {
            inner: sender.clone(),
            epoch,
        };
        // These probes spawn their own bounded workers, so start them without
        // waiting for the serialized identity lookup's network timeouts.
        fetch_latency(&tx, &config);
        fetch_security_info(&tx, &config);
        fetch_ip_and_isp(&tx, &config, &mut ip_success_log, &mut identity_state);

        // Wait for the poll interval, but wake up immediately if nudged.
        // Drain any extra nudges that accumulated while we were fetching.
        if let Ok(next) = nudge_rx.recv_timeout(config.poll_rate) {
            epoch = epoch.max(next);
        }
        while let Ok(next) = nudge_rx.try_recv() {
            epoch = epoch.max(next);
        }
    });

    (rx, nudge_tx)
}

/// Fetches public IP address and ISP information with fallback APIs.
fn fetch_ip_and_isp(
    tx: &Tx,
    cfg: &std::sync::Arc<TelemetryConfig>,
    ip_success_log: &mut IpSuccessLog,
    identity_state: &mut EgressIdentityState,
) {
    // This function deliberately runs on the telemetry coordinator thread.
    // A refresh nudge is coalesced while it is in flight, so two providers can
    // never race separate pieces of egress identity into the UI.
    let _ = tx.send(TelemetryUpdate::Log(
        LogLevel::Debug,
        "Checking the current public IP...".to_string(),
    ));

    // Query an IP-only endpoint on every poll. Geolocation providers have
    // strict daily quotas, so metadata is refreshed only for a new exit IP.
    for provider in &ip_echo_providers(cfg) {
        if let Some(ip) = try_ip_echo(tx, cfg, provider) {
            identity_state.announce_egress_recovered(tx);
            publish_observed_ip(tx, cfg, ip_success_log, identity_state, ip);
            return;
        }
    }

    if let Some(identity) = lookup_location_identity(tx, cfg, identity_state, None) {
        identity_state.announce_egress_recovered(tx);
        identity_state.remember(identity.clone());
        publish_identity(tx, ip_success_log, identity);
        return;
    }

    // Every provider failed. Announce the transition, not every poll of it.
    ip_success_log.reset();
    identity_state.announce_egress_unavailable(tx);
    let _ = tx.send(TelemetryUpdate::EgressUnavailable);
}

fn publish_observed_ip(
    tx: &Tx,
    cfg: &TelemetryConfig,
    ip_success_log: &mut IpSuccessLog,
    identity_state: &mut EgressIdentityState,
    public_ip: String,
) {
    let identity = identity_state
        .complete_for(&public_ip)
        .cloned()
        .or_else(|| lookup_location_identity(tx, cfg, identity_state, Some(&public_ip)))
        .unwrap_or(EgressIdentity {
            public_ip,
            isp: None,
            location: None,
        });
    identity_state.remember(identity.clone());
    publish_identity(tx, ip_success_log, identity);
}

fn publish_identity(tx: &Tx, ip_success_log: &mut IpSuccessLog, identity: EgressIdentity) {
    ip_success_log.publish(tx, &identity);
    let _ = tx.send(TelemetryUpdate::EgressIdentity(identity));
}

fn lookup_location_identity(
    tx: &Tx,
    cfg: &TelemetryConfig,
    state: &mut EgressIdentityState,
    public_ip: Option<&str>,
) -> Option<EgressIdentity> {
    let now = Instant::now();
    let mut partial_primary = None;
    if state.primary_is_available(now) {
        match try_primary_geolocation(tx, cfg) {
            PrimaryLookup::Found(identity)
                if public_ip.is_none_or(|expected| identity.public_ip == expected) =>
            {
                state.announce_primary_recovered();
                if identity.is_location_capable() {
                    return Some(identity);
                }
                partial_primary = Some(identity);
            }
            PrimaryLookup::Found(_) => {
                state.announce_primary_recovered();
                let _ = tx.send(TelemetryUpdate::Log(
                    LogLevel::Debug,
                    "Location service answered about a different address; ignoring it".to_string(),
                ));
            }
            PrimaryLookup::RateLimited => {
                state.suppress_rate_limited_primary(now);
                let _ = tx.send(TelemetryUpdate::Log(
                    LogLevel::Warning,
                    "Location service daily limit reached; using the backup service for today"
                        .to_string(),
                ));
            }
            PrimaryLookup::Unavailable => {
                state.suppress_unavailable_primary(now);
                state.announce_primary_unavailable(tx);
            }
        }
    }

    let fallback = {
        let fallback_ip = public_ip.or_else(|| {
            partial_primary
                .as_ref()
                .map(|identity| identity.public_ip.as_str())
        });
        try_geolocation_fallback(tx, cfg, fallback_ip)
    };
    match (partial_primary, fallback) {
        (Some(primary), Some(fallback)) => Some(EgressIdentity {
            public_ip: fallback.public_ip,
            isp: fallback.isp.or(primary.isp),
            location: fallback.location.or(primary.location),
        }),
        (Some(primary), None) => Some(primary),
        (None, fallback) => fallback,
    }
}

/// Try the configured primary geolocation API with bounded retry.
fn try_primary_geolocation(tx: &Tx, cfg: &TelemetryConfig) -> PrimaryLookup {
    let timeout = Duration::from_secs(cfg.api_timeout);

    for attempt in 0..constants::RETRY_ATTEMPTS {
        let text = match crate::telemetry::get_text_v4_result(&cfg.ip_api_primary, timeout) {
            Ok(text) => text,
            Err(crate::telemetry::GetTextError::HttpStatus(429)) => {
                return PrimaryLookup::RateLimited;
            }
            Err(crate::telemetry::GetTextError::HttpStatus(status))
                if (400..500).contains(&status) =>
            {
                let _ = tx.send(TelemetryUpdate::Log(
                    LogLevel::Debug,
                    format!("Location service rejected the request (HTTP {status})"),
                ));
                return PrimaryLookup::Unavailable;
            }
            Err(_) => {
                let _ = tx.send(TelemetryUpdate::Log(
                    LogLevel::Debug,
                    format!("Location service attempt {} failed", attempt + 1),
                ));
                if attempt == 0 {
                    thread::sleep(Duration::from_millis(constants::RETRY_DELAY_MS));
                }
                continue;
            }
        };

        if let Some(result) = parse_ip_api_response(&text) {
            let (public_ip, isp, location) = result;
            return PrimaryLookup::Found(EgressIdentity {
                public_ip,
                isp,
                location,
            });
        }
        let _ = tx.send(TelemetryUpdate::Log(
            LogLevel::Debug,
            format!(
                "Location service attempt {}: unreadable response",
                attempt + 1
            ),
        ));

        if attempt == 0 {
            thread::sleep(Duration::from_millis(constants::RETRY_DELAY_MS));
        }
    }

    PrimaryLookup::Unavailable
}

fn try_geolocation_fallback(
    tx: &Tx,
    cfg: &TelemetryConfig,
    public_ip: Option<&str>,
) -> Option<EgressIdentity> {
    let base = cfg.geolocation_api_fallback.trim_end_matches('/');
    if base.is_empty() {
        return None;
    }
    let url = public_ip.map_or_else(|| base.to_string(), |ip| format!("{base}/{ip}"));
    let timeout = Duration::from_secs(cfg.api_timeout);
    let text = match crate::telemetry::get_text_v4_result(&url, timeout) {
        Ok(text) => text,
        Err(crate::telemetry::GetTextError::HttpStatus(status)) => {
            let _ = tx.send(TelemetryUpdate::Log(
                LogLevel::Debug,
                format!("Backup location service returned HTTP {status}"),
            ));
            return None;
        }
        Err(crate::telemetry::GetTextError::Transport) => return None,
    };
    let (returned_ip, isp, location) = parse_ipwho_response(&text)?;
    if public_ip.is_some_and(|expected| returned_ip != expected) {
        return None;
    }
    Some(EgressIdentity {
        public_ip: returned_ip,
        isp,
        location,
    })
}

/// Whether `ip` is a dotted-quad IPv4 address.
///
/// `Ipv4Addr`'s parser is the whole check: it rejects out-of-range octets,
/// leading zeros, a leading `+`, surrounding whitespace, and — the reason
/// this matters — every IPv6 form. Every provider answer is run through
/// this before it can reach an IPv4 field.
fn is_valid_ipv4(ip: &str) -> bool {
    ip.parse::<std::net::Ipv4Addr>().is_ok()
}

/// One IP-echo provider: the URL to ask and the name used in its log lines.
struct IpEchoProvider {
    url: String,
    label: &'static str,
}

/// The configured IP-echo chain, in order. Falls back to the compiled
/// defaults for any slot the config leaves out.
fn ip_echo_providers(cfg: &TelemetryConfig) -> [IpEchoProvider; 3] {
    let slot = |index: usize, default: &str| -> String {
        cfg.ip_api_fallbacks
            .get(index)
            .filter(|url| !url.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| default.to_string())
    };
    [
        IpEchoProvider {
            url: slot(0, constants::DEFAULT_IP_API_FALLBACK_1),
            label: "first public-IP provider",
        },
        IpEchoProvider {
            url: slot(1, constants::DEFAULT_IP_API_FALLBACK_2),
            label: "second public-IP provider",
        },
        IpEchoProvider {
            url: slot(2, constants::DEFAULT_IP_API_FALLBACK_3),
            label: "third public-IP provider",
        },
    ]
}

/// Ask one IP-echo provider for this host's public IPv4, with bounded retry.
///
/// Every answer is validated as dotted-quad IPv4 before it is returned. An
/// echo endpoint reports whichever address the request arrived from, so an
/// unvalidated answer is only ever "some address of mine" — not necessarily
/// the IPv4 one. Requests go out over IPv4 (see `telemetry_http`), and this
/// check is the second, independent guard on the same guarantee: nothing
/// that is not an IPv4 address can reach an IPv4 field.
fn try_ip_echo(tx: &Tx, cfg: &TelemetryConfig, provider: &IpEchoProvider) -> Option<String> {
    let timeout = Duration::from_secs(cfg.api_timeout);

    for attempt in 0..constants::RETRY_ATTEMPTS {
        match crate::telemetry::get_text_v4(&provider.url, timeout) {
            Some(body) => {
                let ip = body.trim();
                if is_valid_ipv4(ip) {
                    return Some(ip.to_string());
                }
                let _ = tx.send(TelemetryUpdate::Log(
                    LogLevel::Debug,
                    format!(
                        "{} attempt {}: answer is not an IPv4 address: '{ip}'",
                        provider.label,
                        attempt + 1
                    ),
                ));
            }
            None => {
                let _ = tx.send(TelemetryUpdate::Log(
                    LogLevel::Debug,
                    format!("{} attempt {}: request failed", provider.label, attempt + 1),
                ));
            }
        }

        if attempt == 0 {
            thread::sleep(Duration::from_millis(constants::RETRY_DELAY_MS));
        }
    }

    None
}

/// IP API response structure (supports both ipinfo.io and ip-api.com formats)
#[derive(Debug, Deserialize)]
struct IpApiResponse {
    #[serde(alias = "query")] // ip-api.com uses "query"
    ip: Option<String>,
    isp: Option<String>,
    org: Option<String>,
    city: Option<String>,
    country: Option<String>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpWhoResponse {
    success: bool,
    ip: Option<String>,
    city: Option<String>,
    country_code: Option<String>,
    connection: Option<IpWhoConnection>,
}

#[derive(Debug, Deserialize)]
struct IpWhoConnection {
    isp: Option<String>,
    org: Option<String>,
}

fn parse_ipwho_response(json: &str) -> Option<(String, Option<String>, Option<String>)> {
    let response: IpWhoResponse = serde_json::from_str(json).ok()?;
    if !response.success {
        return None;
    }
    let ip = response.ip?;
    if !is_valid_ipv4(&ip) {
        return None;
    }
    let isp = response
        .connection
        .and_then(|connection| connection.isp.or(connection.org));
    let location = match (response.city, response.country_code) {
        (Some(city), Some(country)) => Some(format!("{city}, {country}")),
        (Some(city), None) => Some(city),
        (None, Some(country)) => Some(country),
        (None, None) => None,
    };
    Some((ip, isp, location))
}

/// Parse IP API JSON response using proper JSON deserialization
/// This replaces the unsafe string-matching approach with proper parsing
/// that handles escaped quotes, unicode, and nested JSON correctly.
///
/// # Safety Benefits
/// - Handles escaped quotes: `"org": "Company \"Premium\" Networks"`
/// - Handles unicode: `"city": "São Paulo"` or `"city": "S\u00e3o Paulo"`
/// - Validates JSON structure
/// - Fails gracefully on malformed JSON
fn parse_ip_api_response(json: &str) -> Option<(String, Option<String>, Option<String>)> {
    let response: IpApiResponse = serde_json::from_str(json).ok()?;

    // Check if API returned success (ip-api.com includes status field)
    if let Some(status) = &response.status {
        if status != "success" {
            return None;
        }
    }

    let ip = response.ip?;

    // Validate that the returned IP is a valid IPv4 address
    if !is_valid_ipv4(&ip) {
        return None;
    }

    // Prefer "org" over "isp" as it's usually more specific (ipinfo.io uses "org")
    let isp = response.org.or(response.isp);

    // Build location string from city and country
    let location = match (response.city, response.country) {
        (Some(city), Some(country)) => Some(format!("{city}, {country}")),
        (Some(city), None) => Some(city),
        (None, Some(country)) => Some(country),
        (None, None) => None,
    };

    Some((ip, isp, location))
}

/// Measures network latency, packet loss, and jitter by pinging reliable hosts.
///
/// replaced the `ping -c 3 -i 0.2 -W <timeout>` shell-out
/// with `icmp::measure_latency`. Same outputs (`latency_ms`,
/// `packet_loss` %, `jitter_ms`); same retry-across-targets behavior;
/// same zero-latency, total-loss quality sample when every target fails.
fn fetch_latency(tx: &Tx, cfg: &std::sync::Arc<TelemetryConfig>) {
    // 3 probes, matching the prior `ping -c 3 -i 0.2` cadence.
    const PROBES_PER_TARGET: u32 = 3;

    let tx_clone = tx.clone();
    let cfg = std::sync::Arc::clone(cfg);
    thread::spawn(move || {
        let per_attempt_timeout = Duration::from_secs(cfg.ping_timeout);

        for target in &cfg.ping_targets {
            for attempt in 0..constants::RETRY_ATTEMPTS {
                if let Some(stats) = crate::telemetry::icmp::measure_latency(
                    target,
                    PROBES_PER_TARGET,
                    per_attempt_timeout,
                ) {
                    if stats.latency_ms > 0 {
                        let _ = tx_clone.send(TelemetryUpdate::NetworkQuality {
                            latency_ms: stats.latency_ms,
                            packet_loss: stats.packet_loss,
                            jitter_ms: stats.jitter_ms,
                        });
                        return;
                    }
                }

                if attempt == 0 {
                    thread::sleep(Duration::from_millis(constants::RETRY_DELAY_MS));
                }
            }
        }

        let _ = tx_clone.send(TelemetryUpdate::NetworkQuality {
            latency_ms: 0,
            packet_loss: 100.0,
            jitter_ms: 0,
        });
    });
}

/// Fetches DNS configuration and probes the current public IPv6.
fn fetch_security_info(tx: &Tx, cfg: &std::sync::Arc<TelemetryConfig>) {
    let tx_clone = tx.clone();
    let cfg = std::sync::Arc::clone(cfg);
    thread::spawn(move || {
        let dns = crate::platform::Dns::get_dns_server();
        if let Some(dns_server) = dns {
            let _ = tx_clone.send(TelemetryUpdate::Dns(dns_server));
        }

        let ipv6_timeout = Duration::from_secs(cfg.api_timeout);
        let mut public_v6: Option<String> = None;
        for endpoint in &cfg.ipv6_check_apis {
            if let Some(ip) = crate::telemetry::probe_ipv6(endpoint, ipv6_timeout) {
                public_v6 = Some(ip);
                break;
            }
        }
        let _ = tx_clone.send(TelemetryUpdate::PublicIpv6(public_v6));
    });
}

// Network stats delta calculation is now handled directly in App::poll_network_stats()
// using last_bytes_in / last_bytes_out fields on the App struct.

#[cfg(test)]
mod tests {
    use super::*;

    struct UntaggedRx(Receiver<(u64, TelemetryUpdate)>);

    impl UntaggedRx {
        fn try_iter(&self) -> impl Iterator<Item = TelemetryUpdate> + '_ {
            self.0.try_iter().map(|(_, update)| update)
        }

        fn try_recv(&self) -> Result<TelemetryUpdate, mpsc::TryRecvError> {
            self.0.try_recv().map(|(_, update)| update)
        }
    }

    fn test_channel() -> (Tx, UntaggedRx) {
        let (inner, rx) = mpsc::channel();
        (Tx { inner, epoch: 0 }, UntaggedRx(rx))
    }

    #[test]
    fn ip_success_log_emits_changes_and_recovery_only_once() {
        let (tx, rx) = test_channel();
        let mut log = IpSuccessLog::default();
        let identity = EgressIdentity {
            public_ip: "192.0.2.1".to_string(),
            isp: Some("Example".to_string()),
            location: Some("Test".to_string()),
        };
        let changed = EgressIdentity {
            public_ip: "192.0.2.2".to_string(),
            ..identity.clone()
        };

        log.publish(&tx, &identity);
        log.publish(&tx, &identity);

        let first_pass = rx.try_iter().collect::<Vec<_>>();
        assert_eq!(first_pass.len(), 1);
        assert!(matches!(
            &first_pass[0],
            TelemetryUpdate::Log(LogLevel::Info, emitted) if emitted.contains("192.0.2.1")
        ));

        log.publish(&tx, &changed);
        log.publish(&tx, &changed);

        assert!(matches!(
            rx.try_recv(),
            Ok(TelemetryUpdate::Log(LogLevel::Info, emitted)) if emitted.contains("192.0.2.2")
        ));
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));

        log.reset();
        log.publish(&tx, &changed);

        assert!(matches!(
            rx.try_recv(),
            Ok(TelemetryUpdate::Log(LogLevel::Info, emitted)) if emitted.contains("192.0.2.2")
        ));
    }

    #[test]
    fn test_is_valid_ipv4_valid() {
        assert!(is_valid_ipv4("1.2.3.4"));
        assert!(is_valid_ipv4("192.168.1.1"));
        assert!(is_valid_ipv4("0.0.0.0"));
        assert!(is_valid_ipv4("255.255.255.255"));
    }

    #[test]
    fn test_is_valid_ipv4_invalid() {
        assert!(!is_valid_ipv4("999.999.999.999"));
        assert!(!is_valid_ipv4("256.1.1.1"));
        assert!(!is_valid_ipv4("1.2.3"));
        assert!(!is_valid_ipv4("1.2.3.4.5"));
        assert!(!is_valid_ipv4("not.an.ip.address"));
        assert!(!is_valid_ipv4(""));
        // v4-mapped forms carry dotted-quad text, so they are what slips past
        // a substring check rather than a parser.
        assert!(!is_valid_ipv4("::ffff:192.168.1.1"));
        assert!(!is_valid_ipv4("::192.168.1.1"));
        assert!(!is_valid_ipv4("[192.168.1.1]"));
    }

    // === Ping output parsing tests ===

    // === DNS parsing tests ===

    #[test]
    fn test_parse_ip_api_response_full() {
        let json =
            r#"{"ip": "1.2.3.4", "org": "AS12345 Test ISP", "city": "Berlin", "country": "DE"}"#;
        let result = parse_ip_api_response(json);
        assert!(result.is_some());
        let (ip, isp, location) = result.unwrap();
        assert_eq!(ip, "1.2.3.4");
        assert_eq!(isp, Some("AS12345 Test ISP".to_string()));
        assert_eq!(location, Some("Berlin, DE".to_string()));
    }

    #[test]
    fn test_parse_ip_api_response_ip_only() {
        let json = r#"{"ip": "8.8.8.8"}"#;
        let result = parse_ip_api_response(json);
        assert!(result.is_some());
        let (ip, isp, location) = result.unwrap();
        assert_eq!(ip, "8.8.8.8");
        assert!(isp.is_none());
        assert!(location.is_none());
    }

    #[test]
    fn test_parse_ip_api_response_invalid() {
        assert!(parse_ip_api_response("not json").is_none());
        assert!(parse_ip_api_response("{}").is_none());
        assert!(parse_ip_api_response(r#"{"ip": "not_an_ip"}"#).is_none());
    }

    #[test]
    fn parses_location_capable_fallback_response() {
        let json = r#"{
            "success": true,
            "ip": "171.61.17.181",
            "city": "Agra",
            "country_code": "IN",
            "connection": {"isp": "Bharti Airtel Ltd."}
        }"#;

        assert_eq!(
            parse_ipwho_response(json),
            Some((
                "171.61.17.181".to_string(),
                Some("Bharti Airtel Ltd.".to_string()),
                Some("Agra, IN".to_string()),
            ))
        );
    }

    #[test]
    fn complete_identity_cache_is_bound_to_exact_public_ip() {
        let mut state = EgressIdentityState {
            located: VecDeque::from([EgressIdentity {
                public_ip: "192.0.2.1".to_string(),
                isp: Some("Example ISP".to_string()),
                location: Some("Test, ZZ".to_string()),
            }]),
            ..EgressIdentityState::default()
        };

        assert!(state.complete_for("192.0.2.1").is_some());
        assert!(state.complete_for("192.0.2.2").is_none());

        state.remember(EgressIdentity {
            public_ip: "192.0.2.2".to_string(),
            isp: Some("ISP without location".to_string()),
            location: None,
        });
        assert!(
            state.complete_for("192.0.2.2").is_none(),
            "ISP-only metadata must not suppress a later location lookup"
        );
        assert!(
            state.complete_for("192.0.2.1").is_some(),
            "switching exits must retain a bounded prior location"
        );
    }

    /// Serve `body` with a 200 to every connection until dropped.
    fn spawn_echo_server(
        body: &'static str,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicBool>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        thread::spawn(move || {
            for stream in listener.incoming() {
                if stop_thread.load(Ordering::Relaxed) {
                    return;
                }
                let Ok(mut stream) = stream else { return };
                let mut request = [0_u8; 1024];
                let _ = stream.read(&mut request);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (format!("http://{address}/ip"), stop)
    }

    fn probe_config(url: &str) -> TelemetryConfig {
        TelemetryConfig {
            poll_rate: Duration::from_secs(30),
            api_timeout: 2,
            ping_timeout: 1,
            ping_targets: Vec::new(),
            ipv6_check_apis: Vec::new(),
            ip_api_primary: String::new(),
            ip_api_fallbacks: vec![url.to_string()],
            geolocation_api_fallback: String::new(),
        }
    }

    /// The field is labelled "IPv4". An echo endpoint reports whichever
    /// address the request arrived from, so a provider that answers with an
    /// IPv6 address must be refused outright — not stored and announced as
    /// an IPv4 change.
    #[test]
    fn an_ipv6_answer_is_never_accepted_as_the_public_ipv4() {
        let (url, stop) = spawn_echo_server("2401:4900:890d:3cd5:a7be:9ed1:f79:dea7");
        let cfg = probe_config(&url);
        let (tx, _rx) = test_channel();

        let observed = try_ip_echo(&tx, &cfg, &ip_echo_providers(&cfg)[0]);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);

        assert_eq!(
            observed, None,
            "an IPv6 answer must not be reported as the public IPv4"
        );
    }

    #[test]
    fn a_valid_ipv4_answer_is_accepted() {
        let (url, stop) = spawn_echo_server("168.144.212.123\n");
        let cfg = probe_config(&url);
        let (tx, _rx) = test_channel();

        let observed = try_ip_echo(&tx, &cfg, &ip_echo_providers(&cfg)[0]);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);

        assert_eq!(observed, Some("168.144.212.123".to_string()));
    }

    /// The poll cadence must not turn a standing outage into a per-poll
    /// event-log line. One line on the way in, one on the way out.
    #[test]
    fn a_standing_outage_is_announced_once_not_once_per_poll() {
        let (tx, rx) = test_channel();
        let mut state = EgressIdentityState::default();

        for _ in 0..5 {
            state.announce_egress_unavailable(&tx);
        }
        state.announce_egress_recovered(&tx);
        state.announce_egress_unavailable(&tx);

        let loud: Vec<String> = rx
            .try_iter()
            .filter_map(|update| match update {
                TelemetryUpdate::Log(LogLevel::Debug, _) => None,
                TelemetryUpdate::Log(level, message) => Some(format!("{level:?}: {message}")),
                _ => None,
            })
            .collect();

        assert_eq!(
            loud.len(),
            3,
            "expected outage, recovery, outage — got:\n{loud:#?}"
        );
        assert!(loud[0].starts_with("Error"), "{loud:#?}");
        assert!(loud[1].starts_with("Info"), "{loud:#?}");
        assert!(loud[2].starts_with("Error"), "{loud:#?}");
    }

    #[test]
    fn an_unreachable_location_provider_is_announced_once_and_paused() {
        let (tx, rx) = test_channel();
        let mut state = EgressIdentityState::default();
        let now = Instant::now();

        for _ in 0..4 {
            state.announce_primary_unavailable(&tx);
        }
        state.suppress_unavailable_primary(now);

        let warnings = rx
            .try_iter()
            .filter(|update| matches!(update, TelemetryUpdate::Log(LogLevel::Warning, _)))
            .count();
        assert_eq!(
            warnings, 1,
            "a standing location-service outage must warn once, not once per poll"
        );
        assert!(
            !state.primary_is_available(now),
            "a failing location provider must be paused, not retried every poll"
        );
        assert!(
            state.primary_is_available(now + UNAVAILABLE_PRIMARY_PAUSE),
            "the pause must expire so a transient outage self-heals"
        );
    }

    #[test]
    fn primary_rate_limit_is_not_retried() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let cfg = TelemetryConfig {
            poll_rate: Duration::from_secs(30),
            api_timeout: 1,
            ping_timeout: 1,
            ping_targets: Vec::new(),
            ipv6_check_apis: Vec::new(),
            ip_api_primary: format!("http://{address}/limited"),
            ip_api_fallbacks: Vec::new(),
            geolocation_api_fallback: String::new(),
        };
        let (tx, _rx) = test_channel();

        assert_eq!(
            try_primary_geolocation(&tx, &cfg),
            PrimaryLookup::RateLimited
        );
        server.join().unwrap();
    }

    // === TelemetryConfig conversion ===

    #[test]
    fn test_telemetry_config_from_app_config() {
        let app_cfg = crate::config::AppConfig {
            theme: crate::theme::ThemeChoice::Synthwave,
            tick_rate: 500, // not used by TelemetryConfig
            telemetry_poll_rate: 45,
            api_timeout: 8,
            ping_timeout: 3,
            connect_timeout: 30, // not used by TelemetryConfig
            wireguard_handshake_timeout_secs: 20,
            wireguard_handshake_stale_secs: 180,
            ping_targets: vec!["4.4.4.4".to_string()],
            ipv6_check_apis: vec!["https://v6.example.com".to_string()],
            ip_api_primary: "https://custom.api/json".to_string(),
            ip_api_fallbacks: vec![
                "https://fb1.example.com".to_string(),
                "https://fb2.example.com".to_string(),
            ],
            geolocation_api_fallback: "https://geo.example.com".to_string(),
            max_log_entries: 1000,
            log_level: "info".to_string(),
            log_rotation_size: 5 * 1024 * 1024,
            log_retention_days: 7,
            disconnect_timeout: 30,
            openvpn_verbosity: "3".to_string(),
            connect_max_retries: 3,
            connect_retry_base_delay_secs: 2,
            connect_retry_max_delay_secs: 300,
            auto_reconnect: true,
            auto_reconnect_delay_secs: 3,
        };

        let tel_cfg = TelemetryConfig::from(&app_cfg);

        assert_eq!(tel_cfg.poll_rate, Duration::from_secs(45));
        assert_eq!(tel_cfg.api_timeout, 8);
        assert_eq!(tel_cfg.ping_timeout, 3);
        assert_eq!(tel_cfg.ping_targets, vec!["4.4.4.4"]);
        assert_eq!(tel_cfg.ipv6_check_apis, vec!["https://v6.example.com"]);
        assert_eq!(tel_cfg.ip_api_primary, "https://custom.api/json");
        assert_eq!(tel_cfg.ip_api_fallbacks.len(), 2);
        assert_eq!(tel_cfg.ip_api_fallbacks[0], "https://fb1.example.com");
        assert_eq!(tel_cfg.ip_api_fallbacks[1], "https://fb2.example.com");
        assert_eq!(tel_cfg.geolocation_api_fallback, "https://geo.example.com");
    }

    #[test]
    fn test_telemetry_config_from_defaults() {
        let defaults = crate::config::AppConfig::default();
        let tel_cfg = TelemetryConfig::from(&defaults);

        assert_eq!(tel_cfg.poll_rate, Duration::from_secs(30));
        assert_eq!(tel_cfg.api_timeout, 5);
        assert_eq!(tel_cfg.ping_timeout, 2);
        assert_eq!(tel_cfg.ping_targets.len(), 4);
        assert_eq!(tel_cfg.ipv6_check_apis.len(), 3);
        assert_eq!(tel_cfg.ip_api_fallbacks.len(), 3);
        assert_eq!(
            tel_cfg.geolocation_api_fallback,
            crate::constants::DEFAULT_GEOLOCATION_API_FALLBACK
        );
    }
}

use std::sync::OnceLock;

use ureq::config::{Config, IpFamily};
use ureq::Agent;

/// Lazy-init process-wide IPv4-only agent. Re-uses TCP connections + TLS
/// sessions across telemetry calls. Configured with redirects disabled to
/// match curl-without-`-L`.
///
/// Pinned to IPv4 for two reasons that both showed up in the field:
///
/// 1. An IP-echo endpoint reports the address the request arrived from. On a
///    dual-stack host the resolver hands back AAAA first for several of the
///    configured providers, so a family-agnostic GET answers with the host's
///    IPv6 — which then landed in the "Public IPv4" slot.
/// 2. A full-tunnel profile that routes only `0.0.0.0/0` leaves the kill
///    switch correctly dropping all IPv6 egress. A family-agnostic probe
///    then aims at the one family the active policy forbids and burns the
///    whole per-call timeout, every poll, so the field never refreshes.
///    Asking over IPv4 is not a relaxation of the policy — it is asking over
///    the family the policy actually carries.
fn ipv4_agent() -> &'static Agent {
    static AGENT: OnceLock<Agent> = OnceLock::new();
    AGENT.get_or_init(|| build_agent(IpFamily::Ipv4Only))
}

/// IPv6-only agent for the leak probe.
fn ipv6_agent() -> &'static Agent {
    static AGENT: OnceLock<Agent> = OnceLock::new();
    AGENT.get_or_init(|| build_agent(IpFamily::Ipv6Only))
}

fn build_agent(family: IpFamily) -> Agent {
    Config::builder()
        .max_redirects(0)
        .ip_family(family)
        .build()
        .new_agent()
}

/// GET `url` over IPv4 with the given per-call timeout. Returns the
/// response body as `String` on 2xx, `None` for any error: timeout, DNS
/// failure, connection refused, TLS failure, non-2xx status, redirect
/// (per the no-follow contract).
///
/// Matches the prior `curl -s -4 --max-time N <url>` semantics.
#[must_use]
pub fn get_text_v4(url: &str, timeout: Duration) -> Option<String> {
    get_text_v4_result(url, timeout).ok()
}

/// Failure returned by [`get_text_v4_result`]. HTTP status is retained so a
/// caller can distinguish a provider quota from a transient transport error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetTextError {
    /// The server returned a non-success HTTP status.
    HttpStatus(u16),
    /// DNS, TLS, timeout, redirect, or response-body failure.
    Transport,
}

/// GET `url` over IPv4 while preserving a non-success HTTP status for
/// provider policy.
pub fn get_text_v4_result(url: &str, timeout: Duration) -> Result<String, GetTextError> {
    let response = ipv4_agent()
        .get(url)
        .config()
        .timeout_global(Some(timeout))
        .build()
        .call();
    let mut response = match response {
        Ok(response) => response,
        Err(ureq::Error::StatusCode(status)) => return Err(GetTextError::HttpStatus(status)),
        Err(_) => return Err(GetTextError::Transport),
    };
    if !response.status().is_success() {
        return Err(GetTextError::HttpStatus(response.status().as_u16()));
    }
    response
        .body_mut()
        .read_to_string()
        .map_err(|_| GetTextError::Transport)
}

/// IPv6-only GET. Returns the trimmed response body (the host's public
/// IPv6 when the endpoint echoes it) or `None` on any failure.
#[must_use]
pub fn probe_ipv6(url: &str, timeout: Duration) -> Option<String> {
    let mut response = ipv6_agent()
        .get(url)
        .config()
        .timeout_global(Some(timeout))
        .build()
        .call()
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let body = response.body_mut().read_to_string().ok()?;
    let trimmed = body.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod http_tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    #[test]
    fn text_request_preserves_rate_limit_status() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });

        let result =
            get_text_v4_result(&format!("http://{address}/limited"), Duration::from_secs(1));
        server.join().unwrap();

        assert_eq!(result, Err(GetTextError::HttpStatus(429)));
    }

    /// The IPv4 probe must not reach a v6-only destination. This is the
    /// structural half of the "no IPv6 value in an IPv4 field" guarantee:
    /// the request cannot leave over IPv6, so the echo it reads back cannot
    /// be an IPv6 address, whatever the endpoint's DNS advertises.
    ///
    /// The mock serves real 200s and reports whether anything connected, so
    /// the assertion is that the probe never reached it — not merely that
    /// the call returned an error.
    #[test]
    fn ipv4_probe_cannot_reach_an_ipv6_only_destination() {
        use std::io::ErrorKind;
        use std::time::Instant;

        let Ok(listener) = TcpListener::bind("[::1]:0") else {
            // No IPv6 loopback on this host — nothing to assert against.
            return;
        };
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            listener.set_nonblocking(true).expect("non-blocking accept");
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).expect("blocking stream");
                        let mut request = [0_u8; 1024];
                        let _ = stream.read(&mut request);
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\n::1",
                        );
                        return true;
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return false,
                }
            }
            false
        });

        let result =
            get_text_v4_result(&format!("http://[::1]:{port}/echo"), Duration::from_secs(1));
        let connected = server.join().expect("mock server thread");

        assert!(
            !connected,
            "the IPv4 probe reached a v6-only endpoint; its answer could be an IPv6 address"
        );
        assert_eq!(result, Err(GetTextError::Transport));
    }
}
