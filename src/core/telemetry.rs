//! Background telemetry collection service.
//!
//! This module handles asynchronous collection of network telemetry data
//! including public IP address, ISP information, latency measurements,
//! DNS configuration, and IPv6 leak detection.
//!
//! The telemetry worker runs in a background thread and communicates
//! updates via an MPSC channel to the main application.

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

use crate::constants;
use crate::logger::LogLevel;
use serde::Deserialize;

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
    /// Fallback API endpoints for IP lookup.
    pub ip_api_fallbacks: Vec<String>,
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
        }
    }
}

/// Telemetry update messages sent from background workers to the main application.
#[derive(Debug, Clone)]
pub enum TelemetryUpdate {
    /// Updated public IP address.
    PublicIp(String),
    /// Updated latency measurement in milliseconds.
    Latency(u64),
    /// Packet loss percentage (0.0-100.0).
    PacketLoss(f32),
    /// Jitter (latency standard deviation) in milliseconds.
    Jitter(u64),
    /// Updated ISP/organization name.
    Isp(String),
    /// Updated DNS server address.
    Dns(String),
    /// Updated physical location (City, Country).
    Location(String),
    /// IPv6 leak detection result (true = leak detected).
    Ipv6Leak(bool),
    /// Log message with level for production logging (uses centralized logger)
    Log(LogLevel, String),
}

/// Spawns a background telemetry worker that periodically fetches network information.
///
/// # Returns
///
/// A receiver channel that yields [`TelemetryUpdate`] messages as they become available.
///
/// # Panics
///
/// This function does not panic. All errors in background threads are silently handled.
///
/// # Example
///
/// ```ignore
/// let rx = spawn_telemetry_worker();
/// while let Ok(update) = rx.try_recv() {
///     match update {
///         TelemetryUpdate::PublicIp(ip) => println!("IP: {}", ip),
///         // ...
///     }
/// }
/// ```
pub fn spawn_telemetry_worker(config: TelemetryConfig) -> Receiver<TelemetryUpdate> {
    let (tx, rx) = mpsc::channel();
    let config = std::sync::Arc::new(config);

    thread::spawn(move || loop {
        fetch_ip_and_isp(&tx, &config);
        fetch_latency(&tx, &config);
        fetch_security_info(&tx, &config);

        thread::sleep(config.poll_rate);
    });

    rx
}

/// Fetches public IP address and ISP information with fallback APIs.
fn fetch_ip_and_isp(tx: &Sender<TelemetryUpdate>, cfg: &std::sync::Arc<TelemetryConfig>) {
    let tx_clone = tx.clone();
    let cfg = std::sync::Arc::clone(cfg);
    thread::spawn(move || {
        // Log start of fetch
        let _ = tx_clone.send(TelemetryUpdate::Log(
            LogLevel::Debug,
            "Starting IP/Location fetch...".to_string(),
        ));

        // Primary: ipinfo.io (provides IP + ISP + Location)
        let _ = tx_clone.send(TelemetryUpdate::Log(
            LogLevel::Debug,
            "Trying ipinfo.io (primary API with location data)...".to_string(),
        ));

        if let Some((ip, isp, loc)) = try_ipinfo_api(&tx_clone, &cfg) {
            let _ = tx_clone.send(TelemetryUpdate::Log(
                LogLevel::Info,
                format!(
                    "✓ ipinfo.io: IP={}, ISP={}, Location={}",
                    ip,
                    isp.as_ref().unwrap_or(&"Unknown".to_string()),
                    loc.as_ref().unwrap_or(&"Unknown".to_string())
                ),
            ));
            let _ = tx_clone.send(TelemetryUpdate::PublicIp(ip));
            if let Some(org) = isp {
                let _ = tx_clone.send(TelemetryUpdate::Isp(org));
            }
            if let Some(location) = loc {
                let _ = tx_clone.send(TelemetryUpdate::Location(location));
            }
            return;
        }

        let _ = tx_clone.send(TelemetryUpdate::Log(
            LogLevel::Warning,
            "ipinfo.io failed, trying fallback APIs (no location data)...".to_string(),
        ));

        // Fallback 1: ipify.org (IP only, very reliable)
        let _ = tx_clone.send(TelemetryUpdate::Log(
            LogLevel::Debug,
            "Trying ipify.org (fallback 1, IP only)...".to_string(),
        ));

        if let Some(ip) = try_ipify_api(&tx_clone, &cfg) {
            let _ = tx_clone.send(TelemetryUpdate::Log(
                LogLevel::Info,
                format!("✓ ipify.org: IP={ip} (no ISP/location)"),
            ));
            let _ = tx_clone.send(TelemetryUpdate::PublicIp(ip));
            let _ = tx_clone.send(TelemetryUpdate::Isp("Unknown".to_string()));
            let _ = tx_clone.send(TelemetryUpdate::Location("Unknown".to_string()));
            return;
        }

        let _ = tx_clone.send(TelemetryUpdate::Log(
            LogLevel::Warning,
            "ipify.org failed, trying icanhazip.com...".to_string(),
        ));

        // Fallback 2: icanhazip.com (IP only)
        let _ = tx_clone.send(TelemetryUpdate::Log(
            LogLevel::Debug,
            "Trying icanhazip.com (fallback 2)...".to_string(),
        ));

        if let Some(ip) = try_icanhazip_api(&tx_clone, &cfg) {
            let _ = tx_clone.send(TelemetryUpdate::Log(
                LogLevel::Info,
                format!("✓ icanhazip.com: IP={ip}"),
            ));
            let _ = tx_clone.send(TelemetryUpdate::PublicIp(ip));
            let _ = tx_clone.send(TelemetryUpdate::Isp("Unknown".to_string()));
            let _ = tx_clone.send(TelemetryUpdate::Location("Unknown".to_string()));
            return;
        }

        let _ = tx_clone.send(TelemetryUpdate::Log(
            LogLevel::Warning,
            "icanhazip.com failed, trying ifconfig.me (last resort)...".to_string(),
        ));

        // Fallback 3: ifconfig.me (IP only)
        if let Some(ip) = try_ifconfig_api(&tx_clone, &cfg) {
            let _ = tx_clone.send(TelemetryUpdate::Log(
                LogLevel::Info,
                format!("✓ ifconfig.me: IP={ip}"),
            ));
            let _ = tx_clone.send(TelemetryUpdate::PublicIp(ip));
            let _ = tx_clone.send(TelemetryUpdate::Isp("Unknown".to_string()));
            let _ = tx_clone.send(TelemetryUpdate::Location("Unknown".to_string()));
            return;
        }

        // All APIs failed - report error
        let _ = tx_clone.send(TelemetryUpdate::Log(
            LogLevel::Error,
            "✗ ALL IP APIs FAILED! Check: 1) Network 2) curl installed 3) VPN routing 4) Firewall"
                .to_string(),
        ));
        let _ = tx_clone.send(TelemetryUpdate::PublicIp("Unavailable".to_string()));
    });
}

/// Try ipinfo.io API (returns IP and optionally ISP + Location) with retry
fn try_ipinfo_api(
    tx: &Sender<TelemetryUpdate>,
    cfg: &TelemetryConfig,
) -> Option<(String, Option<String>, Option<String>)> {
    let timeout = cfg.api_timeout.to_string();

    for attempt in 0..constants::RETRY_ATTEMPTS {
        let output = std::process::Command::new("curl")
            .args(["-s", "--max-time", &timeout, &cfg.ip_api_primary])
            .output();

        if let Err(e) = &output {
            let _ = tx.send(TelemetryUpdate::Log(
                LogLevel::Error,
                format!("ipinfo.io attempt {}: curl failed: {}", attempt + 1, e),
            ));
            if attempt == 0 {
                thread::sleep(std::time::Duration::from_millis(constants::RETRY_DELAY_MS));
            }
            continue;
        }

        let output = output.ok()?;

        if !output.status.success() {
            let _ = tx.send(TelemetryUpdate::Log(
                LogLevel::Debug,
                format!(
                    "ipinfo.io attempt {}: HTTP error {}",
                    attempt + 1,
                    output.status
                ),
            ));
            if attempt == 0 {
                thread::sleep(std::time::Duration::from_millis(constants::RETRY_DELAY_MS));
            }
            continue;
        }

        let text = String::from_utf8_lossy(&output.stdout);
        let _ = tx.send(TelemetryUpdate::Log(
            LogLevel::Debug,
            format!(
                "ipinfo.io attempt {}: received {} bytes",
                attempt + 1,
                text.len()
            ),
        ));

        // Use proper JSON deserialization instead of manual string parsing
        if let Some(result) = parse_ip_api_response(&text) {
            return Some(result);
        }
        let _ = tx.send(TelemetryUpdate::Log(
            LogLevel::Warning,
            format!("ipinfo.io attempt {}: failed to parse JSON", attempt + 1),
        ));

        if attempt == 0 {
            thread::sleep(std::time::Duration::from_millis(constants::RETRY_DELAY_MS));
        }
    }

    let _ = tx.send(TelemetryUpdate::Log(
        LogLevel::Warning,
        format!(
            "ipinfo.io: all {} attempts exhausted",
            constants::RETRY_ATTEMPTS
        ),
    ));
    None
}

/// Validates if a string is a valid IPv4 address
fn is_valid_ipv4(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    // Verify each octet is a valid u8 (0-255) and doesn't have leading zeros
    parts.iter().all(|part| {
        // Reject empty parts or parts with leading zeros (except "0" itself)
        if part.is_empty() || (part.len() > 1 && part.starts_with('0')) {
            return false;
        }
        part.parse::<u8>().is_ok()
    })
}

/// Try ipify.org API (IP only, very reliable) with retry
fn try_ipify_api(tx: &Sender<TelemetryUpdate>, cfg: &TelemetryConfig) -> Option<String> {
    let timeout = cfg.api_timeout.to_string();
    let url = cfg
        .ip_api_fallbacks
        .first()
        .map_or("https://api.ipify.org", String::as_str);

    for attempt in 0..constants::RETRY_ATTEMPTS {
        let output = std::process::Command::new("curl")
            .args(["-s", "--max-time", &timeout, url])
            .output();

        if let Err(e) = &output {
            let _ = tx.send(TelemetryUpdate::Log(
                LogLevel::Error,
                format!("ipify.org attempt {}: curl failed: {}", attempt + 1, e),
            ));
            if attempt == 0 {
                thread::sleep(std::time::Duration::from_millis(constants::RETRY_DELAY_MS));
            }
            continue;
        }

        let output = output.ok()?;

        if output.status.success() {
            let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();

            if !ip.is_empty() && is_valid_ipv4(&ip) {
                return Some(ip);
            }
            let _ = tx.send(TelemetryUpdate::Log(
                LogLevel::Warning,
                format!(
                    "ipify.org attempt {}: invalid IP format: '{}'",
                    attempt + 1,
                    ip
                ),
            ));
        } else {
            let _ = tx.send(TelemetryUpdate::Log(
                LogLevel::Debug,
                format!("ipify.org attempt {}: HTTP error", attempt + 1),
            ));
        }

        if attempt == 0 {
            thread::sleep(std::time::Duration::from_millis(constants::RETRY_DELAY_MS));
        }
    }

    let _ = tx.send(TelemetryUpdate::Log(
        LogLevel::Warning,
        "ipify.org: all attempts failed".to_string(),
    ));
    None
}

/// Try icanhazip.com API (IP only) with retry
fn try_icanhazip_api(tx: &Sender<TelemetryUpdate>, cfg: &TelemetryConfig) -> Option<String> {
    let timeout = cfg.api_timeout.to_string();
    let url = cfg
        .ip_api_fallbacks
        .get(1)
        .map_or("https://icanhazip.com", String::as_str);

    for attempt in 0..constants::RETRY_ATTEMPTS {
        let output = std::process::Command::new("curl")
            .args(["-s", "--max-time", &timeout, url])
            .output();

        if let Err(e) = &output {
            let _ = tx.send(TelemetryUpdate::Log(
                LogLevel::Error,
                format!("icanhazip.com: curl failed: {e}"),
            ));
            continue;
        }

        let output = output.ok()?;

        if output.status.success() {
            let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !ip.is_empty() {
                return Some(ip);
            }
        }

        if attempt == 0 {
            thread::sleep(std::time::Duration::from_millis(constants::RETRY_DELAY_MS));
        }
    }
    None
}

/// Try ifconfig.me API (IP only) with retry
fn try_ifconfig_api(tx: &Sender<TelemetryUpdate>, cfg: &TelemetryConfig) -> Option<String> {
    let timeout = cfg.api_timeout.to_string();
    let url = cfg
        .ip_api_fallbacks
        .get(2)
        .map_or("https://ifconfig.me/ip", String::as_str);

    for attempt in 0..constants::RETRY_ATTEMPTS {
        let output = std::process::Command::new("curl")
            .args(["-s", "--max-time", &timeout, url])
            .output();

        if let Err(e) = &output {
            let _ = tx.send(TelemetryUpdate::Log(
                LogLevel::Error,
                format!("ifconfig.me: curl failed: {e}"),
            ));
            continue;
        }

        let output = output.ok()?;

        if output.status.success() {
            let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !ip.is_empty() {
                return Some(ip);
            }
        }

        if attempt == 0 {
            thread::sleep(std::time::Duration::from_millis(constants::RETRY_DELAY_MS));
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

/// Legacy function kept for backward compatibility with tests
/// DEPRECATED: Use `parse_ip_api_response` instead
#[cfg(test)]
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    // Use proper JSON parsing now
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    value.get(key)?.as_str().map(String::from)
}

/// Parsed ping output statistics.
#[derive(Debug, Default, PartialEq)]
pub struct PingStats {
    pub latency_ms: u64,
    pub packet_loss: f32,
    pub jitter_ms: u64,
}

/// Parse ping command output to extract latency, packet loss, and jitter.
///
/// Handles both macOS and Linux output formats:
/// - macOS: "round-trip min/avg/max/stddev = 1.234/5.678/9.012/3.456 ms"
/// - Linux: "rtt min/avg/max/mdev = 1.234/5.678/9.012/3.456 ms"
/// - macOS loss: "10 packets transmitted, 8 packets received, 20.0% packet loss"
/// - Linux loss: "10 packets transmitted, 8 received, 20% packet loss, time 9001ms"
pub fn parse_ping_output(output: &str) -> PingStats {
    let mut stats = PingStats::default();

    for line in output.lines() {
        if line.contains("packet loss") {
            if let Some(loss_idx) = line.find("% packet loss") {
                let before_loss = &line[..loss_idx];
                if let Some(percent_str) = before_loss
                    .split([',', ' '])
                    .filter(|s| !s.is_empty())
                    .rfind(|s| s.chars().all(|c| c.is_ascii_digit() || c == '.'))
                {
                    if let Ok(val) = percent_str.parse::<f32>() {
                        stats.packet_loss = val;
                    }
                }
            }
        }

        // Handle both "min/avg/max/stddev" (Linux mdev) and "round-trip min/avg/max/stddev" (macOS)
        if line.contains("min/avg/max") {
            if let Some(eq_pos) = line.find('=') {
                let values_str = &line[eq_pos + 1..].trim();
                let values: Vec<&str> = values_str.split('/').collect();
                if values.len() >= 4 {
                    if let Ok(avg) = values[1].trim().parse::<f64>() {
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        {
                            stats.latency_ms = avg.max(0.0) as u64;
                        }
                    }
                    let stddev_str = values[3].trim_end_matches(" ms").trim();
                    if let Ok(stddev) = stddev_str.parse::<f64>() {
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        {
                            stats.jitter_ms = stddev.max(0.0) as u64;
                        }
                    }
                }
            }
        }
    }

    stats
}

/// Parse `/proc/net/dev` output (Linux) to get total bytes in/out.
#[allow(dead_code)]
///
/// Format: `iface: rx_bytes rx_packets rx_errs ... tx_bytes tx_packets tx_errs ...`
/// Returns (`total_bytes_in`, `total_bytes_out`) excluding loopback.
pub fn parse_proc_net_dev(content: &str) -> (u64, u64) {
    let mut total_in: u64 = 0;
    let mut total_out: u64 = 0;

    for line in content.lines().skip(2) {
        // Skip 2 header lines
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Split on ':' to get interface name and stats
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }

        let iface = parts[0].trim();
        // Skip loopback
        if iface == "lo" {
            continue;
        }

        let stats: Vec<&str> = parts[1].split_whitespace().collect();
        // rx_bytes is index 0, tx_bytes is index 8
        if stats.len() >= 10 {
            if let Ok(rx) = stats[0].parse::<u64>() {
                total_in += rx;
            }
            if let Ok(tx) = stats[8].parse::<u64>() {
                total_out += tx;
            }
        }
    }

    (total_in, total_out)
}

/// Parse `ip addr show {iface}` output (Linux) to extract IP and MTU.
#[allow(dead_code)]
///
/// Returns (`ip_address`, `mtu`).
pub fn parse_ip_addr_output(output: &str) -> (String, String) {
    let mut ip = String::new();
    let mut mtu = String::new();

    for line in output.lines() {
        let trimmed = line.trim();
        // MTU is on the first line: "4: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 ..."
        if trimmed.contains("mtu ") && mtu.is_empty() {
            if let Some(mtu_idx) = trimmed.find("mtu ") {
                let rest = &trimmed[mtu_idx + 4..];
                if let Some(val) = rest.split_whitespace().next() {
                    mtu = val.to_string();
                }
            }
        }
        // IP is on an "inet " line: "    inet 10.0.0.2/32 scope global wg0"
        if trimmed.starts_with("inet ") && ip.is_empty() {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                // Strip CIDR notation if present
                ip = parts[1].split('/').next().unwrap_or("").to_string();
            }
        }
    }

    (ip, mtu)
}

/// Measures network latency, packet loss, and jitter by pinging reliable hosts.
fn fetch_latency(tx: &Sender<TelemetryUpdate>, cfg: &std::sync::Arc<TelemetryConfig>) {
    let tx_clone = tx.clone();
    let cfg = std::sync::Arc::clone(cfg);
    thread::spawn(move || {
        // macOS ping -W takes milliseconds; Linux ping -W takes seconds
        #[cfg(target_os = "macos")]
        let timeout = (cfg.ping_timeout * 1000).to_string();
        #[cfg(not(target_os = "macos"))]
        let timeout = cfg.ping_timeout.to_string();

        for target in &cfg.ping_targets {
            for attempt in 0..constants::RETRY_ATTEMPTS {
                if let Ok(output) = std::process::Command::new("ping")
                    .args(["-c", "3", "-i", "0.2", "-W", &timeout, target])
                    .output()
                {
                    if output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stats = parse_ping_output(&stdout);

                        if stats.latency_ms > 0 {
                            let _ = tx_clone.send(TelemetryUpdate::Latency(stats.latency_ms));
                            let _ = tx_clone.send(TelemetryUpdate::PacketLoss(stats.packet_loss));
                            let _ = tx_clone.send(TelemetryUpdate::Jitter(stats.jitter_ms));
                            return;
                        }
                    }
                }

                if attempt == 0 {
                    thread::sleep(std::time::Duration::from_millis(constants::RETRY_DELAY_MS));
                }
            }
        }

        let _ = tx_clone.send(TelemetryUpdate::Latency(0));
        let _ = tx_clone.send(TelemetryUpdate::PacketLoss(100.0));
        let _ = tx_clone.send(TelemetryUpdate::Jitter(0));
    });
}

/// Fetches DNS configuration and checks for IPv6 leaks.
fn fetch_security_info(tx: &Sender<TelemetryUpdate>, cfg: &std::sync::Arc<TelemetryConfig>) {
    let tx_clone = tx.clone();
    let cfg = std::sync::Arc::clone(cfg);
    thread::spawn(move || {
        // Use platform-specific DNS resolution
        let dns = {
            #[cfg(target_os = "macos")]
            {
                use crate::platform::DnsResolver;
                crate::platform::macos::dns::MacDns::get_dns_server()
            }
            #[cfg(target_os = "linux")]
            {
                use crate::platform::DnsResolver;
                crate::platform::linux::dns::LinuxDns::get_dns_server()
            }
        };

        if let Some(dns_server) = dns {
            let _ = tx_clone.send(TelemetryUpdate::Dns(dns_server));
        }

        // Check for IPv6 connectivity with multiple endpoints (indicates potential leak when VPN active)
        let mut is_leaking = false;
        let ipv6_timeout = cfg.api_timeout.to_string();
        for endpoint in &cfg.ipv6_check_apis {
            let output6 = std::process::Command::new("curl")
                .args(["-6", "-s", "--max-time", &ipv6_timeout, endpoint])
                .output();
            if output6.map(|o| o.status.success()).unwrap_or(false) {
                is_leaking = true;
                break;
            }
        }
        let _ = tx_clone.send(TelemetryUpdate::Ipv6Leak(is_leaking));
    });
}

/// Network traffic statistics tracker.
///
/// Tracks cumulative byte counts and calculates per-second throughput rates.
#[derive(Default)]
pub struct NetworkStats {
    last_bytes_in: u64,
    last_bytes_out: u64,
}

impl NetworkStats {
    /// Updates network statistics by reading system interface data.
    ///
    /// Uses platform-specific implementations:
    /// - macOS: `netstat -ib` with dynamic column detection
    /// - Linux: `/proc/net/dev` parsing
    ///
    /// # Returns
    ///
    /// A tuple of (`bytes_down_per_second`, `bytes_up_per_second`).
    pub fn update(&mut self) -> (u64, u64) {
        let mut current_down = 0u64;
        let mut current_up = 0u64;

        let (total_bytes_in, total_bytes_out) = {
            #[cfg(target_os = "macos")]
            {
                use crate::platform::NetworkStatsProvider;
                crate::platform::macos::network::MacNetworkStats::get_total_bytes()
            }
            #[cfg(target_os = "linux")]
            {
                use crate::platform::NetworkStatsProvider;
                crate::platform::linux::network::LinuxNetworkStats::get_total_bytes()
            }
        };

        // Calculate rate (bytes per second since last tick)
        // First call returns 0 as we're establishing baseline
        if self.last_bytes_in > 0 {
            current_down = total_bytes_in.saturating_sub(self.last_bytes_in);
            current_up = total_bytes_out.saturating_sub(self.last_bytes_out);
        }
        self.last_bytes_in = total_bytes_in;
        self.last_bytes_out = total_bytes_out;

        (current_down, current_up)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_json_string_ip() {
        let json = r#"{"ip": "1.2.3.4", "org": "Test ISP"}"#;
        assert_eq!(extract_json_string(json, "ip"), Some("1.2.3.4".to_string()));
    }

    #[test]
    fn test_extract_json_string_org() {
        let json = r#"{"ip": "1.2.3.4", "org": "AS12345 Test Company"}"#;
        assert_eq!(
            extract_json_string(json, "org"),
            Some("AS12345 Test Company".to_string())
        );
    }

    #[test]
    fn test_extract_json_string_missing_key() {
        let json = r#"{"ip": "1.2.3.4"}"#;
        assert_eq!(extract_json_string(json, "org"), None);
    }

    #[test]
    fn test_extract_json_string_with_whitespace() {
        let json = r#"{"ip":   "1.2.3.4"}"#;
        assert_eq!(extract_json_string(json, "ip"), Some("1.2.3.4".to_string()));
    }

    #[test]
    fn test_extract_json_string_empty() {
        let json = r"{}";
        assert_eq!(extract_json_string(json, "ip"), None);
    }

    #[test]
    fn test_network_stats_new() {
        let stats = NetworkStats::default();
        assert_eq!(stats.last_bytes_in, 0);
        assert_eq!(stats.last_bytes_out, 0);
    }

    #[test]
    fn test_network_stats_initial_update() {
        let mut stats = NetworkStats::default();
        let (down, up) = stats.update();
        // First update should return 0 (no previous baseline)
        assert_eq!(down, 0);
        assert_eq!(up, 0);
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
    }

    // === Ping output parsing tests ===

    #[test]
    fn test_parse_ping_output_macos() {
        let output = "\
PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=1.234 ms
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=5.678 ms

--- 1.1.1.1 ping statistics ---
10 packets transmitted, 10 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 1.234/5.678/9.012/3.456 ms";

        let stats = parse_ping_output(output);
        assert_eq!(stats.latency_ms, 5); // avg 5.678 truncated to u64
        assert!((stats.packet_loss - 0.0).abs() < f32::EPSILON);
        assert_eq!(stats.jitter_ms, 3); // stddev 3.456 truncated to u64
    }

    #[test]
    fn test_parse_ping_output_linux() {
        let output = "\
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=1.23 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=5.67 ms

--- 1.1.1.1 ping statistics ---
10 packets transmitted, 8 received, 20% packet loss, time 9001ms
rtt min/avg/max/mdev = 1.234/5.678/9.012/3.456 ms";

        let stats = parse_ping_output(output);
        assert_eq!(stats.latency_ms, 5);
        assert!((stats.packet_loss - 20.0).abs() < f32::EPSILON);
        assert_eq!(stats.jitter_ms, 3);
    }

    #[test]
    fn test_parse_ping_output_100_percent_loss() {
        let output = "\
--- 1.1.1.1 ping statistics ---
10 packets transmitted, 0 packets received, 100.0% packet loss";

        let stats = parse_ping_output(output);
        assert_eq!(stats.latency_ms, 0);
        assert!((stats.packet_loss - 100.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_parse_ping_output_empty() {
        let stats = parse_ping_output("");
        assert_eq!(stats, PingStats::default());
    }

    // === /proc/net/dev parsing tests ===

    #[test]
    fn test_parse_proc_net_dev() {
        let content = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000       10    0    0    0     0          0         0     1000       10    0    0    0     0       0          0
  eth0: 5000       50    0    0    0     0          0         0     3000       30    0    0    0     0       0          0
  wg0:  2000       20    0    0    0     0          0         0     1500       15    0    0    0     0       0          0";

        let (bytes_in, bytes_out) = parse_proc_net_dev(content);
        // Should skip lo (1000/1000) and sum eth0 (5000/3000) + wg0 (2000/1500)
        assert_eq!(bytes_in, 7000);
        assert_eq!(bytes_out, 4500);
    }

    #[test]
    fn test_parse_proc_net_dev_only_loopback() {
        let content = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000       10    0    0    0     0          0         0     1000       10    0    0    0     0       0          0";

        let (bytes_in, bytes_out) = parse_proc_net_dev(content);
        assert_eq!(bytes_in, 0);
        assert_eq!(bytes_out, 0);
    }

    #[test]
    fn test_parse_proc_net_dev_empty() {
        let (bytes_in, bytes_out) = parse_proc_net_dev("");
        assert_eq!(bytes_in, 0);
        assert_eq!(bytes_out, 0);
    }

    // === ip addr output parsing tests ===

    #[test]
    fn test_parse_ip_addr_output_wireguard() {
        let output = "\
4: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN group default qlen 1000
    link/none
    inet 10.0.0.2/32 scope global wg0
       valid_lft forever preferred_lft forever";

        let (ip, mtu) = parse_ip_addr_output(output);
        assert_eq!(ip, "10.0.0.2");
        assert_eq!(mtu, "1420");
    }

    #[test]
    fn test_parse_ip_addr_output_tun() {
        let output = "\
5: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none
    inet 10.8.0.6/24 brd 10.8.0.255 scope global tun0
       valid_lft forever preferred_lft forever";

        let (ip, mtu) = parse_ip_addr_output(output);
        assert_eq!(ip, "10.8.0.6");
        assert_eq!(mtu, "1500");
    }

    #[test]
    fn test_parse_ip_addr_output_empty() {
        let (ip, mtu) = parse_ip_addr_output("");
        assert!(ip.is_empty());
        assert!(mtu.is_empty());
    }

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

    // === TelemetryConfig conversion ===

    #[test]
    fn test_telemetry_config_from_app_config() {
        let app_cfg = crate::config::AppConfig {
            tick_rate: 500, // not used by TelemetryConfig
            telemetry_poll_rate: 45,
            api_timeout: 8,
            ping_timeout: 3,
            connect_timeout: 30, // not used by TelemetryConfig
            ping_targets: vec!["4.4.4.4".to_string()],
            ipv6_check_apis: vec!["https://v6.example.com".to_string()],
            ip_api_primary: "https://custom.api/json".to_string(),
            ip_api_fallbacks: vec![
                "https://fb1.example.com".to_string(),
                "https://fb2.example.com".to_string(),
            ],
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
    }
}
