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

use crate::constants;
use crate::logger::LogLevel;
use serde::Deserialize;

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
pub fn spawn_telemetry_worker() -> Receiver<TelemetryUpdate> {
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || loop {
        fetch_ip_and_isp(&tx);
        fetch_latency(&tx);
        fetch_security_info(&tx);

        thread::sleep(constants::TELEMETRY_POLL_RATE);
    });

    rx
}

/// Fetches public IP address and ISP information with fallback APIs.
fn fetch_ip_and_isp(tx: &Sender<TelemetryUpdate>) {
    let tx_clone = tx.clone();
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

        if let Some((ip, isp, loc)) = try_ipinfo_api(&tx_clone) {
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

        if let Some(ip) = try_ipify_api(&tx_clone) {
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

        if let Some(ip) = try_icanhazip_api(&tx_clone) {
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
        if let Some(ip) = try_ifconfig_api(&tx_clone) {
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
) -> Option<(String, Option<String>, Option<String>)> {
    let timeout = constants::API_TIMEOUT_SECS.to_string();

    for attempt in 0..constants::RETRY_ATTEMPTS {
        let output = std::process::Command::new("curl")
            .args(["-s", "--max-time", &timeout, constants::IP_API_PRIMARY])
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
fn try_ipify_api(tx: &Sender<TelemetryUpdate>) -> Option<String> {
    let timeout = constants::API_TIMEOUT_SECS.to_string();

    for attempt in 0..constants::RETRY_ATTEMPTS {
        let output = std::process::Command::new("curl")
            .args(["-s", "--max-time", &timeout, constants::IP_API_FALLBACK_1])
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
fn try_icanhazip_api(tx: &Sender<TelemetryUpdate>) -> Option<String> {
    let timeout = constants::API_TIMEOUT_SECS.to_string();

    for attempt in 0..constants::RETRY_ATTEMPTS {
        let output = std::process::Command::new("curl")
            .args(["-s", "--max-time", &timeout, constants::IP_API_FALLBACK_2])
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
fn try_ifconfig_api(tx: &Sender<TelemetryUpdate>) -> Option<String> {
    let timeout = constants::API_TIMEOUT_SECS.to_string();

    for attempt in 0..constants::RETRY_ATTEMPTS {
        let output = std::process::Command::new("curl")
            .args(["-s", "--max-time", &timeout, constants::IP_API_FALLBACK_3])
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

/// Measures network latency, packet loss, and jitter by pinging reliable hosts.
fn fetch_latency(tx: &Sender<TelemetryUpdate>) {
    let tx_clone = tx.clone();
    thread::spawn(move || {
        let timeout = constants::PING_TIMEOUT_SECS.to_string();

        for target in constants::PING_TARGETS {
            for attempt in 0..constants::RETRY_ATTEMPTS {
                if let Ok(output) = std::process::Command::new("ping")
                    .args(["-c", "10", "-i", "0.2", "-t", &timeout, target])
                    .output()
                {
                    if output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout);

                        let mut latency_ms = 0u64;
                        let mut packet_loss = 0.0f32;
                        let mut jitter_ms = 0u64;

                        for line in stdout.lines() {
                            if line.contains("packet loss") {
                                // Robust parsing for different ping formats:
                                // macOS:  "10 packets transmitted, 8 packets received, 20.0% packet loss"
                                // Linux:  "10 packets transmitted, 8 received, 20% packet loss, time 9001ms"
                                //
                                // Strategy: Find "% packet loss" and work backwards to get the number
                                if let Some(loss_idx) = line.find("% packet loss") {
                                    // Extract substring before "% packet loss"
                                    let before_loss = &line[..loss_idx];

                                    // Find the last number (which should be the packet loss percentage)
                                    // Split by common delimiters and take the last numeric token
                                    if let Some(percent_str) = before_loss
                                        .split([',', ' '])
                                        .filter(|s| !s.is_empty())
                                        .rfind(|s| {
                                            s.chars().all(|c| c.is_ascii_digit() || c == '.')
                                        })
                                    {
                                        if let Ok(val) = percent_str.parse::<f32>() {
                                            packet_loss = val;
                                        }
                                    }
                                }
                            }

                            // Handle both "min/avg/max/stddev" (Linux) and "round-trip min/avg/max/stddev" (macOS)
                            if line.contains("min/avg/max") {
                                // Find the = sign and parse what comes after
                                if let Some(eq_pos) = line.find('=') {
                                    let values_str = &line[eq_pos + 1..].trim();
                                    let values: Vec<&str> = values_str.split('/').collect();
                                    if values.len() >= 4 {
                                        // avg is index 1
                                        if let Ok(avg) = values[1].trim().parse::<f64>() {
                                            #[allow(
                                                clippy::cast_possible_truncation,
                                                clippy::cast_sign_loss
                                            )]
                                            {
                                                latency_ms = avg.max(0.0) as u64;
                                            }
                                        }
                                        // stddev is index 3, might have " ms" suffix
                                        let stddev_str = values[3].trim_end_matches(" ms").trim();
                                        if let Ok(stddev) = stddev_str.parse::<f64>() {
                                            #[allow(
                                                clippy::cast_possible_truncation,
                                                clippy::cast_sign_loss
                                            )]
                                            {
                                                jitter_ms = stddev.max(0.0) as u64;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if latency_ms > 0 {
                            let _ = tx_clone.send(TelemetryUpdate::Latency(latency_ms));
                            let _ = tx_clone.send(TelemetryUpdate::PacketLoss(packet_loss));
                            let _ = tx_clone.send(TelemetryUpdate::Jitter(jitter_ms));
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
fn fetch_security_info(tx: &Sender<TelemetryUpdate>) {
    let tx_clone = tx.clone();
    thread::spawn(move || {
        // Try multiple methods to get DNS server
        let dns = try_get_dns_resolv_conf()
            .or_else(try_get_dns_scutil)
            .or_else(try_get_dns_networksetup);

        if let Some(dns_server) = dns {
            let _ = tx_clone.send(TelemetryUpdate::Dns(dns_server));
        }

        // Check for IPv6 connectivity with multiple endpoints (indicates potential leak when VPN active)
        let mut is_leaking = false;
        for endpoint in constants::IPV6_CHECK_APIS {
            let output6 = std::process::Command::new("curl")
                .args(["-6", "-s", "--max-time", "2", endpoint])
                .output();
            if output6.map(|o| o.status.success()).unwrap_or(false) {
                is_leaking = true;
                break;
            }
        }
        let _ = tx_clone.send(TelemetryUpdate::Ipv6Leak(is_leaking));
    });
}

/// Try to get DNS from /etc/resolv.conf
fn try_get_dns_resolv_conf() -> Option<String> {
    let output = std::process::Command::new("grep")
        .args(["nameserver", "/etc/resolv.conf"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next()?;
    let dns = line.replace("nameserver", "").trim().to_string();
    if dns.is_empty() {
        return None;
    }
    Some(dns)
}

/// Try to get DNS from scutil (macOS)
fn try_get_dns_scutil() -> Option<String> {
    let output = std::process::Command::new("scutil")
        .args(["--dns"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("nameserver[0]") {
            if let Some(dns) = trimmed.split(':').nth(1) {
                let dns = dns.trim().to_string();
                if !dns.is_empty() {
                    return Some(dns);
                }
            }
        }
    }
    None
}

/// Try to get DNS from networksetup (macOS)
fn try_get_dns_networksetup() -> Option<String> {
    // First get the primary service
    let output = std::process::Command::new("networksetup")
        .args(["-listallnetworkservices"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Try common service names
    for service in ["Wi-Fi", "Ethernet", "USB 10/100/1000 LAN"] {
        if stdout.contains(service) {
            if let Ok(dns_output) = std::process::Command::new("networksetup")
                .args(["-getdnsservers", service])
                .output()
            {
                let dns_stdout = String::from_utf8_lossy(&dns_output.stdout);
                let first_line = dns_stdout.lines().next().unwrap_or("").trim();
                // Skip "There aren't any DNS Servers" message
                if !first_line.is_empty() && !first_line.contains("aren't") {
                    return Some(first_line.to_string());
                }
            }
        }
    }
    None
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
    /// Parses `netstat -ib` output on macOS/Unix to calculate network throughput.
    /// Uses dynamic column detection for robustness across different netstat versions.
    ///
    /// # Returns
    ///
    /// A tuple of (`bytes_down_per_second`, `bytes_up_per_second`).
    pub fn update(&mut self) -> (u64, u64) {
        let mut current_down = 0u64;
        let mut current_up = 0u64;

        if let Ok(output) = std::process::Command::new("netstat").args(["-ib"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut lines = stdout.lines();

            // Parse header row to find column indices (robust against format changes)
            let (ibytes_idx, obytes_idx) = if let Some(header) = lines.next() {
                let headers: Vec<&str> = header.split_whitespace().collect();
                let ibytes_pos = headers
                    .iter()
                    .position(|&h| h.eq_ignore_ascii_case("ibytes"));
                let obytes_pos = headers
                    .iter()
                    .position(|&h| h.eq_ignore_ascii_case("obytes"));

                match (ibytes_pos, obytes_pos) {
                    (Some(i), Some(o)) => (i, o),
                    // Fallback to traditional positions if headers don't match expected format
                    // Standard macOS format: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes
                    _ => (6, 9),
                }
            } else {
                return (current_down, current_up);
            };

            let mut total_bytes_in: u64 = 0;
            let mut total_bytes_out: u64 = 0;

            // Parse data rows
            for line in lines {
                let parts: Vec<&str> = line.split_whitespace().collect();

                // Ensure we have enough columns for both Ibytes and Obytes
                if parts.len() > ibytes_idx.max(obytes_idx) {
                    let iface = parts[0];

                    // Skip loopback interfaces (lo0, lo1, etc.)
                    if iface.starts_with("lo") {
                        continue;
                    }

                    // Validate that the columns contain valid numbers before parsing
                    if let (Some(ibytes_str), Some(obytes_str)) =
                        (parts.get(ibytes_idx), parts.get(obytes_idx))
                    {
                        // Additional validation: check if these look like numbers
                        if ibytes_str.chars().all(|c| c.is_ascii_digit())
                            && obytes_str.chars().all(|c| c.is_ascii_digit())
                        {
                            if let (Ok(ibytes), Ok(obytes)) =
                                (ibytes_str.parse::<u64>(), obytes_str.parse::<u64>())
                            {
                                total_bytes_in += ibytes;
                                total_bytes_out += obytes;
                            }
                        }
                    }
                }
            }

            // Calculate rate (bytes per second since last tick)
            // First call returns 0 as we're establishing baseline
            if self.last_bytes_in > 0 {
                current_down = total_bytes_in.saturating_sub(self.last_bytes_in);
                current_up = total_bytes_out.saturating_sub(self.last_bytes_out);
            }
            self.last_bytes_in = total_bytes_in;
            self.last_bytes_out = total_bytes_out;
        }

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
}
