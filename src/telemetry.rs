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

/// Telemetry update messages sent from background workers to the main application.
#[derive(Debug)]
pub enum TelemetryUpdate {
    /// Updated public IP address.
    PublicIp(String),
    /// Updated latency measurement in milliseconds.
    Latency(u64),
    /// Updated ISP/organization name.
    Isp(String),
    /// Updated DNS server address.
    Dns(String),
    /// IPv6 leak detection result (true = leak detected).
    Ipv6Leak(bool),
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

        thread::sleep(crate::constants::TELEMETRY_POLL_RATE);
    });

    rx
}

/// Fetches public IP address and ISP information from the ipinfo.io API.
fn fetch_ip_and_isp(tx: &Sender<TelemetryUpdate>) {
    let tx_clone = tx.clone();
    thread::spawn(move || {
        if let Ok(output) = std::process::Command::new("curl")
            .args(["-s", crate::constants::IP_TELEMETRY_API])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            // Parse "ip" field from JSON response
            if let Some(ip) = extract_json_string(&text, "ip") {
                let _ = tx_clone.send(TelemetryUpdate::PublicIp(ip));
            }
            // Parse "org" field from JSON response
            if let Some(org) = extract_json_string(&text, "org") {
                let _ = tx_clone.send(TelemetryUpdate::Isp(org));
            }
        }
    });
}

/// Extracts a string value from a simple JSON object.
/// Looks for pattern `"key": "value"` and returns the value.
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\":");
    let start = json.find(&pattern)? + pattern.len();
    let rest = &json[start..];
    // Skip whitespace and find opening quote
    let rest = rest.trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let rest = &rest[1..]; // Skip opening quote
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Measures network latency by pinging a known reliable host.
fn fetch_latency(tx: &Sender<TelemetryUpdate>) {
    let tx_clone = tx.clone();
    thread::spawn(move || {
        if let Ok(output) = std::process::Command::new("ping")
            .args(["-c", "1", "-t", "2", crate::constants::PING_TARGET])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(time_idx) = stdout.find("time=") {
                let part = &stdout[time_idx + 5..];
                if let Some(ms_idx) = part.find(" ms") {
                    if let Ok(ms) = part[..ms_idx].parse::<f64>() {
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        let latency = ms.max(0.0) as u64;
                        let _ = tx_clone.send(TelemetryUpdate::Latency(latency));
                    }
                }
            }
        }
    });
}

/// Fetches DNS configuration and checks for IPv6 leaks.
fn fetch_security_info(tx: &Sender<TelemetryUpdate>) {
    let tx_clone = tx.clone();
    thread::spawn(move || {
        // Check DNS server from resolv.conf
        if let Ok(output) = std::process::Command::new("grep")
            .args(["nameserver", "/etc/resolv.conf"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(line) = stdout.lines().next() {
                let dns = line.replace("nameserver", "").trim().to_string();
                if !dns.is_empty() {
                    let _ = tx_clone.send(TelemetryUpdate::Dns(dns));
                }
            }
        }

        // Check for IPv6 connectivity (indicates potential leak when VPN active)
        let output6 = std::process::Command::new("curl")
            .args([
                "-6",
                "-s",
                "--max-time",
                "2",
                crate::constants::IPV6_CHECK_API,
            ])
            .output();
        let is_leaking = output6.map(|o| o.status.success()).unwrap_or(false);
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
    /// Creates a new network stats tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Updates network statistics by reading system interface data.
    ///
    /// Parses `netstat -ib` output on macOS to calculate network throughput.
    ///
    /// # Returns
    ///
    /// A tuple of (`bytes_down_per_second`, `bytes_up_per_second`).
    pub fn update(&mut self) -> (u64, u64) {
        let mut current_down = 0u64;
        let mut current_up = 0u64;

        if let Ok(output) = std::process::Command::new("netstat").args(["-ib"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut total_bytes_in: u64 = 0;
            let mut total_bytes_out: u64 = 0;

            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // netstat -ib format: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes
                if parts.len() >= 10 {
                    let iface = parts[0];
                    // Skip loopback interfaces
                    if iface.starts_with("lo") {
                        continue;
                    }
                    if let (Ok(ibytes), Ok(obytes)) =
                        (parts[6].parse::<u64>(), parts[9].parse::<u64>())
                    {
                        total_bytes_in += ibytes;
                        total_bytes_out += obytes;
                    }
                }
            }

            // Calculate rate (bytes per second since last tick)
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
        let json = r#"{}"#;
        assert_eq!(extract_json_string(json, "ip"), None);
    }

    #[test]
    fn test_network_stats_new() {
        let stats = NetworkStats::new();
        assert_eq!(stats.last_bytes_in, 0);
        assert_eq!(stats.last_bytes_out, 0);
    }

    #[test]
    fn test_network_stats_initial_update() {
        let mut stats = NetworkStats::new();
        let (down, up) = stats.update();
        // First update should return 0 (no previous baseline)
        assert_eq!(down, 0);
        assert_eq!(up, 0);
    }
}
