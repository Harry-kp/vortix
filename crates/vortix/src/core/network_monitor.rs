//! Network change detection via default gateway monitoring.
//!
//! Spawns a lightweight background thread that periodically checks
//! the system's default gateway. When the gateway changes (e.g. `WiFi`
//! switch, sleep/wake, mobile hotspot), it sends a notification through
//! a channel so the app can trigger auto-reconnect.

use std::sync::mpsc;

/// Events emitted by the network monitor.
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// The default gateway changed (old, new).
    GatewayChanged {
        old: Option<String>,
        new: Option<String>,
    },
}

/// Returns the current default gateway IP, or `None` if unavailable.
#[cfg(target_os = "macos")]
fn get_default_gateway() -> Option<String> {
    let output = std::process::Command::new("route")
        .args(["get", "default"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(gw) = trimmed.strip_prefix("gateway:") {
            let gw = gw.trim();
            if !gw.is_empty() {
                return Some(gw.to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn get_default_gateway() -> Option<String> {
    let output = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    // Format: "default via 192.168.1.1 dev wlan0 ..."
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "default" && parts[1] == "via" {
            return Some(parts[2].to_string());
        }
    }
    None
}

/// Spawns a background thread that monitors the default gateway.
///
/// Returns a receiver that emits [`NetworkEvent`] values when the
/// gateway changes. The thread exits when the receiver is dropped.
#[must_use]
pub fn spawn_network_monitor(poll_interval: std::time::Duration) -> mpsc::Receiver<NetworkEvent> {
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let mut last_gateway = get_default_gateway();

        loop {
            std::thread::sleep(poll_interval);

            let current = get_default_gateway();
            if current != last_gateway {
                let event = NetworkEvent::GatewayChanged {
                    old: last_gateway.clone(),
                    new: current.clone(),
                };
                if tx.send(event).is_err() {
                    break; // Receiver dropped, exit thread
                }
                last_gateway = current;
            }
        }
    });

    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_default_gateway_returns_some_or_none() {
        // Just verify it doesn't panic; actual result depends on system config
        let _gw = get_default_gateway();
    }
}
