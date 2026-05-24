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

/// Returns the current default gateway IP via the platform aggregate.
fn get_default_gateway() -> Option<String> {
    crate::platform::current_platform()
        .route_table
        .default_gateway()
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
