//! Background telemetry and scanner polling.

use std::sync::mpsc;
use std::time::SystemTime;

use super::App;
use crate::constants;
use crate::core::network_monitor::NetworkEvent;
use crate::core::scanner;
use crate::logger::LogLevel;
use crate::message::Message;
use crate::vortix_core::engine::state::Connection;

impl App {
    /// Processes pending telemetry updates from the background worker.
    /// Called frequently to ensure logs appear immediately.
    pub(crate) fn process_telemetry(&mut self) {
        let updates: Vec<_> = if let Some(rx) = &self.runtime.telemetry_rx {
            rx.try_iter().collect()
        } else {
            return;
        };

        for update in updates {
            self.handle_message(Message::Telemetry(update));
        }
    }

    /// Wake the telemetry worker so it refreshes IP/ISP/latency immediately.
    pub(crate) fn refresh_telemetry(&self) {
        if let Some(nudge) = &self.runtime.telemetry_nudge {
            let _ = nudge.send(());
        }
    }

    /// Poll the scanner channel and kick off a new scan if idle.
    ///
    /// Pattern: spawn a short-lived thread per tick (only when the previous one
    /// has finished). No long-running threads, no shared mutable state.
    pub(crate) fn poll_scanner(&mut self) {
        // 1. Try to collect a result from the previous scan
        let mut result = None;
        if let Some(rx) = &self.runtime.scanner_rx {
            match rx.try_recv() {
                Ok(active) => {
                    result = Some(active);
                    self.runtime.scanner_rx = None; // Mark: ready for next scan
                }
                Err(mpsc::TryRecvError::Empty) => {
                    // Previous scan still running — don't start another.
                    // Log slow scanners against the in-flight tunnel (if any).
                    // With multi-tunnel: pick the earliest-started Connecting
                    // entry so the warning targets the tunnel users are
                    // actually waiting on.
                    if let Some((profile_id, started_at)) = self
                        .registry
                        .snapshot_all()
                        .into_iter()
                        .filter_map(|s| match s.state {
                            Connection::Connecting { started_at, .. } => {
                                Some((s.profile_id, started_at))
                            }
                            _ => None,
                        })
                        .min_by_key(|(_, started)| *started)
                    {
                        let elapsed = SystemTime::now()
                            .duration_since(started_at)
                            .unwrap_or_default()
                            .as_secs();
                        if elapsed > 0 && elapsed % constants::SCANNER_LOG_INTERVAL_SECS == 0 {
                            crate::logger::log(
                                LogLevel::Info,
                                "NET",
                                format!(
                                    "Scanner still running for '{}' ({elapsed}s elapsed)",
                                    profile_id.as_str()
                                ),
                            );
                        }
                    }
                    return;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.runtime.scanner_rx = None;
                }
            }
        }

        // 2. Process the result if we got one
        if let Some(result) = result {
            self.handle_message(Message::SyncSystemState {
                sessions: result.sessions,
                default_route_interface: result.default_route_interface,
            });
        }

        // 3. Kick off a new scan (scanner_rx is None here). The
        // background thread probes BOTH active sessions AND the
        // kernel default-route interface so the main thread never
        // shells out to `route get default` / `ip route show default`.
        let profiles = self.runtime.profiles.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let snapshot = scanner::gather_system_state(&profiles);
            let _ = tx.send(snapshot);
        });
        self.runtime.scanner_rx = Some(rx);
    }

    /// Poll the network monitor for gateway changes.
    pub(crate) fn poll_network_monitor(&mut self) {
        let events: Vec<_> = if let Some(rx) = &self.runtime.netmon_rx {
            rx.try_iter().collect()
        } else {
            return;
        };

        for event in events {
            match event {
                NetworkEvent::GatewayChanged { ref old, ref new } => {
                    self.log(&format!(
                        "NET: Gateway changed: {} -> {}",
                        old.as_deref().unwrap_or("none"),
                        new.as_deref().unwrap_or("none")
                    ));
                    self.handle_message(Message::NetworkChanged);
                }
            }
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

        // 2. Kick off a new fetch via the platform aggregate (plan 003 U7).
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let totals = crate::platform::current_platform()
                .network_stats
                .get_total_bytes();
            let _ = tx.send(totals);
        });
        self.runtime.netstats_rx = Some(rx);
    }
}
