//! Background telemetry and scanner polling.

use std::sync::mpsc;

use super::{App, ConnectionState};
use crate::constants;
use crate::core::network_monitor::NetworkEvent;
use crate::core::scanner;
use crate::logger::LogLevel;
use crate::message::Message;

impl App {
    /// Processes pending telemetry updates from the background worker.
    /// Called frequently to ensure logs appear immediately.
    pub(crate) fn process_telemetry(&mut self) {
        let updates: Vec<_> = if let Some(rx) = &self.telemetry_rx {
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
        if let Some(nudge) = &self.telemetry_nudge {
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
        if let Some(rx) = &self.scanner_rx {
            match rx.try_recv() {
                Ok(active) => {
                    result = Some(active);
                    self.scanner_rx = None; // Mark: ready for next scan
                }
                Err(mpsc::TryRecvError::Empty) => {
                    // Previous scan still running — don't start another.
                    if let ConnectionState::Connecting { started, profile } = &self.connection_state
                    {
                        let elapsed = started.elapsed().as_secs();
                        if elapsed > 0 && elapsed % constants::SCANNER_LOG_INTERVAL_SECS == 0 {
                            crate::logger::log(
                                LogLevel::Info,
                                "NET",
                                format!(
                                    "Scanner still running for '{profile}' ({elapsed}s elapsed)"
                                ),
                            );
                        }
                    }
                    return;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.scanner_rx = None;
                }
            }
        }

        // 2. Process the result if we got one
        if let Some(active) = result {
            self.handle_message(Message::SyncSystemState(active));
        }

        // 3. Kick off a new scan (scanner_rx is None here)
        let profiles = self.profiles.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let active = scanner::get_active_profiles(&profiles);
            let _ = tx.send(active);
        });
        self.scanner_rx = Some(rx);
    }

    /// Poll the network monitor for gateway changes.
    pub(crate) fn poll_network_monitor(&mut self) {
        let events: Vec<_> = if let Some(rx) = &self.netmon_rx {
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
        if let Some(rx) = &self.netstats_rx {
            match rx.try_recv() {
                Ok((total_in, total_out)) => {
                    if self.last_bytes_in > 0 {
                        self.current_down = total_in.saturating_sub(self.last_bytes_in);
                        self.current_up = total_out.saturating_sub(self.last_bytes_out);
                    }
                    self.last_bytes_in = total_in;
                    self.last_bytes_out = total_out;
                    self.netstats_rx = None;
                }
                Err(mpsc::TryRecvError::Empty) => {
                    return;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.netstats_rx = None;
                }
            }
        }

        // 2. Kick off a new fetch
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let totals = {
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
            let _ = tx.send(totals);
        });
        self.netstats_rx = Some(rx);
    }
}
