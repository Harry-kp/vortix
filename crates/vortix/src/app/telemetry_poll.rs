//! Background presentation telemetry polling.

use std::sync::mpsc;

use super::App;
use crate::message::Message;

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
            let totals = crate::platform::current_platform()
                .network_stats
                .get_total_bytes();
            let _ = tx.send(totals);
        });
        self.runtime.netstats_rx = Some(rx);
    }
}
