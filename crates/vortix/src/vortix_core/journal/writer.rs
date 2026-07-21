//! Journal writer task — drains the mpsc and writes to disk + broadcast + tail.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::AsyncWriteExt;
use tokio::sync::{broadcast, mpsc, watch};
use tracing::warn;

use crate::vortix_core::engine::event::EventEnvelope;

use super::TailBuffer;

/// Disk-backed writer. Appends one JSON line per event to `path`, fans out to
/// broadcast subscribers, and pushes into the tail buffer.
pub(crate) async fn run(
    path: PathBuf,
    mut mpsc_rx: mpsc::Receiver<EventEnvelope>,
    bcast_tx: broadcast::Sender<EventEnvelope>,
    tail: Arc<Mutex<TailBuffer>>,
    failure_count: Arc<AtomicU64>,
    failure_events: watch::Sender<u64>,
) {
    let mut file = match tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            record_failure(&failure_count, &failure_events);
            warn!(
                target: "vortix::journal",
                path = %path.display(),
                error = %e,
                "failed to open journal file; events will be dropped"
            );
            // Closing the receiver makes subsequent producer loss explicit as
            // WriterGone instead of accepting and silently discarding events.
            return;
        }
    };

    while let Some(env) = mpsc_rx.recv().await {
        // 1. Persist.
        match serde_json::to_vec(&env) {
            Ok(mut bytes) => {
                bytes.push(b'\n');
                if let Err(e) = file.write_all(&bytes).await {
                    record_failure(&failure_count, &failure_events);
                    warn!(
                        target: "vortix::journal",
                        path = %path.display(),
                        error = %e,
                        "journal write failed"
                    );
                } else if let Err(e) = file.flush().await {
                    record_failure(&failure_count, &failure_events);
                    warn!(target: "vortix::journal", error = %e, "journal flush failed");
                }
            }
            Err(e) => {
                record_failure(&failure_count, &failure_events);
                warn!(
                    target: "vortix::journal",
                    error = %e,
                    "failed to serialise journal record"
                );
            }
        }

        // 2. Broadcast (lossy — fine if no subscribers).
        let _ = bcast_tx.send(env.clone());

        // 3. Tail buffer.
        tail.lock().unwrap().push(env);
    }
}

fn record_failure(count: &AtomicU64, events: &watch::Sender<u64>) {
    let next = count.fetch_add(1, Ordering::AcqRel).saturating_add(1);
    events.send_replace(next);
}

/// Disk-disabled writer. Same fan-out minus the file.
pub(crate) async fn run_in_memory(
    mut mpsc_rx: mpsc::Receiver<EventEnvelope>,
    bcast_tx: broadcast::Sender<EventEnvelope>,
    tail: Arc<Mutex<TailBuffer>>,
) {
    while let Some(env) = mpsc_rx.recv().await {
        let _ = bcast_tx.send(env.clone());
        tail.lock().unwrap().push(env);
    }
}
