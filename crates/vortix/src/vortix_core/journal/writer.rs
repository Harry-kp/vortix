//! Journal writer task — drains the mpsc and writes to disk + broadcast + tail.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::io::AsyncWriteExt;
use tokio::sync::{broadcast, mpsc};
use tracing::warn;

use crate::vortix_core::engine::event::EventEnvelope;

use super::TailBuffer;

/// Disk-backed writer. Appends one JSON line per event to `path`, fans out to
/// broadcast subscribers, and pushes into the tail buffer.
pub(crate) async fn run(
    path: PathBuf,
    mut mpsc_rx: mpsc::UnboundedReceiver<EventEnvelope>,
    bcast_tx: broadcast::Sender<EventEnvelope>,
    tail: Arc<Mutex<TailBuffer>>,
) {
    let mut file = match tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            warn!(
                target: "vortix::journal",
                path = %path.display(),
                error = %e,
                "failed to open journal file; events will be dropped"
            );
            // Keep draining so producers don't see WriterGone unexpectedly,
            // but discard records.
            while mpsc_rx.recv().await.is_some() {}
            return;
        }
    };

    while let Some(env) = mpsc_rx.recv().await {
        // 1. Persist.
        match serde_json::to_vec(&env) {
            Ok(mut bytes) => {
                bytes.push(b'\n');
                if let Err(e) = file.write_all(&bytes).await {
                    warn!(
                        target: "vortix::journal",
                        path = %path.display(),
                        error = %e,
                        "journal write failed"
                    );
                } else if let Err(e) = file.flush().await {
                    warn!(target: "vortix::journal", error = %e, "journal flush failed");
                }
            }
            Err(e) => {
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

/// Disk-disabled writer. Same fan-out minus the file.
pub(crate) async fn run_in_memory(
    mut mpsc_rx: mpsc::UnboundedReceiver<EventEnvelope>,
    bcast_tx: broadcast::Sender<EventEnvelope>,
    tail: Arc<Mutex<TailBuffer>>,
) {
    while let Some(env) = mpsc_rx.recv().await {
        let _ = bcast_tx.send(env.clone());
        tail.lock().unwrap().push(env);
    }
}
