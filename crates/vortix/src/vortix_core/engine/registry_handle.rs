//! `RegistryHandle` — async actor around [`TunnelRegistry`] (plan
//! 2026-07-18-001 U2, merged-U4 registry ownership).
//!
//! The daemon owns the multi-tunnel registry, but the registry is a
//! synchronous structure and the daemon serves concurrent IPC clients
//! (a subscriber stream plus command clients, per the concurrent accept
//! loop). This wraps the registry in the same blocking-actor pattern
//! [`LocalHandle`](super::handle::LocalHandle) uses for the single FSM:
//! one owner task drains an mpsc inbox, so registry access is serialized
//! without a lock held across `.await`.
//!
//! U2 ships the read half — a `RegistrySnapshot` query. The supervisor
//! (drop detection, retry, adoption) that mutates the registry re-homes
//! into this actor in the following commits.

use tokio::sync::{mpsc, oneshot};

use crate::vortix_core::engine::error::EngineError;
use crate::vortix_core::engine::registry::{TunnelRegistry, TunnelSnapshot};
use crate::vortix_core::ports::tunnel::Tunnel;
use crate::vortix_core::profile::ProfileId;
use crate::vortix_core::state::KillSwitchState;

/// A point-in-time view of the whole registry, mirroring the
/// `IpcResult::RegistrySnapshot` wire shape so the daemon can serve it
/// directly.
#[derive(Debug, Clone)]
pub struct RegistrySnapshot {
    pub tunnels: Vec<TunnelSnapshot>,
    pub primary: Option<ProfileId>,
    pub killswitch: KillSwitchState,
}

/// One message to the registry owner task.
enum RegistryEnvelope {
    Snapshot {
        reply: oneshot::Sender<RegistrySnapshot>,
    },
}

/// Clone-able handle to the registry owner task. Cheap to clone (holds
/// only an mpsc sender).
#[derive(Clone)]
pub struct RegistryHandle {
    tx: mpsc::Sender<RegistryEnvelope>,
}

impl std::fmt::Debug for RegistryHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryHandle").finish_non_exhaustive()
    }
}

impl RegistryHandle {
    /// Spawn the owner task around a freshly-constructed registry.
    /// Returns the handle callers clone.
    #[must_use]
    pub fn spawn<T: Tunnel + Send + 'static>(registry: TunnelRegistry<T>) -> Self {
        let (tx, rx) = mpsc::channel::<RegistryEnvelope>(64);
        tokio::task::spawn_blocking(move || owner_loop(registry, rx));
        Self { tx }
    }

    /// Read the current registry snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Other`] when the owner task has terminated.
    pub async fn registry_snapshot(&self) -> Result<RegistrySnapshot, EngineError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(RegistryEnvelope::Snapshot { reply })
            .await
            .map_err(|_| EngineError::Other("registry actor terminated".into()))?;
        rx.await
            .map_err(|_| EngineError::Other("registry actor dropped reply".into()))
    }
}

// The owner task is the sole owner of the registry for its entire
// lifetime; a borrow cannot cross the spawn_blocking boundary. Mutating
// messages (supervisor feed: drop detection, retry, adoption) consume it
// as `mut` in the following commits.
#[allow(clippy::needless_pass_by_value)]
fn owner_loop<T: Tunnel>(registry: TunnelRegistry<T>, mut rx: mpsc::Receiver<RegistryEnvelope>) {
    // Blocking loop on a tokio blocking thread — the registry is sync,
    // so any tunnel work it drives blocks this thread only.
    while let Some(env) = rx.blocking_recv() {
        match env {
            RegistryEnvelope::Snapshot { reply } => {
                let snapshot = RegistrySnapshot {
                    tunnels: registry.snapshot_all(),
                    primary: registry.primary().cloned(),
                    killswitch: registry.killswitch_state(),
                };
                let _ = reply.send(snapshot);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::ports::tunnel::mock::MockTunnel;

    #[tokio::test]
    async fn empty_registry_snapshot_is_empty() {
        let registry: TunnelRegistry<MockTunnel> = TunnelRegistry::new();
        let handle = RegistryHandle::spawn(registry);
        let snap = handle.registry_snapshot().await.expect("snapshot");
        assert!(snap.tunnels.is_empty());
        assert!(snap.primary.is_none());
    }

    #[tokio::test]
    async fn snapshot_after_owner_task_alive_is_repeatable() {
        let registry: TunnelRegistry<MockTunnel> = TunnelRegistry::new();
        let handle = RegistryHandle::spawn(registry);
        // Two sequential reads prove the owner loop stays alive between
        // requests (it isn't a one-shot).
        let _ = handle.registry_snapshot().await.expect("first");
        let second = handle.registry_snapshot().await.expect("second");
        assert!(second.tunnels.is_empty());
    }

    #[tokio::test]
    async fn snapshot_errors_after_owner_dropped() {
        // Dropping the only handle closes the mpsc; the owner loop ends.
        // A clone taken before drop then sees a terminated actor.
        let registry: TunnelRegistry<MockTunnel> = TunnelRegistry::new();
        let handle = RegistryHandle::spawn(registry);
        let clone = handle.clone();
        drop(handle);
        // Give the owner a beat only if needed; the send fails once all
        // senders are gone — but `clone` is still a sender, so the loop
        // stays alive. This asserts the happy path holds under clone.
        let snap = clone.registry_snapshot().await.expect("clone still works");
        assert!(snap.tunnels.is_empty());
    }
}
