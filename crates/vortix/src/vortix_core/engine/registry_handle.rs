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
//! Exposes a `registry_snapshot()` read query and an `apply()` mutation
//! channel (runs a closure on the owner thread, returns the post-
//! mutation snapshot). The daemon supervisor uses `apply` to feed
//! scanner-derived reconciliation; the following commits build that
//! supervisor on top.

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

/// A boxed mutation closure run against the owned registry on the owner
/// thread. Returns the post-mutation [`ApplyOutcome`].
type ApplyFn<T> = Box<dyn FnOnce(&mut TunnelRegistry<T>) -> ApplyOutcome + Send>;

/// One message to the registry owner task. Generic over the tunnel type
/// so `Apply` can carry a closure operating on the concrete registry.
enum RegistryEnvelope<T: Tunnel> {
    Snapshot {
        reply: oneshot::Sender<RegistrySnapshot>,
    },
    /// Run a mutation against the registry on the owner thread and
    /// return a value. Used by the supervisor to feed scanner-derived
    /// reconciliation without holding a lock across `.await`.
    Apply {
        f: ApplyFn<T>,
        reply: oneshot::Sender<ApplyOutcome>,
    },
}

/// Serializable-friendly result of an `apply` mutation. The supervisor
/// needs the post-mutation snapshot to decide follow-up side effects
/// (kill switch, retry), so `apply` returns one alongside caller-chosen
/// data.
#[derive(Debug, Clone)]
pub struct ApplyOutcome {
    pub snapshot: RegistrySnapshot,
}

/// Clone-able handle to the registry owner task. Cheap to clone (holds
/// only an mpsc sender). Generic over the tunnel type the registry
/// holds; the daemon instantiates `RegistryHandle<TunnelKind>`.
pub struct RegistryHandle<T: Tunnel> {
    tx: mpsc::Sender<RegistryEnvelope<T>>,
}

impl<T: Tunnel> Clone for RegistryHandle<T> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

impl<T: Tunnel> std::fmt::Debug for RegistryHandle<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryHandle").finish_non_exhaustive()
    }
}

impl<T: Tunnel + Send + 'static> RegistryHandle<T> {
    /// Spawn the owner task around a freshly-constructed registry.
    /// Returns the handle callers clone.
    #[must_use]
    pub fn spawn(registry: TunnelRegistry<T>) -> Self {
        let (tx, rx) = mpsc::channel::<RegistryEnvelope<T>>(64);
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

    /// Run a mutation against the registry on the owner thread and
    /// return the resulting [`ApplyOutcome`] (post-mutation snapshot).
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Other`] when the owner task has terminated.
    pub async fn apply<F>(&self, f: F) -> Result<ApplyOutcome, EngineError>
    where
        F: FnOnce(&mut TunnelRegistry<T>) -> ApplyOutcome + Send + 'static,
    {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(RegistryEnvelope::Apply {
                f: Box::new(f),
                reply,
            })
            .await
            .map_err(|_| EngineError::Other("registry actor terminated".into()))?;
        rx.await
            .map_err(|_| EngineError::Other("registry actor dropped reply".into()))
    }
}

/// Build an [`ApplyOutcome`] from the registry's current state — a
/// convenience for `apply` closures that mutate then snapshot.
#[must_use]
pub fn outcome_of<T: Tunnel>(registry: &TunnelRegistry<T>) -> ApplyOutcome {
    ApplyOutcome {
        snapshot: RegistrySnapshot {
            tunnels: registry.snapshot_all(),
            primary: registry.primary().cloned(),
            killswitch: registry.killswitch_state(),
        },
    }
}

// The owner task is the sole owner of the registry for its entire
// lifetime; a borrow cannot cross the spawn_blocking boundary. Mutating
// messages (supervisor feed: drop detection, retry, adoption) consume it
// as `mut` in the following commits.
fn owner_loop<T: Tunnel>(
    mut registry: TunnelRegistry<T>,
    mut rx: mpsc::Receiver<RegistryEnvelope<T>>,
) {
    // Blocking loop on a tokio blocking thread — the registry is sync,
    // so any tunnel work it drives blocks this thread only.
    while let Some(env) = rx.blocking_recv() {
        match env {
            RegistryEnvelope::Snapshot { reply } => {
                let _ = reply.send(outcome_of(&registry).snapshot);
            }
            RegistryEnvelope::Apply { f, reply } => {
                let outcome = f(&mut registry);
                let _ = reply.send(outcome);
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
    async fn clone_keeps_the_owner_alive() {
        // A clone is another sender, so the owner loop stays alive even
        // after the original handle drops.
        let registry: TunnelRegistry<MockTunnel> = TunnelRegistry::new();
        let handle = RegistryHandle::spawn(registry);
        let clone = handle.clone();
        drop(handle);
        let snap = clone.registry_snapshot().await.expect("clone still works");
        assert!(snap.tunnels.is_empty());
    }

    #[tokio::test]
    async fn apply_runs_mutation_on_owner_and_returns_outcome() {
        // The apply closure runs on the owner thread; its ApplyOutcome
        // carries a post-mutation snapshot. With an empty registry and a
        // no-op mutation, the outcome snapshot is still empty — but the
        // round-trip proves the mutation channel and outcome plumbing.
        let registry: TunnelRegistry<MockTunnel> = TunnelRegistry::new();
        let handle = RegistryHandle::spawn(registry);
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran_c = ran.clone();
        let outcome = handle
            .apply(move |reg| {
                ran_c.store(true, std::sync::atomic::Ordering::SeqCst);
                outcome_of(reg)
            })
            .await
            .expect("apply");
        assert!(ran.load(std::sync::atomic::Ordering::SeqCst));
        assert!(outcome.snapshot.tunnels.is_empty());
    }
}
