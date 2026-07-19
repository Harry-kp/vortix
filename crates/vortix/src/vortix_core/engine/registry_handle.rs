//! `RegistryHandle` — async actor around [`TunnelRegistry`].
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

use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::engine::error::EngineError;
use crate::vortix_core::engine::fsm::Engine;
use crate::vortix_core::engine::registry::{RegistryError, TunnelRegistry, TunnelSnapshot};
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

/// A boxed job run against the owned registry on the owner thread. The
/// job captures its own typed reply sender, so the envelope stays
/// non-generic over the mutation's return type — the standard
/// actor-with-arbitrary-return pattern.
type RegistryJob<T> = Box<dyn FnOnce(&mut TunnelRegistry<T>) + Send>;

/// One message to the registry owner task. Generic over the tunnel type
/// so `Apply` can carry a closure operating on the concrete registry.
enum RegistryEnvelope<T: Tunnel> {
    Snapshot {
        reply: oneshot::Sender<RegistrySnapshot>,
    },
    /// Run a mutation against the registry on the owner thread. The job
    /// owns its reply channel. Used by the supervisor to feed
    /// scanner-derived reconciliation without holding a lock across
    /// `.await`.
    Apply(RegistryJob<T>),
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
    /// return the closure's value. The closure runs to completion on the
    /// owner before any other message, so a decision-then-mutation is
    /// atomic w.r.t. concurrent IPC command handlers.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Other`] when the owner task has terminated.
    pub async fn apply<F, R>(&self, f: F) -> Result<R, EngineError>
    where
        F: FnOnce(&mut TunnelRegistry<T>) -> R + Send + 'static,
        R: Send + 'static,
    {
        let (reply, rx) = oneshot::channel::<R>();
        let job: RegistryJob<T> = Box::new(move |reg| {
            let _ = reply.send(f(reg));
        });
        self.tx
            .send(RegistryEnvelope::Apply(job))
            .await
            .map_err(|_| EngineError::Other("registry actor terminated".into()))?;
        rx.await
            .map_err(|_| EngineError::Other("registry actor dropped reply".into()))
    }

    // ── Per-profile commands ──────────────────
    //
    // The daemon routes every write to the profile's OWN engine, owned by
    // this registry — never a shared single FSM. Each is a thin async
    // wrapper over `apply` so the mutation runs on the owner task
    // (serialized w.r.t. snapshots and other commands). The inner
    // `Result<_, RegistryError>` carries the typed connect/disconnect
    // outcome; the outer `EngineError` only signals a dead owner task.

    /// Connect `profile_id` through its own engine, constructing a fresh
    /// engine via `make_engine` if the profile has no entry yet.
    ///
    /// # Errors
    ///
    /// [`EngineError`] if the owner task is gone; the inner result carries
    /// [`RegistryError`] (conflict, profile-not-found, tunnel failure).
    pub async fn connect(
        &self,
        profile_id: ProfileId,
        allowed_ips: Vec<Cidr>,
        make_engine: impl FnOnce() -> Engine<T> + Send + 'static,
        force: bool,
    ) -> Result<Result<(), RegistryError>, EngineError> {
        self.apply(move |reg| reg.connect(profile_id, allowed_ips, make_engine, force))
            .await
    }

    /// Disconnect a single profile's tunnel through its own engine.
    ///
    /// # Errors
    ///
    /// [`EngineError`] if the owner task is gone; inner [`RegistryError`]
    /// if the profile has no entry.
    pub async fn disconnect(
        &self,
        profile_id: ProfileId,
    ) -> Result<Result<(), RegistryError>, EngineError> {
        self.apply(move |reg| reg.disconnect(&profile_id)).await
    }

    /// Disconnect every active tunnel.
    ///
    /// # Errors
    ///
    /// [`EngineError`] if the owner task is gone.
    pub async fn disconnect_all(&self) -> Result<(), EngineError> {
        self.apply(TunnelRegistry::disconnect_all).await
    }

    /// Reconnect every active tunnel.
    ///
    /// # Errors
    ///
    /// [`EngineError`] if the owner task is gone.
    pub async fn reconnect_all(&self) -> Result<(), EngineError> {
        self.apply(TunnelRegistry::reconnect_all).await
    }

    /// Reconnect a single profile's tunnel through its own engine.
    ///
    /// # Errors
    ///
    /// [`EngineError`] if the owner task is gone; inner [`RegistryError`]
    /// if the profile has no entry.
    pub async fn reconnect(
        &self,
        profile_id: ProfileId,
    ) -> Result<Result<(), RegistryError>, EngineError> {
        self.apply(move |reg| reg.reconnect(&profile_id)).await
    }
}

/// Snapshot the registry's current state — a convenience for `apply`
/// closures and the owner loop's read path.
#[must_use]
pub fn snapshot_of<T: Tunnel>(registry: &TunnelRegistry<T>) -> RegistrySnapshot {
    RegistrySnapshot {
        tunnels: registry.snapshot_all(),
        primary: registry.primary().cloned(),
        killswitch: registry.killswitch_state(),
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
                let _ = reply.send(snapshot_of(&registry));
            }
            RegistryEnvelope::Apply(job) => job(&mut registry),
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
    async fn apply_runs_mutation_on_owner_and_returns_value() {
        // The apply closure runs on the owner thread and returns an
        // arbitrary value. Round-trip proves the mutation channel and
        // the reply-capturing generic-return plumbing.
        let registry: TunnelRegistry<MockTunnel> = TunnelRegistry::new();
        let handle = RegistryHandle::spawn(registry);
        let count = handle
            .apply(|reg| reg.snapshot_all().len())
            .await
            .expect("apply");
        assert_eq!(count, 0);
    }

    // ── Per-profile commands ──────────────────────────────────────

    fn mock_engine(name: &str) -> Engine<MockTunnel> {
        use crate::vortix_core::profile::{Profile, ProtocolKind};
        use std::path::PathBuf;
        let name = name.to_string();
        Engine::new(MockTunnel::new(), move |id: &ProfileId| {
            Some(Profile::new(
                id.clone(),
                &name,
                ProtocolKind::WireGuard,
                PathBuf::from(format!("/tmp/{name}.conf")),
            ))
        })
    }

    #[tokio::test]
    async fn connect_then_disconnect_drives_the_profiles_own_engine() {
        use crate::vortix_core::engine::state::Connection;
        let handle = RegistryHandle::spawn(TunnelRegistry::<MockTunnel>::new());
        let corp = ProfileId::new("corp");

        handle
            .connect(corp.clone(), Vec::new(), || mock_engine("corp"), true)
            .await
            .expect("actor alive")
            .expect("connect ok");

        let snap = handle.registry_snapshot().await.expect("snap");
        assert_eq!(snap.tunnels.len(), 1);
        assert!(matches!(
            snap.tunnels[0].state,
            Connection::Connected { .. }
        ));

        handle
            .disconnect(corp.clone())
            .await
            .expect("actor alive")
            .expect("disconnect ok");

        // corp is no longer Connected after its own engine tore down.
        let snap = handle.registry_snapshot().await.expect("snap2");
        assert!(
            !snap
                .tunnels
                .iter()
                .any(|t| t.profile_id == corp && matches!(t.state, Connection::Connected { .. })),
            "corp should not be Connected after disconnect: {:?}",
            snap.tunnels
        );
    }

    #[tokio::test]
    async fn two_profiles_connect_independently() {
        use crate::vortix_core::engine::state::Connection;
        let handle = RegistryHandle::spawn(TunnelRegistry::<MockTunnel>::new());
        for name in ["corp", "home"] {
            handle
                .connect(
                    ProfileId::new(name),
                    Vec::new(),
                    move || mock_engine(name),
                    true,
                )
                .await
                .expect("actor")
                .expect("connect");
        }
        let snap = handle.registry_snapshot().await.expect("snap");
        assert_eq!(snap.tunnels.len(), 2);
        assert!(snap
            .tunnels
            .iter()
            .all(|t| matches!(t.state, Connection::Connected { .. })));
    }

    #[tokio::test]
    async fn disconnect_unknown_profile_is_profile_not_found() {
        let handle = RegistryHandle::spawn(TunnelRegistry::<MockTunnel>::new());
        let res = handle
            .disconnect(ProfileId::new("ghost"))
            .await
            .expect("actor alive");
        assert!(matches!(res, Err(RegistryError::ProfileNotFound(_))));
    }
}
