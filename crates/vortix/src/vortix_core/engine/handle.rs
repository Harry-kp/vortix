//! `EngineHandle` + `LocalHandle` actor (plan #005 U4).
//!
//! Clone-able Command/Query/Subscribe API around the FSM. The actor lives
//! in a `tokio::spawn`'d task; the handle holds a mpsc sender to the actor
//! plus a broadcast factory for live event subscribers.
//!
//! `EngineHandle` is an `enum` with one variant today (`Local`); future
//! Phase B daemon work (idea 4) adds a `Remote(RemoteHandle)` variant
//! additively (the enum is `#[non_exhaustive]`).

use std::sync::Arc;

use tokio::sync::{broadcast, mpsc, oneshot};

use crate::vortix_core::engine::error::EngineError;
use crate::vortix_core::engine::event::EventEnvelope;
use crate::vortix_core::engine::fsm::Engine;
use crate::vortix_core::engine::input::{Input, UserCommand};
use crate::vortix_core::engine::state::Connection;
use crate::vortix_core::journal::Journal;
use crate::vortix_core::ports::tunnel::Tunnel;

// ───────────────────────────────────────────────────────────────────────────
// Wire protocol between handle and actor
// ───────────────────────────────────────────────────────────────────────────

/// One command/query sent to the actor's mpsc inbox.
enum Envelope {
    Input {
        input: Input,
        reply: oneshot::Sender<Result<CommandAck, EngineError>>,
    },
    Snapshot {
        reply: oneshot::Sender<Snapshot>,
    },
}

/// Acknowledgement returned for `execute()`.
#[derive(Debug, Clone)]
pub struct CommandAck {
    pub events_emitted: usize,
}

/// Snapshot of the engine state at a point in time. Returned by `query()`
/// and also implicitly by `subscribe()` for the "catch-up" half.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub state: Connection,
    pub journal_tail: Vec<EventEnvelope>,
}

/// Live subscription bundle returned by [`EngineHandle::subscribe`].
pub struct EngineSubscription {
    pub snapshot: Snapshot,
    pub receiver: broadcast::Receiver<EventEnvelope>,
}

// ───────────────────────────────────────────────────────────────────────────
// Handle enum + Local variant
// ───────────────────────────────────────────────────────────────────────────

/// Clone-able façade. The mpsc + broadcast + journal under the hood are all
/// `Arc`-internal so cheap to copy.
#[derive(Clone)]
pub struct LocalHandle {
    command_tx: mpsc::Sender<Envelope>,
    journal: Journal,
}

impl std::fmt::Debug for LocalHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalHandle")
            .field("journal", &self.journal)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum EngineHandle {
    Local(LocalHandle),
}

impl EngineHandle {
    /// Spawn the actor for a freshly-constructed FSM. Returns the handle
    /// callers should clone.
    pub fn local<T: Tunnel + Send + 'static>(engine: Engine<T>, journal: Journal) -> Self {
        let (tx, rx) = mpsc::channel::<Envelope>(64);
        let journal_for_actor = journal.clone();
        tokio::task::spawn_blocking(move || actor_loop(engine, journal_for_actor, rx));
        Self::Local(LocalHandle {
            command_tx: tx,
            journal,
        })
    }

    /// Send an FSM input and wait for the actor's ack. Errors only when the
    /// actor task has terminated.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Other`] when the actor task has terminated.
    pub async fn execute(&self, input: Input) -> Result<CommandAck, EngineError> {
        match self {
            Self::Local(h) => h.execute(input).await,
        }
    }

    /// Convenience wrapper around `execute(Input::UserCommand(...))`.
    ///
    /// # Errors
    ///
    /// See [`Self::execute`].
    pub async fn execute_command(&self, cmd: UserCommand) -> Result<CommandAck, EngineError> {
        self.execute(Input::UserCommand(cmd)).await
    }

    /// Take a snapshot of the engine state + the journal's in-memory tail.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Other`] when the actor task has terminated.
    pub async fn snapshot(&self) -> Result<Snapshot, EngineError> {
        match self {
            Self::Local(h) => h.snapshot().await,
        }
    }

    /// Subscribe to live events. The returned bundle includes a current
    /// snapshot + a broadcast receiver so the consumer can resync after a
    /// `Lagged` error without missing transitions.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Other`] when the actor task has terminated.
    pub async fn subscribe(&self) -> Result<EngineSubscription, EngineError> {
        match self {
            Self::Local(h) => h.subscribe().await,
        }
    }

    /// Test fixture: build a handle wrapped around a default-mock tunnel
    /// and an in-memory journal. Callers configure the resolver via
    /// [`LocalHandle::for_test`].
    #[must_use]
    pub fn for_test() -> Self {
        LocalHandle::for_test().into()
    }
}

impl From<LocalHandle> for EngineHandle {
    fn from(h: LocalHandle) -> Self {
        Self::Local(h)
    }
}

impl LocalHandle {
    async fn execute(&self, input: Input) -> Result<CommandAck, EngineError> {
        let (reply, rx) = oneshot::channel();
        self.command_tx
            .send(Envelope::Input { input, reply })
            .await
            .map_err(|_| EngineError::Other("engine actor terminated".into()))?;
        rx.await
            .map_err(|_| EngineError::Other("engine actor dropped reply".into()))?
    }

    async fn snapshot(&self) -> Result<Snapshot, EngineError> {
        let (reply, rx) = oneshot::channel();
        self.command_tx
            .send(Envelope::Snapshot { reply })
            .await
            .map_err(|_| EngineError::Other("engine actor terminated".into()))?;
        rx.await
            .map_err(|_| EngineError::Other("engine actor dropped reply".into()))
    }

    async fn subscribe(&self) -> Result<EngineSubscription, EngineError> {
        let snapshot = self.snapshot().await?;
        Ok(EngineSubscription {
            snapshot,
            receiver: self.journal.subscribe(),
        })
    }

    /// Build a fully-mocked handle for tests. The actor is spawned on the
    /// surrounding tokio runtime; tests must use `#[tokio::test]`.
    ///
    /// # Panics
    ///
    /// Panics if the in-memory journal cannot be opened — only possible
    /// under simulated OS failure.
    #[must_use]
    pub fn for_test() -> Self {
        use crate::vortix_core::ports::tunnel::mock::MockTunnel;
        use crate::vortix_core::profile::{Profile, ProfileId, ProtocolKind};
        use std::path::PathBuf;

        let journal = Journal::open(crate::vortix_core::journal::JournalConfig {
            disk: false,
            ..Default::default()
        })
        .expect("in-memory journal");

        let engine = Engine::new(MockTunnel::new(), |id: &ProfileId| {
            Some(Profile::new(
                id.clone(),
                id.as_str(),
                ProtocolKind::WireGuard,
                PathBuf::from(format!("/tmp/{}.conf", id.as_str())),
            ))
        });

        let (tx, rx) = mpsc::channel::<Envelope>(64);
        let journal_for_actor = journal.clone();
        tokio::task::spawn_blocking(move || actor_loop(engine, journal_for_actor, rx));
        Self {
            command_tx: tx,
            journal,
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Actor loop
// ───────────────────────────────────────────────────────────────────────────

#[allow(clippy::needless_pass_by_value)] // owned for the task's entire lifetime
fn actor_loop<T: Tunnel>(
    mut engine: Engine<T>,
    journal: Journal,
    mut rx: mpsc::Receiver<Envelope>,
) {
    // Blocking loop — runs on a tokio blocking thread. The FSM is sync, so
    // any tunnel.up()/down() calls block this thread but not the broader
    // runtime.
    while let Some(env) = rx.blocking_recv() {
        match env {
            Envelope::Input { input, reply } => {
                let events = engine.handle(input);
                let count = events.len();
                // Best-effort journal append — failures are non-fatal.
                let journal = Arc::new(journal.clone());
                for ev in events {
                    let _ = journal.append(ev);
                }
                let _ = reply.send(Ok(CommandAck {
                    events_emitted: count,
                }));
            }
            Envelope::Snapshot { reply } => {
                let snapshot = Snapshot {
                    state: engine.state().clone(),
                    journal_tail: journal.tail(),
                };
                let _ = reply.send(snapshot);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::engine::input::UserCommand;
    use crate::vortix_core::profile::ProfileId;

    #[tokio::test]
    async fn for_test_handles_connect() {
        let handle = EngineHandle::for_test();

        let ack = handle
            .execute_command(UserCommand::Connect {
                profile_id: ProfileId::new("corp"),
            })
            .await
            .unwrap();
        // ConnectAttemptStarted + TunnelUp + KillswitchEngaged = 3 events.
        assert!(ack.events_emitted >= 2);

        let snap = handle.snapshot().await.unwrap();
        assert!(matches!(snap.state, Connection::Connected { .. }));
    }

    #[tokio::test]
    async fn subscribe_returns_snapshot_plus_receiver() {
        let handle = EngineHandle::for_test();
        let sub = handle.subscribe().await.unwrap();
        assert!(matches!(
            sub.snapshot.state,
            Connection::Disconnected { .. }
        ));
        // Receiver is alive (no events yet).
        let _ = sub.receiver;
    }
}
