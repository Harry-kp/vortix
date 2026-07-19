//! `EngineHandle` + `LocalHandle` actor (plan #005 U4).
//!
//! Clone-able Command/Query/Subscribe API around the FSM. The actor lives
//! in a `tokio::spawn`'d task; the handle holds a mpsc sender to the actor
//! plus a broadcast factory for live event subscribers.
//!
//! `EngineHandle` is an `enum` with two variants: `Local` (in-process
//! actor) and `Remote` (daemon-hosted engine over IPC, read path as of
//! plan 2026-07-18-001 U1). The enum stays `#[non_exhaustive]`.

use std::sync::Arc;

use tokio::sync::{broadcast, mpsc, oneshot};

use crate::vortix_core::engine::error::EngineError;
use crate::vortix_core::engine::event::EventEnvelope;
use crate::vortix_core::engine::fsm::Engine;
use crate::vortix_core::engine::input::{Input, UserCommand};
use crate::vortix_core::engine::registry_handle::RegistrySnapshot;
use crate::vortix_core::engine::state::Connection;
use crate::vortix_core::ipc::{IpcOp, IpcResult, IpcTransport, TransportError};
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

/// Client-side handle to a daemon-hosted engine (plan 2026-07-18-001
/// U1). Wraps a blocking [`IpcTransport`]; each call runs the exchange
/// on the blocking pool. Carries the full surface: snapshot reads,
/// registry reads, `execute` writes, and `subscribe` streaming.
#[derive(Clone)]
pub struct RemoteHandle {
    transport: Arc<dyn IpcTransport>,
}

impl std::fmt::Debug for RemoteHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteHandle").finish_non_exhaustive()
    }
}

impl RemoteHandle {
    #[must_use]
    pub fn new(transport: Arc<dyn IpcTransport>) -> Self {
        Self { transport }
    }

    /// Fetch the daemon's FSM snapshot with the typed transport error
    /// surface preserved — callers that must discriminate
    /// [`TransportError::Unavailable`] (silent fallback) from
    /// [`TransportError::VersionMismatch`] (loud error) use this
    /// directly; the uniform [`EngineHandle::snapshot`] flattens to
    /// [`EngineError`].
    ///
    /// The remote journal tail is not transported in U1; `journal_tail`
    /// is empty until the streaming unit lands.
    ///
    /// # Errors
    ///
    /// See [`TransportError`].
    pub async fn snapshot_remote(&self) -> Result<Snapshot, TransportError> {
        let transport = Arc::clone(&self.transport);
        let result = tokio::task::spawn_blocking(move || transport.request(IpcOp::Snapshot))
            .await
            .map_err(|e| TransportError::Protocol(format!("blocking task join: {e}")))??;
        match result {
            IpcResult::Snapshot { state } => Ok(Snapshot {
                state,
                journal_tail: Vec::new(),
            }),
            other => Err(TransportError::Protocol(format!(
                "expected snapshot, daemon answered {other:?}"
            ))),
        }
    }

    /// Fetch the daemon's full multi-tunnel [`RegistrySnapshot`] — the
    /// authoritative view of every active tunnel plus the derived
    /// primary and global kill-switch (plan 2026-07-18-001 U2). Prefer
    /// this over [`Self::snapshot_remote`] for multi-tunnel-aware
    /// surfaces; the primary-only `Snapshot` stays for v1 compatibility.
    ///
    /// Same tri-state [`TransportError`] contract as `snapshot_remote`:
    /// unavailable falls back silently, version mismatch is loud.
    ///
    /// # Errors
    ///
    /// See [`TransportError`].
    pub async fn registry_snapshot_remote(&self) -> Result<RegistrySnapshot, TransportError> {
        let transport = Arc::clone(&self.transport);
        let result =
            tokio::task::spawn_blocking(move || transport.request(IpcOp::RegistrySnapshot))
                .await
                .map_err(|e| TransportError::Protocol(format!("blocking task join: {e}")))??;
        match result {
            IpcResult::RegistrySnapshot {
                tunnels,
                primary,
                killswitch,
            } => Ok(RegistrySnapshot {
                tunnels,
                primary,
                killswitch,
            }),
            other => Err(TransportError::Protocol(format!(
                "expected registry snapshot, daemon answered {other:?}"
            ))),
        }
    }

    /// Send a user command to the daemon for execution (plan
    /// 2026-07-18-001 U3). The daemon runs it against its engine and
    /// answers `Accepted` once the FSM has processed it (the connection
    /// stays open for the tunnel lifecycle, so this awaits the real
    /// connect/disconnect). A registry conflict comes back as a typed
    /// daemon error surfaced through [`TransportError::Protocol`].
    ///
    /// # Errors
    ///
    /// See [`TransportError`]: unavailable = silent fallback candidate,
    /// version mismatch = loud, protocol = daemon rejected/erred.
    pub async fn execute_remote(&self, cmd: UserCommand) -> Result<(), TransportError> {
        let transport = Arc::clone(&self.transport);
        let result = tokio::task::spawn_blocking(move || transport.request(IpcOp::Execute(cmd)))
            .await
            .map_err(|e| TransportError::Protocol(format!("blocking task join: {e}")))??;
        match result {
            IpcResult::Accepted => Ok(()),
            other => Err(TransportError::Protocol(format!(
                "expected execute ack, daemon answered {other:?}"
            ))),
        }
    }

    /// Open a live subscription to the daemon's event stream (plan
    /// 2026-07-18-001 U2). Pairs the current snapshot (catch-up) with a
    /// receiver fed by the daemon's pushed events, mirroring the shape
    /// [`LocalHandle::subscribe`] returns so consumers are variant-blind.
    ///
    /// # Errors
    ///
    /// See [`TransportError`].
    pub async fn subscribe_remote(&self) -> Result<EngineSubscription, TransportError> {
        let snapshot = self.snapshot_remote().await?;
        let receiver = self.transport.subscribe()?;
        Ok(EngineSubscription { snapshot, receiver })
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum EngineHandle {
    Local(LocalHandle),
    Remote(RemoteHandle),
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
            // Only user commands cross the IPC boundary; the other Input
            // variants are internal FSM feeds (ticks, telemetry, link
            // changes) the daemon generates for itself, never the client.
            Self::Remote(h) => match input {
                Input::UserCommand(cmd) => h
                    .execute_remote(cmd)
                    .await
                    .map(|()| CommandAck { events_emitted: 0 })
                    .map_err(|e| EngineError::Other(e.to_string())),
                other => Err(EngineError::Other(format!(
                    "remote execute only accepts user commands, got {other:?}"
                ))),
            },
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
            Self::Remote(h) => h
                .snapshot_remote()
                .await
                .map_err(|e| EngineError::Other(e.to_string())),
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
            Self::Remote(h) => h
                .subscribe_remote()
                .await
                .map_err(|e| EngineError::Other(e.to_string())),
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

    // ===== RemoteHandle (plan 2026-07-18-001 U1) =====

    struct MockTransport {
        response: std::sync::Mutex<Option<Result<IpcResult, TransportError>>>,
        called: std::sync::atomic::AtomicBool,
    }

    impl MockTransport {
        fn new(response: Result<IpcResult, TransportError>) -> Self {
            Self {
                response: std::sync::Mutex::new(Some(response)),
                called: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    impl IpcTransport for MockTransport {
        fn request(&self, _op: IpcOp) -> Result<IpcResult, TransportError> {
            self.called.store(true, std::sync::atomic::Ordering::SeqCst);
            self.response
                .lock()
                .unwrap()
                .take()
                .expect("single-shot mock")
        }
    }

    #[tokio::test]
    async fn remote_snapshot_maps_wire_state_into_snapshot() {
        let transport = Arc::new(MockTransport::new(Ok(IpcResult::Snapshot {
            state: Connection::Disconnected { last_failure: None },
        })));
        let remote = RemoteHandle::new(transport.clone());
        let snap = remote.snapshot_remote().await.expect("snapshot");
        assert!(matches!(snap.state, Connection::Disconnected { .. }));
        assert!(snap.journal_tail.is_empty());
        assert!(transport.called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn remote_snapshot_propagates_version_mismatch_with_both_sides() {
        let transport = Arc::new(MockTransport::new(Err(TransportError::VersionMismatch {
            daemon: 3,
            client: 1,
        })));
        let remote = RemoteHandle::new(transport);
        match remote.snapshot_remote().await {
            Err(TransportError::VersionMismatch {
                daemon: 3,
                client: 1,
            }) => {}
            other => panic!("expected version mismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn remote_snapshot_unavailable_stays_unavailable() {
        let transport = Arc::new(MockTransport::new(Err(TransportError::Unavailable(
            "connection refused".into(),
        ))));
        let remote = RemoteHandle::new(transport);
        assert!(matches!(
            remote.snapshot_remote().await,
            Err(TransportError::Unavailable(_))
        ));
    }

    #[tokio::test]
    async fn remote_snapshot_rejects_non_snapshot_result() {
        let transport = Arc::new(MockTransport::new(Ok(IpcResult::Accepted)));
        let remote = RemoteHandle::new(transport);
        assert!(matches!(
            remote.snapshot_remote().await,
            Err(TransportError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn remote_registry_snapshot_maps_wire_into_snapshot() {
        use crate::vortix_core::engine::registry::{Role, TunnelSnapshot};
        use crate::vortix_core::engine::state::ConnectionHealth;
        use crate::vortix_core::profile::ProfileId;
        use crate::vortix_core::state::KillSwitchState;

        let tunnel = TunnelSnapshot {
            profile_id: ProfileId::new("corp"),
            state: Connection::Disconnected { last_failure: None },
            role: Role::Primary {
                allowed_ips: Vec::new(),
            },
            health: ConnectionHealth::Healthy,
            interface_name: Some("wg0".into()),
            started_at: None,
        };
        let transport = Arc::new(MockTransport::new(Ok(IpcResult::RegistrySnapshot {
            tunnels: vec![tunnel],
            primary: Some(ProfileId::new("corp")),
            killswitch: KillSwitchState::Disabled,
        })));
        let remote = RemoteHandle::new(transport);
        let snap = remote.registry_snapshot_remote().await.expect("snapshot");
        assert_eq!(snap.tunnels.len(), 1);
        assert_eq!(snap.tunnels[0].profile_id.as_str(), "corp");
        assert_eq!(snap.primary.as_ref().map(ProfileId::as_str), Some("corp"));
        assert_eq!(snap.killswitch, KillSwitchState::Disabled);
    }

    #[tokio::test]
    async fn remote_registry_snapshot_rejects_non_registry_result() {
        let transport = Arc::new(MockTransport::new(Ok(IpcResult::Accepted)));
        let remote = RemoteHandle::new(transport);
        assert!(matches!(
            remote.registry_snapshot_remote().await,
            Err(TransportError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn remote_registry_snapshot_propagates_version_mismatch() {
        let transport = Arc::new(MockTransport::new(Err(TransportError::VersionMismatch {
            daemon: 2,
            client: 1,
        })));
        let remote = RemoteHandle::new(transport);
        assert!(matches!(
            remote.registry_snapshot_remote().await,
            Err(TransportError::VersionMismatch {
                daemon: 2,
                client: 1
            })
        ));
    }

    #[tokio::test]
    async fn remote_execute_maps_accepted_to_ok() {
        let transport = Arc::new(MockTransport::new(Ok(IpcResult::Accepted)));
        let handle = EngineHandle::Remote(RemoteHandle::new(transport));
        let ack = handle
            .execute_command(UserCommand::Disconnect { profile_id: None })
            .await
            .expect("accepted");
        assert_eq!(ack.events_emitted, 0);
    }

    #[tokio::test]
    async fn remote_execute_surfaces_daemon_error() {
        // A non-Accepted success variant is a protocol error.
        let transport = Arc::new(MockTransport::new(Ok(IpcResult::Subscribed)));
        let handle = EngineHandle::Remote(RemoteHandle::new(transport));
        assert!(handle
            .execute_command(UserCommand::Connect {
                profile_id: ProfileId::new("corp"),
            })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn remote_subscribe_errors_when_transport_lacks_streaming() {
        // The snapshot half succeeds; the mock transport uses the default
        // `IpcTransport::subscribe` (no streaming), so subscribe fails at
        // the stream step — exercising the Remote arm's error mapping.
        let transport = Arc::new(MockTransport::new(Ok(IpcResult::Snapshot {
            state: Connection::Disconnected { last_failure: None },
        })));
        let handle = EngineHandle::Remote(RemoteHandle::new(transport));
        assert!(handle.subscribe().await.is_err());
    }
}
