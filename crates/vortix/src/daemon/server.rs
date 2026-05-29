//! Daemon IPC server loop (plan 015 phase D U18 / plan 010).
//!
//! Single-client-at-a-time. Accept → peer-UID check → read frame →
//! dispatch → write response → loop until client disconnects.
//! Multi-client support is follow-up scope.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::vortix_core::engine::EngineHandle;
use crate::vortix_core::ipc::{
    decode_frame, encode_frame, FrameError, IpcError, IpcOp, IpcRequest, IpcResponse, IpcResult,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

/// The daemon server. Holds the socket binding, engine handle, and
/// the effective UID captured at bind time for peer-UID enforcement.
pub struct DaemonServer {
    socket_path: PathBuf,
    listener: UnixListener,
    engine_handle: Option<Arc<EngineHandle>>,
    /// The effective UID of the daemon process at bind time. Every
    /// accepted client is checked against this value via
    /// `SO_PEERCRED` (Linux) / `getpeereid(2)` (macOS) and rejected
    /// if they do not match. This is the security boundary that
    /// prevents a local UID escalation from compromising the daemon
    /// even when the socket file's mode 0600 has been bypassed.
    daemon_uid: u32,
}

impl DaemonServer {
    /// Bind the daemon socket. Cleans up any stale file at the path.
    ///
    /// The returned server has no engine handle attached; clients see
    /// structured "engine handle not initialized" errors for
    /// `Execute`/`Snapshot`/`Subscribe`. Use [`Self::with_engine_handle`]
    /// to attach a `EngineHandle::Local` so dispatch routes through the
    /// real FSM actor.
    ///
    /// # Errors
    ///
    /// Returns `io::Error` when the parent directory is unwritable or
    /// the bind itself fails.
    pub fn bind(socket_path: PathBuf) -> std::io::Result<Self> {
        // Best-effort cleanup of a stale socket from a crashed previous run.
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path)?;
        // Restrict access — only the daemon's owning UID should be
        // able to connect at the filesystem level. SO_PEERCRED /
        // getpeereid auth (below, on each accept) is the in-depth
        // guard on top of this.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&socket_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&socket_path, perms)?;
        }
        // SAFETY: `geteuid` is a vDSO-fast syscall on Linux and a
        // trivial syscall on macOS. It cannot fail and has no
        // pointer arguments.
        #[allow(unsafe_code)]
        let daemon_uid = unsafe { libc::geteuid() };
        Ok(Self {
            socket_path,
            listener,
            engine_handle: None,
            daemon_uid,
        })
    }

    /// Attach an engine handle so dispatch routes `Execute`/`Snapshot`/
    /// `Subscribe` through it. Without this, the daemon responds with
    /// structured "engine handle not initialized" errors so clients see
    /// typed wire errors instead of empty responses or connection drops.
    #[must_use]
    pub fn with_engine_handle(mut self, handle: EngineHandle) -> Self {
        self.engine_handle = Some(Arc::new(handle));
        self
    }

    /// Path to the bound socket.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// The daemon's own effective UID, captured at bind time. Used
    /// to authenticate connecting clients on each accept.
    #[must_use]
    pub fn daemon_uid(&self) -> u32 {
        self.daemon_uid
    }

    /// Accept loop. Returns when the listener is dropped or SIGTERM
    /// arrives (caller handles signal observation; this future
    /// terminates cleanly via `select!` from the caller).
    pub async fn run(self) -> std::io::Result<()> {
        eprintln!("vortix daemon: listening on {}", self.socket_path.display());
        if self.engine_handle.is_none() {
            tracing::warn!(
                "daemon started without an engine handle — Execute/Snapshot/Subscribe will return Internal errors"
            );
        }
        let daemon_uid = self.daemon_uid;
        loop {
            match self.listener.accept().await {
                Ok((stream, _addr)) => {
                    let handle = self.engine_handle.clone();
                    if let Err(e) = handle_client(stream, daemon_uid, handle).await {
                        eprintln!("vortix daemon: client session ended: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("vortix daemon: accept failed: {e}");
                    // Brief backoff before re-accepting to avoid
                    // tight loop on persistent failure.
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }
}

impl Drop for DaemonServer {
    fn drop(&mut self) {
        // Unlink the socket file on shutdown so the next daemon start
        // doesn't trip over a stale file.
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Handle one client connection. Reads framed requests, dispatches
/// them, writes framed responses. Returns when the client disconnects.
///
/// Before any dispatching, the peer's UID is checked against the
/// daemon's own UID via `SO_PEERCRED` (Linux) / `getpeereid` (macOS).
/// A mismatched peer receives a single `IpcError::Unauthorized` frame
/// (best-effort) and the connection is closed.
async fn handle_client(
    mut stream: UnixStream,
    daemon_uid: u32,
    engine_handle: Option<Arc<EngineHandle>>,
) -> Result<(), DaemonError> {
    // Peer-UID enforcement runs before any frame is read so an
    // unauthorized client never gets the chance to drive dispatch.
    match get_peer_uid(&stream) {
        Ok(peer_uid) if peer_uid == daemon_uid => { /* authorized; fall through */ }
        Ok(peer_uid) => {
            tracing::warn!(peer_uid, daemon_uid, "rejecting client with UID mismatch");
            // Best-effort notify-and-close: write a single
            // Unauthorized frame so the client surfaces a typed
            // error rather than an opaque EOF.
            let resp = IpcResponse {
                id: 0,
                result: Err(IpcError::Unauthorized),
            };
            if let Ok(frame) = encode_frame(&resp) {
                let _ = stream.write_all(&frame).await;
                let _ = stream.shutdown().await;
            }
            return Ok(());
        }
        Err(e) => {
            tracing::warn!(error = %e, "peer-UID lookup failed; closing connection");
            let resp = IpcResponse {
                id: 0,
                result: Err(IpcError::Internal(format!("peer-UID lookup failed: {e}"))),
            };
            if let Ok(frame) = encode_frame(&resp) {
                let _ = stream.write_all(&frame).await;
                let _ = stream.shutdown().await;
            }
            return Ok(());
        }
    }

    let mut buf = Vec::with_capacity(4096);
    let mut read_pos = 0usize;
    loop {
        // Read into buf.
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            // EOF — client closed.
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);

        // Drain as many full frames as we have.
        loop {
            match decode_frame::<IpcRequest>(&buf[read_pos..]) {
                Ok(None) => break, // need more bytes
                Ok(Some((req, consumed))) => {
                    read_pos += consumed;
                    let resp = dispatch(req, engine_handle.as_deref()).await;
                    let frame = encode_frame(&resp).map_err(DaemonError::Frame)?;
                    stream.write_all(&frame).await?;
                }
                Err(e) => return Err(DaemonError::Frame(e)),
            }
        }
        // Compact the buffer when we've consumed a meaningful chunk.
        if read_pos > 0 && read_pos >= buf.len() / 2 {
            buf.drain(..read_pos);
            read_pos = 0;
        }
    }
}

/// Look up the peer UID on an accepted Unix-domain socket connection.
///
/// Linux uses `SO_PEERCRED` (returns `struct ucred` with pid/uid/gid).
/// macOS uses `getpeereid(2)` (returns uid + gid directly). Both are
/// syscall-level primitives with no portable abstraction in `std` or
/// `tokio`, hence the platform cfg gating lives here rather than in a
/// `vortix-platform-*` crate.
#[cfg(unix)]
#[allow(unsafe_code)]
fn get_peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();

    // xtask:allow-platform-cfg: SO_PEERCRED/getpeereid are syscall-level primitives, no abstraction layer available.
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `getsockopt` writes at most `len` bytes into the
        // pointer we provide. We zero-initialize a `ucred` (a POD
        // struct of three integers) and pass its size; the kernel
        // either fills it and returns 0, or returns -1 and sets
        // errno without touching the buffer.
        unsafe {
            let mut cred: libc::ucred = std::mem::zeroed();
            let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>()).expect(
                "ucred size fits in socklen_t (a small POD struct on every supported target)",
            );
            let rc = libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                std::ptr::addr_of_mut!(cred).cast::<libc::c_void>(),
                &mut len,
            );
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(cred.uid)
        }
    }

    // xtask:allow-platform-cfg: SO_PEERCRED/getpeereid are syscall-level primitives, no abstraction layer available.
    #[cfg(target_os = "macos")]
    {
        // SAFETY: `getpeereid` writes exactly one `uid_t` and one
        // `gid_t` into the two out-pointers we provide. We pass
        // pointers to stack locals of the correct types.
        unsafe {
            let mut uid: libc::uid_t = 0;
            let mut gid: libc::gid_t = 0;
            let rc = libc::getpeereid(fd, &mut uid, &mut gid);
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(uid)
        }
    }

    // xtask:allow-platform-cfg: SO_PEERCRED/getpeereid are syscall-level primitives, no abstraction layer available.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = fd;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "peer-UID lookup not supported on this unix variant",
        ))
    }
}

/// Route one `IpcRequest` to the engine handle (if attached) and build
/// the response envelope.
///
/// `Subscribe` is acknowledged synchronously — turning the connection
/// into a streaming event channel is follow-up scope (the wire contract
/// reserves it). For now clients can correlate the `Subscribed` ack and
/// then poll `Snapshot` until the streaming half lands.
async fn dispatch(req: IpcRequest, engine_handle: Option<&EngineHandle>) -> IpcResponse {
    let result = match req.op {
        IpcOp::Execute(cmd) => match engine_handle {
            Some(h) => match h.execute_command(cmd).await {
                Ok(_ack) => Ok(IpcResult::Accepted),
                Err(e) => Err(IpcError::Internal(format!("engine error: {e}"))),
            },
            None => Err(IpcError::Internal(
                "engine handle not initialized in daemon".into(),
            )),
        },
        IpcOp::Snapshot => match engine_handle {
            Some(h) => match h.snapshot().await {
                // v1-compat: populate `Snapshot { state }` with the
                // primary's Connection (or Disconnected when no
                // primary). New v2 callers should switch to
                // `RegistrySnapshot` once they upgrade — see plan
                // #001 U22. Today the EngineHandle exposes a single
                // FSM (D1 wired the single-tunnel handle in the
                // daemon); the registry-aware variant lands when a
                // follow-up unit threads the registry into the
                // daemon's accept loop.
                Ok(snap) => Ok(IpcResult::Snapshot { state: snap.state }),
                Err(e) => Err(IpcError::Internal(format!("snapshot error: {e}"))),
            },
            None => Err(IpcError::Internal(
                "engine handle not initialized in daemon".into(),
            )),
        },
        IpcOp::Subscribe => {
            // v1: ack only. Promoting this connection into an event
            // stream (server-pushed `IpcResponse`-like envelopes after
            // the ack) is a follow-up unit — the wire contract reserves
            // it but no client consumes it today.
            if engine_handle.is_some() {
                tracing::warn!(
                    "daemon: Subscribe acknowledged but streaming half is not yet implemented — clients should poll Snapshot until the streaming unit lands"
                );
                Ok(IpcResult::Subscribed)
            } else {
                Err(IpcError::Internal(
                    "engine handle not initialized in daemon".into(),
                ))
            }
        }
        IpcOp::Shutdown => Ok(IpcResult::ShuttingDown),
    };
    IpcResponse { id: req.id, result }
}

#[derive(Debug)]
pub enum DaemonError {
    Io(std::io::Error),
    Frame(FrameError),
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error on client session: {e}"),
            Self::Frame(e) => write!(f, "frame protocol error: {e}"),
        }
    }
}

impl std::error::Error for DaemonError {}

impl From<std::io::Error> for DaemonError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(all(test, unix))]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use crate::vortix_core::engine::input::UserCommand;
    use crate::vortix_core::engine::state::Connection;
    use crate::vortix_core::profile::ProfileId;
    use tokio::net::UnixStream as TokioUnixStream;

    // ===== D1 dispatch tests =====

    #[tokio::test]
    async fn dispatch_execute_without_handle_returns_internal_error() {
        let req = IpcRequest {
            id: 1,
            op: IpcOp::Execute(UserCommand::Connect {
                profile_id: ProfileId::new("corp"),
            }),
        };
        let resp = dispatch(req, None).await;
        assert_eq!(resp.id, 1);
        match resp.result {
            Err(IpcError::Internal(msg)) => assert!(msg.contains("engine handle not initialized")),
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_snapshot_without_handle_returns_internal_error() {
        let req = IpcRequest {
            id: 2,
            op: IpcOp::Snapshot,
        };
        let resp = dispatch(req, None).await;
        assert_eq!(resp.id, 2);
        assert!(matches!(resp.result, Err(IpcError::Internal(_))));
    }

    #[tokio::test]
    async fn dispatch_subscribe_without_handle_returns_internal_error() {
        let req = IpcRequest {
            id: 3,
            op: IpcOp::Subscribe,
        };
        let resp = dispatch(req, None).await;
        assert_eq!(resp.id, 3);
        assert!(matches!(resp.result, Err(IpcError::Internal(_))));
    }

    #[tokio::test]
    async fn dispatch_shutdown_does_not_require_engine_handle() {
        let req = IpcRequest {
            id: 4,
            op: IpcOp::Shutdown,
        };
        let resp = dispatch(req, None).await;
        assert_eq!(resp.id, 4);
        assert!(matches!(resp.result, Ok(IpcResult::ShuttingDown)));
    }

    #[tokio::test]
    async fn dispatch_snapshot_with_handle_returns_disconnected_initially() {
        let handle = EngineHandle::for_test();
        let req = IpcRequest {
            id: 5,
            op: IpcOp::Snapshot,
        };
        let resp = dispatch(req, Some(&handle)).await;
        match resp.result {
            Ok(IpcResult::Snapshot { state }) => {
                assert!(matches!(state, Connection::Disconnected { .. }));
            }
            other => panic!("expected Snapshot, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_execute_connect_with_handle_returns_accepted() {
        let handle = EngineHandle::for_test();
        let req = IpcRequest {
            id: 6,
            op: IpcOp::Execute(UserCommand::Connect {
                profile_id: ProfileId::new("corp"),
            }),
        };
        let resp = dispatch(req, Some(&handle)).await;
        assert!(matches!(resp.result, Ok(IpcResult::Accepted)));
    }

    #[tokio::test]
    async fn dispatch_subscribe_with_handle_returns_subscribed_ack() {
        let handle = EngineHandle::for_test();
        let req = IpcRequest {
            id: 7,
            op: IpcOp::Subscribe,
        };
        let resp = dispatch(req, Some(&handle)).await;
        assert!(matches!(resp.result, Ok(IpcResult::Subscribed)));
    }

    // ===== D2 peer-UID enforcement tests =====

    /// Helper: pick a unique temp socket path.
    fn fresh_socket_path() -> PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("vortix-test-{}-{nanos}.sock", std::process::id()));
        p
    }

    #[tokio::test]
    async fn peer_uid_matches_daemon_uid_for_same_process() {
        // Same-process connect: UID matches, dispatch fires normally.
        let socket = fresh_socket_path();
        let server = DaemonServer::bind(socket.clone()).expect("bind");
        let daemon_uid = server.daemon_uid();
        // SAFETY: trivial syscall, see DaemonServer::bind.
        let process_uid = unsafe { libc::geteuid() };
        assert_eq!(daemon_uid, process_uid, "daemon UID captured correctly");

        let handle = tokio::spawn(server.run());

        let mut client = loop {
            match TokioUnixStream::connect(&socket).await {
                Ok(s) => break s,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };

        // Shutdown is the simplest op — dispatched regardless of engine handle.
        let req = IpcRequest {
            id: 7,
            op: IpcOp::Shutdown,
        };
        let frame = encode_frame(&req).expect("encode");
        client.write_all(&frame).await.expect("write");

        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.expect("read");
        let (resp, _) = decode_frame::<IpcResponse>(&buf[..n])
            .expect("decode ok")
            .expect("complete frame");
        assert_eq!(resp.id, 7);
        assert!(matches!(resp.result, Ok(IpcResult::ShuttingDown)));

        handle.abort();
        let _ = std::fs::remove_file(&socket);
    }

    #[tokio::test]
    async fn unauthorized_path_emits_unauthorized_frame_without_dispatch() {
        // Force the rejection branch by passing a daemon_uid the
        // peer can never match (u32::MAX is never a real UID).
        let (server_end, mut client_end) = TokioUnixStream::pair().expect("socketpair");

        let fake_daemon_uid = u32::MAX;
        let server_task =
            tokio::spawn(async move { handle_client(server_end, fake_daemon_uid, None).await });

        let mut buf = vec![0u8; 4096];
        let n = client_end.read(&mut buf).await.expect("read");
        let (resp, _) = decode_frame::<IpcResponse>(&buf[..n])
            .expect("decode ok")
            .expect("complete frame");
        assert_eq!(resp.id, 0, "unauthorized frame uses id=0");
        assert!(matches!(resp.result, Err(IpcError::Unauthorized)));

        let outcome = server_task.await.expect("join");
        assert!(outcome.is_ok());
    }

    #[tokio::test]
    async fn get_peer_uid_returns_current_process_uid_on_socketpair() {
        let (a, _b) = TokioUnixStream::pair().expect("socketpair");
        let uid = get_peer_uid(&a).expect("peer uid lookup");
        // SAFETY: trivial syscall, see DaemonServer::bind.
        let me = unsafe { libc::geteuid() };
        assert_eq!(uid, me);
    }

    // ===== U22 multi-tunnel command dispatch =====

    #[tokio::test]
    async fn dispatch_execute_disconnect_all_routes_through_engine_handle() {
        let handle = EngineHandle::for_test();
        // Connect first so disconnect has something to act on.
        let connect_req = IpcRequest {
            id: 10,
            op: IpcOp::Execute(UserCommand::Connect {
                profile_id: ProfileId::new("corp"),
            }),
        };
        let _ = dispatch(connect_req, Some(&handle)).await;

        let req = IpcRequest {
            id: 11,
            op: IpcOp::Execute(UserCommand::Disconnect { profile_id: None }),
        };
        let resp = dispatch(req, Some(&handle)).await;
        assert_eq!(resp.id, 11);
        assert!(matches!(resp.result, Ok(IpcResult::Accepted)));
    }

    #[tokio::test]
    async fn dispatch_execute_disconnect_specific_routes_through_engine_handle() {
        let handle = EngineHandle::for_test();
        let req = IpcRequest {
            id: 12,
            op: IpcOp::Execute(UserCommand::Disconnect {
                profile_id: Some(ProfileId::new("corp")),
            }),
        };
        let resp = dispatch(req, Some(&handle)).await;
        assert!(matches!(resp.result, Ok(IpcResult::Accepted)));
    }

    #[tokio::test]
    async fn dispatch_execute_reconnect_all_routes_through_engine_handle() {
        let handle = EngineHandle::for_test();
        let req = IpcRequest {
            id: 13,
            op: IpcOp::Execute(UserCommand::Reconnect { profile_id: None }),
        };
        let resp = dispatch(req, Some(&handle)).await;
        assert!(matches!(resp.result, Ok(IpcResult::Accepted)));
    }

    #[tokio::test]
    async fn dispatch_execute_force_disconnect_specific_routes_through_engine_handle() {
        let handle = EngineHandle::for_test();
        let req = IpcRequest {
            id: 14,
            op: IpcOp::Execute(UserCommand::ForceDisconnect {
                profile_id: Some(ProfileId::new("corp")),
            }),
        };
        let resp = dispatch(req, Some(&handle)).await;
        assert!(matches!(resp.result, Ok(IpcResult::Accepted)));
    }

    #[test]
    fn v1_disconnect_unit_form_does_not_decode_against_v2_op() {
        // A v1 client sending `{"kind":"execute","Execute":"Disconnect"}`
        // (legacy unit-variant payload) must NOT silently mis-parse on
        // the v2 server. Verify against IpcOp::Execute(UserCommand) end
        // to end.
        let v1_envelope = r#"{"kind":"execute","Execute":"Disconnect"}"#;
        let parsed: Result<IpcOp, _> = serde_json::from_str(v1_envelope);
        assert!(
            parsed.is_err(),
            "v1 unit-variant Disconnect should be rejected by v2 IpcOp decoder, got {parsed:?}"
        );
    }

    #[test]
    fn v2_disconnect_struct_form_round_trips_through_ipc_op() {
        let op = IpcOp::Execute(UserCommand::Disconnect { profile_id: None });
        let json = serde_json::to_string(&op).expect("serialize");
        let back: IpcOp = serde_json::from_str(&json).expect("deserialize");
        match back {
            IpcOp::Execute(UserCommand::Disconnect { profile_id: None }) => {}
            other => panic!("v2 Disconnect{{None}} round-trip mismatch: {other:?}"),
        }
    }

    #[test]
    fn ipc_error_conflict_round_trips() {
        use crate::vortix_core::engine::registry::Conflict;
        let err = IpcError::Conflict {
            conflict: Conflict::DefaultRouteTakeover {
                current: ProfileId::new("corp"),
                new: ProfileId::new("home"),
            },
        };
        let json = serde_json::to_string(&err).expect("serialize");
        let back: IpcError = serde_json::from_str(&json).expect("deserialize");
        match back {
            IpcError::Conflict {
                conflict: Conflict::DefaultRouteTakeover { current, new },
            } => {
                assert_eq!(current.as_str(), "corp");
                assert_eq!(new.as_str(), "home");
            }
            other => panic!("expected Conflict round-trip, got {other:?}"),
        }
    }

    #[test]
    fn ipc_result_registry_snapshot_round_trips() {
        use crate::vortix_core::state::KillSwitchState;
        let r = IpcResult::RegistrySnapshot {
            tunnels: vec![],
            primary: None,
            killswitch: KillSwitchState::Disabled,
        };
        let json = serde_json::to_string(&r).expect("serialize");
        let back: IpcResult = serde_json::from_str(&json).expect("deserialize");
        match back {
            IpcResult::RegistrySnapshot {
                tunnels,
                primary,
                killswitch,
            } => {
                assert!(tunnels.is_empty());
                assert!(primary.is_none());
                assert_eq!(killswitch, KillSwitchState::Disabled);
            }
            other => panic!("expected RegistrySnapshot, got {other:?}"),
        }
    }
}
