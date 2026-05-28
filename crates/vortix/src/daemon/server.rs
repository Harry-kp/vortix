//! Daemon IPC server loop (plan 015 phase D U18 / plan 010).
//!
//! Single-client-at-a-time. Accept → read frame → dispatch → write
//! response → loop until client disconnects. Multi-client support is
//! follow-up scope.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::vortix_core::engine::EngineHandle;
use crate::vortix_core::ipc::{
    decode_frame, encode_frame, FrameError, IpcError, IpcOp, IpcRequest, IpcResponse, IpcResult,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

/// The daemon server. Holds the socket binding + the engine handle.
pub struct DaemonServer {
    socket_path: PathBuf,
    listener: UnixListener,
    engine_handle: Option<Arc<EngineHandle>>,
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
        // able to connect at the filesystem level. Phase E adds
        // SO_PEERCRED auth on top.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&socket_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&socket_path, perms)?;
        }
        Ok(Self {
            socket_path,
            listener,
            engine_handle: None,
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
        loop {
            match self.listener.accept().await {
                Ok((stream, _addr)) => {
                    let handle = self.engine_handle.clone();
                    if let Err(e) = handle_client(stream, handle).await {
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
async fn handle_client(
    mut stream: UnixStream,
    engine_handle: Option<Arc<EngineHandle>>,
) -> Result<(), DaemonError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::engine::input::UserCommand;
    use crate::vortix_core::engine::state::Connection;
    use crate::vortix_core::profile::ProfileId;

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
}
