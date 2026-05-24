//! Daemon IPC server loop (plan 015 phase D U18 / plan 010).
//!
//! Single-client-at-a-time. Accept → read frame → dispatch → write
//! response → loop until client disconnects. Multi-client support is
//! follow-up scope.

use std::path::{Path, PathBuf};

use crate::vortix_core::ipc::{
    decode_frame, encode_frame, FrameError, IpcError, IpcOp, IpcRequest, IpcResponse, IpcResult,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

/// The daemon server. Holds the socket binding + the engine handle.
pub struct DaemonServer {
    socket_path: PathBuf,
    listener: UnixListener,
}

impl DaemonServer {
    /// Bind the daemon socket. Cleans up any stale file at the path.
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
        })
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
        loop {
            match self.listener.accept().await {
                Ok((stream, _addr)) => {
                    if let Err(e) = handle_client(stream).await {
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
async fn handle_client(mut stream: UnixStream) -> Result<(), DaemonError> {
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
                    let resp = dispatch(req).await;
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

#[allow(clippy::unused_async)] // future units await the EngineHandle once wired
async fn dispatch(req: IpcRequest) -> IpcResponse {
    // v0.3.0 ships the dispatch skeleton. Real Execute / Snapshot /
    // Subscribe wiring connects to the global EngineHandle in the
    // next phase D unit (deferred — the daemon needs the same
    // tunnel-factory construction that main.rs's TUI path uses, and
    // sharing that initialization is a refactor of run_tui's setup).
    // Today the daemon responds with structured "not yet wired"
    // errors so clients see typed wire errors instead of empty
    // responses or connection drops.
    let result = match req.op {
        IpcOp::Execute(_) | IpcOp::Snapshot | IpcOp::Subscribe => Err(IpcError::Internal(
            "engine wiring not yet connected in daemon — coming in v0.3.x".into(),
        )),
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
