//! Minimal blocking IPC client for CLI use (plan multi-connection D3).
//!
//! Read-only CLI ops (`vortix status`) call into the daemon when its
//! socket is present and connectable, falling back to direct disk +
//! scanner reads otherwise. This client speaks one request → one
//! response on a fresh connection — no streaming, no pooling. The
//! daemon today handles one client at a time anyway, and the bypass
//! path means the client never tries to fight for the socket.
//!
//! Lives next to the server to share the framing/envelope vocabulary
//! without exporting tokio-flavored types from `vortix-core`.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::vortix_core::ipc::{
    decode_frame, encode_frame, FrameError, IpcError, IpcOp, IpcRequest, IpcResponse, IpcResult,
};

/// IPC client error surface visible to CLI handlers. Captures the
/// three failure modes we have to discriminate at the call site: the
/// daemon doesn't accept the connection (treat as "no daemon"), the
/// wire protocol broke down, or the daemon answered with a typed
/// error (e.g. engine wiring still pending — also "no daemon" for
/// bypass purposes).
#[derive(Debug)]
pub enum ClientError {
    /// Socket connect / read / write failed.
    Io(std::io::Error),
    /// Framing / serialization error on the wire.
    Frame(FrameError),
    /// Daemon answered with a typed protocol error.
    Daemon(IpcError),
    /// Daemon returned a result variant we weren't expecting for the
    /// op we sent. Carries a description string for diagnostics.
    Unexpected(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "ipc io: {e}"),
            Self::Frame(e) => write!(f, "ipc frame: {e}"),
            Self::Daemon(e) => write!(f, "daemon error: {e}"),
            Self::Unexpected(s) => write!(f, "unexpected daemon response: {s}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<FrameError> for ClientError {
    fn from(e: FrameError) -> Self {
        Self::Frame(e)
    }
}

/// One-shot RPC against the daemon. Opens a fresh `UnixStream`,
/// sends `op` framed with `id`, reads exactly one response frame.
///
/// Defaults to a 2-second read timeout — read-only ops should be
/// near-instant; if the daemon hangs longer than that, the caller
/// gets an `Io` error and falls back to the direct bypass path.
///
/// # Errors
///
/// Surfaces transport-, framing-, and protocol-level failures. CLI
/// handlers treat any error here as "bypass: read directly from
/// disk + scanner instead".
pub fn request(socket_path: &Path, op: IpcOp) -> Result<IpcResult, ClientError> {
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;

    let req = IpcRequest { id: 1, op };
    let frame = encode_frame(&req)?;
    stream.write_all(&frame)?;

    // Read until we have one full frame. The daemon writes exactly
    // one response per request, so we keep reading 4 KiB chunks until
    // decode_frame succeeds (or the peer closes).
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let resp: IpcResponse = loop {
        if let Some((resp, _consumed)) = decode_frame::<IpcResponse>(&buf)? {
            break resp;
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "daemon closed connection without responding",
            )));
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    resp.result.map_err(ClientError::Daemon)
}

/// Convenience wrapper: ask the daemon for a `Snapshot` and unwrap
/// the `Connection` payload. Anything other than `IpcResult::Snapshot`
/// is reported as `Unexpected`.
///
/// # Errors
///
/// See [`request`] — adds an `Unexpected` arm when the daemon answers
/// with a non-snapshot success variant.
pub fn snapshot(
    socket_path: &Path,
) -> Result<crate::vortix_core::engine::state::Connection, ClientError> {
    match request(socket_path, IpcOp::Snapshot)? {
        IpcResult::Snapshot { state } => Ok(state),
        other => Err(ClientError::Unexpected(format!("{other:?}"))),
    }
}
