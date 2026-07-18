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
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::sync::broadcast;

use crate::vortix_core::engine::event::EventEnvelope;
use crate::vortix_core::ipc::{
    decode_frame, encode_frame, FrameError, IpcError, IpcOp, IpcRequest, IpcResponse, IpcResult,
    IpcTransport, TransportError, IPC_PROTOCOL_VERSION,
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
    /// Peer speaks a different IPC protocol version. Loud by contract
    /// (AE8) — callers must not fold this into the silent bypass path.
    VersionMismatch { daemon: u32, client: u32 },
    /// The connection was made but the daemon didn't answer within the
    /// read deadline — present but slow. Kept distinct from `Io` so a
    /// write caller doesn't fall through to a second local attempt.
    Timeout(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "ipc io: {e}"),
            Self::Frame(e) => write!(f, "ipc frame: {e}"),
            Self::Daemon(e) => write!(f, "daemon error: {e}"),
            Self::Unexpected(s) => write!(f, "unexpected daemon response: {s}"),
            Self::VersionMismatch { daemon, client } => write!(
                f,
                "IPC protocol mismatch: daemon speaks v{daemon}, client speaks v{client}"
            ),
            Self::Timeout(s) => write!(f, "daemon read timeout: {s}"),
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

/// Default read timeout for near-instant read-only ops (`Snapshot`,
/// `RegistrySnapshot`). If the daemon hangs longer, the caller gets an
/// `Io` error and falls back to the direct bypass path.
const DEFAULT_READ_TIMEOUT_SECS: u64 = 2;

/// Read timeout for `Execute` — the daemon holds the connection open
/// until the FSM finishes the (possibly slow) connect/disconnect, so
/// this must comfortably exceed the connect timeout
/// ([`crate::constants::DEFAULT_CONNECT_TIMEOUT`] = 35s) plus teardown
/// margin. A write that outlives this surfaces as a transport failure.
const EXECUTE_READ_TIMEOUT_SECS: u64 = 60;

/// The read timeout appropriate for `op`. Reads are quick; `Execute`
/// blocks on the real tunnel lifecycle.
fn read_timeout_for(op: &IpcOp) -> Duration {
    match op {
        IpcOp::Execute(_) => Duration::from_secs(EXECUTE_READ_TIMEOUT_SECS),
        _ => Duration::from_secs(DEFAULT_READ_TIMEOUT_SECS),
    }
}

/// One-shot RPC against the daemon. Opens a fresh `UnixStream`,
/// sends `op` framed with `id`, reads exactly one response frame. The
/// read timeout is chosen per-op (`Execute` gets a long timeout for the
/// tunnel lifecycle; reads are quick).
///
/// # Errors
///
/// Surfaces transport-, framing-, and protocol-level failures. CLI
/// handlers treat any error here as "bypass: read directly from
/// disk + scanner instead".
pub fn request(socket_path: &Path, op: IpcOp) -> Result<IpcResult, ClientError> {
    let read_timeout = read_timeout_for(&op);
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(read_timeout))?;
    stream.set_write_timeout(Some(Duration::from_secs(DEFAULT_READ_TIMEOUT_SECS)))?;

    let req = IpcRequest {
        id: 1,
        protocol_version: IPC_PROTOCOL_VERSION,
        op,
    };
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
        let n = match stream.read(&mut chunk) {
            Ok(n) => n,
            // A `set_read_timeout` deadline elapses as WouldBlock (Unix)
            // or TimedOut — the daemon is connected but slow, NOT gone.
            // Surface it as a distinct Timeout so a write caller doesn't
            // fall through to a second local attempt.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(ClientError::Timeout(e.to_string()));
            }
            Err(e) => return Err(ClientError::Io(e)),
        };
        if n == 0 {
            return Err(ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "daemon closed connection without responding",
            )));
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    // Version gate on both directions: a pre-versioning daemon answers
    // with the serde default (0); a newer daemon names the mismatch as
    // a typed error. Both surface loudly (AE8).
    if let Err(IpcError::VersionMismatch { daemon, client }) = &resp.result {
        return Err(ClientError::VersionMismatch {
            daemon: *daemon,
            client: *client,
        });
    }
    if resp.protocol_version != IPC_PROTOCOL_VERSION {
        return Err(ClientError::VersionMismatch {
            daemon: resp.protocol_version,
            client: IPC_PROTOCOL_VERSION,
        });
    }

    resp.result.map_err(ClientError::Daemon)
}

/// [`IpcTransport`] over the daemon's Unix socket — the transport a
/// `RemoteHandle` drives. Maps [`ClientError`] onto the tri-state
/// [`TransportError`] contract: availability failures fall back
/// silently, version mismatches are loud, everything else is a
/// protocol failure.
#[derive(Debug, Clone)]
pub struct UnixTransport {
    socket_path: PathBuf,
}

impl UnixTransport {
    #[must_use]
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }
}

impl IpcTransport for UnixTransport {
    fn request(&self, op: IpcOp) -> Result<IpcResult, TransportError> {
        request(&self.socket_path, op).map_err(|e| match e {
            ClientError::Io(io) => TransportError::Unavailable(io.to_string()),
            ClientError::VersionMismatch { daemon, client } => {
                TransportError::VersionMismatch { daemon, client }
            }
            ClientError::Frame(f) => TransportError::Protocol(f.to_string()),
            ClientError::Daemon(d) => TransportError::Protocol(d.to_string()),
            ClientError::Unexpected(s) => TransportError::Protocol(s),
            ClientError::Timeout(s) => TransportError::Timeout(s),
        })
    }

    fn subscribe(&self) -> Result<broadcast::Receiver<EventEnvelope>, TransportError> {
        subscribe(&self.socket_path).map_err(|e| match e {
            ClientError::Io(io) => TransportError::Unavailable(io.to_string()),
            ClientError::VersionMismatch { daemon, client } => {
                TransportError::VersionMismatch { daemon, client }
            }
            ClientError::Frame(f) => TransportError::Protocol(f.to_string()),
            ClientError::Daemon(d) => TransportError::Protocol(d.to_string()),
            ClientError::Unexpected(s) => TransportError::Protocol(s),
            ClientError::Timeout(s) => TransportError::Timeout(s),
        })
    }
}

/// Capacity of the client-side event fan-out channel. Matches the
/// daemon's journal broadcast order of magnitude; a slow consumer that
/// overflows sees `Lagged` and resyncs from a fresh snapshot.
const SUBSCRIBE_CHANNEL_CAP: usize = 256;

/// Open a live subscription: connect, send `Subscribe`, read the
/// `Subscribed` ack, then spawn a reader thread that forwards every
/// pushed [`IpcResult::Event`] into a broadcast channel. The returned
/// receiver yields events until the daemon closes the stream (the thread
/// exits on EOF/error, dropping the sender so receivers see `Closed`).
///
/// # Errors
///
/// Surfaces connect/version/framing failures encountered before the
/// stream is established.
fn subscribe(socket_path: &Path) -> Result<broadcast::Receiver<EventEnvelope>, ClientError> {
    let mut stream = UnixStream::connect(socket_path)?;
    // Streaming is long-lived: no read timeout (block for the next event).
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(Some(Duration::from_secs(DEFAULT_READ_TIMEOUT_SECS)))?;

    let req = IpcRequest {
        id: 1,
        protocol_version: IPC_PROTOCOL_VERSION,
        op: IpcOp::Subscribe,
    };
    stream.write_all(&encode_frame(&req)?)?;

    // Read frames until the first one decodes; that's the ack. Any bytes
    // read past it (an event the daemon already pushed) stay in `buf` and
    // are carried into the reader thread.
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let ack: IpcResponse = loop {
        if let Some((resp, consumed)) = decode_frame::<IpcResponse>(&buf)? {
            buf.drain(..consumed);
            break resp;
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "daemon closed connection before acking subscribe",
            )));
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    if ack.protocol_version != IPC_PROTOCOL_VERSION {
        return Err(ClientError::VersionMismatch {
            daemon: ack.protocol_version,
            client: IPC_PROTOCOL_VERSION,
        });
    }
    match ack.result {
        Ok(IpcResult::Subscribed) => {}
        Ok(other) => return Err(ClientError::Unexpected(format!("{other:?}"))),
        Err(e) => return Err(ClientError::Daemon(e)),
    }

    let (tx, rx) = broadcast::channel(SUBSCRIBE_CHANNEL_CAP);
    std::thread::spawn(move || forward_events(&mut stream, buf, &tx));
    Ok(rx)
}

/// Reader-thread body: decode `Event` frames off `stream` and re-publish
/// them on `tx`. Exits on EOF, a framing error, or when all receivers
/// drop (send returns `Err`). `carry` holds any bytes read past the ack.
fn forward_events(stream: &mut UnixStream, carry: Vec<u8>, tx: &broadcast::Sender<EventEnvelope>) {
    let mut buf = carry;
    let mut chunk = [0u8; 4096];
    loop {
        // Drain any complete frames already buffered.
        loop {
            match decode_frame::<IpcResponse>(&buf) {
                Ok(Some((resp, consumed))) => {
                    buf.drain(..consumed);
                    match resp.result {
                        Ok(IpcResult::Event(event)) => {
                            // Send failing means no receivers remain — stop.
                            if tx.send(event).is_err() {
                                return;
                            }
                        }
                        // A heartbeat carries no event; use it as a chance
                        // to reap this thread if the caller dropped the
                        // receiver (otherwise it would park on the next read).
                        Ok(IpcResult::Heartbeat) => {
                            if tx.receiver_count() == 0 {
                                return;
                            }
                        }
                        _ => {}
                    }
                }
                Ok(None) => break,
                Err(_) => return, // framing broke; end the stream
            }
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return, // EOF or read error
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::engine::handle::EngineHandle;
    use crate::vortix_core::engine::input::UserCommand;
    use crate::vortix_core::profile::ProfileId;

    fn fresh_socket_path() -> PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!(
            "vortix-client-test-{}-{nanos}.sock",
            std::process::id()
        ));
        p
    }

    // Full client path: UnixTransport::subscribe opens the stream, reads
    // the ack, and its reader thread forwards pushed events into the
    // broadcast channel the caller receives on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unix_transport_subscribe_receives_pushed_events() {
        let socket = fresh_socket_path();
        let server = crate::daemon::DaemonServer::bind(socket.clone())
            .expect("bind")
            .with_engine_handle(EngineHandle::for_test());
        let task = tokio::spawn(server.run());

        // subscribe() blocks (connect + ack + spawn reader) — keep it off
        // the runtime so the server task can accept.
        let sub_socket = socket.clone();
        let mut rx = tokio::task::spawn_blocking(move || subscribe(&sub_socket))
            .await
            .expect("join")
            .expect("subscribe");

        // Let the server enter its streaming loop before generating events.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Drive an event through a second (request) connection.
        let cmd_socket = socket.clone();
        tokio::task::spawn_blocking(move || {
            request(
                &cmd_socket,
                IpcOp::Execute(UserCommand::Connect {
                    profile_id: ProfileId::new("corp"),
                }),
            )
        })
        .await
        .expect("join")
        .expect("execute");

        let event = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("event within timeout")
            .expect("event, not lag/close");
        // The forwarded value is a real engine event envelope.
        let _ = event;

        task.abort();
        let _ = std::fs::remove_file(&socket);
    }
}
