//! Blocking IPC client for passive daemon queries and subscriptions.
//!
//! Read-only CLI ops (`vortix status`) call into the daemon when its
//! socket is present and connectable, falling back to direct disk +
//! scanner reads otherwise. One-shot requests use a fresh connection;
//! subscriptions keep their authenticated connection open for full
//! replacement snapshots.
//!
//! Lives next to the server to share the framing/envelope vocabulary
//! without exporting tokio-flavored types from `vortix-core`.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use socket2::{Domain, SockAddr, Socket, Type};

use crate::vortix_core::ipc::{
    decode_frame, encode_frame, ClientHello, FrameError, IpcCapability, IpcError, IpcOp,
    IpcRequest, IpcResponse, IpcResult, PassiveSnapshot, ServerHello, IPC_PROTOCOL_MAX,
    IPC_PROTOCOL_MIN, IPC_SCHEMA_MAX, IPC_SCHEMA_MIN,
};

const IPC_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(2);

/// IPC client error surface visible to CLI handlers. Captures the
/// transport, framing, compatibility, server, and subscription failure
/// modes callers may need to discriminate.
#[derive(Debug)]
pub enum ClientError {
    /// Socket connect / read / write failed.
    Io(std::io::Error),
    /// Framing / serialization error on the wire.
    Frame(FrameError),
    /// Daemon answered with a typed protocol error.
    Daemon(IpcError),
    /// A bounded subscription consumer fell behind. Reconnect to obtain a
    /// fresh subscribe-before-snapshot boundary.
    ResyncRequired { newest_generation: u64 },
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
            Self::ResyncRequired { newest_generation } => write!(
                f,
                "subscription lagged; resubscribe at generation {newest_generation}"
            ),
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
    let handshake_deadline = Instant::now() + IPC_EXCHANGE_TIMEOUT;
    validate_socket_owner(socket_path)?;
    let mut stream = connect_with_deadline(socket_path, handshake_deadline)?;
    let mut buffered = Vec::with_capacity(4096);

    let required = op.required_capability();
    let handshake = IpcRequest {
        id: 1,
        op: IpcOp::Handshake {
            hello: ClientHello::current(vec![required]),
        },
    };
    let handshake = exchange_until(&mut stream, &mut buffered, &handshake, handshake_deadline)?;
    match handshake.result.map_err(ClientError::Daemon)? {
        IpcResult::Handshake { hello } => validate_handshake(&hello, required)?,
        other => {
            return Err(ClientError::Unexpected(format!(
                "invalid handshake response: {other:?}"
            )));
        }
    }

    let request = IpcRequest { id: 2, op };
    let result = exchange_until(
        &mut stream,
        &mut buffered,
        &request,
        Instant::now() + IPC_EXCHANGE_TIMEOUT,
    )?
    .result
    .map_err(ClientError::Daemon)?;
    validate_passive_result(&result)?;
    Ok(result)
}

fn exchange_until(
    stream: &mut UnixStream,
    buffered: &mut Vec<u8>,
    request: &IpcRequest,
    deadline: Instant,
) -> Result<IpcResponse, ClientError> {
    set_deadline_timeouts(stream, deadline)?;
    stream.write_all(&encode_frame(request)?)?;
    let response = read_response_until(stream, buffered, Some(deadline))?;
    if response.id != request.id {
        return Err(ClientError::Unexpected(format!(
            "response id {} did not match request {}",
            response.id, request.id
        )));
    }
    Ok(response)
}

fn read_response(
    stream: &mut UnixStream,
    buffered: &mut Vec<u8>,
) -> Result<IpcResponse, ClientError> {
    read_response_until(stream, buffered, None)
}

fn read_response_until(
    stream: &mut UnixStream,
    buffered: &mut Vec<u8>,
    deadline: Option<Instant>,
) -> Result<IpcResponse, ClientError> {
    let mut chunk = [0u8; 4096];
    loop {
        if let Some((resp, consumed)) = decode_frame::<IpcResponse>(buffered)? {
            buffered.drain(..consumed);
            return Ok(resp);
        }
        if let Some(deadline) = deadline {
            set_deadline_timeouts(stream, deadline)?;
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "daemon closed connection without responding",
            )));
        }
        buffered.extend_from_slice(&chunk[..n]);
    }
}

/// Blocking passive subscription used by CLI/TUI adapters. The initial
/// snapshot is captured after the server subscribes, closing the classic
/// snapshot/subscribe race.
pub struct PassiveSubscription {
    stream: UnixStream,
    buffered: Vec<u8>,
    initial: crate::vortix_core::ipc::PassiveSnapshot,
}

impl PassiveSubscription {
    #[must_use]
    pub fn initial(&self) -> &crate::vortix_core::ipc::PassiveSnapshot {
        &self.initial
    }

    /// Wait for the next full replacement snapshot.
    pub fn recv(&mut self) -> Result<crate::vortix_core::ipc::PassiveSnapshot, ClientError> {
        match read_response(&mut self.stream, &mut self.buffered)?.result {
            Ok(IpcResult::PassiveEvent { snapshot }) => {
                validate_passive_snapshot(&snapshot)?;
                Ok(snapshot)
            }
            Ok(IpcResult::ResyncRequired { newest_generation }) => {
                Err(ClientError::ResyncRequired { newest_generation })
            }
            Ok(other) => Err(ClientError::Unexpected(format!(
                "unexpected subscription result: {other:?}"
            ))),
            Err(error) => Err(ClientError::Daemon(error)),
        }
    }
}

/// Open a passive snapshot stream with a race-free initial boundary.
pub fn subscribe(socket_path: &Path) -> Result<PassiveSubscription, ClientError> {
    let handshake_deadline = Instant::now() + IPC_EXCHANGE_TIMEOUT;
    validate_socket_owner(socket_path)?;
    let mut stream = connect_with_deadline(socket_path, handshake_deadline)?;
    let mut buffered = Vec::with_capacity(4096);
    let required = IpcCapability::PassiveSubscribe;
    let handshake = IpcRequest {
        id: 1,
        op: IpcOp::Handshake {
            hello: ClientHello::current(vec![required]),
        },
    };
    match exchange_until(&mut stream, &mut buffered, &handshake, handshake_deadline)?
        .result
        .map_err(ClientError::Daemon)?
    {
        IpcResult::Handshake { hello } => validate_handshake(&hello, required)?,
        other => {
            return Err(ClientError::Unexpected(format!(
                "invalid handshake response: {other:?}"
            )));
        }
    }
    let request = IpcRequest {
        id: 2,
        op: IpcOp::PassiveSubscribe,
    };
    let initial = match exchange_until(
        &mut stream,
        &mut buffered,
        &request,
        Instant::now() + IPC_EXCHANGE_TIMEOUT,
    )?
    .result
    .map_err(ClientError::Daemon)?
    {
        IpcResult::PassiveSubscribed { snapshot } => {
            validate_passive_snapshot(&snapshot)?;
            snapshot
        }
        other => {
            return Err(ClientError::Unexpected(format!(
                "invalid subscribe response: {other:?}"
            )));
        }
    };
    // Snapshot streams are intentionally quiet when scanner truth is stable.
    // Once the bounded handshake finishes, a fixed idle timeout would turn a
    // healthy connection into a false failure.
    stream.set_read_timeout(None)?;
    Ok(PassiveSubscription {
        stream,
        buffered,
        initial,
    })
}

fn connect_with_deadline(path: &Path, deadline: Instant) -> std::io::Result<UnixStream> {
    let timeout = remaining(deadline)?;
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    socket.connect_timeout(&SockAddr::unix(path)?, timeout)?;
    Ok(socket.into())
}

fn set_deadline_timeouts(stream: &UnixStream, deadline: Instant) -> std::io::Result<()> {
    let timeout = remaining(deadline)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))
}

fn remaining(deadline: Instant) -> std::io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "IPC deadline elapsed"))
}

fn validate_handshake(hello: &ServerHello, required: IpcCapability) -> Result<(), ClientError> {
    if hello.product != "vortix"
        || !hello.passive
        || !(IPC_PROTOCOL_MIN..=IPC_PROTOCOL_MAX).contains(&hello.protocol)
        || !(IPC_SCHEMA_MIN..=IPC_SCHEMA_MAX).contains(&hello.schema)
        || !hello.capabilities.contains(&required)
        || hello.capabilities.contains(&IpcCapability::ControlMutation)
    {
        return Err(ClientError::Unexpected(format!(
            "invalid passive handshake response: {hello:?}"
        )));
    }
    Ok(())
}

fn validate_passive_result(result: &IpcResult) -> Result<(), ClientError> {
    match result {
        IpcResult::PassiveSnapshot { snapshot }
        | IpcResult::PassiveSubscribed { snapshot }
        | IpcResult::PassiveEvent { snapshot } => validate_passive_snapshot(snapshot),
        _ => Ok(()),
    }
}

fn validate_passive_snapshot(snapshot: &PassiveSnapshot) -> Result<(), ClientError> {
    if snapshot.authoritative {
        return Err(ClientError::Unexpected(
            "passive daemon claimed authoritative control state".into(),
        ));
    }
    Ok(())
}

fn validate_socket_owner(path: &Path) -> Result<(), ClientError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
        let metadata = std::fs::symlink_metadata(path)?;
        // SAFETY: geteuid returns a scalar and has no failure mode.
        #[allow(unsafe_code)]
        let uid = unsafe { libc::geteuid() };
        if !metadata.file_type().is_socket()
            || metadata.uid() != uid
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "refusing foreign or unsafe daemon socket",
            )));
        }
    }
    Ok(())
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
    use crate::vortix_core::ipc::{
        CompatibilityRange, IPC_PROTOCOL_MAX, IPC_SCHEMA_MAX, PASSIVE_CAPABILITIES,
    };

    fn passive_hello() -> ServerHello {
        ServerHello {
            product: "vortix".into(),
            product_version: env!("CARGO_PKG_VERSION").into(),
            protocol: IPC_PROTOCOL_MAX,
            schema: IPC_SCHEMA_MAX,
            capabilities: PASSIVE_CAPABILITIES.to_vec(),
            passive: true,
        }
    }

    #[test]
    fn client_rejects_mutation_capability_from_passive_peer() {
        let mut hello = passive_hello();
        hello.capabilities.push(IpcCapability::ControlMutation);
        assert!(validate_handshake(&hello, IpcCapability::PassiveSnapshot).is_err());
    }

    #[test]
    fn client_rejects_authoritative_passive_snapshot() {
        let snapshot = PassiveSnapshot {
            authoritative: true,
            ..PassiveSnapshot::default()
        };
        assert!(validate_passive_snapshot(&snapshot).is_err());
    }

    #[test]
    fn current_client_range_starts_at_the_handshake_protocol() {
        let hello = ClientHello::current(Vec::new());
        assert_eq!(
            hello.protocol,
            CompatibilityRange {
                min: IPC_PROTOCOL_MIN,
                max: IPC_PROTOCOL_MAX,
            }
        );
        assert_eq!(hello.protocol.min, 2);
    }

    #[test]
    fn expired_deadline_prevents_socket_connect() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("deadline.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();

        let error = connect_with_deadline(&socket_path, Instant::now()).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }
}
