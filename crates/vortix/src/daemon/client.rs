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
use std::time::Duration;

use crate::vortix_core::control::{DiagnosticSnapshot, DiagnosticSource, DiagnosticView};
use crate::vortix_core::ipc::{
    decode_frame, encode_frame, ClientHello, FrameError, IpcCapability, IpcError, IpcOp,
    IpcRequest, IpcResponse, IpcResult, PassiveSnapshot, ServerHello, IPC_PROTOCOL_MAX,
    IPC_PROTOCOL_MIN, IPC_SCHEMA_MAX, IPC_SCHEMA_MIN,
};

use super::service::{
    RemoteControlError, RemoteControlSubscription, RemoteControlTransport, RemoteControlUpdate,
};

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
    let required = required_capability(&op);
    let (mut stream, mut buffered) =
        connect_handshaken(socket_path, required, Some(Duration::from_secs(2)))?;
    let request = IpcRequest { id: 2, op };
    let result = exchange(&mut stream, &mut buffered, &request)?
        .result
        .map_err(ClientError::Daemon)?;
    validate_result(&result)?;
    Ok(result)
}

fn connect_handshaken(
    socket_path: &Path,
    required: IpcCapability,
    read_timeout: Option<Duration>,
) -> Result<(UnixStream, Vec<u8>), ClientError> {
    validate_socket_owner(socket_path)?;
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(read_timeout)?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut buffered = Vec::with_capacity(4096);
    let handshake = IpcRequest {
        id: 1,
        op: IpcOp::Handshake {
            hello: ClientHello::current(vec![required]),
        },
    };
    match exchange(&mut stream, &mut buffered, &handshake)?
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
    Ok((stream, buffered))
}

fn exchange(
    stream: &mut UnixStream,
    buffered: &mut Vec<u8>,
    request: &IpcRequest,
) -> Result<IpcResponse, ClientError> {
    let frame = zeroize::Zeroizing::new(encode_frame(request)?);
    stream.write_all(frame.as_slice())?;
    let response = read_response(stream, buffered)?;
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
    let mut chunk = [0u8; 4096];
    loop {
        if let Some((resp, consumed)) = decode_frame::<IpcResponse>(buffered)? {
            buffered.drain(..consumed);
            return Ok(resp);
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

pub struct DiagnosticSubscription {
    stream: UnixStream,
    buffered: Vec<u8>,
    initial: DiagnosticView,
}

struct ControlSubscription {
    stream: UnixStream,
    buffered: Vec<u8>,
}

impl RemoteControlSubscription for ControlSubscription {
    fn try_recv(&mut self) -> Result<Option<RemoteControlUpdate>, RemoteControlError> {
        match read_response(&mut self.stream, &mut self.buffered) {
            Ok(response) => match response.result.map_err(RemoteControlError::from_ipc)? {
                IpcResult::ControlEvent { event, snapshot } => {
                    Ok(Some(RemoteControlUpdate { event, snapshot }))
                }
                IpcResult::ResyncRequired { newest_generation } => {
                    Err(RemoteControlError::ResyncRequired { newest_generation })
                }
                other => Err(RemoteControlError::Protocol(format!(
                    "unexpected control subscription result: {other:?}"
                ))),
            },
            Err(ClientError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(remote_error(error)),
        }
    }
}

/// Unix-socket implementation of the dormant canonical control transport.
/// Constructing this value grants no authority; production connection is
/// still fenced by [`super::service::RemoteMutationGate`].
#[derive(Debug, Clone)]
pub struct UnixRemoteControlTransport {
    socket_path: std::path::PathBuf,
}

impl UnixRemoteControlTransport {
    #[must_use]
    pub fn new(socket_path: std::path::PathBuf) -> Self {
        Self { socket_path }
    }
}

impl RemoteControlTransport for UnixRemoteControlTransport {
    fn exchange(&self, op: IpcOp) -> Result<IpcResult, RemoteControlError> {
        request(&self.socket_path, op).map_err(remote_error)
    }

    fn subscribe(
        &self,
        session_id: &crate::vortix_core::ipc::RemoteSessionId,
    ) -> Result<
        (
            Box<dyn RemoteControlSubscription>,
            crate::vortix_core::control::ControlSnapshot,
        ),
        RemoteControlError,
    > {
        let (stream, buffered, result) = open_subscription(
            &self.socket_path,
            IpcCapability::ControlMutation,
            IpcOp::ControlSubscribe {
                session_id: session_id.clone(),
            },
        )
        .map_err(remote_error)?;
        let IpcResult::ControlSubscribed { snapshot } = result else {
            return Err(RemoteControlError::Protocol(format!(
                "invalid control subscribe response: {result:?}"
            )));
        };
        stream
            .set_nonblocking(true)
            .map_err(|error| RemoteControlError::Unavailable(error.to_string()))?;
        Ok((Box::new(ControlSubscription { stream, buffered }), snapshot))
    }
}

fn remote_error(error: ClientError) -> RemoteControlError {
    match error {
        ClientError::Io(error) => RemoteControlError::Unavailable(error.to_string()),
        ClientError::Frame(error) => RemoteControlError::Protocol(error.to_string()),
        ClientError::Daemon(error) => RemoteControlError::from_ipc(error),
        ClientError::ResyncRequired { newest_generation } => {
            RemoteControlError::ResyncRequired { newest_generation }
        }
        ClientError::Unexpected(error) => RemoteControlError::Protocol(error),
    }
}

impl DiagnosticSubscription {
    #[must_use]
    pub const fn initial(&self) -> &DiagnosticView {
        &self.initial
    }

    pub fn recv(&mut self) -> Result<DiagnosticView, ClientError> {
        match read_response(&mut self.stream, &mut self.buffered)?.result {
            Ok(IpcResult::DiagnosticEvent { snapshot }) => {
                validate_diagnostic_snapshot(&snapshot)?;
                Ok(authenticated_diagnostic_view(snapshot))
            }
            Ok(IpcResult::ResyncRequired { newest_generation }) => {
                Err(ClientError::ResyncRequired { newest_generation })
            }
            Ok(other) => Err(ClientError::Unexpected(format!(
                "unexpected diagnostic subscription result: {other:?}"
            ))),
            Err(error) => Err(ClientError::Daemon(error)),
        }
    }
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
    let (stream, buffered, result) = open_subscription(
        socket_path,
        IpcCapability::PassiveSubscribe,
        IpcOp::PassiveSubscribe,
    )?;
    let initial = match result {
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
    Ok(PassiveSubscription {
        stream,
        buffered,
        initial,
    })
}

pub fn subscribe_diagnostics(socket_path: &Path) -> Result<DiagnosticSubscription, ClientError> {
    let (stream, buffered, result) = open_subscription(
        socket_path,
        IpcCapability::DiagnosticsSubscribe,
        IpcOp::DiagnosticsSubscribe,
    )?;
    let initial = match result {
        IpcResult::DiagnosticSubscribed { snapshot } => {
            validate_diagnostic_snapshot(&snapshot)?;
            authenticated_diagnostic_view(snapshot)
        }
        other => {
            return Err(ClientError::Unexpected(format!(
                "invalid diagnostic subscribe response: {other:?}"
            )));
        }
    };
    Ok(DiagnosticSubscription {
        stream,
        buffered,
        initial,
    })
}

fn open_subscription(
    socket_path: &Path,
    capability: IpcCapability,
    op: IpcOp,
) -> Result<(UnixStream, Vec<u8>, IpcResult), ClientError> {
    let (mut stream, mut buffered) =
        connect_handshaken(socket_path, capability, Some(Duration::from_secs(30)))?;
    let result = exchange(&mut stream, &mut buffered, &IpcRequest { id: 2, op })?
        .result
        .map_err(ClientError::Daemon)?;
    // Snapshot streams are intentionally quiet when source truth is stable.
    stream.set_read_timeout(None)?;
    Ok((stream, buffered, result))
}

fn validate_handshake(hello: &ServerHello, required: IpcCapability) -> Result<(), ClientError> {
    let control = required == IpcCapability::ControlMutation;
    if hello.product != "vortix"
        || hello.passive == control
        || !(IPC_PROTOCOL_MIN..=IPC_PROTOCOL_MAX).contains(&hello.protocol)
        || !(IPC_SCHEMA_MIN..=IPC_SCHEMA_MAX).contains(&hello.schema)
        || (control && hello.schema < 3)
        || !hello.capabilities.contains(&required)
        || (!control && hello.capabilities.contains(&IpcCapability::ControlMutation))
    {
        return Err(ClientError::Unexpected(format!(
            "invalid daemon handshake response: {hello:?}"
        )));
    }
    Ok(())
}

fn validate_result(result: &IpcResult) -> Result<(), ClientError> {
    match result {
        IpcResult::PassiveSnapshot { snapshot }
        | IpcResult::PassiveSubscribed { snapshot }
        | IpcResult::PassiveEvent { snapshot } => validate_passive_snapshot(snapshot),
        IpcResult::DiagnosticSnapshot { snapshot }
        | IpcResult::DiagnosticSubscribed { snapshot }
        | IpcResult::DiagnosticEvent { snapshot } => validate_diagnostic_snapshot(snapshot),
        _ => Ok(()),
    }
}

fn validate_diagnostic_snapshot(snapshot: &DiagnosticSnapshot) -> Result<(), ClientError> {
    if !snapshot.is_compatible() {
        return Err(ClientError::Unexpected(
            "daemon returned an incompatible diagnostic snapshot".into(),
        ));
    }
    Ok(())
}

fn authenticated_diagnostic_view(snapshot: DiagnosticSnapshot) -> DiagnosticView {
    DiagnosticView {
        source: DiagnosticSource::AuthenticatedLive,
        stale: false,
        age_millis: 0,
        snapshot,
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

fn required_capability(op: &IpcOp) -> IpcCapability {
    match op {
        IpcOp::Handshake { .. } | IpcOp::PassiveSnapshot => IpcCapability::PassiveSnapshot,
        IpcOp::Execute(_)
        | IpcOp::ControlOpen
        | IpcOp::ControlSubmit { .. }
        | IpcOp::ControlSnapshot { .. }
        | IpcOp::ControlSubscribe { .. }
        | IpcOp::ControlRespondChallenge { .. }
        | IpcOp::ControlCancelChallenge { .. }
        | IpcOp::ControlStageProfileImport { .. }
        | IpcOp::ControlCancelProfileImport { .. } => IpcCapability::ControlMutation,
        IpcOp::Snapshot => IpcCapability::LegacySnapshot,
        IpcOp::Subscribe | IpcOp::PassiveSubscribe => IpcCapability::PassiveSubscribe,
        IpcOp::Diagnostics => IpcCapability::Diagnostics,
        IpcOp::DiagnosticsSubscribe => IpcCapability::DiagnosticsSubscribe,
        IpcOp::Shutdown => IpcCapability::Shutdown,
    }
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

pub fn diagnostics(socket_path: &Path) -> Result<DiagnosticView, ClientError> {
    match request(socket_path, IpcOp::Diagnostics)? {
        IpcResult::DiagnosticSnapshot { snapshot } => Ok(authenticated_diagnostic_view(snapshot)),
        other => Err(ClientError::Unexpected(format!("{other:?}"))),
    }
}

/// Read authenticated live diagnostics, or the latest owner-private advisory
/// snapshot when the daemon cannot be reached or negotiated.
pub fn diagnostics_or_fallback(
    socket_path: &Path,
    fallback_path: &Path,
    now_unix_millis: u64,
) -> Result<DiagnosticView, ClientError> {
    match diagnostics(socket_path) {
        Ok(view) => Ok(view),
        Err(live_error) => {
            match super::diagnostics::FallbackStore::new(fallback_path.to_path_buf())
                .read(now_unix_millis)
            {
                Ok(view) => Ok(view),
                Err(_) => Err(live_error),
            }
        }
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
}
