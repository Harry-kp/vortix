//! Bounded, authenticated IPC for the passive daemon candidate.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, watch, Semaphore};
use tokio::task::JoinSet;
use zeroize::Zeroize as _;

use super::control_host::ControlAuthorityHost;
use super::diagnostics::{DiagnosticHub, DiagnosticQueryProvider};
use super::passive::{legacy_connection, PassiveQueryProvider};
use crate::vortix_core::control::{ControlSubscription, DiagnosticSnapshot};
use crate::vortix_core::ipc::{
    negotiate_control, negotiate_passive, ControlAvailability, FrameError, IpcCapability, IpcError,
    IpcOp, IpcRequest, IpcResponse, IpcResult, PassiveSnapshot, MAX_FRAME_BYTES,
};

const MAX_CONNECTIONS: usize = 32;
const MAX_REQUEST_IDS: usize = 128;
const REQUEST_DIGEST_BYTES: usize = 32;
// Serialized responses are the only variable-sized replay state. Together
// with MAX_REQUEST_IDS this bounds each connection to 1 MiB plus fixed-size
// map entries and SHA-256 request digests.
const MAX_REPLAY_RESPONSE_BYTES: usize = MAX_FRAME_BYTES;
const OUTPUT_CAPACITY: usize = 16;
const FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

struct EmptyQueryProvider {
    events: tokio::sync::broadcast::Sender<PassiveSnapshot>,
}

#[derive(Clone)]
#[allow(
    dead_code,
    reason = "U13 tests the dormant enrolled endpoint before production activation is wired"
)]
enum ControlEndpoint {
    Disabled,
    Unavailable(ControlAvailability),
    Active(Arc<ControlAuthorityHost>),
}

impl ControlEndpoint {
    fn active(&self) -> Option<&ControlAuthorityHost> {
        match self {
            Self::Active(host) => Some(host),
            Self::Disabled | Self::Unavailable(_) => None,
        }
    }
}

impl EmptyQueryProvider {
    fn new() -> Self {
        let (events, _) = tokio::sync::broadcast::channel(1);
        Self { events }
    }
}

impl PassiveQueryProvider for EmptyQueryProvider {
    fn snapshot(&self) -> PassiveSnapshot {
        PassiveSnapshot::default()
    }

    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<PassiveSnapshot> {
        self.events.subscribe()
    }
}

/// Daemon server whose production construction remains passive.
///
/// The optional canonical host is crate-private and cannot be constructed in
/// production until enrolled helper-backed execution is complete.
pub struct DaemonServer {
    socket_path: PathBuf,
    listener: UnixListener,
    provider: Arc<dyn PassiveQueryProvider>,
    diagnostics: Arc<dyn DiagnosticQueryProvider>,
    control: ControlEndpoint,
    daemon_uid: u32,
    socket_identity: SocketIdentity,
    shutdown: watch::Sender<bool>,
}

impl DaemonServer {
    /// Bind a private owner socket without replacing a live or foreign path.
    pub fn bind(socket_path: PathBuf) -> std::io::Result<Self> {
        prepare_socket_path(&socket_path)?;
        let listener = UnixListener::bind(&socket_path)?;
        set_socket_mode(&socket_path)?;
        let socket_identity = SocketIdentity::read(&socket_path)?;
        Ok(Self {
            socket_path,
            listener,
            provider: Arc::new(EmptyQueryProvider::new()),
            diagnostics: Arc::new(DiagnosticHub::start(None)?),
            control: ControlEndpoint::Disabled,
            daemon_uid: effective_uid(),
            socket_identity,
            shutdown: watch::channel(false).0,
        })
    }

    #[must_use]
    pub fn with_query_provider(mut self, provider: Arc<dyn PassiveQueryProvider>) -> Self {
        self.provider = provider;
        self
    }

    #[must_use]
    pub fn with_diagnostic_provider(
        mut self,
        diagnostics: Arc<dyn DiagnosticQueryProvider>,
    ) -> Self {
        self.diagnostics = diagnostics;
        self
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    #[must_use]
    pub const fn daemon_uid(&self) -> u32 {
        self.daemon_uid
    }

    /// Serve bounded concurrent clients until an authenticated shutdown.
    pub async fn run(self) -> std::io::Result<()> {
        eprintln!(
            "vortix daemon: passive candidate listening on {}",
            self.socket_path.display()
        );
        let capacity = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let mut shutdown = self.shutdown.subscribe();
        let mut clients = JoinSet::new();
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        loop {
            tokio::select! {
                _ = terminate.recv() => break,
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = self.listener.accept() => {
                    let (mut stream, _) = accepted?;
                    let Ok(permit) = Arc::clone(&capacity).try_acquire_owned() else {
                        let _ = write_response_direct(&mut stream, IpcResponse {
                            id: 0,
                            result: Err(IpcError::ServerBusy),
                        }).await;
                        continue;
                    };
                    let provider = Arc::clone(&self.provider);
                    let diagnostics = Arc::clone(&self.diagnostics);
                    let control = self.control.clone();
                    let shutdown = self.shutdown.clone();
                    let daemon_uid = self.daemon_uid;
                    clients.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = handle_client(stream, daemon_uid, provider, diagnostics, control, shutdown).await {
                            tracing::debug!(%error, "daemon client closed");
                        }
                    });
                }
                joined = clients.join_next(), if !clients.is_empty() => {
                    if let Some(Err(error)) = joined {
                        tracing::warn!(%error, "passive daemon client task failed");
                    }
                }
            }
        }
        let _ = self.shutdown.send(true);
        let drain = async { while clients.join_next().await.is_some() {} };
        let _ = tokio::time::timeout(FRAME_TIMEOUT + WRITE_TIMEOUT, drain).await;
        Ok(())
    }
}

impl Drop for DaemonServer {
    fn drop(&mut self) {
        if SocketIdentity::read(&self.socket_path).ok().as_ref() == Some(&self.socket_identity) {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }
}

struct Outbound {
    frame: Arc<[u8]>,
    written: oneshot::Sender<Result<(), String>>,
}

#[derive(PartialEq, Eq)]
struct RequestDigest(zeroize::Zeroizing<[u8; REQUEST_DIGEST_BYTES]>);

impl zeroize::ZeroizeOnDrop for RequestDigest {}

struct ReplayEntry {
    request_digest: RequestDigest,
    response_frame: Arc<[u8]>,
}

#[derive(Default)]
struct ReplayCache<const RESPONSE_BYTE_LIMIT: usize> {
    entries: BTreeMap<u64, ReplayEntry>,
    response_bytes: usize,
}

enum ReplayLookup {
    Miss,
    Replay(Arc<[u8]>),
    Conflict,
}

impl<const RESPONSE_BYTE_LIMIT: usize> ReplayCache<RESPONSE_BYTE_LIMIT> {
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn lookup(&self, request_id: u64, request_digest: &RequestDigest) -> ReplayLookup {
        let Some(entry) = self.entries.get(&request_id) else {
            return ReplayLookup::Miss;
        };
        if &entry.request_digest != request_digest {
            return ReplayLookup::Conflict;
        }
        ReplayLookup::Replay(Arc::clone(&entry.response_frame))
    }

    fn insert(
        &mut self,
        request_id: u64,
        request_digest: RequestDigest,
        response_frame: Arc<[u8]>,
    ) -> bool {
        debug_assert!(!self.entries.contains_key(&request_id));
        let response_bytes = response_frame.len().saturating_sub(size_of::<u32>());
        let Some(next_bytes) = self.response_bytes.checked_add(response_bytes) else {
            return false;
        };
        if next_bytes > RESPONSE_BYTE_LIMIT {
            return false;
        }
        self.entries.insert(
            request_id,
            ReplayEntry {
                request_digest,
                response_frame,
            },
        );
        self.response_bytes = next_bytes;
        true
    }

    #[cfg(test)]
    const fn retained_response_bytes(&self) -> usize {
        self.response_bytes
    }
}

fn request_digest(op: &IpcOp) -> Result<RequestDigest, FrameError> {
    let serialized = crate::vortix_core::ipc::frame::serialize_zeroizing(op)?;
    let mut digest = Sha256::digest(serialized.as_slice());
    let mut retained = zeroize::Zeroizing::new([0_u8; REQUEST_DIGEST_BYTES]);
    retained.copy_from_slice(digest.as_slice());
    digest.as_mut_slice().zeroize();
    Ok(RequestDigest(retained))
}

async fn respond_to_replay<const RESPONSE_BYTE_LIMIT: usize>(
    requests: &ReplayCache<RESPONSE_BYTE_LIMIT>,
    output: &mpsc::Sender<Outbound>,
    request_id: u64,
    digest: &RequestDigest,
) -> Result<bool, DaemonError> {
    match requests.lookup(request_id, digest) {
        ReplayLookup::Miss => return Ok(false),
        ReplayLookup::Replay(frame) => send_frame(output, frame).await?,
        ReplayLookup::Conflict => {
            send_response(
                output,
                IpcResponse {
                    id: request_id,
                    result: Err(IpcError::DuplicateRequestId),
                },
            )
            .await?;
        }
    }
    Ok(true)
}

async fn handle_client(
    stream: UnixStream,
    daemon_uid: u32,
    provider: Arc<dyn PassiveQueryProvider>,
    diagnostics: Arc<dyn DiagnosticQueryProvider>,
    control: ControlEndpoint,
    shutdown: watch::Sender<bool>,
) -> Result<(), DaemonError> {
    if get_peer_uid(&stream)? != daemon_uid {
        let mut stream = stream;
        let _ = write_response_direct(
            &mut stream,
            IpcResponse {
                id: 0,
                result: Err(IpcError::Unauthorized),
            },
        )
        .await;
        return Ok(());
    }

    let (mut reader, writer) = stream.into_split();
    let (output, output_rx) = mpsc::channel(OUTPUT_CAPACITY);
    let writer_task = tokio::spawn(writer_loop(writer, output_rx));
    let result = connection_loop(
        &mut reader,
        &output,
        provider,
        diagnostics,
        control,
        shutdown,
    )
    .await;
    drop(output);
    let _ = writer_task.await;
    result
}

#[allow(
    clippy::too_many_lines,
    reason = "one connection loop keeps handshake, replay, subscription, and shutdown ordering adjacent"
)]
async fn connection_loop<R: AsyncRead + Unpin>(
    reader: &mut R,
    output: &mpsc::Sender<Outbound>,
    provider: Arc<dyn PassiveQueryProvider>,
    diagnostics: Arc<dyn DiagnosticQueryProvider>,
    control: ControlEndpoint,
    shutdown: watch::Sender<bool>,
) -> Result<(), DaemonError> {
    let first = read_request(reader).await?;
    let hello = match &first.op {
        IpcOp::Handshake { hello } => hello,
        // Protocol v1 predates the handshake and performs one base-shape,
        // read-only Snapshot exchange. Keep only that N-1 compatibility seam.
        IpcOp::Snapshot => {
            let response = dispatch(
                first.id,
                first.op.clone(),
                provider.as_ref(),
                diagnostics.as_ref(),
                control.active(),
                &shutdown,
            )
            .await;
            send_response(output, response).await?;
            return Ok(());
        }
        _ => {
            send_response(
                output,
                IpcResponse {
                    id: first.id,
                    result: Err(IpcError::HandshakeRequired),
                },
            )
            .await?;
            return Ok(());
        }
    };
    let control_connection = hello
        .required_capabilities
        .contains(&IpcCapability::ControlMutation);
    let negotiated = if control_connection {
        match &control {
            ControlEndpoint::Active(authority) => match authority.unavailable_state() {
                None => negotiate_control(hello, authority.authority_binding()),
                Some(state) => Err(IpcError::ControlUnavailable { state }),
            },
            ControlEndpoint::Unavailable(state) => {
                Err(IpcError::ControlUnavailable { state: *state })
            }
            ControlEndpoint::Disabled => Err(IpcError::CapabilityUnavailable {
                capability: IpcCapability::ControlMutation,
            }),
        }
    } else {
        negotiate_passive(hello)
    };
    let negotiated_contract = negotiated.as_ref().ok().map(|server_hello| {
        (
            server_hello.schema,
            hello
                .required_capabilities
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
        )
    });
    send_response(
        output,
        IpcResponse {
            id: first.id,
            result: negotiated.map(|hello| IpcResult::Handshake { hello }),
        },
    )
    .await?;
    let Some((negotiated_schema, negotiated_capabilities)) = negotiated_contract else {
        return Ok(());
    };

    let mut requests = ReplayCache::<MAX_REPLAY_RESPONSE_BYTES>::default();
    let mut shutdown_receiver = shutdown.subscribe();
    loop {
        let request = tokio::select! {
            () = wait_for_shutdown(&mut shutdown_receiver) => return Ok(()),
            request = read_request(reader) => match request {
                Ok(request) => request,
                Err(DaemonError::Io(error))
                    if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error),
            },
        };
        if matches!(request.op, IpcOp::Handshake { .. }) {
            send_response(
                output,
                IpcResponse {
                    id: request.id,
                    result: Err(IpcError::MalformedRequest(
                        "handshake may appear only once".into(),
                    )),
                },
            )
            .await?;
            continue;
        }
        let digest = request_digest(&request.op)?;
        if respond_to_replay(&requests, output, request.id, &digest).await? {
            continue;
        }
        if control_connection != request.op.is_canonical_control() {
            let capability = if control_connection {
                request.op.required_capability()
            } else {
                IpcCapability::ControlMutation
            };
            send_response(
                output,
                IpcResponse {
                    id: request.id,
                    result: Err(IpcError::CapabilityUnavailable { capability }),
                },
            )
            .await?;
            continue;
        }
        let required = request.op.required_capability();
        if !required.is_available_in_schema(negotiated_schema)
            || !negotiated_capabilities.contains(&required)
        {
            send_response(
                output,
                IpcResponse {
                    id: request.id,
                    result: Err(IpcError::CapabilityUnavailable {
                        capability: required,
                    }),
                },
            )
            .await?;
            continue;
        }
        if requests.len() >= MAX_REQUEST_IDS {
            send_response(
                output,
                IpcResponse {
                    id: request.id,
                    result: Err(IpcError::MalformedRequest(
                        "request-id retention is full; reconnect".into(),
                    )),
                },
            )
            .await?;
            continue;
        }

        let IpcRequest { id: request_id, op } = request;
        let passive_subscribe = matches!(&op, IpcOp::Subscribe | IpcOp::PassiveSubscribe);
        let diagnostic_subscribe = matches!(&op, IpcOp::DiagnosticsSubscribe);
        let control_session = match &op {
            IpcOp::ControlSubscribe { session_id } => Some(session_id.clone()),
            _ => None,
        };
        let mut subscription = passive_subscribe.then(|| provider.subscribe());
        let mut diagnostic_subscription = diagnostic_subscribe.then(|| diagnostics.subscribe());
        let mut control_subscription = None;
        let response = if let Some(session_id) = &control_session {
            let result = control
                .active()
                .ok_or(IpcError::CapabilityUnavailable {
                    capability: IpcCapability::ControlMutation,
                })
                .and_then(|authority| authority.subscribe(session_id))
                .map(|(subscription, snapshot)| {
                    control_subscription = Some(subscription);
                    IpcResult::ControlSubscribed { snapshot }
                });
            IpcResponse {
                id: request_id,
                result,
            }
        } else {
            dispatch(
                request_id,
                op,
                provider.as_ref(),
                diagnostics.as_ref(),
                control.active(),
                &shutdown,
            )
            .await
        };
        let subscription_boundary = match &response.result {
            Ok(IpcResult::PassiveSubscribed { snapshot }) => snapshot.generation,
            Ok(IpcResult::DiagnosticSubscribed { snapshot }) => snapshot.generation,
            Ok(IpcResult::ControlSubscribed { snapshot }) => snapshot.generation,
            _ => 0,
        };
        // Subscription connections become read-only immediately, so no later
        // request can replay this acknowledgement and it need not be retained.
        let frame = match response_frame(&response) {
            Ok(frame) => frame,
            Err(error) => {
                if let (Some(authority), Some(session_id)) = (control.active(), &control_session) {
                    authority.close_session(session_id);
                }
                return Err(error.into());
            }
        };
        let retained = passive_subscribe
            || diagnostic_subscribe
            || control_subscription.is_some()
            || requests.insert(request_id, digest, Arc::clone(&frame));
        if let Err(error) = send_frame(output, frame).await {
            if let (Some(authority), Some(session_id)) = (control.active(), &control_session) {
                authority.close_session(session_id);
            }
            return Err(error);
        }
        if let Some(receiver) = subscription.as_mut() {
            stream_subscription(
                reader,
                output,
                receiver,
                subscription_boundary,
                &shutdown,
                || provider.snapshot().generation,
            )
            .await?;
            return Ok(());
        }
        if let Some(receiver) = diagnostic_subscription.as_mut() {
            stream_subscription(
                reader,
                output,
                receiver,
                subscription_boundary,
                &shutdown,
                || diagnostics.snapshot().generation,
            )
            .await?;
            return Ok(());
        }
        if let (Some(session_id), Some(receiver)) =
            (control_session.as_ref(), control_subscription.as_mut())
        {
            let result = stream_control_subscription(reader, output, receiver, &shutdown).await;
            if let Some(authority) = control.active() {
                authority.close_session(session_id);
            }
            result?;
            return Ok(());
        }
        // Never keep processing IDs whose response could not be retained:
        // closing after the one successful write preserves exact replay
        // semantics without letting cached response memory exceed its cap.
        if !retained {
            return Ok(());
        }
    }
}

async fn dispatch(
    request_id: u64,
    op: IpcOp,
    provider: &dyn PassiveQueryProvider,
    diagnostics: &dyn DiagnosticQueryProvider,
    control: Option<&ControlAuthorityHost>,
    shutdown: &watch::Sender<bool>,
) -> IpcResponse {
    let result = match op {
        IpcOp::Handshake { .. } => Err(IpcError::HandshakeRequired),
        IpcOp::Execute(_) => Err(IpcError::CapabilityUnavailable {
            capability: IpcCapability::ControlMutation,
        }),
        control_op @ (IpcOp::ControlOpen
        | IpcOp::ControlSubmit { .. }
        | IpcOp::ControlSnapshot { .. }
        | IpcOp::ControlRespondChallenge { .. }
        | IpcOp::ControlCancelChallenge { .. }
        | IpcOp::ControlStageProfileImport { .. }
        | IpcOp::ControlCancelProfileImport { .. }) => match control {
            Some(authority) => authority.dispatch(control_op).await,
            None => Err(IpcError::CapabilityUnavailable {
                capability: IpcCapability::ControlMutation,
            }),
        },
        IpcOp::ControlSubscribe { .. } => Err(IpcError::MalformedRequest(
            "control subscriptions require a dedicated connection".into(),
        )),
        IpcOp::Snapshot => Ok(IpcResult::Snapshot {
            state: legacy_connection(&provider.snapshot()),
        }),
        IpcOp::PassiveSnapshot => Ok(IpcResult::PassiveSnapshot {
            snapshot: provider.snapshot(),
        }),
        IpcOp::Subscribe | IpcOp::PassiveSubscribe => Ok(IpcResult::PassiveSubscribed {
            snapshot: provider.snapshot(),
        }),
        IpcOp::Diagnostics => Ok(IpcResult::DiagnosticSnapshot {
            snapshot: diagnostics.snapshot(),
        }),
        IpcOp::DiagnosticsSubscribe => Ok(IpcResult::DiagnosticSubscribed {
            snapshot: diagnostics.snapshot(),
        }),
        IpcOp::Shutdown => {
            let _ = shutdown.send(true);
            Ok(IpcResult::ShuttingDown)
        }
    };
    IpcResponse {
        id: request_id,
        result,
    }
}

trait SubscriptionSnapshot: Clone + Send + 'static {
    fn generation(&self) -> u64;
    fn into_event(self) -> IpcResult;
}

impl SubscriptionSnapshot for PassiveSnapshot {
    fn generation(&self) -> u64 {
        self.generation
    }

    fn into_event(self) -> IpcResult {
        IpcResult::PassiveEvent { snapshot: self }
    }
}

impl SubscriptionSnapshot for DiagnosticSnapshot {
    fn generation(&self) -> u64 {
        self.generation
    }

    fn into_event(self) -> IpcResult {
        IpcResult::DiagnosticEvent { snapshot: self }
    }
}

async fn stream_subscription<R, S>(
    reader: &mut R,
    output: &mpsc::Sender<Outbound>,
    receiver: &mut tokio::sync::broadcast::Receiver<S>,
    boundary: u64,
    shutdown: &watch::Sender<bool>,
    newest_generation: impl Fn() -> u64,
) -> Result<(), DaemonError>
where
    R: AsyncRead + Unpin,
    S: SubscriptionSnapshot,
{
    let mut probe = [0_u8; 1];
    let mut shutdown_receiver = shutdown.subscribe();
    loop {
        tokio::select! {
            () = wait_for_shutdown(&mut shutdown_receiver) => return Ok(()),
            read = reader.read(&mut probe) => {
                match read {
                    Ok(0) => return Ok(()),
                    Ok(_) => return Err(DaemonError::Protocol("subscription connections are read-only".into())),
                    Err(error) => return Err(DaemonError::Io(error)),
                }
            }
            event = receiver.recv() => match event {
                Ok(snapshot) if snapshot.generation() > boundary => {
                    send_response(output, IpcResponse {
                        id: 0,
                        result: Ok(snapshot.into_event()),
                    }).await?;
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    send_response(output, IpcResponse {
                        id: 0,
                        result: Ok(IpcResult::ResyncRequired {
                            newest_generation: newest_generation(),
                        }),
                    }).await?;
                    return Ok(());
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
            }
        }
    }
}

async fn stream_control_subscription<R: AsyncRead + Unpin>(
    reader: &mut R,
    output: &mpsc::Sender<Outbound>,
    subscription: &mut ControlSubscription,
    shutdown: &watch::Sender<bool>,
) -> Result<(), DaemonError> {
    let mut probe = [0_u8; 1];
    let mut shutdown_receiver = shutdown.subscribe();
    loop {
        tokio::select! {
            () = wait_for_shutdown(&mut shutdown_receiver) => return Ok(()),
            read = reader.read(&mut probe) => {
                match read {
                    Ok(0) => return Ok(()),
                    Ok(_) => return Err(DaemonError::Protocol(
                        "subscription connections are read-only".into(),
                    )),
                    Err(error) => return Err(DaemonError::Io(error)),
                }
            }
            changed = subscription.changed() => {
                let snapshot = changed.map_err(|error| {
                    DaemonError::Protocol(format!("control subscription stopped: {error}"))
                })?;
                send_response(output, IpcResponse {
                    id: 0,
                    result: Ok(IpcResult::ControlEvent {
                        event: None,
                        snapshot,
                    }),
                }).await?;
            }
        }
    }
}

async fn wait_for_shutdown(receiver: &mut watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    while receiver.changed().await.is_ok() {
        if *receiver.borrow() {
            return;
        }
    }
}

async fn writer_loop<W: AsyncWrite + Unpin>(mut writer: W, mut output: mpsc::Receiver<Outbound>) {
    while let Some(outbound) = output.recv().await {
        let result = write_frame_direct(&mut writer, &outbound.frame)
            .await
            .map_err(|error| error.to_string());
        let failed = result.is_err();
        let _ = outbound.written.send(result);
        if failed {
            return;
        }
    }
    let _ = writer.shutdown().await;
}

async fn send_response(
    output: &mpsc::Sender<Outbound>,
    response: IpcResponse,
) -> Result<(), DaemonError> {
    send_frame(output, response_frame(&response)?).await
}

async fn send_frame(output: &mpsc::Sender<Outbound>, frame: Arc<[u8]>) -> Result<(), DaemonError> {
    let (written, completion) = oneshot::channel();
    output
        .send(Outbound { frame, written })
        .await
        .map_err(|_| DaemonError::Protocol("connection writer stopped".into()))?;
    tokio::time::timeout(WRITE_TIMEOUT, completion)
        .await
        .map_err(|_| DaemonError::Timeout("response write"))?
        .map_err(|_| DaemonError::Protocol("connection writer stopped".into()))?
        .map_err(DaemonError::Protocol)
}

async fn write_response_direct<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: IpcResponse,
) -> Result<(), DaemonError> {
    write_frame_direct(writer, &response_frame(&response)?).await
}

fn response_frame(response: &IpcResponse) -> Result<Arc<[u8]>, FrameError> {
    crate::vortix_core::ipc::encode_frame(response).map(Arc::from)
}

async fn write_frame_direct<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &[u8],
) -> Result<(), DaemonError> {
    tokio::time::timeout(WRITE_TIMEOUT, writer.write_all(frame))
        .await
        .map_err(|_| DaemonError::Timeout("response write"))??;
    Ok(())
}

async fn read_request<R: AsyncRead + Unpin>(reader: &mut R) -> Result<IpcRequest, DaemonError> {
    read_request_with_timeout(reader, FRAME_TIMEOUT).await
}

async fn read_request_with_timeout<R: AsyncRead + Unpin>(
    reader: &mut R,
    timeout: Duration,
) -> Result<IpcRequest, DaemonError> {
    let mut header = [0_u8; 4];
    tokio::time::timeout(timeout, reader.read_exact(&mut header))
        .await
        .map_err(|_| DaemonError::Timeout("frame header"))??;
    let body_len = u32::from_be_bytes(header) as usize;
    if body_len > MAX_FRAME_BYTES {
        return Err(DaemonError::Frame(FrameError::TooLarge {
            got: body_len,
            max: MAX_FRAME_BYTES,
        }));
    }
    let mut body = zeroize::Zeroizing::new(vec![0_u8; body_len]);
    tokio::time::timeout(timeout, reader.read_exact(&mut body))
        .await
        .map_err(|_| DaemonError::Timeout("frame body"))??;
    serde_json::from_slice(body.as_slice())
        .map_err(FrameError::Serialize)
        .map_err(DaemonError::Frame)
}

fn prepare_socket_path(path: &Path) -> std::io::Result<()> {
    if std::fs::symlink_metadata(path.parent().unwrap_or_else(|| Path::new(".")))
        .is_ok_and(|metadata| !metadata.is_dir())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "daemon socket parent must be a real directory",
        ));
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
        if !metadata.file_type().is_socket()
            || metadata.uid() != effective_uid()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "refusing to replace unsafe or foreign daemon socket path",
            ));
        }
        let identity = (metadata.dev(), metadata.ino());
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    "daemon socket is already accepting connections",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {}
            Err(error) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("daemon socket liveness is ambiguous: {error}"),
                ));
            }
        }
        let current = std::fs::symlink_metadata(path)?;
        if !current.file_type().is_socket() || (current.dev(), current.ino()) != identity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "daemon socket changed during stale-path validation",
            ));
        }
    }
    std::fs::remove_file(path)
}

fn set_socket_mode(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

impl SocketIdentity {
    fn read(path: &Path) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let metadata = std::fs::symlink_metadata(path)?;
            return Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            });
        }
        #[allow(unreachable_code)]
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Unix socket identity is unavailable",
        ))
    }
}

fn effective_uid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: geteuid returns a scalar and has no failure mode.
        #[allow(unsafe_code)]
        unsafe {
            libc::geteuid()
        }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn get_peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    use std::os::fd::AsRawFd as _;
    let fd = stream.as_raw_fd();
    // xtask:allow-platform-cfg: local IPC peer-credential socket ABI is transport-specific
    #[cfg(target_os = "linux")]
    {
        let mut credential: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
            .expect("ucred size fits socklen_t");
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                std::ptr::addr_of_mut!(credential).cast(),
                std::ptr::from_mut(&mut length),
            )
        };
        if result == 0 {
            Ok(credential.uid)
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    // xtask:allow-platform-cfg: local IPC peer-credential socket ABI is transport-specific
    #[cfg(target_os = "macos")]
    {
        let mut uid = 0;
        let mut gid = 0;
        let result = unsafe {
            libc::getpeereid(
                fd,
                std::ptr::from_mut(&mut uid),
                std::ptr::from_mut(&mut gid),
            )
        };
        if result == 0 {
            Ok(uid)
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum DaemonError {
    #[error("IPC I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("IPC frame: {0}")]
    Frame(#[from] FrameError),
    #[error("IPC {0} timed out")]
    Timeout(&'static str),
    #[error("IPC protocol: {0}")]
    Protocol(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::ipc::{ClientHello, IpcCapability, RemoteSessionId};

    struct FixedProvider {
        snapshot: PassiveSnapshot,
        events: tokio::sync::broadcast::Sender<PassiveSnapshot>,
    }

    impl PassiveQueryProvider for FixedProvider {
        fn snapshot(&self) -> PassiveSnapshot {
            self.snapshot.clone()
        }

        fn subscribe(&self) -> tokio::sync::broadcast::Receiver<PassiveSnapshot> {
            self.events.subscribe()
        }
    }

    struct FixedDiagnostics {
        snapshot: std::sync::Mutex<DiagnosticSnapshot>,
        events: tokio::sync::broadcast::Sender<DiagnosticSnapshot>,
    }

    impl DiagnosticQueryProvider for FixedDiagnostics {
        fn snapshot(&self) -> DiagnosticSnapshot {
            self.snapshot.lock().unwrap().clone()
        }

        fn subscribe(&self) -> tokio::sync::broadcast::Receiver<DiagnosticSnapshot> {
            self.events.subscribe()
        }
    }

    fn handshake(id: u64) -> IpcRequest {
        IpcRequest {
            id,
            op: IpcOp::Handshake {
                hello: ClientHello::current(vec![IpcCapability::PassiveSnapshot]),
            },
        }
    }

    fn test_binding() -> crate::vortix_core::privileged::AuthorityBinding {
        crate::vortix_core::privileged::AuthorityBinding::new(
            crate::vortix_core::control::AuthorityEpoch(7),
            crate::vortix_core::privileged::BootScope::new([1; 16]),
            crate::vortix_core::privileged::LeaseId::new([2; 32]),
            crate::vortix_core::privileged::OperationDigest::of_bytes(b"daemon"),
        )
        .unwrap()
    }

    fn test_control_host() -> Arc<ControlAuthorityHost> {
        Arc::new(ControlAuthorityHost::new_for_test(
            crate::vortix_core::control::ControlService::start(
                crate::vortix_core::control::ControlServiceConfig {
                    authority_epoch: test_binding().authority_epoch(),
                    ..crate::vortix_core::control::ControlServiceConfig::default()
                },
            ),
            test_binding(),
        ))
    }

    fn spawn_test_connection(
        server: tokio::io::DuplexStream,
        control: ControlEndpoint,
    ) -> tokio::task::JoinHandle<Result<(), DaemonError>> {
        tokio::spawn(async move {
            let (mut reader, writer_half) = tokio::io::split(server);
            let (output, output_rx) = mpsc::channel(4);
            let writer = tokio::spawn(writer_loop(writer_half, output_rx));
            let result = connection_loop(
                &mut reader,
                &output,
                Arc::new(EmptyQueryProvider::new()),
                Arc::new(DiagnosticHub::start(None).unwrap()),
                control,
                watch::channel(false).0,
            )
            .await;
            drop(output);
            let _ = writer.await;
            result
        })
    }

    async fn duplex_exchange(
        client: &mut tokio::io::DuplexStream,
        request: &IpcRequest,
    ) -> IpcResponse {
        client
            .write_all(&crate::vortix_core::ipc::encode_frame(request).unwrap())
            .await
            .unwrap();
        duplex_read_response(client).await
    }

    async fn duplex_read_response(client: &mut tokio::io::DuplexStream) -> IpcResponse {
        let mut header = [0_u8; 4];
        client.read_exact(&mut header).await.unwrap();
        let body_len = u32::from_be_bytes(header) as usize;
        let mut body = vec![0_u8; body_len];
        client.read_exact(&mut body).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    async fn read_test_response(client: &mut tokio::io::DuplexStream) -> IpcResponse {
        duplex_read_response(client).await
    }

    fn test_connection() -> (
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<Result<(), DaemonError>>,
    ) {
        let (client, server) = tokio::io::duplex(4096);
        let task = spawn_test_connection(server, ControlEndpoint::Disabled);
        (client, task)
    }

    async fn exchange_test(
        client: &mut tokio::io::DuplexStream,
        request: &IpcRequest,
    ) -> IpcResponse {
        client
            .write_all(&crate::vortix_core::ipc::encode_frame(request).unwrap())
            .await
            .unwrap();
        read_test_response(client).await
    }

    #[tokio::test]
    async fn pre_handshake_v1_snapshot_keeps_the_base_wire_shape() {
        let (mut client, task) = test_connection();
        let request = IpcRequest {
            id: 1,
            op: IpcOp::Snapshot,
        };
        let response = exchange_test(&mut client, &request).await;
        assert!(matches!(response.result, Ok(IpcResult::Snapshot { .. })));
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn negotiated_capabilities_reject_undeclared_diagnostics() {
        let (mut client, task) = test_connection();
        let handshake = IpcRequest {
            id: 1,
            op: IpcOp::Handshake {
                hello: ClientHello::current(vec![IpcCapability::LegacySnapshot]),
            },
        };
        assert!(matches!(
            exchange_test(&mut client, &handshake).await.result,
            Ok(IpcResult::Handshake { .. })
        ));

        let undeclared = IpcRequest {
            id: 2,
            op: IpcOp::Diagnostics,
        };
        assert!(matches!(
            exchange_test(&mut client, &undeclared).await.result,
            Err(IpcError::CapabilityUnavailable {
                capability: IpcCapability::Diagnostics
            })
        ));
        task.abort();
    }

    #[tokio::test]
    async fn schema_one_connection_rejects_diagnostics() {
        let (mut client, task) = test_connection();
        let mut hello = ClientHello::current(vec![IpcCapability::LegacySnapshot]);
        hello.schema = crate::vortix_core::ipc::CompatibilityRange { min: 1, max: 1 };
        let handshake = IpcRequest {
            id: 1,
            op: IpcOp::Handshake { hello },
        };
        assert!(matches!(
            exchange_test(&mut client, &handshake).await.result,
            Ok(IpcResult::Handshake { .. })
        ));
        let diagnostics = IpcRequest {
            id: 2,
            op: IpcOp::Diagnostics,
        };
        assert!(matches!(
            exchange_test(&mut client, &diagnostics).await.result,
            Err(IpcError::CapabilityUnavailable {
                capability: IpcCapability::Diagnostics
            })
        ));
        task.abort();
    }

    #[tokio::test]
    async fn first_non_handshake_request_is_rejected() {
        let (mut client, task) = test_connection();
        let request = IpcRequest {
            id: 1,
            op: IpcOp::PassiveSnapshot,
        };
        let response = exchange_test(&mut client, &request).await;
        assert!(matches!(response.result, Err(IpcError::HandshakeRequired)));
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn control_handshake_requires_explicit_host_and_exact_binding() {
        let (mut absent_client, absent_server) = tokio::io::duplex(16 * 1024);
        let absent_task = spawn_test_connection(absent_server, ControlEndpoint::Disabled);
        let control_handshake = IpcRequest {
            id: 1,
            op: IpcOp::Handshake {
                hello: ClientHello::current(vec![IpcCapability::ControlMutation]),
            },
        };
        assert!(matches!(
            duplex_exchange(&mut absent_client, &control_handshake)
                .await
                .result,
            Err(IpcError::CapabilityUnavailable {
                capability: IpcCapability::ControlMutation
            })
        ));
        drop(absent_client);
        absent_task.await.unwrap().unwrap();

        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let task = spawn_test_connection(server, ControlEndpoint::Active(test_control_host()));
        let response = duplex_exchange(&mut client, &control_handshake).await;
        assert!(matches!(
            response.result,
            Ok(IpcResult::Handshake { hello })
                if !hello.passive && hello.authority_binding == Some(test_binding())
        ));
        assert!(matches!(
            duplex_exchange(
                &mut client,
                &IpcRequest {
                    id: 2,
                    op: IpcOp::PassiveSnapshot,
                },
            )
            .await
            .result,
            Err(IpcError::CapabilityUnavailable {
                capability: IpcCapability::PassiveSnapshot
            })
        ));
        drop(client);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn failed_control_subscribe_retains_request_id_semantics() {
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let task = spawn_test_connection(server, ControlEndpoint::Active(test_control_host()));
        let control_handshake = IpcRequest {
            id: 1,
            op: IpcOp::Handshake {
                hello: ClientHello::current(vec![IpcCapability::ControlMutation]),
            },
        };
        assert!(duplex_exchange(&mut client, &control_handshake)
            .await
            .result
            .is_ok());
        let missing = RemoteSessionId::parse("session-00000000000000000000000000000000").unwrap();
        assert!(matches!(
            duplex_exchange(
                &mut client,
                &IpcRequest {
                    id: 2,
                    op: IpcOp::ControlSubscribe {
                        session_id: missing,
                    },
                },
            )
            .await
            .result,
            Err(IpcError::ControlSessionNotFound)
        ));
        assert!(matches!(
            duplex_exchange(
                &mut client,
                &IpcRequest {
                    id: 2,
                    op: IpcOp::ControlOpen,
                },
            )
            .await
            .result,
            Err(IpcError::DuplicateRequestId)
        ));
        drop(client);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn control_subscription_streams_and_closes_its_hosted_session() {
        let host = test_control_host();
        let handshake = IpcRequest {
            id: 1,
            op: IpcOp::Handshake {
                hello: ClientHello::current(vec![IpcCapability::ControlMutation]),
            },
        };

        let (mut commands, command_server) = tokio::io::duplex(32 * 1024);
        let command_task =
            spawn_test_connection(command_server, ControlEndpoint::Active(Arc::clone(&host)));
        assert!(duplex_exchange(&mut commands, &handshake)
            .await
            .result
            .is_ok());
        let opened = duplex_exchange(
            &mut commands,
            &IpcRequest {
                id: 2,
                op: IpcOp::ControlOpen,
            },
        )
        .await;
        let Ok(IpcResult::ControlOpened { session_id, .. }) = opened.result else {
            panic!("control session must open");
        };

        let (mut events, event_server) = tokio::io::duplex(32 * 1024);
        let event_task = spawn_test_connection(event_server, ControlEndpoint::Active(host));
        assert!(duplex_exchange(&mut events, &handshake)
            .await
            .result
            .is_ok());
        assert!(matches!(
            duplex_exchange(
                &mut events,
                &IpcRequest {
                    id: 2,
                    op: IpcOp::ControlSubscribe {
                        session_id: session_id.clone(),
                    },
                },
            )
            .await
            .result,
            Ok(IpcResult::ControlSubscribed { .. })
        ));

        assert!(matches!(
            duplex_exchange(
                &mut commands,
                &IpcRequest {
                    id: 3,
                    op: IpcOp::ControlSubmit {
                        session_id: session_id.clone(),
                        command: crate::vortix_core::control::UserCommand::Disconnect {
                            profile_id: None,
                        },
                        idempotency_key: crate::vortix_core::control::IdempotencyKey::new(
                            "wire-subscription",
                        ),
                        timeout_millis: 1_000,
                    },
                },
            )
            .await
            .result,
            Ok(IpcResult::ControlAccepted { .. })
        ));
        assert!(matches!(
            duplex_read_response(&mut events).await.result,
            Ok(IpcResult::ControlEvent { .. })
        ));

        events.write_all(b"x").await.unwrap();
        assert!(matches!(
            event_task.await.unwrap(),
            Err(DaemonError::Protocol(_))
        ));
        assert!(matches!(
            duplex_exchange(
                &mut commands,
                &IpcRequest {
                    id: 4,
                    op: IpcOp::ControlSnapshot { session_id },
                },
            )
            .await
            .result,
            Err(IpcError::ControlSessionNotFound)
        ));
        drop(commands);
        command_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn control_handshake_reports_live_nonactive_state() {
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let task = spawn_test_connection(
            server,
            ControlEndpoint::Unavailable(ControlAvailability::Degraded),
        );
        let response = duplex_exchange(
            &mut client,
            &IpcRequest {
                id: 1,
                op: IpcOp::Handshake {
                    hello: ClientHello::current(vec![IpcCapability::ControlMutation]),
                },
            },
        )
        .await;
        assert!(matches!(
            response.result,
            Err(IpcError::ControlUnavailable {
                state: ControlAvailability::Degraded
            })
        ));
        drop(client);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn passive_handshake_cannot_cross_into_present_control_host() {
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let task = spawn_test_connection(server, ControlEndpoint::Active(test_control_host()));
        assert!(matches!(
            duplex_exchange(&mut client, &handshake(1)).await.result,
            Ok(IpcResult::Handshake { hello }) if hello.passive
        ));
        assert!(matches!(
            duplex_exchange(
                &mut client,
                &IpcRequest {
                    id: 2,
                    op: IpcOp::ControlOpen,
                },
            )
            .await
            .result,
            Err(IpcError::CapabilityUnavailable {
                capability: IpcCapability::ControlMutation
            })
        ));
        drop(client);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn passive_dispatch_rejects_execute() {
        let provider = EmptyQueryProvider::new();
        let diagnostics = DiagnosticHub::start(None).unwrap();
        let shutdown = watch::channel(false).0;
        let op = IpcOp::Execute(crate::vortix_core::engine::input::UserCommand::Disconnect {
            profile_id: None,
        });
        assert!(matches!(
            dispatch(9, op, &provider, &diagnostics, None, &shutdown)
                .await
                .result,
            Err(IpcError::CapabilityUnavailable {
                capability: IpcCapability::ControlMutation
            })
        ));
    }

    #[test]
    fn handshake_fixture_is_well_formed() {
        assert!(matches!(handshake(1).op, IpcOp::Handshake { .. }));
    }

    #[tokio::test]
    async fn lagged_diagnostic_stream_requires_resynchronization() {
        let (events, _) = tokio::sync::broadcast::channel(1);
        let initial = DiagnosticHub::start(None).unwrap().snapshot();
        let provider = Arc::new(FixedDiagnostics {
            snapshot: std::sync::Mutex::new(initial.clone()),
            events,
        });
        let mut receiver = provider.subscribe();
        for generation in 2..=4 {
            let mut snapshot = initial.clone();
            snapshot.generation = generation;
            *provider.snapshot.lock().unwrap() = snapshot.clone();
            let _ = provider.events.send(snapshot);
        }

        let (mut client, server) = tokio::io::duplex(4096);
        let (mut server_reader, server_writer) = tokio::io::split(server);
        let (output, output_rx) = mpsc::channel(2);
        let writer = tokio::spawn(writer_loop(server_writer, output_rx));
        let shutdown = watch::channel(false).0;
        stream_subscription(
            &mut server_reader,
            &output,
            &mut receiver,
            1,
            &shutdown,
            || provider.snapshot().generation,
        )
        .await
        .unwrap();
        drop(output);
        writer.await.unwrap();
        let mut bytes = vec![0_u8; 4096];
        let read = client.read(&mut bytes).await.unwrap();
        let (response, _) = crate::vortix_core::ipc::decode_frame::<IpcResponse>(&bytes[..read])
            .unwrap()
            .unwrap();
        assert!(matches!(
            response.result,
            Ok(IpcResult::ResyncRequired {
                newest_generation: 4
            })
        ));
    }

    #[test]
    fn replay_cache_uses_fixed_digests_and_bounds_response_bytes() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<RequestDigest>();

        let mut cache = ReplayCache::<256>::default();
        let digest = request_digest(&IpcOp::PassiveSnapshot).unwrap();
        assert_eq!(std::mem::size_of_val(&digest), REQUEST_DIGEST_BYTES);

        let retained = IpcResponse {
            id: 7,
            result: Err(IpcError::Internal("small".into())),
        };
        assert!(cache.insert(7, digest, response_frame(&retained).unwrap()));
        let retained_bytes = cache.retained_response_bytes();
        assert!(retained_bytes > 0);
        assert!(retained_bytes <= 256);

        let oversized = IpcResponse {
            id: 8,
            result: Err(IpcError::Internal("x".repeat(256))),
        };
        let oversized_digest = request_digest(&IpcOp::Shutdown).unwrap();
        assert!(!cache.insert(8, oversized_digest, response_frame(&oversized).unwrap()));
        assert_eq!(cache.retained_response_bytes(), retained_bytes);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn replay_cache_preserves_same_id_semantics() {
        let mut cache = ReplayCache::<1024>::default();
        let snapshot_digest = request_digest(&IpcOp::PassiveSnapshot).unwrap();
        let response = IpcResponse {
            id: 41,
            result: Err(IpcError::Internal("stable replay".into())),
        };
        let response_frame = response_frame(&response).unwrap();
        assert!(cache.insert(41, snapshot_digest, Arc::clone(&response_frame)));

        let matching_digest = request_digest(&IpcOp::PassiveSnapshot).unwrap();
        let ReplayLookup::Replay(replayed) = cache.lookup(41, &matching_digest) else {
            panic!("same id and operation must replay the retained response");
        };
        assert_eq!(replayed.as_ref(), response_frame.as_ref());

        let shutdown_digest = request_digest(&IpcOp::Shutdown).unwrap();
        assert!(matches!(
            cache.lookup(41, &shutdown_digest),
            ReplayLookup::Conflict
        ));
        assert!(matches!(
            cache.lookup(42, &shutdown_digest),
            ReplayLookup::Miss
        ));
    }

    #[test]
    fn bind_refuses_regular_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("daemon.sock");
        std::fs::write(&path, b"not a socket").unwrap();
        assert!(DaemonServer::bind(path).is_err());
    }

    #[tokio::test]
    async fn bind_refuses_live_socket_and_drop_preserves_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("daemon.sock");
        let server = DaemonServer::bind(path.clone()).unwrap();
        assert_eq!(
            DaemonServer::bind(path.clone()).err().unwrap().kind(),
            std::io::ErrorKind::AddrInUse
        );
        let moved = directory.path().join("moved.sock");
        std::fs::rename(&path, moved).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        drop(server);
        assert_eq!(std::fs::read(path).unwrap(), b"replacement");
    }

    #[tokio::test]
    async fn partial_header_and_body_are_deadline_bounded() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&[0, 0]).await.unwrap();
        assert!(matches!(
            read_request_with_timeout(&mut server, Duration::from_millis(10)).await,
            Err(DaemonError::Timeout("frame header"))
        ));

        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&10_u32.to_be_bytes()).await.unwrap();
        client.write_all(b"{}").await.unwrap();
        assert!(matches!(
            read_request_with_timeout(&mut server, Duration::from_millis(10)).await,
            Err(DaemonError::Timeout("frame body"))
        ));
    }

    #[tokio::test]
    async fn oversized_prefix_is_rejected_before_allocation() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let oversized = u32::try_from(MAX_FRAME_BYTES + 1).unwrap();
        client.write_all(&oversized.to_be_bytes()).await.unwrap();
        assert!(matches!(
            read_request(&mut server).await,
            Err(DaemonError::Frame(FrameError::TooLarge { .. }))
        ));
    }

    #[tokio::test]
    async fn lagged_subscription_requests_full_resynchronization() {
        let (events, _) = tokio::sync::broadcast::channel(1);
        let provider = FixedProvider {
            snapshot: PassiveSnapshot {
                generation: 3,
                ..PassiveSnapshot::default()
            },
            events,
        };
        let mut receiver = provider.subscribe();
        for generation in 2..=3 {
            provider
                .events
                .send(PassiveSnapshot {
                    generation,
                    ..PassiveSnapshot::default()
                })
                .unwrap();
        }

        let (_idle_client, mut idle_reader) = tokio::io::duplex(64);
        let (output_client, output_server) = tokio::io::duplex(4096);
        let (output, output_rx) = mpsc::channel(2);
        let writer = tokio::spawn(writer_loop(output_server, output_rx));
        let shutdown = watch::channel(false).0;
        stream_subscription(
            &mut idle_reader,
            &output,
            &mut receiver,
            1,
            &shutdown,
            || provider.snapshot().generation,
        )
        .await
        .unwrap();
        drop(output);
        writer.await.unwrap();

        let mut response_bytes = Vec::new();
        let mut output_client = output_client;
        output_client
            .read_to_end(&mut response_bytes)
            .await
            .unwrap();
        let (response, _) = crate::vortix_core::ipc::decode_frame::<IpcResponse>(&response_bytes)
            .unwrap()
            .unwrap();
        assert!(matches!(
            response.result,
            Ok(IpcResult::ResyncRequired {
                newest_generation: 3
            })
        ));
    }
}
