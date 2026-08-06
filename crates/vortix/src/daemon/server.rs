//! Bounded, authenticated IPC for the passive daemon candidate.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, watch, Semaphore};
use tokio::task::JoinSet;

use super::passive::{legacy_connection, PassiveQueryProvider};
use crate::vortix_core::ipc::{
    negotiate_passive, FrameError, IpcCapability, IpcError, IpcOp, IpcRequest, IpcResponse,
    IpcResult, PassiveSnapshot, MAX_FRAME_BYTES,
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

/// Passive daemon server. It has no field capable of executing a command,
/// loading desired intent, or applying network policy.
pub struct DaemonServer {
    socket_path: PathBuf,
    listener: UnixListener,
    provider: Arc<dyn PassiveQueryProvider>,
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
                    let shutdown = self.shutdown.clone();
                    let daemon_uid = self.daemon_uid;
                    clients.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = handle_client(stream, daemon_uid, provider, shutdown).await {
                            tracing::debug!(%error, "passive daemon client closed");
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
    response: IpcResponse,
    written: oneshot::Sender<Result<(), String>>,
}

type RequestDigest = [u8; REQUEST_DIGEST_BYTES];

struct ReplayEntry {
    request_digest: RequestDigest,
    response_json: Box<[u8]>,
}

struct ReplayCache<const RESPONSE_BYTE_LIMIT: usize> {
    entries: BTreeMap<u64, ReplayEntry>,
    response_bytes: usize,
}

impl<const RESPONSE_BYTE_LIMIT: usize> Default for ReplayCache<RESPONSE_BYTE_LIMIT> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            response_bytes: 0,
        }
    }
}

enum ReplayLookup {
    Miss,
    Replay(IpcResponse),
    Conflict,
}

impl<const RESPONSE_BYTE_LIMIT: usize> ReplayCache<RESPONSE_BYTE_LIMIT> {
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn lookup(
        &self,
        request_id: u64,
        request_digest: &RequestDigest,
    ) -> Result<ReplayLookup, FrameError> {
        let Some(entry) = self.entries.get(&request_id) else {
            return Ok(ReplayLookup::Miss);
        };
        if &entry.request_digest != request_digest {
            return Ok(ReplayLookup::Conflict);
        }
        let response = serde_json::from_slice(&entry.response_json)?;
        Ok(ReplayLookup::Replay(response))
    }

    fn insert(
        &mut self,
        request_id: u64,
        request_digest: RequestDigest,
        response: &IpcResponse,
    ) -> Result<bool, FrameError> {
        debug_assert!(!self.entries.contains_key(&request_id));
        let response_json = serde_json::to_vec(response)?;
        let Some(next_bytes) = self.response_bytes.checked_add(response_json.len()) else {
            return Ok(false);
        };
        if next_bytes > RESPONSE_BYTE_LIMIT {
            return Ok(false);
        }
        self.entries.insert(
            request_id,
            ReplayEntry {
                request_digest,
                response_json: response_json.into_boxed_slice(),
            },
        );
        self.response_bytes = next_bytes;
        Ok(true)
    }

    #[cfg(test)]
    const fn retained_response_bytes(&self) -> usize {
        self.response_bytes
    }
}

fn request_digest(op: &IpcOp) -> Result<RequestDigest, FrameError> {
    let serialized = serde_json::to_vec(op)?;
    Ok(Sha256::digest(serialized).into())
}

async fn respond_to_replay<const RESPONSE_BYTE_LIMIT: usize>(
    requests: &ReplayCache<RESPONSE_BYTE_LIMIT>,
    output: &mpsc::Sender<Outbound>,
    request_id: u64,
    digest: &RequestDigest,
) -> Result<bool, DaemonError> {
    let response = match requests.lookup(request_id, digest)? {
        ReplayLookup::Miss => return Ok(false),
        ReplayLookup::Replay(response) => response,
        ReplayLookup::Conflict => IpcResponse {
            id: request_id,
            result: Err(IpcError::DuplicateRequestId),
        },
    };
    send_response(output, response).await?;
    Ok(true)
}

async fn handle_client(
    stream: UnixStream,
    daemon_uid: u32,
    provider: Arc<dyn PassiveQueryProvider>,
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
    let result = connection_loop(&mut reader, &output, provider, shutdown).await;
    drop(output);
    let _ = writer_task.await;
    result
}

async fn connection_loop<R: AsyncRead + Unpin>(
    reader: &mut R,
    output: &mpsc::Sender<Outbound>,
    provider: Arc<dyn PassiveQueryProvider>,
    shutdown: watch::Sender<bool>,
) -> Result<(), DaemonError> {
    let first = read_request(reader).await?;
    let IpcOp::Handshake { hello } = &first.op else {
        send_response(
            output,
            IpcResponse {
                id: first.id,
                result: Err(IpcError::HandshakeRequired),
            },
        )
        .await?;
        return Ok(());
    };
    let negotiated = negotiate_passive(hello);
    let handshake_ok = negotiated.is_ok();
    send_response(
        output,
        IpcResponse {
            id: first.id,
            result: negotiated.map(|hello| IpcResult::Handshake { hello }),
        },
    )
    .await?;
    if !handshake_ok {
        return Ok(());
    }

    let mut requests = ReplayCache::<MAX_REPLAY_RESPONSE_BYTES>::default();
    let mut shutdown_receiver = shutdown.subscribe();
    loop {
        let request = tokio::select! {
            () = wait_for_shutdown(&mut shutdown_receiver) => return Ok(()),
            request = read_request(reader) => request?,
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

        let subscribe = matches!(request.op, IpcOp::Subscribe | IpcOp::PassiveSubscribe);
        let mut subscription = subscribe.then(|| provider.subscribe());
        let response = dispatch(&request, provider.as_ref(), &shutdown);
        let subscription_boundary = match &response.result {
            Ok(IpcResult::PassiveSubscribed { snapshot }) => snapshot.generation,
            _ => 0,
        };
        // Subscription connections become read-only immediately, so no later
        // request can replay this acknowledgement and it need not be retained.
        let retained = subscribe || requests.insert(request.id, digest, &response)?;
        send_response(output, response).await?;
        if let Some(receiver) = subscription.as_mut() {
            stream_snapshots(
                reader,
                output,
                provider.as_ref(),
                receiver,
                subscription_boundary,
                &shutdown,
            )
            .await?;
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

fn dispatch(
    request: &IpcRequest,
    provider: &dyn PassiveQueryProvider,
    shutdown: &watch::Sender<bool>,
) -> IpcResponse {
    let result = match &request.op {
        IpcOp::Handshake { .. } => Err(IpcError::HandshakeRequired),
        IpcOp::Execute(_) => Err(IpcError::CapabilityUnavailable {
            capability: IpcCapability::ControlMutation,
        }),
        IpcOp::Snapshot => Ok(IpcResult::Snapshot {
            state: legacy_connection(&provider.snapshot()),
        }),
        IpcOp::PassiveSnapshot => Ok(IpcResult::PassiveSnapshot {
            snapshot: provider.snapshot(),
        }),
        IpcOp::Subscribe | IpcOp::PassiveSubscribe => Ok(IpcResult::PassiveSubscribed {
            snapshot: provider.snapshot(),
        }),
        IpcOp::Shutdown => {
            let _ = shutdown.send(true);
            Ok(IpcResult::ShuttingDown)
        }
    };
    IpcResponse {
        id: request.id,
        result,
    }
}

async fn stream_snapshots<R: AsyncRead + Unpin>(
    reader: &mut R,
    output: &mpsc::Sender<Outbound>,
    provider: &dyn PassiveQueryProvider,
    receiver: &mut tokio::sync::broadcast::Receiver<PassiveSnapshot>,
    boundary: u64,
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
                    Ok(_) => return Err(DaemonError::Protocol("subscription connections are read-only".into())),
                    Err(error) => return Err(DaemonError::Io(error)),
                }
            }
            event = receiver.recv() => match event {
                Ok(snapshot) if snapshot.generation > boundary => {
                    send_response(output, IpcResponse {
                        id: 0,
                        result: Ok(IpcResult::PassiveEvent { snapshot }),
                    }).await?;
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    send_response(output, IpcResponse {
                        id: 0,
                        result: Ok(IpcResult::ResyncRequired {
                            newest_generation: provider.snapshot().generation,
                        }),
                    }).await?;
                    return Ok(());
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
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
        let result = write_response_direct(&mut writer, outbound.response)
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
    let (written, completion) = oneshot::channel();
    output
        .send(Outbound { response, written })
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
    let frame = crate::vortix_core::ipc::encode_frame(&response)?;
    tokio::time::timeout(WRITE_TIMEOUT, writer.write_all(&frame))
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
    let mut body = vec![0_u8; body_len];
    tokio::time::timeout(timeout, reader.read_exact(&mut body))
        .await
        .map_err(|_| DaemonError::Timeout("frame body"))??;
    serde_json::from_slice(&body)
        .map_err(FrameError::Serialize)
        .map_err(DaemonError::Frame)
}

fn prepare_socket_path(path: &Path) -> std::io::Result<()> {
    if std::fs::symlink_metadata(path.parent().unwrap_or_else(|| Path::new(".")))
        .is_ok_and(|metadata| metadata.file_type().is_symlink() || !metadata.is_dir())
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
    use crate::vortix_core::ipc::{ClientHello, IpcCapability};

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

    fn handshake(id: u64) -> IpcRequest {
        IpcRequest {
            id,
            op: IpcOp::Handshake {
                hello: ClientHello::current(vec![IpcCapability::PassiveSnapshot]),
            },
        }
    }

    #[tokio::test]
    async fn first_non_handshake_request_is_rejected() {
        let (mut client, server) = tokio::io::duplex(4096);
        let provider: Arc<dyn PassiveQueryProvider> = Arc::new(EmptyQueryProvider::new());
        let shutdown = watch::channel(false).0;
        let task = tokio::spawn(async move {
            let (mut reader, writer_half) = tokio::io::split(server);
            let (output, output_rx) = mpsc::channel(2);
            let writer = tokio::spawn(writer_loop(writer_half, output_rx));
            let result = connection_loop(&mut reader, &output, provider, shutdown).await;
            drop(output);
            let _ = writer.await;
            result
        });
        let request = IpcRequest {
            id: 1,
            op: IpcOp::PassiveSnapshot,
        };
        let frame = crate::vortix_core::ipc::encode_frame(&request).unwrap();
        client.write_all(&frame).await.unwrap();
        let mut response_bytes = vec![0_u8; 4096];
        let read = client.read(&mut response_bytes).await.unwrap();
        let (response, _) =
            crate::vortix_core::ipc::decode_frame::<IpcResponse>(&response_bytes[..read])
                .unwrap()
                .unwrap();
        assert!(matches!(response.result, Err(IpcError::HandshakeRequired)));
        task.await.unwrap().unwrap();
    }

    #[test]
    fn passive_dispatch_rejects_execute() {
        let provider = EmptyQueryProvider::new();
        let shutdown = watch::channel(false).0;
        let request = IpcRequest {
            id: 9,
            op: IpcOp::Execute(crate::vortix_core::engine::input::UserCommand::Disconnect {
                profile_id: None,
            }),
        };
        assert!(matches!(
            dispatch(&request, &provider, &shutdown).result,
            Err(IpcError::CapabilityUnavailable {
                capability: IpcCapability::ControlMutation
            })
        ));
    }

    #[test]
    fn handshake_fixture_is_well_formed() {
        assert!(matches!(handshake(1).op, IpcOp::Handshake { .. }));
    }

    #[test]
    fn replay_cache_uses_fixed_digests_and_bounds_response_bytes() {
        let mut cache = ReplayCache::<256>::default();
        let digest = request_digest(&IpcOp::PassiveSnapshot).unwrap();
        assert_eq!(std::mem::size_of_val(&digest), REQUEST_DIGEST_BYTES);

        let retained = IpcResponse {
            id: 7,
            result: Err(IpcError::Internal("small".into())),
        };
        assert!(cache.insert(7, digest, &retained).unwrap());
        let retained_bytes = cache.retained_response_bytes();
        assert!(retained_bytes > 0);
        assert!(retained_bytes <= 256);

        let oversized = IpcResponse {
            id: 8,
            result: Err(IpcError::Internal("x".repeat(256))),
        };
        let oversized_digest = request_digest(&IpcOp::Shutdown).unwrap();
        assert!(!cache.insert(8, oversized_digest, &oversized).unwrap());
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
        assert!(cache.insert(41, snapshot_digest, &response).unwrap());

        let ReplayLookup::Replay(replayed) = cache.lookup(41, &snapshot_digest).unwrap() else {
            panic!("same id and operation must replay the retained response");
        };
        assert_eq!(
            serde_json::to_value(replayed).unwrap(),
            serde_json::to_value(response).unwrap()
        );

        let shutdown_digest = request_digest(&IpcOp::Shutdown).unwrap();
        assert!(matches!(
            cache.lookup(41, &shutdown_digest).unwrap(),
            ReplayLookup::Conflict
        ));
        assert!(matches!(
            cache.lookup(42, &shutdown_digest).unwrap(),
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
        stream_snapshots(
            &mut idle_reader,
            &output,
            &provider,
            &mut receiver,
            1,
            &shutdown,
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
