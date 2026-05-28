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
            daemon_uid,
        })
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
        let daemon_uid = self.daemon_uid;
        loop {
            match self.listener.accept().await {
                Ok((stream, _addr)) => {
                    if let Err(e) = handle_client(stream, daemon_uid).await {
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
async fn handle_client(mut stream: UnixStream, daemon_uid: u32) -> Result<(), DaemonError> {
    // Peer-UID enforcement runs before any frame is read so an
    // unauthorized client never gets the chance to drive dispatch.
    match get_peer_uid(&stream) {
        Ok(peer_uid) if peer_uid == daemon_uid => { /* authorized; fall through */ }
        Ok(peer_uid) => {
            tracing::warn!(
                peer_uid,
                daemon_uid,
                "rejecting client with UID mismatch"
            );
            // Best-effort notify-and-close: write a single
            // Unauthorized frame so the client surfaces a typed
            // error rather than an opaque EOF. The response `id` is
            // 0 because we never read a request — clients treat the
            // first frame received as authoritative either way.
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
                result: Err(IpcError::Internal(format!(
                    "peer-UID lookup failed: {e}"
                ))),
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
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
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

#[cfg(all(test, unix))]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use crate::vortix_core::ipc::{decode_frame, IpcOp, IpcRequest};
    use tokio::net::UnixStream as TokioUnixStream;

    /// Helper: bind a fresh daemon on a unique temp socket path.
    fn fresh_socket_path() -> PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        // PID + nanos keeps the path unique across parallel test runs.
        p.push(format!("vortix-test-{}-{nanos}.sock", std::process::id()));
        p
    }

    #[tokio::test]
    async fn peer_uid_matches_daemon_uid_for_same_process() {
        // The simplest realization of the auth path: when the test
        // process connects to a daemon it spawned, both ends share
        // the same UID, so the check should pass and dispatch should
        // fire normally.
        let socket = fresh_socket_path();
        let server = DaemonServer::bind(socket.clone()).expect("bind");
        let daemon_uid = server.daemon_uid();
        // SAFETY: trivial syscall, see DaemonServer::bind.
        let process_uid = unsafe { libc::geteuid() };
        assert_eq!(daemon_uid, process_uid, "daemon UID captured correctly");

        // Spawn the accept loop in the background and connect once.
        let handle = tokio::spawn(server.run());

        // Give the listener a tick to come up; the bind above is
        // synchronous so the socket exists, but tokio's accept
        // future has not necessarily been polled yet.
        let mut client = loop {
            match TokioUnixStream::connect(&socket).await {
                Ok(s) => break s,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };

        // Send a Shutdown op — dispatch returns ShuttingDown, which
        // tells us the UID check passed and we reached dispatch.
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
        assert_eq!(resp.id, 7, "response carries request id (dispatch ran)");
        assert!(
            matches!(resp.result, Ok(IpcResult::ShuttingDown)),
            "expected dispatched ShuttingDown, got {:?}",
            resp.result
        );

        handle.abort();
        let _ = std::fs::remove_file(&socket);
    }

    #[tokio::test]
    async fn unauthorized_path_emits_unauthorized_frame_without_dispatch() {
        // We can't easily run the daemon under a different UID in a
        // unit test, but we can exercise the rejection branch
        // directly by calling handle_client with a daemon_uid that
        // cannot match the connecting peer (the test process). Pick
        // an impossible UID (u32::MAX) — geteuid() will never return
        // it on a real system.
        let (server_end, mut client_end) = TokioUnixStream::pair().expect("socketpair");

        let fake_daemon_uid = u32::MAX;
        let server_task = tokio::spawn(async move {
            handle_client(server_end, fake_daemon_uid).await
        });

        let mut buf = vec![0u8; 4096];
        let n = client_end.read(&mut buf).await.expect("read");
        let (resp, _) = decode_frame::<IpcResponse>(&buf[..n])
            .expect("decode ok")
            .expect("complete frame");
        assert_eq!(resp.id, 0, "unauthorized frame uses id=0");
        assert!(
            matches!(resp.result, Err(IpcError::Unauthorized)),
            "expected Unauthorized, got {:?}",
            resp.result
        );

        // handle_client should return Ok(()) after writing the
        // rejection — the connection is closed deliberately, not
        // due to an error.
        let outcome = server_task.await.expect("join");
        assert!(outcome.is_ok(), "handle_client returned Err: {outcome:?}");
    }

    #[tokio::test]
    async fn get_peer_uid_returns_current_process_uid_on_socketpair() {
        let (a, _b) = TokioUnixStream::pair().expect("socketpair");
        let uid = get_peer_uid(&a).expect("peer uid lookup");
        // SAFETY: trivial syscall, see DaemonServer::bind.
        let me = unsafe { libc::geteuid() };
        assert_eq!(uid, me, "socketpair peer shares our UID");
    }
}
