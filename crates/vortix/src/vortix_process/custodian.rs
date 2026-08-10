//! Tunnel-scoped Standard-mode process custodian.
//!
//! A one-shot CLI may exit after `up`, so a foreground protocol child cannot
//! remain owned by process-global memory. Each attempt gets a small private
//! custodian subprocess. Its socket accepts only `status` and `stop` for one
//! exact profile/generation/token capability; it has no policy authority.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::vortix_core::control::OperationId;
use crate::vortix_core::ports::process::{
    CommandSpec, ManagedProcessId, ProcessError, ProcessLifecycle,
};
use crate::vortix_core::profile::ProfileId;
use crate::vortix_process::real::RealProcessLifecycle;

const HIDDEN_ARG: &str = "__vortix-tunnel-custodian";
const MAX_FRAME: usize = 64 * 1024;
const HANDOFF_TIMEOUT: Duration = Duration::from_secs(10);
const IPC_TIMEOUT: Duration = Duration::from_secs(3);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodianHandshake {
    pub identity: ManagedProcessId,
    pub pid: u32,
    /// Canonical connect operation that created this child. Legacy receipts
    /// omit it and remain readable, but cannot outlive operation retention.
    #[serde(default)]
    pub operation_id: Option<OperationId>,
}

#[derive(Debug, Error)]
pub enum CustodianError {
    #[error("a child is already owned for this stable identity")]
    AlreadyOwned,
    #[error("no child is owned for this exact ownership capability")]
    NotOwned,
    #[error("child exited before the ownership handshake")]
    StartupFailed,
    #[error("custodian handoff timed out")]
    HandoffTimeout,
    #[error("custodian rejected the request: {0}")]
    Rejected(String),
    #[error("custodian cleanup is ambiguous: {0}")]
    Ambiguous(String),
    #[error("custodian I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("custodian protocol: {0}")]
    Protocol(String),
    #[error(transparent)]
    Process(#[from] ProcessError),
}

#[derive(Debug, Serialize, Deserialize)]
struct LaunchRequest {
    identity: ManagedProcessId,
    spec: CommandSpec,
    cleanup_paths: Vec<PathBuf>,
    graceful_timeout_ms: u64,
    #[serde(default)]
    operation_id: Option<OperationId>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HandoffFrame {
    Ready { handshake: CustodianHandshake },
    Commit,
    Committed { handshake: CustodianHandshake },
    Error { message: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum LifecycleRequest {
    Status { identity: ManagedProcessId },
    Stop { identity: ManagedProcessId },
}

#[derive(Debug, Serialize, Deserialize)]
struct LifecycleResponse {
    ok: bool,
    alive: bool,
    error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OwnershipReceipt {
    identity: ManagedProcessId,
    child_pid: u32,
    #[serde(default)]
    operation_id: Option<OperationId>,
}

/// Bounded lifecycle custodian parameterized by a deterministic fake or real
/// process backend. The production hidden entrypoint owns exactly one child;
/// the map keeps the teardown contract independently unit-testable.
pub struct StandardCustodian<P: ProcessLifecycle> {
    process: P,
    owned: BTreeMap<ManagedProcessId, u32>,
    graceful_timeout: Duration,
}

impl<P: ProcessLifecycle> StandardCustodian<P> {
    #[must_use]
    pub fn new(process: P, graceful_timeout: Duration) -> Self {
        Self {
            process,
            owned: BTreeMap::new(),
            graceful_timeout,
        }
    }

    pub fn start(
        &mut self,
        identity: ManagedProcessId,
        spec: CommandSpec,
    ) -> Result<CustodianHandshake, CustodianError> {
        if !identity.has_valid_token() {
            return Err(CustodianError::Protocol(
                "invalid or zero ownership token/generation".into(),
            ));
        }
        if self.owned.contains_key(&identity) {
            return Err(CustodianError::AlreadyOwned);
        }
        let ownership = match self.process.spawn_foreground(identity.clone(), spec) {
            Ok(ownership) => ownership,
            Err(error) => {
                // `spawn_foreground` may have created a child before a stdin
                // write failed. Teardown is therefore mandatory even when the
                // spawn API reports an error.
                return match self.force_cleanup(&identity) {
                    Ok(()) => Err(error.into()),
                    Err(cleanup) => Err(CustodianError::Ambiguous(format!(
                        "spawn failed: {error}; cleanup failed: {cleanup}"
                    ))),
                };
            }
        };
        self.owned.insert(identity.clone(), ownership.pid);
        match self.process.is_alive(&identity) {
            Ok(true) => Ok(CustodianHandshake {
                identity,
                pid: ownership.pid,
                operation_id: None,
            }),
            Ok(false) => match self.force_cleanup(&identity) {
                Ok(()) => Err(CustodianError::StartupFailed),
                Err(cleanup) => Err(CustodianError::Ambiguous(format!(
                    "child exited before handshake; cleanup failed: {cleanup}"
                ))),
            },
            Err(error) => {
                let cleanup = self.force_cleanup(&identity).err();
                Err(CustodianError::Ambiguous(match cleanup {
                    Some(cleanup) => format!("liveness failed: {error}; cleanup failed: {cleanup}"),
                    None => format!("liveness failed: {error}"),
                }))
            }
        }
    }

    /// Graceful stop followed by unconditional bounded containment and reap.
    /// Ownership is retained on ambiguous cleanup so callers cannot mistake a
    /// failed stop for freedom to reuse the identity.
    pub fn stop(&mut self, identity: &ManagedProcessId) -> Result<(), CustodianError> {
        if !self.owned.contains_key(identity) {
            return Err(CustodianError::NotOwned);
        }

        let mut errors = Vec::new();
        if let Err(error) = self.process.graceful_stop(identity) {
            errors.push(format!("graceful stop: {error}"));
        }
        let graceful_exit = match self.process.wait_for_exit(identity, self.graceful_timeout) {
            Ok(exited) => exited,
            Err(error) => {
                errors.push(format!("graceful wait: {error}"));
                false
            }
        };
        if !graceful_exit {
            if let Err(error) = self.process.force_kill(identity) {
                errors.push(format!("force kill: {error}"));
            }
            match self.process.wait_for_exit(identity, self.graceful_timeout) {
                Ok(true) => {}
                Ok(false) => errors.push("process group remained alive after SIGKILL".into()),
                Err(error) => errors.push(format!("forced wait: {error}")),
            }
        }
        if let Err(error) = self.process.reap(identity) {
            errors.push(format!("reap: {error}"));
        }

        if errors.is_empty() {
            self.owned.remove(identity);
            Ok(())
        } else {
            Err(CustodianError::Ambiguous(errors.join("; ")))
        }
    }

    fn force_cleanup(&mut self, identity: &ManagedProcessId) -> Result<(), CustodianError> {
        let mut errors = Vec::new();
        if let Err(error) = self.process.force_kill(identity) {
            errors.push(format!("force kill: {error}"));
        }
        match self.process.wait_for_exit(identity, self.graceful_timeout) {
            Ok(true) => {}
            Ok(false) => errors.push("process group remained alive".into()),
            Err(error) => errors.push(format!("wait: {error}")),
        }
        if let Err(error) = self.process.reap(identity) {
            errors.push(format!("reap: {error}"));
        }
        if errors.is_empty() {
            self.owned.remove(identity);
            Ok(())
        } else {
            Err(CustodianError::Ambiguous(errors.join("; ")))
        }
    }

    pub fn contain_all(&mut self) -> Vec<(ManagedProcessId, CustodianError)> {
        let identities = self.owned.keys().cloned().collect::<Vec<_>>();
        identities
            .into_iter()
            .filter_map(|identity| self.stop(&identity).err().map(|error| (identity, error)))
            .collect()
    }

    #[must_use]
    pub fn owns(&self, identity: &ManagedProcessId) -> bool {
        self.owned.contains_key(identity)
    }
}

/// Start the private custodian subprocess and complete a two-phase handoff.
#[allow(clippy::needless_pass_by_value)] // ownership crosses the process boundary in the frame
pub fn spawn_custodian(
    identity: ManagedProcessId,
    spec: CommandSpec,
    cleanup_paths: Vec<PathBuf>,
    graceful_timeout: Duration,
) -> Result<CustodianHandshake, CustodianError> {
    spawn_custodian_for_operation(identity, spec, cleanup_paths, graceful_timeout, None)
}

/// Start a private custodian and bind its authenticated durable receipt to
/// the canonical operation that created the child.
#[allow(clippy::needless_pass_by_value)] // ownership crosses the process boundary in the frame
pub fn spawn_custodian_for_operation(
    identity: ManagedProcessId,
    spec: CommandSpec,
    cleanup_paths: Vec<PathBuf>,
    graceful_timeout: Duration,
    operation_id: Option<OperationId>,
) -> Result<CustodianHandshake, CustodianError> {
    if !identity.has_valid_token() {
        return Err(CustodianError::Protocol(
            "invalid ownership identity".into(),
        ));
    }
    ensure_runtime_dir()?;
    let executable = std::env::var_os("VORTIX_CUSTODIAN_EXE")
        .map(PathBuf::from)
        .map_or_else(std::env::current_exe, Ok)?;
    let mut child = Command::new(executable)
        .arg(HIDDEN_ARG)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let result = (|| -> Result<CustodianHandshake, CustodianError> {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| CustodianError::Protocol("missing custodian stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| CustodianError::Protocol("missing custodian stdout".into()))?;
        let request = LaunchRequest {
            identity: identity.clone(),
            spec,
            cleanup_paths,
            graceful_timeout_ms: u64::try_from(graceful_timeout.as_millis()).unwrap_or(u64::MAX),
            operation_id,
        };
        write_json_line(&mut stdin, &request)?;

        let (tx, rx) = mpsc::sync_channel(2);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            for _ in 0..2 {
                let result = read_json_line::<_, HandoffFrame>(&mut reader);
                if tx.send(result).is_err() {
                    break;
                }
            }
        });

        let first = recv_handoff(&rx)?;
        let ready = match first {
            HandoffFrame::Ready { handshake } if handshake.identity == identity => handshake,
            HandoffFrame::Error { message } => return Err(CustodianError::Rejected(message)),
            _ => return Err(CustodianError::Protocol("invalid READY frame".into())),
        };
        write_json_line(&mut stdin, &HandoffFrame::Commit)?;
        let second = recv_handoff(&rx)?;
        match second {
            HandoffFrame::Committed { handshake } if handshake == ready => Ok(handshake),
            HandoffFrame::Error { message } => Err(CustodianError::Rejected(message)),
            _ => Err(CustodianError::Protocol("invalid COMMITTED frame".into())),
        }
    })();
    if result.is_err() {
        wait_for_handoff_cleanup(&mut child);
    } else {
        // A long-lived TUI remains the custodian's Unix parent. Retain the
        // Child handle on a tiny waiter so natural custodian exit cannot
        // become a zombie. One-shot CLI parents simply exit first.
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
    result
}

fn recv_handoff(
    rx: &mpsc::Receiver<Result<HandoffFrame, CustodianError>>,
) -> Result<HandoffFrame, CustodianError> {
    let Ok(frame) = rx.recv_timeout(HANDOFF_TIMEOUT) else {
        return Err(CustodianError::HandoffTimeout);
    };
    frame
}

fn wait_for_handoff_cleanup(child: &mut Child) {
    let deadline = Instant::now() + HANDOFF_TIMEOUT;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => std::thread::sleep(POLL_INTERVAL),
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Read the exact current receipt for a profile. Absence is not ownership.
pub fn load_identity(profile_id: &ProfileId) -> Result<Option<ManagedProcessId>, CustodianError> {
    Ok(load_handshake(profile_id)?.map(|receipt| receipt.identity))
}

/// Read the authenticated Standard-mode child capability and PID needed to
/// reconstruct an exact lifecycle handle in a later one-shot process.
pub fn load_handshake(
    profile_id: &ProfileId,
) -> Result<Option<CustodianHandshake>, CustodianError> {
    Ok(load_receipt(profile_id)?.map(|receipt| CustodianHandshake {
        identity: receipt.identity,
        pid: receipt.child_pid,
        operation_id: receipt.operation_id,
    }))
}

fn load_receipt(profile_id: &ProfileId) -> Result<Option<OwnershipReceipt>, CustodianError> {
    ensure_runtime_dir()?;
    let path = receipt_path(profile_id);
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(u64::try_from(MAX_FRAME + 1).expect("frame bound fits u64"))
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_FRAME {
        return Err(CustodianError::Protocol(
            "receipt exceeds frame limit".into(),
        ));
    }
    let receipt: OwnershipReceipt = serde_json::from_slice(&bytes)
        .map_err(|error| CustodianError::Protocol(format!("invalid receipt: {error}")))?;
    if receipt.identity.profile_id != *profile_id || !receipt.identity.has_valid_token() {
        return Err(CustodianError::Protocol("receipt identity mismatch".into()));
    }
    Ok(Some(receipt))
}

pub fn remote_status(identity: &ManagedProcessId) -> Result<bool, CustodianError> {
    lifecycle_request(LifecycleRequest::Status {
        identity: identity.clone(),
    })
}

pub fn remote_stop(identity: &ManagedProcessId) -> Result<(), CustodianError> {
    let receipt = load_receipt(&identity.profile_id)?
        .filter(|receipt| constant_time_identity_eq(&receipt.identity, identity))
        .ok_or(CustodianError::NotOwned)?;
    let request_result = lifecycle_request(LifecycleRequest::Stop {
        identity: identity.clone(),
    });
    let deadline = Instant::now() + IPC_TIMEOUT;
    while Instant::now() < deadline {
        let receipt_gone = load_identity(&identity.profile_id)?
            .as_ref()
            .is_none_or(|current| current != identity);
        if receipt_gone
            && !socket_path(identity).exists()
            && process_group_absent(receipt.child_pid)?
        {
            // A dropped response is connection-local: exact absence is the
            // authoritative success receipt.
            return Ok(());
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    let request = request_result.map_or_else(
        |error| format!("stop request failed: {error}"),
        |alive| {
            if alive {
                "custodian reported the child still alive".into()
            } else {
                "custodian acknowledged stop".into()
            }
        },
    );
    Err(CustodianError::Ambiguous(format!(
        "{request}; exact receipt/socket/process-group absence was not proven"
    )))
}

fn process_group_absent(pid: u32) -> Result<bool, CustodianError> {
    Ok(!crate::vortix_process::real::process_group_has_live_members(pid)?)
}

#[allow(clippy::needless_pass_by_value)] // the complete request is serialized once below
fn lifecycle_request(request: LifecycleRequest) -> Result<bool, CustodianError> {
    let identity = match &request {
        LifecycleRequest::Status { identity } | LifecycleRequest::Stop { identity } => identity,
    };
    if !identity.has_valid_token() {
        return Err(CustodianError::NotOwned);
    }
    let mut stream = UnixStream::connect(socket_path(identity)).map_err(|error| {
        if matches!(
            error.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
        ) {
            CustodianError::NotOwned
        } else {
            error.into()
        }
    })?;
    stream.set_read_timeout(Some(IPC_TIMEOUT))?;
    stream.set_write_timeout(Some(IPC_TIMEOUT))?;
    write_json_line(&mut stream, &request)?;
    let response: LifecycleResponse = read_json_line(&mut BufReader::new(stream))?;
    if response.ok {
        Ok(response.alive)
    } else {
        Err(CustodianError::Rejected(
            response.error.unwrap_or_else(|| "request rejected".into()),
        ))
    }
}

/// Hidden binary entrypoint. Returns `None` for normal CLI invocations.
#[must_use]
pub fn maybe_run_hidden_entrypoint() -> Option<i32> {
    let arg = std::env::args_os().nth(1);
    if arg.as_deref()
        == Some(std::ffi::OsStr::new(
            crate::vortix_process::real::GUARDIAN_ARG,
        ))
    {
        return Some(crate::vortix_process::real::run_guardian_entrypoint().map_or(70, |()| 0));
    }
    (arg.as_deref() == Some(std::ffi::OsStr::new(HIDDEN_ARG))).then(|| {
        run_hidden().map_or_else(
            |error| {
                let _ = write_json_line(
                    &mut std::io::stdout().lock(),
                    &HandoffFrame::Error {
                        message: error.to_string(),
                    },
                );
                70
            },
            |()| 0,
        )
    })
}

#[allow(clippy::too_many_lines)] // one linear spawn/handoff/serve/finally ownership protocol
fn run_hidden() -> Result<(), CustodianError> {
    ensure_runtime_dir()?;
    let mut input = BufReader::new(std::io::stdin().lock());
    let request: LaunchRequest = read_json_line(&mut input)?;
    if !request.identity.has_valid_token() {
        return Err(CustodianError::Protocol("invalid identity".into()));
    }
    TERMINATE.store(false, Ordering::Relaxed);
    install_termination_handler();
    let _profile_lock = lock_profile(&request.identity.profile_id)?;
    let socket_path = socket_path(&request.identity);
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)?;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;

    let graceful_timeout = Duration::from_millis(request.graceful_timeout_ms.clamp(1, 60_000));
    if TERMINATE.load(Ordering::Relaxed) {
        return Err(CustodianError::Protocol(
            "custodian terminated before child spawn".into(),
        ));
    }
    let mut custodian = StandardCustodian::new(RealProcessLifecycle::default(), graceful_timeout);
    let handshake = match custodian.start(request.identity.clone(), request.spec) {
        Ok(mut handshake) => {
            handshake.operation_id = request.operation_id;
            handshake
        }
        Err(error) => {
            let _ = write_json_line(
                &mut std::io::stdout().lock(),
                &HandoffFrame::Error {
                    message: error.to_string(),
                },
            );
            return match cleanup_artifacts(&request.identity, &request.cleanup_paths, &socket_path)
            {
                Ok(()) => Err(error),
                Err(cleanup) => Err(CustodianError::Ambiguous(format!(
                    "startup failed: {error}; artifact cleanup failed: {cleanup}"
                ))),
            };
        }
    };
    let owned_result = (|| -> Result<(), CustodianError> {
        if TERMINATE.load(Ordering::Relaxed) {
            return Err(CustodianError::Protocol(
                "custodian terminated during child spawn".into(),
            ));
        }
        write_receipt(&handshake)?;
        let mut output = std::io::stdout().lock();
        write_json_line(
            &mut output,
            &HandoffFrame::Ready {
                handshake: handshake.clone(),
            },
        )?;
        if !matches!(
            read_commit_interruptible(&mut input),
            Ok(HandoffFrame::Commit)
        ) {
            return Err(CustodianError::Protocol("handoff was not committed".into()));
        }
        write_json_line(
            &mut output,
            &HandoffFrame::Committed {
                handshake: handshake.clone(),
            },
        )?;
        drop(output);
        drop(input);

        loop {
            if TERMINATE.load(Ordering::Relaxed) {
                custodian.stop(&request.identity)?;
                break;
            }
            if !custodian.process.is_alive(&request.identity)? {
                custodian.process.reap(&request.identity)?;
                custodian.owned.remove(&request.identity);
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    if handle_client(stream, &request.identity, &mut custodian)? {
                        break;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        Ok(())
    })();

    // Finally-style containment: every error after spawn, including receipt,
    // handshake, IPC, liveness, and listener failures, reaches this path.
    let containment = if custodian.owns(&request.identity) {
        custodian.stop(&request.identity)
    } else {
        Ok(())
    };
    let artifact_cleanup =
        cleanup_artifacts(&request.identity, &request.cleanup_paths, &socket_path);
    match (owned_result, containment, artifact_cleanup) {
        (Ok(()), Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(()), Ok(()))
        | (Ok(()), Err(error), Ok(()))
        | (Ok(()), Ok(()), Err(error)) => Err(error),
        (owned, containment, artifacts) => {
            let mut errors = Vec::new();
            if let Err(error) = owned {
                errors.push(format!("custodian: {error}"));
            }
            if let Err(error) = containment {
                errors.push(format!("containment: {error}"));
            }
            if let Err(error) = artifacts {
                errors.push(format!("artifacts: {error}"));
            }
            Err(CustodianError::Ambiguous(errors.join("; ")))
        }
    }
}

fn handle_client<P: ProcessLifecycle>(
    mut stream: UnixStream,
    owned: &ManagedProcessId,
    custodian: &mut StandardCustodian<P>,
) -> Result<bool, CustodianError> {
    if stream.set_read_timeout(Some(IPC_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(IPC_TIMEOUT)).is_err()
    {
        return Ok(false);
    }
    let Ok(uid) = peer_uid(&stream) else {
        return Ok(false);
    };
    if uid != effective_uid() {
        let _ = write_json_line(
            &mut stream,
            &LifecycleResponse {
                ok: false,
                alive: true,
                error: Some("peer uid rejected".into()),
            },
        );
        return Ok(false);
    }
    let Ok(cloned) = stream.try_clone() else {
        return Ok(false);
    };
    let request = read_json_line::<_, LifecycleRequest>(&mut BufReader::new(cloned));
    let (identity, stop) = match request {
        Ok(LifecycleRequest::Status { identity }) => (identity, false),
        Ok(LifecycleRequest::Stop { identity }) => (identity, true),
        Err(error) => {
            let _ = write_json_line(
                &mut stream,
                &LifecycleResponse {
                    ok: false,
                    alive: true,
                    error: Some(error.to_string()),
                },
            );
            return Ok(false);
        }
    };
    if !constant_time_identity_eq(&identity, owned) {
        let _ = write_json_line(
            &mut stream,
            &LifecycleResponse {
                ok: false,
                alive: true,
                error: Some("ownership capability rejected".into()),
            },
        );
        return Ok(false);
    }
    if stop {
        return match custodian.stop(owned) {
            Ok(()) => {
                let _ = write_json_line(
                    &mut stream,
                    &LifecycleResponse {
                        ok: true,
                        alive: false,
                        error: None,
                    },
                );
                Ok(true)
            }
            Err(error) => {
                let _ = write_json_line(
                    &mut stream,
                    &LifecycleResponse {
                        ok: false,
                        alive: true,
                        error: Some(error.to_string()),
                    },
                );
                // Ambiguous teardown retains custody and remains retryable.
                Ok(false)
            }
        };
    }
    let alive = custodian.process.is_alive(owned)?;
    let _ = write_json_line(
        &mut stream,
        &LifecycleResponse {
            ok: true,
            alive,
            error: None,
        },
    );
    Ok(false)
}

fn read_commit_interruptible<R: BufRead>(input: &mut R) -> Result<HandoffFrame, CustodianError> {
    loop {
        if TERMINATE.load(Ordering::Relaxed) {
            return Err(CustodianError::Protocol(
                "custodian terminated before COMMIT".into(),
            ));
        }
        let mut descriptor = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        // SAFETY: `descriptor` is a valid one-element poll array.
        #[allow(unsafe_code)]
        let result = unsafe { libc::poll(&raw mut descriptor, 1, 25) };
        if result > 0 {
            return read_json_line(input);
        }
        if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(std::io::Error::last_os_error().into());
        }
    }
}

fn constant_time_identity_eq(left: &ManagedProcessId, right: &ManagedProcessId) -> bool {
    if left.profile_id != right.profile_id || left.generation != right.generation {
        return false;
    }
    let left = left.ownership_token.as_bytes();
    let right = right.ownership_token.as_bytes();
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or_default()
                ^ right.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

fn ensure_runtime_dir() -> Result<PathBuf, CustodianError> {
    let path = runtime_dir();
    match std::fs::create_dir(&path) {
        Ok(()) => std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = std::fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != effective_uid()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(CustodianError::Protocol(format!(
            "unsafe custodian runtime directory {}",
            path.display()
        )));
    }
    Ok(path)
}

fn runtime_dir() -> PathBuf {
    std::env::var_os("VORTIX_CUSTODIAN_RUNTIME_DIR").map_or_else(
        || PathBuf::from(format!("/tmp/vortix-custodian-{}", effective_uid())),
        PathBuf::from,
    )
}

fn profile_key(profile_id: &ProfileId) -> String {
    let digest = Sha256::digest(profile_id.as_str().as_bytes());
    let mut key = String::with_capacity(24);
    for byte in digest.iter().take(12) {
        let _ = write!(key, "{byte:02x}");
    }
    key
}

fn socket_path(identity: &ManagedProcessId) -> PathBuf {
    runtime_dir().join(format!(
        "{}-{:016x}-{}.sock",
        profile_key(&identity.profile_id),
        identity.generation,
        &identity.ownership_token[..16]
    ))
}

fn receipt_path(profile_id: &ProfileId) -> PathBuf {
    runtime_dir().join(format!("{}.receipt", profile_key(profile_id)))
}

fn lock_path(profile_id: &ProfileId) -> PathBuf {
    runtime_dir().join(format!("{}.lock", profile_key(profile_id)))
}

fn lock_profile(profile_id: &ProfileId) -> Result<File, CustodianError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(lock_path(profile_id))?;
    // SAFETY: flock operates on this live descriptor and does not touch Rust
    // memory. The descriptor remains owned by the returned File.
    #[allow(unsafe_code)]
    let status = unsafe {
        libc::flock(
            std::os::fd::AsRawFd::as_raw_fd(&file),
            libc::LOCK_EX | libc::LOCK_NB,
        )
    };
    if status != 0 {
        return Err(CustodianError::AlreadyOwned);
    }
    Ok(file)
}

fn write_receipt(handshake: &CustodianHandshake) -> Result<(), CustodianError> {
    let receipt = OwnershipReceipt {
        identity: handshake.identity.clone(),
        child_pid: handshake.pid,
        operation_id: handshake.operation_id.clone(),
    };
    let final_path = receipt_path(&handshake.identity.profile_id);
    let temp_path = runtime_dir().join(format!(
        ".{}.{}.tmp",
        profile_key(&handshake.identity.profile_id),
        handshake.identity.generation
    ));
    let bytes = serde_json::to_vec(&receipt)
        .map_err(|error| CustodianError::Protocol(format!("serialize receipt: {error}")))?;
    let result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp_path, final_path)?;
        File::open(runtime_dir())?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    result.map_err(CustodianError::Io)
}

fn cleanup_artifacts(
    identity: &ManagedProcessId,
    paths: &[PathBuf],
    socket: &Path,
) -> Result<(), CustodianError> {
    let mut errors = Vec::new();
    for path in paths {
        record_remove_error(path, &mut errors);
    }
    match load_identity(&identity.profile_id) {
        Ok(Some(current)) if current == *identity => {
            record_remove_error(&receipt_path(&identity.profile_id), &mut errors);
        }
        Ok(_) => {}
        Err(error) => errors.push(format!("inspect receipt: {error}")),
    }
    // Socket removal is the client-visible completion barrier: every other
    // attempt-scoped artifact is gone before remote_stop observes this path
    // disappear and permits a reconnect.
    record_remove_error(socket, &mut errors);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(CustodianError::Ambiguous(errors.join("; ")))
    }
}

fn record_remove_error(path: &Path, errors: &mut Vec<String>) {
    if let Err(error) = std::fs::remove_file(path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            errors.push(format!("remove {}: {error}", path.display()));
        }
    }
}

fn write_json_line<W: std::io::Write, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<(), CustodianError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| CustodianError::Protocol(format!("serialize frame: {error}")))?;
    if bytes.len() > MAX_FRAME {
        return Err(CustodianError::Protocol("frame exceeds limit".into()));
    }
    writer.write_all(&bytes)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn read_json_line<R: BufRead, T: for<'de> Deserialize<'de>>(
    reader: &mut R,
) -> Result<T, CustodianError> {
    let mut bytes = Vec::new();
    let read = reader
        .take(u64::try_from(MAX_FRAME + 1).expect("frame bound fits u64"))
        .read_until(b'\n', &mut bytes)?;
    if read == 0 {
        return Err(CustodianError::Protocol("unexpected EOF".into()));
    }
    if bytes.len() > MAX_FRAME || !bytes.ends_with(b"\n") {
        return Err(CustodianError::Protocol(
            "invalid or oversized frame".into(),
        ));
    }
    bytes.pop();
    serde_json::from_slice(&bytes)
        .map_err(|error| CustodianError::Protocol(format!("invalid frame: {error}")))
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    #[allow(unsafe_code)]
    unsafe {
        libc::geteuid()
    }
}

#[allow(unsafe_code)]
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    use std::os::fd::AsRawFd as _;
    let fd = stream.as_raw_fd();
    // xtask:allow-platform-cfg: peer credentials are OS syscall primitives.
    #[cfg(target_os = "linux")]
    unsafe {
        let mut credential: libc::ucred = std::mem::zeroed();
        let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
            .expect("ucred size fits socklen_t");
        if libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credential).cast(),
            std::ptr::from_mut(&mut length),
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(credential.uid)
    }
    // xtask:allow-platform-cfg: peer credentials are OS syscall primitives.
    #[cfg(target_os = "macos")]
    unsafe {
        let mut uid = 0;
        let mut gid = 0;
        if libc::getpeereid(fd, &raw mut uid, &raw mut gid) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(uid)
    }
}

static TERMINATE: AtomicBool = AtomicBool::new(false);

extern "C" fn termination_handler(_: libc::c_int) {
    TERMINATE.store(true, Ordering::Relaxed);
}

fn install_termination_handler() {
    // SAFETY: the handler only performs one lock-free atomic store.
    #[allow(unsafe_code)]
    unsafe {
        libc::signal(libc::SIGTERM, termination_handler as libc::sighandler_t);
        libc::signal(libc::SIGINT, termination_handler as libc::sighandler_t);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_receipt_without_operation_remains_readable_but_unbound() {
        let receipt: OwnershipReceipt = serde_json::from_value(serde_json::json!({
            "identity": {
                "profile_id": "b".repeat(64),
                "generation": 7,
                "ownership_token": "a".repeat(64),
            },
            "child_pid": 42,
        }))
        .unwrap();
        assert_eq!(receipt.identity.profile_id.as_str(), "b".repeat(64));
        assert_eq!(receipt.operation_id, None);
    }
}
