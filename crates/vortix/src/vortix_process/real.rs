//! Production `CommandRunner` implementation backed by `tokio::process`.

use std::collections::BTreeMap;
use std::io::{BufRead as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;
use std::process::{Child, Stdio};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::vortix_core::ports::process::{
    CommandOutcome, CommandRunner as Trait, CommandSpec, DetachedHandle, ExitStatusInfo, Kind,
    ManagedProcessId, PrivilegeReq, ProcessError, ProcessLifecycle, ProcessOwnership,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::runtime::Runtime;
use tracing::{debug, info, warn};

/// Production runner. Constructed once at startup and held in the engine actor.
///
/// Bundles a private `tokio` runtime so callers in synchronous code paths
/// (the TUI loop, CLI commands) can drive async subprocess invocations via
/// `runtime.block_on(...)`. Idea 3's `EngineHandle` PR makes this seam fully
/// async; until then, the runtime here is the transitional shape that lets
/// every subprocess flow through this one trait.
#[derive(Debug, Clone)]
pub struct RealRunner {
    runtime: Arc<Runtime>,
}

async fn drain_bounded(
    mut stream: impl AsyncRead + Unpin,
    limit: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut retained = Vec::with_capacity(limit.min(8192));
    let mut overflowed = false;
    let mut chunk = [0_u8; 8192];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok((retained, overflowed));
        }
        let remaining = limit.saturating_sub(retained.len());
        let keep = remaining.min(read);
        retained.extend_from_slice(&chunk[..keep]);
        overflowed |= keep != read;
    }
}

/// Real foreground-child backend. Each child is placed in its own process
/// group so forced cleanup contains descendants as well as the direct child.
#[derive(Debug, Default)]
pub struct RealProcessLifecycle {
    children: BTreeMap<ManagedProcessId, OwnedProcess>,
}

#[derive(Debug)]
struct OwnedProcess {
    guardian: Child,
    _lifeline: UnixStream,
}

pub(crate) const GUARDIAN_ARG: &str = "__vortix-process-guardian";

impl ProcessLifecycle for RealProcessLifecycle {
    fn spawn_foreground(
        &mut self,
        identity: ManagedProcessId,
        spec: CommandSpec,
    ) -> Result<ProcessOwnership, ProcessError> {
        RealRunner::check_privilege(&spec)?;
        let program = spec.program.clone();
        let encoded_spec = serde_json::to_vec(&spec).map_err(|source| ProcessError::IoError {
            program: program.clone(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, source),
        })?;
        let executable = std::env::current_exe().map_err(|source| ProcessError::IoError {
            program: program.clone(),
            source,
        })?;
        let (lifeline, guardian_lifeline) =
            UnixStream::pair().map_err(|source| ProcessError::IoError {
                program: program.clone(),
                source,
            })?;
        let guardian_fd = guardian_lifeline.as_raw_fd();
        let mut command = std::process::Command::new(executable);
        command
            .arg(GUARDIAN_ARG)
            .env("VORTIX_GUARDIAN_LIFELINE_FD", guardian_fd.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
            // UnixStream pairs are CLOEXEC. Clear the child endpoint only in
            // the post-fork process so unrelated parent-side spawns can never
            // inherit the tunnel lifeline.
            #[allow(unsafe_code)]
            unsafe {
                command.pre_exec(move || {
                    if libc::fcntl(guardian_fd, libc::F_SETFD, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let mut child = command.spawn().map_err(|source| ProcessError::IoError {
            program: program.clone(),
            source,
        })?;
        drop(guardian_lifeline);
        let pid = child.id();
        let mut stdin = child.stdin.take().ok_or_else(|| ProcessError::IoError {
            program: program.clone(),
            source: std::io::Error::other("guardian stdin was not piped"),
        })?;
        let stdout = child.stdout.take().ok_or_else(|| ProcessError::IoError {
            program: program.clone(),
            source: std::io::Error::other("guardian stdout was not piped"),
        })?;
        self.children.insert(
            identity.clone(),
            OwnedProcess {
                guardian: child,
                _lifeline: lifeline,
            },
        );
        stdin
            .write_all(&encoded_spec)
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.flush())
            .map_err(|source| ProcessError::IoError { program, source })?;
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut line = String::new();
            let result = std::io::BufReader::new(stdout)
                .read_line(&mut line)
                .map(|read| (read, line));
            let _ = ready_tx.send(result);
        });
        match ready_rx.recv_timeout(Duration::from_secs(3)) {
            Ok(Ok((read, line))) if read > 0 && line.trim_end() == "READY" => {}
            Ok(Ok(_)) => {
                return Err(ProcessError::IoError {
                    program: "process-guardian".into(),
                    source: std::io::Error::other("guardian exited before target startup"),
                });
            }
            Ok(Err(source)) => {
                return Err(ProcessError::IoError {
                    program: "process-guardian".into(),
                    source,
                });
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err(ProcessError::Timeout {
                    program: "process-guardian".into(),
                    duration: Duration::from_secs(3),
                });
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(ProcessError::IoError {
                    program: "process-guardian".into(),
                    source: std::io::Error::other("guardian startup channel disconnected"),
                });
            }
        }
        Ok(ProcessOwnership { identity, pid })
    }

    fn is_alive(&mut self, identity: &ManagedProcessId) -> Result<bool, ProcessError> {
        let Some(owned) = self.children.get_mut(identity) else {
            return Ok(false);
        };
        let leader_alive = owned
            .guardian
            .try_wait()
            .map_err(|source| ProcessError::IoError {
                program: "managed-child".into(),
                source,
            })?
            .is_none();
        Ok(leader_alive || process_group_exists(&owned.guardian)?)
    }

    fn graceful_stop(&mut self, identity: &ManagedProcessId) -> Result<(), ProcessError> {
        signal_process_group(self.children.get(identity), libc::SIGTERM)
    }

    fn wait_for_exit(
        &mut self,
        identity: &ManagedProcessId,
        timeout: Duration,
    ) -> Result<bool, ProcessError> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if !self.is_alive(identity)? {
                return Ok(true);
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(!self.is_alive(identity)?)
    }

    fn force_kill(&mut self, identity: &ManagedProcessId) -> Result<(), ProcessError> {
        signal_process_group(self.children.get(identity), libc::SIGKILL)
    }

    fn reap(&mut self, identity: &ManagedProcessId) -> Result<(), ProcessError> {
        let Some(owned) = self.children.get_mut(identity) else {
            return Ok(());
        };
        owned
            .guardian
            .wait()
            .map_err(|source| ProcessError::IoError {
                program: "managed-child".into(),
                source,
            })?;
        self.children.remove(identity);
        Ok(())
    }
}

/// Guardian hidden entrypoint shared by Linux and macOS.
///
/// The guardian leads the tunnel process group and watches a pipe retained by
/// the custodian. Custodian death closes the pipe, at which point the guardian
/// kills its complete group, including stubborn descendants. This is a
/// process-death guarantee, not a machine-power-loss guarantee.
#[allow(clippy::too_many_lines)] // one linear hidden-process startup and lifeline loop
pub(crate) fn run_guardian_entrypoint() -> Result<(), ProcessError> {
    let fd = std::env::var("VORTIX_GUARDIAN_LIFELINE_FD")
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|fd| *fd >= 0)
        .ok_or_else(|| ProcessError::IoError {
            program: "process-guardian".into(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "missing guardian lifeline descriptor",
            ),
        })?;
    // SAFETY: these process identity calls do not touch Rust memory.
    #[allow(unsafe_code)]
    let group_is_private = unsafe { libc::getpgrp() == libc::getpid() };
    if !group_is_private {
        return Err(ProcessError::IoError {
            program: "process-guardian".into(),
            source: std::io::Error::other("guardian is not its process-group leader"),
        });
    }

    let mut line = Vec::new();
    std::io::BufReader::new(std::io::stdin().lock())
        .read_until(b'\n', &mut line)
        .map_err(|source| ProcessError::IoError {
            program: "process-guardian".into(),
            source,
        })?;
    let spec: CommandSpec =
        serde_json::from_slice(&line).map_err(|source| ProcessError::IoError {
            program: "process-guardian".into(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, source),
        })?;
    // The protocol child must not retain the guardian endpoint or it would
    // keep its own lifeline open after custodian death. CLOEXEC preserves the
    // guardian's descriptor while closing it in the managed program at exec.
    // SAFETY: `fd` was inherited from the custodian and validated above.
    #[allow(unsafe_code)]
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(ProcessError::IoError {
            program: "process-guardian".into(),
            source: std::io::Error::last_os_error(),
        });
    }
    let program = spec.program.clone();
    let mut command = std::process::Command::new(&spec.program);
    command.args(&spec.args);
    if spec.env_clear {
        command.env_clear();
    }
    command.envs(&spec.env);
    if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }
    command
        .stdin(if spec.stdin_bytes.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|source| ProcessError::IoError {
        program: program.clone(),
        source,
    })?;
    if let Some(bytes) = spec.stdin_bytes {
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(&bytes)
                .map_err(|source| ProcessError::IoError {
                    program: program.clone(),
                    source,
                })?;
        }
    }
    std::io::stdout()
        .lock()
        .write_all(b"READY\n")
        .and_then(|()| std::io::stdout().lock().flush())
        .map_err(|source| ProcessError::IoError {
            program: "process-guardian".into(),
            source,
        })?;

    loop {
        let mut poll_fd = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        // SAFETY: `poll_fd` is a valid one-element array for this syscall.
        #[allow(unsafe_code)]
        let poll_result = unsafe { libc::poll(&raw mut poll_fd, 1, 25) };
        if poll_result < 0
            && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
        {
            return Err(ProcessError::IoError {
                program: "process-guardian".into(),
                source: std::io::Error::last_os_error(),
            });
        }
        if poll_result > 0
            && poll_fd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
        {
            kill_guardian_group();
        }
        if child
            .try_wait()
            .map_err(|source| ProcessError::IoError {
                program: program.clone(),
                source,
            })?
            .is_some()
        {
            kill_guardian_group();
        }
    }
}

fn kill_guardian_group() -> ! {
    // SAFETY: PID zero targets this process's private group, verified above.
    #[allow(unsafe_code)]
    unsafe {
        libc::kill(0, libc::SIGKILL);
        libc::_exit(127);
    }
}

#[cfg(unix)]
fn process_group_exists(child: &Child) -> Result<bool, ProcessError> {
    let pid = i32::try_from(child.id()).map_err(|_| ProcessError::IoError {
        program: "managed-child".into(),
        source: std::io::Error::other("child PID exceeds pid_t"),
    })?;
    // SAFETY: signal zero is an existence/permission probe for the group.
    #[allow(unsafe_code)]
    let status = unsafe { libc::kill(-pid, 0) };
    if status == 0 {
        return Ok(true);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(ProcessError::IoError {
            program: "managed-child".into(),
            source: std::io::Error::last_os_error(),
        }),
    }
}

#[cfg(unix)]
fn signal_process_group(child: Option<&OwnedProcess>, signal: i32) -> Result<(), ProcessError> {
    let Some(child) = child else { return Ok(()) };
    let pid = i32::try_from(child.guardian.id()).map_err(|_| ProcessError::IoError {
        program: "managed-child".into(),
        source: std::io::Error::other("child PID exceeds pid_t"),
    })?;
    // SAFETY: the child was spawned as process-group leader. A negative PID
    // targets that group and carries no Rust memory invariants.
    #[allow(unsafe_code)]
    let status = unsafe { libc::kill(-pid, signal) };
    if status == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(ProcessError::IoError {
            program: "managed-child".into(),
            source: std::io::Error::last_os_error(),
        })
    }
}

#[cfg(not(unix))]
fn signal_process_group(_child: Option<&OwnedProcess>, _signal: i32) -> Result<(), ProcessError> {
    Err(ProcessError::IoError {
        program: "managed-child".into(),
        source: std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "managed process groups are not implemented on this platform",
        ),
    })
}

impl Default for RealRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl RealRunner {
    /// Construct a real runner with a fresh multi-threaded tokio runtime.
    ///
    /// # Panics
    ///
    /// Panics if the runtime cannot be constructed — runtime build failure is
    /// unrecoverable for a process whose subprocesses all flow through this
    /// runner. Callers wanting graceful handling should use [`Self::try_new`].
    #[must_use]
    pub fn new() -> Self {
        Self::try_new().expect("tokio runtime should be constructible at startup")
    }

    /// Construct a real runner with a fresh multi-threaded tokio runtime,
    /// returning the build error if construction fails.
    pub fn try_new() -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("vortix-subprocess")
            .build()?;
        Ok(Self {
            runtime: Arc::new(runtime),
        })
    }

    /// Borrow the underlying runtime handle for callers that need to drive
    /// other async work on the same runtime (e.g., spawning background
    /// telemetry tasks once everything is async).
    #[must_use]
    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    /// Synchronous wrapper around [`Trait::run`].
    pub fn run_blocking(&self, spec: CommandSpec) -> Result<CommandOutcome, ProcessError> {
        self.runtime.block_on(<Self as Trait>::run(self, spec))
    }

    /// Synchronous wrapper around [`Trait::spawn_detached`].
    pub fn spawn_detached_blocking(
        &self,
        spec: CommandSpec,
    ) -> Result<DetachedHandle, ProcessError> {
        self.runtime
            .block_on(<Self as Trait>::spawn_detached(self, spec))
    }

    fn check_privilege(spec: &CommandSpec) -> Result<(), ProcessError> {
        if spec.requires_privilege == PrivilegeReq::Root && !crate::utils::is_root() {
            return Err(ProcessError::PrivilegeDenied {
                program: spec.program.clone(),
            });
        }
        Ok(())
    }
}

impl Trait for RealRunner {
    #[allow(clippy::too_many_lines)]
    async fn run(&self, spec: CommandSpec) -> Result<CommandOutcome, ProcessError> {
        Self::check_privilege(&spec)?;

        let started_at = SystemTime::now();
        let start = Instant::now();

        let redacted_args = redact_args(&spec.args, &spec.redact_in_audit);
        info!(
            target: "vortix::process",
            program = %spec.program,
            args = ?redacted_args,
            requires_privilege = ?spec.requires_privilege,
            kind = ?spec.kind,
            "subprocess.start"
        );

        let mut cmd = Command::new(&spec.program);
        cmd.args(&spec.args);
        if spec.env_clear {
            cmd.env_clear();
        }
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        if let Some(cwd) = &spec.cwd {
            cmd.current_dir(cwd);
        }
        cmd.stdin(if spec.stdin_bytes.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        // Daemonizing subprocesses (e.g. `openvpn --daemon`) fork()+detach.
        // The grandchild inherits the parent's pipe write-ends and may keep
        // them open indefinitely, so `wait_with_output()` would block forever
        // waiting for pipe EOF even after the parent exits cleanly. Route
        // stdout/stderr to /dev/null instead — the caller is responsible for
        // surfacing diagnostics via an alternate channel (e.g. `--log` file).
        if spec.daemonizes {
            cmd.stdout(Stdio::null());
            cmd.stderr(Stdio::null());
        } else {
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());
        }

        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ProcessError::ProgramNotFound {
                    program: spec.program.clone(),
                }
            } else {
                ProcessError::IoError {
                    program: spec.program.clone(),
                    source: e,
                }
            }
        })?;

        // Optionally write stdin.
        if let Some(stdin_bytes) = &spec.stdin_bytes {
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(stdin_bytes)
                    .await
                    .map_err(|e| ProcessError::IoError {
                        program: spec.program.clone(),
                        source: e,
                    })?;
                drop(stdin);
            }
        }

        // Wait with optional timeout. Daemonizing subprocesses take the
        // `wait()`-only path (we routed their stdio to /dev/null above, so
        // there are no pipes to drain); everything else uses
        // `wait_with_output()` to capture stdout/stderr.
        let (status, stdout, stderr) = if spec.daemonizes {
            let status = if let Some(timeout) = spec.timeout {
                let Ok(result) = tokio::time::timeout(timeout, child.wait()).await else {
                    warn!(
                        target: "vortix::process",
                        program = %spec.program,
                        duration_ms = %timeout.as_millis(),
                        "subprocess.timeout"
                    );
                    return Err(ProcessError::Timeout {
                        program: spec.program.clone(),
                        duration: timeout,
                    });
                };
                result.map_err(|e| ProcessError::IoError {
                    program: spec.program.clone(),
                    source: e,
                })?
            } else {
                child.wait().await.map_err(|e| ProcessError::IoError {
                    program: spec.program.clone(),
                    source: e,
                })?
            };
            (status, Vec::new(), Vec::new())
        } else if let Some(limit) = spec.output_limit {
            let stdout = child.stdout.take().ok_or_else(|| ProcessError::IoError {
                program: spec.program.clone(),
                source: std::io::Error::other("child stdout pipe unavailable"),
            })?;
            let stderr = child.stderr.take().ok_or_else(|| ProcessError::IoError {
                program: spec.program.clone(),
                source: std::io::Error::other("child stderr pipe unavailable"),
            })?;
            let stdout_task = tokio::spawn(drain_bounded(stdout, limit));
            let stderr_task = tokio::spawn(drain_bounded(stderr, limit));
            let status = if let Some(timeout) = spec.timeout {
                let Ok(result) = tokio::time::timeout(timeout, child.wait()).await else {
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                    return Err(ProcessError::Timeout {
                        program: spec.program.clone(),
                        duration: timeout,
                    });
                };
                result.map_err(|source| ProcessError::IoError {
                    program: spec.program.clone(),
                    source,
                })?
            } else {
                child.wait().await.map_err(|source| ProcessError::IoError {
                    program: spec.program.clone(),
                    source,
                })?
            };
            let (stdout, stdout_overflow) = stdout_task
                .await
                .map_err(|error| ProcessError::IoError {
                    program: spec.program.clone(),
                    source: std::io::Error::other(error.to_string()),
                })?
                .map_err(|source| ProcessError::IoError {
                    program: spec.program.clone(),
                    source,
                })?;
            let (stderr, stderr_overflow) = stderr_task
                .await
                .map_err(|error| ProcessError::IoError {
                    program: spec.program.clone(),
                    source: std::io::Error::other(error.to_string()),
                })?
                .map_err(|source| ProcessError::IoError {
                    program: spec.program.clone(),
                    source,
                })?;
            if stdout_overflow || stderr_overflow {
                return Err(ProcessError::OutputLimitExceeded {
                    program: spec.program.clone(),
                    limit,
                });
            }
            (status, stdout, stderr)
        } else {
            let output = if let Some(timeout) = spec.timeout {
                let Ok(result) = tokio::time::timeout(timeout, child.wait_with_output()).await
                else {
                    warn!(
                        target: "vortix::process",
                        program = %spec.program,
                        duration_ms = %timeout.as_millis(),
                        "subprocess.timeout"
                    );
                    return Err(ProcessError::Timeout {
                        program: spec.program.clone(),
                        duration: timeout,
                    });
                };
                result.map_err(|e| ProcessError::IoError {
                    program: spec.program.clone(),
                    source: e,
                })?
            } else {
                child
                    .wait_with_output()
                    .await
                    .map_err(|e| ProcessError::IoError {
                        program: spec.program.clone(),
                        source: e,
                    })?
            };
            (output.status, output.stdout, output.stderr)
        };

        let duration = start.elapsed();
        let exit_status = ExitStatusInfo {
            code: status.code(),
            signal: signal_from_status(status),
            success: status.success(),
        };

        info!(
            target: "vortix::process",
            program = %spec.program,
            success = %exit_status.success,
            code = ?exit_status.code,
            duration_ms = %duration.as_millis(),
            "subprocess.end"
        );

        Ok(CommandOutcome {
            stdout,
            stderr,
            exit_status,
            duration,
            started_at,
        })
    }

    async fn spawn_detached(&self, spec: CommandSpec) -> Result<DetachedHandle, ProcessError> {
        Self::check_privilege(&spec)?;

        if spec.kind != Kind::DetachedSpawn {
            debug!(
                target: "vortix::process",
                "spawn_detached called on a OneShot spec; treating as detached anyway"
            );
        }

        let spawned_at = SystemTime::now();
        let redacted_args = redact_args(&spec.args, &spec.redact_in_audit);
        info!(
            target: "vortix::process",
            program = %spec.program,
            args = ?redacted_args,
            requires_privilege = ?spec.requires_privilege,
            "subprocess.spawn_detached"
        );

        let mut cmd = Command::new(&spec.program);
        cmd.args(&spec.args);
        if spec.env_clear {
            cmd.env_clear();
        }
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        if let Some(cwd) = &spec.cwd {
            cmd.current_dir(cwd);
        }
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());

        let child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ProcessError::ProgramNotFound {
                    program: spec.program.clone(),
                }
            } else {
                ProcessError::IoError {
                    program: spec.program.clone(),
                    source: e,
                }
            }
        })?;

        let pid = child.id().ok_or_else(|| ProcessError::IoError {
            program: spec.program.clone(),
            source: std::io::Error::other("no pid available for spawned child"),
        })?;

        // Drop the Child handle without awaiting — on Unix the kernel keeps the
        // detached child alive; vortix tracks liveness via subsequent `kill -0 <pid>`
        // OneShot calls.
        drop(child);

        Ok(DetachedHandle { pid, spawned_at })
    }
}

#[cfg(unix)]
fn signal_from_status(status: std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn signal_from_status(_status: std::process::ExitStatus) -> Option<i32> {
    None
}

fn redact_args(args: &[String], redact_indices: &[usize]) -> Vec<String> {
    args.iter()
        .enumerate()
        .map(|(i, a)| {
            if redact_indices.contains(&i) {
                "***REDACTED***".to_string()
            } else {
                a.clone()
            }
        })
        .collect()
}
