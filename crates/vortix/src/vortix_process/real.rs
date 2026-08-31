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
        Ok(leader_alive || process_group_has_live_members(owned.guardian.id())?)
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
pub(super) fn process_group_has_live_members(group_id: u32) -> Result<bool, ProcessError> {
    match probe_process_group(group_id)? {
        ProcessGroupProbe::Absent => return Ok(false),
        ProcessGroupProbe::PermissionDenied => return Ok(true),
        ProcessGroupProbe::Signalable => {}
    }

    if let Ok(Some(has_live_members)) = crate::platform::process_group_has_live_members(group_id) {
        return Ok(has_live_members);
    }

    Ok(true)
}

#[cfg(unix)]
pub(super) fn process_is_nonleader_group_member(
    process_id: u32,
    group_id: u32,
) -> Result<bool, ProcessError> {
    if process_id == group_id {
        return Ok(false);
    }
    let process_id = i32::try_from(process_id).map_err(|_| ProcessError::IoError {
        program: "managed-child".into(),
        source: std::io::Error::other("process ID exceeds pid_t"),
    })?;
    let group_id = i32::try_from(group_id).map_err(|_| ProcessError::IoError {
        program: "managed-child".into(),
        source: std::io::Error::other("process-group ID exceeds pid_t"),
    })?;
    // SAFETY: getpgid reads one kernel process attribute and does not touch
    // Rust memory. ESRCH is authoritative absence; other errors fail closed.
    #[allow(unsafe_code)]
    let observed_group = unsafe { libc::getpgid(process_id) };
    if observed_group >= 0 {
        return Ok(observed_group == group_id);
    }
    let source = std::io::Error::last_os_error();
    match source.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        _ => Err(ProcessError::IoError {
            program: "managed-child".into(),
            source,
        }),
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessGroupProbe {
    Absent,
    Signalable,
    PermissionDenied,
}

#[cfg(unix)]
fn probe_process_group(group_id: u32) -> Result<ProcessGroupProbe, ProcessError> {
    let pid = i32::try_from(group_id).map_err(|_| ProcessError::IoError {
        program: "managed-child".into(),
        source: std::io::Error::other("process-group ID exceeds pid_t"),
    })?;
    // SAFETY: signal zero is an existence/permission probe for the group.
    #[allow(unsafe_code)]
    let status = unsafe { libc::kill(-pid, 0) };
    if status == 0 {
        return Ok(ProcessGroupProbe::Signalable);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => Ok(ProcessGroupProbe::Absent),
        Some(libc::EPERM) => Ok(ProcessGroupProbe::PermissionDenied),
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
        if let Some(credentials) = &spec.run_as {
            if credentials.uid == 0 || credentials.gid == 0 {
                return Err(ProcessError::InvalidCredentials {
                    program: spec.program.clone(),
                    reason: "owner-run subprocess must use a non-root uid and gid".into(),
                });
            }
            if spec.requires_privilege == PrivilegeReq::Root {
                return Err(ProcessError::InvalidCredentials {
                    program: spec.program.clone(),
                    reason: "a subprocess cannot require root and request credential drop".into(),
                });
            }
            if credentials.supplementary_groups.contains(&0) {
                return Err(ProcessError::InvalidCredentials {
                    program: spec.program.clone(),
                    reason: "owner-run subprocess cannot retain root supplementary groups".into(),
                });
            }
            if i32::try_from(credentials.supplementary_groups.len()).is_err() {
                return Err(ProcessError::InvalidCredentials {
                    program: spec.program.clone(),
                    reason: "too many supplementary groups".into(),
                });
            }
            let (process_user, process_group) = crate::utils::effective_user_group_ids();
            if process_user != 0
                && (process_user != credentials.uid || process_group != credentials.gid)
            {
                return Err(ProcessError::InvalidCredentials {
                    program: spec.program.clone(),
                    reason: "non-root caller may execute only as its current uid/gid".into(),
                });
            }
            if process_user != 0 && current_groups()? != credentials.supplementary_groups {
                return Err(ProcessError::InvalidCredentials {
                    program: spec.program.clone(),
                    reason: "non-root caller cannot change supplementary groups".into(),
                });
            }
        }
        if spec.terminate_process_group && spec.kind == Kind::DetachedSpawn {
            return Err(ProcessError::InvalidCredentials {
                program: spec.program.clone(),
                reason: "contained process groups cannot use detached spawn".into(),
            });
        }
        Ok(())
    }
}

fn configure_owner_process(command: &mut Command, spec: &CommandSpec) {
    command.kill_on_drop(spec.terminate_process_group);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;

        if spec.terminate_process_group {
            command.as_std_mut().process_group(0);
        }
        if crate::utils::effective_user_group_ids().0 == 0 {
            if let Some(credentials) = spec.run_as.clone() {
                let groups = credentials.supplementary_groups;
                let gid = credentials.gid;
                let uid = credentials.uid;
                #[allow(unsafe_code)]
                unsafe {
                    command
                        .as_std_mut()
                        .pre_exec(move || drop_credentials(&groups, gid, uid));
                }
            }
        }
    }
}

#[cfg(unix)]
fn drop_credentials(groups: &[u32], gid: u32, uid: u32) -> std::io::Result<()> {
    // SAFETY: pointers remain valid for the duration of each syscall and all
    // values were prepared before fork. Ordering prevents reacquiring privilege.
    crate::platform::set_process_supplementary_groups(groups)?;
    #[allow(unsafe_code)]
    unsafe {
        if libc::setgid(gid) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::setuid(uid) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn current_groups() -> Result<Vec<u32>, ProcessError> {
    // SAFETY: the first call obtains the required length; the second writes
    // into an allocated vector of exactly that length.
    #[allow(unsafe_code)]
    unsafe {
        let count = libc::getgroups(0, std::ptr::null_mut());
        if count < 0 {
            return Err(ProcessError::InvalidCredentials {
                program: "process-owner".into(),
                reason: std::io::Error::last_os_error().to_string(),
            });
        }
        let mut groups = vec![0; usize::try_from(count).unwrap_or(0)];
        if count > 0 && libc::getgroups(count, groups.as_mut_ptr()) < 0 {
            return Err(ProcessError::InvalidCredentials {
                program: "process-owner".into(),
                reason: std::io::Error::last_os_error().to_string(),
            });
        }
        Ok(groups)
    }
}

async fn terminate_child(child: &mut tokio::process::Child, process_group: bool) {
    #[cfg(unix)]
    if process_group {
        if let Some(pid) = child.id().and_then(|pid| i32::try_from(pid).ok()) {
            // SAFETY: the child was placed in a fresh group whose id is its pid.
            #[allow(unsafe_code)]
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    } else {
        let _ = child.start_kill();
    }
    #[cfg(not(unix))]
    let _ = child.start_kill();
    let _ = child.wait().await;
}

#[cfg(unix)]
struct ProcessGroupGuard(Option<i32>);

#[cfg(unix)]
impl ProcessGroupGuard {
    fn new(child: &tokio::process::Child, enabled: bool) -> Self {
        Self(
            enabled
                .then(|| child.id())
                .flatten()
                .and_then(|pid| i32::try_from(pid).ok()),
        )
    }

    fn contain_descendants(&mut self) {
        if let Some(pgid) = self.0.take() {
            // SAFETY: `pgid` belongs to the fresh child group created before
            // exec. Killing a missing group is harmless.
            #[allow(unsafe_code)]
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
        }
    }
}

#[cfg(unix)]
impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        self.contain_descendants();
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
        configure_owner_process(&mut cmd, &spec);
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
        #[cfg(unix)]
        let mut process_group = ProcessGroupGuard::new(&child, spec.terminate_process_group);

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
                    terminate_child(&mut child, spec.terminate_process_group).await;
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
            #[cfg(unix)]
            process_group.contain_descendants();
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
                    terminate_child(&mut child, spec.terminate_process_group).await;
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
            #[cfg(unix)]
            process_group.contain_descendants();
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
            #[cfg(unix)]
            process_group.contain_descendants();
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
        configure_owner_process(&mut cmd, &spec);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::ports::process::ProcessCredentials;

    #[test]
    fn explicit_owner_credentials_never_resolve_to_root() {
        let (process_user, process_group) = crate::utils::effective_user_group_ids();
        let (uid, gid) = if process_user == 0 {
            (65_534, 65_534)
        } else {
            (process_user, process_group)
        };
        let supplementary_groups = if process_user == 0 {
            Vec::new()
        } else {
            current_groups().unwrap()
        };
        let mut spec =
            CommandSpec::oneshot("/usr/bin/id", vec!["-u".into()]).run_as(ProcessCredentials {
                uid,
                gid,
                supplementary_groups,
            });
        spec.env_clear = true;
        let outcome = RealRunner::new().run_blocking(spec).unwrap();
        assert_eq!(outcome.stdout_lossy().trim(), uid.to_string());
        assert_ne!(uid, 0);
    }

    #[test]
    fn timeout_contains_hook_descendants() {
        let temp = tempfile::tempdir().unwrap();
        let pids = temp.path().join("pids");
        let script = "/bin/sleep 30 & echo \"$$ $!\" > \"$1\"; wait";
        let spec = CommandSpec::oneshot(
            "/bin/sh",
            vec![
                "-c".into(),
                script.into(),
                "vortix-hook-test".into(),
                pids.to_string_lossy().into_owned(),
            ],
        )
        .timeout(Duration::from_millis(250))
        .output_limit(1024)
        .contain_process_group();
        assert!(matches!(
            RealRunner::new().run_blocking(spec),
            Err(ProcessError::Timeout { .. })
        ));
        let recorded = std::fs::read_to_string(&pids).unwrap();
        let pids = recorded
            .split_whitespace()
            .map(|pid| pid.parse::<u32>().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(pids.len(), 2);
        for _ in 0..20 {
            if pids.iter().all(|pid| !process_is_live(*pid)) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("hook process group still has a live member: {pids:?}");
    }

    fn process_is_live(pid: u32) -> bool {
        let output = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .expect("ps must be installed for process-containment tests");
        let state = String::from_utf8_lossy(&output.stdout);
        let state = state.trim();
        !state.is_empty() && !state.starts_with('Z')
    }
}
