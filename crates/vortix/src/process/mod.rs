//! Every subprocess goes through here: `CommandRunner` is the real runner,
//! or a scripted mock in tests.
//!

#![allow(clippy::missing_errors_doc)]

pub mod custodian;
#[cfg(test)]
pub mod mock;
pub mod orphan_scan;
pub mod real;

pub use custodian::{CustodianError, CustodianHandshake, StandardCustodian};
#[cfg(test)]
pub use mock::MockRunner;
pub use orphan_scan::{filter_untracked, scan_orphans, OrphanProcess};
pub use real::{RealProcessLifecycle, RealRunner};

/// The enum carrier — held by value, dispatched statically.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum CommandRunner {
    Real(RealRunner),
    #[cfg(test)]
    Mock(MockRunner),
}

impl CommandRunner {
    pub async fn run(&self, spec: CommandSpec) -> Result<CommandOutcome, ProcessError> {
        match self {
            CommandRunner::Real(r) => r.run(spec).await,
            #[cfg(test)]
            CommandRunner::Mock(m) => m.run_sync(spec),
        }
    }

    /// Synchronous wrapper around `run`. Drives the async future via the
    /// runtime bundled in `RealRunner` (or directly for `MockRunner`, which
    /// never awaits). Used by the synchronous TUI loop and CLI commands.
    pub fn run_blocking(&self, spec: CommandSpec) -> Result<CommandOutcome, ProcessError> {
        match self {
            CommandRunner::Real(r) => r.run_blocking(spec),
            #[cfg(test)]
            CommandRunner::Mock(m) => m.run_sync(spec),
        }
    }

    /// Construct the production runner.
    #[must_use]
    pub fn real() -> Self {
        Self::Real(RealRunner::new())
    }

    /// Borrow the production runner variant, if this enum is `Real`.
    ///
    /// Returns `None` for the `Mock` variant. Used by `main.rs` to grab the
    /// bundled tokio runtime handle for spawning auxiliary tasks.
    #[must_use]
    pub fn as_real(&self) -> Option<&RealRunner> {
        match self {
            Self::Real(r) => Some(r),
            #[cfg(test)]
            Self::Mock(_) => None,
        }
    }

    /// Construct a mock runner that succeeds at every call.
    #[cfg(test)]
    #[must_use]
    pub fn mock_default_success() -> Self {
        Self::Mock(MockRunner::with_default_success())
    }
}

use std::sync::OnceLock;

static GLOBAL_RUNNER: OnceLock<CommandRunner> = OnceLock::new();

/// Get the process-wide runner. Unit tests that never install one get a
/// mock that succeeds at every call; everything else gets the real runner,
/// so a missing setup can never turn commands into silent successes.
pub fn global_runner() -> &'static CommandRunner {
    #[cfg(test)]
    {
        GLOBAL_RUNNER.get_or_init(CommandRunner::mock_default_success)
    }
    #[cfg(not(test))]
    {
        GLOBAL_RUNNER.get_or_init(CommandRunner::real)
    }
}

/// Run a one-shot subprocess through the process-wide runner.
pub fn run(spec: CommandSpec) -> Result<CommandOutcome, ProcessError> {
    global_runner().run_blocking(spec)
}

/// Adapter: run a spec and return an `std::process::Output`-shaped result.
///
/// Many existing callsites match against `std::process::Output`, treating both
/// non-zero exit and I/O errors uniformly. This helper preserves that shape so
/// the migration stays mechanical — `NonZeroExit` becomes a successful
/// `Output` with a non-success status, and only spawn/I/O failures become
/// `Err(std::io::Error)`.
pub fn run_to_output(spec: CommandSpec) -> std::io::Result<std::process::Output> {
    match run(spec) {
        Ok(outcome) => Ok(outcome_to_output(outcome)),
        Err(ProcessError::NonZeroExit { code, stderr, .. }) => {
            Ok(make_output(code.unwrap_or(1), Vec::new(), stderr))
        }
        Err(ProcessError::Timeout { program, duration }) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("`{program}` timed out after {duration:?}"),
        )),
        Err(ProcessError::OutputLimitExceeded { program, limit }) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("`{program}` output exceeded {limit} bytes"),
        )),
        Err(ProcessError::ProgramNotFound { program }) => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("`{program}` not found on PATH"),
        )),
        Err(ProcessError::PrivilegeDenied { program }) => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("`{program}` requires root"),
        )),
        Err(ProcessError::InvalidCredentials { program, reason }) => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("`{program}` has invalid owner credentials: {reason}"),
        )),
        Err(ProcessError::Killed { program, signal }) => Err(std::io::Error::other(format!(
            "`{program}` killed by signal {signal}"
        ))),
        Err(ProcessError::IoError { source, .. }) => Err(source),
    }
}

/// Run a simple unprivileged command and discard invocation errors.
///
/// This helper is used by scanner probes, which must never retain a blocking
/// worker indefinitely during control-runtime shutdown.
#[must_use]
pub fn simple_output(program: &str, args: &[&str]) -> Option<std::process::Output> {
    let args = args.iter().map(|arg| (*arg).to_string()).collect();
    run_to_output(
        CommandSpec::oneshot(program, args)
            .timeout(std::time::Duration::from_secs(2))
            .output_limit(1024 * 1024),
    )
    .ok()
}

fn outcome_to_output(outcome: CommandOutcome) -> std::process::Output {
    let fallback_code = i32::from(!outcome.exit_status.success);
    make_output(
        outcome.exit_status.code.unwrap_or(fallback_code),
        outcome.stdout,
        outcome.stderr,
    )
}

fn make_output(code: i32, stdout: Vec<u8>, stderr: Vec<u8>) -> std::process::Output {
    use std::os::unix::process::ExitStatusExt;
    std::process::Output {
        status: std::process::ExitStatus::from_raw(code << 8),
        stdout,
        stderr,
    }
}

use std::collections::HashMap;
use std::fs::File;
use std::io::Read as _;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::profile::ProfileId;

/// What privilege level a `CommandSpec` requires.
///
/// `RealRunner` checks the running uid against this requirement and fails fast with
/// `ProcessError::PrivilegeDenied` when the requirement is unmet — vortix does NOT
/// auto-escalate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PrivilegeReq {
    /// Runs as the current user. Used for read-only ops (`wg show`, `ps`, `which`, etc.).
    #[default]
    None,
    /// Requires effective uid 0. Used for VPN tool invocation (`wg-quick`, `openvpn`,
    /// `iptables`, `pfctl`, etc.).
    Root,
}

/// Explicit non-root identity for an owner-run subprocess.
///
/// Supplying this never grants privilege: a non-root caller may name only
/// its current identity, while a root caller must drop all three credential
/// sets before `exec`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessCredentials {
    pub uid: u32,
    pub gid: u32,
    pub supplementary_groups: Vec<u32>,
}

/// The full specification of a subprocess invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    /// Optional environment variables. By default merged into the current process env;
    /// callers who need a clean env should set `env_clear = true`.
    pub env: HashMap<String, String>,
    pub env_clear: bool,
    pub cwd: Option<PathBuf>,
    pub stdin_bytes: Option<Vec<u8>>,
    pub timeout: Option<Duration>,
    /// Maximum bytes retained from each captured output stream. The runner
    /// continues draining the child after the limit so a noisy process cannot
    /// deadlock on a full pipe, then returns a typed overflow error.
    pub output_limit: Option<usize>,
    pub requires_privilege: PrivilegeReq,
    /// Arg indices to redact in `tracing` audit logs. Used by callers that pass
    /// secret material (e.g., file paths in `/tmp/vortix-*.conf`) as args.
    /// No current callsite uses this; the field is reserved for future use.
    pub redact_in_audit: Vec<usize>,
    /// Verified non-root credentials applied before `exec`.
    #[serde(default)]
    pub run_as: Option<ProcessCredentials>,
    /// Put the child in a new process group and contain descendants on
    /// timeout/cancellation. Required for lifecycle hooks.
    #[serde(default)]
    pub terminate_process_group: bool,
}

impl CommandSpec {
    /// Construct a default `OneShot` spec running as the current user.
    pub fn oneshot(program: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            program: program.into(),
            args,
            env: HashMap::new(),
            env_clear: false,
            cwd: None,
            stdin_bytes: None,
            timeout: None,
            output_limit: None,
            requires_privilege: PrivilegeReq::None,
            redact_in_audit: Vec::new(),
            run_as: None,
            terminate_process_group: false,
        }
    }

    /// Builder: require root.
    #[must_use]
    pub fn privilege(mut self, req: PrivilegeReq) -> Self {
        self.requires_privilege = req;
        self
    }

    /// Builder: set a timeout for `OneShot` invocations.
    #[must_use]
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout = Some(duration);
        self
    }

    /// Builder: bound each captured stdout/stderr stream.
    #[must_use]
    pub fn output_limit(mut self, bytes: usize) -> Self {
        self.output_limit = Some(bytes);
        self
    }

    /// Builder: feed stdin bytes.
    #[must_use]
    pub fn stdin(mut self, bytes: Vec<u8>) -> Self {
        self.stdin_bytes = Some(bytes);
        self
    }

    /// Builder: mark arg indices as secret (redacted in audit logs).
    #[must_use]
    pub fn redact_args(mut self, indices: impl IntoIterator<Item = usize>) -> Self {
        self.redact_in_audit = indices.into_iter().collect();
        self
    }

    /// Builder: execute under an already-verified non-root identity.
    #[must_use]
    pub fn run_as(mut self, credentials: ProcessCredentials) -> Self {
        self.run_as = Some(credentials);
        self
    }

    /// Builder: contain the child and descendants in a dedicated process group.
    #[must_use]
    pub fn contain_process_group(mut self) -> Self {
        self.terminate_process_group = true;
        self
    }
}

/// Subprocess exit status in a serde-friendly form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitStatusInfo {
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub success: bool,
}

/// Outcome of a `OneShot` subprocess invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandOutcome {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: ExitStatusInfo,
    pub duration: Duration,
    pub started_at: SystemTime,
}

impl CommandOutcome {
    /// Convenience: was the exit successful?
    #[must_use]
    pub fn success(&self) -> bool {
        self.exit_status.success
    }

    /// Convenience: stdout as a UTF-8 string (lossy).
    #[must_use]
    pub fn stdout_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.stdout)
    }

    /// Convenience: stderr as a UTF-8 string (lossy).
    #[must_use]
    pub fn stderr_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.stderr)
    }
}

/// Stable ownership key for a foreground protocol child.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ManagedProcessId {
    pub profile_id: ProfileId,
    /// Non-zero per-attempt generation. It is useful for diagnostics, but is
    /// never accepted as authentication on its own.
    pub generation: u64,
    /// Cryptographically opaque ownership capability. A stale handle cannot
    /// address a later child for the same stable profile identity.
    pub ownership_token: String,
}

impl ManagedProcessId {
    /// Allocate an identity before spawning the child so every cleanup path,
    /// including partial startup, is bound to the exact attempt.
    ///
    /// # Panics
    /// Never: the 8-byte prefix of a 32-byte buffer always converts.
    pub fn generate(profile_id: ProfileId) -> std::io::Result<Self> {
        let mut bytes = [0_u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        let ownership_token = crate::profile::hex(&bytes);
        let generation =
            u64::from_be_bytes(bytes[..8].try_into().expect("fixed-size prefix")).max(1);
        Ok(Self {
            profile_id,
            generation,
            ownership_token,
        })
    }

    #[must_use]
    pub fn has_valid_token(&self) -> bool {
        self.generation != 0
            && self.ownership_token.len() == 64
            && self
                .ownership_token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
}

/// Managed process-group ownership receipt. It contains no command arguments
/// or credentials. Concrete backends may return a containment guardian PID
/// rather than the protocol process PID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOwnership {
    pub identity: ManagedProcessId,
    pub pid: u32,
}

/// Process-lifecycle port used by the Standard-mode custodian. Protocol
/// adapters build the command specification; only the process layer spawns,
/// signals, waits for, and reaps the child.
pub trait ProcessLifecycle: Send + 'static {
    fn spawn_foreground(
        &mut self,
        identity: ManagedProcessId,
        spec: CommandSpec,
    ) -> Result<ProcessOwnership, ProcessError>;
    fn is_alive(&mut self, identity: &ManagedProcessId) -> Result<bool, ProcessError>;
    fn graceful_stop(&mut self, identity: &ManagedProcessId) -> Result<(), ProcessError>;
    fn wait_for_exit(
        &mut self,
        identity: &ManagedProcessId,
        timeout: Duration,
    ) -> Result<bool, ProcessError>;
    fn force_kill(&mut self, identity: &ManagedProcessId) -> Result<(), ProcessError>;
    fn reap(&mut self, identity: &ManagedProcessId) -> Result<(), ProcessError>;
}

/// What failed when invoking a subprocess.
///
/// Each variant carries enough context to populate the JSON envelope's `next_actions`
/// field at the CLI edge.
#[derive(Debug, Error)]
pub enum ProcessError {
    /// The spec required root but the running uid is not zero.
    #[error("subprocess `{program}` requires root but current uid is not 0")]
    PrivilegeDenied { program: String },
    /// Requested credential transition is unsafe or unavailable.
    #[error("subprocess `{program}` has invalid owner credentials: {reason}")]
    InvalidCredentials { program: String, reason: String },
    /// The program could not be found on PATH (`exec` returned ENOENT).
    #[error("subprocess `{program}` not found on PATH")]
    ProgramNotFound { program: String },
    /// The subprocess did not complete within the configured timeout.
    #[error("subprocess `{program}` timed out after {duration:?}")]
    Timeout { program: String, duration: Duration },
    /// A captured stream exceeded the caller's explicit memory bound.
    #[error("subprocess `{program}` output exceeded {limit} bytes")]
    OutputLimitExceeded { program: String, limit: usize },
    /// The subprocess exited non-zero.
    #[error("subprocess `{program}` exited with code {code:?}")]
    NonZeroExit {
        program: String,
        code: Option<i32>,
        stderr: Vec<u8>,
    },
    /// The subprocess was killed by a signal.
    #[error("subprocess `{program}` killed by signal {signal}")]
    Killed { program: String, signal: i32 },
    /// I/O error during spawn / stdin write / output read.
    #[error("subprocess `{program}` I/O error: {source}")]
    IoError {
        program: String,
        #[source]
        source: std::io::Error,
    },
}
