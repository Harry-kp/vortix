//! `CommandRunner` port — the typed seam through which every subprocess flows.
//!
//! Concrete impls (`RealRunner`, `MockRunner`) live in `vortix-process`. This module
//! contains only the trait, the data types, and the error enum. No tokio dependency.
//!
//! See `docs/plans/2026-05-24-002-feat-commandrunner-port-plan.md` for the design.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// What privilege level a `CommandSpec` requires.
///
/// `RealRunner` checks the running uid against this requirement and fails fast with
/// `ProcessError::PrivilegeDenied` when the requirement is unmet — vortix does NOT
/// auto-escalate. Privilege resolution is the daemon's job (see idea 4 Phase B).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PrivilegeReq {
    /// Runs as the current user. Used for read-only ops (`wg show`, `ps`, `which`, etc.).
    #[default]
    None,
    /// Requires effective uid 0. Used for VPN tool invocation (`wg-quick`, `openvpn`,
    /// `iptables`, `pfctl`, etc.).
    Root,
}

/// Lifetime of a subprocess invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Kind {
    /// Run-to-completion; the runner waits for stdout/stderr/exit.
    #[default]
    OneShot,
    /// Fire-and-forget detached spawn (e.g., `openvpn --daemon`). Returns a
    /// `DetachedHandle` carrying the PID; vortix manages liveness via subsequent
    /// `OneShot` calls to `kill -0 <pid>`.
    DetachedSpawn,
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
    pub requires_privilege: PrivilegeReq,
    pub kind: Kind,
    /// Arg indices to redact in `tracing` audit logs. Used by callers that pass
    /// secret material (e.g., file paths in `/tmp/vortix-*.conf`) as args.
    /// Today vortix has no such callsite; the field is reserved for plan 006's
    /// SecretStore-aware Tunnel impls.
    pub redact_in_audit: Vec<usize>,
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
            requires_privilege: PrivilegeReq::None,
            kind: Kind::OneShot,
            redact_in_audit: Vec::new(),
        }
    }

    /// Construct a default `DetachedSpawn` spec.
    pub fn detached(program: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            kind: Kind::DetachedSpawn,
            ..Self::oneshot(program, args)
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

/// Handle to a detached child process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetachedHandle {
    pub pid: u32,
    pub spawned_at: SystemTime,
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
    /// The program could not be found on PATH (`exec` returned ENOENT).
    #[error("subprocess `{program}` not found on PATH")]
    ProgramNotFound { program: String },
    /// The subprocess did not complete within the configured timeout.
    #[error("subprocess `{program}` timed out after {duration:?}")]
    Timeout { program: String, duration: Duration },
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

/// The trait every subprocess invocation flows through.
///
/// Implementations live in `vortix-process` (`RealRunner` for production, `MockRunner`
/// for tests). The trait uses native AFIT (Rust 1.75+); the `vortix-process` crate
/// provides an `enum_dispatch`-driven enum wrapper that callers hold by value.
pub trait CommandRunner: Send + Sync {
    /// Run a one-shot subprocess to completion.
    fn run(
        &self,
        spec: CommandSpec,
    ) -> impl std::future::Future<Output = Result<CommandOutcome, ProcessError>> + Send;

    /// Spawn a detached child and return its PID.
    ///
    /// On Unix, the child survives the parent's `Child` handle being dropped. On
    /// Windows (future), this requires `Child::forget()` — out of scope today.
    fn spawn_detached(
        &self,
        spec: CommandSpec,
    ) -> impl std::future::Future<Output = Result<DetachedHandle, ProcessError>> + Send;
}
