//! `vortix-process`: concrete `CommandRunner` implementations.
//!
//! Owns the tokio + tracing dependency surface. Exposes `CommandRunner` as an
//! `enum_dispatch`-driven enum carrying `Real(RealRunner)` and `Mock(MockRunner)`
//! variants. Callers hold the enum by value; static dispatch, no `Box<dyn>`.
//!
//! See `docs/plans/2026-05-24-002-feat-commandrunner-port-plan.md`.

#![allow(clippy::missing_errors_doc)]

pub mod mock;
pub mod orphan_scan;
pub mod real;

pub use mock::MockRunner;
pub use orphan_scan::{scan_orphans, OrphanProcess};
pub use real::RealRunner;

// Re-export the port types so callers don't have to depend on vortix-core directly
// just to construct specs.
pub use crate::vortix_core::ports::process::{
    CommandOutcome, CommandRunner as CommandRunnerTrait, CommandSpec, DetachedHandle,
    ExitStatusInfo, Kind, PrivilegeReq, ProcessError,
};

/// The enum carrier — held by value, dispatched statically.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum CommandRunner {
    Real(RealRunner),
    Mock(MockRunner),
}

impl CommandRunner {
    pub async fn run(&self, spec: CommandSpec) -> Result<CommandOutcome, ProcessError> {
        match self {
            CommandRunner::Real(r) => r.run(spec).await,
            CommandRunner::Mock(m) => m.run(spec).await,
        }
    }

    pub async fn spawn_detached(&self, spec: CommandSpec) -> Result<DetachedHandle, ProcessError> {
        match self {
            CommandRunner::Real(r) => r.spawn_detached(spec).await,
            CommandRunner::Mock(m) => m.spawn_detached(spec).await,
        }
    }

    /// Synchronous wrapper around `run`. Drives the async future via the
    /// runtime bundled in `RealRunner` (or directly for `MockRunner`, which
    /// never awaits). Use this from sync callers like the TUI loop and CLI
    /// commands until idea 3's `EngineHandle` makes the seam fully async.
    pub fn run_blocking(&self, spec: CommandSpec) -> Result<CommandOutcome, ProcessError> {
        match self {
            CommandRunner::Real(r) => r.run_blocking(spec),
            CommandRunner::Mock(m) => m.run_sync(spec),
        }
    }

    /// Synchronous wrapper around `spawn_detached`. See [`Self::run_blocking`].
    pub fn spawn_detached_blocking(
        &self,
        spec: CommandSpec,
    ) -> Result<DetachedHandle, ProcessError> {
        match self {
            CommandRunner::Real(r) => r.spawn_detached_blocking(spec),
            CommandRunner::Mock(m) => m.spawn_detached_sync(spec),
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
    /// bundled tokio runtime handle for spawning auxiliary tasks (plan 005
    /// journal writer).
    #[must_use]
    pub fn as_real(&self) -> Option<&RealRunner> {
        match self {
            Self::Real(r) => Some(r),
            Self::Mock(_) => None,
        }
    }

    /// Construct a mock runner that succeeds at every call.
    #[must_use]
    pub fn mock_default_success() -> Self {
        Self::Mock(MockRunner::with_default_success())
    }
}

impl Default for CommandRunner {
    fn default() -> Self {
        Self::mock_default_success()
    }
}

// ---------------------------------------------------------------------------
// Process-global runner — the migration seam used by all subprocess callsites.
//
// Plan 002 prescribes threading a `runner: CommandRunner` through the engine
// and supporting functions. For the v1 migration we use a `OnceLock<...>` so
// callsites can be replaced 1:1 without churning every API in the codebase.
// Plan 003 (idea 3's `EngineHandle`) replaces this global with proper
// dependency injection.
// ---------------------------------------------------------------------------

use std::sync::OnceLock;

static GLOBAL_RUNNER: OnceLock<CommandRunner> = OnceLock::new();

/// Set the process-wide runner. First call wins; subsequent calls are ignored.
///
/// `main()` calls this at startup with `CommandRunner::real()`. Test harnesses
/// can call it earlier with a `MockRunner` to redirect subprocess invocations.
pub fn set_global_runner(runner: CommandRunner) {
    let _ = GLOBAL_RUNNER.set(runner);
}

/// Get the process-wide runner. Lazily initialises with a default
/// (mock-default-success) if no explicit runner has been set — which is the
/// right behaviour for tests that don't touch subprocess paths.
pub fn global_runner() -> &'static CommandRunner {
    GLOBAL_RUNNER.get_or_init(CommandRunner::mock_default_success)
}

/// Run a one-shot subprocess through the process-wide runner.
pub fn run(spec: CommandSpec) -> Result<CommandOutcome, ProcessError> {
    global_runner().run_blocking(spec)
}

/// Spawn a detached subprocess through the process-wide runner.
pub fn spawn_detached(spec: CommandSpec) -> Result<DetachedHandle, ProcessError> {
    global_runner().spawn_detached_blocking(spec)
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
        Err(ProcessError::ProgramNotFound { program }) => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("`{program}` not found on PATH"),
        )),
        Err(ProcessError::PrivilegeDenied { program }) => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("`{program}` requires root"),
        )),
        Err(ProcessError::Killed { program, signal }) => Err(std::io::Error::other(format!(
            "`{program}` killed by signal {signal}"
        ))),
        Err(ProcessError::IoError { source, .. }) => Err(source),
    }
}

fn outcome_to_output(outcome: CommandOutcome) -> std::process::Output {
    let fallback_code = i32::from(!outcome.exit_status.success);
    make_output(
        outcome.exit_status.code.unwrap_or(fallback_code),
        outcome.stdout,
        outcome.stderr,
    )
}

#[cfg(unix)]
fn make_output(code: i32, stdout: Vec<u8>, stderr: Vec<u8>) -> std::process::Output {
    use std::os::unix::process::ExitStatusExt;
    std::process::Output {
        status: std::process::ExitStatus::from_raw(code << 8),
        stdout,
        stderr,
    }
}

#[cfg(not(unix))]
fn make_output(_code: i32, stdout: Vec<u8>, stderr: Vec<u8>) -> std::process::Output {
    std::process::Output {
        status: std::process::ExitStatus::default(),
        stdout,
        stderr,
    }
}
