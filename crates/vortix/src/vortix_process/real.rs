//! Production `CommandRunner` implementation backed by `tokio::process`.

use std::process::Stdio;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use crate::vortix_core::ports::process::{
    CommandOutcome, CommandRunner as Trait, CommandSpec, DetachedHandle, ExitStatusInfo, Kind,
    PrivilegeReq, ProcessError,
};
use tokio::io::AsyncWriteExt;
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
        if spec.requires_privilege == PrivilegeReq::Root && !is_root() {
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
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

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

        // Wait with optional timeout.
        let output = if let Some(timeout) = spec.timeout {
            let Ok(result) = tokio::time::timeout(timeout, child.wait_with_output()).await else {
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

        let duration = start.elapsed();
        let exit_status = ExitStatusInfo {
            code: output.status.code(),
            signal: signal_from_status(output.status),
            success: output.status.success(),
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
            stdout: output.stdout,
            stderr: output.stderr,
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

fn is_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` is a thread-safe getter with no side effects.
        #[allow(unsafe_code)]
        unsafe {
            libc::geteuid() == 0
        }
    }
    #[cfg(not(unix))]
    {
        false
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
