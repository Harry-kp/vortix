//! `MockRunner` — scriptable test fixture for the `CommandRunner` trait.
//!
//! Tests construct a runner with an ordered list of `(matcher, scripted_outcome)`
//! expectations. Calls not matching any remaining expectation panic with a clear
//! diagnostic. All invocations are recorded; tests can inspect via `invocations()`.
//!
//! For tests that don't care about subprocess behavior, `MockRunner::with_default_success()`
//! returns a runner where every call succeeds with empty stdout/stderr.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::vortix_core::ports::process::{
    CommandOutcome, CommandRunner as Trait, CommandSpec, DetachedHandle, ExitStatusInfo,
    ProcessError,
};

/// What a recorded invocation looks like.
#[derive(Debug, Clone)]
pub struct RecordedInvocation {
    pub program: String,
    pub args: Vec<String>,
    pub kind: crate::vortix_core::ports::process::Kind,
}

/// Matches a `CommandSpec` against expected criteria.
#[derive(Debug, Clone)]
pub enum SpecMatcher {
    /// Match any spec; useful for "I don't care, just succeed".
    Any,
    /// Match program name exactly; args ignored.
    ExactProgram(String),
    /// Match program + args (each arg matched against an `ArgMatcher`).
    ProgramWithArgs(String, Vec<ArgMatcher>),
}

#[derive(Debug, Clone)]
pub enum ArgMatcher {
    Exact(String),
    StartsWith(String),
    Any,
}

impl SpecMatcher {
    fn matches(&self, spec: &CommandSpec) -> bool {
        match self {
            SpecMatcher::Any => true,
            SpecMatcher::ExactProgram(p) => spec.program == *p,
            SpecMatcher::ProgramWithArgs(p, args) => {
                if spec.program != *p {
                    return false;
                }
                if spec.args.len() != args.len() {
                    return false;
                }
                spec.args.iter().zip(args).all(|(actual, m)| match m {
                    ArgMatcher::Exact(s) => actual == s,
                    ArgMatcher::StartsWith(s) => actual.starts_with(s),
                    ArgMatcher::Any => true,
                })
            }
        }
    }
}

/// Scripted response to a matched invocation.
#[derive(Debug, Clone)]
pub enum ScriptedOutcome {
    Success {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        exit_code: i32,
    },
    Failure(String), // error message; turned into ProcessError::NonZeroExit
    PrivilegeDenied,
    ProgramNotFound,
    Timeout,
    Detached {
        pid: u32,
    },
}

#[derive(Debug, Clone)]
struct Expectation {
    matcher: SpecMatcher,
    outcome: ScriptedOutcome,
}

#[derive(Debug, Default)]
struct Inner {
    expectations: Vec<Expectation>,
    invocations: Vec<RecordedInvocation>,
    default_success: bool,
}

/// Scriptable mock runner.
#[derive(Debug, Clone, Default)]
pub struct MockRunner {
    inner: Arc<Mutex<Inner>>,
}

impl MockRunner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Constructor: every call succeeds with empty output. Useful for tests that don't
    /// care about subprocess specifics.
    #[must_use]
    pub fn with_default_success() -> Self {
        let inner = Inner {
            default_success: true,
            ..Default::default()
        };
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    /// Builder: append an expectation.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (only possible if a previous
    /// expectation closure panicked while holding the lock — none do today).
    pub fn expect(&self, matcher: SpecMatcher, outcome: ScriptedOutcome) {
        self.inner
            .lock()
            .unwrap()
            .expectations
            .push(Expectation { matcher, outcome });
    }

    /// Read the full invocation log.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn invocations(&self) -> Vec<RecordedInvocation> {
        self.inner.lock().unwrap().invocations.clone()
    }

    /// Assert no expectations remain unconsumed.
    ///
    /// # Panics
    ///
    /// Panics if expectations remain — this is the intended failure mode.
    pub fn assert_no_remaining_expectations(&self) {
        let inner = self.inner.lock().unwrap();
        assert!(
            inner.expectations.is_empty(),
            "MockRunner has {} unconsumed expectations",
            inner.expectations.len(),
        );
    }

    /// Synchronous run — equivalent to `run` but doesn't require an async
    /// runtime. The mock never awaits, so this is exact.
    ///
    /// # Panics
    ///
    /// Panics if the call doesn't match a scripted expectation. This is the
    /// intended failure mode for tests.
    pub fn run_sync(&self, spec: CommandSpec) -> Result<CommandOutcome, ProcessError> {
        let outcome = self.next_outcome(&spec).unwrap_or_else(|msg| {
            panic!("{msg}");
        });
        Self::map_run_outcome(spec, outcome)
    }

    /// Synchronous `spawn_detached`.
    ///
    /// # Panics
    ///
    /// Panics on unmatched expectations (see [`Self::run_sync`]).
    pub fn spawn_detached_sync(&self, spec: CommandSpec) -> Result<DetachedHandle, ProcessError> {
        let outcome = self.next_outcome(&spec).unwrap_or_else(|msg| {
            panic!("{msg}");
        });
        Self::map_detached_outcome(spec, outcome)
    }

    fn map_run_outcome(
        spec: CommandSpec,
        outcome: ScriptedOutcome,
    ) -> Result<CommandOutcome, ProcessError> {
        match outcome {
            ScriptedOutcome::Success {
                stdout,
                stderr,
                exit_code,
            } => Ok(CommandOutcome {
                stdout,
                stderr,
                exit_status: ExitStatusInfo {
                    code: Some(exit_code),
                    signal: None,
                    success: exit_code == 0,
                },
                duration: Duration::from_millis(1),
                started_at: SystemTime::now(),
            }),
            ScriptedOutcome::Failure(stderr) => Err(ProcessError::NonZeroExit {
                program: spec.program,
                code: Some(1),
                stderr: stderr.into_bytes(),
            }),
            ScriptedOutcome::PrivilegeDenied => Err(ProcessError::PrivilegeDenied {
                program: spec.program,
            }),
            ScriptedOutcome::ProgramNotFound => Err(ProcessError::ProgramNotFound {
                program: spec.program,
            }),
            ScriptedOutcome::Timeout => Err(ProcessError::Timeout {
                program: spec.program,
                duration: spec.timeout.unwrap_or(Duration::from_secs(30)),
            }),
            ScriptedOutcome::Detached { .. } => {
                panic!("ScriptedOutcome::Detached returned from run(); use spawn_detached")
            }
        }
    }

    fn map_detached_outcome(
        spec: CommandSpec,
        outcome: ScriptedOutcome,
    ) -> Result<DetachedHandle, ProcessError> {
        match outcome {
            ScriptedOutcome::Detached { pid } => Ok(DetachedHandle {
                pid,
                spawned_at: SystemTime::now(),
            }),
            ScriptedOutcome::Success { .. } => Ok(DetachedHandle {
                pid: 99999,
                spawned_at: SystemTime::now(),
            }),
            ScriptedOutcome::Failure(stderr) => Err(ProcessError::NonZeroExit {
                program: spec.program,
                code: Some(1),
                stderr: stderr.into_bytes(),
            }),
            ScriptedOutcome::PrivilegeDenied => Err(ProcessError::PrivilegeDenied {
                program: spec.program,
            }),
            ScriptedOutcome::ProgramNotFound => Err(ProcessError::ProgramNotFound {
                program: spec.program,
            }),
            ScriptedOutcome::Timeout => Err(ProcessError::Timeout {
                program: spec.program,
                duration: Duration::from_secs(30),
            }),
        }
    }

    fn next_outcome(&self, spec: &CommandSpec) -> Result<ScriptedOutcome, String> {
        let mut inner = self.inner.lock().unwrap();
        inner.invocations.push(RecordedInvocation {
            program: spec.program.clone(),
            args: spec.args.clone(),
            kind: spec.kind,
        });

        if inner.default_success {
            return Ok(ScriptedOutcome::Success {
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_code: 0,
            });
        }

        if inner.expectations.is_empty() {
            return Err(format!(
                "unexpected MockRunner call: program={:?} args={:?}",
                spec.program, spec.args
            ));
        }

        // Pop the next expectation and verify it matches.
        let expectation = inner.expectations.remove(0);
        if expectation.matcher.matches(spec) {
            Ok(expectation.outcome)
        } else {
            Err(format!(
                "MockRunner expectation mismatch: matcher={:?}, actual program={:?} args={:?}",
                expectation.matcher, spec.program, spec.args
            ))
        }
    }
}

impl Trait for MockRunner {
    async fn run(&self, spec: CommandSpec) -> Result<CommandOutcome, ProcessError> {
        self.run_sync(spec)
    }

    async fn spawn_detached(&self, spec: CommandSpec) -> Result<DetachedHandle, ProcessError> {
        self.spawn_detached_sync(spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::ports::process::PrivilegeReq;

    #[tokio::test]
    async fn default_success_works() {
        let runner = MockRunner::with_default_success();
        let outcome = runner
            .run(CommandSpec::oneshot("anything", vec!["arg".into()]))
            .await
            .unwrap();
        assert!(outcome.success());
        assert_eq!(runner.invocations().len(), 1);
    }

    #[tokio::test]
    async fn scripted_success() {
        let runner = MockRunner::new();
        runner.expect(
            SpecMatcher::ProgramWithArgs(
                "wg-quick".into(),
                vec![ArgMatcher::Exact("up".into()), ArgMatcher::Any],
            ),
            ScriptedOutcome::Success {
                stdout: b"ok".to_vec(),
                stderr: Vec::new(),
                exit_code: 0,
            },
        );
        // xtask:allow-protocol-leak: mock-runner test fixture, not a real wg-quick invocation
        let outcome = runner
            .run(
                CommandSpec::oneshot("wg-quick", vec!["up".into(), "corp".into()])
                    .privilege(PrivilegeReq::Root),
            )
            .await
            .unwrap();
        assert!(outcome.success());
        assert_eq!(outcome.stdout, b"ok");
        runner.assert_no_remaining_expectations();
    }

    #[tokio::test]
    async fn scripted_failure_returns_error() {
        let runner = MockRunner::new();
        runner.expect(
            SpecMatcher::ExactProgram("wg-quick".into()),
            ScriptedOutcome::Failure("Address already in use".into()),
        );
        // xtask:allow-protocol-leak: mock-runner test fixture, not a real wg-quick invocation
        let result = runner
            .run(CommandSpec::oneshot("wg-quick", vec!["up".into()]))
            .await;
        assert!(matches!(result, Err(ProcessError::NonZeroExit { .. })));
    }

    #[tokio::test]
    async fn detached_returns_pid() {
        let runner = MockRunner::new();
        runner.expect(
            SpecMatcher::ExactProgram("openvpn".into()),
            ScriptedOutcome::Detached { pid: 12345 },
        );
        // xtask:allow-protocol-leak: mock-runner test fixture, not a real openvpn invocation
        let handle = runner
            .spawn_detached(CommandSpec::detached("openvpn", vec!["--daemon".into()]))
            .await
            .unwrap();
        assert_eq!(handle.pid, 12345);
    }

    #[tokio::test]
    #[should_panic(expected = "unexpected MockRunner call")]
    async fn unexpected_call_panics() {
        let runner = MockRunner::new();
        let _ = runner.run(CommandSpec::oneshot("foo", vec![])).await;
    }
}
