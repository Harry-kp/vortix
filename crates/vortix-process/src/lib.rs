//! `vortix-process`: concrete `CommandRunner` implementations.
//!
//! Owns the tokio + tracing dependency surface. Exposes `CommandRunner` as an
//! `enum_dispatch`-driven enum carrying `Real(RealRunner)` and `Mock(MockRunner)`
//! variants. Callers hold the enum by value; static dispatch, no `Box<dyn>`.
//!
//! See `docs/plans/2026-05-24-002-feat-commandrunner-port-plan.md`.

#![allow(clippy::missing_errors_doc)]

pub mod mock;
pub mod real;

pub use mock::MockRunner;
pub use real::RealRunner;

// Re-export the port types so callers don't have to depend on vortix-core directly
// just to construct specs.
pub use vortix_core::ports::process::{
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

    pub async fn spawn_detached(
        &self,
        spec: CommandSpec,
    ) -> Result<DetachedHandle, ProcessError> {
        match self {
            CommandRunner::Real(r) => r.spawn_detached(spec).await,
            CommandRunner::Mock(m) => m.spawn_detached(spec).await,
        }
    }

    /// Construct the production runner.
    #[must_use]
    pub fn real() -> Self {
        Self::Real(RealRunner::new())
    }

    /// Construct a mock runner that succeeds at every call.
    #[must_use]
    pub fn mock_default_success() -> Self {
        Self::Mock(MockRunner::with_default_success())
    }
}
