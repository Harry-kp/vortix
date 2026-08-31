//! Unprivileged lifecycle-hook adapter.

mod runner;

pub use runner::{
    HookAttemptId, HookDiagnostic, HookDiagnosticKind, HookDiagnostics, HookDispatcher,
    HookFailure, HookOwnerError, HookRunner, VerifiedHookOwner,
};
