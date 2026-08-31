//! Unprivileged lifecycle-hook adapter.

mod runner;

use std::path::Path;

use crate::vortix_core::control::ControlService;

pub use runner::{
    HookAttemptId, HookDiagnostic, HookDiagnosticKind, HookDiagnostics, HookDispatcher,
    HookFailure, HookOwnerError, HookRunner, VerifiedHookOwner,
};

const STARTUP_DIAGNOSTIC_MAX_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookStartupFailureKind {
    Configuration,
    Owner,
    Runner,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookStartupDiagnostic {
    pub kind: HookStartupFailureKind,
    pub message: String,
}

impl HookStartupDiagnostic {
    fn new(kind: HookStartupFailureKind, error: impl std::fmt::Display) -> Self {
        let mut message = error.to_string();
        if message.len() > STARTUP_DIAGNOSTIC_MAX_BYTES {
            let mut boundary = STARTUP_DIAGNOSTIC_MAX_BYTES;
            while !message.is_char_boundary(boundary) {
                boundary -= 1;
            }
            message.truncate(boundary);
        }
        Self { kind, message }
    }
}

/// Start owner-privileged observational hooks without making them part of
/// lifecycle correctness. Invalid configuration, unverifiable ownership, or
/// runner startup disables hooks and emits one bounded diagnostic.
pub(crate) fn start_standard_control_hooks(
    config_dir: &Path,
    service: &ControlService,
) -> Option<HookRunner> {
    match try_start_standard_control_hooks(config_dir, service) {
        Ok(runner) => runner,
        Err(diagnostic) => {
            tracing::warn!(
                kind = ?diagnostic.kind,
                message = %diagnostic.message,
                "lifecycle hooks disabled"
            );
            None
        }
    }
}

fn try_start_standard_control_hooks(
    config_dir: &Path,
    service: &ControlService,
) -> Result<Option<HookRunner>, HookStartupDiagnostic> {
    let settings =
        crate::vortix_config::Settings::load_from_config_dir(config_dir).map_err(|error| {
            HookStartupDiagnostic::new(HookStartupFailureKind::Configuration, error)
        })?;
    if settings.hooks.is_empty() {
        return Ok(None);
    }
    let owner = VerifiedHookOwner::for_standard_mode(config_dir)
        .map_err(|error| HookStartupDiagnostic::new(HookStartupFailureKind::Owner, error))?;
    let Some((mut hooks, _diagnostics)) = HookRunner::start(
        settings.hooks,
        owner,
        crate::vortix_process::global_runner().clone(),
    )
    .map_err(|error| HookStartupDiagnostic::new(HookStartupFailureKind::Runner, error))?
    else {
        return Ok(None);
    };
    hooks.attach_control(service.client().subscribe());
    Ok(Some(hooks))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_diagnostic_is_bounded() {
        let diagnostic = HookStartupDiagnostic::new(
            HookStartupFailureKind::Configuration,
            "x".repeat(STARTUP_DIAGNOSTIC_MAX_BYTES * 2),
        );
        assert_eq!(diagnostic.message.len(), STARTUP_DIAGNOSTIC_MAX_BYTES);

        let unicode = HookStartupDiagnostic::new(
            HookStartupFailureKind::Configuration,
            "é".repeat(STARTUP_DIAGNOSTIC_MAX_BYTES),
        );
        assert!(unicode.message.len() <= STARTUP_DIAGNOSTIC_MAX_BYTES);
    }

    #[tokio::test]
    async fn invalid_hook_configuration_is_a_typed_nonfatal_startup_diagnostic() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("settings.toml"), "hooks = [not-valid]").unwrap();
        let service =
            ControlService::start(crate::vortix_core::control::ControlServiceConfig::default());

        let Err(diagnostic) = try_start_standard_control_hooks(temp.path(), &service) else {
            panic!("invalid observational hooks must be disabled");
        };

        assert_eq!(diagnostic.kind, HookStartupFailureKind::Configuration);
        assert!(diagnostic.message.len() <= STARTUP_DIAGNOSTIC_MAX_BYTES);
    }
}
