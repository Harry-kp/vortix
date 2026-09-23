//! Owner-run observational hooks fired on tunnel lifecycle events.

mod event;
mod runner;

use std::path::Path;

pub use event::{HookEvent, HookEventId, LifecycleFact};
pub use runner::{
    HookAttemptId, HookDiagnostic, HookDiagnosticKind, HookDiagnostics, HookDispatcher,
    HookFailure, HookOwnerError, HookRunner, VerifiedHookOwner,
};

/// Start the configured hooks, or `None` when there are none or they cannot
/// run. Hooks never affect lifecycle correctness. Must run inside a tokio
/// runtime.
pub(crate) fn start(config_dir: &Path) -> Option<HookRunner> {
    let started = (|| {
        let settings = crate::vortix_config::Settings::load_from_config_dir(config_dir)
            .map_err(|error| error.to_string())?;
        if settings.hooks.is_empty() {
            return Ok(None);
        }
        let owner =
            VerifiedHookOwner::for_standard_mode(config_dir).map_err(|error| error.to_string())?;
        HookRunner::start(
            settings.hooks,
            owner,
            crate::vortix_process::global_runner().clone(),
        )
        .map(|started| started.map(|(runner, _)| runner))
        .map_err(|error| error.to_string())
    })();
    started.unwrap_or_else(|error: String| {
        tracing::warn!(%error, "lifecycle hooks disabled");
        None
    })
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn invalid_hook_configuration_disables_hooks() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("settings.toml"), "hooks = [not-valid]").unwrap();
        assert!(super::start(temp.path()).is_none());
    }
}
