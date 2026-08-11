//! Prepared Background-mode UX contract.
//!
//! The preparatory release exposes the complete status/setup/recovery
//! vocabulary without granting daemon authority. A later enrollment-capable
//! release can replace the unavailable backend without changing this contract.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// User-visible operating mode. Variant names never appear directly in copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackgroundModeState {
    StandardActive,
    BackgroundEnabling,
    BackgroundActive,
    BackgroundDegraded,
    BackgroundDisabling,
    BackgroundRecoveryRequired,
}

impl BackgroundModeState {
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::StandardActive => "Standard mode: Active",
            Self::BackgroundEnabling => "Background mode: Enabling",
            Self::BackgroundActive => "Background mode: Active",
            Self::BackgroundDegraded => "Background mode: Degraded",
            Self::BackgroundDisabling => "Background mode: Disabling",
            Self::BackgroundRecoveryRequired => "Background mode: Recovery required",
        }
    }

    #[must_use]
    pub const fn header_signal(self) -> &'static str {
        match self {
            Self::StandardActive => "S· Standard",
            Self::BackgroundEnabling => "B… Enabling",
            Self::BackgroundActive => "B● Active",
            Self::BackgroundDegraded => "B! Degraded",
            Self::BackgroundDisabling => "B… Disabling",
            Self::BackgroundRecoveryRequired => "B! Recovery",
        }
    }
}

/// Actions admitted by a user-visible mode record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackgroundAction {
    Setup,
    Status,
    Recover,
    Diagnostics,
    Disable,
}

impl BackgroundAction {
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Status => "status",
            Self::Recover => "recover",
            Self::Diagnostics => "diagnostics",
            Self::Disable => "disable",
        }
    }
}

/// Authority truth shown on every Background-mode surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackgroundAuthority {
    StandardLocal,
    BackgroundControl,
    RecoveryUncertain,
}

impl BackgroundAuthority {
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::StandardLocal => "local Standard-mode control",
            Self::BackgroundControl => "enrolled Background control",
            Self::RecoveryUncertain => "recovery must verify one authority",
        }
    }
}

/// Protection truth shown on every Background-mode surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackgroundProtection {
    Unchanged,
    Verified,
    DegradedFailClosed,
}

impl BackgroundProtection {
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Verified => "verified",
            Self::DegradedFailClosed => "degraded; required blocking retained",
        }
    }
}

/// Shared projection consumed verbatim by CLI, JSON, and TUI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackgroundModeRecord {
    pub state: BackgroundModeState,
    pub reason: String,
    pub authority: BackgroundAuthority,
    pub protection: BackgroundProtection,
    pub permitted_actions: Vec<BackgroundAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackgroundCommandView {
    pub mode: BackgroundModeRecord,
    pub activation_available: bool,
    pub preview: Vec<String>,
}

impl BackgroundCommandView {
    #[must_use]
    pub fn prepared(preview: Vec<String>) -> Self {
        Self {
            mode: BackgroundModeRecord::prepared_standard(),
            activation_available: false,
            preview,
        }
    }
}

impl Default for BackgroundModeRecord {
    fn default() -> Self {
        Self::prepared_standard()
    }
}

impl BackgroundModeRecord {
    #[must_use]
    pub fn prepared_standard() -> Self {
        Self {
            state: BackgroundModeState::StandardActive,
            reason: "Background setup is prepared but enrollment is not enabled in this release; Standard mode remains fully available.".into(),
            authority: BackgroundAuthority::StandardLocal,
            protection: BackgroundProtection::Unchanged,
            permitted_actions: vec![
                BackgroundAction::Setup,
                BackgroundAction::Status,
                BackgroundAction::Recover,
                BackgroundAction::Diagnostics,
                BackgroundAction::Disable,
            ],
        }
    }

    #[must_use]
    pub const fn may_claim_background_authority(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackgroundWorkflow {
    Setup,
    Status,
    Recover,
    Disable,
}

impl BackgroundWorkflow {
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Setup => "Background setup",
            Self::Status => "Background status",
            Self::Recover => "Background recovery",
            Self::Disable => "Disable Background mode",
        }
    }

    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Setup => {
                "Background mode runs persistent Vortix processes to add routine control without sudo after setup, live CLI/TUI sync, automatic drop recovery, boot connections, and continuous policy verification."
            }
            Self::Status => {
                "Status is derived from one typed authority and health record. Advisory diagnostics never establish authority or protection."
            }
            Self::Recover => {
                "Recovery keeps required blocking, shows the failure reason and permitted cleanup, and changes nothing if cancelled before the destructive commit. Repeated failure remains retryable and fail-closed."
            }
            Self::Disable => {
                "Disable would stop live sync, automatic recovery, boot connections, and continuous verification, preview managed tunnels and kill-switch consequences, then require explicit confirmation."
            }
        }
    }

    #[must_use]
    pub const fn cancelled_preview(self) -> &'static str {
        match self {
            Self::Setup => {
                "Setup cancelled before elevation; Standard mode is unchanged. Re-run with --yes when you are ready."
            }
            Self::Status => {
                "Manual CLI/TUI VPN control remains available; Background capabilities require enrollment."
            }
            Self::Recover => {
                "Recovery cancelled before the destructive commit; authority and protection state are unchanged."
            }
            Self::Disable => {
                "Disable preview: Background mode would stop live sync, automatic recovery, boot connection, and continuous verification; cancellation changes nothing."
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackgroundFocus {
    Continue,
    Cancel,
}

impl BackgroundFocus {
    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::Continue => Self::Cancel,
            Self::Cancel => Self::Continue,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackgroundOverlayState {
    pub workflow: BackgroundWorkflow,
    pub focus: BackgroundFocus,
    pub scroll: u16,
    pub committed: bool,
}

impl BackgroundOverlayState {
    #[must_use]
    pub const fn new(workflow: BackgroundWorkflow) -> Self {
        Self {
            workflow,
            focus: BackgroundFocus::Continue,
            scroll: 0,
            committed: false,
        }
    }
}

/// Terminal operations required by a trusted-bootstrap consumer.
/// Keeping this seam typed lets tests prove restoration without invoking
/// `sudo`, a shell, or collecting an administrator password.
pub trait BackgroundTerminal {
    type Error;

    fn suspend(&mut self) -> Result<(), Self::Error>;
    fn restore(&mut self) -> Result<(), Self::Error>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum BackgroundTerminalError<TerminalError, OperationError> {
    Suspend(TerminalError),
    Operation(OperationError),
    Restore(TerminalError),
}

struct TerminalRestoreGuard<'a, T: BackgroundTerminal> {
    terminal: Option<&'a mut T>,
}

impl<T: BackgroundTerminal> TerminalRestoreGuard<'_, T> {
    fn restore(mut self) -> Result<(), T::Error> {
        self.terminal
            .take()
            .expect("terminal guard restores once")
            .restore()
    }
}

impl<T: BackgroundTerminal> Drop for TerminalRestoreGuard<'_, T> {
    fn drop(&mut self) {
        if let Some(terminal) = self.terminal.take() {
            let _ = terminal.restore();
        }
    }
}

/// Run one already-verified operation outside raw/alternate-screen mode.
/// The guard restores the terminal during unwinding as well as normal return.
pub fn with_suspended_background_terminal<T, F, R, E>(
    terminal: &mut T,
    operation: F,
) -> Result<R, BackgroundTerminalError<T::Error, E>>
where
    T: BackgroundTerminal,
    F: FnOnce() -> Result<R, E>,
{
    terminal
        .suspend()
        .map_err(BackgroundTerminalError::Suspend)?;
    let guard = TerminalRestoreGuard {
        terminal: Some(terminal),
    };
    let operation_result = operation();
    guard.restore().map_err(BackgroundTerminalError::Restore)?;
    operation_result.map_err(BackgroundTerminalError::Operation)
}

/// Load one redacted diagnostic view with the same fallback policy for CLI
/// and TUI callers.
pub fn load_diagnostics(
    socket: &Path,
    fallback: &Path,
    allow_fallback: bool,
    now_millis: u64,
) -> Result<crate::vortix_core::control::DiagnosticView, crate::daemon::client::ClientError> {
    if allow_fallback {
        crate::daemon::client::diagnostics_or_fallback(socket, fallback, now_millis)
    } else {
        crate::daemon::client::diagnostics(socket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_mode_has_exact_shared_copy_and_non_color_signal() {
        let states = [
            (
                BackgroundModeState::StandardActive,
                "Standard mode: Active",
                "S· Standard",
                "standard_active",
            ),
            (
                BackgroundModeState::BackgroundEnabling,
                "Background mode: Enabling",
                "B… Enabling",
                "background_enabling",
            ),
            (
                BackgroundModeState::BackgroundActive,
                "Background mode: Active",
                "B● Active",
                "background_active",
            ),
            (
                BackgroundModeState::BackgroundDegraded,
                "Background mode: Degraded",
                "B! Degraded",
                "background_degraded",
            ),
            (
                BackgroundModeState::BackgroundDisabling,
                "Background mode: Disabling",
                "B… Disabling",
                "background_disabling",
            ),
            (
                BackgroundModeState::BackgroundRecoveryRequired,
                "Background mode: Recovery required",
                "B! Recovery",
                "background_recovery_required",
            ),
        ];
        for (state, display, signal, slug) in states {
            assert_eq!(state.display_name(), display);
            assert_eq!(state.header_signal(), signal);
            assert_eq!(serde_json::to_value(state).unwrap(), slug);
        }
        assert_eq!(
            BackgroundAuthority::StandardLocal.display_name(),
            "local Standard-mode control"
        );
        assert_eq!(BackgroundProtection::Unchanged.display_name(), "unchanged");
        assert_eq!(
            BackgroundModeRecord::prepared_standard().permitted_actions,
            vec![
                BackgroundAction::Setup,
                BackgroundAction::Status,
                BackgroundAction::Recover,
                BackgroundAction::Diagnostics,
                BackgroundAction::Disable,
            ]
        );
        assert_eq!(
            [
                BackgroundAction::Setup,
                BackgroundAction::Status,
                BackgroundAction::Recover,
                BackgroundAction::Diagnostics,
                BackgroundAction::Disable,
            ]
            .map(BackgroundAction::display_name),
            ["setup", "status", "recover", "diagnostics", "disable"]
        );
    }

    #[test]
    fn background_views_accept_additive_json_fields() {
        let mut value = serde_json::to_value(BackgroundCommandView::prepared(Vec::new())).unwrap();
        value["future_view_field"] = serde_json::json!(true);
        value["mode"]["future_mode_field"] = serde_json::json!({ "version": 3 });
        let decoded: BackgroundCommandView = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.mode.state, BackgroundModeState::StandardActive);
    }

    #[derive(Default)]
    struct FakeTerminal {
        suspended: bool,
        restores: usize,
        fail_suspend: bool,
        fail_restore: bool,
    }

    impl BackgroundTerminal for FakeTerminal {
        type Error = &'static str;

        fn suspend(&mut self) -> Result<(), Self::Error> {
            if self.fail_suspend {
                return Err("suspend failed");
            }
            self.suspended = true;
            Ok(())
        }

        fn restore(&mut self) -> Result<(), Self::Error> {
            self.restores += 1;
            if self.fail_restore {
                return Err("restore failed");
            }
            self.suspended = false;
            Ok(())
        }
    }

    #[test]
    fn terminal_restores_after_success_denial_and_backend_failure() {
        let mut terminal = FakeTerminal::default();
        assert_eq!(
            with_suspended_background_terminal(&mut terminal, || Ok::<_, &'static str>(7)),
            Ok(7)
        );
        assert!(!terminal.suspended);

        assert_eq!(
            with_suspended_background_terminal(&mut terminal, || {
                Err::<(), _>("permission denied")
            }),
            Err(BackgroundTerminalError::Operation("permission denied"))
        );
        assert!(!terminal.suspended);
        assert_eq!(terminal.restores, 2);
    }

    #[test]
    fn terminal_restores_during_unwind() {
        let mut terminal = FakeTerminal::default();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = with_suspended_background_terminal(&mut terminal, || -> Result<(), ()> {
                panic!("simulated bootstrap panic")
            });
        }));

        assert!(result.is_err());
        assert!(!terminal.suspended);
        assert_eq!(terminal.restores, 1);
    }

    #[test]
    fn terminal_errors_preserve_suspend_and_restore_boundaries() {
        let mut suspend_failure = FakeTerminal {
            fail_suspend: true,
            ..FakeTerminal::default()
        };
        let operation_called = std::cell::Cell::new(false);
        assert_eq!(
            with_suspended_background_terminal(&mut suspend_failure, || {
                operation_called.set(true);
                Ok::<_, &'static str>(())
            }),
            Err(BackgroundTerminalError::Suspend("suspend failed"))
        );
        assert!(!operation_called.get());
        assert_eq!(suspend_failure.restores, 0);

        let mut restore_failure = FakeTerminal {
            fail_restore: true,
            ..FakeTerminal::default()
        };
        assert_eq!(
            with_suspended_background_terminal(&mut restore_failure, || {
                Ok::<_, &'static str>(())
            }),
            Err(BackgroundTerminalError::Restore("restore failed"))
        );
        assert_eq!(restore_failure.restores, 1);
    }
}
