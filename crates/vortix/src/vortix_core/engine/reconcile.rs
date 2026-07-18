//! Pure scanner-reconciliation decision table (plan 2026-07-18-001 U2,
//! merged-U4 supervision migration).
//!
//! Given a registry entry's [`Connection`] state and whether the kernel
//! scanner sees a matching session, [`classify`] returns the
//! [`ReconcileAction`] to take. This is the decision half of the TUI's
//! `handle_sync_system_state`, lifted out from the side-effecting half
//! (logs, toasts, kill-switch sync) so the daemon supervisor and the TUI
//! reconcile identically. The caller applies the action in its own
//! idiom — headless in the daemon, with UI feedback in the TUI.

use crate::vortix_core::engine::state::Connection;

/// What the reconciler decides to do for one registry entry on a
/// scanner tick. The caller maps each variant to its own side effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileAction {
    /// Disconnecting entry, kernel session gone → finalize the
    /// disconnect (drop the entry, clear pending state).
    CompleteDisconnect,
    /// Disconnecting entry still visible in the kernel past the
    /// disconnect timeout → force cleanup.
    ForceDisconnect,
    /// Connected entry with a live session → refresh kernel-truthful
    /// details (transfer, iface, session-start drift).
    RefreshConnected,
    /// A tracked entry lost its kernel session → drop detection.
    /// `was_connected` distinguishes a genuine drop (increments the
    /// drop counter, fires the kill switch) from a
    /// Connecting/Reconnecting entry that never fully came up.
    HandleDrop { was_connected: bool },
    /// Connecting entry (with or without a session yet) → no state
    /// change; the protocol layer owns the Connecting→Connected
    /// transition. Caller may log at its own cadence.
    AwaitingConnect,
    /// Nothing to do (historic Disconnected marker, or a wait state
    /// still within its budget).
    None,
}

/// Classify one registry entry against the scanner's view.
///
/// `session_present` is whether the kernel scanner reports a session
/// matching this profile. `disconnecting_elapsed_secs` is how long the
/// entry has been in `Disconnecting` (0 for non-Disconnecting states);
/// it is compared against `disconnect_timeout_secs` only on the
/// Disconnecting+present branch.
#[must_use]
pub fn classify(
    state: &Connection,
    session_present: bool,
    disconnecting_elapsed_secs: u64,
    disconnect_timeout_secs: u64,
) -> ReconcileAction {
    match (state, session_present) {
        (Connection::Disconnecting { .. }, false) => ReconcileAction::CompleteDisconnect,
        (Connection::Disconnecting { .. }, true) => {
            if disconnecting_elapsed_secs >= disconnect_timeout_secs {
                ReconcileAction::ForceDisconnect
            } else {
                ReconcileAction::None
            }
        }
        (Connection::Connecting { .. }, _) => ReconcileAction::AwaitingConnect,
        (Connection::Connected { .. }, true) => ReconcileAction::RefreshConnected,
        (Connection::Connected { .. }, false) => ReconcileAction::HandleDrop {
            was_connected: true,
        },
        (Connection::Reconnecting { .. } | Connection::AwaitingUserInput { .. }, false) => {
            ReconcileAction::HandleDrop {
                was_connected: false,
            }
        }
        (Connection::Reconnecting { .. } | Connection::AwaitingUserInput { .. }, true) => {
            // Reserved FSM states not driven by today's connect flow;
            // if seen alongside a live kernel session, the kernel is
            // truth — refresh.
            ReconcileAction::RefreshConnected
        }
        (Connection::Disconnected { .. }, _) => ReconcileAction::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid() -> crate::vortix_core::profile::ProfileId {
        crate::vortix_core::profile::ProfileId::new("test")
    }

    fn disconnected() -> Connection {
        Connection::Disconnected { last_failure: None }
    }

    fn disconnecting() -> Connection {
        Connection::Disconnecting {
            profile_id: pid(),
            started_at: std::time::SystemTime::now(),
        }
    }

    fn connecting() -> Connection {
        Connection::Connecting {
            profile_id: pid(),
            started_at: std::time::SystemTime::now(),
            attempt: 1,
            retry_budget_remaining: std::time::Duration::from_secs(0),
        }
    }

    fn reconnecting() -> Connection {
        Connection::Reconnecting {
            profile_id: pid(),
            started_at: std::time::SystemTime::now(),
            attempt: 1,
            retry_budget_remaining: std::time::Duration::from_secs(0),
            last_error: None,
        }
    }

    fn connected() -> Connection {
        Connection::Connected {
            profile_id: pid(),
            since: std::time::SystemTime::now(),
            health: crate::vortix_core::engine::state::ConnectionHealth::Unknown,
            details: Box::new(crate::vortix_core::engine::state::DetailedConnectionInfo::default()),
        }
    }

    // Characterization: pins the exact decision table from the TUI's
    // handle_sync_system_state so the daemon supervisor re-homing cannot
    // silently change which scanner observation triggers which action.

    #[test]
    fn disconnecting_without_session_completes() {
        assert_eq!(
            classify(&disconnecting(), false, 0, 30),
            ReconcileAction::CompleteDisconnect
        );
    }

    #[test]
    fn disconnecting_with_session_forces_only_past_timeout() {
        assert_eq!(
            classify(&disconnecting(), true, 10, 30),
            ReconcileAction::None
        );
        assert_eq!(
            classify(&disconnecting(), true, 30, 30),
            ReconcileAction::ForceDisconnect
        );
        assert_eq!(
            classify(&disconnecting(), true, 31, 30),
            ReconcileAction::ForceDisconnect
        );
    }

    #[test]
    fn connected_with_session_refreshes() {
        assert_eq!(
            classify(&connected(), true, 0, 30),
            ReconcileAction::RefreshConnected
        );
    }

    #[test]
    fn connected_without_session_is_a_real_drop() {
        assert_eq!(
            classify(&connected(), false, 0, 30),
            ReconcileAction::HandleDrop {
                was_connected: true
            }
        );
    }

    #[test]
    fn reconnecting_without_session_drops_as_not_connected() {
        assert_eq!(
            classify(&reconnecting(), false, 0, 30),
            ReconcileAction::HandleDrop {
                was_connected: false
            }
        );
    }

    #[test]
    fn connecting_is_always_awaiting() {
        assert_eq!(
            classify(&connecting(), true, 0, 30),
            ReconcileAction::AwaitingConnect
        );
        assert_eq!(
            classify(&connecting(), false, 0, 30),
            ReconcileAction::AwaitingConnect
        );
    }

    #[test]
    fn historic_disconnected_is_noop() {
        assert_eq!(
            classify(&disconnected(), true, 0, 30),
            ReconcileAction::None
        );
        assert_eq!(
            classify(&disconnected(), false, 0, 30),
            ReconcileAction::None
        );
    }
}
