//! Daemon-side supervision (plan 2026-07-18-001 U2, merged-U4).
//!
//! The supervisor is the headless equivalent of the TUI's scanner
//! reconciliation loop. On each tick it compares the daemon-owned
//! registry against the kernel scanner's view and applies the shared
//! [`reconcile`](crate::vortix_core::engine::reconcile) decision table
//! — atomically, inside one `RegistryHandle::apply`, so a concurrent
//! IPC command handler can't interleave between the decision and the
//! mutation.
//!
//! This commit implements the reconcile tick: drop detection and
//! disconnect finalization mutate the registry, and dropped tunnels are
//! reported back so the caller can drive the kill-switch and retry
//! follow-ups (next commit). Live kernel-scanner cadence and the retry
//! timer wire in subsequently.

use crate::tunnel::TunnelKind;
use crate::vortix_core::engine::reconcile::{classify, ReconcileAction};
use crate::vortix_core::engine::registry_handle::RegistryHandle;
use crate::vortix_core::engine::state::Connection;

/// A tunnel the reconcile tick found dropped (registry said active, the
/// kernel scanner saw no matching session). The caller uses this to
/// drive kill-switch activation and auto-reconnect scheduling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DroppedTunnel {
    pub profile: String,
    /// `true` when the entry was `Connected` (a genuine drop that arms
    /// the kill switch); `false` for a Connecting/Reconnecting entry
    /// that never fully came up.
    pub was_connected: bool,
}

/// Names the scanner reports as currently active. Kept as a thin type so
/// the tick is unit-testable without constructing full `ActiveSession`s.
pub struct ScannerView {
    /// Profile names with a live kernel session this tick.
    pub active_names: Vec<String>,
}

impl ScannerView {
    fn contains(&self, name: &str) -> bool {
        self.active_names.iter().any(|n| n == name)
    }
}

/// Run one reconcile tick against the daemon-owned registry.
///
/// Classifies each registry entry against the scanner view via the
/// shared decision table, applies the registry mutation for drops and
/// disconnect finalization, and returns the tunnels that dropped so the
/// caller can drive kill-switch / retry follow-ups.
///
/// # Errors
///
/// Returns [`EngineError`](crate::vortix_core::engine::error::EngineError)
/// when the registry owner task has terminated.
pub async fn reconcile_tick(
    registry: &RegistryHandle<TunnelKind>,
    view: ScannerView,
    disconnect_timeout_secs: u64,
) -> Result<Vec<DroppedTunnel>, crate::vortix_core::engine::error::EngineError> {
    registry
        .apply(move |reg| {
            let mut dropped = Vec::new();
            // Snapshot first so we iterate a stable set while mutating.
            for snap in reg.snapshot_all() {
                let profile = snap.profile_id.as_str().to_string();
                let present = view.contains(&profile);
                let disconnecting_elapsed = match &snap.state {
                    Connection::Disconnecting { started_at, .. } => std::time::SystemTime::now()
                        .duration_since(*started_at)
                        .unwrap_or_default()
                        .as_secs(),
                    _ => 0,
                };
                match classify(
                    &snap.state,
                    present,
                    disconnecting_elapsed,
                    disconnect_timeout_secs,
                ) {
                    ReconcileAction::CompleteDisconnect | ReconcileAction::ForceDisconnect => {
                        reg.set_disconnected(&snap.profile_id);
                    }
                    ReconcileAction::HandleDrop { was_connected } => {
                        reg.set_disconnected(&snap.profile_id);
                        dropped.push(DroppedTunnel {
                            profile,
                            was_connected,
                        });
                    }
                    // Refresh, AwaitingConnect, and None make no
                    // registry mutation in this commit. Refresh's
                    // detail-resync and adoption land next.
                    ReconcileAction::RefreshConnected
                    | ReconcileAction::AwaitingConnect
                    | ReconcileAction::None => {}
                }
            }
            dropped
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::engine::registry::TunnelRegistry;
    use crate::vortix_core::engine::registry_handle::RegistryHandle;
    use crate::vortix_core::engine::state::DetailedConnectionInfo;
    use crate::vortix_core::profile::ProfileId;

    // Seed a registry with a Connected entry for `name` via the
    // bookkeeping set_connected path (no real Tunnel::up).
    fn seed_connected(reg: &mut TunnelRegistry<TunnelKind>, name: &str) {
        let details = DetailedConnectionInfo {
            interface: format!("utun-{name}"),
            ..Default::default()
        };
        reg.set_connected(
            ProfileId::new(name),
            Vec::new(),
            details,
            std::time::SystemTime::now(),
            || {
                crate::vortix_core::engine::Engine::new(
                    TunnelKind::Mock(crate::vortix_core::ports::tunnel::mock::MockTunnel::new()),
                    |_: &ProfileId| None,
                )
            },
        );
    }

    #[tokio::test]
    async fn connected_without_session_is_detected_as_drop_and_removed() {
        let registry: RegistryHandle<TunnelKind> = RegistryHandle::spawn({
            let mut reg = TunnelRegistry::new();
            seed_connected(&mut reg, "corp");
            reg
        });
        let dropped = reconcile_tick(
            &registry,
            ScannerView {
                active_names: vec![],
            },
            30,
        )
        .await
        .expect("tick");
        assert_eq!(
            dropped,
            vec![DroppedTunnel {
                profile: "corp".into(),
                was_connected: true
            }]
        );
        // The entry was removed from the registry.
        let snap = registry.registry_snapshot().await.expect("snap");
        assert!(snap.tunnels.is_empty());
    }

    #[tokio::test]
    async fn connected_with_matching_session_is_not_dropped() {
        let registry: RegistryHandle<TunnelKind> = RegistryHandle::spawn({
            let mut reg = TunnelRegistry::new();
            seed_connected(&mut reg, "corp");
            reg
        });
        let dropped = reconcile_tick(
            &registry,
            ScannerView {
                active_names: vec!["corp".into()],
            },
            30,
        )
        .await
        .expect("tick");
        assert!(dropped.is_empty());
        let snap = registry.registry_snapshot().await.expect("snap");
        assert_eq!(snap.tunnels.len(), 1);
    }

    #[tokio::test]
    async fn empty_registry_tick_is_noop() {
        let registry: RegistryHandle<TunnelKind> = RegistryHandle::spawn(TunnelRegistry::new());
        let dropped = reconcile_tick(
            &registry,
            ScannerView {
                active_names: vec!["ghost".into()],
            },
            30,
        )
        .await
        .expect("tick");
        assert!(dropped.is_empty());
    }
}
