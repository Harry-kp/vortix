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
//! Responsibilities:
//! - **Adopt** kernel sessions the registry doesn't yet know about as
//!   `Connected` entries (the daemon's own connects flow through a single
//!   FSM, so without adoption the registry would stay empty and
//!   `IpcOp::RegistrySnapshot` would have nothing to serve).
//! - **Reconcile** existing entries: finalize disconnects, detect drops.
//! - **Auto-reconnect** tunnels that dropped unexpectedly, via the retry
//!   ladder re-homed from the TUI (`run_supervisor` / `drive_due_reconnects`).
//!
//! Still to come: arming the kill switch on an unexpected drop (needs the
//! daemon to load kill-switch mode + apply root firewall rules).

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime};

use crate::core::scanner::ActiveSession;
use crate::tunnel::TunnelKind;
use crate::vortix_core::engine::input::UserCommand;
use crate::vortix_core::engine::reconcile::{classify, ReconcileAction};
use crate::vortix_core::engine::registry_handle::RegistryHandle;
use crate::vortix_core::engine::state::{Connection, DetailedConnectionInfo};
use crate::vortix_core::engine::{Engine, EngineHandle};
use crate::vortix_core::ports::tunnel::mock::MockTunnel;
use crate::vortix_core::profile::ProfileId;

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

/// What one reconcile tick changed: tunnels that dropped (need
/// kill-switch / retry follow-up) and tunnels newly adopted from the
/// kernel scanner (informational — already reflected in the registry).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileOutcome {
    pub dropped: Vec<DroppedTunnel>,
    pub adopted: Vec<String>,
}

/// A live kernel session as the scanner reports it, carrying the fields
/// needed both to match against the registry (by `name`) and to adopt an
/// as-yet-unknown session into it. Mirrors the subset of
/// [`crate::core::scanner::ActiveSession`] the registry's
/// `DetailedConnectionInfo` consumes; the daemon boot loop translates the
/// real scanner output into these.
#[derive(Debug, Clone, Default)]
pub struct ScannedSession {
    pub name: String,
    pub interface: String,
    pub interface_authoritative: bool,
    pub internal_ip: String,
    pub endpoint: String,
    pub mtu: String,
    pub public_key: String,
    pub listen_port: String,
    pub transfer_rx: String,
    pub transfer_tx: String,
    pub latest_handshake: String,
    pub pid: Option<u32>,
    pub started_at: Option<SystemTime>,
}

impl ScannedSession {
    /// Build the registry's `DetailedConnectionInfo` from this session —
    /// the same field mapping `App::adopt_registry_from_session` uses.
    fn to_details(&self) -> DetailedConnectionInfo {
        DetailedConnectionInfo {
            interface: self.interface.clone(),
            interface_authoritative: self.interface_authoritative,
            internal_ip: self.internal_ip.clone(),
            endpoint: self.endpoint.clone(),
            mtu: self.mtu.clone(),
            public_key: self.public_key.clone(),
            listen_port: self.listen_port.clone(),
            transfer_rx: self.transfer_rx.clone(),
            transfer_tx: self.transfer_tx.clone(),
            latest_handshake: self.latest_handshake.clone(),
            pid: self.pid,
        }
    }
}

impl From<&ActiveSession> for ScannedSession {
    fn from(s: &ActiveSession) -> Self {
        Self {
            name: s.name.clone(),
            interface: s.interface.clone(),
            interface_authoritative: s.interface_authoritative,
            internal_ip: s.internal_ip.clone(),
            endpoint: s.endpoint.clone(),
            mtu: s.mtu.clone(),
            public_key: s.public_key.clone(),
            listen_port: s.listen_port.clone(),
            transfer_rx: s.transfer_rx.clone(),
            transfer_tx: s.transfer_tx.clone(),
            latest_handshake: s.latest_handshake.clone(),
            pid: s.pid,
            started_at: s.started_at,
        }
    }
}

/// The scanner's view of currently-live kernel sessions this tick.
pub struct ScannerView {
    pub sessions: Vec<ScannedSession>,
}

impl ScannerView {
    fn contains(&self, name: &str) -> bool {
        self.sessions.iter().any(|s| s.name == name)
    }
}

/// Run one reconcile tick against the daemon-owned registry.
///
/// Two passes, atomic within one [`RegistryHandle::apply`] so a
/// concurrent IPC command handler can't interleave:
/// 1. **Reconcile** existing registry entries against the scanner view
///    via the shared decision table — finalize disconnects and detect
///    drops.
/// 2. **Adopt** scanner sessions with no registry entry as fresh
///    `Connected` entries so the daemon owns state for tunnels started
///    outside its FSM (CLI, external `wg-quick`, restart-survivors).
///
/// Returns what changed: dropped tunnels (kill-switch / retry follow-up)
/// and newly-adopted names.
///
/// # Errors
///
/// Returns [`EngineError`](crate::vortix_core::engine::error::EngineError)
/// when the registry owner task has terminated.
pub async fn reconcile_tick(
    registry: &RegistryHandle<TunnelKind>,
    view: ScannerView,
    disconnect_timeout_secs: u64,
) -> Result<ReconcileOutcome, crate::vortix_core::engine::error::EngineError> {
    registry
        .apply(move |reg| {
            let mut outcome = ReconcileOutcome::default();
            // Snapshot first so we iterate a stable set while mutating.
            let existing = reg.snapshot_all();
            for snap in &existing {
                let profile = snap.profile_id.as_str().to_string();
                let present = view.contains(&profile);
                let disconnecting_elapsed = match &snap.state {
                    Connection::Disconnecting { started_at, .. } => SystemTime::now()
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
                        outcome.dropped.push(DroppedTunnel {
                            profile,
                            was_connected,
                        });
                    }
                    // Refresh's detail-resync for existing Connected
                    // entries lands with the streaming unit; AwaitingConnect
                    // and None make no mutation.
                    ReconcileAction::RefreshConnected
                    | ReconcileAction::AwaitingConnect
                    | ReconcileAction::None => {}
                }
            }

            // Adoption pass: kernel sessions with no registry entry are
            // adopted as Connected. The registry constructs a placeholder
            // Engine that is never driven (Tunnel::up is never called on
            // an adopted entry) — the Mock tunnel just satisfies the
            // `T: Tunnel` bound, matching `App::adopt_registry_from_session`.
            for session in &view.sessions {
                if existing
                    .iter()
                    .any(|e| e.profile_id.as_str() == session.name)
                {
                    continue;
                }
                let profile_id = ProfileId::new(&session.name);
                let since = session.started_at.unwrap_or_else(SystemTime::now);
                reg.set_connected(
                    profile_id,
                    Vec::new(),
                    session.to_details(),
                    since,
                    placeholder_engine,
                );
                outcome.adopted.push(session.name.clone());
            }
            outcome
        })
        .await
}

/// A never-driven `Engine<TunnelKind>` for adopted entries. Adoption
/// records kernel-observed state; it never issues `Tunnel::up`/`down`, so
/// the inner tunnel is dead storage that only satisfies the generic bound.
fn placeholder_engine() -> Engine<TunnelKind> {
    Engine::new(TunnelKind::Mock(MockTunnel::new()), |_: &ProfileId| None)
}

/// Knobs the supervision loop needs, lifted from `AppConfig` so the
/// daemon and the TUI compute identical cadence and retry behavior.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    pub scan_interval_secs: u64,
    pub disconnect_timeout_secs: u64,
    pub auto_reconnect: bool,
    pub auto_reconnect_delay_secs: u64,
    pub max_retries: u32,
    pub retry_base_delay_secs: u64,
    pub retry_max_delay_secs: u64,
}

/// One profile's in-flight auto-reconnect bookkeeping.
struct RetryTrack {
    /// 1-based attempt about to be (or just) made.
    attempt: u32,
    /// When the next attempt is due.
    next_at: Instant,
}

/// True when `state` is `Connected` to the named profile.
fn is_connected_to(state: &Connection, name: &str) -> bool {
    matches!(state, Connection::Connected { profile_id, .. } if profile_id.as_str() == name)
}

/// The daemon's headless supervision loop: on each tick, scan the kernel
/// for live sessions, reconcile them against the daemon-owned registry
/// (adopt new, finalize disconnects, detect drops), and drive headless
/// auto-reconnect for tunnels that dropped unexpectedly (AE2/AE3). Runs
/// until the registry owner task terminates (daemon shutdown).
///
/// Reconnect execution needs the daemon's `engine` handle; when absent
/// (engine unavailable at boot) the loop still reconciles the registry
/// but cannot reconnect. Kill-switch arming on drop is a follow-up (it
/// needs the daemon to load kill-switch mode + apply root firewall
/// rules, validated live).
///
/// Spawn this onto the daemon runtime alongside the accept loop.
pub async fn run_supervisor(
    registry: RegistryHandle<TunnelKind>,
    engine: Option<EngineHandle>,
    config: SupervisorConfig,
) {
    let mut retries: HashMap<String, RetryTrack> = HashMap::new();
    let mut ticker = tokio::time::interval(Duration::from_secs(config.scan_interval_secs.max(1)));
    loop {
        ticker.tick().await;

        // The scan reads `/proc`, runs `wg`/`ip`, and loads profile
        // sidecars — all blocking. Keep it off the async worker.
        let sessions = match tokio::task::spawn_blocking(|| {
            let profiles = crate::vpn::load_profiles();
            crate::core::scanner::get_active_profiles(&profiles)
        })
        .await
        {
            Ok(sessions) => sessions,
            Err(e) => {
                tracing::warn!(error = %e, "supervisor scan task failed; skipping tick");
                continue;
            }
        };

        let view = ScannerView {
            sessions: sessions.iter().map(ScannedSession::from).collect(),
        };
        let outcome = match reconcile_tick(&registry, view, config.disconnect_timeout_secs).await {
            Ok(outcome) => outcome,
            Err(e) => {
                tracing::warn!(error = %e, "supervisor registry terminated; stopping supervision");
                break;
            }
        };
        if !outcome.adopted.is_empty() || !outcome.dropped.is_empty() {
            tracing::info!(
                adopted = ?outcome.adopted,
                dropped = ?outcome.dropped,
                "supervisor reconcile"
            );
        }

        // A tunnel that reappeared (adopted) is healthy again — clear any
        // pending reconnect for it.
        for name in &outcome.adopted {
            retries.remove(name);
        }

        // Schedule auto-reconnect for genuine drops (a Connected tunnel
        // that vanished). The first attempt waits the fixed grace window;
        // failures escalate via exponential backoff up to `max_retries`.
        if config.auto_reconnect {
            for dropped in &outcome.dropped {
                if dropped.was_connected && !retries.contains_key(&dropped.profile) {
                    let delay = crate::state::retry::reconnect_delay_for_attempt(
                        1,
                        config.auto_reconnect_delay_secs,
                        config.retry_base_delay_secs,
                        config.retry_max_delay_secs,
                    );
                    tracing::info!(profile = %dropped.profile, delay, "auto-reconnect scheduled");
                    retries.insert(
                        dropped.profile.clone(),
                        RetryTrack {
                            attempt: 1,
                            next_at: Instant::now() + Duration::from_secs(delay),
                        },
                    );
                }
            }
        }

        // Fire any reconnect whose delay has elapsed. Executing a connect
        // blocks this loop until the FSM settles — intended: the whole
        // point of the tick is to bring the tunnel back.
        if let Some(engine) = &engine {
            drive_due_reconnects(engine, &config, &mut retries).await;
        }
    }
}

/// Execute every reconnect that is due, updating the retry bookkeeping:
/// success clears the entry, failure reschedules with backoff until the
/// budget is exhausted (then gives up).
async fn drive_due_reconnects(
    engine: &EngineHandle,
    config: &SupervisorConfig,
    retries: &mut HashMap<String, RetryTrack>,
) {
    let now = Instant::now();
    let due: Vec<String> = retries
        .iter()
        .filter(|(_, track)| track.next_at <= now)
        .map(|(name, _)| name.clone())
        .collect();

    for name in due {
        let attempt = retries.get(&name).map_or(1, |t| t.attempt);
        tracing::info!(profile = %name, attempt, "auto-reconnect attempt");
        let _ = engine
            .execute_command(UserCommand::Connect {
                profile_id: ProfileId::new(&name),
            })
            .await;

        let connected =
            matches!(engine.snapshot().await, Ok(s) if is_connected_to(&s.state, &name));
        if connected {
            tracing::info!(profile = %name, "auto-reconnect succeeded");
            retries.remove(&name);
        } else if crate::state::retry::has_retry_budget(config.max_retries, attempt) {
            let next_attempt = attempt + 1;
            let delay = crate::state::retry::reconnect_delay_for_attempt(
                next_attempt,
                config.auto_reconnect_delay_secs,
                config.retry_base_delay_secs,
                config.retry_max_delay_secs,
            );
            tracing::warn!(profile = %name, next_attempt, delay, "auto-reconnect failed; retrying");
            retries.insert(
                name,
                RetryTrack {
                    attempt: next_attempt,
                    next_at: Instant::now() + Duration::from_secs(delay),
                },
            );
        } else {
            tracing::warn!(profile = %name, "auto-reconnect gave up (retry budget exhausted)");
            retries.remove(&name);
        }
    }
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

    // A scanner session for `name` with just enough to adopt.
    fn session(name: &str) -> ScannedSession {
        ScannedSession {
            name: name.into(),
            interface: format!("utun-{name}"),
            interface_authoritative: true,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn connected_without_session_is_detected_as_drop_and_removed() {
        let registry: RegistryHandle<TunnelKind> = RegistryHandle::spawn({
            let mut reg = TunnelRegistry::new();
            seed_connected(&mut reg, "corp");
            reg
        });
        let outcome = reconcile_tick(&registry, ScannerView { sessions: vec![] }, 30)
            .await
            .expect("tick");
        assert_eq!(
            outcome.dropped,
            vec![DroppedTunnel {
                profile: "corp".into(),
                was_connected: true
            }]
        );
        assert!(outcome.adopted.is_empty());
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
        let outcome = reconcile_tick(
            &registry,
            ScannerView {
                sessions: vec![session("corp")],
            },
            30,
        )
        .await
        .expect("tick");
        assert!(outcome.dropped.is_empty());
        assert!(outcome.adopted.is_empty());
        let snap = registry.registry_snapshot().await.expect("snap");
        assert_eq!(snap.tunnels.len(), 1);
    }

    #[tokio::test]
    async fn empty_registry_tick_with_no_sessions_is_noop() {
        let registry: RegistryHandle<TunnelKind> = RegistryHandle::spawn(TunnelRegistry::new());
        let outcome = reconcile_tick(&registry, ScannerView { sessions: vec![] }, 30)
            .await
            .expect("tick");
        assert_eq!(outcome, ReconcileOutcome::default());
    }

    #[tokio::test]
    async fn unknown_session_is_adopted_as_connected() {
        let registry: RegistryHandle<TunnelKind> = RegistryHandle::spawn(TunnelRegistry::new());
        let outcome = reconcile_tick(
            &registry,
            ScannerView {
                sessions: vec![session("home")],
            },
            30,
        )
        .await
        .expect("tick");
        assert_eq!(outcome.adopted, vec!["home".to_string()]);
        assert!(outcome.dropped.is_empty());
        let snap = registry.registry_snapshot().await.expect("snap");
        assert_eq!(snap.tunnels.len(), 1);
        assert_eq!(snap.tunnels[0].profile_id.as_str(), "home");
        assert!(matches!(
            snap.tunnels[0].state,
            Connection::Connected { .. }
        ));
    }

    #[tokio::test]
    async fn already_known_session_is_not_re_adopted() {
        let registry: RegistryHandle<TunnelKind> = RegistryHandle::spawn({
            let mut reg = TunnelRegistry::new();
            seed_connected(&mut reg, "corp");
            reg
        });
        let outcome = reconcile_tick(
            &registry,
            ScannerView {
                sessions: vec![session("corp")],
            },
            30,
        )
        .await
        .expect("tick");
        assert!(outcome.adopted.is_empty());
    }

    #[tokio::test]
    async fn adopts_new_while_dropping_a_vanished_one_in_one_tick() {
        let registry: RegistryHandle<TunnelKind> = RegistryHandle::spawn({
            let mut reg = TunnelRegistry::new();
            seed_connected(&mut reg, "corp");
            reg
        });
        // "corp" vanished from the kernel; "home" appeared.
        let outcome = reconcile_tick(
            &registry,
            ScannerView {
                sessions: vec![session("home")],
            },
            30,
        )
        .await
        .expect("tick");
        assert_eq!(
            outcome.dropped,
            vec![DroppedTunnel {
                profile: "corp".into(),
                was_connected: true
            }]
        );
        assert_eq!(outcome.adopted, vec!["home".to_string()]);
        let snap = registry.registry_snapshot().await.expect("snap");
        assert_eq!(snap.tunnels.len(), 1);
        assert_eq!(snap.tunnels[0].profile_id.as_str(), "home");
    }
}
