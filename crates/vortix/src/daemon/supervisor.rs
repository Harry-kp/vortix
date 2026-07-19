//! Daemon-side supervision.
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
use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::engine::reconcile::{classify, ReconcileAction};
use crate::vortix_core::engine::registry_handle::RegistryHandle;
use crate::vortix_core::engine::state::{Connection, DetailedConnectionInfo};
use crate::vortix_core::engine::Engine;
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

/// Resolves the per-reconnect context for a profile: its declared
/// `AllowedIPs` plus a fresh `Disconnected` `Engine<TunnelKind>` to drive
/// the connect through the registry. Returns
/// `None` when the profile isn't resolvable or engine prerequisites are
/// missing. Injected so the loop is unit-testable without real tunnels;
/// in production it wraps `daemon::connect_allowed_ips` + `build_engine`.
///
/// Reconnect goes through `RegistryHandle::connect` (not a throwaway
/// engine) so the recovered tunnel becomes a real, drivable entry in the
/// one source of truth — disconnectable/reconnectable like any other.
pub type ReconnectContext =
    std::sync::Arc<dyn Fn(&str) -> Option<(Vec<Cidr>, Engine<TunnelKind>)> + Send + Sync>;

/// Hard cap on one kernel scan so a hung `wg`/`ip`/`/proc` read can't
/// wedge the whole supervision loop.
const SCAN_TIMEOUT_SECS: u64 = 15;

/// The daemon's headless supervision loop: on each tick, scan the kernel
/// for live sessions, reconcile them against the daemon-owned registry
/// (adopt new, finalize disconnects, detect drops), and drive headless
/// auto-reconnect for tunnels that dropped unexpectedly. Runs
/// until the registry owner task terminates (daemon shutdown).
///
/// `reconnect_ctx` resolves a profile's `AllowedIPs` + a fresh engine per
/// reconnect (see [`ReconnectContext`]); when it yields `None` the loop
/// still reconciles the registry but performs no reconnect for that
/// profile. Kill-switch arming on drop is a follow-up (it needs the daemon
/// to load kill-switch mode + apply root firewall rules, validated live).
///
/// Spawn this onto the daemon runtime alongside the accept loop.
pub async fn run_supervisor(
    registry: RegistryHandle<TunnelKind>,
    reconnect_ctx: ReconnectContext,
    config: SupervisorConfig,
) {
    let mut retries: HashMap<String, RetryTrack> = HashMap::new();
    let mut ticker = tokio::time::interval(Duration::from_secs(config.scan_interval_secs.max(1)));
    // A blocking reconnect can overrun several tick periods; Skip collapses
    // the missed-tick backlog to a single tick so the loop doesn't fire a
    // burst of back-to-back kernel scans when it catches up.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;

        // The scan reads `/proc`, runs `wg`/`ip`, and loads profile
        // sidecars — all blocking. Keep it off the async worker AND bound
        // it, so a hung subprocess skips the tick rather than freezing
        // supervision forever.
        let scan = tokio::time::timeout(
            Duration::from_secs(SCAN_TIMEOUT_SECS),
            tokio::task::spawn_blocking(|| {
                let profiles = crate::vpn::load_profiles();
                crate::core::scanner::get_active_profiles(&profiles)
            }),
        )
        .await;
        let sessions = match scan {
            Ok(Ok(sessions)) => sessions,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "supervisor scan task failed; skipping tick");
                continue;
            }
            Err(_elapsed) => {
                tracing::warn!(
                    timeout_secs = SCAN_TIMEOUT_SECS,
                    "supervisor scan timed out; skipping tick"
                );
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
        // pending reconnect for it. This is also how a *successful*
        // reconnect is confirmed: the scanner re-adopts the tunnel a tick
        // later and its retry is cleared here.
        for name in &outcome.adopted {
            retries.remove(name);
        }

        schedule_drops(&outcome, &config, &mut retries, Instant::now());

        // Fire any reconnect whose delay has elapsed.
        drive_due_reconnects(&registry, &reconnect_ctx, &config, &mut retries).await;
    }
}

/// Insert a first-attempt retry for each genuine drop (a `Connected`
/// tunnel that vanished) not already being retried. Pure over `now` so
/// the scheduling is unit-testable. No-op when `auto_reconnect` is off.
fn schedule_drops(
    outcome: &ReconcileOutcome,
    config: &SupervisorConfig,
    retries: &mut HashMap<String, RetryTrack>,
    now: Instant,
) {
    if !config.auto_reconnect {
        return;
    }
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
                    next_at: now + Duration::from_secs(delay),
                },
            );
        }
    }
}

/// After an attempt for `name`, either reschedule the next attempt with
/// backoff (budget remaining) or give up and drop the entry. Pure over
/// `now`; unit-testable. Returns `true` when the entry was kept.
fn reschedule_after_attempt(
    name: &str,
    config: &SupervisorConfig,
    retries: &mut HashMap<String, RetryTrack>,
    now: Instant,
) -> bool {
    let attempt = retries.get(name).map_or(1, |t| t.attempt);
    if crate::state::retry::has_retry_budget(config.max_retries, attempt) {
        let next_attempt = attempt + 1;
        let delay = crate::state::retry::reconnect_delay_for_attempt(
            next_attempt,
            config.auto_reconnect_delay_secs,
            config.retry_base_delay_secs,
            config.retry_max_delay_secs,
        );
        tracing::warn!(profile = %name, next_attempt, delay, "auto-reconnect attempt made; will retry if still down");
        retries.insert(
            name.to_string(),
            RetryTrack {
                attempt: next_attempt,
                next_at: now + Duration::from_secs(delay),
            },
        );
        true
    } else {
        tracing::warn!(profile = %name, "auto-reconnect gave up (retry budget exhausted)");
        retries.remove(name);
        false
    }
}

/// Execute every reconnect that is due by driving `RegistryHandle::connect`
/// for the profile — so the recovered tunnel becomes a real entry in the
/// one source of truth. `registry.connect` is authoritative: on success we
/// clear the retry immediately; on a connect failure (or a missing
/// context) we reschedule with backoff / give up per budget.
async fn drive_due_reconnects(
    registry: &RegistryHandle<TunnelKind>,
    reconnect_ctx: &ReconnectContext,
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
        let Some((allowed_ips, engine)) = reconnect_ctx(&name) else {
            tracing::warn!(profile = %name, "auto-reconnect skipped: profile/engine unavailable");
            // Keep the entry; a later tick may resolve the context.
            continue;
        };
        tracing::info!(profile = %name, attempt, "auto-reconnect attempt");
        match registry
            .connect(ProfileId::new(&name), allowed_ips, move || engine, true)
            .await
        {
            Ok(Ok(())) => {
                tracing::info!(profile = %name, "auto-reconnect succeeded");
                retries.remove(&name);
            }
            Ok(Err(e)) => {
                tracing::warn!(profile = %name, ?e, "auto-reconnect failed; will retry");
                let _ = reschedule_after_attempt(&name, config, retries, Instant::now());
            }
            Err(e) => {
                tracing::warn!(profile = %name, %e, "auto-reconnect: registry actor gone");
                let _ = reschedule_after_attempt(&name, config, retries, Instant::now());
            }
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

    fn test_config() -> SupervisorConfig {
        SupervisorConfig {
            scan_interval_secs: 2,
            disconnect_timeout_secs: 30,
            auto_reconnect: true,
            auto_reconnect_delay_secs: 5,
            max_retries: 3,
            retry_base_delay_secs: 2,
            retry_max_delay_secs: 300,
        }
    }

    fn outcome_with_drop(name: &str, was_connected: bool) -> ReconcileOutcome {
        ReconcileOutcome {
            dropped: vec![DroppedTunnel {
                profile: name.into(),
                was_connected,
            }],
            adopted: vec![],
        }
    }

    // ===== scheduling (pure over `now`) =====

    #[test]
    fn schedule_drops_arms_first_attempt_for_connected_drop() {
        let mut retries = HashMap::new();
        schedule_drops(
            &outcome_with_drop("corp", true),
            &test_config(),
            &mut retries,
            Instant::now(),
        );
        assert_eq!(retries.get("corp").map(|t| t.attempt), Some(1));
    }

    #[test]
    fn schedule_drops_ignores_never_connected_and_already_tracked() {
        let cfg = test_config();
        let mut retries = HashMap::new();
        // A Connecting/never-up drop does not schedule an auto-reconnect.
        schedule_drops(
            &outcome_with_drop("corp", false),
            &cfg,
            &mut retries,
            Instant::now(),
        );
        assert!(retries.is_empty());
        // An already-tracked profile is not re-armed (attempt preserved).
        retries.insert(
            "home".to_string(),
            RetryTrack {
                attempt: 2,
                next_at: Instant::now() + Duration::from_secs(999),
            },
        );
        schedule_drops(
            &outcome_with_drop("home", true),
            &cfg,
            &mut retries,
            Instant::now(),
        );
        assert_eq!(retries.get("home").map(|t| t.attempt), Some(2));
    }

    #[test]
    fn schedule_drops_noop_when_auto_reconnect_off() {
        let mut cfg = test_config();
        cfg.auto_reconnect = false;
        let mut retries = HashMap::new();
        schedule_drops(
            &outcome_with_drop("corp", true),
            &cfg,
            &mut retries,
            Instant::now(),
        );
        assert!(retries.is_empty());
    }

    #[test]
    fn reschedule_backs_off_until_budget_exhausted() {
        let cfg = test_config(); // max_retries = 3
        let mut retries = HashMap::new();
        retries.insert(
            "corp".to_string(),
            RetryTrack {
                attempt: 1,
                next_at: Instant::now(),
            },
        );
        // attempt 1 → budget remains → rescheduled at attempt 2.
        assert!(reschedule_after_attempt(
            "corp",
            &cfg,
            &mut retries,
            Instant::now()
        ));
        assert_eq!(retries.get("corp").map(|t| t.attempt), Some(2));
        // bump to the cap and confirm give-up removes the entry.
        retries.get_mut("corp").unwrap().attempt = 3;
        assert!(!reschedule_after_attempt(
            "corp",
            &cfg,
            &mut retries,
            Instant::now()
        ));
        assert!(!retries.contains_key("corp"));
    }

    // ===== drive_due_reconnects (fresh-engine factory) =====

    // A reconnect context that hands back a mock engine (connects instantly)
    // and empty AllowedIPs, so `registry.connect` succeeds in tests.
    fn mock_ctx() -> ReconnectContext {
        std::sync::Arc::new(|name: &str| {
            let engine = mock_engine_for(name);
            Some((Vec::new(), engine))
        })
    }

    fn mock_engine_for(name: &str) -> Engine<TunnelKind> {
        use crate::vortix_core::profile::{Profile, ProtocolKind};
        use std::path::PathBuf;
        let name = name.to_string();
        Engine::new(
            TunnelKind::Mock(MockTunnel::new()),
            move |id: &ProfileId| {
                Some(Profile::new(
                    id.clone(),
                    &name,
                    ProtocolKind::WireGuard,
                    PathBuf::from(format!("/tmp/{name}.conf")),
                ))
            },
        )
    }

    #[tokio::test]
    async fn drive_fires_due_and_clears_on_success() {
        let registry = RegistryHandle::spawn(TunnelRegistry::<TunnelKind>::new());
        let cfg = test_config();
        let mut retries = HashMap::new();
        retries.insert(
            "corp".to_string(),
            RetryTrack {
                attempt: 1,
                next_at: Instant::now().checked_sub(Duration::from_secs(1)).unwrap(), // due
            },
        );
        drive_due_reconnects(&registry, &mock_ctx(), &cfg, &mut retries).await;
        // registry.connect succeeded (mock) → retry cleared, and the
        // profile is now a real Connected entry in the registry.
        assert!(!retries.contains_key("corp"));
        let snap = registry.registry_snapshot().await.expect("snap");
        assert!(snap.tunnels.iter().any(|t| t.profile_id.as_str() == "corp"));
    }

    #[tokio::test]
    async fn drive_ignores_not_due_entries() {
        let registry = RegistryHandle::spawn(TunnelRegistry::<TunnelKind>::new());
        let cfg = test_config();
        let mut retries = HashMap::new();
        retries.insert(
            "corp".to_string(),
            RetryTrack {
                attempt: 1,
                next_at: Instant::now() + Duration::from_secs(999), // not due
            },
        );
        drive_due_reconnects(&registry, &mock_ctx(), &cfg, &mut retries).await;
        assert_eq!(retries.get("corp").map(|t| t.attempt), Some(1));
    }

    #[tokio::test]
    async fn drive_keeps_entry_when_context_unavailable() {
        let registry = RegistryHandle::spawn(TunnelRegistry::<TunnelKind>::new());
        let none_ctx: ReconnectContext = std::sync::Arc::new(|_| None);
        let cfg = test_config();
        let mut retries = HashMap::new();
        retries.insert(
            "corp".to_string(),
            RetryTrack {
                attempt: 1,
                next_at: Instant::now().checked_sub(Duration::from_secs(1)).unwrap(), // due
            },
        );
        drive_due_reconnects(&registry, &none_ctx, &cfg, &mut retries).await;
        // No context → attempt not consumed, entry preserved for a later tick.
        assert_eq!(retries.get("corp").map(|t| t.attempt), Some(1));
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
