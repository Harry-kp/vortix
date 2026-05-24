//! Engine FSM (plan #005 U2).
//!
//! `Engine<T>` is generic over a concrete `Tunnel` impl so the FSM stays in
//! `vortix-core` without depending on the binary's `TunnelKind` aggregate.
//! Real use: `Engine<TunnelKind>` constructed in `vortix` after `tunnel_for`
//! resolves the variant. Tests use `Engine<MockTunnel>`.
//!
//! The FSM is **synchronous**. Per plans #002 / #003, the runner and
//! platform are accessed via process-global helpers; `Tunnel::up` etc. are
//! blocking. Plan #005 U4's `EngineHandle` actor wraps the FSM in a
//! `tokio::spawn`'d task so blocking subprocess work doesn't stall the
//! caller — but the FSM itself stays sync, which makes the state-transition
//! match readable and the tests deterministic.

use std::time::{Duration, SystemTime};

use crate::engine::event::{EngineEvent, KillswitchEngageReason, TunnelDownReason};
use crate::engine::input::{Input, LinkState, ProfileChange, TunnelStatusObservation, UserCommand};
use crate::engine::state::{
    Connection, DetailedConnectionInfo, FailureReason, DEFAULT_RETRY_BUDGET_SECS,
};
use crate::ports::tunnel::{Tunnel, TunnelHandle};
use crate::profile::{Profile, ProfileId, ProtocolKind};

/// Knobs the FSM consults. Plan #006's `Settings` will absorb this.
#[derive(Debug, Clone)]
pub struct EngineSettings {
    pub retry_budget: Duration,
    /// Initial backoff between retries; doubles each attempt up to `retry_budget`.
    pub initial_backoff: Duration,
}

impl Default for EngineSettings {
    fn default() -> Self {
        Self {
            retry_budget: Duration::from_secs(DEFAULT_RETRY_BUDGET_SECS),
            initial_backoff: Duration::from_secs(2),
        }
    }
}

/// The FSM.
///
/// Holds the current state and a `Tunnel` impl. The caller threads input
/// events into `handle()` and consumes the emitted `EngineEvent` list (also
/// suitable for appending to a journal).
/// Profile lookup callback — see `Engine::new`.
pub type ProfileResolver = Box<dyn Fn(&ProfileId) -> Option<Profile> + Send>;

/// Optional factory that builds a fresh tunnel per `Connect` call.
///
/// Plan #006 U6: when set, the FSM swaps `self.tunnel = factory(&profile)`
/// before invoking `tunnel.up()`. Lets a single `Engine<TunnelKind>` drive
/// arbitrary protocols by picking the right variant from the profile.
pub type TunnelFactory<T> = Box<dyn Fn(&Profile) -> T + Send>;

pub struct Engine<T: Tunnel> {
    state: Connection,
    tunnel: T,
    tunnel_factory: Option<TunnelFactory<T>>,
    settings: EngineSettings,
    /// Profile lookup callback — the FSM doesn't know about the binary's
    /// profile store, so the caller injects a closure. Returning `None`
    /// triggers `EngineError::ProfileNotFound` semantics (today we just
    /// transition to `Disconnected { last_failure: ProfileGone }`).
    profile_resolver: ProfileResolver,
}

impl<T: Tunnel> Engine<T> {
    /// Construct an engine starting from `Disconnected { last_failure: None }`.
    pub fn new(
        tunnel: T,
        profile_resolver: impl Fn(&ProfileId) -> Option<Profile> + Send + 'static,
    ) -> Self {
        Self {
            state: Connection::default(),
            tunnel,
            tunnel_factory: None,
            settings: EngineSettings::default(),
            profile_resolver: Box::new(profile_resolver),
        }
    }

    /// Override settings (test ergonomics).
    #[must_use]
    pub fn with_settings(mut self, settings: EngineSettings) -> Self {
        self.settings = settings;
        self
    }

    /// Install a per-Connect tunnel factory. When set, the FSM rebuilds
    /// `self.tunnel = factory(&profile)` before each `Connect` so a single
    /// `Engine<TunnelKind>` can drive multiple protocols.
    #[must_use]
    pub fn with_tunnel_factory(mut self, factory: impl Fn(&Profile) -> T + Send + 'static) -> Self {
        self.tunnel_factory = Some(Box::new(factory));
        self
    }

    #[must_use]
    pub fn state(&self) -> &Connection {
        &self.state
    }

    /// Drive one input through the FSM. Returns the events emitted during
    /// the transition; the caller is expected to append them to the journal
    /// and broadcast.
    pub fn handle(&mut self, input: Input) -> Vec<EngineEvent> {
        let mut events = Vec::new();
        match input {
            Input::UserCommand(cmd) => self.handle_user_command(cmd, &mut events),
            Input::Tick => self.handle_tick(&mut events),
            Input::NetworkLinkChanged(link) => self.handle_link(link, &mut events),
            Input::TelemetryReport(_) => {
                // Plan 005 U7 handles telemetry-driven health updates here.
                // For now, telemetry reports are recorded but don't trigger
                // state transitions.
            }
            Input::ProfileChanged(change) => self.handle_profile_change(change, &mut events),
            Input::TunnelStatusObserved(obs) => self.handle_tunnel_status(obs, &mut events),
        }
        events
    }

    fn handle_user_command(&mut self, cmd: UserCommand, events: &mut Vec<EngineEvent>) {
        match cmd {
            UserCommand::Connect { profile_id } => self.try_connect(profile_id, events),
            UserCommand::Disconnect | UserCommand::ForceDisconnect => self.try_disconnect(events),
            UserCommand::Reconnect => self.try_reconnect(events),
            // Plan 008 U2: slot reserved for the 2FA flow (issue #191).
            // No consumer wired in v0.3.0 — answer is dropped silently
            // because no `AwaitingUserInput` transition emits the
            // outstanding prompt yet.
            UserCommand::UserAnswered { .. } => {}
        }
    }

    fn try_connect(&mut self, profile_id: ProfileId, events: &mut Vec<EngineEvent>) {
        // Only Disconnected → Connecting is valid here; other states are
        // ignored (caller should query state first).
        if !matches!(self.state, Connection::Disconnected { .. }) {
            return;
        }
        let Some(profile) = (self.profile_resolver)(&profile_id) else {
            self.state = Connection::Disconnected {
                last_failure: Some(FailureReason::ProfileGone(profile_id)),
            };
            return;
        };

        let now = SystemTime::now();
        self.state = Connection::Connecting {
            profile_id: profile_id.clone(),
            started_at: now,
            attempt: 1,
            retry_budget_remaining: self.settings.retry_budget,
        };
        events.push(EngineEvent::ConnectAttemptStarted {
            profile_id: profile_id.clone(),
            protocol: profile.protocol,
            attempt: 1,
        });

        // Plan 006 U6: rebuild the tunnel per profile when a factory is
        // installed. Lets `Engine<TunnelKind>` route WG vs OVPN based on
        // the profile's protocol rather than the fixed initial variant.
        if let Some(factory) = &self.tunnel_factory {
            self.tunnel = factory(&profile);
        }

        // Invoke tunnel.up. Sync; blocks the caller. The actor wraps this in
        // a tokio task to keep the broader system responsive.
        match self.tunnel.up(&profile) {
            Ok(handle) => {
                self.transition_to_connected(handle, profile.protocol, events);
            }
            Err(err) => self.handle_connect_failure(profile_id, profile.protocol, 1, err, events),
        }
    }

    fn try_disconnect(&mut self, events: &mut Vec<EngineEvent>) {
        let (profile_id, _interface) = match &self.state {
            Connection::Connected {
                profile_id,
                details,
                ..
            } => (profile_id.clone(), details.interface.clone()),
            Connection::Connecting { profile_id, .. }
            | Connection::Reconnecting { profile_id, .. } => (profile_id.clone(), String::new()),
            _ => return,
        };

        let handle = self.synth_handle(&profile_id);
        self.state = Connection::Disconnecting {
            profile_id: profile_id.clone(),
            started_at: SystemTime::now(),
        };

        match self.tunnel.down(handle) {
            Ok(()) => {
                events.push(EngineEvent::TunnelDown {
                    profile_id,
                    reason: TunnelDownReason::UserDisconnect,
                });
                self.state = Connection::Disconnected { last_failure: None };
            }
            Err(err) => {
                // Best-effort: even if down fails, transition to Disconnected
                // with a failure record so the user isn't stuck.
                self.state = Connection::Disconnected {
                    last_failure: Some(FailureReason::Other(err.to_string())),
                };
            }
        }
    }

    fn try_reconnect(&mut self, events: &mut Vec<EngineEvent>) {
        let profile_id = match self.state.profile_id() {
            Some(id) => id.clone(),
            None => return,
        };
        // Treat reconnect as disconnect-then-connect at FSM level.
        self.try_disconnect(events);
        self.try_connect(profile_id, events);
    }

    fn handle_tick(&mut self, events: &mut Vec<EngineEvent>) {
        // Tick drives retry-budget exhaustion checks for Connecting and
        // Reconnecting states. Backoff scheduling between attempts happens
        // inside `try_connect` on the next inbound command — the FSM stays
        // event-driven rather than running its own retry timer.
        match &self.state {
            Connection::Connecting {
                profile_id,
                started_at,
                attempt,
                ..
            }
            | Connection::Reconnecting {
                profile_id,
                started_at,
                attempt,
                ..
            } => {
                let elapsed = started_at.elapsed().unwrap_or(Duration::ZERO);
                if elapsed >= self.settings.retry_budget {
                    let pid = profile_id.clone();
                    let total = *attempt;
                    events.push(EngineEvent::RetryBudgetExhausted {
                        profile_id: pid.clone(),
                        total_attempts: total,
                        elapsed,
                    });
                    self.state = Connection::Disconnected {
                        last_failure: Some(FailureReason::RetryBudgetExhausted {
                            attempts: total,
                            elapsed,
                        }),
                    };
                }
            }
            _ => {}
        }
    }

    fn handle_link(&mut self, link: LinkState, events: &mut Vec<EngineEvent>) {
        match (link, &self.state) {
            (LinkState::Down, Connection::Connected { profile_id, .. }) => {
                let pid = profile_id.clone();
                events.push(EngineEvent::NetworkLinkLost);
                events.push(EngineEvent::TunnelDown {
                    profile_id: pid.clone(),
                    reason: TunnelDownReason::NetworkLinkLost,
                });
                self.state = Connection::Reconnecting {
                    profile_id: pid,
                    started_at: SystemTime::now(),
                    attempt: 1,
                    retry_budget_remaining: self.settings.retry_budget,
                    last_error: Some("network link lost".to_string()),
                };
            }
            (LinkState::Up, Connection::Reconnecting { .. }) => {
                events.push(EngineEvent::NetworkLinkRestored { new_gateway: None });
                // Leave the reconnect attempt running; the next Tick or
                // explicit retry will drive the tunnel.up call.
            }
            _ => {}
        }
    }

    fn handle_profile_change(&mut self, change: ProfileChange, events: &mut Vec<EngineEvent>) {
        match change {
            ProfileChange::Renamed {
                profile_id,
                old_display_name,
                new_display_name,
            } => {
                // ProfileId is stable across renames (plan 005 R3); the
                // FSM only records the rename.
                events.push(EngineEvent::ProfileRenamed {
                    profile_id,
                    old_display_name,
                    new_display_name,
                });
            }
            ProfileChange::Deleted { profile_id } => {
                events.push(EngineEvent::ProfileDeletionRequested {
                    profile_id: profile_id.clone(),
                });
                if self.state.profile_id() == Some(&profile_id) {
                    // Tear down the tunnel; the deleter is responsible for
                    // removing the profile store entry afterwards.
                    self.try_disconnect(events);
                }
            }
            ProfileChange::Imported { .. } => { /* nothing FSM-visible today */ }
        }
    }

    fn handle_tunnel_status(
        &mut self,
        obs: TunnelStatusObservation,
        events: &mut Vec<EngineEvent>,
    ) {
        // Per brainstorm R18 the scanner is now an input source. When it
        // reports an active tunnel we don't know about, treat that as
        // ground truth and transition to Connected. Plan 005 U7 fleshes
        // this out with health updates.
        if let TunnelStatusObservation::Active {
            profile_id,
            interface_name,
            started_at,
        } = obs
        {
            if matches!(self.state, Connection::Disconnected { .. }) {
                self.state = Connection::Connected {
                    profile_id: profile_id.clone(),
                    since: started_at,
                    health: crate::engine::state::ConnectionHealth::default(),
                    details: Box::new(DetailedConnectionInfo {
                        interface: interface_name.clone(),
                        ..Default::default()
                    }),
                };
                // We can't know the protocol from the observation alone;
                // resolve via the profile resolver.
                let protocol = (self.profile_resolver)(&profile_id)
                    .map_or(ProtocolKind::WireGuard, |p| p.protocol);
                events.push(EngineEvent::TunnelUp {
                    profile_id,
                    protocol,
                    interface_name,
                    pid: None,
                });
            }
        }
    }

    fn transition_to_connected(
        &mut self,
        handle: TunnelHandle,
        protocol: ProtocolKind,
        events: &mut Vec<EngineEvent>,
    ) {
        let now = SystemTime::now();
        events.push(EngineEvent::TunnelUp {
            profile_id: handle.profile_id.clone(),
            protocol,
            interface_name: handle.interface_name.clone(),
            pid: handle.pid,
        });
        // Killswitch auto-engage on connect (plan 005 R-killswitch).
        events.push(EngineEvent::KillswitchEngaged {
            reason: KillswitchEngageReason::AutoOnConnect,
        });
        self.state = Connection::Connected {
            profile_id: handle.profile_id.clone(),
            since: now,
            health: crate::engine::state::ConnectionHealth::default(),
            details: Box::new(DetailedConnectionInfo {
                interface: handle.interface_name,
                pid: handle.pid,
                ..Default::default()
            }),
        };
    }

    #[allow(clippy::needless_pass_by_value)] // future units consume `err` more deeply
    fn handle_connect_failure(
        &mut self,
        profile_id: ProfileId,
        _protocol: ProtocolKind,
        attempt: u32,
        err: crate::ports::tunnel::TunnelError,
        events: &mut Vec<EngineEvent>,
    ) {
        let reason = tunnel_err_to_failure(err);
        events.push(EngineEvent::ConnectAttemptFailed {
            profile_id: profile_id.clone(),
            attempt,
            reason: reason.clone(),
        });
        self.state = Connection::Disconnected {
            last_failure: Some(reason),
        };
    }

    fn synth_handle(&self, profile_id: &ProfileId) -> TunnelHandle {
        // The FSM doesn't track the last-seen `TunnelHandle` directly today
        // (Connected only carries DetailedConnectionInfo). Synthesise one
        // from the current state for tunnel.down().
        let (interface, pid) = match &self.state {
            Connection::Connected { details, .. } => (details.interface.clone(), details.pid),
            _ => (String::new(), None),
        };
        TunnelHandle {
            profile_id: profile_id.clone(),
            interface_name: interface,
            pid,
            started_at: SystemTime::now(),
            kind: self.tunnel.kind_tag(),
        }
    }
}

fn tunnel_err_to_failure(err: crate::ports::tunnel::TunnelError) -> FailureReason {
    use crate::ports::tunnel::TunnelError;
    match err {
        TunnelError::HandshakeFailed(s) => FailureReason::HandshakeFailed(s),
        TunnelError::AuthFailed(s) => FailureReason::AuthFailed(s),
        TunnelError::Timeout(d) => FailureReason::Timeout(d),
        TunnelError::DaemonExited(s) | TunnelError::Subprocess(s) | TunnelError::Other(s) => {
            FailureReason::Other(s)
        }
        TunnelError::Io(e) => FailureReason::Other(e.to_string()),
        TunnelError::CapabilityUnsupported(c) => {
            FailureReason::ConfigInvalid(format!("capability unsupported: {c}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::tunnel::mock::{MockTunnel, ScriptedTunnelOutcome};
    use std::path::PathBuf;

    fn corp_profile() -> Profile {
        Profile::new(
            ProfileId::new("corp"),
            "corp",
            ProtocolKind::WireGuard,
            PathBuf::from("/etc/wireguard/corp.conf"),
        )
    }

    fn engine_with(tunnel: MockTunnel) -> Engine<MockTunnel> {
        let p = corp_profile();
        Engine::new(tunnel, move |id| {
            if id.as_str() == "corp" {
                Some(p.clone())
            } else {
                None
            }
        })
    }

    #[test]
    fn connect_succeeds_transitions_to_connected() {
        let tunnel = MockTunnel::new();
        let mut engine = engine_with(tunnel);
        let events = engine.handle(Input::UserCommand(UserCommand::Connect {
            profile_id: ProfileId::new("corp"),
        }));
        assert!(matches!(engine.state(), Connection::Connected { .. }));
        let kinds: Vec<&'static str> = events
            .iter()
            .map(|e| match e {
                EngineEvent::ConnectAttemptStarted { .. } => "start",
                EngineEvent::TunnelUp { .. } => "up",
                EngineEvent::KillswitchEngaged { .. } => "ks",
                _ => "other",
            })
            .collect();
        assert!(kinds.contains(&"start"));
        assert!(kinds.contains(&"up"));
        assert!(kinds.contains(&"ks"));
    }

    #[test]
    fn missing_profile_recorded_as_profile_gone() {
        let mut engine = engine_with(MockTunnel::new());
        let _ = engine.handle(Input::UserCommand(UserCommand::Connect {
            profile_id: ProfileId::new("does-not-exist"),
        }));
        assert!(matches!(
            engine.state(),
            Connection::Disconnected {
                last_failure: Some(FailureReason::ProfileGone(_))
            }
        ));
    }

    #[test]
    fn handshake_failure_transitions_to_disconnected_with_reason() {
        let tunnel = MockTunnel::new();
        tunnel.script_up(ScriptedTunnelOutcome::HandshakeFailed("bad key".into()));
        let mut engine = engine_with(tunnel);
        let events = engine.handle(Input::UserCommand(UserCommand::Connect {
            profile_id: ProfileId::new("corp"),
        }));
        assert!(matches!(
            engine.state(),
            Connection::Disconnected {
                last_failure: Some(FailureReason::HandshakeFailed(_))
            }
        ));
        assert!(events
            .iter()
            .any(|e| matches!(e, EngineEvent::ConnectAttemptFailed { .. })));
    }

    #[test]
    fn link_down_while_connected_transitions_to_reconnecting() {
        let mut engine = engine_with(MockTunnel::new());
        let _ = engine.handle(Input::UserCommand(UserCommand::Connect {
            profile_id: ProfileId::new("corp"),
        }));
        let events = engine.handle(Input::NetworkLinkChanged(LinkState::Down));
        assert!(matches!(engine.state(), Connection::Reconnecting { .. }));
        assert!(events
            .iter()
            .any(|e| matches!(e, EngineEvent::NetworkLinkLost)));
    }

    #[test]
    fn profile_renamed_emits_event_without_state_change() {
        let mut engine = engine_with(MockTunnel::new());
        let _ = engine.handle(Input::UserCommand(UserCommand::Connect {
            profile_id: ProfileId::new("corp"),
        }));
        let events = engine.handle(Input::ProfileChanged(ProfileChange::Renamed {
            profile_id: ProfileId::new("corp"),
            old_display_name: "corp".into(),
            new_display_name: "work-corp".into(),
        }));
        assert!(matches!(engine.state(), Connection::Connected { .. }));
        assert!(events
            .iter()
            .any(|e| matches!(e, EngineEvent::ProfileRenamed { .. })));
    }
}
