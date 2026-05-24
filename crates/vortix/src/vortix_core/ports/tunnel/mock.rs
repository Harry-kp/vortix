//! `MockTunnel` — scriptable test fixture for the `Tunnel` trait.
//!
//! Same shape as `MockKillswitch` (plan 003 U5) and `MockRunner` (plan 002):
//! scripted outcomes, an invocation log, and a default-success constructor
//! for tests that don't care about subprocess specifics.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use super::{
    ParseError, ParsedProfile, ProtocolStatus, RecordedTunnelCall, Tunnel, TunnelCallLog,
    TunnelCapabilities, TunnelError, TunnelHandle, TunnelKindTag, TunnelStatus,
};
use crate::vortix_core::profile::Profile;

/// Scripted outcome for the next `up` / `down` / `status` call.
#[derive(Debug, Clone, Default)]
pub enum ScriptedTunnelOutcome {
    /// Succeed with default values.
    #[default]
    DefaultSuccess,
    /// Succeed with a custom interface name (only for `up`).
    UpSuccess {
        interface_name: String,
        pid: Option<u32>,
    },
    /// Fail with the given error message (mapped to `TunnelError::Subprocess`).
    Failure(String),
    /// Fail with `TunnelError::HandshakeFailed`.
    HandshakeFailed(String),
    /// Fail with `TunnelError::AuthFailed`.
    AuthFailed(String),
    /// Fail with `TunnelError::Timeout`.
    Timeout(Duration),
}

#[derive(Debug, Default)]
struct MockState {
    next_up: Option<ScriptedTunnelOutcome>,
    next_down: Option<ScriptedTunnelOutcome>,
    next_status: Option<ScriptedTunnelOutcome>,
    last_handle: Option<TunnelHandle>,
}

/// Scriptable mock implementation of [`Tunnel`].
#[derive(Debug, Clone, Default)]
pub struct MockTunnel {
    state: Arc<Mutex<MockState>>,
    invocations: TunnelCallLog,
    capabilities: TunnelCapabilities,
}

impl MockTunnel {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a clone of the shared invocation log handle.
    #[must_use]
    pub fn invocations(&self) -> TunnelCallLog {
        Arc::clone(&self.invocations)
    }

    /// Script the next `up` call.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn script_up(&self, outcome: ScriptedTunnelOutcome) {
        self.state.lock().unwrap().next_up = Some(outcome);
    }

    /// Script the next `down` call.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn script_down(&self, outcome: ScriptedTunnelOutcome) {
        self.state.lock().unwrap().next_down = Some(outcome);
    }

    /// Script the next `status` call.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn script_status(&self, outcome: ScriptedTunnelOutcome) {
        self.state.lock().unwrap().next_status = Some(outcome);
    }

    /// Override the capabilities this mock reports.
    pub fn set_capabilities(&mut self, caps: TunnelCapabilities) {
        self.capabilities = caps;
    }

    fn record(
        &self,
        method: &'static str,
        profile_id: &crate::vortix_core::profile::ProfileId,
        iface: Option<&str>,
    ) {
        self.invocations.lock().unwrap().push(RecordedTunnelCall {
            method,
            profile_id: profile_id.clone(),
            interface_name: iface.map(str::to_string),
        });
    }
}

#[derive(Debug, Default)]
struct MockProtocolStatus;

impl ProtocolStatus for MockProtocolStatus {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Debug, Default)]
struct MockParsedProfile;

impl ParsedProfile for MockParsedProfile {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn outcome_to_handle(
    profile: &Profile,
    outcome: ScriptedTunnelOutcome,
) -> Result<TunnelHandle, TunnelError> {
    match outcome {
        ScriptedTunnelOutcome::DefaultSuccess => Ok(TunnelHandle {
            profile_id: profile.id.clone(),
            interface_name: "mock0".to_string(),
            pid: None,
            started_at: SystemTime::now(),
            kind: TunnelKindTag::Mock,
        }),
        ScriptedTunnelOutcome::UpSuccess {
            interface_name,
            pid,
        } => Ok(TunnelHandle {
            profile_id: profile.id.clone(),
            interface_name,
            pid,
            started_at: SystemTime::now(),
            kind: TunnelKindTag::Mock,
        }),
        ScriptedTunnelOutcome::Failure(msg) => Err(TunnelError::Subprocess(msg)),
        ScriptedTunnelOutcome::HandshakeFailed(msg) => Err(TunnelError::HandshakeFailed(msg)),
        ScriptedTunnelOutcome::AuthFailed(msg) => Err(TunnelError::AuthFailed(msg)),
        ScriptedTunnelOutcome::Timeout(d) => Err(TunnelError::Timeout(d)),
    }
}

fn outcome_to_unit(outcome: ScriptedTunnelOutcome) -> Result<(), TunnelError> {
    match outcome {
        ScriptedTunnelOutcome::DefaultSuccess | ScriptedTunnelOutcome::UpSuccess { .. } => Ok(()),
        ScriptedTunnelOutcome::Failure(msg) => Err(TunnelError::Subprocess(msg)),
        ScriptedTunnelOutcome::HandshakeFailed(msg) => Err(TunnelError::HandshakeFailed(msg)),
        ScriptedTunnelOutcome::AuthFailed(msg) => Err(TunnelError::AuthFailed(msg)),
        ScriptedTunnelOutcome::Timeout(d) => Err(TunnelError::Timeout(d)),
    }
}

impl Tunnel for MockTunnel {
    fn up(&mut self, profile: &Profile) -> Result<TunnelHandle, TunnelError> {
        self.record("up", &profile.id, None);
        let outcome = self
            .state
            .lock()
            .unwrap()
            .next_up
            .take()
            .unwrap_or(ScriptedTunnelOutcome::DefaultSuccess);
        let handle = outcome_to_handle(profile, outcome)?;
        self.state.lock().unwrap().last_handle = Some(handle.clone());
        Ok(handle)
    }

    fn down(&mut self, handle: TunnelHandle) -> Result<(), TunnelError> {
        self.record("down", &handle.profile_id, Some(&handle.interface_name));
        let outcome = self
            .state
            .lock()
            .unwrap()
            .next_down
            .take()
            .unwrap_or(ScriptedTunnelOutcome::DefaultSuccess);
        outcome_to_unit(outcome)
    }

    fn status(&self, handle: &TunnelHandle) -> Result<TunnelStatus, TunnelError> {
        self.record("status", &handle.profile_id, Some(&handle.interface_name));
        let outcome = self
            .state
            .lock()
            .unwrap()
            .next_status
            .take()
            .unwrap_or(ScriptedTunnelOutcome::DefaultSuccess);
        outcome_to_unit(outcome.clone())?;
        Ok(TunnelStatus {
            handle: handle.clone(),
            bytes_rx: 0,
            bytes_tx: 0,
            last_handshake: None,
            observed_at: SystemTime::now(),
            detail: Box::new(MockProtocolStatus),
        })
    }

    fn parse_profile(&self, _raw: &[u8]) -> Result<Box<dyn ParsedProfile>, ParseError> {
        Ok(Box::new(MockParsedProfile))
    }

    fn capabilities(&self) -> TunnelCapabilities {
        self.capabilities
    }

    fn kind_tag(&self) -> TunnelKindTag {
        TunnelKindTag::Mock
    }
}

impl Default for TunnelCapabilities {
    fn default() -> Self {
        Self {
            supports_split_tunnel: false,
            supports_ipv6: true,
            mtu_configurable: false,
            supports_reconnect_without_disconnect: false,
            requires_root: false,
            userspace: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::ports::tunnel::test_profile;
    use crate::vortix_core::profile::ProtocolKind;

    #[test]
    fn default_success_returns_handle() {
        let mut t = MockTunnel::new();
        let p = test_profile("corp", ProtocolKind::WireGuard);
        let h = t.up(&p).unwrap();
        assert_eq!(h.profile_id.as_str(), "corp");
        assert_eq!(h.kind, TunnelKindTag::Mock);
    }

    #[test]
    fn scripted_handshake_failure() {
        let mut t = MockTunnel::new();
        t.script_up(ScriptedTunnelOutcome::HandshakeFailed("bad key".into()));
        let p = test_profile("corp", ProtocolKind::WireGuard);
        let err = t.up(&p).unwrap_err();
        assert!(matches!(err, TunnelError::HandshakeFailed(_)));
    }

    #[test]
    fn invocations_recorded() {
        let mut t = MockTunnel::new();
        let p = test_profile("corp", ProtocolKind::WireGuard);
        let h = t.up(&p).unwrap();
        t.status(&h).unwrap();
        t.down(h).unwrap();
        let log = t.invocations();
        let calls = log.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].method, "up");
        assert_eq!(calls[1].method, "status");
        assert_eq!(calls[2].method, "down");
    }
}
