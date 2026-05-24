//! `EngineEvent` schema and JSONL envelope (plan #005 U1).
//!
//! Fifteen day-one event variants describe everything the FSM emits to the
//! journal and the broadcast channel. The envelope carries a
//! `schema_version: u32` (starts at 1) so future schema evolution can be
//! detected by replay tooling.

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::vortix_core::engine::state::{ConnectionHealth, DegradedReason, FailureReason};
use crate::vortix_core::profile::{ProfileId, ProtocolKind};

/// Current journal schema version. Bumped when `EngineEvent`'s wire format
/// changes incompatibly.
pub const SCHEMA_VERSION: u32 = 1;

/// JSONL envelope written to disk and broadcast to subscribers.
///
/// Each envelope is one line in the journal file. `timestamp` is RFC3339;
/// `event` is the tagged enum below.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub schema_version: u32,
    pub timestamp: SystemTime,
    pub event: EngineEvent,
}

impl EventEnvelope {
    /// Wrap an event in a fresh envelope stamped with the current schema
    /// version and "now".
    #[must_use]
    pub fn new(event: EngineEvent) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            timestamp: SystemTime::now(),
            event,
        }
    }
}

/// Everything the FSM emits.
///
/// `#[non_exhaustive]` so future variants don't break replay tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EngineEvent {
    /// FSM started a connect attempt for `profile_id`.
    ConnectAttemptStarted {
        profile_id: ProfileId,
        protocol: ProtocolKind,
        attempt: u32,
    },
    /// A connect / reconnect attempt failed without exhausting the retry
    /// budget. Followed by `RetryScheduled` or `RetryBudgetExhausted`.
    ConnectAttemptFailed {
        profile_id: ProfileId,
        attempt: u32,
        reason: FailureReason,
    },
    /// Tunnel came up successfully.
    TunnelUp {
        profile_id: ProfileId,
        protocol: ProtocolKind,
        interface_name: String,
        pid: Option<u32>,
    },
    /// Tunnel went down (user-initiated disconnect, network loss, or daemon
    /// exit).
    TunnelDown {
        profile_id: ProfileId,
        reason: TunnelDownReason,
    },
    /// `wg show` reports `latest_handshake` exceeding the staleness threshold.
    HandshakeStale {
        profile_id: ProfileId,
        seconds_since_last_handshake: u64,
    },
    /// `Connected` health field changed.
    ConnectionHealthChanged {
        profile_id: ProfileId,
        old: ConnectionHealth,
        new: ConnectionHealth,
    },
    /// Detected a public IP change (telemetry-observed).
    IpChanged { old: Option<String>, new: String },
    /// Kill switch transitioned to actively blocking.
    KillswitchEngaged { reason: KillswitchEngageReason },
    /// Kill switch released.
    KillswitchDisengaged,
    /// A retry was scheduled after a transient failure.
    RetryScheduled {
        profile_id: ProfileId,
        next_attempt: u32,
        delay: Duration,
        retry_budget_remaining: Duration,
    },
    /// The retry budget was exhausted; FSM is moving back to
    /// `Disconnected { last_failure: RetryBudgetExhausted }`.
    RetryBudgetExhausted {
        profile_id: ProfileId,
        total_attempts: u32,
        elapsed: Duration,
    },
    /// Network monitor detected loss of the default route.
    NetworkLinkLost,
    /// Network monitor detected the default route returning.
    NetworkLinkRestored { new_gateway: Option<String> },
    /// Profile renamed by the user; FSM updates display name in place
    /// (`profile_id` is stable across renames per plan #005 R3).
    ProfileRenamed {
        profile_id: ProfileId,
        old_display_name: String,
        new_display_name: String,
    },
    /// User requested deletion of a profile that's currently in scope; FSM
    /// may have to tear down the tunnel before honoring the request.
    ProfileDeletionRequested { profile_id: ProfileId },
    /// Journal startup retention pass deleted N stale files.
    JournalRetentionApplied { deleted: u32 },
    /// A degraded condition cleared (paired with `ConnectionHealthChanged`
    /// when health returns to `Healthy`).
    DegradedReasonCleared {
        profile_id: ProfileId,
        reason: DegradedReason,
    },
    /// Plan 008 U2: the FSM needs the user to supply input to continue
    /// (2FA code, passphrase, etc.). Reserved for issue #191; no
    /// consumer wired in v0.3.0. The corresponding `UserCommand::UserAnswered`
    /// references the same `prompt_id`.
    UserPromptRequested {
        profile_id: ProfileId,
        prompt_id: String,
        prompt_kind: crate::vortix_core::engine::state::PromptKind,
        prompt_text: String,
    },
}

/// Why a tunnel went down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum TunnelDownReason {
    UserDisconnect,
    NetworkLinkLost,
    DaemonExited,
    HandshakeFailed,
}

/// Why the kill switch engaged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum KillswitchEngageReason {
    UserRequest,
    AutoOnConnect,
    AlwaysOn,
    RecoveredFromCrash,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trips_through_json() {
        let env = EventEnvelope::new(EngineEvent::TunnelUp {
            profile_id: ProfileId::new("corp"),
            protocol: ProtocolKind::WireGuard,
            interface_name: "wg0".to_string(),
            pid: None,
        });
        let json = serde_json::to_string(&env).unwrap();
        let back: EventEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema_version, SCHEMA_VERSION);
        match back.event {
            EngineEvent::TunnelUp { interface_name, .. } => {
                assert_eq!(interface_name, "wg0");
            }
            _ => panic!("expected TunnelUp"),
        }
    }

    #[test]
    fn snake_case_tag_uses_kind() {
        let env = EventEnvelope::new(EngineEvent::NetworkLinkLost);
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains(r#""kind":"network_link_lost""#));
    }
}
