//! Engine connection state types (plan #005 U1).
//!
//! Five-variant `Connection` machine plus the supporting health/failure
//! enums. Matches the brainstorm shape: `Failed` collapses into
//! `Disconnected { last_failure }` rather than being a sixth variant.

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::vortix_core::profile::ProfileId;

/// How long the engine waits for a connect/reconnect to succeed before
/// declaring the retry budget exhausted. Per the brainstorm: 300s default,
/// configurable via plan #006's `[engine] retry_budget_secs`.
pub const DEFAULT_RETRY_BUDGET_SECS: u64 = 300;

/// Why a previous connect or reconnect attempt ended in `Disconnected`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum FailureReason {
    /// The retry budget expired with no successful connection.
    RetryBudgetExhausted { attempts: u32, elapsed: Duration },
    /// `Tunnel::up` reported `HandshakeFailed`.
    HandshakeFailed(String),
    /// `Tunnel::up` reported `AuthFailed`.
    AuthFailed(String),
    /// Profile parsing surfaced an unrecoverable error.
    ConfigInvalid(String),
    /// `Tunnel::up` exceeded its configured timeout with no progress.
    Timeout(Duration),
    /// The network link went down and never came back during the retry budget.
    NoNetworkLink,
    /// The profile referenced by the in-flight connect was deleted or renamed
    /// out from under the engine. `ProfileRenamed` updates the FSM in place
    /// when possible; this variant covers the unrecoverable cases.
    ProfileGone(ProfileId),
    /// Anything else surfaced as `TunnelError::Other`.
    Other(String),
}

/// Cause for `ConnectionHealth::Degraded`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DegradedReason {
    /// `wg show` reports `latest_handshake` exceeding the staleness threshold.
    HandshakeStale { seconds_since_last_handshake: u64 },
    /// Telemetry reports high packet loss to all configured probe targets.
    HighPacketLoss { loss_percent: f32 },
    /// Telemetry reports ICMP latency above the configured threshold.
    HighLatency { latency_ms: u64 },
}

/// Health summary for `Connection::Connected`.
///
/// `Unknown` is the initial state immediately after a successful `up` —
/// telemetry hasn't reported yet. The TUI renders "Measuring…" in that
/// window (v0.1.7 ROADMAP item).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ConnectionHealth {
    #[default]
    Unknown,
    Healthy,
    Degraded {
        reason: DegradedReason,
    },
}

/// Technical details parsed from the VPN interface (relocated from the
/// binary-side `crates/vortix/src/state/connection.rs`; plan 007 prunes
/// the duplicate).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetailedConnectionInfo {
    pub interface: String,
    pub internal_ip: String,
    pub endpoint: String,
    pub mtu: String,
    /// `WireGuard` public key (empty for `OpenVPN`).
    pub public_key: String,
    pub listen_port: String,
    pub transfer_rx: String,
    pub transfer_tx: String,
    pub latest_handshake: String,
    pub pid: Option<u32>,
}

/// What kind of user input the FSM is paused waiting for (plan 008 U2).
///
/// `#[non_exhaustive]` so adding e.g. `BiometricChallenge` later doesn't
/// break consumers pattern-matching on this enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum PromptKind {
    /// One-time code from an authenticator app or SMS.
    TwoFactorCode,
    /// Password / passphrase for an encrypted credential file.
    Passphrase,
    /// Anything else; `label` is rendered verbatim to the user.
    Generic { label: String },
}

/// The connection state machine (plan 005, extended in plan 008 U2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Connection {
    /// No active VPN connection. Optionally remembers why the previous attempt
    /// failed so the TUI can surface a "Last error: …" hint.
    Disconnected { last_failure: Option<FailureReason> },
    /// Initial connect in progress.
    Connecting {
        profile_id: ProfileId,
        started_at: SystemTime,
        /// 1-based attempt counter for the current connect operation.
        attempt: u32,
        retry_budget_remaining: Duration,
    },
    /// Active VPN connection.
    Connected {
        profile_id: ProfileId,
        since: SystemTime,
        health: ConnectionHealth,
        details: Box<DetailedConnectionInfo>,
    },
    /// Lost the tunnel; trying to bring it back without involving the user.
    Reconnecting {
        profile_id: ProfileId,
        started_at: SystemTime,
        attempt: u32,
        retry_budget_remaining: Duration,
        last_error: Option<String>,
    },
    /// User-initiated disconnect in progress.
    Disconnecting {
        profile_id: ProfileId,
        started_at: SystemTime,
    },
    /// Mid-connect prompt waiting for the user to supply input
    /// (2FA challenge, certificate passphrase, etc.). Plan 008 U2
    /// reserves the slot for issue #191 (Interactive 2FA/MFA);
    /// no consumer is wired in v0.3.0.
    AwaitingUserInput {
        profile_id: ProfileId,
        prompt_id: String,
        prompt_kind: PromptKind,
        since: SystemTime,
    },
}

impl Default for Connection {
    fn default() -> Self {
        Self::Disconnected { last_failure: None }
    }
}

impl Connection {
    /// The profile currently in scope (`None` only for `Disconnected`).
    #[must_use]
    pub fn profile_id(&self) -> Option<&ProfileId> {
        match self {
            Self::Disconnected { .. } => None,
            Self::Connecting { profile_id, .. }
            | Self::Connected { profile_id, .. }
            | Self::Reconnecting { profile_id, .. }
            | Self::Disconnecting { profile_id, .. }
            | Self::AwaitingUserInput { profile_id, .. } => Some(profile_id),
        }
    }

    /// `true` when the engine is in a steady-state, non-transitional state.
    #[must_use]
    pub fn is_steady(&self) -> bool {
        matches!(self, Self::Disconnected { .. } | Self::Connected { .. })
    }

    /// `true` when an active tunnel exists (Connected).
    #[must_use]
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disconnected_with_no_failure() {
        let s = Connection::default();
        assert!(matches!(s, Connection::Disconnected { last_failure: None }));
    }

    #[test]
    fn profile_id_is_none_for_disconnected() {
        let s = Connection::default();
        assert!(s.profile_id().is_none());
    }

    #[test]
    fn profile_id_is_some_for_other_states() {
        let p = ProfileId::new("corp");
        let s = Connection::Connecting {
            profile_id: p.clone(),
            started_at: SystemTime::now(),
            attempt: 1,
            retry_budget_remaining: Duration::from_secs(300),
        };
        assert_eq!(s.profile_id(), Some(&p));
    }

    #[test]
    fn is_steady_distinguishes_states() {
        let p = ProfileId::new("corp");
        assert!(Connection::default().is_steady());
        assert!(!Connection::Connecting {
            profile_id: p.clone(),
            started_at: SystemTime::now(),
            attempt: 1,
            retry_budget_remaining: Duration::from_secs(300),
        }
        .is_steady());
    }

    // Plan 008 U2 — AwaitingUserInput coverage.

    #[test]
    fn awaiting_user_input_carries_profile_id() {
        let p = ProfileId::new("corp");
        let s = Connection::AwaitingUserInput {
            profile_id: p.clone(),
            prompt_id: "2fa".into(),
            prompt_kind: PromptKind::TwoFactorCode,
            since: SystemTime::now(),
        };
        assert_eq!(s.profile_id(), Some(&p));
    }

    #[test]
    fn awaiting_user_input_is_not_steady() {
        // Like Connecting/Disconnecting, it's a transitional state.
        let s = Connection::AwaitingUserInput {
            profile_id: ProfileId::new("corp"),
            prompt_id: "2fa".into(),
            prompt_kind: PromptKind::TwoFactorCode,
            since: SystemTime::now(),
        };
        assert!(!s.is_steady());
        assert!(!s.is_connected());
    }

    #[test]
    fn prompt_kind_roundtrips_through_json() {
        let kinds = [
            PromptKind::TwoFactorCode,
            PromptKind::Passphrase,
            PromptKind::Generic {
                label: "Hardware token PIN".into(),
            },
        ];
        for k in kinds {
            let json = serde_json::to_string(&k).unwrap();
            let back: PromptKind = serde_json::from_str(&json).unwrap();
            assert_eq!(k, back);
        }
    }
}
