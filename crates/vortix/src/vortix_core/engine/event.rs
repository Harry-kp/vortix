//! `EngineEvent` schema and JSONL envelope (plan #005 U1).
//!
//! Fifteen day-one event variants describe everything the FSM emits to the
//! journal and the broadcast channel. The envelope carries a
//! `schema_version: u32` (starts at 1) so future schema evolution can be
//! detected by replay tooling.

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::vortix_core::engine::registry::Conflict;
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
    /// Multi-connection plan U23: the primary tunnel (the one holding the
    /// kernel default route) changed. `from`/`to` are `None` when the
    /// transition crosses the "no primary" boundary (initial connect or
    /// last-primary disconnect). The wiring that emits this event from the
    /// registry lands in U7/U6B; U23 only adds the variant.
    PrimaryTunnelChanged {
        from: Option<ProfileId>,
        to: Option<ProfileId>,
        via_interface: Option<String>,
        reason: PrimaryChangeReason,
    },
    /// Multi-connection plan U23: a connect attempt was rejected by
    /// `TunnelRegistry::connect` because a `Conflict` was detected and the
    /// caller did not pass `force=true`. The UI uses this to render the
    /// takeover overlay; CLI replay tooling uses it to summarise blocked
    /// attempts.
    ConnectAttemptBlockedByConflict {
        conflict: Conflict,
        profile_id: ProfileId,
    },
}

/// Why the primary tunnel changed.
///
/// Distinct from `vortix_core::engine::registry::PrimaryTunnelChangeReason`
/// (which is the internal, non-serde enum the registry uses for structured
/// logging today). The journal-event variant is named per plan U23 — its
/// `InitialConnect` value covers the "no primary → new primary" transition
/// the registry expresses with `NewTunnelTookDefaultRoute`. Keeping them
/// separate lets the journal vocabulary evolve without forcing every
/// registry internal-state change to bump the journal schema, and vice
/// versa. The U7/U6B wiring is responsible for mapping the registry's
/// reason onto this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum PrimaryChangeReason {
    /// A new connect succeeded and there was no prior primary (or the
    /// transition crossed the "no primary → primary" boundary).
    InitialConnect,
    /// The prior primary disconnected; another tunnel already declaring
    /// `0/0` was promoted by the kernel.
    PriorPrimaryDisconnected,
    /// An external route change (user ran `wg-quick down`, route flap, etc.)
    /// observed by the Tick-bound safety net.
    ExternalRouteChange,
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

    // ─────────────────────────────────────────────────────────────────────
    // U23: PrimaryTunnelChanged + ConnectAttemptBlockedByConflict
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn primary_tunnel_changed_round_trips_through_json() {
        let event = EngineEvent::PrimaryTunnelChanged {
            from: Some(ProfileId::new("corp")),
            to: Some(ProfileId::new("home")),
            via_interface: Some("wg1".to_string()),
            reason: PrimaryChangeReason::PriorPrimaryDisconnected,
        };
        let json = serde_json::to_string(&event).unwrap();
        // Tag uses snake_case `kind` discriminator.
        assert!(json.contains(r#""kind":"primary_tunnel_changed""#));
        assert!(json.contains(r#""reason":"prior_primary_disconnected""#));
        let back: EngineEvent = serde_json::from_str(&json).unwrap();
        match back {
            EngineEvent::PrimaryTunnelChanged {
                from,
                to,
                via_interface,
                reason,
            } => {
                assert_eq!(from.as_ref().map(ProfileId::as_str), Some("corp"));
                assert_eq!(to.as_ref().map(ProfileId::as_str), Some("home"));
                assert_eq!(via_interface.as_deref(), Some("wg1"));
                assert_eq!(reason, PrimaryChangeReason::PriorPrimaryDisconnected);
            }
            _ => panic!("expected PrimaryTunnelChanged"),
        }
    }

    #[test]
    fn primary_tunnel_changed_with_no_prior_primary_round_trips() {
        // Initial-connect: `from` is `None`.
        let event = EngineEvent::PrimaryTunnelChanged {
            from: None,
            to: Some(ProfileId::new("corp")),
            via_interface: None,
            reason: PrimaryChangeReason::InitialConnect,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: EngineEvent = serde_json::from_str(&json).unwrap();
        match back {
            EngineEvent::PrimaryTunnelChanged {
                from,
                to,
                via_interface,
                reason,
            } => {
                assert!(from.is_none());
                assert_eq!(to.as_ref().map(ProfileId::as_str), Some("corp"));
                assert!(via_interface.is_none());
                assert_eq!(reason, PrimaryChangeReason::InitialConnect);
            }
            _ => panic!("expected PrimaryTunnelChanged"),
        }
    }

    #[test]
    fn primary_change_reason_external_route_change_round_trips() {
        let event = EngineEvent::PrimaryTunnelChanged {
            from: Some(ProfileId::new("corp")),
            to: None,
            via_interface: None,
            reason: PrimaryChangeReason::ExternalRouteChange,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#""reason":"external_route_change""#));
        let back: EngineEvent = serde_json::from_str(&json).unwrap();
        if let EngineEvent::PrimaryTunnelChanged { reason, .. } = back {
            assert_eq!(reason, PrimaryChangeReason::ExternalRouteChange);
        } else {
            panic!("expected PrimaryTunnelChanged");
        }
    }

    #[test]
    fn connect_attempt_blocked_by_conflict_round_trips_default_route_takeover() {
        let event = EngineEvent::ConnectAttemptBlockedByConflict {
            conflict: Conflict::DefaultRouteTakeover {
                current: ProfileId::new("corp"),
                new: ProfileId::new("home"),
            },
            profile_id: ProfileId::new("home"),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#""kind":"connect_attempt_blocked_by_conflict""#));
        assert!(json.contains(r#""kind":"default_route_takeover""#));
        let back: EngineEvent = serde_json::from_str(&json).unwrap();
        match back {
            EngineEvent::ConnectAttemptBlockedByConflict {
                conflict,
                profile_id,
            } => {
                assert_eq!(profile_id.as_str(), "home");
                match conflict {
                    Conflict::DefaultRouteTakeover { current, new } => {
                        assert_eq!(current.as_str(), "corp");
                        assert_eq!(new.as_str(), "home");
                    }
                    _ => panic!("expected DefaultRouteTakeover"),
                }
            }
            _ => panic!("expected ConnectAttemptBlockedByConflict"),
        }
    }

    #[test]
    fn connect_attempt_blocked_by_conflict_round_trips_route_overlap() {
        use crate::vortix_core::cidr::Cidr;
        use std::net::IpAddr;
        use std::str::FromStr;

        let cidr = Cidr::new(IpAddr::from_str("10.0.0.0").unwrap(), 8).unwrap();
        let event = EngineEvent::ConnectAttemptBlockedByConflict {
            conflict: Conflict::RouteOverlap {
                with: ProfileId::new("corp"),
                overlapping_cidrs: vec![cidr],
            },
            profile_id: ProfileId::new("home"),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: EngineEvent = serde_json::from_str(&json).unwrap();
        match back {
            EngineEvent::ConnectAttemptBlockedByConflict {
                conflict:
                    Conflict::RouteOverlap {
                        with,
                        overlapping_cidrs,
                    },
                profile_id,
            } => {
                assert_eq!(with.as_str(), "corp");
                assert_eq!(profile_id.as_str(), "home");
                assert_eq!(overlapping_cidrs.len(), 1);
                assert_eq!(overlapping_cidrs[0].prefix_len, 8);
            }
            _ => panic!("expected ConnectAttemptBlockedByConflict / RouteOverlap"),
        }
    }

    #[test]
    fn existing_tunnel_up_serialization_unchanged() {
        // Regression guard: adding U23 variants must not alter the wire shape
        // of any pre-existing variant. The serialized JSON for TunnelUp is
        // pinned exactly.
        let event = EngineEvent::TunnelUp {
            profile_id: ProfileId::new("corp"),
            protocol: ProtocolKind::WireGuard,
            interface_name: "wg0".to_string(),
            pid: Some(1234),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"tunnel_up","profile_id":"corp","protocol":"WireGuard","interface_name":"wg0","pid":1234}"#
        );
    }

    #[test]
    fn existing_network_link_lost_serialization_unchanged() {
        let event = EngineEvent::NetworkLinkLost;
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(json, r#"{"kind":"network_link_lost"}"#);
    }

    #[test]
    fn existing_journal_retention_applied_serialization_unchanged() {
        let event = EngineEvent::JournalRetentionApplied { deleted: 7 };
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(json, r#"{"kind":"journal_retention_applied","deleted":7}"#);
    }
}
