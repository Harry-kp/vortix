//! `Input` enum and friends — what the FSM `handle(input)` consumes.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::vortix_core::profile::ProfileId;

/// Legacy commands accepted by the per-tunnel engine.
///
/// This remains a distinct compatibility contract until U7/U8 move every
/// engine caller onto the canonical control service. In particular,
/// [`Self::UserAnswered`] retains its historical serde shape and no-op FSM
/// behaviour. Credential-bearing answers must never be converted into the
/// canonical, serializable control command/event/snapshot vocabulary; new
/// challenge answers use the memory-only `control::ChallengeResponse` path.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[doc(hidden)]
pub enum EngineUserCommand {
    Connect {
        profile_id: ProfileId,
    },
    Disconnect {
        profile_id: Option<ProfileId>,
    },
    Reconnect {
        profile_id: Option<ProfileId>,
    },
    ForceDisconnect {
        profile_id: Option<ProfileId>,
    },
    /// Compatibility-only response reserved for the unfinished legacy 2FA
    /// flow. The engine deliberately ignores it.
    UserAnswered {
        prompt_id: String,
        answer: String,
    },
}

/// U7/U8 compatibility export for the historical engine command path.
pub use EngineUserCommand as UserCommand;

/// Network link state (default gateway availability).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum LinkState {
    Up,
    Down,
}

/// Why the FSM was told a profile changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ProfileChange {
    Renamed {
        profile_id: ProfileId,
        old_display_name: String,
        new_display_name: String,
    },
    Deleted {
        profile_id: ProfileId,
    },
    Imported {
        profile_id: ProfileId,
    },
}

/// What the scanner (or any other observer) reports about a live tunnel.
///
/// Scanner facts are observation-only. In particular, an `Active` fact does
/// not contain a protocol receipt and can never promote `Disconnected` to
/// `Connected`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TunnelStatusObservation {
    Active {
        profile_id: ProfileId,
        interface_name: String,
        started_at: SystemTime,
    },
    Inactive {
        profile_id: ProfileId,
    },
}

/// Telemetry updates that the engine consumes (loose union of what
/// `vortix::core::telemetry::TelemetryUpdate` carries today). A later
/// migration moves telemetry to its own actor and tightens this shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TelemetryReport {
    Ip(Option<String>),
    Latency(u64),
    PacketLoss(f32),
    Jitter(u64),
    Dns(String),
    PublicIpv6(Option<String>),
}

/// The single input type `Engine::handle(input)` consumes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Input {
    UserCommand(UserCommand),
    /// Per-tick wake-up (drives retry-budget decrement, telemetry polling, etc.).
    Tick,
    NetworkLinkChanged(LinkState),
    TelemetryReport(TelemetryReport),
    ProfileChanged(ProfileChange),
    TunnelStatusObserved(TunnelStatusObservation),
}

#[cfg(test)]
mod tests {
    //! `UserCommand` wire-format round-trip + v1 wire-break
    //! verification.

    use super::*;

    fn pid(label: &str) -> ProfileId {
        let digit = if label == "corp" { 'c' } else { 'd' };
        ProfileId::parse(digit.to_string().repeat(ProfileId::HEX_LEN)).unwrap()
    }

    fn roundtrip(cmd: &UserCommand) -> UserCommand {
        let json = serde_json::to_string(cmd).expect("serialize");
        serde_json::from_str::<UserCommand>(&json).expect("deserialize")
    }

    #[test]
    fn disconnect_none_round_trips() {
        let cmd = UserCommand::Disconnect { profile_id: None };
        let back = roundtrip(&cmd);
        match back {
            UserCommand::Disconnect { profile_id: None } => {}
            other => panic!("expected Disconnect{{None}}, got {other:?}"),
        }
    }

    #[test]
    fn disconnect_some_round_trips() {
        let cmd = UserCommand::Disconnect {
            profile_id: Some(pid("corp")),
        };
        let back = roundtrip(&cmd);
        match back {
            UserCommand::Disconnect {
                profile_id: Some(id),
            } => assert_eq!(id, pid("corp")),
            other => panic!("expected Disconnect{{Some(corp)}}, got {other:?}"),
        }
    }

    #[test]
    fn reconnect_none_round_trips() {
        let cmd = UserCommand::Reconnect { profile_id: None };
        assert!(matches!(
            roundtrip(&cmd),
            UserCommand::Reconnect { profile_id: None }
        ));
    }

    #[test]
    fn force_disconnect_some_round_trips() {
        let cmd = UserCommand::ForceDisconnect {
            profile_id: Some(pid("home")),
        };
        match roundtrip(&cmd) {
            UserCommand::ForceDisconnect {
                profile_id: Some(id),
            } => assert_eq!(id, pid("home")),
            other => panic!("expected ForceDisconnect{{Some}}, got {other:?}"),
        }
    }

    #[test]
    fn disconnect_serializes_as_tagged_object_not_string() {
        // The wire-break verification: v2 wire form must be a tagged
        // *object*, not a tagged string. A v1 client sending
        // `{"kind":"disconnect"}` is the exact regression we want to
        // catch — see `v1_unit_variant_payload_rejected_by_v2`.
        let cmd = UserCommand::Disconnect { profile_id: None };
        let json = serde_json::to_string(&cmd).expect("serialize");
        // serde struct-variant emits `{"Disconnect":{"profile_id":null}}`
        // for the default (untagged) representation. The serde tagging
        // belongs to the IPC envelope (`IpcOp` carries the `tag="kind"`);
        // UserCommand itself uses the externally-tagged shape so the
        // wire still distinguishes `"Disconnect"` (object) from the
        // legacy `"Disconnect"` (string).
        assert!(
            json.contains("\"Disconnect\""),
            "expected externally-tagged Disconnect variant, got: {json}"
        );
        assert!(
            json.contains("profile_id"),
            "expected struct-variant payload key, got: {json}"
        );
    }

    #[test]
    fn v1_unit_variant_payload_rejected_by_v2() {
        // A v1 client sending the legacy unit form `"Disconnect"`
        // (string, not object) must NOT silently mis-parse as
        // `Disconnect{profile_id: None}` — that would defeat the
        // coordinated-upgrade requirement. With externally-tagged
        // struct variants, serde rejects the string form.
        let v1_payload = "\"Disconnect\"";
        let parsed: Result<UserCommand, _> = serde_json::from_str(v1_payload);
        assert!(
            parsed.is_err(),
            "v1 unit-variant payload `{v1_payload}` should be rejected by v2 deserializer, \
             got: {parsed:?}"
        );
    }

    #[test]
    fn legacy_user_answered_wire_shape_is_pinned() {
        let command = UserCommand::UserAnswered {
            prompt_id: "prompt-7".to_owned(),
            answer: "legacy-secret".to_owned(),
        };
        let json = serde_json::to_string(&command).expect("serialize legacy command");
        assert_eq!(
            json,
            r#"{"UserAnswered":{"prompt_id":"prompt-7","answer":"legacy-secret"}}"#
        );

        let decoded: UserCommand = serde_json::from_str(&json).expect("deserialize legacy command");
        assert!(matches!(
            decoded,
            UserCommand::UserAnswered { prompt_id, answer }
                if prompt_id == "prompt-7" && answer == "legacy-secret"
        ));
    }
}
