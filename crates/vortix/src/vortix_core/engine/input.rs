//! `Input` enum and friends — what the FSM `handle(input)` consumes (plan #005 U1).

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::vortix_core::profile::ProfileId;

/// User-initiated commands routed through the engine.
///
/// ## Multi-tunnel wire shape (plan 001 U22)
///
/// The disconnect / reconnect / force-disconnect variants carry an
/// `Option<ProfileId>` payload: `None` targets every active tunnel
/// (the v1 "disconnect everything" intent), `Some(id)` targets a
/// single tunnel.
///
/// **Wire-protocol break:** under `#[serde(tag="kind", rename_all="snake_case")]`
/// this changes the JSON shape from a tagged string
/// (`{"kind":"disconnect"}`) to a tagged object
/// (`{"kind":"disconnect","profile_id":null}`). v1 daemon clients and
/// v2 daemons cannot interop on these three variants; a coordinated
/// upgrade is required.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum UserCommand {
    Connect {
        profile_id: ProfileId,
    },
    /// Disconnect a single tunnel (`Some(profile_id)`) or every active
    /// tunnel (`None`). The daemon's UID gate is sufficient
    /// authorization for the `None` form in v1's single-user trust
    /// model; multi-user scenarios will need an explicit confirmation
    /// parameter (see SECURITY.md once U24 lands).
    Disconnect {
        profile_id: Option<ProfileId>,
    },
    /// Reconnect a single tunnel (`Some(profile_id)`) or every active
    /// tunnel (`None`).
    Reconnect {
        profile_id: Option<ProfileId>,
    },
    /// Force-disconnect (skip graceful teardown). Same `None`/`Some`
    /// semantics as [`UserCommand::Disconnect`].
    ForceDisconnect {
        profile_id: Option<ProfileId>,
    },
    /// Plan 008 U2: response to a mid-connect `UserPromptRequested`
    /// event. Reserved for issue #191 (2FA); no consumer wired in
    /// v0.3.0. `prompt_id` matches the value emitted on the prompt
    /// event so the FSM can correlate the answer with the right
    /// outstanding prompt.
    UserAnswered {
        prompt_id: String,
        answer: String,
    },
}

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
/// Per the brainstorm R18, the scanner is now an *input source* — the FSM
/// reconciles its model against the observation instead of the scanner
/// mutating the engine directly.
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
/// `vortix::core::telemetry::TelemetryUpdate` carries today). Plan #005 U7
/// migrates telemetry to its own actor and tightens this shape.
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
    //! Plan #001 U22 — `UserCommand` wire-format round-trip + v1 wire-break
    //! verification.

    use super::*;

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
            profile_id: Some(ProfileId::new("corp")),
        };
        let back = roundtrip(&cmd);
        match back {
            UserCommand::Disconnect {
                profile_id: Some(id),
            } => assert_eq!(id.as_str(), "corp"),
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
            profile_id: Some(ProfileId::new("home")),
        };
        match roundtrip(&cmd) {
            UserCommand::ForceDisconnect {
                profile_id: Some(id),
            } => assert_eq!(id.as_str(), "home"),
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
}
