//! `Input` enum and friends — what the FSM `handle(input)` consumes (plan #005 U1).

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::profile::ProfileId;

/// User-initiated commands routed through the engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum UserCommand {
    Connect {
        profile_id: ProfileId,
    },
    Disconnect,
    Reconnect,
    ForceDisconnect,
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
    Ipv6Leak(bool),
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
