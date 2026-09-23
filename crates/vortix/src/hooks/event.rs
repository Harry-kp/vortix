//! Typed lifecycle facts consumed by unprivileged observational hooks.
//!
//! This module deliberately contains no subprocess vocabulary.  The control
//! owner publishes committed facts; an outer adapter may attempt bounded
//! delivery without gaining any lifecycle veto or privileged capability.

use serde::{Deserialize, Serialize};

use crate::vortix_core::profile::{ProfileId, ProtocolKind};

/// Lifecycle transitions available to global hook specifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookEvent {
    ConnectStarted,
    Connected,
    DisconnectStarted,
    Disconnected,
    ConnectFailed,
    Reconnecting,
}

impl HookEvent {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConnectStarted => "connect_started",
            Self::Connected => "connected",
            Self::DisconnectStarted => "disconnect_started",
            Self::Disconnected => "disconnected",
            Self::ConnectFailed => "connect_failed",
            Self::Reconnecting => "reconnecting",
        }
    }
}

/// Stable identity for one committed lifecycle fact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HookEventId(String);

impl HookEventId {
    pub(crate) fn from_parts(authority_epoch: u64, sequence: u64) -> Self {
        Self(format!("hook-{authority_epoch:016x}-{sequence:016x}"))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for HookEventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A committed lifecycle transition safe to expose to an owner-run hook.
///
/// Endpoint, address, DNS, credential, and profile-body data are
/// intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleFact {
    pub event_id: HookEventId,
    pub event: HookEvent,
    pub profile_id: ProfileId,
    pub display_name: String,
    pub protocol: ProtocolKind,
    pub occurred_at_millis: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_fact_schema_excludes_network_and_secret_material() {
        let fact = LifecycleFact {
            event_id: HookEventId::from_parts(4, 9),
            event: HookEvent::Connected,
            profile_id: ProfileId::new("corp"),
            display_name: "Corporate".into(),
            protocol: ProtocolKind::WireGuard,
            occurred_at_millis: 42,
        };
        let json = serde_json::to_value(fact).unwrap();
        let object = json.as_object().unwrap();
        assert_eq!(object.len(), 6);
        for forbidden in [
            "endpoint",
            "address",
            "dns",
            "credential",
            "secret",
            "profile_body",
        ] {
            assert!(!object.contains_key(forbidden));
        }
    }
}
