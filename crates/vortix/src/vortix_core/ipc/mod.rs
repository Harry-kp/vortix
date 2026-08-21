//! Versioned IPC envelope and framing for passive daemon queries.
//!
//! The daemon (`vortix daemon`) and clients communicate
//! via length-prefixed JSON frames on a Unix domain socket. This
//! module defines:
//!
//! - The request/response envelope ([`IpcRequest`], [`IpcResponse`])
//! - The op vocabulary ([`IpcOp`], [`IpcResult`])
//! - Typed wire errors ([`IpcError`])
//! - The length-prefix codec ([`frame`])
//!
//! The actual transport (`tokio::net::UnixStream`) and the daemon
//! server loop live outside this module. The wire contract remains in core
//! so future clients and tests can speak it without importing transport
//! implementation details.

pub mod frame;

pub use frame::{decode_frame, encode_frame, FrameError, MAX_FRAME_BYTES};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Inclusive protocol range supported by this build. Protocol 2 introduced
/// the mandatory first-frame handshake; pre-handshake protocol 1 is not wire
/// compatible with this server.
pub const IPC_PROTOCOL_MIN: u16 = 2;
pub const IPC_PROTOCOL_MAX: u16 = 2;
/// Inclusive snapshot schema range supported by this build.
pub const IPC_SCHEMA_MIN: u16 = 1;
pub const IPC_SCHEMA_MAX: u16 = 1;

use crate::vortix_core::engine::input::UserCommand;
use crate::vortix_core::engine::registry::{Conflict, TunnelSnapshot};
use crate::vortix_core::engine::state::Connection;
use crate::vortix_core::profile::ProfileId;
use crate::vortix_core::state::KillSwitchState;

/// One operation a client can request from the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IpcOp {
    /// Mandatory first exchange on every connection. No other operation is
    /// decoded or dispatched until product, protocol, schema, and capability
    /// compatibility has been established.
    Handshake { hello: ClientHello },
    /// Execute a user command (Connect, Disconnect, Reconnect, ...).
    Execute(UserCommand),
    /// Read the legacy scanner projection used by transitional clients.
    Snapshot,
    /// Read the scanner-only candidate snapshot.
    PassiveSnapshot,
    /// Legacy spelling for a passive scanner subscription.
    Subscribe,
    /// Subscribe to complete scanner-only replacement snapshots.
    PassiveSubscribe,
    /// Graceful daemon shutdown. Authorized client only (UID-matching
    /// per `SO_PEERCRED`; see peer-credential auth).
    Shutdown,
}

impl IpcOp {
    /// Capability negotiated before this operation may be dispatched.
    #[must_use]
    pub const fn required_capability(&self) -> IpcCapability {
        match self {
            Self::Handshake { .. } | Self::PassiveSnapshot => IpcCapability::PassiveSnapshot,
            Self::Execute(_) => IpcCapability::ControlMutation,
            Self::Snapshot => IpcCapability::LegacySnapshot,
            Self::Subscribe | Self::PassiveSubscribe => IpcCapability::PassiveSubscribe,
            Self::Shutdown => IpcCapability::Shutdown,
        }
    }
}

/// Wrapper for the client→server direction. `id` is opaque to the
/// daemon; the client correlates response IDs back to outstanding
/// requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest {
    pub id: u64,
    pub op: IpcOp,
}

/// Wrapper for the server→client direction. `id` matches the
/// originating [`IpcRequest::id`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    pub id: u64,
    pub result: Result<IpcResult, IpcError>,
}

/// Inclusive compatibility range advertised during the mandatory handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityRange {
    pub min: u16,
    pub max: u16,
}

impl CompatibilityRange {
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.min > 0 && self.min <= self.max
    }

    #[must_use]
    pub fn highest_common(self, other: Self) -> Option<u16> {
        let minimum = self.min.max(other.min);
        let maximum = self.max.min(other.max);
        (minimum <= maximum).then_some(maximum)
    }
}

/// Explicit daemon capabilities. The passive candidate deliberately omits
/// every mutation/desired-state capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcCapability {
    LegacySnapshot,
    PassiveSnapshot,
    PassiveSubscribe,
    Shutdown,
    /// Reserved for the future enrolled control authority. Never advertised
    /// by the passive candidate.
    ControlMutation,
}

impl IpcCapability {
    /// Whether this capability has a wire representation in `schema`.
    #[must_use]
    pub const fn is_available_in_schema(self, schema: u16) -> bool {
        schema == 1
            && matches!(
                self,
                Self::LegacySnapshot
                    | Self::PassiveSnapshot
                    | Self::PassiveSubscribe
                    | Self::Shutdown
            )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientHello {
    pub product: String,
    pub product_version: String,
    pub protocol: CompatibilityRange,
    pub schema: CompatibilityRange,
    pub required_capabilities: Vec<IpcCapability>,
}

impl ClientHello {
    #[must_use]
    pub fn current(required_capabilities: Vec<IpcCapability>) -> Self {
        Self {
            product: "vortix".into(),
            product_version: env!("CARGO_PKG_VERSION").into(),
            protocol: CompatibilityRange {
                min: IPC_PROTOCOL_MIN,
                max: IPC_PROTOCOL_MAX,
            },
            schema: CompatibilityRange {
                min: IPC_SCHEMA_MIN,
                max: IPC_SCHEMA_MAX,
            },
            required_capabilities,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerHello {
    pub product: String,
    pub product_version: String,
    pub protocol: u16,
    pub schema: u16,
    pub capabilities: Vec<IpcCapability>,
    /// This candidate is observational only and can never own mutations.
    pub passive: bool,
}

/// One scanner-derived tunnel fact. It is intentionally unable to carry an
/// ownership receipt, desired state, protection claim, or mutation handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassiveTunnel {
    pub profile_id: ProfileId,
    pub display_name: String,
    pub protocol: crate::vortix_core::profile::ProtocolKind,
    pub interface_name: String,
    pub observed_at_millis: u64,
}

/// Complete read-only view published by the passive daemon candidate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassiveSnapshot {
    pub generation: u64,
    pub observed_at_millis: u64,
    pub tunnels: Vec<PassiveTunnel>,
    /// Always false. Kept on the wire so clients cannot accidentally treat a
    /// scanner projection as canonical control truth.
    pub authoritative: bool,
}

/// Successful payload variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IpcResult {
    /// Successful mandatory connection handshake.
    Handshake { hello: ServerHello },
    /// Reserved response for a future enrolled mutation authority.
    Accepted,
    /// `Snapshot` payload — legacy primary-only view. When the
    /// registry has no primary, `state` is `Connection::Disconnected`.
    /// Multi-tunnel-aware clients should prefer [`Self::RegistrySnapshot`].
    Snapshot { state: Connection },
    /// Multi-tunnel snapshot. Carries the full set of
    /// active tunnels plus the derived primary and global killswitch
    /// state. New clients query this; transitional protocol-2 clients that
    /// only know [`Self::Snapshot`] keep working through the legacy
    /// population the daemon does alongside.
    RegistrySnapshot {
        tunnels: Vec<TunnelSnapshot>,
        primary: Option<ProfileId>,
        killswitch: KillSwitchState,
    },
    /// Scanner-only daemon candidate view.
    PassiveSnapshot { snapshot: PassiveSnapshot },
    /// Subscription acknowledgement includes the subscribe-before-snapshot
    /// boundary. Later events are strictly newer than this generation.
    PassiveSubscribed { snapshot: PassiveSnapshot },
    /// Full replacement view; bounded consumers never reconstruct state from
    /// an unbounded delta stream.
    PassiveEvent { snapshot: PassiveSnapshot },
    /// The client lagged and must issue a fresh subscribe operation.
    ResyncRequired { newest_generation: u64 },
    /// Reserved legacy subscription acknowledgement.
    Subscribed,
    /// `Shutdown` acknowledged; daemon will terminate after draining.
    ShuttingDown,
}

/// Typed wire errors the daemon can return to the client.
///
/// External tagging (default serde repr) is preserved so existing wire
/// decoders that match `"Unauthorized"` and
/// `"ShuttingDown"` as bare strings continue to round-trip.
#[derive(Debug, Clone, Error, Serialize, Deserialize)]
#[non_exhaustive]
pub enum IpcError {
    #[error("client UID mismatch — daemon refuses to authorize this request")]
    Unauthorized,
    #[error("malformed request: {0}")]
    MalformedRequest(String),
    #[error("daemon is shutting down")]
    ShuttingDown,
    #[error("IPC handshake must be the first request on a connection")]
    HandshakeRequired,
    #[error("incompatible IPC peer: {reason}")]
    Incompatible { reason: String },
    #[error("daemon capability is unavailable: {capability:?}")]
    CapabilityUnavailable { capability: IpcCapability },
    #[error("request id was reused with different content")]
    DuplicateRequestId,
    #[error("daemon connection capacity is saturated")]
    ServerBusy,
    /// A connect attempt was blocked by a registry conflict. Carries
    /// the typed `Conflict` so CLI thin-clients can map to
    /// `ExitCode::StateConflict` (4) with the same hint text as the
    /// direct-app path.
    #[error("connect blocked by conflict: {conflict:?}")]
    Conflict { conflict: Conflict },
    /// A client sent a legacy wire shape this daemon cannot parse
    /// (e.g. `{"kind":"disconnect"}` instead of
    /// `{"kind":"disconnect","profile_id":null}`). Distinct from
    /// `MalformedRequest` so clients can suggest a binary upgrade.
    #[error("unsupported wire format: {0}")]
    UnsupportedWireFormat(String),
    #[error("internal daemon error: {0}")]
    Internal(String),
}

/// Capabilities of the passive candidate. Mutation is absent by construction.
pub const PASSIVE_CAPABILITIES: [IpcCapability; 4] = [
    IpcCapability::LegacySnapshot,
    IpcCapability::PassiveSnapshot,
    IpcCapability::PassiveSubscribe,
    IpcCapability::Shutdown,
];

/// Negotiate one client hello against this passive daemon build.
pub fn negotiate_passive(hello: &ClientHello) -> Result<ServerHello, IpcError> {
    if hello.product != "vortix" {
        return Err(IpcError::Incompatible {
            reason: "product identity does not match vortix".into(),
        });
    }
    if !hello.protocol.is_valid() || !hello.schema.is_valid() {
        return Err(IpcError::Incompatible {
            reason: "invalid compatibility range".into(),
        });
    }
    let protocol = hello
        .protocol
        .highest_common(CompatibilityRange {
            min: IPC_PROTOCOL_MIN,
            max: IPC_PROTOCOL_MAX,
        })
        .ok_or_else(|| IpcError::Incompatible {
            reason: format!(
                "protocol ranges do not overlap (client {}..={}, daemon {}..={})",
                hello.protocol.min, hello.protocol.max, IPC_PROTOCOL_MIN, IPC_PROTOCOL_MAX
            ),
        })?;
    let schema = hello
        .schema
        .highest_common(CompatibilityRange {
            min: IPC_SCHEMA_MIN,
            max: IPC_SCHEMA_MAX,
        })
        .ok_or_else(|| IpcError::Incompatible {
            reason: format!(
                "schema ranges do not overlap (client {}..={}, daemon {}..={})",
                hello.schema.min, hello.schema.max, IPC_SCHEMA_MIN, IPC_SCHEMA_MAX
            ),
        })?;
    for capability in &hello.required_capabilities {
        if !PASSIVE_CAPABILITIES.contains(capability) || !capability.is_available_in_schema(schema)
        {
            return Err(IpcError::CapabilityUnavailable {
                capability: *capability,
            });
        }
    }
    Ok(ServerHello {
        product: "vortix".into(),
        product_version: env!("CARGO_PKG_VERSION").into(),
        protocol,
        schema,
        capabilities: PASSIVE_CAPABILITIES.to_vec(),
        passive: true,
    })
}

#[cfg(test)]
mod handshake_tests {
    use super::*;

    #[test]
    fn passive_handshake_selects_highest_common_versions() {
        let hello = ClientHello::current(vec![IpcCapability::PassiveSnapshot]);
        let selected = negotiate_passive(&hello).unwrap();
        assert_eq!(selected.protocol, IPC_PROTOCOL_MAX);
        assert_eq!(selected.schema, IPC_SCHEMA_MAX);
        assert!(selected.passive);
        assert!(!selected.capabilities.is_empty());
    }

    #[test]
    fn pre_handshake_protocol_generation_is_incompatible() {
        let mut hello = ClientHello::current(vec![IpcCapability::PassiveSnapshot]);
        hello.protocol = CompatibilityRange { min: 1, max: 1 };
        assert!(matches!(
            negotiate_passive(&hello),
            Err(IpcError::Incompatible { .. })
        ));
    }

    #[test]
    fn incompatible_protocol_fails_before_any_operation() {
        let mut hello = ClientHello::current(Vec::new());
        hello.protocol = CompatibilityRange { min: 99, max: 100 };
        assert!(matches!(
            negotiate_passive(&hello),
            Err(IpcError::Incompatible { .. })
        ));
    }

    #[test]
    fn passive_candidate_never_advertises_mutation() {
        let selected = negotiate_passive(&ClientHello::current(Vec::new())).unwrap();
        assert_eq!(selected.capabilities, PASSIVE_CAPABILITIES);
        assert!(selected.passive);
    }

    #[test]
    fn invalid_range_and_unknown_product_fail_closed() {
        let mut hello = ClientHello::current(Vec::new());
        hello.protocol = CompatibilityRange { min: 2, max: 1 };
        assert!(negotiate_passive(&hello).is_err());

        let mut hello = ClientHello::current(Vec::new());
        hello.product = "not-vortix".into();
        assert!(negotiate_passive(&hello).is_err());
    }
}
