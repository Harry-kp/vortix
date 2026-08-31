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
/// Inclusive snapshot schema range supported by this build. Schema 3 reserves
/// the canonical control session/command/challenge shapes while the passive
/// candidate continues to advertise no mutation capability.
pub const IPC_SCHEMA_MIN: u16 = 1;
pub const IPC_SCHEMA_MAX: u16 = 3;

use crate::vortix_core::control::{
    AdmissionError, AdmittedOperation, ChallengeError, ChallengeId, ClientId, ControlEventEnvelope,
    ControlSnapshot, DiagnosticSnapshot, IdempotencyKey,
};
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
    /// Read the current bounded, redacted diagnostic snapshot.
    Diagnostics,
    /// Subscribe to full diagnostic replacement snapshots.
    DiagnosticsSubscribe,
    /// Open one same-owner control client session. The passive candidate
    /// never advertises the required capability, so production cannot reach
    /// this operation until enrollment activation lands.
    ControlOpen,
    /// Submit one canonical command under a server-issued client identity.
    ControlSubmit {
        session_id: RemoteSessionId,
        command: crate::vortix_core::control::UserCommand,
        idempotency_key: IdempotencyKey,
        timeout_millis: u64,
    },
    /// Read the complete canonical snapshot without reconstructing state in
    /// the adapter.
    ControlSnapshot { session_id: RemoteSessionId },
    /// Subscribe to canonical events with a full snapshot resync boundary.
    ControlSubscribe { session_id: RemoteSessionId },
    /// Deliver one memory-only challenge answer to its authorized client.
    ControlRespondChallenge {
        session_id: RemoteSessionId,
        challenge_id: ChallengeId,
        answer: SensitiveBytes,
    },
    /// Cancel one challenge through its authorized client identity.
    ControlCancelChallenge {
        session_id: RemoteSessionId,
        challenge_id: ChallengeId,
    },
    /// Stage one bounded profile body in the daemon's memory-only import
    /// executor before submitting the durable identity-only command.
    ControlStageProfileImport {
        session_id: RemoteSessionId,
        file_name: String,
        offset: u64,
        final_chunk: bool,
        contents: SensitiveBytes,
    },
    /// Discard an interrupted memory-only profile upload.
    ControlCancelProfileImport { session_id: RemoteSessionId },
    /// Graceful daemon shutdown. Authorized client only (UID-matching
    /// per `SO_PEERCRED`; see peer-credential auth).
    Shutdown,
}

impl IpcOp {
    /// Capability that must have been declared and negotiated before this
    /// operation may be dispatched.
    #[must_use]
    pub const fn required_capability(&self) -> IpcCapability {
        match self {
            Self::Handshake { .. } | Self::PassiveSnapshot => IpcCapability::PassiveSnapshot,
            Self::Execute(_)
            | Self::ControlOpen
            | Self::ControlSubmit { .. }
            | Self::ControlSnapshot { .. }
            | Self::ControlSubscribe { .. }
            | Self::ControlRespondChallenge { .. }
            | Self::ControlCancelChallenge { .. }
            | Self::ControlStageProfileImport { .. }
            | Self::ControlCancelProfileImport { .. } => IpcCapability::ControlMutation,
            Self::Snapshot => IpcCapability::LegacySnapshot,
            Self::Subscribe | Self::PassiveSubscribe => IpcCapability::PassiveSubscribe,
            Self::Diagnostics => IpcCapability::Diagnostics,
            Self::DiagnosticsSubscribe => IpcCapability::DiagnosticsSubscribe,
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
    Diagnostics,
    DiagnosticsSubscribe,
    Shutdown,
    /// Reserved for the future enrolled control authority. Never advertised
    /// by the passive candidate.
    ControlMutation,
}

impl IpcCapability {
    /// Whether this capability has a wire representation in `schema`.
    #[must_use]
    pub const fn is_available_in_schema(self, schema: u16) -> bool {
        match self {
            Self::Diagnostics | Self::DiagnosticsSubscribe => schema >= 2,
            Self::LegacySnapshot
            | Self::PassiveSnapshot
            | Self::PassiveSubscribe
            | Self::Shutdown => schema >= 1,
            Self::ControlMutation => schema >= 3,
        }
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

/// Opaque daemon-issued session identity. It names one canonical
/// [`ClientId`] without granting observation or completion authority.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RemoteSessionId(String);

impl RemoteSessionId {
    #[must_use]
    pub fn parse(value: impl Into<String>) -> Option<Self> {
        let value = value.into();
        let suffix = value.strip_prefix("session-")?;
        (suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .then_some(Self(value))
    }
}

impl<'de> Deserialize<'de> for RemoteSessionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?)
            .ok_or_else(|| serde::de::Error::custom("invalid remote control session ID"))
    }
}

/// Secret-bearing IPC bytes. The value is serialized only for the live
/// same-owner socket exchange, is always redacted from `Debug`, and is
/// overwritten when dropped. It never enters snapshots, events, replay
/// caches, diagnostics, or persistence.
#[derive(Clone)]
pub struct SensitiveBytes(std::sync::Arc<zeroize::Zeroizing<Vec<u8>>>);

impl SensitiveBytes {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(std::sync::Arc::new(zeroize::Zeroizing::new(bytes)))
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        match std::sync::Arc::try_unwrap(self.0) {
            Ok(mut bytes) => std::mem::take(&mut *bytes),
            Err(bytes) => bytes.as_ref().to_vec(),
        }
    }
}

impl std::fmt::Debug for SensitiveBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Serialize for SensitiveBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use base64::Engine as _;
        let encoded = zeroize::Zeroizing::new(
            base64::engine::general_purpose::STANDARD.encode(self.0.as_slice()),
        );
        serializer.serialize_str(encoded.as_str())
    }
}

impl<'de> Deserialize<'de> for SensitiveBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use base64::Engine as _;
        let encoded = zeroize::Zeroizing::new(String::deserialize(deserializer)?);
        base64::engine::general_purpose::STANDARD
            .decode(encoded.as_bytes())
            .map(Self::new)
            .map_err(serde::de::Error::custom)
    }
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
    Handshake {
        hello: ServerHello,
    },
    /// Reserved response for a future enrolled mutation authority.
    Accepted,
    /// `Snapshot` payload — legacy primary-only view. When the
    /// registry has no primary, `state` is `Connection::Disconnected`.
    /// Multi-tunnel-aware clients should prefer [`Self::RegistrySnapshot`].
    Snapshot {
        state: Connection,
    },
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
    PassiveSnapshot {
        snapshot: PassiveSnapshot,
    },
    /// Subscription acknowledgement includes the subscribe-before-snapshot
    /// boundary. Later events are strictly newer than this generation.
    PassiveSubscribed {
        snapshot: PassiveSnapshot,
    },
    /// Full replacement view; bounded consumers never reconstruct state from
    /// an unbounded delta stream.
    PassiveEvent {
        snapshot: PassiveSnapshot,
    },
    DiagnosticSnapshot {
        snapshot: DiagnosticSnapshot,
    },
    DiagnosticSubscribed {
        snapshot: DiagnosticSnapshot,
    },
    DiagnosticEvent {
        snapshot: DiagnosticSnapshot,
    },
    ControlOpened {
        session_id: RemoteSessionId,
        client_id: ClientId,
    },
    ControlAccepted {
        admitted: AdmittedOperation,
    },
    ControlSnapshot {
        snapshot: ControlSnapshot,
    },
    ControlSubscribed {
        snapshot: ControlSnapshot,
    },
    ControlEvent {
        /// Some canonical publications (notably fresh observations) change
        /// the snapshot without emitting a control event.
        event: Option<ControlEventEnvelope>,
        snapshot: ControlSnapshot,
    },
    ChallengeAccepted,
    ControlProfileImportStaged {
        profile_id: ProfileId,
        display_name: String,
    },
    ControlProfileImportChunkAccepted {
        next_offset: u64,
    },
    /// The client lagged and must issue a fresh subscribe operation.
    ResyncRequired {
        newest_generation: u64,
    },
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
    #[error("control admission failed: {error}")]
    ControlAdmission { error: AdmissionError },
    #[error("control challenge failed: {error}")]
    ControlChallenge { error: ChallengeError },
    #[error("remote control session was not found")]
    ControlSessionNotFound,
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
pub const PASSIVE_CAPABILITIES: [IpcCapability; 6] = [
    IpcCapability::LegacySnapshot,
    IpcCapability::PassiveSnapshot,
    IpcCapability::PassiveSubscribe,
    IpcCapability::Diagnostics,
    IpcCapability::DiagnosticsSubscribe,
    IpcCapability::Shutdown,
];

const PASSIVE_CAPABILITIES_V1: [IpcCapability; 4] = [
    IpcCapability::LegacySnapshot,
    IpcCapability::PassiveSnapshot,
    IpcCapability::PassiveSubscribe,
    IpcCapability::Shutdown,
];

/// Passive capabilities whose result shapes exist in the negotiated schema.
#[must_use]
pub const fn capabilities_for_schema(schema: u16) -> &'static [IpcCapability] {
    if schema >= 2 {
        &PASSIVE_CAPABILITIES
    } else if schema == 1 {
        &PASSIVE_CAPABILITIES_V1
    } else {
        &[]
    }
}

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
    let capabilities = capabilities_for_schema(schema);
    for capability in &hello.required_capabilities {
        if !capability.is_available_in_schema(schema) || !capabilities.contains(capability) {
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
        capabilities: capabilities.to_vec(),
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
    fn schema_one_peer_receives_only_pre_diagnostics_capabilities() {
        let mut hello = ClientHello::current(vec![IpcCapability::PassiveSnapshot]);
        hello.schema = CompatibilityRange { min: 1, max: 1 };
        let selected = negotiate_passive(&hello).unwrap();
        assert_eq!(selected.schema, 1);
        assert_eq!(selected.capabilities, PASSIVE_CAPABILITIES_V1);

        hello.required_capabilities = vec![IpcCapability::Diagnostics];
        assert!(matches!(
            negotiate_passive(&hello),
            Err(IpcError::CapabilityUnavailable {
                capability: IpcCapability::Diagnostics
            })
        ));
    }

    #[test]
    fn operation_contract_centralizes_capability_and_schema_requirements() {
        assert_eq!(
            IpcOp::Diagnostics.required_capability(),
            IpcCapability::Diagnostics
        );
        assert!(!IpcCapability::Diagnostics.is_available_in_schema(1));
        assert!(IpcCapability::Diagnostics.is_available_in_schema(2));
        assert_eq!(
            capabilities_for_schema(1),
            PASSIVE_CAPABILITIES_V1.as_slice()
        );
        assert_eq!(capabilities_for_schema(2), PASSIVE_CAPABILITIES.as_slice());
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

    #[test]
    fn challenge_bytes_are_redacted_from_debug_but_cross_the_live_frame() {
        let session_id = RemoteSessionId::parse(format!("session-{}", "a".repeat(32))).unwrap();
        let challenge_id = serde_json::from_str("1").unwrap();
        let request = IpcRequest {
            id: 7,
            op: IpcOp::ControlRespondChallenge {
                session_id,
                challenge_id,
                answer: SensitiveBytes::new(b"single-use-secret".to_vec()),
            },
        };
        assert!(!format!("{request:?}").contains("single-use-secret"));
        let frame = encode_frame(&request).unwrap();
        let (decoded, _) = decode_frame::<IpcRequest>(&frame).unwrap().unwrap();
        let IpcOp::ControlRespondChallenge { answer, .. } = decoded.op else {
            panic!("challenge response must round-trip as its dedicated wire shape");
        };
        assert_eq!(answer.into_vec(), b"single-use-secret");
    }

    #[test]
    fn public_requests_remain_cloneable_without_copying_secret_storage() {
        let answer = SensitiveBytes::new(b"single-use-secret".to_vec());
        let shared = answer.clone();
        assert!(std::sync::Arc::ptr_eq(&answer.0, &shared.0));
        let request = IpcRequest {
            id: 7,
            op: IpcOp::ControlRespondChallenge {
                session_id: RemoteSessionId::parse(format!("session-{}", "a".repeat(32))).unwrap(),
                challenge_id: serde_json::from_str("1").unwrap(),
                answer,
            },
        };

        let cloned = request.clone();
        let IpcOp::ControlRespondChallenge { answer, .. } = cloned.op else {
            panic!("cloned request must preserve its operation");
        };
        assert_eq!(answer.into_vec(), b"single-use-secret");
    }

    #[test]
    fn maximum_profile_chunk_fits_the_bounded_live_frame() {
        let request = IpcRequest {
            id: 2,
            op: IpcOp::ControlStageProfileImport {
                session_id: RemoteSessionId::parse(format!("session-{}", "b".repeat(32))).unwrap(),
                file_name: "bounded.ovpn".into(),
                offset: 0,
                final_chunk: false,
                contents: SensitiveBytes::new(vec![b'x'; 64 * 1024]),
            },
        };
        assert!(encode_frame(&request).is_ok());
    }
}
