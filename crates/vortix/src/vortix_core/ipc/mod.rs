//! IPC envelope + framing for `EngineHandle::Remote` (plan 015 phase D / plan 010).
//!
//! The daemon (`vortix daemon`) and the client (TUI/CLI) communicate
//! via length-prefixed JSON frames on a Unix domain socket. This
//! module defines:
//!
//! - The request/response envelope ([`IpcRequest`], [`IpcResponse`])
//! - The op vocabulary ([`IpcOp`], [`IpcResult`])
//! - Typed wire errors ([`IpcError`])
//! - The length-prefix codec ([`frame`])
//!
//! The actual transport (`tokio::net::UnixStream`) and the daemon
//! server loop live in the binary crate. This crate only owns the
//! wire contract so `vortix-core` consumers (future external tooling,
//! tests) can speak the protocol without pulling tokio.

pub mod frame;

pub use frame::{decode_frame, encode_frame, FrameError, MAX_FRAME_BYTES};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Wire protocol version spoken by this build. Bumped on any breaking
/// change to the envelope, op, or result shapes. Peers compare versions
/// on every exchange; a mismatch is a loud typed error naming both
/// sides — never a silent fallback (#242-era lesson: silent degradation
/// masks real bugs). Frames from pre-versioning builds deserialize with
/// `protocol_version = 0` via `#[serde(default)]`, which fails the
/// comparison and surfaces the upgrade hint.
pub const IPC_PROTOCOL_VERSION: u32 = 1;

use tokio::sync::broadcast;

use crate::vortix_core::engine::event::EventEnvelope;
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
    /// Execute a user command (Connect, Disconnect, Reconnect, ...).
    Execute(UserCommand),
    /// Read the current single-FSM snapshot (v1-compat).
    Snapshot,
    /// Read the full multi-tunnel registry snapshot (plan
    /// 2026-07-18-001 U2). Answered with [`IpcResult::RegistrySnapshot`].
    RegistrySnapshot,
    /// Subscribe to live `EngineEvent` stream. The daemon switches the
    /// connection into streaming mode after sending the ack; subsequent
    /// frames on this connection are events until the client closes.
    Subscribe,
    /// Graceful daemon shutdown. Authorized client only (UID-matching
    /// per `SO_PEERCRED`; see plan 015 phase E).
    Shutdown,
}

/// Wrapper for the client→server direction. `id` is opaque to the
/// daemon; the client correlates response IDs back to outstanding
/// requests. `protocol_version` defaults to 0 for frames from
/// pre-versioning builds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest {
    pub id: u64,
    #[serde(default)]
    pub protocol_version: u32,
    pub op: IpcOp,
}

/// Wrapper for the server→client direction. `id` matches the
/// originating [`IpcRequest::id`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    pub id: u64,
    #[serde(default)]
    pub protocol_version: u32,
    pub result: Result<IpcResult, IpcError>,
}

/// Successful payload variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IpcResult {
    /// `Execute` was accepted; the FSM is processing it.
    Accepted,
    /// `Snapshot` payload — **v1-compat** primary-only view. When the
    /// registry has no primary, `state` is `Connection::Disconnected`.
    /// Multi-tunnel-aware clients should prefer [`Self::RegistrySnapshot`].
    Snapshot { state: Connection },
    /// Multi-tunnel snapshot (plan #001 U22). Carries the full set of
    /// active tunnels plus the derived primary and global killswitch
    /// state. New clients query this; v1 clients that only know
    /// [`Self::Snapshot`] keep working through the back-compat
    /// population the daemon does alongside.
    RegistrySnapshot {
        tunnels: Vec<TunnelSnapshot>,
        primary: Option<ProfileId>,
        killswitch: KillSwitchState,
    },
    /// `Subscribe` acknowledged; subsequent frames are streamed events.
    Subscribed,
    /// A streamed engine event, pushed by the daemon after the
    /// `Subscribed` ack on a subscription connection (plan
    /// 2026-07-18-001 U2). Only ever appears server→client on a
    /// subscribe stream, never as a request/response result.
    Event(EventEnvelope),
    /// Periodic keep-alive on an idle subscription stream. Its only job
    /// is to make a broken pipe observable: the daemon's write fails when
    /// the subscriber is gone (reaping the server task/fd), and the client
    /// reader wakes to check whether any receiver remains (reaping its
    /// thread). Carries no data and is never forwarded as an event.
    Heartbeat,
    /// `Shutdown` acknowledged; daemon will terminate after draining.
    ShuttingDown,
}

/// Typed wire errors the daemon can return to the client.
///
/// External tagging (default serde repr) is preserved so the existing
/// v1 client decoders that match `"Unauthorized"` and
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
    /// A connect attempt was blocked by a registry conflict. Carries
    /// the typed `Conflict` so CLI thin-clients can map to
    /// `ExitCode::StateConflict` (4) with the same hint text as the
    /// direct-app path.
    #[error("connect blocked by conflict: {conflict:?}")]
    Conflict { conflict: Conflict },
    /// A v1 client sent a wire shape this v2 daemon cannot parse
    /// (e.g. `{"kind":"disconnect"}` instead of
    /// `{"kind":"disconnect","profile_id":null}`). Distinct from
    /// `MalformedRequest` so clients can suggest a binary upgrade.
    #[error("unsupported wire format: {0}")]
    UnsupportedWireFormat(String),
    /// Peer speaks a different [`IPC_PROTOCOL_VERSION`]. Both sides are
    /// named so the user knows which binary to upgrade (AE8).
    #[error("IPC protocol mismatch: daemon speaks v{daemon}, client speaks v{client}")]
    VersionMismatch { daemon: u32, client: u32 },
    #[error("internal daemon error: {0}")]
    Internal(String),
}

/// Blocking transport a [`RemoteHandle`](crate::vortix_core::engine::handle)
/// drives. The trait lives in `vortix-core` so the handle stays
/// transport-agnostic; the Unix-socket implementation lives in the
/// binary crate's `daemon::client`.
pub trait IpcTransport: Send + Sync {
    /// One request/response exchange.
    ///
    /// # Errors
    ///
    /// See [`TransportError`] — availability failures are distinguished
    /// from protocol failures so callers can fall back silently on the
    /// former and fail loudly on the latter.
    fn request(&self, op: IpcOp) -> Result<IpcResult, TransportError>;

    /// Open a live event subscription: send `Subscribe` and return a
    /// receiver fed by the daemon's pushed [`IpcResult::Event`] stream
    /// (plan 2026-07-18-001 U2). The concrete transport owns the reader
    /// that forwards frames into the returned channel.
    ///
    /// Default: unsupported — read-only / mock transports don't stream.
    ///
    /// # Errors
    ///
    /// See [`TransportError`].
    fn subscribe(&self) -> Result<broadcast::Receiver<EventEnvelope>, TransportError> {
        Err(TransportError::Protocol(
            "this transport does not support event streaming".into(),
        ))
    }
}

/// Client-side transport error surface, discriminated by how callers
/// must react (per U1: absent daemon = silent fallback; version
/// mismatch = loud error).
#[derive(Debug, Clone, Error)]
pub enum TransportError {
    /// The daemon is not reachable (connect refused, socket gone, EOF).
    /// Callers fall back to the Local path silently.
    #[error("daemon unavailable: {0}")]
    Unavailable(String),
    /// The connection was established but the daemon did not answer within
    /// the read deadline — it is present but slow (e.g. mid-connect).
    /// Distinct from [`Self::Unavailable`] so a WRITE caller does NOT fall
    /// through to a second local attempt (which would double-act on the
    /// same profile while the daemon is still processing the first); read
    /// callers may still treat it as a silent bypass.
    #[error("daemon did not respond in time: {0}")]
    Timeout(String),
    /// Peer version differs — loud, never silently swallowed.
    #[error("IPC protocol mismatch: daemon speaks v{daemon}, client speaks v{client}")]
    VersionMismatch { daemon: u32, client: u32 },
    /// The wire broke or the daemon answered nonsense — a bug surface,
    /// reported like unavailability but logged at warn.
    #[error("IPC protocol failure: {0}")]
    Protocol(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_with_protocol_version() {
        let req = IpcRequest {
            id: 7,
            protocol_version: IPC_PROTOCOL_VERSION,
            op: IpcOp::Snapshot,
        };
        let bytes = encode_frame(&req).unwrap();
        let (decoded, _) = decode_frame::<IpcRequest>(&bytes).unwrap().unwrap();
        assert_eq!(decoded.protocol_version, IPC_PROTOCOL_VERSION);
        assert_eq!(decoded.id, 7);
    }

    #[test]
    fn legacy_request_without_version_field_decodes_as_v0() {
        // Pre-versioning builds emit envelopes without protocol_version;
        // serde default must map them to 0 so the gate catches them.
        let legacy = br#"{"id":1,"op":{"kind":"snapshot"}}"#;
        let mut frame = Vec::new();
        frame.extend_from_slice(&u32::try_from(legacy.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(legacy);
        let (decoded, _) = decode_frame::<IpcRequest>(&frame).unwrap().unwrap();
        assert_eq!(decoded.protocol_version, 0);
    }

    #[test]
    fn version_mismatch_error_names_both_sides() {
        let e = IpcError::VersionMismatch {
            daemon: 2,
            client: 1,
        };
        let msg = e.to_string();
        assert!(msg.contains("v2") && msg.contains("v1"), "got: {msg}");
    }
}
