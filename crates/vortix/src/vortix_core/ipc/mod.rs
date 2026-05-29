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
    /// Read the current FSM snapshot.
    Snapshot,
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
    #[error("internal daemon error: {0}")]
    Internal(String),
}
