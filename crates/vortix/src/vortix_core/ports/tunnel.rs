//! `Tunnel` port — the per-protocol adapter the engine drives.
//!
//! Each protocol (`WireGuard`, `OpenVPN`, future `IKEv2`) implements this
//! trait in its own crate. The engine never branches on protocol after
//! construction — it routes once via `profile.protocol → TunnelKind` (the
//! aggregate carrier defined in the binary) and dispatches statically.
//!
//! Plan #004 keeps trait methods sync (engine is sync today; mocks and real
//! impls reach the global runner directly). Plan #005's async engine
//! migration adds `&CommandRunner` arguments and `async fn` where useful.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use thiserror::Error;

use crate::vortix_core::profile::{Profile, ProfileId, ProtocolKind};

pub mod mock;

// ───────────────────────────────────────────────────────────────────────────
// Handle / status / capabilities / errors
// ───────────────────────────────────────────────────────────────────────────

/// Tag identifying which `Tunnel` impl owns a [`TunnelHandle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TunnelKindTag {
    WireGuard,
    OpenVpn,
    Mock,
}

/// Lifecycle handle returned by [`Tunnel::up`] and consumed by `down` / `status`.
#[derive(Debug, Clone)]
pub struct TunnelHandle {
    pub profile_id: ProfileId,
    pub interface_name: String,
    /// Some(pid) when the impl manages a long-running daemon (e.g., `openvpn`);
    /// `None` when the kernel owns the lifecycle (e.g., kernel `WireGuard`).
    pub pid: Option<u32>,
    pub started_at: SystemTime,
    pub kind: TunnelKindTag,
}

/// Per-protocol introspection blob returned by [`Tunnel::status`].
///
/// Boxed so concrete protocols can carry their own peer / route shapes. Use
/// the `as_any` downcast hook when the TUI needs to render per-protocol
/// detail.
pub trait ProtocolStatus: std::fmt::Debug + Send + Sync {
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Snapshot of the current tunnel state.
#[derive(Debug)]
pub struct TunnelStatus {
    pub handle: TunnelHandle,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub last_handshake: Option<SystemTime>,
    pub observed_at: SystemTime,
    pub detail: Box<dyn ProtocolStatus>,
}

/// Compile-time capability advertisement, returned `const` per impl.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // capability struct is intentionally feature-flag-shaped
pub struct TunnelCapabilities {
    pub supports_split_tunnel: bool,
    pub supports_ipv6: bool,
    pub mtu_configurable: bool,
    pub supports_reconnect_without_disconnect: bool,
    pub requires_root: bool,
    pub userspace: bool,
}

/// Parsed protocol-specific profile body.
///
/// Returned by [`Tunnel::parse_profile`]. The engine treats this as opaque;
/// each protocol crate downcasts via `as_any` when it needs the concrete
/// shape.
pub trait ParsedProfile: std::fmt::Debug + Send + Sync {
    fn as_any(&self) -> &dyn std::any::Any;

    /// DNS servers this profile expects the system to apply (used to surface
    /// `resolvconf` dependency hints before connect). Empty when the profile
    /// has no `DNS = ...` directive.
    fn dns_servers(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Errors a `Tunnel::up` / `down` / `status` call can return.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TunnelError {
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    #[error("connection timed out after {0:?}")]
    Timeout(std::time::Duration),
    #[error("daemon exited unexpectedly: {0}")]
    DaemonExited(String),
    #[error("subprocess failure: {0}")]
    Subprocess(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("requested capability `{0}` not supported by this protocol")]
    CapabilityUnsupported(&'static str),
    #[error("{0}")]
    Other(String),
}

/// Errors [`Tunnel::parse_profile`] can return.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ParseError {
    #[error("invalid encoding: {0}")]
    Encoding(String),
    #[error("missing required field `{0}`")]
    MissingField(&'static str),
    #[error("malformed value for `{field}`: {detail}")]
    MalformedField { field: &'static str, detail: String },
    #[error("unsupported profile feature: {0}")]
    Unsupported(String),
    #[error("{0}")]
    Other(String),
}

/// The per-protocol adapter the engine drives.
pub trait Tunnel {
    /// Bring up the tunnel for `profile`. The returned handle is opaque to the
    /// engine and must be passed back to [`Self::down`] / [`Self::status`].
    ///
    /// # Errors
    ///
    /// Returns [`TunnelError`] on subprocess failure, handshake failure, auth
    /// failure, timeout, or I/O error.
    fn up(&mut self, profile: &Profile) -> Result<TunnelHandle, TunnelError>;

    /// Tear down a previously-established tunnel.
    ///
    /// # Errors
    ///
    /// Returns [`TunnelError`] on subprocess failure or I/O error.
    fn down(&mut self, handle: TunnelHandle) -> Result<(), TunnelError>;

    /// Snapshot the current state of the tunnel.
    ///
    /// # Errors
    ///
    /// Returns [`TunnelError`] when the underlying subprocess query fails.
    fn status(&self, handle: &TunnelHandle) -> Result<TunnelStatus, TunnelError>;

    /// Parse raw profile bytes (typically a `.conf` or `.ovpn` file) into a
    /// protocol-specific [`ParsedProfile`].
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] on encoding errors, missing/malformed required
    /// fields, or unsupported profile features.
    fn parse_profile(&self, raw: &[u8]) -> Result<Box<dyn ParsedProfile>, ParseError>;

    /// Capabilities of this protocol impl.
    fn capabilities(&self) -> TunnelCapabilities;

    /// Tag this impl reports — used by `TunnelHandle::kind` and by the engine
    /// when dispatching back to the right `TunnelKind` variant.
    fn kind_tag(&self) -> TunnelKindTag;
}

/// Convenience: builds a [`Profile`] for tests / quick prototypes.
#[must_use]
pub fn test_profile(id: &str, protocol: ProtocolKind) -> Profile {
    Profile::new(
        ProfileId::new(id),
        id,
        protocol,
        std::path::PathBuf::from(format!("/tmp/{id}.conf")),
    )
}

// ───────────────────────────────────────────────────────────────────────────
// Recorded invocations (shared by mocks)
// ───────────────────────────────────────────────────────────────────────────

/// What a mock recorded about a `up`/`down`/`status` call.
#[derive(Debug, Clone)]
pub struct RecordedTunnelCall {
    pub method: &'static str,
    pub profile_id: ProfileId,
    pub interface_name: Option<String>,
}

/// Shared invocation log used by mock tunnels (and useful for tests that
/// thread custom mock impls).
pub type TunnelCallLog = Arc<Mutex<Vec<RecordedTunnelCall>>>;
