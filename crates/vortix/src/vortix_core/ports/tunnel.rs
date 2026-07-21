//! `Tunnel` port — the per-protocol adapter the engine drives.
//!
//! Each protocol (`WireGuard`, `OpenVPN`, future `IKEv2`) implements this
//! trait in its own crate. The engine never branches on protocol after
//! construction — it routes once via `profile.protocol → TunnelKind` (the
//! aggregate carrier defined in the binary) and dispatches statically.
//!
//! Plan #004 keeps trait methods sync (engine is sync today; mocks and real
//! impls reach the global runner directly). The async engine
//! migration adds `&CommandRunner` arguments and `async fn` where useful.

use std::path::PathBuf;
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

/// Protocol-owned configuration needed to tear a tunnel down safely.
///
/// `managed` distinguishes a private, sanitized lifecycle copy from the
/// user's source profile. Protocol adapters may remove managed copies after
/// a successful teardown, but must never remove source profiles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelTeardownConfig {
    pub path: PathBuf,
    pub managed: bool,
}

/// Lifecycle handle returned by [`Tunnel::up`] and consumed by `down` / `status`.
#[derive(Debug, Clone)]
pub struct TunnelHandle {
    pub profile_id: ProfileId,
    /// Boundary label used only for user-visible output and legacy runtime
    /// filenames; lifecycle ownership remains keyed by `profile_id`.
    pub display_name: String,
    pub interface_name: String,
    /// Some(pid) when the impl manages a long-running daemon (e.g., `openvpn`);
    /// `None` when the kernel owns the lifecycle (e.g., kernel `WireGuard`).
    pub pid: Option<u32>,
    pub started_at: SystemTime,
    pub kind: TunnelKindTag,
    /// Exact lifecycle ownership capability for a userspace child. Kernel
    /// tunnels and externally observed sessions carry `None`.
    pub process_ownership: Option<crate::vortix_core::ports::process::ManagedProcessId>,
    /// Optional protocol configuration used by `down`. `WireGuard` carries a
    /// DNS-free copy here so `wg-quick down` cannot replay resolver changes.
    pub teardown_config: Option<TunnelTeardownConfig>,
    /// Resolver settings observed from the protocol profile and, where
    /// available, its negotiated runtime options. Platform mutation is not
    /// performed by the protocol adapter.
    pub dns_request: crate::vortix_core::ports::dns::DnsRequest,
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
        self.dns_request()
            .servers
            .into_iter()
            .map(|server| server.to_string())
            .collect()
    }

    /// Typed DNS intent extracted without applying platform state.
    fn dns_request(&self) -> crate::vortix_core::ports::dns::DnsRequest {
        crate::vortix_core::ports::dns::DnsRequest::default()
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

/// Marker contract for scanner evidence accepted for future ownership
/// adoption. Creating a value requires protocol-specific, stable identity and
/// interface evidence; ordinary scanner observations never produce one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptionEvidence {
    profile_id: ProfileId,
    interface_name: String,
    kind: TunnelKindTag,
    pid: Option<u32>,
    protocol_attestation: String,
}

impl AdoptionEvidence {
    /// Issue protocol-authoritative adoption evidence. The attestation must be
    /// derived from stable protocol metadata (never display/scanner text).
    // U6 exposes the crate-private protocol seam before U7 routes the legacy
    // protocol adapters through it. Keeping construction private prevents an
    // external client/scanner from self-attesting in the interim.
    #[allow(dead_code)]
    pub(crate) fn attest(
        profile_id: ProfileId,
        interface_name: impl Into<String>,
        kind: TunnelKindTag,
        pid: Option<u32>,
        protocol_attestation: impl Into<String>,
    ) -> Result<Self, TunnelError> {
        let interface_name = interface_name.into();
        let protocol_attestation = protocol_attestation.into();
        if interface_name.is_empty()
            || interface_name.len() > 256
            || protocol_attestation.len() < 16
            || protocol_attestation.len() > 256
        {
            return Err(TunnelError::Other(
                "invalid protocol adoption attestation".to_owned(),
            ));
        }
        Ok(Self {
            profile_id,
            interface_name,
            kind,
            pid,
            protocol_attestation,
        })
    }

    #[must_use]
    pub const fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }

    #[must_use]
    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }

    #[must_use]
    pub const fn kind(&self) -> TunnelKindTag {
        self.kind
    }

    #[must_use]
    pub const fn pid(&self) -> Option<u32> {
        self.pid
    }

    #[must_use]
    pub fn protocol_attestation(&self) -> &str {
        &self.protocol_attestation
    }
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
