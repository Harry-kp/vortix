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

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::vortix_core::profile::{Profile, ProfileId, ProtocolKind};

pub mod mock;

/// Cooperative cancellation fence shared by the canonical worker and
/// protocol adapters. It lives at the port boundary so protocol crates never
/// import the control implementation.
#[derive(Debug, Clone, Default)]
pub struct TunnelCancellation(Arc<AtomicBool>);

impl TunnelCancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Canonical bounds for one protocol mutation.
#[derive(Debug, Clone)]
pub struct TunnelExecutionContext {
    pub cancellation: TunnelCancellation,
    pub deadline: Instant,
}

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
    /// Stable basename passed to `wg-quick`. On macOS this differs from the
    /// kernel-assigned `utunN` interface and is required to resolve the
    /// `/var/run/wireguard/<name>.name` ownership mapping during teardown.
    pub wg_quick_interface: Option<String>,
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
    /// Attempt generation that owns this handle. Protocol observations copy
    /// this fence into handshake evidence so an older attempt can never
    /// complete newer desired state.
    pub generation: u64,
    /// Current-generation cryptographic proof. Present only after a
    /// `WireGuard` handshake gate succeeds.
    pub handshake: Option<HandshakeEvidence>,
    /// Every handshake-eliciting probe actually issued for this attempt.
    /// Configured targets alone never create a health expectation.
    pub probe_receipts: Vec<ProbeReceipt>,
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
    /// Complete configured and negotiated `OpenVPN` route truth from the
    /// same live generation. Other protocols carry `None`.
    pub openvpn_routes: Option<crate::vortix_core::privileged::OpenVpnRouteEvidence>,
}

/// Protocol-attested record of one `WireGuard` peer probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeReceipt {
    pub peer_public_key: String,
    pub target: IpAddr,
    pub allowed_routes: Vec<String>,
    pub issued_at: SystemTime,
}

/// One `WireGuard` peer observation in protocol-neutral, typed form.
///
/// Public-key identity and allowed routes are copied directly from `WireGuard`'s
/// machine-readable dump. The control layer never parses `wg show` display
/// strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelPeerStatus {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_routes: Vec<String>,
    pub latest_handshake: Option<SystemTime>,
    pub evidence_observed_at: SystemTime,
    pub evidence_generation: u64,
    pub persistent_keepalive: Option<Duration>,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
}

impl TunnelPeerStatus {
    /// Whether this peer is expected to produce fresh handshakes while idle.
    #[must_use]
    pub const fn keepalive_expected(&self) -> bool {
        self.persistent_keepalive.is_some()
    }
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
    pub peers: Vec<TunnelPeerStatus>,
    pub detail: Box<dyn ProtocolStatus>,
}

/// Immutable handshake attempt fence captured before interface creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeAttempt {
    pub generation: u64,
    pub started_at: SystemTime,
    pub expected_peers: BTreeSet<String>,
    pub baseline: BTreeMap<String, Option<SystemTime>>,
}

/// Current-generation cryptographic liveness proof for one peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeEvidence {
    pub generation: u64,
    pub peer_public_key: String,
    pub handshake_at: SystemTime,
    pub observed_at: SystemTime,
    pub allowed_routes: Vec<String>,
}

impl HandshakeAttempt {
    /// Accept only an expected peer whose timestamp is newer than both the
    /// pre-attempt baseline and attempt start, and whose observation carries
    /// this exact generation.
    #[must_use]
    pub fn evaluate(&self, status: &TunnelStatus) -> Option<HandshakeEvidence> {
        status.peers.iter().find_map(|peer| {
            if peer.evidence_generation != self.generation
                || !self.expected_peers.contains(&peer.public_key)
            {
                return None;
            }
            let handshake_at = peer.latest_handshake?;
            let baseline = self.baseline.get(&peer.public_key).copied().flatten();
            // WireGuard exports whole-second timestamps. Permit evidence from
            // the same wall-clock second as admission only when no baseline
            // existed; a captured baseline must always be strictly exceeded.
            let predates_attempt = baseline.map_or_else(
                || {
                    handshake_at
                        .checked_add(Duration::from_secs(1))
                        .is_none_or(|rounded| rounded <= self.started_at)
                },
                |baseline| handshake_at <= baseline,
            );
            if predates_attempt {
                return None;
            }
            Some(HandshakeEvidence {
                generation: self.generation,
                peer_public_key: peer.public_key.clone(),
                handshake_at,
                observed_at: peer.evidence_observed_at,
                allowed_routes: peer.allowed_routes.clone(),
            })
        })
    }
}

/// Why ongoing freshness is expected for a `WireGuard` peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerTrafficExpectation {
    Idle,
    PersistentKeepalive,
    RoutedTraffic,
    ConfiguredProbe { target: IpAddr },
}

/// Typed ongoing peer health; idle peers do not become falsely degraded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerHandshakeHealth {
    InformationalIdle { age: Option<Duration> },
    Healthy { age: Duration },
    Stale { age: Duration },
    NeverObserved,
}

/// Classify one peer without conflating interface presence with health.
#[must_use]
pub fn classify_peer_handshake_health(
    peer: &TunnelPeerStatus,
    now: SystemTime,
    expectation: &PeerTrafficExpectation,
    stale_after: Duration,
) -> PeerHandshakeHealth {
    let age = peer
        .latest_handshake
        .and_then(|handshake| now.duration_since(handshake).ok());
    if matches!(expectation, PeerTrafficExpectation::Idle) {
        return PeerHandshakeHealth::InformationalIdle { age };
    }
    match age {
        Some(age) if age > stale_after => PeerHandshakeHealth::Stale { age },
        Some(age) => PeerHandshakeHealth::Healthy { age },
        None => PeerHandshakeHealth::NeverObserved,
    }
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

    /// Convert already-parsed, validated protocol data into the narrow plan
    /// accepted by privileged execution.
    ///
    /// Protocol implementations override this seam during the helper
    /// cutover. The core never parses raw profile text and the returned type
    /// cannot carry commands, paths, hooks, plugins, or arbitrary options.
    fn privileged_plan(
        &self,
        _profile_id: &ProfileId,
        _generation: u64,
    ) -> Result<crate::vortix_core::privileged::ProtocolPlan, ParseError> {
        Err(ParseError::Unsupported(
            "privileged planning is not implemented for this protocol".to_owned(),
        ))
    }

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
    #[error("tunnel operation was cancelled")]
    Cancelled,
    #[error("tunnel outcome is ambiguous: {0}")]
    OutcomeUnknown(String),
    #[error("malformed protocol status: {0}")]
    MalformedStatus(String),
    #[error("protocol resource `{resource}` exceeded limit {limit}")]
    ResourceLimit {
        resource: &'static str,
        limit: usize,
    },
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
