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

use crate::core::profile::{Profile, ProfileId};

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
    pub process_ownership: Option<crate::core::ports::process::ManagedProcessId>,
    /// Optional protocol configuration used by `down`. `WireGuard` carries a
    /// DNS-free copy here so `wg-quick down` cannot replay resolver changes.
    pub teardown_config: Option<TunnelTeardownConfig>,
    /// Resolver settings observed from the protocol profile and, where
    /// available, its negotiated runtime options. Platform mutation is not
    /// performed by the protocol adapter.
    pub dns_request: crate::core::ports::dns::DnsRequest,
    /// Complete configured and negotiated `OpenVPN` route truth from the
    /// same live generation. Other protocols carry `None`.
    pub openvpn_routes: Option<crate::core::openvpn_routes::OpenVpnRouteEvidence>,
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

/// Snapshot of the current tunnel state.
#[derive(Debug)]
pub struct TunnelStatus {
    pub handle: TunnelHandle,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub last_handshake: Option<SystemTime>,
    pub observed_at: SystemTime,
    pub peers: Vec<TunnelPeerStatus>,
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

/// Errors a profile parser can return.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ParseError {
    #[error("malformed value for `{field}`: {detail}")]
    MalformedField { field: &'static str, detail: String },
    #[error("unsupported profile feature: {0}")]
    Unsupported(String),
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
