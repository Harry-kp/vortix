//! Types shared by the protocol adapters: handles, status, errors.
//!

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::profile::ProfileId;

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

/// Lifecycle handle returned by a protocol's `up` and consumed by `down` / `status`.
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
    pub process_ownership: Option<crate::process::ManagedProcessId>,
    /// Optional protocol configuration used by `down`. `WireGuard` carries a
    /// DNS-free copy here so `wg-quick down` cannot replay resolver changes.
    pub teardown_config: Option<TunnelTeardownConfig>,
    /// Resolver settings observed from the protocol profile and, where
    /// available, its negotiated runtime options. Platform mutation is not
    /// performed by the protocol adapter.
    pub dns_request: crate::control::dns::DnsRequest,
    /// Complete configured and negotiated `OpenVPN` route truth from the
    /// same live generation. Other protocols carry `None`.
    pub openvpn_routes: Option<crate::openvpn::routes::OpenVpnRouteEvidence>,
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

/// Errors a protocol `up` / `down` / `status` call can return.
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

/// Cause for `ConnectionHealth::Degraded`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DegradedReason {
    /// `wg show` reports `latest_handshake` exceeding the staleness threshold.
    HandshakeStale { seconds_since_last_handshake: u64 },
    /// One `WireGuard` peer with expected traffic has stale evidence; unrelated
    /// peers/routes do not borrow another peer's health.
    WireGuardPeerStale {
        peer_public_key: String,
        allowed_routes: Vec<String>,
        seconds_since_last_handshake: u64,
    },
    /// A peer with expected traffic has never produced cryptographic evidence.
    WireGuardPeerNeverObserved {
        peer_public_key: String,
        allowed_routes: Vec<String>,
    },
    /// Telemetry reports high packet loss to all configured probe targets.
    HighPacketLoss { loss_percent: f32 },
    /// Telemetry reports ICMP latency above the configured threshold.
    HighLatency { latency_ms: u64 },
}

/// Health summary for `Connection::Connected`.
///
/// `Unknown` is the initial state immediately after a successful `up` —
/// telemetry hasn't reported yet. The TUI renders "Measuring…" in that
/// window (v0.1.7 ROADMAP item).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ConnectionHealth {
    #[default]
    Unknown,
    Healthy,
    Degraded {
        reason: DegradedReason,
    },
}

/// Technical details parsed from the VPN interface.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DetailedConnectionInfo {
    pub interface: String,
    pub internal_ip: String,
    pub endpoint: String,
    pub mtu: String,
    /// `WireGuard` public key (empty for `OpenVPN`).
    pub public_key: String,
    pub listen_port: String,
    pub transfer_rx: String,
    pub transfer_tx: String,
    pub latest_handshake: String,
    /// Scanner-derived health carried atomically with refreshed metadata.
    /// Internal-only; the enclosing `Connection` owns the public projection.
    #[serde(skip)]
    pub health_hint: ConnectionHealth,
    pub pid: Option<u32>,
    /// Exact attempt generation that produced this connected state.
    #[serde(skip)]
    pub generation: u64,
    /// Protocol-authoritative handshake evidence for this attempt.
    #[serde(skip)]
    pub handshake: Option<crate::tunnel::HandshakeEvidence>,
    /// Per-peer probes actually issued and route-verified for this attempt.
    #[serde(skip)]
    pub probe_receipts: Vec<crate::tunnel::ProbeReceipt>,
    /// Exact userspace-child ownership capability. Internal-only and never
    /// exposed through snapshots or JSON.
    #[serde(skip)]
    pub process_ownership: Option<crate::process::ManagedProcessId>,
    /// Protocol-requested resolver intent retained for the global policy
    /// worker. Internal-only so existing IPC/JSON snapshots remain stable.
    #[serde(skip)]
    pub dns_request: crate::control::dns::DnsRequest,
    /// Protocol-owned teardown config. Never serialized into snapshots.
    #[serde(skip)]
    pub teardown_config: Option<crate::tunnel::TunnelTeardownConfig>,
    /// Whether `interface` came from a reliable per-tunnel source.
    ///
    /// `true` when set by the protocol layer's the protocol `up()` result
    /// (`OpenVPN` log scrape, wg-quick output resolved through the
    /// platform port). `false` only when the scanner adopted an
    /// externally-started tunnel on a platform where its per-PID
    /// interface detection is unreliable (current state: macOS
    /// multi-`OpenVPN`, where the ifconfig fallback collides across
    /// PIDs). The engine never adopts a tunnel with `false`, because
    /// vortix cannot claim a routing status it can't verify against the
    /// kernel.
    ///
    /// Defaults to `true` — most tunnels are authoritative; the
    /// adoption path is the narrow exception that must opt out.
    #[serde(default = "default_interface_authoritative")]
    pub interface_authoritative: bool,
}

fn default_interface_authoritative() -> bool {
    true
}

impl Default for DetailedConnectionInfo {
    fn default() -> Self {
        Self {
            interface: String::new(),
            internal_ip: String::new(),
            endpoint: String::new(),
            mtu: String::new(),
            public_key: String::new(),
            listen_port: String::new(),
            transfer_rx: String::new(),
            transfer_tx: String::new(),
            latest_handshake: String::new(),
            health_hint: ConnectionHealth::default(),
            pid: None,
            generation: 0,
            handshake: None,
            probe_receipts: Vec::new(),
            process_ownership: None,
            dns_request: crate::control::dns::DnsRequest::default(),
            teardown_config: None,
            interface_authoritative: true,
        }
    }
}

/// What a mid-connect prompt asks the user for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptKind {
    TwoFactorCode,
    Passphrase,
    Generic { label: String },
}

/// The connection state machine.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Connection {
    /// No active VPN connection.
    #[default]
    Disconnected,
    /// Initial connect in progress.
    Connecting {
        profile_id: ProfileId,
        started_at: SystemTime,
    },
    /// Active VPN connection.
    Connected {
        profile_id: ProfileId,
        since: SystemTime,
        details: Box<DetailedConnectionInfo>,
    },
    /// Lost the tunnel; trying to bring it back without involving the user.
    Reconnecting {
        profile_id: ProfileId,
        started_at: SystemTime,
    },
    /// User-initiated disconnect in progress.
    Disconnecting {
        profile_id: ProfileId,
        started_at: SystemTime,
    },
    /// Waiting for the user to supply credentials.
    AwaitingUserInput {
        profile_id: ProfileId,
        prompt_kind: PromptKind,
        since: SystemTime,
    },
}

impl Connection {
    /// The profile currently in scope (`None` only for `Disconnected`).
    #[must_use]
    pub fn profile_id(&self) -> Option<&ProfileId> {
        match self {
            Self::Disconnected { .. } => None,
            Self::Connecting { profile_id, .. }
            | Self::Connected { profile_id, .. }
            | Self::Reconnecting { profile_id, .. }
            | Self::Disconnecting { profile_id, .. }
            | Self::AwaitingUserInput { profile_id, .. } => Some(profile_id),
        }
    }

    /// `true` when the engine is in a steady-state, non-transitional state.
    #[must_use]
    pub fn is_steady(&self) -> bool {
        matches!(self, Self::Disconnected { .. } | Self::Connected { .. })
    }

    /// `true` when an active tunnel exists (Connected).
    #[must_use]
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disconnected() {
        let s = Connection::default();
        assert!(matches!(s, Connection::Disconnected));
    }

    #[test]
    fn profile_id_is_none_for_disconnected() {
        let s = Connection::default();
        assert!(s.profile_id().is_none());
    }

    #[test]
    fn profile_id_is_some_for_other_states() {
        let p = ProfileId::new("corp");
        let s = Connection::Connecting {
            profile_id: p.clone(),
            started_at: SystemTime::now(),
        };
        assert_eq!(s.profile_id(), Some(&p));
    }

    #[test]
    fn is_steady_distinguishes_states() {
        let p = ProfileId::new("corp");
        assert!(Connection::default().is_steady());
        assert!(!Connection::Connecting {
            profile_id: p.clone(),
            started_at: SystemTime::now(),
        }
        .is_steady());
    }
    #[test]
    fn awaiting_user_input_carries_profile_id() {
        let p = ProfileId::new("corp");
        let s = Connection::AwaitingUserInput {
            profile_id: p.clone(),
            prompt_kind: PromptKind::TwoFactorCode,
            since: SystemTime::now(),
        };
        assert_eq!(s.profile_id(), Some(&p));
    }

    #[test]
    fn awaiting_user_input_is_not_steady() {
        // Like Connecting/Disconnecting, it's a transitional state.
        let s = Connection::AwaitingUserInput {
            profile_id: ProfileId::new("corp"),
            prompt_kind: PromptKind::TwoFactorCode,
            since: SystemTime::now(),
        };
        assert!(!s.is_steady());
        assert!(!s.is_connected());
    }

    #[test]
    fn prompt_kind_roundtrips_through_json() {
        let kinds = [
            PromptKind::TwoFactorCode,
            PromptKind::Passphrase,
            PromptKind::Generic {
                label: "Hardware token PIN".into(),
            },
        ];
        for k in kinds {
            let json = serde_json::to_string(&k).unwrap();
            let back: PromptKind = serde_json::from_str(&json).unwrap();
            assert_eq!(k, back);
        }
    }
}

/// Opaque operation identity scoped by the monotonic authority epoch.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct OperationId(String);

impl OperationId {
    #[must_use]
    pub fn parse(value: impl Into<String>) -> Option<Self> {
        let value = Self(value.into());
        value.sequence().map(|_| value)
    }

    pub(crate) fn from_parts(authority_epoch: AuthorityEpoch, sequence: u64) -> Self {
        Self(format!("op-{:016x}-{sequence:016x}", authority_epoch.0))
    }

    pub(crate) fn sequence(&self) -> Option<u64> {
        parse_scoped_id(&self.0, "op").map(|(_, sequence)| sequence)
    }
}

impl<'de> Deserialize<'de> for OperationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Self(String::deserialize(deserializer)?);
        value
            .sequence()
            .map(|_| value)
            .ok_or_else(|| serde::de::Error::custom("invalid service-issued operation ID"))
    }
}

impl std::fmt::Display for OperationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn parse_scoped_id(value: &str, prefix: &str) -> Option<(u64, u64)> {
    let rest = value.strip_prefix(prefix)?.strip_prefix('-')?;
    let (epoch, sequence) = rest.split_once('-')?;
    if epoch.len() != 16
        || sequence.len() != 16
        || !epoch.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !sequence.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some((
        u64::from_str_radix(epoch, 16).ok()?,
        u64::from_str_radix(sequence, 16).ok()?,
    ))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthorityEpoch(pub u64);

/// Identity of one tunnel generation, recorded with its ownership receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TunnelRevision {
    pub authority_epoch: AuthorityEpoch,
    pub generation: u64,
}
