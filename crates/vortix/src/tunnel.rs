//! `TunnelKind` aggregate — runtime-selectable tunnel dispatcher.
//!
//! The engine routes `profile.protocol → TunnelKind` exactly once via
//! [`tunnel_for`]; everything downstream calls the trait without protocol
//! match arms.
//!
//! The aggregate lives in the binary (not `vortix-core`) for the same
//! Cargo-cycle reason as `Platform`: the protocol crates already
//! depend on `vortix-core`.

use std::collections::BTreeMap;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::vortix_core::ports::tunnel::{
    ParseError, ParsedProfile, Tunnel, TunnelCapabilities, TunnelError, TunnelExecutionContext,
    TunnelHandle, TunnelKindTag, TunnelStatus,
};
use crate::vortix_core::profile::{Profile, ProfileId, ProtocolKind};
use crate::vortix_protocol_openvpn::OvpnTunnel;
use crate::vortix_protocol_wireguard::WgTunnel;

use crate::state::{Protocol, VpnProfile};

/// Runtime-selectable carrier over the closed protocol set.
///
/// Mock variant uses `crate::vortix_core::ports::tunnel::mock::MockTunnel` so tests
/// can substitute scripted behaviour without touching the real impls.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum TunnelKind {
    WireGuard(WgTunnel),
    OpenVpn(OvpnTunnel),
    Mock(crate::vortix_core::ports::tunnel::mock::MockTunnel),
}

impl TunnelKind {
    #[must_use]
    pub fn for_generation(self, generation: u64) -> Self {
        match self {
            Self::WireGuard(tunnel) => Self::WireGuard(tunnel.for_generation(generation)),
            other => other,
        }
    }

    #[must_use]
    pub fn with_execution_context(self, context: TunnelExecutionContext) -> Self {
        match self {
            Self::WireGuard(tunnel) => Self::WireGuard(tunnel.with_execution_context(context)),
            other => other,
        }
    }
    pub fn up(&mut self, profile: &Profile) -> Result<TunnelHandle, TunnelError> {
        match self {
            Self::WireGuard(t) => t.up(profile),
            Self::OpenVpn(t) => t.up(profile),
            Self::Mock(t) => t.up(profile),
        }
    }

    pub fn down(&mut self, handle: TunnelHandle) -> Result<(), TunnelError> {
        match self {
            Self::WireGuard(t) => t.down(handle),
            Self::OpenVpn(t) => t.down(handle),
            Self::Mock(t) => t.down(handle),
        }
    }

    pub fn status(&self, handle: &TunnelHandle) -> Result<TunnelStatus, TunnelError> {
        match self {
            Self::WireGuard(t) => t.status(handle),
            Self::OpenVpn(t) => t.status(handle),
            Self::Mock(t) => t.status(handle),
        }
    }

    pub fn parse_profile(&self, raw: &[u8]) -> Result<Box<dyn ParsedProfile>, ParseError> {
        match self {
            Self::WireGuard(t) => t.parse_profile(raw),
            Self::OpenVpn(t) => t.parse_profile(raw),
            Self::Mock(t) => t.parse_profile(raw),
        }
    }

    #[must_use]
    pub fn capabilities(&self) -> TunnelCapabilities {
        match self {
            Self::WireGuard(t) => t.capabilities(),
            Self::OpenVpn(t) => t.capabilities(),
            Self::Mock(t) => t.capabilities(),
        }
    }

    #[must_use]
    pub fn kind_tag(&self) -> TunnelKindTag {
        match self {
            Self::WireGuard(t) => t.kind_tag(),
            Self::OpenVpn(t) => t.kind_tag(),
            Self::Mock(t) => t.kind_tag(),
        }
    }

    /// Compensate a protocol attempt that unwound before returning a handle.
    pub fn compensate_inflight(&mut self) -> Result<(), String> {
        match self {
            Self::WireGuard(tunnel) => tunnel
                .compensate_inflight()
                .map_err(|error| error.to_string()),
            Self::OpenVpn(_) | Self::Mock(_) => {
                Err("protocol did not retain an exact in-flight capability".into())
            }
        }
    }
}

/// Immutable production settings for canonical tunnel workers.
#[derive(Debug, Clone)]
pub struct CanonicalTunnelSettings {
    pub config_dir: PathBuf,
    pub openvpn_verbosity: String,
    pub connect_timeout_secs: u64,
    pub wireguard_handshake_timeout_secs: u64,
    pub wireguard_health_targets: Vec<String>,
}

type CanonicalProfileResolver = dyn Fn(&ProfileId) -> Option<Profile> + Send + Sync;

/// Production adapter from bounded canonical work to the concrete protocol
/// implementations. Successful `WireGuard` receipts are generated only from
/// the exact generation-bound handle returned by `WgTunnel::up`.
pub struct CanonicalTunnelExecutor {
    settings: CanonicalTunnelSettings,
    profiles: Arc<CanonicalProfileResolver>,
    active: Mutex<BTreeMap<ProfileId, (TunnelKind, TunnelHandle)>>,
}

impl CanonicalTunnelExecutor {
    #[must_use]
    pub fn new(
        settings: CanonicalTunnelSettings,
        profiles: impl Fn(&ProfileId) -> Option<Profile> + Send + Sync + 'static,
    ) -> Self {
        Self {
            settings,
            profiles: Arc::new(profiles),
            active: Mutex::new(BTreeMap::new()),
        }
    }

    fn protocol_for(kind: TunnelKindTag) -> Result<Protocol, String> {
        match kind {
            TunnelKindTag::WireGuard => Ok(Protocol::WireGuard),
            TunnelKindTag::OpenVpn => Ok(Protocol::OpenVPN),
            TunnelKindTag::Mock => Err("mock protocol cannot execute in production".into()),
        }
    }

    fn execute_connect(
        &self,
        work: &crate::vortix_core::control::worker::TunnelWork,
        cancellation: &crate::vortix_core::control::worker::CancellationToken,
    ) -> Result<crate::vortix_core::control::worker::TunnelExecutionReceipt, String> {
        let profile = (self.profiles)(&work.profile_id)
            .ok_or_else(|| format!("profile {} no longer exists", work.profile_id))?;
        let protocol = Self::protocol_for(work.protocol)?;
        let expected_protocol = match profile.protocol {
            ProtocolKind::WireGuard => Protocol::WireGuard,
            ProtocolKind::OpenVpn => Protocol::OpenVPN,
        };
        if protocol != expected_protocol {
            return Err("canonical work protocol did not match profile".into());
        }
        let context = TunnelExecutionContext {
            cancellation: cancellation.clone(),
            deadline: work.deadline,
        };
        let mut tunnel = tunnel_for_with_wireguard_policy(
            protocol,
            &self.settings.config_dir,
            &self.settings.openvpn_verbosity,
            self.settings.connect_timeout_secs,
            self.settings.wireguard_handshake_timeout_secs,
            &self.settings.wireguard_health_targets,
        )
        .for_generation(work.revision.generation)
        .with_execution_context(context);
        let handle = match panic::catch_unwind(AssertUnwindSafe(|| tunnel.up(&profile))) {
            Ok(result) => result.map_err(|error| error.to_string())?,
            Err(_) => {
                return Err(match tunnel.compensate_inflight() {
                    Ok(()) => "canonical tunnel executor panicked; exact attempt removed".into(),
                    Err(error) => format!(
                        "canonical tunnel executor panicked and ownership is ambiguous: {error}"
                    ),
                });
            }
        };
        if cancellation.is_cancelled() || std::time::Instant::now() >= work.deadline {
            let cleanup = tunnel.down(handle);
            return Err(match cleanup {
                Ok(()) => "canonical tunnel work was cancelled; owned attempt removed".into(),
                Err(error) => format!(
                    "canonical tunnel work was cancelled and ownership is ambiguous: {error}"
                ),
            });
        }
        let receipt = Self::receipt_for(work, &handle);
        let receipt = match receipt {
            Ok(receipt) => receipt,
            Err(error) => {
                let cleanup = tunnel.down(handle);
                return Err(match cleanup {
                    Ok(()) => error,
                    Err(cleanup) => format!(
                        "{error}; receipt failure cleanup left ownership ambiguous: {cleanup}"
                    ),
                });
            }
        };
        self.active
            .lock()
            .map_err(|_| "canonical active-tunnel ledger poisoned".to_string())?
            .insert(work.profile_id.clone(), (tunnel, handle));
        Ok(receipt)
    }

    fn receipt_for(
        work: &crate::vortix_core::control::worker::TunnelWork,
        handle: &TunnelHandle,
    ) -> Result<crate::vortix_core::control::worker::TunnelExecutionReceipt, String> {
        use crate::vortix_core::control::worker::TunnelExecutionReceipt;
        if work.protocol != TunnelKindTag::WireGuard {
            return TunnelExecutionReceipt::attested(
                work.profile_id.clone(),
                handle.interface_name.clone(),
                work.protocol,
                handle.pid,
                format!("openvpn-generation:{}", work.revision.generation),
            );
        }
        let handshake = handle
            .handshake
            .clone()
            .filter(|evidence| evidence.generation == work.revision.generation)
            .ok_or_else(|| {
                "WireGuard returned without exact current-generation handshake evidence".to_string()
            })?;
        TunnelExecutionReceipt::wireguard(
            work.profile_id.clone(),
            handle.interface_name.clone(),
            format!(
                "wg-generation:{}:peer:{}",
                work.revision.generation, handshake.peer_public_key
            ),
            handshake,
        )
        .map(|receipt| receipt.with_probe_receipts(handle.probe_receipts.clone()))
    }

    fn execute_disconnect(
        &self,
        work: &crate::vortix_core::control::worker::TunnelWork,
    ) -> Result<crate::vortix_core::control::worker::TunnelExecutionReceipt, String> {
        use crate::vortix_core::control::worker::TunnelExecutionReceipt;
        let owned = self
            .active
            .lock()
            .map_err(|_| "canonical active-tunnel ledger poisoned".to_string())?
            .remove(&work.profile_id);
        let Some((mut tunnel, handle)) = owned else {
            return Ok(TunnelExecutionReceipt::default());
        };
        match tunnel.down(handle.clone()) {
            Ok(()) => Ok(TunnelExecutionReceipt::default()),
            Err(error) => {
                self.active
                    .lock()
                    .map_err(|_| "canonical active-tunnel ledger poisoned".to_string())?
                    .insert(work.profile_id.clone(), (tunnel, handle));
                Err(error.to_string())
            }
        }
    }
}

impl crate::vortix_core::control::worker::TunnelExecutor for CanonicalTunnelExecutor {
    fn execute(
        &self,
        work: &crate::vortix_core::control::worker::TunnelWork,
        cancellation: &crate::vortix_core::control::worker::CancellationToken,
    ) -> Result<crate::vortix_core::control::worker::TunnelExecutionReceipt, String> {
        use crate::vortix_core::control::worker::TunnelMutation;
        if cancellation.is_cancelled() || std::time::Instant::now() >= work.deadline {
            return Err("canonical tunnel work was cancelled or expired".into());
        }
        match work.mutation {
            TunnelMutation::Connect => self.execute_connect(work, cancellation),
            TunnelMutation::Disconnect => self.execute_disconnect(work),
        }
    }

    fn classify_failure(&self, error: &str) -> crate::vortix_core::control::worker::WorkFailure {
        use crate::vortix_core::control::worker::WorkFailure;
        if error.contains("ownership is ambiguous") || error.contains("outcome is ambiguous") {
            WorkFailure::OutcomeUnknown
        } else if error.contains("panicked") {
            WorkFailure::Panicked
        } else if error.contains("cancelled") {
            WorkFailure::Cancelled
        } else if error.contains("expired") || error.contains("timed out") {
            WorkFailure::TimedOut
        } else if error.contains("handshake") || error.contains("Handshake") {
            WorkFailure::HandshakeFailed
        } else {
            WorkFailure::EffectFailed
        }
    }

    fn compensate_late_success(
        &self,
        work: &crate::vortix_core::control::worker::TunnelWork,
    ) -> Result<(), String> {
        if work.mutation != crate::vortix_core::control::worker::TunnelMutation::Connect {
            return Ok(());
        }
        let owned = self
            .active
            .lock()
            .map_err(|_| "canonical active-tunnel ledger poisoned".to_string())?
            .remove(&work.profile_id);
        let Some((mut tunnel, handle)) = owned else {
            return Ok(());
        };
        if handle.generation != work.revision.generation {
            self.active
                .lock()
                .map_err(|_| "canonical active-tunnel ledger poisoned".to_string())?
                .insert(work.profile_id.clone(), (tunnel, handle));
            return Err("late completion did not own the active generation".into());
        }
        tunnel.down(handle).map_err(|error| error.to_string())
    }

    fn compensate_uncertain(
        &self,
        work: &crate::vortix_core::control::worker::TunnelWork,
    ) -> Result<(), String> {
        self.compensate_late_success(work)
    }
}

// Implement the `Tunnel` trait by delegating to the inherent methods.
// Plan 005's `Engine<T: Tunnel>` requires this so the binary can construct
// `Engine<TunnelKind>` and drive the FSM with the existing dispatch.
impl crate::vortix_core::ports::tunnel::Tunnel for TunnelKind {
    fn up(&mut self, profile: &Profile) -> Result<TunnelHandle, TunnelError> {
        TunnelKind::up(self, profile)
    }
    fn down(&mut self, handle: TunnelHandle) -> Result<(), TunnelError> {
        TunnelKind::down(self, handle)
    }
    fn status(&self, handle: &TunnelHandle) -> Result<TunnelStatus, TunnelError> {
        TunnelKind::status(self, handle)
    }
    fn parse_profile(&self, raw: &[u8]) -> Result<Box<dyn ParsedProfile>, ParseError> {
        TunnelKind::parse_profile(self, raw)
    }
    fn capabilities(&self) -> TunnelCapabilities {
        TunnelKind::capabilities(self)
    }
    fn kind_tag(&self) -> TunnelKindTag {
        TunnelKind::kind_tag(self)
    }
}

/// THE single routing function: protocol → `TunnelKind`.
///
/// Engine and CLI call this once per connect/disconnect and never branch on
/// protocol again. Adding a third protocol means adding one variant here.
#[must_use]
pub fn tunnel_for(
    protocol: Protocol,
    config_dir: &Path,
    ovpn_verbosity: &str,
    connect_timeout_secs: u64,
) -> TunnelKind {
    match protocol {
        Protocol::WireGuard => TunnelKind::WireGuard(WgTunnel::new()),
        Protocol::OpenVPN => TunnelKind::OpenVpn(
            OvpnTunnel::new(config_dir.join(crate::constants::OPENVPN_RUN_DIR))
                .with_auth_dir(config_dir.join(crate::constants::OPENVPN_AUTH_DIR))
                .with_verbosity(ovpn_verbosity)
                .with_connect_timeout(connect_timeout_secs),
        ),
    }
}

/// Construct a tunnel with the configured `WireGuard` handshake gate.
#[must_use]
pub fn tunnel_for_with_wireguard_policy(
    protocol: Protocol,
    config_dir: &Path,
    ovpn_verbosity: &str,
    connect_timeout_secs: u64,
    wireguard_handshake_timeout_secs: u64,
    wireguard_health_targets: &[String],
) -> TunnelKind {
    match protocol {
        Protocol::WireGuard => TunnelKind::WireGuard(
            WgTunnel::new().with_handshake_policy(
                std::time::Duration::from_secs(wireguard_handshake_timeout_secs),
                wireguard_health_targets
                    .iter()
                    .filter_map(|target| target.parse().ok()),
            ),
        ),
        Protocol::OpenVPN => tunnel_for(protocol, config_dir, ovpn_verbosity, connect_timeout_secs),
    }
}

/// Build a `vortix-core` [`Profile`] view from the binary-side `VpnProfile`.
///
/// Plan 007 reconciles the two profile types; until then the engine
/// translates at the trait boundary.
#[must_use]
pub fn profile_view(p: &VpnProfile) -> Profile {
    Profile::new(
        p.id.clone(),
        &p.name,
        match p.protocol {
            Protocol::WireGuard => ProtocolKind::WireGuard,
            Protocol::OpenVPN => ProtocolKind::OpenVpn,
        },
        p.config_path.clone(),
    )
}

#[cfg(test)]
mod canonical_tests {
    use super::*;
    use crate::vortix_core::control::model::{AuthorityEpoch, OperationId};
    use crate::vortix_core::control::worker::{TunnelMutation, TunnelRevision, TunnelWork};
    use crate::vortix_core::ports::dns::DnsRequest;
    use crate::vortix_core::ports::tunnel::{HandshakeEvidence, TunnelTeardownConfig};
    use std::time::{Duration, Instant, SystemTime};

    fn work(generation: u64) -> TunnelWork {
        TunnelWork {
            profile_id: ProfileId::new("corp"),
            operation_id: serde_json::from_str::<OperationId>(
                "\"op-0000000000000001-0000000000000001\"",
            )
            .unwrap(),
            revision: TunnelRevision {
                authority_epoch: AuthorityEpoch(1),
                generation,
            },
            mutation: TunnelMutation::Connect,
            protocol: TunnelKindTag::WireGuard,
            deadline: Instant::now() + Duration::from_secs(1),
        }
    }

    fn handle(generation: u64) -> TunnelHandle {
        TunnelHandle {
            profile_id: ProfileId::new("corp"),
            display_name: "corp".into(),
            interface_name: "wg0".into(),
            pid: None,
            started_at: SystemTime::now(),
            kind: TunnelKindTag::WireGuard,
            generation,
            handshake: Some(HandshakeEvidence {
                generation,
                peer_public_key: "peer".into(),
                handshake_at: SystemTime::now(),
                observed_at: SystemTime::now(),
                allowed_routes: vec!["10.0.0.0/24".into()],
            }),
            probe_receipts: Vec::new(),
            process_ownership: None,
            teardown_config: None::<TunnelTeardownConfig>,
            dns_request: DnsRequest::default(),
        }
    }

    #[test]
    fn canonical_wireguard_receipt_requires_exact_generation() {
        let exact = CanonicalTunnelExecutor::receipt_for(&work(7), &handle(7)).unwrap();
        assert_eq!(exact.handshake.unwrap().generation, 7);
        assert!(CanonicalTunnelExecutor::receipt_for(&work(8), &handle(7)).is_err());
    }
}
