//! Authenticated helper receipts translated into canonical tunnel evidence.

#![allow(
    dead_code,
    reason = "helper tunnel execution remains dormant until enrolled daemon authority activation"
)]

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use thiserror::Error;

use super::helper_client::{
    AuthenticatedHelperConnector, AuthenticatedHelperOutcome, AuthenticatedHelperTransport,
    HelperClientError, HelperExecutionFailure, RecoveryAction,
};
use super::tunnel_material::PreparedTunnelStart;
use crate::helper::{process_group_for_tunnel, HelperRuntimeIdentity};
use crate::helper::{HelperCapability, PlatformLayout};
use crate::vortix_core::control::worker::{
    TunnelExecutionReceipt, TunnelExecutor, TunnelMutation, TunnelWork, WorkFailure,
};
use crate::vortix_core::ports::tunnel::{
    HandshakeEvidence, ProbeReceipt, TunnelCancellation, TunnelKindTag,
};
use crate::vortix_core::privileged::{
    AuthorityBinding, ObservationState, OperationDigest, PrivilegedOperation, ProtocolPlan,
    ResourceObservationTarget, ResourceTag, WireGuardPlan,
};
use crate::vortix_core::profile::{Profile, ProfileId, ProtocolKind};

const HELPER_UNAVAILABLE: &str = "helper-tunnel:unavailable";
const HELPER_TIMED_OUT: &str = "helper-tunnel:timed-out";
const HELPER_CANCELLED: &str = "helper-tunnel:cancelled";
const HELPER_BUSY: &str = "helper-tunnel:busy";
const HELPER_HANDSHAKE_MISSING: &str = "helper-tunnel:handshake-missing";
const HELPER_EFFECT_FAILED: &str = "helper-tunnel:effect-failed";
const HELPER_OUTCOME_UNKNOWN: &str = "helper-tunnel:outcome-unknown";
const COMPENSATION_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HANDSHAKE_HEALTH_TARGETS: usize = 64;

type ProfileLookup = dyn Fn(&ProfileId) -> Option<Profile> + Send + Sync;

pub(super) trait HelperTunnelSession: Send {
    fn execute_bound(
        &mut self,
        operation: PrivilegedOperation,
        descriptors: &[RawFd],
        deadline: Instant,
    ) -> Result<AuthenticatedHelperOutcome, HelperTunnelTransportFailure>;
}

pub(super) trait HelperTunnelTransport: Send + Sync {
    fn authority_binding(&self) -> AuthorityBinding;

    fn enables(&self, capability: HelperCapability) -> bool;

    fn connect(
        &self,
        deadline: Instant,
    ) -> Result<Box<dyn HelperTunnelSession>, HelperTunnelTransportFailure>;
}

impl HelperTunnelSession for AuthenticatedHelperTransport {
    fn execute_bound(
        &mut self,
        operation: PrivilegedOperation,
        descriptors: &[RawFd],
        deadline: Instant,
    ) -> Result<AuthenticatedHelperOutcome, HelperTunnelTransportFailure> {
        AuthenticatedHelperTransport::execute_bound(self, operation, descriptors, deadline)
            .map_err(HelperTunnelTransportFailure::from)
    }
}

impl HelperTunnelTransport for AuthenticatedHelperConnector {
    fn authority_binding(&self) -> AuthorityBinding {
        self.authority_binding()
    }

    fn enables(&self, capability: HelperCapability) -> bool {
        self.enables(capability)
    }

    fn connect(
        &self,
        deadline: Instant,
    ) -> Result<Box<dyn HelperTunnelSession>, HelperTunnelTransportFailure> {
        AuthenticatedHelperConnector::connect(self, deadline)
            .map(|session| Box::new(session) as Box<dyn HelperTunnelSession>)
            .map_err(HelperTunnelTransportFailure::from)
    }
}

#[derive(Debug, Clone)]
pub(super) struct WireGuardHandshakePolicy {
    timeout: Duration,
    poll_interval: Duration,
    probe_timeout: Duration,
    health_targets: Vec<IpAddr>,
}

impl WireGuardHandshakePolicy {
    pub(super) fn new(
        timeout: Duration,
        poll_interval: Duration,
        probe_timeout: Duration,
        health_targets: Vec<IpAddr>,
    ) -> Result<Self, HelperBackedTunnelExecutorError> {
        if timeout.is_zero()
            || poll_interval.is_zero()
            || probe_timeout.is_zero()
            || health_targets.len() > MAX_HANDSHAKE_HEALTH_TARGETS
        {
            return Err(HelperBackedTunnelExecutorError::InvalidHandshakePolicy);
        }
        Ok(Self {
            timeout,
            poll_interval,
            probe_timeout,
            health_targets,
        })
    }
}

trait WireGuardProbeIssuer: Send + Sync {
    fn issue(
        &self,
        target: IpAddr,
        owned_interface: &str,
        timeout: Duration,
    ) -> Result<SystemTime, ()>;
}

struct ProtocolWireGuardProbeIssuer;

impl WireGuardProbeIssuer for ProtocolWireGuardProbeIssuer {
    fn issue(
        &self,
        target: IpAddr,
        owned_interface: &str,
        timeout: Duration,
    ) -> Result<SystemTime, ()> {
        crate::vortix_protocol_wireguard::tunnel::issue_handshake_probe(
            target,
            owned_interface,
            timeout,
        )
        .map_err(|_| ())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HelperTunnelTransportFailure {
    Unavailable,
    TimedOut,
    OutcomeUnknown,
}

impl From<HelperExecutionFailure> for HelperTunnelTransportFailure {
    fn from(failure: HelperExecutionFailure) -> Self {
        match failure.recovery() {
            RecoveryAction::ReconcileRequired => Self::OutcomeUnknown,
            RecoveryAction::Unavailable
                if matches!(failure.source(), HelperClientError::DeadlineExpired) =>
            {
                Self::TimedOut
            }
            RecoveryAction::Unavailable => Self::Unavailable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(super) enum HelperBackedTunnelExecutorError {
    #[error("authenticated helper lacks tunnel lifecycle or managed observation capability")]
    CapabilityMismatch,
    #[error("WireGuard handshake policy is invalid")]
    InvalidHandshakePolicy,
}

pub(super) struct HelperBackedTunnelExecutor {
    helper: Arc<dyn HelperTunnelTransport>,
    profiles: Arc<ProfileLookup>,
    receipts: HelperTunnelReceiptAdapter,
    handshake: WireGuardHandshakePolicy,
    probe_issuer: Arc<dyn WireGuardProbeIssuer>,
}

impl HelperBackedTunnelExecutor {
    pub(super) fn new(
        helper: Arc<dyn HelperTunnelTransport>,
        profiles: Arc<ProfileLookup>,
        handshake: WireGuardHandshakePolicy,
    ) -> Result<Self, HelperBackedTunnelExecutorError> {
        Self::with_probe_issuer(
            helper,
            profiles,
            handshake,
            Arc::new(ProtocolWireGuardProbeIssuer),
        )
    }

    fn with_probe_issuer(
        helper: Arc<dyn HelperTunnelTransport>,
        profiles: Arc<ProfileLookup>,
        handshake: WireGuardHandshakePolicy,
        probe_issuer: Arc<dyn WireGuardProbeIssuer>,
    ) -> Result<Self, HelperBackedTunnelExecutorError> {
        if !helper.enables(HelperCapability::TunnelLifecycle)
            || !helper.enables(HelperCapability::Observe)
        {
            return Err(HelperBackedTunnelExecutorError::CapabilityMismatch);
        }
        let receipts = HelperTunnelReceiptAdapter::new(helper.authority_binding());
        Ok(Self {
            helper,
            profiles,
            receipts,
            handshake,
            probe_issuer,
        })
    }

    fn connect(
        &self,
        work: &TunnelWork,
        cancellation: &TunnelCancellation,
    ) -> Result<TunnelExecutionReceipt, &'static str> {
        Self::check_pre_effect(work, cancellation)?;
        let tunnel = self
            .receipts
            .validate_work(work, TunnelMutation::Connect)
            .map_err(|_| HELPER_EFFECT_FAILED)?;
        let profile = (self.profiles)(&work.profile_id).ok_or(HELPER_EFFECT_FAILED)?;
        if profile.id != work.profile_id || profile.protocol != ProtocolKind::WireGuard {
            return Err(HELPER_EFFECT_FAILED);
        }
        let prepared = PreparedTunnelStart::wireguard(&profile, work.resource_revision.generation)
            .map_err(|_| HELPER_EFFECT_FAILED)?;
        Self::check_pre_effect(work, cancellation)?;
        let descriptor_fds = prepared.raw_descriptors();
        let (plan, descriptors) = prepared.into_parts();
        let ProtocolPlan::WireGuard(wireguard_plan) = &plan else {
            return Err(HELPER_EFFECT_FAILED);
        };
        let expected_routes = wireguard_peer_routes(wireguard_plan);
        let probes = wireguard_probe_plan(wireguard_plan, &self.handshake.health_targets)
            .map_err(|()| HELPER_HANDSHAKE_MISSING)?;
        let mut session = self.open_session(work.deadline)?;
        let started_at = SystemTime::now();
        let handshake_deadline = Instant::now()
            .checked_add(self.handshake.timeout)
            .map_or(work.deadline, |deadline| deadline.min(work.deadline));
        let start = match session.execute_bound(
            PrivilegedOperation::StartTunnel(plan),
            &descriptor_fds,
            work.deadline,
        ) {
            Ok(outcome) => outcome,
            Err(HelperTunnelTransportFailure::OutcomeUnknown) => {
                return Err(if self.reconcile_and_stop(work).is_ok() {
                    HELPER_EFFECT_FAILED
                } else {
                    HELPER_OUTCOME_UNKNOWN
                });
            }
            Err(error) => return Err(transport_error(error)),
        };
        drop(descriptors);

        if start.receipt().is_ambiguous() {
            return Err(if self.reconcile_and_stop(work).is_ok() {
                HELPER_EFFECT_FAILED
            } else {
                HELPER_OUTCOME_UNKNOWN
            });
        }
        if start.receipt().rejection_code().is_some() {
            return Err(receipt_failure(start.receipt()));
        }
        if !self.receipts.outcome_matches_authority(&start) || !start.receipt().owns(&tunnel) {
            return self.stop_after_start(work, HELPER_EFFECT_FAILED);
        }
        if let Err(error) = Self::check_pre_effect(work, cancellation) {
            return self.stop_after_start(work, error);
        }

        let probe_receipts =
            match self.issue_probes(work, cancellation, &tunnel, &probes, handshake_deadline) {
                Ok(receipts) => receipts,
                Err(error) => return self.stop_after_start(work, error),
            };
        self.await_handshake(
            session.as_mut(),
            work,
            cancellation,
            &HelperHandshakeContext {
                tunnel: &tunnel,
                started_at,
                start: &start,
                probe_receipts: &probe_receipts,
                expected_routes: &expected_routes,
                deadline: handshake_deadline,
            },
        )
    }

    fn await_handshake(
        &self,
        session: &mut dyn HelperTunnelSession,
        work: &TunnelWork,
        cancellation: &TunnelCancellation,
        context: &HelperHandshakeContext<'_>,
    ) -> Result<TunnelExecutionReceipt, &'static str> {
        loop {
            if let Err(error) = Self::check_pre_effect(work, cancellation) {
                return self.stop_after_start(work, error);
            }
            if Instant::now() >= context.deadline {
                let failure = if Instant::now() >= work.deadline {
                    HELPER_TIMED_OUT
                } else {
                    HELPER_HANDSHAKE_MISSING
                };
                return self.stop_after_start(work, failure);
            }
            let observation = match session.execute_bound(
                managed_observation_operation(context.tunnel),
                &[],
                context.deadline,
            ) {
                Ok(outcome) => outcome,
                Err(HelperTunnelTransportFailure::TimedOut) if Instant::now() < work.deadline => {
                    return self.stop_after_start(work, HELPER_HANDSHAKE_MISSING);
                }
                Err(error) => return self.stop_after_start(work, transport_error(error)),
            };
            let observation_failure = receipt_failure(observation.receipt());
            match self.receipts.connect_receipt(
                work,
                context.started_at,
                context.start,
                &observation,
                context.probe_receipts,
                context.expected_routes,
            ) {
                Ok(receipt) => return Ok(receipt),
                Err(HelperTunnelReceiptError::HandshakeMissing) => {
                    if let Err(error) =
                        self.wait_for_next_observation(work, cancellation, context.deadline)
                    {
                        return self.stop_after_start(work, error);
                    }
                }
                Err(_) => return self.stop_after_start(work, observation_failure),
            }
        }
    }

    fn disconnect(&self, work: &TunnelWork) -> Result<TunnelExecutionReceipt, &'static str> {
        let tunnel = self
            .receipts
            .resource_for_work(work)
            .map_err(|_| HELPER_EFFECT_FAILED)?;
        let mut session = self.open_session(work.deadline)?;
        let stopped = match session.execute_bound(
            PrivilegedOperation::StopTunnel(tunnel),
            &[],
            work.deadline,
        ) {
            Ok(outcome) => outcome,
            Err(error) => return Err(transport_error(error)),
        };
        if stopped.receipt().is_ambiguous() {
            return self
                .reconcile_and_stop(work)
                .map(|()| TunnelExecutionReceipt::default())
                .map_err(|()| HELPER_OUTCOME_UNKNOWN);
        }
        if stopped.receipt().rejection_code().is_some() {
            return Err(receipt_failure(stopped.receipt()));
        }
        self.receipts
            .disconnect_receipt(work, &stopped)
            .map_err(|_| HELPER_EFFECT_FAILED)
    }

    fn check_pre_effect(
        work: &TunnelWork,
        cancellation: &TunnelCancellation,
    ) -> Result<(), &'static str> {
        if cancellation.is_cancelled() {
            Err(HELPER_CANCELLED)
        } else if Instant::now() >= work.deadline {
            Err(HELPER_TIMED_OUT)
        } else {
            Ok(())
        }
    }

    fn open_session(
        &self,
        deadline: Instant,
    ) -> Result<Box<dyn HelperTunnelSession>, &'static str> {
        self.helper.connect(deadline).map_err(transport_error)
    }

    fn stop_after_start(
        &self,
        work: &TunnelWork,
        failure: &'static str,
    ) -> Result<TunnelExecutionReceipt, &'static str> {
        Err(if self.stop_and_prove_absence(work).is_ok() {
            failure
        } else {
            HELPER_OUTCOME_UNKNOWN
        })
    }

    fn stop_and_prove_absence(&self, work: &TunnelWork) -> Result<(), ()> {
        let tunnel = self.receipts.resource_for_work(work).map_err(|_| ())?;
        let deadline = Instant::now() + COMPENSATION_TIMEOUT;
        let mut session = self.helper.connect(deadline).map_err(|_| ())?;
        self.stop_with_session(session.as_mut(), work, tunnel, deadline)
    }

    fn stop_with_session(
        &self,
        session: &mut dyn HelperTunnelSession,
        work: &TunnelWork,
        tunnel: ResourceTag,
        deadline: Instant,
    ) -> Result<(), ()> {
        let stopped = session
            .execute_bound(PrivilegedOperation::StopTunnel(tunnel), &[], deadline)
            .map_err(|_| ())?;
        self.receipts
            .compensation_proves_absence(work, &stopped)
            .map_err(|_| ())
    }

    fn reconcile_and_stop(&self, work: &TunnelWork) -> Result<(), ()> {
        let tunnel = self.receipts.resource_for_work(work).map_err(|_| ())?;
        let deadline = Instant::now() + COMPENSATION_TIMEOUT;
        let mut session = self.helper.connect(deadline).map_err(|_| ())?;
        let observation = session
            .execute_bound(managed_observation_operation(&tunnel), &[], deadline)
            .map_err(|_| ())?;
        match self
            .receipts
            .managed_state(work, &observation)
            .map_err(|_| ())?
        {
            ObservationState::Absent => Ok(()),
            ObservationState::Present => {
                self.stop_with_session(session.as_mut(), work, tunnel, deadline)
            }
            ObservationState::Drifted | ObservationState::Unknown => Err(()),
        }
    }

    fn issue_probes(
        &self,
        work: &TunnelWork,
        cancellation: &TunnelCancellation,
        tunnel: &ResourceTag,
        probes: &[WireGuardProbePlan],
        deadline: Instant,
    ) -> Result<Vec<ProbeReceipt>, &'static str> {
        let interface = self
            .receipts
            .kernel_alias_for(tunnel)
            .map_err(|_| HELPER_EFFECT_FAILED)?;
        let mut receipts = Vec::with_capacity(probes.len());
        for probe in probes {
            Self::check_pre_effect(work, cancellation)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(if Instant::now() >= work.deadline {
                    HELPER_TIMED_OUT
                } else {
                    HELPER_HANDSHAKE_MISSING
                });
            }
            let issued_at = self
                .probe_issuer
                .issue(
                    probe.target,
                    &interface,
                    self.handshake.probe_timeout.min(remaining),
                )
                .map_err(|()| HELPER_HANDSHAKE_MISSING)?;
            receipts.push(ProbeReceipt {
                peer_public_key: base64::engine::general_purpose::STANDARD
                    .encode(probe.peer_public_key),
                target: probe.target,
                allowed_routes: probe.allowed_routes.clone(),
                issued_at,
            });
        }
        Ok(receipts)
    }

    fn wait_for_next_observation(
        &self,
        work: &TunnelWork,
        cancellation: &TunnelCancellation,
        handshake_deadline: Instant,
    ) -> Result<(), &'static str> {
        let wake_at = Instant::now()
            .checked_add(self.handshake.poll_interval)
            .map_or(handshake_deadline, |wake| wake.min(handshake_deadline));
        loop {
            Self::check_pre_effect(work, cancellation)?;
            let remaining = wake_at.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(());
            }
            std::thread::sleep(remaining.min(Duration::from_millis(25)));
        }
    }
}

impl TunnelExecutor for HelperBackedTunnelExecutor {
    fn execute(
        &self,
        work: &TunnelWork,
        cancellation: &TunnelCancellation,
    ) -> Result<TunnelExecutionReceipt, String> {
        if work.protocol != TunnelKindTag::WireGuard {
            return Err(HELPER_EFFECT_FAILED.to_owned());
        }
        Self::check_pre_effect(work, cancellation)
            .and_then(|()| match work.mutation {
                TunnelMutation::Connect => self.connect(work, cancellation),
                TunnelMutation::Disconnect => self.disconnect(work),
            })
            .map_err(str::to_owned)
    }

    fn classify_failure(&self, error: &str) -> WorkFailure {
        match error {
            HELPER_TIMED_OUT => WorkFailure::TimedOut,
            HELPER_CANCELLED => WorkFailure::Cancelled,
            HELPER_BUSY => WorkFailure::Busy,
            HELPER_HANDSHAKE_MISSING => WorkFailure::HandshakeFailed,
            HELPER_OUTCOME_UNKNOWN => WorkFailure::OutcomeUnknown,
            _ => WorkFailure::EffectFailed,
        }
    }

    fn compensate_unaccepted_success(&self, work: &TunnelWork) -> Result<(), String> {
        if work.mutation == TunnelMutation::Disconnect {
            Ok(())
        } else {
            self.stop_and_prove_absence(work)
                .map_err(|()| HELPER_OUTCOME_UNKNOWN.to_owned())
        }
    }

    fn compensate_uncertain(&self, work: &TunnelWork) -> Result<(), String> {
        self.reconcile_and_stop(work)
            .map_err(|()| HELPER_OUTCOME_UNKNOWN.to_owned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WireGuardProbePlan {
    peer_public_key: [u8; 32],
    target: IpAddr,
    allowed_routes: Vec<String>,
}

struct HelperHandshakeContext<'a> {
    tunnel: &'a ResourceTag,
    started_at: SystemTime,
    start: &'a AuthenticatedHelperOutcome,
    probe_receipts: &'a [ProbeReceipt],
    expected_routes: &'a WireGuardPeerRoutes,
    deadline: Instant,
}

type WireGuardPeerRoutes = HashMap<[u8; 32], HashSet<crate::vortix_core::cidr::Cidr>>;

fn wireguard_peer_routes(plan: &WireGuardPlan) -> WireGuardPeerRoutes {
    plan.peers()
        .iter()
        .map(|peer| {
            (
                peer.public_key(),
                peer.allowed_routes().iter().copied().collect(),
            )
        })
        .collect()
}

fn wireguard_probe_plan(
    plan: &WireGuardPlan,
    health_targets: &[IpAddr],
) -> Result<Vec<WireGuardProbePlan>, ()> {
    plan.peers()
        .iter()
        .filter(|peer| peer.persistent_keepalive_seconds().is_none())
        .map(|peer| {
            let target =
                crate::vortix_protocol_wireguard::tunnel::select_health_probe_for_allowed_routes(
                    peer.allowed_routes(),
                    health_targets,
                )
                .ok_or(())?;
            Ok(WireGuardProbePlan {
                peer_public_key: peer.public_key(),
                target,
                allowed_routes: peer
                    .allowed_routes()
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            })
        })
        .collect()
}

fn managed_observation_operation(tunnel: &ResourceTag) -> PrivilegedOperation {
    PrivilegedOperation::ObserveManaged(vec![ResourceObservationTarget::new(
        tunnel.clone(),
        Some(ProtocolKind::WireGuard),
    )
    .expect("a validated WireGuard tunnel forms a managed observation target")])
}

const fn transport_error(error: HelperTunnelTransportFailure) -> &'static str {
    match error {
        HelperTunnelTransportFailure::Unavailable => HELPER_UNAVAILABLE,
        HelperTunnelTransportFailure::TimedOut => HELPER_TIMED_OUT,
        HelperTunnelTransportFailure::OutcomeUnknown => HELPER_OUTCOME_UNKNOWN,
    }
}

const fn receipt_failure(
    receipt: &crate::vortix_core::privileged::VerifiedReceipt,
) -> &'static str {
    match receipt.rejection_code() {
        Some(crate::vortix_core::privileged::RejectionCode::Overloaded) => HELPER_BUSY,
        Some(
            crate::vortix_core::privileged::RejectionCode::StaleAuthority
            | crate::vortix_core::privileged::RejectionCode::Replay
            | crate::vortix_core::privileged::RejectionCode::InvalidResource
            | crate::vortix_core::privileged::RejectionCode::InvalidPlan
            | crate::vortix_core::privileged::RejectionCode::ExecutionFailed,
        )
        | None => HELPER_EFFECT_FAILED,
    }
}

pub(super) struct HelperTunnelReceiptAdapter {
    authority: AuthorityBinding,
}

impl HelperTunnelReceiptAdapter {
    pub(super) const fn new(authority: AuthorityBinding) -> Self {
        Self { authority }
    }

    pub(super) fn connect_receipt(
        &self,
        work: &TunnelWork,
        started_at: SystemTime,
        start: &AuthenticatedHelperOutcome,
        observation: &AuthenticatedHelperOutcome,
        probe_receipts: &[ProbeReceipt],
        expected_routes: &WireGuardPeerRoutes,
    ) -> Result<TunnelExecutionReceipt, HelperTunnelReceiptError> {
        let tunnel = self.validate_work(work, TunnelMutation::Connect)?;
        let PrivilegedOperation::StartTunnel(plan) = start.operation() else {
            return Err(HelperTunnelReceiptError::EvidenceMismatch);
        };
        if plan.profile_id() != &work.profile_id
            || plan.generation() != work.resource_revision.generation
            || kind_for_protocol(plan.protocol()) != work.protocol
            || !self.outcome_matches_authority(start)
            || !start.receipt().owns(&tunnel)
            || !managed_observation_matches(observation.operation(), plan.protocol(), &tunnel)
            || !self.outcome_matches_authority(observation)
            || !observation
                .receipt()
                .observes(&tunnel, ObservationState::Present)
        {
            return Err(HelperTunnelReceiptError::EvidenceMismatch);
        }
        let handshake = match plan {
            ProtocolPlan::WireGuard(_) => Some(wireguard_handshake(
                work.resource_revision.generation,
                started_at,
                expected_routes,
                observation
                    .receipt()
                    .observation(&tunnel)
                    .ok_or(HelperTunnelReceiptError::EvidenceMismatch)?,
            )?),
            ProtocolPlan::OpenVpn(_) => None,
        };
        let layout = PlatformLayout::current().ok_or(HelperTunnelReceiptError::RuntimeIdentity)?;
        let runtime = HelperRuntimeIdentity::derive(layout, self.authority.lease_id(), &tunnel)
            .map_err(|_| HelperTunnelReceiptError::RuntimeIdentity)?;
        let attestation = helper_attestation(*start.receipt().digest());
        match plan {
            ProtocolPlan::WireGuard(_) => TunnelExecutionReceipt::wireguard(
                work.profile_id.clone(),
                runtime.kernel_alias(),
                attestation,
                handshake.expect("WireGuard observations always produce handshake evidence"),
            )
            .map(|receipt| receipt.with_probe_receipts(probe_receipts.to_vec()))
            .map_err(|_| HelperTunnelReceiptError::EvidenceMismatch),
            ProtocolPlan::OpenVpn(_) => {
                let routes = observation
                    .receipt()
                    .observation(&tunnel)
                    .and_then(crate::vortix_core::privileged::ResourceObservation::openvpn_routes)
                    .cloned()
                    .ok_or(HelperTunnelReceiptError::EvidenceMismatch)?;
                TunnelExecutionReceipt::attested(
                    work.profile_id.clone(),
                    runtime.kernel_alias(),
                    TunnelKindTag::OpenVpn,
                    None,
                    attestation,
                )
                .map(|receipt| receipt.with_openvpn_routes(routes))
                .map_err(|_| HelperTunnelReceiptError::EvidenceMismatch)
            }
        }
    }

    pub(super) fn disconnect_receipt(
        &self,
        work: &TunnelWork,
        stopped: &AuthenticatedHelperOutcome,
    ) -> Result<TunnelExecutionReceipt, HelperTunnelReceiptError> {
        let tunnel = self.validate_work(work, TunnelMutation::Disconnect)?;
        self.prove_absence_for(&tunnel, stopped)?;
        Ok(TunnelExecutionReceipt::default())
    }

    fn validate_work(
        &self,
        work: &TunnelWork,
        mutation: TunnelMutation,
    ) -> Result<ResourceTag, HelperTunnelReceiptError> {
        if work.mutation != mutation
            || (mutation == TunnelMutation::Connect && work.revision != work.resource_revision)
        {
            return Err(HelperTunnelReceiptError::WorkAuthorityMismatch);
        }
        self.resource_for_work(work)
    }

    fn resource_for_work(
        &self,
        work: &TunnelWork,
    ) -> Result<ResourceTag, HelperTunnelReceiptError> {
        if work.revision.authority_epoch != self.authority.authority_epoch()
            || work.resource_revision.authority_epoch != self.authority.authority_epoch()
            || work.resource_revision.generation == 0
        {
            return Err(HelperTunnelReceiptError::WorkAuthorityMismatch);
        }
        ResourceTag::tunnel(work.profile_id.clone(), work.resource_revision.generation)
            .map_err(|_| HelperTunnelReceiptError::WorkAuthorityMismatch)
    }

    fn managed_state(
        &self,
        work: &TunnelWork,
        observation: &AuthenticatedHelperOutcome,
    ) -> Result<ObservationState, HelperTunnelReceiptError> {
        let tunnel = self.resource_for_work(work)?;
        if !managed_observation_matches(
            observation.operation(),
            protocol_for_kind(work.protocol)?,
            &tunnel,
        ) || !self.outcome_matches_authority(observation)
        {
            return Err(HelperTunnelReceiptError::EvidenceMismatch);
        }
        observation
            .receipt()
            .observation(&tunnel)
            .map(crate::vortix_core::privileged::ResourceObservation::state)
            .ok_or(HelperTunnelReceiptError::EvidenceMismatch)
    }

    fn compensation_proves_absence(
        &self,
        work: &TunnelWork,
        stopped: &AuthenticatedHelperOutcome,
    ) -> Result<(), HelperTunnelReceiptError> {
        let tunnel = self.resource_for_work(work)?;
        self.prove_absence_for(&tunnel, stopped)
    }

    fn prove_absence_for(
        &self,
        tunnel: &ResourceTag,
        stopped: &AuthenticatedHelperOutcome,
    ) -> Result<(), HelperTunnelReceiptError> {
        if !matches!(stopped.operation(), PrivilegedOperation::StopTunnel(actual) if actual == tunnel)
            || !self.outcome_matches_authority(stopped)
            || !stopped.receipt().observes(tunnel, ObservationState::Absent)
        {
            return Err(HelperTunnelReceiptError::EvidenceMismatch);
        }
        Ok(())
    }

    fn outcome_matches_authority(&self, outcome: &AuthenticatedHelperOutcome) -> bool {
        outcome.receipt().operation_id().authority_epoch() == self.authority.authority_epoch()
            && outcome.receipt().operation_id().lease_id() == self.authority.lease_id()
    }

    fn kernel_alias_for(&self, tunnel: &ResourceTag) -> Result<String, HelperTunnelReceiptError> {
        let layout = PlatformLayout::current().ok_or(HelperTunnelReceiptError::RuntimeIdentity)?;
        HelperRuntimeIdentity::derive(layout, self.authority.lease_id(), tunnel)
            .map(|runtime| runtime.kernel_alias().to_owned())
            .map_err(|_| HelperTunnelReceiptError::RuntimeIdentity)
    }
}

fn managed_observation_matches(
    operation: &PrivilegedOperation,
    protocol: ProtocolKind,
    tunnel: &ResourceTag,
) -> bool {
    let PrivilegedOperation::ObserveManaged(targets) = operation else {
        return false;
    };
    let tunnel_target = ResourceObservationTarget::new(tunnel.clone(), Some(protocol))
        .expect("validated tunnel and protocol form an observation target");
    match protocol {
        ProtocolKind::WireGuard => targets.as_slice() == [tunnel_target],
        ProtocolKind::OpenVpn => {
            let Ok(group) = process_group_for_tunnel(tunnel) else {
                return false;
            };
            let group_target = ResourceObservationTarget::new(group, Some(protocol))
                .expect("OpenVPN process groups use the OpenVPN observation protocol");
            targets.len() == 2
                && targets.contains(&tunnel_target)
                && targets.contains(&group_target)
        }
    }
}

fn wireguard_handshake(
    generation: u64,
    started_at: SystemTime,
    expected_routes: &WireGuardPeerRoutes,
    observation: &crate::vortix_core::privileged::ResourceObservation,
) -> Result<HandshakeEvidence, HelperTunnelReceiptError> {
    let observed_at = millis_to_system_time(observation.observed_at_millis())?;
    let peers = observation
        .wireguard_peers()
        .ok_or(HelperTunnelReceiptError::EvidenceMismatch)?;
    for peer in peers {
        let Some(routes) = expected_routes.get(&peer.public_key()) else {
            continue;
        };
        if peer.allowed_routes().len() != routes.len()
            || peer
                .allowed_routes()
                .iter()
                .any(|route| !routes.contains(route))
        {
            continue;
        }
        let Some(handshake_at) = peer
            .latest_handshake_at_millis()
            .map(millis_to_system_time)
            .transpose()?
        else {
            continue;
        };
        if handshake_at > observed_at
            || handshake_at
                .checked_add(Duration::from_secs(1))
                .is_none_or(|rounded| rounded <= started_at)
        {
            continue;
        }
        return Ok(HandshakeEvidence {
            generation,
            peer_public_key: base64::engine::general_purpose::STANDARD.encode(peer.public_key()),
            handshake_at,
            observed_at,
            allowed_routes: peer
                .allowed_routes()
                .iter()
                .map(ToString::to_string)
                .collect(),
        });
    }
    Err(HelperTunnelReceiptError::HandshakeMissing)
}

fn millis_to_system_time(value: u64) -> Result<SystemTime, HelperTunnelReceiptError> {
    UNIX_EPOCH
        .checked_add(Duration::from_millis(value))
        .ok_or(HelperTunnelReceiptError::EvidenceMismatch)
}

fn kind_for_protocol(protocol: ProtocolKind) -> TunnelKindTag {
    match protocol {
        ProtocolKind::WireGuard => TunnelKindTag::WireGuard,
        ProtocolKind::OpenVpn => TunnelKindTag::OpenVpn,
    }
}

fn protocol_for_kind(kind: TunnelKindTag) -> Result<ProtocolKind, HelperTunnelReceiptError> {
    match kind {
        TunnelKindTag::WireGuard => Ok(ProtocolKind::WireGuard),
        TunnelKindTag::OpenVpn => Ok(ProtocolKind::OpenVpn),
        TunnelKindTag::Mock => Err(HelperTunnelReceiptError::WorkAuthorityMismatch),
    }
}

fn helper_attestation(digest: OperationDigest) -> String {
    let mut output = String::with_capacity(10 + 64);
    output.push_str("helper-v1:");
    for byte in digest.as_bytes() {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(super) enum HelperTunnelReceiptError {
    #[error("canonical work does not match the enrolled helper authority")]
    WorkAuthorityMismatch,
    #[error("authenticated helper receipt does not match the exact tunnel operation")]
    EvidenceMismatch,
    #[error("WireGuard managed observation has no fresh exact peer handshake")]
    HandshakeMissing,
    #[error("helper tunnel runtime identity could not be derived")]
    RuntimeIdentity,
}

#[cfg(test)]
#[path = "tunnel_executor_tests.rs"]
mod tests;
