//! Authenticated helper receipts translated into canonical tunnel evidence.

#![allow(
    dead_code,
    reason = "the helper receipt adapter remains dormant until typed profile-plan preparation is complete"
)]

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use thiserror::Error;

use super::helper_client::AuthenticatedHelperOutcome;
use crate::helper::PlatformLayout;
use crate::helper::{process_group_for_tunnel, HelperRuntimeIdentity};
use crate::vortix_core::control::worker::{TunnelExecutionReceipt, TunnelMutation, TunnelWork};
use crate::vortix_core::ports::tunnel::{HandshakeEvidence, TunnelKindTag};
use crate::vortix_core::privileged::{
    AuthorityBinding, ObservationState, OperationDigest, PrivilegedOperation, ProtocolPlan,
    ResourceObservationTarget, ResourceTag, WireGuardPlan,
};
use crate::vortix_core::profile::ProtocolKind;

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
        let layout = PlatformLayout::current().ok_or(HelperTunnelReceiptError::RuntimeIdentity)?;
        let runtime = HelperRuntimeIdentity::derive(layout, self.authority.lease_id(), &tunnel)
            .map_err(|_| HelperTunnelReceiptError::RuntimeIdentity)?;
        let attestation = helper_attestation(*start.receipt().digest());
        match plan {
            ProtocolPlan::WireGuard(plan) => {
                let handshake = wireguard_handshake(
                    work.resource_revision.generation,
                    started_at,
                    plan,
                    observation
                        .receipt()
                        .observation(&tunnel)
                        .ok_or(HelperTunnelReceiptError::EvidenceMismatch)?,
                )?;
                TunnelExecutionReceipt::wireguard(
                    work.profile_id.clone(),
                    runtime.kernel_alias(),
                    attestation,
                    handshake,
                )
                .map_err(|_| HelperTunnelReceiptError::EvidenceMismatch)
            }
            ProtocolPlan::OpenVpn(_) => TunnelExecutionReceipt::attested(
                work.profile_id.clone(),
                runtime.kernel_alias(),
                TunnelKindTag::OpenVpn,
                None,
                attestation,
            )
            .map_err(|_| HelperTunnelReceiptError::EvidenceMismatch),
        }
    }

    pub(super) fn disconnect_receipt(
        &self,
        work: &TunnelWork,
        stopped: &AuthenticatedHelperOutcome,
    ) -> Result<TunnelExecutionReceipt, HelperTunnelReceiptError> {
        let tunnel = self.validate_work(work, TunnelMutation::Disconnect)?;
        if !matches!(stopped.operation(), PrivilegedOperation::StopTunnel(actual) if actual == &tunnel)
            || !self.outcome_matches_authority(stopped)
            || !stopped
                .receipt()
                .observes(&tunnel, ObservationState::Absent)
        {
            return Err(HelperTunnelReceiptError::EvidenceMismatch);
        }
        Ok(TunnelExecutionReceipt::default())
    }

    fn validate_work(
        &self,
        work: &TunnelWork,
        mutation: TunnelMutation,
    ) -> Result<ResourceTag, HelperTunnelReceiptError> {
        if work.mutation != mutation
            || work.revision.authority_epoch != self.authority.authority_epoch()
            || work.resource_revision.authority_epoch != self.authority.authority_epoch()
            || work.resource_revision.generation == 0
            || (mutation == TunnelMutation::Connect && work.revision != work.resource_revision)
        {
            return Err(HelperTunnelReceiptError::WorkAuthorityMismatch);
        }
        ResourceTag::tunnel(work.profile_id.clone(), work.resource_revision.generation)
            .map_err(|_| HelperTunnelReceiptError::WorkAuthorityMismatch)
    }

    fn outcome_matches_authority(&self, outcome: &AuthenticatedHelperOutcome) -> bool {
        outcome.receipt().operation_id().authority_epoch() == self.authority.authority_epoch()
            && outcome.receipt().operation_id().lease_id() == self.authority.lease_id()
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
    plan: &WireGuardPlan,
    observation: &crate::vortix_core::privileged::ResourceObservation,
) -> Result<HandshakeEvidence, HelperTunnelReceiptError> {
    let observed_at = millis_to_system_time(observation.observed_at_millis())?;
    let peers = observation
        .wireguard_peers()
        .ok_or(HelperTunnelReceiptError::EvidenceMismatch)?;
    let expected_routes = plan
        .peers()
        .iter()
        .map(|peer| {
            (
                peer.public_key(),
                peer.allowed_routes()
                    .iter()
                    .copied()
                    .collect::<HashSet<_>>(),
            )
        })
        .collect::<HashMap<_, _>>();
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
mod tests {
    use std::net::SocketAddr;
    use std::time::{Duration, Instant, UNIX_EPOCH};

    use crate::vortix_core::control::worker::{TunnelMutation, TunnelRevision, TunnelWork};
    use crate::vortix_core::control::AuthorityEpoch;
    use crate::vortix_core::ports::tunnel::TunnelKindTag;
    use crate::vortix_core::privileged::{
        BootScope, HelperEpoch, LeaseId, ObservationState, OpenVpnAuthFactors, OpenVpnPlan,
        OpenVpnRemote, OpenVpnRemoteSelection, OpenVpnTransport, OperationDigest,
        PeerProcessIdentity, PlatformVerifiedAuthority, PrivilegedOperation, PrivilegedRequest,
        ProtocolEndpoint, ProtocolPlan, ReceiptLedger, RequestSequence, ResourceKind,
        ResourceObservation, ResourceObservationTarget, ResourceTag, RootAuthorityLedger,
        ServiceInstanceClaim, TrustedDaemonPrincipal, WireGuardInterfaceOptions,
        WireGuardPeerObservation, WireGuardPeerPlan, WireGuardPlan,
    };
    use crate::vortix_core::profile::{ProfileId, ProtocolKind};

    use super::HelperTunnelReceiptAdapter;
    use crate::daemon::helper_client::AuthenticatedHelperOutcome;

    fn profile() -> ProfileId {
        ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap()
    }

    fn authority() -> (
        RootAuthorityLedger,
        TrustedDaemonPrincipal,
        crate::vortix_core::privileged::AuthorityBinding,
    ) {
        let service = ServiceInstanceClaim::systemd(
            42,
            99,
            OperationDigest::of_bytes(b"verified executable"),
            [3; 32],
        )
        .unwrap();
        let peer = PeerProcessIdentity::untrusted_claim(1000, 42, 99).unwrap();
        let verified =
            PlatformVerifiedAuthority::from_platform_verifier(1000, peer, &service).unwrap();
        let root = RootAuthorityLedger::from_platform_verified(
            verified,
            BootScope::new([1; 16]),
            AuthorityEpoch(7),
            LeaseId::new([2; 32]),
        )
        .unwrap();
        let principal = root.principal();
        let binding = root.authority_binding();
        (root, principal, binding)
    }

    fn work(mutation: TunnelMutation) -> TunnelWork {
        work_for(mutation, TunnelKindTag::WireGuard)
    }

    fn work_for(mutation: TunnelMutation, protocol: TunnelKindTag) -> TunnelWork {
        TunnelWork {
            profile_id: profile(),
            operation_id: serde_json::from_str("\"op-0000000000000007-0000000000000001\"").unwrap(),
            revision: TunnelRevision {
                authority_epoch: AuthorityEpoch(7),
                generation: 4,
            },
            resource_revision: TunnelRevision {
                authority_epoch: AuthorityEpoch(7),
                generation: 4,
            },
            mutation,
            protocol,
            deadline: Instant::now() + Duration::from_secs(5),
        }
    }

    fn plan() -> ProtocolPlan {
        ProtocolPlan::WireGuard(
            WireGuardPlan::new(
                profile(),
                4,
                Vec::new(),
                vec![WireGuardPeerPlan::new(
                    [7; 32],
                    Some(
                        ProtocolEndpoint::ip(SocketAddr::from(([198, 51, 100, 7], 51_820)))
                            .unwrap(),
                    ),
                    vec!["10.0.0.0/24".parse().unwrap()],
                    None,
                )
                .unwrap()],
                WireGuardInterfaceOptions::default(),
            )
            .unwrap(),
        )
    }

    fn request(
        principal: &TrustedDaemonPrincipal,
        helper: HelperEpoch,
        sequence: u64,
        operation: PrivilegedOperation,
    ) -> PrivilegedRequest {
        PrivilegedRequest::new(
            principal,
            helper,
            RequestSequence::new(sequence).unwrap(),
            operation,
        )
        .unwrap()
    }

    #[test]
    fn wireguard_connect_accepts_only_fresh_exact_authenticated_peer_evidence() {
        let (root, principal, binding) = authority();
        let helper = HelperEpoch::new(3).unwrap();
        let plan = plan();
        let tunnel = ResourceTag::tunnel(profile(), 4).unwrap();
        let start_operation = PrivilegedOperation::StartTunnel(plan);
        let start_request = request(&principal, helper, 1, start_operation);
        let start = ReceiptLedger::new(&root, &principal)
            .unwrap()
            .applied(&start_request, vec![tunnel.clone()])
            .unwrap();
        let observe_operation =
            PrivilegedOperation::ObserveManaged(vec![ResourceObservationTarget::new(
                tunnel.clone(),
                Some(ProtocolKind::WireGuard),
            )
            .unwrap()]);
        let observe_request = request(&principal, helper, 2, observe_operation);
        let observed_at = 1_700_000_000_500;
        let observation = ResourceObservation::with_wireguard_peers(
            tunnel,
            ObservationState::Present,
            observed_at,
            vec![WireGuardPeerObservation::new(
                [7; 32],
                vec!["10.0.0.0/24".parse().unwrap()],
                Some(1_700_000_000_000),
                None,
                42,
                84,
            )
            .unwrap()],
        )
        .unwrap();
        let observed = ReceiptLedger::new(&root, &principal)
            .unwrap()
            .observed(&observe_request, vec![observation])
            .unwrap();
        let adapter = HelperTunnelReceiptAdapter::new(binding);
        let start = AuthenticatedHelperOutcome::from_verified_for_test(start_request, start);
        let observed =
            AuthenticatedHelperOutcome::from_verified_for_test(observe_request, observed);

        let receipt = adapter
            .connect_receipt(
                &work(TunnelMutation::Connect),
                UNIX_EPOCH + Duration::from_millis(1_700_000_000_100),
                &start,
                &observed,
            )
            .unwrap();

        let adoption = receipt.adoption.unwrap();
        assert_eq!(adoption.profile_id(), &profile());
        assert_eq!(adoption.kind(), TunnelKindTag::WireGuard);
        assert_eq!(adoption.pid(), None);
        let handshake = receipt.handshake.unwrap();
        assert_eq!(handshake.generation, 4);
        assert_eq!(handshake.peer_public_key, base64_key([7; 32]));
        assert_eq!(handshake.allowed_routes, ["10.0.0.0/24"]);
        assert!(receipt.probe_receipts.is_empty());
        assert_eq!(
            adapter
                .connect_receipt(
                    &work(TunnelMutation::Connect),
                    UNIX_EPOCH + Duration::from_millis(1_700_000_001_000),
                    &start,
                    &observed,
                )
                .unwrap_err(),
            super::HelperTunnelReceiptError::HandshakeMissing
        );
    }

    #[test]
    fn openvpn_connect_keeps_process_identity_inside_the_helper_boundary() {
        let (root, principal, binding) = authority();
        let helper = HelperEpoch::new(3).unwrap();
        let plan = ProtocolPlan::OpenVpn(
            OpenVpnPlan::new(
                profile(),
                4,
                vec![OpenVpnRemote::new(
                    SocketAddr::from(([203, 0, 113, 9], 1194)),
                    OpenVpnTransport::Udp,
                )
                .unwrap()],
                OpenVpnRemoteSelection::Ordered,
                OpenVpnAuthFactors::certificate(),
                Vec::new(),
            )
            .unwrap(),
        );
        let tunnel = ResourceTag::tunnel(profile(), 4).unwrap();
        let group = ResourceTag::profile(profile(), 4, ResourceKind::ProcessGroup).unwrap();
        let start_operation = PrivilegedOperation::StartTunnel(plan);
        let start_request = request(&principal, helper, 1, start_operation);
        let start = ReceiptLedger::new(&root, &principal)
            .unwrap()
            .applied(&start_request, vec![tunnel.clone(), group.clone()])
            .unwrap();
        let observe_operation = PrivilegedOperation::ObserveManaged(vec![
            ResourceObservationTarget::new(tunnel.clone(), Some(ProtocolKind::OpenVpn)).unwrap(),
            ResourceObservationTarget::new(group.clone(), Some(ProtocolKind::OpenVpn)).unwrap(),
        ]);
        let observe_request = request(&principal, helper, 2, observe_operation);
        let observed = ReceiptLedger::new(&root, &principal)
            .unwrap()
            .observed(
                &observe_request,
                vec![
                    ResourceObservation::new(tunnel, ObservationState::Present, 10).unwrap(),
                    ResourceObservation::new(group, ObservationState::Present, 10).unwrap(),
                ],
            )
            .unwrap();
        let start = AuthenticatedHelperOutcome::from_verified_for_test(start_request, start);
        let observed =
            AuthenticatedHelperOutcome::from_verified_for_test(observe_request, observed);
        let adapter = HelperTunnelReceiptAdapter::new(binding);

        let receipt = adapter
            .connect_receipt(
                &work_for(TunnelMutation::Connect, TunnelKindTag::OpenVpn),
                UNIX_EPOCH + Duration::from_secs(1),
                &start,
                &observed,
            )
            .unwrap();

        let adoption = receipt.adoption.unwrap();
        assert_eq!(adoption.kind(), TunnelKindTag::OpenVpn);
        assert!(adoption.interface_name().starts_with("vx"));
        assert_eq!(adoption.pid(), None);
        assert!(receipt.handshake.is_none());
    }

    #[test]
    fn helper_disconnect_requires_exact_authenticated_absence() {
        let (root, principal, binding) = authority();
        let helper = HelperEpoch::new(3).unwrap();
        let tunnel = ResourceTag::tunnel(profile(), 4).unwrap();
        let stop_operation = PrivilegedOperation::StopTunnel(tunnel.clone());
        let stop_request = request(&principal, helper, 1, stop_operation);
        let stopped = ReceiptLedger::new(&root, &principal)
            .unwrap()
            .observed(
                &stop_request,
                vec![ResourceObservation::new(tunnel, ObservationState::Absent, 1).unwrap()],
            )
            .unwrap();
        let adapter = HelperTunnelReceiptAdapter::new(binding);
        let stopped = AuthenticatedHelperOutcome::from_verified_for_test(stop_request, stopped);

        let receipt = adapter
            .disconnect_receipt(&work(TunnelMutation::Disconnect), &stopped)
            .unwrap();

        assert_eq!(
            receipt,
            crate::vortix_core::control::worker::TunnelExecutionReceipt::default()
        );
    }

    fn base64_key(value: [u8; 32]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(value)
    }
}
