use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

use base64::Engine as _;
use tempfile::TempDir;

use crate::vortix_core::control::worker::{
    TunnelExecutionReceipt, TunnelMutation, TunnelRevision, TunnelWork,
};
use crate::vortix_core::control::AuthorityEpoch;
use crate::vortix_core::ports::tunnel::TunnelKindTag;
use crate::vortix_core::privileged::{
    AmbiguousPhase, BootScope, HelperEpoch, LeaseId, ObservationState, OpenVpnAuthFactors,
    OpenVpnPlan, OpenVpnRemote, OpenVpnRemoteSelection, OpenVpnTransport, OperationDigest,
    PeerProcessIdentity, PlatformVerifiedAuthority, PrivilegedOperation, PrivilegedRequest,
    ProtocolEndpoint, ProtocolPlan, ReceiptLedger, RequestSequence, ResourceKind,
    ResourceObservation, ResourceObservationTarget, ResourceTag, RootAuthorityLedger,
    ServiceInstanceClaim, TrustedDaemonPrincipal, VerifiedReceipt, WireGuardInterfaceOptions,
    WireGuardPeerObservation, WireGuardPeerPlan, WireGuardPlan,
};
use crate::vortix_core::profile::{Profile, ProfileId, ProtocolKind};

use super::{
    HelperBackedTunnelExecutor, HelperTunnelReceiptAdapter, HelperTunnelTransport,
    HelperTunnelTransportFailure, WireGuardHandshakePolicy, WireGuardProbeIssuer,
};
use crate::daemon::helper_client::AuthenticatedHelperOutcome;

#[derive(Clone, Copy)]
enum FakeStartOutcome {
    Applied,
    Ambiguous,
    Overloaded,
    TransportLost,
    WrongAuthorityEvidence,
}

struct FakeHelper {
    state: Arc<FakeHelperState>,
}

struct FakeHelperState {
    root: RootAuthorityLedger,
    principal: TrustedDaemonPrincipal,
    binding: crate::vortix_core::privileged::AuthorityBinding,
    helper_epoch: HelperEpoch,
    next_sequence: Mutex<u64>,
    operations: Mutex<Vec<PrivilegedOperation>>,
    connections: Mutex<usize>,
    observations: Mutex<usize>,
    observation_started: Option<std::sync::mpsc::SyncSender<()>>,
    start_outcome: FakeStartOutcome,
    handshake_after_observations: usize,
    stop_fails: bool,
}

struct FakeHelperSession {
    state: Arc<FakeHelperState>,
    poisoned: bool,
}

struct FakeProbeIssuer;

impl WireGuardProbeIssuer for FakeProbeIssuer {
    fn issue(
        &self,
        _target: std::net::IpAddr,
        _owned_interface: &str,
        _timeout: Duration,
    ) -> Result<std::time::SystemTime, ()> {
        Ok(std::time::SystemTime::now())
    }
}

impl FakeHelper {
    fn new(start_outcome: FakeStartOutcome, handshake_present: bool) -> Self {
        let (root, principal, binding) = authority();
        Self {
            state: Arc::new(FakeHelperState {
                root,
                principal,
                binding,
                helper_epoch: HelperEpoch::new(3).unwrap(),
                next_sequence: Mutex::new(1),
                operations: Mutex::new(Vec::new()),
                connections: Mutex::new(0),
                observations: Mutex::new(0),
                observation_started: None,
                start_outcome,
                handshake_after_observations: if handshake_present { 0 } else { usize::MAX },
                stop_fails: false,
            }),
        }
    }

    fn with_stop_failure(mut self) -> Self {
        Arc::get_mut(&mut self.state).unwrap().stop_fails = true;
        self
    }

    fn with_handshake_after(mut self, observations: usize) -> Self {
        Arc::get_mut(&mut self.state)
            .unwrap()
            .handshake_after_observations = observations;
        self
    }

    fn with_observation_signal(
        mut self,
        observation_started: std::sync::mpsc::SyncSender<()>,
    ) -> Self {
        Arc::get_mut(&mut self.state).unwrap().observation_started = Some(observation_started);
        self
    }

    fn operations(&self) -> Vec<PrivilegedOperation> {
        self.state.operations.lock().unwrap().clone()
    }

    fn connection_count(&self) -> usize {
        *self.state.connections.lock().unwrap()
    }
}

impl HelperTunnelTransport for FakeHelper {
    fn authority_binding(&self) -> crate::vortix_core::privileged::AuthorityBinding {
        self.state.binding
    }

    fn enables(&self, _capability: crate::helper::HelperCapability) -> bool {
        true
    }

    fn connect(
        &self,
        _deadline: Instant,
    ) -> Result<Box<dyn super::HelperTunnelSession>, HelperTunnelTransportFailure> {
        *self.state.connections.lock().unwrap() += 1;
        Ok(Box::new(FakeHelperSession {
            state: Arc::clone(&self.state),
            poisoned: false,
        }))
    }
}

impl FakeHelperSession {
    fn receipt_for(
        &self,
        operation: PrivilegedOperation,
        helper_request: &PrivilegedRequest,
    ) -> VerifiedReceipt {
        let ledger = ReceiptLedger::new(&self.state.root, &self.state.principal).unwrap();
        match operation {
            PrivilegedOperation::StartTunnel(_)
                if matches!(self.state.start_outcome, FakeStartOutcome::Ambiguous) =>
            {
                ledger
                    .ambiguous(helper_request, AmbiguousPhase::EffectMayHaveApplied)
                    .unwrap()
            }
            PrivilegedOperation::StartTunnel(_)
                if matches!(self.state.start_outcome, FakeStartOutcome::Overloaded) =>
            {
                ledger
                    .rejected(
                        helper_request,
                        crate::vortix_core::privileged::RejectionCode::Overloaded,
                    )
                    .unwrap()
            }
            PrivilegedOperation::StartTunnel(plan)
                if matches!(
                    self.state.start_outcome,
                    FakeStartOutcome::WrongAuthorityEvidence
                ) =>
            {
                let (other_root, other_principal, _) = authority_with_epoch(8);
                let other_request = request(
                    &other_principal,
                    self.state.helper_epoch,
                    1,
                    PrivilegedOperation::StartTunnel(plan.clone()),
                );
                ReceiptLedger::new(&other_root, &other_principal)
                    .unwrap()
                    .applied(
                        &other_request,
                        vec![
                            ResourceTag::tunnel(plan.profile_id().clone(), plan.generation())
                                .unwrap(),
                        ],
                    )
                    .unwrap()
            }
            PrivilegedOperation::StartTunnel(plan) => ledger
                .applied(
                    helper_request,
                    vec![
                        ResourceTag::tunnel(plan.profile_id().clone(), plan.generation()).unwrap(),
                    ],
                )
                .unwrap(),
            PrivilegedOperation::ObserveManaged(targets) => ledger
                .observed(
                    helper_request,
                    vec![self.wireguard_observation(targets.first().unwrap().resource().clone())],
                )
                .unwrap(),
            PrivilegedOperation::StopTunnel(tunnel) => ledger
                .observed(
                    helper_request,
                    vec![ResourceObservation::new(tunnel, ObservationState::Absent, 1).unwrap()],
                )
                .unwrap(),
            _ => panic!("unexpected helper operation"),
        }
    }

    fn wireguard_observation(&self, target: ResourceTag) -> ResourceObservation {
        let mut observations = self.state.observations.lock().unwrap();
        let handshake_present = *observations >= self.state.handshake_after_observations;
        *observations += 1;
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        let peers = if handshake_present {
            vec![WireGuardPeerObservation::new(
                [7; 32],
                vec!["10.0.0.0/24".parse().unwrap()],
                Some(now + 1_000),
                None,
                1,
                1,
            )
            .unwrap()]
        } else {
            Vec::new()
        };
        ResourceObservation::with_wireguard_peers(
            target,
            ObservationState::Present,
            now + 2_000,
            peers,
        )
        .unwrap()
    }
}

impl super::HelperTunnelSession for FakeHelperSession {
    fn execute_bound(
        &mut self,
        operation: PrivilegedOperation,
        descriptors: &[std::os::fd::RawFd],
        _deadline: Instant,
    ) -> Result<AuthenticatedHelperOutcome, HelperTunnelTransportFailure> {
        if self.poisoned {
            return Err(HelperTunnelTransportFailure::OutcomeUnknown);
        }
        if matches!(operation, PrivilegedOperation::StartTunnel(_)) {
            assert_eq!(descriptors.len(), 1);
        } else {
            assert!(descriptors.is_empty());
        }
        self.state
            .operations
            .lock()
            .unwrap()
            .push(operation.clone());
        if matches!(operation, PrivilegedOperation::ObserveManaged(_)) {
            if let Some(sender) = &self.state.observation_started {
                let _ = sender.try_send(());
            }
        }
        if self.state.stop_fails && matches!(operation, PrivilegedOperation::StopTunnel(_)) {
            return Err(HelperTunnelTransportFailure::OutcomeUnknown);
        }
        if matches!(operation, PrivilegedOperation::StartTunnel(_))
            && matches!(self.state.start_outcome, FakeStartOutcome::TransportLost)
        {
            self.poisoned = true;
            return Err(HelperTunnelTransportFailure::OutcomeUnknown);
        }
        let mut next = self.state.next_sequence.lock().unwrap();
        let helper_request = request(
            &self.state.principal,
            self.state.helper_epoch,
            *next,
            operation.clone(),
        );
        *next += 1;
        let receipt = self.receipt_for(operation, &helper_request);
        Ok(AuthenticatedHelperOutcome::from_verified_for_test(
            helper_request,
            receipt,
        ))
    }
}

fn stored_profile() -> (TempDir, Profile) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("corp.conf");
    std::fs::write(
            &path,
            format!(
                "[Interface]\nPrivateKey = {}\nAddress = 10.8.0.2/24\n\n[Peer]\nPublicKey = {}\nEndpoint = 198.51.100.7:51820\nAllowedIPs = 10.0.0.0/24\n",
                base64::engine::general_purpose::STANDARD.encode([1; 32]),
                base64::engine::general_purpose::STANDARD.encode([7; 32]),
            ),
        )
        .unwrap();
    (
        directory,
        Profile::new(profile(), "corp", ProtocolKind::WireGuard, path)
            .require_managed_endpoint_resolution(),
    )
}

fn executor_for(helper: Arc<FakeHelper>, profile: &Profile) -> HelperBackedTunnelExecutor {
    let expected_profile = profile.clone();
    HelperBackedTunnelExecutor::with_probe_issuer(
        helper,
        Arc::new(move |profile_id| {
            (profile_id == &expected_profile.id).then(|| expected_profile.clone())
        }),
        WireGuardHandshakePolicy::new(
            Duration::from_millis(40),
            Duration::from_millis(2),
            Duration::from_millis(5),
            vec!["10.0.0.1".parse().unwrap()],
        )
        .unwrap(),
        Arc::new(FakeProbeIssuer),
    )
    .unwrap()
}

fn profile() -> ProfileId {
    ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap()
}

fn authority() -> (
    RootAuthorityLedger,
    TrustedDaemonPrincipal,
    crate::vortix_core::privileged::AuthorityBinding,
) {
    authority_with_epoch(7)
}

fn authority_with_epoch(
    epoch: u64,
) -> (
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
    let verified = PlatformVerifiedAuthority::from_platform_verifier(1000, peer, &service).unwrap();
    let root = RootAuthorityLedger::from_platform_verified(
        verified,
        BootScope::new([1; 16]),
        AuthorityEpoch(epoch),
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
                Some(ProtocolEndpoint::ip(SocketAddr::from(([198, 51, 100, 7], 51_820))).unwrap()),
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
    let ProtocolPlan::WireGuard(wireguard_plan) = &plan else {
        panic!("test plan must be WireGuard");
    };
    let expected_routes = super::wireguard_peer_routes(wireguard_plan);
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
    let observed = AuthenticatedHelperOutcome::from_verified_for_test(observe_request, observed);

    let receipt = adapter
        .connect_receipt(
            &work(TunnelMutation::Connect),
            UNIX_EPOCH + Duration::from_millis(1_700_000_000_100),
            &start,
            &observed,
            &[],
            &expected_routes,
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
                &[],
                &expected_routes,
            )
            .unwrap_err(),
        super::HelperTunnelReceiptError::HandshakeMissing
    );
}

#[test]
fn helper_handshake_probe_plan_preserves_keepalive_semantics() {
    let ProtocolPlan::WireGuard(needs_probe) = plan() else {
        panic!("test plan must be WireGuard");
    };
    let probes = super::wireguard_probe_plan(
        &needs_probe,
        &["192.0.2.1".parse().unwrap(), "10.0.0.1".parse().unwrap()],
    )
    .unwrap();
    assert_eq!(probes.len(), 1);
    assert_eq!(
        probes[0].target,
        "10.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
    assert!(super::wireguard_probe_plan(&needs_probe, &["192.0.2.1".parse().unwrap()]).is_err());

    let keepalive = WireGuardPlan::new(
        profile(),
        4,
        Vec::new(),
        vec![WireGuardPeerPlan::new(
            [7; 32],
            Some(ProtocolEndpoint::ip(SocketAddr::from(([198, 51, 100, 7], 51_820))).unwrap()),
            vec!["10.0.0.0/24".parse().unwrap()],
            Some(25),
        )
        .unwrap()],
        WireGuardInterfaceOptions::default(),
    )
    .unwrap();
    assert!(super::wireguard_probe_plan(&keepalive, &[])
        .unwrap()
        .is_empty());
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
    let observed = AuthenticatedHelperOutcome::from_verified_for_test(observe_request, observed);
    let adapter = HelperTunnelReceiptAdapter::new(binding);
    let expected_routes = std::collections::HashMap::new();

    let receipt = adapter
        .connect_receipt(
            &work_for(TunnelMutation::Connect, TunnelKindTag::OpenVpn),
            UNIX_EPOCH + Duration::from_secs(1),
            &start,
            &observed,
            &[],
            &expected_routes,
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

#[test]
fn helper_backed_wireguard_connect_requires_authenticated_handshake_truth() {
    use crate::vortix_core::control::worker::TunnelExecutor as _;

    let (_directory, profile) = stored_profile();
    let helper = Arc::new(FakeHelper::new(FakeStartOutcome::Applied, true));
    let executor = executor_for(helper.clone(), &profile);

    let receipt = executor
        .execute(
            &work(TunnelMutation::Connect),
            &crate::vortix_core::ports::tunnel::TunnelCancellation::default(),
        )
        .unwrap();

    assert_eq!(receipt.handshake.unwrap().generation, 4);
    let operations = helper.operations();
    assert!(matches!(
        operations.as_slice(),
        [
            PrivilegedOperation::StartTunnel(_),
            PrivilegedOperation::ObserveManaged(_)
        ]
    ));
}

#[test]
fn stale_work_authority_is_rejected_before_any_helper_effect() {
    use crate::vortix_core::control::worker::TunnelExecutor as _;

    let (_directory, profile) = stored_profile();
    let helper = Arc::new(FakeHelper::new(FakeStartOutcome::Applied, true));
    let executor = executor_for(helper.clone(), &profile);
    let mut stale = work(TunnelMutation::Connect);
    stale.revision.authority_epoch = AuthorityEpoch(8);
    stale.resource_revision.authority_epoch = AuthorityEpoch(8);

    let error = executor
        .execute(
            &stale,
            &crate::vortix_core::ports::tunnel::TunnelCancellation::default(),
        )
        .unwrap_err();

    assert_eq!(
        executor.classify_failure(&error),
        crate::vortix_core::control::worker::WorkFailure::EffectFailed
    );
    assert_eq!(helper.connection_count(), 0);
    assert!(helper.operations().is_empty());
}

#[test]
fn mismatched_start_authority_is_torn_down_before_failure() {
    use crate::vortix_core::control::worker::TunnelExecutor as _;

    let (_directory, profile) = stored_profile();
    let helper = Arc::new(FakeHelper::new(
        FakeStartOutcome::WrongAuthorityEvidence,
        true,
    ));
    let executor = executor_for(helper.clone(), &profile);

    let error = executor
        .execute(
            &work(TunnelMutation::Connect),
            &crate::vortix_core::ports::tunnel::TunnelCancellation::default(),
        )
        .unwrap_err();

    assert_eq!(
        executor.classify_failure(&error),
        crate::vortix_core::control::worker::WorkFailure::EffectFailed
    );
    assert!(matches!(
        helper.operations().as_slice(),
        [
            PrivilegedOperation::StartTunnel(_),
            PrivilegedOperation::StopTunnel(_)
        ]
    ));
    assert_eq!(helper.connection_count(), 2);
}

#[test]
fn transport_loss_reconnects_before_reconciliation_and_teardown() {
    use crate::vortix_core::control::worker::TunnelExecutor as _;

    let (_directory, profile) = stored_profile();
    let helper = Arc::new(FakeHelper::new(FakeStartOutcome::TransportLost, true));
    let executor = executor_for(helper.clone(), &profile);

    let error = executor
        .execute(
            &work(TunnelMutation::Connect),
            &crate::vortix_core::ports::tunnel::TunnelCancellation::default(),
        )
        .unwrap_err();

    assert_eq!(
        executor.classify_failure(&error),
        crate::vortix_core::control::worker::WorkFailure::EffectFailed
    );
    assert_started_observed_then_stopped(&helper.operations());
    assert_eq!(helper.connection_count(), 2);
}

#[test]
fn first_missing_handshake_is_polled_until_later_authenticated_success() {
    use crate::vortix_core::control::worker::TunnelExecutor as _;

    let (_directory, profile) = stored_profile();
    let helper =
        Arc::new(FakeHelper::new(FakeStartOutcome::Applied, false).with_handshake_after(1));
    let executor = executor_for(helper.clone(), &profile);

    let receipt = executor
        .execute(
            &work(TunnelMutation::Connect),
            &crate::vortix_core::ports::tunnel::TunnelCancellation::default(),
        )
        .unwrap();

    assert_eq!(receipt.handshake.unwrap().generation, 4);
    assert_eq!(receipt.probe_receipts.len(), 1);
    assert!(matches!(
        helper.operations().as_slice(),
        [
            PrivilegedOperation::StartTunnel(_),
            PrivilegedOperation::ObserveManaged(_),
            PrivilegedOperation::ObserveManaged(_)
        ]
    ));
}

#[test]
fn missing_wireguard_handshake_is_torn_down_before_known_failure() {
    use crate::vortix_core::control::worker::TunnelExecutor as _;

    let (_directory, profile) = stored_profile();
    let helper = Arc::new(FakeHelper::new(FakeStartOutcome::Applied, false));
    let executor = executor_for(helper.clone(), &profile);

    let error = executor
        .execute(
            &work(TunnelMutation::Connect),
            &crate::vortix_core::ports::tunnel::TunnelCancellation::default(),
        )
        .unwrap_err();

    assert_eq!(
        executor.classify_failure(&error),
        crate::vortix_core::control::worker::WorkFailure::HandshakeFailed
    );
    assert_started_observed_then_stopped(&helper.operations());
}

#[test]
fn cancelled_handshake_poll_is_torn_down_before_cancelled_failure() {
    use crate::vortix_core::control::worker::TunnelExecutor as _;

    let (_directory, profile) = stored_profile();
    let (observation_started, observation_receiver) = std::sync::mpsc::sync_channel(1);
    let helper = Arc::new(
        FakeHelper::new(FakeStartOutcome::Applied, false)
            .with_observation_signal(observation_started),
    );
    let executor = executor_for(helper.clone(), &profile);
    let cancellation = crate::vortix_core::ports::tunnel::TunnelCancellation::default();
    let cancel = cancellation.clone();
    let canceller = std::thread::spawn(move || {
        observation_receiver.recv().unwrap();
        cancel.cancel();
    });

    let error = executor
        .execute(&work(TunnelMutation::Connect), &cancellation)
        .unwrap_err();
    canceller.join().unwrap();

    assert_eq!(
        executor.classify_failure(&error),
        crate::vortix_core::control::worker::WorkFailure::Cancelled
    );
    assert_started_observed_then_stopped(&helper.operations());
}

#[test]
fn ambiguous_start_is_observed_and_torn_down_before_known_failure() {
    use crate::vortix_core::control::worker::TunnelExecutor as _;

    let (_directory, profile) = stored_profile();
    let helper = Arc::new(FakeHelper::new(FakeStartOutcome::Ambiguous, true));
    let executor = executor_for(helper.clone(), &profile);

    let error = executor
        .execute(
            &work(TunnelMutation::Connect),
            &crate::vortix_core::ports::tunnel::TunnelCancellation::default(),
        )
        .unwrap_err();

    assert_eq!(
        executor.classify_failure(&error),
        crate::vortix_core::control::worker::WorkFailure::EffectFailed
    );
    assert_started_observed_then_stopped(&helper.operations());
}

fn assert_started_observed_then_stopped(operations: &[PrivilegedOperation]) {
    assert!(matches!(
        operations.first(),
        Some(PrivilegedOperation::StartTunnel(_))
    ));
    assert!(matches!(
        operations.last(),
        Some(PrivilegedOperation::StopTunnel(_))
    ));
    assert!(operations[1..operations.len() - 1]
        .iter()
        .all(|operation| matches!(operation, PrivilegedOperation::ObserveManaged(_))));
    assert!(operations.len() >= 3);
}

#[test]
fn helper_overload_is_busy_without_cleanup_or_false_success() {
    use crate::vortix_core::control::worker::TunnelExecutor as _;

    let (_directory, profile) = stored_profile();
    let helper = Arc::new(FakeHelper::new(FakeStartOutcome::Overloaded, true));
    let executor = executor_for(helper.clone(), &profile);

    let error = executor
        .execute(
            &work(TunnelMutation::Connect),
            &crate::vortix_core::ports::tunnel::TunnelCancellation::default(),
        )
        .unwrap_err();

    assert_eq!(
        executor.classify_failure(&error),
        crate::vortix_core::control::worker::WorkFailure::Busy
    );
    assert!(matches!(
        helper.operations().as_slice(),
        [PrivilegedOperation::StartTunnel(_)]
    ));
}

#[test]
fn helper_backed_wireguard_disconnect_requires_authenticated_absence() {
    use crate::vortix_core::control::worker::TunnelExecutor as _;

    let (_directory, profile) = stored_profile();
    let helper = Arc::new(FakeHelper::new(FakeStartOutcome::Applied, true));
    let executor = executor_for(helper.clone(), &profile);

    let receipt = executor
        .execute(
            &work(TunnelMutation::Disconnect),
            &crate::vortix_core::ports::tunnel::TunnelCancellation::default(),
        )
        .unwrap();

    assert_eq!(receipt, TunnelExecutionReceipt::default());
    assert!(matches!(
        helper.operations().as_slice(),
        [PrivilegedOperation::StopTunnel(_)]
    ));
}

#[test]
fn failed_handshake_cleanup_is_outcome_unknown() {
    use crate::vortix_core::control::worker::TunnelExecutor as _;

    let (_directory, profile) = stored_profile();
    let helper = Arc::new(FakeHelper::new(FakeStartOutcome::Applied, false).with_stop_failure());
    let executor = executor_for(helper.clone(), &profile);

    let error = executor
        .execute(
            &work(TunnelMutation::Connect),
            &crate::vortix_core::ports::tunnel::TunnelCancellation::default(),
        )
        .unwrap_err();

    assert_eq!(
        executor.classify_failure(&error),
        crate::vortix_core::control::worker::WorkFailure::OutcomeUnknown
    );
    assert_started_observed_then_stopped(&helper.operations());
}

fn base64_key(value: [u8; 32]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(value)
}
