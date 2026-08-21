use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;
use crate::helper::HelperPolicyResource;
use crate::vortix_core::control::worker::{PolicyStage, RouteClaim, TopologyTransitionKind};
use crate::vortix_core::control::{AuthorityEpoch, PolicyDigest};
use crate::vortix_core::privileged::{
    BootScope, HelperEpoch, LeaseId, NetworkPolicyOperation, OpenVpnDefaultGateway,
    OpenVpnDefaultGateways, OpenVpnRedirectFlag, OpenVpnRedirectGateway, OpenVpnRoute,
    OpenVpnRouteDefaults, OpenVpnRouteEvidence, OpenVpnRouteGateway, OpenVpnRouteSetEvidence,
    OperationDigest, PeerProcessIdentity, PlatformVerifiedAuthority, PrivilegedRequest,
    ReceiptLedger, RequestSequence, ResourceKind, ResourceObservation, RootAuthorityLedger,
    ScopedRouteGateway, ScopedRouteOrigin, ServiceInstanceClaim, TrustedDaemonPrincipal,
    VerifiedReceipt,
};

struct FakeHelper {
    state: Arc<FakeHelperState>,
}

struct FakeHelperState {
    root: RootAuthorityLedger,
    principal: TrustedDaemonPrincipal,
    helper_epoch: HelperEpoch,
    sequence: Mutex<u64>,
    ledger: Mutex<FakePolicyLedger>,
    operations: Mutex<Vec<PrivilegedOperation>>,
    lose_after_first_mutation: Mutex<bool>,
    lose_after_release: Mutex<bool>,
    lose_before_release_effect: Mutex<bool>,
    tunnel_observation_state: Mutex<ObservationState>,
    audit_observation_state: Mutex<Option<ObservationState>>,
}

#[derive(Default)]
struct FakePolicyLedger {
    current: Option<ResourceTag>,
    predecessor: Option<PolicyPredecessor>,
    projections: BTreeMap<ResourceTag, PolicyProjection>,
    resources: BTreeMap<
        ResourceTag,
        (
            HelperResourceState,
            crate::vortix_core::privileged::PolicyDigest,
            Option<crate::vortix_core::privileged::PolicyDigest>,
        ),
    >,
}

struct FakeHelperSession {
    state: Arc<FakeHelperState>,
}

impl FakeHelper {
    fn new() -> Self {
        let (root, principal) = authority();
        Self {
            state: Arc::new(FakeHelperState {
                root,
                principal,
                helper_epoch: HelperEpoch::new(3).unwrap(),
                sequence: Mutex::new(1),
                ledger: Mutex::new(FakePolicyLedger::default()),
                operations: Mutex::new(Vec::new()),
                lose_after_first_mutation: Mutex::new(false),
                lose_after_release: Mutex::new(false),
                lose_before_release_effect: Mutex::new(false),
                tunnel_observation_state: Mutex::new(ObservationState::Present),
                audit_observation_state: Mutex::new(None),
            }),
        }
    }

    fn operations(&self) -> Vec<PrivilegedOperation> {
        self.state.operations.lock().unwrap().clone()
    }

    fn lose_after_first_mutation(&self) {
        *self.state.lose_after_first_mutation.lock().unwrap() = true;
    }

    fn lose_after_release(&self) {
        *self.state.lose_after_release.lock().unwrap() = true;
    }

    fn lose_before_release_effect(&self) {
        *self.state.lose_before_release_effect.lock().unwrap() = true;
    }

    fn observe_tunnels_as(&self, state: ObservationState) {
        *self.state.tunnel_observation_state.lock().unwrap() = state;
    }

    fn observe_policy_audits_as(&self, state: ObservationState) {
        *self.state.audit_observation_state.lock().unwrap() = Some(state);
    }
}

impl FakePolicyLedger {
    fn inventory(&self) -> HelperPolicyInventory {
        let resources = self
            .resources
            .iter()
            .map(|(resource, (state, intended, effective))| {
                HelperPolicyResource::new(resource.clone(), *state, *intended, *effective).unwrap()
            })
            .collect();
        HelperPolicyInventory::new(self.current.clone(), self.predecessor, resources).unwrap()
    }

    fn projection_before_current(&self) -> Option<&PolicyProjection> {
        self.current
            .as_ref()
            .and_then(|resource| self.projections.get(resource))
    }

    fn apply_mutation(
        &mut self,
        operation: &NetworkPolicyOperation,
    ) -> (ResourceTag, PolicyProjection) {
        let projection =
            PolicyProjection::from_mutation(operation, self.projection_before_current())
                .unwrap()
                .unwrap();
        let resource = operation.policy_resource().clone();
        let digest = projection.digest();
        let prior_effective = self
            .resources
            .get(&resource)
            .and_then(|(_, _, effective)| *effective);
        self.projections
            .insert(resource.clone(), projection.clone());
        self.resources.insert(
            resource.clone(),
            (HelperResourceState::PendingEffect, digest, prior_effective),
        );
        self.current = Some(resource.clone());
        self.predecessor = Some(
            PolicyPredecessor::pending(
                crate::vortix_core::privileged::PolicyDigest::of(operation),
                projection.phase(),
            )
            .unwrap(),
        );
        (resource, projection)
    }

    fn observe(&mut self, policy: &ResourceTag) -> (ObservationState, PolicyProjection) {
        assert_eq!(self.current.as_ref(), Some(policy));
        let projection = self.projections.get(policy).unwrap().clone();
        let digest = projection.digest();
        self.resources.insert(
            policy.clone(),
            (HelperResourceState::Owned, digest, Some(digest)),
        );
        let operation_digest = self.predecessor.unwrap().digest();
        self.predecessor =
            Some(PolicyPredecessor::settled(operation_digest, projection.phase()).unwrap());
        (projection.expected_observation_state(), projection)
    }

    fn mark_release_pending(&mut self, operation: &NetworkPolicyOperation) {
        let NetworkPolicyOperation::ReleaseObsolete {
            policy, resources, ..
        } = operation
        else {
            unreachable!();
        };
        assert_eq!(self.current.as_ref(), Some(policy));
        for resource in resources {
            self.resources.get_mut(resource).unwrap().0 = HelperResourceState::PendingRelease;
        }
        self.predecessor = Some(
            PolicyPredecessor::pending(
                crate::vortix_core::privileged::PolicyDigest::of(operation),
                PolicyPhase::Released,
            )
            .unwrap(),
        );
    }
}

impl HelperPolicyTransport for FakeHelper {
    fn enables(&self, _capability: HelperCapability) -> bool {
        true
    }

    fn connect(
        &self,
        _deadline: Instant,
    ) -> Result<Box<dyn HelperPolicySession>, HelperPolicyTransportFailure> {
        Ok(Box::new(FakeHelperSession {
            state: Arc::clone(&self.state),
        }))
    }
}

impl HelperPolicySession for FakeHelperSession {
    fn inventory(&self) -> Option<HelperPolicyInventory> {
        Some(self.state.ledger.lock().unwrap().inventory())
    }

    fn execute_bound(
        &mut self,
        operation: PrivilegedOperation,
        descriptors: &[std::os::fd::RawFd],
        _deadline: Instant,
    ) -> Result<AuthenticatedHelperOutcome, HelperPolicyTransportFailure> {
        assert!(descriptors.is_empty());
        self.state
            .operations
            .lock()
            .unwrap()
            .push(operation.clone());
        let mut sequence = self.state.sequence.lock().unwrap();
        let request = PrivilegedRequest::new(
            &self.state.principal,
            self.state.helper_epoch,
            RequestSequence::new(*sequence).unwrap(),
            operation.clone(),
        )
        .unwrap();
        *sequence += 1;
        let is_release = matches!(
            operation,
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ReleaseObsolete { .. })
        );
        let mut lose_before_release = self.state.lose_before_release_effect.lock().unwrap();
        if is_release && *lose_before_release {
            *lose_before_release = false;
            let PrivilegedOperation::NetworkPolicy(release) = &operation else {
                unreachable!();
            };
            self.state
                .ledger
                .lock()
                .unwrap()
                .mark_release_pending(release);
            return Err(HelperPolicyTransportFailure::OutcomeUnknown);
        }
        drop(lose_before_release);
        let receipt = self.receipt_for(&operation, &request);
        let is_mutation = matches!(
            operation,
            PrivilegedOperation::NetworkPolicy(
                NetworkPolicyOperation::EstablishFirewall { .. }
                    | NetworkPolicyOperation::EstablishBlocking { .. }
                    | NetworkPolicyOperation::ApplyRoutes { .. }
                    | NetworkPolicyOperation::ApplyDns { .. }
                    | NetworkPolicyOperation::ApplyFirewall { .. }
            )
        );
        let mut lose = self.state.lose_after_first_mutation.lock().unwrap();
        if is_mutation && *lose {
            *lose = false;
            return Err(HelperPolicyTransportFailure::OutcomeUnknown);
        }
        let mut lose_release = self.state.lose_after_release.lock().unwrap();
        if is_release && *lose_release {
            *lose_release = false;
            return Err(HelperPolicyTransportFailure::OutcomeUnknown);
        }
        Ok(AuthenticatedHelperOutcome::from_verified_for_test(
            request, receipt,
        ))
    }
}

impl FakeHelperSession {
    fn receipt_for(
        &self,
        operation: &PrivilegedOperation,
        request: &PrivilegedRequest,
    ) -> VerifiedReceipt {
        let receipts = ReceiptLedger::new(&self.state.root, &self.state.principal).unwrap();
        if let PrivilegedOperation::ObserveManaged(targets)
        | PrivilegedOperation::ObserveManagedAbsence(targets) = operation
        {
            let state = if matches!(operation, PrivilegedOperation::ObserveManagedAbsence(_)) {
                ObservationState::Absent
            } else {
                *self.state.tunnel_observation_state.lock().unwrap()
            };
            let observations = managed_observations(targets, state);
            return receipts.observed(request, observations).unwrap();
        }
        if let PrivilegedOperation::AuditPolicy(policy) = operation {
            let state = self.audit_observation_state(policy);
            return receipts
                .observed(
                    request,
                    vec![ResourceObservation::new(policy.clone(), state, 1).unwrap()],
                )
                .unwrap();
        }
        let PrivilegedOperation::NetworkPolicy(operation) = operation else {
            panic!("policy fake accepts only managed observations and network-policy operations")
        };
        match operation {
            NetworkPolicyOperation::EstablishFirewall { .. }
            | NetworkPolicyOperation::EstablishBlocking { .. }
            | NetworkPolicyOperation::ApplyRoutes { .. }
            | NetworkPolicyOperation::ApplyDns { .. }
            | NetworkPolicyOperation::ApplyFirewall { .. } => {
                let (resource, _) = self.state.ledger.lock().unwrap().apply_mutation(operation);
                receipts.applied(request, vec![resource]).unwrap()
            }
            NetworkPolicyOperation::ObserveBarrier {
                policy,
                predecessor,
            } => {
                let current = self.state.ledger.lock().unwrap().predecessor;
                assert_eq!(current, Some(*predecessor));
                assert!(!predecessor.observed());
                let (state, _) = self.state.ledger.lock().unwrap().observe(policy);
                receipts
                    .observed(
                        request,
                        vec![ResourceObservation::new(policy.clone(), state, 1).unwrap()],
                    )
                    .unwrap()
            }
            NetworkPolicyOperation::ReleaseObsolete {
                policy,
                resources,
                retained_state,
                ..
            } => {
                let mut ledger = self.state.ledger.lock().unwrap();
                assert_eq!(
                    ledger
                        .projections
                        .get(policy)
                        .unwrap()
                        .expected_observation_state(),
                    *retained_state
                );
                for resource in resources {
                    ledger.resources.remove(resource);
                    ledger.projections.remove(resource);
                }
                let retained_digest = ledger.projections.get(policy).unwrap().digest();
                ledger.predecessor = Some(
                    PolicyPredecessor::settled(retained_digest, PolicyPhase::Released).unwrap(),
                );
                let mut observations =
                    vec![ResourceObservation::new(policy.clone(), *retained_state, 1).unwrap()];
                observations.extend(resources.iter().cloned().map(|resource| {
                    ResourceObservation::new(resource, ObservationState::Absent, 1).unwrap()
                }));
                receipts.observed(request, observations).unwrap()
            }
        }
    }

    fn audit_observation_state(&self, policy: &ResourceTag) -> ObservationState {
        self.state
            .audit_observation_state
            .lock()
            .unwrap()
            .unwrap_or_else(|| {
                self.state
                    .ledger
                    .lock()
                    .unwrap()
                    .projections
                    .get(policy)
                    .unwrap()
                    .expected_observation_state()
            })
    }
}

fn managed_observations(
    targets: &[ResourceObservationTarget],
    state: ObservationState,
) -> Vec<ResourceObservation> {
    targets
        .iter()
        .map(|target| {
            if state == ObservationState::Present
                && target.protocol() == Some(ProtocolKind::WireGuard)
            {
                ResourceObservation::with_wireguard_peers(
                    target.resource().clone(),
                    state,
                    1,
                    Vec::new(),
                )
                .unwrap()
            } else if state == ObservationState::Present
                && target.protocol() == Some(ProtocolKind::OpenVpn)
                && target.resource().kind() == ResourceKind::Tunnel
            {
                ResourceObservation::with_openvpn_routes(
                    target.resource().clone(),
                    state,
                    1,
                    OpenVpnRouteEvidence::new(
                        OpenVpnRouteSetEvidence::new(Vec::new(), None).unwrap(),
                        OpenVpnRouteSetEvidence::new(Vec::new(), None).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap()
            } else {
                ResourceObservation::new(target.resource().clone(), state, 1).unwrap()
            }
        })
        .collect()
}

fn authority() -> (RootAuthorityLedger, TrustedDaemonPrincipal) {
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
        AuthorityEpoch(3),
        LeaseId::new([2; 32]),
    )
    .unwrap();
    let principal = root.principal();
    (root, principal)
}

fn profile() -> ProfileId {
    ProfileId::new("corp")
}

fn state(profile: &ProfileId, mode: KillSwitchMode) -> TopologyState {
    TopologyState {
        profiles: BTreeSet::from([profile.clone()]),
        protocols: BTreeMap::from([(profile.clone(), ProtocolKind::WireGuard)]),
        interfaces: BTreeMap::from([(profile.clone(), "wg-vortix".into())]),
        routes: BTreeMap::from([(
            profile.clone(),
            BTreeSet::from([RouteClaim::parse("0.0.0.0/0").unwrap()]),
        )]),
        server_ips: BTreeMap::from([(
            profile.clone(),
            BTreeSet::from([IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))]),
        )]),
        dns_requests: BTreeMap::from([(
            profile.clone(),
            DnsRequest {
                servers: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))],
                search_domains: vec!["corp.example".into()],
            },
        )]),
        kill_switch: mode,
        ..TopologyState::default()
    }
}

fn policy(required_blocking: bool) -> TopologyPolicy {
    let profile = profile();
    let prior = if required_blocking {
        state(&profile, KillSwitchMode::Auto)
    } else {
        TopologyState::default()
    };
    let prior_tunnel_revisions = if required_blocking {
        BTreeMap::from([(
            profile.clone(),
            TunnelRevision {
                authority_epoch: AuthorityEpoch(3),
                generation: 3,
            },
        )])
    } else {
        BTreeMap::new()
    };
    TopologyPolicy {
        generation: 7,
        authority_epoch: AuthorityEpoch(3),
        digest: PolicyDigest("canonical-policy".into()),
        operation_id: serde_json::from_str("\"op-0000000000000001-0000000000000001\"").unwrap(),
        deadline: Instant::now() + Duration::from_secs(1),
        prior,
        target: state(&profile, KillSwitchMode::Auto),
        prior_tunnel_revisions,
        tunnel_revisions: BTreeMap::from([(
            profile,
            TunnelRevision {
                authority_epoch: AuthorityEpoch(3),
                generation: 4,
            },
        )]),
        transition: TopologyTransitionKind::Connect,
        required_blocking,
        stage: if required_blocking {
            PolicyStage::PreTunnelBlocking
        } else {
            PolicyStage::Final
        },
    }
}

#[test]
fn ordinary_and_safety_stages_begin_with_distinct_firewall_operations() {
    let ordinary = HelperPolicyPlan::forward(&policy(false)).unwrap();
    let safety = HelperPolicyPlan::forward(&policy(true)).unwrap();

    assert_eq!(ordinary.generation, 13);
    assert_eq!(safety.generation, 13);
    assert!(matches!(
        ordinary.initial_operation(),
        NetworkPolicyOperation::EstablishFirewall {
            mode: KillSwitchMode::Auto,
            ..
        }
    ));
    let NetworkPolicyOperation::EstablishBlocking { tunnels, .. } = safety.initial_operation()
    else {
        panic!("safety stage must establish blocking")
    };
    assert_eq!(
        tunnels
            .iter()
            .map(|tunnel| (tunnel.tunnel().generation(), tunnel.role()))
            .collect::<Vec<_>>(),
        vec![
            (3, PrivilegedFirewallRole::Primary),
            (4, PrivilegedFirewallRole::PendingEndpoint),
        ]
    );
}

#[test]
fn planner_rejects_target_without_exact_owned_tunnel_revision() {
    let mut policy = policy(false);
    policy.tunnel_revisions.clear();

    assert_eq!(
        HelperPolicyPlan::forward(&policy),
        Err(HelperPolicyPlanError::TunnelOwnership)
    );
}

#[test]
fn planner_rejects_openvpn_routes_until_the_helper_owns_the_route_mutation() {
    let mut policy = policy(false);
    policy
        .target
        .protocols
        .insert(profile(), ProtocolKind::OpenVpn);

    assert_eq!(
        HelperPolicyPlan::forward(&policy),
        Err(HelperPolicyPlanError::RouteMutationUnavailable)
    );
}

#[test]
fn planner_preserves_openvpn_route_gateway_metric_redirect_and_origin() {
    let mut policy = policy(false);
    let profile = profile();
    policy
        .target
        .protocols
        .insert(profile.clone(), ProtocolKind::OpenVpn);
    policy.target.openvpn_routes.insert(
        profile,
        OpenVpnRouteEvidence::new(
            OpenVpnRouteSetEvidence::with_route_defaults(
                vec![OpenVpnRoute::with_gateway(
                    "10.20.0.0/16".parse().unwrap(),
                    OpenVpnRouteGateway::NetGateway,
                    Some(7),
                )
                .unwrap()],
                Some(OpenVpnRedirectGateway::new(vec![OpenVpnRedirectFlag::Def1]).unwrap()),
                OpenVpnRouteDefaults::new(
                    OpenVpnDefaultGateways::new(
                        Some(OpenVpnDefaultGateway::Address("10.8.0.1".parse().unwrap())),
                        None,
                    )
                    .unwrap(),
                    Some(5),
                ),
            )
            .unwrap(),
            OpenVpnRouteSetEvidence::with_route_defaults(
                vec![OpenVpnRoute::with_gateway(
                    "10.30.0.0/16".parse().unwrap(),
                    OpenVpnRouteGateway::VpnDefault,
                    Some(9),
                )
                .unwrap()],
                None,
                OpenVpnRouteDefaults::new(
                    OpenVpnDefaultGateways::new(
                        Some(OpenVpnDefaultGateway::Address("10.9.0.1".parse().unwrap())),
                        None,
                    )
                    .unwrap(),
                    Some(6),
                ),
            )
            .unwrap(),
        )
        .unwrap(),
    );

    let plan = HelperPolicyPlan::forward(&policy).unwrap();
    let initial = PolicyProjection::from_mutation(&plan.initial_operation(), None)
        .unwrap()
        .unwrap();
    let predecessor = PolicyPredecessor::settled(initial.digest(), plan.initial_phase()).unwrap();
    let NetworkPolicyOperation::ApplyRoutes {
        routes, redirects, ..
    } = plan.routes_operation(predecessor)
    else {
        panic!("route phase must remain typed")
    };
    assert_eq!(routes.len(), 2);
    assert_eq!(
        routes[0].gateway(),
        ScopedRouteGateway::OpenVpn(OpenVpnRouteGateway::NetGateway)
    );
    assert_eq!(routes[0].metric(), Some(7));
    assert_eq!(routes[0].origin(), ScopedRouteOrigin::OpenVpnConfigured);
    assert_eq!(routes[1].origin(), ScopedRouteOrigin::OpenVpnPushed);
    let effective_defaults = OpenVpnRouteDefaults::new(
        OpenVpnDefaultGateways::new(
            Some(OpenVpnDefaultGateway::Address("10.9.0.1".parse().unwrap())),
            None,
        )
        .unwrap(),
        Some(6),
    );
    assert_eq!(routes[0].route_defaults(), effective_defaults);
    assert_eq!(routes[1].route_defaults(), effective_defaults);
    assert_eq!(redirects.len(), 1);
    assert_eq!(redirects[0].origin(), ScopedRouteOrigin::OpenVpnConfigured);
    assert_eq!(redirects[0].route_defaults(), effective_defaults);
}

#[test]
fn planner_binds_remote_host_to_the_authenticated_selected_endpoint() {
    let mut policy = policy(false);
    let profile = profile();
    policy
        .target
        .protocols
        .insert(profile.clone(), ProtocolKind::OpenVpn);
    let selected_remote = "203.0.113.9".parse().unwrap();
    policy.target.openvpn_routes.insert(
        profile,
        OpenVpnRouteEvidence::new(
            OpenVpnRouteSetEvidence::new(
                vec![OpenVpnRoute::with_gateway(
                    "10.20.0.0/16".parse().unwrap(),
                    OpenVpnRouteGateway::RemoteHost,
                    None,
                )
                .unwrap()],
                None,
            )
            .unwrap(),
            OpenVpnRouteSetEvidence::new(Vec::new(), None).unwrap(),
        )
        .unwrap()
        .with_selected_remote(Some(selected_remote))
        .unwrap(),
    );

    let plan = HelperPolicyPlan::forward(&policy).unwrap();
    let initial = PolicyProjection::from_mutation(&plan.initial_operation(), None)
        .unwrap()
        .unwrap();
    let predecessor = PolicyPredecessor::settled(initial.digest(), plan.initial_phase()).unwrap();
    let NetworkPolicyOperation::ApplyRoutes { routes, .. } = plan.routes_operation(predecessor)
    else {
        panic!("route phase must remain typed")
    };
    assert_eq!(routes.len(), 1);
    assert_eq!(
        routes[0].gateway(),
        ScopedRouteGateway::OpenVpn(OpenVpnRouteGateway::RemoteHost)
    );
    assert_eq!(routes[0].selected_remote(), Some(selected_remote));
}

#[test]
fn route_projection_rejects_selected_remote_outside_authenticated_endpoints() {
    let mut policy = policy(false);
    let profile = profile();
    policy
        .target
        .protocols
        .insert(profile.clone(), ProtocolKind::OpenVpn);
    policy.target.openvpn_routes.insert(
        profile,
        OpenVpnRouteEvidence::new(
            OpenVpnRouteSetEvidence::new(
                vec![OpenVpnRoute::with_gateway(
                    "10.20.0.0/16".parse().unwrap(),
                    OpenVpnRouteGateway::RemoteHost,
                    None,
                )
                .unwrap()],
                None,
            )
            .unwrap(),
            OpenVpnRouteSetEvidence::new(Vec::new(), None).unwrap(),
        )
        .unwrap()
        .with_selected_remote(Some("198.51.100.44".parse().unwrap()))
        .unwrap(),
    );

    let plan = HelperPolicyPlan::forward(&policy).unwrap();
    let initial = PolicyProjection::from_mutation(&plan.initial_operation(), None)
        .unwrap()
        .unwrap();
    let predecessor = PolicyPredecessor::settled(initial.digest(), plan.initial_phase()).unwrap();
    let routes = plan.routes_operation(predecessor);
    assert!(PolicyProjection::from_mutation(&routes, Some(&initial)).is_err());
}

#[test]
fn preblock_merges_new_endpoint_into_same_owned_tunnel_subject() {
    let mut policy = policy(true);
    policy
        .tunnel_revisions
        .get_mut(&profile())
        .unwrap()
        .generation = 3;
    policy
        .target
        .server_ips
        .get_mut(&profile())
        .unwrap()
        .insert("198.51.100.44".parse().unwrap());

    let plan = HelperPolicyPlan::forward(&policy).unwrap();
    let NetworkPolicyOperation::EstablishBlocking { tunnels, .. } = plan.initial_operation() else {
        panic!("required pre-barrier must block")
    };
    assert_eq!(tunnels.len(), 1);
    assert_eq!(tunnels[0].tunnel().generation(), 3);
    assert_eq!(tunnels[0].endpoint_ips().len(), 2);
}

#[test]
fn resume_rejects_same_generation_with_a_different_projection_digest() {
    let policy = policy(false);
    let plan = HelperPolicyPlan::forward(&policy).unwrap();
    let wrong = crate::vortix_core::privileged::PolicyDigest::for_test(OperationDigest::of_bytes(
        b"different-policy",
    ));
    let inventory = HelperPolicyInventory::new(
        Some(plan.firewall.clone()),
        Some(PolicyPredecessor::settled(wrong, PolicyPhase::Firewall).unwrap()),
        vec![HelperPolicyResource::new(
            plan.firewall.clone(),
            HelperResourceState::Owned,
            wrong,
            Some(wrong),
        )
        .unwrap()],
    )
    .unwrap();

    assert_eq!(
        helper_policy_progress(&inventory, &plan),
        Err(HelperPolicyPlanError::HelperUnavailable)
    );
}

#[test]
fn full_policy_sequence_uses_authenticated_observation_at_every_effect_boundary() {
    let helper = Arc::new(FakeHelper::new());
    let executor = HelperBackedPolicyExecutor::new(helper.clone()).unwrap();
    let policy = policy(false);

    for barrier in PolicyBarrier::ORDERED {
        executor.apply(&policy, barrier).unwrap();
    }

    assert!(executor.verification(&policy).is_some());
    assert_eq!(
        helper
            .operations()
            .iter()
            .map(|operation| match operation {
                PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::EstablishFirewall {
                    ..
                }) => "baseline",
                PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ApplyRoutes {
                    ..
                }) => "routes",
                PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ApplyDns { .. }) => {
                    "dns"
                }
                PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ApplyFirewall {
                    ..
                }) => "firewall",
                PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ObserveBarrier {
                    ..
                }) => "observe",
                PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ReleaseObsolete {
                    ..
                }) => "release",
                PrivilegedOperation::ObserveManaged(_) => "tunnel-observe",
                PrivilegedOperation::AuditPolicy(resource) => match resource.kind() {
                    ResourceKind::Firewall => "audit-firewall",
                    ResourceKind::Routes => "audit-routes",
                    ResourceKind::Dns => "audit-dns",
                    ResourceKind::Tunnel
                    | ResourceKind::ProcessGroup
                    | ResourceKind::RuntimeSecret => "unexpected",
                },
                _ => "unexpected",
            })
            .collect::<Vec<_>>(),
        vec![
            "baseline",
            "observe",
            "tunnel-observe",
            "routes",
            "observe",
            "dns",
            "observe",
            "firewall",
            "observe",
            "audit-routes",
            "audit-dns",
            "audit-firewall",
            "tunnel-observe",
        ]
    );
}

#[test]
fn effective_publication_reaudits_every_policy_family_and_live_tunnel() {
    let helper = Arc::new(FakeHelper::new());
    let executor = HelperBackedPolicyExecutor::new(helper.clone()).unwrap();
    let policy = policy(false);
    for barrier in PolicyBarrier::ORDERED {
        executor.apply(&policy, barrier).unwrap();
    }

    let operations = helper.operations();
    let audited = operations
        .iter()
        .filter_map(|operation| match operation {
            PrivilegedOperation::AuditPolicy(resource) => Some(resource.kind()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        audited,
        BTreeSet::from([
            ResourceKind::Firewall,
            ResourceKind::Routes,
            ResourceKind::Dns
        ])
    );
    assert_eq!(
        operations
            .iter()
            .filter(|operation| matches!(operation, PrivilegedOperation::ObserveManaged(_)))
            .count(),
        2
    );
    assert!(executor.verification(&policy).is_some());
}

#[test]
fn forward_plan_is_reused_for_each_barrier_of_the_same_policy() {
    let executor = HelperBackedPolicyExecutor::new(Arc::new(FakeHelper::new())).unwrap();
    let policy = policy(false);
    executor.update_readback(&policy, |_| {});

    let first = executor.forward_plan(&policy).unwrap();
    let second = executor.forward_plan(&policy).unwrap();

    assert!(Arc::ptr_eq(&first, &second));

    let mut next = policy;
    next.digest = PolicyDigest("next-policy".into());
    executor.update_readback(&next, |_| {});
    let replacement = executor.forward_plan(&next).unwrap();
    assert!(!Arc::ptr_eq(&first, &replacement));
}

#[test]
fn tunnel_barrier_requires_a_live_authenticated_managed_observation() {
    let helper = Arc::new(FakeHelper::new());
    helper.observe_tunnels_as(ObservationState::Absent);
    let executor = HelperBackedPolicyExecutor::new(helper).unwrap();
    let policy = policy(false);

    let error = executor.apply(&policy, PolicyBarrier::Tunnel).unwrap_err();

    assert!(error.contains("unavailable or unverified"));
    assert!(executor.verification(&policy).is_none());
}

#[test]
fn tunnel_barrier_live_checks_removed_tunnels_after_owned_teardown() {
    let helper = Arc::new(FakeHelper::new());
    helper.observe_tunnels_as(ObservationState::Absent);
    let executor = HelperBackedPolicyExecutor::new(helper.clone()).unwrap();
    let profile = profile();
    let mut policy = policy(false);
    policy.prior = state(&profile, KillSwitchMode::Auto);
    policy.target = TopologyState::default();
    policy.prior_tunnel_revisions = policy.tunnel_revisions.clone();
    policy.tunnel_revisions.clear();
    policy.transition = TopologyTransitionKind::Disconnect;

    executor.apply(&policy, PolicyBarrier::Tunnel).unwrap();

    assert!(helper.operations().iter().any(|operation| matches!(
        operation,
        PrivilegedOperation::ObserveManagedAbsence(targets)
            if targets.len() == 1
    )));
}

#[test]
fn tunnel_barrier_uses_exact_openvpn_tunnel_and_process_group_identity() {
    let helper = Arc::new(FakeHelper::new());
    helper.observe_tunnels_as(ObservationState::Absent);
    let executor = HelperBackedPolicyExecutor::new(helper.clone()).unwrap();
    let profile = profile();
    let mut policy = policy(false);
    policy.prior = state(&profile, KillSwitchMode::Auto);
    policy
        .prior
        .protocols
        .insert(profile.clone(), ProtocolKind::OpenVpn);
    policy.target = TopologyState::default();
    policy.prior_tunnel_revisions = policy.tunnel_revisions.clone();
    policy.tunnel_revisions.clear();
    policy.transition = TopologyTransitionKind::Disconnect;

    executor.apply(&policy, PolicyBarrier::Tunnel).unwrap();

    let targets = helper
        .operations()
        .into_iter()
        .find_map(|operation| match operation {
            PrivilegedOperation::ObserveManagedAbsence(targets) => Some(targets),
            _ => None,
        })
        .unwrap();
    assert_eq!(targets.len(), 2);
    assert!(targets.iter().all(|target| {
        target.protocol() == Some(ProtocolKind::OpenVpn)
            && matches!(
                target.resource().kind(),
                ResourceKind::Tunnel | ResourceKind::ProcessGroup
            )
    }));
}

#[test]
fn tunnel_barrier_reads_back_live_openvpn_as_a_closed_resource_set() {
    let helper = Arc::new(FakeHelper::new());
    let executor = HelperBackedPolicyExecutor::new(helper.clone()).unwrap();
    let profile = profile();
    let mut policy = policy(false);
    policy
        .target
        .protocols
        .insert(profile.clone(), ProtocolKind::OpenVpn);
    policy.target.openvpn_routes.insert(
        profile,
        OpenVpnRouteEvidence::new(
            OpenVpnRouteSetEvidence::new(Vec::new(), None).unwrap(),
            OpenVpnRouteSetEvidence::new(Vec::new(), None).unwrap(),
        )
        .unwrap(),
    );

    executor.apply(&policy, PolicyBarrier::Tunnel).unwrap();

    let targets = helper
        .operations()
        .into_iter()
        .find_map(|operation| match operation {
            PrivilegedOperation::ObserveManaged(targets) => Some(targets),
            _ => None,
        })
        .unwrap();
    assert_eq!(targets.len(), 2);
    assert!(targets
        .iter()
        .all(|target| target.protocol() == Some(ProtocolKind::OpenVpn)));
}

#[test]
fn tunnel_barrier_rejects_changed_openvpn_route_evidence() {
    let helper = Arc::new(FakeHelper::new());
    let executor = HelperBackedPolicyExecutor::new(helper).unwrap();
    let profile = profile();
    let mut policy = policy(false);
    policy
        .target
        .protocols
        .insert(profile.clone(), ProtocolKind::OpenVpn);
    policy.target.openvpn_routes.insert(
        profile,
        OpenVpnRouteEvidence::new(
            OpenVpnRouteSetEvidence::new(
                vec![OpenVpnRoute::with_gateway(
                    "10.20.0.0/16".parse().unwrap(),
                    OpenVpnRouteGateway::RemoteHost,
                    None,
                )
                .unwrap()],
                None,
            )
            .unwrap(),
            OpenVpnRouteSetEvidence::new(Vec::new(), None).unwrap(),
        )
        .unwrap()
        .with_selected_remote(Some("203.0.113.9".parse().unwrap()))
        .unwrap(),
    );

    assert!(executor.apply(&policy, PolicyBarrier::Tunnel).is_err());
}

#[test]
fn ambiguous_mutation_reconnects_to_inventory_without_replaying_the_effect() {
    let helper = Arc::new(FakeHelper::new());
    helper.lose_after_first_mutation();
    let executor = HelperBackedPolicyExecutor::new(helper.clone()).unwrap();
    let policy = policy(false);

    executor.apply(&policy, PolicyBarrier::Blocking).unwrap();

    let operations = helper.operations();
    assert_eq!(
        operations
            .iter()
            .filter(|operation| matches!(
                operation,
                PrivilegedOperation::NetworkPolicy(
                    NetworkPolicyOperation::EstablishFirewall { .. }
                )
            ))
            .count(),
        1
    );
    assert_eq!(
        operations
            .iter()
            .filter(|operation| matches!(
                operation,
                PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ObserveBarrier { .. })
            ))
            .count(),
        1
    );
}

#[test]
fn final_firewall_recovery_accepts_the_authenticated_prior_effective_projection() {
    let helper = Arc::new(FakeHelper::new());
    let executor = HelperBackedPolicyExecutor::new(helper.clone()).unwrap();
    let policy = policy(false);
    for barrier in [
        PolicyBarrier::Blocking,
        PolicyBarrier::Tunnel,
        PolicyBarrier::Route,
        PolicyBarrier::Dns,
        PolicyBarrier::Observation,
    ] {
        executor.apply(&policy, barrier).unwrap();
    }
    helper.lose_after_first_mutation();

    executor
        .apply(&policy, PolicyBarrier::EffectivePublication)
        .unwrap();

    assert_eq!(
        helper
            .operations()
            .iter()
            .filter(|operation| matches!(
                operation,
                PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ApplyFirewall { .. })
            ))
            .count(),
        1
    );
    assert!(executor.verification(&policy).is_some());
}

#[test]
fn restarted_executor_resumes_from_authenticated_policy_inventory() {
    let helper = Arc::new(FakeHelper::new());
    let first = HelperBackedPolicyExecutor::new(helper.clone()).unwrap();
    let policy = policy(false);
    first.apply(&policy, PolicyBarrier::Blocking).unwrap();

    let restarted = HelperBackedPolicyExecutor::new(helper.clone()).unwrap();
    for barrier in [
        PolicyBarrier::Tunnel,
        PolicyBarrier::Route,
        PolicyBarrier::Dns,
        PolicyBarrier::Observation,
        PolicyBarrier::EffectivePublication,
    ] {
        restarted.apply(&policy, barrier).unwrap();
    }

    assert!(restarted.verification(&policy).is_some());
    assert_eq!(
        helper
            .operations()
            .iter()
            .filter(|operation| matches!(
                operation,
                PrivilegedOperation::NetworkPolicy(
                    NetworkPolicyOperation::EstablishFirewall { .. }
                )
            ))
            .count(),
        1
    );
}

#[test]
fn restarted_route_barrier_observes_pending_effect_without_replaying_mutation() {
    let helper = Arc::new(FakeHelper::new());
    let first = HelperBackedPolicyExecutor::new(helper.clone()).unwrap();
    let policy = policy(false);
    first.apply(&policy, PolicyBarrier::Blocking).unwrap();

    let plan = HelperPolicyPlan::forward(&policy).unwrap();
    let predecessor = helper.state.ledger.lock().unwrap().predecessor.unwrap();
    helper
        .state
        .ledger
        .lock()
        .unwrap()
        .apply_mutation(&plan.routes_operation(predecessor));

    let restarted = HelperBackedPolicyExecutor::new(helper.clone()).unwrap();
    restarted.apply(&policy, PolicyBarrier::Route).unwrap();
    let after_first = helper.operations();
    restarted.apply(&policy, PolicyBarrier::Route).unwrap();
    let after_second = helper.operations();

    assert_eq!(after_first, after_second);
    assert_eq!(
        after_first
            .iter()
            .filter(|operation| matches!(
                operation,
                PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ApplyRoutes { .. })
            ))
            .count(),
        0
    );
    assert_eq!(
        after_first
            .iter()
            .filter(|operation| matches!(
                operation,
                PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ObserveBarrier {
                    policy,
                    ..
                }) if policy.kind() == ResourceKind::Routes
            ))
            .count(),
        1
    );
}

#[test]
fn restarted_dns_barriers_resume_pending_effect_without_replaying_mutation() {
    let helper = Arc::new(FakeHelper::new());
    let first = HelperBackedPolicyExecutor::new(helper.clone()).unwrap();
    let policy = policy(false);
    first.apply(&policy, PolicyBarrier::Blocking).unwrap();
    first.apply(&policy, PolicyBarrier::Route).unwrap();

    let plan = HelperPolicyPlan::forward(&policy).unwrap();
    let predecessor = helper.state.ledger.lock().unwrap().predecessor.unwrap();
    helper
        .state
        .ledger
        .lock()
        .unwrap()
        .apply_mutation(&plan.dns_operation(predecessor));

    let restarted = HelperBackedPolicyExecutor::new(helper.clone()).unwrap();
    restarted.apply(&policy, PolicyBarrier::Dns).unwrap();
    restarted
        .apply(&policy, PolicyBarrier::Observation)
        .unwrap();

    let operations = helper.operations();
    assert_eq!(
        operations
            .iter()
            .filter(|operation| matches!(
                operation,
                PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ApplyDns { .. })
            ))
            .count(),
        0
    );
    assert_eq!(
        operations
            .iter()
            .filter(|operation| matches!(
                operation,
                PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ObserveBarrier {
                    policy,
                    ..
                }) if policy.kind() == ResourceKind::Dns
            ))
            .count(),
        1
    );
}

#[test]
fn next_generation_releases_only_exact_older_policy_resources() {
    let helper = Arc::new(FakeHelper::new());
    let executor = HelperBackedPolicyExecutor::new(helper.clone()).unwrap();
    let first = policy(false);
    for barrier in PolicyBarrier::ORDERED {
        executor.apply(&first, barrier).unwrap();
    }

    let mut second = policy(false);
    second.generation = 8;
    second.operation_id = serde_json::from_str("\"op-0000000000000001-0000000000000002\"").unwrap();
    second
        .tunnel_revisions
        .get_mut(&profile())
        .unwrap()
        .generation = 5;
    for barrier in PolicyBarrier::ORDERED {
        executor.apply(&second, barrier).unwrap();
    }

    let release = helper
        .operations()
        .into_iter()
        .find_map(|operation| match operation {
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ReleaseObsolete {
                policy,
                resources,
                retained_state,
                ..
            }) => Some((policy, resources, retained_state)),
            _ => None,
        })
        .expect("the next generation releases the prior helper projection");
    assert_eq!(release.0.generation(), 15);
    assert_eq!(release.2, ObservationState::Absent);
    assert_eq!(release.1.len(), 3);
    assert!(release.1.iter().all(|resource| resource.generation() == 13));
}

#[test]
fn compensation_uses_a_distinct_generation_and_is_idempotently_resumable() {
    let helper = Arc::new(FakeHelper::new());
    let executor = HelperBackedPolicyExecutor::new(helper.clone()).unwrap();
    let policy = policy(true);
    for barrier in PolicyBarrier::ORDERED {
        executor.apply(&policy, barrier).unwrap();
    }

    executor
        .compensate(&policy, PolicyBarrier::EffectivePublication)
        .unwrap();
    let after_first = helper.operations();
    executor.compensate(&policy, PolicyBarrier::Dns).unwrap();
    let after_second = helper.operations();

    assert_eq!(after_second.len(), after_first.len());
    assert!(after_first.iter().any(|operation| matches!(
        operation,
        PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ApplyFirewall {
            policy,
            mode: KillSwitchMode::AlwaysOn,
            ..
        }) if policy.generation() == 14
    )));
    assert!(after_first.iter().any(|operation| matches!(
        operation,
        PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ReleaseObsolete {
            policy,
            resources,
            retained_state: ObservationState::Present,
            ..
        }) if policy.generation() == 14
            && resources.iter().any(|resource| resource.generation() == 13)
    )));
}

#[test]
fn compensation_settles_an_unobserved_forward_generation_before_restoring() {
    let helper = Arc::new(FakeHelper::new());
    let executor = HelperBackedPolicyExecutor::new(helper.clone()).unwrap();
    let policy = policy(true);
    let forward = HelperPolicyPlan::forward(&policy).unwrap();
    helper
        .state
        .ledger
        .lock()
        .unwrap()
        .apply_mutation(&forward.initial_operation());

    executor
        .compensate(&policy, PolicyBarrier::Blocking)
        .unwrap();

    let operations = helper.operations();
    assert!(matches!(
        operations.first(),
        Some(PrivilegedOperation::NetworkPolicy(
            NetworkPolicyOperation::ObserveBarrier { policy, .. }
        )) if policy.generation() == 13
    ));
    assert!(operations.iter().any(|operation| matches!(
        operation,
        PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::EstablishBlocking {
            policy,
            ..
        }) if policy.generation() == 14
    )));
}

#[test]
fn reconnect_verifies_the_superseded_tunnel_revision_is_absent() {
    let helper = Arc::new(FakeHelper::new());
    let executor = HelperBackedPolicyExecutor::new(helper.clone()).unwrap();
    let policy = policy(true);

    executor.apply(&policy, PolicyBarrier::Tunnel).unwrap();

    assert!(helper.operations().iter().any(|operation| matches!(
        operation,
        PrivilegedOperation::ObserveManagedAbsence(targets)
            if targets.iter().any(|target| target.resource().generation() == 3)
    )));
}

#[test]
fn final_publication_rejects_fresh_policy_readback_drift() {
    let helper = Arc::new(FakeHelper::new());
    let executor = HelperBackedPolicyExecutor::new(helper.clone()).unwrap();
    let policy = policy(false);
    for barrier in [
        PolicyBarrier::Blocking,
        PolicyBarrier::Tunnel,
        PolicyBarrier::Route,
        PolicyBarrier::Dns,
        PolicyBarrier::Observation,
    ] {
        executor.apply(&policy, barrier).unwrap();
    }
    helper.observe_policy_audits_as(ObservationState::Present);

    assert!(executor
        .apply(&policy, PolicyBarrier::EffectivePublication)
        .is_err());
    assert!(executor.verification(&policy).is_none());
}

#[test]
fn ambiguous_release_accepts_only_inventory_proven_absence_without_replay() {
    let helper = Arc::new(FakeHelper::new());
    let executor = HelperBackedPolicyExecutor::new(helper.clone()).unwrap();
    let first = policy(false);
    for barrier in PolicyBarrier::ORDERED {
        executor.apply(&first, barrier).unwrap();
    }
    let mut second = policy(false);
    second.generation = 8;
    second.operation_id = serde_json::from_str("\"op-0000000000000001-0000000000000002\"").unwrap();
    second
        .tunnel_revisions
        .get_mut(&profile())
        .unwrap()
        .generation = 5;
    for barrier in [
        PolicyBarrier::Blocking,
        PolicyBarrier::Tunnel,
        PolicyBarrier::Route,
        PolicyBarrier::Dns,
        PolicyBarrier::Observation,
    ] {
        executor.apply(&second, barrier).unwrap();
    }
    helper.lose_after_release();

    executor
        .apply(&second, PolicyBarrier::EffectivePublication)
        .unwrap();

    assert_eq!(
        helper
            .operations()
            .iter()
            .filter(|operation| matches!(
                operation,
                PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ReleaseObsolete { .. })
            ))
            .count(),
        1
    );
}

#[test]
fn pending_release_retries_with_the_authenticated_released_cursor() {
    let helper = Arc::new(FakeHelper::new());
    let executor = HelperBackedPolicyExecutor::new(helper.clone()).unwrap();
    let first = policy(false);
    for barrier in PolicyBarrier::ORDERED {
        executor.apply(&first, barrier).unwrap();
    }
    let mut second = policy(false);
    second.generation = 8;
    second.operation_id = serde_json::from_str("\"op-0000000000000001-0000000000000002\"").unwrap();
    second
        .tunnel_revisions
        .get_mut(&profile())
        .unwrap()
        .generation = 5;
    for barrier in [
        PolicyBarrier::Blocking,
        PolicyBarrier::Tunnel,
        PolicyBarrier::Route,
        PolicyBarrier::Dns,
        PolicyBarrier::Observation,
    ] {
        executor.apply(&second, barrier).unwrap();
    }
    helper.lose_before_release_effect();

    executor
        .apply(&second, PolicyBarrier::EffectivePublication)
        .unwrap();

    let predecessors = helper
        .operations()
        .into_iter()
        .filter_map(|operation| match operation {
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ReleaseObsolete {
                predecessor,
                ..
            }) => Some(predecessor),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(predecessors.len(), 2);
    assert!(predecessors[0].observed());
    assert_eq!(predecessors[1].phase(), PolicyPhase::Released);
    assert!(!predecessors[1].observed());
}
