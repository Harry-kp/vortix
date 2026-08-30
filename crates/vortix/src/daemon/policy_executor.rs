//! Authenticated helper execution for canonical topology policy barriers.

#![allow(
    dead_code,
    reason = "helper policy execution remains dormant until enrolled daemon authority activation"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use thiserror::Error;

use super::helper_client::{
    AuthenticatedHelperConnector, AuthenticatedHelperOutcome, AuthenticatedHelperTransport,
    HelperExecutionFailure, RecoveryAction,
};
use crate::helper::{HelperCapability, HelperPolicyInventory};
use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::control::worker::{
    PolicyBarrier, PolicyExecutionEvidence, PolicyExecutor, PolicyStage, TopologyPolicy,
    TopologyState, TunnelRevision,
};
use crate::vortix_core::ports::dns::DnsRequest;
use crate::vortix_core::privileged::{
    DnsHostname, HelperResourceState, NetworkPolicyOperation, ObservationState,
    OpenVpnRouteDefaults, OpenVpnRouteGateway, PolicyPhase, PolicyPredecessor, PolicyProjection,
    PrivilegedDnsAssignment, PrivilegedDnsScope, PrivilegedFirewallRole, PrivilegedFirewallTunnel,
    PrivilegedOperation, ResourceKind, ResourceObservationTarget, ResourceTag,
    ScopedOpenVpnRedirect, ScopedRoute, ScopedRouteOrigin,
};
use crate::vortix_core::profile::{ProfileId, ProtocolKind};
use crate::vortix_core::state::killswitch::KillSwitchMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelperPolicyGeneration {
    Forward,
    Compensation,
}

fn helper_generation(
    canonical_generation: u64,
    kind: HelperPolicyGeneration,
) -> Result<u64, &'static str> {
    let doubled = canonical_generation
        .checked_mul(2)
        .ok_or("canonical policy generation exceeds helper range")?;
    match kind {
        HelperPolicyGeneration::Forward => doubled
            .checked_sub(1)
            .filter(|generation| *generation != 0)
            .ok_or("canonical policy generation is invalid"),
        HelperPolicyGeneration::Compensation => Ok(doubled),
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
enum HelperPolicyPlanError {
    #[error("canonical policy generation cannot be represented by the helper")]
    Generation,
    #[error("topology policy has missing or mismatched tunnel ownership")]
    TunnelOwnership,
    #[error("topology policy contains invalid firewall, route, or DNS input")]
    InvalidInput,
    #[error("helper-owned route mutation is not available for this tunnel protocol")]
    RouteMutationUnavailable,
    #[error("authenticated helper policy execution is unavailable or unverified")]
    HelperUnavailable,
    #[error("helper policy outcome is unknown and requires inventory reconciliation")]
    OutcomeUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HelperPolicyPlan {
    generation: u64,
    firewall: ResourceTag,
    routes: ResourceTag,
    dns: ResourceTag,
    initial_tunnels: Vec<PrivilegedFirewallTunnel>,
    target_tunnels: Vec<PrivilegedFirewallTunnel>,
    routes_payload: Vec<ScopedRoute>,
    redirects_payload: Vec<ScopedOpenVpnRedirect>,
    dns_payload: Vec<PrivilegedDnsAssignment>,
    initial_blocks: bool,
    final_mode: KillSwitchMode,
}

const POLICY_COMPENSATION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelperPolicyProgress {
    BeforeGeneration,
    Phase { phase: PolicyPhase, observed: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyReadbackKey {
    generation: u64,
    operation_id: crate::vortix_core::control::OperationId,
    stage: PolicyStage,
    digest: crate::vortix_core::control::PolicyDigest,
}

#[derive(Debug, Clone)]
struct PolicyReadback {
    key: PolicyReadbackKey,
    evidence: PolicyExecutionEvidence,
    forward_plan: Option<Arc<HelperPolicyPlan>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelperPolicyTransportFailure {
    Unavailable,
    OutcomeUnknown,
}

impl From<HelperExecutionFailure> for HelperPolicyTransportFailure {
    fn from(failure: HelperExecutionFailure) -> Self {
        match failure.recovery() {
            RecoveryAction::ReconcileRequired => Self::OutcomeUnknown,
            RecoveryAction::Unavailable => Self::Unavailable,
        }
    }
}

trait HelperPolicySession: Send {
    fn inventory(&self) -> Option<HelperPolicyInventory>;

    fn execute_bound(
        &mut self,
        operation: PrivilegedOperation,
        descriptors: &[RawFd],
        deadline: Instant,
    ) -> Result<AuthenticatedHelperOutcome, HelperPolicyTransportFailure>;
}

trait HelperPolicyTransport: Send + Sync {
    fn enables(&self, capability: HelperCapability) -> bool;

    fn connect(
        &self,
        deadline: Instant,
    ) -> Result<Box<dyn HelperPolicySession>, HelperPolicyTransportFailure>;
}

impl HelperPolicySession for AuthenticatedHelperTransport {
    fn inventory(&self) -> Option<HelperPolicyInventory> {
        self.policy_inventory().cloned()
    }

    fn execute_bound(
        &mut self,
        operation: PrivilegedOperation,
        descriptors: &[RawFd],
        deadline: Instant,
    ) -> Result<AuthenticatedHelperOutcome, HelperPolicyTransportFailure> {
        AuthenticatedHelperTransport::execute_bound(self, operation, descriptors, deadline)
            .map_err(HelperPolicyTransportFailure::from)
    }
}

impl HelperPolicyTransport for AuthenticatedHelperConnector {
    fn enables(&self, capability: HelperCapability) -> bool {
        self.enables(capability)
    }

    fn connect(
        &self,
        deadline: Instant,
    ) -> Result<Box<dyn HelperPolicySession>, HelperPolicyTransportFailure> {
        AuthenticatedHelperConnector::connect(self, deadline)
            .map(|session| Box::new(session) as Box<dyn HelperPolicySession>)
            .map_err(HelperPolicyTransportFailure::from)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
enum HelperBackedPolicyExecutorError {
    #[error("authenticated helper lacks network-policy or observation capability")]
    CapabilityMismatch,
}

struct HelperBackedPolicyExecutor {
    helper: Arc<dyn HelperPolicyTransport>,
    readback: Mutex<Option<PolicyReadback>>,
}

impl HelperBackedPolicyExecutor {
    fn new(
        helper: Arc<dyn HelperPolicyTransport>,
    ) -> Result<Self, HelperBackedPolicyExecutorError> {
        if !helper.enables(HelperCapability::NetworkPolicy)
            || !helper.enables(HelperCapability::Observe)
        {
            return Err(HelperBackedPolicyExecutorError::CapabilityMismatch);
        }
        Ok(Self {
            helper,
            readback: Mutex::new(None),
        })
    }

    fn readback_key(policy: &TopologyPolicy) -> PolicyReadbackKey {
        PolicyReadbackKey {
            generation: policy.generation,
            operation_id: policy.operation_id.clone(),
            stage: policy.stage,
            digest: policy.digest.clone(),
        }
    }

    fn update_readback(
        &self,
        policy: &TopologyPolicy,
        update: impl FnOnce(&mut PolicyExecutionEvidence),
    ) {
        let key = Self::readback_key(policy);
        let mut readback = self
            .readback
            .lock()
            .expect("helper policy readback mutex poisoned");
        if readback.as_ref().is_none_or(|state| state.key != key) {
            *readback = Some(PolicyReadback {
                key,
                evidence: PolicyExecutionEvidence {
                    observed_at_millis: 0,
                    interface_verified: false,
                    route_verified: false,
                    dns_verified: false,
                    firewall_verified: false,
                },
                forward_plan: None,
            });
        }
        update(
            &mut readback
                .as_mut()
                .expect("readback was initialized")
                .evidence,
        );
    }

    fn forward_plan(
        &self,
        policy: &TopologyPolicy,
    ) -> Result<Arc<HelperPolicyPlan>, HelperPolicyPlanError> {
        let key = Self::readback_key(policy);
        let mut readback = self
            .readback
            .lock()
            .expect("helper policy readback mutex poisoned");
        let state = readback
            .as_mut()
            .filter(|state| state.key == key)
            .ok_or(HelperPolicyPlanError::InvalidInput)?;
        if let Some(plan) = &state.forward_plan {
            return Ok(Arc::clone(plan));
        }
        let plan = Arc::new(HelperPolicyPlan::forward(policy)?);
        state.forward_plan = Some(Arc::clone(&plan));
        Ok(plan)
    }

    fn open_session(
        &self,
        deadline: Instant,
    ) -> Result<Box<dyn HelperPolicySession>, HelperPolicyPlanError> {
        self.helper
            .connect(deadline)
            .map_err(|_| HelperPolicyPlanError::HelperUnavailable)
    }

    fn apply_initial(
        &self,
        policy: &TopologyPolicy,
        plan: &HelperPolicyPlan,
    ) -> Result<(), HelperPolicyPlanError> {
        let operation = plan.initial_operation();
        let projection = plan.projection_for_phase(plan.initial_phase())?;
        self.run_observed_mutation(policy.deadline, &operation, &projection)
    }

    fn apply_routes(
        &self,
        policy: &TopologyPolicy,
        plan: &HelperPolicyPlan,
    ) -> Result<(), HelperPolicyPlanError> {
        let initial = plan.projection_for_phase(plan.initial_phase())?;
        let projection = plan.projection_for_phase(PolicyPhase::Routes)?;
        self.run_observed_transition(
            policy.deadline,
            &initial,
            &projection,
            None,
            |predecessor| plan.routes_operation(predecessor),
        )
    }

    fn apply_dns(
        &self,
        policy: &TopologyPolicy,
        plan: &HelperPolicyPlan,
    ) -> Result<(), HelperPolicyPlanError> {
        let routes = plan.projection_for_phase(PolicyPhase::Routes)?;
        let projection = plan.projection_for_phase(PolicyPhase::Dns)?;
        self.run_pending_transition(policy.deadline, &routes, &projection, None, |predecessor| {
            plan.dns_operation(predecessor)
        })
    }

    fn observe_dns(
        &self,
        policy: &TopologyPolicy,
        plan: &HelperPolicyPlan,
    ) -> Result<(), HelperPolicyPlanError> {
        let mut session = self.open_session(policy.deadline)?;
        let inventory = required_inventory(session.as_ref())?;
        let projection = plan.projection_for_phase(PolicyPhase::Dns)?;
        match classify_projection(&inventory, &projection, PolicyPhase::Dns, None)? {
            InventoryProjectionStatus::Observed(_) => Ok(()),
            InventoryProjectionStatus::Pending(predecessor) => {
                self.run_observation(session.as_mut(), &projection, predecessor, policy.deadline)
            }
            InventoryProjectionStatus::Other => Err(HelperPolicyPlanError::HelperUnavailable),
        }
    }

    fn apply_final_firewall(
        &self,
        policy: &TopologyPolicy,
        plan: &HelperPolicyPlan,
    ) -> Result<(), HelperPolicyPlanError> {
        let dns = plan.projection_for_phase(PolicyPhase::Dns)?;
        let projection = plan.final_projection();
        let prior_effective = plan.projection_for_phase(plan.initial_phase())?.digest();
        self.run_observed_transition(
            policy.deadline,
            &dns,
            &projection,
            Some(prior_effective),
            |predecessor| plan.final_firewall_operation(predecessor),
        )?;
        let mut release_session = self.open_session(policy.deadline)?;
        let release_inventory = required_inventory(release_session.as_ref())?;
        self.release_obsolete_exact(
            release_session.as_mut(),
            &release_inventory,
            &projection,
            policy.deadline,
        )
    }

    fn run_observed_mutation(
        &self,
        deadline: Instant,
        operation: &NetworkPolicyOperation,
        projection: &PolicyProjection,
    ) -> Result<(), HelperPolicyPlanError> {
        let mut session = self.open_session(deadline)?;
        match ensure_mutation_observed(
            session.as_mut(),
            operation,
            projection,
            None,
            None,
            deadline,
            true,
        ) {
            Err(HelperPolicyPlanError::OutcomeUnknown) => {
                let mut recovery = self.open_session(deadline)?;
                ensure_mutation_observed(
                    recovery.as_mut(),
                    operation,
                    projection,
                    None,
                    None,
                    deadline,
                    false,
                )
            }
            result => result,
        }
    }

    fn run_observed_transition(
        &self,
        deadline: Instant,
        prior: &PolicyProjection,
        projection: &PolicyProjection,
        pending_effective: Option<crate::vortix_core::privileged::PolicyDigest>,
        operation: impl FnOnce(PolicyPredecessor) -> NetworkPolicyOperation,
    ) -> Result<(), HelperPolicyPlanError> {
        let mut session = self.open_session(deadline)?;
        let inventory = required_inventory(session.as_ref())?;
        match classify_projection(
            &inventory,
            projection,
            projection.phase(),
            pending_effective,
        )? {
            InventoryProjectionStatus::Observed(_) => return Ok(()),
            InventoryProjectionStatus::Pending(predecessor) => {
                return self.run_observation(session.as_mut(), projection, predecessor, deadline);
            }
            InventoryProjectionStatus::Other => {}
        }
        let operation = operation(authenticated_settled_predecessor(&inventory, prior)?);
        match ensure_mutation_observed(
            session.as_mut(),
            &operation,
            projection,
            pending_effective,
            Some(inventory),
            deadline,
            true,
        ) {
            Err(HelperPolicyPlanError::OutcomeUnknown) => {
                let mut recovery = self.open_session(deadline)?;
                ensure_mutation_observed(
                    recovery.as_mut(),
                    &operation,
                    projection,
                    pending_effective,
                    None,
                    deadline,
                    false,
                )
            }
            result => result,
        }
    }

    fn run_pending_transition(
        &self,
        deadline: Instant,
        prior: &PolicyProjection,
        projection: &PolicyProjection,
        pending_effective: Option<crate::vortix_core::privileged::PolicyDigest>,
        operation: impl FnOnce(PolicyPredecessor) -> NetworkPolicyOperation,
    ) -> Result<(), HelperPolicyPlanError> {
        let mut session = self.open_session(deadline)?;
        let inventory = required_inventory(session.as_ref())?;
        match classify_projection(
            &inventory,
            projection,
            projection.phase(),
            pending_effective,
        )? {
            InventoryProjectionStatus::Pending(_) | InventoryProjectionStatus::Observed(_) => {
                return Ok(());
            }
            InventoryProjectionStatus::Other => {}
        }
        let operation = operation(authenticated_settled_predecessor(&inventory, prior)?);
        match ensure_mutation_pending(
            session.as_mut(),
            &operation,
            projection,
            pending_effective,
            Some(inventory),
            deadline,
            true,
        ) {
            Err(HelperPolicyPlanError::OutcomeUnknown) => {
                let mut recovery = self.open_session(deadline)?;
                ensure_mutation_pending(
                    recovery.as_mut(),
                    &operation,
                    projection,
                    pending_effective,
                    None,
                    deadline,
                    false,
                )
            }
            result => result,
        }
    }

    fn run_observation(
        &self,
        session: &mut dyn HelperPolicySession,
        projection: &PolicyProjection,
        predecessor: PolicyPredecessor,
        deadline: Instant,
    ) -> Result<(), HelperPolicyPlanError> {
        match execute_observation(
            session,
            projection.policy(),
            predecessor,
            projection.expected_observation_state(),
            deadline,
        ) {
            Err(HelperPolicyPlanError::OutcomeUnknown) => {
                let mut recovery = self.open_session(deadline)?;
                let inventory = required_inventory(recovery.as_ref())?;
                match classify_projection(&inventory, projection, predecessor.phase(), None)? {
                    InventoryProjectionStatus::Observed(_) => Ok(()),
                    InventoryProjectionStatus::Pending(recovered_predecessor) => {
                        execute_observation(
                            recovery.as_mut(),
                            projection.policy(),
                            recovered_predecessor,
                            projection.expected_observation_state(),
                            deadline,
                        )
                    }
                    InventoryProjectionStatus::Other => Err(HelperPolicyPlanError::OutcomeUnknown),
                }
            }
            result => result,
        }
    }

    fn release_obsolete_exact(
        &self,
        session: &mut dyn HelperPolicySession,
        inventory: &HelperPolicyInventory,
        retained: &PolicyProjection,
        deadline: Instant,
    ) -> Result<(), HelperPolicyPlanError> {
        let Some(operation) = release_operation(inventory, retained)? else {
            return Ok(());
        };
        match execute_release(session, &operation, deadline) {
            Err(HelperPolicyPlanError::OutcomeUnknown) => {
                let mut recovery = self.open_session(deadline)?;
                let recovered = required_inventory(recovery.as_ref())?;
                let NetworkPolicyOperation::ReleaseObsolete { resources, .. } = &operation else {
                    unreachable!("release builder returns only release operations")
                };
                if inventory_proves_release(&recovered, retained, resources) {
                    Ok(())
                } else if inventory_proves_release_pending(&recovered, retained, resources) {
                    let continuation = release_operation(&recovered, retained)?
                        .ok_or(HelperPolicyPlanError::OutcomeUnknown)?;
                    execute_release(recovery.as_mut(), &continuation, deadline)
                } else {
                    Err(HelperPolicyPlanError::OutcomeUnknown)
                }
            }
            result => result,
        }
    }

    fn restore_complete(
        &self,
        policy: &TopologyPolicy,
        plan: &HelperPolicyPlan,
    ) -> Result<(), HelperPolicyPlanError> {
        self.settle_pending_forward_before_compensation(policy, plan)?;
        let session = self.open_session(policy.deadline)?;
        let progress = helper_policy_progress(&required_inventory(session.as_ref())?, plan)?;
        let (phase, phase_observed) = match progress {
            HelperPolicyProgress::BeforeGeneration => (None, false),
            HelperPolicyProgress::Phase { phase, observed } => (Some(phase), observed),
        };
        if phase.is_none_or(|phase| {
            matches!(phase, PolicyPhase::FirewallBaseline | PolicyPhase::Blocking)
        }) {
            self.apply_initial(policy, plan)?;
        }
        if phase.is_none_or(|phase| {
            matches!(
                phase,
                PolicyPhase::FirewallBaseline | PolicyPhase::Blocking | PolicyPhase::Routes
            )
        }) {
            self.apply_routes(policy, plan)?;
        }
        if phase.is_none_or(|phase| {
            matches!(
                phase,
                PolicyPhase::FirewallBaseline
                    | PolicyPhase::Blocking
                    | PolicyPhase::Routes
                    | PolicyPhase::Dns
            )
        }) {
            self.apply_dns(policy, plan)?;
            if phase != Some(PolicyPhase::Dns) || !phase_observed {
                self.observe_dns(policy, plan)?;
            }
        }
        if phase == Some(PolicyPhase::Released) {
            let final_projection = plan.final_projection();
            let mut session = self.open_session(policy.deadline)?;
            let inventory = required_inventory(session.as_ref())?;
            self.release_obsolete_exact(
                session.as_mut(),
                &inventory,
                &final_projection,
                policy.deadline,
            )?;
        } else {
            self.apply_final_firewall(policy, plan)?;
        }
        Ok(())
    }

    fn settle_pending_forward_before_compensation(
        &self,
        policy: &TopologyPolicy,
        compensation: &HelperPolicyPlan,
    ) -> Result<(), HelperPolicyPlanError> {
        let mut session = self.open_session(policy.deadline)?;
        let inventory = required_inventory(session.as_ref())?;
        let Some(current) = inventory.current() else {
            return Ok(());
        };
        let Some(predecessor) = inventory.predecessor() else {
            return Err(HelperPolicyPlanError::HelperUnavailable);
        };
        if current.generation() >= compensation.generation || predecessor.observed() {
            return Ok(());
        }

        let forward = HelperPolicyPlan::forward(policy)?;
        if current.generation() != forward.generation {
            return Err(HelperPolicyPlanError::HelperUnavailable);
        }
        let projection = forward.projection_for_phase(predecessor.phase())?;
        let pending_effective = pending_effective_for_phase(&forward, predecessor.phase())?;
        let InventoryProjectionStatus::Pending(authenticated_predecessor) = classify_projection(
            &inventory,
            &projection,
            predecessor.phase(),
            pending_effective,
        )?
        else {
            return Err(HelperPolicyPlanError::HelperUnavailable);
        };
        self.run_observation(
            session.as_mut(),
            &projection,
            authenticated_predecessor,
            policy.deadline,
        )
    }

    fn verify_tunnel_projection(
        &self,
        policy: &TopologyPolicy,
    ) -> Result<(), HelperPolicyPlanError> {
        let mut session = self.open_session(policy.deadline)?;
        Self::verify_tunnel_projection_with(session.as_mut(), policy)
    }

    fn verify_tunnel_projection_with(
        session: &mut dyn HelperPolicySession,
        policy: &TopologyPolicy,
    ) -> Result<(), HelperPolicyPlanError> {
        let exact_profiles = policy.target.profiles.iter().all(|profile| {
            policy
                .tunnel_revisions
                .get(profile)
                .is_some_and(|revision| {
                    revision.authority_epoch == policy.authority_epoch && revision.generation != 0
                })
                && policy
                    .target
                    .interfaces
                    .get(profile)
                    .is_some_and(|interface| !interface.is_empty())
        }) && topology_protocols_are_exact(&policy.target);
        let removed_profiles_absent = policy
            .prior
            .profiles
            .difference(&policy.target.profiles)
            .all(|profile| !policy.target.interfaces.contains_key(profile))
            && topology_protocols_are_exact(&policy.prior);
        if !exact_profiles || !removed_profiles_absent {
            return Err(HelperPolicyPlanError::TunnelOwnership);
        }
        let present = managed_tunnel_targets(
            &policy.target,
            policy.target.profiles.iter(),
            &policy.tunnel_revisions,
        )?;
        let superseded = policy
            .prior
            .profiles
            .iter()
            .filter(|profile| {
                !policy.target.profiles.contains(*profile)
                    || policy.prior_tunnel_revisions.get(*profile)
                        != policy.tunnel_revisions.get(*profile)
            })
            .collect::<BTreeSet<_>>();
        let absent =
            managed_tunnel_targets(&policy.prior, superseded, &policy.prior_tunnel_revisions)?;
        Self::verify_managed_tunnel_state(
            session,
            policy.deadline,
            &present,
            ObservationState::Present,
            &policy.target.openvpn_routes,
        )?;
        Self::verify_managed_tunnel_state(
            session,
            policy.deadline,
            &absent,
            ObservationState::Absent,
            &BTreeMap::new(),
        )
    }

    fn audit_projection(
        session: &mut dyn HelperPolicySession,
        deadline: Instant,
        projection: &PolicyProjection,
    ) -> Result<(), HelperPolicyPlanError> {
        let outcome = execute_helper_operation(
            session,
            PrivilegedOperation::AuditPolicy(projection.policy().clone()),
            deadline,
        )?;
        if outcome
            .receipt()
            .observes(projection.policy(), projection.expected_observation_state())
        {
            Ok(())
        } else {
            Err(HelperPolicyPlanError::HelperUnavailable)
        }
    }

    fn audit_final_publication(
        &self,
        policy: &TopologyPolicy,
        plan: &HelperPolicyPlan,
    ) -> Result<(), HelperPolicyPlanError> {
        let mut session = self.open_session(policy.deadline)?;
        Self::audit_projection(
            session.as_mut(),
            policy.deadline,
            &plan.projection_for_phase(PolicyPhase::Routes)?,
        )?;
        Self::audit_projection(
            session.as_mut(),
            policy.deadline,
            &plan.projection_for_phase(PolicyPhase::Dns)?,
        )?;
        Self::audit_projection(session.as_mut(), policy.deadline, &plan.final_projection())?;
        Self::verify_tunnel_projection_with(session.as_mut(), policy)
    }

    fn verify_managed_tunnel_state(
        session: &mut dyn HelperPolicySession,
        deadline: Instant,
        targets: &[ResourceObservationTarget],
        expected: ObservationState,
        expected_openvpn_routes: &BTreeMap<
            ProfileId,
            crate::vortix_core::privileged::OpenVpnRouteEvidence,
        >,
    ) -> Result<(), HelperPolicyPlanError> {
        if targets.is_empty() {
            return Ok(());
        }
        let operation = if expected == ObservationState::Absent {
            PrivilegedOperation::ObserveManagedAbsence(targets.to_vec())
        } else {
            PrivilegedOperation::ObserveManaged(targets.to_vec())
        };
        let outcome = execute_helper_operation(session, operation, deadline)?;
        if targets.iter().all(|target| {
            let observation = outcome.receipt().observation(target.resource());
            let state_matches =
                observation.is_some_and(|observation| observation.state() == expected);
            let openvpn_routes_match = if expected == ObservationState::Present
                && target.protocol() == Some(ProtocolKind::OpenVpn)
                && target.resource().kind() == ResourceKind::Tunnel
            {
                target
                    .resource()
                    .profile_id()
                    .and_then(|profile| expected_openvpn_routes.get(profile))
                    .zip(observation.and_then(
                        crate::vortix_core::privileged::ResourceObservation::openvpn_routes,
                    ))
                    .is_some_and(|(expected, observed)| expected == observed)
            } else {
                true
            };
            state_matches && openvpn_routes_match
        }) {
            Ok(())
        } else {
            Err(HelperPolicyPlanError::HelperUnavailable)
        }
    }
}

fn topology_protocols_are_exact(state: &TopologyState) -> bool {
    state.protocols.keys().eq(state.profiles.iter())
}

fn managed_tunnel_targets<'a>(
    state: &TopologyState,
    profiles: impl IntoIterator<Item = &'a ProfileId>,
    revisions: &BTreeMap<ProfileId, TunnelRevision>,
) -> Result<Vec<ResourceObservationTarget>, HelperPolicyPlanError> {
    let mut targets = Vec::new();
    for profile in profiles {
        let tunnel = tunnel_resource(profile, revisions)?;
        let protocol = state
            .protocols
            .get(profile)
            .copied()
            .ok_or(HelperPolicyPlanError::TunnelOwnership)?;
        targets.push(
            ResourceObservationTarget::new(tunnel.clone(), Some(protocol))
                .map_err(|_| HelperPolicyPlanError::TunnelOwnership)?,
        );
        if protocol == ProtocolKind::OpenVpn {
            let group = ResourceTag::profile(
                profile.clone(),
                tunnel.generation(),
                ResourceKind::ProcessGroup,
            )
            .map_err(|_| HelperPolicyPlanError::TunnelOwnership)?;
            targets.push(
                ResourceObservationTarget::new(group, Some(protocol))
                    .map_err(|_| HelperPolicyPlanError::TunnelOwnership)?,
            );
        }
    }
    Ok(targets)
}

fn helper_policy_progress(
    inventory: &HelperPolicyInventory,
    plan: &HelperPolicyPlan,
) -> Result<HelperPolicyProgress, HelperPolicyPlanError> {
    let Some(current) = inventory.current() else {
        return inventory
            .resources()
            .is_empty()
            .then_some(HelperPolicyProgress::BeforeGeneration)
            .ok_or(HelperPolicyPlanError::HelperUnavailable);
    };
    if current.generation() < plan.generation {
        return inventory
            .predecessor()
            .is_some_and(PolicyPredecessor::observed)
            .then_some(HelperPolicyProgress::BeforeGeneration)
            .ok_or(HelperPolicyPlanError::HelperUnavailable);
    }
    if current.generation() != plan.generation {
        return Err(HelperPolicyPlanError::HelperUnavailable);
    }
    let phase = inventory
        .predecessor()
        .ok_or(HelperPolicyPlanError::HelperUnavailable)?
        .phase();
    let expected = plan.projection_for_phase(phase)?;
    if phase == PolicyPhase::Released {
        let predecessor = inventory
            .predecessor()
            .ok_or(HelperPolicyPlanError::HelperUnavailable)?;
        let retained = inventory
            .resources()
            .iter()
            .find(|entry| entry.resource() == expected.policy())
            .ok_or(HelperPolicyPlanError::HelperUnavailable)?;
        if inventory.current() != Some(expected.policy())
            || predecessor.phase() != PolicyPhase::Released
            || retained.state() != HelperResourceState::Owned
            || retained.intended() != expected.digest()
            || retained.effective() != Some(expected.digest())
        {
            return Err(HelperPolicyPlanError::HelperUnavailable);
        }
        return Ok(HelperPolicyProgress::Phase {
            phase,
            observed: predecessor.observed(),
        });
    }
    let pending_effective = pending_effective_for_phase(plan, phase)?;
    let observed = match classify_projection(inventory, &expected, phase, pending_effective)? {
        InventoryProjectionStatus::Pending(_) => false,
        InventoryProjectionStatus::Observed(_) => true,
        InventoryProjectionStatus::Other => {
            return Err(HelperPolicyPlanError::HelperUnavailable);
        }
    };
    Ok(HelperPolicyProgress::Phase { phase, observed })
}

fn pending_effective_for_phase(
    plan: &HelperPolicyPlan,
    phase: PolicyPhase,
) -> Result<Option<crate::vortix_core::privileged::PolicyDigest>, HelperPolicyPlanError> {
    if phase == PolicyPhase::Firewall {
        Ok(Some(
            plan.projection_for_phase(plan.initial_phase())?.digest(),
        ))
    } else {
        Ok(None)
    }
}

impl HelperPolicyPlan {
    fn forward(policy: &TopologyPolicy) -> Result<Self, HelperPolicyPlanError> {
        Self::new(
            policy,
            HelperPolicyGeneration::Forward,
            &policy.prior,
            &policy.target,
        )
    }

    fn compensation(policy: &TopologyPolicy) -> Result<Self, HelperPolicyPlanError> {
        Self::new(
            policy,
            HelperPolicyGeneration::Compensation,
            &policy.target,
            &policy.prior,
        )
    }

    fn new(
        policy: &TopologyPolicy,
        generation_kind: HelperPolicyGeneration,
        prior: &TopologyState,
        target: &TopologyState,
    ) -> Result<Self, HelperPolicyPlanError> {
        let generation = helper_generation(policy.generation, generation_kind)
            .map_err(|_| HelperPolicyPlanError::Generation)?;
        let initial_revisions = match generation_kind {
            HelperPolicyGeneration::Forward => &policy.prior_tunnel_revisions,
            HelperPolicyGeneration::Compensation => &policy.tunnel_revisions,
        };
        let target_revisions = match generation_kind {
            HelperPolicyGeneration::Forward => &policy.tunnel_revisions,
            HelperPolicyGeneration::Compensation => &policy.prior_tunnel_revisions,
        };
        validate_revision_authority(policy, initial_revisions)?;
        validate_revision_authority(policy, target_revisions)?;

        let initial_tunnels = if policy.required_blocking {
            pre_block_tunnels(prior, target, initial_revisions, target_revisions)?
        } else {
            firewall_tunnels(target, target_revisions, FirewallSubjects::Exact)?
        };
        let final_mode = if generation_kind == HelperPolicyGeneration::Compensation
            && policy.required_blocking
        {
            KillSwitchMode::AlwaysOn
        } else {
            target.kill_switch
        };
        let final_subjects = if final_mode == KillSwitchMode::AlwaysOn {
            FirewallSubjects::VpnOnly {
                retained_state: prior,
                retained_revisions: initial_revisions,
            }
        } else {
            FirewallSubjects::Exact
        };
        let target_tunnels = firewall_tunnels(target, target_revisions, final_subjects)?;
        let (routes_payload, redirects_payload) = route_payload(target, target_revisions)?;
        let dns_payload = dns_payload(target, target_revisions)?;
        Ok(Self {
            generation,
            firewall: topology_resource(policy, generation, ResourceKind::Firewall)?,
            routes: topology_resource(policy, generation, ResourceKind::Routes)?,
            dns: topology_resource(policy, generation, ResourceKind::Dns)?,
            initial_tunnels,
            target_tunnels,
            routes_payload,
            redirects_payload,
            dns_payload,
            initial_blocks: policy.required_blocking,
            final_mode,
        })
    }

    fn initial_operation(&self) -> NetworkPolicyOperation {
        if self.initial_blocks {
            NetworkPolicyOperation::EstablishBlocking {
                policy: self.firewall.clone(),
                tunnels: self.initial_tunnels.clone(),
            }
        } else {
            NetworkPolicyOperation::EstablishFirewall {
                policy: self.firewall.clone(),
                mode: self.final_mode,
                tunnels: self.initial_tunnels.clone(),
            }
        }
    }

    const fn initial_phase(&self) -> PolicyPhase {
        if self.initial_blocks {
            PolicyPhase::Blocking
        } else {
            PolicyPhase::FirewallBaseline
        }
    }

    fn routes_operation(&self, predecessor: PolicyPredecessor) -> NetworkPolicyOperation {
        NetworkPolicyOperation::ApplyRoutes {
            policy: self.routes.clone(),
            routes: self.routes_payload.clone(),
            redirects: self.redirects_payload.clone(),
            predecessor,
        }
    }

    fn dns_operation(&self, predecessor: PolicyPredecessor) -> NetworkPolicyOperation {
        NetworkPolicyOperation::ApplyDns {
            policy: self.dns.clone(),
            assignments: self.dns_payload.clone(),
            predecessor,
        }
    }

    fn final_firewall_operation(&self, predecessor: PolicyPredecessor) -> NetworkPolicyOperation {
        NetworkPolicyOperation::ApplyFirewall {
            policy: self.firewall.clone(),
            mode: self.final_mode,
            tunnels: self.target_tunnels.clone(),
            predecessor,
        }
    }

    fn final_projection(&self) -> PolicyProjection {
        PolicyProjection::Firewall {
            policy: self.firewall.clone(),
            mode: self.final_mode,
            tunnels: self.target_tunnels.clone(),
        }
    }

    fn projection_for_phase(
        &self,
        phase: PolicyPhase,
    ) -> Result<PolicyProjection, HelperPolicyPlanError> {
        let initial_operation = self.initial_operation();
        let initial = PolicyProjection::from_mutation(&initial_operation, None)
            .map_err(|_| HelperPolicyPlanError::InvalidInput)?
            .ok_or(HelperPolicyPlanError::InvalidInput)?;
        match phase {
            PolicyPhase::FirewallBaseline | PolicyPhase::Blocking => Ok(initial),
            PolicyPhase::Routes => {
                let predecessor = PolicyPredecessor::settled(initial.digest(), initial.phase())
                    .map_err(|_| HelperPolicyPlanError::InvalidInput)?;
                PolicyProjection::from_mutation(&self.routes_operation(predecessor), Some(&initial))
                    .map_err(|_| HelperPolicyPlanError::InvalidInput)?
                    .ok_or(HelperPolicyPlanError::InvalidInput)
            }
            PolicyPhase::Dns => {
                let routes = self.projection_for_phase(PolicyPhase::Routes)?;
                let predecessor = PolicyPredecessor::settled(routes.digest(), routes.phase())
                    .map_err(|_| HelperPolicyPlanError::InvalidInput)?;
                PolicyProjection::from_mutation(&self.dns_operation(predecessor), None)
                    .map_err(|_| HelperPolicyPlanError::InvalidInput)?
                    .ok_or(HelperPolicyPlanError::InvalidInput)
            }
            PolicyPhase::Firewall | PolicyPhase::Released => Ok(self.final_projection()),
        }
    }
}

fn topology_resource(
    policy: &TopologyPolicy,
    generation: u64,
    kind: ResourceKind,
) -> Result<ResourceTag, HelperPolicyPlanError> {
    ResourceTag::topology(policy.authority_epoch, generation, kind)
        .map_err(|_| HelperPolicyPlanError::InvalidInput)
}

fn validate_revision_authority(
    policy: &TopologyPolicy,
    revisions: &BTreeMap<ProfileId, TunnelRevision>,
) -> Result<(), HelperPolicyPlanError> {
    if revisions.values().any(|revision| {
        revision.authority_epoch != policy.authority_epoch || revision.generation == 0
    }) {
        Err(HelperPolicyPlanError::TunnelOwnership)
    } else {
        Ok(())
    }
}

fn tunnel_resource(
    profile: &ProfileId,
    revisions: &BTreeMap<ProfileId, TunnelRevision>,
) -> Result<ResourceTag, HelperPolicyPlanError> {
    let revision = revisions
        .get(profile)
        .ok_or(HelperPolicyPlanError::TunnelOwnership)?;
    ResourceTag::tunnel(profile.clone(), revision.generation)
        .map_err(|_| HelperPolicyPlanError::TunnelOwnership)
}

fn route_cidrs(state: &TopologyState, profile: &ProfileId) -> Vec<Cidr> {
    state
        .routes
        .get(profile)
        .into_iter()
        .flatten()
        .filter_map(|claim| Cidr::new(claim.network(), claim.prefix_len()))
        .collect()
}

fn firewall_role(state: &TopologyState, profile: &ProfileId) -> PrivilegedFirewallRole {
    if state
        .routes
        .get(profile)
        .is_some_and(|routes| routes.iter().any(|route| route.is_default()))
    {
        PrivilegedFirewallRole::Primary
    } else {
        PrivilegedFirewallRole::Secondary
    }
}

fn firewall_subject(
    state: &TopologyState,
    profile: &ProfileId,
    resource: ResourceTag,
    role: PrivilegedFirewallRole,
) -> Result<PrivilegedFirewallTunnel, HelperPolicyPlanError> {
    PrivilegedFirewallTunnel::new(
        resource,
        state
            .server_ips
            .get(profile)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect(),
        route_cidrs(state, profile),
        role,
    )
    .map_err(|_| HelperPolicyPlanError::InvalidInput)
}

fn pre_block_tunnels(
    prior: &TopologyState,
    target: &TopologyState,
    prior_revisions: &BTreeMap<ProfileId, TunnelRevision>,
    target_revisions: &BTreeMap<ProfileId, TunnelRevision>,
) -> Result<Vec<PrivilegedFirewallTunnel>, HelperPolicyPlanError> {
    let mut subjects = Vec::new();
    for profile in &prior.profiles {
        let resource = tunnel_resource(profile, prior_revisions)?;
        let same_target_resource = target_revisions
            .get(profile)
            .zip(prior_revisions.get(profile))
            .is_some_and(|(target, prior)| target.generation == prior.generation);
        if same_target_resource {
            let endpoints = prior
                .server_ips
                .get(profile)
                .into_iter()
                .flatten()
                .chain(target.server_ips.get(profile).into_iter().flatten())
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            subjects.push(
                PrivilegedFirewallTunnel::new(
                    resource,
                    endpoints,
                    route_cidrs(prior, profile),
                    firewall_role(prior, profile),
                )
                .map_err(|_| HelperPolicyPlanError::InvalidInput)?,
            );
        } else {
            subjects.push(firewall_subject(
                prior,
                profile,
                resource,
                firewall_role(prior, profile),
            )?);
        }
    }
    for profile in &target.profiles {
        let target_resource = tunnel_resource(profile, target_revisions)?;
        let already_active = prior_revisions.get(profile).is_some_and(|prior_revision| {
            prior_revision.generation
                == target_revisions
                    .get(profile)
                    .expect("target resource was validated")
                    .generation
        });
        if !already_active {
            subjects.push(firewall_subject(
                target,
                profile,
                target_resource,
                PrivilegedFirewallRole::PendingEndpoint,
            )?);
        }
    }
    Ok(subjects)
}

#[derive(Clone, Copy)]
enum FirewallSubjects<'a> {
    Exact,
    VpnOnly {
        retained_state: &'a TopologyState,
        retained_revisions: &'a BTreeMap<ProfileId, TunnelRevision>,
    },
}

fn firewall_tunnels(
    state: &TopologyState,
    revisions: &BTreeMap<ProfileId, TunnelRevision>,
    mode: FirewallSubjects<'_>,
) -> Result<Vec<PrivilegedFirewallTunnel>, HelperPolicyPlanError> {
    let mut subjects = Vec::new();
    let mut endpoints = BTreeSet::new();
    for profile in &state.profiles {
        let subject = firewall_subject(
            state,
            profile,
            tunnel_resource(profile, revisions)?,
            firewall_role(state, profile),
        )?;
        if matches!(mode, FirewallSubjects::VpnOnly { .. }) && subject.endpoint_ips().is_empty() {
            return Err(HelperPolicyPlanError::InvalidInput);
        }
        endpoints.extend(subject.endpoint_ips().iter().copied());
        subjects.push(subject);
    }
    if let FirewallSubjects::VpnOnly {
        retained_state,
        retained_revisions,
    } = mode
    {
        for profile in retained_state.profiles.difference(&state.profiles) {
            let retained = retained_state
                .server_ips
                .get(profile)
                .into_iter()
                .flatten()
                .copied()
                .filter(|endpoint| endpoints.insert(*endpoint))
                .collect::<Vec<_>>();
            if !retained.is_empty() {
                let revision = retained_revisions
                    .get(profile)
                    .ok_or(HelperPolicyPlanError::TunnelOwnership)?;
                let resource = ResourceTag::tunnel(profile.clone(), revision.generation)
                    .map_err(|_| HelperPolicyPlanError::TunnelOwnership)?;
                subjects.push(
                    PrivilegedFirewallTunnel::new(
                        resource,
                        retained,
                        Vec::new(),
                        PrivilegedFirewallRole::PendingEndpoint,
                    )
                    .map_err(|_| HelperPolicyPlanError::InvalidInput)?,
                );
            }
        }
    }
    Ok(subjects)
}

fn route_payload(
    state: &TopologyState,
    revisions: &BTreeMap<ProfileId, TunnelRevision>,
) -> Result<(Vec<ScopedRoute>, Vec<ScopedOpenVpnRedirect>), HelperPolicyPlanError> {
    let mut routes = Vec::new();
    let mut redirects = Vec::new();
    for profile in &state.profiles {
        let resource = tunnel_resource(profile, revisions)?;
        match state.protocols.get(profile) {
            Some(ProtocolKind::WireGuard) => {
                for claim in state.routes.get(profile).into_iter().flatten() {
                    let destination = Cidr::new(claim.network(), claim.prefix_len())
                        .ok_or(HelperPolicyPlanError::InvalidInput)?;
                    routes.push(
                        ScopedRoute::new(destination, resource.clone())
                            .map_err(|_| HelperPolicyPlanError::InvalidInput)?,
                    );
                }
            }
            Some(ProtocolKind::OpenVpn) => {
                let evidence = state
                    .openvpn_routes
                    .get(profile)
                    .ok_or(HelperPolicyPlanError::RouteMutationUnavailable)?;
                let route_defaults = OpenVpnRouteDefaults::merged(
                    evidence.configured().route_defaults(),
                    evidence.pushed().route_defaults(),
                );
                for (set, origin) in [
                    (evidence.configured(), ScopedRouteOrigin::OpenVpnConfigured),
                    (evidence.pushed(), ScopedRouteOrigin::OpenVpnPushed),
                ] {
                    routes.extend(
                        set.routes()
                            .iter()
                            .copied()
                            .map(|route| {
                                if route.gateway() == OpenVpnRouteGateway::RemoteHost {
                                    ScopedRoute::openvpn_with_selected_remote(
                                        route,
                                        resource.clone(),
                                        origin,
                                        route_defaults,
                                        evidence.selected_remote().ok_or(
                                            crate::vortix_core::privileged::OperationError::ResourceScopeMismatch,
                                        )?,
                                    )
                                } else {
                                    ScopedRoute::openvpn(
                                        route,
                                        resource.clone(),
                                        origin,
                                        route_defaults,
                                    )
                                }
                            })
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(|_| HelperPolicyPlanError::InvalidInput)?,
                    );
                    if let Some(redirect) = set.redirect_gateway() {
                        redirects.push(
                            ScopedOpenVpnRedirect::new(
                                resource.clone(),
                                redirect.clone(),
                                origin,
                                route_defaults,
                            )
                            .map_err(|_| HelperPolicyPlanError::InvalidInput)?,
                        );
                    }
                }
            }
            None => return Err(HelperPolicyPlanError::InvalidInput),
        }
    }
    Ok((routes, redirects))
}

fn dns_payload(
    state: &TopologyState,
    revisions: &BTreeMap<ProfileId, TunnelRevision>,
) -> Result<Vec<PrivilegedDnsAssignment>, HelperPolicyPlanError> {
    let mut assignments = Vec::new();
    for profile in &state.profiles {
        let Some(request) = state
            .dns_requests
            .get(profile)
            .filter(|request| !request.is_empty())
        else {
            continue;
        };
        assignments.push(dns_assignment(
            request,
            tunnel_resource(profile, revisions)?,
            firewall_role(state, profile),
        )?);
    }
    Ok(assignments)
}

fn dns_assignment(
    request: &DnsRequest,
    tunnel: ResourceTag,
    role: PrivilegedFirewallRole,
) -> Result<PrivilegedDnsAssignment, HelperPolicyPlanError> {
    let search_domains = request
        .search_domains
        .iter()
        .map(DnsHostname::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| HelperPolicyPlanError::InvalidInput)?;
    let scope = match role {
        PrivilegedFirewallRole::Primary => PrivilegedDnsScope::CatchAll,
        PrivilegedFirewallRole::Secondary if search_domains.is_empty() => {
            PrivilegedDnsScope::Suppressed
        }
        PrivilegedFirewallRole::Secondary => PrivilegedDnsScope::Scoped {
            domains: search_domains.clone(),
        },
        PrivilegedFirewallRole::PendingEndpoint => {
            return Err(HelperPolicyPlanError::InvalidInput);
        }
    };
    PrivilegedDnsAssignment::new(tunnel, request.servers.clone(), search_domains, scope)
        .map_err(|_| HelperPolicyPlanError::InvalidInput)
}

fn required_inventory(
    session: &dyn HelperPolicySession,
) -> Result<HelperPolicyInventory, HelperPolicyPlanError> {
    session
        .inventory()
        .ok_or(HelperPolicyPlanError::HelperUnavailable)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InventoryProjectionStatus {
    Other,
    Pending(PolicyPredecessor),
    Observed(PolicyPredecessor),
}

fn authenticated_settled_predecessor(
    inventory: &HelperPolicyInventory,
    projection: &PolicyProjection,
) -> Result<PolicyPredecessor, HelperPolicyPlanError> {
    match classify_projection(inventory, projection, projection.phase(), None)? {
        InventoryProjectionStatus::Observed(predecessor) => Ok(predecessor),
        InventoryProjectionStatus::Other | InventoryProjectionStatus::Pending(_) => {
            Err(HelperPolicyPlanError::HelperUnavailable)
        }
    }
}

fn classify_projection(
    inventory: &HelperPolicyInventory,
    projection: &PolicyProjection,
    expected_phase: PolicyPhase,
    pending_effective: Option<crate::vortix_core::privileged::PolicyDigest>,
) -> Result<InventoryProjectionStatus, HelperPolicyPlanError> {
    if inventory.current() != Some(projection.policy()) {
        return Ok(InventoryProjectionStatus::Other);
    }
    let predecessor = inventory
        .predecessor()
        .ok_or(HelperPolicyPlanError::HelperUnavailable)?;
    let entry = inventory
        .resources()
        .iter()
        .find(|entry| entry.resource() == projection.policy())
        .ok_or(HelperPolicyPlanError::HelperUnavailable)?;
    if predecessor.phase() != expected_phase || entry.intended() != projection.digest() {
        return Err(HelperPolicyPlanError::HelperUnavailable);
    }
    if predecessor.observed()
        && entry.state() == HelperResourceState::Owned
        && entry.effective() == Some(projection.digest())
    {
        Ok(InventoryProjectionStatus::Observed(predecessor))
    } else if !predecessor.observed()
        && entry.state() == HelperResourceState::PendingEffect
        && entry.effective() == pending_effective
    {
        Ok(InventoryProjectionStatus::Pending(predecessor))
    } else {
        Err(HelperPolicyPlanError::HelperUnavailable)
    }
}

fn ensure_mutation_pending(
    session: &mut dyn HelperPolicySession,
    operation: &NetworkPolicyOperation,
    projection: &PolicyProjection,
    pending_effective: Option<crate::vortix_core::privileged::PolicyDigest>,
    inventory: Option<HelperPolicyInventory>,
    deadline: Instant,
    allow_mutation: bool,
) -> Result<(), HelperPolicyPlanError> {
    let policy = operation.policy_resource();
    let inventory = match inventory {
        Some(inventory) => inventory,
        None => required_inventory(session)?,
    };
    match classify_projection(
        &inventory,
        projection,
        projection.phase(),
        pending_effective,
    )? {
        InventoryProjectionStatus::Pending(_) | InventoryProjectionStatus::Observed(_) => {
            return Ok(());
        }
        InventoryProjectionStatus::Other => {}
    }
    if !allow_mutation || !operation_can_follow_inventory(operation, &inventory) {
        return Err(HelperPolicyPlanError::OutcomeUnknown);
    }
    let mutation = execute_policy_operation(session, operation.clone(), deadline)?;
    if mutation.receipt().owns(policy) {
        Ok(())
    } else {
        Err(HelperPolicyPlanError::HelperUnavailable)
    }
}

fn ensure_mutation_observed(
    session: &mut dyn HelperPolicySession,
    operation: &NetworkPolicyOperation,
    projection: &PolicyProjection,
    pending_effective: Option<crate::vortix_core::privileged::PolicyDigest>,
    inventory: Option<HelperPolicyInventory>,
    deadline: Instant,
    allow_mutation: bool,
) -> Result<(), HelperPolicyPlanError> {
    let policy = operation.policy_resource().clone();
    let inventory = match inventory {
        Some(inventory) => inventory,
        None => required_inventory(session)?,
    };
    match classify_projection(
        &inventory,
        projection,
        projection.phase(),
        pending_effective,
    )? {
        InventoryProjectionStatus::Observed(_) => return Ok(()),
        InventoryProjectionStatus::Pending(predecessor) => {
            return execute_observation(
                session,
                &policy,
                predecessor,
                projection.expected_observation_state(),
                deadline,
            );
        }
        InventoryProjectionStatus::Other => {}
    }
    if !allow_mutation || !operation_can_follow_inventory(operation, &inventory) {
        return Err(HelperPolicyPlanError::OutcomeUnknown);
    }
    let mutation = execute_policy_operation(session, operation.clone(), deadline)?;
    if !mutation.receipt().owns(&policy) {
        return Err(HelperPolicyPlanError::HelperUnavailable);
    }
    let predecessor = PolicyPredecessor::pending(
        crate::vortix_core::privileged::PolicyDigest::of(operation),
        projection.phase(),
    )
    .map_err(|_| HelperPolicyPlanError::InvalidInput)?;
    execute_observation(
        session,
        &policy,
        predecessor,
        projection.expected_observation_state(),
        deadline,
    )
}

fn operation_can_follow_inventory(
    operation: &NetworkPolicyOperation,
    inventory: &HelperPolicyInventory,
) -> bool {
    match operation.predecessor() {
        None => match inventory.current() {
            None => inventory.resources().is_empty(),
            Some(current) => {
                inventory
                    .predecessor()
                    .is_some_and(PolicyPredecessor::observed)
                    && current.generation() < operation.policy_resource().generation()
            }
        },
        Some(expected) => {
            inventory.predecessor() == Some(expected)
                && inventory.current() != Some(operation.policy_resource())
        }
    }
}

fn execute_observation(
    session: &mut dyn HelperPolicySession,
    policy: &ResourceTag,
    predecessor: PolicyPredecessor,
    expected_state: ObservationState,
    deadline: Instant,
) -> Result<(), HelperPolicyPlanError> {
    let operation = NetworkPolicyOperation::ObserveBarrier {
        policy: policy.clone(),
        predecessor,
    };
    let outcome = execute_policy_operation(session, operation, deadline)?;
    if outcome.receipt().observes(policy, expected_state) {
        Ok(())
    } else {
        Err(HelperPolicyPlanError::HelperUnavailable)
    }
}

fn release_operation(
    inventory: &HelperPolicyInventory,
    retained: &PolicyProjection,
) -> Result<Option<NetworkPolicyOperation>, HelperPolicyPlanError> {
    let current = retained.policy();
    let predecessor = inventory
        .predecessor()
        .ok_or(HelperPolicyPlanError::HelperUnavailable)?;
    let retained_entry = inventory
        .resources()
        .iter()
        .find(|entry| entry.resource() == current)
        .ok_or(HelperPolicyPlanError::HelperUnavailable)?;
    let is_observed_final = predecessor.observed() && predecessor.phase() == retained.phase();
    let is_completed_release =
        predecessor.observed() && predecessor.phase() == PolicyPhase::Released;
    let is_pending_release =
        !predecessor.observed() && predecessor.phase() == PolicyPhase::Released;
    if inventory.current() != Some(current)
        || (!is_observed_final && !is_pending_release && !is_completed_release)
        || retained_entry.state() != HelperResourceState::Owned
        || retained_entry.intended() != retained.digest()
        || retained_entry.effective() != Some(retained.digest())
    {
        return Err(HelperPolicyPlanError::HelperUnavailable);
    }
    let resources = inventory
        .resources()
        .iter()
        .map(crate::helper::HelperPolicyResource::resource)
        .filter(|resource| {
            resource.authority_epoch() == current.authority_epoch()
                && resource.generation() < current.generation()
        })
        .cloned()
        .collect::<Vec<_>>();
    if resources.is_empty() {
        return Ok(None);
    }
    let retained_state = retained.expected_observation_state();
    Ok(Some(NetworkPolicyOperation::ReleaseObsolete {
        policy: current.clone(),
        resources,
        predecessor,
        retained_state,
    }))
}

fn execute_release(
    session: &mut dyn HelperPolicySession,
    operation: &NetworkPolicyOperation,
    deadline: Instant,
) -> Result<(), HelperPolicyPlanError> {
    let NetworkPolicyOperation::ReleaseObsolete {
        policy,
        resources,
        retained_state,
        ..
    } = operation
    else {
        return Err(HelperPolicyPlanError::InvalidInput);
    };
    let outcome = execute_policy_operation(session, operation.clone(), deadline)?;
    if !outcome.receipt().observes(policy, *retained_state)
        || resources.iter().any(|resource| {
            !outcome
                .receipt()
                .observes(resource, ObservationState::Absent)
        })
    {
        return Err(HelperPolicyPlanError::HelperUnavailable);
    }
    Ok(())
}

fn inventory_proves_release(
    inventory: &HelperPolicyInventory,
    retained: &PolicyProjection,
    obsolete: &[ResourceTag],
) -> bool {
    matches!(
        classify_projection(inventory, retained, PolicyPhase::Released, None),
        Ok(InventoryProjectionStatus::Observed(_))
    ) && obsolete.iter().all(|resource| {
        !inventory
            .resources()
            .iter()
            .any(|entry| entry.resource() == resource)
    })
}

fn inventory_proves_release_pending(
    inventory: &HelperPolicyInventory,
    retained: &PolicyProjection,
    obsolete: &[ResourceTag],
) -> bool {
    inventory.current() == Some(retained.policy())
        && inventory.predecessor().is_some_and(|predecessor| {
            !predecessor.observed() && predecessor.phase() == PolicyPhase::Released
        })
        && inventory.resources().iter().any(|entry| {
            entry.resource() == retained.policy()
                && entry.state() == HelperResourceState::Owned
                && entry.intended() == retained.digest()
                && entry.effective() == Some(retained.digest())
        })
        && obsolete.iter().all(|resource| {
            inventory.resources().iter().any(|entry| {
                entry.resource() == resource && entry.state() == HelperResourceState::PendingRelease
            })
        })
}

fn execute_policy_operation(
    session: &mut dyn HelperPolicySession,
    operation: NetworkPolicyOperation,
    deadline: Instant,
) -> Result<AuthenticatedHelperOutcome, HelperPolicyPlanError> {
    if Instant::now() >= deadline {
        return Err(HelperPolicyPlanError::HelperUnavailable);
    }
    execute_helper_operation(
        session,
        PrivilegedOperation::NetworkPolicy(operation),
        deadline,
    )
}

fn execute_helper_operation(
    session: &mut dyn HelperPolicySession,
    exact: PrivilegedOperation,
    deadline: Instant,
) -> Result<AuthenticatedHelperOutcome, HelperPolicyPlanError> {
    let outcome = session
        .execute_bound(exact, &[], deadline)
        .map_err(|failure| match failure {
            HelperPolicyTransportFailure::OutcomeUnknown => HelperPolicyPlanError::OutcomeUnknown,
            HelperPolicyTransportFailure::Unavailable => HelperPolicyPlanError::HelperUnavailable,
        })?;
    if outcome.receipt().rejection_code().is_some() {
        return Err(HelperPolicyPlanError::HelperUnavailable);
    }
    if outcome.receipt().is_ambiguous() {
        return Err(HelperPolicyPlanError::OutcomeUnknown);
    }
    Ok(outcome)
}

impl PolicyExecutor for HelperBackedPolicyExecutor {
    fn apply(&self, policy: &TopologyPolicy, barrier: PolicyBarrier) -> Result<(), String> {
        self.update_readback(policy, |_| {});
        if barrier == PolicyBarrier::Tunnel {
            self.verify_tunnel_projection(policy)
                .map_err(|error| error.to_string())?;
            self.update_readback(policy, |evidence| evidence.interface_verified = true);
            return Ok(());
        }
        let plan = self
            .forward_plan(policy)
            .map_err(|error| error.to_string())?;
        match barrier {
            PolicyBarrier::Blocking => {
                self.apply_initial(policy, &plan)
                    .map_err(|error| error.to_string())?;
            }
            PolicyBarrier::Tunnel => unreachable!("tunnel barrier returned before policy planning"),
            PolicyBarrier::Route => {
                self.apply_routes(policy, &plan)
                    .map_err(|error| error.to_string())?;
            }
            PolicyBarrier::Dns => {
                self.apply_dns(policy, &plan)
                    .map_err(|error| error.to_string())?;
            }
            PolicyBarrier::Observation => {
                self.observe_dns(policy, &plan)
                    .map_err(|error| error.to_string())?;
            }
            PolicyBarrier::EffectivePublication => {
                self.apply_final_firewall(policy, &plan)
                    .map_err(|error| error.to_string())?;
                self.audit_final_publication(policy, &plan)
                    .map_err(|error| error.to_string())?;
                let observed_at_millis = crate::utils::boot_elapsed_millis().ok_or_else(|| {
                    "OS boot clock is unavailable for policy evidence".to_string()
                })?;
                self.update_readback(policy, |evidence| {
                    evidence.interface_verified = true;
                    evidence.route_verified = true;
                    evidence.dns_verified = true;
                    evidence.firewall_verified = true;
                    evidence.observed_at_millis = observed_at_millis;
                });
            }
        }
        Ok(())
    }

    fn compensate(&self, policy: &TopologyPolicy, barrier: PolicyBarrier) -> Result<(), String> {
        match barrier {
            PolicyBarrier::Tunnel | PolicyBarrier::Observation => Ok(()),
            PolicyBarrier::Blocking
            | PolicyBarrier::Route
            | PolicyBarrier::Dns
            | PolicyBarrier::EffectivePublication => {
                let mut compensation = policy.clone();
                compensation.deadline = Instant::now()
                    .checked_add(POLICY_COMPENSATION_TIMEOUT)
                    .ok_or_else(|| "helper policy compensation deadline overflow".to_string())?;
                let plan = HelperPolicyPlan::compensation(&compensation)
                    .map_err(|error| error.to_string())?;
                self.restore_complete(&compensation, &plan)
                    .map_err(|error| error.to_string())
            }
        }
    }

    fn audit(&self, policy: &TopologyPolicy) -> Result<PolicyExecutionEvidence, String> {
        if policy.stage != PolicyStage::Final {
            return Err("only a final topology policy can be audited".into());
        }
        self.update_readback(policy, |_| {});
        let plan = self
            .forward_plan(policy)
            .map_err(|error| error.to_string())?;
        self.audit_final_publication(policy, &plan)
            .map_err(|error| error.to_string())?;
        let observed_at_millis = crate::utils::boot_elapsed_millis()
            .ok_or_else(|| "OS boot clock is unavailable for policy evidence".to_string())?;
        Ok(PolicyExecutionEvidence {
            observed_at_millis,
            interface_verified: true,
            route_verified: true,
            dns_verified: true,
            firewall_verified: true,
        })
    }

    fn verification(&self, policy: &TopologyPolicy) -> Option<PolicyExecutionEvidence> {
        let readback = self.readback.lock().ok()?;
        let state = readback.as_ref()?;
        (state.key == Self::readback_key(policy)
            && state.evidence.interface_verified
            && state.evidence.route_verified
            && state.evidence.dns_verified
            && state.evidence.firewall_verified
            && state.evidence.observed_at_millis != 0)
            .then_some(state.evidence)
    }
}

#[cfg(test)]
#[path = "policy_executor_tests.rs"]
mod tests;
