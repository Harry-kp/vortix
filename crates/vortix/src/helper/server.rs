//! Enrolled helper execution core.
//!
//! U12 enables operation families here one at a time. Observation and tunnel
//! lifecycle are admitted, but no listener is enrolled until U13. Fresh
//! requests are persisted before an executor is entered; a failed ledger write
//! poisons the session fail-closed.

#![allow(
    dead_code,
    reason = "U12 execution slice remains unreachable until U13 enrollment gates it"
)]

use std::collections::{BTreeMap, BTreeSet};

use super::dns::RecoveredDnsState;
use crate::helper::material::TunnelMaterialSet;
use crate::helper::protocol::{
    capability_for_operation, minimum_schema_for_operation, negotiate_enrolled, HelperCapability,
    HelperClientHello, HelperError, HelperOp, HelperPolicyInventory, HelperPolicyResource,
    HelperReleasedInventory, HelperRequest, HelperResponse, HelperResult, RELEASE_ACK_SCHEMA_MIN,
};
use crate::vortix_core::privileged::{
    AmbiguousPhase, ChildOwner, ChildSpawnAuthority, HelperEpoch, HelperLedgerDns,
    HelperLedgerFirewall, HelperLedgerPhysicalOwnership, HelperLedgerPolicy, HelperLedgerRecord,
    HelperLedgerResource, HelperLedgerRoutes, HelperResourceState, NetworkPolicyOperation,
    ObservationState, ObservedChildIdentity, OperationAdmission, OperationError, OperationGuard,
    OwnedChild, PhysicalDnsStage, PhysicalFirewallStage, PhysicalRouteStage, PolicyPredecessor,
    PolicyProjection, PrivilegedOperation, ProtocolPlan, ReceiptError, ReceiptLedger,
    RejectionCode, ResourceKind, ResourceObservation, ResourceObservationTarget, ResourceTag,
    RootAuthorityLedger, VerifiedReceipt, MAX_RESOURCE_ITEMS,
};
use crate::vortix_core::profile::ProtocolKind;

const ENABLED_CAPABILITIES: [HelperCapability; 5] = [
    HelperCapability::Handshake,
    HelperCapability::Observe,
    HelperCapability::TunnelLifecycle,
    HelperCapability::NetworkPolicy,
    HelperCapability::CleanupOwned,
];

fn release_families(operation: &NetworkPolicyOperation) -> BTreeSet<ResourceKind> {
    let NetworkPolicyOperation::ReleaseObsolete {
        policy, resources, ..
    } = operation
    else {
        return BTreeSet::new();
    };
    std::iter::once(policy.kind())
        .chain(resources.iter().map(ResourceTag::kind))
        .collect()
}

/// Typed platform seam for read-back. Implementations may inspect only the
/// exact canonical resource identities supplied by the admitted request.
pub(crate) trait ObservationExecutor {
    fn observe(
        &mut self,
        targets: &[ResourceObservationTarget],
        scope: ObservationScope,
    ) -> Result<ObservationOutcome, ObservationError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObservationScope {
    External,
    Managed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleasedAcknowledgementMode {
    Fresh,
    ReplayDuplicate,
}

pub(crate) struct ObservationOutcome {
    observations: Vec<ResourceObservation>,
    child_observations: Vec<ObservedChildIdentity>,
}

impl ObservationOutcome {
    pub(crate) const fn new(
        observations: Vec<ResourceObservation>,
        child_observations: Vec<ObservedChildIdentity>,
    ) -> Self {
        Self {
            observations,
            child_observations,
        }
    }

    pub(crate) fn into_parts(self) -> (Vec<ResourceObservation>, Vec<ObservedChildIdentity>) {
        (self.observations, self.child_observations)
    }
}

fn child_observations_match_request(
    targets: &[ResourceObservationTarget],
    children: &[ObservedChildIdentity],
) -> bool {
    children.len() <= targets.len()
        && children.iter().enumerate().all(|(index, child)| {
            targets
                .iter()
                .any(|target| target.resource() == child.resource())
                && !children[..index]
                    .iter()
                    .any(|prior| prior.resource() == child.resource())
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObservationError {
    InvalidResource,
    Overloaded,
    Unavailable,
}

/// Typed protocol lifecycle seam. `WireGuard` returns exact interface evidence
/// after its bounded setup child has exited; `OpenVPN` returns OS-observed
/// foreground containment identity, not ownership. A successful stop must mean
/// the interface is absent and any contained process group is gone and reaped.
pub(crate) trait TunnelLifecycleExecutor {
    fn start_tunnel(
        &mut self,
        plan: &ProtocolPlan,
        materials: Option<TunnelMaterialSet>,
    ) -> Result<TunnelStartOutcome, PrivilegedExecutionError>;

    fn stop_tunnel(
        &mut self,
        tunnel: &ResourceTag,
        child: Option<&ObservedChildIdentity>,
    ) -> Result<ResourceObservation, PrivilegedExecutionError>;

    /// Contain a child whose returned identity cannot be claimed for the
    /// admitted request. Failure means the effect remains ambiguous.
    fn contain_unclaimed(
        &mut self,
        child: &ObservedChildIdentity,
    ) -> Result<(), PrivilegedExecutionError>;
}

/// Protocol-specific successful start evidence. `WireGuard` must leave no
/// long-lived setup child; `OpenVPN` must return a foreground containment
/// identity that the helper can claim.
pub(crate) enum TunnelStartOutcome {
    InterfaceApplied(ResourceObservation),
    ForegroundOwned(ObservedChildIdentity),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrivilegedExecutionError {
    InvalidPlan,
    Overloaded,
    FailedBeforeEffect,
    EffectMayHaveApplied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkPolicyPreparationError {
    InvalidPlan,
    FailedBeforeEffect,
}

impl From<NetworkPolicyPreparationError> for PrivilegedExecutionError {
    fn from(error: NetworkPolicyPreparationError) -> Self {
        match error {
            NetworkPolicyPreparationError::InvalidPlan => Self::InvalidPlan,
            NetworkPolicyPreparationError::FailedBeforeEffect => Self::FailedBeforeEffect,
        }
    }
}

/// Fully ledger-derived authority for one privileged network-policy call.
///
/// Executors never combine an untrusted operation with separately supplied
/// recovery state. The enrolled session validates and persists the operation,
/// then prepares this closed plan from its root-owned projection inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetworkPolicyExecutionPlan {
    operation: NetworkPolicyOperation,
    intended: PolicyProjection,
    prior_effective: Option<PolicyProjection>,
    release_families: BTreeSet<ResourceKind>,
    retained_effective: Vec<PolicyProjection>,
    obsolete_effective: Vec<PolicyProjection>,
    recovered_firewalls: Vec<HelperLedgerFirewall>,
    recovered_dns: Vec<HelperLedgerDns>,
    recovered_routes: Vec<HelperLedgerRoutes>,
}

impl NetworkPolicyExecutionPlan {
    pub(crate) const fn operation(&self) -> &NetworkPolicyOperation {
        &self.operation
    }

    pub(crate) const fn intended(&self) -> &PolicyProjection {
        &self.intended
    }

    pub(crate) const fn prior_effective(&self) -> Option<&PolicyProjection> {
        self.prior_effective.as_ref()
    }

    pub(crate) fn retained_effective(&self, kind: ResourceKind) -> Option<&PolicyProjection> {
        self.retained_effective
            .iter()
            .find(|projection| projection.policy().kind() == kind)
    }

    pub(crate) fn release_involves(&self, kind: ResourceKind) -> bool {
        self.release_families.contains(&kind)
    }

    #[cfg(test)]
    pub(crate) fn retained_effective_all(&self) -> &[PolicyProjection] {
        &self.retained_effective
    }

    pub(crate) fn release_family(
        &self,
        kind: ResourceKind,
    ) -> Option<(&PolicyProjection, Vec<&PolicyProjection>)> {
        let NetworkPolicyOperation::ReleaseObsolete { resources, .. } = &self.operation else {
            return None;
        };
        if !self.release_involves(kind) {
            return None;
        }
        let current = self.retained_effective(kind)?;
        let obsolete = self
            .obsolete_effective
            .iter()
            .filter(|projection| projection.policy().kind() == kind)
            .collect::<Vec<_>>();
        let family_resources = resources
            .iter()
            .filter(|resource| resource.kind() == kind)
            .collect::<Vec<_>>();
        (obsolete.len() == family_resources.len()
            && family_resources.iter().all(|resource| {
                obsolete
                    .iter()
                    .any(|projection| projection.policy() == *resource)
            }))
        .then_some((current, obsolete))
    }

    pub(crate) fn obsolete_effective(&self) -> &[PolicyProjection] {
        &self.obsolete_effective
    }

    pub(crate) fn recovered_firewalls(&self) -> &[HelperLedgerFirewall] {
        &self.recovered_firewalls
    }

    pub(crate) fn recovered_dns(&self) -> &[HelperLedgerDns] {
        &self.recovered_dns
    }

    pub(crate) fn recovered_routes(&self) -> &[HelperLedgerRoutes] {
        &self.recovered_routes
    }

    #[cfg(test)]
    pub(crate) fn release_for_test(
        operation: NetworkPolicyOperation,
        retained_effective: Vec<PolicyProjection>,
        obsolete_effective: Vec<PolicyProjection>,
        recovered_firewalls: Vec<HelperLedgerFirewall>,
        recovered_dns: Vec<HelperLedgerDns>,
    ) -> Self {
        let release_families = release_families(&operation);
        let intended = retained_effective
            .iter()
            .find(|projection| projection.policy() == operation.policy_resource())
            .expect("release test operation policy must be retained")
            .clone();
        Self {
            operation,
            intended,
            prior_effective: None,
            release_families,
            retained_effective,
            obsolete_effective,
            recovered_firewalls,
            recovered_dns,
            recovered_routes: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn mutation_for_test(
        operation: NetworkPolicyOperation,
        intended: PolicyProjection,
        prior_effective: Option<PolicyProjection>,
        recovered_routes: Vec<HelperLedgerRoutes>,
    ) -> Self {
        assert_eq!(operation.policy_resource(), intended.policy());
        Self {
            operation,
            intended,
            prior_effective,
            release_families: BTreeSet::new(),
            retained_effective: Vec::new(),
            obsolete_effective: Vec::new(),
            recovered_firewalls: Vec::new(),
            recovered_dns: Vec::new(),
            recovered_routes,
        }
    }
}

/// Exact logical context for one physical firewall record recovered from the
/// authenticated root ledger. Restart validation needs the payload—not only
/// its digest—to prove the recorded backend matches kernel state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecoveredFirewallState {
    physical: HelperLedgerFirewall,
    intended: PolicyProjection,
    effective: Option<PolicyProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecoveredRouteState {
    state: HelperResourceState,
    intended: PolicyProjection,
    effective: Option<PolicyProjection>,
    physical: Option<HelperLedgerRoutes>,
}

impl RecoveredRouteState {
    pub(crate) const fn new(
        state: HelperResourceState,
        intended: PolicyProjection,
        effective: Option<PolicyProjection>,
    ) -> Self {
        Self {
            state,
            intended,
            effective,
            physical: None,
        }
    }

    pub(crate) const fn with_physical(
        state: HelperResourceState,
        intended: PolicyProjection,
        effective: Option<PolicyProjection>,
        physical: HelperLedgerRoutes,
    ) -> Self {
        Self {
            state,
            intended,
            effective,
            physical: Some(physical),
        }
    }

    pub(crate) const fn state(&self) -> HelperResourceState {
        self.state
    }

    pub(crate) const fn intended(&self) -> &PolicyProjection {
        &self.intended
    }

    pub(crate) const fn effective(&self) -> Option<&PolicyProjection> {
        self.effective.as_ref()
    }

    pub(crate) const fn physical(&self) -> Option<&HelperLedgerRoutes> {
        self.physical.as_ref()
    }
}

impl RecoveredFirewallState {
    pub(crate) const fn physical(&self) -> &HelperLedgerFirewall {
        &self.physical
    }

    pub(crate) const fn intended(&self) -> &PolicyProjection {
        &self.intended
    }

    pub(crate) const fn effective(&self) -> Option<&PolicyProjection> {
        self.effective.as_ref()
    }
}

fn recovered_firewall_states(
    physical_firewalls: &[HelperLedgerFirewall],
    policy_projections: &[HelperLedgerPolicy],
) -> Result<Vec<RecoveredFirewallState>, OperationError> {
    physical_firewalls
        .iter()
        .map(|physical| {
            let policy = policy_projections
                .iter()
                .find(|policy| policy.resource() == physical.resource())
                .ok_or(OperationError::InvalidReplayState)?;
            Ok(RecoveredFirewallState {
                physical: physical.clone(),
                intended: policy.intended().clone(),
                effective: policy.effective().cloned(),
            })
        })
        .collect()
}

fn recovered_dns_states(
    physical_dns: &[HelperLedgerDns],
    resources: &[HelperLedgerResource],
    policy_projections: &[HelperLedgerPolicy],
) -> Vec<RecoveredDnsState> {
    policy_projections
        .iter()
        .filter(|policy| policy.resource().kind() == ResourceKind::Dns)
        .filter_map(|policy| {
            let state = resources
                .iter()
                .find(|resource| resource.resource() == policy.resource())
                .map(HelperLedgerResource::state)?;
            let physical = physical_dns
                .iter()
                .find(|physical| physical.resource() == policy.resource())
                .cloned();
            Some(physical.map_or_else(
                || {
                    RecoveredDnsState::new(
                        state,
                        policy.intended().clone(),
                        policy.effective().cloned(),
                    )
                },
                |physical| {
                    RecoveredDnsState::with_physical(
                        state,
                        policy.intended().clone(),
                        policy.effective().cloned(),
                        physical,
                    )
                },
            ))
        })
        .collect()
}

fn recovered_route_states(
    physical_routes: &[HelperLedgerRoutes],
    resources: &[HelperLedgerResource],
    policy_projections: &[HelperLedgerPolicy],
) -> Vec<RecoveredRouteState> {
    policy_projections
        .iter()
        .filter(|policy| policy.resource().kind() == ResourceKind::Routes)
        .filter_map(|policy| {
            let state = resources
                .iter()
                .find(|resource| resource.resource() == policy.resource())
                .map(HelperLedgerResource::state)?;
            let physical = physical_routes
                .iter()
                .find(|physical| physical.resource() == policy.resource())
                .cloned();
            Some(physical.map_or_else(
                || {
                    RecoveredRouteState::new(
                        state,
                        policy.intended().clone(),
                        policy.effective().cloned(),
                    )
                },
                |physical| {
                    RecoveredRouteState::with_physical(
                        state,
                        policy.intended().clone(),
                        policy.effective().cloned(),
                        physical,
                    )
                },
            ))
        })
        .collect()
}

/// Side-effect-free executor preparation result. The server validates this
/// against its closed logical plan, durably records physical ownership, then
/// alone permits the corresponding effect method to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedNetworkPolicyExecutionPlan {
    execution: NetworkPolicyExecutionPlan,
    prepared_firewalls: Vec<HelperLedgerFirewall>,
    prepared_dns: Vec<HelperLedgerDns>,
    prepared_routes: Vec<HelperLedgerRoutes>,
    route_writer: PreparedRouteWriter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreparedRouteWriter {
    ProtocolOwned,
    HelperOwned,
}

impl PreparedNetworkPolicyExecutionPlan {
    pub(crate) fn new(
        execution: NetworkPolicyExecutionPlan,
        prepared_firewalls: Vec<HelperLedgerFirewall>,
    ) -> Self {
        let prepared_routes = execution.recovered_routes.clone();
        Self {
            execution,
            prepared_firewalls,
            prepared_dns: Vec::new(),
            prepared_routes,
            route_writer: PreparedRouteWriter::ProtocolOwned,
        }
    }

    pub(crate) fn with_physical_ownership(
        execution: NetworkPolicyExecutionPlan,
        prepared_firewalls: Vec<HelperLedgerFirewall>,
        prepared_dns: Vec<HelperLedgerDns>,
    ) -> Self {
        let prepared_routes = execution.recovered_routes.clone();
        Self {
            execution,
            prepared_firewalls,
            prepared_dns,
            prepared_routes,
            route_writer: PreparedRouteWriter::ProtocolOwned,
        }
    }

    pub(crate) const fn with_complete_physical_ownership(
        execution: NetworkPolicyExecutionPlan,
        prepared_firewalls: Vec<HelperLedgerFirewall>,
        prepared_dns: Vec<HelperLedgerDns>,
        prepared_routes: Vec<HelperLedgerRoutes>,
    ) -> Self {
        Self {
            execution,
            prepared_firewalls,
            prepared_dns,
            prepared_routes,
            route_writer: PreparedRouteWriter::ProtocolOwned,
        }
    }

    pub(crate) const fn with_helper_owned_routes(
        execution: NetworkPolicyExecutionPlan,
        prepared_firewalls: Vec<HelperLedgerFirewall>,
        prepared_dns: Vec<HelperLedgerDns>,
        prepared_routes: Vec<HelperLedgerRoutes>,
    ) -> Self {
        Self {
            execution,
            prepared_firewalls,
            prepared_dns,
            prepared_routes,
            route_writer: PreparedRouteWriter::HelperOwned,
        }
    }

    pub(crate) const fn execution(&self) -> &NetworkPolicyExecutionPlan {
        &self.execution
    }

    pub(crate) fn prepared_firewalls(&self) -> &[HelperLedgerFirewall] {
        &self.prepared_firewalls
    }

    pub(crate) fn prepared_dns(&self) -> &[HelperLedgerDns] {
        &self.prepared_dns
    }

    pub(crate) fn prepared_routes(&self) -> &[HelperLedgerRoutes] {
        &self.prepared_routes
    }

    pub(crate) const fn route_writer(&self) -> PreparedRouteWriter {
        self.route_writer
    }

    fn into_parts(
        self,
    ) -> (
        NetworkPolicyExecutionPlan,
        Vec<HelperLedgerFirewall>,
        Vec<HelperLedgerDns>,
        Vec<HelperLedgerRoutes>,
        PreparedRouteWriter,
    ) {
        (
            self.execution,
            self.prepared_firewalls,
            self.prepared_dns,
            self.prepared_routes,
            self.route_writer,
        )
    }
}

/// Ordered platform-policy seam. The executor may report one applied mutation
/// phase or exact read-back observations for a barrier or release. The helper
/// derives receipt ownership from the admitted canonical operation.
pub(crate) trait NetworkPolicyExecutor {
    /// Validate recovered backend ownership against the current platform. No
    /// effects or backend selection may occur here.
    fn validate_recovered_firewalls(
        &mut self,
        firewalls: &[RecoveredFirewallState],
        policy_enabled: bool,
    ) -> Result<(), PrivilegedExecutionError>;

    fn validate_recovered_dns(
        &mut self,
        states: &[RecoveredDnsState],
        policy_enabled: bool,
    ) -> Result<(), PrivilegedExecutionError>;

    fn validate_recovered_routes(
        &mut self,
        states: &[RecoveredRouteState],
        policy_enabled: bool,
    ) -> Result<(), PrivilegedExecutionError>;

    /// Select or validate physical ownership without invoking an OS effect.
    /// A real adapter must audit the recorded backend and reject unexpected
    /// Vortix-owned state in every alternative backend before returning.
    fn prepare_network_policy(
        &mut self,
        plan: &NetworkPolicyExecutionPlan,
    ) -> Result<PreparedNetworkPolicyExecutionPlan, NetworkPolicyPreparationError>;

    fn execute_network_policy(
        &mut self,
        plan: &PreparedNetworkPolicyExecutionPlan,
    ) -> Result<NetworkPolicyOutcome, PrivilegedExecutionError>;
}

pub(crate) enum NetworkPolicyOutcome {
    Applied,
    Observed(Vec<ResourceObservation>),
}

/// Bounded recovery seam for resources already owned by this helper
/// incarnation. The server authenticates every resource before entry and
/// forgets ownership only after exact absence observations validate.
pub(crate) trait CleanupExecutor {
    fn cleanup_owned(
        &mut self,
        resources: &[ResourceTag],
        children: &[ObservedChildIdentity],
    ) -> Result<Vec<ResourceObservation>, PrivilegedExecutionError>;
}

/// Root-owned atomic persistence seam. A successful return means the replay
/// checkpoint has reached durable storage before an executor is entered.
pub(crate) trait HelperLedgerStore {
    fn persist(&mut self, ledger: &HelperLedgerRecord) -> Result<(), ()>;
}

enum ChildEvidence {
    Live(OwnedChild),
    Recovered(ObservedChildIdentity),
}

#[derive(Clone)]
struct PolicyRecoveryState {
    intended: PolicyProjection,
    effective: Option<PolicyProjection>,
}

impl ChildEvidence {
    const fn identity(&self) -> &ObservedChildIdentity {
        match self {
            Self::Live(child) => child.identity(),
            Self::Recovered(identity) => identity,
        }
    }
}

/// One authenticated helper connection. U13 will own construction after its
/// platform enrollment and peer-credential gates; there is deliberately no
/// public constructor from wire scalars.
pub(crate) struct EnrolledHelperSession<E, S> {
    root: RootAuthorityLedger,
    helper_epoch: HelperEpoch,
    guard: OperationGuard,
    receipts: ReceiptLedger,
    executor: E,
    ledger_store: S,
    resource_states: BTreeMap<ResourceTag, HelperResourceState>,
    policy_projections: BTreeMap<ResourceTag, PolicyRecoveryState>,
    physical_firewalls: BTreeMap<ResourceTag, HelperLedgerFirewall>,
    physical_dns: BTreeMap<ResourceTag, HelperLedgerDns>,
    physical_routes: BTreeMap<ResourceTag, HelperLedgerRoutes>,
    released_resources: BTreeSet<ResourceTag>,
    children: BTreeMap<ResourceTag, ChildEvidence>,
    last_receipt: Option<VerifiedReceipt>,
    enabled_capabilities: Vec<HelperCapability>,
    negotiated_schema: Option<u16>,
    handshaken: bool,
    poisoned: bool,
}

impl<E, S> EnrolledHelperSession<E, S>
where
    E: ObservationExecutor + TunnelLifecycleExecutor + NetworkPolicyExecutor + CleanupExecutor,
    S: HelperLedgerStore,
{
    pub(crate) fn resume(
        root: RootAuthorityLedger,
        helper_epoch: HelperEpoch,
        baseline: crate::vortix_core::privileged::ReplayBaseline,
        executor: E,
        ledger_store: S,
    ) -> Result<Self, OperationError> {
        Self::resume_restricted(
            root,
            helper_epoch,
            baseline,
            executor,
            ledger_store,
            ENABLED_CAPABILITIES.to_vec(),
        )
    }

    pub(crate) fn resume_restricted(
        root: RootAuthorityLedger,
        helper_epoch: HelperEpoch,
        baseline: crate::vortix_core::privileged::ReplayBaseline,
        executor: E,
        ledger_store: S,
        enabled_capabilities: Vec<HelperCapability>,
    ) -> Result<Self, OperationError> {
        let principal = root.principal();
        let guard = OperationGuard::resume(&principal, helper_epoch, baseline)?;
        let receipts =
            ReceiptLedger::new(&root, &principal).map_err(|_| OperationError::PrincipalMismatch)?;
        Ok(Self {
            root,
            helper_epoch,
            guard,
            receipts,
            executor,
            ledger_store,
            resource_states: BTreeMap::new(),
            policy_projections: BTreeMap::new(),
            physical_firewalls: BTreeMap::new(),
            physical_dns: BTreeMap::new(),
            physical_routes: BTreeMap::new(),
            released_resources: BTreeSet::new(),
            children: BTreeMap::new(),
            last_receipt: None,
            enabled_capabilities,
            negotiated_schema: None,
            handshaken: false,
            poisoned: false,
        })
    }

    /// Rebuilds only root-ledger-backed resource authority. Persisted child
    /// identities remain observation/containment evidence and are never
    /// converted into `OwnedChild` for the new helper incarnation.
    pub(crate) fn recover(
        root: RootAuthorityLedger,
        helper_epoch: HelperEpoch,
        ledger: HelperLedgerRecord,
        executor: E,
        ledger_store: S,
    ) -> Result<Self, OperationError> {
        Self::recover_restricted(
            root,
            helper_epoch,
            ledger,
            executor,
            ledger_store,
            ENABLED_CAPABILITIES.to_vec(),
        )
    }

    pub(crate) fn recover_restricted(
        root: RootAuthorityLedger,
        helper_epoch: HelperEpoch,
        ledger: HelperLedgerRecord,
        mut executor: E,
        ledger_store: S,
        enabled_capabilities: Vec<HelperCapability>,
    ) -> Result<Self, OperationError> {
        let principal = root.principal();
        let (
            replay,
            resources,
            policy_projections,
            physical_firewalls,
            physical_dns,
            physical_routes,
            released_resources,
            child_observations,
        ) = ledger.into_parts();
        let baseline = root.loaded_replay_baseline(&principal, replay)?;
        let recovered_firewall_states =
            recovered_firewall_states(&physical_firewalls, &policy_projections)?;
        let recovered_dns_states =
            recovered_dns_states(&physical_dns, &resources, &policy_projections);
        let recovered_route_states =
            recovered_route_states(&physical_routes, &resources, &policy_projections);
        let policy_enabled = enabled_capabilities.contains(&HelperCapability::NetworkPolicy);
        executor
            .validate_recovered_firewalls(&recovered_firewall_states, policy_enabled)
            .map_err(|_| OperationError::InvalidReplayState)?;
        executor
            .validate_recovered_dns(&recovered_dns_states, policy_enabled)
            .map_err(|_| OperationError::InvalidReplayState)?;
        executor
            .validate_recovered_routes(&recovered_route_states, policy_enabled)
            .map_err(|_| OperationError::InvalidReplayState)?;
        let mut session = Self::resume_restricted(
            root,
            helper_epoch,
            baseline,
            executor,
            ledger_store,
            enabled_capabilities,
        )?;
        for entry in resources {
            session
                .resource_states
                .insert(entry.resource().clone(), entry.state());
        }
        session.policy_projections = policy_projections
            .into_iter()
            .map(HelperLedgerPolicy::into_parts)
            .map(|(resource, intended, effective)| {
                (
                    resource,
                    PolicyRecoveryState {
                        intended,
                        effective,
                    },
                )
            })
            .collect();
        session.physical_firewalls = physical_firewalls
            .into_iter()
            .map(|firewall| (firewall.resource().clone(), firewall))
            .collect();
        session.physical_dns = physical_dns
            .into_iter()
            .map(|dns| (dns.resource().clone(), dns))
            .collect();
        session.physical_routes = physical_routes
            .into_iter()
            .map(|routes| (routes.resource().clone(), routes))
            .collect();
        session.released_resources = released_resources.into_iter().collect();
        session.children = child_observations
            .into_iter()
            .map(|identity| {
                (
                    identity.resource().clone(),
                    ChildEvidence::Recovered(identity),
                )
            })
            .collect();
        Ok(session)
    }

    pub(crate) fn handle(&mut self, request: HelperRequest) -> HelperResponse {
        self.handle_with_materials(request, None)
    }

    pub(crate) fn handle_with_materials(
        &mut self,
        request: HelperRequest,
        materials: Option<TunnelMaterialSet>,
    ) -> HelperResponse {
        let result = match request.op {
            HelperOp::Handshake(hello) => self.handshake(&hello).map(HelperResult::Handshake),
            HelperOp::Execute(operation) => self.execute(&operation, materials),
        };
        HelperResponse {
            id: request.id,
            result,
        }
    }

    fn handshake(
        &mut self,
        hello: &HelperClientHello,
    ) -> Result<crate::helper::HelperServerHello, HelperError> {
        if self.handshaken {
            return Err(HelperError::Malformed {
                reason: "helper connection already handshaken".into(),
            });
        }
        if hello.owner_uid != self.root.owner_uid()
            || !self.root.matches_service_claim(&hello.service)
        {
            return Err(HelperError::AuthenticationFailed);
        }
        let mut response = negotiate_enrolled(
            hello,
            self.root.authority_binding(),
            self.helper_epoch,
            self.guard
                .next_sequence()
                .map_err(|_| HelperError::LedgerUnavailable)?,
            &self.enabled_capabilities,
        )?;
        if response.schema >= 6
            && self
                .enabled_capabilities
                .contains(&HelperCapability::NetworkPolicy)
        {
            response.policy_inventory = Some(Box::new(self.policy_inventory()?));
        }
        if response.schema >= RELEASE_ACK_SCHEMA_MIN
            && self
                .enabled_capabilities
                .contains(&HelperCapability::Observe)
        {
            response.released_resources = Some(Box::new(
                HelperReleasedInventory::new(self.released_resources.iter().cloned().collect())
                    .map_err(|_| HelperError::LedgerUnavailable)?,
            ));
        }
        self.negotiated_schema = Some(response.schema);
        self.handshaken = true;
        Ok(response)
    }

    fn policy_inventory(&self) -> Result<HelperPolicyInventory, HelperError> {
        let resources = self
            .policy_projections
            .iter()
            .map(|(resource, projection)| {
                let state = self
                    .resource_states
                    .get(resource)
                    .copied()
                    .ok_or(HelperError::LedgerUnavailable)?;
                HelperPolicyResource::new(
                    resource.clone(),
                    state,
                    projection.intended.digest(),
                    projection.effective.as_ref().map(PolicyProjection::digest),
                )
                .map_err(|_| HelperError::LedgerUnavailable)
            })
            .collect::<Result<Vec<_>, _>>()?;
        HelperPolicyInventory::new(
            self.guard
                .policy_projection()
                .map(PolicyProjection::policy)
                .cloned(),
            self.guard.policy_predecessor(),
            resources,
        )
        .map_err(|_| HelperError::LedgerUnavailable)
    }

    fn execute(
        &mut self,
        request: &crate::vortix_core::privileged::PrivilegedRequest,
        materials: Option<TunnelMaterialSet>,
    ) -> Result<HelperResult, HelperError> {
        if !self.handshaken {
            return Err(HelperError::AuthenticationFailed);
        }
        if self.poisoned {
            return Err(HelperError::LedgerUnavailable);
        }
        if self
            .negotiated_schema
            .is_none_or(|schema| schema < minimum_schema_for_operation(request.operation()))
        {
            return Err(HelperError::Incompatible {
                reason: "operation requires a newer negotiated helper schema".into(),
            });
        }
        if !self
            .enabled_capabilities
            .contains(&capability_for_operation(request.operation()))
        {
            return Err(HelperError::CapabilityUnavailable {
                capability: capability_for_operation(request.operation()),
            });
        }

        let admission = self
            .guard
            .admit(request)
            .map_err(|error| map_operation_error(&error))?;
        if admission == OperationAdmission::Duplicate {
            return self.replay_duplicate(request);
        }

        // A later duplicate must never inherit the prior operation's receipt
        // if this fresh execution loses its terminal result.
        self.last_receipt = None;
        if let PrivilegedOperation::NetworkPolicy(operation) = request.operation() {
            if self.prepare_network_policy(operation, admission).is_err() {
                if !matches!(operation, NetworkPolicyOperation::ObserveBarrier { .. })
                    && admission != OperationAdmission::PendingReleaseContinuation
                {
                    self.guard
                        .rollback_policy_before_effect(request)
                        .map_err(|_| HelperError::LedgerUnavailable)?;
                }
                self.persist_ledger()?;
                let receipt = self
                    .receipts
                    .rejected(request, RejectionCode::InvalidResource)
                    .map_err(map_receipt_error)?;
                self.last_receipt = Some(receipt.clone());
                return receipt_result(receipt);
            }
        }
        if !matches!(
            request.operation(),
            PrivilegedOperation::StartTunnel(_)
                | PrivilegedOperation::StopTunnel(_)
                | PrivilegedOperation::NetworkPolicy(_)
                | PrivilegedOperation::CleanupOwned(_)
        ) {
            self.persist_ledger()?;
        }

        let receipt = match request.operation() {
            PrivilegedOperation::Observe(targets) => self.observe(request, targets),
            PrivilegedOperation::ObserveManaged(targets) => self.observe_managed(request, targets),
            PrivilegedOperation::ObserveManagedAbsence(targets) => {
                self.observe_managed_absence(request, targets)
            }
            PrivilegedOperation::AcknowledgeReleased(targets) => {
                self.acknowledge_released(request, targets, ReleasedAcknowledgementMode::Fresh)
            }
            PrivilegedOperation::AuditPolicy(policy) => self.audit_policy(request, policy),
            PrivilegedOperation::StartTunnel(plan) => self.start_tunnel(request, plan, materials),
            PrivilegedOperation::StopTunnel(resource) => self.stop_tunnel(request, resource),
            PrivilegedOperation::NetworkPolicy(operation) => {
                self.execute_network_policy(request, operation, admission)
            }
            PrivilegedOperation::CleanupOwned(resources) => self.cleanup_owned(request, resources),
        }?;
        self.last_receipt = Some(receipt.clone());
        receipt_result(receipt)
    }

    fn replay_duplicate(
        &mut self,
        request: &crate::vortix_core::privileged::PrivilegedRequest,
    ) -> Result<HelperResult, HelperError> {
        if self.last_receipt.is_none() {
            if let PrivilegedOperation::AcknowledgeReleased(targets) = request.operation() {
                let receipt = self.acknowledge_released(
                    request,
                    targets,
                    ReleasedAcknowledgementMode::ReplayDuplicate,
                )?;
                self.last_receipt = Some(receipt.clone());
                return receipt_result(receipt);
            }
        }
        let receipt = if let Some(receipt) = &self.last_receipt {
            receipt
                .validate_against(request, &self.root)
                .map_err(map_receipt_error)?;
            receipt.clone()
        } else {
            self.receipts
                .ambiguous(request, AmbiguousPhase::ReplyLost)
                .map_err(map_receipt_error)?
        };
        self.last_receipt = Some(receipt.clone());
        receipt_result(receipt)
    }

    fn prepare_network_policy(
        &mut self,
        operation: &NetworkPolicyOperation,
        admission: OperationAdmission,
    ) -> Result<(), ()> {
        let resource = operation.policy_resource().clone();
        if matches!(&operation, NetworkPolicyOperation::ApplyRoutes { .. })
            && self.guard.policy_projection().is_some_and(|projection| {
                projection.route_inputs().is_none_or(|(_, _, tunnels)| {
                    tunnels.iter().any(|tunnel| {
                        self.resource_states.get(tunnel.tunnel())
                            != Some(&HelperResourceState::Owned)
                    })
                })
            })
        {
            return Err(());
        }
        match operation {
            NetworkPolicyOperation::EstablishFirewall { .. }
            | NetworkPolicyOperation::EstablishBlocking { .. }
            | NetworkPolicyOperation::ApplyRoutes { .. }
            | NetworkPolicyOperation::ApplyDns { .. }
            | NetworkPolicyOperation::ApplyFirewall { .. } => {
                let projection = self
                    .guard
                    .policy_projection()
                    .filter(|projection| projection.policy() == &resource)
                    .cloned()
                    .ok_or(())?;
                self.policy_projections
                    .entry(resource.clone())
                    .and_modify(|state| state.intended.clone_from(&projection))
                    .or_insert(PolicyRecoveryState {
                        intended: projection,
                        effective: None,
                    });
                self.resource_states
                    .insert(resource, HelperResourceState::PendingEffect);
            }
            NetworkPolicyOperation::ObserveBarrier { .. } => {
                let projection = self.guard.policy_projection().ok_or(())?;
                if !matches!(
                    self.resource_states.get(&resource),
                    Some(HelperResourceState::PendingEffect | HelperResourceState::Owned)
                ) || self
                    .policy_projections
                    .get(&resource)
                    .is_none_or(|state| state.intended != *projection)
                {
                    return Err(());
                }
            }
            NetworkPolicyOperation::ReleaseObsolete { resources, .. } => {
                if self.resource_states.get(&resource) != Some(&HelperResourceState::Owned)
                    || resources.iter().any(|obsolete| {
                        self.resource_states.get(obsolete)
                            != Some(
                                &if admission == OperationAdmission::PendingReleaseContinuation {
                                    HelperResourceState::PendingRelease
                                } else {
                                    HelperResourceState::Owned
                                },
                            )
                            || !self.policy_projections.contains_key(obsolete)
                    })
                {
                    return Err(());
                }
                if admission != OperationAdmission::PendingReleaseContinuation {
                    for obsolete in resources {
                        self.resource_states
                            .insert(obsolete.clone(), HelperResourceState::PendingRelease);
                    }
                }
            }
        }
        Ok(())
    }

    fn observe(
        &mut self,
        request: &crate::vortix_core::privileged::PrivilegedRequest,
        targets: &[ResourceObservationTarget],
    ) -> Result<VerifiedReceipt, HelperError> {
        self.execute_observation(request, targets, ObservationScope::External, None)
    }

    fn execute_observation(
        &mut self,
        request: &crate::vortix_core::privileged::PrivilegedRequest,
        targets: &[ResourceObservationTarget],
        scope: ObservationScope,
        required_state: Option<ObservationState>,
    ) -> Result<VerifiedReceipt, HelperError> {
        let outcome = match self.executor.observe(targets, scope) {
            Ok(outcome) => outcome,
            Err(ObservationError::InvalidResource) => {
                return self
                    .receipts
                    .rejected(request, RejectionCode::InvalidResource)
                    .map_err(map_receipt_error);
            }
            Err(ObservationError::Overloaded) => {
                return self
                    .receipts
                    .rejected(request, RejectionCode::Overloaded)
                    .map_err(map_receipt_error);
            }
            Err(ObservationError::Unavailable) => {
                return self
                    .receipts
                    .rejected(request, RejectionCode::ExecutionFailed)
                    .map_err(map_receipt_error);
            }
        };
        if !child_observations_match_request(targets, &outcome.child_observations) {
            return self
                .receipts
                .rejected(request, RejectionCode::InvalidResource)
                .map_err(map_receipt_error);
        }
        if scope == ObservationScope::Managed
            && !managed_observation_evidence_matches(targets, &outcome.observations)
        {
            return self
                .receipts
                .rejected(request, RejectionCode::InvalidResource)
                .map_err(map_receipt_error);
        }
        if required_state.is_some_and(|required| {
            targets.iter().any(|target| {
                observation_state(&outcome.observations, target.resource()) != Some(required)
            })
        }) {
            return self
                .receipts
                .rejected(request, RejectionCode::InvalidResource)
                .map_err(map_receipt_error);
        }
        let receipt = self
            .receipts
            .observed(request, outcome.observations.clone())
            .map_err(map_receipt_error)?;
        if self.reconcile_recovery(&outcome) {
            self.persist_ledger()?;
        }
        Ok(receipt)
    }

    fn observe_managed(
        &mut self,
        request: &crate::vortix_core::privileged::PrivilegedRequest,
        targets: &[ResourceObservationTarget],
    ) -> Result<VerifiedReceipt, HelperError> {
        if !self.managed_observation_is_closed(targets) {
            return self
                .receipts
                .rejected(request, RejectionCode::InvalidResource)
                .map_err(map_receipt_error);
        }
        self.execute_observation(request, targets, ObservationScope::Managed, None)
    }

    fn observe_managed_absence(
        &mut self,
        request: &crate::vortix_core::privileged::PrivilegedRequest,
        targets: &[ResourceObservationTarget],
    ) -> Result<VerifiedReceipt, HelperError> {
        if !self.released_observation_is_closed(targets) {
            return self
                .receipts
                .rejected(request, RejectionCode::InvalidResource)
                .map_err(map_receipt_error);
        }
        self.execute_observation(
            request,
            targets,
            ObservationScope::Managed,
            Some(ObservationState::Absent),
        )
    }

    fn acknowledge_released(
        &mut self,
        request: &crate::vortix_core::privileged::PrivilegedRequest,
        targets: &[ResourceObservationTarget],
        mode: ReleasedAcknowledgementMode,
    ) -> Result<VerifiedReceipt, HelperError> {
        let requested = targets
            .iter()
            .map(ResourceObservationTarget::resource)
            .collect::<BTreeSet<_>>();
        let closed =
            managed_observation_is_closed(targets, |resource| requested.contains(resource));
        let retained = targets
            .iter()
            .all(|target| self.released_resources.contains(target.resource()));
        let already_collected = mode == ReleasedAcknowledgementMode::ReplayDuplicate
            && targets.iter().all(|target| {
                !self.released_resources.contains(target.resource())
                    && !self.resource_states.contains_key(target.resource())
            });
        if !closed || (!retained && !already_collected) {
            return self
                .receipts
                .rejected(request, RejectionCode::InvalidResource)
                .map_err(map_receipt_error);
        }
        let receipt = self.execute_observation(
            request,
            targets,
            ObservationScope::Managed,
            Some(ObservationState::Absent),
        )?;
        if retained {
            for target in targets {
                self.released_resources.remove(target.resource());
            }
            self.persist_ledger()?;
        }
        Ok(receipt)
    }

    fn released_observation_is_closed(&self, targets: &[ResourceObservationTarget]) -> bool {
        managed_observation_is_closed(targets, |resource| {
            self.released_resources.contains(resource)
                && !self.resource_states.contains_key(resource)
        })
    }

    fn audit_policy(
        &mut self,
        request: &crate::vortix_core::privileged::PrivilegedRequest,
        policy: &ResourceTag,
    ) -> Result<VerifiedReceipt, HelperError> {
        let effective = self
            .policy_projections
            .get(policy)
            .filter(|state| {
                self.resource_states.get(policy) == Some(&HelperResourceState::Owned)
                    && state.effective.as_ref() == Some(&state.intended)
            })
            .and_then(|state| state.effective.clone());
        let Some(effective) = effective else {
            return self
                .receipts
                .rejected(request, RejectionCode::InvalidResource)
                .map_err(map_receipt_error);
        };
        let predecessor = PolicyPredecessor::settled(effective.digest(), effective.phase())
            .map_err(|_| HelperError::LedgerUnavailable)?;
        let operation = NetworkPolicyOperation::ObserveBarrier {
            policy: policy.clone(),
            predecessor,
        };
        let plan = NetworkPolicyExecutionPlan {
            operation,
            intended: effective.clone(),
            prior_effective: None,
            release_families: BTreeSet::new(),
            retained_effective: Vec::new(),
            obsolete_effective: Vec::new(),
            recovered_firewalls: self
                .physical_firewalls
                .get(policy)
                .cloned()
                .into_iter()
                .collect(),
            recovered_dns: self.physical_dns.get(policy).cloned().into_iter().collect(),
            recovered_routes: self
                .physical_routes
                .get(policy)
                .cloned()
                .into_iter()
                .collect(),
        };
        let prepared = self
            .executor
            .prepare_network_policy(&plan)
            .map_err(PrivilegedExecutionError::from)
            .and_then(|prepared| {
                Self::accept_prepared_network_policy(&plan, &prepared)
                    .then_some(prepared)
                    .ok_or(PrivilegedExecutionError::InvalidPlan)
            });
        let outcome =
            match prepared.and_then(|prepared| self.executor.execute_network_policy(&prepared)) {
                Ok(NetworkPolicyOutcome::Observed(observations))
                    if observations.len() == 1
                        && observations[0].resource() == policy
                        && observations[0].state() == effective.expected_observation_state() =>
                {
                    observations
                }
                Ok(_) => {
                    return self
                        .receipts
                        .rejected(request, RejectionCode::InvalidResource)
                        .map_err(map_receipt_error);
                }
                Err(error) => {
                    return self
                        .execution_error_receipt(request, error)
                        .map_err(map_receipt_error);
                }
            };
        self.receipts
            .observed(request, outcome)
            .map_err(map_receipt_error)
    }

    fn managed_observation_is_closed(&self, targets: &[ResourceObservationTarget]) -> bool {
        managed_observation_is_closed(targets, |resource| {
            self.resource_states.contains_key(resource)
        })
    }

    fn reconcile_recovery(&mut self, outcome: &ObservationOutcome) -> bool {
        let mut changed = false;
        for observation in &outcome.observations {
            let resource = observation.resource();
            if resource.kind() != ResourceKind::Tunnel {
                continue;
            }
            let Some(state) = self.resource_states.get(resource).copied() else {
                continue;
            };
            let process_group = process_group_for_tunnel(resource).ok();
            let paired_state = process_group
                .as_ref()
                .and_then(|group| self.resource_states.get(group).copied());
            match (state, paired_state) {
                (HelperResourceState::PendingEffect, None) => {
                    changed |= self.reconcile_wireguard_observation(observation);
                }
                (HelperResourceState::PendingRelease, None)
                    if observation.state() == ObservationState::Absent =>
                {
                    if self.record_released_resources(std::slice::from_ref(resource)) {
                        self.resource_states.remove(resource);
                        changed = true;
                    }
                }
                (HelperResourceState::PendingEffect, Some(HelperResourceState::PendingEffect)) => {
                    let Some(group) = process_group.as_ref() else {
                        continue;
                    };
                    changed |= self.reconcile_openvpn_pending(
                        resource,
                        group,
                        &outcome.observations,
                        &outcome.child_observations,
                    );
                }
                (
                    HelperResourceState::PendingRelease,
                    Some(HelperResourceState::PendingRelease),
                ) => {
                    let Some(group) = process_group.as_ref() else {
                        continue;
                    };
                    if observation.state() == ObservationState::Absent
                        && observation_state(&outcome.observations, group)
                            == Some(ObservationState::Absent)
                        && self.record_released_resources(&[resource.clone(), group.clone()])
                    {
                        self.resource_states.remove(resource);
                        self.resource_states.remove(group);
                        self.children.remove(resource);
                        changed = true;
                    }
                }
                (
                    HelperResourceState::Owned | HelperResourceState::PendingRelease,
                    Some(HelperResourceState::Owned | HelperResourceState::PendingEffect) | None,
                )
                | (
                    HelperResourceState::PendingEffect | HelperResourceState::Owned,
                    Some(HelperResourceState::PendingRelease),
                )
                | (HelperResourceState::PendingEffect, Some(HelperResourceState::Owned)) => {}
            }
        }
        changed
    }

    fn reconcile_wireguard_observation(&mut self, observation: &ResourceObservation) -> bool {
        match observation.state() {
            ObservationState::Present => {
                self.resource_states
                    .insert(observation.resource().clone(), HelperResourceState::Owned);
                true
            }
            ObservationState::Absent => {
                self.resource_states.remove(observation.resource());
                true
            }
            ObservationState::Drifted | ObservationState::Unknown => false,
        }
    }

    fn reconcile_openvpn_pending(
        &mut self,
        tunnel: &ResourceTag,
        process_group: &ResourceTag,
        observations: &[ResourceObservation],
        child_observations: &[ObservedChildIdentity],
    ) -> bool {
        let tunnel_state = observation_state(observations, tunnel);
        let group_state = observation_state(observations, process_group);
        if tunnel_state == Some(ObservationState::Absent)
            && group_state == Some(ObservationState::Absent)
        {
            self.resource_states.remove(tunnel);
            self.resource_states.remove(process_group);
            return true;
        }
        if tunnel_state != Some(ObservationState::Present)
            || group_state != Some(ObservationState::Present)
        {
            return false;
        }
        let mut matching = child_observations
            .iter()
            .filter(|identity| identity.resource() == tunnel);
        let Some(identity) = matching.next() else {
            return false;
        };
        if matching.next().is_some() {
            return false;
        }
        self.resource_states
            .insert(tunnel.clone(), HelperResourceState::Owned);
        self.resource_states
            .insert(process_group.clone(), HelperResourceState::Owned);
        self.children
            .insert(tunnel.clone(), ChildEvidence::Recovered(identity.clone()));
        true
    }

    fn start_tunnel(
        &mut self,
        request: &crate::vortix_core::privileged::PrivilegedRequest,
        plan: &ProtocolPlan,
        materials: Option<TunnelMaterialSet>,
    ) -> Result<VerifiedReceipt, HelperError> {
        let Ok(tunnel) = ResourceTag::tunnel(plan.profile_id().clone(), plan.generation()) else {
            self.persist_ledger()?;
            return self
                .receipts
                .rejected(request, RejectionCode::InvalidPlan)
                .map_err(map_receipt_error);
        };
        let process_group = matches!(plan, ProtocolPlan::OpenVpn(_))
            .then(|| process_group_for_tunnel(&tunnel))
            .transpose()
            .map_err(|()| HelperError::LedgerUnavailable)?;
        let intended = std::iter::once(tunnel.clone())
            .chain(process_group.iter().cloned())
            .collect::<Vec<_>>();
        if intended
            .iter()
            .any(|resource| self.resource_states.contains_key(resource))
        {
            self.persist_ledger()?;
            return self
                .receipts
                .rejected(request, RejectionCode::InvalidResource)
                .map_err(map_receipt_error);
        }

        for resource in &intended {
            self.resource_states
                .insert(resource.clone(), HelperResourceState::PendingEffect);
        }
        self.persist_ledger()?;

        let outcome = match self.executor.start_tunnel(plan, materials) {
            Ok(outcome) => outcome,
            Err(error) => return self.start_error_receipt(request, &intended, error),
        };
        match (plan, outcome) {
            (ProtocolPlan::WireGuard(_), TunnelStartOutcome::InterfaceApplied(observation))
                if observation.resource() == &tunnel
                    && observation.state() == ObservationState::Present => {}
            (ProtocolPlan::OpenVpn(_), TunnelStartOutcome::ForegroundOwned(identity))
                if identity.resource() == &tunnel =>
            {
                let authority =
                    ChildSpawnAuthority::new(ChildOwner::BackgroundHelper(self.helper_epoch));
                let Ok(owned) = authority.claim(identity) else {
                    return self
                        .receipts
                        .ambiguous(request, AmbiguousPhase::EffectMayHaveApplied)
                        .map_err(map_receipt_error);
                };
                self.children
                    .insert(tunnel.clone(), ChildEvidence::Live(owned));
            }
            (_, TunnelStartOutcome::ForegroundOwned(identity)) => {
                return if self.executor.contain_unclaimed(&identity).is_ok() {
                    self.clear_resources(&intended)?;
                    self.receipts
                        .rejected(request, RejectionCode::InvalidResource)
                        .map_err(map_receipt_error)
                } else {
                    self.receipts
                        .ambiguous(request, AmbiguousPhase::EffectMayHaveApplied)
                        .map_err(map_receipt_error)
                };
            }
            (_, TunnelStartOutcome::InterfaceApplied(_)) => {
                return self
                    .receipts
                    .ambiguous(request, AmbiguousPhase::EffectMayHaveApplied)
                    .map_err(map_receipt_error);
            }
        }
        for resource in &intended {
            self.resource_states
                .insert(resource.clone(), HelperResourceState::Owned);
        }
        if let Err(error) = self.persist_ledger() {
            if let Some(identity) = self
                .children
                .get(&tunnel)
                .map(|child| child.identity().clone())
            {
                let _ = self.executor.contain_unclaimed(&identity);
            }
            return Err(error);
        }
        self.receipts
            .applied(request, intended)
            .map_err(map_receipt_error)
    }

    fn stop_tunnel(
        &mut self,
        request: &crate::vortix_core::privileged::PrivilegedRequest,
        tunnel: &ResourceTag,
    ) -> Result<VerifiedReceipt, HelperError> {
        if !self.owns_tunnel(tunnel) {
            self.persist_ledger()?;
            return self
                .receipts
                .rejected(request, RejectionCode::InvalidResource)
                .map_err(map_receipt_error);
        }
        let identity = self.child_identity(tunnel).cloned();
        let mut releasing = vec![tunnel.clone()];
        if identity.is_some() {
            releasing.push(
                process_group_for_tunnel(tunnel).map_err(|()| HelperError::LedgerUnavailable)?,
            );
        }
        if !self.can_record_released_resources(&releasing) {
            self.persist_ledger()?;
            return self
                .receipts
                .rejected(request, RejectionCode::Overloaded)
                .map_err(map_receipt_error);
        }
        for resource in &releasing {
            self.resource_states
                .insert(resource.clone(), HelperResourceState::PendingRelease);
        }
        self.persist_ledger()?;
        let observation = match self.executor.stop_tunnel(tunnel, identity.as_ref()) {
            Ok(observation) => observation,
            Err(error) => return self.release_error_receipt(request, &releasing, error),
        };
        let receipt = match self.receipts.observed(request, vec![observation]) {
            Ok(receipt) => receipt,
            Err(_) => self
                .receipts
                .ambiguous(request, AmbiguousPhase::EffectMayHaveApplied)
                .map_err(map_receipt_error)?,
        };
        if !receipt.is_ambiguous() {
            if !self.record_released_resources(&releasing) {
                self.poisoned = true;
                return Err(HelperError::LedgerUnavailable);
            }
            for resource in &releasing {
                self.resource_states.remove(resource);
            }
            self.children.remove(tunnel);
            self.persist_ledger()?;
        }
        Ok(receipt)
    }

    fn execute_network_policy(
        &mut self,
        request: &crate::vortix_core::privileged::PrivilegedRequest,
        operation: &NetworkPolicyOperation,
        admission: OperationAdmission,
    ) -> Result<VerifiedReceipt, HelperError> {
        let Some(plan) = self.network_policy_execution_plan(operation) else {
            self.poisoned = true;
            return Err(HelperError::LedgerUnavailable);
        };
        let prepared = match self.executor.prepare_network_policy(&plan) {
            Ok(prepared) => prepared,
            Err(error) => {
                return self.network_policy_error_receipt(
                    request,
                    operation,
                    error.into(),
                    admission,
                );
            }
        };
        if !Self::accept_prepared_network_policy(&plan, &prepared) {
            return self.network_policy_error_receipt(
                request,
                operation,
                PrivilegedExecutionError::InvalidPlan,
                admission,
            );
        }
        let effect_plan = self.persist_prepared_network_policy(prepared, admission)?;
        let outcome = match self.executor.execute_network_policy(&effect_plan) {
            Ok(outcome) => outcome,
            Err(error) => {
                return self.network_policy_error_receipt(request, operation, error, admission);
            }
        };
        self.record_network_policy_outcome(request, operation, outcome)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "durable prepare/effect checkpoints form one crash-safety transaction"
    )]
    fn persist_prepared_network_policy(
        &mut self,
        prepared: PreparedNetworkPolicyExecutionPlan,
        admission: OperationAdmission,
    ) -> Result<PreparedNetworkPolicyExecutionPlan, HelperError> {
        let operation = prepared.execution().operation().clone();
        let prepared = if let NetworkPolicyOperation::ReleaseObsolete { resources, .. } = &operation
        {
            let (execution, firewalls, dns, routes, route_writer) = prepared.into_parts();
            let prepared_firewalls = firewalls
                .into_iter()
                .map(|physical| {
                    if resources.contains(physical.resource())
                        && admission != OperationAdmission::PendingReleaseContinuation
                    {
                        physical
                            .mark_release_pending()
                            .map_err(|_| HelperError::LedgerUnavailable)
                    } else {
                        Ok(physical)
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            let prepared_dns = dns
                .into_iter()
                .map(|physical| {
                    if resources.contains(physical.resource())
                        && admission != OperationAdmission::PendingReleaseContinuation
                    {
                        physical
                            .mark_release_pending()
                            .map_err(|_| HelperError::LedgerUnavailable)
                    } else {
                        Ok(physical)
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            let prepared_routes = routes
                .into_iter()
                .map(|physical| {
                    if resources.contains(physical.resource())
                        && admission != OperationAdmission::PendingReleaseContinuation
                    {
                        physical
                            .mark_release_pending()
                            .map_err(|_| HelperError::LedgerUnavailable)
                    } else {
                        Ok(physical)
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            match route_writer {
                PreparedRouteWriter::ProtocolOwned => {
                    PreparedNetworkPolicyExecutionPlan::with_complete_physical_ownership(
                        execution,
                        prepared_firewalls,
                        prepared_dns,
                        prepared_routes,
                    )
                }
                PreparedRouteWriter::HelperOwned => {
                    PreparedNetworkPolicyExecutionPlan::with_helper_owned_routes(
                        execution,
                        prepared_firewalls,
                        prepared_dns,
                        prepared_routes,
                    )
                }
            }
        } else {
            prepared
        };
        self.record_prepared_network_policy(&operation, &prepared)?;
        self.persist_ledger()?;
        if matches!(operation, NetworkPolicyOperation::ApplyRoutes { .. })
            && prepared.route_writer() == PreparedRouteWriter::ProtocolOwned
        {
            return Ok(prepared);
        }
        if !matches!(
            operation,
            NetworkPolicyOperation::EstablishFirewall { .. }
                | NetworkPolicyOperation::EstablishBlocking { .. }
                | NetworkPolicyOperation::ApplyFirewall { .. }
                | NetworkPolicyOperation::ApplyRoutes { .. }
                | NetworkPolicyOperation::ApplyDns { .. }
        ) {
            return Ok(prepared);
        }

        let policy = operation.policy_resource();
        let (execution, firewalls, dns, routes, route_writer) = prepared.into_parts();
        let mut pending_firewall = None;
        let prepared_firewalls = firewalls
            .into_iter()
            .map(|physical| {
                if physical.resource() != policy {
                    return Ok(physical);
                }
                let pending = physical
                    .mark_effect_pending()
                    .map_err(|_| HelperError::LedgerUnavailable)?;
                pending_firewall = Some(pending.clone());
                Ok(pending)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut pending_dns = None;
        let prepared_dns = dns
            .into_iter()
            .map(|physical| {
                if physical.resource() != policy {
                    return Ok(physical);
                }
                let pending = physical
                    .mark_effect_pending()
                    .map_err(|_| HelperError::LedgerUnavailable)?;
                pending_dns = Some(pending.clone());
                Ok(pending)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut pending_routes = None;
        let prepared_routes = routes
            .into_iter()
            .map(|physical| {
                if physical.resource() != policy {
                    return Ok(physical);
                }
                let pending = physical
                    .mark_effect_pending()
                    .map_err(|_| HelperError::LedgerUnavailable)?;
                pending_routes = Some(pending.clone());
                Ok(pending)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let has_required_pending = match &operation {
            NetworkPolicyOperation::EstablishFirewall { .. }
            | NetworkPolicyOperation::EstablishBlocking { .. }
            | NetworkPolicyOperation::ApplyFirewall { .. } => pending_firewall.is_some(),
            NetworkPolicyOperation::ApplyDns { .. } => pending_dns.is_some(),
            NetworkPolicyOperation::ApplyRoutes { .. } => pending_routes.is_some(),
            _ => false,
        };
        if !has_required_pending {
            self.poisoned = true;
            return Err(HelperError::LedgerUnavailable);
        }
        if let Some(pending) = pending_firewall {
            self.physical_firewalls.insert(policy.clone(), pending);
        }
        if let Some(pending) = pending_dns {
            self.physical_dns.insert(policy.clone(), pending);
        }
        if let Some(pending) = pending_routes {
            self.physical_routes.insert(policy.clone(), pending);
        }
        let effect_plan = match route_writer {
            PreparedRouteWriter::ProtocolOwned => {
                PreparedNetworkPolicyExecutionPlan::with_complete_physical_ownership(
                    execution,
                    prepared_firewalls,
                    prepared_dns,
                    prepared_routes,
                )
            }
            PreparedRouteWriter::HelperOwned => {
                PreparedNetworkPolicyExecutionPlan::with_helper_owned_routes(
                    execution,
                    prepared_firewalls,
                    prepared_dns,
                    prepared_routes,
                )
            }
        };
        self.persist_ledger()?;
        Ok(effect_plan)
    }

    fn record_network_policy_outcome(
        &mut self,
        request: &crate::vortix_core::privileged::PrivilegedRequest,
        operation: &NetworkPolicyOperation,
        outcome: NetworkPolicyOutcome,
    ) -> Result<VerifiedReceipt, HelperError> {
        let receipt = match (operation, outcome) {
            (
                NetworkPolicyOperation::EstablishFirewall { .. }
                | NetworkPolicyOperation::EstablishBlocking { .. }
                | NetworkPolicyOperation::ApplyRoutes { .. }
                | NetworkPolicyOperation::ApplyDns { .. }
                | NetworkPolicyOperation::ApplyFirewall { .. },
                NetworkPolicyOutcome::Applied,
            ) => self
                .receipts
                .applied(request, vec![operation.policy_resource().clone()]),
            (
                NetworkPolicyOperation::ObserveBarrier { .. }
                | NetworkPolicyOperation::ReleaseObsolete { .. },
                NetworkPolicyOutcome::Observed(observations),
            ) => self.receipts.observed(request, observations),
            _ => self
                .receipts
                .ambiguous(request, AmbiguousPhase::EffectMayHaveApplied),
        }
        .map_err(map_receipt_error)?;

        if !receipt.is_ambiguous() {
            let confirmed = match operation {
                NetworkPolicyOperation::ObserveBarrier { policy, .. } => {
                    let confirmation = self
                        .guard
                        .confirm_observation(request, &receipt, &self.root);
                    if confirmation.is_ok() {
                        self.record_confirmed_policy_observation(policy)?;
                    }
                    confirmation
                }
                NetworkPolicyOperation::ReleaseObsolete { resources, .. } => {
                    let confirmation = self.guard.confirm_release(request, &receipt, &self.root);
                    if confirmation.is_ok() {
                        for resource in resources {
                            self.resource_states.remove(resource);
                            self.policy_projections.remove(resource);
                            self.physical_firewalls.remove(resource);
                            self.physical_dns.remove(resource);
                            self.physical_routes.remove(resource);
                        }
                    }
                    confirmation
                }
                _ => return Ok(receipt),
            };
            if confirmed.is_err() || self.persist_ledger().is_err() {
                self.poisoned = true;
                return Err(HelperError::LedgerUnavailable);
            }
        }
        Ok(receipt)
    }

    fn record_confirmed_policy_observation(
        &mut self,
        policy: &ResourceTag,
    ) -> Result<(), HelperError> {
        let Some(state) = self.policy_projections.get_mut(policy) else {
            self.poisoned = true;
            return Err(HelperError::LedgerUnavailable);
        };
        state.effective = Some(state.intended.clone());
        self.resource_states
            .insert(policy.clone(), HelperResourceState::Owned);
        match policy.kind() {
            ResourceKind::Firewall => {
                let physical = self
                    .physical_firewalls
                    .get(policy)
                    .cloned()
                    .ok_or(HelperError::LedgerUnavailable)?;
                let observed = physical
                    .confirm_observed(&state.intended)
                    .map_err(|_| HelperError::LedgerUnavailable)?;
                for (resource, prior) in &mut self.physical_firewalls {
                    if resource != policy && prior.stage() == PhysicalFirewallStage::ObservedOwned {
                        *prior = prior
                            .clone()
                            .supersede()
                            .map_err(|_| HelperError::LedgerUnavailable)?;
                    }
                }
                self.physical_firewalls.insert(policy.clone(), observed);
            }
            ResourceKind::Dns => {
                let physical = self
                    .physical_dns
                    .get(policy)
                    .cloned()
                    .ok_or(HelperError::LedgerUnavailable)?;
                let observed = physical
                    .confirm_observed(&state.intended)
                    .map_err(|_| HelperError::LedgerUnavailable)?;
                for (resource, prior) in &mut self.physical_dns {
                    if resource != policy && prior.stage() == PhysicalDnsStage::ObservedOwned {
                        *prior = prior
                            .clone()
                            .supersede()
                            .map_err(|_| HelperError::LedgerUnavailable)?;
                    }
                }
                self.physical_dns.insert(policy.clone(), observed);
            }
            ResourceKind::Routes => {
                if let Some(physical) = self.physical_routes.get(policy).cloned() {
                    let observed = physical
                        .confirm_observed(&state.intended)
                        .map_err(|_| HelperError::LedgerUnavailable)?;
                    for (resource, prior) in &mut self.physical_routes {
                        if resource != policy && prior.stage() == PhysicalRouteStage::ObservedOwned
                        {
                            *prior = prior
                                .clone()
                                .supersede()
                                .map_err(|_| HelperError::LedgerUnavailable)?;
                        }
                    }
                    self.physical_routes.insert(policy.clone(), observed);
                }
            }
            ResourceKind::Tunnel | ResourceKind::ProcessGroup | ResourceKind::RuntimeSecret => {
                return Err(HelperError::LedgerUnavailable);
            }
        }
        Ok(())
    }

    fn network_policy_execution_plan(
        &self,
        operation: &NetworkPolicyOperation,
    ) -> Option<NetworkPolicyExecutionPlan> {
        let policy = operation.policy_resource();
        let state = self.policy_projections.get(policy)?;
        let intended = self.guard.policy_projection()?;
        if intended != &state.intended || intended.policy() != policy || !intended.is_valid() {
            return None;
        }
        if intended.route_inputs().is_some_and(|(_, _, tunnels)| {
            tunnels.iter().any(|tunnel| {
                self.resource_states.get(tunnel.tunnel()) != Some(&HelperResourceState::Owned)
            })
        }) {
            return None;
        }

        let prior_effective = state.effective.clone().or_else(|| {
            self.policy_projections
                .iter()
                .filter(|(resource, candidate)| {
                    resource.kind() == policy.kind()
                        && resource.authority_epoch() == policy.authority_epoch()
                        && resource.generation() < policy.generation()
                        && self.resource_states.get(*resource) == Some(&HelperResourceState::Owned)
                        && candidate.effective.is_some()
                })
                .max_by_key(|(resource, _)| resource.generation())
                .and_then(|(_, candidate)| candidate.effective.clone())
        });

        let obsolete_effective = match operation {
            NetworkPolicyOperation::ReleaseObsolete { resources, .. } => resources
                .iter()
                .map(|resource| {
                    let state = self.policy_projections.get(resource)?;
                    (self.resource_states.get(resource)
                        == Some(&HelperResourceState::PendingRelease))
                    .then(|| state.effective.clone())
                    .flatten()
                })
                .collect::<Option<Vec<_>>>()?,
            _ => Vec::new(),
        };

        let (release_families, retained_effective) =
            self.retained_effective_for_release(operation, policy);

        let recovered_firewalls = self.recovered_firewalls_for(
            operation,
            policy,
            prior_effective.as_ref(),
            &retained_effective,
        )?;
        let recovered_dns = self.recovered_dns_for(
            operation,
            policy,
            prior_effective.as_ref(),
            &retained_effective,
        )?;
        let recovered_routes = self.recovered_routes_for(
            operation,
            policy,
            prior_effective.as_ref(),
            &retained_effective,
        )?;

        Some(NetworkPolicyExecutionPlan {
            operation: operation.clone(),
            intended: intended.clone(),
            prior_effective,
            release_families,
            retained_effective,
            obsolete_effective,
            recovered_firewalls,
            recovered_dns,
            recovered_routes,
        })
    }

    fn retained_effective_for_release(
        &self,
        operation: &NetworkPolicyOperation,
        policy: &ResourceTag,
    ) -> (BTreeSet<ResourceKind>, Vec<PolicyProjection>) {
        let families = release_families(operation);
        let NetworkPolicyOperation::ReleaseObsolete { resources, .. } = operation else {
            return (families, Vec::new());
        };
        let obsolete_resources = resources.iter().cloned().collect::<BTreeSet<_>>();
        let mut latest = BTreeMap::<ResourceKind, (&ResourceTag, &PolicyProjection)>::new();
        for (resource, state) in &self.policy_projections {
            let kind = resource.kind();
            let Some(effective) = state.effective.as_ref() else {
                continue;
            };
            if !families.contains(&kind)
                || resource.authority_epoch() != policy.authority_epoch()
                || resource.generation() > policy.generation()
                || obsolete_resources.contains(resource)
                || self.resource_states.get(resource) != Some(&HelperResourceState::Owned)
            {
                continue;
            }
            if latest
                .get(&kind)
                .is_none_or(|(current, _)| resource.generation() > current.generation())
            {
                latest.insert(kind, (resource, effective));
            }
        }
        let retained = [
            ResourceKind::Firewall,
            ResourceKind::Routes,
            ResourceKind::Dns,
        ]
        .into_iter()
        .filter_map(|kind| {
            latest
                .get(&kind)
                .map(|(_, projection)| (*projection).clone())
        })
        .collect();
        (families, retained)
    }

    fn recovered_firewalls_for(
        &self,
        operation: &NetworkPolicyOperation,
        policy: &ResourceTag,
        prior_effective: Option<&PolicyProjection>,
        retained_effective: &[PolicyProjection],
    ) -> Option<Vec<HelperLedgerFirewall>> {
        Some(match operation {
            NetworkPolicyOperation::EstablishFirewall { .. }
            | NetworkPolicyOperation::EstablishBlocking { .. }
            | NetworkPolicyOperation::ApplyFirewall { .. } => {
                let mut resources = Vec::new();
                if let Some(current) = self.physical_firewalls.get(policy) {
                    resources.push(current.clone());
                }
                if let Some(prior) = prior_effective.map(PolicyProjection::policy) {
                    if prior != policy {
                        resources.push(self.physical_firewalls.get(prior)?.clone());
                    }
                }
                resources
            }
            NetworkPolicyOperation::ObserveBarrier { .. }
                if policy.kind() == ResourceKind::Firewall =>
            {
                vec![self.physical_firewalls.get(policy)?.clone()]
            }
            NetworkPolicyOperation::ReleaseObsolete {
                policy, resources, ..
            } => {
                let mut firewalls = resources
                    .iter()
                    .filter(|resource| resource.kind() == ResourceKind::Firewall)
                    .map(|resource| self.physical_firewalls.get(resource).cloned())
                    .collect::<Option<Vec<_>>>()?;
                let retained = retained_effective
                    .iter()
                    .find(|projection| projection.policy().kind() == ResourceKind::Firewall);
                if resources
                    .iter()
                    .any(|resource| resource.kind() == ResourceKind::Firewall)
                    || policy.kind() == ResourceKind::Firewall
                {
                    let retained = retained?;
                    if !firewalls
                        .iter()
                        .any(|physical| physical.resource() == retained.policy())
                    {
                        firewalls.push(self.physical_firewalls.get(retained.policy())?.clone());
                    }
                }
                firewalls
            }
            NetworkPolicyOperation::ApplyRoutes { .. }
            | NetworkPolicyOperation::ApplyDns { .. }
            | NetworkPolicyOperation::ObserveBarrier { .. } => Vec::new(),
        })
    }

    fn recovered_dns_for(
        &self,
        operation: &NetworkPolicyOperation,
        policy: &ResourceTag,
        prior_effective: Option<&PolicyProjection>,
        retained_effective: &[PolicyProjection],
    ) -> Option<Vec<HelperLedgerDns>> {
        Some(match operation {
            NetworkPolicyOperation::ApplyDns { .. } => {
                let mut resources = Vec::new();
                if let Some(current) = self.physical_dns.get(policy) {
                    resources.push(current.clone());
                }
                if let Some(prior) = prior_effective.map(PolicyProjection::policy) {
                    if prior != policy {
                        if let Some(physical) = self.physical_dns.get(prior) {
                            resources.push(physical.clone());
                        }
                    }
                }
                resources
            }
            NetworkPolicyOperation::ObserveBarrier { .. } if policy.kind() == ResourceKind::Dns => {
                self.physical_dns.get(policy).cloned().into_iter().collect()
            }
            NetworkPolicyOperation::ReleaseObsolete {
                policy, resources, ..
            } => {
                let mut dns = resources
                    .iter()
                    .filter(|resource| resource.kind() == ResourceKind::Dns)
                    .filter_map(|resource| self.physical_dns.get(resource).cloned())
                    .collect::<Vec<_>>();
                let retained = retained_effective
                    .iter()
                    .find(|projection| projection.policy().kind() == ResourceKind::Dns);
                if resources
                    .iter()
                    .any(|resource| resource.kind() == ResourceKind::Dns)
                    || policy.kind() == ResourceKind::Dns
                {
                    let retained = retained?;
                    if !dns
                        .iter()
                        .any(|physical| physical.resource() == retained.policy())
                    {
                        dns.extend(self.physical_dns.get(retained.policy()).cloned());
                    }
                }
                dns
            }
            NetworkPolicyOperation::EstablishFirewall { .. }
            | NetworkPolicyOperation::EstablishBlocking { .. }
            | NetworkPolicyOperation::ApplyRoutes { .. }
            | NetworkPolicyOperation::ApplyFirewall { .. }
            | NetworkPolicyOperation::ObserveBarrier { .. } => Vec::new(),
        })
    }

    fn recovered_routes_for(
        &self,
        operation: &NetworkPolicyOperation,
        policy: &ResourceTag,
        prior_effective: Option<&PolicyProjection>,
        retained_effective: &[PolicyProjection],
    ) -> Option<Vec<HelperLedgerRoutes>> {
        Some(match operation {
            NetworkPolicyOperation::ApplyRoutes { .. } => {
                let mut resources = Vec::new();
                if let Some(current) = self.physical_routes.get(policy) {
                    resources.push(current.clone());
                }
                if let Some(prior) = prior_effective.map(PolicyProjection::policy) {
                    if prior != policy {
                        if let Some(physical) = self.physical_routes.get(prior) {
                            resources.push(physical.clone());
                        }
                    }
                }
                resources
            }
            NetworkPolicyOperation::ObserveBarrier { .. }
                if policy.kind() == ResourceKind::Routes =>
            {
                self.physical_routes
                    .get(policy)
                    .cloned()
                    .into_iter()
                    .collect()
            }
            NetworkPolicyOperation::ReleaseObsolete {
                policy, resources, ..
            } => {
                let mut routes = resources
                    .iter()
                    .filter(|resource| resource.kind() == ResourceKind::Routes)
                    .filter_map(|resource| self.physical_routes.get(resource).cloned())
                    .collect::<Vec<_>>();
                let retained = retained_effective
                    .iter()
                    .find(|projection| projection.policy().kind() == ResourceKind::Routes);
                if resources
                    .iter()
                    .any(|resource| resource.kind() == ResourceKind::Routes)
                    || policy.kind() == ResourceKind::Routes
                {
                    let retained = retained?;
                    if !routes
                        .iter()
                        .any(|physical| physical.resource() == retained.policy())
                    {
                        routes.extend(self.physical_routes.get(retained.policy()).cloned());
                    }
                }
                routes
            }
            NetworkPolicyOperation::EstablishFirewall { .. }
            | NetworkPolicyOperation::EstablishBlocking { .. }
            | NetworkPolicyOperation::ApplyDns { .. }
            | NetworkPolicyOperation::ApplyFirewall { .. }
            | NetworkPolicyOperation::ObserveBarrier { .. } => Vec::new(),
        })
    }

    fn accept_prepared_network_policy(
        plan: &NetworkPolicyExecutionPlan,
        prepared: &PreparedNetworkPolicyExecutionPlan,
    ) -> bool {
        if prepared.execution() != plan {
            return false;
        }
        match plan.operation() {
            NetworkPolicyOperation::EstablishFirewall { policy, .. }
            | NetworkPolicyOperation::EstablishBlocking { policy, .. }
            | NetworkPolicyOperation::ApplyFirewall { policy, .. } => {
                prepared.prepared_dns() == plan.recovered_dns()
                    && prepared.prepared_routes() == plan.recovered_routes()
                    && accepts_prepared_firewall(plan, prepared, policy)
            }
            NetworkPolicyOperation::ApplyDns { policy, .. } => {
                prepared.prepared_firewalls() == plan.recovered_firewalls()
                    && prepared.prepared_routes() == plan.recovered_routes()
                    && accepts_prepared_dns(plan, prepared, policy)
            }
            NetworkPolicyOperation::ApplyRoutes { policy, .. } => {
                prepared.prepared_firewalls() == plan.recovered_firewalls()
                    && prepared.prepared_dns() == plan.recovered_dns()
                    && ((prepared.route_writer() == PreparedRouteWriter::ProtocolOwned
                        && plan.recovered_routes().is_empty()
                        && prepared.prepared_routes().is_empty())
                        || (prepared.route_writer() == PreparedRouteWriter::HelperOwned
                            && accepts_prepared_routes(plan, prepared, policy)))
            }
            NetworkPolicyOperation::ReleaseObsolete { .. }
            | NetworkPolicyOperation::ObserveBarrier { .. } => {
                prepared.prepared_firewalls() == plan.recovered_firewalls()
                    && prepared.prepared_dns() == plan.recovered_dns()
                    && prepared.prepared_routes() == plan.recovered_routes()
            }
        }
    }

    fn record_prepared_network_policy(
        &mut self,
        operation: &NetworkPolicyOperation,
        prepared: &PreparedNetworkPolicyExecutionPlan,
    ) -> Result<(), HelperError> {
        match operation {
            NetworkPolicyOperation::EstablishFirewall { policy, .. }
            | NetworkPolicyOperation::EstablishBlocking { policy, .. }
            | NetworkPolicyOperation::ApplyFirewall { policy, .. } => {
                let physical = prepared
                    .prepared_firewalls()
                    .iter()
                    .find(|physical| physical.resource() == policy)
                    .cloned()
                    .ok_or(HelperError::LedgerUnavailable)?;
                self.physical_firewalls.insert(policy.clone(), physical);
            }
            NetworkPolicyOperation::ApplyDns { policy, .. } => {
                let physical = prepared
                    .prepared_dns()
                    .iter()
                    .find(|physical| physical.resource() == policy)
                    .cloned()
                    .ok_or(HelperError::LedgerUnavailable)?;
                self.physical_dns.insert(policy.clone(), physical);
            }
            NetworkPolicyOperation::ApplyRoutes { policy, .. } => {
                let physical = prepared
                    .prepared_routes()
                    .iter()
                    .find(|physical| physical.resource() == policy)
                    .cloned();
                if let Some(physical) = physical {
                    self.physical_routes.insert(policy.clone(), physical);
                } else if !prepared.prepared_routes().is_empty() {
                    return Err(HelperError::LedgerUnavailable);
                }
            }
            NetworkPolicyOperation::ReleaseObsolete { resources, .. } => {
                self.record_prepared_policy_release(resources, prepared)?;
            }
            NetworkPolicyOperation::ObserveBarrier { .. } => {}
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the release checkpoint validates three distinct backend stage vocabularies"
    )]
    fn record_prepared_policy_release(
        &mut self,
        resources: &[ResourceTag],
        prepared: &PreparedNetworkPolicyExecutionPlan,
    ) -> Result<(), HelperError> {
        let retained_firewall = prepared
            .execution()
            .retained_effective(ResourceKind::Firewall)
            .map(PolicyProjection::policy);
        let retained_dns = prepared
            .execution()
            .retained_effective(ResourceKind::Dns)
            .map(PolicyProjection::policy);
        let retained_routes = prepared
            .execution()
            .retained_effective(ResourceKind::Routes)
            .map(PolicyProjection::policy);
        for physical in prepared.prepared_firewalls() {
            if resources.contains(physical.resource()) {
                if !matches!(
                    physical.stage(),
                    PhysicalFirewallStage::OwnedReleasePending
                        | PhysicalFirewallStage::AbsentReleasePending
                        | PhysicalFirewallStage::SupersededReleasePending
                ) {
                    return Err(HelperError::LedgerUnavailable);
                }
                self.physical_firewalls
                    .insert(physical.resource().clone(), physical.clone());
            } else if Some(physical.resource()) != retained_firewall
                || !matches!(
                    physical.stage(),
                    PhysicalFirewallStage::ObservedOwned | PhysicalFirewallStage::ObservedAbsent
                )
                || self.physical_firewalls.get(physical.resource()) != Some(physical)
            {
                return Err(HelperError::LedgerUnavailable);
            }
        }
        for physical in prepared.prepared_dns() {
            if resources.contains(physical.resource()) {
                if !matches!(
                    physical.stage(),
                    PhysicalDnsStage::OwnedReleasePending
                        | PhysicalDnsStage::AbsentReleasePending
                        | PhysicalDnsStage::SupersededReleasePending
                ) {
                    return Err(HelperError::LedgerUnavailable);
                }
                self.physical_dns
                    .insert(physical.resource().clone(), physical.clone());
            } else if Some(physical.resource()) != retained_dns
                || !matches!(
                    physical.stage(),
                    PhysicalDnsStage::ObservedOwned | PhysicalDnsStage::ObservedAbsent
                )
                || self.physical_dns.get(physical.resource()) != Some(physical)
            {
                return Err(HelperError::LedgerUnavailable);
            }
        }
        for physical in prepared.prepared_routes() {
            if resources.contains(physical.resource()) {
                if !matches!(
                    physical.stage(),
                    PhysicalRouteStage::OwnedReleasePending
                        | PhysicalRouteStage::AbsentReleasePending
                        | PhysicalRouteStage::SupersededReleasePending
                ) {
                    return Err(HelperError::LedgerUnavailable);
                }
                self.physical_routes
                    .insert(physical.resource().clone(), physical.clone());
            } else if Some(physical.resource()) != retained_routes
                || !matches!(
                    physical.stage(),
                    PhysicalRouteStage::ObservedOwned | PhysicalRouteStage::ObservedAbsent
                )
                || self.physical_routes.get(physical.resource()) != Some(physical)
            {
                return Err(HelperError::LedgerUnavailable);
            }
        }
        Ok(())
    }

    fn network_policy_error_receipt(
        &mut self,
        request: &crate::vortix_core::privileged::PrivilegedRequest,
        operation: &NetworkPolicyOperation,
        error: PrivilegedExecutionError,
        admission: OperationAdmission,
    ) -> Result<VerifiedReceipt, HelperError> {
        if admission == OperationAdmission::PendingReleaseContinuation {
            self.persist_ledger()?;
            return self
                .execution_error_receipt(request, PrivilegedExecutionError::EffectMayHaveApplied)
                .map_err(map_receipt_error);
        }
        if !matches!(error, PrivilegedExecutionError::EffectMayHaveApplied) {
            match operation {
                NetworkPolicyOperation::EstablishFirewall { policy, .. }
                | NetworkPolicyOperation::EstablishBlocking { policy, .. }
                | NetworkPolicyOperation::ApplyRoutes { policy, .. }
                | NetworkPolicyOperation::ApplyDns { policy, .. }
                | NetworkPolicyOperation::ApplyFirewall { policy, .. } => {
                    self.rollback_policy_mutation(request, policy)?;
                }
                NetworkPolicyOperation::ReleaseObsolete { resources, .. } => {
                    self.rollback_policy_release(request, resources)?;
                }
                NetworkPolicyOperation::ObserveBarrier { .. } => self.persist_ledger()?,
            }
        }
        self.execution_error_receipt(request, error)
            .map_err(map_receipt_error)
    }

    fn rollback_policy_mutation(
        &mut self,
        request: &crate::vortix_core::privileged::PrivilegedRequest,
        policy: &ResourceTag,
    ) -> Result<(), HelperError> {
        self.guard
            .rollback_policy_before_effect(request)
            .map_err(|_| HelperError::LedgerUnavailable)?;
        let effective = self
            .policy_projections
            .get(policy)
            .and_then(|state| state.effective.clone());
        if let Some(effective) = effective {
            self.restore_physical_after_failed_mutation(policy, &effective)?;
            self.policy_projections.insert(
                policy.clone(),
                PolicyRecoveryState {
                    intended: effective.clone(),
                    effective: Some(effective),
                },
            );
            self.resource_states
                .insert(policy.clone(), HelperResourceState::Owned);
        } else {
            self.policy_projections.remove(policy);
            self.resource_states.remove(policy);
            self.physical_firewalls.remove(policy);
            self.physical_dns.remove(policy);
            self.physical_routes.remove(policy);
        }
        self.persist_ledger()
    }

    fn restore_physical_after_failed_mutation(
        &mut self,
        policy: &ResourceTag,
        effective: &PolicyProjection,
    ) -> Result<(), HelperError> {
        match policy.kind() {
            ResourceKind::Firewall => {
                let physical = self
                    .physical_firewalls
                    .get(policy)
                    .cloned()
                    .and_then(|physical| physical.restore_after_failed_mutation(effective).ok())
                    .ok_or(HelperError::LedgerUnavailable)?;
                self.physical_firewalls.insert(policy.clone(), physical);
            }
            ResourceKind::Dns => {
                let physical = self
                    .physical_dns
                    .get(policy)
                    .cloned()
                    .and_then(|physical| physical.restore_after_failed_mutation(effective).ok())
                    .ok_or(HelperError::LedgerUnavailable)?;
                self.physical_dns.insert(policy.clone(), physical);
            }
            ResourceKind::Routes => {
                let physical = self
                    .physical_routes
                    .get(policy)
                    .cloned()
                    .and_then(|physical| physical.restore_after_failed_mutation(effective).ok())
                    .ok_or(HelperError::LedgerUnavailable)?;
                self.physical_routes.insert(policy.clone(), physical);
            }
            ResourceKind::Tunnel | ResourceKind::ProcessGroup | ResourceKind::RuntimeSecret => {
                return Err(HelperError::LedgerUnavailable);
            }
        }
        Ok(())
    }

    fn rollback_policy_release(
        &mut self,
        request: &crate::vortix_core::privileged::PrivilegedRequest,
        resources: &[ResourceTag],
    ) -> Result<(), HelperError> {
        self.guard
            .rollback_policy_before_effect(request)
            .map_err(|_| HelperError::LedgerUnavailable)?;
        for resource in resources {
            self.resource_states
                .insert(resource.clone(), HelperResourceState::Owned);
            let effective = self
                .policy_projections
                .get(resource)
                .and_then(|state| state.effective.as_ref())
                .ok_or(HelperError::LedgerUnavailable)?;
            match resource.kind() {
                ResourceKind::Firewall => {
                    let physical = self
                        .physical_firewalls
                        .get(resource)
                        .cloned()
                        .filter(|physical| physical.intended_digest() == effective.digest())
                        .and_then(|physical| physical.restore_after_failed_release().ok())
                        .ok_or(HelperError::LedgerUnavailable)?;
                    self.physical_firewalls.insert(resource.clone(), physical);
                }
                ResourceKind::Dns => {
                    let physical = self
                        .physical_dns
                        .get(resource)
                        .cloned()
                        .filter(|physical| physical.intended_digest() == effective.digest())
                        .and_then(|physical| physical.restore_after_failed_release().ok())
                        .ok_or(HelperError::LedgerUnavailable)?;
                    self.physical_dns.insert(resource.clone(), physical);
                }
                ResourceKind::Routes => {
                    let physical = self
                        .physical_routes
                        .get(resource)
                        .cloned()
                        .filter(|physical| physical.intended_digest() == effective.digest())
                        .and_then(|physical| physical.restore_after_failed_release().ok())
                        .ok_or(HelperError::LedgerUnavailable)?;
                    self.physical_routes.insert(resource.clone(), physical);
                }
                ResourceKind::Tunnel | ResourceKind::ProcessGroup | ResourceKind::RuntimeSecret => {
                    return Err(HelperError::LedgerUnavailable)
                }
            }
        }
        self.persist_ledger()
    }

    fn cleanup_owned(
        &mut self,
        request: &crate::vortix_core::privileged::PrivilegedRequest,
        resources: &[ResourceTag],
    ) -> Result<VerifiedReceipt, HelperError> {
        if resources.is_empty()
            || resources
                .iter()
                .any(|resource| !self.owns_cleanup_resource(resource))
            || !self.cleanup_set_is_closed(resources)
        {
            self.persist_ledger()?;
            return self
                .receipts
                .rejected(request, RejectionCode::InvalidResource)
                .map_err(map_receipt_error);
        }
        if !self.can_record_released_resources(resources) {
            self.persist_ledger()?;
            return self
                .receipts
                .rejected(request, RejectionCode::Overloaded)
                .map_err(map_receipt_error);
        }

        let children = self.cleanup_children(resources);
        for resource in resources {
            self.resource_states
                .insert(resource.clone(), HelperResourceState::PendingRelease);
        }
        self.persist_ledger()?;
        let observations = match self.executor.cleanup_owned(resources, &children) {
            Ok(observations) => observations,
            Err(error) => return self.release_error_receipt(request, resources, error),
        };
        let receipt = match self.receipts.observed(request, observations) {
            Ok(receipt) => receipt,
            Err(_) => self
                .receipts
                .ambiguous(request, AmbiguousPhase::EffectMayHaveApplied)
                .map_err(map_receipt_error)?,
        };
        if !receipt.is_ambiguous() {
            if !self.record_released_resources(resources) {
                self.poisoned = true;
                return Err(HelperError::LedgerUnavailable);
            }
            for resource in resources {
                self.resource_states.remove(resource);
                match resource.kind() {
                    ResourceKind::ProcessGroup => {
                        if let Some(tunnel) = resource.corresponding_tunnel() {
                            self.children.remove(&tunnel);
                        }
                    }
                    ResourceKind::Tunnel | ResourceKind::RuntimeSecret => {}
                    ResourceKind::Firewall | ResourceKind::Dns | ResourceKind::Routes => {
                        unreachable!("cleanup operation validation excludes policy resources")
                    }
                }
            }
            self.persist_ledger()?;
        }
        Ok(receipt)
    }

    fn cleanup_set_is_closed(&self, resources: &[ResourceTag]) -> bool {
        self.children.keys().all(|tunnel| {
            if !resources.contains(tunnel) {
                return true;
            }
            process_group_for_tunnel(tunnel).is_ok_and(|group| resources.contains(&group))
        })
    }

    fn owns_tunnel(&self, resource: &ResourceTag) -> bool {
        resource.kind() == ResourceKind::Tunnel
            && self.resource_states.get(resource).is_some_and(|state| {
                matches!(
                    state,
                    HelperResourceState::Owned | HelperResourceState::PendingRelease
                )
            })
    }

    fn owns_cleanup_resource(&self, resource: &ResourceTag) -> bool {
        match resource.kind() {
            ResourceKind::Tunnel => self.owns_tunnel(resource),
            ResourceKind::ProcessGroup => resource
                .corresponding_tunnel()
                .is_some_and(|tunnel| self.child_identity(&tunnel).is_some()),
            ResourceKind::RuntimeSecret
            | ResourceKind::Firewall
            | ResourceKind::Dns
            | ResourceKind::Routes => false,
        }
    }

    fn cleanup_children(&self, resources: &[ResourceTag]) -> Vec<ObservedChildIdentity> {
        let mut children = BTreeMap::new();
        for resource in resources {
            let tunnel = match resource.kind() {
                ResourceKind::Tunnel => Some(resource.clone()),
                ResourceKind::ProcessGroup => resource.corresponding_tunnel(),
                ResourceKind::RuntimeSecret
                | ResourceKind::Firewall
                | ResourceKind::Dns
                | ResourceKind::Routes => None,
            };
            if let Some((tunnel, child)) =
                tunnel.and_then(|tunnel| self.child_identity(&tunnel).map(|child| (tunnel, child)))
            {
                children.insert(tunnel, child.clone());
            }
        }
        children.into_values().collect()
    }

    fn child_identity(&self, tunnel: &ResourceTag) -> Option<&ObservedChildIdentity> {
        self.children.get(tunnel).map(ChildEvidence::identity)
    }

    fn persist_ledger(&mut self) -> Result<(), HelperError> {
        let Some(checkpoint) = self.guard.checkpoint() else {
            self.poisoned = true;
            return Err(HelperError::LedgerUnavailable);
        };
        let resources = self
            .resource_states
            .iter()
            .map(|(resource, state)| match state {
                HelperResourceState::PendingEffect => {
                    HelperLedgerResource::pending(resource.clone())
                }
                HelperResourceState::Owned => HelperLedgerResource::owned(resource.clone()),
                HelperResourceState::PendingRelease => {
                    HelperLedgerResource::releasing(resource.clone())
                }
            })
            .collect();
        let policy_projections = self
            .policy_projections
            .iter()
            .map(|(resource, state)| {
                HelperLedgerPolicy::new(
                    resource.clone(),
                    state.intended.clone(),
                    state.effective.clone(),
                )
            })
            .collect::<Result<Vec<_>, _>>();
        let Ok(policy_projections) = policy_projections else {
            self.poisoned = true;
            return Err(HelperError::LedgerUnavailable);
        };
        let child_observations = self
            .children
            .iter()
            .map(|child| child.1.identity().clone())
            .collect();
        let physical_firewalls = self.physical_firewalls.values().cloned().collect();
        let physical_dns = self.physical_dns.values().cloned().collect();
        let physical_routes = self.physical_routes.values().cloned().collect();
        let Ok(ledger) = HelperLedgerRecord::new_with_complete_physical_ownership_and_released(
            checkpoint,
            resources,
            policy_projections,
            HelperLedgerPhysicalOwnership {
                firewalls: physical_firewalls,
                dns: physical_dns,
                routes: physical_routes,
            },
            self.released_resources.iter().cloned().collect(),
            child_observations,
        ) else {
            self.poisoned = true;
            return Err(HelperError::LedgerUnavailable);
        };
        if self.ledger_store.persist(&ledger).is_err() {
            self.poisoned = true;
            return Err(HelperError::LedgerUnavailable);
        }
        Ok(())
    }

    fn can_record_released_resources(&self, resources: &[ResourceTag]) -> bool {
        self.released_resources_after(resources).is_some()
    }

    fn record_released_resources(&mut self, resources: &[ResourceTag]) -> bool {
        let Some(projected) = self.released_resources_after(resources) else {
            return false;
        };
        self.released_resources = projected;
        true
    }

    fn released_resources_after(&self, resources: &[ResourceTag]) -> Option<BTreeSet<ResourceTag>> {
        let profiles = resources
            .iter()
            .map(ResourceTag::profile_id)
            .collect::<Option<BTreeSet<_>>>()?;
        let mut projected = self
            .released_resources
            .iter()
            .filter(|existing| {
                existing
                    .profile_id()
                    .is_none_or(|profile| !profiles.contains(profile))
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        projected.extend(resources.iter().cloned());
        (projected.len() <= MAX_RESOURCE_ITEMS).then_some(projected)
    }

    fn clear_resources(&mut self, resources: &[ResourceTag]) -> Result<(), HelperError> {
        for resource in resources {
            self.resource_states.remove(resource);
        }
        self.persist_ledger()
    }

    fn start_error_receipt(
        &mut self,
        request: &crate::vortix_core::privileged::PrivilegedRequest,
        resources: &[ResourceTag],
        error: PrivilegedExecutionError,
    ) -> Result<VerifiedReceipt, HelperError> {
        if !matches!(error, PrivilegedExecutionError::EffectMayHaveApplied) {
            self.clear_resources(resources)?;
        }
        self.execution_error_receipt(request, error)
            .map_err(map_receipt_error)
    }

    fn release_error_receipt(
        &mut self,
        request: &crate::vortix_core::privileged::PrivilegedRequest,
        resources: &[ResourceTag],
        error: PrivilegedExecutionError,
    ) -> Result<VerifiedReceipt, HelperError> {
        if !matches!(error, PrivilegedExecutionError::EffectMayHaveApplied) {
            for resource in resources {
                self.resource_states
                    .insert(resource.clone(), HelperResourceState::Owned);
            }
            self.persist_ledger()?;
        }
        self.execution_error_receipt(request, error)
            .map_err(map_receipt_error)
    }

    fn execution_error_receipt(
        &self,
        request: &crate::vortix_core::privileged::PrivilegedRequest,
        error: PrivilegedExecutionError,
    ) -> Result<VerifiedReceipt, ReceiptError> {
        match error {
            PrivilegedExecutionError::InvalidPlan => {
                self.receipts.rejected(request, RejectionCode::InvalidPlan)
            }
            PrivilegedExecutionError::Overloaded => {
                self.receipts.rejected(request, RejectionCode::Overloaded)
            }
            PrivilegedExecutionError::FailedBeforeEffect => self
                .receipts
                .rejected(request, RejectionCode::ExecutionFailed),
            PrivilegedExecutionError::EffectMayHaveApplied => self
                .receipts
                .ambiguous(request, AmbiguousPhase::EffectMayHaveApplied),
        }
    }
}

fn managed_observation_evidence_matches(
    targets: &[ResourceObservationTarget],
    observations: &[ResourceObservation],
) -> bool {
    targets.iter().all(|target| {
        let Some(observation) = observations
            .iter()
            .find(|observation| observation.resource() == target.resource())
        else {
            return false;
        };
        if target.protocol() == Some(ProtocolKind::WireGuard)
            && observation.state() == ObservationState::Present
        {
            observation.wireguard_peers().is_some()
        } else {
            observation.wireguard_peers().is_none()
        }
    })
}

fn accepts_prepared_firewall(
    plan: &NetworkPolicyExecutionPlan,
    prepared: &PreparedNetworkPolicyExecutionPlan,
    policy: &ResourceTag,
) -> bool {
    let candidates = prepared.prepared_firewalls();
    if candidates.len()
        != plan.recovered_firewalls().len()
            + usize::from(
                !plan
                    .recovered_firewalls()
                    .iter()
                    .any(|physical| physical.resource() == policy),
            )
    {
        return false;
    }
    let Some(current) = candidates
        .iter()
        .find(|physical| physical.resource() == policy)
    else {
        return false;
    };
    if current.stage() != PhysicalFirewallStage::Prepared
        || current.intended_digest() != plan.intended().digest()
    {
        return false;
    }
    if let Some(existing) = plan
        .recovered_firewalls()
        .iter()
        .find(|physical| physical.resource() == policy)
    {
        if current.backend() != existing.backend()
            || current.transaction_id() != existing.transaction_id()
        {
            return false;
        }
    }
    candidates.iter().enumerate().all(|(index, candidate)| {
        !candidates[..index]
            .iter()
            .any(|prior| prior.resource() == candidate.resource())
            && (candidate.resource() == policy
                || plan
                    .recovered_firewalls()
                    .iter()
                    .any(|expected| expected == candidate))
    })
}

fn accepts_prepared_dns(
    plan: &NetworkPolicyExecutionPlan,
    prepared: &PreparedNetworkPolicyExecutionPlan,
    policy: &ResourceTag,
) -> bool {
    let candidates = prepared.prepared_dns();
    if candidates.len()
        != plan.recovered_dns().len()
            + usize::from(
                !plan
                    .recovered_dns()
                    .iter()
                    .any(|physical| physical.resource() == policy),
            )
    {
        return false;
    }
    let Some(current) = candidates
        .iter()
        .find(|physical| physical.resource() == policy)
    else {
        return false;
    };
    if current.stage() != PhysicalDnsStage::Prepared
        || current.intended_digest() != plan.intended().digest()
    {
        return false;
    }
    if let Some(existing) = plan
        .recovered_dns()
        .iter()
        .find(|physical| physical.resource() == policy)
    {
        if current.backend() != existing.backend()
            || current.transaction_id() != existing.transaction_id()
            || current.links() != existing.links()
        {
            return false;
        }
    }
    candidates.iter().enumerate().all(|(index, candidate)| {
        !candidates[..index]
            .iter()
            .any(|prior| prior.resource() == candidate.resource())
            && (candidate.resource() == policy
                || plan
                    .recovered_dns()
                    .iter()
                    .any(|expected| expected == candidate))
    })
}

fn accepts_prepared_routes(
    plan: &NetworkPolicyExecutionPlan,
    prepared: &PreparedNetworkPolicyExecutionPlan,
    policy: &ResourceTag,
) -> bool {
    let candidates = prepared.prepared_routes();
    if candidates.len()
        != plan.recovered_routes().len()
            + usize::from(
                !plan
                    .recovered_routes()
                    .iter()
                    .any(|physical| physical.resource() == policy),
            )
    {
        return false;
    }
    let Some(current) = candidates
        .iter()
        .find(|physical| physical.resource() == policy)
    else {
        return false;
    };
    if current.stage() != PhysicalRouteStage::Prepared
        || current.intended_digest() != plan.intended().digest()
    {
        return false;
    }
    if let Some(existing) = plan
        .recovered_routes()
        .iter()
        .find(|physical| physical.resource() == policy)
    {
        if current.backend() != existing.backend()
            || current.transaction_id() != existing.transaction_id()
        {
            return false;
        }
    }
    candidates.iter().enumerate().all(|(index, candidate)| {
        !candidates[..index]
            .iter()
            .any(|prior| prior.resource() == candidate.resource())
            && (candidate.resource() == policy
                || plan
                    .recovered_routes()
                    .iter()
                    .any(|expected| expected == candidate))
    })
}

fn managed_observation_is_closed(
    targets: &[ResourceObservationTarget],
    owns: impl Fn(&ResourceTag) -> bool,
) -> bool {
    let requested = targets
        .iter()
        .map(|target| (target.resource(), target.protocol()))
        .collect::<BTreeMap<_, _>>();
    targets.iter().all(|target| {
        let resource = target.resource();
        if !owns(resource) {
            return false;
        }
        match resource.kind() {
            ResourceKind::Tunnel => {
                let Ok(group) = process_group_for_tunnel(resource) else {
                    return false;
                };
                if owns(&group) {
                    target.protocol() == Some(ProtocolKind::OpenVpn)
                        && requested.get(&group) == Some(&Some(ProtocolKind::OpenVpn))
                } else {
                    target.protocol() == Some(ProtocolKind::WireGuard)
                }
            }
            ResourceKind::ProcessGroup => resource.corresponding_tunnel().is_some_and(|tunnel| {
                owns(&tunnel)
                    && requested.get(&tunnel) == Some(&Some(ProtocolKind::OpenVpn))
                    && target.protocol() == Some(ProtocolKind::OpenVpn)
            }),
            ResourceKind::Firewall
            | ResourceKind::Dns
            | ResourceKind::Routes
            | ResourceKind::RuntimeSecret => false,
        }
    })
}

pub(crate) fn process_group_for_tunnel(tunnel: &ResourceTag) -> Result<ResourceTag, ()> {
    let Some(profile_id) = tunnel.profile_id() else {
        return Err(());
    };
    ResourceTag::profile(
        profile_id.clone(),
        tunnel.generation(),
        ResourceKind::ProcessGroup,
    )
    .map_err(|_| ())
}

fn observation_state(
    observations: &[ResourceObservation],
    resource: &ResourceTag,
) -> Option<ObservationState> {
    observations
        .iter()
        .find(|observation| observation.resource() == resource)
        .map(ResourceObservation::state)
}

fn receipt_result(receipt: VerifiedReceipt) -> Result<HelperResult, HelperError> {
    serde_json::to_value(receipt)
        .map(HelperResult::Receipt)
        .map_err(|_| HelperError::LedgerUnavailable)
}

fn map_operation_error(error: &OperationError) -> HelperError {
    match error {
        OperationError::PrincipalMismatch
        | OperationError::HelperEpochMismatch
        | OperationError::InvalidReplayState => HelperError::AuthenticationFailed,
        OperationError::SequenceReplay | OperationError::DuplicateDigestMismatch => {
            HelperError::Malformed {
                reason: "replayed or conflicting operation identity".into(),
            }
        }
        _ => HelperError::Malformed {
            reason: "invalid privileged operation".into(),
        },
    }
}

fn map_receipt_error(_error: ReceiptError) -> HelperError {
    HelperError::LedgerUnavailable
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::helper_client::{AuthenticatedHelperSession, DeliveryState, RecoveryAction};
    use crate::helper::replay_store::FsHelperLedgerStore;
    use crate::helper::validate::{
        verify_helper_peer, verify_service_instance, ArtifactFact, HelperPeerFacts,
        InstallManifest, PlatformLayout, VerifiedServiceFacts,
    };
    use crate::vortix_core::cidr::Cidr;
    use crate::vortix_core::control::AuthorityEpoch;
    use crate::vortix_core::privileged::{
        BootScope, ContainmentId, DnsTransactionId, FirewallTransactionId, LeaseId,
        ObservationState, OpenVpnAuthFactors, OpenVpnPlan, OpenVpnRemote, OpenVpnRemoteSelection,
        OpenVpnRouteEvidence, OpenVpnRouteSetEvidence, OpenVpnTransport, OperationDigest,
        PeerProcessIdentity, PhysicalDnsBackend, PhysicalFirewallBackend, PhysicalRouteBackend,
        PolicyPhase, PrivilegedRequest, ProtocolEndpoint, RequestSequence, RouteTransactionId,
        ScopedRoute, ServiceInstanceClaim, ServiceManager, WireGuardInterfaceOptions,
        WireGuardPeerPlan, WireGuardPlan,
    };
    use crate::vortix_core::profile::{ProfileId, ProtocolKind};
    use crate::vortix_core::state::killswitch::KillSwitchMode;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::os::unix::fs::PermissionsExt as _;

    #[derive(Default)]
    struct MemoryHelperLedgerStore {
        writes: Vec<HelperLedgerRecord>,
        fail: bool,
        fail_on_write: Option<usize>,
    }

    impl HelperLedgerStore for MemoryHelperLedgerStore {
        fn persist(&mut self, checkpoint: &HelperLedgerRecord) -> Result<(), ()> {
            if self.fail || self.fail_on_write == Some(self.writes.len() + 1) {
                Err(())
            } else {
                self.writes.push(checkpoint.clone());
                Ok(())
            }
        }
    }

    #[derive(Default)]
    enum FakeCleanupEvidence {
        #[default]
        Absent,
        Present,
    }

    #[derive(Default)]
    enum FakeChildObservation {
        #[default]
        None,
        Matching,
        Foreign,
    }

    #[derive(Default)]
    enum FakeOpenVpnRouteEvidence {
        #[default]
        Complete,
        Missing,
    }

    #[derive(Default)]
    #[allow(
        clippy::struct_excessive_bools,
        reason = "the test fake independently injects each privileged failure boundary"
    )]
    struct FakeExecutor {
        observations: usize,
        starts: usize,
        stops: usize,
        stops_with_child: usize,
        policy_calls: usize,
        policy_prepares: usize,
        policy_prepare_error: Option<NetworkPolicyPreparationError>,
        prepare_physical_routes: bool,
        policy_plans: Vec<PreparedNetworkPolicyExecutionPlan>,
        recovered_dns_validations: Vec<Vec<RecoveredDnsState>>,
        recovered_firewall_validations: Vec<Vec<RecoveredFirewallState>>,
        recovered_route_validations: Vec<Vec<RecoveredRouteState>>,
        recovered_policy_enabled: Vec<bool>,
        cleanups: usize,
        cleanup_children: usize,
        containments: usize,
        foreground_start: bool,
        foreign_start: bool,
        containment_fails: bool,
        start_error: Option<PrivilegedExecutionError>,
        policy_error: Option<PrivilegedExecutionError>,
        cleanup_error: Option<PrivilegedExecutionError>,
        cleanup_evidence: FakeCleanupEvidence,
        observation_state: Option<ObservationState>,
        child_observation: FakeChildObservation,
        openvpn_route_evidence: FakeOpenVpnRouteEvidence,
    }

    impl ObservationExecutor for FakeExecutor {
        fn observe(
            &mut self,
            targets: &[ResourceObservationTarget],
            scope: ObservationScope,
        ) -> Result<ObservationOutcome, ObservationError> {
            self.observations += 1;
            let observations = targets
                .iter()
                .map(|target| {
                    let state = self.observation_state.unwrap_or(ObservationState::Present);
                    if scope == ObservationScope::Managed
                        && target.protocol() == Some(ProtocolKind::WireGuard)
                        && state == ObservationState::Present
                    {
                        ResourceObservation::with_wireguard_peers(
                            target.resource().clone(),
                            state,
                            1,
                            Vec::new(),
                        )
                    } else if scope == ObservationScope::Managed
                        && target.protocol() == Some(ProtocolKind::OpenVpn)
                        && target.resource().kind() == ResourceKind::Tunnel
                        && state == ObservationState::Present
                        && matches!(
                            self.openvpn_route_evidence,
                            FakeOpenVpnRouteEvidence::Complete
                        )
                    {
                        ResourceObservation::with_openvpn_routes(
                            target.resource().clone(),
                            state,
                            1,
                            OpenVpnRouteEvidence::new(
                                OpenVpnRouteSetEvidence::new(Vec::new(), None)
                                    .expect("empty configured routes are complete"),
                                OpenVpnRouteSetEvidence::new(Vec::new(), None)
                                    .expect("empty pushed routes are complete"),
                            )
                            .expect("empty route evidence is complete"),
                        )
                    } else {
                        ResourceObservation::new(target.resource().clone(), state, 1)
                    }
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ObservationError::InvalidResource)?;
            let child_resources = match self.child_observation {
                FakeChildObservation::None => Vec::new(),
                FakeChildObservation::Matching => targets
                    .iter()
                    .map(ResourceObservationTarget::resource)
                    .filter(|resource| resource.kind() == ResourceKind::Tunnel)
                    .cloned()
                    .collect(),
                FakeChildObservation::Foreign => vec![ResourceTag::tunnel(
                    ProfileId::parse("b".repeat(ProfileId::HEX_LEN)).unwrap(),
                    1,
                )
                .unwrap()],
            };
            let child_observations = child_resources
                .into_iter()
                .map(|resource| {
                    ObservedChildIdentity::new(resource, 42, 99, ContainmentId::new([3; 32]))
                        .map_err(|_| ObservationError::InvalidResource)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ObservationOutcome::new(observations, child_observations))
        }
    }

    impl TunnelLifecycleExecutor for FakeExecutor {
        fn start_tunnel(
            &mut self,
            plan: &ProtocolPlan,
            _materials: Option<TunnelMaterialSet>,
        ) -> Result<TunnelStartOutcome, PrivilegedExecutionError> {
            self.starts += 1;
            if let Some(error) = self.start_error {
                return Err(error);
            }
            let profile_id = if self.foreign_start {
                ProfileId::parse("b".repeat(ProfileId::HEX_LEN)).unwrap()
            } else {
                plan.profile_id().clone()
            };
            let resource = ResourceTag::tunnel(profile_id, plan.generation()).unwrap();
            if self.foreground_start {
                ObservedChildIdentity::new(resource, 42, 99, ContainmentId::new([3; 32]))
                    .map(TunnelStartOutcome::ForegroundOwned)
                    .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)
            } else {
                ResourceObservation::new(resource, ObservationState::Present, 1)
                    .map(TunnelStartOutcome::InterfaceApplied)
                    .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)
            }
        }

        fn stop_tunnel(
            &mut self,
            tunnel: &ResourceTag,
            child: Option<&ObservedChildIdentity>,
        ) -> Result<ResourceObservation, PrivilegedExecutionError> {
            self.stops += 1;
            self.stops_with_child += usize::from(child.is_some());
            ResourceObservation::new(tunnel.clone(), ObservationState::Absent, 2)
                .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)
        }

        fn contain_unclaimed(
            &mut self,
            _child: &ObservedChildIdentity,
        ) -> Result<(), PrivilegedExecutionError> {
            self.containments += 1;
            if self.containment_fails {
                Err(PrivilegedExecutionError::EffectMayHaveApplied)
            } else {
                Ok(())
            }
        }
    }

    impl NetworkPolicyExecutor for FakeExecutor {
        fn validate_recovered_firewalls(
            &mut self,
            firewalls: &[RecoveredFirewallState],
            policy_enabled: bool,
        ) -> Result<(), PrivilegedExecutionError> {
            self.recovered_firewall_validations.push(firewalls.to_vec());
            self.recovered_policy_enabled.push(policy_enabled);
            if firewalls
                .iter()
                .all(|firewall| firewall.physical().backend() != PhysicalFirewallBackend::MacOsPf)
            {
                Ok(())
            } else {
                Err(PrivilegedExecutionError::InvalidPlan)
            }
        }

        fn validate_recovered_dns(
            &mut self,
            states: &[RecoveredDnsState],
            _policy_enabled: bool,
        ) -> Result<(), PrivilegedExecutionError> {
            self.recovered_dns_validations.push(states.to_vec());
            Ok(())
        }

        fn validate_recovered_routes(
            &mut self,
            states: &[RecoveredRouteState],
            _policy_enabled: bool,
        ) -> Result<(), PrivilegedExecutionError> {
            self.recovered_route_validations.push(states.to_vec());
            Ok(())
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the test fake constructs each family-specific prepared policy payload"
        )]
        fn prepare_network_policy(
            &mut self,
            plan: &NetworkPolicyExecutionPlan,
        ) -> Result<PreparedNetworkPolicyExecutionPlan, NetworkPolicyPreparationError> {
            self.policy_prepares += 1;
            if let Some(error) = self.policy_prepare_error {
                return Err(error);
            }
            let mut firewalls = plan.recovered_firewalls().to_vec();
            if matches!(
                plan.operation(),
                NetworkPolicyOperation::EstablishFirewall { .. }
                    | NetworkPolicyOperation::EstablishBlocking { .. }
                    | NetworkPolicyOperation::ApplyFirewall { .. }
            ) {
                let resource = plan.operation().policy_resource();
                let prepared = if let Some(existing) = firewalls
                    .iter()
                    .find(|physical| physical.resource() == resource)
                {
                    existing
                        .prepare_for(plan.intended())
                        .map_err(|_| NetworkPolicyPreparationError::InvalidPlan)?
                } else {
                    let mut transaction = [0; 32];
                    transaction[..8].copy_from_slice(&resource.generation().to_be_bytes());
                    HelperLedgerFirewall::prepared(
                        resource.clone(),
                        PhysicalFirewallBackend::LinuxNft,
                        FirewallTransactionId::new(transaction)
                            .map_err(|_| NetworkPolicyPreparationError::InvalidPlan)?,
                        plan.intended().digest(),
                    )
                };
                if let Some(existing) = firewalls
                    .iter_mut()
                    .find(|physical| physical.resource() == resource)
                {
                    *existing = prepared;
                } else {
                    firewalls.push(prepared);
                }
            }
            let mut dns = plan.recovered_dns().to_vec();
            if matches!(plan.operation(), NetworkPolicyOperation::ApplyDns { .. }) {
                let resource = plan.operation().policy_resource();
                let prepared = if let Some(existing) =
                    dns.iter().find(|physical| physical.resource() == resource)
                {
                    existing
                        .prepare_for(plan.intended())
                        .map_err(|_| NetworkPolicyPreparationError::InvalidPlan)?
                } else {
                    let mut transaction = [0; 32];
                    transaction[..8].copy_from_slice(&resource.generation().to_be_bytes());
                    HelperLedgerDns::prepared(
                        resource.clone(),
                        PhysicalDnsBackend::MacOsResolverFiles,
                        DnsTransactionId::new(transaction)
                            .map_err(|_| NetworkPolicyPreparationError::InvalidPlan)?,
                        plan.intended().digest(),
                        Vec::new(),
                    )
                    .map_err(|_| NetworkPolicyPreparationError::InvalidPlan)?
                };
                if let Some(existing) = dns
                    .iter_mut()
                    .find(|physical| physical.resource() == resource)
                {
                    *existing = prepared;
                } else {
                    dns.push(prepared);
                }
            }
            let mut routes = plan.recovered_routes().to_vec();
            if self.prepare_physical_routes
                && matches!(plan.operation(), NetworkPolicyOperation::ApplyRoutes { .. })
            {
                let resource = plan.operation().policy_resource();
                let (_, redirects, _) = plan
                    .intended()
                    .route_inputs()
                    .ok_or(NetworkPolicyPreparationError::InvalidPlan)?;
                if !redirects.is_empty() {
                    return Err(NetworkPolicyPreparationError::InvalidPlan);
                }
                let entries = plan
                    .intended()
                    .route_inputs()
                    .ok_or(NetworkPolicyPreparationError::InvalidPlan)?
                    .0
                    .iter()
                    .map(|route| {
                        crate::vortix_core::privileged::PhysicalRouteEntry::new(
                            route.destination(),
                            "vxroute0".into(),
                            None,
                            route.metric(),
                        )
                        .map_err(|_| NetworkPolicyPreparationError::InvalidPlan)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let mut transaction = [0; 32];
                transaction[..8].copy_from_slice(&resource.generation().to_be_bytes());
                let prepared = HelperLedgerRoutes::prepared(
                    resource.clone(),
                    PhysicalRouteBackend::LinuxPolicyV1,
                    RouteTransactionId::new(transaction)
                        .map_err(|_| NetworkPolicyPreparationError::InvalidPlan)?,
                    plan.intended().digest(),
                    entries,
                    plan.intended()
                        .route_inputs()
                        .into_iter()
                        .flat_map(|(_, _, tunnels)| tunnels)
                        .flat_map(
                            crate::vortix_core::privileged::PrivilegedFirewallTunnel::endpoint_ips,
                        )
                        .copied()
                        .collect::<std::collections::BTreeSet<_>>()
                        .into_iter()
                        .collect(),
                    Vec::new(),
                )
                .map_err(|_| NetworkPolicyPreparationError::InvalidPlan)?;
                routes.push(prepared);
            }
            if self.prepare_physical_routes
                && matches!(plan.operation(), NetworkPolicyOperation::ApplyRoutes { .. })
            {
                Ok(
                    PreparedNetworkPolicyExecutionPlan::with_helper_owned_routes(
                        plan.clone(),
                        firewalls,
                        dns,
                        routes,
                    ),
                )
            } else {
                Ok(
                    PreparedNetworkPolicyExecutionPlan::with_complete_physical_ownership(
                        plan.clone(),
                        firewalls,
                        dns,
                        routes,
                    ),
                )
            }
        }

        fn execute_network_policy(
            &mut self,
            prepared: &PreparedNetworkPolicyExecutionPlan,
        ) -> Result<NetworkPolicyOutcome, PrivilegedExecutionError> {
            let plan = prepared.execution();
            self.policy_calls += 1;
            assert_eq!(plan.intended().policy(), plan.operation().policy_resource());
            self.policy_plans.push(prepared.clone());
            if let Some(error) = self.policy_error {
                return Err(error);
            }
            match plan.operation() {
                NetworkPolicyOperation::ObserveBarrier { policy, .. } => {
                    Ok(NetworkPolicyOutcome::Observed(vec![
                        ResourceObservation::new(
                            policy.clone(),
                            plan.intended().expected_observation_state(),
                            3,
                        )
                        .unwrap(),
                    ]))
                }
                NetworkPolicyOperation::ReleaseObsolete {
                    policy,
                    resources,
                    retained_state,
                    ..
                } => {
                    let mut observations =
                        vec![ResourceObservation::new(policy.clone(), *retained_state, 3).unwrap()];
                    observations.extend(resources.iter().cloned().map(|resource| {
                        ResourceObservation::new(resource, ObservationState::Absent, 3).unwrap()
                    }));
                    Ok(NetworkPolicyOutcome::Observed(observations))
                }
                NetworkPolicyOperation::EstablishFirewall { .. }
                | NetworkPolicyOperation::EstablishBlocking { .. }
                | NetworkPolicyOperation::ApplyRoutes { .. }
                | NetworkPolicyOperation::ApplyDns { .. }
                | NetworkPolicyOperation::ApplyFirewall { .. } => Ok(NetworkPolicyOutcome::Applied),
            }
        }
    }

    impl CleanupExecutor for FakeExecutor {
        fn cleanup_owned(
            &mut self,
            resources: &[ResourceTag],
            children: &[ObservedChildIdentity],
        ) -> Result<Vec<ResourceObservation>, PrivilegedExecutionError> {
            self.cleanups += 1;
            self.cleanup_children += children.len();
            if let Some(error) = self.cleanup_error {
                return Err(error);
            }
            resources
                .iter()
                .cloned()
                .map(|resource| {
                    ResourceObservation::new(
                        resource,
                        match self.cleanup_evidence {
                            FakeCleanupEvidence::Absent => ObservationState::Absent,
                            FakeCleanupEvidence::Present => ObservationState::Present,
                        },
                        4,
                    )
                    .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)
                })
                .collect()
        }
    }

    fn fixture() -> (
        RootAuthorityLedger,
        crate::vortix_core::privileged::TrustedDaemonPrincipal,
        ServiceInstanceClaim,
        HelperEpoch,
        crate::vortix_core::privileged::ReplayBaseline,
    ) {
        let digest = OperationDigest::of_bytes(b"root-owned daemon");
        let claim = ServiceInstanceClaim::systemd(42, 99, digest, [7; 32]).unwrap();
        let facts = VerifiedServiceFacts::from_os_verifier(
            ServiceManager::Systemd,
            501,
            42,
            99,
            digest,
            [7; 32],
            true,
            true,
        );
        let verified = verify_service_instance(501, &claim, &facts).unwrap();
        let root = RootAuthorityLedger::from_platform_verified(
            verified,
            BootScope::new([4; 16]),
            AuthorityEpoch(3),
            LeaseId::new([5; 32]),
        )
        .unwrap();
        let principal = root.principal();
        let helper_epoch = HelperEpoch::new(8).unwrap();
        let baseline = root
            .unused_replay_baseline(&principal, helper_epoch)
            .unwrap();
        (root, principal, claim, helper_epoch, baseline)
    }

    fn verified_helper_peer() -> crate::helper::validate::VerifiedHelperPeer {
        let helper_digest = OperationDigest::of_bytes(b"helper");
        let manifest = InstallManifest::new(
            "0.4.3".into(),
            1,
            OperationDigest::of_bytes(b"daemon"),
            helper_digest,
            OperationDigest::of_bytes(b"bootstrap"),
            None,
        )
        .unwrap();
        let artifact = ArtifactFact::from_os_verifier(
            crate::helper::ArtifactKind::Helper,
            std::path::PathBuf::from(PlatformLayout::Linux.helper_path()),
            0,
            0o755,
            helper_digest,
            false,
        );
        let facts = HelperPeerFacts::from_os_verifier(
            0,
            77,
            91,
            std::path::PathBuf::from(PlatformLayout::Linux.helper_socket()),
            501,
            crate::helper::HELPER_SOCKET_MODE,
            artifact,
        );
        verify_helper_peer(501, PlatformLayout::Linux, &manifest, &facts).unwrap()
    }

    fn resource() -> ResourceTag {
        ResourceTag::tunnel(ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap(), 1).unwrap()
    }

    fn wireguard_target(resource: ResourceTag) -> ResourceObservationTarget {
        ResourceObservationTarget::new(resource, Some(ProtocolKind::WireGuard)).unwrap()
    }

    fn openvpn_target(resource: ResourceTag) -> ResourceObservationTarget {
        ResourceObservationTarget::new(resource, Some(ProtocolKind::OpenVpn)).unwrap()
    }

    fn wireguard_plan(generation: u64) -> ProtocolPlan {
        let allowed = Cidr::new(IpAddr::V4(Ipv4Addr::new(10, 7, 0, 0)), 16).unwrap();
        let peer = WireGuardPeerPlan::new(
            [7; 32],
            Some(ProtocolEndpoint::ip(SocketAddr::from(([198, 51, 100, 7], 51820))).unwrap()),
            vec![allowed],
            None,
        )
        .unwrap();
        ProtocolPlan::WireGuard(
            WireGuardPlan::new(
                ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap(),
                generation,
                Vec::new(),
                vec![peer],
                WireGuardInterfaceOptions::default(),
            )
            .unwrap(),
        )
    }

    fn openvpn_plan_for(profile: &str, generation: u64) -> ProtocolPlan {
        ProtocolPlan::OpenVpn(
            OpenVpnPlan::new(
                ProfileId::parse(profile.repeat(ProfileId::HEX_LEN)).unwrap(),
                generation,
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
        )
    }

    fn openvpn_plan(generation: u64) -> ProtocolPlan {
        openvpn_plan_for("a", generation)
    }

    fn execute_policy_phase(
        harness: &mut LifecycleHarness,
        sequence: u64,
        operation: NetworkPolicyOperation,
    ) {
        let policy = operation.policy_resource().clone();
        let request = harness.request(sequence, PrivilegedOperation::NetworkPolicy(operation));
        assert!(!harness.execute(sequence + 1, &request).is_ambiguous());
        let barrier = harness.request(
            sequence + 1,
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ObserveBarrier {
                policy,
                predecessor: harness.server.guard.policy_predecessor().unwrap(),
            }),
        );
        assert!(!harness.execute(sequence + 2, &barrier).is_ambiguous());
    }

    fn install_policy_generation(
        harness: &mut LifecycleHarness,
        generation: u64,
        first_sequence: u64,
    ) -> (ResourceTag, ResourceTag, ResourceTag) {
        install_policy_generation_with_mode(
            harness,
            generation,
            first_sequence,
            KillSwitchMode::AlwaysOn,
        )
    }

    fn install_policy_generation_with_mode(
        harness: &mut LifecycleHarness,
        generation: u64,
        first_sequence: u64,
        mode: KillSwitchMode,
    ) -> (ResourceTag, ResourceTag, ResourceTag) {
        let firewall =
            ResourceTag::topology(AuthorityEpoch(3), generation, ResourceKind::Firewall).unwrap();
        let routes =
            ResourceTag::topology(AuthorityEpoch(3), generation, ResourceKind::Routes).unwrap();
        let dns = ResourceTag::topology(AuthorityEpoch(3), generation, ResourceKind::Dns).unwrap();
        let establish = if mode == KillSwitchMode::AlwaysOn {
            NetworkPolicyOperation::EstablishBlocking {
                policy: firewall.clone(),
                tunnels: Vec::new(),
            }
        } else {
            NetworkPolicyOperation::EstablishFirewall {
                policy: firewall.clone(),
                mode,
                tunnels: Vec::new(),
            }
        };
        execute_policy_phase(harness, first_sequence, establish);
        let predecessor = harness.server.guard.policy_predecessor().unwrap();
        execute_policy_phase(
            harness,
            first_sequence + 2,
            NetworkPolicyOperation::ApplyRoutes {
                policy: routes.clone(),
                routes: Vec::new(),
                redirects: Vec::new(),
                predecessor,
            },
        );
        let predecessor = harness.server.guard.policy_predecessor().unwrap();
        execute_policy_phase(
            harness,
            first_sequence + 4,
            NetworkPolicyOperation::ApplyDns {
                policy: dns.clone(),
                assignments: Vec::new(),
                predecessor,
            },
        );
        let predecessor = harness.server.guard.policy_predecessor().unwrap();
        execute_policy_phase(
            harness,
            first_sequence + 6,
            NetworkPolicyOperation::ApplyFirewall {
                policy: firewall.clone(),
                mode,
                tunnels: Vec::new(),
                predecessor,
            },
        );
        (firewall, routes, dns)
    }

    #[test]
    fn nonblocking_final_firewall_records_verified_absence_not_physical_ownership() {
        let mut harness = LifecycleHarness::for_policy(FakeExecutor::default());
        let (firewall, _, _) =
            install_policy_generation_with_mode(&mut harness, 1, 1, KillSwitchMode::Auto);

        assert!(matches!(
            harness.server.executor.policy_plans[0]
                .execution()
                .intended(),
            PolicyProjection::FirewallBaseline {
                mode: KillSwitchMode::Auto,
                ..
            }
        ));
        assert_eq!(
            harness.server.physical_firewalls[&firewall].stage(),
            PhysicalFirewallStage::ObservedAbsent
        );
        let persisted = harness.server.ledger_store.writes.last().unwrap();
        assert_eq!(
            persisted.physical_firewalls()[0].stage(),
            PhysicalFirewallStage::ObservedAbsent
        );
        let encoded = serde_json::to_vec(persisted).unwrap();
        assert!(serde_json::from_slice::<HelperLedgerRecord>(&encoded).is_ok());
    }

    #[test]
    fn policy_audit_rechecks_exact_root_owned_effective_projection() {
        let mut harness = LifecycleHarness::for_policy(FakeExecutor::default());
        let (_, routes, _) = install_policy_generation(&mut harness, 1, 1);
        let audit = harness.request(9, PrivilegedOperation::AuditPolicy(routes.clone()));

        let receipt = harness.execute(10, &audit);

        assert!(receipt.observes(&routes, ObservationState::Absent));
        assert!(matches!(
            harness
                .server
                .executor
                .policy_plans
                .last()
                .unwrap()
                .execution()
                .operation(),
            NetworkPolicyOperation::ObserveBarrier { policy, .. } if policy == &routes
        ));
    }

    fn recover_policy_inventory(
        root: RootAuthorityLedger,
        ledger: HelperLedgerRecord,
    ) -> HelperPolicyInventory {
        let (helper_epoch, _) = ledger.next_helper_session().unwrap();
        let (_, principal, claim, _, _) = fixture();
        let mut recovered = EnrolledHelperSession::recover(
            root,
            helper_epoch,
            ledger,
            FakeExecutor::default(),
            MemoryHelperLedgerStore::default(),
        )
        .unwrap();
        let response = recovered.handle(HelperRequest {
            id: 1,
            op: HelperOp::Handshake(HelperClientHello::current(
                501,
                claim,
                vec![HelperCapability::NetworkPolicy],
            )),
        });
        let HelperResult::Handshake(hello) = response.result.unwrap() else {
            panic!("expected enrolled handshake");
        };
        AuthenticatedHelperSession::from_handshake(&principal, &verified_helper_peer(), &hello)
            .unwrap();
        *hello.policy_inventory.unwrap()
    }

    #[test]
    fn recovered_schema_six_handshake_exposes_exact_policy_inventory() {
        let mut harness = LifecycleHarness::for_policy(FakeExecutor::default());
        let (firewall, routes, dns) = install_policy_generation(&mut harness, 1, 1);
        let ledger = harness.server.ledger_store.writes.last().unwrap().clone();
        let legacy_ledger = ledger.clone();
        let (helper_epoch, _) = ledger.next_helper_session().unwrap();
        let (root, principal, claim, _, _) = fixture();
        let mut recovered = EnrolledHelperSession::recover(
            root,
            helper_epoch,
            ledger,
            FakeExecutor::default(),
            MemoryHelperLedgerStore::default(),
        )
        .unwrap();

        let response = recovered.handle(HelperRequest {
            id: 1,
            op: HelperOp::Handshake(HelperClientHello::current(
                501,
                claim,
                vec![HelperCapability::NetworkPolicy],
            )),
        });
        let HelperResult::Handshake(hello) = response.result.unwrap() else {
            panic!("expected enrolled handshake");
        };
        let inventory = hello.policy_inventory.as_ref().unwrap();
        assert_eq!(inventory.current(), Some(&firewall));
        let predecessor = inventory.predecessor().unwrap();
        assert_eq!(
            predecessor.phase(),
            crate::vortix_core::privileged::PolicyPhase::Firewall
        );
        assert!(predecessor.observed());
        assert_eq!(inventory.resources().len(), 3);
        for resource in [&firewall, &routes, &dns] {
            let record = inventory
                .resources()
                .iter()
                .find(|record| record.resource() == resource)
                .unwrap();
            assert_eq!(record.state(), HelperResourceState::Owned);
            assert_eq!(record.effective(), Some(record.intended()));
        }
        AuthenticatedHelperSession::from_handshake(&principal, &verified_helper_peer(), &hello)
            .unwrap();

        let (legacy_epoch, _) = legacy_ledger.next_helper_session().unwrap();
        let (root, _, claim, _, _) = fixture();
        let mut legacy = EnrolledHelperSession::recover(
            root,
            legacy_epoch,
            legacy_ledger,
            FakeExecutor::default(),
            MemoryHelperLedgerStore::default(),
        )
        .unwrap();
        let mut client_hello =
            HelperClientHello::current(501, claim, vec![HelperCapability::NetworkPolicy]);
        client_hello.schema.max = 5;
        let response = legacy.handle(HelperRequest {
            id: 1,
            op: HelperOp::Handshake(client_hello),
        });
        let HelperResult::Handshake(legacy_hello) = response.result.unwrap() else {
            panic!("expected legacy enrolled handshake");
        };
        assert_eq!(legacy_hello.schema, 5);
        assert!(legacy_hello.policy_inventory.is_none());
        assert!(!serde_json::to_value(legacy_hello)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("policy_inventory"));
    }

    #[test]
    fn recovered_schema_six_inventory_preserves_interrupted_policy_states() {
        let mut pending_effect = LifecycleHarness::for_policy(FakeExecutor::default());
        let firewall = ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Firewall).unwrap();
        let blocking = pending_effect.request(
            1,
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::EstablishBlocking {
                policy: firewall.clone(),
                tunnels: Vec::new(),
            }),
        );
        assert!(!pending_effect.execute(2, &blocking).is_ambiguous());
        let inventory = recover_policy_inventory(
            pending_effect.server.root.clone(),
            pending_effect
                .server
                .ledger_store
                .writes
                .last()
                .unwrap()
                .clone(),
        );
        let predecessor = inventory.predecessor().unwrap();
        assert_eq!(predecessor.phase(), PolicyPhase::Blocking);
        assert!(!predecessor.observed());
        assert_eq!(inventory.current(), Some(&firewall));
        assert_eq!(inventory.resources().len(), 1);
        assert_eq!(
            inventory.resources()[0].state(),
            HelperResourceState::PendingEffect
        );

        let mut pending_release = LifecycleHarness::for_policy(FakeExecutor::default());
        let (firewall_1, routes_1, dns_1) = install_policy_generation(&mut pending_release, 1, 1);
        let (firewall_2, _, _) = install_policy_generation(&mut pending_release, 2, 9);
        let obsolete = [firewall_1, routes_1, dns_1];
        let release = pending_release.request(
            17,
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ReleaseObsolete {
                policy: firewall_2.clone(),
                resources: obsolete.to_vec(),
                predecessor: pending_release.server.guard.policy_predecessor().unwrap(),
                retained_state: ObservationState::Present,
            }),
        );
        assert!(!pending_release.execute(18, &release).is_ambiguous());
        let ledger = pending_release
            .server
            .ledger_store
            .writes
            .iter()
            .rev()
            .find(|ledger| {
                obsolete.iter().all(|resource| {
                    ledger.resources().iter().any(|entry| {
                        entry.resource() == resource
                            && entry.state() == HelperResourceState::PendingRelease
                    })
                })
            })
            .unwrap()
            .clone();
        let inventory = recover_policy_inventory(pending_release.server.root.clone(), ledger);
        let predecessor = inventory.predecessor().unwrap();
        assert_eq!(predecessor.phase(), PolicyPhase::Released);
        assert!(!predecessor.observed());
        assert_eq!(inventory.current(), Some(&firewall_2));
        assert_eq!(
            inventory
                .resources()
                .iter()
                .find(|record| record.resource() == &firewall_2)
                .unwrap()
                .state(),
            HelperResourceState::Owned
        );
        for resource in &obsolete {
            assert_eq!(
                inventory
                    .resources()
                    .iter()
                    .find(|record| record.resource() == resource)
                    .unwrap()
                    .state(),
                HelperResourceState::PendingRelease
            );
        }
    }

    struct LifecycleHarness {
        server: EnrolledHelperSession<FakeExecutor, MemoryHelperLedgerStore>,
        principal: crate::vortix_core::privileged::TrustedDaemonPrincipal,
        client: AuthenticatedHelperSession,
        helper_epoch: HelperEpoch,
    }

    impl LifecycleHarness {
        fn new(executor: FakeExecutor) -> Self {
            Self::with_capability(executor, HelperCapability::TunnelLifecycle)
        }

        fn for_policy(executor: FakeExecutor) -> Self {
            Self::with_capability(executor, HelperCapability::NetworkPolicy)
        }

        fn for_cleanup(executor: FakeExecutor) -> Self {
            Self::with_capability(executor, HelperCapability::CleanupOwned)
        }

        fn with_capability(executor: FakeExecutor, capability: HelperCapability) -> Self {
            Self::with_capabilities(executor, vec![capability])
        }

        fn with_capabilities(executor: FakeExecutor, capabilities: Vec<HelperCapability>) -> Self {
            let (root, principal, claim, helper_epoch, baseline) = fixture();
            let mut server = EnrolledHelperSession::resume(
                root,
                helper_epoch,
                baseline,
                executor,
                MemoryHelperLedgerStore::default(),
            )
            .unwrap();
            let handshake = server.handle(HelperRequest {
                id: 1,
                op: HelperOp::Handshake(HelperClientHello::current(501, claim, capabilities)),
            });
            let HelperResult::Handshake(server_hello) = handshake.result.unwrap() else {
                panic!("expected handshake");
            };
            let client = AuthenticatedHelperSession::from_handshake(
                &principal,
                &verified_helper_peer(),
                &server_hello,
            )
            .unwrap();
            Self {
                server,
                principal,
                client,
                helper_epoch,
            }
        }

        fn request(&self, sequence: u64, operation: PrivilegedOperation) -> PrivilegedRequest {
            PrivilegedRequest::new(
                &self.principal,
                self.helper_epoch,
                RequestSequence::new(sequence).unwrap(),
                operation,
            )
            .unwrap()
        }

        fn execute(&mut self, id: u64, request: &PrivilegedRequest) -> VerifiedReceipt {
            let response = self.server.handle(HelperRequest {
                id,
                op: HelperOp::Execute(Box::new(request.clone())),
            });
            self.client.verify_receipt(id, request, response).unwrap()
        }
    }

    #[test]
    fn persistent_ledger_reconnect_advances_epoch_and_authenticated_sequence_cursor() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            directory.path(),
            std::fs::Permissions::from_mode(crate::helper::HELPER_RUNTIME_DIR_MODE),
        )
        .unwrap();
        let path = directory.path().join("helper-ledger.json");
        let uid = crate::utils::effective_user_group_ids().0;
        let (root, principal, claim, first_epoch, baseline) = fixture();
        let mut initial_store = FsHelperLedgerStore::for_test(&path, uid);
        initial_store.initialize(baseline.clone()).unwrap();
        let mut first = EnrolledHelperSession::resume(
            root.clone(),
            first_epoch,
            baseline,
            FakeExecutor::default(),
            initial_store,
        )
        .unwrap();
        assert!(first
            .handle(HelperRequest {
                id: 1,
                op: HelperOp::Handshake(HelperClientHello::current(
                    501,
                    claim.clone(),
                    vec![HelperCapability::Observe],
                )),
            })
            .result
            .is_ok());
        let first_request = PrivilegedRequest::new(
            &principal,
            first_epoch,
            RequestSequence::new(1).unwrap(),
            PrivilegedOperation::Observe(vec![wireguard_target(resource())]),
        )
        .unwrap();
        let first_result = first.handle(HelperRequest {
            id: 2,
            op: HelperOp::Execute(Box::new(first_request)),
        });
        assert!(
            first_result.result.is_ok(),
            "{:?}",
            first_result.result.err()
        );
        drop(first);

        let recovered_store = FsHelperLedgerStore::for_test(&path, uid);
        let ledger = recovered_store.load().unwrap();
        let (second_epoch, next_sequence) = ledger.next_helper_session().unwrap();
        assert_eq!(second_epoch, HelperEpoch::new(9).unwrap());
        assert_eq!(next_sequence, RequestSequence::new(2).unwrap());
        let mut second = EnrolledHelperSession::recover(
            root,
            second_epoch,
            ledger,
            FakeExecutor::default(),
            recovered_store,
        )
        .unwrap();
        let handshake = second.handle(HelperRequest {
            id: 1,
            op: HelperOp::Handshake(HelperClientHello::current(
                501,
                claim,
                vec![HelperCapability::Observe],
            )),
        });
        let HelperResult::Handshake(hello) = handshake.result.unwrap() else {
            panic!("expected enrolled handshake");
        };
        let binding = hello.session.unwrap();
        assert_eq!(binding.helper_epoch(), second_epoch);
        assert_eq!(binding.next_sequence(), Some(next_sequence));
        let second_request = PrivilegedRequest::new(
            &principal,
            second_epoch,
            next_sequence,
            PrivilegedOperation::Observe(vec![wireguard_target(resource())]),
        )
        .unwrap();
        assert!(second
            .handle(HelperRequest {
                id: 2,
                op: HelperOp::Execute(Box::new(second_request)),
            })
            .result
            .is_ok());
    }

    fn recover_session(
        root: RootAuthorityLedger,
        ledger: HelperLedgerRecord,
        executor: FakeExecutor,
        capability: HelperCapability,
    ) -> (
        EnrolledHelperSession<FakeExecutor, MemoryHelperLedgerStore>,
        crate::vortix_core::privileged::TrustedDaemonPrincipal,
        HelperEpoch,
    ) {
        let (_fixture_root, principal, claim, _old_epoch, _baseline) = fixture();
        let helper_epoch = HelperEpoch::new(9).unwrap();
        let mut recovered = EnrolledHelperSession::recover(
            root,
            helper_epoch,
            ledger,
            executor,
            MemoryHelperLedgerStore::default(),
        )
        .unwrap();
        let response = recovered.handle(HelperRequest {
            id: 1,
            op: HelperOp::Handshake(HelperClientHello::current(501, claim, vec![capability])),
        });
        assert!(response.result.is_ok(), "{:?}", response.result);
        (recovered, principal, helper_epoch)
    }

    fn pending_tunnel_ledger(
        plans: impl IntoIterator<Item = ProtocolPlan>,
    ) -> (RootAuthorityLedger, HelperLedgerRecord) {
        let mut harness = LifecycleHarness::new(FakeExecutor {
            start_error: Some(PrivilegedExecutionError::EffectMayHaveApplied),
            ..FakeExecutor::default()
        });
        for (index, plan) in plans.into_iter().enumerate() {
            let sequence = u64::try_from(index + 1).unwrap();
            let start = harness.request(sequence, PrivilegedOperation::StartTunnel(plan));
            assert!(harness.execute(sequence + 1, &start).is_ambiguous());
        }
        (
            harness.server.root.clone(),
            harness.server.ledger_store.writes.last().unwrap().clone(),
        )
    }

    fn pending_release_ledger(
        plan: ProtocolPlan,
        executor: FakeExecutor,
    ) -> (RootAuthorityLedger, HelperLedgerRecord, ResourceTag) {
        let tunnel = ResourceTag::tunnel(plan.profile_id().clone(), plan.generation()).unwrap();
        let mut harness = LifecycleHarness::new(executor);
        let start = harness.request(1, PrivilegedOperation::StartTunnel(plan));
        assert!(!harness.execute(2, &start).is_ambiguous());
        harness.server.ledger_store.fail_on_write = Some(4);
        let stop = harness.request(2, PrivilegedOperation::StopTunnel(tunnel.clone()));
        assert!(matches!(
            harness
                .server
                .handle(HelperRequest {
                    id: 3,
                    op: HelperOp::Execute(Box::new(stop)),
                })
                .result,
            Err(HelperError::LedgerUnavailable)
        ));
        (
            harness.server.root.clone(),
            harness.server.ledger_store.writes.last().unwrap().clone(),
            tunnel,
        )
    }

    fn managed_observation_request(
        principal: &crate::vortix_core::privileged::TrustedDaemonPrincipal,
        helper_epoch: HelperEpoch,
        sequence: u64,
        targets: Vec<ResourceObservationTarget>,
    ) -> PrivilegedRequest {
        PrivilegedRequest::new(
            principal,
            helper_epoch,
            RequestSequence::new(sequence).unwrap(),
            PrivilegedOperation::ObserveManaged(targets),
        )
        .unwrap()
    }

    #[test]
    fn observation_is_persisted_then_authenticated_and_duplicates_are_safe() {
        let (root, principal, claim, helper_epoch, baseline) = fixture();
        let mut server = EnrolledHelperSession::resume(
            root,
            helper_epoch,
            baseline,
            FakeExecutor::default(),
            MemoryHelperLedgerStore::default(),
        )
        .unwrap();
        let hello = HelperClientHello::current(
            501,
            claim,
            vec![HelperCapability::Handshake, HelperCapability::Observe],
        );
        let handshake = server.handle(HelperRequest {
            id: 1,
            op: HelperOp::Handshake(hello),
        });
        let HelperResult::Handshake(server_hello) = handshake.result.unwrap() else {
            panic!("expected handshake");
        };
        let client = AuthenticatedHelperSession::from_handshake(
            &principal,
            &verified_helper_peer(),
            &server_hello,
        )
        .unwrap();
        let request = PrivilegedRequest::new(
            &principal,
            helper_epoch,
            RequestSequence::new(1).unwrap(),
            PrivilegedOperation::Observe(vec![wireguard_target(resource())]),
        )
        .unwrap();

        for id in [2, 3] {
            let response = server.handle(HelperRequest {
                id,
                op: HelperOp::Execute(Box::new(request.clone())),
            });
            client.verify_receipt(id, &request, response).unwrap();
        }
        assert_eq!(server.ledger_store.writes.len(), 1);
    }

    #[test]
    fn managed_observation_requires_root_ledger_accounting_before_platform_readback() {
        let (root, principal, claim, helper_epoch, baseline) = fixture();
        let mut server = EnrolledHelperSession::resume(
            root,
            helper_epoch,
            baseline,
            FakeExecutor::default(),
            MemoryHelperLedgerStore::default(),
        )
        .unwrap();
        let handshake = server.handle(HelperRequest {
            id: 1,
            op: HelperOp::Handshake(HelperClientHello::current(
                501,
                claim,
                vec![HelperCapability::Observe],
            )),
        });
        let HelperResult::Handshake(server_hello) = handshake.result.unwrap() else {
            panic!("expected handshake");
        };
        let client = AuthenticatedHelperSession::from_handshake(
            &principal,
            &verified_helper_peer(),
            &server_hello,
        )
        .unwrap();
        let request = PrivilegedRequest::new(
            &principal,
            helper_epoch,
            RequestSequence::new(1).unwrap(),
            PrivilegedOperation::ObserveManaged(vec![wireguard_target(resource())]),
        )
        .unwrap();

        let response = server.handle(HelperRequest {
            id: 2,
            op: HelperOp::Execute(Box::new(request.clone())),
        });
        let receipt = client.verify_receipt(2, &request, response).unwrap();

        assert!(receipt.is_rejected());
        assert_eq!(server.executor.observations, 0);
    }

    #[test]
    fn managed_absence_rejects_never_owned_wireguard_resources() {
        let (root, principal, claim, helper_epoch, baseline) = fixture();
        let mut server = EnrolledHelperSession::resume(
            root,
            helper_epoch,
            baseline,
            FakeExecutor {
                observation_state: Some(ObservationState::Absent),
                ..FakeExecutor::default()
            },
            MemoryHelperLedgerStore::default(),
        )
        .unwrap();
        let handshake = server.handle(HelperRequest {
            id: 1,
            op: HelperOp::Handshake(HelperClientHello::current(
                501,
                claim,
                vec![HelperCapability::Observe],
            )),
        });
        let HelperResult::Handshake(server_hello) = handshake.result.unwrap() else {
            panic!("expected handshake");
        };
        let client = AuthenticatedHelperSession::from_handshake(
            &principal,
            &verified_helper_peer(),
            &server_hello,
        )
        .unwrap();
        let request = PrivilegedRequest::new(
            &principal,
            helper_epoch,
            RequestSequence::new(1).unwrap(),
            PrivilegedOperation::ObserveManagedAbsence(vec![wireguard_target(resource())]),
        )
        .unwrap();

        let response = server.handle(HelperRequest {
            id: 2,
            op: HelperOp::Execute(Box::new(request.clone())),
        });
        let receipt = client.verify_receipt(2, &request, response).unwrap();

        assert!(receipt.is_rejected());
        assert_eq!(server.executor.observations, 0);
    }

    #[test]
    fn managed_absence_requires_durable_released_wireguard_identity() {
        let mut harness = LifecycleHarness::with_capabilities(
            FakeExecutor {
                observation_state: Some(ObservationState::Absent),
                ..FakeExecutor::default()
            },
            vec![HelperCapability::TunnelLifecycle, HelperCapability::Observe],
        );
        let start = harness.request(1, PrivilegedOperation::StartTunnel(wireguard_plan(1)));
        assert!(!harness.execute(2, &start).is_ambiguous());
        let stop = harness.request(2, PrivilegedOperation::StopTunnel(resource()));
        assert!(!harness.execute(3, &stop).is_ambiguous());
        let observe = harness.request(
            3,
            PrivilegedOperation::ObserveManagedAbsence(vec![wireguard_target(resource())]),
        );

        let receipt = harness.execute(4, &observe);

        assert!(receipt.observes(&resource(), ObservationState::Absent));
        assert_eq!(harness.server.executor.observations, 1);
        assert_eq!(
            harness
                .server
                .ledger_store
                .writes
                .last()
                .unwrap()
                .released_resources(),
            &[resource()]
        );
    }

    #[test]
    fn released_identity_capacity_rejects_before_tunnel_teardown() {
        let mut harness = LifecycleHarness::with_capabilities(
            FakeExecutor::default(),
            vec![HelperCapability::TunnelLifecycle],
        );
        let start = harness.request(1, PrivilegedOperation::StartTunnel(wireguard_plan(1)));
        assert!(!harness.execute(2, &start).is_ambiguous());
        harness.server.released_resources = (1..=MAX_RESOURCE_ITEMS)
            .map(|seed| {
                ResourceTag::tunnel(ProfileId::parse(format!("{seed:064x}")).unwrap(), 1).unwrap()
            })
            .collect();
        let stop = harness.request(2, PrivilegedOperation::StopTunnel(resource()));

        let receipt = harness.execute(3, &stop);

        assert!(receipt.is_rejected());
        assert_eq!(harness.server.executor.stops, 0);
        assert!(harness.server.owns_tunnel(&resource()));
    }

    #[test]
    fn released_identity_acknowledgement_rechecks_absence_and_persists_collection() {
        let mut harness = LifecycleHarness::with_capabilities(
            FakeExecutor {
                observation_state: Some(ObservationState::Absent),
                ..FakeExecutor::default()
            },
            vec![HelperCapability::TunnelLifecycle, HelperCapability::Observe],
        );
        let start = harness.request(1, PrivilegedOperation::StartTunnel(wireguard_plan(1)));
        assert!(!harness.execute(2, &start).is_ambiguous());
        let stop = harness.request(2, PrivilegedOperation::StopTunnel(resource()));
        assert!(!harness.execute(3, &stop).is_ambiguous());
        let acknowledge = harness.request(
            3,
            PrivilegedOperation::AcknowledgeReleased(vec![wireguard_target(resource())]),
        );

        let receipt = harness.execute(4, &acknowledge);

        assert!(receipt.observes(&resource(), ObservationState::Absent));
        assert_eq!(harness.server.executor.observations, 1);
        assert!(harness
            .server
            .ledger_store
            .writes
            .last()
            .unwrap()
            .released_resources()
            .is_empty());
    }

    #[test]
    fn released_identity_acknowledgement_rejects_unowned_identity_before_observation() {
        let mut harness = LifecycleHarness::with_capability(
            FakeExecutor {
                observation_state: Some(ObservationState::Absent),
                ..FakeExecutor::default()
            },
            HelperCapability::Observe,
        );
        let acknowledge = harness.request(
            1,
            PrivilegedOperation::AcknowledgeReleased(vec![wireguard_target(resource())]),
        );

        let receipt = harness.execute(2, &acknowledge);

        assert!(receipt.is_rejected());
        assert_eq!(harness.server.executor.observations, 0);
    }

    #[test]
    fn released_identity_acknowledgement_recovers_after_collection_checkpoint_failure() {
        let mut harness = LifecycleHarness::with_capabilities(
            FakeExecutor {
                observation_state: Some(ObservationState::Absent),
                ..FakeExecutor::default()
            },
            vec![HelperCapability::TunnelLifecycle, HelperCapability::Observe],
        );
        let start = harness.request(1, PrivilegedOperation::StartTunnel(wireguard_plan(1)));
        assert!(!harness.execute(2, &start).is_ambiguous());
        let stop = harness.request(2, PrivilegedOperation::StopTunnel(resource()));
        assert!(!harness.execute(3, &stop).is_ambiguous());
        let writes_before = harness.server.ledger_store.writes.len();
        harness.server.ledger_store.fail_on_write = Some(writes_before + 2);
        let acknowledge = harness.request(
            3,
            PrivilegedOperation::AcknowledgeReleased(vec![wireguard_target(resource())]),
        );

        let failed = harness.server.handle(HelperRequest {
            id: 4,
            op: HelperOp::Execute(Box::new(acknowledge)),
        });

        assert!(matches!(failed.result, Err(HelperError::LedgerUnavailable)));
        assert!(harness.server.poisoned);
        let ledger = harness.server.ledger_store.writes.last().unwrap().clone();
        assert_eq!(ledger.released_resources(), &[resource()]);
        let (_, next_sequence) = ledger.next_helper_session().unwrap();
        let root = harness.server.root.clone();
        let (mut recovered, principal, helper_epoch) = recover_session(
            root,
            ledger,
            FakeExecutor {
                observation_state: Some(ObservationState::Absent),
                ..FakeExecutor::default()
            },
            HelperCapability::Observe,
        );
        let retry = PrivilegedRequest::new(
            &principal,
            helper_epoch,
            next_sequence,
            PrivilegedOperation::AcknowledgeReleased(vec![wireguard_target(resource())]),
        )
        .unwrap();

        let response = recovered.handle(HelperRequest {
            id: 5,
            op: HelperOp::Execute(Box::new(retry)),
        });

        assert!(response.result.is_ok(), "{:?}", response.result);
        assert!(recovered
            .ledger_store
            .writes
            .last()
            .unwrap()
            .released_resources()
            .is_empty());
    }

    #[test]
    fn released_inventory_is_exposed_only_from_the_authenticated_ledger() {
        let mut harness = LifecycleHarness::with_capabilities(
            FakeExecutor::default(),
            vec![HelperCapability::TunnelLifecycle, HelperCapability::Observe],
        );
        let start = harness.request(1, PrivilegedOperation::StartTunnel(wireguard_plan(1)));
        assert!(!harness.execute(2, &start).is_ambiguous());
        let stop = harness.request(2, PrivilegedOperation::StopTunnel(resource()));
        assert!(!harness.execute(3, &stop).is_ambiguous());
        let ledger = harness.server.ledger_store.writes.last().unwrap().clone();
        let (helper_epoch, _) = ledger.next_helper_session().unwrap();
        let root = harness.server.root.clone();
        let (_fixture_root, _principal, claim, _old_epoch, _baseline) = fixture();
        let mut recovered = EnrolledHelperSession::recover(
            root,
            helper_epoch,
            ledger,
            FakeExecutor::default(),
            MemoryHelperLedgerStore::default(),
        )
        .unwrap();

        let response = recovered.handle(HelperRequest {
            id: 1,
            op: HelperOp::Handshake(HelperClientHello::current(
                501,
                claim,
                vec![HelperCapability::Observe],
            )),
        });
        let HelperResult::Handshake(hello) = response.result.unwrap() else {
            panic!("expected enrolled helper handshake");
        };

        assert_eq!(hello.released_resources.unwrap().resources(), &[resource()]);
    }

    #[test]
    fn schema_nine_handshake_omits_released_inventory_for_rollback_compatibility() {
        let (root, _principal, claim, helper_epoch, baseline) = fixture();
        let mut server = EnrolledHelperSession::resume(
            root,
            helper_epoch,
            baseline,
            FakeExecutor::default(),
            MemoryHelperLedgerStore::default(),
        )
        .unwrap();
        let mut hello = HelperClientHello::current(501, claim, vec![HelperCapability::Observe]);
        hello.schema.max = 9;

        let response = server.handle(HelperRequest {
            id: 1,
            op: HelperOp::Handshake(hello),
        });
        let HelperResult::Handshake(hello) = response.result.unwrap() else {
            panic!("expected enrolled helper handshake");
        };

        assert_eq!(hello.schema, 9);
        assert!(hello.released_resources.is_none());
    }

    #[test]
    fn managed_openvpn_absence_requires_released_tunnel_and_group_set() {
        let mut harness = LifecycleHarness::with_capabilities(
            FakeExecutor {
                foreground_start: true,
                observation_state: Some(ObservationState::Absent),
                ..FakeExecutor::default()
            },
            vec![HelperCapability::TunnelLifecycle, HelperCapability::Observe],
        );
        let start = harness.request(1, PrivilegedOperation::StartTunnel(openvpn_plan(1)));
        assert!(!harness.execute(2, &start).is_ambiguous());
        let tunnel = resource();
        let group = process_group_for_tunnel(&tunnel).unwrap();
        let stop = harness.request(2, PrivilegedOperation::StopTunnel(tunnel.clone()));
        assert!(!harness.execute(3, &stop).is_ambiguous());
        let incomplete = harness.request(
            3,
            PrivilegedOperation::ObserveManagedAbsence(vec![openvpn_target(tunnel.clone())]),
        );
        assert!(harness.execute(4, &incomplete).is_rejected());
        assert_eq!(harness.server.executor.observations, 0);
        let complete = harness.request(
            4,
            PrivilegedOperation::ObserveManagedAbsence(vec![
                openvpn_target(tunnel.clone()),
                openvpn_target(group.clone()),
            ]),
        );

        let receipt = harness.execute(5, &complete);

        assert!(receipt.observes(&tunnel, ObservationState::Absent));
        assert!(receipt.observes(&group, ObservationState::Absent));
        assert_eq!(harness.server.executor.observations, 1);
    }

    #[test]
    fn released_tunnel_identity_survives_helper_restart() {
        let mut harness = LifecycleHarness::with_capabilities(
            FakeExecutor::default(),
            vec![HelperCapability::TunnelLifecycle],
        );
        let start = harness.request(1, PrivilegedOperation::StartTunnel(wireguard_plan(1)));
        assert!(!harness.execute(2, &start).is_ambiguous());
        let stop = harness.request(2, PrivilegedOperation::StopTunnel(resource()));
        assert!(!harness.execute(3, &stop).is_ambiguous());
        let ledger = harness.server.ledger_store.writes.last().unwrap().clone();
        let (_, next_sequence) = ledger.next_helper_session().unwrap();
        let root = harness.server.root.clone();
        let (mut recovered, principal, helper_epoch) = recover_session(
            root,
            ledger,
            FakeExecutor {
                observation_state: Some(ObservationState::Absent),
                ..FakeExecutor::default()
            },
            HelperCapability::Observe,
        );
        let request = PrivilegedRequest::new(
            &principal,
            helper_epoch,
            next_sequence,
            PrivilegedOperation::ObserveManagedAbsence(vec![wireguard_target(resource())]),
        )
        .unwrap();

        let response = recovered.handle(HelperRequest {
            id: 2,
            op: HelperOp::Execute(Box::new(request)),
        });

        assert!(response.result.is_ok(), "{:?}", response.result);
        assert_eq!(recovered.executor.observations, 1);
    }

    #[test]
    fn managed_observation_accepts_exact_wireguard_ledger_resource() {
        let mut harness = LifecycleHarness::new(FakeExecutor::default());
        let start = harness.request(1, PrivilegedOperation::StartTunnel(wireguard_plan(1)));
        assert!(!harness.execute(2, &start).is_ambiguous());
        let observe = harness.request(
            2,
            PrivilegedOperation::ObserveManaged(vec![wireguard_target(resource())]),
        );

        let receipt = harness.execute(3, &observe);

        assert!(receipt.observes(&resource(), ObservationState::Present));
        assert_eq!(
            receipt.observation(&resource()).unwrap().wireguard_peers(),
            Some([].as_slice())
        );
        assert_eq!(harness.server.executor.observations, 1);
    }

    #[test]
    fn managed_openvpn_observation_requires_closed_tunnel_and_group_set() {
        let mut harness = LifecycleHarness::new(FakeExecutor {
            foreground_start: true,
            ..FakeExecutor::default()
        });
        let start = harness.request(1, PrivilegedOperation::StartTunnel(openvpn_plan(1)));
        assert!(!harness.execute(2, &start).is_ambiguous());
        let tunnel = resource();
        let group = process_group_for_tunnel(&tunnel).unwrap();
        let incomplete = harness.request(
            2,
            PrivilegedOperation::ObserveManaged(vec![openvpn_target(tunnel.clone())]),
        );

        let rejected = harness.execute(3, &incomplete);

        assert!(rejected.is_rejected());
        assert_eq!(harness.server.executor.observations, 0);

        let complete = harness.request(
            3,
            PrivilegedOperation::ObserveManaged(vec![
                openvpn_target(tunnel.clone()),
                openvpn_target(group.clone()),
            ]),
        );
        let accepted = harness.execute(4, &complete);
        assert!(accepted.observes(&tunnel, ObservationState::Present));
        assert!(accepted.observes(&group, ObservationState::Present));
        assert_eq!(harness.server.executor.observations, 1);
    }

    #[test]
    fn managed_openvpn_observation_rejects_missing_route_evidence() {
        let mut harness = LifecycleHarness::new(FakeExecutor {
            foreground_start: true,
            openvpn_route_evidence: FakeOpenVpnRouteEvidence::Missing,
            ..FakeExecutor::default()
        });
        let start = harness.request(1, PrivilegedOperation::StartTunnel(openvpn_plan(1)));
        assert!(!harness.execute(2, &start).is_ambiguous());
        let tunnel = resource();
        let group = process_group_for_tunnel(&tunnel).unwrap();
        let observe = harness.request(
            2,
            PrivilegedOperation::ObserveManaged(vec![
                openvpn_target(tunnel),
                openvpn_target(group),
            ]),
        );

        let rejected = harness.server.handle(HelperRequest {
            id: 3,
            op: HelperOp::Execute(Box::new(observe)),
        });

        assert!(matches!(
            rejected.result,
            Err(HelperError::LedgerUnavailable)
        ));
        assert_eq!(harness.server.executor.observations, 1);
    }

    #[test]
    fn failed_replay_persistence_prevents_execution_and_poisons_session() {
        let (root, principal, claim, helper_epoch, baseline) = fixture();
        let mut server = EnrolledHelperSession::resume(
            root,
            helper_epoch,
            baseline,
            FakeExecutor::default(),
            MemoryHelperLedgerStore {
                writes: Vec::new(),
                fail: true,
                ..MemoryHelperLedgerStore::default()
            },
        )
        .unwrap();
        server.handle(HelperRequest {
            id: 1,
            op: HelperOp::Handshake(HelperClientHello::current(
                501,
                claim,
                vec![HelperCapability::Observe],
            )),
        });
        let request = PrivilegedRequest::new(
            &principal,
            helper_epoch,
            RequestSequence::new(1).unwrap(),
            PrivilegedOperation::Observe(vec![wireguard_target(resource())]),
        )
        .unwrap();
        let response = server.handle(HelperRequest {
            id: 2,
            op: HelperOp::Execute(Box::new(request)),
        });
        assert!(matches!(
            response.result,
            Err(HelperError::LedgerUnavailable)
        ));
    }

    #[test]
    fn failed_post_start_ownership_persistence_keeps_pending_intent_and_poisons() {
        let mut harness = LifecycleHarness::new(FakeExecutor::default());
        harness.server.ledger_store.fail_on_write = Some(2);
        let start = harness.request(1, PrivilegedOperation::StartTunnel(wireguard_plan(1)));

        let response = harness.server.handle(HelperRequest {
            id: 2,
            op: HelperOp::Execute(Box::new(start)),
        });

        assert!(matches!(
            response.result,
            Err(HelperError::LedgerUnavailable)
        ));
        assert!(harness.server.poisoned);
        assert_eq!(harness.server.executor.starts, 1);
        let persisted = harness.server.ledger_store.writes.last().unwrap();
        assert_eq!(persisted.resources().len(), 1);
        assert_eq!(
            persisted.resources()[0].state(),
            HelperResourceState::PendingEffect
        );
    }

    #[test]
    fn failed_openvpn_ownership_persistence_contains_unrecorded_child() {
        let mut harness = LifecycleHarness::new(FakeExecutor {
            foreground_start: true,
            ..FakeExecutor::default()
        });
        harness.server.ledger_store.fail_on_write = Some(2);
        let start = harness.request(1, PrivilegedOperation::StartTunnel(openvpn_plan(1)));

        let response = harness.server.handle(HelperRequest {
            id: 2,
            op: HelperOp::Execute(Box::new(start)),
        });

        assert!(matches!(
            response.result,
            Err(HelperError::LedgerUnavailable)
        ));
        assert_eq!(harness.server.executor.containments, 1);
        assert!(harness.server.poisoned);
        let persisted = harness.server.ledger_store.writes.last().unwrap();
        assert_eq!(persisted.resources().len(), 2);
        assert!(persisted
            .resources()
            .iter()
            .all(|entry| entry.state() == HelperResourceState::PendingEffect));
    }

    #[test]
    fn sent_request_without_receipt_requires_observation_before_retry() {
        let (_root, principal, _claim, helper_epoch, _baseline) = fixture();
        let request = PrivilegedRequest::new(
            &principal,
            helper_epoch,
            RequestSequence::new(1).unwrap(),
            PrivilegedOperation::Observe(vec![wireguard_target(resource())]),
        )
        .unwrap();
        let mut delivery = DeliveryState::prepared(request);
        assert_eq!(delivery.transport_lost(), RecoveryAction::Unavailable);
        delivery.mark_sent();
        assert_eq!(delivery.transport_lost(), RecoveryAction::ReconcileRequired);
    }

    #[test]
    fn scalar_peer_claim_cannot_replace_service_verification() {
        let (root, _principal, claim, helper_epoch, baseline) = fixture();
        let mut server = EnrolledHelperSession::resume(
            root,
            helper_epoch,
            baseline,
            FakeExecutor::default(),
            MemoryHelperLedgerStore::default(),
        )
        .unwrap();
        let wrong_peer = PeerProcessIdentity::untrusted_claim(501, 43, 99).unwrap();
        assert_ne!(
            wrong_peer,
            PeerProcessIdentity::untrusted_claim(501, 42, 99).unwrap()
        );
        let forged = ServiceInstanceClaim::systemd(
            43,
            claim.process_start_token(),
            claim.executable_digest(),
            claim.manager_instance_nonce(),
        )
        .unwrap();
        let response = server.handle(HelperRequest {
            id: 1,
            op: HelperOp::Handshake(HelperClientHello::current(
                501,
                forged,
                vec![HelperCapability::Observe],
            )),
        });
        assert!(matches!(
            response.result,
            Err(HelperError::AuthenticationFailed)
        ));
    }

    #[test]
    fn connection_requires_exactly_one_successful_handshake() {
        let (root, principal, claim, helper_epoch, baseline) = fixture();
        let mut server = EnrolledHelperSession::resume(
            root,
            helper_epoch,
            baseline,
            FakeExecutor::default(),
            MemoryHelperLedgerStore::default(),
        )
        .unwrap();
        let request = PrivilegedRequest::new(
            &principal,
            helper_epoch,
            RequestSequence::new(1).unwrap(),
            PrivilegedOperation::Observe(vec![wireguard_target(resource())]),
        )
        .unwrap();
        assert!(matches!(
            server
                .handle(HelperRequest {
                    id: 1,
                    op: HelperOp::Execute(Box::new(request)),
                })
                .result,
            Err(HelperError::AuthenticationFailed)
        ));

        let hello = HelperClientHello::current(501, claim, vec![HelperCapability::Observe]);
        assert!(server
            .handle(HelperRequest {
                id: 2,
                op: HelperOp::Handshake(hello.clone()),
            })
            .result
            .is_ok());
        assert!(matches!(
            server
                .handle(HelperRequest {
                    id: 3,
                    op: HelperOp::Handshake(hello),
                })
                .result,
            Err(HelperError::Malformed { .. })
        ));
    }

    #[test]
    fn restricted_session_rejects_unadvertised_operation_before_admission() {
        let (root, principal, claim, helper_epoch, baseline) = fixture();
        let mut server = EnrolledHelperSession::resume_restricted(
            root,
            helper_epoch,
            baseline,
            FakeExecutor::default(),
            MemoryHelperLedgerStore::default(),
            vec![HelperCapability::Handshake, HelperCapability::Observe],
        )
        .unwrap();
        assert!(server
            .handle(HelperRequest {
                id: 1,
                op: HelperOp::Handshake(HelperClientHello::current(
                    501,
                    claim,
                    vec![HelperCapability::Observe],
                )),
            })
            .result
            .is_ok());
        let request = PrivilegedRequest::new(
            &principal,
            helper_epoch,
            RequestSequence::new(1).unwrap(),
            PrivilegedOperation::StartTunnel(wireguard_plan(1)),
        )
        .unwrap();
        assert!(matches!(
            server
                .handle(HelperRequest {
                    id: 2,
                    op: HelperOp::Execute(Box::new(request)),
                })
                .result,
            Err(HelperError::CapabilityUnavailable {
                capability: HelperCapability::TunnelLifecycle
            })
        ));
        assert_eq!(server.executor.starts, 0);
        assert!(server.ledger_store.writes.is_empty());
    }

    #[test]
    fn schema_v4_session_rejects_managed_observation_before_admission() {
        let (root, principal, claim, helper_epoch, baseline) = fixture();
        let mut server = EnrolledHelperSession::resume(
            root,
            helper_epoch,
            baseline,
            FakeExecutor::default(),
            MemoryHelperLedgerStore::default(),
        )
        .unwrap();
        let mut hello = HelperClientHello::current(
            501,
            claim,
            vec![HelperCapability::Handshake, HelperCapability::Observe],
        );
        hello.schema.max = 4;
        assert!(server
            .handle(HelperRequest {
                id: 1,
                op: HelperOp::Handshake(hello),
            })
            .result
            .is_ok());
        let request = PrivilegedRequest::new(
            &principal,
            helper_epoch,
            RequestSequence::new(1).unwrap(),
            PrivilegedOperation::ObserveManaged(vec![wireguard_target(resource())]),
        )
        .unwrap();

        let response = server.handle(HelperRequest {
            id: 2,
            op: HelperOp::Execute(Box::new(request)),
        });

        assert!(matches!(
            response.result,
            Err(HelperError::Incompatible { .. })
        ));
        assert_eq!(server.executor.observations, 0);
        assert!(server.ledger_store.writes.is_empty());
    }

    #[test]
    fn forged_receipt_binding_never_authenticates() {
        let (root, principal, claim, helper_epoch, baseline) = fixture();
        let mut server = EnrolledHelperSession::resume(
            root,
            helper_epoch,
            baseline,
            FakeExecutor::default(),
            MemoryHelperLedgerStore::default(),
        )
        .unwrap();
        let handshake = server.handle(HelperRequest {
            id: 1,
            op: HelperOp::Handshake(HelperClientHello::current(
                501,
                claim,
                vec![HelperCapability::Observe],
            )),
        });
        let HelperResult::Handshake(server_hello) = handshake.result.unwrap() else {
            panic!("expected handshake");
        };
        let client = AuthenticatedHelperSession::from_handshake(
            &principal,
            &verified_helper_peer(),
            &server_hello,
        )
        .unwrap();
        let request = PrivilegedRequest::new(
            &principal,
            helper_epoch,
            RequestSequence::new(1).unwrap(),
            PrivilegedOperation::Observe(vec![wireguard_target(resource())]),
        )
        .unwrap();
        let mut response = server.handle(HelperRequest {
            id: 2,
            op: HelperOp::Execute(Box::new(request.clone())),
        });
        let Ok(HelperResult::Receipt(value)) = &mut response.result else {
            panic!("expected receipt");
        };
        value["helper_epoch"] = serde_json::json!(99);
        assert!(client.verify_receipt(2, &request, response).is_err());
    }

    #[test]
    fn tunnel_start_is_owned_duplicate_safe_and_stops_only_after_absence() {
        let mut harness = LifecycleHarness::new(FakeExecutor::default());
        let start = harness.request(1, PrivilegedOperation::StartTunnel(wireguard_plan(1)));

        for id in [2, 3] {
            let receipt = harness.execute(id, &start);
            assert!(!receipt.is_ambiguous());
        }
        assert_eq!(harness.server.executor.starts, 1);
        assert!(harness.server.owns_tunnel(&resource()));
        assert!(harness.server.children.is_empty());

        let stop = harness.request(2, PrivilegedOperation::StopTunnel(resource()));
        let receipt = harness.execute(4, &stop);
        assert!(!receipt.is_ambiguous());
        assert_eq!(harness.server.executor.stops, 1);
        assert_eq!(harness.server.executor.stops_with_child, 0);
        assert!(!harness.server.owns_tunnel(&resource()));
        assert!(harness.server.children.is_empty());
        assert_eq!(harness.server.ledger_store.writes.len(), 4);
    }

    #[test]
    fn failed_post_stop_persistence_keeps_release_intent_and_poisons() {
        let mut harness = LifecycleHarness::new(FakeExecutor::default());
        let start = harness.request(1, PrivilegedOperation::StartTunnel(wireguard_plan(1)));
        assert!(!harness.execute(2, &start).is_ambiguous());
        harness.server.ledger_store.fail_on_write = Some(4);
        let stop = harness.request(2, PrivilegedOperation::StopTunnel(resource()));

        let response = harness.server.handle(HelperRequest {
            id: 3,
            op: HelperOp::Execute(Box::new(stop)),
        });

        assert!(matches!(
            response.result,
            Err(HelperError::LedgerUnavailable)
        ));
        assert!(harness.server.poisoned);
        assert_eq!(harness.server.executor.stops, 1);
        let persisted = harness.server.ledger_store.writes.last().unwrap();
        assert_eq!(persisted.resources().len(), 1);
        assert_eq!(
            persisted.resources()[0].state(),
            HelperResourceState::PendingRelease
        );
    }

    #[test]
    fn stop_never_reaches_executor_without_exact_helper_ownership() {
        let mut harness = LifecycleHarness::new(FakeExecutor::default());
        let stop = harness.request(1, PrivilegedOperation::StopTunnel(resource()));

        harness.execute(2, &stop);
        assert_eq!(harness.server.executor.stops, 0);
        assert!(!harness.server.owns_tunnel(&resource()));
        assert!(harness.server.children.is_empty());
    }

    #[test]
    fn openvpn_start_claims_foreground_child_and_stop_reaps_it() {
        let mut harness = LifecycleHarness::new(FakeExecutor {
            foreground_start: true,
            ..FakeExecutor::default()
        });
        let start = harness.request(1, PrivilegedOperation::StartTunnel(openvpn_plan(1)));
        assert!(!harness.execute(2, &start).is_ambiguous());
        assert!(harness.server.owns_tunnel(&resource()));
        assert_eq!(harness.server.children.len(), 1);

        let stop = harness.request(2, PrivilegedOperation::StopTunnel(resource()));
        assert!(!harness.execute(3, &stop).is_ambiguous());
        assert_eq!(harness.server.executor.stops_with_child, 1);
        assert!(!harness.server.owns_tunnel(&resource()));
        assert!(harness.server.children.is_empty());
    }

    #[test]
    fn released_identity_replacement_is_atomic_across_protocol_changes() {
        let mut harness = LifecycleHarness::new(FakeExecutor {
            foreground_start: true,
            ..FakeExecutor::default()
        });
        let profile = resource().profile_id().unwrap().clone();
        let first = resource();
        let second = ResourceTag::tunnel(profile, 2).unwrap();

        let start = harness.request(1, PrivilegedOperation::StartTunnel(openvpn_plan(1)));
        let receipt = harness.execute(2, &start);
        assert_eq!(receipt.rejection_code(), None);
        assert!(!receipt.is_ambiguous());
        let stop = harness.request(2, PrivilegedOperation::StopTunnel(first));
        let receipt = harness.execute(3, &stop);
        assert_eq!(receipt.rejection_code(), None);
        assert!(!receipt.is_ambiguous());

        harness.server.executor.foreground_start = false;
        let start = harness.request(3, PrivilegedOperation::StartTunnel(wireguard_plan(2)));
        let receipt = harness.execute(4, &start);
        assert_eq!(receipt.rejection_code(), None);
        assert!(!receipt.is_ambiguous());
        let stop = harness.request(4, PrivilegedOperation::StopTunnel(second.clone()));
        let receipt = harness.execute(5, &stop);
        assert_eq!(receipt.rejection_code(), None);
        assert!(!receipt.is_ambiguous());

        assert!(!harness.server.poisoned);
        assert_eq!(
            harness
                .server
                .ledger_store
                .writes
                .last()
                .unwrap()
                .released_resources(),
            &[second]
        );
    }

    #[test]
    fn restart_restores_resources_but_keeps_child_identity_observation_only() {
        let mut harness = LifecycleHarness::new(FakeExecutor {
            foreground_start: true,
            ..FakeExecutor::default()
        });
        let start = harness.request(1, PrivilegedOperation::StartTunnel(openvpn_plan(1)));
        assert!(!harness.execute(2, &start).is_ambiguous());
        let ledger = harness.server.ledger_store.writes.last().unwrap().clone();
        let root = harness.server.root.clone();
        let (_fixture_root, principal, claim, _old_epoch, _baseline) = fixture();
        let helper_epoch = HelperEpoch::new(9).unwrap();
        let mut recovered = EnrolledHelperSession::recover(
            root,
            helper_epoch,
            ledger,
            FakeExecutor::default(),
            MemoryHelperLedgerStore::default(),
        )
        .unwrap();

        let handshake = recovered.handle(HelperRequest {
            id: 1,
            op: HelperOp::Handshake(HelperClientHello::current(
                501,
                claim,
                vec![HelperCapability::TunnelLifecycle],
            )),
        });
        assert!(handshake.result.is_ok());
        assert!(recovered.owns_tunnel(&resource()));
        assert!(matches!(
            recovered.children.get(&resource()),
            Some(ChildEvidence::Recovered(_))
        ));

        let stop = PrivilegedRequest::new(
            &principal,
            helper_epoch,
            RequestSequence::new(2).unwrap(),
            PrivilegedOperation::StopTunnel(resource()),
        )
        .unwrap();
        let response = recovered.handle(HelperRequest {
            id: 2,
            op: HelperOp::Execute(Box::new(stop)),
        });
        assert!(response.result.is_ok());
        assert_eq!(recovered.executor.stops_with_child, 1);
        assert!(recovered.children.is_empty());
    }

    #[test]
    fn restart_scan_promotes_pending_wireguard_only_after_exact_presence() {
        let (root, ledger) = pending_tunnel_ledger([wireguard_plan(1)]);
        let (mut recovered, principal, helper_epoch) = recover_session(
            root,
            ledger,
            FakeExecutor::default(),
            HelperCapability::Observe,
        );
        assert!(!recovered.owns_tunnel(&resource()));

        let observe = managed_observation_request(
            &principal,
            helper_epoch,
            2,
            vec![wireguard_target(resource())],
        );
        let response = recovered.handle(HelperRequest {
            id: 2,
            op: HelperOp::Execute(Box::new(observe)),
        });

        assert!(response.result.is_ok());
        assert!(recovered.owns_tunnel(&resource()));
        let persisted = recovered.ledger_store.writes.last().unwrap();
        assert_eq!(persisted.resources().len(), 1);
        assert_eq!(persisted.resources()[0].state(), HelperResourceState::Owned);
    }

    #[test]
    fn restart_scan_requires_openvpn_topology_and_containment_identity() {
        let (root, ledger) = pending_tunnel_ledger([openvpn_plan(1)]);
        let (mut without_child, principal, helper_epoch) = recover_session(
            root.clone(),
            ledger.clone(),
            FakeExecutor::default(),
            HelperCapability::Observe,
        );
        let tunnel = resource();
        let group = process_group_for_tunnel(&tunnel).unwrap();
        let observe = managed_observation_request(
            &principal,
            helper_epoch,
            2,
            vec![
                openvpn_target(tunnel.clone()),
                openvpn_target(group.clone()),
            ],
        );

        assert!(without_child
            .handle(HelperRequest {
                id: 2,
                op: HelperOp::Execute(Box::new(observe)),
            })
            .result
            .is_ok());
        assert!(!without_child.owns_tunnel(&tunnel));
        assert!(without_child.children.is_empty());

        let (mut with_child, principal, helper_epoch) = recover_session(
            root,
            ledger,
            FakeExecutor {
                child_observation: FakeChildObservation::Matching,
                ..FakeExecutor::default()
            },
            HelperCapability::Observe,
        );
        let observe = managed_observation_request(
            &principal,
            helper_epoch,
            2,
            vec![openvpn_target(tunnel.clone()), openvpn_target(group)],
        );
        assert!(with_child
            .handle(HelperRequest {
                id: 2,
                op: HelperOp::Execute(Box::new(observe)),
            })
            .result
            .is_ok());
        assert!(with_child.owns_tunnel(&tunnel));
        assert!(matches!(
            with_child.children.get(&tunnel),
            Some(ChildEvidence::Recovered(_))
        ));
        let persisted = with_child.ledger_store.writes.last().unwrap();
        assert!(persisted
            .resources()
            .iter()
            .all(|entry| entry.state() == HelperResourceState::Owned));
    }

    #[test]
    fn restart_scan_rejects_foreign_child_evidence_without_minting_ownership() {
        let (root, ledger) = pending_tunnel_ledger([openvpn_plan(1)]);
        let (mut recovered, principal, helper_epoch) = recover_session(
            root,
            ledger,
            FakeExecutor {
                child_observation: FakeChildObservation::Foreign,
                ..FakeExecutor::default()
            },
            HelperCapability::Observe,
        );
        let tunnel = resource();
        let group = process_group_for_tunnel(&tunnel).unwrap();
        let observe = managed_observation_request(
            &principal,
            helper_epoch,
            2,
            vec![openvpn_target(tunnel.clone()), openvpn_target(group)],
        );

        assert!(recovered
            .handle(HelperRequest {
                id: 2,
                op: HelperOp::Execute(Box::new(observe)),
            })
            .result
            .is_ok());
        assert!(!recovered.owns_tunnel(&tunnel));
        assert!(recovered.children.is_empty());
        assert!(recovered
            .resource_states
            .values()
            .all(|state| *state == HelperResourceState::PendingEffect));
        assert_eq!(recovered.ledger_store.writes.len(), 1);
    }

    #[test]
    fn restart_scan_reconciles_each_openvpn_tunnel_independently() {
        let (root, ledger) =
            pending_tunnel_ledger([openvpn_plan_for("a", 1), openvpn_plan_for("b", 1)]);
        let (mut recovered, principal, helper_epoch) = recover_session(
            root,
            ledger,
            FakeExecutor {
                child_observation: FakeChildObservation::Matching,
                ..FakeExecutor::default()
            },
            HelperCapability::Observe,
        );
        let tunnels = ["a", "b"].map(|profile| {
            ResourceTag::tunnel(
                ProfileId::parse(profile.repeat(ProfileId::HEX_LEN)).unwrap(),
                1,
            )
            .unwrap()
        });
        let targets = tunnels
            .iter()
            .flat_map(|tunnel| [tunnel.clone(), process_group_for_tunnel(tunnel).unwrap()])
            .map(openvpn_target)
            .collect();
        let observe = managed_observation_request(&principal, helper_epoch, 3, targets);

        assert!(recovered
            .handle(HelperRequest {
                id: 4,
                op: HelperOp::Execute(Box::new(observe)),
            })
            .result
            .is_ok());
        assert!(tunnels.iter().all(|tunnel| recovered.owns_tunnel(tunnel)));
        assert_eq!(recovered.children.len(), 2);
        assert!(recovered
            .children
            .values()
            .all(|child| matches!(child, ChildEvidence::Recovered(_))));
    }

    #[test]
    fn failed_recovery_transition_persistence_poisons_without_reporting_success() {
        let (root, ledger) = pending_tunnel_ledger([wireguard_plan(1)]);
        let (mut recovered, principal, helper_epoch) = recover_session(
            root,
            ledger,
            FakeExecutor::default(),
            HelperCapability::Observe,
        );
        recovered.ledger_store.fail_on_write = Some(2);
        let observe = managed_observation_request(
            &principal,
            helper_epoch,
            2,
            vec![wireguard_target(resource())],
        );

        let response = recovered.handle(HelperRequest {
            id: 2,
            op: HelperOp::Execute(Box::new(observe)),
        });

        assert!(matches!(
            response.result,
            Err(HelperError::LedgerUnavailable)
        ));
        assert!(recovered.poisoned);
        let persisted = recovered.ledger_store.writes.last().unwrap();
        assert_eq!(persisted.resources().len(), 1);
        assert_eq!(
            persisted.resources()[0].state(),
            HelperResourceState::PendingEffect
        );
    }

    #[test]
    fn restart_scan_clears_pending_wireguard_only_after_exact_absence() {
        let (root, ledger) = pending_tunnel_ledger([wireguard_plan(1)]);
        let (mut recovered, principal, helper_epoch) = recover_session(
            root,
            ledger,
            FakeExecutor {
                observation_state: Some(ObservationState::Absent),
                ..FakeExecutor::default()
            },
            HelperCapability::Observe,
        );
        let observe = managed_observation_request(
            &principal,
            helper_epoch,
            2,
            vec![wireguard_target(resource())],
        );

        assert!(recovered
            .handle(HelperRequest {
                id: 2,
                op: HelperOp::Execute(Box::new(observe)),
            })
            .result
            .is_ok());
        assert!(!recovered.resource_states.contains_key(&resource()));
        assert!(recovered
            .ledger_store
            .writes
            .last()
            .unwrap()
            .resources()
            .is_empty());
    }

    #[test]
    fn restart_scan_completes_pending_release_after_exact_absence() {
        for (plan, executor) in [
            (wireguard_plan(1), FakeExecutor::default()),
            (
                openvpn_plan(1),
                FakeExecutor {
                    foreground_start: true,
                    ..FakeExecutor::default()
                },
            ),
        ] {
            let (root, ledger, tunnel) = pending_release_ledger(plan, executor);
            let resources = if ledger.resources().len() == 2 {
                vec![tunnel.clone(), process_group_for_tunnel(&tunnel).unwrap()]
            } else {
                vec![tunnel.clone()]
            };
            let targets = resources
                .into_iter()
                .map(if ledger.resources().len() == 2 {
                    openvpn_target
                } else {
                    wireguard_target
                })
                .collect();
            assert!(ledger
                .resources()
                .iter()
                .all(|entry| entry.state() == HelperResourceState::PendingRelease));
            let (mut recovered, principal, helper_epoch) = recover_session(
                root,
                ledger,
                FakeExecutor {
                    observation_state: Some(ObservationState::Absent),
                    ..FakeExecutor::default()
                },
                HelperCapability::Observe,
            );
            let observe = managed_observation_request(&principal, helper_epoch, 3, targets);

            assert!(recovered
                .handle(HelperRequest {
                    id: 4,
                    op: HelperOp::Execute(Box::new(observe)),
                })
                .result
                .is_ok());
            assert!(recovered.resource_states.is_empty());
            assert!(recovered.children.is_empty());
            assert!(recovered
                .ledger_store
                .writes
                .last()
                .unwrap()
                .resources()
                .is_empty());
        }
    }

    #[test]
    fn foreign_start_evidence_is_contained_without_minting_ownership() {
        let mut harness = LifecycleHarness::new(FakeExecutor {
            foreground_start: true,
            foreign_start: true,
            ..FakeExecutor::default()
        });
        let start = harness.request(1, PrivilegedOperation::StartTunnel(openvpn_plan(1)));

        harness.execute(2, &start);
        assert_eq!(harness.server.executor.starts, 1);
        assert_eq!(harness.server.executor.containments, 1);
        assert!(!harness.server.owns_tunnel(&resource()));
        assert!(harness.server.children.is_empty());
    }

    #[test]
    fn failed_foreign_containment_stays_ambiguous() {
        let mut harness = LifecycleHarness::new(FakeExecutor {
            foreground_start: true,
            foreign_start: true,
            containment_fails: true,
            ..FakeExecutor::default()
        });
        let start = harness.request(1, PrivilegedOperation::StartTunnel(openvpn_plan(1)));

        assert!(harness.execute(2, &start).is_ambiguous());
        assert_eq!(harness.server.executor.containments, 1);
        assert!(!harness.server.owns_tunnel(&resource()));
        assert!(harness.server.children.is_empty());
    }

    #[test]
    fn uncertain_start_is_ambiguous_and_duplicate_never_reexecutes() {
        let mut harness = LifecycleHarness::new(FakeExecutor {
            start_error: Some(PrivilegedExecutionError::EffectMayHaveApplied),
            ..FakeExecutor::default()
        });
        let start = harness.request(1, PrivilegedOperation::StartTunnel(wireguard_plan(1)));

        for id in [2, 3] {
            let receipt = harness.execute(id, &start);
            assert!(receipt.is_ambiguous());
        }
        assert_eq!(harness.server.executor.starts, 1);
        assert!(!harness.server.owns_tunnel(&resource()));
        assert!(harness.server.children.is_empty());
    }

    #[test]
    fn cleanup_reaches_executor_only_for_exact_owned_resources_and_is_duplicate_safe() {
        let mut harness = LifecycleHarness::for_cleanup(FakeExecutor {
            foreground_start: true,
            ..FakeExecutor::default()
        });
        let start = harness.request(1, PrivilegedOperation::StartTunnel(openvpn_plan(1)));
        assert!(!harness.execute(2, &start).is_ambiguous());
        let tunnel = resource();
        let group = ResourceTag::profile(
            tunnel.profile_id().unwrap().clone(),
            tunnel.generation(),
            ResourceKind::ProcessGroup,
        )
        .unwrap();
        let cleanup = harness.request(2, PrivilegedOperation::CleanupOwned(vec![tunnel, group]));

        for id in [3, 4] {
            assert!(!harness.execute(id, &cleanup).is_ambiguous());
        }
        assert_eq!(harness.server.executor.cleanups, 1);
        assert_eq!(harness.server.executor.cleanup_children, 1);
        assert!(!harness.server.owns_tunnel(&resource()));
        assert!(harness.server.children.is_empty());
    }

    #[test]
    fn forged_cleanup_ownership_never_reaches_executor() {
        let mut harness = LifecycleHarness::for_cleanup(FakeExecutor::default());
        let start = harness.request(1, PrivilegedOperation::StartTunnel(wireguard_plan(1)));
        assert!(!harness.execute(2, &start).is_ambiguous());
        let secret = ResourceTag::profile(
            resource().profile_id().unwrap().clone(),
            1,
            ResourceKind::RuntimeSecret,
        )
        .unwrap();
        let cleanup = harness.request(
            2,
            PrivilegedOperation::CleanupOwned(vec![resource(), secret]),
        );

        assert!(!harness.execute(3, &cleanup).is_ambiguous());
        assert_eq!(harness.server.executor.cleanups, 0);
        assert!(harness.server.owns_tunnel(&resource()));
    }

    #[test]
    fn empty_cleanup_never_reaches_executor() {
        let mut harness = LifecycleHarness::for_cleanup(FakeExecutor::default());
        let cleanup = harness.request(1, PrivilegedOperation::CleanupOwned(Vec::new()));

        assert!(!harness.execute(2, &cleanup).is_ambiguous());
        assert_eq!(harness.server.executor.cleanups, 0);
    }

    #[test]
    fn cleanup_keeps_ownership_when_absence_cannot_be_proven() {
        let mut harness = LifecycleHarness::for_cleanup(FakeExecutor::default());
        let start = harness.request(1, PrivilegedOperation::StartTunnel(wireguard_plan(1)));
        assert!(!harness.execute(2, &start).is_ambiguous());
        harness.server.executor.cleanup_evidence = FakeCleanupEvidence::Present;
        let cleanup = harness.request(2, PrivilegedOperation::CleanupOwned(vec![resource()]));

        for id in [3, 4] {
            assert!(harness.execute(id, &cleanup).is_ambiguous());
        }
        assert_eq!(harness.server.executor.cleanups, 1);
        assert!(harness.server.owns_tunnel(&resource()));
    }

    #[test]
    fn network_policy_barrier_is_confirmed_and_persisted_before_next_phase() {
        let mut harness = LifecycleHarness::for_policy(FakeExecutor::default());
        let firewall = ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Firewall).unwrap();
        let blocking = harness.request(
            1,
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::EstablishBlocking {
                policy: firewall.clone(),
                tunnels: Vec::new(),
            }),
        );
        assert!(!harness.execute(2, &blocking).is_ambiguous());
        let unobserved = harness.server.guard.policy_predecessor().unwrap();

        let barrier = harness.request(
            2,
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ObserveBarrier {
                policy: firewall,
                predecessor: unobserved,
            }),
        );
        assert!(!harness.execute(3, &barrier).is_ambiguous());
        assert!(!harness.execute(4, &barrier).is_ambiguous());
        let observed = harness.server.guard.policy_predecessor().unwrap();
        assert_ne!(observed, unobserved);

        let routes = ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Routes).unwrap();
        let apply = harness.request(
            3,
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ApplyRoutes {
                policy: routes,
                routes: Vec::new(),
                redirects: Vec::new(),
                predecessor: observed,
            }),
        );
        assert!(!harness.execute(5, &apply).is_ambiguous());
        assert_eq!(harness.server.executor.policy_calls, 3);
        assert_eq!(harness.server.ledger_store.writes.len(), 5);
        let first = &harness.server.ledger_store.writes[0];
        assert_eq!(first.resources().len(), 1);
        assert_eq!(
            first.resources()[0].state(),
            HelperResourceState::PendingEffect
        );
        assert_eq!(
            first.physical_firewalls()[0].stage(),
            PhysicalFirewallStage::Prepared
        );
        assert_eq!(
            harness.server.ledger_store.writes[1].physical_firewalls()[0].stage(),
            PhysicalFirewallStage::EffectPendingObservation
        );
        let applied = &harness.server.ledger_store.writes[3];
        assert_eq!(applied.resources()[0].state(), HelperResourceState::Owned);
    }

    #[test]
    fn route_policy_requires_exact_helper_owned_tunnel_subjects() {
        fn establish(harness: &mut LifecycleHarness) -> (ResourceTag, Cidr) {
            let tunnel = resource();
            let destination: Cidr = "10.0.0.0/8".parse().unwrap();
            let firewall =
                ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Firewall).unwrap();
            execute_policy_phase(
                harness,
                1,
                NetworkPolicyOperation::EstablishBlocking {
                    policy: firewall,
                    tunnels: vec![
                        crate::vortix_core::privileged::PrivilegedFirewallTunnel::new(
                            tunnel.clone(),
                            vec!["198.51.100.7".parse().unwrap()],
                            vec![destination],
                            crate::vortix_core::privileged::PrivilegedFirewallRole::Primary,
                        )
                        .unwrap(),
                    ],
                },
            );
            (tunnel, destination)
        }

        let mut rejected = LifecycleHarness::for_policy(FakeExecutor::default());
        let (tunnel, destination) = establish(&mut rejected);
        let request = rejected.request(
            3,
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ApplyRoutes {
                policy: ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Routes).unwrap(),
                routes: vec![ScopedRoute::new(destination, tunnel).unwrap()],
                redirects: Vec::new(),
                predecessor: rejected.server.guard.policy_predecessor().unwrap(),
            }),
        );
        let receipt = rejected.execute(4, &request);
        assert!(receipt.is_rejected());
        assert_eq!(rejected.server.executor.policy_calls, 2);
        assert!(!rejected.server.poisoned);

        let mut accepted = LifecycleHarness::for_policy(FakeExecutor::default());
        let (tunnel, destination) = establish(&mut accepted);
        accepted
            .server
            .resource_states
            .insert(tunnel.clone(), HelperResourceState::Owned);
        let predecessor = accepted.server.guard.policy_predecessor().unwrap();
        execute_policy_phase(
            &mut accepted,
            3,
            NetworkPolicyOperation::ApplyRoutes {
                policy: ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Routes).unwrap(),
                routes: vec![ScopedRoute::new(destination, tunnel).unwrap()],
                redirects: Vec::new(),
                predecessor,
            },
        );
        assert_eq!(accepted.server.executor.policy_calls, 4);
    }

    #[test]
    fn failed_physical_firewall_persistence_prevents_the_first_effect() {
        for failed_write in [1, 2] {
            let mut harness = LifecycleHarness::for_policy(FakeExecutor::default());
            harness.server.ledger_store.fail_on_write = Some(failed_write);
            let firewall =
                ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Firewall).unwrap();
            let blocking = harness.request(
                1,
                PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::EstablishBlocking {
                    policy: firewall,
                    tunnels: Vec::new(),
                }),
            );

            let response = harness.server.handle(HelperRequest {
                id: 2,
                op: HelperOp::Execute(Box::new(blocking)),
            });

            assert!(matches!(
                response.result,
                Err(HelperError::LedgerUnavailable)
            ));
            assert_eq!(harness.server.executor.policy_prepares, 1);
            assert_eq!(harness.server.executor.policy_calls, 0);
            assert!(harness.server.poisoned);
        }
    }

    #[test]
    fn physical_dns_is_durable_before_effect_and_write_failure_prevents_mutation() {
        for failed_checkpoint in [1, 2] {
            let mut harness = LifecycleHarness::for_policy(FakeExecutor::default());
            let firewall =
                ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Firewall).unwrap();
            execute_policy_phase(
                &mut harness,
                1,
                NetworkPolicyOperation::EstablishBlocking {
                    policy: firewall,
                    tunnels: Vec::new(),
                },
            );
            let routes = ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Routes).unwrap();
            let predecessor = harness.server.guard.policy_predecessor().unwrap();
            execute_policy_phase(
                &mut harness,
                3,
                NetworkPolicyOperation::ApplyRoutes {
                    policy: routes,
                    routes: Vec::new(),
                    redirects: Vec::new(),
                    predecessor,
                },
            );
            let writes_before = harness.server.ledger_store.writes.len();
            let calls_before = harness.server.executor.policy_calls;
            harness.server.ledger_store.fail_on_write = Some(writes_before + failed_checkpoint);
            let dns = ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Dns).unwrap();
            let apply = harness.request(
                5,
                PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ApplyDns {
                    policy: dns,
                    assignments: Vec::new(),
                    predecessor: harness.server.guard.policy_predecessor().unwrap(),
                }),
            );

            let response = harness.server.handle(HelperRequest {
                id: 6,
                op: HelperOp::Execute(Box::new(apply)),
            });

            assert!(matches!(
                response.result,
                Err(HelperError::LedgerUnavailable)
            ));
            assert_eq!(harness.server.executor.policy_calls, calls_before);
            assert!(harness.server.poisoned);
            if failed_checkpoint == 2 {
                assert_eq!(
                    harness.server.ledger_store.writes[writes_before].physical_dns()[0].stage(),
                    PhysicalDnsStage::Prepared
                );
            }
        }
    }

    #[test]
    fn physical_routes_are_durable_before_effect_and_write_failure_prevents_mutation() {
        for failed_checkpoint in [1, 2] {
            let mut harness = LifecycleHarness::for_policy(FakeExecutor {
                prepare_physical_routes: true,
                ..FakeExecutor::default()
            });
            let tunnel = resource();
            let destination: Cidr = "10.0.0.0/8".parse().unwrap();
            let firewall =
                ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Firewall).unwrap();
            execute_policy_phase(
                &mut harness,
                1,
                NetworkPolicyOperation::EstablishBlocking {
                    policy: firewall,
                    tunnels: vec![
                        crate::vortix_core::privileged::PrivilegedFirewallTunnel::new(
                            tunnel.clone(),
                            vec!["198.51.100.7".parse().unwrap()],
                            vec![destination],
                            crate::vortix_core::privileged::PrivilegedFirewallRole::Primary,
                        )
                        .unwrap(),
                    ],
                },
            );
            harness
                .server
                .resource_states
                .insert(tunnel.clone(), HelperResourceState::Owned);
            let writes_before = harness.server.ledger_store.writes.len();
            let calls_before = harness.server.executor.policy_calls;
            harness.server.ledger_store.fail_on_write = Some(writes_before + failed_checkpoint);
            let routes = ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Routes).unwrap();
            let apply = harness.request(
                3,
                PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ApplyRoutes {
                    policy: routes,
                    routes: vec![ScopedRoute::new(destination, tunnel).unwrap()],
                    redirects: Vec::new(),
                    predecessor: harness.server.guard.policy_predecessor().unwrap(),
                }),
            );

            let response = harness.server.handle(HelperRequest {
                id: 4,
                op: HelperOp::Execute(Box::new(apply)),
            });

            assert!(matches!(
                response.result,
                Err(HelperError::LedgerUnavailable)
            ));
            assert_eq!(harness.server.executor.policy_calls, calls_before);
            assert!(harness.server.poisoned);
            if failed_checkpoint == 2 {
                assert_eq!(
                    harness.server.ledger_store.writes[writes_before].physical_routes()[0].stage(),
                    PhysicalRouteStage::Prepared
                );
            }
        }
    }

    #[test]
    fn release_rejects_obsolete_policy_without_root_ledger_ownership() {
        let mut harness = LifecycleHarness::for_policy(FakeExecutor::default());
        let firewall = ResourceTag::topology(AuthorityEpoch(3), 2, ResourceKind::Firewall).unwrap();
        let blocking = harness.request(
            1,
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::EstablishBlocking {
                policy: firewall.clone(),
                tunnels: Vec::new(),
            }),
        );
        assert!(!harness.execute(2, &blocking).is_ambiguous());
        let barrier = harness.request(
            2,
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ObserveBarrier {
                policy: firewall.clone(),
                predecessor: harness.server.guard.policy_predecessor().unwrap(),
            }),
        );
        assert!(!harness.execute(3, &barrier).is_ambiguous());
        let foreign = ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Dns).unwrap();
        let before_release = harness.server.guard.policy_predecessor().unwrap();
        let release = harness.request(
            3,
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ReleaseObsolete {
                policy: firewall,
                resources: vec![foreign],
                predecessor: before_release,
                retained_state: ObservationState::Present,
            }),
        );

        let receipt = harness.execute(4, &release);

        assert!(receipt.is_rejected());
        assert_eq!(harness.server.executor.policy_calls, 2);
        assert_eq!(
            harness.server.guard.policy_predecessor(),
            Some(before_release)
        );
    }

    #[test]
    fn restart_observes_the_persisted_intended_policy_projection() {
        let mut harness = LifecycleHarness::for_policy(FakeExecutor::default());
        let firewall = ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Firewall).unwrap();
        let blocking = harness.request(
            1,
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::EstablishBlocking {
                policy: firewall.clone(),
                tunnels: Vec::new(),
            }),
        );
        assert!(!harness.execute(2, &blocking).is_ambiguous());
        let ledger = harness.server.ledger_store.writes.last().unwrap().clone();
        let root = harness.server.root.clone();

        let (mut recovered, principal, helper_epoch) = recover_session(
            root,
            ledger,
            FakeExecutor::default(),
            HelperCapability::NetworkPolicy,
        );
        let barrier = PrivilegedRequest::new(
            &principal,
            helper_epoch,
            RequestSequence::new(2).unwrap(),
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ObserveBarrier {
                policy: firewall.clone(),
                predecessor: recovered.guard.policy_predecessor().unwrap(),
            }),
        )
        .unwrap();

        let response = recovered.handle(HelperRequest {
            id: 3,
            op: HelperOp::Execute(Box::new(barrier)),
        });

        assert!(response.result.is_ok());
        assert_eq!(recovered.executor.policy_calls, 1);
        assert_eq!(
            recovered.resource_states.get(&firewall),
            Some(&HelperResourceState::Owned)
        );
        let physical = recovered.physical_firewalls.get(&firewall).unwrap();
        assert_eq!(physical.backend(), PhysicalFirewallBackend::LinuxNft);
        assert_eq!(physical.stage(), PhysicalFirewallStage::ObservedOwned);
        let recovered_state = &recovered.executor.recovered_firewall_validations[0][0];
        assert_eq!(recovered.executor.recovered_policy_enabled, vec![true]);
        assert_eq!(recovered_state.physical().resource(), &firewall);
        assert_eq!(recovered_state.intended().policy(), &firewall);
        assert_eq!(
            recovered_state.effective().map(PolicyProjection::policy),
            None
        );
    }

    #[test]
    fn restart_passes_exact_owned_dns_projection_to_platform_validation() {
        let mut harness = LifecycleHarness::for_policy(FakeExecutor::default());
        let (_, _, dns) =
            install_policy_generation_with_mode(&mut harness, 1, 1, KillSwitchMode::Auto);
        let ledger = harness.server.ledger_store.writes.last().unwrap().clone();
        let root = harness.server.root.clone();

        let (recovered, _, _) = recover_session(
            root,
            ledger,
            FakeExecutor::default(),
            HelperCapability::NetworkPolicy,
        );

        let states = &recovered.executor.recovered_dns_validations[0];
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].state(), HelperResourceState::Owned);
        assert_eq!(states[0].intended().policy(), &dns);
        assert_eq!(
            states[0].effective().map(PolicyProjection::policy),
            Some(&dns)
        );
        assert_eq!(
            states[0].physical().map(HelperLedgerDns::resource),
            Some(&dns)
        );
        assert_eq!(
            states[0].physical().map(HelperLedgerDns::stage),
            Some(PhysicalDnsStage::ObservedAbsent)
        );
    }

    #[test]
    fn restart_passes_exact_owned_route_projection_to_platform_validation() {
        let mut harness = LifecycleHarness::for_policy(FakeExecutor::default());
        let (_, routes, _) =
            install_policy_generation_with_mode(&mut harness, 1, 1, KillSwitchMode::Auto);
        let ledger = harness.server.ledger_store.writes.last().unwrap().clone();
        let root = harness.server.root.clone();

        let (recovered, _, _) = recover_session(
            root,
            ledger,
            FakeExecutor::default(),
            HelperCapability::NetworkPolicy,
        );

        let states = &recovered.executor.recovered_route_validations[0];
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].state(), HelperResourceState::Owned);
        assert_eq!(states[0].intended().policy(), &routes);
        assert_eq!(
            states[0].effective().map(PolicyProjection::policy),
            Some(&routes)
        );
    }

    #[test]
    fn restart_restores_physical_route_ownership_and_validates_the_exact_record() {
        let mut harness = LifecycleHarness::for_policy(FakeExecutor {
            prepare_physical_routes: true,
            ..FakeExecutor::default()
        });
        let (_, routes, _) =
            install_policy_generation_with_mode(&mut harness, 1, 1, KillSwitchMode::Auto);
        let root = harness.server.root.clone();
        let ledger = harness.server.ledger_store.writes.last().unwrap().clone();

        let recovered = EnrolledHelperSession::recover(
            root,
            HelperEpoch::new(9).unwrap(),
            ledger,
            FakeExecutor::default(),
            MemoryHelperLedgerStore::default(),
        )
        .unwrap();

        let physical = recovered.physical_routes.get(&routes).unwrap();
        assert_eq!(physical.stage(), PhysicalRouteStage::ObservedAbsent);
        assert!(physical.entries().is_empty());
        assert_eq!(
            recovered.executor.recovered_route_validations[0][0]
                .physical()
                .map(HelperLedgerRoutes::resource),
            Some(&routes)
        );
    }

    #[test]
    fn restart_rejects_a_physical_firewall_backend_from_another_platform() {
        let mut harness = LifecycleHarness::for_policy(FakeExecutor::default());
        let firewall = ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Firewall).unwrap();
        execute_policy_phase(
            &mut harness,
            1,
            NetworkPolicyOperation::EstablishBlocking {
                policy: firewall,
                tunnels: Vec::new(),
            },
        );
        let root = harness.server.root.clone();
        let mut wire =
            serde_json::to_value(harness.server.ledger_store.writes.last().unwrap()).unwrap();
        wire["physical_firewalls"][0]["backend"] = serde_json::json!("mac_os_pf");
        let ledger: HelperLedgerRecord = serde_json::from_value(wire).unwrap();
        let helper_epoch = HelperEpoch::new(9).unwrap();

        let recovered = EnrolledHelperSession::recover(
            root,
            helper_epoch,
            ledger,
            FakeExecutor::default(),
            MemoryHelperLedgerStore::default(),
        );

        assert!(matches!(recovered, Err(OperationError::InvalidReplayState)));
    }

    #[test]
    fn replacement_execution_plan_carries_the_prior_effective_projection() {
        let mut harness = LifecycleHarness::for_policy(FakeExecutor::default());
        let first = ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Firewall).unwrap();
        let blocking = harness.request(
            1,
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::EstablishBlocking {
                policy: first.clone(),
                tunnels: Vec::new(),
            }),
        );
        assert!(!harness.execute(2, &blocking).is_ambiguous());
        let barrier = harness.request(
            2,
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ObserveBarrier {
                policy: first.clone(),
                predecessor: harness.server.guard.policy_predecessor().unwrap(),
            }),
        );
        assert!(!harness.execute(3, &barrier).is_ambiguous());

        let replacement =
            ResourceTag::topology(AuthorityEpoch(3), 2, ResourceKind::Firewall).unwrap();
        let blocking = harness.request(
            3,
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::EstablishBlocking {
                policy: replacement.clone(),
                tunnels: Vec::new(),
            }),
        );
        assert!(!harness.execute(4, &blocking).is_ambiguous());
        let prepared = harness.server.executor.policy_plans.last().unwrap().clone();
        let barrier = harness.request(
            4,
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ObserveBarrier {
                policy: replacement.clone(),
                predecessor: harness.server.guard.policy_predecessor().unwrap(),
            }),
        );
        assert!(!harness.execute(5, &barrier).is_ambiguous());

        let plan = prepared.execution();
        assert_eq!(plan.intended().policy(), &replacement);
        assert_eq!(
            plan.prior_effective().map(PolicyProjection::policy),
            Some(&first)
        );
        assert!(plan.obsolete_effective().is_empty());
        assert_eq!(harness.server.physical_firewalls.len(), 2);
        assert_eq!(
            harness.server.physical_firewalls[&first].stage(),
            PhysicalFirewallStage::Superseded
        );
        assert_eq!(
            plan.recovered_firewalls()
                .iter()
                .map(HelperLedgerFirewall::resource)
                .collect::<Vec<_>>(),
            vec![&first]
        );
    }

    #[test]
    fn restart_rebuilds_replacement_plan_from_persisted_root_ledger() {
        let mut harness = LifecycleHarness::for_policy(FakeExecutor::default());
        let first = ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Firewall).unwrap();
        execute_policy_phase(
            &mut harness,
            1,
            NetworkPolicyOperation::EstablishBlocking {
                policy: first.clone(),
                tunnels: Vec::new(),
            },
        );

        let replacement =
            ResourceTag::topology(AuthorityEpoch(3), 2, ResourceKind::Firewall).unwrap();
        let blocking = harness.request(
            3,
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::EstablishBlocking {
                policy: replacement.clone(),
                tunnels: Vec::new(),
            }),
        );
        assert!(!harness.execute(4, &blocking).is_ambiguous());
        let ledger = harness.server.ledger_store.writes.last().unwrap().clone();
        let root = harness.server.root.clone();

        let (mut recovered, principal, helper_epoch) = recover_session(
            root,
            ledger,
            FakeExecutor::default(),
            HelperCapability::NetworkPolicy,
        );
        let barrier = PrivilegedRequest::new(
            &principal,
            helper_epoch,
            RequestSequence::new(4).unwrap(),
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ObserveBarrier {
                policy: replacement.clone(),
                predecessor: recovered.guard.policy_predecessor().unwrap(),
            }),
        )
        .unwrap();
        let response = recovered.handle(HelperRequest {
            id: 2,
            op: HelperOp::Execute(Box::new(barrier)),
        });

        assert!(response.result.is_ok());
        let plan = recovered.executor.policy_plans.last().unwrap().execution();
        assert_eq!(plan.intended().policy(), &replacement);
        assert_eq!(
            plan.prior_effective().map(PolicyProjection::policy),
            Some(&first)
        );
    }

    #[test]
    fn release_execution_plan_carries_every_obsolete_effective_projection() {
        let mut harness = LifecycleHarness::for_policy(FakeExecutor::default());
        let (firewall_1, routes_1, dns_1) = install_policy_generation(&mut harness, 1, 1);
        let (firewall_2, routes_2, dns_2) = install_policy_generation(&mut harness, 2, 9);

        let obsolete = vec![firewall_1.clone(), routes_1.clone(), dns_1.clone()];
        let release = harness.request(
            17,
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ReleaseObsolete {
                policy: firewall_2.clone(),
                resources: obsolete.clone(),
                predecessor: harness.server.guard.policy_predecessor().unwrap(),
                retained_state: ObservationState::Present,
            }),
        );
        assert!(!harness.execute(18, &release).is_ambiguous());

        let prepared = harness.server.executor.policy_plans.last().unwrap();
        let plan = prepared.execution();
        assert_eq!(plan.intended().policy(), &firewall_2);
        assert_eq!(
            plan.prior_effective().map(PolicyProjection::policy),
            Some(&firewall_2)
        );
        assert_eq!(
            plan.obsolete_effective()
                .iter()
                .map(PolicyProjection::policy)
                .collect::<Vec<_>>(),
            obsolete.iter().collect::<Vec<_>>()
        );
        assert_eq!(
            plan.retained_effective_all()
                .iter()
                .map(PolicyProjection::policy)
                .collect::<Vec<_>>(),
            vec![&firewall_2, &routes_2, &dns_2]
        );
        assert!(plan.release_involves(ResourceKind::Firewall));
        assert!(plan.release_involves(ResourceKind::Routes));
        assert!(plan.release_involves(ResourceKind::Dns));
        assert!(!plan.release_involves(ResourceKind::Tunnel));
        assert_eq!(plan.recovered_firewalls().len(), 2);
        assert_eq!(plan.recovered_firewalls()[0].resource(), &firewall_1);
        assert_eq!(
            plan.recovered_firewalls()[0].backend(),
            PhysicalFirewallBackend::LinuxNft
        );
        assert_eq!(plan.recovered_firewalls()[1].resource(), &firewall_2);
        assert_eq!(
            plan.recovered_firewalls()[1].stage(),
            PhysicalFirewallStage::ObservedOwned
        );
        assert_eq!(
            prepared.prepared_firewalls()[0].stage(),
            PhysicalFirewallStage::SupersededReleasePending
        );
        assert_eq!(
            prepared.prepared_firewalls()[1].stage(),
            PhysicalFirewallStage::ObservedOwned
        );
    }

    #[test]
    fn policy_failure_before_effect_rolls_back_intent_but_not_replay() {
        let mut harness = LifecycleHarness::for_policy(FakeExecutor {
            policy_prepare_error: Some(NetworkPolicyPreparationError::FailedBeforeEffect),
            ..FakeExecutor::default()
        });
        let firewall = ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Firewall).unwrap();
        let blocking = harness.request(
            1,
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::EstablishBlocking {
                policy: firewall.clone(),
                tunnels: Vec::new(),
            }),
        );

        let receipt = harness.execute(2, &blocking);

        assert!(receipt.is_rejected());
        assert!(harness.server.guard.policy_predecessor().is_none());
        assert!(!harness.server.resource_states.contains_key(&firewall));
        assert!(!harness.server.policy_projections.contains_key(&firewall));
        assert!(harness
            .server
            .ledger_store
            .writes
            .last()
            .unwrap()
            .resources()
            .is_empty());
    }

    #[test]
    fn failed_barrier_confirmation_persistence_poisons_policy_session() {
        let mut harness = LifecycleHarness::for_policy(FakeExecutor::default());
        let firewall = ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Firewall).unwrap();
        let blocking = harness.request(
            1,
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::EstablishBlocking {
                policy: firewall.clone(),
                tunnels: Vec::new(),
            }),
        );
        harness.execute(2, &blocking);
        let predecessor = harness.server.guard.policy_predecessor().unwrap();
        let barrier = harness.request(
            2,
            PrivilegedOperation::NetworkPolicy(NetworkPolicyOperation::ObserveBarrier {
                policy: firewall,
                predecessor,
            }),
        );
        harness.server.ledger_store.fail_on_write = Some(4);

        let response = harness.server.handle(HelperRequest {
            id: 3,
            op: HelperOp::Execute(Box::new(barrier)),
        });
        assert!(matches!(
            response.result,
            Err(HelperError::LedgerUnavailable)
        ));
        assert!(harness.server.poisoned);
        assert_eq!(harness.server.executor.policy_calls, 2);
    }
}
