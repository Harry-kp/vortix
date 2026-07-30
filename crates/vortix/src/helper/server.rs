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

use std::collections::BTreeMap;

use crate::helper::protocol::{
    negotiate_enrolled, HelperCapability, HelperClientHello, HelperError, HelperOp, HelperRequest,
    HelperResponse, HelperResult, HelperSessionBinding,
};
use crate::vortix_core::privileged::{
    AmbiguousPhase, ChildOwner, ChildSpawnAuthority, HelperEpoch, HelperLedgerRecord,
    HelperLedgerResource, HelperResourceState, NetworkPolicyOperation, ObservationState,
    ObservedChildIdentity, OperationAdmission, OperationError, OperationGuard, OwnedChild,
    PrivilegedOperation, ProtocolPlan, ReceiptError, ReceiptLedger, RejectionCode, ResourceKind,
    ResourceObservation, ResourceTag, RootAuthorityLedger, VerifiedReceipt,
};

const ENABLED_CAPABILITIES: [HelperCapability; 5] = [
    HelperCapability::Handshake,
    HelperCapability::Observe,
    HelperCapability::TunnelLifecycle,
    HelperCapability::NetworkPolicy,
    HelperCapability::CleanupOwned,
];

/// Typed platform seam for read-back. Implementations may inspect only the
/// exact canonical resource identities supplied by the admitted request.
pub(crate) trait ObservationExecutor {
    fn observe(
        &mut self,
        resources: &[ResourceTag],
    ) -> Result<Vec<ResourceObservation>, ObservationError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObservationError {
    InvalidResource,
    Overloaded,
}

/// Typed protocol lifecycle seam. `WireGuard` returns exact interface evidence
/// after its bounded setup child has exited; `OpenVPN` returns OS-observed
/// foreground containment identity, not ownership. A successful stop must mean
/// the interface is absent and any contained process group is gone and reaped.
pub(crate) trait TunnelLifecycleExecutor {
    fn start_tunnel(
        &mut self,
        plan: &ProtocolPlan,
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

/// Ordered platform-policy seam. The executor may report one applied mutation
/// phase or exact read-back observations for a barrier or release. The helper
/// derives receipt ownership from the admitted canonical operation.
pub(crate) trait NetworkPolicyExecutor {
    fn execute_network_policy(
        &mut self,
        operation: &NetworkPolicyOperation,
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
    children: BTreeMap<ResourceTag, ChildEvidence>,
    last_receipt: Option<VerifiedReceipt>,
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
            children: BTreeMap::new(),
            last_receipt: None,
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
        let principal = root.principal();
        let (replay, resources, child_observations) = ledger.into_parts();
        let baseline = root.loaded_replay_baseline(&principal, replay)?;
        let mut session = Self::resume(root, helper_epoch, baseline, executor, ledger_store)?;
        for entry in resources {
            session
                .resource_states
                .insert(entry.resource().clone(), entry.state());
        }
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
        let result = match request.op {
            HelperOp::Handshake(hello) => self.handshake(&hello).map(HelperResult::Handshake),
            HelperOp::Execute(operation) => self.execute(&operation),
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
        let response = negotiate_enrolled(
            hello,
            HelperSessionBinding {
                authority_epoch: self.root.authority_epoch(),
                lease_id: self.root.lease_id(),
                helper_epoch: self.helper_epoch,
            },
            &ENABLED_CAPABILITIES,
        )?;
        self.handshaken = true;
        Ok(response)
    }

    fn execute(
        &mut self,
        request: &crate::vortix_core::privileged::PrivilegedRequest,
    ) -> Result<HelperResult, HelperError> {
        if !self.handshaken {
            return Err(HelperError::AuthenticationFailed);
        }
        if self.poisoned {
            return Err(HelperError::LedgerUnavailable);
        }
        if !matches!(
            request.operation(),
            PrivilegedOperation::Observe(_)
                | PrivilegedOperation::StartTunnel(_)
                | PrivilegedOperation::StopTunnel(_)
                | PrivilegedOperation::NetworkPolicy(_)
                | PrivilegedOperation::CleanupOwned(_)
        ) {
            return Err(HelperError::CapabilityUnavailable {
                capability: capability_for(request.operation()),
            });
        }

        let admission = self
            .guard
            .admit(request)
            .map_err(|error| map_operation_error(&error))?;
        if admission == OperationAdmission::Duplicate {
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
            return receipt_result(receipt);
        }

        if admission == OperationAdmission::Fresh {
            // A later duplicate must never inherit the prior operation's
            // receipt if this fresh execution loses its terminal result.
            self.last_receipt = None;
            if !matches!(
                request.operation(),
                PrivilegedOperation::StartTunnel(_)
                    | PrivilegedOperation::StopTunnel(_)
                    | PrivilegedOperation::CleanupOwned(_)
            ) {
                self.persist_ledger()?;
            }
        }

        let receipt = match request.operation() {
            PrivilegedOperation::Observe(resources) => match self.executor.observe(resources) {
                Ok(observations) => self.receipts.observed(request, observations),
                Err(ObservationError::InvalidResource) => self
                    .receipts
                    .rejected(request, RejectionCode::InvalidResource),
                Err(ObservationError::Overloaded) => {
                    self.receipts.rejected(request, RejectionCode::Overloaded)
                }
            }
            .map_err(map_receipt_error),
            PrivilegedOperation::StartTunnel(plan) => self.start_tunnel(request, plan),
            PrivilegedOperation::StopTunnel(resource) => self.stop_tunnel(request, resource),
            PrivilegedOperation::NetworkPolicy(operation) => {
                self.execute_network_policy(request, operation)
            }
            PrivilegedOperation::CleanupOwned(resources) => self.cleanup_owned(request, resources),
        }?;
        self.last_receipt = Some(receipt.clone());
        receipt_result(receipt)
    }

    fn start_tunnel(
        &mut self,
        request: &crate::vortix_core::privileged::PrivilegedRequest,
        plan: &ProtocolPlan,
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

        let outcome = match self.executor.start_tunnel(plan) {
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
    ) -> Result<VerifiedReceipt, HelperError> {
        let outcome = match self.executor.execute_network_policy(operation) {
            Ok(outcome) => outcome,
            Err(error) => {
                return self
                    .execution_error_receipt(request, error)
                    .map_err(map_receipt_error);
            }
        };
        let receipt = match (operation, outcome) {
            (
                NetworkPolicyOperation::EstablishBlocking { .. }
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
                NetworkPolicyOperation::ObserveBarrier { .. } => self
                    .guard
                    .confirm_observation(request, &receipt, &self.root),
                NetworkPolicyOperation::ReleaseObsolete { .. } => {
                    self.guard.confirm_release(request, &receipt, &self.root)
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
            for resource in resources {
                self.resource_states.remove(resource);
                match resource.kind() {
                    ResourceKind::ProcessGroup => {
                        if let Some(tunnel) = tunnel_for_profile_resource(resource) {
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
            ResourceKind::ProcessGroup => tunnel_for_profile_resource(resource)
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
                ResourceKind::ProcessGroup => tunnel_for_profile_resource(resource),
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
        let child_observations = self
            .children
            .iter()
            .map(|child| child.1.identity().clone())
            .collect();
        let Ok(ledger) = HelperLedgerRecord::new(checkpoint, resources, child_observations) else {
            self.poisoned = true;
            return Err(HelperError::LedgerUnavailable);
        };
        if self.ledger_store.persist(&ledger).is_err() {
            self.poisoned = true;
            return Err(HelperError::LedgerUnavailable);
        }
        Ok(())
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

fn tunnel_for_profile_resource(resource: &ResourceTag) -> Option<ResourceTag> {
    ResourceTag::tunnel(resource.profile_id()?.clone(), resource.generation()).ok()
}

fn process_group_for_tunnel(tunnel: &ResourceTag) -> Result<ResourceTag, ()> {
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

fn capability_for(operation: &PrivilegedOperation) -> HelperCapability {
    match operation {
        PrivilegedOperation::StartTunnel(_) | PrivilegedOperation::StopTunnel(_) => {
            HelperCapability::TunnelLifecycle
        }
        PrivilegedOperation::NetworkPolicy(_) => HelperCapability::NetworkPolicy,
        PrivilegedOperation::Observe(_) => HelperCapability::Observe,
        PrivilegedOperation::CleanupOwned(_) => HelperCapability::CleanupOwned,
    }
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
    use crate::helper::validate::{
        verify_helper_peer, verify_service_instance, ArtifactFact, HelperPeerFacts,
        InstallManifest, PlatformLayout, VerifiedServiceFacts,
    };
    use crate::vortix_core::cidr::Cidr;
    use crate::vortix_core::control::AuthorityEpoch;
    use crate::vortix_core::privileged::{
        BootScope, ContainmentId, LeaseId, ObservationState, OpenVpnAuthFactors, OpenVpnPlan,
        OpenVpnRemote, OpenVpnRemoteSelection, OpenVpnTransport, OperationDigest,
        PeerProcessIdentity, PrivilegedRequest, ProtocolEndpoint, RequestSequence,
        ServiceInstanceClaim, ServiceManager, WireGuardInterfaceOptions, WireGuardPeerPlan,
        WireGuardPlan,
    };
    use crate::vortix_core::profile::ProfileId;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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
    struct FakeExecutor {
        starts: usize,
        stops: usize,
        stops_with_child: usize,
        policy_calls: usize,
        cleanups: usize,
        cleanup_children: usize,
        containments: usize,
        foreground_start: bool,
        foreign_start: bool,
        containment_fails: bool,
        start_error: Option<PrivilegedExecutionError>,
        cleanup_error: Option<PrivilegedExecutionError>,
        cleanup_evidence: FakeCleanupEvidence,
    }

    impl ObservationExecutor for FakeExecutor {
        fn observe(
            &mut self,
            resources: &[ResourceTag],
        ) -> Result<Vec<ResourceObservation>, ObservationError> {
            resources
                .iter()
                .cloned()
                .map(|resource| ResourceObservation::new(resource, ObservationState::Present, 1))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ObservationError::InvalidResource)
        }
    }

    impl TunnelLifecycleExecutor for FakeExecutor {
        fn start_tunnel(
            &mut self,
            plan: &ProtocolPlan,
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
        fn execute_network_policy(
            &mut self,
            operation: &NetworkPolicyOperation,
        ) -> Result<NetworkPolicyOutcome, PrivilegedExecutionError> {
            self.policy_calls += 1;
            match operation {
                NetworkPolicyOperation::ObserveBarrier { policy, .. } => {
                    Ok(NetworkPolicyOutcome::Observed(vec![
                        ResourceObservation::new(policy.clone(), ObservationState::Present, 3)
                            .unwrap(),
                    ]))
                }
                NetworkPolicyOperation::ReleaseObsolete {
                    policy, resources, ..
                } => {
                    let mut observations = vec![ResourceObservation::new(
                        policy.clone(),
                        ObservationState::Present,
                        3,
                    )
                    .unwrap()];
                    observations.extend(resources.iter().cloned().map(|resource| {
                        ResourceObservation::new(resource, ObservationState::Absent, 3).unwrap()
                    }));
                    Ok(NetworkPolicyOutcome::Observed(observations))
                }
                NetworkPolicyOperation::EstablishBlocking { .. }
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

    fn openvpn_plan(generation: u64) -> ProtocolPlan {
        ProtocolPlan::OpenVpn(
            OpenVpnPlan::new(
                ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap(),
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
                op: HelperOp::Handshake(HelperClientHello::current(501, claim, vec![capability])),
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
            PrivilegedOperation::Observe(vec![resource()]),
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
            PrivilegedOperation::Observe(vec![resource()]),
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
            PrivilegedOperation::Observe(vec![resource()]),
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
            PrivilegedOperation::Observe(vec![resource()]),
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
            PrivilegedOperation::Observe(vec![resource()]),
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
                predecessor: observed,
            }),
        );
        assert!(!harness.execute(5, &apply).is_ambiguous());
        assert_eq!(harness.server.executor.policy_calls, 3);
        assert_eq!(harness.server.ledger_store.writes.len(), 4);
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
        harness.server.ledger_store.fail_on_write = Some(3);

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
