//! Helper-owned firewall orchestration.
//!
//! Ledger sequencing and typed policy validation stay here. Platform-specific
//! commands and read-back live behind the core owned-firewall port.

use std::fs::File;
use std::io::Read as _;

use super::observe::authority_interface_name;
use super::server::{
    NetworkPolicyExecutionPlan, NetworkPolicyOutcome, NetworkPolicyPreparationError,
    PreparedNetworkPolicyExecutionPlan, PrivilegedExecutionError, RecoveredFirewallState,
};
use super::validate::PlatformLayout;
use crate::vortix_core::ports::killswitch::ActiveTunnelInfo;
use crate::vortix_core::ports::owned_firewall::{
    ExpectedFirewallState, OwnedFirewall, OwnedFirewallError,
};
use crate::vortix_core::privileged::{
    FirewallTransactionId, HelperLedgerFirewall, LeaseId, NetworkPolicyOperation,
    PhysicalFirewallBackend, PhysicalFirewallStage, PolicyProjection, PrivilegedFirewallRole,
    ResourceObservation,
};

pub(crate) struct HelperFirewallExecutor {
    layout: PlatformLayout,
    lease_id: LeaseId,
    platform: Box<dyn OwnedFirewall>,
}

impl HelperFirewallExecutor {
    pub(crate) fn new(lease_id: LeaseId) -> Self {
        let platform = crate::platform::helper_owned_firewall();
        Self {
            layout: layout_for_backend(platform.backend()),
            lease_id,
            platform,
        }
    }

    #[cfg(test)]
    fn with_platform(
        layout: PlatformLayout,
        lease_id: LeaseId,
        platform: impl OwnedFirewall + 'static,
    ) -> Self {
        let platform = Box::new(platform);
        assert_eq!(layout, layout_for_backend(platform.backend()));
        Self {
            layout: layout_for_backend(platform.backend()),
            lease_id,
            platform,
        }
    }

    pub(crate) fn validate_recovered(
        &mut self,
        firewalls: &[RecoveredFirewallState],
        policy_enabled: bool,
    ) -> Result<(), PrivilegedExecutionError> {
        if firewalls.is_empty() {
            return if policy_enabled {
                self.platform
                    .audit_recovery(&[], true)
                    .map_err(map_execution_error)
            } else {
                Ok(())
            };
        }
        if firewalls.iter().any(|state| {
            state.physical().backend() != self.platform.backend()
                || state.physical().intended_digest() != state.intended().digest()
        }) {
            return Err(PrivilegedExecutionError::InvalidPlan);
        }

        let pending = firewalls.iter().find(|state| {
            state.physical().stage() == PhysicalFirewallStage::EffectPendingObservation
        });
        let mut expected = Vec::new();
        let mut allow_absent = false;
        if let Some(state) = pending {
            expected.push(state.intended());
            if let Some(prior) = state.effective() {
                expected.push(prior);
            }
            expected.extend(firewalls.iter().filter_map(|candidate| {
                matches!(
                    candidate.physical().stage(),
                    PhysicalFirewallStage::ObservedOwned
                        | PhysicalFirewallStage::OwnedReleasePending
                )
                .then(|| candidate.effective())
                .flatten()
            }));
        } else {
            let owner = firewalls.iter().find(|state| {
                matches!(
                    state.physical().stage(),
                    PhysicalFirewallStage::ObservedOwned
                        | PhysicalFirewallStage::OwnedReleasePending
                )
            });
            if let Some(state) = owner {
                expected.push(
                    state
                        .effective()
                        .ok_or(PrivilegedExecutionError::InvalidPlan)?,
                );
            } else {
                allow_absent = true;
            }
        }
        self.audit_recovery_expectations(&expected, allow_absent)
    }

    pub(crate) fn prepare(
        &mut self,
        plan: &NetworkPolicyExecutionPlan,
    ) -> Result<PreparedNetworkPolicyExecutionPlan, NetworkPolicyPreparationError> {
        match plan.operation() {
            NetworkPolicyOperation::EstablishFirewall { policy, .. }
            | NetworkPolicyOperation::EstablishBlocking { policy, .. }
            | NetworkPolicyOperation::ApplyFirewall { policy, .. } => {
                self.audit_before_mutation(plan)?;
                let mut firewalls = plan.recovered_firewalls().to_vec();
                let prepared = match firewalls
                    .iter()
                    .find(|physical| physical.resource() == policy)
                {
                    Some(existing) => existing
                        .prepare_for(plan.intended())
                        .map_err(|_| NetworkPolicyPreparationError::InvalidPlan)?,
                    None => HelperLedgerFirewall::prepared(
                        policy.clone(),
                        self.platform.backend(),
                        new_transaction_id()
                            .map_err(|_| NetworkPolicyPreparationError::FailedBeforeEffect)?,
                        plan.intended().digest(),
                    ),
                };
                if let Some(existing) = firewalls
                    .iter_mut()
                    .find(|physical| physical.resource() == policy)
                {
                    *existing = prepared;
                } else {
                    firewalls.push(prepared);
                }
                Ok(PreparedNetworkPolicyExecutionPlan::new(
                    plan.clone(),
                    firewalls,
                ))
            }
            NetworkPolicyOperation::ObserveBarrier { .. } => {
                Ok(PreparedNetworkPolicyExecutionPlan::new(
                    plan.clone(),
                    plan.recovered_firewalls().to_vec(),
                ))
            }
            NetworkPolicyOperation::ApplyRoutes { .. }
            | NetworkPolicyOperation::ApplyDns { .. }
            | NetworkPolicyOperation::ReleaseObsolete { .. } => {
                Err(NetworkPolicyPreparationError::InvalidPlan)
            }
        }
    }

    pub(crate) fn execute(
        &mut self,
        prepared: &PreparedNetworkPolicyExecutionPlan,
    ) -> Result<NetworkPolicyOutcome, PrivilegedExecutionError> {
        let plan = prepared.execution();
        match plan.operation() {
            NetworkPolicyOperation::EstablishFirewall { policy, .. }
            | NetworkPolicyOperation::EstablishBlocking { policy, .. }
            | NetworkPolicyOperation::ApplyFirewall { policy, .. } => {
                if !prepared.prepared_firewalls().iter().any(|physical| {
                    physical.resource() == policy
                        && physical.stage() == PhysicalFirewallStage::EffectPendingObservation
                }) {
                    return Err(PrivilegedExecutionError::InvalidPlan);
                }
                self.apply_projection(plan.intended(), plan.prior_effective())?;
                Ok(NetworkPolicyOutcome::Applied)
            }
            NetworkPolicyOperation::ObserveBarrier { policy, .. } => {
                self.audit_projection(plan.intended())?;
                Ok(NetworkPolicyOutcome::Observed(vec![
                    ResourceObservation::new(
                        policy.clone(),
                        plan.intended().expected_observation_state(),
                        1,
                    )
                    .map_err(|_| PrivilegedExecutionError::InvalidPlan)?,
                ]))
            }
            NetworkPolicyOperation::ApplyRoutes { .. }
            | NetworkPolicyOperation::ApplyDns { .. }
            | NetworkPolicyOperation::ReleaseObsolete { .. } => {
                Err(PrivilegedExecutionError::InvalidPlan)
            }
        }
    }

    pub(crate) fn prepare_release(
        &mut self,
        plan: &NetworkPolicyExecutionPlan,
    ) -> Result<(), NetworkPolicyPreparationError> {
        let (current, _) = plan
            .release_family(crate::vortix_core::privileged::ResourceKind::Firewall)
            .ok_or(NetworkPolicyPreparationError::InvalidPlan)?;
        self.audit_projection(current)
            .map_err(|_| NetworkPolicyPreparationError::FailedBeforeEffect)
    }

    pub(crate) fn execute_release(
        &mut self,
        prepared: &PreparedNetworkPolicyExecutionPlan,
    ) -> Result<(), PrivilegedExecutionError> {
        let plan = prepared.execution();
        let NetworkPolicyOperation::ReleaseObsolete { resources, .. } = plan.operation() else {
            return Err(PrivilegedExecutionError::InvalidPlan);
        };
        self.release_obsolete(prepared, resources)?;
        let (current, _) = plan
            .release_family(crate::vortix_core::privileged::ResourceKind::Firewall)
            .ok_or(PrivilegedExecutionError::InvalidPlan)?;
        self.audit_projection(current)
    }

    fn audit_before_mutation(
        &mut self,
        plan: &NetworkPolicyExecutionPlan,
    ) -> Result<(), NetworkPolicyPreparationError> {
        if let Some(prior) = plan.prior_effective() {
            self.audit_projection(prior)
        } else {
            self.audit_absent()
        }
        .map_err(|_| NetworkPolicyPreparationError::FailedBeforeEffect)
    }

    fn apply_projection(
        &mut self,
        projection: &PolicyProjection,
        prior: Option<&PolicyProjection>,
    ) -> Result<(), PrivilegedExecutionError> {
        let prior_active = prior
            .filter(|projection| projection.firewall_blocks() == Some(true))
            .map(|projection| firewall_tunnels(self.layout, self.lease_id, projection))
            .transpose()?;
        let expected = prior_active.as_deref().map_or(
            ExpectedFirewallState::Absent,
            ExpectedFirewallState::Blocking,
        );
        if projection.firewall_blocks() != Some(true) {
            self.platform.clear(expected).map_err(map_execution_error)?;
            return Ok(());
        }
        let active = firewall_tunnels(self.layout, self.lease_id, projection)?;
        self.platform
            .apply_blocking(&active, expected)
            .map_err(map_execution_error)
    }

    fn audit_projection(
        &mut self,
        projection: &PolicyProjection,
    ) -> Result<(), PrivilegedExecutionError> {
        if projection.firewall_blocks() != Some(true) {
            return self.audit_absent();
        }
        let active = firewall_tunnels(self.layout, self.lease_id, projection)?;
        self.platform
            .audit_blocking(&active)
            .map_err(map_execution_error)
    }

    fn audit_absent(&mut self) -> Result<(), PrivilegedExecutionError> {
        self.platform.audit_absent().map_err(map_execution_error)
    }

    fn audit_recovery_expectations(
        &mut self,
        projections: &[&PolicyProjection],
        mut allow_absent: bool,
    ) -> Result<(), PrivilegedExecutionError> {
        let mut blocking_candidates = Vec::new();
        for projection in projections {
            match projection.firewall_blocks() {
                Some(true) => blocking_candidates.push(firewall_tunnels(
                    self.layout,
                    self.lease_id,
                    projection,
                )?),
                Some(false) => allow_absent = true,
                None => return Err(PrivilegedExecutionError::InvalidPlan),
            }
        }
        self.platform
            .audit_recovery(&blocking_candidates, allow_absent)
            .map_err(map_execution_error)
    }

    fn release_obsolete(
        &mut self,
        prepared: &PreparedNetworkPolicyExecutionPlan,
        resources: &[crate::vortix_core::privileged::ResourceTag],
    ) -> Result<(), PrivilegedExecutionError> {
        let releasing_owner = prepared.prepared_firewalls().iter().find(|physical| {
            resources.contains(physical.resource())
                && physical.stage() == PhysicalFirewallStage::OwnedReleasePending
        });
        let retained_owner = prepared.prepared_firewalls().iter().any(|physical| {
            !resources.contains(physical.resource())
                && physical.stage() == PhysicalFirewallStage::ObservedOwned
        });
        if let Some(releasing_owner) = releasing_owner {
            if retained_owner {
                return Err(PrivilegedExecutionError::InvalidPlan);
            }
            let prior = prepared
                .execution()
                .obsolete_effective()
                .iter()
                .find(|projection| projection.policy() == releasing_owner.resource())
                .ok_or(PrivilegedExecutionError::InvalidPlan)?;
            let prior_active = firewall_tunnels(self.layout, self.lease_id, prior)?;
            self.platform
                .clear(ExpectedFirewallState::Blocking(&prior_active))
                .map_err(map_execution_error)?;
        }
        Ok(())
    }
}

const fn layout_for_backend(backend: PhysicalFirewallBackend) -> PlatformLayout {
    match backend {
        PhysicalFirewallBackend::LinuxNft | PhysicalFirewallBackend::LinuxIptablesDualFamily => {
            PlatformLayout::Linux
        }
        PhysicalFirewallBackend::MacOsPf => PlatformLayout::MacOs,
    }
}

const fn map_execution_error(error: OwnedFirewallError) -> PrivilegedExecutionError {
    match error {
        OwnedFirewallError::FailedBeforeEffect => PrivilegedExecutionError::FailedBeforeEffect,
        OwnedFirewallError::EffectMayHaveApplied => PrivilegedExecutionError::EffectMayHaveApplied,
    }
}

fn firewall_tunnels(
    layout: PlatformLayout,
    lease_id: LeaseId,
    projection: &PolicyProjection,
) -> Result<Vec<ActiveTunnelInfo>, PrivilegedExecutionError> {
    let tunnels = match projection {
        PolicyProjection::FirewallBaseline { tunnels, .. }
        | PolicyProjection::Blocking { tunnels, .. }
        | PolicyProjection::Firewall { tunnels, .. } => tunnels,
        PolicyProjection::Routes { .. } | PolicyProjection::Dns { .. } => {
            return Err(PrivilegedExecutionError::InvalidPlan);
        }
    };
    tunnels
        .iter()
        .map(|tunnel| {
            if tunnel.role() == PrivilegedFirewallRole::PendingEndpoint {
                return Ok(ActiveTunnelInfo::endpoint_allowlist(
                    tunnel.endpoint_ips().to_vec(),
                ));
            }
            let interface = authority_interface_name(layout, lease_id, tunnel.tunnel())
                .map_err(|()| PrivilegedExecutionError::FailedBeforeEffect)?;
            Ok(ActiveTunnelInfo {
                interface,
                server_ips: tunnel.endpoint_ips().to_vec(),
                declared_cidrs: tunnel.declared_cidrs().to_vec(),
                is_primary: tunnel.role() == PrivilegedFirewallRole::Primary,
            })
        })
        .collect()
}

fn new_transaction_id() -> std::io::Result<FirewallTransactionId> {
    let mut bytes = [0; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    FirewallTransactionId::new(bytes)
        .map_err(|reason| std::io::Error::new(std::io::ErrorKind::InvalidData, reason))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::vortix_core::control::AuthorityEpoch;
    use crate::vortix_core::privileged::PhysicalFirewallBackend;
    use crate::vortix_core::privileged::{
        NetworkPolicyOperation, PolicyPhase, PolicyPredecessor, PrivilegedFirewallTunnel,
        ResourceKind, ResourceTag,
    };
    use crate::vortix_core::profile::ProfileId;
    use crate::vortix_core::state::killswitch::KillSwitchMode;

    struct RecoveryAuditCounter(Arc<AtomicUsize>);

    impl OwnedFirewall for RecoveryAuditCounter {
        fn backend(&self) -> PhysicalFirewallBackend {
            PhysicalFirewallBackend::MacOsPf
        }

        fn apply_blocking(
            &mut self,
            _active: &[ActiveTunnelInfo],
            _expected: ExpectedFirewallState<'_>,
        ) -> Result<(), OwnedFirewallError> {
            unreachable!()
        }

        fn clear(
            &mut self,
            _expected: ExpectedFirewallState<'_>,
        ) -> Result<(), OwnedFirewallError> {
            unreachable!()
        }

        fn audit_blocking(
            &mut self,
            _active: &[ActiveTunnelInfo],
        ) -> Result<(), OwnedFirewallError> {
            unreachable!()
        }

        fn audit_absent(&mut self) -> Result<(), OwnedFirewallError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn audit_recovery(
            &mut self,
            blocking_candidates: &[Vec<ActiveTunnelInfo>],
            allow_absent: bool,
        ) -> Result<(), OwnedFirewallError> {
            assert!(blocking_candidates.is_empty());
            assert!(allow_absent);
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    fn tunnel() -> ResourceTag {
        ResourceTag::tunnel(ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap(), 7).unwrap()
    }

    fn policy(tunnels: Vec<PrivilegedFirewallTunnel>) -> PolicyProjection {
        PolicyProjection::Blocking {
            policy: ResourceTag::topology(AuthorityEpoch(3), 7, ResourceKind::Firewall).unwrap(),
            tunnels,
        }
    }

    fn nonblocking_policy(generation: u64) -> PolicyProjection {
        PolicyProjection::Firewall {
            policy: ResourceTag::topology(AuthorityEpoch(3), generation, ResourceKind::Firewall)
                .unwrap(),
            mode: KillSwitchMode::Off,
            tunnels: Vec::new(),
        }
    }

    #[test]
    fn linux_interface_identity_is_derived_from_lease_and_tunnel_tag() {
        let subject = PrivilegedFirewallTunnel::new(
            tunnel(),
            vec!["198.51.100.7".parse().unwrap()],
            vec!["10.0.0.0/8".parse().unwrap()],
            PrivilegedFirewallRole::Primary,
        )
        .unwrap();

        let active = firewall_tunnels(
            PlatformLayout::Linux,
            LeaseId::new([7; 32]),
            &policy(vec![subject]),
        )
        .unwrap();

        assert_eq!(active.len(), 1);
        assert!(active[0].interface.starts_with("vx"));
        assert_eq!(
            active[0].server_ips,
            vec!["198.51.100.7".parse::<std::net::IpAddr>().unwrap()]
        );
        assert!(active[0].is_primary);
    }

    #[test]
    fn pending_endpoint_never_mints_an_interface_allowance() {
        let subject = PrivilegedFirewallTunnel::new(
            tunnel(),
            vec!["198.51.100.7".parse().unwrap()],
            vec!["10.0.0.0/8".parse().unwrap()],
            PrivilegedFirewallRole::PendingEndpoint,
        )
        .unwrap();

        let active = firewall_tunnels(
            PlatformLayout::MacOs,
            LeaseId::new([7; 32]),
            &policy(vec![subject]),
        )
        .unwrap();

        assert_eq!(active.len(), 1);
        assert!(active[0].is_endpoint_allowlist());
        assert!(active[0].declared_cidrs.is_empty());
        assert_eq!(
            active[0].server_ips,
            vec!["198.51.100.7".parse::<std::net::IpAddr>().unwrap()]
        );
    }

    #[test]
    fn enabled_policy_recovery_proves_an_empty_ledger_is_absent() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut subject = HelperFirewallExecutor::with_platform(
            PlatformLayout::MacOs,
            LeaseId::new([7; 32]),
            RecoveryAuditCounter(Arc::clone(&calls)),
        );

        subject.validate_recovered(&[], false).unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        subject.validate_recovered(&[], true).unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn release_audits_only_the_retained_firewall_projection() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut subject = HelperFirewallExecutor::with_platform(
            PlatformLayout::MacOs,
            LeaseId::new([7; 32]),
            RecoveryAuditCounter(Arc::clone(&calls)),
        );
        let current = nonblocking_policy(8);
        let obsolete = nonblocking_policy(7);
        let plan = NetworkPolicyExecutionPlan::release_for_test(
            NetworkPolicyOperation::ReleaseObsolete {
                policy: current.policy().clone(),
                resources: vec![obsolete.policy().clone()],
                predecessor: PolicyPredecessor::for_test(current.digest(), PolicyPhase::Firewall),
                retained_state: crate::vortix_core::privileged::ObservationState::Absent,
            },
            vec![current],
            vec![obsolete],
            Vec::new(),
            Vec::new(),
        );

        subject.prepare_release(&plan).unwrap();
        let prepared = PreparedNetworkPolicyExecutionPlan::with_physical_ownership(
            plan,
            Vec::new(),
            Vec::new(),
        );
        subject.execute_release(&prepared).unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }
}
