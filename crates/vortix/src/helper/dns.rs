//! Helper-owned DNS policy orchestration.

use std::fs::File;
use std::io::Read as _;

use super::observe::authority_interface_name;
use super::server::{
    NetworkPolicyExecutionPlan, NetworkPolicyOutcome, NetworkPolicyPreparationError,
    PreparedNetworkPolicyExecutionPlan, PrivilegedExecutionError,
};
use super::validate::PlatformLayout;
use crate::vortix_core::ports::dns::{DnsAssignment, DnsPolicy, DnsScope};
use crate::vortix_core::ports::owned_dns::{
    ExpectedDnsState, OwnedDns, OwnedDnsBackend, OwnedDnsError, OwnedDnsLink,
    OwnedDnsRecoveryCandidate, PreparedOwnedDns,
};
use crate::vortix_core::privileged::{
    DnsTransactionId, HelperLedgerDns, HelperResourceState, LeaseId, NetworkPolicyOperation,
    ObservationState, PhysicalDnsBackend, PhysicalDnsStage, PolicyProjection, PrivilegedDnsScope,
    ResourceObservation,
};

#[derive(Clone)]
pub(crate) struct RecoveredDnsState {
    state: HelperResourceState,
    intended: PolicyProjection,
    effective: Option<PolicyProjection>,
    physical: Option<HelperLedgerDns>,
}

impl RecoveredDnsState {
    pub(crate) fn new(
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

    pub(crate) fn with_physical(
        state: HelperResourceState,
        intended: PolicyProjection,
        effective: Option<PolicyProjection>,
        physical: HelperLedgerDns,
    ) -> Self {
        Self {
            state,
            intended,
            effective,
            physical: Some(physical),
        }
    }

    #[cfg(test)]
    pub(crate) const fn state(&self) -> HelperResourceState {
        self.state
    }

    #[cfg(test)]
    pub(crate) const fn intended(&self) -> &PolicyProjection {
        &self.intended
    }

    #[cfg(test)]
    pub(crate) const fn effective(&self) -> Option<&PolicyProjection> {
        self.effective.as_ref()
    }

    pub(crate) const fn physical(&self) -> Option<&HelperLedgerDns> {
        self.physical.as_ref()
    }
}

pub(crate) struct HelperDnsExecutor {
    layout: PlatformLayout,
    lease_id: LeaseId,
    platform: Box<dyn OwnedDns>,
}

impl HelperDnsExecutor {
    pub(crate) fn new(lease_id: LeaseId) -> Self {
        let platform = crate::platform::helper_owned_dns();
        Self {
            layout: layout_for_backend(platform.backend()),
            lease_id,
            platform,
        }
    }

    #[cfg(test)]
    fn with_platform(lease_id: LeaseId, platform: impl OwnedDns + 'static) -> Self {
        let platform = Box::new(platform);
        Self {
            layout: layout_for_backend(platform.backend()),
            lease_id,
            platform,
        }
    }

    pub(crate) fn validate_recovered(
        &mut self,
        states: &[RecoveredDnsState],
        policy_enabled: bool,
    ) -> Result<(), PrivilegedExecutionError> {
        if states.is_empty() {
            return if policy_enabled {
                self.platform
                    .audit_recovery_physical(&[], true)
                    .map_err(map_execution_error)
            } else {
                Ok(())
            };
        }
        if states.iter().any(|state| {
            state.physical().is_some_and(|physical| {
                !backend_matches_family(physical.backend(), self.platform.backend())
                    || physical.intended_digest() != state.intended.digest()
            })
        }) {
            return Err(PrivilegedExecutionError::InvalidPlan);
        }
        let pending = states
            .iter()
            .filter(|state| state.state == HelperResourceState::PendingEffect)
            .collect::<Vec<_>>();
        if pending.len() > 1 {
            return Err(PrivilegedExecutionError::InvalidPlan);
        }
        if let Some(state) = pending.first() {
            let desired = dns_policy(self.layout, self.lease_id, &state.intended)?;
            let prior = recovery_prior(states, state)
                .map(|projection| dns_policy(self.layout, self.lease_id, projection))
                .transpose()?;
            let Some(physical) = state.physical() else {
                return self
                    .platform
                    .recover_pending(&desired, prior.as_ref())
                    .map_err(map_execution_error);
            };
            let prepared = physical_preparation(self.layout, self.lease_id, physical)?;
            let recovered = states
                .iter()
                .filter_map(RecoveredDnsState::physical)
                .map(|physical| physical_preparation(self.layout, self.lease_id, physical))
                .collect::<Result<Vec<_>, _>>()?;
            return self
                .platform
                .recover_pending_physical(&desired, prior.as_ref(), &prepared, &recovered)
                .map_err(map_execution_error);
        }
        let mut candidates = Vec::new();
        let allow_absent = false;
        for state in states {
            match state.state {
                HelperResourceState::PendingEffect => unreachable!("handled above"),
                HelperResourceState::Owned | HelperResourceState::PendingRelease => {
                    let effective = state
                        .effective
                        .as_ref()
                        .ok_or(PrivilegedExecutionError::InvalidPlan)?;
                    let policy = dns_policy(self.layout, self.lease_id, effective)?;
                    let physical = state
                        .physical()
                        .map(|physical| physical_preparation(self.layout, self.lease_id, physical))
                        .transpose()?
                        .or_else(|| legacy_physical(self.platform.backend()))
                        .ok_or(PrivilegedExecutionError::InvalidPlan)?;
                    candidates.push(OwnedDnsRecoveryCandidate::new(policy, physical));
                }
            }
        }
        self.platform
            .audit_recovery_physical(&candidates, allow_absent)
            .map_err(map_execution_error)
    }

    pub(crate) fn prepare(
        &mut self,
        plan: &NetworkPolicyExecutionPlan,
    ) -> Result<PreparedNetworkPolicyExecutionPlan, NetworkPolicyPreparationError> {
        match plan.operation() {
            NetworkPolicyOperation::ApplyDns { .. } => self.prepare_apply(plan),
            NetworkPolicyOperation::ObserveBarrier { policy, .. }
                if policy.kind() == crate::vortix_core::privileged::ResourceKind::Dns =>
            {
                Ok(PreparedNetworkPolicyExecutionPlan::with_physical_ownership(
                    plan.clone(),
                    Vec::new(),
                    plan.recovered_dns().to_vec(),
                ))
            }
            NetworkPolicyOperation::ReleaseObsolete {
                policy, resources, ..
            } if policy.kind() == crate::vortix_core::privileged::ResourceKind::Dns
                && !resources.is_empty()
                && resources.iter().all(|resource| {
                    resource.kind() == crate::vortix_core::privileged::ResourceKind::Dns
                })
                && plan.obsolete_effective().len() == resources.len() =>
            {
                let intended = dns_policy(self.layout, self.lease_id, plan.intended())
                    .map_err(|_| NetworkPolicyPreparationError::InvalidPlan)?;
                self.audit_intended(plan, &intended)
                    .map_err(|_| NetworkPolicyPreparationError::FailedBeforeEffect)?;
                if plan.obsolete_effective().iter().any(|projection| {
                    !resources.contains(projection.policy())
                        || dns_policy(self.layout, self.lease_id, projection).is_err()
                }) {
                    return Err(NetworkPolicyPreparationError::InvalidPlan);
                }
                Ok(PreparedNetworkPolicyExecutionPlan::with_physical_ownership(
                    plan.clone(),
                    Vec::new(),
                    plan.recovered_dns().to_vec(),
                ))
            }
            _ => Err(NetworkPolicyPreparationError::InvalidPlan),
        }
    }

    fn prepare_apply(
        &mut self,
        plan: &NetworkPolicyExecutionPlan,
    ) -> Result<PreparedNetworkPolicyExecutionPlan, NetworkPolicyPreparationError> {
        let desired = dns_policy(self.layout, self.lease_id, plan.intended())
            .map_err(|_| NetworkPolicyPreparationError::InvalidPlan)?;
        let prior = plan
            .prior_effective()
            .map(|projection| dns_policy(self.layout, self.lease_id, projection))
            .transpose()
            .map_err(|_| NetworkPolicyPreparationError::InvalidPlan)?;
        let expected = prior
            .as_ref()
            .map_or(ExpectedDnsState::Absent, ExpectedDnsState::Applied);
        let recovered = plan
            .recovered_dns()
            .iter()
            .map(|physical| physical_preparation(self.layout, self.lease_id, physical))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| NetworkPolicyPreparationError::InvalidPlan)?;
        let inherited = recovered
            .iter()
            .flat_map(|physical| physical.links().iter().cloned())
            .collect::<Vec<_>>();
        let physical = self
            .platform
            .prepare_physical(&desired, expected, &inherited)
            .map_err(|_| NetworkPolicyPreparationError::FailedBeforeEffect)?;
        let policy = plan.operation().policy_resource();
        let mut dns = plan.recovered_dns().to_vec();
        let links = physical_links_for_projection(
            self.layout,
            self.lease_id,
            plan.intended(),
            &desired,
            &physical,
        )
        .map_err(|()| NetworkPolicyPreparationError::InvalidPlan)?;
        let prepared = match dns.iter().find(|physical| physical.resource() == policy) {
            Some(existing) => {
                let prepared = existing
                    .prepare_for(plan.intended())
                    .map_err(|_| NetworkPolicyPreparationError::InvalidPlan)?;
                if prepared.backend() != physical.backend() || prepared.links() != links {
                    return Err(NetworkPolicyPreparationError::InvalidPlan);
                }
                prepared
            }
            None => HelperLedgerDns::prepared(
                policy.clone(),
                physical.backend(),
                new_transaction_id()
                    .map_err(|_| NetworkPolicyPreparationError::FailedBeforeEffect)?,
                plan.intended().digest(),
                links,
            )
            .map_err(|_| NetworkPolicyPreparationError::InvalidPlan)?,
        };
        if let Some(existing) = dns
            .iter_mut()
            .find(|physical| physical.resource() == policy)
        {
            *existing = prepared;
        } else {
            dns.push(prepared);
        }
        Ok(PreparedNetworkPolicyExecutionPlan::with_physical_ownership(
            plan.clone(),
            Vec::new(),
            dns,
        ))
    }

    pub(crate) fn execute(
        &mut self,
        prepared: &PreparedNetworkPolicyExecutionPlan,
    ) -> Result<NetworkPolicyOutcome, PrivilegedExecutionError> {
        let plan = prepared.execution();
        match plan.operation() {
            NetworkPolicyOperation::ApplyDns { .. } => {
                if !prepared.prepared_dns().iter().any(|physical| {
                    physical.resource() == plan.operation().policy_resource()
                        && physical.stage() == PhysicalDnsStage::EffectPendingObservation
                }) {
                    return Err(PrivilegedExecutionError::InvalidPlan);
                }
                let desired = dns_policy(self.layout, self.lease_id, plan.intended())?;
                let prior = plan
                    .prior_effective()
                    .map(|projection| dns_policy(self.layout, self.lease_id, projection))
                    .transpose()?;
                let expected = prior
                    .as_ref()
                    .map_or(ExpectedDnsState::Absent, ExpectedDnsState::Applied);
                let physical = prepared
                    .prepared_dns()
                    .iter()
                    .find(|physical| physical.resource() == plan.operation().policy_resource())
                    .ok_or(PrivilegedExecutionError::InvalidPlan)
                    .and_then(|physical| {
                        physical_preparation(self.layout, self.lease_id, physical)
                    })?;
                let recovered = prepared
                    .prepared_dns()
                    .iter()
                    .map(|physical| physical_preparation(self.layout, self.lease_id, physical))
                    .collect::<Result<Vec<_>, _>>()?;
                self.platform
                    .apply_physical(&desired, expected, &physical, &recovered)
                    .map_err(map_execution_error)?;
                Ok(NetworkPolicyOutcome::Applied)
            }
            NetworkPolicyOperation::ObserveBarrier { policy, .. } => {
                let desired = dns_policy(self.layout, self.lease_id, plan.intended())?;
                let physical = prepared
                    .prepared_dns()
                    .iter()
                    .find(|physical| physical.resource() == policy)
                    .ok_or(PrivilegedExecutionError::InvalidPlan)
                    .and_then(|physical| {
                        physical_preparation(self.layout, self.lease_id, physical)
                    })?;
                self.platform
                    .audit_physical(&desired, &physical)
                    .map_err(map_execution_error)?;
                Ok(NetworkPolicyOutcome::Observed(vec![
                    ResourceObservation::new(policy.clone(), ObservationState::Present, 1)
                        .map_err(|_| PrivilegedExecutionError::InvalidPlan)?,
                ]))
            }
            NetworkPolicyOperation::ReleaseObsolete {
                policy, resources, ..
            } => {
                let desired = dns_policy(self.layout, self.lease_id, plan.intended())?;
                self.audit_intended(plan, &desired)?;
                let mut observations =
                    vec![
                        ResourceObservation::new(policy.clone(), ObservationState::Present, 1)
                            .map_err(|_| PrivilegedExecutionError::InvalidPlan)?,
                    ];
                observations.extend(resources.iter().cloned().map(|resource| {
                    ResourceObservation::new(resource, ObservationState::Absent, 1)
                        .expect("validated DNS resources produce observations")
                }));
                Ok(NetworkPolicyOutcome::Observed(observations))
            }
            _ => Err(PrivilegedExecutionError::InvalidPlan),
        }
    }

    fn audit_intended(
        &mut self,
        plan: &NetworkPolicyExecutionPlan,
        desired: &DnsPolicy,
    ) -> Result<(), PrivilegedExecutionError> {
        let Some(physical) = plan
            .recovered_dns()
            .iter()
            .find(|physical| physical.resource() == plan.operation().policy_resource())
        else {
            return self.platform.audit(desired).map_err(map_execution_error);
        };
        let prepared = physical_preparation(self.layout, self.lease_id, physical)?;
        self.platform
            .audit_physical(desired, &prepared)
            .map_err(map_execution_error)
    }
}

fn recovery_prior<'a>(
    states: &'a [RecoveredDnsState],
    pending: &'a RecoveredDnsState,
) -> Option<&'a PolicyProjection> {
    pending.effective.as_ref().or_else(|| {
        let policy = pending.intended.policy();
        states
            .iter()
            .filter(|candidate| {
                matches!(
                    candidate.state,
                    HelperResourceState::Owned | HelperResourceState::PendingRelease
                ) && candidate.intended.policy().authority_epoch() == policy.authority_epoch()
                    && candidate.intended.policy().generation() < policy.generation()
                    && candidate.effective.is_some()
            })
            .max_by_key(|candidate| candidate.intended.policy().generation())
            .and_then(|candidate| candidate.effective.as_ref())
    })
}

fn backend_matches_family(physical: PhysicalDnsBackend, family: OwnedDnsBackend) -> bool {
    matches!(
        (physical, family),
        (
            PhysicalDnsBackend::LinuxResolved | PhysicalDnsBackend::LinuxResolvconf,
            OwnedDnsBackend::LinuxPendingPhysicalLedger
        ) | (
            PhysicalDnsBackend::MacOsResolverFiles,
            OwnedDnsBackend::MacOsResolverFiles
        )
    )
}

fn legacy_physical(family: OwnedDnsBackend) -> Option<PreparedOwnedDns> {
    (family == OwnedDnsBackend::MacOsResolverFiles)
        .then(|| PreparedOwnedDns::new(PhysicalDnsBackend::MacOsResolverFiles, Vec::new()))
}

fn physical_preparation(
    layout: PlatformLayout,
    lease_id: LeaseId,
    physical: &HelperLedgerDns,
) -> Result<PreparedOwnedDns, PrivilegedExecutionError> {
    let links = physical
        .links()
        .iter()
        .map(|link| -> Result<OwnedDnsLink, PrivilegedExecutionError> {
            let interface = authority_interface_name(layout, lease_id, link.tunnel())
                .map_err(|()| PrivilegedExecutionError::InvalidPlan)?;
            Ok(OwnedDnsLink::new(interface, link.prior().clone()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PreparedOwnedDns::new(physical.backend(), links))
}

fn physical_links_for_projection(
    layout: PlatformLayout,
    lease_id: LeaseId,
    projection: &PolicyProjection,
    desired: &DnsPolicy,
    prepared: &PreparedOwnedDns,
) -> Result<Vec<crate::vortix_core::privileged::PhysicalDnsLink>, ()> {
    if prepared.backend() == PhysicalDnsBackend::MacOsResolverFiles {
        return prepared.links().is_empty().then(Vec::new).ok_or(());
    }
    let PolicyProjection::Dns { assignments, .. } = projection else {
        return Err(());
    };
    if assignments.len() != desired.assignments.len() {
        return Err(());
    }
    let mut expected = assignments
        .iter()
        .zip(&desired.assignments)
        .filter(|(_, assignment)| !matches!(assignment.scope, DnsScope::Suppressed))
        .map(|(assignment, desired)| (desired.interface.as_str(), assignment.tunnel()))
        .collect::<Vec<_>>();
    if prepared.links().len() != expected.len() {
        return Err(());
    }
    let mut links = Vec::with_capacity(expected.len());
    for link in prepared.links() {
        let Some(index) = expected
            .iter()
            .position(|(interface, _)| *interface == link.interface())
        else {
            return Err(());
        };
        let (_, tunnel) = expected.swap_remove(index);
        if authority_interface_name(layout, lease_id, tunnel).as_deref() != Ok(link.interface()) {
            return Err(());
        }
        links.push(
            crate::vortix_core::privileged::PhysicalDnsLink::new(
                tunnel.clone(),
                link.prior().clone(),
            )
            .map_err(|_| ())?,
        );
    }
    expected.is_empty().then_some(links).ok_or(())
}

fn dns_policy(
    layout: PlatformLayout,
    lease_id: LeaseId,
    projection: &PolicyProjection,
) -> Result<DnsPolicy, PrivilegedExecutionError> {
    let PolicyProjection::Dns {
        policy,
        assignments,
    } = projection
    else {
        return Err(PrivilegedExecutionError::InvalidPlan);
    };
    let assignments = assignments
        .iter()
        .map(
            |assignment| -> Result<DnsAssignment, PrivilegedExecutionError> {
                let tunnel = assignment.tunnel();
                let profile_id = tunnel
                    .profile_id()
                    .cloned()
                    .ok_or(PrivilegedExecutionError::InvalidPlan)?;
                let interface = authority_interface_name(layout, lease_id, tunnel)
                    .map_err(|()| PrivilegedExecutionError::InvalidPlan)?;
                let scope = match assignment.scope() {
                    PrivilegedDnsScope::CatchAll => DnsScope::CatchAll,
                    PrivilegedDnsScope::Scoped { domains } => DnsScope::Scoped {
                        domains: domains
                            .iter()
                            .map(|domain| domain.as_str().to_string())
                            .collect(),
                    },
                    PrivilegedDnsScope::Suppressed => DnsScope::Suppressed,
                };
                Ok(DnsAssignment {
                    profile_id,
                    interface,
                    servers: assignment.servers().to_vec(),
                    search_domains: assignment
                        .search_domains()
                        .iter()
                        .map(|domain| domain.as_str().to_string())
                        .collect(),
                    scope,
                })
            },
        )
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DnsPolicy {
        generation: policy.generation(),
        assignments,
    })
}

const fn layout_for_backend(backend: OwnedDnsBackend) -> PlatformLayout {
    match backend {
        OwnedDnsBackend::LinuxPendingPhysicalLedger => PlatformLayout::Linux,
        OwnedDnsBackend::MacOsResolverFiles => PlatformLayout::MacOs,
    }
}

fn new_transaction_id() -> std::io::Result<DnsTransactionId> {
    let mut bytes = [0; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    DnsTransactionId::new(bytes)
        .map_err(|reason| std::io::Error::new(std::io::ErrorKind::InvalidData, reason))
}

const fn map_execution_error(error: OwnedDnsError) -> PrivilegedExecutionError {
    match error {
        OwnedDnsError::FailedBeforeEffect => PrivilegedExecutionError::FailedBeforeEffect,
        OwnedDnsError::EffectMayHaveApplied => PrivilegedExecutionError::EffectMayHaveApplied,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::vortix_core::control::AuthorityEpoch;
    use crate::vortix_core::ports::owned_dns::OwnedDnsBackend;
    use crate::vortix_core::privileged::DnsHostname;
    use crate::vortix_core::privileged::{PrivilegedDnsAssignment, ResourceKind, ResourceTag};
    use crate::vortix_core::profile::ProfileId;

    #[derive(Default)]
    struct AuditCapture {
        candidates: Vec<DnsPolicy>,
        allow_absent: bool,
        recovered: Option<(DnsPolicy, Option<DnsPolicy>)>,
    }

    struct CaptureDns(Arc<Mutex<AuditCapture>>);

    impl OwnedDns for CaptureDns {
        fn backend(&self) -> OwnedDnsBackend {
            OwnedDnsBackend::LinuxPendingPhysicalLedger
        }

        fn apply(
            &mut self,
            _desired: &DnsPolicy,
            _expected: ExpectedDnsState<'_>,
        ) -> Result<(), OwnedDnsError> {
            unreachable!()
        }

        fn audit(&mut self, _desired: &DnsPolicy) -> Result<(), OwnedDnsError> {
            unreachable!()
        }

        fn audit_absent(&mut self) -> Result<(), OwnedDnsError> {
            unreachable!()
        }

        fn recover_pending(
            &mut self,
            desired: &DnsPolicy,
            prior: Option<&DnsPolicy>,
        ) -> Result<(), OwnedDnsError> {
            self.0.lock().unwrap().recovered = Some((desired.clone(), prior.cloned()));
            Ok(())
        }

        fn audit_recovery(
            &mut self,
            candidates: &[DnsPolicy],
            allow_absent: bool,
        ) -> Result<(), OwnedDnsError> {
            let mut capture = self.0.lock().unwrap();
            capture.candidates = candidates.to_vec();
            capture.allow_absent = allow_absent;
            Ok(())
        }
    }

    fn projection(generation: u64, server: &str) -> PolicyProjection {
        let profile_id = ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap();
        let tunnel = ResourceTag::tunnel(profile_id, generation).unwrap();
        let assignment = PrivilegedDnsAssignment::new(
            tunnel,
            vec![server.parse().unwrap()],
            vec![DnsHostname::new("corp.example").unwrap()],
            PrivilegedDnsScope::CatchAll,
        )
        .unwrap();
        PolicyProjection::Dns {
            policy: ResourceTag::topology(AuthorityEpoch(3), generation, ResourceKind::Dns)
                .unwrap(),
            assignments: vec![assignment],
        }
    }

    #[test]
    fn typed_projection_derives_interface_and_preserves_dns_scope() {
        let projection = projection(7, "1.1.1.1");
        let policy = dns_policy(PlatformLayout::Linux, LeaseId::new([7; 32]), &projection).unwrap();

        assert_eq!(policy.generation, 7);
        assert_eq!(policy.assignments.len(), 1);
        assert!(policy.assignments[0].interface.starts_with("vx"));
        assert_eq!(
            policy.assignments[0].servers,
            vec!["1.1.1.1".parse::<std::net::IpAddr>().unwrap()]
        );
        assert_eq!(policy.assignments[0].search_domains, vec!["corp.example"]);
        assert_eq!(policy.assignments[0].scope, DnsScope::CatchAll);
    }

    #[test]
    fn pending_recovery_reconciles_only_intended_and_prior() {
        let capture = Arc::new(Mutex::new(AuditCapture::default()));
        let mut subject = HelperDnsExecutor::with_platform(
            LeaseId::new([7; 32]),
            CaptureDns(Arc::clone(&capture)),
        );
        let intended = projection(8, "9.9.9.9");
        let prior = projection(7, "1.1.1.1");

        subject
            .validate_recovered(
                &[
                    RecoveredDnsState::new(HelperResourceState::Owned, prior.clone(), Some(prior)),
                    RecoveredDnsState::new(HelperResourceState::PendingEffect, intended, None),
                ],
                true,
            )
            .unwrap();

        let capture = capture.lock().unwrap();
        let (desired, prior) = capture.recovered.as_ref().unwrap();
        assert_eq!(desired.generation, 8);
        assert_eq!(prior.as_ref().unwrap().generation, 7);
        assert!(capture.candidates.is_empty());
    }
}
