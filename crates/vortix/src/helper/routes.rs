//! Exact route-selection barriers for helper-owned tunnel generations.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use super::observe::authority_interface_name;
use super::server::{
    NetworkPolicyExecutionPlan, NetworkPolicyOutcome, NetworkPolicyPreparationError,
    PreparedNetworkPolicyExecutionPlan, PrivilegedExecutionError, RecoveredRouteState,
};
use super::validate::PlatformLayout;
use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::ports::owned_routes::OwnedRoutes;
use crate::vortix_core::privileged::{
    HelperResourceState, LeaseId, NetworkPolicyOperation, ObservationState, PolicyProjection,
    PrivilegedFirewallTunnel, ResourceObservation, ScopedRoute,
};

const ROUTE_AUDIT_BUDGET: Duration = Duration::from_secs(5);

pub(crate) struct HelperRouteExecutor {
    layout: PlatformLayout,
    lease_id: LeaseId,
    platform: Box<dyn OwnedRoutes>,
}

impl HelperRouteExecutor {
    pub(crate) fn new(layout: PlatformLayout, lease_id: LeaseId) -> Self {
        Self {
            layout,
            lease_id,
            platform: crate::platform::helper_owned_routes(),
        }
    }

    #[cfg(test)]
    fn with_platform(
        layout: PlatformLayout,
        lease_id: LeaseId,
        platform: impl OwnedRoutes + 'static,
    ) -> Self {
        Self {
            layout,
            lease_id,
            platform: Box::new(platform),
        }
    }

    pub(crate) fn validate_recovered(
        &mut self,
        states: &[RecoveredRouteState],
        policy_enabled: bool,
    ) -> Result<(), PrivilegedExecutionError> {
        if states.is_empty() {
            return Ok(());
        }
        if !policy_enabled {
            return Err(PrivilegedExecutionError::InvalidPlan);
        }
        let latest_generation = states
            .iter()
            .map(|state| state.intended().policy().generation())
            .max()
            .ok_or(PrivilegedExecutionError::InvalidPlan)?;
        let pending = states
            .iter()
            .filter(|state| state.state() == HelperResourceState::PendingEffect)
            .count();
        if pending > 1
            || states.iter().any(|state| {
                state.state() == HelperResourceState::PendingEffect
                    && state.intended().policy().generation() != latest_generation
            })
        {
            return Err(PrivilegedExecutionError::InvalidPlan);
        }
        for state in states {
            let projection = if state.state() == HelperResourceState::PendingEffect {
                state.intended()
            } else {
                state
                    .effective()
                    .ok_or(PrivilegedExecutionError::InvalidPlan)?
            };
            let observed = self.classify(projection)?;
            if state.intended().policy().generation() == latest_generation
                && state.state() != HelperResourceState::PendingRelease
                && observed != ProjectionState::Present
            {
                return Err(PrivilegedExecutionError::EffectMayHaveApplied);
            }
        }
        Ok(())
    }

    pub(crate) fn prepare(
        &mut self,
        plan: &NetworkPolicyExecutionPlan,
    ) -> Result<PreparedNetworkPolicyExecutionPlan, NetworkPolicyPreparationError> {
        match plan.operation() {
            NetworkPolicyOperation::ApplyRoutes { .. }
            | NetworkPolicyOperation::ObserveBarrier { .. }
                if plan.intended().route_inputs().is_some() =>
            {
                self.probes(plan.intended())
                    .map_err(|_| NetworkPolicyPreparationError::InvalidPlan)?;
                Ok(PreparedNetworkPolicyExecutionPlan::with_physical_ownership(
                    plan.clone(),
                    plan.recovered_firewalls().to_vec(),
                    plan.recovered_dns().to_vec(),
                ))
            }
            NetworkPolicyOperation::EstablishBlocking { .. }
            | NetworkPolicyOperation::ApplyRoutes { .. }
            | NetworkPolicyOperation::ApplyDns { .. }
            | NetworkPolicyOperation::ApplyFirewall { .. }
            | NetworkPolicyOperation::ObserveBarrier { .. }
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
        if self.classify(plan.intended())? != ProjectionState::Present {
            return Err(PrivilegedExecutionError::FailedBeforeEffect);
        }
        match plan.operation() {
            NetworkPolicyOperation::ApplyRoutes { .. } => Ok(NetworkPolicyOutcome::Applied),
            NetworkPolicyOperation::ObserveBarrier { policy, .. }
                if policy == plan.intended().policy() =>
            {
                Ok(NetworkPolicyOutcome::Observed(vec![
                    ResourceObservation::new(policy.clone(), ObservationState::Present, 1)
                        .map_err(|_| PrivilegedExecutionError::InvalidPlan)?,
                ]))
            }
            NetworkPolicyOperation::EstablishBlocking { .. }
            | NetworkPolicyOperation::ApplyDns { .. }
            | NetworkPolicyOperation::ApplyFirewall { .. }
            | NetworkPolicyOperation::ObserveBarrier { .. }
            | NetworkPolicyOperation::ReleaseObsolete { .. } => {
                Err(PrivilegedExecutionError::InvalidPlan)
            }
        }
    }

    pub(crate) fn prepare_release(
        &mut self,
        plan: &NetworkPolicyExecutionPlan,
    ) -> Result<(), NetworkPolicyPreparationError> {
        self.verify_release(plan).map_err(|error| match error {
            PrivilegedExecutionError::InvalidPlan => NetworkPolicyPreparationError::InvalidPlan,
            PrivilegedExecutionError::Overloaded
            | PrivilegedExecutionError::FailedBeforeEffect
            | PrivilegedExecutionError::EffectMayHaveApplied => {
                NetworkPolicyPreparationError::FailedBeforeEffect
            }
        })
    }

    pub(crate) fn execute_release(
        &mut self,
        prepared: &PreparedNetworkPolicyExecutionPlan,
    ) -> Result<(), PrivilegedExecutionError> {
        self.verify_release(prepared.execution())
    }

    fn verify_release(
        &mut self,
        plan: &NetworkPolicyExecutionPlan,
    ) -> Result<(), PrivilegedExecutionError> {
        let (current, obsolete) = plan
            .release_family(crate::vortix_core::privileged::ResourceKind::Routes)
            .ok_or(PrivilegedExecutionError::InvalidPlan)?;
        let current_claims = self.route_probes(current)?;
        let current_probes = probe_map(&current_claims)?;
        let deadline = Instant::now() + ROUTE_AUDIT_BUDGET;
        for (target, expected) in &current_probes {
            let interface = self.observe_route(*target, deadline)?;
            if interface != *expected {
                return Err(PrivilegedExecutionError::FailedBeforeEffect);
            }
        }
        let mut exact_observations = Vec::<(Cidr, Vec<String>)>::new();
        for projection in obsolete {
            for old in self.route_probes(projection)? {
                if current_claims.iter().any(|current| {
                    current.destination == old.destination && current.interface == old.interface
                }) {
                    continue;
                }
                let interfaces = if let Some((_, interfaces)) = exact_observations
                    .iter()
                    .find(|(destination, _)| *destination == old.destination)
                {
                    interfaces.clone()
                } else {
                    let interfaces = self.observe_exact_route(old.destination, deadline)?;
                    exact_observations.push((old.destination, interfaces.clone()));
                    interfaces
                };
                if interfaces.contains(&old.interface) {
                    return Err(PrivilegedExecutionError::FailedBeforeEffect);
                }
            }
        }
        Ok(())
    }

    fn observe_route(
        &mut self,
        target: IpAddr,
        deadline: Instant,
    ) -> Result<String, PrivilegedExecutionError> {
        if Instant::now() >= deadline {
            return Err(PrivilegedExecutionError::FailedBeforeEffect);
        }
        let observed = self
            .platform
            .route_interface_for(target)
            .map_err(|_| PrivilegedExecutionError::FailedBeforeEffect)?;
        if Instant::now() >= deadline {
            return Err(PrivilegedExecutionError::FailedBeforeEffect);
        }
        Ok(observed)
    }

    fn observe_exact_route(
        &mut self,
        destination: Cidr,
        deadline: Instant,
    ) -> Result<Vec<String>, PrivilegedExecutionError> {
        if Instant::now() >= deadline {
            return Err(PrivilegedExecutionError::FailedBeforeEffect);
        }
        let observed = self
            .platform
            .exact_route_interfaces(destination)
            .map_err(|_| PrivilegedExecutionError::FailedBeforeEffect)?;
        if Instant::now() >= deadline {
            return Err(PrivilegedExecutionError::FailedBeforeEffect);
        }
        Ok(observed)
    }

    fn classify(
        &mut self,
        projection: &PolicyProjection,
    ) -> Result<ProjectionState, PrivilegedExecutionError> {
        let probes = self.probes(projection)?;
        if probes.is_empty() {
            return Ok(ProjectionState::Present);
        }
        let deadline = Instant::now() + ROUTE_AUDIT_BUDGET;
        let mut matching = 0;
        for (target, expected_interface) in &probes {
            if Instant::now() >= deadline {
                return Err(PrivilegedExecutionError::EffectMayHaveApplied);
            }
            let observed = self
                .platform
                .route_interface_for(*target)
                .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
            if Instant::now() >= deadline {
                return Err(PrivilegedExecutionError::EffectMayHaveApplied);
            }
            matching += usize::from(observed == *expected_interface);
        }
        match matching {
            0 => Ok(ProjectionState::Absent),
            count if count == probes.len() => Ok(ProjectionState::Present),
            _ => Err(PrivilegedExecutionError::EffectMayHaveApplied),
        }
    }

    fn probes(
        &self,
        projection: &PolicyProjection,
    ) -> Result<BTreeMap<IpAddr, String>, PrivilegedExecutionError> {
        probe_map(&self.route_probes(projection)?)
    }

    fn route_probes(
        &self,
        projection: &PolicyProjection,
    ) -> Result<Vec<RouteProbe>, PrivilegedExecutionError> {
        let (routes, tunnels) = projection
            .route_inputs()
            .ok_or(PrivilegedExecutionError::InvalidPlan)?;
        let transport_endpoints = tunnels
            .iter()
            .flat_map(PrivilegedFirewallTunnel::endpoint_ips)
            .copied()
            .collect::<Vec<_>>();
        let mut probes = Vec::with_capacity(routes.len());
        for route in routes {
            if !tunnels
                .iter()
                .any(|subject| subject.tunnel() == route.tunnel())
            {
                return Err(PrivilegedExecutionError::InvalidPlan);
            }
            let target = probe_address(route, &transport_endpoints)?;
            let interface = authority_interface_name(self.layout, self.lease_id, route.tunnel())
                .map_err(|()| PrivilegedExecutionError::InvalidPlan)?;
            probes.push(RouteProbe {
                destination: route.destination(),
                target,
                interface,
            });
        }
        Ok(probes)
    }
}

struct RouteProbe {
    destination: Cidr,
    target: IpAddr,
    interface: String,
}

fn probe_map(probes: &[RouteProbe]) -> Result<BTreeMap<IpAddr, String>, PrivilegedExecutionError> {
    let mut mapped = BTreeMap::new();
    for probe in probes {
        if mapped
            .insert(probe.target, probe.interface.clone())
            .is_some_and(|prior| prior != probe.interface)
        {
            return Err(PrivilegedExecutionError::InvalidPlan);
        }
    }
    Ok(mapped)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionState {
    Present,
    Absent,
}

fn probe_address(
    route: &ScopedRoute,
    transport_endpoints: &[IpAddr],
) -> Result<IpAddr, PrivilegedExecutionError> {
    let destination = route.destination();
    let fixed = match destination.addr {
        IpAddr::V4(_) => &[
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)),
        ][..],
        IpAddr::V6(_) => &[
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
            IpAddr::V6(Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe)),
        ][..],
    };
    fixed
        .iter()
        .copied()
        .find(|candidate| {
            cidr_contains(destination, *candidate) && !transport_endpoints.contains(candidate)
        })
        .or_else(|| {
            (destination.prefix_len != 0).then(|| {
                representative_addresses(destination)
                    .into_iter()
                    .find(|candidate| !transport_endpoints.contains(candidate))
            })?
        })
        .ok_or(PrivilegedExecutionError::InvalidPlan)
}

fn representative_addresses(cidr: Cidr) -> Vec<IpAddr> {
    match cidr.addr {
        IpAddr::V4(address) => {
            let bits = u32::from(address);
            [1_u32, 2, 3, 0]
                .into_iter()
                .filter_map(|offset| {
                    let candidate = IpAddr::V4(bits.saturating_add(offset).into());
                    cidr_contains(cidr, candidate).then_some(candidate)
                })
                .collect()
        }
        IpAddr::V6(address) => {
            let bits = u128::from(address);
            [1_u128, 2, 3, 0]
                .into_iter()
                .filter_map(|offset| {
                    let candidate = IpAddr::V6(bits.saturating_add(offset).into());
                    cidr_contains(cidr, candidate).then_some(candidate)
                })
                .collect()
        }
    }
}

fn cidr_contains(cidr: Cidr, address: IpAddr) -> bool {
    Cidr::new(address, if address.is_ipv4() { 32 } else { 128 })
        .is_some_and(|address| cidr.intersects(&address))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::vortix_core::control::AuthorityEpoch;
    use crate::vortix_core::ports::owned_routes::OwnedRouteError;
    use crate::vortix_core::privileged::{
        NetworkPolicyOperation, PolicyPhase, PolicyPredecessor, PrivilegedFirewallRole,
        ResourceKind, ResourceTag,
    };
    use crate::vortix_core::profile::ProfileId;

    #[derive(Clone)]
    struct FakeRoutes {
        decisions: Arc<Mutex<BTreeMap<IpAddr, String>>>,
        exact: Vec<(Cidr, Vec<String>)>,
    }

    impl FakeRoutes {
        fn new(decisions: Arc<Mutex<BTreeMap<IpAddr, String>>>) -> Self {
            Self {
                decisions,
                exact: Vec::new(),
            }
        }

        fn with_exact(mut self, destination: Cidr, interfaces: Vec<String>) -> Self {
            self.exact.push((destination, interfaces));
            self
        }
    }

    impl OwnedRoutes for FakeRoutes {
        fn route_interface_for(&mut self, target: IpAddr) -> Result<String, OwnedRouteError> {
            self.decisions
                .lock()
                .unwrap()
                .get(&target)
                .cloned()
                .ok_or(OwnedRouteError::Unknown)
        }

        fn exact_route_interfaces(
            &mut self,
            destination: Cidr,
        ) -> Result<Vec<String>, OwnedRouteError> {
            Ok(self
                .exact
                .iter()
                .find(|(candidate, _)| *candidate == destination)
                .map(|(_, interfaces)| interfaces.clone())
                .unwrap_or_default())
        }
    }

    fn projection(
        lease_id: LeaseId,
        routes: &[(&str, &str, &[&str])],
    ) -> (PolicyProjection, BTreeMap<IpAddr, String>) {
        let mut scoped = Vec::new();
        let mut subjects = Vec::new();
        let mut observations = BTreeMap::new();
        for (index, (destination, endpoint, candidates)) in routes.iter().enumerate() {
            let profile = ProfileId::parse(format!("{:064x}", index + 1)).unwrap();
            let tunnel = ResourceTag::tunnel(profile, 1).unwrap();
            let destination: Cidr = destination.parse().unwrap();
            let subject = PrivilegedFirewallTunnel::new(
                tunnel.clone(),
                vec![endpoint.parse().unwrap()],
                vec![destination],
                PrivilegedFirewallRole::Primary,
            )
            .unwrap();
            let route = ScopedRoute::new(destination, tunnel.clone()).unwrap();
            let target = probe_address(&route, subject.endpoint_ips()).unwrap();
            let interface =
                authority_interface_name(PlatformLayout::Linux, lease_id, &tunnel).unwrap();
            let observed = candidates
                .first()
                .copied()
                .unwrap_or(&interface)
                .to_string();
            observations.insert(target, observed);
            scoped.push(route);
            subjects.push(subject);
        }
        (
            PolicyProjection::Routes {
                policy: ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Routes).unwrap(),
                routes: scoped,
                tunnels: subjects,
            },
            observations,
        )
    }

    fn with_policy_generation(projection: PolicyProjection, generation: u64) -> PolicyProjection {
        let PolicyProjection::Routes {
            routes, tunnels, ..
        } = projection
        else {
            unreachable!();
        };
        PolicyProjection::Routes {
            policy: ResourceTag::topology(AuthorityEpoch(3), generation, ResourceKind::Routes)
                .unwrap(),
            routes,
            tunnels,
        }
    }

    fn with_transport_endpoints(
        projection: PolicyProjection,
        endpoints: &[IpAddr],
    ) -> PolicyProjection {
        let PolicyProjection::Routes {
            policy,
            routes,
            tunnels,
        } = projection
        else {
            unreachable!();
        };
        let tunnels = tunnels
            .into_iter()
            .map(|tunnel| {
                PrivilegedFirewallTunnel::new(
                    tunnel.tunnel().clone(),
                    endpoints.to_vec(),
                    tunnel.declared_cidrs().to_vec(),
                    tunnel.role(),
                )
                .unwrap()
            })
            .collect();
        PolicyProjection::Routes {
            policy,
            routes,
            tunnels,
        }
    }

    fn with_tunnel_profile(projection: PolicyProjection, profile_seed: usize) -> PolicyProjection {
        let PolicyProjection::Routes {
            policy,
            routes,
            tunnels,
        } = projection
        else {
            unreachable!();
        };
        assert_eq!(routes.len(), 1);
        assert_eq!(tunnels.len(), 1);
        let tunnel = ResourceTag::tunnel(
            ProfileId::parse(format!("{profile_seed:064x}")).unwrap(),
            routes[0].tunnel().generation(),
        )
        .unwrap();
        let routes = vec![ScopedRoute::new(routes[0].destination(), tunnel.clone()).unwrap()];
        let subject = &tunnels[0];
        let tunnels = vec![PrivilegedFirewallTunnel::new(
            tunnel,
            subject.endpoint_ips().to_vec(),
            subject.declared_cidrs().to_vec(),
            subject.role(),
        )
        .unwrap()];
        PolicyProjection::Routes {
            policy,
            routes,
            tunnels,
        }
    }

    fn release_plan(
        current: PolicyProjection,
        obsolete: Vec<PolicyProjection>,
    ) -> NetworkPolicyExecutionPlan {
        let resources = obsolete
            .iter()
            .map(PolicyProjection::policy)
            .cloned()
            .collect();
        NetworkPolicyExecutionPlan::release_for_test(
            NetworkPolicyOperation::ReleaseObsolete {
                policy: current.policy().clone(),
                resources,
                predecessor: PolicyPredecessor::for_test(current.digest(), PolicyPhase::Firewall),
            },
            vec![current],
            obsolete,
            Vec::new(),
            Vec::new(),
        )
    }

    #[test]
    fn default_probe_avoids_the_authenticated_transport_endpoint() {
        let lease = LeaseId::new([7; 32]);
        let (projection, observations) = projection(lease, &[("0.0.0.0/0", "1.1.1.1", &[])]);
        assert_eq!(
            observations.keys().next(),
            Some(&"8.8.8.8".parse().unwrap())
        );

        let platform = FakeRoutes::new(Arc::new(Mutex::new(observations)));
        let mut routes = HelperRouteExecutor::with_platform(PlatformLayout::Linux, lease, platform);
        assert_eq!(
            routes.classify(&projection).unwrap(),
            ProjectionState::Present
        );
    }

    #[test]
    fn default_probe_avoids_every_authenticated_transport_endpoint() {
        let lease = LeaseId::new([11; 32]);
        let (mut projection, _) = projection(lease, &[("0.0.0.0/0", "1.1.1.1", &[])]);
        if let PolicyProjection::Routes {
            routes, tunnels, ..
        } = &mut projection
        {
            assert_eq!(routes.len(), 1);
            let secondary =
                ResourceTag::tunnel(ProfileId::parse(format!("{:064x}", 2)).unwrap(), 1).unwrap();
            tunnels.push(
                PrivilegedFirewallTunnel::new(
                    secondary,
                    vec!["8.8.8.8".parse().unwrap()],
                    Vec::new(),
                    PrivilegedFirewallRole::PendingEndpoint,
                )
                .unwrap(),
            );
        } else {
            unreachable!();
        }

        let probes = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            lease,
            FakeRoutes::new(Arc::new(Mutex::new(BTreeMap::new()))),
        )
        .probes(&projection)
        .unwrap();
        assert_eq!(probes.keys().next(), Some(&"9.9.9.9".parse().unwrap()));
    }

    #[test]
    fn projection_is_absent_only_when_no_claim_selects_its_owned_interface() {
        let lease = LeaseId::new([8; 32]);
        let (projection, mut observations) = projection(
            lease,
            &[
                ("10.0.0.0/8", "198.51.100.7", &[]),
                ("192.168.0.0/16", "198.51.100.8", &[]),
            ],
        );
        for interface in observations.values_mut() {
            *interface = "eth0".into();
        }
        let platform = FakeRoutes::new(Arc::new(Mutex::new(observations)));
        let mut routes = HelperRouteExecutor::with_platform(PlatformLayout::Linux, lease, platform);
        assert_eq!(
            routes.classify(&projection).unwrap(),
            ProjectionState::Absent
        );
    }

    #[test]
    fn mixed_projection_is_never_reported_present_or_absent() {
        let lease = LeaseId::new([9; 32]);
        let (projection, mut observations) = projection(
            lease,
            &[
                ("10.0.0.0/8", "198.51.100.7", &[]),
                ("192.168.0.0/16", "198.51.100.8", &[]),
            ],
        );
        *observations.values_mut().next().unwrap() = "eth0".into();
        let platform = FakeRoutes::new(Arc::new(Mutex::new(observations)));
        let mut routes = HelperRouteExecutor::with_platform(PlatformLayout::Linux, lease, platform);
        assert_eq!(
            routes.classify(&projection),
            Err(PrivilegedExecutionError::EffectMayHaveApplied)
        );
    }

    #[test]
    fn restart_requires_latest_owned_projection_to_remain_present() {
        let lease = LeaseId::new([10; 32]);
        let (projection, observations) = projection(lease, &[("10.0.0.0/8", "198.51.100.7", &[])]);
        let state = RecoveredRouteState::new(
            HelperResourceState::Owned,
            projection.clone(),
            Some(projection),
        );
        let shared = Arc::new(Mutex::new(observations));
        let mut routes = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            lease,
            FakeRoutes::new(Arc::clone(&shared)),
        );
        routes
            .validate_recovered(std::slice::from_ref(&state), true)
            .unwrap();

        for interface in shared.lock().unwrap().values_mut() {
            *interface = "eth0".into();
        }
        assert_eq!(
            routes.validate_recovered(std::slice::from_ref(&state), true),
            Err(PrivilegedExecutionError::EffectMayHaveApplied)
        );
        assert_eq!(
            routes.validate_recovered(&[state], false),
            Err(PrivilegedExecutionError::InvalidPlan)
        );
    }

    #[test]
    fn release_accepts_an_obsolete_route_only_when_current_truth_supersedes_it() {
        let lease = LeaseId::new([12; 32]);
        let (base, observations) = projection(lease, &[("10.0.0.0/8", "198.51.100.7", &[])]);
        let obsolete = with_policy_generation(base.clone(), 1);
        let current = with_policy_generation(base, 2);
        let plan = release_plan(current, vec![obsolete]);
        let mut routes = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            lease,
            FakeRoutes::new(Arc::new(Mutex::new(observations))),
        );

        routes.prepare_release(&plan).unwrap();
        let prepared = PreparedNetworkPolicyExecutionPlan::with_physical_ownership(
            plan,
            Vec::new(),
            Vec::new(),
        );
        routes.execute_release(&prepared).unwrap();
    }

    #[test]
    fn semantic_route_supersession_does_not_depend_on_the_probe_address() {
        let lease = LeaseId::new([14; 32]);
        let (base, _) = projection(lease, &[("0.0.0.0/0", "1.1.1.1", &[])]);
        let obsolete = with_policy_generation(base.clone(), 1);
        let current = with_transport_endpoints(
            with_policy_generation(base, 2),
            &["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
        );
        let probe_builder = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            lease,
            FakeRoutes::new(Arc::new(Mutex::new(BTreeMap::new()))),
        );
        let mut observations = probe_builder.probes(&obsolete).unwrap();
        observations.extend(probe_builder.probes(&current).unwrap());
        assert_eq!(observations.len(), 2);
        let plan = release_plan(current, vec![obsolete]);
        let mut routes = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            lease,
            FakeRoutes::new(Arc::new(Mutex::new(observations))),
        );

        routes.prepare_release(&plan).unwrap();
    }

    #[test]
    fn release_rejects_an_obsolete_route_that_still_selects_its_old_interface() {
        let lease = LeaseId::new([13; 32]);
        let (current, mut observations) = projection(lease, &[("10.0.0.0/8", "198.51.100.7", &[])]);
        let (obsolete, obsolete_observations) =
            projection(lease, &[("192.168.0.0/16", "198.51.100.7", &[])]);
        let obsolete_interface = obsolete_observations.values().next().unwrap().clone();
        observations.extend(obsolete_observations);
        let plan = release_plan(
            with_policy_generation(current, 2),
            vec![with_policy_generation(obsolete, 1)],
        );
        let mut routes = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            lease,
            FakeRoutes::new(Arc::new(Mutex::new(observations)))
                .with_exact("192.168.0.0/16".parse().unwrap(), vec![obsolete_interface]),
        );

        assert_eq!(
            routes.prepare_release(&plan),
            Err(NetworkPolicyPreparationError::FailedBeforeEffect)
        );
        let prepared = PreparedNetworkPolicyExecutionPlan::with_physical_ownership(
            plan,
            Vec::new(),
            Vec::new(),
        );
        assert_eq!(
            routes.execute_release(&prepared),
            Err(PrivilegedExecutionError::FailedBeforeEffect)
        );
    }

    #[test]
    fn release_accepts_removed_narrower_route_covered_by_retained_broader_route() {
        let lease = LeaseId::new([15; 32]);
        let (current, observations) = projection(lease, &[("10.0.0.0/8", "198.51.100.7", &[])]);
        let (obsolete, _) = projection(lease, &[("10.0.0.0/9", "198.51.100.7", &[])]);
        let plan = release_plan(
            with_policy_generation(current, 2),
            vec![with_policy_generation(obsolete, 1)],
        );
        let mut routes = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            lease,
            FakeRoutes::new(Arc::new(Mutex::new(observations))),
        );

        routes.prepare_release(&plan).unwrap();
    }

    #[test]
    fn release_rejects_hidden_obsolete_broader_route_from_another_tunnel() {
        let lease = LeaseId::new([16; 32]);
        let (current, _) = projection(lease, &[("10.0.0.0/9", "198.51.100.7", &[])]);
        let current = with_tunnel_profile(with_policy_generation(current, 2), 1);
        let current_builder = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            lease,
            FakeRoutes::new(Arc::new(Mutex::new(BTreeMap::new()))),
        );
        let current_observations = current_builder.probes(&current).unwrap();
        let (obsolete, _) = projection(lease, &[("10.0.0.0/8", "198.51.100.8", &[])]);
        let obsolete = with_tunnel_profile(with_policy_generation(obsolete, 1), 2);
        let obsolete_builder = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            lease,
            FakeRoutes::new(Arc::new(Mutex::new(BTreeMap::new()))),
        );
        let obsolete_interface = obsolete_builder
            .route_probes(&obsolete)
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .interface;
        let plan = release_plan(current, vec![obsolete]);
        let mut routes = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            lease,
            FakeRoutes::new(Arc::new(Mutex::new(current_observations)))
                .with_exact("10.0.0.0/8".parse().unwrap(), vec![obsolete_interface]),
        );

        assert_eq!(
            routes.prepare_release(&plan),
            Err(NetworkPolicyPreparationError::FailedBeforeEffect)
        );
    }
}
