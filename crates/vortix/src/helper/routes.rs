//! Exact route-selection barriers for helper-owned tunnel generations.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use super::observe::authority_interface_name;
use super::server::{
    NetworkPolicyExecutionPlan, NetworkPolicyOutcome, NetworkPolicyPreparationError,
    PreparedNetworkPolicyExecutionPlan, PreparedRouteWriter, PrivilegedExecutionError,
    RecoveredRouteState,
};
use super::validate::PlatformLayout;
use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::ports::owned_routes::{OwnedRoutes, RouteEntry};
use crate::vortix_core::privileged::{
    HelperLedgerRoutes, HelperResourceState, LeaseId, NetworkPolicyOperation,
    OpenVpnDefaultGateway, OpenVpnRouteGateway, PhysicalRouteBackend, PhysicalRouteStage,
    PolicyProjection, PrivilegedFirewallTunnel, ResourceObservation, RouteTransactionId,
    ScopedOpenVpnRedirect, ScopedRoute, ScopedRouteGateway, ScopedRouteOrigin, MAX_RESOURCE_ITEMS,
};

const ROUTE_AUDIT_BUDGET: Duration = Duration::from_secs(5);

pub(crate) struct HelperRouteExecutor {
    lease_id: LeaseId,
    platform: Box<dyn OwnedRoutes>,
    interface_name: fn(
        PlatformLayout,
        LeaseId,
        &crate::vortix_core::privileged::ResourceTag,
    ) -> Result<String, ()>,
}

struct PhysicalRoutePlan {
    entries: Vec<RouteEntry>,
    transport_bypass_targets: Vec<IpAddr>,
    transport_bypass_entries: Vec<RouteEntry>,
}

impl HelperRouteExecutor {
    pub(crate) fn new(
        layout: PlatformLayout,
        lease_id: LeaseId,
    ) -> Result<Self, super::server::ObservationError> {
        let platform = crate::platform::helper_owned_routes();
        if layout != layout_for_backend(platform.backend()) {
            return Err(super::server::ObservationError::Unavailable);
        }
        Ok(Self {
            lease_id,
            platform,
            interface_name: authority_interface_name,
        })
    }

    #[cfg(test)]
    fn with_platform(
        layout: PlatformLayout,
        lease_id: LeaseId,
        platform: impl OwnedRoutes + 'static,
    ) -> Self {
        assert_eq!(layout, layout_for_backend(platform.backend()));
        Self {
            lease_id,
            platform: Box::new(platform),
            interface_name: authority_interface_name,
        }
    }

    #[cfg(test)]
    fn with_platform_and_interfaces(
        layout: PlatformLayout,
        lease_id: LeaseId,
        platform: impl OwnedRoutes + 'static,
        interface_name: fn(
            PlatformLayout,
            LeaseId,
            &crate::vortix_core::privileged::ResourceTag,
        ) -> Result<String, ()>,
    ) -> Self {
        let mut executor = Self::with_platform(layout, lease_id, platform);
        executor.interface_name = interface_name;
        executor
    }

    fn layout(&self) -> PlatformLayout {
        layout_for_backend(self.platform.backend())
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
        let physical = states
            .iter()
            .filter_map(RecoveredRouteState::physical)
            .collect::<Vec<_>>();
        if !physical.is_empty() {
            if physical.len() != states.len()
                || physical
                    .iter()
                    .any(|record| record.backend() != self.platform.backend())
            {
                return Err(PrivilegedExecutionError::InvalidPlan);
            }
            return self.validate_recovered_physical(&physical);
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

    fn validate_recovered_physical(
        &mut self,
        states: &[&HelperLedgerRoutes],
    ) -> Result<(), PrivilegedExecutionError> {
        let pending = states.iter().find(|state| {
            matches!(
                state.stage(),
                PhysicalRouteStage::Prepared | PhysicalRouteStage::EffectPendingObservation
            )
        });
        let owner = states.iter().find(|state| {
            matches!(
                state.stage(),
                PhysicalRouteStage::ObservedOwned | PhysicalRouteStage::OwnedReleasePending
            )
        });
        let observed = self.observed_owned_domain(
            self.platform.backend(),
            states
                .iter()
                .flat_map(|record| physical_route_entries(record)),
        )?;
        if let Some(pending) = pending {
            let target_matches = owned_domain_matches(pending, &observed);
            let prior_matches = owner.map_or_else(
                || empty_owned_domain_matches(self.platform.backend(), &observed),
                |owner| owned_domain_matches(owner, &observed),
            );
            return match pending.stage() {
                PhysicalRouteStage::Prepared if prior_matches => Ok(()),
                PhysicalRouteStage::EffectPendingObservation if target_matches || prior_matches => {
                    Ok(())
                }
                _ => Err(PrivilegedExecutionError::EffectMayHaveApplied),
            };
        }
        if let Some(owner) = owner {
            if owned_domain_matches(owner, &observed) {
                return Ok(());
            }
            if owner.stage() == PhysicalRouteStage::OwnedReleasePending
                && empty_owned_domain_matches(self.platform.backend(), &observed)
            {
                return Ok(());
            }
            return Err(PrivilegedExecutionError::EffectMayHaveApplied);
        }
        if empty_owned_domain_matches(self.platform.backend(), &observed) {
            Ok(())
        } else {
            Err(PrivilegedExecutionError::EffectMayHaveApplied)
        }
    }

    fn observed_entries_for<'a>(
        &mut self,
        entries: impl Iterator<Item = &'a RouteEntry>,
    ) -> Result<HashMap<Cidr, Vec<RouteEntry>>, PrivilegedExecutionError> {
        let destinations = entries
            .map(RouteEntry::destination)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let observed = self
            .platform
            .exact_route_entries_batch(&destinations)
            .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
        Ok(destinations.into_iter().zip(observed).collect())
    }

    fn observed_owned_domain<'a>(
        &mut self,
        backend: PhysicalRouteBackend,
        entries: impl Iterator<Item = &'a RouteEntry>,
    ) -> Result<ObservedOwnedDomain, PrivilegedExecutionError> {
        let entries = self.observed_entries_for(entries)?;
        if backend == PhysicalRouteBackend::MacOsScopedV1 {
            return Ok(ObservedOwnedDomain {
                entries,
                transport_bypass_targets: None,
                active: None,
            });
        }
        Ok(ObservedOwnedDomain {
            entries,
            transport_bypass_targets: Some(
                self.platform
                    .exact_transport_bypass_targets()
                    .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?
                    .into_iter()
                    .collect(),
            ),
            active: Some(
                self.platform
                    .route_domain_active()
                    .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?,
            ),
        })
    }

    /// Exercise the future fixed route-writer transaction without making it
    /// reachable from policy execution. Activation remains blocked until the
    /// physical route plan is durably recorded and protocol route creation is
    /// disabled in the same cutover.
    #[allow(
        dead_code,
        reason = "dormant until the atomic protocol-to-policy route ownership cutover"
    )]
    pub(crate) fn install_owned_routes(
        &mut self,
        desired: &[RouteEntry],
    ) -> Result<(), PrivilegedExecutionError> {
        self.replace_owned_routes(&[], desired)
    }

    fn replace_owned_routes(
        &mut self,
        prior: &[RouteEntry],
        desired: &[RouteEntry],
    ) -> Result<(), PrivilegedExecutionError> {
        if prior.len() > MAX_RESOURCE_ITEMS
            || desired.len() > MAX_RESOURCE_ITEMS
            || has_duplicate_destinations(prior)
            || has_duplicate_destinations(desired)
        {
            return Err(PrivilegedExecutionError::InvalidPlan);
        }
        let observed = self.observed_entries_for(prior.iter().chain(desired))?;
        if !entries_match_snapshot(prior, &observed) {
            return Err(PrivilegedExecutionError::FailedBeforeEffect);
        }
        if prior == desired {
            return Ok(());
        }

        for route in prior.iter().rev() {
            if self.platform.remove_route(route).is_err()
                || !matches!(
                    self.platform.exact_route_entries(route.destination()),
                    Ok(entries) if entries.is_empty()
                )
            {
                return Err(self.rollback_to(prior, desired));
            }
        }
        for route in desired {
            if self.platform.add_route(route).is_err()
                || !matches!(
                    self.platform.exact_route_entries(route.destination()),
                    Ok(entries) if entries.len() == 1 && entries.first() == Some(route)
                )
            {
                return Err(self.rollback_to(prior, desired));
            }
        }
        let observed = self.observed_entries_for(prior.iter().chain(desired));
        if observed.is_ok_and(|observed| entries_match_snapshot(desired, &observed)) {
            Ok(())
        } else {
            Err(self.rollback_to(prior, desired))
        }
    }

    fn rollback_to(
        &mut self,
        prior: &[RouteEntry],
        desired: &[RouteEntry],
    ) -> PrivilegedExecutionError {
        for route in desired.iter().rev() {
            match self.platform.exact_route_entries(route.destination()) {
                Ok(observed) if observed.is_empty() => {}
                Ok(observed) if observed.len() == 1 && observed.first() == Some(route) => {
                    let _ = self.platform.remove_route(route);
                    if !matches!(
                        self.platform.exact_route_entries(route.destination()),
                        Ok(remaining) if remaining.is_empty()
                    ) {
                        return PrivilegedExecutionError::EffectMayHaveApplied;
                    }
                }
                Ok(_) | Err(_) => return PrivilegedExecutionError::EffectMayHaveApplied,
            }
        }
        for route in prior {
            match self.platform.exact_route_entries(route.destination()) {
                Ok(observed) if observed.is_empty() => {
                    if self.platform.add_route(route).is_err()
                        || !matches!(
                            self.platform.exact_route_entries(route.destination()),
                            Ok(restored) if restored.len() == 1 && restored.first() == Some(route)
                        )
                    {
                        return PrivilegedExecutionError::EffectMayHaveApplied;
                    }
                }
                Ok(observed) if observed.len() == 1 && observed.first() == Some(route) => {}
                Ok(_) | Err(_) => return PrivilegedExecutionError::EffectMayHaveApplied,
            }
        }
        match self.observed_entries_for(prior.iter().chain(desired)) {
            Ok(observed) if entries_match_snapshot(prior, &observed) => {
                PrivilegedExecutionError::FailedBeforeEffect
            }
            Ok(_) | Err(_) => PrivilegedExecutionError::EffectMayHaveApplied,
        }
    }

    fn replace_linux_policy_routes(
        &mut self,
        prior: Option<&HelperLedgerRoutes>,
        target: &HelperLedgerRoutes,
    ) -> Result<(), PrivilegedExecutionError> {
        if target.backend() != PhysicalRouteBackend::LinuxPolicyV1
            || prior.is_some_and(|prior| prior.backend() != target.backend())
        {
            return Err(PrivilegedExecutionError::InvalidPlan);
        }
        let observed = self.observed_owned_domain(
            PhysicalRouteBackend::LinuxPolicyV1,
            prior
                .into_iter()
                .flat_map(HelperLedgerRoutes::entries)
                .chain(target.entries()),
        )?;
        if prior.map_or_else(
            || empty_owned_domain_matches(PhysicalRouteBackend::LinuxPolicyV1, &observed),
            |prior| owned_domain_matches(prior, &observed),
        ) {
            self.apply_linux_policy_routes(prior, target)
        } else {
            Err(PrivilegedExecutionError::FailedBeforeEffect)
        }
    }

    fn apply_linux_policy_routes(
        &mut self,
        prior: Option<&HelperLedgerRoutes>,
        target: &HelperLedgerRoutes,
    ) -> Result<(), PrivilegedExecutionError> {
        let prior_entries = prior.map_or(&[] as &[RouteEntry], HelperLedgerRoutes::entries);
        let prior_bypass = prior.map_or(
            &[] as &[IpAddr],
            HelperLedgerRoutes::transport_bypass_targets,
        );
        let desired_bypass = target.transport_bypass_targets();

        let effect = (|| {
            for target in desired_bypass {
                if !prior_bypass.contains(target) {
                    self.platform
                        .add_transport_bypass(*target)
                        .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
                }
            }
            if target.entries().is_empty() {
                self.set_route_domain_active(false)?;
            }
            self.replace_owned_routes(prior_entries, target.entries())?;
            if !target.entries().is_empty() {
                self.set_route_domain_active(true)?;
            }
            for target in prior_bypass.iter().rev() {
                if !desired_bypass.contains(target) {
                    self.platform
                        .remove_transport_bypass(*target)
                        .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
                }
            }
            let observed = self.observed_owned_domain(
                PhysicalRouteBackend::LinuxPolicyV1,
                prior_entries.iter().chain(target.entries()),
            )?;
            if owned_domain_matches(target, &observed) {
                Ok(())
            } else {
                Err(PrivilegedExecutionError::EffectMayHaveApplied)
            }
        })();

        match effect {
            Ok(()) => Ok(()),
            Err(_) => Err(self.restore_linux_policy_routes(prior, target)),
        }
    }

    fn restore_linux_policy_routes(
        &mut self,
        prior: Option<&HelperLedgerRoutes>,
        target: &HelperLedgerRoutes,
    ) -> PrivilegedExecutionError {
        let prior_entries = prior.map_or(&[] as &[RouteEntry], HelperLedgerRoutes::entries);
        let prior_bypass = prior.map_or(
            &[] as &[IpAddr],
            HelperLedgerRoutes::transport_bypass_targets,
        );

        let Ok(observed_bypass) = self.platform.exact_transport_bypass_targets() else {
            return PrivilegedExecutionError::EffectMayHaveApplied;
        };
        for target in prior_bypass {
            if !observed_bypass.contains(target)
                && self.platform.add_transport_bypass(*target).is_err()
            {
                return PrivilegedExecutionError::EffectMayHaveApplied;
            }
        }

        let Ok(observed_entries) =
            self.observed_entries_for(prior_entries.iter().chain(target.entries()))
        else {
            return PrivilegedExecutionError::EffectMayHaveApplied;
        };
        if prior_entries.is_empty() && self.set_route_domain_active(false).is_err() {
            return PrivilegedExecutionError::EffectMayHaveApplied;
        }
        if !entries_match_snapshot(prior_entries, &observed_entries)
            && (!entries_match_snapshot(target.entries(), &observed_entries)
                || self
                    .replace_owned_routes(target.entries(), prior_entries)
                    .is_err())
        {
            return PrivilegedExecutionError::EffectMayHaveApplied;
        }
        if !prior_entries.is_empty() && self.set_route_domain_active(true).is_err() {
            return PrivilegedExecutionError::EffectMayHaveApplied;
        }

        let Ok(observed_bypass) = self.platform.exact_transport_bypass_targets() else {
            return PrivilegedExecutionError::EffectMayHaveApplied;
        };
        for target in observed_bypass.iter().rev() {
            if !prior_bypass.contains(target)
                && self.platform.remove_transport_bypass(*target).is_err()
            {
                return PrivilegedExecutionError::EffectMayHaveApplied;
            }
        }
        match self.observed_owned_domain(
            PhysicalRouteBackend::LinuxPolicyV1,
            prior_entries.iter().chain(target.entries()),
        ) {
            Ok(observed)
                if prior.map_or_else(
                    || empty_owned_domain_matches(PhysicalRouteBackend::LinuxPolicyV1, &observed),
                    |prior| owned_domain_matches(prior, &observed),
                ) =>
            {
                PrivilegedExecutionError::FailedBeforeEffect
            }
            Ok(_) | Err(_) => PrivilegedExecutionError::EffectMayHaveApplied,
        }
    }

    fn set_route_domain_active(&mut self, expected: bool) -> Result<(), PrivilegedExecutionError> {
        let active = self
            .platform
            .route_domain_active()
            .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
        if active != expected {
            let mutation = if expected {
                self.platform.activate_route_domain()
            } else {
                self.platform.deactivate_route_domain()
            };
            if mutation.is_err() || self.platform.route_domain_active().ok() != Some(expected) {
                return Err(PrivilegedExecutionError::EffectMayHaveApplied);
            }
        }
        Ok(())
    }

    fn replace_macos_scoped_routes(
        &mut self,
        prior: Option<&HelperLedgerRoutes>,
        target: &HelperLedgerRoutes,
    ) -> Result<(), PrivilegedExecutionError> {
        if target.backend() != PhysicalRouteBackend::MacOsScopedV1
            || prior.is_some_and(|prior| prior.backend() != target.backend())
        {
            return Err(PrivilegedExecutionError::InvalidPlan);
        }
        let observed = self.observed_owned_domain(
            PhysicalRouteBackend::MacOsScopedV1,
            prior
                .into_iter()
                .flat_map(physical_route_entries)
                .chain(physical_route_entries(target)),
        )?;
        if !prior.map_or_else(
            || empty_owned_domain_matches(PhysicalRouteBackend::MacOsScopedV1, &observed),
            |prior| owned_domain_matches(prior, &observed),
        ) {
            return Err(PrivilegedExecutionError::FailedBeforeEffect);
        }
        let effect = self.apply_macos_scoped_routes(prior, target);
        match effect {
            Ok(()) => Ok(()),
            Err(_) => Err(self.restore_macos_scoped_routes(prior, target)),
        }
    }

    fn apply_macos_scoped_routes(
        &mut self,
        prior: Option<&HelperLedgerRoutes>,
        target: &HelperLedgerRoutes,
    ) -> Result<(), PrivilegedExecutionError> {
        let prior_entries = prior.map_or(&[] as &[RouteEntry], HelperLedgerRoutes::entries);
        let prior_bypass = prior.map_or(
            &[] as &[RouteEntry],
            HelperLedgerRoutes::transport_bypass_entries,
        );
        for route in target.transport_bypass_entries() {
            if !prior_bypass.contains(route) {
                self.add_exact_route(route)?;
            }
        }
        self.replace_owned_routes(prior_entries, target.entries())?;
        for route in prior_bypass.iter().rev() {
            if !target.transport_bypass_entries().contains(route) {
                self.remove_exact_route(route)?;
            }
        }
        let observed = self.observed_owned_domain(
            PhysicalRouteBackend::MacOsScopedV1,
            prior
                .into_iter()
                .flat_map(physical_route_entries)
                .chain(physical_route_entries(target)),
        )?;
        owned_domain_matches(target, &observed)
            .then_some(())
            .ok_or(PrivilegedExecutionError::EffectMayHaveApplied)
    }

    fn restore_macos_scoped_routes(
        &mut self,
        prior: Option<&HelperLedgerRoutes>,
        target: &HelperLedgerRoutes,
    ) -> PrivilegedExecutionError {
        let prior_entries = prior.map_or(&[] as &[RouteEntry], HelperLedgerRoutes::entries);
        let prior_bypass = prior.map_or(
            &[] as &[RouteEntry],
            HelperLedgerRoutes::transport_bypass_entries,
        );
        for route in prior_bypass {
            match self.platform.exact_route_entries(route.destination()) {
                Ok(entries) if entries.is_empty() => {
                    if self.add_exact_route(route).is_err() {
                        return PrivilegedExecutionError::EffectMayHaveApplied;
                    }
                }
                Ok(entries) if entries.len() == 1 && entries.first() == Some(route) => {}
                Ok(_) | Err(_) => return PrivilegedExecutionError::EffectMayHaveApplied,
            }
        }
        let Ok(observed_entries) =
            self.observed_entries_for(prior_entries.iter().chain(target.entries()))
        else {
            return PrivilegedExecutionError::EffectMayHaveApplied;
        };
        if !entries_match_snapshot(prior_entries, &observed_entries)
            && (!entries_match_snapshot(target.entries(), &observed_entries)
                || self
                    .replace_owned_routes(target.entries(), prior_entries)
                    .is_err())
        {
            return PrivilegedExecutionError::EffectMayHaveApplied;
        }
        for route in target.transport_bypass_entries().iter().rev() {
            if !prior_bypass.contains(route) && self.remove_exact_route(route).is_err() {
                return PrivilegedExecutionError::EffectMayHaveApplied;
            }
        }
        match self.observed_owned_domain(
            PhysicalRouteBackend::MacOsScopedV1,
            prior
                .into_iter()
                .flat_map(physical_route_entries)
                .chain(physical_route_entries(target)),
        ) {
            Ok(observed)
                if prior.map_or_else(
                    || empty_owned_domain_matches(PhysicalRouteBackend::MacOsScopedV1, &observed),
                    |prior| owned_domain_matches(prior, &observed),
                ) =>
            {
                PrivilegedExecutionError::FailedBeforeEffect
            }
            Ok(_) | Err(_) => PrivilegedExecutionError::EffectMayHaveApplied,
        }
    }

    fn add_exact_route(&mut self, route: &RouteEntry) -> Result<(), PrivilegedExecutionError> {
        if self.platform.add_route(route).is_err()
            || !matches!(
                self.platform.exact_route_entries(route.destination()),
                Ok(entries) if entries.len() == 1 && entries.first() == Some(route)
            )
        {
            return Err(PrivilegedExecutionError::EffectMayHaveApplied);
        }
        Ok(())
    }

    fn remove_exact_route(&mut self, route: &RouteEntry) -> Result<(), PrivilegedExecutionError> {
        if self.platform.remove_route(route).is_err()
            || !matches!(
                self.platform.exact_route_entries(route.destination()),
                Ok(entries) if entries.is_empty()
            )
        {
            return Err(PrivilegedExecutionError::EffectMayHaveApplied);
        }
        Ok(())
    }

    pub(crate) fn prepare_owned(
        &mut self,
        plan: &NetworkPolicyExecutionPlan,
    ) -> Result<PreparedNetworkPolicyExecutionPlan, NetworkPolicyPreparationError> {
        match plan.operation() {
            NetworkPolicyOperation::ApplyRoutes { policy, .. }
                if plan.intended().route_inputs().is_some() =>
            {
                let physical = self
                    .physical_plan(plan.intended(), plan.recovered_routes())
                    .map_err(|_| NetworkPolicyPreparationError::InvalidPlan)?;
                let mut routes = plan.recovered_routes().to_vec();
                let prepared = if let Some(existing) =
                    routes.iter().find(|physical| physical.resource() == policy)
                {
                    existing
                        .prepare_for(
                            plan.intended(),
                            physical.entries,
                            physical.transport_bypass_targets,
                            physical.transport_bypass_entries,
                        )
                        .map_err(|_| NetworkPolicyPreparationError::InvalidPlan)?
                } else {
                    HelperLedgerRoutes::prepared(
                        policy.clone(),
                        self.platform.backend(),
                        new_transaction_id()
                            .map_err(|_| NetworkPolicyPreparationError::FailedBeforeEffect)?,
                        plan.intended().digest(),
                        physical.entries,
                        physical.transport_bypass_targets,
                        physical.transport_bypass_entries,
                    )
                    .map_err(|_| NetworkPolicyPreparationError::InvalidPlan)?
                };
                if let Some(existing) = routes
                    .iter_mut()
                    .find(|physical| physical.resource() == policy)
                {
                    *existing = prepared;
                } else {
                    routes.push(prepared);
                }
                Ok(
                    PreparedNetworkPolicyExecutionPlan::with_helper_owned_routes(
                        plan.clone(),
                        plan.recovered_firewalls().to_vec(),
                        plan.recovered_dns().to_vec(),
                        routes,
                    ),
                )
            }
            NetworkPolicyOperation::ObserveBarrier { .. }
                if plan.intended().route_inputs().is_some() =>
            {
                Ok(
                    PreparedNetworkPolicyExecutionPlan::with_helper_owned_routes(
                        plan.clone(),
                        plan.recovered_firewalls().to_vec(),
                        plan.recovered_dns().to_vec(),
                        plan.recovered_routes().to_vec(),
                    ),
                )
            }
            NetworkPolicyOperation::EstablishFirewall { .. }
            | NetworkPolicyOperation::EstablishBlocking { .. }
            | NetworkPolicyOperation::ApplyRoutes { .. }
            | NetworkPolicyOperation::ApplyDns { .. }
            | NetworkPolicyOperation::ApplyFirewall { .. }
            | NetworkPolicyOperation::ObserveBarrier { .. }
            | NetworkPolicyOperation::ReleaseObsolete { .. } => {
                Err(NetworkPolicyPreparationError::InvalidPlan)
            }
        }
    }

    pub(crate) fn execute_owned(
        &mut self,
        prepared: &PreparedNetworkPolicyExecutionPlan,
    ) -> Result<NetworkPolicyOutcome, PrivilegedExecutionError> {
        let plan = prepared.execution();
        if prepared.route_writer() != PreparedRouteWriter::HelperOwned {
            return Err(PrivilegedExecutionError::InvalidPlan);
        }
        match plan.operation() {
            NetworkPolicyOperation::ApplyRoutes { policy, .. } => {
                let target = prepared
                    .prepared_routes()
                    .iter()
                    .find(|physical| physical.resource() == policy)
                    .filter(|physical| {
                        physical.stage() == PhysicalRouteStage::EffectPendingObservation
                    })
                    .ok_or(PrivilegedExecutionError::InvalidPlan)?;
                let prior = prepared
                    .prepared_routes()
                    .iter()
                    .filter(|physical| physical.resource() != policy)
                    .filter(|physical| physical.stage() == PhysicalRouteStage::ObservedOwned)
                    .collect::<Vec<_>>();
                if prior.len() > 1 {
                    return Err(PrivilegedExecutionError::InvalidPlan);
                }
                match target.backend() {
                    PhysicalRouteBackend::LinuxPolicyV1 => {
                        self.replace_linux_policy_routes(prior.first().copied(), target)?;
                    }
                    PhysicalRouteBackend::MacOsScopedV1 => {
                        self.replace_macos_scoped_routes(prior.first().copied(), target)?;
                    }
                    PhysicalRouteBackend::LinuxIpMain | PhysicalRouteBackend::MacOsRouteTable => {
                        return Err(PrivilegedExecutionError::InvalidPlan);
                    }
                }
                Ok(NetworkPolicyOutcome::Applied)
            }
            NetworkPolicyOperation::ObserveBarrier { policy, .. }
                if policy == plan.intended().policy() =>
            {
                let target = prepared
                    .prepared_routes()
                    .iter()
                    .find(|physical| physical.resource() == policy)
                    .ok_or(PrivilegedExecutionError::InvalidPlan)?;
                let observed =
                    self.observed_owned_domain(target.backend(), physical_route_entries(target))?;
                if !owned_domain_matches(target, &observed) {
                    return Err(PrivilegedExecutionError::FailedBeforeEffect);
                }
                Ok(NetworkPolicyOutcome::Observed(vec![
                    ResourceObservation::new(
                        policy.clone(),
                        plan.intended().expected_observation_state(),
                        1,
                    )
                    .map_err(|_| PrivilegedExecutionError::InvalidPlan)?,
                ]))
            }
            NetworkPolicyOperation::EstablishFirewall { .. }
            | NetworkPolicyOperation::EstablishBlocking { .. }
            | NetworkPolicyOperation::ApplyDns { .. }
            | NetworkPolicyOperation::ApplyFirewall { .. }
            | NetworkPolicyOperation::ObserveBarrier { .. }
            | NetworkPolicyOperation::ReleaseObsolete { .. } => {
                Err(PrivilegedExecutionError::InvalidPlan)
            }
        }
    }

    fn physical_plan(
        &mut self,
        projection: &PolicyProjection,
        recovered: &[HelperLedgerRoutes],
    ) -> Result<PhysicalRoutePlan, PrivilegedExecutionError> {
        let (routes, redirects, tunnels) = projection
            .route_inputs()
            .ok_or(PrivilegedExecutionError::InvalidPlan)?;
        let entries = self.policy_route_entries(routes, redirects, tunnels)?;
        let transport_bypass_targets = if entries.is_empty() {
            Vec::new()
        } else {
            tunnels
                .iter()
                .flat_map(PrivilegedFirewallTunnel::endpoint_ips)
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        };
        let transport_bypass_entries = self.resolved_transport_bypass_entries(
            &transport_bypass_targets,
            tunnels,
            &entries,
            recovered,
        )?;
        Ok(PhysicalRoutePlan {
            entries,
            transport_bypass_targets,
            transport_bypass_entries,
        })
    }

    fn policy_route_entries(
        &mut self,
        routes: &[ScopedRoute],
        redirects: &[ScopedOpenVpnRedirect],
        tunnels: &[PrivilegedFirewallTunnel],
    ) -> Result<Vec<RouteEntry>, PrivilegedExecutionError> {
        let mut entries = routes
            .iter()
            .map(|route| self.policy_route_entry(route, tunnels))
            .collect::<Result<Vec<_>, _>>()?;
        for redirect in redirects {
            let interface = (self.interface_name)(self.layout(), self.lease_id, redirect.tunnel())
                .map_err(|()| PrivilegedExecutionError::InvalidPlan)?;
            for destination in redirect
                .destinations()
                .map_err(|_| PrivilegedExecutionError::InvalidPlan)?
            {
                let gateway = openvpn_default_gateway(destination, redirect.route_defaults())?;
                let metric = redirect.route_defaults().metric();
                if self.layout() == PlatformLayout::MacOs && metric.is_some() {
                    return Err(PrivilegedExecutionError::InvalidPlan);
                }
                entries.push(
                    RouteEntry::new(destination, interface.clone(), gateway, metric)
                        .map_err(|_| PrivilegedExecutionError::InvalidPlan)?,
                );
            }
        }
        Ok(entries)
    }

    fn policy_route_entry(
        &mut self,
        route: &ScopedRoute,
        tunnels: &[PrivilegedFirewallTunnel],
    ) -> Result<RouteEntry, PrivilegedExecutionError> {
        if !tunnels
            .iter()
            .any(|subject| subject.tunnel() == route.tunnel())
        {
            return Err(PrivilegedExecutionError::InvalidPlan);
        }
        let metric = route.metric().or(route.route_defaults().metric());
        let entry = match (route.origin(), route.gateway()) {
            (ScopedRouteOrigin::WireGuard, ScopedRouteGateway::Interface)
                if route.metric().is_none() =>
            {
                RouteEntry::new(
                    route.destination(),
                    self.route_interface(route)?,
                    None,
                    None,
                )
            }
            (
                ScopedRouteOrigin::OpenVpnConfigured | ScopedRouteOrigin::OpenVpnPushed,
                ScopedRouteGateway::OpenVpn(OpenVpnRouteGateway::VpnDefault),
            ) => RouteEntry::new(
                route.destination(),
                self.route_interface(route)?,
                openvpn_default_gateway(route.destination(), route.route_defaults())?,
                metric,
            ),
            (
                ScopedRouteOrigin::OpenVpnConfigured | ScopedRouteOrigin::OpenVpnPushed,
                ScopedRouteGateway::OpenVpn(OpenVpnRouteGateway::Address(gateway)),
            ) => RouteEntry::new(
                route.destination(),
                self.route_interface(route)?,
                Some(gateway),
                metric,
            ),
            (
                ScopedRouteOrigin::OpenVpnConfigured | ScopedRouteOrigin::OpenVpnPushed,
                ScopedRouteGateway::OpenVpn(OpenVpnRouteGateway::NetGateway),
            ) => {
                let resolved = self
                    .platform
                    .resolve_net_gateway(route.destination())
                    .map_err(|_| PrivilegedExecutionError::FailedBeforeEffect)?;
                RouteEntry::new(
                    route.destination(),
                    resolved.interface().to_owned(),
                    resolved.gateway(),
                    metric,
                )
            }
            (
                ScopedRouteOrigin::OpenVpnConfigured | ScopedRouteOrigin::OpenVpnPushed,
                ScopedRouteGateway::OpenVpn(OpenVpnRouteGateway::RemoteHost),
            ) => RouteEntry::new(
                route.destination(),
                self.route_interface(route)?,
                Some(
                    route
                        .selected_remote()
                        .ok_or(PrivilegedExecutionError::InvalidPlan)?,
                ),
                metric,
            ),
            _ => return Err(PrivilegedExecutionError::InvalidPlan),
        }
        .map_err(|_| PrivilegedExecutionError::InvalidPlan)?;
        if self.layout() == PlatformLayout::MacOs && metric.is_some() {
            return Err(PrivilegedExecutionError::InvalidPlan);
        }
        Ok(entry)
    }

    fn route_interface(&self, route: &ScopedRoute) -> Result<String, PrivilegedExecutionError> {
        (self.interface_name)(self.layout(), self.lease_id, route.tunnel())
            .map_err(|()| PrivilegedExecutionError::InvalidPlan)
    }

    fn resolved_transport_bypass_entries(
        &mut self,
        targets: &[IpAddr],
        tunnels: &[PrivilegedFirewallTunnel],
        entries: &[RouteEntry],
        recovered: &[HelperLedgerRoutes],
    ) -> Result<Vec<RouteEntry>, PrivilegedExecutionError> {
        Ok(match self.platform.backend() {
            PhysicalRouteBackend::LinuxPolicyV1 => Vec::new(),
            PhysicalRouteBackend::MacOsScopedV1 => {
                let tunnel_interfaces = tunnels
                    .iter()
                    .map(|tunnel| {
                        (self.interface_name)(self.layout(), self.lease_id, tunnel.tunnel())
                            .map_err(|()| PrivilegedExecutionError::InvalidPlan)
                    })
                    .collect::<Result<HashSet<_>, _>>()?;
                let mut bypass = Vec::with_capacity(targets.len());
                for target in targets {
                    let destination = Cidr::new(*target, if target.is_ipv4() { 32 } else { 128 })
                        .ok_or(PrivilegedExecutionError::InvalidPlan)?;
                    let retained = recovered
                        .iter()
                        .filter(|record| {
                            record.backend() == PhysicalRouteBackend::MacOsScopedV1
                                && matches!(
                                    record.stage(),
                                    PhysicalRouteStage::ObservedOwned
                                        | PhysicalRouteStage::OwnedReleasePending
                                )
                        })
                        .flat_map(HelperLedgerRoutes::transport_bypass_entries)
                        .filter(|entry| entry.destination() == destination)
                        .collect::<Vec<_>>();
                    let entry = match retained.as_slice() {
                        [] => self
                            .platform
                            .resolve_transport_bypass(*target)
                            .map_err(|_| PrivilegedExecutionError::FailedBeforeEffect)?,
                        [entry] => (*entry).clone(),
                        _ => return Err(PrivilegedExecutionError::InvalidPlan),
                    };
                    if tunnel_interfaces.contains(entry.interface())
                        || entries
                            .iter()
                            .any(|route| route.destination() == entry.destination())
                    {
                        return Err(PrivilegedExecutionError::InvalidPlan);
                    }
                    bypass.push(entry);
                }
                bypass
            }
            PhysicalRouteBackend::LinuxIpMain | PhysicalRouteBackend::MacOsRouteTable => {
                return Err(PrivilegedExecutionError::InvalidPlan);
            }
        })
    }

    pub(crate) fn prepare_release(
        &mut self,
        plan: &NetworkPolicyExecutionPlan,
    ) -> Result<(), NetworkPolicyPreparationError> {
        self.verify_physical_release(plan.recovered_routes(), plan)
            .and_then(|()| self.verify_release(plan))
            .map_err(|error| match error {
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
        self.verify_physical_release(prepared.prepared_routes(), prepared.execution())?;
        self.verify_release(prepared.execution())
    }

    fn verify_physical_release(
        &mut self,
        physical: &[HelperLedgerRoutes],
        plan: &NetworkPolicyExecutionPlan,
    ) -> Result<(), PrivilegedExecutionError> {
        if physical.is_empty() {
            return Ok(());
        }
        let (current, obsolete) = plan
            .release_family(crate::vortix_core::privileged::ResourceKind::Routes)
            .ok_or(PrivilegedExecutionError::InvalidPlan)?;
        let retained = physical
            .iter()
            .find(|entry| entry.resource() == current.policy())
            .filter(|entry| {
                matches!(
                    entry.stage(),
                    PhysicalRouteStage::ObservedOwned | PhysicalRouteStage::ObservedAbsent
                )
            })
            .ok_or(PrivilegedExecutionError::InvalidPlan)?;
        for projection in obsolete {
            let entry = physical
                .iter()
                .find(|entry| entry.resource() == projection.policy())
                .ok_or(PrivilegedExecutionError::InvalidPlan)?;
            if !matches!(
                entry.stage(),
                PhysicalRouteStage::Superseded
                    | PhysicalRouteStage::ObservedAbsent
                    | PhysicalRouteStage::SupersededReleasePending
                    | PhysicalRouteStage::AbsentReleasePending
            ) {
                return Err(PrivilegedExecutionError::InvalidPlan);
            }
        }
        let observed = self.observed_owned_domain(
            retained.backend(),
            physical.iter().flat_map(physical_route_entries),
        )?;
        if owned_domain_matches(retained, &observed) {
            Ok(())
        } else {
            Err(PrivilegedExecutionError::FailedBeforeEffect)
        }
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
            return Ok(ProjectionState::Absent);
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
        let (routes, redirects, tunnels) = projection
            .route_inputs()
            .ok_or(PrivilegedExecutionError::InvalidPlan)?;
        if !redirects.is_empty() {
            return Err(PrivilegedExecutionError::InvalidPlan);
        }
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
            let interface = (self.interface_name)(self.layout(), self.lease_id, route.tunnel())
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

struct ObservedOwnedDomain {
    entries: HashMap<Cidr, Vec<RouteEntry>>,
    transport_bypass_targets: Option<BTreeSet<IpAddr>>,
    active: Option<bool>,
}

fn owned_domain_matches(expected: &HelperLedgerRoutes, observed: &ObservedOwnedDomain) -> bool {
    let entries = physical_route_entries(expected).collect::<Vec<_>>();
    entries_match_snapshot_refs(&entries, &observed.entries)
        && match expected.backend() {
            PhysicalRouteBackend::LinuxPolicyV1 => {
                observed.transport_bypass_targets.as_ref()
                    == Some(
                        &expected
                            .transport_bypass_targets()
                            .iter()
                            .copied()
                            .collect(),
                    )
                    && observed.active == Some(!expected.entries().is_empty())
            }
            PhysicalRouteBackend::MacOsScopedV1 => {
                observed.transport_bypass_targets.is_none() && observed.active.is_none()
            }
            PhysicalRouteBackend::LinuxIpMain | PhysicalRouteBackend::MacOsRouteTable => false,
        }
}

fn empty_owned_domain_matches(
    backend: PhysicalRouteBackend,
    observed: &ObservedOwnedDomain,
) -> bool {
    entries_match_snapshot(&[], &observed.entries)
        && match backend {
            PhysicalRouteBackend::LinuxPolicyV1 => {
                observed
                    .transport_bypass_targets
                    .as_ref()
                    .is_some_and(BTreeSet::is_empty)
                    && observed.active == Some(false)
            }
            PhysicalRouteBackend::MacOsScopedV1 => {
                observed.transport_bypass_targets.is_none() && observed.active.is_none()
            }
            PhysicalRouteBackend::LinuxIpMain | PhysicalRouteBackend::MacOsRouteTable => false,
        }
}

fn physical_route_entries(record: &HelperLedgerRoutes) -> impl Iterator<Item = &RouteEntry> {
    record
        .entries()
        .iter()
        .chain(record.transport_bypass_entries())
}

fn openvpn_default_gateway(
    destination: Cidr,
    defaults: crate::vortix_core::privileged::OpenVpnRouteDefaults,
) -> Result<Option<IpAddr>, PrivilegedExecutionError> {
    if destination.is_v4() {
        return match defaults.gateways().ipv4() {
            Some(OpenVpnDefaultGateway::Address(address)) => Ok(Some(address)),
            Some(OpenVpnDefaultGateway::Dhcp) => Err(PrivilegedExecutionError::InvalidPlan),
            None => Ok(None),
        };
    }
    Ok(defaults.gateways().ipv6().map(IpAddr::V6))
}

fn has_duplicate_destinations(entries: &[RouteEntry]) -> bool {
    let destinations = entries
        .iter()
        .map(RouteEntry::destination)
        .collect::<HashSet<_>>();
    destinations.len() != entries.len()
}

fn entries_match_snapshot(
    expected: &[RouteEntry],
    observed: &HashMap<Cidr, Vec<RouteEntry>>,
) -> bool {
    if has_duplicate_destinations(expected) {
        return false;
    }
    observed.iter().all(|(destination, entries)| {
        expected
            .iter()
            .find(|entry| entry.destination() == *destination)
            .map_or_else(
                || entries.is_empty(),
                |entry| entries.len() == 1 && entries.first() == Some(entry),
            )
    }) && expected
        .iter()
        .all(|entry| observed.contains_key(&entry.destination()))
}

fn entries_match_snapshot_refs(
    expected: &[&RouteEntry],
    observed: &HashMap<Cidr, Vec<RouteEntry>>,
) -> bool {
    let destinations = expected
        .iter()
        .map(|entry| entry.destination())
        .collect::<HashSet<_>>();
    if destinations.len() != expected.len() {
        return false;
    }
    observed.iter().all(|(destination, entries)| {
        expected
            .iter()
            .find(|entry| entry.destination() == *destination)
            .map_or_else(
                || entries.is_empty(),
                |entry| entries.len() == 1 && entries.first() == Some(*entry),
            )
    }) && expected
        .iter()
        .all(|entry| observed.contains_key(&entry.destination()))
}

fn new_transaction_id() -> std::io::Result<RouteTransactionId> {
    let mut bytes = [0; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    RouteTransactionId::new(bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

const fn layout_for_backend(backend: PhysicalRouteBackend) -> PlatformLayout {
    match backend {
        PhysicalRouteBackend::LinuxIpMain | PhysicalRouteBackend::LinuxPolicyV1 => {
            PlatformLayout::Linux
        }
        PhysicalRouteBackend::MacOsRouteTable | PhysicalRouteBackend::MacOsScopedV1 => {
            PlatformLayout::MacOs
        }
    }
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
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::vortix_core::control::AuthorityEpoch;
    use crate::vortix_core::ports::owned_routes::{
        OwnedRouteError, RouteEntry, RouteMutationError,
    };
    use crate::vortix_core::privileged::{
        NetworkPolicyOperation, ObservationState, OpenVpnDefaultGateways, OpenVpnRedirectFlag,
        OpenVpnRedirectGateway, OpenVpnRoute, OpenVpnRouteDefaults, PolicyPhase, PolicyPredecessor,
        PrivilegedFirewallRole, ResourceKind, ResourceTag,
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
        fn backend(&self) -> crate::vortix_core::privileged::PhysicalRouteBackend {
            crate::vortix_core::privileged::PhysicalRouteBackend::LinuxIpMain
        }

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

        fn exact_route_entries_batch(
            &mut self,
            _destinations: &[Cidr],
        ) -> Result<Vec<Vec<RouteEntry>>, OwnedRouteError> {
            Err(OwnedRouteError::Unknown)
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
                redirects: Vec::new(),
                tunnels: subjects,
            },
            observations,
        )
    }

    fn with_policy_generation(projection: PolicyProjection, generation: u64) -> PolicyProjection {
        let PolicyProjection::Routes {
            routes,
            redirects,
            tunnels,
            ..
        } = projection
        else {
            unreachable!();
        };
        PolicyProjection::Routes {
            policy: ResourceTag::topology(AuthorityEpoch(3), generation, ResourceKind::Routes)
                .unwrap(),
            routes,
            redirects,
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
            redirects,
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
            redirects,
            tunnels,
        }
    }

    fn with_tunnel_profile(projection: PolicyProjection, profile_seed: usize) -> PolicyProjection {
        let PolicyProjection::Routes {
            policy,
            routes,
            redirects,
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
            redirects,
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
                retained_state: ObservationState::Present,
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

    #[derive(Default)]
    struct MutationState {
        exact: HashMap<Cidr, Vec<RouteEntry>>,
        calls: Vec<(&'static str, Cidr)>,
        policy_steps: Vec<&'static str>,
        bypass_targets: std::collections::BTreeSet<IpAddr>,
        resolved_bypass: HashMap<IpAddr, RouteEntry>,
        resolved_net_gateway: HashMap<Cidr, RouteEntry>,
        domain_active: bool,
        fail_add: Option<Cidr>,
        fail_remove: Option<Cidr>,
        fail_activate: bool,
    }

    #[derive(Clone)]
    struct MutationRoutes {
        state: Arc<Mutex<MutationState>>,
        backend: PhysicalRouteBackend,
    }

    impl MutationRoutes {
        fn linux(state: Arc<Mutex<MutationState>>) -> Self {
            Self {
                state,
                backend: PhysicalRouteBackend::LinuxPolicyV1,
            }
        }

        fn macos(state: Arc<Mutex<MutationState>>) -> Self {
            Self {
                state,
                backend: PhysicalRouteBackend::MacOsScopedV1,
            }
        }
    }

    impl OwnedRoutes for MutationRoutes {
        fn backend(&self) -> crate::vortix_core::privileged::PhysicalRouteBackend {
            self.backend
        }

        fn route_interface_for(&mut self, _target: IpAddr) -> Result<String, OwnedRouteError> {
            Err(OwnedRouteError::Unknown)
        }

        fn exact_route_interfaces(
            &mut self,
            destination: Cidr,
        ) -> Result<Vec<String>, OwnedRouteError> {
            Ok(self
                .state
                .lock()
                .unwrap()
                .exact
                .get(&destination)
                .into_iter()
                .flatten()
                .map(|route| route.interface().to_owned())
                .collect())
        }

        fn exact_route_entries(
            &mut self,
            destination: Cidr,
        ) -> Result<Vec<RouteEntry>, OwnedRouteError> {
            Ok(self
                .state
                .lock()
                .unwrap()
                .exact
                .get(&destination)
                .cloned()
                .unwrap_or_default())
        }

        fn exact_route_entries_batch(
            &mut self,
            destinations: &[Cidr],
        ) -> Result<Vec<Vec<RouteEntry>>, OwnedRouteError> {
            let state = self.state.lock().unwrap();
            Ok(destinations
                .iter()
                .map(|destination| state.exact.get(destination).cloned().unwrap_or_default())
                .collect())
        }

        fn add_route(&mut self, route: &RouteEntry) -> Result<(), RouteMutationError> {
            let mut state = self.state.lock().unwrap();
            state.calls.push(("add", route.destination()));
            state.policy_steps.push("add_route");
            if state.fail_add == Some(route.destination()) {
                return Err(RouteMutationError::FailedBeforeEffect);
            }
            state
                .exact
                .entry(route.destination())
                .or_default()
                .push(route.clone());
            Ok(())
        }

        fn remove_route(&mut self, route: &RouteEntry) -> Result<(), RouteMutationError> {
            let mut state = self.state.lock().unwrap();
            state.calls.push(("remove", route.destination()));
            state.policy_steps.push("remove_route");
            if state.fail_remove == Some(route.destination()) {
                return Err(RouteMutationError::EffectMayHaveApplied);
            }
            state.exact.remove(&route.destination());
            Ok(())
        }

        fn exact_transport_bypass_targets(&mut self) -> Result<Vec<IpAddr>, OwnedRouteError> {
            Ok(self
                .state
                .lock()
                .unwrap()
                .bypass_targets
                .iter()
                .copied()
                .collect())
        }

        fn add_transport_bypass(&mut self, target: IpAddr) -> Result<(), RouteMutationError> {
            let mut state = self.state.lock().unwrap();
            state.policy_steps.push("add_bypass");
            state.bypass_targets.insert(target);
            Ok(())
        }

        fn remove_transport_bypass(&mut self, target: IpAddr) -> Result<(), RouteMutationError> {
            let mut state = self.state.lock().unwrap();
            state.policy_steps.push("remove_bypass");
            state.bypass_targets.remove(&target);
            Ok(())
        }

        fn route_domain_active(&mut self) -> Result<bool, OwnedRouteError> {
            Ok(self.state.lock().unwrap().domain_active)
        }

        fn activate_route_domain(&mut self) -> Result<(), RouteMutationError> {
            let mut state = self.state.lock().unwrap();
            if state.fail_activate {
                return Err(RouteMutationError::FailedBeforeEffect);
            }
            state.policy_steps.push("activate_domain");
            state.domain_active = true;
            Ok(())
        }

        fn deactivate_route_domain(&mut self) -> Result<(), RouteMutationError> {
            let mut state = self.state.lock().unwrap();
            state.policy_steps.push("deactivate_domain");
            state.domain_active = false;
            Ok(())
        }

        fn resolve_transport_bypass(
            &mut self,
            target: IpAddr,
        ) -> Result<RouteEntry, OwnedRouteError> {
            self.state
                .lock()
                .unwrap()
                .resolved_bypass
                .get(&target)
                .cloned()
                .ok_or(OwnedRouteError::Unknown)
        }

        fn resolve_net_gateway(
            &mut self,
            destination: Cidr,
        ) -> Result<RouteEntry, OwnedRouteError> {
            self.state
                .lock()
                .unwrap()
                .resolved_net_gateway
                .get(&destination)
                .cloned()
                .ok_or(OwnedRouteError::Unknown)
        }
    }

    fn route_entry(destination: &str) -> RouteEntry {
        RouteEntry::new(destination.parse().unwrap(), "vxroute0".into(), None, None).unwrap()
    }

    fn test_interface_name(
        layout: PlatformLayout,
        lease_id: LeaseId,
        tunnel: &ResourceTag,
    ) -> Result<String, ()> {
        if layout == PlatformLayout::MacOs {
            Ok("utun7".into())
        } else {
            authority_interface_name(layout, lease_id, tunnel)
        }
    }

    #[test]
    fn fixed_route_writer_applies_and_reads_back_the_complete_plan() {
        let state = Arc::new(Mutex::new(MutationState::default()));
        let platform = MutationRoutes::linux(Arc::clone(&state));
        let mut routes = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            LeaseId::new([21; 32]),
            platform,
        );
        let desired = vec![route_entry("10.0.0.0/8"), route_entry("192.168.0.0/16")];

        routes.install_owned_routes(&desired).unwrap();

        let state = state.lock().unwrap();
        assert_eq!(
            state.calls,
            vec![
                ("add", desired[0].destination()),
                ("add", desired[1].destination())
            ]
        );
        assert_eq!(
            state.exact.get(&desired[0].destination()),
            Some(&vec![desired[0].clone()])
        );
        assert_eq!(
            state.exact.get(&desired[1].destination()),
            Some(&vec![desired[1].clone()])
        );
    }

    #[test]
    fn canonical_wireguard_projection_prepares_then_applies_the_exact_physical_plan() {
        let lease_id = LeaseId::new([27; 32]);
        let (projection, _) = projection(lease_id, &[("10.0.0.0/8", "198.51.100.7", &[])]);
        let (scoped, redirects, _) = projection.route_inputs().unwrap();
        let operation = NetworkPolicyOperation::ApplyRoutes {
            policy: projection.policy().clone(),
            routes: scoped.to_vec(),
            redirects: redirects.to_vec(),
            predecessor: PolicyPredecessor::settled(projection.digest(), PolicyPhase::Blocking)
                .unwrap(),
        };
        let plan =
            NetworkPolicyExecutionPlan::mutation_for_test(operation, projection, None, Vec::new());
        let state = Arc::new(Mutex::new(MutationState::default()));
        let mut routes = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            lease_id,
            MutationRoutes::linux(Arc::clone(&state)),
        );

        let prepared = routes.prepare_owned(&plan).unwrap();
        assert_eq!(prepared.prepared_routes().len(), 1);
        assert_eq!(
            prepared.prepared_routes()[0].transport_bypass_targets(),
            &["198.51.100.7".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            prepared.prepared_routes()[0].stage(),
            PhysicalRouteStage::Prepared
        );
        let target = prepared.prepared_routes()[0]
            .clone()
            .mark_effect_pending()
            .unwrap();
        let effect = PreparedNetworkPolicyExecutionPlan::with_helper_owned_routes(
            plan,
            Vec::new(),
            Vec::new(),
            vec![target.clone()],
        );

        assert!(matches!(
            routes.execute_owned(&effect),
            Ok(NetworkPolicyOutcome::Applied)
        ));
        let state = state.lock().unwrap();
        assert_eq!(
            state.exact.get(&target.entries()[0].destination()),
            Some(&vec![target.entries()[0].clone()])
        );
        assert_eq!(
            state.bypass_targets,
            std::collections::BTreeSet::from(["198.51.100.7".parse().unwrap()])
        );
        assert!(state.domain_active);
    }

    #[test]
    fn macos_route_plan_persists_and_applies_the_resolved_endpoint_escape() {
        let lease_id = LeaseId::new([32; 32]);
        let endpoint = "198.51.100.7".parse::<IpAddr>().unwrap();
        let (projection, _) = projection(lease_id, &[("10.0.0.0/8", "198.51.100.7", &[])]);
        let (scoped, redirects, _) = projection.route_inputs().unwrap();
        let operation = NetworkPolicyOperation::ApplyRoutes {
            policy: projection.policy().clone(),
            routes: scoped.to_vec(),
            redirects: redirects.to_vec(),
            predecessor: PolicyPredecessor::settled(projection.digest(), PolicyPhase::Blocking)
                .unwrap(),
        };
        let plan =
            NetworkPolicyExecutionPlan::mutation_for_test(operation, projection, None, Vec::new());
        let bypass = RouteEntry::new(
            "198.51.100.7/32".parse().unwrap(),
            "en0".into(),
            Some("192.0.2.1".parse().unwrap()),
            None,
        )
        .unwrap();
        let state = Arc::new(Mutex::new(MutationState {
            resolved_bypass: HashMap::from([(endpoint, bypass.clone())]),
            ..MutationState::default()
        }));
        let mut routes = HelperRouteExecutor::with_platform_and_interfaces(
            PlatformLayout::MacOs,
            lease_id,
            MutationRoutes::macos(Arc::clone(&state)),
            test_interface_name,
        );

        let physical = routes
            .physical_plan(plan.intended(), plan.recovered_routes())
            .unwrap();
        assert_eq!(physical.transport_bypass_targets, vec![endpoint]);
        assert_eq!(physical.transport_bypass_entries, vec![bypass.clone()]);
        let prepared = routes.prepare_owned(&plan).unwrap();
        let target = prepared.prepared_routes()[0]
            .clone()
            .mark_effect_pending()
            .unwrap();
        assert_eq!(target.transport_bypass_targets(), &[endpoint]);
        assert_eq!(
            target.transport_bypass_entries(),
            std::slice::from_ref(&bypass)
        );
        let effect = PreparedNetworkPolicyExecutionPlan::with_helper_owned_routes(
            plan,
            Vec::new(),
            Vec::new(),
            vec![target.clone()],
        );

        assert!(routes.execute_owned(&effect).is_ok());
        let observed_state = state.lock().unwrap();
        assert_eq!(
            observed_state.exact.get(&bypass.destination()),
            Some(&vec![bypass.clone()])
        );
        assert_eq!(
            observed_state.exact.get(&target.entries()[0].destination()),
            Some(&vec![target.entries()[0].clone()])
        );
        assert!(!observed_state.domain_active);
        drop(observed_state);

        let intended = effect.execution().intended().clone();
        let owned = target.confirm_observed(&intended).unwrap();
        let recovered = RecoveredRouteState::with_physical(
            HelperResourceState::Owned,
            intended.clone(),
            Some(intended),
            owned,
        );
        routes
            .validate_recovered(std::slice::from_ref(&recovered), true)
            .unwrap();
        state.lock().unwrap().exact.insert(
            bypass.destination(),
            vec![RouteEntry::new(
                bypass.destination(),
                "en0".into(),
                Some("192.0.2.254".parse().unwrap()),
                None,
            )
            .unwrap()],
        );
        assert_eq!(
            routes.validate_recovered(&[recovered], true),
            Err(PrivilegedExecutionError::EffectMayHaveApplied)
        );
    }

    #[test]
    fn openvpn_route_plan_preserves_vpn_gateway_metric_and_def1_destinations() {
        let lease_id = LeaseId::new([33; 32]);
        let profile = ProfileId::parse(format!("{:064x}", 33)).unwrap();
        let tunnel = ResourceTag::tunnel(profile, 1).unwrap();
        let defaults = OpenVpnRouteDefaults::new(
            OpenVpnDefaultGateways::new(
                Some(OpenVpnDefaultGateway::Address("10.8.0.1".parse().unwrap())),
                None,
            )
            .unwrap(),
            Some(7),
        );
        let route = ScopedRoute::openvpn(
            OpenVpnRoute::with_gateway(
                "10.20.0.0/16".parse().unwrap(),
                OpenVpnRouteGateway::VpnDefault,
                None,
            )
            .unwrap(),
            tunnel.clone(),
            ScopedRouteOrigin::OpenVpnPushed,
            defaults,
        )
        .unwrap();
        let redirect = crate::vortix_core::privileged::ScopedOpenVpnRedirect::new(
            tunnel.clone(),
            OpenVpnRedirectGateway::new(vec![OpenVpnRedirectFlag::Def1]).unwrap(),
            ScopedRouteOrigin::OpenVpnPushed,
            defaults,
        )
        .unwrap();
        let subject = PrivilegedFirewallTunnel::new(
            tunnel,
            vec!["198.51.100.7".parse().unwrap()],
            vec!["10.20.0.0/16".parse().unwrap()],
            PrivilegedFirewallRole::Primary,
        )
        .unwrap();
        let projection = PolicyProjection::Routes {
            policy: ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Routes).unwrap(),
            routes: vec![route],
            redirects: vec![redirect],
            tunnels: vec![subject],
        };
        let (routes_payload, redirects_payload, _) = projection.route_inputs().unwrap();
        let operation = NetworkPolicyOperation::ApplyRoutes {
            policy: projection.policy().clone(),
            routes: routes_payload.to_vec(),
            redirects: redirects_payload.to_vec(),
            predecessor: PolicyPredecessor::settled(projection.digest(), PolicyPhase::Blocking)
                .unwrap(),
        };
        let plan =
            NetworkPolicyExecutionPlan::mutation_for_test(operation, projection, None, Vec::new());
        let state = Arc::new(Mutex::new(MutationState::default()));
        let mut executor = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            lease_id,
            MutationRoutes::linux(Arc::clone(&state)),
        );

        let prepared = executor.prepare_owned(&plan).unwrap();
        let entries = prepared.prepared_routes()[0].entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].destination(), "10.20.0.0/16".parse().unwrap());
        assert_eq!(entries[0].gateway(), Some("10.8.0.1".parse().unwrap()));
        assert_eq!(entries[0].metric(), Some(7));
        assert_eq!(entries[1].destination(), "0.0.0.0/1".parse().unwrap());
        assert_eq!(entries[2].destination(), "128.0.0.0/1".parse().unwrap());
        let pending = prepared.prepared_routes()[0]
            .clone()
            .mark_effect_pending()
            .unwrap();
        let effect = PreparedNetworkPolicyExecutionPlan::with_helper_owned_routes(
            plan,
            Vec::new(),
            Vec::new(),
            vec![pending],
        );
        assert!(executor.execute_owned(&effect).is_ok());
        let state = state.lock().unwrap();
        assert_eq!(state.exact.len(), 3);
        assert_eq!(
            state.bypass_targets,
            BTreeSet::from(["198.51.100.7".parse().unwrap()])
        );
        assert!(state.domain_active);
    }

    #[test]
    fn openvpn_route_plan_resolves_net_gateway_from_pre_tunnel_kernel_truth() {
        let (lease_id, plan) = openvpn_route_execution_plan(
            OpenVpnRouteGateway::NetGateway,
            OpenVpnRouteDefaults::default(),
            Vec::new(),
        );
        let destination = "10.20.0.0/16".parse().unwrap();
        let state = Arc::new(Mutex::new(MutationState {
            resolved_net_gateway: HashMap::from([(
                destination,
                RouteEntry::new(
                    destination,
                    "en0".into(),
                    Some("192.0.2.1".parse().unwrap()),
                    None,
                )
                .unwrap(),
            )]),
            ..MutationState::default()
        }));
        let mut executor = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            lease_id,
            MutationRoutes::linux(Arc::clone(&state)),
        );

        let prepared = executor.prepare_owned(&plan).unwrap();
        assert_eq!(
            prepared.prepared_routes()[0].entries()[0].interface(),
            "en0"
        );
        assert_eq!(
            prepared.prepared_routes()[0].entries()[0].gateway(),
            Some("192.0.2.1".parse().unwrap())
        );
        assert!(state.lock().unwrap().policy_steps.is_empty());
    }

    #[test]
    fn openvpn_route_plan_uses_authenticated_selected_remote_host() {
        let (lease_id, plan) = openvpn_route_execution_plan(
            OpenVpnRouteGateway::RemoteHost,
            OpenVpnRouteDefaults::default(),
            Vec::new(),
        );
        let state = Arc::new(Mutex::new(MutationState::default()));
        let mut executor = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            lease_id,
            MutationRoutes::linux(Arc::clone(&state)),
        );

        let prepared = executor.prepare_owned(&plan).unwrap();
        let route = &prepared.prepared_routes()[0].entries()[0];
        assert!(!route.interface().is_empty());
        assert_eq!(route.gateway(), Some("198.51.100.7".parse().unwrap()));
        assert!(state.lock().unwrap().policy_steps.is_empty());
    }

    #[test]
    fn openvpn_route_plan_rejects_dhcp_gateway_and_unrepresented_redirect_exceptions() {
        let dhcp_defaults = OpenVpnRouteDefaults::new(
            OpenVpnDefaultGateways::new(Some(OpenVpnDefaultGateway::Dhcp), None).unwrap(),
            None,
        );
        let (lease_id, plan) = openvpn_route_execution_plan(
            OpenVpnRouteGateway::VpnDefault,
            dhcp_defaults,
            Vec::new(),
        );
        let state = Arc::new(Mutex::new(MutationState::default()));
        let mut executor = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            lease_id,
            MutationRoutes::linux(Arc::clone(&state)),
        );
        assert_eq!(
            executor.prepare_owned(&plan),
            Err(NetworkPolicyPreparationError::InvalidPlan)
        );
        assert!(state.lock().unwrap().policy_steps.is_empty());

        for flag in [
            OpenVpnRedirectFlag::BypassDhcp,
            OpenVpnRedirectFlag::BypassDns,
            OpenVpnRedirectFlag::BlockLocal,
        ] {
            let (lease_id, plan) = openvpn_route_execution_plan(
                OpenVpnRouteGateway::Address("10.8.0.1".parse().unwrap()),
                OpenVpnRouteDefaults::default(),
                vec![flag],
            );
            let state = Arc::new(Mutex::new(MutationState::default()));
            let mut executor = HelperRouteExecutor::with_platform(
                PlatformLayout::Linux,
                lease_id,
                MutationRoutes::linux(Arc::clone(&state)),
            );
            assert_eq!(
                executor.prepare_owned(&plan),
                Err(NetworkPolicyPreparationError::InvalidPlan)
            );
            assert!(state.lock().unwrap().policy_steps.is_empty());
        }
    }

    fn openvpn_route_execution_plan(
        gateway: OpenVpnRouteGateway,
        defaults: OpenVpnRouteDefaults,
        redirect_flags: Vec<OpenVpnRedirectFlag>,
    ) -> (LeaseId, NetworkPolicyExecutionPlan) {
        let lease_id = LeaseId::new([34; 32]);
        let profile = ProfileId::parse(format!("{:064x}", 34)).unwrap();
        let tunnel = ResourceTag::tunnel(profile, 1).unwrap();
        let semantic_route =
            OpenVpnRoute::with_gateway("10.20.0.0/16".parse().unwrap(), gateway, None).unwrap();
        let route = if gateway == OpenVpnRouteGateway::RemoteHost {
            ScopedRoute::openvpn_with_selected_remote(
                semantic_route,
                tunnel.clone(),
                ScopedRouteOrigin::OpenVpnPushed,
                defaults,
                "198.51.100.7".parse().unwrap(),
            )
        } else {
            ScopedRoute::openvpn(
                semantic_route,
                tunnel.clone(),
                ScopedRouteOrigin::OpenVpnPushed,
                defaults,
            )
        }
        .unwrap();
        let redirects = if redirect_flags.is_empty() {
            Vec::new()
        } else {
            vec![crate::vortix_core::privileged::ScopedOpenVpnRedirect::new(
                tunnel.clone(),
                OpenVpnRedirectGateway::new(redirect_flags).unwrap(),
                ScopedRouteOrigin::OpenVpnPushed,
                defaults,
            )
            .unwrap()]
        };
        let subject = PrivilegedFirewallTunnel::new(
            tunnel,
            vec!["198.51.100.7".parse().unwrap()],
            vec!["10.20.0.0/16".parse().unwrap()],
            PrivilegedFirewallRole::Primary,
        )
        .unwrap();
        let projection = PolicyProjection::Routes {
            policy: ResourceTag::topology(AuthorityEpoch(3), 1, ResourceKind::Routes).unwrap(),
            routes: vec![route],
            redirects,
            tunnels: vec![subject],
        };
        let (routes, redirects, _) = projection.route_inputs().unwrap();
        let operation = NetworkPolicyOperation::ApplyRoutes {
            policy: projection.policy().clone(),
            routes: routes.to_vec(),
            redirects: redirects.to_vec(),
            predecessor: PolicyPredecessor::settled(projection.digest(), PolicyPhase::Blocking)
                .unwrap(),
        };
        (
            lease_id,
            NetworkPolicyExecutionPlan::mutation_for_test(operation, projection, None, Vec::new()),
        )
    }

    #[test]
    fn linux_policy_teardown_disables_lookup_before_removing_routes_and_bypass() {
        let lease_id = LeaseId::new([31; 32]);
        let (prior_projection, _) = projection(lease_id, &[("10.0.0.0/8", "198.51.100.7", &[])]);
        let prior_entry = route_entry("10.0.0.0/8");
        let prior = HelperLedgerRoutes::prepared(
            prior_projection.policy().clone(),
            PhysicalRouteBackend::LinuxPolicyV1,
            RouteTransactionId::new([1; 32]).unwrap(),
            prior_projection.digest(),
            vec![prior_entry.clone()],
            vec!["198.51.100.7".parse().unwrap()],
            Vec::new(),
        )
        .unwrap()
        .mark_effect_pending()
        .unwrap()
        .confirm_observed(&prior_projection)
        .unwrap();
        let target_projection = PolicyProjection::Routes {
            policy: ResourceTag::topology(AuthorityEpoch(3), 2, ResourceKind::Routes).unwrap(),
            routes: Vec::new(),
            redirects: Vec::new(),
            tunnels: Vec::new(),
        };
        let target = HelperLedgerRoutes::prepared(
            target_projection.policy().clone(),
            PhysicalRouteBackend::LinuxPolicyV1,
            RouteTransactionId::new([2; 32]).unwrap(),
            target_projection.digest(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap()
        .mark_effect_pending()
        .unwrap();
        let state = Arc::new(Mutex::new(MutationState {
            exact: HashMap::from([(prior_entry.destination(), vec![prior_entry])]),
            bypass_targets: BTreeSet::from(["198.51.100.7".parse().unwrap()]),
            domain_active: true,
            ..MutationState::default()
        }));
        let mut routes = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            lease_id,
            MutationRoutes::linux(Arc::clone(&state)),
        );

        routes
            .replace_linux_policy_routes(Some(&prior), &target)
            .unwrap();

        let state = state.lock().unwrap();
        assert_eq!(
            state.policy_steps,
            ["deactivate_domain", "remove_route", "remove_bypass"]
        );
        assert!(state.exact.is_empty());
        assert!(state.bypass_targets.is_empty());
        assert!(!state.domain_active);
    }

    #[test]
    fn failed_linux_policy_route_effect_restores_routes_bypass_and_activation() {
        let lease_id = LeaseId::new([28; 32]);
        let (projection, _) = projection(lease_id, &[("10.0.0.0/8", "198.51.100.7", &[])]);
        let (scoped, redirects, _) = projection.route_inputs().unwrap();
        let operation = NetworkPolicyOperation::ApplyRoutes {
            policy: projection.policy().clone(),
            routes: scoped.to_vec(),
            redirects: redirects.to_vec(),
            predecessor: PolicyPredecessor::settled(projection.digest(), PolicyPhase::Blocking)
                .unwrap(),
        };
        let plan =
            NetworkPolicyExecutionPlan::mutation_for_test(operation, projection, None, Vec::new());
        let state = Arc::new(Mutex::new(MutationState::default()));
        let mut routes = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            lease_id,
            MutationRoutes::linux(Arc::clone(&state)),
        );
        let prepared = routes.prepare_owned(&plan).unwrap();
        let target = prepared.prepared_routes()[0]
            .clone()
            .mark_effect_pending()
            .unwrap();
        state.lock().unwrap().fail_add = Some(target.entries()[0].destination());
        let effect = PreparedNetworkPolicyExecutionPlan::with_helper_owned_routes(
            plan,
            Vec::new(),
            Vec::new(),
            vec![target],
        );

        assert!(matches!(
            routes.execute_owned(&effect),
            Err(PrivilegedExecutionError::FailedBeforeEffect)
        ));
        let state = state.lock().unwrap();
        assert!(state.exact.values().all(Vec::is_empty));
        assert!(state.bypass_targets.is_empty());
        assert!(!state.domain_active);
    }

    #[test]
    fn recovered_linux_policy_route_requires_exact_bypass_and_activation_truth() {
        let lease_id = LeaseId::new([30; 32]);
        let (projection, _) = projection(lease_id, &[("10.0.0.0/8", "198.51.100.7", &[])]);
        let (scoped, redirects, _) = projection.route_inputs().unwrap();
        let operation = NetworkPolicyOperation::ApplyRoutes {
            policy: projection.policy().clone(),
            routes: scoped.to_vec(),
            redirects: redirects.to_vec(),
            predecessor: PolicyPredecessor::settled(projection.digest(), PolicyPhase::Blocking)
                .unwrap(),
        };
        let plan = NetworkPolicyExecutionPlan::mutation_for_test(
            operation,
            projection.clone(),
            None,
            Vec::new(),
        );
        let state = Arc::new(Mutex::new(MutationState::default()));
        let mut routes = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            lease_id,
            MutationRoutes::linux(Arc::clone(&state)),
        );
        let prepared = routes.prepare_owned(&plan).unwrap();
        let pending = prepared.prepared_routes()[0]
            .clone()
            .mark_effect_pending()
            .unwrap();
        let effect = PreparedNetworkPolicyExecutionPlan::with_helper_owned_routes(
            plan,
            Vec::new(),
            Vec::new(),
            vec![pending.clone()],
        );
        routes.execute_owned(&effect).unwrap();
        let owned = pending.confirm_observed(&projection).unwrap();
        let recovered = RecoveredRouteState::with_physical(
            HelperResourceState::Owned,
            projection.clone(),
            Some(projection),
            owned,
        );

        routes
            .validate_recovered(std::slice::from_ref(&recovered), true)
            .unwrap();
        state.lock().unwrap().bypass_targets.clear();
        assert_eq!(
            routes.validate_recovered(&[recovered], true),
            Err(PrivilegedExecutionError::EffectMayHaveApplied)
        );
    }

    #[test]
    fn canonical_route_preparation_uses_the_helper_owned_writer_after_table_off_cutover() {
        let lease_id = LeaseId::new([29; 32]);
        let (projection, _) = projection(lease_id, &[("10.0.0.0/8", "198.51.100.7", &[])]);
        let (scoped, redirects, _) = projection.route_inputs().unwrap();
        let operation = NetworkPolicyOperation::ApplyRoutes {
            policy: projection.policy().clone(),
            routes: scoped.to_vec(),
            redirects: redirects.to_vec(),
            predecessor: PolicyPredecessor::settled(projection.digest(), PolicyPhase::Blocking)
                .unwrap(),
        };
        let plan =
            NetworkPolicyExecutionPlan::mutation_for_test(operation, projection, None, Vec::new());
        let mut routes = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            lease_id,
            MutationRoutes::linux(Arc::new(Mutex::new(MutationState::default()))),
        );

        let prepared = routes.prepare_owned(&plan).unwrap();

        assert_eq!(prepared.route_writer(), PreparedRouteWriter::HelperOwned);
        assert_eq!(prepared.prepared_routes().len(), 1);
    }

    #[test]
    fn legacy_protocol_route_backend_cannot_prepare_helper_ownership() {
        let lease_id = LeaseId::new([28; 32]);
        let (projection, decisions) = projection(lease_id, &[("10.0.0.0/8", "198.51.100.7", &[])]);
        let (scoped, redirects, _) = projection.route_inputs().unwrap();
        let operation = NetworkPolicyOperation::ApplyRoutes {
            policy: projection.policy().clone(),
            routes: scoped.to_vec(),
            redirects: redirects.to_vec(),
            predecessor: PolicyPredecessor::settled(projection.digest(), PolicyPhase::Blocking)
                .unwrap(),
        };
        let plan =
            NetworkPolicyExecutionPlan::mutation_for_test(operation, projection, None, Vec::new());
        let mut routes = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            lease_id,
            FakeRoutes::new(Arc::new(Mutex::new(decisions))),
        );

        assert_eq!(
            routes.prepare_owned(&plan),
            Err(NetworkPolicyPreparationError::InvalidPlan)
        );
    }

    #[test]
    fn fixed_route_writer_replaces_only_the_exact_prior_owned_plan() {
        let prior = route_entry("10.0.0.0/8");
        let desired = RouteEntry::new(prior.destination(), "vxroute1".into(), None, None).unwrap();
        let state = Arc::new(Mutex::new(MutationState {
            exact: HashMap::from([(prior.destination(), vec![prior.clone()])]),
            ..MutationState::default()
        }));
        let mut routes = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            LeaseId::new([25; 32]),
            MutationRoutes::linux(Arc::clone(&state)),
        );

        routes
            .replace_owned_routes(std::slice::from_ref(&prior), std::slice::from_ref(&desired))
            .unwrap();

        let state = state.lock().unwrap();
        assert_eq!(
            state.calls,
            vec![
                ("remove", prior.destination()),
                ("add", desired.destination())
            ]
        );
        assert_eq!(
            state.exact.get(&desired.destination()),
            Some(&vec![desired])
        );
    }

    #[test]
    fn failed_route_replacement_restores_the_exact_prior_plan() {
        let prior = route_entry("10.0.0.0/8");
        let desired = route_entry("192.168.0.0/16");
        let state = Arc::new(Mutex::new(MutationState {
            exact: HashMap::from([(prior.destination(), vec![prior.clone()])]),
            fail_add: Some(desired.destination()),
            ..MutationState::default()
        }));
        let mut routes = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            LeaseId::new([26; 32]),
            MutationRoutes::linux(Arc::clone(&state)),
        );

        assert_eq!(
            routes
                .replace_owned_routes(std::slice::from_ref(&prior), std::slice::from_ref(&desired)),
            Err(PrivilegedExecutionError::FailedBeforeEffect)
        );

        let state = state.lock().unwrap();
        assert_eq!(state.exact.get(&prior.destination()), Some(&vec![prior]));
        assert!(!state.exact.contains_key(&desired.destination()));
    }

    #[test]
    fn fixed_route_writer_rejects_existing_exact_route_before_effect() {
        let desired = route_entry("10.0.0.0/8");
        let foreign = RouteEntry::new(
            desired.destination(),
            "en0".into(),
            Some("192.0.2.1".parse().unwrap()),
            Some(20),
        )
        .unwrap();
        let state = Arc::new(Mutex::new(MutationState {
            exact: HashMap::from([(desired.destination(), vec![foreign])]),
            ..MutationState::default()
        }));
        let mut routes = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            LeaseId::new([22; 32]),
            MutationRoutes::linux(Arc::clone(&state)),
        );

        assert_eq!(
            routes.install_owned_routes(&[desired]),
            Err(PrivilegedExecutionError::FailedBeforeEffect)
        );
        assert!(state.lock().unwrap().calls.is_empty());
    }

    #[test]
    fn fixed_route_writer_rolls_back_in_reverse_after_partial_failure() {
        let first = route_entry("10.0.0.0/8");
        let second = route_entry("192.168.0.0/16");
        let state = Arc::new(Mutex::new(MutationState {
            fail_add: Some(second.destination()),
            ..MutationState::default()
        }));
        let mut routes = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            LeaseId::new([23; 32]),
            MutationRoutes::linux(Arc::clone(&state)),
        );

        assert_eq!(
            routes.install_owned_routes(&[first.clone(), second.clone()]),
            Err(PrivilegedExecutionError::FailedBeforeEffect)
        );
        let state = state.lock().unwrap();
        assert_eq!(
            state.calls,
            vec![
                ("add", first.destination()),
                ("add", second.destination()),
                ("remove", first.destination()),
            ]
        );
        assert!(state.exact.is_empty());
    }

    #[test]
    fn fixed_route_writer_reports_ambiguity_when_rollback_cannot_prove_absence() {
        let first = route_entry("10.0.0.0/8");
        let second = route_entry("192.168.0.0/16");
        let state = Arc::new(Mutex::new(MutationState {
            fail_add: Some(second.destination()),
            fail_remove: Some(first.destination()),
            ..MutationState::default()
        }));
        let mut routes = HelperRouteExecutor::with_platform(
            PlatformLayout::Linux,
            LeaseId::new([24; 32]),
            MutationRoutes::linux(Arc::clone(&state)),
        );

        assert_eq!(
            routes.install_owned_routes(&[first, second]),
            Err(PrivilegedExecutionError::EffectMayHaveApplied)
        );
    }
}
