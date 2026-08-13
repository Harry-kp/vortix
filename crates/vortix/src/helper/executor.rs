//! Production helper executor assembled one verified capability at a time.

#![allow(
    dead_code,
    reason = "the observation executor is activated after enrolled transport persistence"
)]

use super::observe::SystemObservationExecutor;
use super::server::{
    CleanupExecutor, NetworkPolicyExecutor, NetworkPolicyOutcome, ObservationError,
    ObservationExecutor, ObservationOutcome, PrivilegedExecutionError, TunnelLifecycleExecutor,
    TunnelStartOutcome,
};
use super::validate::PlatformLayout;
use crate::vortix_core::privileged::{
    LeaseId, NetworkPolicyOperation, ObservedChildIdentity, ProtocolPlan, ResourceObservation,
    ResourceObservationTarget, ResourceTag,
};

pub(crate) struct ProductionHelperExecutor {
    observation: SystemObservationExecutor,
}

impl ProductionHelperExecutor {
    pub(crate) fn observation_only(
        layout: PlatformLayout,
        lease_id: LeaseId,
    ) -> Result<Self, ObservationError> {
        Ok(Self {
            observation: SystemObservationExecutor::new(layout, lease_id)?,
        })
    }
}

impl ObservationExecutor for ProductionHelperExecutor {
    fn observe(
        &mut self,
        targets: &[ResourceObservationTarget],
    ) -> Result<ObservationOutcome, ObservationError> {
        self.observation.observe(targets)
    }
}

impl TunnelLifecycleExecutor for ProductionHelperExecutor {
    fn start_tunnel(
        &mut self,
        _plan: &ProtocolPlan,
    ) -> Result<TunnelStartOutcome, PrivilegedExecutionError> {
        Err(PrivilegedExecutionError::InvalidPlan)
    }

    fn stop_tunnel(
        &mut self,
        _tunnel: &ResourceTag,
        _child: Option<&ObservedChildIdentity>,
    ) -> Result<ResourceObservation, PrivilegedExecutionError> {
        Err(PrivilegedExecutionError::InvalidPlan)
    }

    fn contain_unclaimed(
        &mut self,
        _child: &ObservedChildIdentity,
    ) -> Result<(), PrivilegedExecutionError> {
        Err(PrivilegedExecutionError::FailedBeforeEffect)
    }
}

impl NetworkPolicyExecutor for ProductionHelperExecutor {
    fn execute_network_policy(
        &mut self,
        _operation: &NetworkPolicyOperation,
    ) -> Result<NetworkPolicyOutcome, PrivilegedExecutionError> {
        Err(PrivilegedExecutionError::InvalidPlan)
    }
}

impl CleanupExecutor for ProductionHelperExecutor {
    fn cleanup_owned(
        &mut self,
        _resources: &[ResourceTag],
        _children: &[ObservedChildIdentity],
    ) -> Result<Vec<ResourceObservation>, PrivilegedExecutionError> {
        Err(PrivilegedExecutionError::InvalidPlan)
    }
}
