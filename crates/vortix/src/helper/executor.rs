//! Production helper executor assembled one verified capability at a time.

#![allow(
    dead_code,
    reason = "the observation executor is activated after enrolled transport persistence"
)]

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::material::{StagedWireGuardRuntime, TunnelMaterialSet, WireGuardRuntimeStager};
use super::observe::SystemObservationExecutor;
use super::runtime::HelperRuntimeIdentity;
use super::server::{
    CleanupExecutor, NetworkPolicyExecutor, NetworkPolicyOutcome, ObservationError,
    ObservationExecutor, ObservationOutcome, PrivilegedExecutionError, TunnelLifecycleExecutor,
    TunnelStartOutcome,
};
use super::validate::PlatformLayout;
use crate::vortix_core::privileged::{
    LeaseId, NetworkPolicyOperation, ObservationState, ObservedChildIdentity, ProtocolPlan,
    ResourceObservation, ResourceObservationTarget, ResourceTag,
};
use crate::vortix_core::profile::ProtocolKind;
use crate::vortix_protocol_wireguard::execution::{
    run_wg_quick, WgQuickAction, WireGuardCommandError,
};

const WIREGUARD_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) struct ProductionHelperExecutor {
    observation: SystemObservationExecutor,
    layout: PlatformLayout,
    lease_id: LeaseId,
    wireguard: BTreeMap<ResourceTag, StagedWireGuardRuntime>,
}

impl ProductionHelperExecutor {
    pub(crate) fn observation_only(
        layout: PlatformLayout,
        lease_id: LeaseId,
    ) -> Result<Self, ObservationError> {
        Ok(Self {
            observation: SystemObservationExecutor::new(layout, lease_id)?,
            layout,
            lease_id,
            wireguard: BTreeMap::new(),
        })
    }

    fn observe_tunnel(
        &mut self,
        tunnel: &ResourceTag,
        protocol: ProtocolKind,
    ) -> Result<ResourceObservation, PrivilegedExecutionError> {
        let target = ResourceObservationTarget::new(tunnel.clone(), Some(protocol))
            .map_err(|_| PrivilegedExecutionError::InvalidPlan)?;
        let outcome = self
            .observation
            .observe(&[target])
            .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
        let (mut observations, children) = outcome.into_parts();
        if !children.is_empty() || observations.len() != 1 {
            return Err(PrivilegedExecutionError::EffectMayHaveApplied);
        }
        observations
            .pop()
            .ok_or(PrivilegedExecutionError::EffectMayHaveApplied)
    }

    fn wireguard_stager(
        &self,
        tunnel: &ResourceTag,
    ) -> Result<WireGuardRuntimeStager, PrivilegedExecutionError> {
        let runtime = HelperRuntimeIdentity::derive(self.layout, self.lease_id, tunnel)
            .map_err(|_| PrivilegedExecutionError::InvalidPlan)?;
        Ok(WireGuardRuntimeStager::root_owned(self.layout, &runtime))
    }

    fn settle_wireguard_start_failure(
        &mut self,
        tunnel: ResourceTag,
        mut runtime: StagedWireGuardRuntime,
        attempted_effect: bool,
    ) -> Result<TunnelStartOutcome, PrivilegedExecutionError> {
        if attempted_effect {
            let _ =
                verified_protocol_binary(self.layout, ProtocolKind::WireGuard).and_then(|binary| {
                    run_wg_quick(
                        &binary,
                        WgQuickAction::Down,
                        runtime.config_path(),
                        WIREGUARD_COMMAND_TIMEOUT,
                    )
                    .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)
                });
        }
        let observation = match self.observe_tunnel(&tunnel, ProtocolKind::WireGuard) {
            Ok(observation) => observation,
            Err(error) => {
                self.wireguard.insert(tunnel, runtime);
                return Err(error);
            }
        };
        if observation.state() == ObservationState::Absent && runtime.cleanup().is_ok() {
            Err(PrivilegedExecutionError::FailedBeforeEffect)
        } else {
            self.wireguard.insert(tunnel, runtime);
            Err(PrivilegedExecutionError::EffectMayHaveApplied)
        }
    }

    fn start_wireguard(
        &mut self,
        plan: &crate::vortix_core::privileged::WireGuardPlan,
        materials: Option<TunnelMaterialSet>,
    ) -> Result<TunnelStartOutcome, PrivilegedExecutionError> {
        let Some(TunnelMaterialSet::WireGuard(materials)) = materials else {
            return Err(PrivilegedExecutionError::InvalidPlan);
        };
        let tunnel = ResourceTag::tunnel(plan.profile_id().clone(), plan.generation())
            .map_err(|_| PrivilegedExecutionError::InvalidPlan)?;
        if self.wireguard.contains_key(&tunnel) {
            return Err(PrivilegedExecutionError::InvalidPlan);
        }
        let stager = self.wireguard_stager(&tunnel)?;
        let runtime = stager
            .stage(plan, materials)
            .map_err(|_| PrivilegedExecutionError::FailedBeforeEffect)?;
        let Ok(binary) = verified_protocol_binary(self.layout, ProtocolKind::WireGuard) else {
            return self.settle_wireguard_start_failure(tunnel, runtime, false);
        };
        if let Err(error) = run_wg_quick(
            &binary,
            WgQuickAction::Up,
            runtime.config_path(),
            WIREGUARD_COMMAND_TIMEOUT,
        ) {
            return self.settle_wireguard_start_failure(
                tunnel,
                runtime,
                !matches!(error, WireGuardCommandError::Spawn),
            );
        }
        let observation = match self.observe_tunnel(&tunnel, ProtocolKind::WireGuard) {
            Ok(observation) => observation,
            Err(error) => {
                self.wireguard.insert(tunnel, runtime);
                return Err(error);
            }
        };
        if observation.state() != ObservationState::Present {
            return self.settle_wireguard_start_failure(tunnel, runtime, true);
        }
        self.wireguard.insert(tunnel, runtime);
        Ok(TunnelStartOutcome::InterfaceApplied(observation))
    }

    fn stop_wireguard(
        &mut self,
        tunnel: &ResourceTag,
    ) -> Result<ResourceObservation, PrivilegedExecutionError> {
        let mut runtime = if let Some(runtime) = self.wireguard.remove(tunnel) {
            runtime
        } else {
            self.wireguard_stager(tunnel)?
                .recover()
                .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?
        };
        let binary = match verified_protocol_binary(self.layout, ProtocolKind::WireGuard) {
            Ok(binary) => binary,
            Err(error) => {
                self.wireguard.insert(tunnel.clone(), runtime);
                return Err(error);
            }
        };
        let _command = run_wg_quick(
            &binary,
            WgQuickAction::Down,
            runtime.config_path(),
            WIREGUARD_COMMAND_TIMEOUT,
        );
        let observation = match self.observe_tunnel(tunnel, ProtocolKind::WireGuard) {
            Ok(observation) => observation,
            Err(error) => {
                self.wireguard.insert(tunnel.clone(), runtime);
                return Err(error);
            }
        };
        if observation.state() == ObservationState::Absent {
            runtime
                .cleanup()
                .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
            Ok(observation)
        } else {
            self.wireguard.insert(tunnel.clone(), runtime);
            Err(PrivilegedExecutionError::EffectMayHaveApplied)
        }
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
        plan: &ProtocolPlan,
        materials: Option<TunnelMaterialSet>,
    ) -> Result<TunnelStartOutcome, PrivilegedExecutionError> {
        match plan {
            ProtocolPlan::WireGuard(plan) => self.start_wireguard(plan, materials),
            ProtocolPlan::OpenVpn(_) => Err(PrivilegedExecutionError::InvalidPlan),
        }
    }

    fn stop_tunnel(
        &mut self,
        tunnel: &ResourceTag,
        child: Option<&ObservedChildIdentity>,
    ) -> Result<ResourceObservation, PrivilegedExecutionError> {
        if child.is_some() {
            Err(PrivilegedExecutionError::InvalidPlan)
        } else {
            self.stop_wireguard(tunnel)
        }
    }

    fn contain_unclaimed(
        &mut self,
        _child: &ObservedChildIdentity,
    ) -> Result<(), PrivilegedExecutionError> {
        Err(PrivilegedExecutionError::FailedBeforeEffect)
    }
}

fn verified_protocol_binary(
    layout: PlatformLayout,
    protocol: ProtocolKind,
) -> Result<PathBuf, PrivilegedExecutionError> {
    let path = match (layout, protocol) {
        (PlatformLayout::Linux, ProtocolKind::WireGuard) => Path::new("/usr/bin/wg-quick"),
        (PlatformLayout::Linux, ProtocolKind::OpenVpn) => Path::new("/usr/sbin/openvpn"),
        (PlatformLayout::MacOs, _) => return Err(PrivilegedExecutionError::InvalidPlan),
    };
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| PrivilegedExecutionError::FailedBeforeEffect)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(PrivilegedExecutionError::FailedBeforeEffect);
    }
    Ok(path.to_owned())
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
