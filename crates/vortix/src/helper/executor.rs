//! Production helper executor assembled one verified capability at a time.

#![allow(
    dead_code,
    reason = "the observation executor is activated after enrolled transport persistence"
)]

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::thread;
use std::time::{Duration, Instant};

use super::child_evidence::{AttestedChildState, ChildEvidenceError, ChildEvidenceStore};
use super::material::{
    OpenVpnRuntimeStager, StagedOpenVpnRuntime, StagedWireGuardRuntime, TunnelMaterialSet,
    WireGuardRuntimeStager,
};
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
use crate::vortix_protocol_openvpn::execution::{
    signal_helper_process_group, spawn_helper_foreground, terminate_helper_foreground,
    HelperGroupSignal,
};
use crate::vortix_protocol_wireguard::execution::{
    run_wg_quick, WgQuickAction, WireGuardCommandError,
};

const WIREGUARD_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const OPENVPN_TERMINATION_TIMEOUT: Duration = Duration::from_secs(5);
const MIN_SETTLE_INTERVAL: Duration = Duration::from_millis(25);
const MAX_SETTLE_INTERVAL: Duration = Duration::from_millis(250);

struct PollBackoff {
    next: Duration,
}

impl PollBackoff {
    const fn new() -> Self {
        Self {
            next: MIN_SETTLE_INTERVAL,
        }
    }

    fn pause(&mut self) {
        thread::sleep(self.next);
        self.next = (self.next * 2).min(MAX_SETTLE_INTERVAL);
    }
}

pub(crate) struct ProductionHelperExecutor {
    observation: SystemObservationExecutor,
    layout: PlatformLayout,
    lease_id: LeaseId,
    wireguard: BTreeMap<ResourceTag, StagedWireGuardRuntime>,
    openvpn: BTreeMap<ResourceTag, ActiveOpenVpnRuntime>,
}

struct ActiveOpenVpnRuntime {
    child: Child,
    identity: ObservedChildIdentity,
    runtime: StagedOpenVpnRuntime,
    evidence: ChildEvidenceStore,
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
            openvpn: BTreeMap::new(),
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

    fn start_openvpn(
        &mut self,
        plan: &crate::vortix_core::privileged::OpenVpnPlan,
        materials: Option<TunnelMaterialSet>,
    ) -> Result<TunnelStartOutcome, PrivilegedExecutionError> {
        if plan.authentication().uses_username_password() {
            return Err(PrivilegedExecutionError::InvalidPlan);
        }
        let Some(TunnelMaterialSet::OpenVpn(materials)) = materials else {
            return Err(PrivilegedExecutionError::InvalidPlan);
        };
        let tunnel = ResourceTag::tunnel(plan.profile_id().clone(), plan.generation())
            .map_err(|_| PrivilegedExecutionError::InvalidPlan)?;
        if self.openvpn.contains_key(&tunnel) {
            return Err(PrivilegedExecutionError::InvalidPlan);
        }
        let helper_identity = HelperRuntimeIdentity::derive(self.layout, self.lease_id, &tunnel)
            .map_err(|_| PrivilegedExecutionError::InvalidPlan)?;
        let mut runtime = OpenVpnRuntimeStager::root_owned(self.layout, &helper_identity)
            .stage(plan, materials)
            .map_err(|_| PrivilegedExecutionError::FailedBeforeEffect)?;
        let binary = match verified_protocol_binary(self.layout, ProtocolKind::OpenVpn) {
            Ok(binary) => binary,
            Err(error) => {
                let _ = runtime.cleanup_after_child();
                return Err(error);
            }
        };
        let Ok(mut child) = spawn_helper_foreground(&binary, runtime.execution()) else {
            let _ = runtime.cleanup_after_child();
            return Err(PrivilegedExecutionError::FailedBeforeEffect);
        };
        let evidence = ChildEvidenceStore::root_owned(self.layout, &helper_identity);
        let Ok(child_identity) = evidence.attest_live(child.id()) else {
            return settle_unattested_openvpn(child, runtime);
        };
        if evidence.persist_attested(&child_identity).is_err() {
            if matches!(evidence.load_attested(), Ok(identity) if identity == child_identity) {
                self.openvpn.insert(
                    tunnel,
                    ActiveOpenVpnRuntime {
                        child,
                        identity: child_identity,
                        runtime,
                        evidence,
                    },
                );
                return Err(PrivilegedExecutionError::EffectMayHaveApplied);
            }
            let terminated = terminate_helper_foreground(&mut child, OPENVPN_TERMINATION_TIMEOUT);
            if terminated.is_err() {
                self.openvpn.insert(
                    tunnel,
                    ActiveOpenVpnRuntime {
                        child,
                        identity: child_identity,
                        runtime,
                        evidence,
                    },
                );
                return Err(PrivilegedExecutionError::EffectMayHaveApplied);
            }
            return Err(if runtime.cleanup_after_child().is_ok() {
                PrivilegedExecutionError::FailedBeforeEffect
            } else {
                PrivilegedExecutionError::EffectMayHaveApplied
            });
        }
        match child.try_wait() {
            Ok(Some(_)) => {
                let removed = evidence.remove(&child_identity);
                let cleaned = runtime.cleanup_after_child();
                return Err(if removed.is_ok() && cleaned.is_ok() {
                    PrivilegedExecutionError::FailedBeforeEffect
                } else {
                    PrivilegedExecutionError::EffectMayHaveApplied
                });
            }
            Err(_) => {
                self.openvpn.insert(
                    tunnel,
                    ActiveOpenVpnRuntime {
                        child,
                        identity: child_identity,
                        runtime,
                        evidence,
                    },
                );
                return Err(PrivilegedExecutionError::EffectMayHaveApplied);
            }
            Ok(None) => {}
        }
        self.openvpn.insert(
            tunnel,
            ActiveOpenVpnRuntime {
                child,
                identity: child_identity.clone(),
                runtime,
                evidence,
            },
        );
        Ok(TunnelStartOutcome::ForegroundOwned(child_identity))
    }

    fn stop_openvpn(
        &mut self,
        tunnel: &ResourceTag,
        expected: &ObservedChildIdentity,
    ) -> Result<ResourceObservation, PrivilegedExecutionError> {
        if expected.resource() != tunnel {
            return Err(PrivilegedExecutionError::InvalidPlan);
        }
        if let Some(active) = self.openvpn.remove(tunnel) {
            self.stop_active_openvpn(tunnel, expected, active)
        } else {
            self.stop_recovered_openvpn(tunnel, expected)
        }
    }

    fn stop_active_openvpn(
        &mut self,
        tunnel: &ResourceTag,
        expected: &ObservedChildIdentity,
        mut active: ActiveOpenVpnRuntime,
    ) -> Result<ResourceObservation, PrivilegedExecutionError> {
        if &active.identity != expected
            || !matches!(active.evidence.load_attested(), Ok(identity) if &identity == expected)
        {
            self.openvpn.insert(tunnel.clone(), active);
            return Err(PrivilegedExecutionError::EffectMayHaveApplied);
        }
        match active.evidence.classify_attested(expected) {
            Ok(AttestedChildState::Live) => {
                if terminate_helper_foreground(&mut active.child, OPENVPN_TERMINATION_TIMEOUT)
                    .is_err()
                {
                    self.openvpn.insert(tunnel.clone(), active);
                    return Err(PrivilegedExecutionError::EffectMayHaveApplied);
                }
            }
            Ok(AttestedChildState::Exited) => {
                if !matches!(active.child.try_wait(), Ok(Some(_))) {
                    self.openvpn.insert(tunnel.clone(), active);
                    return Err(PrivilegedExecutionError::EffectMayHaveApplied);
                }
            }
            Ok(AttestedChildState::Drifted) | Err(_) => {
                self.openvpn.insert(tunnel.clone(), active);
                return Err(PrivilegedExecutionError::EffectMayHaveApplied);
            }
        }
        if !matches!(
            active.evidence.classify_attested(expected),
            Ok(AttestedChildState::Exited)
        ) {
            self.openvpn.insert(tunnel.clone(), active);
            return Err(PrivilegedExecutionError::EffectMayHaveApplied);
        }
        let observation = match self.wait_for_openvpn_absence(tunnel) {
            Ok(observation) => observation,
            Err(error) => {
                self.openvpn.insert(tunnel.clone(), active);
                return Err(error);
            }
        };
        if active.runtime.cleanup_payload_after_child().is_err() {
            self.openvpn.insert(tunnel.clone(), active);
            return Err(PrivilegedExecutionError::EffectMayHaveApplied);
        }
        if active.evidence.remove(expected).is_err() {
            self.openvpn.insert(tunnel.clone(), active);
            return Err(PrivilegedExecutionError::EffectMayHaveApplied);
        }
        active
            .runtime
            .finish_cleanup()
            .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
        Ok(observation)
    }

    fn stop_recovered_openvpn(
        &mut self,
        tunnel: &ResourceTag,
        expected: &ObservedChildIdentity,
    ) -> Result<ResourceObservation, PrivilegedExecutionError> {
        let runtime_identity = HelperRuntimeIdentity::derive(self.layout, self.lease_id, tunnel)
            .map_err(|_| PrivilegedExecutionError::InvalidPlan)?;
        let evidence = ChildEvidenceStore::root_owned(self.layout, &runtime_identity);
        let mut runtime = OpenVpnRuntimeStager::root_owned(self.layout, &runtime_identity)
            .recover_for_cleanup()
            .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
        let evidence_present = match evidence.load_attested() {
            Ok(identity) if &identity == expected => true,
            Err(ChildEvidenceError::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound
                    && runtime.is_drained().is_ok_and(|drained| drained) =>
            {
                false
            }
            Ok(_) | Err(_) => return Err(PrivilegedExecutionError::EffectMayHaveApplied),
        };
        match evidence.classify_attested(expected) {
            Ok(AttestedChildState::Live) => {
                terminate_recovered_openvpn(&evidence, expected)?;
            }
            Ok(AttestedChildState::Exited) => {}
            Ok(AttestedChildState::Drifted) | Err(_) => {
                return Err(PrivilegedExecutionError::EffectMayHaveApplied);
            }
        }
        let observation = self.wait_for_openvpn_absence(tunnel)?;
        runtime
            .cleanup_payload_after_child()
            .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
        if evidence_present {
            evidence
                .remove(expected)
                .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
        }
        runtime
            .finish_cleanup()
            .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
        Ok(observation)
    }

    fn wait_for_openvpn_absence(
        &mut self,
        tunnel: &ResourceTag,
    ) -> Result<ResourceObservation, PrivilegedExecutionError> {
        let deadline = Instant::now() + OPENVPN_TERMINATION_TIMEOUT;
        let mut backoff = PollBackoff::new();
        let observation = loop {
            let observation = self.observe_tunnel(tunnel, ProtocolKind::OpenVpn)?;
            if observation.state() == ObservationState::Absent || Instant::now() >= deadline {
                break observation;
            }
            backoff.pause();
        };
        if observation.state() == ObservationState::Absent {
            Ok(observation)
        } else {
            Err(PrivilegedExecutionError::EffectMayHaveApplied)
        }
    }
}

fn settle_unattested_openvpn(
    mut child: Child,
    mut runtime: StagedOpenVpnRuntime,
) -> Result<TunnelStartOutcome, PrivilegedExecutionError> {
    let terminated = terminate_helper_foreground(&mut child, OPENVPN_TERMINATION_TIMEOUT);
    let cleaned = runtime.cleanup_after_child();
    Err(if terminated.is_ok() && cleaned.is_ok() {
        PrivilegedExecutionError::FailedBeforeEffect
    } else {
        PrivilegedExecutionError::EffectMayHaveApplied
    })
}

fn terminate_recovered_openvpn(
    evidence: &ChildEvidenceStore,
    identity: &ObservedChildIdentity,
) -> Result<(), PrivilegedExecutionError> {
    signal_helper_process_group(identity.pid(), HelperGroupSignal::Terminate)
        .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
    let graceful_deadline = Instant::now() + OPENVPN_TERMINATION_TIMEOUT;
    let mut backoff = PollBackoff::new();
    loop {
        match evidence.classify_attested(identity) {
            Ok(AttestedChildState::Exited) => return Ok(()),
            Ok(AttestedChildState::Drifted) | Err(_) => {
                return Err(PrivilegedExecutionError::EffectMayHaveApplied);
            }
            Ok(AttestedChildState::Live) if Instant::now() < graceful_deadline => {
                backoff.pause();
            }
            Ok(AttestedChildState::Live) => break,
        }
    }
    signal_helper_process_group(identity.pid(), HelperGroupSignal::Kill)
        .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
    let kill_deadline = Instant::now() + OPENVPN_TERMINATION_TIMEOUT;
    let mut backoff = PollBackoff::new();
    loop {
        match evidence.classify_attested(identity) {
            Ok(AttestedChildState::Exited) => return Ok(()),
            Ok(AttestedChildState::Live) if Instant::now() < kill_deadline => {
                backoff.pause();
            }
            Ok(AttestedChildState::Live | AttestedChildState::Drifted) | Err(_) => {
                return Err(PrivilegedExecutionError::EffectMayHaveApplied);
            }
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
            ProtocolPlan::OpenVpn(plan) => self.start_openvpn(plan, materials),
        }
    }

    fn stop_tunnel(
        &mut self,
        tunnel: &ResourceTag,
        child: Option<&ObservedChildIdentity>,
    ) -> Result<ResourceObservation, PrivilegedExecutionError> {
        match child {
            Some(child) => self.stop_openvpn(tunnel, child),
            None => self.stop_wireguard(tunnel),
        }
    }

    fn contain_unclaimed(
        &mut self,
        child: &ObservedChildIdentity,
    ) -> Result<(), PrivilegedExecutionError> {
        self.stop_openvpn(child.resource(), child).map(|_| ())
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
