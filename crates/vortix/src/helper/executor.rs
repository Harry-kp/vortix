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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::child_evidence::{AttestedChildState, ChildEvidenceError, ChildEvidenceStore};
use super::firewall::HelperFirewallExecutor;
use super::material::{
    OpenVpnRuntimeStager, StagedOpenVpnRuntime, StagedWireGuardRuntime, TunnelMaterialSet,
    WireGuardRuntimeStager,
};
use super::observe::SystemObservationExecutor;
use super::runtime::HelperRuntimeIdentity;
use super::server::{
    process_group_for_tunnel, tunnel_for_profile_resource, CleanupExecutor,
    NetworkPolicyExecutionPlan, NetworkPolicyExecutor, NetworkPolicyOutcome,
    NetworkPolicyPreparationError, ObservationError, ObservationExecutor, ObservationOutcome,
    PreparedNetworkPolicyExecutionPlan, PrivilegedExecutionError, RecoveredFirewallState,
    TunnelLifecycleExecutor, TunnelStartOutcome,
};
use super::validate::PlatformLayout;
use crate::vortix_core::openvpn_credentials::DecodedOpenVpnCredentials;
use crate::vortix_core::privileged::{
    LeaseId, ObservationState, ObservedChildIdentity, OpenVpnChallengeKind, ProtocolPlan,
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
const OPENVPN_MANAGEMENT_SOCKET_TIMEOUT: Duration = Duration::from_secs(5);
const OPENVPN_AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(30);
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
    firewall: HelperFirewallExecutor,
    wireguard: BTreeMap<ResourceTag, StagedWireGuardRuntime>,
    openvpn: BTreeMap<ResourceTag, ActiveOpenVpnRuntime>,
}

struct ActiveOpenVpnRuntime {
    child: Child,
    identity: ObservedChildIdentity,
    runtime: StagedOpenVpnRuntime,
    evidence: ChildEvidenceStore,
}

struct OpenVpnStopOutcome {
    tunnel: ResourceObservation,
    process_group: ResourceObservation,
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
            firewall: HelperFirewallExecutor::new(lease_id),
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
        let initial = self.observe_tunnel(tunnel, ProtocolKind::WireGuard)?;
        let mut runtime = self.wireguard.remove(tunnel);
        if initial.state() == ObservationState::Absent {
            if runtime.is_none() {
                runtime = self
                    .wireguard_stager(tunnel)?
                    .recover_for_cleanup_if_present()
                    .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
            }
            if let Some(mut runtime) = runtime {
                if runtime.cleanup().is_err() {
                    self.wireguard.insert(tunnel.clone(), runtime);
                    return Err(PrivilegedExecutionError::EffectMayHaveApplied);
                }
            }
            return Ok(initial);
        }
        if initial.state() != ObservationState::Present {
            if let Some(runtime) = runtime {
                self.wireguard.insert(tunnel.clone(), runtime);
            }
            return Err(PrivilegedExecutionError::EffectMayHaveApplied);
        }
        let mut runtime = match runtime {
            Some(runtime) => runtime,
            None => self
                .wireguard_stager(tunnel)?
                .recover_for_cleanup_if_present()
                .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?
                .ok_or(PrivilegedExecutionError::EffectMayHaveApplied)?,
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
        if plan.authentication().challenge() == Some(OpenVpnChallengeKind::Remote) {
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
        let staged = OpenVpnRuntimeStager::root_owned(self.layout, &helper_identity)
            .stage(plan, materials)
            .map_err(|_| PrivilegedExecutionError::FailedBeforeEffect)?;
        let (mut runtime, credentials) = staged.into_parts();
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
            return self.settle_openvpn_persistence_failure(
                tunnel,
                ActiveOpenVpnRuntime {
                    child,
                    identity: child_identity,
                    runtime,
                    evidence,
                },
            );
        }
        if let Some(credentials) = credentials {
            if authenticate_helper_openvpn(
                &mut child,
                &runtime,
                credentials,
                plan.authentication().challenge(),
            )
            .is_err()
            {
                return self.settle_openvpn_auth_failure(
                    tunnel,
                    ActiveOpenVpnRuntime {
                        child,
                        identity: child_identity,
                        runtime,
                        evidence,
                    },
                );
            }
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

    fn settle_openvpn_persistence_failure(
        &mut self,
        tunnel: ResourceTag,
        mut active: ActiveOpenVpnRuntime,
    ) -> Result<TunnelStartOutcome, PrivilegedExecutionError> {
        if matches!(active.evidence.load_attested(), Ok(actual) if actual == active.identity)
            || terminate_helper_foreground(&mut active.child, OPENVPN_TERMINATION_TIMEOUT).is_err()
        {
            self.openvpn.insert(tunnel, active);
            return Err(PrivilegedExecutionError::EffectMayHaveApplied);
        }
        Err(if active.runtime.cleanup_after_child().is_ok() {
            PrivilegedExecutionError::FailedBeforeEffect
        } else {
            PrivilegedExecutionError::EffectMayHaveApplied
        })
    }

    fn settle_openvpn_auth_failure(
        &mut self,
        tunnel: ResourceTag,
        mut active: ActiveOpenVpnRuntime,
    ) -> Result<TunnelStartOutcome, PrivilegedExecutionError> {
        if terminate_helper_foreground(&mut active.child, OPENVPN_TERMINATION_TIMEOUT).is_err() {
            self.openvpn.insert(tunnel, active);
            return Err(PrivilegedExecutionError::EffectMayHaveApplied);
        }
        let removed = active.evidence.remove(&active.identity);
        let cleaned = active.runtime.cleanup_after_child();
        Err(if removed.is_ok() && cleaned.is_ok() {
            PrivilegedExecutionError::FailedBeforeEffect
        } else {
            PrivilegedExecutionError::EffectMayHaveApplied
        })
    }

    fn stop_openvpn(
        &mut self,
        tunnel: &ResourceTag,
        expected: &ObservedChildIdentity,
    ) -> Result<ResourceObservation, PrivilegedExecutionError> {
        self.stop_openvpn_owned(tunnel, expected)
            .map(|outcome| outcome.tunnel)
    }

    fn stop_openvpn_owned(
        &mut self,
        tunnel: &ResourceTag,
        expected: &ObservedChildIdentity,
    ) -> Result<OpenVpnStopOutcome, PrivilegedExecutionError> {
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
    ) -> Result<OpenVpnStopOutcome, PrivilegedExecutionError> {
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
        let process_group = match force_process_group_absence(&active.evidence, expected) {
            Ok(observation) => observation,
            Err(error) => {
                self.openvpn.insert(tunnel.clone(), active);
                return Err(error);
            }
        };
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
        Ok(OpenVpnStopOutcome {
            tunnel: observation,
            process_group,
        })
    }

    fn stop_recovered_openvpn(
        &mut self,
        tunnel: &ResourceTag,
        expected: &ObservedChildIdentity,
    ) -> Result<OpenVpnStopOutcome, PrivilegedExecutionError> {
        let runtime_identity = HelperRuntimeIdentity::derive(self.layout, self.lease_id, tunnel)
            .map_err(|_| PrivilegedExecutionError::InvalidPlan)?;
        let evidence = ChildEvidenceStore::root_owned(self.layout, &runtime_identity);
        let mut runtime = OpenVpnRuntimeStager::root_owned(self.layout, &runtime_identity)
            .recover_for_cleanup_if_present()
            .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
        let evidence_present = match evidence.load_attested() {
            Ok(identity) if &identity == expected => true,
            Err(ChildEvidenceError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                false
            }
            Ok(_) | Err(_) => return Err(PrivilegedExecutionError::EffectMayHaveApplied),
        };
        if evidence_present {
            if runtime.is_none() {
                return Err(PrivilegedExecutionError::EffectMayHaveApplied);
            }
            match evidence.classify_attested(expected) {
                Ok(AttestedChildState::Live) => {
                    terminate_recovered_openvpn(&evidence, expected)?;
                }
                Ok(AttestedChildState::Exited) => {}
                Ok(AttestedChildState::Drifted) | Err(_) => {
                    return Err(PrivilegedExecutionError::EffectMayHaveApplied);
                }
            }
        }
        let process_group = if evidence_present {
            force_process_group_absence(&evidence, expected)?
        } else {
            wait_for_process_group_absence(expected)?
        };
        let observation = self.wait_for_openvpn_absence(tunnel)?;
        if let Some(runtime) = runtime.as_mut() {
            runtime
                .cleanup_payload_after_child()
                .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
        }
        if evidence_present {
            evidence
                .remove(expected)
                .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
        }
        if let Some(runtime) = runtime {
            runtime
                .finish_cleanup()
                .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
        }
        Ok(OpenVpnStopOutcome {
            tunnel: observation,
            process_group,
        })
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

fn authenticate_helper_openvpn(
    child: &mut Child,
    runtime: &StagedOpenVpnRuntime,
    credentials: DecodedOpenVpnCredentials,
    challenge: Option<OpenVpnChallengeKind>,
) -> Result<(), ()> {
    let deadline = Instant::now() + OPENVPN_MANAGEMENT_SOCKET_TIMEOUT;
    let mut backoff = PollBackoff::new();
    let stream = loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return Err(()),
            Ok(None) => {}
        }
        match runtime.try_connect_management() {
            Ok(Some(stream)) => break stream,
            Ok(None) if Instant::now() < deadline => backoff.pause(),
            Ok(None) | Err(_) => return Err(()),
        }
    };
    let (username, password, answer) = credentials.into_parts();
    crate::vortix_protocol_openvpn::management::authenticate(
        stream,
        username.as_str(),
        password.as_str(),
        &answer,
        challenge,
        OPENVPN_AUTHENTICATION_TIMEOUT,
    )
    .map_err(|_| ())
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
    if wait_for_attested_group_absence(
        evidence,
        identity,
        Instant::now() + OPENVPN_TERMINATION_TIMEOUT,
    )? {
        return Ok(());
    }
    signal_helper_process_group(identity.pid(), HelperGroupSignal::Kill)
        .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
    if wait_for_attested_group_absence(
        evidence,
        identity,
        Instant::now() + OPENVPN_TERMINATION_TIMEOUT,
    )? {
        Ok(())
    } else {
        Err(PrivilegedExecutionError::EffectMayHaveApplied)
    }
}

fn wait_for_attested_group_absence(
    evidence: &ChildEvidenceStore,
    identity: &ObservedChildIdentity,
    deadline: Instant,
) -> Result<bool, PrivilegedExecutionError> {
    let mut backoff = PollBackoff::new();
    loop {
        match evidence.classify_attested(identity) {
            Ok(AttestedChildState::Exited | AttestedChildState::Live) => {}
            Ok(AttestedChildState::Drifted) | Err(_) => {
                return Err(PrivilegedExecutionError::EffectMayHaveApplied);
            }
        }
        if !helper_process_group_has_live_members(identity.pid())? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        backoff.pause();
    }
}

fn wait_for_process_group_absence(
    identity: &ObservedChildIdentity,
) -> Result<ResourceObservation, PrivilegedExecutionError> {
    let deadline = Instant::now() + OPENVPN_TERMINATION_TIMEOUT;
    let mut backoff = PollBackoff::new();
    while helper_process_group_has_live_members(identity.pid())? {
        if Instant::now() >= deadline {
            return Err(PrivilegedExecutionError::EffectMayHaveApplied);
        }
        backoff.pause();
    }
    let resource = process_group_for_tunnel(identity.resource())
        .map_err(|()| PrivilegedExecutionError::InvalidPlan)?;
    let observed_at_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    ResourceObservation::new(
        resource,
        ObservationState::Absent,
        u64::try_from(observed_at_millis).unwrap_or(u64::MAX).max(1),
    )
    .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)
}

fn force_process_group_absence(
    evidence: &ChildEvidenceStore,
    identity: &ObservedChildIdentity,
) -> Result<ResourceObservation, PrivilegedExecutionError> {
    if helper_process_group_has_live_members(identity.pid())? {
        if matches!(
            evidence.classify_attested(identity),
            Ok(AttestedChildState::Drifted) | Err(_)
        ) {
            return Err(PrivilegedExecutionError::EffectMayHaveApplied);
        }
        signal_helper_process_group(identity.pid(), HelperGroupSignal::Kill)
            .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
    }
    wait_for_process_group_absence(identity)
}

fn helper_process_group_has_live_members(group_id: u32) -> Result<bool, PrivilegedExecutionError> {
    if let Some(has_live_members) = crate::platform::process_group_has_live_members(group_id)
        .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?
    {
        return Ok(has_live_members);
    }
    let pid =
        i32::try_from(group_id).map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
    // SAFETY: signal zero only probes the process-group namespace and does not
    // mutate the target group or access Rust memory.
    #[allow(unsafe_code)]
    let status = unsafe { libc::kill(-pid, 0) };
    if status == 0 {
        return Ok(true);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(PrivilegedExecutionError::EffectMayHaveApplied),
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
    fn validate_recovered_firewalls(
        &mut self,
        firewalls: &[RecoveredFirewallState],
        policy_enabled: bool,
    ) -> Result<(), PrivilegedExecutionError> {
        self.firewall.validate_recovered(firewalls, policy_enabled)
    }

    fn prepare_network_policy(
        &mut self,
        plan: &NetworkPolicyExecutionPlan,
    ) -> Result<PreparedNetworkPolicyExecutionPlan, NetworkPolicyPreparationError> {
        self.firewall.prepare(plan)
    }

    fn execute_network_policy(
        &mut self,
        plan: &PreparedNetworkPolicyExecutionPlan,
    ) -> Result<NetworkPolicyOutcome, PrivilegedExecutionError> {
        self.firewall.execute(plan)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CleanupAction {
    WireGuard(ResourceTag),
    OpenVpn {
        tunnel: ResourceTag,
        child: ObservedChildIdentity,
    },
}

fn plan_cleanup_actions(
    resources: &[ResourceTag],
    children: &[ObservedChildIdentity],
) -> Result<Vec<CleanupAction>, ()> {
    if resources.is_empty() {
        return Err(());
    }
    let resource_set = resources.iter().collect::<std::collections::BTreeSet<_>>();
    if resource_set.len() != resources.len()
        || resources.iter().any(|resource| {
            !matches!(
                resource.kind(),
                crate::vortix_core::privileged::ResourceKind::Tunnel
                    | crate::vortix_core::privileged::ResourceKind::ProcessGroup
            )
        })
    {
        return Err(());
    }
    let mut children_by_tunnel = BTreeMap::new();
    for child in children {
        if !resource_set.contains(child.resource())
            || children_by_tunnel.insert(child.resource(), child).is_some()
        {
            return Err(());
        }
        let group = process_group_for_tunnel(child.resource())?;
        if !resource_set.contains(&group) {
            return Err(());
        }
    }
    for resource in resources.iter().filter(|resource| {
        resource.kind() == crate::vortix_core::privileged::ResourceKind::ProcessGroup
    }) {
        let tunnel = tunnel_for_profile_resource(resource).ok_or(())?;
        if !children_by_tunnel.contains_key(&tunnel) || !resource_set.contains(&tunnel) {
            return Err(());
        }
    }
    resources
        .iter()
        .filter(|resource| resource.kind() == crate::vortix_core::privileged::ResourceKind::Tunnel)
        .map(|tunnel| match children_by_tunnel.remove(tunnel) {
            Some(child) => Ok(CleanupAction::OpenVpn {
                tunnel: tunnel.clone(),
                child: child.clone(),
            }),
            None => Ok(CleanupAction::WireGuard(tunnel.clone())),
        })
        .collect()
}

impl CleanupExecutor for ProductionHelperExecutor {
    fn cleanup_owned(
        &mut self,
        resources: &[ResourceTag],
        children: &[ObservedChildIdentity],
    ) -> Result<Vec<ResourceObservation>, PrivilegedExecutionError> {
        let actions = plan_cleanup_actions(resources, children)
            .map_err(|()| PrivilegedExecutionError::InvalidPlan)?;
        let mut observations = BTreeMap::new();
        for action in actions {
            match action {
                CleanupAction::WireGuard(tunnel) => {
                    let observation = self
                        .stop_wireguard(&tunnel)
                        .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
                    observations.insert(tunnel, observation);
                }
                CleanupAction::OpenVpn { tunnel, child } => {
                    let process_group = process_group_for_tunnel(&tunnel)
                        .map_err(|()| PrivilegedExecutionError::InvalidPlan)?;
                    let outcome = self
                        .stop_openvpn_owned(&tunnel, &child)
                        .map_err(|_| PrivilegedExecutionError::EffectMayHaveApplied)?;
                    if outcome.process_group.resource() != &process_group
                        || outcome.process_group.state() != ObservationState::Absent
                    {
                        return Err(PrivilegedExecutionError::EffectMayHaveApplied);
                    }
                    observations.insert(tunnel, outcome.tunnel);
                    observations.insert(process_group, outcome.process_group);
                }
            }
        }
        resources
            .iter()
            .map(|resource| {
                observations
                    .remove(resource)
                    .filter(|observation| observation.state() == ObservationState::Absent)
                    .ok_or(PrivilegedExecutionError::EffectMayHaveApplied)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::CommandExt as _;
    use std::process::Command;

    use crate::vortix_core::privileged::{
        ContainmentId, ObservedChildIdentity, ResourceKind, ResourceTag,
    };
    use crate::vortix_core::profile::ProfileId;

    use super::{
        helper_process_group_has_live_members, plan_cleanup_actions, CleanupAction,
        HelperGroupSignal,
    };

    fn tunnel(byte: char, generation: u64) -> ResourceTag {
        ResourceTag::tunnel(
            ProfileId::parse(byte.to_string().repeat(ProfileId::HEX_LEN)).unwrap(),
            generation,
        )
        .unwrap()
    }

    fn group(tunnel: &ResourceTag) -> ResourceTag {
        ResourceTag::profile(
            tunnel.profile_id().unwrap().clone(),
            tunnel.generation(),
            ResourceKind::ProcessGroup,
        )
        .unwrap()
    }

    fn child(tunnel: &ResourceTag) -> ObservedChildIdentity {
        ObservedChildIdentity::new(tunnel.clone(), 42, 7, ContainmentId::new([9; 32])).unwrap()
    }

    #[test]
    fn cleanup_plan_requires_closed_exact_child_topology_before_mutation() {
        let wireguard = tunnel('a', 3);
        let openvpn = tunnel('b', 4);
        let openvpn_group = group(&openvpn);
        let openvpn_child = child(&openvpn);

        let actions = plan_cleanup_actions(
            &[wireguard.clone(), openvpn.clone(), openvpn_group.clone()],
            std::slice::from_ref(&openvpn_child),
        )
        .unwrap();
        assert!(matches!(
            actions.as_slice(),
            [CleanupAction::WireGuard(actual), CleanupAction::OpenVpn {
                tunnel: actual_tunnel,
                child: actual_child,
            }] if actual == &wireguard
                && actual_tunnel == &openvpn
                && actual_child == &openvpn_child
        ));

        assert!(plan_cleanup_actions(
            std::slice::from_ref(&openvpn),
            std::slice::from_ref(&openvpn_child)
        )
        .is_err());
        assert!(plan_cleanup_actions(&[openvpn_group], &[openvpn_child]).is_err());
        assert!(plan_cleanup_actions(&[wireguard, openvpn], &[]).is_ok());
    }

    #[test]
    fn process_group_probe_tracks_the_contained_group_not_only_its_leader() {
        let mut command = Command::new("/bin/sleep");
        command.arg("30").process_group(0);
        let mut child = command.spawn().unwrap();
        let group = child.id();
        assert!(helper_process_group_has_live_members(group).unwrap());

        super::signal_helper_process_group(group, HelperGroupSignal::Kill).unwrap();
        child.wait().unwrap();
        assert!(!helper_process_group_has_live_members(group).unwrap());
    }
}
