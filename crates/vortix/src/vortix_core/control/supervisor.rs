//! Coordinator-facing bounded supervision facade.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::vortix_core::control::model::{
    AuthorityEpoch, OperationId, PolicyDigest, MAX_PROTECTION_AGE_MILLIS,
};
use crate::vortix_core::control::worker::{
    CancellationToken, ControlRevision, PolicyExecutor, PolicyOutcome, PolicyResult, PolicyWorker,
    ProfileAdmission, ProfileWorkerPool, TopologyPolicy, TopologyState, TunnelExecutor,
    TunnelMutation, TunnelWork, TunnelWorkResult, WorkFailure,
};
use crate::vortix_core::ports::tunnel::AdoptionEvidence;
use crate::vortix_core::profile::ProfileId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisedTruth {
    Reserved,
    WaitingForObservation,
    ObservedPresent,
    Degraded(WorkFailure),
    OutcomeUnknown,
    DisconnectedTombstone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSupervision {
    pub generation: u64,
    pub authority_epoch: AuthorityEpoch,
    pub policy_digest: PolicyDigest,
    pub operation_id: OperationId,
    pub mutation: TunnelMutation,
    pub adoption: Option<AdoptionEvidence>,
    pub truth: SupervisedTruth,
}

impl ProfileSupervision {
    #[must_use]
    pub fn revision(&self) -> ControlRevision {
        ControlRevision {
            authority_epoch: self.authority_epoch,
            generation: self.generation,
            digest: self.policy_digest.clone(),
        }
    }
}

/// Fresh platform evidence required before publishing protection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Explicit protection gates are an auditable bit-set.
pub struct PolicyVerification {
    pub revision: ControlRevision,
    pub operation_id: OperationId,
    pub observed_at_millis: u64,
    pub received_at_millis: u64,
    pub interface_verified: bool,
    pub route_verified: bool,
    pub dns_verified: bool,
    pub firewall_verified: bool,
}

impl PolicyVerification {
    #[must_use]
    pub fn is_complete_and_fresh(&self, now_millis: u64) -> bool {
        self.observed_at_millis <= now_millis
            && self.received_at_millis <= now_millis
            && now_millis.saturating_sub(self.observed_at_millis) <= MAX_PROTECTION_AGE_MILLIS
            && now_millis.saturating_sub(self.received_at_millis) <= MAX_PROTECTION_AGE_MILLIS
            && self.interface_verified
            && self.route_verified
            && self.dns_verified
            && self.firewall_verified
    }
}

#[derive(Debug)]
struct State {
    authority_epoch: AuthorityEpoch,
    latest_policy: Option<(ControlRevision, OperationId)>,
    latest_topology: Option<TopologyPolicy>,
    applied_policy: Option<(ControlRevision, OperationId)>,
    applied_topology: Option<TopologyState>,
    profiles: BTreeMap<ProfileId, ProfileSupervision>,
    tombstones: BTreeMap<ProfileId, ProfileSupervision>,
    policy_degraded: Option<WorkFailure>,
    protected: Option<(ControlRevision, OperationId, u64)>,
}

impl State {
    fn new(authority_epoch: AuthorityEpoch) -> Self {
        Self {
            authority_epoch,
            latest_policy: None,
            latest_topology: None,
            applied_policy: None,
            applied_topology: None,
            profiles: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            policy_degraded: None,
            protected: None,
        }
    }
}

pub struct Supervisor {
    tunnels: ProfileWorkerPool,
    policy: PolicyWorker,
    state: Mutex<State>,
}

impl Supervisor {
    #[must_use]
    pub fn new(
        authority_epoch: AuthorityEpoch,
        tunnel_executor: Arc<dyn TunnelExecutor>,
        policy_executor: Arc<dyn PolicyExecutor>,
        per_profile_capacity: usize,
        result_capacity: usize,
    ) -> Self {
        Self {
            tunnels: ProfileWorkerPool::with_limits(
                tunnel_executor,
                per_profile_capacity,
                result_capacity,
                result_capacity.max(1),
                Duration::from_secs(30),
            ),
            policy: PolicyWorker::start(policy_executor, result_capacity),
            state: Mutex::new(State::new(authority_epoch)),
        }
    }

    pub fn dispatch_tunnel(
        &self,
        work: TunnelWork,
        routes: impl IntoIterator<Item = String>,
    ) -> Result<CancellationToken, WorkFailure> {
        let mut state = self.state.lock().expect("supervisor mutex poisoned");
        if work.authority_epoch != state.authority_epoch {
            return Err(WorkFailure::Stale);
        }
        if let Some(entry) = state.profiles.get(&work.profile_id) {
            if matches!(
                entry.truth,
                SupervisedTruth::Reserved
                    | SupervisedTruth::OutcomeUnknown
                    | SupervisedTruth::DisconnectedTombstone
            ) {
                if entry.revision() != work.revision() {
                    self.tunnels.cancel_profile(&work.profile_id);
                }
                return Err(WorkFailure::Busy);
            }
            if entry.revision() == work.revision()
                && matches!(entry.truth, SupervisedTruth::WaitingForObservation)
            {
                return Err(WorkFailure::Busy);
            }
        }
        let profile_id = work.profile_id.clone();
        let entry = ProfileSupervision {
            generation: work.generation,
            authority_epoch: work.authority_epoch,
            policy_digest: work.policy_digest.clone(),
            operation_id: work.operation_id.clone(),
            mutation: work.mutation,
            adoption: None,
            truth: if work.mutation == TunnelMutation::Disconnect {
                SupervisedTruth::DisconnectedTombstone
            } else {
                SupervisedTruth::Reserved
            },
        };
        let cancellation = self.tunnels.dispatch(work, routes)?;
        state.profiles.insert(profile_id.clone(), entry.clone());
        if entry.mutation == TunnelMutation::Disconnect {
            state.tombstones.insert(profile_id, entry);
        }
        Ok(cancellation)
    }

    /// Reserve the exact bounded worker slot and normalized route lease used
    /// by a later admitted operation.
    pub fn reserve_tunnel(
        &self,
        profile_id: &ProfileId,
        routes: impl IntoIterator<Item = String>,
    ) -> Result<ProfileAdmission, WorkFailure> {
        if self
            .state
            .lock()
            .expect("supervisor mutex poisoned")
            .profiles
            .get(profile_id)
            .is_some_and(|entry| {
                matches!(
                    entry.truth,
                    SupervisedTruth::Reserved
                        | SupervisedTruth::WaitingForObservation
                        | SupervisedTruth::OutcomeUnknown
                        | SupervisedTruth::DisconnectedTombstone
                )
            })
        {
            return Err(WorkFailure::Busy);
        }
        self.tunnels.reserve(profile_id, routes)
    }

    pub fn dispatch_reserved_tunnel(
        &self,
        work: TunnelWork,
        admission: ProfileAdmission,
    ) -> Result<CancellationToken, WorkFailure> {
        let mut state = self.state.lock().expect("supervisor mutex poisoned");
        if work.authority_epoch != state.authority_epoch {
            return Err(WorkFailure::Stale);
        }
        let profile_id = work.profile_id.clone();
        let entry = ProfileSupervision {
            generation: work.generation,
            authority_epoch: work.authority_epoch,
            policy_digest: work.policy_digest.clone(),
            operation_id: work.operation_id.clone(),
            mutation: work.mutation,
            adoption: None,
            truth: if work.mutation == TunnelMutation::Disconnect {
                SupervisedTruth::DisconnectedTombstone
            } else {
                SupervisedTruth::Reserved
            },
        };
        let cancellation = self.tunnels.dispatch_admitted(work, admission)?;
        state.profiles.insert(profile_id.clone(), entry.clone());
        if entry.mutation == TunnelMutation::Disconnect {
            state.tombstones.insert(profile_id, entry);
        }
        Ok(cancellation)
    }

    /// Promote only protocol-attested external evidence. The planner keeps all
    /// scanner-only sessions read-only and never calls this seam for guesses.
    pub fn adopt_attested(
        &self,
        evidence: AdoptionEvidence,
        revision: ControlRevision,
        operation_id: OperationId,
    ) -> Result<(), WorkFailure> {
        let mut state = self.state.lock().expect("supervisor mutex poisoned");
        if revision.authority_epoch != state.authority_epoch {
            return Err(WorkFailure::Stale);
        }
        let profile_id = evidence.profile_id().clone();
        if state.profiles.get(&profile_id).is_some_and(|entry| {
            matches!(
                entry.truth,
                SupervisedTruth::Reserved
                    | SupervisedTruth::OutcomeUnknown
                    | SupervisedTruth::DisconnectedTombstone
            )
        }) {
            return Err(WorkFailure::Busy);
        }
        state.profiles.insert(
            profile_id,
            ProfileSupervision {
                generation: revision.generation,
                authority_epoch: revision.authority_epoch,
                policy_digest: revision.digest,
                operation_id,
                mutation: TunnelMutation::Connect,
                adoption: Some(evidence),
                truth: SupervisedTruth::ObservedPresent,
            },
        );
        Ok(())
    }

    pub fn submit_policy(&self, policy: &TopologyPolicy) -> Result<(), WorkFailure> {
        let mut state = self.state.lock().expect("supervisor mutex poisoned");
        let revision = policy.revision();
        if revision.authority_epoch != state.authority_epoch
            || state.latest_policy.as_ref().is_some_and(|(current, _)| {
                current.generation > revision.generation
                    || current.generation == revision.generation
                        && current.digest == revision.digest
            })
        {
            return Err(WorkFailure::Stale);
        }
        self.policy.submit(policy.clone())?;
        state.latest_policy = Some((revision, policy.operation_id.clone()));
        state.latest_topology = Some(policy.clone());
        state.applied_policy = None;
        state.protected = None;
        state.policy_degraded = None;
        Ok(())
    }

    pub fn poll_tunnel(&self) -> Option<TunnelWorkResult> {
        let mut result = self.tunnels.try_result()?;
        let mut state = self.state.lock().expect("supervisor mutex poisoned");
        let exact = state.profiles.get(&result.profile_id).is_some_and(|entry| {
            entry.generation == result.generation
                && entry.authority_epoch == result.authority_epoch
                && entry.policy_digest == result.policy_digest
                && entry.operation_id == result.operation_id
                && entry.mutation == result.mutation
        });
        if !exact {
            result.result = Err(WorkFailure::Stale);
            return Some(result);
        }
        let truth = match result.result {
            Ok(()) => SupervisedTruth::WaitingForObservation,
            Err(WorkFailure::OutcomeUnknown | WorkFailure::TimedOut) => {
                SupervisedTruth::OutcomeUnknown
            }
            Err(error) => SupervisedTruth::Degraded(error),
        };
        if let Some(entry) = state.profiles.get_mut(&result.profile_id) {
            entry.truth = truth;
            if result.result.is_ok() {
                entry.adoption.clone_from(&result.adoption);
            }
        }
        if let Some(entry) = state.tombstones.get_mut(&result.profile_id) {
            entry.truth = truth;
        }
        Some(result)
    }

    pub fn poll_policy(&self) -> Option<PolicyResult> {
        let result = self.policy.try_result()?;
        let mut state = self.state.lock().expect("supervisor mutex poisoned");
        let exact = state
            .latest_policy
            .as_ref()
            .is_some_and(|(revision, operation)| {
                revision.authority_epoch == result.authority_epoch
                    && revision.generation == result.generation
                    && revision.digest == result.digest
                    && operation == &result.operation_id
            });
        if exact && result.outcome == PolicyOutcome::Applied {
            state.applied_policy = Some((
                ControlRevision {
                    authority_epoch: result.authority_epoch,
                    generation: result.generation,
                    digest: result.digest.clone(),
                },
                result.operation_id.clone(),
            ));
            state.applied_topology = state
                .latest_topology
                .as_ref()
                .map(|policy| policy.target.clone());
        } else {
            state.policy_degraded = Some(if exact {
                WorkFailure::EffectFailed
            } else {
                WorkFailure::Stale
            });
        }
        // Worker completion is never protection truth. Only verify_policy can publish.
        Some(result)
    }

    pub fn verify_policy(
        &self,
        evidence: &PolicyVerification,
        now_millis: u64,
    ) -> Result<(), WorkFailure> {
        let mut state = self.state.lock().expect("supervisor mutex poisoned");
        let exact = state
            .latest_policy
            .as_ref()
            .zip(state.applied_policy.as_ref())
            .is_some_and(|(latest, applied)| {
                latest.0 == evidence.revision
                    && latest.1 == evidence.operation_id
                    && applied == latest
            });
        if !exact {
            state.protected = None;
            state.policy_degraded = Some(WorkFailure::Stale);
            return Err(WorkFailure::Stale);
        }
        if !evidence.is_complete_and_fresh(now_millis) {
            state.protected = None;
            state.policy_degraded = Some(WorkFailure::EffectFailed);
            return Err(WorkFailure::EffectFailed);
        }
        state.protected = Some((
            evidence.revision.clone(),
            evidence.operation_id.clone(),
            evidence.received_at_millis,
        ));
        state.policy_degraded = None;
        Ok(())
    }

    /// Only a fresh exact observation can settle a tunnel effect.
    pub fn confirm_tunnel(
        &self,
        profile_id: &ProfileId,
        revision: &ControlRevision,
        present: bool,
        interface_name: Option<&str>,
    ) -> Result<(), WorkFailure> {
        let mut state = self.state.lock().expect("supervisor mutex poisoned");
        let exact = state
            .profiles
            .get(profile_id)
            .is_some_and(|entry| entry.revision() == *revision);
        if !exact {
            return Err(WorkFailure::Stale);
        }
        let entry = state
            .profiles
            .get(profile_id)
            .cloned()
            .ok_or(WorkFailure::Stale)?;
        if entry.truth != SupervisedTruth::WaitingForObservation {
            return Err(WorkFailure::Busy);
        }
        if present {
            if state.tombstones.contains_key(profile_id) {
                return Err(WorkFailure::EffectFailed);
            }
            if entry.mutation != TunnelMutation::Connect
                || entry
                    .adoption
                    .as_ref()
                    .is_none_or(|adoption| Some(adoption.interface_name()) != interface_name)
            {
                return Err(WorkFailure::EffectFailed);
            }
            if let Some(entry) = state.profiles.get_mut(profile_id) {
                entry.truth = SupervisedTruth::ObservedPresent;
            }
        } else {
            if entry.mutation != TunnelMutation::Disconnect {
                return Err(WorkFailure::EffectFailed);
            }
            state.profiles.remove(profile_id);
            state.tombstones.remove(profile_id);
            self.tunnels.confirm_absence(profile_id);
        }
        Ok(())
    }

    #[must_use]
    pub fn is_tombstoned(&self, profile_id: &ProfileId) -> bool {
        self.state
            .lock()
            .expect("supervisor mutex poisoned")
            .tombstones
            .contains_key(profile_id)
    }
    #[must_use]
    pub fn profile_truth(&self, profile_id: &ProfileId) -> Option<ProfileSupervision> {
        self.state
            .lock()
            .expect("supervisor mutex poisoned")
            .profiles
            .get(profile_id)
            .cloned()
    }
    #[must_use]
    pub fn profiles(&self) -> BTreeMap<ProfileId, ProfileSupervision> {
        self.state
            .lock()
            .expect("supervisor mutex poisoned")
            .profiles
            .clone()
    }
    #[must_use]
    pub fn tombstones(&self) -> BTreeMap<ProfileId, ProfileSupervision> {
        self.state
            .lock()
            .expect("supervisor mutex poisoned")
            .tombstones
            .clone()
    }
    #[must_use]
    pub fn latest_policy(&self) -> Option<(ControlRevision, OperationId)> {
        self.state
            .lock()
            .expect("supervisor mutex poisoned")
            .latest_policy
            .clone()
    }
    #[must_use]
    pub fn applied_topology(&self) -> Option<TopologyState> {
        self.state
            .lock()
            .expect("supervisor mutex poisoned")
            .applied_topology
            .clone()
    }
    #[must_use]
    pub fn protected_revision(&self) -> Option<ControlRevision> {
        self.state
            .lock()
            .expect("supervisor mutex poisoned")
            .protected
            .as_ref()
            .map(|(revision, _, _)| revision.clone())
    }
    #[must_use]
    pub fn protected_generation(&self) -> Option<u64> {
        self.protected_revision()
            .map(|revision| revision.generation)
    }

    #[must_use]
    pub fn protects(&self, revision: &ControlRevision, now_millis: u64) -> bool {
        let state = self.state.lock().expect("supervisor mutex poisoned");
        state
            .protected
            .as_ref()
            .is_some_and(|(protected, operation, verified_at)| {
                protected == revision
                    && state
                        .applied_policy
                        .as_ref()
                        .is_some_and(|(applied, applied_operation)| {
                            applied == protected && applied_operation == operation
                        })
                    && *verified_at <= now_millis
                    && now_millis.saturating_sub(*verified_at) <= MAX_PROTECTION_AGE_MILLIS
            })
    }
    #[must_use]
    pub fn lost_results(&self) -> u64 {
        self.tunnels
            .dropped_results()
            .saturating_add(self.policy.dropped_results())
    }

    pub fn shutdown_bounded(&self, timeout: Duration) -> bool {
        let half = timeout / 2;
        self.tunnels.shutdown_bounded(half)
            & self.policy.shutdown_bounded(timeout.saturating_sub(half))
    }
    pub fn shutdown(&self) {
        let _ = self.shutdown_bounded(Duration::from_millis(200));
    }
}
