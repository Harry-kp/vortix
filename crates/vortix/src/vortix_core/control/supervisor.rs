//! Coordinator-facing bounded supervision facade.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::vortix_core::control::model::{AuthorityEpoch, OperationId, MAX_PROTECTION_AGE_MILLIS};
use crate::vortix_core::control::persistence::PersistedTombstone;
use crate::vortix_core::control::worker::{
    CancellationToken, ControlRevision, PolicyAuditResult, PolicyExecutor, PolicyOutcome,
    PolicyResult, PolicyStage, PolicyWorker, ProfileAdmission, ProfileWorkerPool, TopologyPolicy,
    TopologyState, TopologyTransitionKind, TunnelExecutor, TunnelMutation, TunnelRevision,
    TunnelWork, TunnelWorkResult, WorkFailure,
};
use crate::vortix_core::ports::tunnel::{
    AdoptionEvidence, HandshakeEvidence, ProbeReceipt, TunnelKindTag,
};
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
    pub revision: TunnelRevision,
    pub resource_revision: TunnelRevision,
    pub operation_id: OperationId,
    pub mutation: TunnelMutation,
    pub adoption: Option<AdoptionEvidence>,
    pub handshake: Option<HandshakeEvidence>,
    pub probe_receipts: Vec<ProbeReceipt>,
    pub truth: SupervisedTruth,
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
    /// Age fence shared by every gate scope: a read-back from the future or
    /// from beyond the protection ceiling is not evidence about now.
    fn is_fresh(&self, now_millis: u64) -> bool {
        self.observed_at_millis <= now_millis
            && self.received_at_millis <= now_millis
            && now_millis.saturating_sub(self.observed_at_millis) <= MAX_PROTECTION_AGE_MILLIS
            && now_millis.saturating_sub(self.received_at_millis) <= MAX_PROTECTION_AGE_MILLIS
    }

    #[must_use]
    pub fn is_complete_and_fresh(&self, now_millis: u64) -> bool {
        self.is_fresh(now_millis)
            && self.interface_verified
            && self.route_verified
            && self.dns_verified
            && self.firewall_verified
    }

    /// Proof scope of an emergency pre-tunnel barrier. It is the whole
    /// four-gate fence minus the three gates that cannot exist while the
    /// barrier stands alone: no tunnel, no route through it, no resolver.
    #[must_use]
    pub fn firewall_is_fresh(&self, now_millis: u64) -> bool {
        self.is_fresh(now_millis) && self.firewall_verified
    }
}

#[derive(Debug)]
struct State {
    authority_epoch: AuthorityEpoch,
    latest_policy: Option<(ControlRevision, OperationId, PolicyStage)>,
    latest_topology: Option<TopologyPolicy>,
    pre_tunnel_blocking: Option<(ControlRevision, OperationId)>,
    /// The exact pre-block policy currently submitted, retained so the audit
    /// cadence can re-read the barrier after the final stage has taken over
    /// `latest_topology`.
    ///
    /// Only a recovery is retained. `block-on-drop` also pre-blocks for a
    /// planned reconnect or primary transfer, where the firewall is engaged
    /// but the VPN did not drop — reporting those would put "VPN dropped" on
    /// screen during a transition the user asked for.
    pre_block_topology: Option<TopologyPolicy>,
    /// Fenced platform read-back of the emergency barrier, with the instant
    /// it arrived. This is the only thing that may publish `Blocking` for a
    /// pre-tunnel block.
    pre_block_proof: Option<(ControlRevision, OperationId, u64)>,
    last_pre_block_audit: Option<(ControlRevision, OperationId, u64)>,
    applied_policy: Option<(ControlRevision, OperationId)>,
    applied_topology: Option<TopologyState>,
    profiles: BTreeMap<ProfileId, ProfileSupervision>,
    tombstones: BTreeMap<ProfileId, ProfileSupervision>,
    policy_degraded: Option<WorkFailure>,
    protected: Option<(ControlRevision, OperationId, u64)>,
    last_policy_audit: Option<(ControlRevision, OperationId, u64)>,
}

impl State {
    fn new(authority_epoch: AuthorityEpoch) -> Self {
        Self {
            authority_epoch,
            latest_policy: None,
            latest_topology: None,
            pre_tunnel_blocking: None,
            pre_block_topology: None,
            pre_block_proof: None,
            last_pre_block_audit: None,
            applied_policy: None,
            applied_topology: None,
            profiles: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            policy_degraded: None,
            protected: None,
            last_policy_audit: None,
        }
    }
}

/// Identity fence shared by [`Supervisor::fences_policy`] and
/// [`Supervisor::verify_policy`]: the read-back must describe the exact
/// applied final policy and only tunnels the supervisor still owns.
fn policy_fence_holds(state: &State, evidence: &PolicyVerification) -> bool {
    let exact = state
        .latest_policy
        .as_ref()
        .zip(state.applied_policy.as_ref())
        .is_some_and(|(latest, applied)| {
            latest.0 == evidence.revision
                && latest.1 == evidence.operation_id
                && latest.2 == PolicyStage::Final
                && applied.0 == latest.0
                && applied.1 == latest.1
        });
    let tunnel_truth_exact = state.latest_topology.as_ref().is_some_and(|policy| {
        policy.target.profiles.iter().all(|profile| {
            policy
                .tunnel_revisions
                .get(profile)
                .is_some_and(|revision| {
                    state.profiles.get(profile).is_some_and(|entry| {
                        entry.revision == *revision
                            && entry.truth == SupervisedTruth::ObservedPresent
                            && entry.adoption.as_ref().is_some_and(|adoption| {
                                adoption.kind() != TunnelKindTag::WireGuard
                                    || entry.handshake.as_ref().is_some_and(|handshake| {
                                        handshake.generation == revision.generation
                                            && !handshake.peer_public_key.is_empty()
                                    })
                            })
                    })
                })
        })
    });
    exact && tunnel_truth_exact
}

/// Identity fence for the emergency pre-tunnel barrier, the pre-block
/// counterpart of [`policy_fence_holds`].
///
/// It holds while the supervisor still owns that exact barrier: the pre-block
/// applied and was not superseded, nothing newer has been submitted, and the
/// final stage for the same revision has not published yet. Once the final
/// stage is applied it carries the richer four-gate truth and this fence must
/// step aside.
///
/// `pre_block_topology` is only retained for a recovery, so the fence is also
/// what scopes the claim to a barrier the user's VPN actually dropped into.
fn pre_block_fence_holds(
    state: &State,
    revision: &ControlRevision,
    operation_id: &OperationId,
) -> bool {
    let identity = (revision.clone(), operation_id.clone());
    state.pre_tunnel_blocking.as_ref() == Some(&identity)
        && state.pre_block_topology.as_ref().is_some_and(|policy| {
            policy.revision() == *revision && policy.operation_id == *operation_id
        })
        && state
            .latest_policy
            .as_ref()
            .is_some_and(|(latest, operation, _)| latest == revision && operation == operation_id)
        && state.applied_policy.as_ref() != Some(&identity)
}

/// A read-only refresh is due once the current proof is halfway to the
/// protection ceiling. A stamp from the future is treated as due.
fn audit_rate_limited(last_attempt: Option<u64>, now_millis: u64) -> bool {
    last_attempt.is_some_and(|last_attempt| {
        last_attempt > now_millis
            || now_millis.saturating_sub(last_attempt) < MAX_PROTECTION_AGE_MILLIS / 2
    })
}

/// Pick the policy whose platform read-back is due for a refresh.
///
/// The emergency barrier comes first: while it is the supervisor's own, it is
/// the only firewall installed, and the final policy that would otherwise be
/// audited describes a topology that is no longer in force.
fn audit_due_policy(state: &State, now_millis: u64) -> Result<Option<TopologyPolicy>, WorkFailure> {
    if let Some(policy) = state
        .pre_block_topology
        .as_ref()
        .filter(|policy| pre_block_fence_holds(state, &policy.revision(), &policy.operation_id))
    {
        let for_pre_block = |candidate: &ControlRevision, operation: &OperationId, at: u64| {
            (*candidate == policy.revision() && *operation == policy.operation_id).then_some(at)
        };
        let last_attempt = state
            .pre_block_proof
            .as_ref()
            .and_then(|(candidate, operation, received_at)| {
                for_pre_block(candidate, operation, *received_at)
            })
            .into_iter()
            .chain(state.last_pre_block_audit.as_ref().and_then(
                |(candidate, operation, attempted_at)| {
                    for_pre_block(candidate, operation, *attempted_at)
                },
            ))
            .max();
        return Ok((!audit_rate_limited(last_attempt, now_millis)).then(|| policy.clone()));
    }

    let Some((revision, operation_id)) = state.applied_policy.clone() else {
        return Ok(None);
    };
    let for_applied = |candidate: &ControlRevision, operation: &OperationId, at: u64| {
        (*candidate == revision && *operation == operation_id).then_some(at)
    };
    let last_attempt =
        state
            .protected
            .as_ref()
            .and_then(|(candidate, operation, verified_at)| {
                for_applied(candidate, operation, *verified_at)
            })
            .into_iter()
            .chain(state.last_policy_audit.as_ref().and_then(
                |(candidate, operation, attempted_at)| {
                    for_applied(candidate, operation, *attempted_at)
                },
            ))
            .max();
    if audit_rate_limited(last_attempt, now_millis) {
        return Ok(None);
    }
    state
        .latest_topology
        .as_ref()
        .filter(|policy| {
            policy.stage == PolicyStage::Final
                && policy.revision() == revision
                && policy.operation_id == operation_id
        })
        .cloned()
        .map(Some)
        .ok_or(WorkFailure::Stale)
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
        if work.revision.authority_epoch != state.authority_epoch {
            return Err(WorkFailure::Stale);
        }
        if let Some(entry) = state.profiles.get(&work.profile_id) {
            if matches!(
                entry.truth,
                SupervisedTruth::Reserved
                    | SupervisedTruth::OutcomeUnknown
                    | SupervisedTruth::DisconnectedTombstone
            ) {
                if entry.revision != work.revision {
                    self.tunnels.cancel_profile(&work.profile_id);
                }
                return Err(WorkFailure::Busy);
            }
            if entry.revision == work.revision
                && matches!(entry.truth, SupervisedTruth::WaitingForObservation)
            {
                return Err(WorkFailure::Busy);
            }
        }
        let profile_id = work.profile_id.clone();
        let entry = ProfileSupervision {
            revision: work.revision,
            resource_revision: work.resource_revision,
            operation_id: work.operation_id.clone(),
            mutation: work.mutation,
            adoption: None,
            handshake: None,
            probe_receipts: Vec::new(),
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

    /// Reserve teardown capacity without claiming connect-only routes or
    /// rejecting the exact managed tunnel that the work will remove.
    pub fn reserve_disconnect(
        &self,
        profile_id: &ProfileId,
    ) -> Result<ProfileAdmission, WorkFailure> {
        self.tunnels
            .reserve(profile_id, std::iter::empty::<String>())
    }

    pub fn reserve_tunnel_with_acknowledgement(
        &self,
        profile_id: &ProfileId,
        routes: impl IntoIterator<Item = String>,
        acknowledgement: Option<&crate::vortix_core::engine::registry::Conflict>,
    ) -> Result<ProfileAdmission, WorkFailure> {
        self.tunnels
            .reserve_with_acknowledgement(profile_id, routes, acknowledgement)
    }

    pub fn dispatch_reserved_tunnel(
        &self,
        work: TunnelWork,
        admission: ProfileAdmission,
    ) -> Result<CancellationToken, WorkFailure> {
        let mut state = self.state.lock().expect("supervisor mutex poisoned");
        if work.revision.authority_epoch != state.authority_epoch {
            return Err(WorkFailure::Stale);
        }
        let profile_id = work.profile_id.clone();
        let entry = ProfileSupervision {
            revision: work.revision,
            resource_revision: work.resource_revision,
            operation_id: work.operation_id.clone(),
            mutation: work.mutation,
            adoption: None,
            handshake: None,
            probe_receipts: Vec::new(),
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
        revision: TunnelRevision,
        operation_id: OperationId,
    ) -> Result<(), WorkFailure> {
        // WireGuard adoption requires an exact worker receipt containing the
        // current revision, operation and cryptographic handshake. This
        // legacy adoption seam carries only interface attestation, so WG is
        // deliberately observation-only here.
        if evidence.kind() == TunnelKindTag::WireGuard {
            return Err(WorkFailure::EffectFailed);
        }
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
                revision,
                resource_revision: revision,
                operation_id,
                mutation: TunnelMutation::Connect,
                adoption: Some(evidence),
                handshake: None,
                probe_receipts: Vec::new(),
                truth: SupervisedTruth::ObservedPresent,
            },
        );
        Ok(())
    }

    /// Restore an exact protocol-owned Standard-mode capability after a
    /// one-shot client process exits. Scanner evidence alone cannot call this
    /// seam: `WireGuard` requires its generation-bound handshake, while
    /// `OpenVPN` requires the authenticated custodian identity.
    pub fn restore_owned_tunnel(
        &self,
        evidence: AdoptionEvidence,
        handshake: Option<HandshakeEvidence>,
        probe_receipts: Vec<ProbeReceipt>,
        process_ownership: Option<&crate::vortix_core::ports::process::ManagedProcessId>,
        revision: TunnelRevision,
        operation_id: OperationId,
    ) -> Result<(), WorkFailure> {
        if revision.authority_epoch
            != self
                .state
                .lock()
                .expect("supervisor mutex poisoned")
                .authority_epoch
        {
            return Err(WorkFailure::Stale);
        }
        let profile_id = evidence.profile_id().clone();
        let protocol_correct = match evidence.kind() {
            TunnelKindTag::WireGuard => {
                process_ownership.is_none()
                    && handshake.as_ref().is_some_and(|handshake| {
                        handshake.generation == revision.generation
                            && !handshake.peer_public_key.is_empty()
                    })
            }
            TunnelKindTag::OpenVpn => {
                handshake.is_none()
                    && process_ownership.as_ref().is_some_and(|identity| {
                        identity.profile_id == profile_id
                            && identity.generation == revision.generation
                            && identity.has_valid_token()
                    })
            }
            TunnelKindTag::Mock => false,
        };
        if !protocol_correct {
            return Err(WorkFailure::EffectFailed);
        }
        let mut state = self.state.lock().expect("supervisor mutex poisoned");
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
                revision,
                resource_revision: revision,
                operation_id,
                mutation: TunnelMutation::Connect,
                adoption: Some(evidence),
                handshake,
                probe_receipts,
                truth: SupervisedTruth::ObservedPresent,
            },
        );
        Ok(())
    }

    pub fn submit_policy(&self, policy: &TopologyPolicy) -> Result<(), WorkFailure> {
        let mut state = self.state.lock().expect("supervisor mutex poisoned");
        let revision = policy.revision();
        if revision.authority_epoch != state.authority_epoch
            || state
                .latest_policy
                .as_ref()
                .is_some_and(|(current, operation, stage)| {
                    current.generation > revision.generation
                        || current.generation == revision.generation
                            && current.digest == revision.digest
                            && operation == &policy.operation_id
                            && *stage >= policy.stage
                })
        {
            return Err(WorkFailure::Stale);
        }
        if policy.stage == PolicyStage::Final
            && policy.required_blocking
            && state.pre_tunnel_blocking.as_ref()
                != Some(&(revision.clone(), policy.operation_id.clone()))
        {
            return Err(WorkFailure::Busy);
        }
        self.policy.submit(policy.clone())?;
        if policy.stage == PolicyStage::PreTunnelBlocking {
            state.pre_tunnel_blocking = None;
            state.pre_block_proof = None;
            state.last_pre_block_audit = None;
            state.pre_block_topology =
                (policy.transition == TopologyTransitionKind::Recovery).then(|| policy.clone());
        }
        state.latest_policy = Some((revision, policy.operation_id.clone(), policy.stage));
        state.latest_topology = Some(policy.clone());
        if policy.stage == PolicyStage::Final {
            state.applied_policy = None;
        }
        state.protected = None;
        state.last_policy_audit = None;
        state.policy_degraded = None;
        Ok(())
    }

    pub fn poll_tunnel(&self) -> Option<TunnelWorkResult> {
        let mut result = self.tunnels.try_result()?;
        let mut state = self.state.lock().expect("supervisor mutex poisoned");
        let exact = state.profiles.get(&result.profile_id).is_some_and(|entry| {
            entry.revision == result.revision
                && entry.operation_id == result.operation_id
                && entry.mutation == result.mutation
        });
        if !exact {
            result.result = Err(WorkFailure::Stale);
            return Some(result);
        }
        let truth = match result.result {
            Ok(()) => SupervisedTruth::WaitingForObservation,
            Err(WorkFailure::OutcomeUnknown) => SupervisedTruth::OutcomeUnknown,
            Err(error) => SupervisedTruth::Degraded(error),
        };
        if let Some(entry) = state.profiles.get_mut(&result.profile_id) {
            entry.truth = truth;
            if result.result.is_ok() {
                entry.adoption.clone_from(&result.adoption);
                entry.handshake.clone_from(&result.handshake);
                entry.probe_receipts.clone_from(&result.probe_receipts);
            }
        }
        if let Some(entry) = state.tombstones.get_mut(&result.profile_id) {
            entry.truth = truth;
        }
        Some(result)
    }

    /// Retire only the exact failed connect whose worker proved that no
    /// accepted tunnel effect remains. Ambiguous outcomes keep their ownership
    /// fence until observation or recovery resolves them.
    pub(crate) fn retire_definitive_connect_failure(
        &self,
        profile_id: &ProfileId,
        revision: &TunnelRevision,
        operation_id: &OperationId,
    ) -> Result<(), WorkFailure> {
        let mut state = self.state.lock().expect("supervisor mutex poisoned");
        let exact = state.profiles.get(profile_id).is_some_and(|entry| {
            entry.revision == *revision
                && entry.operation_id == *operation_id
                && entry.mutation == TunnelMutation::Connect
                && matches!(
                    entry.truth,
                    SupervisedTruth::Degraded(
                        WorkFailure::EffectFailed
                            | WorkFailure::AuthenticationFailed
                            | WorkFailure::HandshakeFailed
                            | WorkFailure::InvalidProfile
                            | WorkFailure::RouteConflict
                    )
                )
        });
        if !exact {
            return Err(WorkFailure::Stale);
        }
        state.profiles.remove(profile_id);
        Ok(())
    }

    /// Retire a timed-out connect after its protocol executor proved that no
    /// owned effect remains. A generic timeout is otherwise kept ambiguous;
    /// callers may use this seam only for an exact cleanup contract.
    pub(crate) fn retire_cleaned_connect_timeout(
        &self,
        profile_id: &ProfileId,
        revision: &TunnelRevision,
        operation_id: &OperationId,
    ) -> Result<(), WorkFailure> {
        let mut state = self.state.lock().expect("supervisor mutex poisoned");
        let exact = state.profiles.get(profile_id).is_some_and(|entry| {
            entry.revision == *revision
                && entry.operation_id == *operation_id
                && entry.mutation == TunnelMutation::Connect
                && entry.truth == SupervisedTruth::Degraded(WorkFailure::TimedOut)
        });
        if !exact {
            return Err(WorkFailure::Stale);
        }
        state.profiles.remove(profile_id);
        drop(state);
        // Timeout reservations are conservatively marked ambiguous by the
        // generic worker. Exact protocol cleanup makes this profile lease safe
        // to release instead of blocking the next user attempt.
        self.tunnels.reservations().release_profile(profile_id);
        Ok(())
    }

    pub fn poll_policy(&self) -> Option<PolicyResult> {
        let result = self.policy.try_result()?;
        let mut state = self.state.lock().expect("supervisor mutex poisoned");
        let exact = state
            .latest_policy
            .as_ref()
            .is_some_and(|(revision, operation, stage)| {
                revision.authority_epoch == result.authority_epoch
                    && revision.generation == result.generation
                    && revision.digest == result.digest
                    && operation == &result.operation_id
                    && *stage == result.stage
            });
        if exact
            && result.stage == PolicyStage::PreTunnelBlocking
            && result.outcome == PolicyOutcome::Applied
        {
            state.pre_tunnel_blocking = Some((
                ControlRevision {
                    authority_epoch: result.authority_epoch,
                    generation: result.generation,
                    digest: result.digest.clone(),
                },
                result.operation_id.clone(),
            ));
        } else if exact
            && result.stage == PolicyStage::Final
            && result.outcome == PolicyOutcome::Applied
        {
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
            state.pre_block_topology = None;
            state.pre_block_proof = None;
        } else {
            if exact && result.stage == PolicyStage::PreTunnelBlocking {
                state.pre_tunnel_blocking = None;
                state.pre_block_proof = None;
            }
            state.policy_degraded = Some(if exact {
                WorkFailure::EffectFailed
            } else {
                WorkFailure::Stale
            });
        }
        // Worker completion is never protection truth. Only verify_policy can publish.
        Some(result)
    }

    /// Queue a read-only refresh before the current protection proof expires.
    /// Policy mutation work always has priority in the shared worker.
    ///
    /// Anchored on the *applied* policy, never on the last proof. Anchoring on
    /// the proof latched the snapshot: one unverifiable gate cleared
    /// `protected`, which stopped every further audit, so protection stayed
    /// degraded until the next mutation instead of recovering on its own.
    pub fn submit_policy_audit_if_due(&self, now_millis: u64) -> Result<bool, WorkFailure> {
        let Some(mut policy) = ({
            let state = self.state.lock().expect("supervisor mutex poisoned");
            audit_due_policy(&state, now_millis)?
        }) else {
            return Ok(false);
        };
        policy.deadline = Instant::now()
            .checked_add(Duration::from_millis(MAX_PROTECTION_AGE_MILLIS / 2))
            .ok_or(WorkFailure::TimedOut)?;
        let audited_stage = policy.stage;
        let revision = policy.revision();
        let operation_id = policy.operation_id.clone();
        match self.policy.submit_audit(policy) {
            Ok(()) => {
                let mut state = self.state.lock().expect("supervisor mutex poisoned");
                let stamp = Some((revision, operation_id, now_millis));
                if audited_stage == PolicyStage::PreTunnelBlocking {
                    state.last_pre_block_audit = stamp;
                } else {
                    state.last_policy_audit = stamp;
                }
                Ok(true)
            }
            Err(WorkFailure::Busy) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub fn poll_policy_audit(&self) -> Option<PolicyAuditResult> {
        let mut result = self.policy.try_audit_result()?;
        let state = self.state.lock().expect("supervisor mutex poisoned");
        let exact = match result.stage {
            PolicyStage::PreTunnelBlocking => {
                pre_block_fence_holds(&state, &result.revision, &result.operation_id)
            }
            PolicyStage::Final => state
                .latest_policy
                .as_ref()
                .zip(state.applied_policy.as_ref())
                .is_some_and(|(latest, applied)| {
                    latest.0 == result.revision
                        && latest.1 == result.operation_id
                        && latest.2 == PolicyStage::Final
                        && applied.0 == result.revision
                        && applied.1 == result.operation_id
                }),
        };
        if !exact {
            result.result = Err(WorkFailure::Stale);
        }
        Some(result)
    }

    /// Whether read-back belongs to the exact applied final policy and to
    /// tunnels the supervisor still owns. This is the identity fence only —
    /// it says the evidence is *about* current state, not that current state
    /// is protected. Per-gate evidence may be recorded once it holds.
    #[must_use]
    pub fn fences_policy(&self, evidence: &PolicyVerification) -> bool {
        let state = self.state.lock().expect("supervisor mutex poisoned");
        policy_fence_holds(&state, evidence)
    }

    pub fn verify_policy(
        &self,
        evidence: &PolicyVerification,
        now_millis: u64,
    ) -> Result<(), WorkFailure> {
        let mut state = self.state.lock().expect("supervisor mutex poisoned");
        if !policy_fence_holds(&state, evidence) {
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

    /// Record fenced platform read-back of the emergency pre-tunnel barrier.
    ///
    /// Deliberately separate from [`Self::verify_policy`]: a pre-block proves
    /// the firewall and nothing else, so it must never set `protected`, which
    /// is the four-gate whole-topology claim. It publishes one fact — the
    /// block the user is relying on right now is really installed.
    pub fn verify_pre_block(
        &self,
        evidence: &PolicyVerification,
        now_millis: u64,
    ) -> Result<(), WorkFailure> {
        let mut state = self.state.lock().expect("supervisor mutex poisoned");
        if !pre_block_fence_holds(&state, &evidence.revision, &evidence.operation_id) {
            state.pre_block_proof = None;
            return Err(WorkFailure::Stale);
        }
        if !evidence.firewall_is_fresh(now_millis) {
            state.pre_block_proof = None;
            return Err(WorkFailure::EffectFailed);
        }
        state.pre_block_proof = Some((
            evidence.revision.clone(),
            evidence.operation_id.clone(),
            evidence.received_at_millis,
        ));
        Ok(())
    }

    /// Whether the emergency barrier is provably installed *now*: the exact
    /// pre-block is still the supervisor's, and its read-back has not aged
    /// past the protection ceiling.
    #[must_use]
    pub fn pre_block_blocking(&self, now_millis: u64) -> bool {
        let state = self.state.lock().expect("supervisor mutex poisoned");
        state
            .pre_block_proof
            .as_ref()
            .is_some_and(|(revision, operation_id, received_at)| {
                pre_block_fence_holds(&state, revision, operation_id)
                    && *received_at <= now_millis
                    && now_millis.saturating_sub(*received_at) <= MAX_PROTECTION_AGE_MILLIS
            })
    }

    /// Only a fresh exact observation can settle a tunnel effect.
    pub fn confirm_tunnel(
        &self,
        profile_id: &ProfileId,
        revision: &TunnelRevision,
        present: bool,
        interface_name: Option<&str>,
    ) -> Result<(), WorkFailure> {
        let mut state = self.state.lock().expect("supervisor mutex poisoned");
        let exact = state
            .profiles
            .get(profile_id)
            .is_some_and(|entry| entry.revision == *revision);
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
                || entry.adoption.as_ref().is_some_and(|adoption| {
                    adoption.kind() == TunnelKindTag::WireGuard
                        && entry.handshake.as_ref().is_none_or(|handshake| {
                            handshake.generation != revision.generation
                                || handshake.peer_public_key.is_empty()
                        })
                })
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

    /// Clear an exact disconnect fence after current observation proves the
    /// managed tunnel absent. Restored tombstones have no live profile entry;
    /// an in-process teardown must first finish before its fence can clear.
    pub fn confirm_tombstone_absence(
        &self,
        profile_id: &ProfileId,
        revision: &TunnelRevision,
    ) -> Result<(), WorkFailure> {
        let mut state = self.state.lock().expect("supervisor mutex poisoned");
        let exact_tombstone = state
            .tombstones
            .get(profile_id)
            .is_some_and(|entry| entry.revision == *revision);
        if !exact_tombstone {
            return Err(WorkFailure::Stale);
        }
        if state.profiles.get(profile_id).is_some_and(|entry| {
            entry.revision != *revision
                || !matches!(
                    entry.truth,
                    SupervisedTruth::WaitingForObservation
                        | SupervisedTruth::OutcomeUnknown
                        | SupervisedTruth::Degraded(_)
                )
        }) {
            return Err(WorkFailure::Busy);
        }
        state.profiles.remove(profile_id);
        state.tombstones.remove(profile_id);
        self.tunnels.confirm_absence(profile_id);
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

    /// Restore only teardown fences. Persisted observations, adoption handles,
    /// and connection truth are intentionally never reconstructed.
    pub fn restore_tombstones(
        &self,
        tombstones: &BTreeMap<ProfileId, PersistedTombstone>,
    ) -> Result<(), WorkFailure> {
        let mut state = self.state.lock().expect("supervisor mutex poisoned");
        if tombstones.values().any(|tombstone| {
            tombstone.authority_epoch != state.authority_epoch
                || tombstone.resource_generation == Some(0)
        }) {
            return Err(WorkFailure::Stale);
        }
        state.tombstones = tombstones
            .iter()
            .map(|(profile_id, tombstone)| {
                (
                    profile_id.clone(),
                    ProfileSupervision {
                        revision: TunnelRevision {
                            authority_epoch: tombstone.authority_epoch,
                            generation: tombstone.generation,
                        },
                        resource_revision: TunnelRevision {
                            authority_epoch: tombstone.authority_epoch,
                            generation: tombstone
                                .resource_generation
                                .unwrap_or(tombstone.generation),
                        },
                        operation_id: tombstone.operation_id.clone(),
                        mutation: TunnelMutation::Disconnect,
                        adoption: None,
                        handshake: None,
                        probe_receipts: Vec::new(),
                        truth: if tombstone.teardown_failed {
                            SupervisedTruth::OutcomeUnknown
                        } else {
                            SupervisedTruth::DisconnectedTombstone
                        },
                    },
                )
            })
            .collect();
        Ok(())
    }
    #[must_use]
    pub fn latest_policy(&self) -> Option<(ControlRevision, OperationId)> {
        self.state
            .lock()
            .expect("supervisor mutex poisoned")
            .latest_policy
            .as_ref()
            .and_then(|(revision, operation, stage)| {
                (*stage == PolicyStage::Final).then(|| (revision.clone(), operation.clone()))
            })
    }

    /// Return the exact resource generation currently owned for one profile.
    /// A disconnect work revision may be newer than the tunnel it tears down,
    /// so policy planning must not infer this from desired state.
    pub fn resource_revision(&self, profile_id: &ProfileId) -> Option<TunnelRevision> {
        let state = self.state.lock().expect("supervisor mutex poisoned");
        state
            .profiles
            .get(profile_id)
            .or_else(|| state.tombstones.get(profile_id))
            .map(|entry| entry.resource_revision)
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
        std::thread::scope(|scope| {
            let policy = scope.spawn(|| self.policy.shutdown_bounded(timeout));
            let tunnels_stopped = self.tunnels.shutdown_bounded(timeout);
            let policy_stopped = policy.join().unwrap_or(false);
            tunnels_stopped & policy_stopped
        })
    }
    pub fn shutdown(&self) {
        let _ = self.shutdown_bounded(Duration::from_millis(200));
    }
}
