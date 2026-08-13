//! Live Background-authority activation proof.
//!
//! Persisted enrollment intent selects a recovery path but never grants
//! mutation authority. Activation requires the process-held writer lease, an
//! authenticated helper incarnation for the reserved epoch, and one exact
//! reconciled control snapshot before the durable phase may become enrolled.

#![allow(
    dead_code,
    reason = "the verified activation token remains unreachable until the production helper transport owns it"
)]

use thiserror::Error;

use super::helper_client::AuthenticatedHelperSession;
use crate::vortix_config::authority::{
    AuthorityLease, EnrollmentError, EnrollmentPhase, EnrollmentRecord, EnrollmentStore,
};
use crate::vortix_core::control::{
    AuthorityEpoch, ControlSnapshot, ProtectionStatus, RequestedTunnelState,
};
use crate::vortix_core::state::killswitch::KillSwitchMode;

/// Opaque process-held proof consumed by the activated daemon host. Dropping
/// it releases the shared writer lease, so a remote host cannot outlive its
/// exclusive authority.
pub(crate) struct VerifiedEnrollmentActivation {
    epoch: AuthorityEpoch,
    helper: AuthenticatedHelperSession,
    _lease: AuthorityLease,
}

impl VerifiedEnrollmentActivation {
    #[must_use]
    pub(crate) const fn epoch(&self) -> AuthorityEpoch {
        self.epoch
    }

    #[must_use]
    pub(crate) const fn helper_binding(&self) -> crate::helper::HelperSessionBinding {
        self.helper.binding()
    }
}

pub(crate) fn verify_and_commit_activation(
    store: &EnrollmentStore,
    lease: AuthorityLease,
    helper: AuthenticatedHelperSession,
    snapshot: &ControlSnapshot,
) -> Result<VerifiedEnrollmentActivation, ActivationError> {
    let record = store.load()?;
    let epoch = verify_live_evidence(&record, &helper, snapshot)?;
    store.commit_enrolled(&lease, record.generation(), epoch)?;
    Ok(VerifiedEnrollmentActivation {
        epoch,
        helper,
        _lease: lease,
    })
}

fn verify_live_evidence(
    record: &EnrollmentRecord,
    helper: &AuthenticatedHelperSession,
    snapshot: &ControlSnapshot,
) -> Result<AuthorityEpoch, ActivationError> {
    if record.phase() != EnrollmentPhase::CandidateReady {
        return Err(ActivationError::NotReady);
    }
    let epoch = record.reserved_epoch().ok_or(ActivationError::NotReady)?;
    if helper.binding().authority_epoch != epoch {
        return Err(ActivationError::HelperAuthorityMismatch);
    }
    if !record.matches_candidate_versions(env!("CARGO_PKG_VERSION"), helper.product_version()) {
        return Err(ActivationError::VersionMismatch);
    }
    if !snapshot.readiness.reconciliation_complete || !snapshot.readiness.authority_verified {
        return Err(ActivationError::ReconciliationIncomplete);
    }
    if snapshot.desired.authority_epoch != epoch
        || snapshot.effective.authority_epoch != epoch
        || snapshot.effective.desired_generation != snapshot.desired.generation
        || snapshot.effective.policy_digest != snapshot.desired.policy_digest
    {
        return Err(ActivationError::ControlAuthorityMismatch);
    }
    if !snapshot
        .operations
        .values()
        .all(|operation| operation.status.is_terminal())
        || !snapshot.challenges.is_empty()
    {
        return Err(ActivationError::WorkInFlight);
    }

    let connected = snapshot
        .desired
        .tunnels
        .iter()
        .filter_map(|(profile_id, state)| {
            (*state == RequestedTunnelState::Connected).then_some(profile_id)
        })
        .collect::<Vec<_>>();
    if connected.iter().any(|profile_id| {
        !snapshot
            .observed
            .tunnels
            .get(*profile_id)
            .is_some_and(|observed| observed.active)
    }) {
        return Err(ActivationError::ConvergenceIncomplete);
    }
    let requires_protection =
        !connected.is_empty() || snapshot.desired.kill_switch == KillSwitchMode::AlwaysOn;
    if requires_protection
        && (snapshot.effective.protection != ProtectionStatus::Protected
            || !snapshot.effective.freshness.current)
    {
        return Err(ActivationError::ProtectionUnverified);
    }
    Ok(epoch)
}

#[derive(Debug, Error)]
pub(crate) enum ActivationError {
    #[error("enrollment activation state failed: {0}")]
    Enrollment(#[from] EnrollmentError),
    #[error("Background activation requires a reserved candidate epoch")]
    NotReady,
    #[error("authenticated helper authority does not match the reserved epoch")]
    HelperAuthorityMismatch,
    #[error("daemon/helper versions do not match the staged enrollment candidate")]
    VersionMismatch,
    #[error("control service authority does not match the reserved epoch")]
    ControlAuthorityMismatch,
    #[error("control service has not completed authenticated reconciliation")]
    ReconciliationIncomplete,
    #[error("control service still has nonterminal work or an interactive challenge")]
    WorkInFlight,
    #[error("desired tunnels have not converged to authenticated active observations")]
    ConvergenceIncomplete,
    #[error("required network protection is not fresh and verified")]
    ProtectionUnverified,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::{
        HelperAuthorityMode, HelperCapability, HelperServerHello, HelperSessionBinding,
        HELPER_PROTOCOL_MAX, HELPER_SCHEMA_MAX,
    };
    use crate::vortix_core::control::{
        ClientId, IdempotencyKey, OperationId, OperationIntent, OperationRecord, OperationStatus,
    };
    use crate::vortix_core::privileged::{HelperEpoch, LeaseId, TrustedDaemonPrincipal};
    use tempfile::tempdir;

    fn candidate() -> crate::vortix_config::authority::EnrollmentCandidate {
        crate::vortix_config::authority::EnrollmentCandidate::new(
            7,
            [0x41; 32],
            "0.4.3".into(),
            "0.4.3".into(),
        )
        .unwrap()
    }

    fn reserved_store() -> (EnrollmentStore, AuthorityLease, EnrollmentRecord) {
        let directory = tempdir().unwrap().keep();
        let store = EnrollmentStore::new(directory.join("control"));
        let standard = store.acquire_standard_authority().unwrap();
        let staged = store.stage(&standard, candidate()).unwrap();
        let ready = store
            .mark_candidate_ready(&standard, staged.generation())
            .unwrap();
        let reserved = store
            .reserve_enrollment(&standard, ready.generation())
            .unwrap();
        drop(standard);
        let background = store.acquire_background_authority().unwrap();
        (store, background, reserved)
    }

    fn helper(epoch: AuthorityEpoch) -> AuthenticatedHelperSession {
        helper_with_version(epoch, "0.4.3")
    }

    fn helper_with_version(epoch: AuthorityEpoch, version: &str) -> AuthenticatedHelperSession {
        let lease_id = LeaseId::new([5; 32]);
        let principal = TrustedDaemonPrincipal::test_fixture(epoch, lease_id);
        AuthenticatedHelperSession::from_handshake(
            &principal,
            &crate::helper::validate::VerifiedHelperPeer::test_fixture(),
            &HelperServerHello {
                product: "vortix-helper".into(),
                product_version: version.into(),
                protocol: HELPER_PROTOCOL_MAX,
                schema: HELPER_SCHEMA_MAX,
                authority_mode: HelperAuthorityMode::Enrolled,
                contract_capabilities: vec![HelperCapability::Handshake, HelperCapability::Observe],
                enabled_capabilities: vec![HelperCapability::Handshake, HelperCapability::Observe],
                session: Some(HelperSessionBinding {
                    authority_epoch: epoch,
                    lease_id,
                    helper_epoch: HelperEpoch::new(1).unwrap(),
                }),
            },
        )
        .unwrap()
    }

    fn ready_snapshot(epoch: AuthorityEpoch) -> ControlSnapshot {
        let mut snapshot = ControlSnapshot::default();
        snapshot.readiness.reconciliation_complete = true;
        snapshot.readiness.authority_verified = true;
        snapshot.desired.authority_epoch = epoch;
        snapshot.effective.authority_epoch = epoch;
        snapshot.effective.desired_generation = snapshot.desired.generation;
        snapshot.effective.policy_digest = snapshot.desired.policy_digest.clone();
        snapshot
    }

    #[test]
    fn activation_requires_exact_live_helper_and_reconciled_snapshot() {
        let (store, lease, reserved) = reserved_store();
        let epoch = reserved.reserved_epoch().unwrap();
        let activation =
            verify_and_commit_activation(&store, lease, helper(epoch), &ready_snapshot(epoch))
                .unwrap();

        assert_eq!(activation.epoch(), epoch);
        assert_eq!(activation.helper_binding().authority_epoch, epoch);
        assert_eq!(store.load().unwrap().phase(), EnrollmentPhase::Enrolled);
    }

    #[test]
    fn activation_rejects_stale_epoch_unready_and_pending_work() {
        let (store, lease, reserved) = reserved_store();
        let epoch = reserved.reserved_epoch().unwrap();
        assert!(matches!(
            verify_and_commit_activation(
                &store,
                lease,
                helper(AuthorityEpoch(epoch.0 + 1)),
                &ready_snapshot(epoch),
            ),
            Err(ActivationError::HelperAuthorityMismatch)
        ));

        let lease = store.acquire_background_authority().unwrap();
        let mut unready = ready_snapshot(epoch);
        unready.readiness.reconciliation_complete = false;
        assert!(matches!(
            verify_and_commit_activation(&store, lease, helper(epoch), &unready),
            Err(ActivationError::ReconciliationIncomplete)
        ));

        let lease = store.acquire_background_authority().unwrap();
        let mut pending = ready_snapshot(epoch);
        pending.operations.insert(
            OperationId::from_parts(epoch, 1),
            OperationRecord {
                id: OperationId::from_parts(epoch, 1),
                client_id: ClientId::from_parts(epoch, 1),
                idempotency_key: IdempotencyKey::new("pending-enrollment"),
                command_digest: crate::vortix_core::control::PolicyDigest(
                    "pending-enrollment".into(),
                ),
                authority_epoch: epoch,
                desired_generation: pending.desired.generation,
                intent: OperationIntent::GenerationScoped,
                status: OperationStatus::Admitted,
                result: None,
                admitted_at_millis: 1,
                deadline_millis: 2,
            },
        );
        assert!(matches!(
            verify_and_commit_activation(&store, lease, helper(epoch), &pending),
            Err(ActivationError::WorkInFlight)
        ));
    }

    #[test]
    fn activation_rejects_a_helper_from_a_different_release() {
        let (store, lease, reserved) = reserved_store();
        let epoch = reserved.reserved_epoch().unwrap();

        assert!(matches!(
            verify_and_commit_activation(
                &store,
                lease,
                helper_with_version(epoch, "0.4.2"),
                &ready_snapshot(epoch),
            ),
            Err(ActivationError::VersionMismatch)
        ));
        assert_eq!(
            store.load().unwrap().phase(),
            EnrollmentPhase::CandidateReady
        );
    }

    #[test]
    fn activation_requires_fresh_protection_only_for_protected_intent() {
        let (store, lease, reserved) = reserved_store();
        let epoch = reserved.reserved_epoch().unwrap();
        let mut snapshot = ready_snapshot(epoch);
        snapshot.desired.kill_switch = KillSwitchMode::AlwaysOn;
        assert!(matches!(
            verify_and_commit_activation(&store, lease, helper(epoch), &snapshot),
            Err(ActivationError::ProtectionUnverified)
        ));

        let (store, lease, reserved) = reserved_store();
        let epoch = reserved.reserved_epoch().unwrap();
        let mut snapshot = ready_snapshot(epoch);
        let profile_id = crate::vortix_core::profile::ProfileId::parse(
            "a".repeat(crate::vortix_core::profile::ProfileId::HEX_LEN),
        )
        .unwrap();
        snapshot
            .desired
            .tunnels
            .insert(profile_id.clone(), RequestedTunnelState::Connected);
        assert!(matches!(
            verify_and_commit_activation(&store, lease, helper(epoch), &snapshot),
            Err(ActivationError::ConvergenceIncomplete)
        ));

        let (store, lease, reserved) = reserved_store();
        let epoch = reserved.reserved_epoch().unwrap();
        let mut snapshot = ready_snapshot(epoch);
        snapshot
            .desired
            .tunnels
            .insert(profile_id.clone(), RequestedTunnelState::Connected);
        snapshot.observed.tunnels.insert(
            profile_id,
            crate::vortix_core::control::model::ObservedTunnel {
                active: true,
                interface_name: Some("wg0".into()),
                observed_at_millis: 1,
                received_at_millis: 1,
            },
        );
        assert!(matches!(
            verify_and_commit_activation(&store, lease, helper(epoch), &snapshot),
            Err(ActivationError::ProtectionUnverified)
        ));
    }
}
