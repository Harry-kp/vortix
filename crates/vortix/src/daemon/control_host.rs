//! Dormant daemon-side host for the canonical control service.
//!
//! This module owns only the remote-session boundary. Production activation
//! remains unavailable until U13 has a concrete helper-backed tunnel/policy
//! runtime and a durable local-admission drain transaction. Keeping that
//! constructor absent is deliberate: a generic builder could ignore the
//! authenticated helper and advertise authority it does not own.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::vortix_core::control::{
    ControlHandle, ControlService, ControlSnapshot, ControlSubscription, Secret,
};
use crate::vortix_core::ipc::{
    ControlAvailability, IpcError, IpcOp, IpcResult, RemoteSessionId, SensitiveBytes,
};
use crate::vortix_core::privileged::AuthorityBinding;
use crate::vortix_core::profile::ProfileId;

const MAX_REMOTE_SESSIONS: usize = 64;
const PENDING_SESSION_TTL: Duration = Duration::from_secs(5);
const MAX_REMOTE_OPERATION_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Result of consuming the final chunk of one memory-only remote import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StagedRemoteProfile {
    pub(crate) profile_id: ProfileId,
    pub(crate) display_name: String,
}

/// Daemon-owned profile staging seam. Private bodies stay memory-only until
/// the canonical identity-only import operation commits. Implementations must
/// enforce the existing aggregate import bound, monotonic offsets, and an
/// inactivity deadline that clears partial secret material.
pub(crate) trait RemoteProfileStager: Send + Sync {
    fn stage_chunk(
        &self,
        session_id: &RemoteSessionId,
        file_name: &str,
        offset: u64,
        final_chunk: bool,
        contents: SensitiveBytes,
    ) -> Result<Option<StagedRemoteProfile>, IpcError>;

    fn cancel(&self, session_id: &RemoteSessionId);
}

enum HostedSessionState {
    Pending { opened_at: Instant },
    Subscribed,
}

struct HostedSession {
    handle: ControlHandle,
    state: HostedSessionState,
}

/// One daemon-owned canonical service shared by every remote session.
///
/// Only the test constructor exists in this slice. The production constructor
/// must be added together with the helper-backed executors so its type can
/// prove that effects use the exact authenticated authority binding.
pub(crate) struct ControlAuthorityHost {
    service: ControlService,
    authority_binding: AuthorityBinding,
    sessions: Mutex<BTreeMap<RemoteSessionId, HostedSession>>,
    profile_stager: Option<Arc<dyn RemoteProfileStager>>,
}

impl ControlAuthorityHost {
    #[cfg(test)]
    pub(crate) fn new_for_test(
        service: ControlService,
        authority_binding: AuthorityBinding,
    ) -> Self {
        Self {
            service,
            authority_binding,
            sessions: Mutex::new(BTreeMap::new()),
            profile_stager: None,
        }
    }

    #[must_use]
    pub(crate) const fn authority_binding(&self) -> AuthorityBinding {
        self.authority_binding
    }

    #[must_use]
    pub(crate) fn unavailable_state(&self) -> Option<ControlAvailability> {
        let snapshot = self.service.client().snapshot();
        if snapshot.desired.authority_epoch != self.authority_binding.authority_epoch()
            || snapshot.effective.authority_epoch != self.authority_binding.authority_epoch()
            || !snapshot.readiness.authority_verified
        {
            Some(ControlAvailability::RecoveryRequired)
        } else if !snapshot.readiness.reconciliation_complete {
            Some(ControlAvailability::Starting)
        } else {
            None
        }
    }

    pub(crate) fn open_session(&self) -> Result<IpcResult, IpcError> {
        self.require_available()?;
        let session_id = allocate_session_id()?;
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        prune_pending_sessions(&mut sessions, Instant::now());
        if sessions.len() >= MAX_REMOTE_SESSIONS {
            return Err(IpcError::ServerBusy);
        }
        if sessions.contains_key(&session_id) {
            return Err(IpcError::Internal(
                "could not allocate a unique control session".into(),
            ));
        }
        let handle = self
            .service
            .new_client()
            .map_err(|error| IpcError::ControlAdmission { error })?;
        let client_id = handle.client_id().clone();
        sessions.insert(
            session_id.clone(),
            HostedSession {
                handle,
                state: HostedSessionState::Pending {
                    opened_at: Instant::now(),
                },
            },
        );
        Ok(IpcResult::ControlOpened {
            session_id,
            client_id,
        })
    }

    pub(crate) fn subscribe(
        &self,
        session_id: &RemoteSessionId,
    ) -> Result<(ControlSubscription, ControlSnapshot), IpcError> {
        self.require_available()?;
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        prune_pending_sessions(&mut sessions, Instant::now());
        let session = sessions
            .get_mut(session_id)
            .ok_or(IpcError::ControlSessionNotFound)?;
        if !matches!(session.state, HostedSessionState::Pending { .. }) {
            return Err(IpcError::MalformedRequest(
                "control session already has a subscription".into(),
            ));
        }
        let subscription = session.handle.subscribe();
        let snapshot = subscription.snapshot();
        session.state = HostedSessionState::Subscribed;
        Ok((subscription, snapshot))
    }

    pub(crate) fn close_session(&self, session_id: &RemoteSessionId) {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(session_id);
        self.cancel_staging(session_id);
    }

    pub(crate) async fn dispatch(&self, op: IpcOp) -> Result<IpcResult, IpcError> {
        match op {
            IpcOp::ControlOpen => self.open_session(),
            IpcOp::ControlSubmit {
                session_id,
                command,
                idempotency_key,
                timeout_millis,
            } => {
                self.require_available()?;
                let timeout = checked_remote_timeout(timeout_millis)?;
                let handle = self.subscribed_handle(&session_id)?;
                let admitted = handle
                    .submit(crate::vortix_core::control::CommandRequest {
                        command,
                        idempotency_key,
                        deadline: handle.deadline_after(timeout),
                    })
                    .await
                    .map_err(|error| IpcError::ControlAdmission { error })?;
                Ok(IpcResult::ControlAccepted { admitted })
            }
            IpcOp::ControlSnapshot { session_id } => Ok(IpcResult::ControlSnapshot {
                snapshot: self.subscribed_handle(&session_id)?.snapshot(),
            }),
            IpcOp::ControlRespondChallenge {
                session_id,
                challenge_id,
                answer,
            } => {
                self.require_available()?;
                self.subscribed_handle(&session_id)?
                    .respond_challenge(challenge_id, Secret::new(answer.into_vec()))
                    .await
                    .map_err(|error| IpcError::ControlChallenge { error })?;
                Ok(IpcResult::ChallengeAccepted)
            }
            IpcOp::ControlCancelChallenge {
                session_id,
                challenge_id,
            } => {
                self.subscribed_handle(&session_id)?
                    .cancel_challenge(challenge_id)
                    .await
                    .map_err(|error| IpcError::ControlChallenge { error })?;
                Ok(IpcResult::ChallengeAccepted)
            }
            IpcOp::ControlStageProfileImport {
                session_id,
                file_name,
                offset,
                final_chunk,
                contents,
            } => {
                self.dispatch_profile_chunk(&session_id, &file_name, offset, final_chunk, contents)
            }
            IpcOp::ControlCancelProfileImport { session_id } => {
                let _ = self.subscribed_handle(&session_id)?;
                self.cancel_staging(&session_id);
                Ok(IpcResult::ChallengeAccepted)
            }
            other => Err(IpcError::MalformedRequest(format!(
                "operation is not a canonical control request: {other:?}"
            ))),
        }
    }

    fn require_available(&self) -> Result<(), IpcError> {
        self.unavailable_state()
            .map_or(Ok(()), |state| Err(IpcError::ControlUnavailable { state }))
    }

    fn dispatch_profile_chunk(
        &self,
        session_id: &RemoteSessionId,
        file_name: &str,
        offset: u64,
        final_chunk: bool,
        contents: SensitiveBytes,
    ) -> Result<IpcResult, IpcError> {
        self.require_available()?;
        let _ = self.subscribed_handle(session_id)?;
        let backend = self
            .profile_stager
            .as_ref()
            .ok_or_else(|| IpcError::Internal("remote profile staging is unavailable".into()))?;
        let contents = contents.into_vec();
        let chunk_len = u64::try_from(contents.len())
            .map_err(|_| IpcError::Internal("profile chunk is too large".into()))?;
        let outcome = backend.stage_chunk(
            session_id,
            file_name,
            offset,
            final_chunk,
            SensitiveBytes::new(contents),
        );
        match outcome {
            Ok(Some(profile)) if final_chunk => Ok(IpcResult::ControlProfileImportStaged {
                profile_id: profile.profile_id,
                display_name: profile.display_name,
            }),
            Ok(None) if !final_chunk => {
                let next_offset = offset.checked_add(chunk_len).ok_or_else(|| {
                    self.cancel_staging(session_id);
                    IpcError::MalformedRequest("profile offset overflow".into())
                })?;
                Ok(IpcResult::ControlProfileImportChunkAccepted { next_offset })
            }
            Ok(_) => {
                self.cancel_staging(session_id);
                Err(IpcError::Internal(
                    "profile stager returned an invalid chunk outcome".into(),
                ))
            }
            Err(error) => {
                self.cancel_staging(session_id);
                Err(error)
            }
        }
    }

    fn cancel_staging(&self, session_id: &RemoteSessionId) {
        if let Some(stager) = &self.profile_stager {
            stager.cancel(session_id);
        }
    }

    fn subscribed_handle(&self, session_id: &RemoteSessionId) -> Result<ControlHandle, IpcError> {
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let session = sessions
            .get(session_id)
            .ok_or(IpcError::ControlSessionNotFound)?;
        if !matches!(session.state, HostedSessionState::Subscribed) {
            return Err(IpcError::ControlSessionNotFound);
        }
        Ok(session.handle.clone())
    }
}

fn checked_remote_timeout(timeout_millis: u64) -> Result<Duration, IpcError> {
    let timeout = Duration::from_millis(timeout_millis);
    if timeout.is_zero() || timeout > MAX_REMOTE_OPERATION_TIMEOUT {
        return Err(IpcError::MalformedRequest(
            "control timeout must be within 1..=3600000 milliseconds".into(),
        ));
    }
    Ok(timeout)
}

fn prune_pending_sessions(sessions: &mut BTreeMap<RemoteSessionId, HostedSession>, now: Instant) {
    sessions.retain(|_, session| match session.state {
        HostedSessionState::Pending { opened_at } => {
            now.saturating_duration_since(opened_at) <= PENDING_SESSION_TTL
        }
        HostedSessionState::Subscribed => true,
    });
}

fn allocate_session_id() -> Result<RemoteSessionId, IpcError> {
    let mut bytes = [0_u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|error| IpcError::Internal(error.to_string()))?;
    let mut encoded = String::with_capacity(40);
    encoded.push_str("session-");
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("String write");
    }
    RemoteSessionId::parse(encoded)
        .ok_or_else(|| IpcError::Internal("generated invalid session ID".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::control::{IdempotencyKey, UserCommand};

    fn enrolled_binding() -> AuthorityBinding {
        AuthorityBinding::new(
            crate::vortix_core::control::AuthorityEpoch(7),
            crate::vortix_core::privileged::BootScope::new([1; 16]),
            crate::vortix_core::privileged::LeaseId::new([2; 32]),
            crate::vortix_core::privileged::OperationDigest::of_bytes(b"enrolled daemon"),
        )
        .unwrap()
    }

    fn hosted_authority() -> ControlAuthorityHost {
        ControlAuthorityHost::new_for_test(
            crate::vortix_core::control::ControlService::start(
                crate::vortix_core::control::ControlServiceConfig {
                    authority_epoch: crate::vortix_core::control::AuthorityEpoch(7),
                    ..crate::vortix_core::control::ControlServiceConfig::default()
                },
            ),
            enrolled_binding(),
        )
    }

    fn opened_session(result: IpcResult) -> RemoteSessionId {
        let IpcResult::ControlOpened { session_id, .. } = result else {
            panic!("authority must return a control session");
        };
        session_id
    }

    #[tokio::test]
    async fn enrolled_host_shares_one_canonical_service_across_remote_sessions() {
        let authority = hosted_authority();
        assert_eq!(authority.authority_binding(), enrolled_binding());
        let first = opened_session(authority.open_session().unwrap());
        let second = opened_session(authority.open_session().unwrap());
        let (_first_events, first_boundary) = authority.subscribe(&first).unwrap();
        let (_second_events, second_boundary) = authority.subscribe(&second).unwrap();
        assert_eq!(first_boundary.generation, second_boundary.generation);

        let accepted = authority
            .dispatch(IpcOp::ControlSubmit {
                session_id: first,
                command: UserCommand::Disconnect { profile_id: None },
                idempotency_key: IdempotencyKey::new("shared-service"),
                timeout_millis: 1_000,
            })
            .await
            .unwrap();
        assert!(matches!(accepted, IpcResult::ControlAccepted { .. }));

        let IpcResult::ControlSnapshot { snapshot } = authority
            .dispatch(IpcOp::ControlSnapshot { session_id: second })
            .await
            .unwrap()
        else {
            panic!("second session must read the canonical snapshot");
        };
        assert!(snapshot.generation > second_boundary.generation);
        assert_eq!(
            snapshot.desired.authority_epoch,
            enrolled_binding().authority_epoch()
        );
    }

    #[tokio::test]
    async fn hosted_session_must_subscribe_before_mutation() {
        let authority = hosted_authority();
        let session_id = opened_session(authority.open_session().unwrap());
        assert!(matches!(
            authority
                .dispatch(IpcOp::ControlSubmit {
                    session_id,
                    command: UserCommand::Disconnect { profile_id: None },
                    idempotency_key: IdempotencyKey::new("not-subscribed"),
                    timeout_millis: 1_000,
                })
                .await,
            Err(IpcError::ControlSessionNotFound)
        ));
    }

    #[tokio::test]
    async fn readiness_distinguishes_starting_from_inconsistent_authority() {
        let authority = hosted_authority();
        assert_eq!(authority.unavailable_state(), None);
        authority
            .service
            .completer()
            .set_readiness(crate::vortix_core::control::AuthorityEpoch(7), false, true)
            .await
            .unwrap();
        assert_eq!(
            authority.unavailable_state(),
            Some(ControlAvailability::Starting)
        );
        authority
            .service
            .completer()
            .set_readiness(crate::vortix_core::control::AuthorityEpoch(7), true, false)
            .await
            .unwrap();
        assert_eq!(
            authority.unavailable_state(),
            Some(ControlAvailability::RecoveryRequired)
        );
    }
}
