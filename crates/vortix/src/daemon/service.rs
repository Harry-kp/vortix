//! Dormant remote adapters for the canonical control service.
//!
//! U19 prepares the client-side command, snapshot, event, and challenge
//! contract without selecting it in production. [`RemoteMutationGate`] is
//! intentionally closed until the atomic enrollment cutover supplies a
//! verified authority token in U13. Standard mode therefore keeps its local
//! [`crate::vortix_core::control::ControlService`] as the only writer.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::vortix_core::control::{
    AdmissionError, AdmittedOperation, ChallengeError, ChallengeId, ClientId, CommandRequest,
    ControlEventEnvelope, ControlHandle, ControlService, ControlSnapshot, ControlSubscription,
    IdempotencyKey, OperationId, OperationResult, OperationStatus, Secret, UserCommand,
};
use crate::vortix_core::ipc::{IpcError, IpcOp, IpcResult, RemoteSessionId, SensitiveBytes};
use crate::vortix_core::profile::ProfileId;

const MAX_REMOTE_SESSIONS: usize = 64;
const PENDING_SESSION_TTL: Duration = Duration::from_secs(5);
const MAX_REMOTE_OPERATION_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Production activation is deliberately one-state in the preparatory
/// release. U13 replaces this closed gate only after enrollment is verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteMutationGate {
    Disabled,
}

impl RemoteMutationGate {
    #[must_use]
    pub const fn production() -> Self {
        Self::Disabled
    }

    pub const fn require_enabled(self) -> Result<(), RemoteControlError> {
        match self {
            Self::Disabled => Err(RemoteControlError::MutationDisabled),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RemoteControlError {
    #[error("remote mutation is unavailable until Background enrollment is atomically activated")]
    MutationDisabled,
    #[error("remote control daemon is unavailable: {0}")]
    Unavailable(String),
    #[error("remote control daemon is incompatible: {0}")]
    Incompatible(String),
    #[error("remote control protocol failed: {0}")]
    Protocol(String),
    #[error("remote control subscription lagged at generation {newest_generation}")]
    ResyncRequired { newest_generation: u64 },
    #[error("remote control admission failed: {0}")]
    Admission(AdmissionError),
    #[error("remote control challenge failed: {0}")]
    Challenge(ChallengeError),
    #[error("remote control session no longer exists")]
    SessionNotFound,
}

impl RemoteControlError {
    #[must_use]
    pub fn from_ipc(error: IpcError) -> Self {
        match error {
            IpcError::Incompatible { reason } => Self::Incompatible(reason),
            IpcError::CapabilityUnavailable { .. } => {
                Self::Incompatible("daemon does not advertise canonical control".into())
            }
            IpcError::ControlAdmission { error } => Self::Admission(error),
            IpcError::ControlChallenge { error } => Self::Challenge(error),
            IpcError::ControlSessionNotFound => Self::SessionNotFound,
            other => Self::Protocol(other.to_string()),
        }
    }
}

/// Result of consuming the final chunk of one memory-only remote import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StagedRemoteProfile {
    pub(crate) profile_id: ProfileId,
    pub(crate) display_name: String,
}

/// Daemon-owned profile staging seam. Implementations retain private bodies
/// only in memory until the canonical identity-only import command commits.
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

/// Bounded daemon-side owner of remote client capabilities. This type is not
/// wired into [`crate::daemon::DaemonServer`] until verified enrollment mints
/// the activation capability; constructing it alone cannot advertise or
/// execute remote mutation over the production socket.
pub(crate) struct ControlAuthorityHost {
    service: ControlService,
    sessions: Mutex<BTreeMap<RemoteSessionId, HostedSession>>,
    profile_stager: Option<Arc<dyn RemoteProfileStager>>,
}

impl ControlAuthorityHost {
    #[allow(
        dead_code,
        reason = "the verified enrollment constructor consumes this host in U13's final activation commit"
    )]
    pub(crate) fn new(
        service: ControlService,
        profile_stager: Option<Arc<dyn RemoteProfileStager>>,
    ) -> Self {
        Self {
            service,
            sessions: Mutex::new(BTreeMap::new()),
            profile_stager,
        }
    }

    pub(crate) fn open_session(&self) -> Result<IpcResult, IpcError> {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        prune_pending_sessions(&mut sessions, Instant::now());
        if sessions.len() >= MAX_REMOTE_SESSIONS {
            return Err(IpcError::ServerBusy);
        }
        let handle = self
            .service
            .new_client()
            .map_err(|error| IpcError::ControlAdmission { error })?;
        let client_id = handle.client_id().clone();
        let session_id = allocate_session_id(&sessions)?;
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
        if let Some(stager) = &self.profile_stager {
            stager.cancel(session_id);
        }
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
                let timeout = checked_remote_timeout(timeout_millis)?;
                let handle = self.subscribed_handle(&session_id)?;
                let admitted = handle
                    .submit(CommandRequest {
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
                let _ = self.subscribed_handle(&session_id)?;
                let backend = self.profile_stager.as_ref().ok_or_else(|| {
                    IpcError::Internal("remote profile staging is unavailable".into())
                })?;
                let contents = contents.into_vec();
                let chunk_len = contents.len();
                match backend.stage_chunk(
                    &session_id,
                    &file_name,
                    offset,
                    final_chunk,
                    SensitiveBytes::new(contents),
                )? {
                    Some(profile) if final_chunk => Ok(IpcResult::ControlProfileImportStaged {
                        profile_id: profile.profile_id,
                        display_name: profile.display_name,
                    }),
                    None if !final_chunk => Ok(IpcResult::ControlProfileImportChunkAccepted {
                        next_offset: offset.saturating_add(chunk_len as u64),
                    }),
                    _ => Err(IpcError::Internal(
                        "profile stager returned an invalid chunk outcome".into(),
                    )),
                }
            }
            IpcOp::ControlCancelProfileImport { session_id } => {
                let _ = self.subscribed_handle(&session_id)?;
                if let Some(stager) = &self.profile_stager {
                    stager.cancel(&session_id);
                }
                Ok(IpcResult::ChallengeAccepted)
            }
            other => Err(IpcError::MalformedRequest(format!(
                "operation is not a canonical control request: {other:?}"
            ))),
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

fn allocate_session_id(
    sessions: &BTreeMap<RemoteSessionId, HostedSession>,
) -> Result<RemoteSessionId, IpcError> {
    for _ in 0..8 {
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
        let id = RemoteSessionId::parse(encoded)
            .ok_or_else(|| IpcError::Internal("generated invalid session ID".into()))?;
        if !sessions.contains_key(&id) {
            return Ok(id);
        }
    }
    Err(IpcError::Internal(
        "could not allocate a unique control session".into(),
    ))
}

/// One canonical event plus the complete snapshot at its publication
/// boundary. Consumers replace their projection; they never replay deltas to
/// reconstruct control truth.
#[derive(Debug, Clone)]
pub struct RemoteControlUpdate {
    /// `None` is a semantic snapshot publication with no matching control
    /// event (for example, a fresh observation). Clients must still replace
    /// their projection at that boundary.
    pub event: Option<ControlEventEnvelope>,
    pub snapshot: ControlSnapshot,
}

#[derive(Debug, Clone)]
pub struct RemoteOperationOutcome {
    pub operation_id: OperationId,
    pub status: OperationStatus,
    pub result: Option<OperationResult>,
    pub snapshot: ControlSnapshot,
}

/// Blocking subscription owned by a background adapter worker.
pub trait RemoteControlSubscription: Send {
    fn try_recv(&mut self) -> Result<Option<RemoteControlUpdate>, RemoteControlError>;
}

/// Transport seam implemented by the Unix-socket client and parity fakes.
/// It carries only the public client capability: no observation, completion,
/// readiness, helper, or privileged mutation handle crosses this boundary.
pub trait RemoteControlTransport: Send + Sync + 'static {
    fn exchange(&self, op: IpcOp) -> Result<IpcResult, RemoteControlError>;

    fn subscribe(
        &self,
        session_id: &RemoteSessionId,
    ) -> Result<(Box<dyn RemoteControlSubscription>, ControlSnapshot), RemoteControlError>;
}

/// Remote counterpart of a local `ControlHandle`. Its constructor is exposed
/// only for parity fixtures; the production constructor always checks the
/// closed enrollment gate before opening a socket.
pub struct RemoteControlSession {
    transport: Arc<dyn RemoteControlTransport>,
    session_id: RemoteSessionId,
    client_id: ClientId,
    snapshot: Mutex<ControlSnapshot>,
    subscription: Mutex<Box<dyn RemoteControlSubscription>>,
    profile_stage: Mutex<()>,
}

impl std::fmt::Debug for RemoteControlSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteControlSession")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

impl RemoteControlSession {
    fn snapshot_guard(&self) -> std::sync::MutexGuard<'_, ControlSnapshot> {
        self.snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn subscription_guard(&self) -> std::sync::MutexGuard<'_, Box<dyn RemoteControlSubscription>> {
        self.subscription
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Production entry point. No socket or fallback is touched while the
    /// gate is closed.
    pub fn connect_production(
        gate: RemoteMutationGate,
        transport: Arc<dyn RemoteControlTransport>,
    ) -> Result<Self, RemoteControlError> {
        gate.require_enabled()?;
        Self::open(transport)
    }

    /// Fixture entry point used to prove local/remote parity without enabling
    /// production enrollment or performing kernel effects twice.
    #[doc(hidden)]
    pub fn open_for_parity(
        transport: Arc<dyn RemoteControlTransport>,
    ) -> Result<Self, RemoteControlError> {
        Self::open(transport)
    }

    fn open(transport: Arc<dyn RemoteControlTransport>) -> Result<Self, RemoteControlError> {
        let IpcResult::ControlOpened {
            session_id,
            client_id,
        } = transport.exchange(IpcOp::ControlOpen)?
        else {
            return Err(RemoteControlError::Protocol(
                "daemon returned a non-control open response".into(),
            ));
        };
        let (subscription, snapshot) = transport.subscribe(&session_id)?;
        Ok(Self {
            transport,
            session_id,
            client_id,
            snapshot: Mutex::new(snapshot),
            subscription: Mutex::new(subscription),
            profile_stage: Mutex::new(()),
        })
    }

    #[must_use]
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    pub fn submit(
        &self,
        command: UserCommand,
        timeout: Duration,
        idempotency_key: impl Into<String>,
    ) -> Result<AdmittedOperation, RemoteControlError> {
        let timeout_millis = timeout.as_millis().try_into().unwrap_or(u64::MAX);
        let result = self.transport.exchange(IpcOp::ControlSubmit {
            session_id: self.session_id.clone(),
            command,
            idempotency_key: IdempotencyKey::new(idempotency_key),
            timeout_millis,
        })?;
        match result {
            IpcResult::ControlAccepted { admitted } => Ok(admitted),
            other => Err(RemoteControlError::Protocol(format!(
                "daemon returned an invalid submit response: {other:?}"
            ))),
        }
    }

    pub fn refresh_snapshot(&self) -> Result<ControlSnapshot, RemoteControlError> {
        let result = self.transport.exchange(IpcOp::ControlSnapshot {
            session_id: self.session_id.clone(),
        })?;
        let IpcResult::ControlSnapshot { snapshot } = result else {
            return Err(RemoteControlError::Protocol(format!(
                "daemon returned an invalid snapshot response: {result:?}"
            )));
        };
        *self.snapshot_guard() = snapshot.clone();
        Ok(snapshot)
    }

    #[must_use]
    pub fn current_snapshot(&self) -> ControlSnapshot {
        self.snapshot_guard().clone()
    }

    /// Drain available complete event boundaries and return only the newest
    /// snapshot. This is the TUI's non-blocking tick seam.
    pub fn take_changed_snapshot(&self) -> Result<Option<ControlSnapshot>, RemoteControlError> {
        let mut newest = None;
        let mut subscription = self.subscription_guard();
        loop {
            match subscription.try_recv() {
                Ok(Some(update)) => newest = Some(update.snapshot),
                Ok(None) => break,
                Err(RemoteControlError::ResyncRequired { .. }) => {
                    let resubscribed = self.transport.subscribe(&self.session_id);
                    match resubscribed {
                        Ok((replacement, boundary)) => {
                            if let Some(drained) = newest
                                .as_ref()
                                .filter(|drained| boundary.generation < drained.generation)
                            {
                                *self.snapshot_guard() = drained.clone();
                                return Err(RemoteControlError::Protocol(format!(
                                    "control resubscribe boundary regressed from generation {} to {}",
                                    drained.generation, boundary.generation
                                )));
                            }
                            *subscription = replacement;
                            newest = Some(boundary);
                            break;
                        }
                        Err(error) => {
                            if let Some(snapshot) = &newest {
                                *self.snapshot_guard() = snapshot.clone();
                            }
                            return Err(error);
                        }
                    }
                }
                Err(error) => {
                    if let Some(snapshot) = &newest {
                        *self.snapshot_guard() = snapshot.clone();
                    }
                    return Err(error);
                }
            }
        }
        if let Some(snapshot) = &newest {
            *self.snapshot_guard() = snapshot.clone();
        }
        Ok(newest)
    }

    pub fn respond_challenge(
        &self,
        challenge_id: ChallengeId,
        answer: Secret,
    ) -> Result<(), RemoteControlError> {
        let result = self.transport.exchange(IpcOp::ControlRespondChallenge {
            session_id: self.session_id.clone(),
            challenge_id,
            answer: SensitiveBytes::new(answer.into_vec()),
        })?;
        match result {
            IpcResult::ChallengeAccepted => Ok(()),
            other => Err(RemoteControlError::Protocol(format!(
                "daemon returned an invalid challenge response: {other:?}"
            ))),
        }
    }

    pub fn cancel_challenge(&self, challenge_id: ChallengeId) -> Result<(), RemoteControlError> {
        let result = self.transport.exchange(IpcOp::ControlCancelChallenge {
            session_id: self.session_id.clone(),
            challenge_id,
        })?;
        match result {
            IpcResult::ChallengeAccepted => Ok(()),
            other => Err(RemoteControlError::Protocol(format!(
                "daemon returned an invalid challenge cancellation: {other:?}"
            ))),
        }
    }

    /// Stage a profile body without placing private configuration in the
    /// durable command/event/snapshot vocabulary.
    pub fn stage_profile_import(
        &self,
        path: &std::path::Path,
    ) -> Result<(crate::vortix_core::profile::ProfileId, String), RemoteControlError> {
        let _stage = self
            .profile_stage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let file_name = path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .filter(|name| !name.is_empty() && name.len() <= 255)
            .ok_or_else(|| RemoteControlError::Protocol("invalid profile file name".into()))?
            .to_owned();
        let mut file = std::fs::File::open(path)
            .map_err(|error| RemoteControlError::Protocol(error.to_string()))?;
        let metadata = file
            .metadata()
            .map_err(|error| RemoteControlError::Protocol(error.to_string()))?;
        if !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > crate::constants::MAX_CONFIG_SIZE_BYTES
        {
            return Err(RemoteControlError::Protocol(
                "profile body must be a regular file containing 1..=1048576 bytes".into(),
            ));
        }
        self.stage_profile_reader(&file_name, metadata.len(), &mut file)
    }

    fn stage_profile_reader<R: std::io::Read>(
        &self,
        file_name: &str,
        expected_len: u64,
        reader: &mut R,
    ) -> Result<(crate::vortix_core::profile::ProfileId, String), RemoteControlError> {
        const CHUNK_BYTES: usize = 64 * 1024;
        let mut offset = 0_u64;
        loop {
            let remaining = expected_len.saturating_sub(offset);
            let chunk_len = usize::try_from(remaining.min(CHUNK_BYTES as u64))
                .map_err(|error| RemoteControlError::Protocol(error.to_string()))?;
            let mut chunk = vec![0_u8; chunk_len];
            if let Err(error) = reader.read_exact(&mut chunk) {
                self.cancel_profile_stage();
                return Err(RemoteControlError::Protocol(
                    if error.kind() == std::io::ErrorKind::UnexpectedEof {
                        "profile changed while it was being staged".into()
                    } else {
                        error.to_string()
                    },
                ));
            }
            let next_offset = offset.saturating_add(chunk_len as u64);
            let final_chunk = next_offset == expected_len;
            if final_chunk {
                let mut extra = [0_u8; 1];
                loop {
                    match reader.read(&mut extra) {
                        Ok(0) => break,
                        Ok(_) => {
                            self.cancel_profile_stage();
                            return Err(RemoteControlError::Protocol(
                                "profile changed while it was being staged".into(),
                            ));
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(error) => {
                            self.cancel_profile_stage();
                            return Err(RemoteControlError::Protocol(error.to_string()));
                        }
                    }
                }
            }
            let result = self.transport.exchange(IpcOp::ControlStageProfileImport {
                session_id: self.session_id.clone(),
                file_name: file_name.to_owned(),
                offset,
                final_chunk,
                contents: SensitiveBytes::new(chunk),
            });
            match result {
                Ok(IpcResult::ControlProfileImportStaged {
                    profile_id,
                    display_name,
                }) if final_chunk => return Ok((profile_id, display_name)),
                Ok(IpcResult::ControlProfileImportChunkAccepted {
                    next_offset: accepted,
                }) if !final_chunk && accepted == next_offset => {
                    offset = next_offset;
                }
                Ok(other) => {
                    let error = RemoteControlError::Protocol(format!(
                        "daemon returned an invalid profile staging response: {other:?}"
                    ));
                    self.cancel_profile_stage();
                    return Err(error);
                }
                Err(error) => {
                    self.cancel_profile_stage();
                    return Err(error);
                }
            }
        }
    }

    fn cancel_profile_stage(&self) {
        let _ = self.transport.exchange(IpcOp::ControlCancelProfileImport {
            session_id: self.session_id.clone(),
        });
    }

    /// CLI one-shot adapter. It uses the same canonical operation/challenge
    /// records as the local client and never retries through a local writer.
    pub fn run_with_challenges<F>(
        &self,
        command: UserCommand,
        timeout: Duration,
        idempotency_key: impl Into<String>,
        mut answer_challenge: F,
    ) -> Result<RemoteOperationOutcome, RemoteControlError>
    where
        F: FnMut(
            &crate::vortix_core::control::ChallengeRecord,
        ) -> Result<Secret, RemoteControlError>,
    {
        let admitted = self.submit(command, timeout, idempotency_key)?;
        let wall_deadline = std::time::Instant::now() + timeout + Duration::from_secs(2);
        let mut handled = std::collections::BTreeSet::new();
        loop {
            let snapshot = self
                .take_changed_snapshot()?
                .unwrap_or_else(|| self.current_snapshot());
            let challenges = snapshot
                .challenges
                .values()
                .filter(|challenge| {
                    challenge.operation_id == admitted.operation_id
                        && challenge.authorized_client == self.client_id
                        && !handled.contains(&challenge.id)
                })
                .cloned()
                .collect::<Vec<_>>();
            for challenge in challenges {
                handled.insert(challenge.id);
                match answer_challenge(&challenge) {
                    Ok(answer) => self.respond_challenge(challenge.id, answer)?,
                    Err(error) => {
                        let _ = self.cancel_challenge(challenge.id);
                        return Err(error);
                    }
                }
            }
            if let Some(operation) = snapshot.operations.get(&admitted.operation_id) {
                if operation.status.is_terminal() {
                    return Ok(RemoteOperationOutcome {
                        operation_id: admitted.operation_id,
                        status: operation.status,
                        result: operation.result,
                        snapshot,
                    });
                }
            }
            if std::time::Instant::now() >= wall_deadline {
                return Err(RemoteControlError::Protocol(format!(
                    "operation {} did not reach a terminal snapshot before the client deadline",
                    admitted.operation_id
                )));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;

    fn hosted_authority() -> ControlAuthorityHost {
        let profile_id = ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap();
        let known_profiles = std::collections::BTreeSet::from([profile_id.clone()]);
        ControlAuthorityHost::new(
            ControlService::start(crate::vortix_core::control::ControlServiceConfig {
                known_profiles,
                profile_topologies: BTreeMap::from([(
                    profile_id,
                    crate::vortix_core::control::ProfileTopology::default(),
                )]),
                ..crate::vortix_core::control::ControlServiceConfig::default()
            }),
            None,
        )
    }

    fn opened_session(result: IpcResult) -> RemoteSessionId {
        let IpcResult::ControlOpened { session_id, .. } = result else {
            panic!("authority must return a control session");
        };
        session_id
    }

    #[tokio::test]
    async fn hosted_session_requires_subscription_and_dies_with_it() {
        let authority = hosted_authority();
        let session_id = opened_session(authority.open_session().unwrap());
        let command = UserCommand::Connect {
            profile_id: ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap(),
            conflict_acknowledgement: None,
        };
        let submit = |session_id: RemoteSessionId| IpcOp::ControlSubmit {
            session_id,
            command: command.clone(),
            idempotency_key: IdempotencyKey::new("hosted-session"),
            timeout_millis: 1_000,
        };

        assert!(matches!(
            authority.dispatch(submit(session_id.clone())).await,
            Err(IpcError::ControlSessionNotFound)
        ));
        let (_subscription, initial) = authority.subscribe(&session_id).unwrap();
        assert_eq!(
            initial.desired.authority_epoch,
            crate::vortix_core::control::AuthorityEpoch(0)
        );
        assert!(matches!(
            authority.dispatch(submit(session_id.clone())).await,
            Ok(IpcResult::ControlAccepted { .. })
        ));
        authority.close_session(&session_id);
        assert!(matches!(
            authority.dispatch(submit(session_id)).await,
            Err(IpcError::ControlSessionNotFound)
        ));
    }

    #[tokio::test]
    async fn hosted_sessions_are_bounded_before_allocating_clients() {
        let authority = hosted_authority();
        for _ in 0..MAX_REMOTE_SESSIONS {
            authority.open_session().unwrap();
        }
        assert!(matches!(
            authority.open_session(),
            Err(IpcError::ServerBusy)
        ));
    }

    struct EmptySubscription;

    impl RemoteControlSubscription for EmptySubscription {
        fn try_recv(&mut self) -> Result<Option<RemoteControlUpdate>, RemoteControlError> {
            Ok(None)
        }
    }

    struct GrowingProfileTransport {
        path: std::path::PathBuf,
        stage_calls: AtomicUsize,
        cancelled: AtomicBool,
    }

    struct ProfileChunkTransport {
        stage_calls: AtomicUsize,
        cancelled: AtomicBool,
    }

    impl RemoteControlTransport for ProfileChunkTransport {
        fn exchange(&self, op: IpcOp) -> Result<IpcResult, RemoteControlError> {
            match op {
                IpcOp::ControlOpen => Ok(IpcResult::ControlOpened {
                    session_id: RemoteSessionId::parse(format!("session-{}", "b".repeat(32)))
                        .unwrap(),
                    client_id: serde_json::from_str("\"client-0000000000000000-0000000000000001\"")
                        .unwrap(),
                }),
                IpcOp::ControlStageProfileImport {
                    offset,
                    final_chunk,
                    contents,
                    ..
                } => {
                    self.stage_calls.fetch_add(1, Ordering::SeqCst);
                    let next_offset = offset + contents.into_vec().len() as u64;
                    if final_chunk {
                        Ok(IpcResult::ControlProfileImportStaged {
                            profile_id: crate::vortix_core::profile::ProfileId::parse(
                                "b".repeat(crate::vortix_core::profile::ProfileId::HEX_LEN),
                            )
                            .unwrap(),
                            display_name: "short-read".into(),
                        })
                    } else {
                        Ok(IpcResult::ControlProfileImportChunkAccepted { next_offset })
                    }
                }
                IpcOp::ControlCancelProfileImport { .. } => {
                    self.cancelled.store(true, Ordering::SeqCst);
                    Ok(IpcResult::ChallengeAccepted)
                }
                other => Err(RemoteControlError::Protocol(format!(
                    "unexpected test operation: {other:?}"
                ))),
            }
        }

        fn subscribe(
            &self,
            _session_id: &RemoteSessionId,
        ) -> Result<(Box<dyn RemoteControlSubscription>, ControlSnapshot), RemoteControlError>
        {
            Ok((Box::new(EmptySubscription), ControlSnapshot::default()))
        }
    }

    struct ScriptedReader {
        bytes: Vec<u8>,
        position: usize,
        max_read: usize,
        fail_at: Option<usize>,
    }

    impl std::io::Read for ScriptedReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if self.fail_at.is_some_and(|fail_at| self.position >= fail_at) {
                return Err(std::io::Error::other("injected profile read failure"));
            }
            if self.position == self.bytes.len() {
                return Ok(0);
            }
            let until_failure = self
                .fail_at
                .map_or(usize::MAX, |fail_at| fail_at.saturating_sub(self.position));
            let count = output
                .len()
                .min(self.max_read)
                .min(self.bytes.len() - self.position)
                .min(until_failure);
            output[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
            self.position += count;
            Ok(count)
        }
    }

    impl RemoteControlTransport for GrowingProfileTransport {
        fn exchange(&self, op: IpcOp) -> Result<IpcResult, RemoteControlError> {
            match op {
                IpcOp::ControlOpen => Ok(IpcResult::ControlOpened {
                    session_id: RemoteSessionId::parse(format!("session-{}", "a".repeat(32)))
                        .unwrap(),
                    client_id: serde_json::from_str("\"client-0000000000000000-0000000000000001\"")
                        .unwrap(),
                }),
                IpcOp::ControlStageProfileImport {
                    offset, contents, ..
                } => {
                    let bytes = contents.into_vec();
                    if self.stage_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        std::fs::OpenOptions::new()
                            .append(true)
                            .open(&self.path)
                            .unwrap()
                            .write_all(b"grew")
                            .unwrap();
                    }
                    Ok(IpcResult::ControlProfileImportChunkAccepted {
                        next_offset: offset + bytes.len() as u64,
                    })
                }
                IpcOp::ControlCancelProfileImport { .. } => {
                    self.cancelled.store(true, Ordering::SeqCst);
                    Ok(IpcResult::ChallengeAccepted)
                }
                other => Err(RemoteControlError::Protocol(format!(
                    "unexpected test operation: {other:?}"
                ))),
            }
        }

        fn subscribe(
            &self,
            _session_id: &RemoteSessionId,
        ) -> Result<(Box<dyn RemoteControlSubscription>, ControlSnapshot), RemoteControlError>
        {
            Ok((Box::new(EmptySubscription), ControlSnapshot::default()))
        }
    }

    #[test]
    fn profile_growth_is_cancelled_before_the_final_chunk_is_accepted() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("growing.conf");
        std::fs::write(&path, vec![b'x'; 128 * 1024]).unwrap();
        let transport = Arc::new(GrowingProfileTransport {
            path: path.clone(),
            stage_calls: AtomicUsize::new(0),
            cancelled: AtomicBool::new(false),
        });
        let session = RemoteControlSession::open_for_parity(transport.clone()).unwrap();

        let error = session.stage_profile_import(&path).unwrap_err();

        assert!(error
            .to_string()
            .contains("changed while it was being staged"));
        assert_eq!(transport.stage_calls.load(Ordering::SeqCst), 1);
        assert!(transport.cancelled.load(Ordering::SeqCst));
    }

    #[test]
    fn profile_staging_accepts_legal_short_reads() {
        let transport = Arc::new(ProfileChunkTransport {
            stage_calls: AtomicUsize::new(0),
            cancelled: AtomicBool::new(false),
        });
        let session = RemoteControlSession::open_for_parity(transport.clone()).unwrap();
        let bytes = vec![b'x'; 70 * 1024];
        let mut reader = ScriptedReader {
            bytes,
            position: 0,
            max_read: 7,
            fail_at: None,
        };

        session
            .stage_profile_reader("short-read.conf", 70 * 1024, &mut reader)
            .unwrap();

        assert_eq!(transport.stage_calls.load(Ordering::SeqCst), 2);
        assert!(!transport.cancelled.load(Ordering::SeqCst));
    }

    #[test]
    fn profile_read_error_after_an_accepted_chunk_cancels_the_stage() {
        let transport = Arc::new(ProfileChunkTransport {
            stage_calls: AtomicUsize::new(0),
            cancelled: AtomicBool::new(false),
        });
        let session = RemoteControlSession::open_for_parity(transport.clone()).unwrap();
        let mut reader = ScriptedReader {
            bytes: vec![b'x'; 128 * 1024],
            position: 0,
            max_read: 4096,
            fail_at: Some(64 * 1024),
        };

        let error = session
            .stage_profile_reader("read-error.conf", 128 * 1024, &mut reader)
            .unwrap_err();

        assert!(error.to_string().contains("injected profile read failure"));
        assert_eq!(transport.stage_calls.load(Ordering::SeqCst), 1);
        assert!(transport.cancelled.load(Ordering::SeqCst));
    }
}
