//! Dormant remote adapters for the canonical control service.
//!
//! U19 prepares the client-side command, snapshot, event, and challenge
//! contract without selecting it in production. [`RemoteMutationGate`] is
//! intentionally closed until the atomic enrollment cutover supplies a
//! verified authority token in U13. Standard mode therefore keeps its local
//! [`crate::vortix_core::control::ControlService`] as the only writer.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use thiserror::Error;

use crate::vortix_core::control::{
    AdmissionError, AdmittedOperation, ChallengeError, ChallengeId, ClientId, ControlEventEnvelope,
    ControlSnapshot, IdempotencyKey, OperationId, OperationResult, OperationStatus, Secret,
    UserCommand,
};
use crate::vortix_core::ipc::{IpcError, IpcOp, IpcResult, RemoteSessionId, SensitiveBytes};

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
