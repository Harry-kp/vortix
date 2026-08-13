//! Fenced ownership metadata shared by Standard and Background authorities.
#![allow(
    dead_code,
    reason = "U13 lands the fenced store before the final verified activation commit"
)]

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::control_state::{
    open_control_directory, prepare_created_descriptor, read_owned_entry, write_owned_atomic,
    ControlStateError,
};
use crate::vortix_core::control::AuthorityEpoch;

const ENROLLMENT_SCHEMA_VERSION: u16 = 1;
const ENROLLMENT_FILE: &str = "enrollment.json";
const AUTHORITY_LOCK_FILE: &str = "authority.lock";
/// The existing local authority epoch is already live in durable Standard
/// state. Background reservations must begin strictly after it.
pub(crate) const STANDARD_AUTHORITY_EPOCH: AuthorityEpoch = AuthorityEpoch(1);

/// Durable enrollment phases. Persisted state selects a recovery path; it is
/// never sufficient evidence that a live daemon may mutate the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EnrollmentPhase {
    Unenrolled,
    Staged,
    CandidateReady,
    Enrolled,
    TakeoverPending,
}

/// Immutable identity of package-owned artifacts that passed staging
/// inspection. The root-owned bootstrap is responsible for producing these
/// values; persisting them does not turn them into live authority evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrollmentCandidate {
    manifest_generation: u64,
    manifest_digest: [u8; 32],
    daemon_version: String,
    helper_version: String,
}

impl EnrollmentCandidate {
    pub(crate) fn new(
        manifest_generation: u64,
        manifest_digest: [u8; 32],
        daemon_version: String,
        helper_version: String,
    ) -> Result<Self, EnrollmentError> {
        let candidate = Self {
            manifest_generation,
            manifest_digest,
            daemon_version,
            helper_version,
        };
        candidate.validate()?;
        Ok(candidate)
    }

    fn validate(&self) -> Result<(), EnrollmentError> {
        if self.manifest_generation == 0
            || self.manifest_digest == [0; 32]
            || !valid_version(&self.daemon_version)
            || !valid_version(&self.helper_version)
        {
            return Err(EnrollmentError::InvalidCandidate);
        }
        Ok(())
    }
}

fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 64
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}

/// Owner-authenticated, atomically replaced enrollment intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrollmentRecord {
    schema_version: u16,
    owner_uid: u32,
    generation: u64,
    phase: EnrollmentPhase,
    last_issued_epoch: AuthorityEpoch,
    reserved_epoch: Option<AuthorityEpoch>,
    active_epoch: Option<AuthorityEpoch>,
    candidate: Option<EnrollmentCandidate>,
}

impl EnrollmentRecord {
    fn unenrolled(owner_uid: u32) -> Self {
        Self {
            schema_version: ENROLLMENT_SCHEMA_VERSION,
            owner_uid,
            generation: 0,
            phase: EnrollmentPhase::Unenrolled,
            last_issued_epoch: STANDARD_AUTHORITY_EPOCH,
            reserved_epoch: None,
            active_epoch: None,
            candidate: None,
        }
    }

    fn validate(&self, expected_uid: u32) -> Result<(), EnrollmentError> {
        if self.schema_version != ENROLLMENT_SCHEMA_VERSION {
            return Err(EnrollmentError::UnsupportedSchema(self.schema_version));
        }
        if self.owner_uid != expected_uid {
            return Err(EnrollmentError::OwnerMismatch);
        }
        if let Some(candidate) = &self.candidate {
            candidate.validate()?;
        }
        let last = self.last_issued_epoch.0;
        if self
            .reserved_epoch
            .is_some_and(|epoch| epoch.0 == 0 || epoch.0 > last)
            || self
                .active_epoch
                .is_some_and(|epoch| epoch.0 == 0 || epoch.0 > last)
        {
            return Err(EnrollmentError::Corrupt);
        }
        let shape_is_valid = match self.phase {
            EnrollmentPhase::Unenrolled => {
                self.candidate.is_none()
                    && self.reserved_epoch.is_none()
                    && self.active_epoch.is_none()
            }
            EnrollmentPhase::Staged => {
                self.candidate.is_some()
                    && self.reserved_epoch.is_none()
                    && self.active_epoch.is_none()
            }
            EnrollmentPhase::CandidateReady => {
                self.candidate.is_some() && self.active_epoch.is_none()
            }
            EnrollmentPhase::Enrolled | EnrollmentPhase::TakeoverPending => {
                self.candidate.is_some()
                    && self.reserved_epoch.is_none()
                    && self.active_epoch.is_some()
            }
        };
        if !shape_is_valid {
            return Err(EnrollmentError::Corrupt);
        }
        Ok(())
    }

    #[must_use]
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub(crate) const fn phase(&self) -> EnrollmentPhase {
        self.phase
    }

    #[must_use]
    pub(crate) const fn last_issued_epoch(&self) -> AuthorityEpoch {
        self.last_issued_epoch
    }

    #[must_use]
    pub(crate) const fn reserved_epoch(&self) -> Option<AuthorityEpoch> {
        self.reserved_epoch
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorityKind {
    Standard,
    Background,
}

/// Kernel-released exclusive lease for the one canonical writer. The path
/// binding prevents a lease for one user's control directory from authorizing
/// writes to another.
#[derive(Debug)]
pub(crate) struct AuthorityLease {
    directory: PathBuf,
    kind: AuthorityKind,
    _file: std::fs::File,
}

#[derive(Debug, Clone)]
pub(crate) struct EnrollmentStore {
    directory: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
}

impl EnrollmentStore {
    #[must_use]
    pub(crate) fn new(directory: impl Into<PathBuf>) -> Self {
        let owner = crate::utils::effective_user_group_ids();
        Self::for_owner(directory, owner.0, owner.1)
    }

    #[must_use]
    #[allow(
        clippy::similar_names,
        reason = "uid and gid are the two independent authenticated owner facts"
    )]
    pub(crate) fn for_owner(
        directory: impl Into<PathBuf>,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Self {
        Self {
            directory: absolute(directory.into()),
            expected_uid,
            expected_gid,
        }
    }

    pub(crate) fn acquire_authority(
        &self,
        kind: AuthorityKind,
    ) -> Result<AuthorityLease, EnrollmentError> {
        let directory =
            open_control_directory(&self.directory, true, self.expected_uid, self.expected_gid)?
                .ok_or(EnrollmentError::Corrupt)?;
        let file = acquire_lock_file(
            &directory,
            self.expected_uid,
            self.expected_gid,
            AUTHORITY_LOCK_FILE,
        )?
        .ok_or(EnrollmentError::AuthorityBusy)?;
        Ok(AuthorityLease {
            directory: self.directory.clone(),
            kind,
            _file: file,
        })
    }

    /// Acquire Standard authority only while durable selection still names
    /// the local writer. An enrolled or takeover-pending record never falls
    /// back merely because the daemon is currently absent and its lock was
    /// released by a crash.
    pub(crate) fn acquire_standard_authority(&self) -> Result<AuthorityLease, EnrollmentError> {
        let lease = self.acquire_authority(AuthorityKind::Standard)?;
        let record = self.load()?;
        if matches!(
            record.phase,
            EnrollmentPhase::Enrolled | EnrollmentPhase::TakeoverPending
        ) {
            return Err(EnrollmentError::RemoteAuthoritySelected {
                phase: record.phase,
            });
        }
        Ok(lease)
    }

    pub(crate) fn load(&self) -> Result<EnrollmentRecord, EnrollmentError> {
        let Some(directory) =
            open_control_directory(&self.directory, false, self.expected_uid, self.expected_gid)?
        else {
            return Ok(EnrollmentRecord::unenrolled(self.expected_uid));
        };
        let Some(body) = read_owned_entry(&directory, ENROLLMENT_FILE, self.expected_uid)? else {
            return Ok(EnrollmentRecord::unenrolled(self.expected_uid));
        };
        let record: EnrollmentRecord =
            serde_json::from_slice(&body).map_err(|_| EnrollmentError::Corrupt)?;
        record.validate(self.expected_uid)?;
        Ok(record)
    }

    pub(crate) fn stage(
        &self,
        lease: &AuthorityLease,
        candidate: EnrollmentCandidate,
    ) -> Result<EnrollmentRecord, EnrollmentError> {
        self.require_lease(lease, AuthorityKind::Standard)?;
        candidate.validate()?;
        let current = self.load()?;
        if current.phase != EnrollmentPhase::Unenrolled {
            return Err(EnrollmentError::InvalidTransition {
                from: current.phase,
                to: EnrollmentPhase::Staged,
            });
        }
        let mut next = current;
        next.phase = EnrollmentPhase::Staged;
        next.candidate = Some(candidate);
        self.persist_next(next)
    }

    pub(crate) fn mark_candidate_ready(
        &self,
        lease: &AuthorityLease,
        expected_generation: u64,
    ) -> Result<EnrollmentRecord, EnrollmentError> {
        self.require_lease(lease, AuthorityKind::Standard)?;
        self.transition(expected_generation, EnrollmentPhase::Staged, |next| {
            next.phase = EnrollmentPhase::CandidateReady;
            Ok(())
        })
    }

    pub(crate) fn reserve_enrollment(
        &self,
        lease: &AuthorityLease,
        expected_generation: u64,
    ) -> Result<EnrollmentRecord, EnrollmentError> {
        self.require_lease(lease, AuthorityKind::Standard)?;
        self.transition(
            expected_generation,
            EnrollmentPhase::CandidateReady,
            |next| {
                if next.reserved_epoch.is_some() {
                    return Ok(());
                }
                let epoch = next
                    .last_issued_epoch
                    .0
                    .checked_add(1)
                    .filter(|epoch| *epoch != 0)
                    .ok_or(EnrollmentError::EpochExhausted)?;
                next.last_issued_epoch = AuthorityEpoch(epoch);
                next.reserved_epoch = Some(AuthorityEpoch(epoch));
                Ok(())
            },
        )
    }

    pub(crate) fn cancel_before_enrollment(
        &self,
        lease: &AuthorityLease,
        expected_generation: u64,
    ) -> Result<EnrollmentRecord, EnrollmentError> {
        self.require_lease(lease, AuthorityKind::Standard)?;
        let current = self.load()?;
        Self::require_generation(&current, expected_generation)?;
        if !matches!(
            current.phase,
            EnrollmentPhase::Staged | EnrollmentPhase::CandidateReady
        ) {
            return Err(EnrollmentError::InvalidTransition {
                from: current.phase,
                to: EnrollmentPhase::Unenrolled,
            });
        }
        let mut next = current;
        next.phase = EnrollmentPhase::Unenrolled;
        next.reserved_epoch = None;
        next.active_epoch = None;
        next.candidate = None;
        self.persist_next(next)
    }

    fn transition(
        &self,
        expected_generation: u64,
        expected_phase: EnrollmentPhase,
        mutate: impl FnOnce(&mut EnrollmentRecord) -> Result<(), EnrollmentError>,
    ) -> Result<EnrollmentRecord, EnrollmentError> {
        let mut current = self.load()?;
        Self::require_generation(&current, expected_generation)?;
        if current.phase != expected_phase {
            return Err(EnrollmentError::InvalidTransition {
                from: current.phase,
                to: expected_phase,
            });
        }
        mutate(&mut current)?;
        self.persist_next(current)
    }

    fn persist_next(
        &self,
        mut next: EnrollmentRecord,
    ) -> Result<EnrollmentRecord, EnrollmentError> {
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or(EnrollmentError::GenerationExhausted)?;
        next.validate(self.expected_uid)?;
        let body = serde_json::to_vec_pretty(&next).map_err(|_| EnrollmentError::Corrupt)?;
        let directory =
            open_control_directory(&self.directory, true, self.expected_uid, self.expected_gid)?
                .ok_or(EnrollmentError::Corrupt)?;
        write_owned_atomic(
            &directory,
            ENROLLMENT_FILE,
            &body,
            self.expected_uid,
            self.expected_gid,
        )?;
        Ok(next)
    }

    fn require_generation(
        current: &EnrollmentRecord,
        expected: u64,
    ) -> Result<(), EnrollmentError> {
        if current.generation != expected {
            return Err(EnrollmentError::GenerationConflict {
                expected,
                actual: current.generation,
            });
        }
        Ok(())
    }

    fn require_lease(
        &self,
        lease: &AuthorityLease,
        kind: AuthorityKind,
    ) -> Result<(), EnrollmentError> {
        if lease.directory != self.directory || lease.kind != kind {
            return Err(EnrollmentError::WrongAuthorityLease);
        }
        Ok(())
    }
}

fn absolute(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        std::env::current_dir().map_or(path.clone(), |current| current.join(path))
    }
}

/// Persisted phase can select remote-only recovery, but only a later live
/// verifier may mint the opaque mutation gate consumed by the remote client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteAuthorityDecision {
    NotSelected,
    AwaitingLiveProof,
}

impl RemoteAuthorityDecision {
    #[must_use]
    pub(crate) const fn from_persisted_phase(phase: EnrollmentPhase) -> Self {
        match phase {
            EnrollmentPhase::Unenrolled => Self::NotSelected,
            EnrollmentPhase::Staged
            | EnrollmentPhase::CandidateReady
            | EnrollmentPhase::Enrolled
            | EnrollmentPhase::TakeoverPending => Self::AwaitingLiveProof,
        }
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn acquire_lock_file(
    directory: &std::fs::File,
    uid: u32,
    gid: u32,
    name: &str,
) -> Result<Option<std::fs::File>, EnrollmentError> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let name = CString::new(name).map_err(|_| EnrollmentError::Corrupt)?;
    let (file, created) = loop {
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd >= 0 {
            break (unsafe { std::fs::File::from_raw_fd(fd) }, false);
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOENT) {
            return Err(error.into());
        }
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd >= 0 {
            break (unsafe { std::fs::File::from_raw_fd(fd) }, true);
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(error.into());
        }
    };
    if created {
        prepare_created_descriptor(&file, uid, gid, 0o600)?;
        file.sync_all()?;
        directory.sync_all()?;
    }
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(EnrollmentError::Corrupt);
    }
    let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if locked != 0 {
        let error = std::io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN)
        {
            return Ok(None);
        }
        return Err(error.into());
    }
    Ok(Some(file))
}

#[cfg(not(unix))]
fn acquire_lock_file(
    directory: &std::path::Path,
    _uid: u32,
    _gid: u32,
    name: &str,
) -> Result<Option<std::fs::File>, EnrollmentError> {
    // Background enrollment is unsupported on non-Unix targets, so there is
    // no competing remote writer. Retaining this descriptor still keeps the
    // Standard-mode call shape portable without pretending to enable U13.
    Ok(Some(
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join(name))?,
    ))
}

#[derive(Debug, Error)]
pub(crate) enum EnrollmentError {
    #[error("enrollment candidate identity is invalid")]
    InvalidCandidate,
    #[error("enrollment metadata is corrupt")]
    Corrupt,
    #[error("enrollment metadata belongs to a different owner")]
    OwnerMismatch,
    #[error("enrollment metadata has unsupported schema version {0}")]
    UnsupportedSchema(u16),
    #[error("another Vortix authority already owns the shared writer lease")]
    AuthorityBusy,
    #[error(
        "Background authority remains selected in {phase:?}; local mutation fallback is forbidden"
    )]
    RemoteAuthoritySelected { phase: EnrollmentPhase },
    #[error("the supplied authority lease does not own this transition")]
    WrongAuthorityLease,
    #[error(
        "enrollment state changed concurrently (expected generation {expected}, found {actual})"
    )]
    GenerationConflict { expected: u64, actual: u64 },
    #[error("invalid enrollment transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: EnrollmentPhase,
        to: EnrollmentPhase,
    },
    #[error("enrollment generation is exhausted")]
    GenerationExhausted,
    #[error("authority epoch is exhausted")]
    EpochExhausted,
    #[error("enrollment state storage failed: {0}")]
    State(#[from] ControlStateError),
    #[error("enrollment state I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn candidate() -> EnrollmentCandidate {
        EnrollmentCandidate::new(7, [0x41; 32], "0.4.3".into(), "0.4.3".into()).unwrap()
    }

    #[test]
    fn enrollment_reserves_monotonic_epochs_without_reuse() {
        let directory = tempdir().unwrap();
        let store = EnrollmentStore::new(directory.path().join("control"));
        let lease = store.acquire_authority(AuthorityKind::Standard).unwrap();

        let staged = store.stage(&lease, candidate()).unwrap();
        let ready = store
            .mark_candidate_ready(&lease, staged.generation())
            .unwrap();
        let first = store
            .reserve_enrollment(&lease, ready.generation())
            .unwrap();
        let first_epoch = first.reserved_epoch().unwrap();
        let rolled_back = store
            .cancel_before_enrollment(&lease, first.generation())
            .unwrap();
        let staged = store.stage(&lease, candidate()).unwrap();
        let ready = store
            .mark_candidate_ready(&lease, staged.generation())
            .unwrap();
        let second = store
            .reserve_enrollment(&lease, ready.generation())
            .unwrap();

        assert_eq!(first_epoch, AuthorityEpoch(2));
        assert_eq!(rolled_back.last_issued_epoch(), first_epoch);
        assert!(second.reserved_epoch().unwrap() > first_epoch);
    }

    #[test]
    fn interrupted_reserved_enrollment_resumes_exactly() {
        let directory = tempdir().unwrap();
        let store = EnrollmentStore::new(directory.path().join("control"));
        let lease = store.acquire_authority(AuthorityKind::Standard).unwrap();
        let staged = store.stage(&lease, candidate()).unwrap();
        let ready = store
            .mark_candidate_ready(&lease, staged.generation())
            .unwrap();
        let reserved = store
            .reserve_enrollment(&lease, ready.generation())
            .unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded, reserved);
        assert_eq!(loaded.phase(), EnrollmentPhase::CandidateReady);
        assert!(loaded.reserved_epoch().is_some());
    }

    #[test]
    fn stale_generation_cannot_commit_or_overwrite_newer_state() {
        let directory = tempdir().unwrap();
        let store = EnrollmentStore::new(directory.path().join("control"));
        let lease = store.acquire_authority(AuthorityKind::Standard).unwrap();
        let staged = store.stage(&lease, candidate()).unwrap();
        let ready = store
            .mark_candidate_ready(&lease, staged.generation())
            .unwrap();

        assert!(matches!(
            store.reserve_enrollment(&lease, staged.generation()),
            Err(EnrollmentError::GenerationConflict { .. })
        ));
        assert_eq!(store.load().unwrap(), ready);
    }

    #[cfg(unix)]
    #[test]
    fn shared_authority_lock_rejects_an_overlapping_writer() {
        let directory = tempdir().unwrap();
        let first = EnrollmentStore::new(directory.path().join("control"));
        let second = EnrollmentStore::new(directory.path().join("control"));
        let held = first.acquire_authority(AuthorityKind::Standard).unwrap();

        assert!(matches!(
            second.acquire_authority(AuthorityKind::Background),
            Err(EnrollmentError::AuthorityBusy)
        ));
        drop(held);
        second.acquire_authority(AuthorityKind::Background).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn existing_unsafe_authority_lock_is_rejected_not_repaired() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempdir().unwrap();
        let control = directory.path().join("control");
        std::fs::create_dir(&control).unwrap();
        std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o700)).unwrap();
        let lock = control.join(AUTHORITY_LOCK_FILE);
        std::fs::write(&lock, []).unwrap();
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o666)).unwrap();
        let store = EnrollmentStore::new(control);

        assert!(store.acquire_authority(AuthorityKind::Standard).is_err());
        assert_eq!(
            std::fs::metadata(lock).unwrap().permissions().mode() & 0o777,
            0o666
        );
    }

    #[test]
    fn persisted_enrolled_intent_is_not_live_authority_proof() {
        assert_eq!(
            RemoteAuthorityDecision::from_persisted_phase(EnrollmentPhase::Enrolled),
            RemoteAuthorityDecision::AwaitingLiveProof,
        );
    }

    #[test]
    fn enrolled_metadata_forbids_standard_fallback_when_daemon_is_absent() {
        let directory = tempdir().unwrap();
        let store = EnrollmentStore::new(directory.path().join("control"));
        let lease = store.acquire_standard_authority().unwrap();
        let staged = store.stage(&lease, candidate()).unwrap();
        let ready = store
            .mark_candidate_ready(&lease, staged.generation())
            .unwrap();
        let mut enrolled = store
            .reserve_enrollment(&lease, ready.generation())
            .unwrap();
        enrolled.phase = EnrollmentPhase::Enrolled;
        enrolled.active_epoch = enrolled.reserved_epoch.take();
        let enrolled = store.persist_next(enrolled).unwrap();
        drop(lease);

        assert!(matches!(
            store.acquire_standard_authority(),
            Err(EnrollmentError::RemoteAuthoritySelected {
                phase: EnrollmentPhase::Enrolled
            })
        ));
        assert_eq!(store.load().unwrap(), enrolled);
    }
}
