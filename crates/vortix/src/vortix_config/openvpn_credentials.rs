//! Owner-bound storage for remembered `OpenVPN` username/password pairs.
//!
//! This module deliberately stores only reusable base credentials. One-shot
//! challenge and OTP values belong to the live control channel and never enter
//! this store.

use std::fmt;
use std::path::PathBuf;

use thiserror::Error;
use zeroize::Zeroizing;

use crate::constants::OPENVPN_AUTH_DIR;
use crate::vortix_core::profile::{unambiguous_legacy_artifact_key, ProfileId};

use super::control_state::{
    open_control_directory, open_owned_directory_at, write_owned_atomic_with_hook,
    AtomicWriteError, AtomicWriteStage, ControlDirectory, ControlStateError,
};

const MAX_AUTH_BYTES: u64 = 16 * 1024;

/// Reusable `OpenVPN` username/password values whose allocations are cleared on drop.
pub struct RememberedOpenVpnCredentials {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl RememberedOpenVpnCredentials {
    /// Construct a reusable credential pair accepted by `OpenVPN`'s line format.
    pub fn new(
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, CredentialStoreError> {
        let username = Zeroizing::new(username.into());
        let password = Zeroizing::new(password.into());
        validate_field(&username)?;
        validate_field(&password)?;
        let credentials = Self { username, password };
        if credentials.encoded_len() as u64 > MAX_AUTH_BYTES {
            return Err(CredentialStoreError::Capacity);
        }
        Ok(credentials)
    }

    /// The remembered username.
    #[must_use]
    pub fn username(&self) -> &str {
        self.username.as_str()
    }

    /// The remembered password.
    #[must_use]
    pub fn password(&self) -> &str {
        self.password.as_str()
    }

    fn encoded_len(&self) -> usize {
        self.username
            .len()
            .saturating_add(self.password.len())
            .saturating_add(2)
    }

    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut body = Zeroizing::new(Vec::with_capacity(self.encoded_len()));
        body.extend_from_slice(self.username.as_bytes());
        body.push(b'\n');
        body.extend_from_slice(self.password.as_bytes());
        body.push(b'\n');
        body
    }
}

impl fmt::Debug for RememberedOpenVpnCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RememberedOpenVpnCredentials")
            .field("username", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// Why a credential artifact was rejected without consuming or deleting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialArtifactIssue {
    UnsafeDirectory,
    Symlink,
    NotRegularFile,
    MultipleLinks,
    LoosePermissions,
    UnexpectedOwner,
    Empty,
    ChangedEntry,
}

impl fmt::Display for CredentialArtifactIssue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::UnsafeDirectory => "unsafe credential directory",
            Self::Symlink => "credential symlink",
            Self::NotRegularFile => "non-regular credential entry",
            Self::MultipleLinks => "multiply-linked credential file",
            Self::LoosePermissions => "loosely permissioned credential file",
            Self::UnexpectedOwner => "credential owner mismatch",
            Self::Empty => "empty credential file",
            Self::ChangedEntry => "credential entry changed during validation",
        };
        formatter.write_str(label)
    }
}

/// A redacted operation category for credential-store I/O failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialIoOperation {
    OpenDirectory,
    OpenEntry,
    Read,
    AdoptOwner,
    Replace,
    Clear,
}

/// Result of clearing one profile's remembered credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialClearOutcome {
    Cleared,
    NotFound,
}

impl fmt::Display for CredentialIoOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::OpenDirectory => "opening storage",
            Self::OpenEntry => "opening a record",
            Self::Read => "reading a record",
            Self::AdoptOwner => "normalizing ownership",
            Self::Replace => "replacing a record",
            Self::Clear => "clearing a record",
        })
    }
}

/// Typed, secret-free failures from the remembered-credential authority.
#[derive(Debug, Error)]
pub enum CredentialStoreError {
    #[error("remembered credential artifact was rejected: {0}")]
    UnsafeArtifact(CredentialArtifactIssue),
    #[error("remembered credentials must contain non-empty single-line values")]
    InvalidCredentials,
    #[error("remembered credential record exceeds its fixed capacity")]
    Capacity,
    #[error("remembered credential record is malformed")]
    Malformed,
    #[error("remembered credential store I/O failed while {operation}")]
    Io {
        operation: CredentialIoOperation,
        #[source]
        source: std::io::Error,
    },
    #[error("remembered credentials were published, but disk durability could not be confirmed")]
    DurabilityUncertain,
    #[error("remembered credential storage is unsupported on this platform")]
    Unsupported,
}

/// Whether this authority may repair the exact root-owned artifact emitted by
/// the affected sudo writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootOwnedCredentialAdoption {
    Disabled,
    StandardAuthority,
}

/// Filesystem-backed remembered `OpenVPN` credential authority.
#[derive(Debug, Clone)]
pub struct FsOpenVpnCredentialStore {
    config_directory: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
    root_adoption: RootOwnedCredentialAdoption,
}

impl FsOpenVpnCredentialStore {
    /// Construct an owner-bound store. Root-owned compatibility artifacts are
    /// intentionally unavailable through this unprivileged/background-safe path.
    #[must_use]
    pub fn for_owner(config_directory: impl Into<PathBuf>, uid: u32, gid: u32) -> Self {
        Self {
            config_directory: config_directory.into(),
            expected_uid: uid,
            expected_gid: gid,
            root_adoption: RootOwnedCredentialAdoption::Disabled,
        }
    }

    /// Construct the Standard-mode authority. Adoption still requires the
    /// effective process UID to be root at the moment the record is inspected.
    #[must_use]
    pub fn for_standard_owner(config_directory: impl Into<PathBuf>, uid: u32, gid: u32) -> Self {
        Self {
            config_directory: config_directory.into(),
            expected_uid: uid,
            expected_gid: gid,
            root_adoption: RootOwnedCredentialAdoption::StandardAuthority,
        }
    }

    /// Load a stable-ID record, falling back only to a lossless legacy key.
    pub fn load(
        &self,
        profile_id: &ProfileId,
        legacy_display_name: &str,
    ) -> Result<Option<RememberedOpenVpnCredentials>, CredentialStoreError> {
        let Some(directory) = self.auth_directory(false)? else {
            return Ok(None);
        };
        if let Some(opened) = self.open_entry(&directory, profile_id.as_str(), true)? {
            return Ok(Some(opened.credentials));
        }
        let Some(legacy_key) = legacy_artifact_key(legacy_display_name) else {
            return Ok(None);
        };
        if legacy_key == profile_id.as_str() {
            return Ok(None);
        }
        self.open_entry(&directory, legacy_key, false)
            .map(|opened| opened.map(|entry| entry.credentials))
    }

    /// Atomically replace the stable-ID credential record without first
    /// deleting the previous valid generation.
    pub fn replace(
        &self,
        profile_id: &ProfileId,
        credentials: &RememberedOpenVpnCredentials,
    ) -> Result<(), CredentialStoreError> {
        self.replace_with_stage_hook(profile_id, credentials, |_, _| Ok(()))
    }

    /// Remove the stable record and its lossless legacy fallback. Legacy is
    /// removed first so an interrupted clear cannot resurrect it after the
    /// stable record disappears.
    pub fn clear(
        &self,
        profile_id: &ProfileId,
        legacy_display_name: &str,
    ) -> Result<CredentialClearOutcome, CredentialStoreError> {
        let Some(directory) = self.auth_directory(false)? else {
            return Ok(CredentialClearOutcome::NotFound);
        };
        let mut changed = false;
        if let Some(legacy_key) =
            legacy_artifact_key(legacy_display_name).filter(|key| *key != profile_id.as_str())
        {
            changed |= self.clear_entry(&directory, legacy_key, false)?;
        }
        changed |= self.clear_entry(&directory, profile_id.as_str(), true)?;
        if !changed {
            return Ok(CredentialClearOutcome::NotFound);
        }
        directory
            .sync_all()
            .map_err(|_| CredentialStoreError::DurabilityUncertain)?;
        Ok(CredentialClearOutcome::Cleared)
    }

    fn replace_with_stage_hook(
        &self,
        profile_id: &ProfileId,
        credentials: &RememberedOpenVpnCredentials,
        mut stage_hook: impl FnMut(
            AtomicWriteStage,
            Option<&std::fs::File>,
        ) -> Result<(), ControlStateError>,
    ) -> Result<(), CredentialStoreError> {
        let directory = self
            .auth_directory(true)?
            .ok_or(CredentialStoreError::UnsafeArtifact(
                CredentialArtifactIssue::UnsafeDirectory,
            ))?;
        let name = format!("{}.auth", profile_id.as_str());
        let expected = self
            .open_entry(&directory, profile_id.as_str(), true)?
            .map(|entry| entry.identity);
        let body = credentials.encode();
        let changed = std::cell::Cell::new(false);
        let result = write_owned_atomic_with_hook(
            &directory,
            &name,
            &body,
            self.expected_uid,
            self.expected_gid,
            |stage, temporary| {
                stage_hook(stage, temporary)?;
                if stage == AtomicWriteStage::Publish
                    && !entry_matches(&directory, &name, expected)?
                {
                    changed.set(true);
                    return Err(ControlStateError::UnsafeFile);
                }
                Ok(())
            },
        );
        if changed.get() {
            return Err(CredentialStoreError::UnsafeArtifact(
                CredentialArtifactIssue::ChangedEntry,
            ));
        }
        match result {
            Ok(()) => Ok(()),
            Err(AtomicWriteError::NotPublished(error)) => {
                Err(map_control_error(error, CredentialIoOperation::Replace))
            }
            Err(AtomicWriteError::PublishedButDirectoryUnsynced(_)) => {
                Err(CredentialStoreError::DurabilityUncertain)
            }
        }
    }

    fn auth_directory(
        &self,
        create: bool,
    ) -> Result<Option<ControlDirectory>, CredentialStoreError> {
        let config = open_control_directory(
            &self.config_directory,
            false,
            self.expected_uid,
            self.expected_gid,
        )
        .map_err(|error| map_control_error(error, CredentialIoOperation::OpenDirectory))?
        .ok_or(CredentialStoreError::UnsafeArtifact(
            CredentialArtifactIssue::UnsafeDirectory,
        ))?;
        let directory = open_owned_directory_at(
            &config,
            OPENVPN_AUTH_DIR,
            create,
            self.expected_uid,
            self.expected_gid,
        )
        .map_err(|error| map_control_error(error, CredentialIoOperation::OpenDirectory))?;
        if let Some(directory) = directory.as_ref() {
            normalize_private_directory(directory, self.expected_uid)?;
        }
        Ok(directory)
    }

    #[cfg(unix)]
    #[allow(unsafe_code)]
    fn open_entry(
        &self,
        directory: &ControlDirectory,
        key: &str,
        canonical_stable_id: bool,
    ) -> Result<Option<OpenedCredential>, CredentialStoreError> {
        use std::ffi::CString;
        use std::io::Read as _;
        use std::os::fd::{AsRawFd as _, FromRawFd as _};

        validate_artifact_key(key)?;
        let name = format!("{key}.auth");
        let c_name = CString::new(name.as_str()).map_err(|_| {
            CredentialStoreError::UnsafeArtifact(CredentialArtifactIssue::ChangedEntry)
        })?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let source = std::io::Error::last_os_error();
            return match source.raw_os_error() {
                Some(libc::ENOENT) => Ok(None),
                Some(libc::ELOOP) => Err(CredentialStoreError::UnsafeArtifact(
                    CredentialArtifactIssue::Symlink,
                )),
                _ => Err(CredentialStoreError::Io {
                    operation: CredentialIoOperation::OpenEntry,
                    source,
                }),
            };
        }
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|source| CredentialStoreError::Io {
            operation: CredentialIoOperation::OpenEntry,
            source,
        })?;
        let facts = EntryFacts::from_metadata(&metadata);
        let action = classify_entry(
            facts,
            self.expected_uid,
            self.expected_gid,
            canonical_stable_id,
            self.root_adoption,
            effective_owner(),
        )?;
        let identity = EntryIdentity::from_metadata(&metadata);
        let capacity =
            usize::try_from(metadata.len()).map_err(|_| CredentialStoreError::Capacity)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
        file.by_ref()
            .take(MAX_AUTH_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| CredentialStoreError::Io {
                operation: CredentialIoOperation::Read,
                source,
            })?;
        if bytes.len() as u64 > MAX_AUTH_BYTES {
            return Err(CredentialStoreError::Capacity);
        }
        let credentials = decode_credentials(&bytes)?;
        if action == EntryAction::AdoptRoot {
            if bytes.as_slice() != credentials.encode().as_slice() {
                return Err(CredentialStoreError::Malformed);
            }
            if !entry_matches(directory, &name, Some(identity))
                .map_err(|error| map_control_error(error, CredentialIoOperation::OpenEntry))?
            {
                return Err(CredentialStoreError::UnsafeArtifact(
                    CredentialArtifactIssue::ChangedEntry,
                ));
            }
            adopt_descriptor(&file, self.expected_uid, self.expected_gid)?;
            if !entry_matches(directory, &name, Some(identity))
                .map_err(|error| map_control_error(error, CredentialIoOperation::OpenEntry))?
            {
                return Err(CredentialStoreError::UnsafeArtifact(
                    CredentialArtifactIssue::ChangedEntry,
                ));
            }
        }
        Ok(Some(OpenedCredential {
            credentials,
            identity,
        }))
    }

    #[cfg(not(unix))]
    fn open_entry(
        &self,
        _directory: &ControlDirectory,
        _key: &str,
        _canonical_stable_id: bool,
    ) -> Result<Option<OpenedCredential>, CredentialStoreError> {
        Err(CredentialStoreError::Unsupported)
    }

    #[cfg(unix)]
    #[allow(unsafe_code)]
    fn clear_entry(
        &self,
        directory: &ControlDirectory,
        key: &str,
        canonical_stable_id: bool,
    ) -> Result<bool, CredentialStoreError> {
        use std::ffi::CString;
        use std::os::fd::AsRawFd as _;

        let Some(opened) = self.open_entry(directory, key, canonical_stable_id)? else {
            return Ok(false);
        };
        let name = format!("{key}.auth");
        if !entry_matches(directory, &name, Some(opened.identity))
            .map_err(|error| map_control_error(error, CredentialIoOperation::Clear))?
        {
            return Err(CredentialStoreError::UnsafeArtifact(
                CredentialArtifactIssue::ChangedEntry,
            ));
        }
        let c_name = CString::new(name).map_err(|_| {
            CredentialStoreError::UnsafeArtifact(CredentialArtifactIssue::ChangedEntry)
        })?;
        if unsafe { libc::unlinkat(directory.as_raw_fd(), c_name.as_ptr(), 0) } != 0 {
            return Err(CredentialStoreError::Io {
                operation: CredentialIoOperation::Clear,
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(true)
    }

    #[cfg(not(unix))]
    fn clear_entry(
        &self,
        _directory: &ControlDirectory,
        _key: &str,
        _canonical_stable_id: bool,
    ) -> Result<bool, CredentialStoreError> {
        Err(CredentialStoreError::Unsupported)
    }
}

struct OpenedCredential {
    credentials: RememberedOpenVpnCredentials,
    identity: EntryIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EntryIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl EntryIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[cfg(not(unix))]
impl EntryIdentity {
    fn from_metadata(_metadata: &std::fs::Metadata) -> Self {
        Self {
            device: 0,
            inode: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct EntryFacts {
    regular: bool,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    len: u64,
}

#[cfg(unix)]
impl EntryFacts {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            regular: metadata.is_file(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode() & 0o777,
            links: metadata.nlink(),
            len: metadata.len(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryAction {
    ReadOwned,
    AdoptRoot,
}

#[allow(clippy::similar_names)]
fn classify_entry(
    facts: EntryFacts,
    expected_uid: u32,
    expected_gid: u32,
    canonical_stable_id: bool,
    adoption: RootOwnedCredentialAdoption,
    effective_owner: (u32, u32),
) -> Result<EntryAction, CredentialStoreError> {
    if !facts.regular {
        return Err(CredentialStoreError::UnsafeArtifact(
            CredentialArtifactIssue::NotRegularFile,
        ));
    }
    if facts.links != 1 {
        return Err(CredentialStoreError::UnsafeArtifact(
            CredentialArtifactIssue::MultipleLinks,
        ));
    }
    if facts.mode != 0o600 {
        return Err(CredentialStoreError::UnsafeArtifact(
            CredentialArtifactIssue::LoosePermissions,
        ));
    }
    if facts.len == 0 {
        return Err(CredentialStoreError::UnsafeArtifact(
            CredentialArtifactIssue::Empty,
        ));
    }
    if facts.len > MAX_AUTH_BYTES {
        return Err(CredentialStoreError::Capacity);
    }
    if facts.uid == expected_uid {
        return Ok(EntryAction::ReadOwned);
    }
    if facts.uid == 0
        && (facts.gid == expected_gid || facts.gid == effective_owner.1)
        && expected_uid != 0
        && canonical_stable_id
        && adoption == RootOwnedCredentialAdoption::StandardAuthority
        && effective_owner.0 == 0
    {
        return Ok(EntryAction::AdoptRoot);
    }
    Err(CredentialStoreError::UnsafeArtifact(
        CredentialArtifactIssue::UnexpectedOwner,
    ))
}

fn legacy_artifact_key(display_name: &str) -> Option<&str> {
    let key = unambiguous_legacy_artifact_key(display_name)?;
    ProfileId::parse(key.to_owned()).is_err().then_some(key)
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn normalize_private_directory(
    directory: &ControlDirectory,
    expected_uid: u32,
) -> Result<(), CredentialStoreError> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = directory
        .metadata()
        .map_err(|source| CredentialStoreError::Io {
            operation: CredentialIoOperation::OpenDirectory,
            source,
        })?;
    if metadata.uid() != expected_uid {
        return Err(CredentialStoreError::UnsafeArtifact(
            CredentialArtifactIssue::UnsafeDirectory,
        ));
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
            return Err(CredentialStoreError::Io {
                operation: CredentialIoOperation::OpenDirectory,
                source: std::io::Error::last_os_error(),
            });
        }
        directory
            .sync_all()
            .map_err(|source| CredentialStoreError::Io {
                operation: CredentialIoOperation::OpenDirectory,
                source,
            })?;
    }
    let metadata = directory
        .metadata()
        .map_err(|source| CredentialStoreError::Io {
            operation: CredentialIoOperation::OpenDirectory,
            source,
        })?;
    if metadata.uid() != expected_uid || metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(CredentialStoreError::UnsafeArtifact(
            CredentialArtifactIssue::UnsafeDirectory,
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn normalize_private_directory(
    _directory: &ControlDirectory,
    _expected_uid: u32,
) -> Result<(), CredentialStoreError> {
    Ok(())
}

fn validate_field(value: &str) -> Result<(), CredentialStoreError> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| matches!(byte, b'\n' | b'\r' | b'\0'))
    {
        Err(CredentialStoreError::InvalidCredentials)
    } else {
        Ok(())
    }
}

fn decode_credentials(body: &[u8]) -> Result<RememberedOpenVpnCredentials, CredentialStoreError> {
    let text = std::str::from_utf8(body).map_err(|_| CredentialStoreError::Malformed)?;
    let body = text.strip_suffix('\n').unwrap_or(text);
    let mut lines = body.split('\n');
    let username = lines.next().unwrap_or_default();
    let password = lines.next().unwrap_or_default();
    if lines.next().is_some() {
        return Err(CredentialStoreError::Malformed);
    }
    RememberedOpenVpnCredentials::new(username, password)
        .map_err(|_| CredentialStoreError::Malformed)
}

fn validate_artifact_key(key: &str) -> Result<(), CredentialStoreError> {
    crate::utils::validate_openvpn_artifact_key(key)
        .map_err(|_| CredentialStoreError::UnsafeArtifact(CredentialArtifactIssue::ChangedEntry))
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn adopt_descriptor(file: &std::fs::File, uid: u32, gid: u32) -> Result<(), CredentialStoreError> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::MetadataExt as _;

    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0
        || unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0
    {
        return Err(CredentialStoreError::Io {
            operation: CredentialIoOperation::AdoptOwner,
            source: std::io::Error::last_os_error(),
        });
    }
    file.sync_all().map_err(|source| CredentialStoreError::Io {
        operation: CredentialIoOperation::AdoptOwner,
        source,
    })?;
    let metadata = file.metadata().map_err(|source| CredentialStoreError::Io {
        operation: CredentialIoOperation::AdoptOwner,
        source,
    })?;
    if metadata.uid() != uid || metadata.gid() != gid || metadata.mode() & 0o777 != 0o600 {
        return Err(CredentialStoreError::UnsafeArtifact(
            CredentialArtifactIssue::UnexpectedOwner,
        ));
    }
    Ok(())
}

#[cfg(unix)]
#[allow(unsafe_code)]
#[allow(clippy::cast_sign_loss, clippy::unnecessary_cast)]
fn entry_matches(
    directory: &ControlDirectory,
    name: &str,
    expected: Option<EntryIdentity>,
) -> Result<bool, ControlStateError> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd as _;

    let name = CString::new(name).map_err(|_| ControlStateError::UnsafeFile)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(expected.is_none())
        } else {
            Err(error.into())
        };
    }
    let stat = unsafe { stat.assume_init() };
    Ok(expected.is_some_and(|identity| {
        stat.st_dev as u64 == identity.device && stat.st_ino as u64 == identity.inode
    }))
}

#[cfg(not(unix))]
fn entry_matches(
    _directory: &ControlDirectory,
    _name: &str,
    _expected: Option<EntryIdentity>,
) -> Result<bool, ControlStateError> {
    Err(ControlStateError::UnsafeFile)
}

fn map_control_error(
    error: ControlStateError,
    operation: CredentialIoOperation,
) -> CredentialStoreError {
    match error {
        ControlStateError::UnsafeFile => {
            CredentialStoreError::UnsafeArtifact(CredentialArtifactIssue::UnsafeDirectory)
        }
        ControlStateError::Capacity => CredentialStoreError::Capacity,
        ControlStateError::Io(source) => CredentialStoreError::Io { operation, source },
        ControlStateError::UnsupportedSchema(_)
        | ControlStateError::Invalid(_)
        | ControlStateError::Corrupt
        | ControlStateError::Json(_) => CredentialStoreError::Io {
            operation,
            source: std::io::Error::other("owner-bound filesystem operation failed"),
        },
    }
}

#[cfg(unix)]
fn effective_owner() -> (u32, u32) {
    crate::utils::effective_user_group_ids()
}

#[cfg(not(unix))]
const fn effective_owner() -> (u32, u32) {
    (u32::MAX, u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_errors_do_not_render_credential_values() {
        let credentials =
            RememberedOpenVpnCredentials::new("private-user", "private-pass").unwrap();
        let rendered = format!("{credentials:?}");
        assert!(!rendered.contains("private-user"));
        assert!(!rendered.contains("private-pass"));
    }

    #[test]
    fn root_adoption_requires_every_standard_authority_condition() {
        let safe_root = EntryFacts {
            regular: true,
            uid: 0,
            gid: 20,
            mode: 0o600,
            links: 1,
            len: 12,
        };
        assert_eq!(
            classify_entry(
                safe_root,
                501,
                20,
                true,
                RootOwnedCredentialAdoption::StandardAuthority,
                (0, 0),
            )
            .unwrap(),
            EntryAction::AdoptRoot
        );
        for (stable, mode, effective) in [
            (
                false,
                RootOwnedCredentialAdoption::StandardAuthority,
                (0, 0),
            ),
            (true, RootOwnedCredentialAdoption::Disabled, (0, 0)),
            (
                true,
                RootOwnedCredentialAdoption::StandardAuthority,
                (501, 20),
            ),
        ] {
            assert!(matches!(
                classify_entry(safe_root, 501, 20, stable, mode, effective),
                Err(CredentialStoreError::UnsafeArtifact(
                    CredentialArtifactIssue::UnexpectedOwner
                ))
            ));
        }
    }

    #[test]
    fn owner_written_record_does_not_depend_on_historical_group_id() {
        let facts = EntryFacts {
            regular: true,
            uid: 501,
            gid: 999,
            mode: 0o600,
            links: 1,
            len: 12,
        };
        assert_eq!(
            classify_entry(
                facts,
                501,
                20,
                true,
                RootOwnedCredentialAdoption::Disabled,
                (501, 20),
            )
            .unwrap(),
            EntryAction::ReadOwned
        );
    }

    #[test]
    fn unsafe_entry_shapes_have_specific_classifications() {
        let safe = EntryFacts {
            regular: true,
            uid: 501,
            gid: 20,
            mode: 0o600,
            links: 1,
            len: 12,
        };
        let cases = [
            (
                EntryFacts {
                    regular: false,
                    ..safe
                },
                CredentialArtifactIssue::NotRegularFile,
            ),
            (
                EntryFacts { links: 2, ..safe },
                CredentialArtifactIssue::MultipleLinks,
            ),
            (
                EntryFacts {
                    mode: 0o640,
                    ..safe
                },
                CredentialArtifactIssue::LoosePermissions,
            ),
            (
                EntryFacts { uid: 777, ..safe },
                CredentialArtifactIssue::UnexpectedOwner,
            ),
            (
                EntryFacts { len: 0, ..safe },
                CredentialArtifactIssue::Empty,
            ),
        ];
        for (facts, issue) in cases {
            assert!(matches!(
                classify_entry(
                    facts,
                    501,
                    20,
                    true,
                    RootOwnedCredentialAdoption::Disabled,
                    (501, 20),
                ),
                Err(CredentialStoreError::UnsafeArtifact(actual)) if actual == issue
            ));
        }
        assert!(matches!(
            classify_entry(
                EntryFacts {
                    len: MAX_AUTH_BYTES + 1,
                    ..safe
                },
                501,
                20,
                true,
                RootOwnedCredentialAdoption::Disabled,
                (501, 20),
            ),
            Err(CredentialStoreError::Capacity)
        ));
    }

    #[test]
    fn parser_rejects_extra_lines_and_values_that_could_store_an_otp() {
        assert!(matches!(
            decode_credentials(b"user\npass\n123456\n"),
            Err(CredentialStoreError::Malformed)
        ));
        assert!(matches!(
            RememberedOpenVpnCredentials::new("user\nother", "pass"),
            Err(CredentialStoreError::InvalidCredentials)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_hardlink_malformed_and_oversized_records_remain_untouched() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let (uid, gid) = crate::utils::effective_user_group_ids();
        let store = FsOpenVpnCredentialStore::for_owner(temp.path(), uid, gid);
        let auth = temp.path().join(OPENVPN_AUTH_DIR);
        std::fs::create_dir(&auth).unwrap();
        std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o700)).unwrap();

        let link_id = ProfileId::parse("1".repeat(ProfileId::HEX_LEN)).unwrap();
        let decoy = temp.path().join("decoy");
        std::fs::write(&decoy, b"user\npass\n").unwrap();
        symlink(&decoy, auth.join(format!("{link_id}.auth"))).unwrap();
        assert!(matches!(
            store.load(&link_id, "legacy"),
            Err(CredentialStoreError::UnsafeArtifact(
                CredentialArtifactIssue::Symlink
            ))
        ));
        assert_eq!(std::fs::read(&decoy).unwrap(), b"user\npass\n");

        let hard_id = ProfileId::parse("2".repeat(ProfileId::HEX_LEN)).unwrap();
        let hard_source = auth.join("hard-source.auth");
        std::fs::write(&hard_source, b"user\npass\n").unwrap();
        std::fs::set_permissions(&hard_source, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&hard_source, auth.join(format!("{hard_id}.auth"))).unwrap();
        assert!(matches!(
            store.load(&hard_id, "legacy"),
            Err(CredentialStoreError::UnsafeArtifact(
                CredentialArtifactIssue::MultipleLinks
            ))
        ));
        assert!(hard_source.exists());

        let malformed_id = ProfileId::parse("3".repeat(ProfileId::HEX_LEN)).unwrap();
        let malformed = auth.join(format!("{malformed_id}.auth"));
        std::fs::write(&malformed, b"user\npass\notp\n").unwrap();
        std::fs::set_permissions(&malformed, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            store.load(&malformed_id, "legacy"),
            Err(CredentialStoreError::Malformed)
        ));
        assert_eq!(std::fs::read(&malformed).unwrap(), b"user\npass\notp\n");

        let large_id = ProfileId::parse("4".repeat(ProfileId::HEX_LEN)).unwrap();
        let large = auth.join(format!("{large_id}.auth"));
        std::fs::write(
            &large,
            vec![b'x'; usize::try_from(MAX_AUTH_BYTES + 1).unwrap()],
        )
        .unwrap();
        std::fs::set_permissions(&large, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            store.load(&large_id, "legacy"),
            Err(CredentialStoreError::Capacity)
        ));
        assert_eq!(std::fs::metadata(&large).unwrap().len(), MAX_AUTH_BYTES + 1);
    }

    #[cfg(unix)]
    #[test]
    #[allow(unsafe_code)]
    fn fifo_entry_is_rejected_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let (uid, gid) = crate::utils::effective_user_group_ids();
        let store = FsOpenVpnCredentialStore::for_owner(temp.path(), uid, gid);
        let auth = temp.path().join(OPENVPN_AUTH_DIR);
        std::fs::create_dir(&auth).unwrap();
        std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o700)).unwrap();
        let profile = ProfileId::parse("5".repeat(ProfileId::HEX_LEN)).unwrap();
        let path = auth.join(format!("{profile}.auth"));
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);

        assert!(matches!(
            store.load(&profile, "legacy"),
            Err(CredentialStoreError::UnsafeArtifact(
                CredentialArtifactIssue::NotRegularFile
            ))
        ));
        assert!(matches!(
            store.clear(&profile, "legacy"),
            Err(CredentialStoreError::UnsafeArtifact(
                CredentialArtifactIssue::NotRegularFile
            ))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn stable_id_shaped_display_name_never_enters_legacy_namespace() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let (uid, gid) = crate::utils::effective_user_group_ids();
        let store = FsOpenVpnCredentialStore::for_owner(temp.path(), uid, gid);
        let first = ProfileId::parse("6".repeat(ProfileId::HEX_LEN)).unwrap();
        let second = ProfileId::parse("7".repeat(ProfileId::HEX_LEN)).unwrap();
        let credentials = RememberedOpenVpnCredentials::new("first-user", "first-pass").unwrap();
        store.replace(&first, &credentials).unwrap();

        assert!(store.load(&second, first.as_str()).unwrap().is_none());
        assert_eq!(
            store.clear(&second, first.as_str()).unwrap(),
            CredentialClearOutcome::NotFound
        );
        let retained = store.load(&first, "first").unwrap().unwrap();
        assert_eq!(retained.username(), "first-user");
    }

    #[cfg(unix)]
    #[test]
    fn existing_auth_directory_is_normalized_to_private_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let auth = temp.path().join(OPENVPN_AUTH_DIR);
        std::fs::create_dir(&auth).unwrap();
        std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (uid, gid) = crate::utils::effective_user_group_ids();
        let store = FsOpenVpnCredentialStore::for_owner(temp.path(), uid, gid);
        let profile = ProfileId::parse("8".repeat(ProfileId::HEX_LEN)).unwrap();

        assert!(store.load(&profile, "legacy").unwrap().is_none());
        assert_eq!(
            std::fs::metadata(auth).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[cfg(unix)]
    #[test]
    fn failed_replacement_keeps_the_previous_complete_record() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let (uid, gid) = crate::utils::effective_user_group_ids();
        let store = FsOpenVpnCredentialStore::for_owner(temp.path(), uid, gid);
        let profile = ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap();
        let old = RememberedOpenVpnCredentials::new("old-user", "old-pass").unwrap();
        let new = RememberedOpenVpnCredentials::new("new-user", "new-pass").unwrap();
        store.replace(&profile, &old).unwrap();

        let result = store.replace_with_stage_hook(&profile, &new, |stage, _| {
            if stage == AtomicWriteStage::Publish {
                return Err(ControlStateError::Io(std::io::Error::other(
                    "injected pre-publish failure",
                )));
            }
            Ok(())
        });

        assert!(result.is_err());
        let loaded = store.load(&profile, "legacy").unwrap().unwrap();
        assert_eq!(loaded.username(), "old-user");
        assert_eq!(loaded.password(), "old-pass");
    }

    #[cfg(unix)]
    #[test]
    fn every_atomic_stage_has_a_truthful_failure_outcome() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let (uid, gid) = crate::utils::effective_user_group_ids();
        let store = FsOpenVpnCredentialStore::for_owner(temp.path(), uid, gid);
        let old = RememberedOpenVpnCredentials::new("old-user", "old-pass").unwrap();
        let new = RememberedOpenVpnCredentials::new("new-user", "new-pass").unwrap();
        let before_publish = [
            AtomicWriteStage::Create,
            AtomicWriteStage::Write,
            AtomicWriteStage::FirstFileSync,
            AtomicWriteStage::OwnerPreparation,
            AtomicWriteStage::SecondFileSync,
            AtomicWriteStage::Publish,
        ];
        for (index, injected) in before_publish.into_iter().enumerate() {
            let profile = ProfileId::parse(format!("{index:064x}")).unwrap();
            for has_prior in [false, true] {
                if has_prior {
                    store.replace(&profile, &old).unwrap();
                }
                let result = store.replace_with_stage_hook(&profile, &new, |stage, _| {
                    if stage == injected {
                        return Err(ControlStateError::Io(std::io::Error::other(
                            "injected atomic stage failure",
                        )));
                    }
                    Ok(())
                });
                assert!(result.is_err(), "{injected:?} must fail");
                let retained = store.load(&profile, "legacy").unwrap();
                if has_prior {
                    let retained = retained.expect("prior record must remain visible");
                    assert_eq!(retained.username(), "old-user", "{injected:?}");
                    assert_eq!(retained.password(), "old-pass", "{injected:?}");
                } else {
                    assert!(retained.is_none(), "{injected:?}");
                }
                assert_no_atomic_temporary(&temp);
                store.clear(&profile, "legacy").unwrap();
            }
        }

        let profile = ProfileId::parse("9".repeat(ProfileId::HEX_LEN)).unwrap();
        store.replace(&profile, &old).unwrap();
        let result = store.replace_with_stage_hook(&profile, &new, |stage, _| {
            if stage == AtomicWriteStage::DirectorySync {
                return Err(ControlStateError::Io(std::io::Error::other(
                    "injected directory sync failure",
                )));
            }
            Ok(())
        });
        assert!(matches!(
            result,
            Err(CredentialStoreError::DurabilityUncertain)
        ));
        let published = store.load(&profile, "legacy").unwrap().unwrap();
        assert_eq!(published.username(), "new-user");

        assert_no_atomic_temporary(&temp);
    }

    #[cfg(unix)]
    fn assert_no_atomic_temporary(temp: &tempfile::TempDir) {
        let auth = temp.path().join(OPENVPN_AUTH_DIR);
        assert!(std::fs::read_dir(auth).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn changed_destination_is_not_overwritten_after_validation() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let (uid, gid) = crate::utils::effective_user_group_ids();
        let store = FsOpenVpnCredentialStore::for_owner(temp.path(), uid, gid);
        let profile = ProfileId::parse("b".repeat(ProfileId::HEX_LEN)).unwrap();
        let old = RememberedOpenVpnCredentials::new("old-user", "old-pass").unwrap();
        let new = RememberedOpenVpnCredentials::new("new-user", "new-pass").unwrap();
        store.replace(&profile, &old).unwrap();
        let path = temp
            .path()
            .join(OPENVPN_AUTH_DIR)
            .join(format!("{profile}.auth"));

        let result = store.replace_with_stage_hook(&profile, &new, |stage, _| {
            if stage == AtomicWriteStage::Publish {
                std::fs::remove_file(&path).unwrap();
                std::fs::write(&path, b"changed-user\nchanged-pass\n").unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            Ok(())
        });

        assert!(matches!(
            result,
            Err(CredentialStoreError::UnsafeArtifact(
                CredentialArtifactIssue::ChangedEntry
            ))
        ));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"changed-user\nchanged-pass\n"
        );
    }
}
