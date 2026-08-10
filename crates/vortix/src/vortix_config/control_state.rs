//! Crash-safe user-owned canonical control intent.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::vortix_core::control::{
    BootConnection, ControlPersistenceConfig, ControlStateStore, ControlStateStoreError,
    DesiredState, DurableControlState, OperationId, OperationIntent, OperationRecord,
    OperationResult, OperationStatus, PersistedTombstone, RecoveredControlState,
    RequestedResources, RequestedTunnelState, RetentionMetadata,
};
use crate::vortix_core::profile::ProfileId;

const MIN_STATE_SCHEMA_VERSION: u16 = 1;
const STATE_SCHEMA_VERSION: u16 = 2;
const STATE_FILE: &str = "control-state.json";
const PREVIOUS_STATE_FILE: &str = "control-state.previous.json";
const ENDPOINT_CACHE_FILE: &str = "endpoint-resolutions.json";
const MAX_STATE_BYTES: u64 = 1024 * 1024;
const MAX_PROFILES: usize = 512;
const MAX_OPERATIONS: usize = 512;
const MAX_ROUTES_PER_PROFILE: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedControlState {
    schema_version: u16,
    boot_id: String,
    pub(crate) desired: DesiredState,
    pub(crate) operations: BTreeMap<OperationId, OperationRecord>,
    pub(crate) boot_connections: BTreeMap<ProfileId, BootConnection>,
    pub(crate) requested_resources: BTreeMap<ProfileId, RequestedResources>,
    pub(crate) tombstones: BTreeMap<ProfileId, PersistedTombstone>,
    pub(crate) retention: RetentionMetadata,
    pub(crate) reconciliation_required: bool,
}

impl PersistedControlState {
    pub(crate) fn new(boot_id: impl Into<String>, desired: DesiredState) -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            boot_id: boot_id.into(),
            desired,
            operations: BTreeMap::new(),
            boot_connections: BTreeMap::new(),
            requested_resources: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            retention: RetentionMetadata::default(),
            reconciliation_required: true,
        }
    }

    fn validate(&self) -> Result<(), ControlStateError> {
        if !(MIN_STATE_SCHEMA_VERSION..=STATE_SCHEMA_VERSION).contains(&self.schema_version) {
            return Err(ControlStateError::UnsupportedSchema(self.schema_version));
        }
        if self.boot_id.is_empty() || self.boot_id.len() > 128 {
            return Err(ControlStateError::Invalid(
                "boot ID must contain 1..=128 bytes",
            ));
        }
        if self.desired.tunnels.len() > MAX_PROFILES
            || self.boot_connections.len() > MAX_PROFILES
            || self.requested_resources.len() > MAX_PROFILES
            || self.tombstones.len() > MAX_PROFILES
            || self.operations.len() > MAX_OPERATIONS
        {
            return Err(ControlStateError::Capacity);
        }
        if !self.desired.policy_digest.is_valid()
            || self.requested_resources.values().any(|resources| {
                resources.routes.len() > MAX_ROUTES_PER_PROFILE
                    || !resources.dns_digest.is_valid()
                    || !resources.firewall_digest.is_valid()
                    || resources
                        .routes
                        .iter()
                        .any(|route| route.parse::<crate::vortix_core::Cidr>().is_err())
            })
            || self.tombstones.values().any(|tombstone| {
                !tombstone.policy_digest.is_valid()
                    || tombstone.authority_epoch != self.desired.authority_epoch
                    || tombstone.operation_id.authority_epoch() != Some(tombstone.authority_epoch)
            })
            || self.operations.iter().any(|(id, operation)| {
                id != &operation.id
                    || id.authority_epoch() != Some(operation.authority_epoch)
                    || operation.client_id.authority_epoch() != Some(operation.authority_epoch)
                    || operation.authority_epoch != self.desired.authority_epoch
                    || id.sequence() == Some(u64::MAX)
                    || operation.client_id.sequence() == Some(u64::MAX)
                    || !operation.idempotency_key.is_valid()
                    || !operation.command_digest.is_valid()
                    || operation.desired_generation > self.desired.generation
                    || operation.admitted_at_millis > operation.deadline_millis
                    || matches!(
                        &operation.intent,
                        OperationIntent::DesiredSubset { tunnels, .. }
                            | OperationIntent::UnexpectedRecovery { tunnels, .. }
                            if tunnels.len() > MAX_PROFILES
                    )
                    || matches!(
                        &operation.intent,
                        OperationIntent::UnexpectedRecovery {
                            profile_id,
                            tunnels,
                            ..
                        } if tunnels.get(profile_id) != Some(&RequestedTunnelState::Connected)
                    )
                    || !operation_result_matches_status(operation)
                    || (self.schema_version == 1
                        && (matches!(operation.intent, OperationIntent::ProfileMutation { .. })
                            || matches!(
                                operation.result,
                                Some(
                                    OperationResult::ProfileMutationApplied
                                        | OperationResult::ProfileMutationAppliedAfterDeadline
                                )
                            )))
            })
        {
            return Err(ControlStateError::Invalid("invalid persisted control fact"));
        }
        Ok(())
    }
}

fn operation_result_matches_status(operation: &OperationRecord) -> bool {
    matches!(
        (operation.status, operation.result),
        (
            OperationStatus::Admitted | OperationStatus::WaitingForObservation,
            None
        ) | (
            OperationStatus::Succeeded,
            Some(OperationResult::ObservedConvergence | OperationResult::ProfileMutationApplied)
        ) | (OperationStatus::Failed, Some(OperationResult::Failed(_)))
            | (OperationStatus::Cancelled, Some(OperationResult::Cancelled))
            | (
                OperationStatus::Expired,
                Some(
                    OperationResult::Expired | OperationResult::ProfileMutationAppliedAfterDeadline
                )
            )
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LoadedControlState {
    Missing,
    Current(PersistedControlState),
    RecoveredPrevious(PersistedControlState),
    FutureSchema(u16),
}

#[derive(Debug, Clone)]
pub struct FsControlStateStore {
    directory: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
}

impl FsControlStateStore {
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        let expected = crate::utils::effective_user_group_ids();
        Self {
            directory: directory.into(),
            expected_uid: expected.0,
            expected_gid: expected.1,
        }
    }

    /// Construct a store for the authenticated invoking owner while the
    /// Standard-mode control process itself remains root.
    #[must_use]
    pub fn for_owner(directory: impl Into<PathBuf>, uid: u32, gid: u32) -> Self {
        Self {
            directory: directory.into(),
            expected_uid: uid,
            expected_gid: gid,
        }
    }

    /// Build the canonical persistence configuration using the current OS
    /// boot identity and this user-owned state directory.
    pub fn persistence_config(
        directory: impl Into<PathBuf>,
    ) -> Result<ControlPersistenceConfig, ControlStateStoreError> {
        let boot_id = crate::utils::boot_identity().ok_or_else(|| {
            ControlStateStoreError::Invalid("OS boot identity is unavailable".to_string())
        })?;
        Ok(ControlPersistenceConfig::new(
            boot_id,
            Arc::new(Self::new(directory)),
        ))
    }

    /// Read one durable operation without starting a control authority.
    pub fn operation(
        &self,
        current_boot_id: &str,
        operation_id: &OperationId,
    ) -> Result<Option<OperationRecord>, ControlStateStoreError> {
        Ok(self
            .load(current_boot_id)?
            .and_then(|recovered| recovered.state.operations.get(operation_id).cloned()))
    }

    /// Read the bounded owner-authenticated endpoint-resolution cache.
    pub fn endpoint_resolution_cache(&self) -> Result<Option<Vec<u8>>, ControlStateStoreError> {
        let Some(directory) =
            open_control_directory(&self.directory, false, self.expected_uid, self.expected_gid)
                .map_err(ControlStateStoreError::from)?
        else {
            return Ok(None);
        };
        read_owned_entry(&directory, ENDPOINT_CACHE_FILE, self.expected_uid)
            .map_err(ControlStateStoreError::from)
    }

    /// Atomically replace the bounded owner-authenticated endpoint cache.
    pub fn save_endpoint_resolution_cache(
        &self,
        body: &[u8],
    ) -> Result<(), ControlStateStoreError> {
        if body.len() as u64 > MAX_STATE_BYTES {
            return Err(ControlStateStoreError::Capacity);
        }
        let directory =
            open_control_directory(&self.directory, true, self.expected_uid, self.expected_gid)
                .map_err(ControlStateStoreError::from)?
                .ok_or(ControlStateStoreError::UnsafeFile)?;
        write_owned_atomic(
            &directory,
            ENDPOINT_CACHE_FILE,
            body,
            self.expected_uid,
            self.expected_gid,
        )
        .map_err(ControlStateStoreError::from)
    }

    fn load_state(&self) -> Result<LoadedControlState, ControlStateError> {
        let Some(directory) =
            open_control_directory(&self.directory, false, self.expected_uid, self.expected_gid)?
        else {
            return Ok(LoadedControlState::Missing);
        };
        match read_state(&directory, STATE_FILE, self.expected_uid) {
            Ok(Some(DecodedState::Current(state))) => Ok(LoadedControlState::Current(*state)),
            Ok(Some(DecodedState::Future(version))) => {
                Ok(LoadedControlState::FutureSchema(version))
            }
            Ok(None) => self.load_previous(&directory, false),
            Err(ControlStateError::Corrupt) => self.load_previous(&directory, true),
            Err(error) => Err(error),
        }
    }

    fn load_previous(
        &self,
        directory: &ControlDirectory,
        current_was_corrupt: bool,
    ) -> Result<LoadedControlState, ControlStateError> {
        match read_state(directory, PREVIOUS_STATE_FILE, self.expected_uid)? {
            Some(DecodedState::Current(state)) => Ok(LoadedControlState::RecoveredPrevious(*state)),
            Some(DecodedState::Future(version)) => Ok(LoadedControlState::FutureSchema(version)),
            None if current_was_corrupt => Err(ControlStateError::Corrupt),
            None => Ok(LoadedControlState::Missing),
        }
    }

    fn save_state(&self, state: &PersistedControlState) -> Result<(), ControlStateError> {
        let directory =
            open_control_directory(&self.directory, true, self.expected_uid, self.expected_gid)?
                .ok_or(ControlStateError::UnsafeFile)?;
        state.validate()?;
        let body = serde_json::to_vec_pretty(state)?;
        if body.len() as u64 > MAX_STATE_BYTES {
            return Err(ControlStateError::Capacity);
        }
        if !matches!(decode_state(&body)?, DecodedState::Current(_)) {
            return Err(ControlStateError::Corrupt);
        }
        if let Some(bytes) = read_owned_entry(&directory, STATE_FILE, self.expected_uid)? {
            match decode_state(&bytes) {
                Ok(DecodedState::Current(_)) => {
                    write_owned_atomic(
                        &directory,
                        PREVIOUS_STATE_FILE,
                        &bytes,
                        self.expected_uid,
                        self.expected_gid,
                    )?;
                }
                Ok(DecodedState::Future(version)) => {
                    return Err(ControlStateError::UnsupportedSchema(version));
                }
                Err(ControlStateError::Corrupt) => {}
                Err(error) => return Err(error),
            }
        }
        write_owned_atomic(
            &directory,
            STATE_FILE,
            &body,
            self.expected_uid,
            self.expected_gid,
        )?;
        Ok(())
    }
}

impl ControlStateStore for FsControlStateStore {
    fn load(
        &self,
        current_boot_id: &str,
    ) -> Result<Option<RecoveredControlState>, ControlStateStoreError> {
        match self.load_state().map_err(ControlStateStoreError::from)? {
            LoadedControlState::Missing => Ok(None),
            LoadedControlState::Current(state) | LoadedControlState::RecoveredPrevious(state) => {
                Ok(Some(recovered_state(state, current_boot_id)))
            }
            LoadedControlState::FutureSchema(version) => {
                Err(ControlStateStoreError::UnsupportedSchema(version))
            }
        }
    }

    fn save(
        &self,
        current_boot_id: &str,
        durable: &DurableControlState,
    ) -> Result<(), ControlStateStoreError> {
        let mut state = PersistedControlState::new(current_boot_id, durable.desired.clone());
        state.operations.clone_from(&durable.operations);
        state.boot_connections.clone_from(&durable.boot_connections);
        state
            .requested_resources
            .clone_from(&durable.requested_resources);
        state.tombstones.clone_from(&durable.tombstones);
        state.retention = durable.retention;
        state.reconciliation_required = durable.reconciliation_required;
        self.save_state(&state)
            .map_err(ControlStateStoreError::from)
    }
}

fn recovered_state(state: PersistedControlState, current_boot_id: &str) -> RecoveredControlState {
    let same_boot = state.boot_id == current_boot_id;
    RecoveredControlState {
        state: DurableControlState {
            desired: state.desired,
            operations: state.operations,
            boot_connections: state.boot_connections,
            requested_resources: state.requested_resources,
            tombstones: state.tombstones,
            retention: state.retention,
            reconciliation_required: true,
        },
        same_boot,
    }
}

enum DecodedState {
    Current(Box<PersistedControlState>),
    Future(u16),
}

fn read_state(
    directory: &ControlDirectory,
    name: &str,
    expected_uid: u32,
) -> Result<Option<DecodedState>, ControlStateError> {
    read_owned_entry(directory, name, expected_uid)?
        .map(|bytes| decode_state(&bytes))
        .transpose()
}

fn decode_state(bytes: &[u8]) -> Result<DecodedState, ControlStateError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| ControlStateError::Corrupt)?;
    let version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or(ControlStateError::Corrupt)?;
    if version > STATE_SCHEMA_VERSION {
        return Ok(DecodedState::Future(version));
    }
    let state: PersistedControlState =
        serde_json::from_value(value).map_err(|_| ControlStateError::Corrupt)?;
    state.validate()?;
    Ok(DecodedState::Current(Box::new(state)))
}

#[cfg(unix)]
type ControlDirectory = std::fs::File;

#[cfg(not(unix))]
type ControlDirectory = PathBuf;

#[cfg(unix)]
#[allow(unsafe_code)]
#[allow(clippy::similar_names)]
fn open_control_directory(
    path: &Path,
    create: bool,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<Option<ControlDirectory>, ControlStateError> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let leaf = absolute.file_name().ok_or(ControlStateError::UnsafeFile)?;
    let parent_path = absolute
        .parent()
        .ok_or(ControlStateError::UnsafeFile)?
        .canonicalize()?;
    let parent = open_absolute_directory(&parent_path)?;
    let leaf = CString::new(leaf.as_bytes()).map_err(|_| ControlStateError::UnsafeFile)?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let mut fd = unsafe { libc::openat(parent.as_raw_fd(), leaf.as_ptr(), flags) };
    let mut created = false;
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if is_unsafe_path_error(&error) {
            return Err(ControlStateError::UnsafeFile);
        }
        if error.raw_os_error() != Some(libc::ENOENT) {
            return Err(error.into());
        }
        if !create {
            return Ok(None);
        }
        validate_directory_descriptor(&parent, expected_uid)?;
        if unsafe { libc::mkdirat(parent.as_raw_fd(), leaf.as_ptr(), 0o700) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(error.into());
            }
        } else {
            created = true;
        }
        fd = unsafe { libc::openat(parent.as_raw_fd(), leaf.as_ptr(), flags) };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return if is_unsafe_path_error(&error) {
                Err(ControlStateError::UnsafeFile)
            } else {
                Err(error.into())
            };
        }
    }
    let directory = unsafe { std::fs::File::from_raw_fd(fd) };
    if created {
        prepare_created_descriptor(&directory, expected_uid, expected_gid, 0o700)?;
        parent.sync_all()?;
    }
    validate_directory_descriptor(&directory, expected_uid)?;
    Ok(Some(directory))
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn open_absolute_directory(path: &Path) -> Result<std::fs::File, ControlStateError> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Component;

    let root = CString::new("/").expect("static path");
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let fd = unsafe { libc::open(root.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut directory = unsafe { std::fs::File::from_raw_fd(fd) };
    for component in path.components() {
        let Component::Normal(component) = component else {
            if matches!(component, Component::RootDir | Component::CurDir) {
                continue;
            }
            return Err(ControlStateError::UnsafeFile);
        };
        let name = CString::new(component.as_bytes()).map_err(|_| ControlStateError::UnsafeFile)?;
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return if is_unsafe_path_error(&error) {
                Err(ControlStateError::UnsafeFile)
            } else {
                Err(error.into())
            };
        }
        directory = unsafe { std::fs::File::from_raw_fd(fd) };
    }
    Ok(directory)
}

#[cfg(unix)]
fn validate_directory_descriptor(
    directory: &std::fs::File,
    expected_uid: u32,
) -> Result<(), ControlStateError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(ControlStateError::UnsafeFile);
    }
    Ok(())
}

#[cfg(unix)]
fn is_unsafe_path_error(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code) if code == libc::ELOOP || code == libc::ENOTDIR)
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn prepare_created_descriptor(
    descriptor: &std::fs::File,
    uid: u32,
    gid: u32,
    mode: libc::mode_t,
) -> Result<(), ControlStateError> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let effective = crate::utils::effective_user_group_ids();
    let metadata = descriptor.metadata()?;
    if metadata.uid() != effective.0 && metadata.uid() != uid {
        return Err(ControlStateError::UnsafeFile);
    }
    if unsafe { libc::fchmod(descriptor.as_raw_fd(), mode) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if effective.0 == 0 {
        if unsafe { libc::fchown(descriptor.as_raw_fd(), uid, gid) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    } else if effective != (uid, gid) {
        return Err(ControlStateError::UnsafeFile);
    }
    let metadata = descriptor.metadata()?;
    if metadata.uid() != uid
        || metadata.gid() != gid
        || u64::from(metadata.permissions().mode() & 0o777) != u64::from(mode)
    {
        return Err(ControlStateError::UnsafeFile);
    }
    Ok(())
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn read_owned_entry(
    directory: &ControlDirectory,
    name: &str,
    expected_uid: u32,
) -> Result<Option<Vec<u8>>, ControlStateError> {
    use std::ffi::CString;
    use std::io::Read as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let name = CString::new(name).map_err(|_| ControlStateError::UnsafeFile)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else if is_unsafe_path_error(&error) {
            Err(ControlStateError::UnsafeFile)
        } else {
            Err(error.into())
        };
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ControlStateError::UnsafeFile);
    }
    if metadata.len() > MAX_STATE_BYTES {
        return Err(ControlStateError::Capacity);
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| ControlStateError::Capacity)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(ControlStateError::Capacity);
    }
    Ok(Some(bytes))
}

#[cfg(unix)]
fn write_owned_atomic(
    directory: &ControlDirectory,
    name: &str,
    body: &[u8],
    uid: u32,
    gid: u32,
) -> Result<(), ControlStateError> {
    write_owned_atomic_with_hook(directory, name, body, uid, gid, |_| {})
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn write_owned_atomic_with_hook(
    directory: &ControlDirectory,
    name: &str,
    body: &[u8],
    uid: u32,
    gid: u32,
    before_publish: impl FnOnce(&std::fs::File),
) -> Result<(), ControlStateError> {
    use std::ffi::CString;
    use std::io::Write as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let destination = CString::new(name).map_err(|_| ControlStateError::UnsafeFile)?;
    let mut allocated = None;
    for _ in 0..128 {
        let candidate = format!(
            ".{name}.{}.{}.tmp",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let candidate_c =
            CString::new(candidate.as_str()).map_err(|_| ControlStateError::UnsafeFile)?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                candidate_c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd >= 0 {
            allocated = Some((candidate, unsafe { std::fs::File::from_raw_fd(fd) }));
            break;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error.into());
        }
    }
    let (temporary_name, mut temporary) = allocated.ok_or_else(|| {
        ControlStateError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a private control-state temp file",
        ))
    })?;
    let temporary_name_c =
        CString::new(temporary_name.as_str()).map_err(|_| ControlStateError::UnsafeFile)?;
    let result = (|| {
        temporary.write_all(body)?;
        temporary.sync_all()?;
        prepare_created_descriptor(&temporary, uid, gid, 0o600)?;
        temporary.sync_all()?;
        before_publish(&temporary);
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temporary_name_c.as_ptr(),
                directory.as_raw_fd(),
                destination.as_ptr(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        directory.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = unsafe { libc::unlinkat(directory.as_raw_fd(), temporary_name_c.as_ptr(), 0) };
    }
    result
}

#[cfg(not(unix))]
fn open_control_directory(
    path: &Path,
    create: bool,
    _expected_uid: u32,
    _expected_gid: u32,
) -> Result<Option<ControlDirectory>, ControlStateError> {
    if !path.exists() {
        if !create {
            return Ok(None);
        }
        std::fs::create_dir_all(path)?;
    }
    path.is_dir()
        .then(|| path.to_path_buf())
        .map(Some)
        .ok_or(ControlStateError::UnsafeFile)
}

#[cfg(not(unix))]
fn read_owned_entry(
    directory: &ControlDirectory,
    name: &str,
    _expected_uid: u32,
) -> Result<Option<Vec<u8>>, ControlStateError> {
    let path = directory.join(name);
    match std::fs::read(path) {
        Ok(bytes) if bytes.len() as u64 <= MAX_STATE_BYTES => Ok(Some(bytes)),
        Ok(_) => Err(ControlStateError::Capacity),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(unix))]
fn write_owned_atomic(
    directory: &ControlDirectory,
    name: &str,
    body: &[u8],
    _uid: u32,
    _gid: u32,
) -> Result<(), ControlStateError> {
    crate::vortix_config::profile_store::write_atomic(&directory.join(name), body)?;
    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum ControlStateError {
    #[error("control state has unsupported schema version {0}")]
    UnsupportedSchema(u16),
    #[error("control state exceeds its fixed capacity")]
    Capacity,
    #[error("control state is invalid: {0}")]
    Invalid(&'static str),
    #[error("control state is corrupt")]
    Corrupt,
    #[error("control state path is not a private owner-controlled regular file")]
    UnsafeFile,
    #[error("control state I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("control state serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<ControlStateError> for ControlStateStoreError {
    fn from(error: ControlStateError) -> Self {
        match error {
            ControlStateError::UnsupportedSchema(version) => Self::UnsupportedSchema(version),
            ControlStateError::Capacity => Self::Capacity,
            ControlStateError::Invalid(reason) => Self::Invalid(reason.to_owned()),
            ControlStateError::Corrupt => Self::Corrupt,
            ControlStateError::UnsafeFile => Self::UnsafeFile,
            ControlStateError::Io(error) => Self::Io(error.to_string()),
            ControlStateError::Json(error) => Self::Invalid(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::control::{
        AdmissionError, AuthorityEpoch, BootEligibility, ClientId, CommandRequest,
        ControlPersistenceConfig, ControlService, ControlServiceConfig, IdempotencyKey,
        PolicyDigest, ProfileTopology, ProtectionStatus, ReadinessError, RequestedTunnelState,
        UserCommand,
    };
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::tempdir;

    fn profile(byte: char) -> ProfileId {
        ProfileId::parse(byte.to_string().repeat(ProfileId::HEX_LEN)).unwrap()
    }

    fn state(boot_id: &str) -> PersistedControlState {
        let mut desired = DesiredState {
            authority_epoch: AuthorityEpoch(7),
            policy_digest: PolicyDigest("policy".into()),
            ..DesiredState::default()
        };
        desired
            .tunnels
            .insert(profile('a'), RequestedTunnelState::Connected);
        PersistedControlState::new(boot_id, desired)
    }

    fn operation(epoch: u64, sequence: u64, client_sequence: u64) -> OperationRecord {
        let authority_epoch = AuthorityEpoch(epoch);
        let id = OperationId::from_parts(authority_epoch, sequence);
        OperationRecord {
            id,
            idempotency_key: IdempotencyKey::new("persisted-operation"),
            client_id: ClientId::from_parts(authority_epoch, client_sequence),
            command_digest: PolicyDigest("command".into()),
            authority_epoch,
            desired_generation: 0,
            admitted_at_millis: 0,
            deadline_millis: 1,
            intent: OperationIntent::GenerationScoped,
            status: OperationStatus::WaitingForObservation,
            result: None,
        }
    }

    #[test]
    fn durable_operation_is_queryable_without_starting_an_authority() {
        let temp = tempdir().unwrap();
        let store = FsControlStateStore::new(temp.path());
        let mut persisted = state("query-boot");
        let operation = operation(7, 3, 2);
        let operation_id = operation.id.clone();
        persisted.operations.insert(operation_id.clone(), operation);
        store.save_state(&persisted).unwrap();

        let loaded = store
            .operation("query-boot", &operation_id)
            .unwrap()
            .expect("operation remains queryable");

        assert_eq!(loaded.id, operation_id);
        assert_eq!(loaded.status, OperationStatus::WaitingForObservation);
    }

    #[test]
    fn endpoint_resolution_cache_round_trips_through_owned_atomic_entry() {
        let temp = tempdir().unwrap();
        let store = FsControlStateStore::new(temp.path());
        let body = br#"{"schema_version":1,"profiles":{}}"#;
        assert!(store.endpoint_resolution_cache().unwrap().is_none());
        store.save_endpoint_resolution_cache(body).unwrap();
        assert_eq!(
            store.endpoint_resolution_cache().unwrap().as_deref(),
            Some(body.as_slice())
        );
    }

    #[test]
    fn operation_intent_defaults_to_generation_scope_for_older_state() {
        let mut persisted = state("legacy-intent");
        let operation = operation(7, 1, 1);
        persisted.operations.insert(operation.id.clone(), operation);
        let mut encoded = serde_json::to_value(&persisted).unwrap();
        encoded["schema_version"] = serde_json::json!(1);
        encoded["operations"]
            .as_object_mut()
            .unwrap()
            .values_mut()
            .for_each(|operation| {
                operation.as_object_mut().unwrap().remove("intent");
            });

        let decoded: PersistedControlState = serde_json::from_value(encoded).unwrap();
        assert!(matches!(
            decoded.operations.values().next().unwrap().intent,
            OperationIntent::GenerationScoped
        ));
        decoded.validate().unwrap();
    }

    #[test]
    fn schema_one_loads_but_cannot_claim_profile_mutation_facts() {
        let mut persisted = state("schema-one");
        let operation = operation(7, 1, 1);
        persisted.operations.insert(operation.id.clone(), operation);
        let mut encoded = serde_json::to_value(&persisted).unwrap();
        encoded["schema_version"] = serde_json::json!(1);

        assert!(matches!(
            decode_state(&serde_json::to_vec(&encoded).unwrap()).unwrap(),
            DecodedState::Current(_)
        ));

        let operation = encoded["operations"]
            .as_object_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap();
        operation["intent"] = serde_json::json!({
            "kind": "profile_mutation",
            "profile_id": profile('a')
        });
        operation["status"] = serde_json::json!("succeeded");
        operation["result"] = serde_json::json!("profile_mutation_applied");
        assert!(matches!(
            decode_state(&serde_json::to_vec(&encoded).unwrap()),
            Err(ControlStateError::Invalid(_))
        ));
    }

    #[test]
    fn operation_intent_persists_canonical_kill_switch_slug() {
        let mut persisted = state("intent-slug");
        let mut operation = operation(7, 1, 1);
        operation.intent = OperationIntent::DesiredSubset {
            tunnels: BTreeMap::new(),
            kill_switch: Some(crate::vortix_core::state::killswitch::KillSwitchMode::Auto),
        };
        persisted.operations.insert(operation.id.clone(), operation);

        let encoded = serde_json::to_value(&persisted).unwrap();
        let intent = &encoded["operations"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap()["intent"];
        assert_eq!(intent["kill_switch"], "block-on-drop");
        let decoded: PersistedControlState = serde_json::from_value(encoded).unwrap();
        decoded.validate().unwrap();
    }

    #[test]
    fn save_is_private_atomic_and_retains_previous_generation() {
        let directory = tempdir().unwrap();
        let state_directory = directory.path().join("control");
        let store = FsControlStateStore::new(&state_directory);
        let first = state("boot-a");
        store.save_state(&first).unwrap();
        let mut second = first.clone();
        second.desired.generation = 2;
        store.save_state(&second).unwrap();

        assert_eq!(
            store.load_state().unwrap(),
            LoadedControlState::Current(second)
        );
        let (uid, gid) = crate::utils::effective_user_group_ids();
        let pinned = open_control_directory(&state_directory, false, uid, gid)
            .unwrap()
            .expect("state directory exists");
        let previous = read_state(&pinned, PREVIOUS_STATE_FILE, uid).unwrap();
        assert!(matches!(previous, Some(DecodedState::Current(state)) if *state == first));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(state_directory.join(STATE_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
            let directory_mode = std::fs::metadata(&state_directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(directory_mode, 0o700);
        }
    }

    #[cfg(unix)]
    #[test]
    fn atomic_publish_owns_private_temp_before_visibility() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let directory = tempdir().unwrap();
        let (uid, gid) = crate::utils::effective_user_group_ids();
        let pinned = open_control_directory(directory.path(), false, uid, gid)
            .unwrap()
            .expect("existing directory is pinned");

        write_owned_atomic_with_hook(
            &pinned,
            STATE_FILE,
            br#"{"schema_version":1}"#,
            uid,
            gid,
            |temporary| {
                assert!(read_owned_entry(&pinned, STATE_FILE, uid)
                    .unwrap()
                    .is_none());
                let metadata = temporary.metadata().unwrap();
                assert_eq!(metadata.uid(), uid);
                assert_eq!(metadata.gid(), gid);
                assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            },
        )
        .unwrap();

        assert_eq!(
            read_owned_entry(&pinned, STATE_FILE, uid).unwrap(),
            Some(br#"{"schema_version":1}"#.to_vec())
        );
    }

    #[cfg(unix)]
    #[test]
    fn pinned_directory_cannot_be_redirected_after_open() {
        use std::os::unix::fs::symlink;

        let parent = tempdir().unwrap();
        let state_directory = parent.path().join("control");
        let redirected = parent.path().join("redirected");
        let moved = parent.path().join("moved-control");
        std::fs::create_dir(&state_directory).unwrap();
        std::fs::create_dir(&redirected).unwrap();
        let (uid, gid) = crate::utils::effective_user_group_ids();
        let pinned = open_control_directory(&state_directory, false, uid, gid)
            .unwrap()
            .expect("state directory is pinned");

        std::fs::rename(&state_directory, &moved).unwrap();
        symlink(&redirected, &state_directory).unwrap();
        write_owned_atomic(&pinned, STATE_FILE, b"pinned", uid, gid).unwrap();

        assert_eq!(std::fs::read(moved.join(STATE_FILE)).unwrap(), b"pinned");
        assert!(!redirected.join(STATE_FILE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn writable_or_symlinked_state_directory_is_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let directory = tempdir().unwrap();
        let writable = directory.path().join("writable");
        std::fs::create_dir(&writable).unwrap();
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            FsControlStateStore::new(&writable).load_state(),
            Err(ControlStateError::UnsafeFile)
        ));

        let linked = directory.path().join("linked");
        symlink(directory.path(), &linked).unwrap();
        assert!(matches!(
            FsControlStateStore::new(linked).load_state(),
            Err(ControlStateError::UnsafeFile)
        ));
    }

    #[test]
    fn corrupt_current_recovers_previous_without_claiming_current() {
        let directory = tempdir().unwrap();
        let store = FsControlStateStore::new(directory.path());
        let first = state("boot-a");
        store.save_state(&first).unwrap();
        let mut second = first.clone();
        second.desired.generation = 2;
        store.save_state(&second).unwrap();
        std::fs::write(directory.path().join(STATE_FILE), b"{").unwrap();

        assert_eq!(
            store.load_state().unwrap(),
            LoadedControlState::RecoveredPrevious(first)
        );
    }

    #[test]
    fn future_schema_is_preserved_and_never_overwritten() {
        let directory = tempdir().unwrap();
        let store = FsControlStateStore::new(directory.path());
        let path = directory.path().join(STATE_FILE);
        crate::vortix_config::profile_store::write_atomic(&path, br#"{"schema_version":99}"#)
            .unwrap();

        assert!(matches!(
            store.load_state().unwrap(),
            LoadedControlState::FutureSchema(99)
        ));
        assert!(matches!(
            store.save_state(&state("boot-a")),
            Err(ControlStateError::UnsupportedSchema(99))
        ));
        assert_eq!(std::fs::read(path).unwrap(), br#"{"schema_version":99}"#);
    }

    #[test]
    fn reboot_filters_connected_intent_by_explicit_noninteractive_eligibility() {
        let mut persisted = state("old-boot");
        let interactive = profile('b');
        let disabled = profile('c');
        let unsupported = profile('d');
        persisted
            .desired
            .tunnels
            .insert(interactive.clone(), RequestedTunnelState::Connected);
        persisted
            .desired
            .tunnels
            .insert(disabled.clone(), RequestedTunnelState::Connected);
        persisted
            .desired
            .tunnels
            .insert(unsupported.clone(), RequestedTunnelState::Connected);
        persisted.boot_connections.insert(
            profile('a'),
            BootConnection {
                enabled: true,
                eligibility: BootEligibility::Eligible,
            },
        );
        persisted.boot_connections.insert(
            interactive.clone(),
            BootConnection {
                enabled: true,
                eligibility: BootEligibility::InteractiveCredentials,
            },
        );
        persisted.boot_connections.insert(
            disabled.clone(),
            BootConnection {
                enabled: false,
                eligibility: BootEligibility::Eligible,
            },
        );
        persisted.boot_connections.insert(
            unsupported.clone(),
            BootConnection {
                enabled: true,
                eligibility: BootEligibility::UnsupportedKeyProvider,
            },
        );

        let same_boot = recovered_state(persisted.clone(), "old-boot");
        assert!(same_boot.same_boot);
        assert_eq!(same_boot.state.desired, persisted.desired);
        let mut rebooted = recovered_state(persisted, "new-boot");
        assert!(!rebooted.same_boot);
        rebooted.state.prepare_for_reboot();
        assert_eq!(
            rebooted.state.desired.tunnels.get(&profile('a')),
            Some(&RequestedTunnelState::Connected)
        );
        assert_eq!(
            rebooted.state.desired.tunnels.get(&interactive),
            Some(&RequestedTunnelState::Disconnected)
        );
        assert_eq!(
            rebooted.state.desired.tunnels.get(&disabled),
            Some(&RequestedTunnelState::Disconnected)
        );
        assert_eq!(
            rebooted.state.desired.tunnels.get(&unsupported),
            Some(&RequestedTunnelState::Disconnected)
        );
    }

    #[test]
    fn persisted_operations_share_authority_and_leave_identifier_capacity() {
        let mut foreign = state("boot-a");
        let foreign_operation = operation(8, 1, 1);
        foreign
            .operations
            .insert(foreign_operation.id.clone(), foreign_operation);
        assert!(matches!(
            foreign.validate(),
            Err(ControlStateError::Invalid("invalid persisted control fact"))
        ));

        for exhausted in [operation(7, u64::MAX, 1), operation(7, 1, u64::MAX)] {
            let mut persisted = state("boot-a");
            persisted.operations.insert(exhausted.id.clone(), exhausted);
            assert!(matches!(
                persisted.validate(),
                Err(ControlStateError::Invalid("invalid persisted control fact"))
            ));
        }
    }

    #[tokio::test]
    async fn real_store_forces_scan_before_admission_and_recovers_intent() {
        let directory = tempdir().unwrap();
        let store = Arc::new(FsControlStateStore::new(directory.path()));
        let profile_id = profile('a');
        let config = ControlServiceConfig {
            authority_epoch: AuthorityEpoch(7),
            known_profiles: BTreeSet::from([profile_id.clone()]),
            profile_topologies: std::collections::BTreeMap::from([(
                profile_id.clone(),
                ProfileTopology::default(),
            )]),
            persistence: Some(ControlPersistenceConfig::new("boot-a", store.clone())),
            ..ControlServiceConfig::default()
        };

        let first_operation = {
            let service = ControlService::start(config.clone());
            let client = service.client();
            assert_eq!(
                client
                    .submit(CommandRequest {
                        command: UserCommand::Connect {
                            profile_id: profile_id.clone(),
                        },
                        idempotency_key: IdempotencyKey::new("before-scan"),
                        deadline: client.deadline_after(Duration::from_secs(5)),
                    })
                    .await
                    .unwrap_err(),
                AdmissionError::NotReady
            );
            service
                .completer()
                .set_readiness(AuthorityEpoch(7), true, true)
                .await
                .unwrap();
            let admitted = client
                .submit(CommandRequest {
                    command: UserCommand::Connect {
                        profile_id: profile_id.clone(),
                    },
                    idempotency_key: IdempotencyKey::new("connect"),
                    deadline: client.deadline_after(Duration::from_secs(5)),
                })
                .await
                .unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
            while !client
                .snapshot()
                .operations
                .contains_key(&admitted.operation_id)
            {
                assert!(tokio::time::Instant::now() < deadline);
                tokio::task::yield_now().await;
            }
            assert_eq!(
                client.snapshot().desired.tunnels.get(&profile_id),
                Some(&RequestedTunnelState::Connected)
            );
            admitted.operation_id
        };

        tokio::time::sleep(Duration::from_millis(20)).await;
        let restarted = ControlService::start(config);
        let snapshot = restarted.client().snapshot();
        assert!(!snapshot.readiness.reconciliation_complete);
        assert!(snapshot.observed.tunnels.is_empty());
        assert!(snapshot.observed.evidence.is_none());
        assert_eq!(snapshot.effective.protection, ProtectionStatus::Unknown);
        assert_eq!(
            snapshot.desired.tunnels.get(&profile_id),
            Some(&RequestedTunnelState::Connected)
        );
        assert!(snapshot.operations.contains_key(&first_operation));
    }

    #[tokio::test]
    async fn authority_mismatch_is_not_restored_or_rewritten() {
        let directory = tempdir().unwrap();
        let store = Arc::new(FsControlStateStore::new(directory.path()));
        let persisted = state("boot-a");
        store.save_state(&persisted).unwrap();
        let original = std::fs::read(directory.path().join(STATE_FILE)).unwrap();

        let service = ControlService::start(ControlServiceConfig {
            authority_epoch: AuthorityEpoch(8),
            persistence: Some(ControlPersistenceConfig::new("boot-a", store)),
            ..ControlServiceConfig::default()
        });
        let snapshot = service.client().snapshot();
        assert_eq!(snapshot.desired.authority_epoch, AuthorityEpoch(8));
        assert!(snapshot.desired.tunnels.is_empty());
        assert!(!snapshot.readiness.authority_verified);
        assert_eq!(
            service
                .completer()
                .set_readiness(AuthorityEpoch(8), true, true)
                .await
                .unwrap_err(),
            ReadinessError::Persistence
        );
        assert_eq!(
            std::fs::read(directory.path().join(STATE_FILE)).unwrap(),
            original
        );
    }
}
