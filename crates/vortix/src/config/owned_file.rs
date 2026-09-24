//! Owner-checked directories and atomic file writes for private state.

use std::path::Path;

use thiserror::Error;

#[cfg(unix)]
pub(crate) type OwnedDirectory = std::fs::File;

#[cfg(not(unix))]
pub(crate) type OwnedDirectory = PathBuf;

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AtomicWriteStage {
    Create,
    Write,
    FirstFileSync,
    OwnerPreparation,
    SecondFileSync,
    Publish,
    DirectorySync,
}

#[cfg(unix)]
#[derive(Debug)]
pub(crate) enum AtomicWriteError {
    NotPublished(FileError),
    PublishedButDirectoryUnsynced(FileError),
}

#[cfg(unix)]
impl AtomicWriteError {
    pub(crate) fn into_file_error(self) -> FileError {
        match self {
            Self::NotPublished(error) | Self::PublishedButDirectoryUnsynced(error) => error,
        }
    }
}

#[cfg(unix)]
impl From<FileError> for AtomicWriteError {
    fn from(error: FileError) -> Self {
        Self::NotPublished(error)
    }
}

#[cfg(unix)]
impl From<std::io::Error> for AtomicWriteError {
    fn from(error: std::io::Error) -> Self {
        Self::NotPublished(FileError::Io(error))
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
#[allow(clippy::similar_names)]
pub(crate) fn open_owned_directory(
    path: &Path,
    create: bool,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<Option<OwnedDirectory>, FileError> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let leaf = absolute.file_name().ok_or(FileError::UnsafeFile)?;
    let parent_path = absolute
        .parent()
        .ok_or(FileError::UnsafeFile)?
        .canonicalize()?;
    let parent = open_absolute_directory(&parent_path)?;
    let leaf = CString::new(leaf.as_bytes()).map_err(|_| FileError::UnsafeFile)?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let mut fd = unsafe { libc::openat(parent.as_raw_fd(), leaf.as_ptr(), flags) };
    let mut created = false;
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if is_unsafe_path_error(&error) {
            return Err(FileError::UnsafeFile);
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
                Err(FileError::UnsafeFile)
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
#[allow(clippy::similar_names)]
pub(crate) fn open_owned_directory_at(
    parent: &OwnedDirectory,
    name: &str,
    create: bool,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<Option<OwnedDirectory>, FileError> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    validate_directory_descriptor(parent, expected_uid)?;
    let name = CString::new(name).map_err(|_| FileError::UnsafeFile)?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let mut fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    let mut created = false;
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if is_unsafe_path_error(&error) {
            return Err(FileError::UnsafeFile);
        }
        if error.raw_os_error() != Some(libc::ENOENT) {
            return Err(error.into());
        }
        if !create {
            return Ok(None);
        }
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(error.into());
            }
        } else {
            created = true;
        }
        fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return if is_unsafe_path_error(&error) {
                Err(FileError::UnsafeFile)
            } else {
                Err(error.into())
            };
        }
    }
    let directory = unsafe { std::fs::File::from_raw_fd(fd) };
    if created {
        if let Err(error) =
            prepare_created_descriptor(&directory, expected_uid, expected_gid, 0o700)
        {
            let _ =
                unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
            return Err(error);
        }
        parent.sync_all()?;
    } else {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let metadata = directory.metadata()?;
        let effective_uid = crate::utils::effective_user_group_ids().0;
        if effective_uid == 0
            && expected_uid != 0
            && metadata.uid() == 0
            && metadata.permissions().mode() & 0o777 == 0o700
        {
            prepare_created_descriptor(&directory, expected_uid, expected_gid, 0o700)?;
            parent.sync_all()?;
        }
    }
    validate_directory_descriptor(&directory, expected_uid)?;
    Ok(Some(directory))
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn open_absolute_directory(path: &Path) -> Result<std::fs::File, FileError> {
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
            return Err(FileError::UnsafeFile);
        };
        let name = CString::new(component.as_bytes()).map_err(|_| FileError::UnsafeFile)?;
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return if is_unsafe_path_error(&error) {
                Err(FileError::UnsafeFile)
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
) -> Result<(), FileError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(FileError::UnsafeFile);
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
) -> Result<(), FileError> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let effective = crate::utils::effective_user_group_ids();
    let metadata = descriptor.metadata()?;
    if metadata.uid() != effective.0 && metadata.uid() != uid {
        return Err(FileError::UnsafeFile);
    }
    if unsafe { libc::fchmod(descriptor.as_raw_fd(), mode) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if effective.0 == 0 {
        if unsafe { libc::fchown(descriptor.as_raw_fd(), uid, gid) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    } else if effective != (uid, gid) {
        return Err(FileError::UnsafeFile);
    }
    let metadata = descriptor.metadata()?;
    if metadata.uid() != uid
        || metadata.gid() != gid
        || u64::from(metadata.permissions().mode() & 0o777) != u64::from(mode)
    {
        return Err(FileError::UnsafeFile);
    }
    Ok(())
}
#[cfg(unix)]
#[derive(Clone, Copy)]
struct EntryReadPolicy {
    max_bytes: u64,
    forbidden_permission_bits: u32,
    require_single_link: bool,
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn read_owned_entry_with_policy(
    directory: &OwnedDirectory,
    name: &str,
    expected_uid: u32,
    policy: EntryReadPolicy,
) -> Result<Option<Vec<u8>>, FileError> {
    use std::ffi::CString;
    use std::io::Read as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let name = CString::new(name).map_err(|_| FileError::UnsafeFile)?;
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
            Err(FileError::UnsafeFile)
        } else {
            Err(error.into())
        };
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || (policy.require_single_link && metadata.nlink() != 1)
        || metadata.permissions().mode() & policy.forbidden_permission_bits != 0
    {
        return Err(FileError::UnsafeFile);
    }
    if metadata.len() > policy.max_bytes {
        return Err(FileError::Capacity);
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| FileError::Capacity)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(policy.max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > policy.max_bytes {
        return Err(FileError::Capacity);
    }
    Ok(Some(bytes))
}

/// Read a user configuration entry without following links.
///
/// Unlike canonical private state, ordinary user configuration may be
/// world-readable for compatibility, but it must never be writable by a
/// different principal.
#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) fn read_owned_user_entry(
    directory: &OwnedDirectory,
    name: &str,
    expected_uid: u32,
    max_bytes: u64,
) -> Result<Option<Vec<u8>>, FileError> {
    read_owned_entry_with_policy(
        directory,
        name,
        expected_uid,
        EntryReadPolicy {
            max_bytes,
            forbidden_permission_bits: 0o022,
            require_single_link: true,
        },
    )
}

#[cfg(unix)]
pub(crate) fn write_owned_atomic(
    directory: &OwnedDirectory,
    name: &str,
    body: &[u8],
    uid: u32,
    gid: u32,
) -> Result<(), FileError> {
    write_owned_atomic_with_hook(directory, name, body, uid, gid, |_, _| Ok(()))
        .map_err(AtomicWriteError::into_file_error)
}

#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) fn write_owned_atomic_with_hook(
    directory: &OwnedDirectory,
    name: &str,
    body: &[u8],
    uid: u32,
    gid: u32,
    mut stage_hook: impl FnMut(AtomicWriteStage, Option<&std::fs::File>) -> Result<(), FileError>,
) -> Result<(), AtomicWriteError> {
    use std::ffi::CString;
    use std::io::Write as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let destination =
        CString::new(name).map_err(|_| AtomicWriteError::NotPublished(FileError::UnsafeFile))?;
    stage_hook(AtomicWriteStage::Create, None).map_err(AtomicWriteError::NotPublished)?;
    let mut allocated = None;
    for _ in 0..128 {
        let candidate = format!(
            ".{name}.{}.{}.tmp",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let candidate_c = CString::new(candidate.as_str())
            .map_err(|_| AtomicWriteError::NotPublished(FileError::UnsafeFile))?;
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
            return Err(AtomicWriteError::NotPublished(error.into()));
        }
    }
    let (temporary_name, mut temporary) = allocated.ok_or_else(|| {
        AtomicWriteError::NotPublished(FileError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a private owned temporary file",
        )))
    })?;
    let temporary_name_c = CString::new(temporary_name.as_str())
        .map_err(|_| AtomicWriteError::NotPublished(FileError::UnsafeFile))?;
    let result: Result<(), AtomicWriteError> = (|| {
        stage_hook(AtomicWriteStage::Write, Some(&temporary))
            .map_err(AtomicWriteError::NotPublished)?;
        temporary.write_all(body)?;
        stage_hook(AtomicWriteStage::FirstFileSync, Some(&temporary))
            .map_err(AtomicWriteError::NotPublished)?;
        temporary.sync_all()?;
        stage_hook(AtomicWriteStage::OwnerPreparation, Some(&temporary))
            .map_err(AtomicWriteError::NotPublished)?;
        prepare_created_descriptor(&temporary, uid, gid, 0o600)?;
        stage_hook(AtomicWriteStage::SecondFileSync, Some(&temporary))
            .map_err(AtomicWriteError::NotPublished)?;
        temporary.sync_all()?;
        stage_hook(AtomicWriteStage::Publish, Some(&temporary))
            .map_err(AtomicWriteError::NotPublished)?;
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temporary_name_c.as_ptr(),
                directory.as_raw_fd(),
                destination.as_ptr(),
            )
        } != 0
        {
            return Err(AtomicWriteError::NotPublished(
                std::io::Error::last_os_error().into(),
            ));
        }
        stage_hook(AtomicWriteStage::DirectorySync, Some(&temporary))
            .map_err(AtomicWriteError::PublishedButDirectoryUnsynced)?;
        directory
            .sync_all()
            .map_err(FileError::from)
            .map_err(AtomicWriteError::PublishedButDirectoryUnsynced)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = unsafe { libc::unlinkat(directory.as_raw_fd(), temporary_name_c.as_ptr(), 0) };
    }
    result
}

#[cfg(not(unix))]
pub(crate) fn open_owned_directory(
    path: &Path,
    create: bool,
    _expected_uid: u32,
    _expected_gid: u32,
) -> Result<Option<OwnedDirectory>, FileError> {
    if !path.exists() {
        if !create {
            return Ok(None);
        }
        std::fs::create_dir_all(path)?;
    }
    path.is_dir()
        .then(|| path.to_path_buf())
        .map(Some)
        .ok_or(FileError::UnsafeFile)
}

#[cfg(not(unix))]
pub(crate) fn open_owned_directory_at(
    parent: &OwnedDirectory,
    name: &str,
    create: bool,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<Option<OwnedDirectory>, FileError> {
    open_owned_directory(&parent.join(name), create, expected_uid, expected_gid)
}
#[cfg(not(unix))]
pub(crate) fn read_owned_user_entry(
    directory: &OwnedDirectory,
    name: &str,
    _expected_uid: u32,
    max_bytes: u64,
) -> Result<Option<Vec<u8>>, FileError> {
    let path = directory.join(name);
    match std::fs::read(path) {
        Ok(bytes) if bytes.len() as u64 <= max_bytes => Ok(Some(bytes)),
        Ok(_) => Err(FileError::Capacity),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(unix))]
pub(crate) fn write_owned_atomic(
    directory: &OwnedDirectory,
    name: &str,
    body: &[u8],
    _uid: u32,
    _gid: u32,
) -> Result<(), FileError> {
    crate::config::profile_store::write_atomic(&directory.join(name), body)?;
    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum FileError {
    #[error("private state exceeds its fixed capacity")]
    Capacity,
    #[error("private state path is not a private owner-controlled regular file")]
    UnsafeFile,
    #[error("private state I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("private state serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}
