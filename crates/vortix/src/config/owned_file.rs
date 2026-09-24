//! Owner-checked directories and atomic file writes for private state.

use std::path::Path;

use thiserror::Error;

pub(crate) type OwnedDirectory = std::fs::File;

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

#[derive(Debug)]
pub(crate) enum AtomicWriteError {
    NotPublished(FileError),
    PublishedButDirectoryUnsynced(FileError),
}

impl AtomicWriteError {
    pub(crate) fn into_file_error(self) -> FileError {
        match self {
            Self::NotPublished(error) | Self::PublishedButDirectoryUnsynced(error) => error,
        }
    }
}

impl From<FileError> for AtomicWriteError {
    fn from(error: FileError) -> Self {
        Self::NotPublished(error)
    }
}

impl From<std::io::Error> for AtomicWriteError {
    fn from(error: std::io::Error) -> Self {
        Self::NotPublished(FileError::Io(error))
    }
}

/// `openat` relative to `dir` with `O_NOFOLLOW | O_CLOEXEC` always added, as
/// an owned file. Every descriptor-relative open goes through here.
///
/// # Errors
///
/// Returns the OS error; callers map `ENOENT` / `ELOOP` as they need.
#[allow(unsafe_code)]
pub(crate) fn openat(
    dir: &impl std::os::fd::AsRawFd,
    name: &std::ffi::CStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<std::fs::File> {
    use std::os::fd::FromRawFd as _;
    // SAFETY: `dir` is a live descriptor and `name` a NUL-terminated string
    // for the duration of the call; the mode is only read with O_CREAT.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            libc::c_uint::from(mode),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a new descriptor that nothing else owns.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// `mkdirat` relative to `dir`; `EEXIST` is the caller's to interpret.
///
/// # Errors
///
/// Returns the OS error.
#[allow(unsafe_code)]
pub(crate) fn mkdirat(
    dir: &impl std::os::fd::AsRawFd,
    name: &std::ffi::CStr,
    mode: libc::mode_t,
) -> std::io::Result<()> {
    // SAFETY: descriptor and C string stay live for the call.
    if unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), mode) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Open or create the directory `name` under `parent` without following a
/// link. `Ok(None)` when it is missing and `create` is false; the bool says
/// whether this call created it.
fn open_or_create_dir_at(
    parent: &std::fs::File,
    name: &std::ffi::CStr,
    create: bool,
    before_create: impl FnOnce() -> Result<(), FileError>,
) -> Result<Option<(std::fs::File, bool)>, FileError> {
    let unsafe_or = |error: std::io::Error| {
        if is_unsafe_path_error(&error) {
            FileError::UnsafeFile
        } else {
            error.into()
        }
    };
    match openat(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
        Ok(directory) => return Ok(Some((directory, false))),
        Err(error) if error.raw_os_error() != Some(libc::ENOENT) => return Err(unsafe_or(error)),
        Err(_) if !create => return Ok(None),
        Err(_) => {}
    }
    before_create()?;
    let created = match mkdirat(parent, name, 0o700) {
        Ok(()) => true,
        Err(error) if error.raw_os_error() == Some(libc::EEXIST) => false,
        Err(error) => return Err(error.into()),
    };
    let directory =
        openat(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0).map_err(unsafe_or)?;
    Ok(Some((directory, created)))
}

#[allow(unsafe_code)]
#[allow(clippy::similar_names)]
pub(crate) fn open_owned_directory(
    path: &Path,
    create: bool,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<Option<OwnedDirectory>, FileError> {
    use std::ffi::CString;
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
    let Some((directory, created)) = open_or_create_dir_at(&parent, &leaf, create, || {
        validate_directory_descriptor(&parent, expected_uid)
    })?
    else {
        return Ok(None);
    };
    if created {
        prepare_created_descriptor(&directory, expected_uid, expected_gid, 0o700)?;
        parent.sync_all()?;
    }
    validate_directory_descriptor(&directory, expected_uid)?;
    Ok(Some(directory))
}

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
    use std::os::fd::AsRawFd as _;

    validate_directory_descriptor(parent, expected_uid)?;
    let name = CString::new(name).map_err(|_| FileError::UnsafeFile)?;
    let Some((directory, created)) = open_or_create_dir_at(parent, &name, create, || Ok(()))?
    else {
        return Ok(None);
    };
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
        let effective_uid = crate::platform::effective_user_group_ids().0;
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

#[allow(unsafe_code)]
fn open_absolute_directory(path: &Path) -> Result<std::fs::File, FileError> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd as _;
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
        directory = openat(&directory, &name, flags, 0).map_err(|error| {
            if is_unsafe_path_error(&error) {
                FileError::UnsafeFile
            } else {
                error.into()
            }
        })?;
    }
    Ok(directory)
}

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

fn is_unsafe_path_error(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code) if code == libc::ELOOP || code == libc::ENOTDIR)
}

#[allow(unsafe_code)]
fn prepare_created_descriptor(
    descriptor: &std::fs::File,
    uid: u32,
    gid: u32,
    mode: libc::mode_t,
) -> Result<(), FileError> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let effective = crate::platform::effective_user_group_ids();
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
#[derive(Clone, Copy)]
struct EntryReadPolicy {
    max_bytes: u64,
    forbidden_permission_bits: u32,
    require_single_link: bool,
}

#[allow(unsafe_code)]
fn read_owned_entry_with_policy(
    directory: &OwnedDirectory,
    name: &str,
    expected_uid: u32,
    policy: EntryReadPolicy,
) -> Result<Option<Vec<u8>>, FileError> {
    use std::ffi::CString;
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let name = CString::new(name).map_err(|_| FileError::UnsafeFile)?;
    let mut file = match openat(directory, &name, libc::O_RDONLY, 0) {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
        Err(error) if is_unsafe_path_error(&error) => return Err(FileError::UnsafeFile),
        Err(error) => return Err(error.into()),
    };
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
    use std::os::fd::AsRawFd as _;
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
        match openat(
            directory,
            &candidate_c,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        ) {
            Ok(file) => {
                allocated = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(AtomicWriteError::NotPublished(error.into())),
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

/// Who Vortix-written user state belongs to: the sudo user under sudo,
/// otherwise the current user.
pub(crate) fn invoking_owner() -> std::io::Result<(u32, u32)> {
    Ok(match crate::config::sudo_ids()? {
        Some(ids) if crate::platform::is_root() => ids,
        _ => crate::platform::effective_user_group_ids(),
    })
}

/// Pin `dir` (creating the leaf if missing) for the invoking user.
pub(crate) fn pin_user_dir(dir: &Path) -> std::io::Result<(OwnedDirectory, u32, u32)> {
    let (uid, gid) = invoking_owner()?;
    let directory = open_owned_directory(dir, true, uid, gid)
        .map_err(std::io::Error::other)?
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
    Ok((directory, uid, gid))
}

/// Atomically replace `dir/name` with `body`, owned by the invoking user,
/// without following links anywhere in the write.
pub(crate) fn write_user_file_atomic(dir: &Path, name: &str, body: &[u8]) -> std::io::Result<()> {
    let (directory, uid, gid) = pin_user_dir(dir)?;
    write_owned_atomic(&directory, name, body, uid, gid).map_err(std::io::Error::other)
}

/// Open (creating if needed) a lock file inside a pinned directory without
/// following links, and give it to `uid:gid` with mode 0600.
#[allow(unsafe_code)]
pub(crate) fn open_owned_lock(
    directory: &OwnedDirectory,
    name: &str,
    uid: u32,
    gid: u32,
) -> Result<std::fs::File, FileError> {
    use std::ffi::CString;

    let name = CString::new(name).map_err(|_| FileError::UnsafeFile)?;
    // O_NONBLOCK: a FIFO planted at the name must not hang the open.
    let file = openat(
        directory,
        &name,
        libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
        0o600,
    )
    .map_err(|error| {
        if is_unsafe_path_error(&error) {
            FileError::UnsafeFile
        } else {
            error.into()
        }
    })?;
    if !file.metadata()?.is_file() {
        return Err(FileError::UnsafeFile);
    }
    prepare_created_descriptor(&file, uid, gid, 0o600)?;
    Ok(file)
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

/// Create a directory (and parents) owned by, and private to, the real user.
///
/// Under sudo, `create_dir_all` produces root-owned dirs, so ownership is
/// handed back to the invoking user.
///
/// It also applies the caller's umask, and Debian derivatives log in at 002 —
/// which produced a group-writable 0775 for the profile store and the session
/// journal. The files inside are 0600, so keys stayed unreadable, but any
/// member of the user's group could rename, delete or replace a profile.
/// Every directory Vortix creates holds VPN state, so none of them should be
/// reachable by anyone else whatever the umask happens to be.
///
/// # Errors
///
/// Returns an error if directory creation fails.
pub fn create_user_dir(path: &std::path::Path) -> std::io::Result<()> {
    create_private_dir_all(path)?;
    make_private(path);
    crate::config::fix_ownership(path);
    Ok(())
}

/// Drop group and world access from a directory that already exists.
///
/// [`create_private_dir_all`] only sets the mode on directories it creates,
/// so an install made before Vortix set 0700 keeps whatever the umask gave
/// it — 0755 on macOS, 0775 on Ubuntu — for the rest of its life. These
/// directories hold VPN private keys, inline certificates and credentials,
/// so the mode is repaired on every run rather than only at creation.
///
/// Owner bits are preserved and access is only ever narrowed. A failure is
/// not fatal: the durable-state checks reject a directory that is still
/// unsafe, with a message that names it.
pub fn make_private(path: &std::path::Path) {
    {
        use std::os::unix::fs::PermissionsExt as _;
        let Ok(metadata) = std::fs::metadata(path) else {
            return;
        };
        let mode = metadata.permissions().mode() & 0o777;
        let private = mode & 0o700;
        if private == mode {
            return;
        }
        if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(private))
        {
            tracing::warn!(
                target: "vortix::config",
                path = %path.display(),
                from = format!("{mode:04o}"),
                to = format!("{private:04o}"),
                %error,
                "could not restrict a Vortix directory to owner-only access"
            );
        }
    }
}

/// `create_dir_all` with 0700 on every directory it creates.
///
/// `DirBuilder::mode` applies to each level it makes, which plain
/// `create_dir_all` plus a `set_permissions` on the leaf does not — the
/// intermediate parents keep the umask. Directories that already exist are
/// left alone, so a shared ancestor such as `~/.local/share` is untouched.
///
/// # Errors
///
/// Returns an error if directory creation fails.
pub fn create_private_dir_all(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

/// Write a file owned by the real user.
///
/// Under sudo, `fs::write` produces root-owned files.
/// This wraps that call and hands ownership to the invoking user.
///
/// # Errors
///
/// Returns an error if the write fails.
pub fn write_user_file(path: &std::path::Path, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(path, contents)?;
    crate::config::fix_ownership(path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An install predating the 0700 rule keeps the umask's mode forever
    /// unless startup repairs it. macOS gives 0755, Ubuntu 0775; both leave
    /// VPN private keys readable by every other account on the machine.
    #[test]
    fn an_existing_world_readable_directory_is_repaired() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::env::temp_dir().join(format!(
            "vortix-make-private-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");

        for laxity in [0o755, 0o775, 0o700] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(laxity))
                .expect("set mode");
            make_private(&dir);
            let mode = std::fs::metadata(&dir)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode, 0o700,
                "a directory created as {laxity:04o} must end up owner-only"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Narrowing only. A directory with no owner-execute bit must not gain
    /// one just because the repair ran.
    #[test]
    fn make_private_never_widens_owner_access() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::env::temp_dir().join(format!(
            "vortix-make-private-narrow-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o600)).expect("set mode");

        make_private(&dir);

        assert_eq!(
            std::fs::metadata(&dir)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "owner bits are preserved exactly; only group and other are dropped"
        );

        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
