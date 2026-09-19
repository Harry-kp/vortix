//! Root-controlled cross-process writer lock for enrollment-capable packages.
//!
//! The legacy lock lives in the invoking user's config directory. That is
//! sufficient while Standard mode is the only authority, but an enrolled
//! daemon must not depend on an owner-replaceable inode. The trusted package
//! bootstrap installs this owner-readable lock below a fixed root-owned
//! directory. Current clients retain the legacy lock before acquiring this
//! one, so they remain serialized with a process that started before package
//! installation. Bootstrap transitions use the installed lock, but this
//! preparatory release does not activate a remote writer; U13 still requires
//! its minimum-version and local-admission drain gates before authority
//! cutover. A present-but-malformed installation always fails closed.

#![allow(
    unsafe_code,
    reason = "descriptor-relative no-follow opens and flock require libc"
)]

#[cfg(unix)]
use std::ffi::{CStr, CString};
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::os::fd::{AsRawFd as _, FromRawFd as _};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
#[cfg(unix)]
use std::path::{Path, PathBuf};

#[cfg(unix)]
const AUTHORITY_LOCK_MODE: u32 = 0o400;

/// Where a packaged install puts its root-owned lock. Absent on any OS
/// Vortix has no package layout for, which makes the lock a no-op there.
#[cfg(target_os = "linux")]
// xtask:allow-platform-cfg: package layout is selected by the build target
const AUTHORITY_LOCK_PATH: Option<&str> = Some("/var/lib/vortix-public/authority.lock");
#[cfg(target_os = "macos")]
// xtask:allow-platform-cfg: package layout is selected by the build target
const AUTHORITY_LOCK_PATH: Option<&str> =
    Some("/Library/Application Support/Vortix/Public/authority.lock");
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const AUTHORITY_LOCK_PATH: Option<&str> = None;

const AUTHORITY_LOCK_DIR_MODE: u32 = 0o755;

#[cfg(unix)]
struct AuthorityLockStore {
    path: PathBuf,
    expected_parent_owner_uid: u32,
    expected_file_owner_uid: u32,
    expected_parent_mode: u32,
}

#[cfg(unix)]
impl AuthorityLockStore {
    fn installed(path: &str, owner_uid: u32) -> Self {
        Self {
            path: PathBuf::from(path),
            expected_parent_owner_uid: 0,
            expected_file_owner_uid: owner_uid,
            expected_parent_mode: AUTHORITY_LOCK_DIR_MODE,
        }
    }

    #[cfg(test)]
    fn for_test(
        path: PathBuf,
        expected_parent_owner_uid: u32,
        expected_file_owner_uid: u32,
        expected_parent_mode: u32,
    ) -> Self {
        Self {
            path,
            expected_parent_owner_uid,
            expected_file_owner_uid,
            expected_parent_mode,
        }
    }

    #[cfg(test)]
    fn path(&self) -> &Path {
        &self.path
    }

    fn acquire(&self) -> std::io::Result<Option<File>> {
        let directory = match self.open_parent() {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let file = match self.open_file(&directory) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(unsafe_path());
            }
            Err(error) => return Err(error),
        };
        self.validate_file(&file)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Some(file))
    }

    fn parent(&self) -> std::io::Result<&Path> {
        self.path
            .parent()
            .filter(|path| path.is_absolute())
            .ok_or_else(unsafe_path)
    }

    fn name(&self) -> std::io::Result<CString> {
        let name = self
            .path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(unsafe_path)?;
        CString::new(name.as_bytes()).map_err(|_| unsafe_path())
    }

    fn open_parent(&self) -> std::io::Result<File> {
        let parent =
            CString::new(self.parent()?.as_os_str().as_bytes()).map_err(|_| unsafe_path())?;
        let fd = unsafe {
            libc::open(
                parent.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let directory = unsafe { File::from_raw_fd(fd) };
        let metadata = directory.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != self.expected_parent_owner_uid
            || metadata.permissions().mode() & 0o777 != self.expected_parent_mode
        {
            return Err(unsafe_path());
        }
        Ok(directory)
    }

    fn open_file(&self, directory: &File) -> std::io::Result<File> {
        let name = self.name()?;
        openat_read(directory, &name)
    }

    fn validate_file(&self, file: &File) -> std::io::Result<()> {
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != self.expected_file_owner_uid
            || metadata.permissions().mode() & 0o777 != AUTHORITY_LOCK_MODE
            || metadata.nlink() != 1
        {
            return Err(unsafe_path());
        }
        Ok(())
    }
}

#[cfg(unix)]
fn openat_read(directory: &File, name: &CStr) -> std::io::Result<File> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(unix)]
fn unsafe_path() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "installed Vortix authority lock is not bound to its expected owner and root-controlled directory",
    )
}

#[cfg(unix)]
pub(crate) fn acquire_installed(owner_uid: u32) -> std::io::Result<Option<File>> {
    let Some(path) = AUTHORITY_LOCK_PATH else {
        return Ok(None);
    };
    AuthorityLockStore::installed(path, owner_uid).acquire()
}

#[cfg(not(unix))]
pub(crate) fn acquire_installed(_owner_uid: u32) -> std::io::Result<Option<std::fs::File>> {
    Ok(None)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn test_store(directory: &tempfile::TempDir) -> AuthorityLockStore {
        let metadata = directory.path().metadata().unwrap();
        AuthorityLockStore::for_test(
            directory.path().join("authority.lock"),
            metadata.uid(),
            metadata.uid(),
            metadata.permissions().mode() & 0o777,
        )
    }

    #[test]
    fn unsafe_installed_lock_never_falls_back_to_legacy_authority() {
        let directory = tempfile::tempdir().unwrap();
        let store = test_store(&directory);
        std::os::unix::fs::symlink(directory.path().join("victim"), store.path()).unwrap();

        assert!(store.acquire().is_err());
    }

    #[test]
    fn absent_package_lock_is_distinct_from_an_invalid_installed_lock() {
        let directory = tempfile::tempdir().unwrap();
        let metadata = directory.path().metadata().unwrap();
        let store = AuthorityLockStore::for_test(
            directory
                .path()
                .join("not-installed")
                .join("authority.lock"),
            metadata.uid(),
            metadata.uid(),
            metadata.permissions().mode() & 0o777,
        );

        assert!(store.acquire().unwrap().is_none());
    }

    #[test]
    fn installed_marker_without_lock_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let store = test_store(&directory);

        assert!(store.acquire().is_err());
    }

    #[test]
    fn parent_expectations_are_not_derived_from_the_path_under_test() {
        let directory = tempfile::tempdir().unwrap();
        let metadata = directory.path().metadata().unwrap();
        let wrong_mode = (metadata.permissions().mode() & 0o777) ^ 0o100;
        let store = AuthorityLockStore::for_test(
            directory.path().join("authority.lock"),
            metadata.uid(),
            metadata.uid(),
            wrong_mode,
        );

        assert!(store.acquire().is_err());
    }
}
