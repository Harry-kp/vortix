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
use std::fs::{DirBuilder, File};
#[cfg(unix)]
use std::os::fd::{AsRawFd as _, FromRawFd as _};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
#[cfg(unix)]
use std::path::{Path, PathBuf};

#[cfg(unix)]
const AUTHORITY_LOCK_MODE: u32 = 0o400;
#[cfg(unix)]
const TEMPORARY_NAME: &CStr = c".authority.lock.installing";

#[cfg(unix)]
struct AuthorityLockStore {
    path: PathBuf,
    expected_parent_owner_uid: u32,
    expected_file_owner_uid: u32,
    expected_parent_mode: u32,
}

#[cfg(unix)]
impl AuthorityLockStore {
    fn installed(layout: crate::helper::validate::PlatformLayout, owner_uid: u32) -> Self {
        Self {
            path: PathBuf::from(layout.authority_lock()),
            expected_parent_owner_uid: 0,
            expected_file_owner_uid: owner_uid,
            expected_parent_mode: layout.authority_lock_dir_mode(),
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

    fn install(&self) -> std::io::Result<()> {
        let parent = self.parent()?;
        let created_parent = match DirBuilder::new()
            .mode(self.expected_parent_mode)
            .create(parent)
        {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(error) => return Err(error),
        };
        if created_parent {
            if let Some(ancestor) = parent.parent() {
                File::open(ancestor)?.sync_all()?;
            }
        }

        let parent_metadata = std::fs::symlink_metadata(parent)?;
        if !parent_metadata.is_dir()
            || parent_metadata.file_type().is_symlink()
            || parent_metadata.uid() != self.expected_parent_owner_uid
        {
            return Err(unsafe_path());
        }
        std::fs::set_permissions(
            parent,
            std::fs::Permissions::from_mode(self.expected_parent_mode),
        )?;

        let directory = self.open_parent()?;
        directory.sync_all()?;
        match self.open_file(&directory) {
            Ok(file) => {
                self.remove_recoverable_temporary(&directory, Some(&file))?;
                return self.repair_existing(&file);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        self.remove_recoverable_temporary(&directory, None)?;
        let temporary = Self::create_temporary(&directory)?;
        let result = (|| {
            self.initialize_temporary(&temporary)?;
            temporary.sync_all()?;
            self.validate_file(&temporary)?;

            let name = self.name()?;
            if unsafe {
                libc::linkat(
                    directory.as_raw_fd(),
                    TEMPORARY_NAME.as_ptr(),
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    0,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Self::unlink_temporary(&directory)?;
            directory.sync_all()?;
            let installed = self.open_file(&directory)?;
            self.validate_file(&installed)
        })();
        if result.is_err() {
            let _ = Self::unlink_temporary(&directory);
        }
        result
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

    fn create_temporary(directory: &File) -> std::io::Result<File> {
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                TEMPORARY_NAME.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                AUTHORITY_LOCK_MODE,
            )
        };
        if fd < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            let file = unsafe { File::from_raw_fd(fd) };
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(file)
        }
    }

    fn initialize_temporary(&self, file: &File) -> std::io::Result<()> {
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(unsafe_path());
        }
        if metadata.uid() != self.expected_file_owner_uid
            && unsafe {
                libc::fchown(
                    file.as_raw_fd(),
                    self.expected_file_owner_uid,
                    !0 as libc::gid_t,
                )
            } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        set_mode(file, AUTHORITY_LOCK_MODE)
    }

    fn repair_existing(&self, file: &File) -> std::io::Result<()> {
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != self.expected_file_owner_uid
            || metadata.nlink() != 1
        {
            return Err(unsafe_path());
        }
        set_mode(file, AUTHORITY_LOCK_MODE)?;
        self.validate_file(file)?;
        file.sync_all()
    }

    fn remove_recoverable_temporary(
        &self,
        directory: &File,
        installed: Option<&File>,
    ) -> std::io::Result<()> {
        let temporary = match openat_read(directory, TEMPORARY_NAME) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if unsafe { libc::flock(temporary.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let temporary_metadata = temporary.metadata()?;
        let expected_links = if let Some(installed) = installed {
            let installed_metadata = installed.metadata()?;
            if temporary_metadata.dev() == installed_metadata.dev()
                && temporary_metadata.ino() == installed_metadata.ino()
            {
                2
            } else {
                1
            }
        } else {
            1
        };
        if !temporary_metadata.is_file()
            || !matches!(
                temporary_metadata.uid(),
                uid if uid == 0 || uid == self.expected_file_owner_uid
            )
            || temporary_metadata.nlink() != expected_links
        {
            return Err(unsafe_path());
        }
        Self::unlink_temporary(directory)?;
        directory.sync_all()
    }

    fn unlink_temporary(directory: &File) -> std::io::Result<()> {
        if unsafe { libc::unlinkat(directory.as_raw_fd(), TEMPORARY_NAME.as_ptr(), 0) } != 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
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
fn set_mode(file: &File, mode: u32) -> std::io::Result<()> {
    let mode = libc::mode_t::try_from(mode).expect("authority lock mode fits mode_t");
    if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
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
pub(crate) fn install_and_acquire(
    layout: crate::helper::validate::PlatformLayout,
    owner_uid: u32,
) -> std::io::Result<File> {
    let store = AuthorityLockStore::installed(layout, owner_uid);
    store.install()?;
    store.acquire()?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "installed Vortix authority lock disappeared before acquisition",
        )
    })
}

#[cfg(unix)]
pub(crate) fn acquire_installed(owner_uid: u32) -> std::io::Result<Option<File>> {
    let Some(layout) = crate::helper::validate::PlatformLayout::current() else {
        return Ok(None);
    };
    AuthorityLockStore::installed(layout, owner_uid).acquire()
}

#[cfg(not(unix))]
pub(crate) fn install_and_acquire(
    _layout: crate::helper::validate::PlatformLayout,
    _owner_uid: u32,
) -> std::io::Result<std::fs::File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "installed authority lock is unavailable on this platform",
    ))
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
    fn root_controlled_transition_lock_serializes_writers() {
        let directory = tempfile::tempdir().unwrap();
        let store = test_store(&directory);
        store.install().unwrap();
        let metadata = std::fs::metadata(store.path()).unwrap();
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.permissions().mode() & 0o777, AUTHORITY_LOCK_MODE);

        let _first = store.acquire().unwrap().unwrap();
        let second = store.acquire().unwrap_err();

        assert_eq!(second.kind(), std::io::ErrorKind::WouldBlock);
    }

    #[test]
    fn unsafe_installed_lock_never_falls_back_to_legacy_authority() {
        let directory = tempfile::tempdir().unwrap();
        let store = test_store(&directory);
        std::os::unix::fs::symlink(directory.path().join("victim"), store.path()).unwrap();

        assert!(store.acquire().is_err());
    }

    #[test]
    fn linked_or_loose_installed_lock_is_rejected() {
        let loose_directory = tempfile::tempdir().unwrap();
        let loose = test_store(&loose_directory);
        loose.install().unwrap();
        std::fs::set_permissions(loose.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(loose.acquire().is_err());

        let linked_directory = tempfile::tempdir().unwrap();
        let linked = test_store(&linked_directory);
        linked.install().unwrap();
        std::fs::hard_link(linked.path(), linked_directory.path().join("alias")).unwrap();
        assert!(linked.acquire().is_err());
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
    fn trusted_install_repairs_owner_mode_tampering() {
        let directory = tempfile::tempdir().unwrap();
        let store = test_store(&directory);
        store.install().unwrap();
        std::fs::set_permissions(store.path(), std::fs::Permissions::from_mode(0o600)).unwrap();

        assert!(store.acquire().is_err());
        store.install().unwrap();
        assert_eq!(
            std::fs::metadata(store.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            AUTHORITY_LOCK_MODE
        );
        assert!(store.acquire().unwrap().is_some());
    }

    #[test]
    fn interrupted_temporary_install_is_recovered_before_publication() {
        let directory = tempfile::tempdir().unwrap();
        let store = test_store(&directory);
        let temporary = directory.path().join(".authority.lock.installing");
        std::fs::write(&temporary, []).unwrap();

        store.install().unwrap();

        assert!(store.path().is_file());
        assert!(!temporary.exists());
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

    #[test]
    fn trusted_install_repairs_an_interrupted_parent_mode() {
        let outer = tempfile::tempdir().unwrap();
        let parent = outer.path().join("public");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = parent.metadata().unwrap();
        let store = AuthorityLockStore::for_test(
            parent.join("authority.lock"),
            metadata.uid(),
            metadata.uid(),
            0o755,
        );

        store.install().unwrap();

        assert_eq!(
            parent.metadata().unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
}
