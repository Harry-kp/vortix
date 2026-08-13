//! Descriptor-relative storage for bounded root-owned helper state.

#![allow(
    dead_code,
    reason = "the shared store becomes production-reachable with helper enrollment"
)]
#![allow(
    unsafe_code,
    reason = "descriptor-relative no-follow storage requires openat/renameat/unlinkat"
)]

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

use super::HELPER_LEDGER_MODE;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) struct RootOwnedJsonStore {
    parent: PathBuf,
    name: CString,
    expected_owner_uid: u32,
    expected_parent_mode: u32,
    max_bytes: u64,
    temporary_prefix: &'static str,
}

impl RootOwnedJsonStore {
    pub(super) fn new(
        path: impl Into<PathBuf>,
        expected_owner_uid: u32,
        expected_parent_mode: u32,
        max_bytes: u64,
        temporary_prefix: &'static str,
    ) -> Result<Self, RootStoreError> {
        let path = path.into();
        let parent = path
            .parent()
            .filter(|parent| parent.is_absolute())
            .ok_or(RootStoreError::UnsafePath)?
            .to_owned();
        let name = path
            .file_name()
            .filter(|name| !name.is_empty() && name.as_bytes().len() <= 255)
            .ok_or(RootStoreError::UnsafePath)?;
        let name = CString::new(name.as_bytes()).map_err(|_| RootStoreError::UnsafePath)?;
        if max_bytes == 0 || temporary_prefix.is_empty() {
            return Err(RootStoreError::UnsafePath);
        }
        Ok(Self {
            parent,
            name,
            expected_owner_uid,
            expected_parent_mode,
            max_bytes,
            temporary_prefix,
        })
    }

    pub(super) fn load(&self) -> Result<Vec<u8>, RootStoreError> {
        let directory = self.open_parent()?;
        let file = openat_read(&directory, &self.name)?;
        validate_file(&file, self.expected_owner_uid)?;
        read_bounded(file, self.max_bytes)
    }

    pub(super) fn write(&self, bytes: &[u8]) -> Result<(), RootStoreError> {
        if bytes.is_empty() || bytes.len() as u64 > self.max_bytes {
            return Err(RootStoreError::Capacity);
        }
        let directory = self.open_parent()?;
        match openat_read(&directory, &self.name) {
            Ok(existing) => validate_file(&existing, self.expected_owner_uid)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        let (temporary_name, mut temporary) = self.create_temporary(&directory)?;
        let result = (|| {
            temporary.write_all(bytes)?;
            temporary.sync_all()?;
            validate_file(&temporary, self.expected_owner_uid)?;
            renameat(&directory, &temporary_name, &self.name)?;
            directory.sync_all()?;
            let installed = openat_read(&directory, &self.name)?;
            validate_file(&installed, self.expected_owner_uid)
        })();
        if result.is_err() {
            let _ = unlinkat(&directory, &temporary_name);
        }
        result
    }

    pub(super) fn lock_sibling(&self, name: &CStr) -> Result<RootOwnedStoreLock, RootStoreError> {
        let directory = self.open_parent()?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                HELPER_LEDGER_MODE,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        validate_file(&file, self.expected_owner_uid)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(RootOwnedStoreLock { file })
    }

    fn open_parent(&self) -> Result<File, RootStoreError> {
        let parent = CString::new(self.parent.as_os_str().as_bytes())
            .map_err(|_| RootStoreError::UnsafePath)?;
        let fd = unsafe {
            libc::open(
                parent.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let directory = unsafe { File::from_raw_fd(fd) };
        let metadata = directory.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != self.expected_owner_uid
            || metadata.permissions().mode() & 0o777 != self.expected_parent_mode
        {
            return Err(RootStoreError::UnsafePath);
        }
        Ok(directory)
    }

    fn create_temporary(&self, directory: &File) -> Result<(CString, File), RootStoreError> {
        for _ in 0..64 {
            let name = CString::new(format!(
                ".{}.{}.{}.tmp",
                self.temporary_prefix,
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ))
            .expect("fixed temporary prefix and integers contain no NUL");
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    HELPER_LEDGER_MODE,
                )
            };
            if fd >= 0 {
                let file = unsafe { File::from_raw_fd(fd) };
                validate_file(&file, self.expected_owner_uid)?;
                return Ok((name, file));
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(error.into());
            }
        }
        Err(RootStoreError::TemporaryNamespaceExhausted)
    }
}

pub(super) struct RootOwnedStoreLock {
    file: File,
}

impl Drop for RootOwnedStoreLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn openat_read(directory: &File, name: &CString) -> std::io::Result<File> {
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

fn validate_file(file: &File, expected_owner_uid: u32) -> Result<(), RootStoreError> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != expected_owner_uid
        || metadata.permissions().mode() & 0o777 != HELPER_LEDGER_MODE
        || metadata.nlink() != 1
    {
        return Err(RootStoreError::UnsafePath);
    }
    Ok(())
}

fn read_bounded(mut file: File, max_bytes: u64) -> Result<Vec<u8>, RootStoreError> {
    let length = file.metadata()?.len();
    if length == 0 || length > max_bytes {
        return Err(RootStoreError::Capacity);
    }
    let capacity = usize::try_from(length).map_err(|_| RootStoreError::Capacity)?;
    let mut bytes = Vec::with_capacity(capacity);
    std::io::Read::by_ref(&mut file)
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        return Err(RootStoreError::Capacity);
    }
    Ok(bytes)
}

fn renameat(directory: &File, from: &CString, to: &CString) -> std::io::Result<()> {
    let result = unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn unlinkat(directory: &File, name: &CString) -> std::io::Result<()> {
    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[derive(Debug, Error)]
pub(super) enum RootStoreError {
    #[error("helper state path, owner, mode, or link count is unsafe")]
    UnsafePath,
    #[error("helper state is empty or exceeds its fixed size")]
    Capacity,
    #[error("helper state temporary namespace is exhausted")]
    TemporaryNamespaceExhausted,
    #[error("helper state I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, RootOwnedJsonStore) {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            directory.path(),
            std::fs::Permissions::from_mode(super::super::HELPER_RUNTIME_DIR_MODE),
        )
        .unwrap();
        let uid = crate::utils::effective_user_group_ids().0;
        let store = RootOwnedJsonStore::new(
            directory.path().join("state.json"),
            uid,
            super::super::HELPER_RUNTIME_DIR_MODE,
            1024,
            "state",
        )
        .unwrap();
        (directory, store)
    }

    #[test]
    fn descriptor_relative_roundtrip_replaces_atomically() {
        let (directory, store) = store();
        store.write(br#"{"generation":1}"#).unwrap();
        store.write(br#"{"generation":2}"#).unwrap();

        assert_eq!(store.load().unwrap(), br#"{"generation":2}"#);
        assert_eq!(
            std::fs::read_dir(directory.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                .count(),
            0
        );
    }

    #[test]
    fn unsafe_parent_link_and_oversized_state_fail_closed() {
        let (directory, store) = store();
        assert!(matches!(
            store.write(&vec![b'x'; 1025]),
            Err(RootStoreError::Capacity)
        ));

        let link = directory.path().with_extension("link");
        std::os::unix::fs::symlink(directory.path(), &link).unwrap();
        let linked = RootOwnedJsonStore::new(
            link.join("state.json"),
            crate::utils::effective_user_group_ids().0,
            super::super::HELPER_RUNTIME_DIR_MODE,
            1024,
            "state",
        )
        .unwrap();
        assert!(linked.write(b"{}").is_err());
    }

    #[test]
    fn existing_unsafe_file_is_rejected_without_repair() {
        let (directory, store) = store();
        let path = directory.path().join("state.json");
        std::fs::write(&path, b"foreign").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert!(matches!(
            store.write(b"{}"),
            Err(RootStoreError::UnsafePath)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"foreign");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
}
