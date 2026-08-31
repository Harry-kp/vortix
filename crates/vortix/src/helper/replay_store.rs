//! Root-owned, crash-safe helper replay checkpoint storage.

#![allow(
    dead_code,
    reason = "U12 store remains unreachable until U13 enrollment gates it"
)]

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

use super::server::HelperLedgerStore;
use super::{PlatformLayout, HELPER_LEDGER_MODE, HELPER_RUNTIME_DIR_MODE};
use crate::vortix_core::privileged::{HelperLedgerRecord, ReplayBaseline};

const MAX_HELPER_LEDGER_BYTES: u64 = 64 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Filesystem-backed replay store rooted in the package-created helper data
/// directory. Production construction requires UID 0; tests can exercise the
/// same ownership checks with their current effective UID.
pub(crate) struct FsHelperLedgerStore {
    path: PathBuf,
    expected_owner_uid: u32,
}

impl FsHelperLedgerStore {
    pub(crate) fn root_owned(layout: PlatformLayout) -> Self {
        Self {
            path: PathBuf::from(layout.root_ledger()),
            expected_owner_uid: 0,
        }
    }

    #[cfg(test)]
    fn for_test(path: impl Into<PathBuf>, expected_owner_uid: u32) -> Self {
        Self {
            path: path.into(),
            expected_owner_uid,
        }
    }

    pub(crate) fn load(&self) -> Result<HelperLedgerRecord, HelperLedgerStoreError> {
        let parent = self.parent()?;
        validate_directory(parent, self.expected_owner_uid)?;
        self.load_from_validated_parent()
    }

    fn load_from_validated_parent(&self) -> Result<HelperLedgerRecord, HelperLedgerStoreError> {
        let file = open_read_no_follow(&self.path)?;
        validate_file(&file, self.expected_owner_uid)?;
        let length = file.metadata()?.len();
        if length == 0 || length > MAX_HELPER_LEDGER_BYTES {
            return Err(HelperLedgerStoreError::Capacity);
        }
        let capacity = usize::try_from(length).map_err(|_| HelperLedgerStoreError::Capacity)?;
        let mut bytes = Vec::with_capacity(capacity);
        file.take(MAX_HELPER_LEDGER_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_HELPER_LEDGER_BYTES {
            return Err(HelperLedgerStoreError::Capacity);
        }
        serde_json::from_slice(&bytes).map_err(|_| HelperLedgerStoreError::Corrupt)
    }

    pub(crate) fn initialize(
        &mut self,
        baseline: ReplayBaseline,
    ) -> Result<(), HelperLedgerStoreError> {
        self.write(&HelperLedgerRecord::empty(baseline.into_record()))
    }

    fn write(&self, ledger: &HelperLedgerRecord) -> Result<(), HelperLedgerStoreError> {
        let parent = self.parent()?;
        validate_directory(parent, self.expected_owner_uid)?;
        match self.load_from_validated_parent() {
            Ok(_) => {}
            Err(HelperLedgerStoreError::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let bytes = serde_json::to_vec(ledger)?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_HELPER_LEDGER_BYTES {
            return Err(HelperLedgerStoreError::Capacity);
        }
        let (temporary, mut file) = create_temporary(parent)?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            validate_file(&file, self.expected_owner_uid)?;
            std::fs::rename(&temporary, &self.path)?;
            File::open(parent)?.sync_all()?;
            let installed = open_read_no_follow(&self.path)?;
            validate_file(&installed, self.expected_owner_uid)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    fn parent(&self) -> Result<&Path, HelperLedgerStoreError> {
        self.path.parent().ok_or(HelperLedgerStoreError::UnsafePath)
    }
}

fn create_temporary(parent: &Path) -> Result<(PathBuf, File), HelperLedgerStoreError> {
    for _ in 0..64 {
        let path = parent.join(format!(
            ".helper-ledger.{}.{}.tmp",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        match open_new_private(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "helper replay temporary namespace is exhausted",
    )
    .into())
}

impl HelperLedgerStore for FsHelperLedgerStore {
    fn persist(&mut self, ledger: &HelperLedgerRecord) -> Result<(), ()> {
        self.write(ledger).map_err(|_| ())
    }
}

fn open_read_no_follow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn open_new_private(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(HELPER_LEDGER_MODE)
            .custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn validate_directory(path: &Path, expected_owner_uid: u32) -> Result<(), HelperLedgerStoreError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(HelperLedgerStoreError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != expected_owner_uid
            || metadata.permissions().mode() & 0o777 != HELPER_RUNTIME_DIR_MODE
        {
            return Err(HelperLedgerStoreError::UnsafePath);
        }
    }
    Ok(())
}

fn validate_file(file: &File, expected_owner_uid: u32) -> Result<(), HelperLedgerStoreError> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(HelperLedgerStoreError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != expected_owner_uid
            || metadata.permissions().mode() & 0o777 != HELPER_LEDGER_MODE
            || metadata.nlink() != 1
        {
            return Err(HelperLedgerStoreError::UnsafePath);
        }
    }
    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum HelperLedgerStoreError {
    #[error("helper replay ledger path, owner, mode, or link count is unsafe")]
    UnsafePath,
    #[error("helper replay ledger is empty or exceeds its fixed size")]
    Capacity,
    #[error("helper replay ledger is malformed or failed strict validation")]
    Corrupt,
    #[error("helper replay ledger I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("helper replay ledger serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::validate::{verify_service_instance, VerifiedServiceFacts};
    use crate::vortix_core::control::AuthorityEpoch;
    use crate::vortix_core::privileged::{
        BootScope, HelperEpoch, LeaseId, OperationDigest, RootAuthorityLedger,
        ServiceInstanceClaim, ServiceManager,
    };

    fn replay_baseline() -> ReplayBaseline {
        let digest = OperationDigest::of_bytes(b"root-owned daemon");
        let claim = ServiceInstanceClaim::systemd(42, 99, digest, [7; 32]).unwrap();
        let uid = 501;
        let facts = VerifiedServiceFacts::from_os_verifier(
            ServiceManager::Systemd,
            uid,
            42,
            99,
            digest,
            [7; 32],
            true,
            true,
        );
        let verified = verify_service_instance(uid, &claim, &facts).unwrap();
        let root = RootAuthorityLedger::from_platform_verified(
            verified,
            BootScope::new([4; 16]),
            AuthorityEpoch(3),
            LeaseId::new([5; 32]),
        )
        .unwrap();
        let principal = root.principal();
        root.unused_replay_baseline(&principal, HelperEpoch::new(8).unwrap())
            .unwrap()
    }

    fn ledger_record() -> HelperLedgerRecord {
        HelperLedgerRecord::empty(replay_baseline().into_record())
    }

    fn store() -> (tempfile::TempDir, FsHelperLedgerStore) {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                directory.path(),
                std::fs::Permissions::from_mode(HELPER_RUNTIME_DIR_MODE),
            )
            .unwrap();
        }
        let uid = crate::utils::effective_user_group_ids().0;
        let store = FsHelperLedgerStore::for_test(directory.path().join("ledger.json"), uid);
        (directory, store)
    }

    #[test]
    fn private_checkpoint_roundtrips_and_replaces_atomically() {
        let (directory, mut store) = store();
        let baseline = replay_baseline();
        let record = HelperLedgerRecord::empty(baseline.clone().into_record());
        store.initialize(baseline).unwrap();
        store.persist(&record).unwrap();

        assert_eq!(store.load().unwrap(), record);
        let leftovers = std::fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn corrupt_oversized_and_unsafe_paths_fail_closed() {
        let (directory, store) = store();
        let record = ledger_record();
        let mut writable = FsHelperLedgerStore::for_test(
            directory.path().join("ledger.json"),
            crate::utils::effective_user_group_ids().0,
        );
        writable.persist(&record).unwrap();
        std::fs::write(directory.path().join("ledger.json"), b"not json").unwrap();
        assert!(matches!(store.load(), Err(HelperLedgerStoreError::Corrupt)));
        assert!(writable.persist(&record).is_err());
        assert_eq!(
            std::fs::read(directory.path().join("ledger.json")).unwrap(),
            b"not json"
        );

        std::fs::write(
            directory.path().join("ledger.json"),
            vec![b'x'; usize::try_from(MAX_HELPER_LEDGER_BYTES).unwrap() + 1],
        )
        .unwrap();
        assert!(matches!(
            store.load(),
            Err(HelperLedgerStoreError::Capacity)
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755))
                .unwrap();
            assert!(matches!(
                store.load(),
                Err(HelperLedgerStoreError::UnsafePath)
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_ledger_is_never_followed() {
        use std::os::unix::fs::symlink;

        let (directory, mut store) = store();
        let outside = directory.path().join("outside");
        std::fs::write(&outside, b"outside").unwrap();
        symlink(&outside, directory.path().join("ledger.json")).unwrap();

        assert!(store.persist(&ledger_record()).is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside");
    }

    #[cfg(unix)]
    #[test]
    fn hard_linked_ledger_is_never_loaded_or_replaced() {
        let (directory, mut store) = store();
        let record = ledger_record();
        store.persist(&record).unwrap();
        std::fs::hard_link(
            directory.path().join("ledger.json"),
            directory.path().join("ledger.alias"),
        )
        .unwrap();

        assert!(matches!(
            store.load(),
            Err(HelperLedgerStoreError::UnsafePath)
        ));
        assert!(store.persist(&record).is_err());
    }
}
