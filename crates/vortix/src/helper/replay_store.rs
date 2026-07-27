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

use super::server::ReplayStore;
use super::{PlatformLayout, HELPER_LEDGER_MODE, HELPER_RUNTIME_DIR_MODE};
use crate::vortix_core::privileged::{HelperLedgerRecord, ReplayBaseline, ReplayRecord};

const MAX_REPLAY_BYTES: u64 = 64 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Filesystem-backed replay store rooted in the package-created helper data
/// directory. Production construction requires UID 0; tests can exercise the
/// same ownership checks with their current effective UID.
pub(crate) struct FsReplayStore {
    path: PathBuf,
    expected_owner_uid: u32,
}

impl FsReplayStore {
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

    pub(crate) fn load(&self) -> Result<ReplayRecord, ReplayStoreError> {
        self.load_ledger().map(HelperLedgerRecord::into_replay)
    }

    fn load_ledger(&self) -> Result<HelperLedgerRecord, ReplayStoreError> {
        let parent = self.parent()?;
        validate_directory(parent, self.expected_owner_uid)?;
        let file = open_read_no_follow(&self.path)?;
        validate_file(&file, self.expected_owner_uid)?;
        let length = file.metadata()?.len();
        if length == 0 || length > MAX_REPLAY_BYTES {
            return Err(ReplayStoreError::Capacity);
        }
        let capacity = usize::try_from(length).map_err(|_| ReplayStoreError::Capacity)?;
        let mut bytes = Vec::with_capacity(capacity);
        file.take(MAX_REPLAY_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_REPLAY_BYTES {
            return Err(ReplayStoreError::Capacity);
        }
        serde_json::from_slice(&bytes).map_err(|_| ReplayStoreError::Corrupt)
    }

    pub(crate) fn initialize(&mut self, baseline: ReplayBaseline) -> Result<(), ReplayStoreError> {
        self.write(&baseline.into_record())
    }

    fn write(&self, checkpoint: &ReplayRecord) -> Result<(), ReplayStoreError> {
        let parent = self.parent()?;
        validate_directory(parent, self.expected_owner_uid)?;
        match open_read_no_follow(&self.path) {
            Ok(file) => validate_file(&file, self.expected_owner_uid)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        let mut ledger = match self.load_ledger() {
            Ok(ledger) => ledger,
            Err(ReplayStoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                HelperLedgerRecord::empty(checkpoint.clone())
            }
            Err(error) => return Err(error),
        };
        ledger.replace_replay(checkpoint.clone());
        let bytes = serde_json::to_vec(&ledger)?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_REPLAY_BYTES {
            return Err(ReplayStoreError::Capacity);
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

    fn parent(&self) -> Result<&Path, ReplayStoreError> {
        self.path.parent().ok_or(ReplayStoreError::UnsafePath)
    }
}

fn create_temporary(parent: &Path) -> Result<(PathBuf, File), ReplayStoreError> {
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

impl ReplayStore for FsReplayStore {
    fn persist(&mut self, checkpoint: &ReplayRecord) -> Result<(), ()> {
        self.write(checkpoint).map_err(|_| ())
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

fn validate_directory(path: &Path, expected_owner_uid: u32) -> Result<(), ReplayStoreError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ReplayStoreError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != expected_owner_uid
            || metadata.permissions().mode() & 0o777 != HELPER_RUNTIME_DIR_MODE
        {
            return Err(ReplayStoreError::UnsafePath);
        }
    }
    Ok(())
}

fn validate_file(file: &File, expected_owner_uid: u32) -> Result<(), ReplayStoreError> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(ReplayStoreError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != expected_owner_uid
            || metadata.permissions().mode() & 0o777 != HELPER_LEDGER_MODE
            || metadata.nlink() != 1
        {
            return Err(ReplayStoreError::UnsafePath);
        }
    }
    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum ReplayStoreError {
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

    fn replay_record() -> ReplayRecord {
        replay_baseline().into_record()
    }

    fn store() -> (tempfile::TempDir, FsReplayStore) {
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
        let store = FsReplayStore::for_test(directory.path().join("ledger.json"), uid);
        (directory, store)
    }

    #[test]
    fn private_checkpoint_roundtrips_and_replaces_atomically() {
        let (directory, mut store) = store();
        let baseline = replay_baseline();
        let record = baseline.clone().into_record();
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
        let record = replay_record();
        let mut writable = FsReplayStore::for_test(
            directory.path().join("ledger.json"),
            crate::utils::effective_user_group_ids().0,
        );
        writable.persist(&record).unwrap();
        std::fs::write(directory.path().join("ledger.json"), b"not json").unwrap();
        assert!(matches!(store.load(), Err(ReplayStoreError::Corrupt)));

        std::fs::write(
            directory.path().join("ledger.json"),
            vec![b'x'; usize::try_from(MAX_REPLAY_BYTES).unwrap() + 1],
        )
        .unwrap();
        assert!(matches!(store.load(), Err(ReplayStoreError::Capacity)));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755))
                .unwrap();
            assert!(matches!(store.load(), Err(ReplayStoreError::UnsafePath)));
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

        assert!(store.persist(&replay_record()).is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside");
    }

    #[cfg(unix)]
    #[test]
    fn hard_linked_ledger_is_never_loaded_or_replaced() {
        let (directory, mut store) = store();
        let record = replay_record();
        store.persist(&record).unwrap();
        std::fs::hard_link(
            directory.path().join("ledger.json"),
            directory.path().join("ledger.alias"),
        )
        .unwrap();

        assert!(matches!(store.load(), Err(ReplayStoreError::UnsafePath)));
        assert!(store.persist(&record).is_err());
    }
}
