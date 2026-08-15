//! Root-owned, crash-safe helper replay checkpoint storage.

#![allow(
    dead_code,
    reason = "U12 store remains unreachable until U13 enrollment gates it"
)]

use thiserror::Error;

use super::root_store::{RootOwnedJsonStore, RootStoreError};
use super::server::HelperLedgerStore;
use super::PlatformLayout;
use crate::vortix_core::privileged::{HelperLedgerRecord, ReplayBaseline};

const MAX_HELPER_LEDGER_BYTES: u64 = 64 * 1024;

/// Filesystem-backed replay store rooted in the package-created helper data
/// directory. Production construction requires UID 0; tests can exercise the
/// same ownership checks with their current effective UID.
pub(crate) struct FsHelperLedgerStore {
    store: RootOwnedJsonStore,
}

impl FsHelperLedgerStore {
    pub(crate) fn root_owned(layout: PlatformLayout) -> Self {
        Self {
            store: RootOwnedJsonStore::new(
                layout.root_ledger(),
                0,
                layout.root_state_dir_mode(),
                MAX_HELPER_LEDGER_BYTES,
                "helper-ledger",
            )
            .expect("fixed helper ledger path is absolute and valid"),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(path: impl Into<std::path::PathBuf>, expected_owner_uid: u32) -> Self {
        Self {
            store: RootOwnedJsonStore::new(
                path,
                expected_owner_uid,
                super::HELPER_RUNTIME_DIR_MODE,
                MAX_HELPER_LEDGER_BYTES,
                "helper-ledger",
            )
            .unwrap(),
        }
    }

    pub(crate) fn load(&self) -> Result<HelperLedgerRecord, HelperLedgerStoreError> {
        let bytes = self.store.load().map_err(HelperLedgerStoreError::from)?;
        serde_json::from_slice(&bytes).map_err(|_| HelperLedgerStoreError::Corrupt)
    }

    pub(crate) fn initialize(
        &mut self,
        baseline: ReplayBaseline,
    ) -> Result<(), HelperLedgerStoreError> {
        let _lock = self.store.lock_sibling(c"helper-ledger.lock")?;
        match self.load() {
            Err(HelperLedgerStoreError::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err(HelperLedgerStoreError::AlreadyInitialized),
            Err(error) => return Err(error),
        }
        self.write_under_lock(&HelperLedgerRecord::empty(baseline.into_record()))
    }

    fn write(&self, ledger: &HelperLedgerRecord) -> Result<(), HelperLedgerStoreError> {
        let _lock = self.store.lock_sibling(c"helper-ledger.lock")?;
        self.write_under_lock(ledger)
    }

    fn write_under_lock(&self, ledger: &HelperLedgerRecord) -> Result<(), HelperLedgerStoreError> {
        match self.load() {
            Ok(_) => {}
            Err(HelperLedgerStoreError::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let bytes = serde_json::to_vec(ledger)?;
        self.store
            .write(&bytes)
            .map_err(HelperLedgerStoreError::from)
    }
}

impl HelperLedgerStore for FsHelperLedgerStore {
    fn persist(&mut self, ledger: &HelperLedgerRecord) -> Result<(), ()> {
        self.write(ledger).map_err(|_| ())
    }
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
    #[error("helper replay ledger is already initialized")]
    AlreadyInitialized,
}

impl From<RootStoreError> for HelperLedgerStoreError {
    fn from(error: RootStoreError) -> Self {
        match error {
            RootStoreError::UnsafePath => Self::UnsafePath,
            RootStoreError::Capacity => Self::Capacity,
            RootStoreError::TemporaryNamespaceExhausted => Self::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "helper state temporary namespace is exhausted",
            )),
            RootStoreError::Io(error) => Self::Io(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::validate::{verify_service_instance, VerifiedServiceFacts};
    use crate::helper::HELPER_RUNTIME_DIR_MODE;
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
        assert!(matches!(
            store.initialize(replay_baseline()),
            Err(HelperLedgerStoreError::AlreadyInitialized)
        ));
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
