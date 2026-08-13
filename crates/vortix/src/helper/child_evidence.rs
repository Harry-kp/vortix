//! Root-owned, no-overwrite persistence for foreground child identity.

#![allow(
    dead_code,
    reason = "U12 child persistence remains unreachable until tunnel execution lands"
)]

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

use crate::helper::private_fs::{create_private_directory, private_directory_is_valid};
use crate::helper::runtime::HelperRuntimeIdentity;
use crate::helper::validate::{
    PlatformLayout, HELPER_LEDGER_MODE, HELPER_RUNTIME_DIR_MODE, HELPER_SOCKET_DIR_MODE,
};
use crate::vortix_core::ports::process::KernelProcessIdentity;
use crate::vortix_core::privileged::{ContainmentId, ObservedChildIdentity, ResourceTag};

const MAX_CHILD_EVIDENCE_BYTES: u64 = 4 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Fixed storage for one lease/profile/generation-scoped child record.
pub(crate) struct ChildEvidenceStore {
    runtime_root: PathBuf,
    runtime_dir: PathBuf,
    path: PathBuf,
    resource: ResourceTag,
    containment: ContainmentId,
    expected_owner_uid: u32,
}

impl ChildEvidenceStore {
    pub(crate) fn root_owned(layout: PlatformLayout, runtime: &HelperRuntimeIdentity) -> Self {
        Self {
            runtime_root: PathBuf::from(layout.helper_runtime_dir()),
            runtime_dir: runtime.runtime_dir().to_owned(),
            path: runtime.openvpn_child_evidence(),
            resource: runtime.resource().clone(),
            containment: runtime.containment(),
            expected_owner_uid: 0,
        }
    }

    #[cfg(test)]
    fn for_test(
        runtime_root: PathBuf,
        resource: ResourceTag,
        containment: ContainmentId,
        expected_owner_uid: u32,
    ) -> Self {
        let runtime_dir = runtime_root.join("resources").join("test-resource");
        let path = runtime_dir.join("openvpn-child.json");
        Self {
            runtime_root,
            runtime_dir,
            path,
            resource,
            containment,
            expected_owner_uid,
        }
    }

    /// Observe the kernel identity only after spawn containment, then persist
    /// the exact result. A numeric PID or caller-created token is insufficient.
    pub(crate) fn persist_live(
        &self,
        pid: u32,
    ) -> Result<ObservedChildIdentity, ChildEvidenceError> {
        self.persist_live_with(pid, crate::platform::observe_process_identity)
    }

    fn persist_live_with<F>(
        &self,
        pid: u32,
        observe: F,
    ) -> Result<ObservedChildIdentity, ChildEvidenceError>
    where
        F: FnOnce(u32) -> std::io::Result<Option<KernelProcessIdentity>>,
    {
        let kernel = observe(pid)?.ok_or(ChildEvidenceError::ProcessUnavailable)?;
        if !kernel.is_process_group_leader() {
            return Err(ChildEvidenceError::NotPrivateProcessGroup);
        }
        let identity = ObservedChildIdentity::new(
            self.resource.clone(),
            pid,
            kernel.start_token(),
            self.containment,
        )
        .map_err(|_| ChildEvidenceError::IdentityMismatch)?;
        self.persist(&identity)?;
        Ok(identity)
    }

    /// The hard-link install is atomic and refuses to replace stale evidence.
    fn persist(&self, identity: &ObservedChildIdentity) -> Result<(), ChildEvidenceError> {
        self.validate_identity(identity)?;
        self.prepare_runtime_dir()?;
        if self.path.try_exists()? {
            return Err(ChildEvidenceError::AlreadyExists);
        }
        let bytes = serde_json::to_vec(identity)?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_CHILD_EVIDENCE_BYTES {
            return Err(ChildEvidenceError::Capacity);
        }
        let (temporary, mut file) = self.create_temporary()?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            validate_file(&file, self.expected_owner_uid)?;
            std::fs::hard_link(&temporary, &self.path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    ChildEvidenceError::AlreadyExists
                } else {
                    error.into()
                }
            })?;
            std::fs::remove_file(&temporary)?;
            File::open(&self.runtime_dir)?.sync_all()?;
            let installed = open_read_no_follow(&self.path)?;
            validate_file(&installed, self.expected_owner_uid)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    /// Remove the record only when its strict content still names the exact
    /// child being reaped. Mismatch is drift, not cleanup authority.
    pub(crate) fn remove(
        &self,
        identity: &ObservedChildIdentity,
    ) -> Result<(), ChildEvidenceError> {
        self.validate_identity(identity)?;
        validate_directory(
            &self.runtime_dir,
            self.expected_owner_uid,
            HELPER_RUNTIME_DIR_MODE,
        )?;
        let installed = self.load()?;
        if &installed != identity {
            return Err(ChildEvidenceError::IdentityMismatch);
        }
        std::fs::remove_file(&self.path)?;
        File::open(&self.runtime_dir)?.sync_all()?;
        Ok(())
    }

    fn load(&self) -> Result<ObservedChildIdentity, ChildEvidenceError> {
        let mut file = open_read_no_follow(&self.path)?;
        validate_file(&file, self.expected_owner_uid)?;
        let length = file.metadata()?.len();
        if length == 0 || length > MAX_CHILD_EVIDENCE_BYTES {
            return Err(ChildEvidenceError::Capacity);
        }
        let mut bytes =
            Vec::with_capacity(usize::try_from(length).map_err(|_| ChildEvidenceError::Capacity)?);
        std::io::Read::by_ref(&mut file)
            .take(MAX_CHILD_EVIDENCE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_CHILD_EVIDENCE_BYTES {
            return Err(ChildEvidenceError::Capacity);
        }
        serde_json::from_slice(&bytes).map_err(|_| ChildEvidenceError::Corrupt)
    }

    fn validate_identity(
        &self,
        identity: &ObservedChildIdentity,
    ) -> Result<(), ChildEvidenceError> {
        if identity.resource() != &self.resource || identity.containment() != self.containment {
            Err(ChildEvidenceError::IdentityMismatch)
        } else {
            Ok(())
        }
    }

    fn prepare_runtime_dir(&self) -> Result<(), ChildEvidenceError> {
        validate_directory(
            &self.runtime_root,
            self.expected_owner_uid,
            HELPER_SOCKET_DIR_MODE,
        )?;
        let resources = self.runtime_root.join("resources");
        create_private_directory(&resources, HELPER_RUNTIME_DIR_MODE)?;
        validate_directory(&resources, self.expected_owner_uid, HELPER_RUNTIME_DIR_MODE)?;
        if self.runtime_dir.parent() != Some(resources.as_path()) {
            return Err(ChildEvidenceError::UnsafePath);
        }
        create_private_directory(&self.runtime_dir, HELPER_RUNTIME_DIR_MODE)?;
        validate_directory(
            &self.runtime_dir,
            self.expected_owner_uid,
            HELPER_RUNTIME_DIR_MODE,
        )
    }

    fn create_temporary(&self) -> Result<(PathBuf, File), ChildEvidenceError> {
        for _ in 0..64 {
            let path = self.runtime_dir.join(format!(
                ".openvpn-child.{}.{}.tmp",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            let mut options = OpenOptions::new();
            options
                .create_new(true)
                .write(true)
                .mode(HELPER_LEDGER_MODE)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            match options.open(&path) {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(ChildEvidenceError::TemporaryNamespaceExhausted)
    }
}

fn validate_directory(
    path: &Path,
    expected_owner_uid: u32,
    expected_mode: u32,
) -> Result<(), ChildEvidenceError> {
    if !private_directory_is_valid(path, expected_owner_uid, expected_mode)? {
        return Err(ChildEvidenceError::UnsafePath);
    }
    Ok(())
}

fn validate_file(file: &File, expected_owner_uid: u32) -> Result<(), ChildEvidenceError> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != expected_owner_uid
        || metadata.mode() & 0o777 != HELPER_LEDGER_MODE
        || metadata.nlink() != 1
    {
        return Err(ChildEvidenceError::UnsafePath);
    }
    Ok(())
}

fn open_read_no_follow(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[derive(Debug, Error)]
pub(crate) enum ChildEvidenceError {
    #[error("child evidence does not match its derived resource identity")]
    IdentityMismatch,
    #[error("child evidence already exists and cannot be replaced")]
    AlreadyExists,
    #[error("foreground child exited before kernel identity attestation")]
    ProcessUnavailable,
    #[error("foreground child is not the leader of a private process group")]
    NotPrivateProcessGroup,
    #[error("child evidence path, owner, mode, or link count is unsafe")]
    UnsafePath,
    #[error("child evidence is empty or exceeds its fixed size")]
    Capacity,
    #[error("child evidence is malformed or failed strict validation")]
    Corrupt,
    #[error("child evidence temporary namespace is exhausted")]
    TemporaryNamespaceExhausted,
    #[error("child evidence I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("child evidence serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    use super::*;
    use crate::vortix_core::profile::ProfileId;

    fn current_uid() -> u32 {
        // SAFETY: geteuid has no preconditions and touches no Rust memory.
        #[allow(unsafe_code)]
        unsafe {
            libc::geteuid()
        }
    }

    fn tunnel(generation: u64) -> ResourceTag {
        ResourceTag::tunnel(
            ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap(),
            generation,
        )
        .unwrap()
    }

    fn store() -> (tempfile::TempDir, ChildEvidenceStore) {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            root.path(),
            std::fs::Permissions::from_mode(HELPER_SOCKET_DIR_MODE),
        )
        .unwrap();
        let store = ChildEvidenceStore::for_test(
            root.path().to_owned(),
            tunnel(7),
            ContainmentId::new([4; 32]),
            current_uid(),
        );
        (root, store)
    }

    fn child() -> ObservedChildIdentity {
        ObservedChildIdentity::new(tunnel(7), 42, 99, ContainmentId::new([4; 32])).unwrap()
    }

    #[test]
    fn exact_child_roundtrips_at_private_mode_without_overwrite() {
        let (_root, store) = store();
        let child = child();
        store.persist(&child).unwrap();
        assert_eq!(store.load().unwrap(), child);
        let metadata = std::fs::metadata(&store.path).unwrap();
        assert_eq!(metadata.mode() & 0o777, HELPER_LEDGER_MODE);
        assert_eq!(metadata.nlink(), 1);
        assert!(matches!(
            store.persist(&child),
            Err(ChildEvidenceError::AlreadyExists)
        ));
        assert_eq!(store.load().unwrap(), child);
        store.remove(&child).unwrap();
        assert!(!store.path.exists());
    }

    #[test]
    fn live_persistence_gets_start_token_and_group_leadership_from_kernel_probe() {
        let (_root, store) = store();
        let observed = store
            .persist_live_with(42, |_| Ok(KernelProcessIdentity::new(99, true)))
            .unwrap();
        assert_eq!(observed, child());
        assert_eq!(store.load().unwrap(), observed);
    }

    #[test]
    fn exited_or_nonleader_process_never_creates_evidence() {
        for (identity, expected) in [
            (None, ChildEvidenceError::ProcessUnavailable),
            (
                KernelProcessIdentity::new(99, false),
                ChildEvidenceError::NotPrivateProcessGroup,
            ),
        ] {
            let (_root, store) = store();
            let error = store.persist_live_with(42, |_| Ok(identity)).unwrap_err();
            assert_eq!(
                std::mem::discriminant(&error),
                std::mem::discriminant(&expected)
            );
            assert!(!store.path.exists());
        }
    }

    #[test]
    fn mismatched_identity_never_creates_or_removes_evidence() {
        let (_root, store) = store();
        let wrong =
            ObservedChildIdentity::new(tunnel(8), 42, 99, ContainmentId::new([4; 32])).unwrap();
        assert!(matches!(
            store.persist(&wrong),
            Err(ChildEvidenceError::IdentityMismatch)
        ));
        assert!(!store.path.exists());

        let child = child();
        store.persist(&child).unwrap();
        assert!(matches!(
            store.remove(&wrong),
            Err(ChildEvidenceError::IdentityMismatch)
        ));
        assert_eq!(store.load().unwrap(), child);
    }

    #[test]
    fn symlinked_runtime_component_and_corrupt_record_fail_closed() {
        let (root, store) = store();
        let foreign = tempfile::tempdir().unwrap();
        symlink(foreign.path(), root.path().join("resources")).unwrap();
        assert!(matches!(
            store.persist(&child()),
            Err(ChildEvidenceError::UnsafePath)
        ));

        std::fs::remove_file(root.path().join("resources")).unwrap();
        store.prepare_runtime_dir().unwrap();
        std::fs::write(&store.path, b"not-json").unwrap();
        std::fs::set_permissions(
            &store.path,
            std::fs::Permissions::from_mode(HELPER_LEDGER_MODE),
        )
        .unwrap();
        assert!(matches!(store.load(), Err(ChildEvidenceError::Corrupt)));
    }
}
