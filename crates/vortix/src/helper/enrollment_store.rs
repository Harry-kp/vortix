//! Root-owned enrollment authority and monotonic epoch storage.

#![allow(
    dead_code,
    reason = "the store is activated by the package bootstrap before U13 client cutover"
)]

#[cfg(test)]
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::root_store::{RootOwnedJsonStore, RootStoreError};
use super::validate::{InstallManifest, InstallRequest, PackageChannel, PlatformLayout};
use crate::vortix_core::control::AuthorityEpoch;
use crate::vortix_core::privileged::{BootScope, LeaseId, OperationDigest};

const ENROLLMENT_SCHEMA_VERSION: u16 = 1;
const MAX_ENROLLMENT_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum EnrollmentPhase {
    Staged,
    Reserved {
        authority_epoch: AuthorityEpoch,
        boot_scope: BootScope,
        lease_id: LeaseId,
        manager_instance_nonce: [u8; 32],
    },
    Enrolled {
        authority_epoch: AuthorityEpoch,
        boot_scope: BootScope,
        lease_id: LeaseId,
        manager_instance_nonce: [u8; 32],
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootEnrollmentRecord {
    schema_version: u16,
    generation: u64,
    owner_uid: u32,
    layout: PlatformLayout,
    channel: PackageChannel,
    manifest_generation: u64,
    manifest_digest: OperationDigest,
    request_nonce_digest: OperationDigest,
    last_authority_epoch: AuthorityEpoch,
    phase: EnrollmentPhase,
}

impl RootEnrollmentRecord {
    fn from_request(request: &InstallRequest) -> Self {
        Self {
            schema_version: ENROLLMENT_SCHEMA_VERSION,
            generation: 1,
            owner_uid: request.owner_uid(),
            layout: request.layout(),
            channel: request.channel(),
            manifest_generation: request.manifest_generation(),
            manifest_digest: request.manifest_digest(),
            request_nonce_digest: request_nonce_digest(request.request_nonce()),
            last_authority_epoch: AuthorityEpoch(0),
            phase: EnrollmentPhase::Staged,
        }
    }

    fn matches_request(&self, request: &InstallRequest) -> bool {
        self.owner_uid == request.owner_uid()
            && self.layout == request.layout()
            && self.channel == request.channel()
            && self.manifest_generation == request.manifest_generation()
            && self.manifest_digest == request.manifest_digest()
            && self.request_nonce_digest == request_nonce_digest(request.request_nonce())
    }

    fn validate(&self) -> Result<(), EnrollmentStoreError> {
        if self.schema_version != ENROLLMENT_SCHEMA_VERSION
            || self.generation == 0
            || self.owner_uid == 0
            || self.manifest_generation == 0
            || self.manifest_digest.as_bytes() == [0; 32]
            || self.request_nonce_digest.as_bytes() == [0; 32]
            || !matches!(
                (self.layout, self.channel),
                (PlatformLayout::Linux, PackageChannel::DistroPackage)
                    | (PlatformLayout::MacOs, PackageChannel::MacOsSignedPackage)
            )
        {
            return Err(EnrollmentStoreError::Corrupt);
        }
        match self.phase {
            EnrollmentPhase::Staged => {}
            EnrollmentPhase::Reserved {
                authority_epoch,
                boot_scope,
                lease_id,
                manager_instance_nonce,
            }
            | EnrollmentPhase::Enrolled {
                authority_epoch,
                boot_scope,
                lease_id,
                manager_instance_nonce,
            } => {
                if authority_epoch.0 == 0
                    || authority_epoch != self.last_authority_epoch
                    || boot_scope == BootScope::new([0; 16])
                    || lease_id == LeaseId::new([0; 32])
                    || manager_instance_nonce == [0; 32]
                {
                    return Err(EnrollmentStoreError::Corrupt);
                }
            }
        }
        Ok(())
    }

    fn reservation(&self) -> Option<AuthorityReservation> {
        match self.phase {
            EnrollmentPhase::Reserved {
                authority_epoch,
                boot_scope,
                lease_id,
                manager_instance_nonce,
            }
            | EnrollmentPhase::Enrolled {
                authority_epoch,
                boot_scope,
                lease_id,
                manager_instance_nonce,
            } => Some(AuthorityReservation {
                authority_epoch,
                boot_scope,
                lease_id,
                manager_instance_nonce,
            }),
            EnrollmentPhase::Staged => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthorityReservation {
    authority_epoch: AuthorityEpoch,
    boot_scope: BootScope,
    lease_id: LeaseId,
    manager_instance_nonce: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RootEnrollmentAuthority {
    reservation: AuthorityReservation,
    enrolled: bool,
}

impl RootEnrollmentAuthority {
    pub(crate) const fn reservation(self) -> AuthorityReservation {
        self.reservation
    }

    pub(crate) const fn is_enrolled(self) -> bool {
        self.enrolled
    }
}

impl AuthorityReservation {
    #[cfg(test)]
    pub(crate) const fn test_fixture(
        authority_epoch: AuthorityEpoch,
        boot_scope: BootScope,
        lease_id: LeaseId,
        manager_instance_nonce: [u8; 32],
    ) -> Self {
        Self {
            authority_epoch,
            boot_scope,
            lease_id,
            manager_instance_nonce,
        }
    }

    pub(crate) const fn authority_epoch(self) -> AuthorityEpoch {
        self.authority_epoch
    }

    pub(crate) const fn boot_scope(self) -> BootScope {
        self.boot_scope
    }

    pub(crate) const fn lease_id(self) -> LeaseId {
        self.lease_id
    }

    pub(crate) const fn manager_instance_nonce(self) -> [u8; 32] {
        self.manager_instance_nonce
    }
}

pub(crate) struct RootEnrollmentStore {
    store: RootOwnedJsonStore,
}

impl RootEnrollmentStore {
    pub(crate) fn root_owned(layout: PlatformLayout) -> Self {
        Self {
            store: RootOwnedJsonStore::new(
                layout.root_enrollment(),
                0,
                layout.root_state_dir_mode(),
                MAX_ENROLLMENT_BYTES,
                "enrollment",
            )
            .expect("fixed root enrollment path is absolute and valid"),
        }
    }

    #[cfg(test)]
    fn for_test(path: impl Into<PathBuf>, owner_uid: u32) -> Self {
        Self {
            store: RootOwnedJsonStore::new(
                path,
                owner_uid,
                super::HELPER_RUNTIME_DIR_MODE,
                MAX_ENROLLMENT_BYTES,
                "enrollment",
            )
            .unwrap(),
        }
    }

    pub(crate) fn stage(
        &self,
        request: &InstallRequest,
        manifest: &InstallManifest,
    ) -> Result<(), EnrollmentStoreError> {
        request.verify_manifest(manifest)?;
        let _lock = self.store.lock_sibling(c"enrollment.lock")?;
        match self.load_optional()? {
            Some(existing) if existing.matches_request(request) => Ok(()),
            Some(_) => Err(EnrollmentStoreError::ConflictingEnrollment),
            None => self.persist(&RootEnrollmentRecord::from_request(request)),
        }
    }

    pub(crate) fn owner_uid(&self) -> Result<u32, EnrollmentStoreError> {
        let _lock = self.store.lock_sibling(c"enrollment.lock")?;
        self.load_optional()?
            .map(|record| record.owner_uid)
            .ok_or(EnrollmentStoreError::NotStaged)
    }

    pub(crate) fn authority_for_owner(
        &self,
        owner_uid: u32,
    ) -> Result<RootEnrollmentAuthority, EnrollmentStoreError> {
        let _lock = self.store.lock_sibling(c"enrollment.lock")?;
        let record = self
            .load_optional()?
            .ok_or(EnrollmentStoreError::NotStaged)?;
        if record.owner_uid != owner_uid {
            return Err(EnrollmentStoreError::ConflictingEnrollment);
        }
        let reservation = record
            .reservation()
            .ok_or(EnrollmentStoreError::NotEnrolled)?;
        Ok(RootEnrollmentAuthority {
            reservation,
            enrolled: matches!(record.phase, EnrollmentPhase::Enrolled { .. }),
        })
    }

    pub(crate) fn reserve(
        &self,
        request: &InstallRequest,
        boot_scope: BootScope,
        lease_id: LeaseId,
        manager_instance_nonce: [u8; 32],
    ) -> Result<AuthorityReservation, EnrollmentStoreError> {
        if boot_scope == BootScope::new([0; 16])
            || lease_id == LeaseId::new([0; 32])
            || manager_instance_nonce == [0; 32]
        {
            return Err(EnrollmentStoreError::InvalidLease);
        }
        let _lock = self.store.lock_sibling(c"enrollment.lock")?;
        let mut record = self.load_required_for(request)?;
        if let Some(existing) = record.reservation() {
            return Ok(existing);
        }
        let next = record
            .last_authority_epoch
            .0
            .checked_add(1)
            .filter(|epoch| *epoch != 0)
            .ok_or(EnrollmentStoreError::EpochExhausted)?;
        let reservation = AuthorityReservation {
            authority_epoch: AuthorityEpoch(next),
            boot_scope,
            lease_id,
            manager_instance_nonce,
        };
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or(EnrollmentStoreError::GenerationExhausted)?;
        record.last_authority_epoch = reservation.authority_epoch;
        record.phase = EnrollmentPhase::Reserved {
            authority_epoch: reservation.authority_epoch,
            boot_scope,
            lease_id,
            manager_instance_nonce,
        };
        self.persist(&record)?;
        Ok(reservation)
    }

    pub(crate) fn commit(
        &self,
        request: &InstallRequest,
        reservation: AuthorityReservation,
    ) -> Result<(), EnrollmentStoreError> {
        let _lock = self.store.lock_sibling(c"enrollment.lock")?;
        let mut record = self.load_required_for(request)?;
        match record.phase {
            EnrollmentPhase::Enrolled { .. } if record.reservation() == Some(reservation) => {
                return Ok(());
            }
            EnrollmentPhase::Reserved { .. } if record.reservation() == Some(reservation) => {}
            _ => return Err(EnrollmentStoreError::ReservationMismatch),
        }
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or(EnrollmentStoreError::GenerationExhausted)?;
        record.phase = EnrollmentPhase::Enrolled {
            authority_epoch: reservation.authority_epoch,
            boot_scope: reservation.boot_scope,
            lease_id: reservation.lease_id,
            manager_instance_nonce: reservation.manager_instance_nonce,
        };
        self.persist(&record)
    }

    pub(crate) fn commit_epoch(
        &self,
        request: &InstallRequest,
        authority_epoch: AuthorityEpoch,
    ) -> Result<AuthorityReservation, EnrollmentStoreError> {
        if authority_epoch.0 == 0 {
            return Err(EnrollmentStoreError::ReservationMismatch);
        }
        let _lock = self.store.lock_sibling(c"enrollment.lock")?;
        let mut record = self.load_required_for(request)?;
        let reservation = record
            .reservation()
            .filter(|reservation| reservation.authority_epoch == authority_epoch)
            .ok_or(EnrollmentStoreError::ReservationMismatch)?;
        match record.phase {
            EnrollmentPhase::Enrolled { .. } => return Ok(reservation),
            EnrollmentPhase::Reserved { .. } => {}
            EnrollmentPhase::Staged => return Err(EnrollmentStoreError::ReservationMismatch),
        }
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or(EnrollmentStoreError::GenerationExhausted)?;
        record.phase = EnrollmentPhase::Enrolled {
            authority_epoch: reservation.authority_epoch,
            boot_scope: reservation.boot_scope,
            lease_id: reservation.lease_id,
            manager_instance_nonce: reservation.manager_instance_nonce,
        };
        self.persist(&record)?;
        Ok(reservation)
    }

    pub(crate) fn rotate_boot_lease(
        &self,
        request: &InstallRequest,
        boot_scope: BootScope,
        lease_id: LeaseId,
        manager_instance_nonce: [u8; 32],
    ) -> Result<AuthorityReservation, EnrollmentStoreError> {
        if boot_scope == BootScope::new([0; 16])
            || lease_id == LeaseId::new([0; 32])
            || manager_instance_nonce == [0; 32]
        {
            return Err(EnrollmentStoreError::InvalidLease);
        }
        let _lock = self.store.lock_sibling(c"enrollment.lock")?;
        let mut record = self.load_required_for(request)?;
        let current = match record.phase {
            EnrollmentPhase::Enrolled { .. } => record
                .reservation()
                .expect("an enrolled record always carries a reservation"),
            _ => return Err(EnrollmentStoreError::NotEnrolled),
        };
        if current.boot_scope == boot_scope {
            return Ok(current);
        }
        let rotated = AuthorityReservation {
            authority_epoch: current.authority_epoch,
            boot_scope,
            lease_id,
            manager_instance_nonce,
        };
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or(EnrollmentStoreError::GenerationExhausted)?;
        record.phase = EnrollmentPhase::Enrolled {
            authority_epoch: rotated.authority_epoch,
            boot_scope,
            lease_id,
            manager_instance_nonce,
        };
        self.persist(&record)?;
        Ok(rotated)
    }

    pub(crate) fn revoke(
        &self,
        request: &InstallRequest,
        reservation: AuthorityReservation,
    ) -> Result<(), EnrollmentStoreError> {
        let _lock = self.store.lock_sibling(c"enrollment.lock")?;
        let mut record = self.load_required_for(request)?;
        if record.reservation() != Some(reservation) {
            return Err(EnrollmentStoreError::ReservationMismatch);
        }
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or(EnrollmentStoreError::GenerationExhausted)?;
        record.phase = EnrollmentPhase::Staged;
        self.persist(&record)
    }

    fn load_required_for(
        &self,
        request: &InstallRequest,
    ) -> Result<RootEnrollmentRecord, EnrollmentStoreError> {
        let record = self
            .load_optional()?
            .ok_or(EnrollmentStoreError::NotStaged)?;
        if !record.matches_request(request) {
            return Err(EnrollmentStoreError::ConflictingEnrollment);
        }
        Ok(record)
    }

    fn load_optional(&self) -> Result<Option<RootEnrollmentRecord>, EnrollmentStoreError> {
        let bytes = match self.store.load() {
            Ok(bytes) => bytes,
            Err(RootStoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        let record: RootEnrollmentRecord =
            serde_json::from_slice(&bytes).map_err(|_| EnrollmentStoreError::Corrupt)?;
        record.validate()?;
        Ok(Some(record))
    }

    fn persist(&self, record: &RootEnrollmentRecord) -> Result<(), EnrollmentStoreError> {
        record.validate()?;
        let bytes = serde_json::to_vec(record)?;
        self.store.write(&bytes)?;
        Ok(())
    }
}

fn request_nonce_digest(nonce: [u8; 32]) -> OperationDigest {
    let mut material = Vec::with_capacity(65);
    material.extend_from_slice(b"vortix-install-request-nonce-v1\0");
    material.extend_from_slice(&nonce);
    OperationDigest::of_bytes(&material)
}

#[derive(Debug, Error)]
pub(crate) enum EnrollmentStoreError {
    #[error("root enrollment state is malformed or internally inconsistent")]
    Corrupt,
    #[error("root enrollment state belongs to a different request")]
    ConflictingEnrollment,
    #[error("root enrollment has not been staged")]
    NotStaged,
    #[error("root enrollment is not active")]
    NotEnrolled,
    #[error("root enrollment reservation does not match")]
    ReservationMismatch,
    #[error("root authority epoch space is exhausted")]
    EpochExhausted,
    #[error("root enrollment generation space is exhausted")]
    GenerationExhausted,
    #[error("root enrollment lease evidence is invalid")]
    InvalidLease,
    #[error("root enrollment request is invalid: {0}")]
    Request(#[from] super::validate::InstallError),
    #[error("root enrollment storage failed: {0}")]
    Store(#[from] RootStoreError),
    #[error("root enrollment serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::helper::HELPER_RUNTIME_DIR_MODE;

    fn manifest(generation: u64) -> InstallManifest {
        InstallManifest::new(
            "0.4.3".into(),
            generation,
            OperationDigest::of_bytes(b"daemon"),
            OperationDigest::of_bytes(b"helper"),
            OperationDigest::of_bytes(b"bootstrap"),
            (generation > 1).then(|| OperationDigest::of_bytes(b"prior")),
        )
        .unwrap()
    }

    fn request(manifest: &InstallManifest, nonce: u8) -> InstallRequest {
        InstallRequest::new(
            501,
            PlatformLayout::Linux,
            PackageChannel::DistroPackage,
            manifest.generation(),
            manifest.digest(),
            [nonce; 32],
        )
        .unwrap()
    }

    fn store() -> (tempfile::TempDir, RootEnrollmentStore) {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            directory.path(),
            std::fs::Permissions::from_mode(HELPER_RUNTIME_DIR_MODE),
        )
        .unwrap();
        let store = RootEnrollmentStore::for_test(
            directory.path().join("enrollment.json"),
            crate::utils::effective_user_group_ids().0,
        );
        (directory, store)
    }

    #[test]
    fn root_issues_monotonic_epochs_and_never_reuses_revoked_authority() {
        let (_directory, store) = store();
        let manifest = manifest(1);
        let request = request(&manifest, 7);
        store.stage(&request, &manifest).unwrap();

        let first = store
            .reserve(
                &request,
                BootScope::new([1; 16]),
                LeaseId::new([2; 32]),
                [3; 32],
            )
            .unwrap();
        assert_eq!(first.authority_epoch(), AuthorityEpoch(1));
        store.revoke(&request, first).unwrap();

        let second = store
            .reserve(
                &request,
                BootScope::new([1; 16]),
                LeaseId::new([3; 32]),
                [4; 32],
            )
            .unwrap();
        assert_eq!(second.authority_epoch(), AuthorityEpoch(2));
        assert_ne!(first.lease_id(), second.lease_id());
    }

    #[test]
    fn reservation_commit_and_boot_rotation_are_exact_and_idempotent() {
        let (_directory, store) = store();
        let manifest = manifest(1);
        let request = request(&manifest, 8);
        store.stage(&request, &manifest).unwrap();
        let reserved = store
            .reserve(
                &request,
                BootScope::new([1; 16]),
                LeaseId::new([2; 32]),
                [3; 32],
            )
            .unwrap();
        assert_eq!(
            store
                .reserve(
                    &request,
                    BootScope::new([9; 16]),
                    LeaseId::new([9; 32]),
                    [9; 32],
                )
                .unwrap(),
            reserved
        );
        store.commit(&request, reserved).unwrap();
        store.commit(&request, reserved).unwrap();
        assert_eq!(
            store
                .commit_epoch(&request, reserved.authority_epoch())
                .unwrap(),
            reserved
        );
        assert!(matches!(
            store.commit_epoch(&request, AuthorityEpoch(99)),
            Err(EnrollmentStoreError::ReservationMismatch)
        ));

        let same_boot = store
            .rotate_boot_lease(
                &request,
                BootScope::new([1; 16]),
                LeaseId::new([7; 32]),
                [8; 32],
            )
            .unwrap();
        assert_eq!(same_boot, reserved);
        let rotated = store
            .rotate_boot_lease(
                &request,
                BootScope::new([4; 16]),
                LeaseId::new([5; 32]),
                [6; 32],
            )
            .unwrap();
        assert_eq!(rotated.authority_epoch(), reserved.authority_epoch());
        assert_eq!(rotated.boot_scope(), BootScope::new([4; 16]));
        assert_eq!(rotated.lease_id(), LeaseId::new([5; 32]));
        assert_eq!(rotated.manager_instance_nonce(), [6; 32]);
    }

    #[test]
    fn mismatched_manifest_request_and_corrupt_state_fail_closed() {
        let (directory, store) = store();
        let manifest = manifest(1);
        let install_request = request(&manifest, 9);
        let other_manifest = InstallManifest::new(
            "0.4.4".into(),
            1,
            OperationDigest::of_bytes(b"other-daemon"),
            OperationDigest::of_bytes(b"other-helper"),
            OperationDigest::of_bytes(b"other-bootstrap"),
            None,
        )
        .unwrap();
        assert!(matches!(
            store.stage(&install_request, &other_manifest),
            Err(EnrollmentStoreError::Request(_))
        ));
        store.stage(&install_request, &manifest).unwrap();
        assert!(matches!(
            store.stage(&request(&manifest, 10), &manifest),
            Err(EnrollmentStoreError::ConflictingEnrollment)
        ));

        std::fs::write(directory.path().join("enrollment.json"), b"not json").unwrap();
        assert!(matches!(
            store.reserve(
                &install_request,
                BootScope::new([1; 16]),
                LeaseId::new([2; 32]),
                [3; 32]
            ),
            Err(EnrollmentStoreError::Corrupt)
        ));
        assert_eq!(
            std::fs::read(directory.path().join("enrollment.json")).unwrap(),
            b"not json"
        );
    }
}
