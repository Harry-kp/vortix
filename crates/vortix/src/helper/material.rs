//! Root-owned transient material staging for canonical `OpenVPN` execution.

#![allow(
    dead_code,
    reason = "U12 staging remains dormant until the foreground executor is enrolled"
)]

use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::helper::private_fs::{
    create_private_directory, private_directory_is_valid, DirectoryCreation,
};
use crate::helper::runtime::HelperRuntimeIdentity;
use crate::helper::validate::{PlatformLayout, HELPER_RUNTIME_DIR_MODE, HELPER_SOCKET_DIR_MODE};
use crate::vortix_core::privileged::{OpenVpnPlan, ProfileMaterialSlot, ResourceKind, ResourceTag};
use crate::vortix_core::profile::ProtocolKind;
use crate::vortix_core::secret_file::{
    write_secret_file_tracked, SecretFileError, SecretFileIdentity,
};
use crate::vortix_protocol_openvpn::execution::{
    render_helper_execution_under, supports_material_slot, OpenVpnExecutionSpec,
};

pub(crate) const MAX_MATERIAL_BYTES: usize = 1024 * 1024;

/// Descriptors received out-of-band from the authenticated daemon. This type
/// has no serde implementation and its debug form reveals slots only.
pub(crate) struct OpenVpnMaterialSet {
    descriptors: BTreeMap<ProfileMaterialSlot, File>,
}

impl Debug for OpenVpnMaterialSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenVpnMaterialSet")
            .field("slots", &self.descriptors.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl OpenVpnMaterialSet {
    pub(crate) fn from_inherited_descriptors(
        descriptors: impl IntoIterator<Item = (ProfileMaterialSlot, File)>,
    ) -> Result<Self, OpenVpnStagingError> {
        let mut by_slot = BTreeMap::new();
        for (slot, descriptor) in descriptors {
            if !supports_material_slot(slot) {
                return Err(OpenVpnStagingError::InvalidMaterialSlot);
            }
            if by_slot.insert(slot, descriptor).is_some() {
                return Err(OpenVpnStagingError::DuplicateMaterial);
            }
        }
        Ok(Self {
            descriptors: by_slot,
        })
    }

    #[cfg(test)]
    fn into_descriptors(self) -> Vec<(ProfileMaterialSlot, File)> {
        self.descriptors.into_iter().collect()
    }
}

/// Root/runtime facts are fixed before this object exists. No wire path can
/// construct or redirect it.
pub(crate) struct OpenVpnRuntimeStager {
    runtime_root: PathBuf,
    runtime_directory: PathBuf,
    resource: ResourceTag,
    expected_owner_uid: u32,
}

impl OpenVpnRuntimeStager {
    pub(crate) fn root_owned(layout: PlatformLayout, runtime: &HelperRuntimeIdentity) -> Self {
        Self {
            runtime_root: PathBuf::from(layout.helper_runtime_dir()),
            runtime_directory: runtime.runtime_dir().to_owned(),
            resource: runtime.resource().clone(),
            expected_owner_uid: 0,
        }
    }

    #[cfg(test)]
    fn for_test(
        runtime_root: PathBuf,
        runtime_directory: PathBuf,
        resource: ResourceTag,
        expected_owner_uid: u32,
    ) -> Self {
        Self {
            runtime_root,
            runtime_directory,
            resource,
            expected_owner_uid,
        }
    }

    pub(crate) fn runtime_directory(&self) -> &Path {
        &self.runtime_directory
    }

    pub(crate) fn stage(
        &self,
        plan: &OpenVpnPlan,
        materials: OpenVpnMaterialSet,
    ) -> Result<StagedOpenVpnRuntime, OpenVpnStagingError> {
        if self.resource.kind() != ResourceKind::Tunnel
            || self.resource.profile_id() != Some(plan.profile_id())
            || self.resource.generation() != plan.generation()
        {
            return Err(OpenVpnStagingError::PlanIdentityMismatch);
        }
        if !materials.descriptors.keys().eq(plan.materials().iter()) {
            return Err(OpenVpnStagingError::MaterialSetMismatch);
        }

        let resource_root = self.runtime_root.join("resources");
        let execution =
            render_helper_execution_under(plan, &self.runtime_directory, &resource_root)
                .map_err(|_| OpenVpnStagingError::UnsafeRuntime)?;
        validate_directory(
            &self.runtime_root,
            self.expected_owner_uid,
            HELPER_SOCKET_DIR_MODE,
        )?;
        let mut setup = DirectorySetup::default();
        setup.create_and_validate(&resource_root, self.expected_owner_uid)?;
        setup.create_and_validate(&self.runtime_directory, self.expected_owner_uid)?;
        let secret_directory = self.runtime_directory.join("secrets");
        setup.create_and_validate(&secret_directory, self.expected_owner_uid)?;
        let created_secret_directory = if setup.was_created(&secret_directory) {
            Some(CreatedDirectory::read(secret_directory)?)
        } else {
            None
        };

        let mut staged = StagedOpenVpnRuntime {
            execution,
            runtime_directory: self.runtime_directory.clone(),
            created_paths: Vec::new(),
            created_secret_directory,
            expected_owner_uid: self.expected_owner_uid,
            cleaned: false,
        };

        let config_identity = write_staged_file(
            staged.execution.config_path(),
            staged.execution.config().as_bytes(),
        )?;
        let config_path = staged.execution.config_path().to_owned();
        staged.created_paths.push(CreatedPath {
            path: config_path,
            identity: config_identity,
        });

        for (slot, mut descriptor) in materials.descriptors {
            let metadata = descriptor.metadata()?;
            if !metadata.is_file() {
                return Err(OpenVpnStagingError::InvalidMaterialDescriptor);
            }
            let material_len = usize::try_from(metadata.len())
                .map_err(|_| OpenVpnStagingError::MaterialTooLarge)?;
            if material_len > MAX_MATERIAL_BYTES {
                return Err(OpenVpnStagingError::MaterialTooLarge);
            }
            if material_len == 0 {
                return Err(OpenVpnStagingError::EmptyMaterial);
            }
            descriptor.seek(SeekFrom::Start(0))?;
            // Read into exact capacity, then probe one trailing byte. This
            // bounds descriptor I/O to MAX + 1 without reallocating a secret
            // prefix if the file changed after `metadata`.
            let mut bytes = Zeroizing::new(Vec::with_capacity(material_len));
            descriptor
                .by_ref()
                .take(material_len as u64)
                .read_to_end(&mut bytes)?;
            let mut trailing = [0_u8; 1];
            if bytes.len() != material_len || descriptor.read(&mut trailing)? != 0 {
                return Err(OpenVpnStagingError::InvalidMaterialDescriptor);
            }
            let path = staged
                .execution
                .material_path(slot)
                .ok_or(OpenVpnStagingError::InvalidMaterialSlot)?
                .to_owned();
            let identity = write_staged_file(&path, &bytes)?;
            staged.created_paths.push(CreatedPath { path, identity });
        }

        setup.commit();
        Ok(staged)
    }
}

struct CreatedPath {
    path: PathBuf,
    identity: SecretFileIdentity,
}

struct CreatedDirectory {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl CreatedDirectory {
    fn read(path: PathBuf) -> Result<Self, OpenVpnStagingError> {
        let metadata = std::fs::symlink_metadata(&path)?;
        Ok(Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

/// Owns all transient files until the foreground lifecycle executor either
/// stores the guard beside the child or drops it on a failed start.
pub(crate) struct StagedOpenVpnRuntime {
    execution: OpenVpnExecutionSpec,
    runtime_directory: PathBuf,
    created_paths: Vec<CreatedPath>,
    created_secret_directory: Option<CreatedDirectory>,
    expected_owner_uid: u32,
    cleaned: bool,
}

impl Debug for StagedOpenVpnRuntime {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StagedOpenVpnRuntime")
            .field("protocol", &ProtocolKind::OpenVpn)
            .field("material_count", &self.execution.material_paths().count())
            .finish_non_exhaustive()
    }
}

impl StagedOpenVpnRuntime {
    pub(crate) const fn execution(&self) -> &OpenVpnExecutionSpec {
        &self.execution
    }

    pub(crate) fn runtime_directory(&self) -> &Path {
        &self.runtime_directory
    }

    pub(crate) fn material_path(&self, slot: ProfileMaterialSlot) -> Option<&Path> {
        self.execution.material_path(slot)
    }

    pub(crate) fn material_paths(&self) -> impl Iterator<Item = &Path> {
        self.execution.material_paths()
    }

    /// Remove only the exact files created by this staging guard. Unknown,
    /// replaced, linked, or non-private artifacts fail closed for recovery.
    pub(crate) fn cleanup(mut self) -> Result<(), OpenVpnStagingError> {
        self.remove_created_paths_checked()
    }

    fn remove_created_paths_checked(&mut self) -> Result<(), OpenVpnStagingError> {
        if self.cleaned {
            return Ok(());
        }
        for created in self.created_paths.iter().rev() {
            if created_path_is_safe(created, self.expected_owner_uid)? {
                std::fs::remove_file(&created.path)?;
            }
        }
        if let Some(directory) = &self.created_secret_directory {
            if created_directory_is_safe(directory, self.expected_owner_uid)? {
                std::fs::remove_dir(&directory.path)?;
            }
        }
        self.cleaned = true;
        Ok(())
    }

    fn remove_created_paths_best_effort(&mut self) {
        if self.remove_created_paths_checked().is_ok() {
            return;
        }
        // Drop cannot report drift. Re-authenticate every entry and leave any
        // missing, replaced, linked, or otherwise changed artifact untouched.
        for created in self.created_paths.iter().rev() {
            if matches!(
                created_path_is_safe(created, self.expected_owner_uid),
                Ok(true)
            ) {
                let _ = std::fs::remove_file(&created.path);
            }
        }
        if let Some(directory) = &self.created_secret_directory {
            if matches!(
                created_directory_is_safe(directory, self.expected_owner_uid),
                Ok(true)
            ) {
                let _ = std::fs::remove_dir(&directory.path);
            }
        }
    }
}

impl Drop for StagedOpenVpnRuntime {
    fn drop(&mut self) {
        self.remove_created_paths_best_effort();
    }
}

#[derive(Debug, Error)]
pub(crate) enum OpenVpnStagingError {
    #[error("duplicate OpenVPN material slot")]
    DuplicateMaterial,
    #[error("non-OpenVPN material slot supplied to OpenVPN staging")]
    InvalidMaterialSlot,
    #[error("OpenVPN descriptor set does not exactly match the canonical plan")]
    MaterialSetMismatch,
    #[error("OpenVPN plan identity does not match the helper runtime resource")]
    PlanIdentityMismatch,
    #[error("OpenVPN material descriptor is empty")]
    EmptyMaterial,
    #[error("OpenVPN material descriptor exceeds its fixed byte limit")]
    MaterialTooLarge,
    #[error("OpenVPN material descriptor is not a regular file")]
    InvalidMaterialDescriptor,
    #[error("OpenVPN helper runtime identity, ownership, or mode is unsafe")]
    UnsafeRuntime,
    #[error("stale OpenVPN helper runtime file already exists")]
    StaleRuntime,
    #[error("OpenVPN material staging I/O failed")]
    Io(#[from] std::io::Error),
}

fn validate_directory(
    path: &Path,
    expected_owner_uid: u32,
    expected_mode: u32,
) -> Result<(), OpenVpnStagingError> {
    if !private_directory_is_valid(path, expected_owner_uid, expected_mode)? {
        return Err(OpenVpnStagingError::UnsafeRuntime);
    }
    Ok(())
}

#[derive(Default)]
struct DirectorySetup {
    created: Vec<PathBuf>,
    committed: bool,
}

impl DirectorySetup {
    fn create_and_validate(
        &mut self,
        path: &Path,
        expected_owner_uid: u32,
    ) -> Result<(), OpenVpnStagingError> {
        if create_private_directory(path, HELPER_RUNTIME_DIR_MODE)? == DirectoryCreation::Created {
            self.created.push(path.to_owned());
        }
        validate_directory(path, expected_owner_uid, HELPER_RUNTIME_DIR_MODE)
    }

    fn was_created(&self, path: &Path) -> bool {
        self.created.iter().any(|created| created == path)
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for DirectorySetup {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for path in self.created.iter().rev() {
            let _ = std::fs::remove_dir(path);
        }
    }
}

fn write_staged_file(
    path: &Path,
    contents: &[u8],
) -> Result<SecretFileIdentity, OpenVpnStagingError> {
    write_secret_file_tracked(path, contents).map_err(|error| match error {
        SecretFileError::FileExists => OpenVpnStagingError::StaleRuntime,
        SecretFileError::SymlinkParent
        | SecretFileError::NoParent
        | SecretFileError::NoBasename
        | SecretFileError::InvalidFilename => OpenVpnStagingError::UnsafeRuntime,
        SecretFileError::Io(error) => OpenVpnStagingError::Io(error),
    })
}

fn created_path_is_safe(
    created: &CreatedPath,
    expected_owner_uid: u32,
) -> Result<bool, OpenVpnStagingError> {
    match std::fs::symlink_metadata(&created.path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
        Ok(metadata)
            if !metadata.file_type().is_symlink()
                && metadata.is_file()
                && metadata.uid() == expected_owner_uid
                && metadata.mode() & 0o777 == 0o600
                && metadata.nlink() == 1
                && created.identity.matches_metadata(&metadata) =>
        {
            Ok(true)
        }
        Ok(_) => Err(OpenVpnStagingError::UnsafeRuntime),
    }
}

fn created_directory_is_safe(
    created: &CreatedDirectory,
    expected_owner_uid: u32,
) -> Result<bool, OpenVpnStagingError> {
    match std::fs::symlink_metadata(&created.path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
        Ok(metadata)
            if !metadata.file_type().is_symlink()
                && metadata.is_dir()
                && metadata.uid() == expected_owner_uid
                && metadata.mode() & 0o777 == HELPER_RUNTIME_DIR_MODE
                && metadata.dev() == created.device
                && metadata.ino() == created.inode =>
        {
            Ok(true)
        }
        Ok(_) => Err(OpenVpnStagingError::UnsafeRuntime),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{Seek as _, SeekFrom, Write as _};
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    use crate::helper::HELPER_SOCKET_DIR_MODE;
    use crate::vortix_core::privileged::{
        OpenVpnAuthFactors, OpenVpnPlan, OpenVpnRemote, OpenVpnRemoteSelection, OpenVpnTransport,
        ProfileMaterialSlot, ResourceTag,
    };
    use crate::vortix_core::profile::ProfileId;

    use super::{OpenVpnMaterialSet, OpenVpnRuntimeStager, OpenVpnStagingError};

    fn current_uid() -> u32 {
        // SAFETY: `geteuid` has no preconditions and does not touch Rust memory.
        #[allow(unsafe_code)]
        unsafe {
            libc::geteuid()
        }
    }

    fn profile(byte: char) -> ProfileId {
        ProfileId::parse(byte.to_string().repeat(ProfileId::HEX_LEN)).unwrap()
    }

    fn plan_for(profile_id: ProfileId, generation: u64) -> OpenVpnPlan {
        OpenVpnPlan::new(
            profile_id,
            generation,
            vec![OpenVpnRemote::dns("vpn.example.com", 1194, OpenVpnTransport::Udp).unwrap()],
            OpenVpnRemoteSelection::Ordered,
            OpenVpnAuthFactors::certificate(),
            Vec::new(),
        )
        .unwrap()
    }

    fn plan() -> OpenVpnPlan {
        plan_for(profile('a'), 7)
    }

    fn descriptor(contents: &[u8]) -> (tempfile::NamedTempFile, File) {
        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(contents).unwrap();
        let descriptor = File::open(source.path()).unwrap();
        (source, descriptor)
    }

    fn fixture() -> (tempfile::TempDir, OpenVpnRuntimeStager) {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            root.path(),
            std::fs::Permissions::from_mode(HELPER_SOCKET_DIR_MODE),
        )
        .unwrap();
        let runtime = root
            .path()
            .join("resources")
            .join("a".repeat(ProfileId::HEX_LEN));
        let resource = ResourceTag::tunnel(profile('a'), 7).unwrap();
        let stager = OpenVpnRuntimeStager::for_test(
            root.path().to_owned(),
            runtime,
            resource,
            current_uid(),
        );
        (root, stager)
    }

    fn certificate_materials() -> (Vec<tempfile::NamedTempFile>, OpenVpnMaterialSet) {
        let (ca_source, ca) = descriptor(b"ca-certificate");
        let (cert_source, cert) = descriptor(b"client-certificate");
        let (key_source, key) = descriptor(b"private-key-secret");
        let materials = OpenVpnMaterialSet::from_inherited_descriptors([
            (ProfileMaterialSlot::OpenVpnCaCertificate, ca),
            (ProfileMaterialSlot::OpenVpnClientCertificate, cert),
            (ProfileMaterialSlot::OpenVpnPrivateKey, key),
        ])
        .unwrap();
        (vec![ca_source, cert_source, key_source], materials)
    }

    #[test]
    fn exact_descriptor_set_stages_private_runtime_and_cleans_on_drop() {
        let (root, runtime_stager) = fixture();
        let (_sources, materials) = certificate_materials();

        let staged = runtime_stager.stage(&plan(), materials).unwrap();
        assert!(staged.execution().config_path().is_file());
        assert_eq!(
            std::fs::metadata(staged.runtime_directory())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        for path in staged.material_paths() {
            assert!(path.is_file());
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            std::fs::read(
                staged
                    .material_path(ProfileMaterialSlot::OpenVpnPrivateKey)
                    .unwrap()
            )
            .unwrap(),
            b"private-key-secret"
        );
        let runtime = staged.runtime_directory().to_owned();
        let debug = format!("{staged:?}");
        assert!(!debug.contains("private-key-secret"));
        assert!(!debug.contains(runtime.to_string_lossy().as_ref()));

        drop(staged);
        assert!(runtime.exists(), "the tunnel lifecycle owns its runtime");
        assert!(root.path().join("resources").exists());
        assert!(!runtime.join("secrets").exists());
    }

    #[test]
    fn preexisting_lifecycle_directories_and_shared_sibling_survive_cleanup() {
        let (root, runtime_stager) = fixture();
        let resources = root.path().join("resources");
        std::fs::create_dir(&resources).unwrap();
        std::fs::set_permissions(&resources, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(runtime_stager.runtime_directory()).unwrap();
        std::fs::set_permissions(
            runtime_stager.runtime_directory(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let secrets = runtime_stager.runtime_directory().join("secrets");
        std::fs::create_dir(&secrets).unwrap();
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700)).unwrap();
        let sibling = resources.join("another-tunnel");
        std::fs::create_dir(&sibling).unwrap();
        let (_sources, materials) = certificate_materials();

        runtime_stager
            .stage(&plan(), materials)
            .unwrap()
            .cleanup()
            .unwrap();

        assert!(resources.is_dir());
        assert!(runtime_stager.runtime_directory().is_dir());
        assert!(secrets.is_dir());
        assert!(sibling.is_dir());
    }

    #[test]
    fn plan_identity_mismatch_is_rejected_before_directory_creation() {
        let (_root, runtime_stager) = fixture();
        let runtime = runtime_stager.runtime_directory().to_owned();
        let (_sources, materials) = certificate_materials();
        assert!(matches!(
            runtime_stager.stage(&plan_for(profile('b'), 7), materials),
            Err(OpenVpnStagingError::PlanIdentityMismatch)
        ));
        assert!(!runtime.exists());

        let (_sources, materials) = certificate_materials();
        assert!(matches!(
            runtime_stager.stage(&plan_for(profile('a'), 8), materials),
            Err(OpenVpnStagingError::PlanIdentityMismatch)
        ));
        assert!(!runtime.exists());
    }

    #[test]
    fn missing_or_extra_material_is_rejected_before_runtime_creation() {
        let (_root, runtime_stager) = fixture();
        let runtime = runtime_stager.runtime_directory().to_owned();
        let (source, ca) = descriptor(b"ca");
        let missing = OpenVpnMaterialSet::from_inherited_descriptors([(
            ProfileMaterialSlot::OpenVpnCaCertificate,
            ca,
        )])
        .unwrap();
        assert!(matches!(
            runtime_stager.stage(&plan(), missing),
            Err(OpenVpnStagingError::MaterialSetMismatch)
        ));
        assert!(!runtime.exists());
        drop(source);

        let (_sources, materials) = certificate_materials();
        let (extra_source, extra) = descriptor(b"tls-auth");
        let mut entries = materials.into_descriptors();
        entries.push((ProfileMaterialSlot::OpenVpnTlsAuthKey, extra));
        let extra = OpenVpnMaterialSet::from_inherited_descriptors(entries).unwrap();
        assert!(matches!(
            runtime_stager.stage(&plan(), extra),
            Err(OpenVpnStagingError::MaterialSetMismatch)
        ));
        assert!(!runtime.exists());
        drop(extra_source);
    }

    #[test]
    fn symlinked_secret_directory_is_rejected_without_touching_target() {
        let (root, runtime_stager) = fixture();
        let resources = root.path().join("resources");
        std::fs::create_dir(&resources).unwrap();
        std::fs::set_permissions(&resources, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(runtime_stager.runtime_directory()).unwrap();
        std::fs::set_permissions(
            runtime_stager.runtime_directory(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let target = root.path().join("target");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, runtime_stager.runtime_directory().join("secrets")).unwrap();
        let (_sources, materials) = certificate_materials();

        assert!(matches!(
            runtime_stager.stage(&plan(), materials),
            Err(OpenVpnStagingError::UnsafeRuntime)
        ));
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
    }

    #[test]
    fn duplicate_slots_and_oversized_descriptors_fail_closed() {
        let (first_source, first) = descriptor(b"first");
        let (second_source, second) = descriptor(b"second");
        assert!(matches!(
            OpenVpnMaterialSet::from_inherited_descriptors([
                (ProfileMaterialSlot::OpenVpnCaCertificate, first),
                (ProfileMaterialSlot::OpenVpnCaCertificate, second),
            ]),
            Err(OpenVpnStagingError::DuplicateMaterial)
        ));
        drop((first_source, second_source));

        let (_root, runtime_stager) = fixture();
        let (ca_source, ca) = descriptor(b"ca");
        let (cert_source, cert) = descriptor(b"cert");
        let oversized = vec![b'x'; super::MAX_MATERIAL_BYTES + 1];
        let (key_source, key) = descriptor(&oversized);
        let materials = OpenVpnMaterialSet::from_inherited_descriptors([
            (ProfileMaterialSlot::OpenVpnCaCertificate, ca),
            (ProfileMaterialSlot::OpenVpnClientCertificate, cert),
            (ProfileMaterialSlot::OpenVpnPrivateKey, key),
        ])
        .unwrap();
        let runtime = runtime_stager.runtime_directory().to_owned();

        assert!(matches!(
            runtime_stager.stage(&plan(), materials),
            Err(OpenVpnStagingError::MaterialTooLarge)
        ));
        assert!(
            !runtime.exists(),
            "failed staging rolls back setup directories"
        );
        drop((ca_source, cert_source, key_source));
    }

    #[test]
    fn non_regular_material_descriptor_is_rejected_without_blocking() {
        let (root, runtime_stager) = fixture();
        let (ca_source, ca) = descriptor(b"ca");
        let (cert_source, cert) = descriptor(b"cert");
        let directory = File::open(root.path()).unwrap();
        let materials = OpenVpnMaterialSet::from_inherited_descriptors([
            (ProfileMaterialSlot::OpenVpnCaCertificate, ca),
            (ProfileMaterialSlot::OpenVpnClientCertificate, cert),
            (ProfileMaterialSlot::OpenVpnPrivateKey, directory),
        ])
        .unwrap();
        let runtime = runtime_stager.runtime_directory().to_owned();

        assert!(matches!(
            runtime_stager.stage(&plan(), materials),
            Err(OpenVpnStagingError::InvalidMaterialDescriptor)
        ));
        assert!(!runtime.exists());
        drop((ca_source, cert_source));
    }

    #[test]
    fn descriptor_offset_is_reset_before_staging() {
        let (_root, runtime_stager) = fixture();
        let (ca_source, mut ca) = descriptor(b"ca-from-start");
        let (cert_source, cert) = descriptor(b"cert");
        let (key_source, key) = descriptor(b"key");
        ca.seek(SeekFrom::End(0)).unwrap();
        let materials = OpenVpnMaterialSet::from_inherited_descriptors([
            (ProfileMaterialSlot::OpenVpnCaCertificate, ca),
            (ProfileMaterialSlot::OpenVpnClientCertificate, cert),
            (ProfileMaterialSlot::OpenVpnPrivateKey, key),
        ])
        .unwrap();

        let staged = runtime_stager.stage(&plan(), materials).unwrap();
        assert_eq!(
            std::fs::read(
                staged
                    .material_path(ProfileMaterialSlot::OpenVpnCaCertificate)
                    .unwrap()
            )
            .unwrap(),
            b"ca-from-start"
        );
        drop((ca_source, cert_source, key_source, staged));
    }

    #[test]
    fn checked_cleanup_refuses_and_preserves_replaced_tracked_file() {
        let (_root, runtime_stager) = fixture();
        let (_sources, materials) = certificate_materials();
        let staged = runtime_stager.stage(&plan(), materials).unwrap();
        let tracked = staged
            .material_path(ProfileMaterialSlot::OpenVpnPrivateKey)
            .unwrap()
            .to_owned();
        let mut replacement = tempfile::NamedTempFile::new().unwrap();
        replacement.write_all(b"replacement").unwrap();
        std::fs::set_permissions(replacement.path(), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        std::fs::rename(replacement.path(), &tracked).unwrap();

        assert!(matches!(
            staged.cleanup(),
            Err(OpenVpnStagingError::UnsafeRuntime)
        ));
        assert_eq!(std::fs::read(tracked).unwrap(), b"replacement");
    }
}
