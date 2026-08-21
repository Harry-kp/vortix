//! Root-owned transient material staging for canonical `OpenVPN` execution.

#![allow(
    dead_code,
    reason = "U12 staging remains dormant until the foreground executor is enrolled"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Formatter};
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::helper::child_evidence::MAX_CHILD_EVIDENCE_BYTES;
use crate::helper::observe::MAX_INTERFACE_EVIDENCE_BYTES;
use crate::helper::private_fs::{
    create_private_directory, private_directory_is_valid, DirectoryCreation,
};
use crate::helper::runtime::{
    HelperRuntimeIdentity, INTERFACE_EVIDENCE_FILE, OPENVPN_CHILD_EVIDENCE_FILE,
};
use crate::helper::validate::{PlatformLayout, HELPER_RUNTIME_DIR_MODE, HELPER_SOCKET_DIR_MODE};
use crate::vortix_core::openvpn_credentials::{
    DecodedOpenVpnCredentials, MAX_CREDENTIAL_FRAME_BYTES,
};
use crate::vortix_core::privileged::{
    OpenVpnPlan, OpenVpnRoute, OpenVpnRouteEvidence, OpenVpnRouteGateway, OpenVpnRouteSetEvidence,
    ProfileMaterialSlot, ResourceKind, ResourceTag,
};
use crate::vortix_core::privileged::{ProfileMaterialRef, TunnelDescriptorRef, WireGuardPlan};
use crate::vortix_core::profile::ProtocolKind;
use crate::vortix_core::secret_file::{
    write_secret_file_tracked, SecretFileError, SecretFileIdentity,
};
use crate::vortix_protocol_openvpn::execution::{
    is_helper_material_filename, render_helper_execution_under, supports_material_slot,
    OpenVpnExecutionSpec, CONFIG_FILE, LOG_FILE, MANAGEMENT_SOCKET, SECRET_DIRECTORY,
};
use crate::vortix_protocol_wireguard::execution::{
    render_helper_execution as render_wireguard_execution, WireGuardMaterial,
};

pub(crate) const MAX_MATERIAL_BYTES: usize = 1024 * 1024;
const MAX_OPENVPN_LOG_EVIDENCE_BYTES: usize = 1024 * 1024;

pub(crate) enum TunnelMaterialSet {
    WireGuard(WireGuardMaterialSet),
    OpenVpn(OpenVpnDescriptorSet),
}

impl TunnelMaterialSet {
    pub(crate) fn for_plan(
        plan: &crate::vortix_core::privileged::ProtocolPlan,
        descriptors: Vec<File>,
    ) -> Result<Self, TunnelMaterialError> {
        let refs = plan.descriptor_refs();
        if refs.len() != descriptors.len() {
            return Err(TunnelMaterialError::CountMismatch);
        }
        match plan {
            crate::vortix_core::privileged::ProtocolPlan::WireGuard(plan) => {
                WireGuardMaterialSet::from_inherited_descriptors(
                    plan.material_refs().into_iter().zip(descriptors),
                )
                .map(Self::WireGuard)
                .map_err(|_| TunnelMaterialError::InvalidIdentity)
            }
            crate::vortix_core::privileged::ProtocolPlan::OpenVpn(_) => {
                OpenVpnDescriptorSet::from_tunnel_descriptors(refs.into_iter().zip(descriptors))
                    .map(Self::OpenVpn)
                    .map_err(|_| TunnelMaterialError::InvalidIdentity)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum TunnelMaterialError {
    #[error("tunnel descriptor count does not match the plan")]
    CountMismatch,
    #[error("tunnel material identity does not match the protocol plan")]
    InvalidIdentity,
}

/// Descriptor-backed `WireGuard` keys paired with their canonical material
/// identity. The transport constructs this value locally; it is never
/// serialized and its debug form cannot reveal key bytes.
pub(crate) struct WireGuardMaterialSet {
    descriptors: BTreeMap<ProfileMaterialRef, File>,
}

impl Debug for WireGuardMaterialSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireGuardMaterialSet")
            .field("material_count", &self.descriptors.len())
            .finish_non_exhaustive()
    }
}

impl WireGuardMaterialSet {
    pub(crate) fn from_inherited_descriptors(
        descriptors: impl IntoIterator<Item = (ProfileMaterialRef, File)>,
    ) -> Result<Self, WireGuardStagingError> {
        let mut by_ref = BTreeMap::new();
        for (material_ref, descriptor) in descriptors {
            if by_ref.insert(material_ref, descriptor).is_some() {
                return Err(WireGuardStagingError::DuplicateMaterial);
            }
        }
        Ok(Self {
            descriptors: by_ref,
        })
    }
}

/// Fixed-root staging for the one private config consumed by `wg-quick`.
pub(crate) struct WireGuardRuntimeStager {
    runtime_root: PathBuf,
    runtime_directory: PathBuf,
    config_path: PathBuf,
    resource: ResourceTag,
    expected_owner_uid: u32,
}

impl WireGuardRuntimeStager {
    pub(crate) fn root_owned(layout: PlatformLayout, runtime: &HelperRuntimeIdentity) -> Self {
        Self {
            runtime_root: PathBuf::from(layout.helper_runtime_dir()),
            runtime_directory: runtime.runtime_dir().to_owned(),
            config_path: runtime.wireguard_config(),
            resource: runtime.resource().clone(),
            expected_owner_uid: 0,
        }
    }

    #[cfg(test)]
    fn for_test(
        runtime_root: PathBuf,
        runtime_directory: PathBuf,
        config_path: PathBuf,
        resource: ResourceTag,
        expected_owner_uid: u32,
    ) -> Self {
        Self {
            runtime_root,
            runtime_directory,
            config_path,
            resource,
            expected_owner_uid,
        }
    }

    pub(crate) fn stage(
        &self,
        plan: &WireGuardPlan,
        materials: WireGuardMaterialSet,
    ) -> Result<StagedWireGuardRuntime, WireGuardStagingError> {
        if self.resource.kind() != ResourceKind::Tunnel
            || self.resource.profile_id() != Some(plan.profile_id())
            || self.resource.generation() != plan.generation()
        {
            return Err(WireGuardStagingError::PlanIdentityMismatch);
        }
        let expected = plan.material_refs().into_iter().collect::<BTreeSet<_>>();
        let actual = materials
            .descriptors
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        if expected != actual {
            return Err(WireGuardStagingError::MaterialSetMismatch);
        }

        let mut bytes = BTreeMap::new();
        for (material_ref, descriptor) in materials.descriptors {
            bytes.insert(material_ref, read_material_descriptor(descriptor)?);
        }
        let private_ref = ProfileMaterialRef::ProfileSlot {
            slot: ProfileMaterialSlot::WireGuardPrivateKey,
        };
        let private_key = bytes
            .get(&private_ref)
            .ok_or(WireGuardStagingError::MaterialSetMismatch)?;
        let preshared_keys = bytes
            .iter()
            .filter_map(|(material_ref, value)| match material_ref {
                ProfileMaterialRef::WireGuardPresharedKey { peer_public_key } => {
                    Some((*peer_public_key, value.as_slice()))
                }
                ProfileMaterialRef::ProfileSlot { .. } => None,
            })
            .collect();
        let execution = render_wireguard_execution(
            plan,
            &self.config_path,
            &WireGuardMaterial::new(private_key, preshared_keys),
        )
        .map_err(|_| WireGuardStagingError::InvalidMaterial)?;

        validate_directory(
            &self.runtime_root,
            self.expected_owner_uid,
            HELPER_SOCKET_DIR_MODE,
        )
        .map_err(WireGuardStagingError::from_openvpn)?;
        let resource_root = self.runtime_root.join("resources");
        let mut setup = DirectorySetup::default();
        setup
            .create_and_validate(&resource_root, self.expected_owner_uid)
            .map_err(WireGuardStagingError::from_openvpn)?;
        setup
            .create_and_validate(&self.runtime_directory, self.expected_owner_uid)
            .map_err(WireGuardStagingError::from_openvpn)?;
        let identity = write_staged_file(execution.config_path(), execution.config())
            .map_err(WireGuardStagingError::from_openvpn)?;
        setup.commit();
        Ok(StagedWireGuardRuntime {
            config_path: self.config_path.clone(),
            runtime_directory: self.runtime_directory.clone(),
            created: CreatedPath {
                path: self.config_path.clone(),
                identity,
            },
            expected_owner_uid: self.expected_owner_uid,
            cleaned: false,
        })
    }

    pub(crate) fn recover(&self) -> Result<StagedWireGuardRuntime, WireGuardStagingError> {
        self.recover_for_cleanup_if_present()?.ok_or_else(|| {
            WireGuardStagingError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "WireGuard helper runtime is absent",
            ))
        })
    }

    /// Recover the exact staged config when it still exists. A missing or
    /// empty derived runtime is the expected state after a completed cleanup;
    /// any other artifact is drift and must not be treated as success.
    pub(crate) fn recover_for_cleanup_if_present(
        &self,
    ) -> Result<Option<StagedWireGuardRuntime>, WireGuardStagingError> {
        validate_directory(
            &self.runtime_root,
            self.expected_owner_uid,
            HELPER_SOCKET_DIR_MODE,
        )
        .map_err(WireGuardStagingError::from_openvpn)?;
        let resource_root = self.runtime_root.join("resources");
        if self.runtime_directory.parent() != Some(resource_root.as_path()) {
            return Err(WireGuardStagingError::UnsafeRuntime);
        }
        match private_directory_presence(
            &resource_root,
            self.expected_owner_uid,
            HELPER_RUNTIME_DIR_MODE,
        )? {
            None => return Ok(None),
            Some(false) => return Err(WireGuardStagingError::UnsafeRuntime),
            Some(true) => {}
        }
        match private_directory_presence(
            &self.runtime_directory,
            self.expected_owner_uid,
            HELPER_RUNTIME_DIR_MODE,
        )? {
            None => return Ok(None),
            Some(false) => return Err(WireGuardStagingError::UnsafeRuntime),
            Some(true) => {}
        }
        let entries = std::fs::read_dir(&self.runtime_directory)?;
        let expected_name = self
            .config_path
            .file_name()
            .ok_or(WireGuardStagingError::UnsafeRuntime)?;
        let mut config_present = false;
        for entry in entries {
            let entry = entry?;
            if entry.file_name() != expected_name || config_present {
                return Err(WireGuardStagingError::UnsafeRuntime);
            }
            config_present = true;
        }
        if !config_present {
            return Ok(None);
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.config_path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != self.expected_owner_uid
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > MAX_MATERIAL_BYTES as u64
        {
            return Err(WireGuardStagingError::UnsafeRuntime);
        }
        Ok(Some(StagedWireGuardRuntime {
            config_path: self.config_path.clone(),
            runtime_directory: self.runtime_directory.clone(),
            created: CreatedPath {
                path: self.config_path.clone(),
                identity: SecretFileIdentity::from_metadata(&metadata),
            },
            expected_owner_uid: self.expected_owner_uid,
            cleaned: false,
        }))
    }
}

pub(crate) struct StagedWireGuardRuntime {
    config_path: PathBuf,
    runtime_directory: PathBuf,
    created: CreatedPath,
    expected_owner_uid: u32,
    cleaned: bool,
}

impl Debug for StagedWireGuardRuntime {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StagedWireGuardRuntime")
            .field("protocol", &ProtocolKind::WireGuard)
            .finish_non_exhaustive()
    }
}

impl StagedWireGuardRuntime {
    pub(crate) fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub(crate) fn cleanup(&mut self) -> Result<(), WireGuardStagingError> {
        self.remove_checked()
    }

    fn remove_checked(&mut self) -> Result<(), WireGuardStagingError> {
        if self.cleaned {
            return Ok(());
        }
        if created_path_is_safe(&self.created, self.expected_owner_uid)
            .map_err(WireGuardStagingError::from_openvpn)?
        {
            std::fs::remove_file(&self.created.path)?;
            File::open(&self.runtime_directory)?.sync_all()?;
        }
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for StagedWireGuardRuntime {
    fn drop(&mut self) {
        let _ = self.remove_checked();
    }
}

#[derive(Debug, Error)]
pub(crate) enum WireGuardStagingError {
    #[error("duplicate WireGuard material identity")]
    DuplicateMaterial,
    #[error("WireGuard descriptor set does not exactly match the canonical plan")]
    MaterialSetMismatch,
    #[error("WireGuard plan identity does not match the helper runtime resource")]
    PlanIdentityMismatch,
    #[error("WireGuard key material is invalid")]
    InvalidMaterial,
    #[error("WireGuard material descriptor is empty")]
    EmptyMaterial,
    #[error("WireGuard material descriptor exceeds its fixed byte limit")]
    MaterialTooLarge,
    #[error("WireGuard material descriptor is not a regular file")]
    InvalidMaterialDescriptor,
    #[error("WireGuard helper runtime identity, ownership, or mode is unsafe")]
    UnsafeRuntime,
    #[error("stale WireGuard helper runtime file already exists")]
    StaleRuntime,
    #[error("WireGuard material staging I/O failed")]
    Io(#[from] std::io::Error),
}

impl WireGuardStagingError {
    fn from_openvpn(error: OpenVpnStagingError) -> Self {
        match error {
            OpenVpnStagingError::StaleRuntime => Self::StaleRuntime,
            OpenVpnStagingError::Io(error) => Self::Io(error),
            _ => Self::UnsafeRuntime,
        }
    }

    fn from_descriptor(error: DescriptorReadError) -> Self {
        match error {
            DescriptorReadError::Io(error) => Self::Io(error),
            DescriptorReadError::NotRegular | DescriptorReadError::Changed => {
                Self::InvalidMaterialDescriptor
            }
            DescriptorReadError::Empty => Self::EmptyMaterial,
            DescriptorReadError::TooLarge => Self::MaterialTooLarge,
        }
    }
}

fn read_material_descriptor(descriptor: File) -> Result<Zeroizing<Vec<u8>>, WireGuardStagingError> {
    read_bounded_descriptor(descriptor, MAX_MATERIAL_BYTES)
        .map_err(WireGuardStagingError::from_descriptor)
}

enum DescriptorReadError {
    Io(std::io::Error),
    NotRegular,
    Empty,
    TooLarge,
    Changed,
}

fn read_bounded_descriptor(
    mut descriptor: File,
    max_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, DescriptorReadError> {
    let metadata = descriptor.metadata()?;
    if !metadata.is_file() {
        return Err(DescriptorReadError::NotRegular);
    }
    let material_len =
        usize::try_from(metadata.len()).map_err(|_| DescriptorReadError::TooLarge)?;
    if material_len > max_bytes {
        return Err(DescriptorReadError::TooLarge);
    }
    if material_len == 0 {
        return Err(DescriptorReadError::Empty);
    }
    descriptor.seek(SeekFrom::Start(0))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(material_len));
    descriptor
        .by_ref()
        .take(material_len as u64)
        .read_to_end(&mut bytes)?;
    let mut trailing = [0_u8; 1];
    if bytes.len() != material_len || descriptor.read(&mut trailing)? != 0 {
        return Err(DescriptorReadError::Changed);
    }
    Ok(bytes)
}

impl From<std::io::Error> for DescriptorReadError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Descriptors received out-of-band from the authenticated daemon. This type
/// has no serde implementation and its debug form reveals slots only.
pub(crate) struct OpenVpnDescriptorSet {
    profile_materials: BTreeMap<ProfileMaterialSlot, File>,
    credentials: Option<File>,
}

impl Debug for OpenVpnDescriptorSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenVpnDescriptorSet")
            .field("slots", &self.profile_materials.keys().collect::<Vec<_>>())
            .field("has_credentials", &self.credentials.is_some())
            .finish()
    }
}

impl OpenVpnDescriptorSet {
    pub(crate) fn from_inherited_descriptors(
        descriptors: impl IntoIterator<Item = (ProfileMaterialSlot, File)>,
    ) -> Result<Self, OpenVpnStagingError> {
        let mut by_slot = BTreeMap::new();
        for (slot, descriptor) in descriptors {
            if !supports_material_slot(slot) {
                return Err(OpenVpnStagingError::InvalidMaterialSlot);
            }
            if by_slot.insert(slot, descriptor).is_some() {
                return Err(OpenVpnStagingError::DuplicateDescriptor);
            }
        }
        Ok(Self {
            profile_materials: by_slot,
            credentials: None,
        })
    }

    fn from_tunnel_descriptors(
        descriptors: impl IntoIterator<Item = (TunnelDescriptorRef, File)>,
    ) -> Result<Self, OpenVpnStagingError> {
        let mut profile_materials = Vec::new();
        let mut credentials = None;
        for (descriptor_ref, descriptor) in descriptors {
            match descriptor_ref {
                TunnelDescriptorRef::ProfileMaterial(ProfileMaterialRef::ProfileSlot { slot }) => {
                    profile_materials.push((slot, descriptor));
                }
                TunnelDescriptorRef::ProfileMaterial(
                    ProfileMaterialRef::WireGuardPresharedKey { .. },
                ) => return Err(OpenVpnStagingError::InvalidMaterialSlot),
                TunnelDescriptorRef::OpenVpnCredentials => {
                    if credentials.replace(descriptor).is_some() {
                        return Err(OpenVpnStagingError::DuplicateDescriptor);
                    }
                }
            }
        }
        let mut materials = Self::from_inherited_descriptors(profile_materials)?;
        materials.credentials = credentials;
        Ok(materials)
    }

    #[cfg(test)]
    fn into_descriptors(self) -> Vec<(ProfileMaterialSlot, File)> {
        self.profile_materials.into_iter().collect()
    }
}

/// Root/runtime facts are fixed before this object exists. No wire path can
/// construct or redirect it.
pub(crate) struct OpenVpnRuntimeStager {
    runtime_root: PathBuf,
    runtime_directory: PathBuf,
    resource: ResourceTag,
    interface_name: String,
    expected_owner_uid: u32,
}

impl OpenVpnRuntimeStager {
    pub(crate) fn root_owned(layout: PlatformLayout, runtime: &HelperRuntimeIdentity) -> Self {
        Self {
            runtime_root: PathBuf::from(layout.helper_runtime_dir()),
            runtime_directory: runtime.runtime_dir().to_owned(),
            resource: runtime.resource().clone(),
            interface_name: runtime.kernel_alias().to_owned(),
            expected_owner_uid: 0,
        }
    }

    #[cfg(test)]
    fn for_test(
        runtime_root: PathBuf,
        runtime_directory: PathBuf,
        resource: ResourceTag,
        interface_name: String,
        expected_owner_uid: u32,
    ) -> Self {
        Self {
            runtime_root,
            runtime_directory,
            resource,
            interface_name,
            expected_owner_uid,
        }
    }

    pub(crate) fn runtime_directory(&self) -> &Path {
        &self.runtime_directory
    }

    pub(crate) fn stage(
        &self,
        plan: &OpenVpnPlan,
        mut materials: OpenVpnDescriptorSet,
    ) -> Result<StagedOpenVpnStart, OpenVpnStagingError> {
        if self.resource.kind() != ResourceKind::Tunnel
            || self.resource.profile_id() != Some(plan.profile_id())
            || self.resource.generation() != plan.generation()
        {
            return Err(OpenVpnStagingError::PlanIdentityMismatch);
        }
        let credentials = take_validated_openvpn_credentials(plan, &mut materials)?;

        let resource_root = self.runtime_root.join("resources");
        let execution = render_helper_execution_under(
            plan,
            &self.runtime_directory,
            &resource_root,
            &self.interface_name,
        )
        .map_err(|_| OpenVpnStagingError::UnsafeRuntime)?;
        validate_directory(
            &self.runtime_root,
            self.expected_owner_uid,
            HELPER_SOCKET_DIR_MODE,
        )?;
        let mut setup = DirectorySetup::default();
        setup.create_and_validate(&resource_root, self.expected_owner_uid)?;
        setup.create_and_validate(&self.runtime_directory, self.expected_owner_uid)?;
        let secret_directory = self.runtime_directory.join(SECRET_DIRECTORY);
        setup.create_and_validate(&secret_directory, self.expected_owner_uid)?;
        let created_secret_directory = if setup.was_created(&secret_directory) {
            Some(CreatedDirectory::read(secret_directory)?)
        } else {
            None
        };
        for child_created in [
            execution.log_path(),
            execution.management_socket(),
            &self.runtime_directory.join(OPENVPN_CHILD_EVIDENCE_FILE),
            &self.runtime_directory.join(INTERFACE_EVIDENCE_FILE),
        ] {
            match std::fs::symlink_metadata(child_created) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(OpenVpnStagingError::StaleRuntime),
            }
        }

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

        for (slot, descriptor) in materials.profile_materials {
            let bytes = read_bounded_descriptor(descriptor, MAX_MATERIAL_BYTES)
                .map_err(OpenVpnStagingError::from_material_descriptor)?;
            let path = staged
                .execution
                .material_path(slot)
                .ok_or(OpenVpnStagingError::InvalidMaterialSlot)?
                .to_owned();
            let identity = write_staged_file(&path, &bytes)?;
            staged.created_paths.push(CreatedPath { path, identity });
        }

        setup.commit();
        Ok(StagedOpenVpnStart {
            runtime: staged,
            credentials,
        })
    }

    pub(crate) fn recover_for_cleanup(
        &self,
    ) -> Result<RecoveredOpenVpnRuntime, OpenVpnStagingError> {
        self.recover_for_cleanup_if_present()?.ok_or_else(|| {
            OpenVpnStagingError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "OpenVPN helper runtime is absent",
            ))
        })
    }

    pub(crate) fn recover_for_cleanup_if_present(
        &self,
    ) -> Result<Option<RecoveredOpenVpnRuntime>, OpenVpnStagingError> {
        validate_directory(
            &self.runtime_root,
            self.expected_owner_uid,
            HELPER_SOCKET_DIR_MODE,
        )?;
        let resource_root = self.runtime_root.join("resources");
        if self.runtime_directory.parent() != Some(resource_root.as_path()) {
            return Err(OpenVpnStagingError::UnsafeRuntime);
        }
        match private_directory_presence(
            &resource_root,
            self.expected_owner_uid,
            HELPER_RUNTIME_DIR_MODE,
        )? {
            None => return Ok(None),
            Some(false) => return Err(OpenVpnStagingError::UnsafeRuntime),
            Some(true) => {}
        }
        match private_directory_presence(
            &self.runtime_directory,
            self.expected_owner_uid,
            HELPER_RUNTIME_DIR_MODE,
        )? {
            None => return Ok(None),
            Some(false) => return Err(OpenVpnStagingError::UnsafeRuntime),
            Some(true) => {}
        }
        let entries = std::fs::read_dir(&self.runtime_directory)?;
        let recovered = RecoveredOpenVpnRuntime {
            runtime_root: self.runtime_root.clone(),
            runtime_directory: self.runtime_directory.clone(),
            expected_owner_uid: self.expected_owner_uid,
        };
        recovered.validate_entries(entries)?;
        Ok(Some(recovered))
    }
}

fn take_validated_openvpn_credentials(
    plan: &OpenVpnPlan,
    materials: &mut OpenVpnDescriptorSet,
) -> Result<Option<DecodedOpenVpnCredentials>, OpenVpnStagingError> {
    if !materials
        .profile_materials
        .keys()
        .eq(plan.materials().iter())
        || materials.credentials.is_some() != plan.authentication().uses_username_password()
    {
        return Err(OpenVpnStagingError::MaterialSetMismatch);
    }
    let credentials = materials
        .credentials
        .take()
        .map(read_openvpn_credential_descriptor)
        .transpose()?;
    if credentials.as_ref().is_some_and(|credentials| {
        credentials.answer_is_empty() == plan.authentication().challenge().is_some()
    }) {
        return Err(OpenVpnStagingError::InvalidCredentials);
    }
    Ok(credentials)
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
pub(crate) struct StagedOpenVpnStart {
    runtime: StagedOpenVpnRuntime,
    credentials: Option<DecodedOpenVpnCredentials>,
}

impl StagedOpenVpnStart {
    pub(crate) fn into_parts(self) -> (StagedOpenVpnRuntime, Option<DecodedOpenVpnCredentials>) {
        (self.runtime, self.credentials)
    }

    #[cfg(test)]
    fn into_runtime(self) -> StagedOpenVpnRuntime {
        assert!(self.credentials.is_none());
        self.runtime
    }
}

pub(crate) struct StagedOpenVpnRuntime {
    execution: OpenVpnExecutionSpec,
    runtime_directory: PathBuf,
    created_paths: Vec<CreatedPath>,
    created_secret_directory: Option<CreatedDirectory>,
    expected_owner_uid: u32,
    cleaned: bool,
}

pub(crate) struct RecoveredOpenVpnRuntime {
    runtime_root: PathBuf,
    runtime_directory: PathBuf,
    expected_owner_uid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecoveredRuntimeState {
    payload_present: bool,
    child_evidence_present: bool,
}

impl Debug for RecoveredOpenVpnRuntime {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoveredOpenVpnRuntime")
            .field("protocol", &ProtocolKind::OpenVpn)
            .finish_non_exhaustive()
    }
}

impl RecoveredOpenVpnRuntime {
    pub(crate) fn openvpn_route_evidence(
        &self,
    ) -> Result<OpenVpnRouteEvidence, OpenVpnStagingError> {
        read_openvpn_route_evidence(&self.runtime_directory, self.expected_owner_uid)
    }

    pub(crate) fn is_drained(&self) -> Result<bool, OpenVpnStagingError> {
        self.validate().map(|state| !state.payload_present)
    }

    fn validate(&self) -> Result<RecoveredRuntimeState, OpenVpnStagingError> {
        validate_directory(
            &self.runtime_root,
            self.expected_owner_uid,
            HELPER_SOCKET_DIR_MODE,
        )?;
        let resource_root = self.runtime_root.join("resources");
        validate_directory(
            &resource_root,
            self.expected_owner_uid,
            HELPER_RUNTIME_DIR_MODE,
        )?;
        if self.runtime_directory.parent() != Some(resource_root.as_path()) {
            return Err(OpenVpnStagingError::UnsafeRuntime);
        }
        validate_directory(
            &self.runtime_directory,
            self.expected_owner_uid,
            HELPER_RUNTIME_DIR_MODE,
        )?;

        self.validate_entries(std::fs::read_dir(&self.runtime_directory)?)
    }

    fn validate_entries(
        &self,
        entries: std::fs::ReadDir,
    ) -> Result<RecoveredRuntimeState, OpenVpnStagingError> {
        let mut payload_present = false;
        let mut child_evidence_present = false;
        for entry in entries {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                return Err(OpenVpnStagingError::UnsafeRuntime);
            };
            let path = entry.path();
            match name.as_str() {
                CONFIG_FILE => {
                    validate_private_regular(
                        &path,
                        self.expected_owner_uid,
                        Some(MAX_MATERIAL_BYTES as u64),
                    )?;
                    payload_present = true;
                }
                LOG_FILE => {
                    validate_private_regular(&path, self.expected_owner_uid, None)?;
                    payload_present = true;
                }
                MANAGEMENT_SOCKET => {
                    validate_private_socket(&path, self.expected_owner_uid)?;
                    payload_present = true;
                }
                OPENVPN_CHILD_EVIDENCE_FILE => {
                    validate_private_regular(
                        &path,
                        self.expected_owner_uid,
                        Some(MAX_CHILD_EVIDENCE_BYTES),
                    )?;
                    child_evidence_present = true;
                }
                INTERFACE_EVIDENCE_FILE => {
                    validate_private_regular(
                        &path,
                        self.expected_owner_uid,
                        Some(MAX_INTERFACE_EVIDENCE_BYTES),
                    )?;
                    payload_present = true;
                }
                SECRET_DIRECTORY => {
                    validate_directory(&path, self.expected_owner_uid, HELPER_RUNTIME_DIR_MODE)?;
                    validate_recovered_secret_directory(&path, self.expected_owner_uid)?;
                    payload_present = true;
                }
                _ => return Err(OpenVpnStagingError::UnsafeRuntime),
            }
        }
        Ok(RecoveredRuntimeState {
            payload_present,
            child_evidence_present,
        })
    }

    pub(crate) fn cleanup_payload_after_child(&mut self) -> Result<(), OpenVpnStagingError> {
        if !self.validate()?.payload_present {
            return Ok(());
        }
        let secrets = self.runtime_directory.join(SECRET_DIRECTORY);
        match std::fs::read_dir(&secrets) {
            Ok(entries) => {
                for entry in entries {
                    std::fs::remove_file(entry?.path())?;
                }
                File::open(&secrets)?.sync_all()?;
                std::fs::remove_dir(&secrets)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        for name in [
            CONFIG_FILE,
            LOG_FILE,
            MANAGEMENT_SOCKET,
            INTERFACE_EVIDENCE_FILE,
        ] {
            let path = self.runtime_directory.join(name);
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        File::open(&self.runtime_directory)?.sync_all()?;
        if self.validate()?.payload_present {
            return Err(OpenVpnStagingError::UnsafeRuntime);
        }
        Ok(())
    }

    pub(crate) fn finish_cleanup(self) -> Result<(), OpenVpnStagingError> {
        let state = self.validate()?;
        if state.payload_present || state.child_evidence_present {
            return Err(OpenVpnStagingError::UnsafeRuntime);
        }
        std::fs::remove_dir(&self.runtime_directory)?;
        File::open(self.runtime_root.join("resources"))?.sync_all()?;
        Ok(())
    }
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

    pub(crate) fn openvpn_route_evidence(
        &self,
    ) -> Result<OpenVpnRouteEvidence, OpenVpnStagingError> {
        read_openvpn_route_evidence(&self.runtime_directory, self.expected_owner_uid)
    }

    pub(crate) fn material_path(&self, slot: ProfileMaterialSlot) -> Option<&Path> {
        self.execution.material_path(slot)
    }

    pub(crate) fn material_paths(&self) -> impl Iterator<Item = &Path> {
        self.execution.material_paths()
    }

    pub(crate) fn try_connect_management(&self) -> Result<Option<UnixStream>, OpenVpnStagingError> {
        match std::fs::symlink_metadata(self.execution.management_socket()) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
            Ok(metadata) => validate_private_socket_metadata(&metadata, self.expected_owner_uid)?,
        }
        match UnixStream::connect(self.execution.management_socket()) {
            Ok(stream) => Ok(Some(stream)),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Remove only the exact files created by this staging guard. Unknown,
    /// replaced, linked, or non-private artifacts fail closed for recovery.
    pub(crate) fn cleanup(&mut self) -> Result<(), OpenVpnStagingError> {
        self.remove_created_paths_checked()
    }

    pub(crate) fn cleanup_after_child(&mut self) -> Result<(), OpenVpnStagingError> {
        self.cleanup_payload_after_child()?;
        self.finish_cleanup()
    }

    pub(crate) fn cleanup_payload_after_child(&mut self) -> Result<(), OpenVpnStagingError> {
        for path in [
            self.execution.management_socket(),
            self.execution.log_path(),
            &self.runtime_directory.join(INTERFACE_EVIDENCE_FILE),
        ] {
            let metadata = match std::fs::symlink_metadata(path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            let valid_type = if path == self.execution.management_socket() {
                metadata.file_type().is_socket()
            } else {
                metadata.is_file() && metadata.nlink() == 1
            };
            if !valid_type
                || metadata.uid() != self.expected_owner_uid
                || metadata.mode() & 0o077 != 0
            {
                return Err(OpenVpnStagingError::UnsafeRuntime);
            }
            std::fs::remove_file(path)?;
        }
        self.remove_created_paths_checked()
    }

    pub(crate) fn finish_cleanup(&mut self) -> Result<(), OpenVpnStagingError> {
        match std::fs::remove_dir(&self.runtime_directory) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
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
        let _ = std::fs::remove_dir(&self.runtime_directory);
    }
}

impl Drop for StagedOpenVpnRuntime {
    fn drop(&mut self) {
        self.remove_created_paths_best_effort();
    }
}

#[derive(Debug, Error)]
pub(crate) enum OpenVpnStagingError {
    #[error("duplicate OpenVPN tunnel descriptor identity")]
    DuplicateDescriptor,
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
    #[error("OpenVPN credential descriptor is malformed or incompatible with the plan")]
    InvalidCredentials,
    #[error("OpenVPN helper runtime identity, ownership, or mode is unsafe")]
    UnsafeRuntime,
    #[error("stale OpenVPN helper runtime file already exists")]
    StaleRuntime,
    #[error("OpenVPN material staging I/O failed")]
    Io(#[from] std::io::Error),
    #[error("OpenVPN route negotiation evidence is incomplete or invalid")]
    InvalidRouteEvidence,
}

impl OpenVpnStagingError {
    fn from_material_descriptor(error: DescriptorReadError) -> Self {
        match error {
            DescriptorReadError::Io(error) => Self::Io(error),
            DescriptorReadError::NotRegular | DescriptorReadError::Changed => {
                Self::InvalidMaterialDescriptor
            }
            DescriptorReadError::Empty => Self::EmptyMaterial,
            DescriptorReadError::TooLarge => Self::MaterialTooLarge,
        }
    }
}

fn read_openvpn_credential_descriptor(
    descriptor: File,
) -> Result<DecodedOpenVpnCredentials, OpenVpnStagingError> {
    let bytes = read_bounded_descriptor(descriptor, MAX_CREDENTIAL_FRAME_BYTES).map_err(
        |error| match error {
            DescriptorReadError::Empty => OpenVpnStagingError::InvalidCredentials,
            other => OpenVpnStagingError::from_material_descriptor(other),
        },
    )?;
    crate::vortix_core::openvpn_credentials::decode(&bytes)
        .ok_or(OpenVpnStagingError::InvalidCredentials)
}

fn read_openvpn_route_evidence(
    runtime_directory: &Path,
    expected_owner_uid: u32,
) -> Result<OpenVpnRouteEvidence, OpenVpnStagingError> {
    let config = read_private_text_snapshot(
        &runtime_directory.join(CONFIG_FILE),
        expected_owner_uid,
        MAX_MATERIAL_BYTES,
        false,
    )?;
    let parsed = crate::vortix_protocol_openvpn::parser::parse_ovpn_conf(&config.text)
        .map_err(|_| OpenVpnStagingError::InvalidRouteEvidence)?;
    if parsed.unsupported_route_semantics {
        return Err(OpenVpnStagingError::InvalidRouteEvidence);
    }
    let configured = parsed
        .routes
        .iter()
        .map(canonical_openvpn_route)
        .collect::<Result<Vec<_>, _>>()?;
    let log = read_private_text_snapshot(
        &runtime_directory.join(LOG_FILE),
        expected_owner_uid,
        MAX_OPENVPN_LOG_EVIDENCE_BYTES,
        true,
    )?;
    let pushed = crate::vortix_protocol_openvpn::push::pushed_route_evidence(&log.text)
        .map_err(|_| OpenVpnStagingError::InvalidRouteEvidence)?;
    if log.truncated && !pushed.push_reply_present() {
        return Err(OpenVpnStagingError::InvalidRouteEvidence);
    }
    let pushed_routes = pushed
        .routes()
        .iter()
        .map(canonical_openvpn_route)
        .collect::<Result<Vec<_>, _>>()?;
    let selected_remote_required = configured
        .iter()
        .chain(&pushed_routes)
        .any(|route| route.gateway() == OpenVpnRouteGateway::RemoteHost);
    let selected_remote = if selected_remote_required {
        Some(
            crate::vortix_protocol_openvpn::push::selected_remote_address(&log.text)
                .map_err(|_| OpenVpnStagingError::InvalidRouteEvidence)?
                .ok_or(OpenVpnStagingError::InvalidRouteEvidence)?,
        )
    } else {
        None
    };
    OpenVpnRouteEvidence::new(
        OpenVpnRouteSetEvidence::with_route_defaults(
            configured,
            parsed.redirect_gateway,
            parsed.route_defaults,
        )
        .map_err(|_| OpenVpnStagingError::InvalidRouteEvidence)?,
        OpenVpnRouteSetEvidence::with_route_defaults(
            pushed_routes,
            pushed.redirect_gateway().cloned(),
            pushed.route_defaults(),
        )
        .map_err(|_| OpenVpnStagingError::InvalidRouteEvidence)?,
    )
    .and_then(|evidence| evidence.with_selected_remote(selected_remote))
    .map_err(|_| OpenVpnStagingError::InvalidRouteEvidence)
}

fn canonical_openvpn_route(
    route: &crate::vortix_protocol_openvpn::parser::OvpnRoute,
) -> Result<OpenVpnRoute, OpenVpnStagingError> {
    let destination =
        crate::vortix_core::cidr::Cidr::new(route.destination.addr, route.destination.prefix_len)
            .ok_or(OpenVpnStagingError::InvalidRouteEvidence)?;
    OpenVpnRoute::with_gateway(destination, route.gateway, route.metric)
        .map_err(|_| OpenVpnStagingError::InvalidRouteEvidence)
}

struct PrivateTextSnapshot {
    text: String,
    truncated: bool,
}

fn read_private_text_snapshot(
    path: &Path,
    expected_owner_uid: u32,
    max_bytes: usize,
    tail: bool,
) -> Result<PrivateTextSnapshot, OpenVpnStagingError> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != expected_owner_uid
        || before.mode() & 0o777 != 0o600
        || before.nlink() != 1
        || before.len() == 0
        || (!tail && before.len() > max_bytes as u64)
    {
        return Err(OpenVpnStagingError::UnsafeRuntime);
    }
    let identity = SecretFileIdentity::from_metadata(&before);
    let start = if tail {
        before.len().saturating_sub(max_bytes as u64)
    } else {
        0
    };
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(before.len().saturating_sub(start)).unwrap_or(max_bytes),
    );
    (&mut file)
        .take(u64::try_from(max_bytes).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if !identity.matches_metadata(&after)
        || before.len() != after.len()
        || bytes.len() != usize::try_from(before.len().saturating_sub(start)).unwrap_or(usize::MAX)
    {
        return Err(OpenVpnStagingError::InvalidRouteEvidence);
    }
    if start != 0 {
        let newline = bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or(OpenVpnStagingError::InvalidRouteEvidence)?;
        bytes.drain(..=newline);
    }
    let text = String::from_utf8(bytes).map_err(|_| OpenVpnStagingError::InvalidRouteEvidence)?;
    Ok(PrivateTextSnapshot {
        text,
        truncated: start != 0,
    })
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

fn private_directory_presence(
    path: &Path,
    expected_owner_uid: u32,
    expected_mode: u32,
) -> std::io::Result<Option<bool>> {
    match private_directory_is_valid(path, expected_owner_uid, expected_mode) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
        Ok(valid) => Ok(Some(valid)),
    }
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
            if metadata.is_file()
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
            if metadata.is_dir()
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

fn validate_private_regular(
    path: &Path,
    expected_owner_uid: u32,
    max_bytes: Option<u64>,
) -> Result<(), OpenVpnStagingError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.uid() != expected_owner_uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() == 0
        || max_bytes.is_some_and(|max| metadata.len() > max)
    {
        return Err(OpenVpnStagingError::UnsafeRuntime);
    }
    Ok(())
}

fn validate_private_socket(
    path: &Path,
    expected_owner_uid: u32,
) -> Result<(), OpenVpnStagingError> {
    let metadata = std::fs::symlink_metadata(path)?;
    validate_private_socket_metadata(&metadata, expected_owner_uid)
}

fn validate_private_socket_metadata(
    metadata: &std::fs::Metadata,
    expected_owner_uid: u32,
) -> Result<(), OpenVpnStagingError> {
    if !metadata.file_type().is_socket()
        || metadata.uid() != expected_owner_uid
        || metadata.mode() & 0o077 != 0
    {
        return Err(OpenVpnStagingError::UnsafeRuntime);
    }
    Ok(())
}

fn validate_recovered_secret_directory(
    directory: &Path,
    expected_owner_uid: u32,
) -> Result<(), OpenVpnStagingError> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            return Err(OpenVpnStagingError::UnsafeRuntime);
        };
        if !is_helper_material_filename(&name) {
            return Err(OpenVpnStagingError::UnsafeRuntime);
        }
        validate_private_regular(
            &entry.path(),
            expected_owner_uid,
            Some(MAX_MATERIAL_BYTES as u64),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{Seek as _, SeekFrom, Write as _};
    use std::os::unix::fs::{symlink, OpenOptionsExt as _, PermissionsExt as _};

    use crate::helper::HELPER_SOCKET_DIR_MODE;
    use crate::vortix_core::privileged::{
        OpenVpnAuthFactors, OpenVpnDefaultGateway, OpenVpnDefaultGateways, OpenVpnPlan,
        OpenVpnRemote, OpenVpnRemoteSelection, OpenVpnRoute, OpenVpnRouteDefaults,
        OpenVpnRouteGateway, OpenVpnTransport, ProfileMaterialRef, ProfileMaterialSlot,
        ProtocolPlan, ResourceTag, WireGuardInterfaceOptions, WireGuardPeerPlan, WireGuardPlan,
        WireGuardPresharedKeyRef,
    };
    use crate::vortix_core::profile::ProfileId;

    use super::{
        OpenVpnDescriptorSet, OpenVpnRuntimeStager, OpenVpnStagingError, TunnelMaterialError,
        TunnelMaterialSet, WireGuardMaterialSet, WireGuardRuntimeStager, WireGuardStagingError,
        MAX_OPENVPN_LOG_EVIDENCE_BYTES,
    };
    use base64::engine::{general_purpose::STANDARD as BASE64, Engine as _};

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
            vec![OpenVpnRoute::new(
                crate::vortix_core::cidr::Cidr::new("10.40.0.0".parse().unwrap(), 16).unwrap(),
                Some("10.8.0.1".parse().unwrap()),
                Some(4),
            )
            .unwrap()],
        )
        .unwrap()
        .with_route_defaults(OpenVpnRouteDefaults::new(
            OpenVpnDefaultGateways::new(
                Some(OpenVpnDefaultGateway::Address("10.8.0.1".parse().unwrap())),
                Some("2001:db8::1".parse().unwrap()),
            )
            .unwrap(),
            Some(12),
        ))
    }

    fn plan() -> OpenVpnPlan {
        plan_for(profile('a'), 7)
    }

    fn remote_host_plan() -> OpenVpnPlan {
        OpenVpnPlan::new(
            profile('a'),
            7,
            vec![OpenVpnRemote::dns("vpn.example.com", 1194, OpenVpnTransport::Udp).unwrap()],
            OpenVpnRemoteSelection::Ordered,
            OpenVpnAuthFactors::certificate(),
            vec![OpenVpnRoute::with_gateway(
                "10.40.0.0/16".parse().unwrap(),
                OpenVpnRouteGateway::RemoteHost,
                None,
            )
            .unwrap()],
        )
        .unwrap()
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
            "vxtest0".into(),
            current_uid(),
        );
        (root, stager)
    }

    #[test]
    fn staged_and_recovered_openvpn_runtime_reconstruct_complete_route_evidence() {
        let (_root, runtime_stager) = fixture();
        let (_sources, materials) = certificate_materials();
        let prepared = runtime_stager.stage(&plan(), materials).unwrap();
        let runtime = prepared.into_runtime();
        let log_path = runtime.execution().log_path();
        let mut log = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(log_path)
            .unwrap();
        log.write_all(
            b"PUSH_REPLY,route 10.50.0.0 255.255.0.0 vpn_gateway 5,route-gateway 10.9.0.1,route-ipv6-gateway 2001:db8:1::1,route-metric 13,redirect-gateway def1\nInitialization Sequence Completed\n",
        )
        .unwrap();
        log.sync_all().unwrap();

        let active = runtime.openvpn_route_evidence().unwrap();
        assert_eq!(active.configured().routes()[0].metric(), Some(4));
        assert_eq!(active.pushed().routes()[0].metric(), Some(5));
        assert_eq!(
            active.configured().route_defaults().gateways().ipv4(),
            Some(OpenVpnDefaultGateway::Address("10.8.0.1".parse().unwrap()))
        );
        assert_eq!(
            active.pushed().route_defaults().gateways().ipv4(),
            Some(OpenVpnDefaultGateway::Address("10.9.0.1".parse().unwrap()))
        );
        assert_eq!(
            active.pushed().route_defaults().gateways().ipv6(),
            Some("2001:db8:1::1".parse().unwrap())
        );
        assert_eq!(active.configured().route_defaults().metric(), Some(12));
        assert_eq!(active.pushed().route_defaults().metric(), Some(13));
        assert!(active.pushed().redirect_gateway().unwrap().ipv4());

        std::mem::forget(runtime);
        let recovered = runtime_stager.recover_for_cleanup().unwrap();
        assert_eq!(recovered.openvpn_route_evidence().unwrap(), active);
    }

    #[test]
    fn openvpn_remote_host_evidence_uses_the_selected_successful_remote() {
        let (_root, runtime_stager) = fixture();
        let (_sources, materials) = certificate_materials();
        let runtime = runtime_stager
            .stage(&remote_host_plan(), materials)
            .unwrap()
            .into_runtime();
        let mut log = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(runtime.execution().log_path())
            .unwrap();
        log.write_all(
            b"UDPv4 link remote: [AF_INET]198.51.100.7:1194\nPUSH_REPLY,ping 10\nInitialization Sequence Completed\n",
        )
        .unwrap();
        log.sync_all().unwrap();

        assert_eq!(
            runtime.openvpn_route_evidence().unwrap().selected_remote(),
            Some("198.51.100.7".parse().unwrap())
        );

        drop(log);
        let mut log = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(runtime.execution().log_path())
            .unwrap();
        log.write_all(b"PUSH_REPLY,ping 10\nInitialization Sequence Completed\n")
            .unwrap();
        log.sync_all().unwrap();
        assert!(matches!(
            runtime.openvpn_route_evidence(),
            Err(OpenVpnStagingError::InvalidRouteEvidence)
        ));
    }

    #[test]
    fn openvpn_route_evidence_rejects_truncated_or_malformed_authority() {
        let (_root, runtime_stager) = fixture();
        let (_sources, materials) = certificate_materials();
        let runtime = runtime_stager
            .stage(&plan(), materials)
            .unwrap()
            .into_runtime();
        let mut log = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(runtime.execution().log_path())
            .unwrap();
        log.write_all(b"PUSH_REPLY,route 10.60.0.0 255.255.0.0\n")
            .unwrap();
        log.write_all(&vec![b'x'; MAX_OPENVPN_LOG_EVIDENCE_BYTES + 64])
            .unwrap();
        log.write_all(b"\nInitialization Sequence Completed\n")
            .unwrap();
        log.sync_all().unwrap();
        assert!(matches!(
            runtime.openvpn_route_evidence(),
            Err(OpenVpnStagingError::InvalidRouteEvidence)
        ));

        drop(log);
        let mut log = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(runtime.execution().log_path())
            .unwrap();
        log.write_all(b"PUSH_REPLY,ping 10\nInitialization Sequence Completed\n")
            .unwrap();
        log.sync_all().unwrap();
        let mut config = std::fs::OpenOptions::new()
            .append(true)
            .open(runtime.execution().config_path())
            .unwrap();
        config.write_all(b"route malformed\n").unwrap();
        config.sync_all().unwrap();
        assert!(matches!(
            runtime.openvpn_route_evidence(),
            Err(OpenVpnStagingError::InvalidRouteEvidence)
        ));
    }

    fn wireguard_plan() -> WireGuardPlan {
        let public_key = [2; 32];
        WireGuardPlan::new(
            profile('c'),
            9,
            vec!["10.8.0.2/24".parse().unwrap()],
            vec![WireGuardPeerPlan::with_preshared_key(
                public_key,
                None,
                vec!["0.0.0.0/0".parse().unwrap()],
                None,
                WireGuardPresharedKeyRef::for_peer(public_key).unwrap(),
            )
            .unwrap()],
            WireGuardInterfaceOptions::default(),
        )
        .unwrap()
    }

    fn wireguard_fixture() -> (tempfile::TempDir, WireGuardRuntimeStager) {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            root.path(),
            std::fs::Permissions::from_mode(HELPER_SOCKET_DIR_MODE),
        )
        .unwrap();
        let runtime = root
            .path()
            .join("resources")
            .join("c".repeat(ProfileId::HEX_LEN));
        let resource = ResourceTag::tunnel(profile('c'), 9).unwrap();
        let stager = WireGuardRuntimeStager::for_test(
            root.path().to_owned(),
            runtime.clone(),
            runtime.join("vxcandidate.conf"),
            resource,
            current_uid(),
        );
        (root, stager)
    }

    fn wireguard_materials() -> (Vec<tempfile::NamedTempFile>, WireGuardMaterialSet) {
        let (private_source, private) = descriptor(BASE64.encode([1; 32]).as_bytes());
        let (psk_source, psk) = descriptor(BASE64.encode([3; 32]).as_bytes());
        let materials = WireGuardMaterialSet::from_inherited_descriptors([
            (
                ProfileMaterialRef::ProfileSlot {
                    slot: ProfileMaterialSlot::WireGuardPrivateKey,
                },
                private,
            ),
            (
                ProfileMaterialRef::WireGuardPresharedKey {
                    peer_public_key: [2; 32],
                },
                psk,
            ),
        ])
        .unwrap();
        (vec![private_source, psk_source], materials)
    }

    #[test]
    fn wireguard_exact_descriptors_stage_one_private_canonical_config() {
        let (_root, stager) = wireguard_fixture();
        let (_sources, materials) = wireguard_materials();
        let mut runtime = stager.stage(&wireguard_plan(), materials).unwrap();
        let path = runtime.config_path().to_owned();
        let body = std::fs::read_to_string(&path).unwrap();

        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(body.contains("Address = 10.8.0.2/24"));
        assert!(body.contains("AllowedIPs = 0.0.0.0/0"));
        assert!(!body.contains("PostUp"));
        assert!(!format!("{runtime:?}").contains(&BASE64.encode([1; 32])));

        runtime.cleanup().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn wireguard_material_identity_and_plan_generation_fail_before_staging() {
        let (_root, stager) = wireguard_fixture();
        let (private_source, private) = descriptor(BASE64.encode([1; 32]).as_bytes());
        let missing = WireGuardMaterialSet::from_inherited_descriptors([(
            ProfileMaterialRef::ProfileSlot {
                slot: ProfileMaterialSlot::WireGuardPrivateKey,
            },
            private,
        )])
        .unwrap();
        assert!(matches!(
            stager.stage(&wireguard_plan(), missing),
            Err(WireGuardStagingError::MaterialSetMismatch)
        ));
        drop(private_source);

        let (_sources, materials) = wireguard_materials();
        let wrong = WireGuardPlan::new(
            profile('c'),
            10,
            Vec::new(),
            vec![WireGuardPeerPlan::new([2; 32], None, Vec::new(), None).unwrap()],
            WireGuardInterfaceOptions::default(),
        )
        .unwrap();
        assert!(matches!(
            stager.stage(&wrong, materials),
            Err(WireGuardStagingError::PlanIdentityMismatch)
        ));
    }

    #[test]
    fn wireguard_runtime_recovery_reauthenticates_exact_private_inode() {
        let (_root, stager) = wireguard_fixture();
        let (_sources, materials) = wireguard_materials();
        let runtime = stager.stage(&wireguard_plan(), materials).unwrap();
        let config = runtime.config_path().to_owned();
        std::mem::forget(runtime);

        let mut recovered = stager.recover().unwrap();
        assert_eq!(recovered.config_path(), config);
        recovered.cleanup().unwrap();
        assert!(!config.exists());

        let (_sources, materials) = wireguard_materials();
        let runtime = stager.stage(&wireguard_plan(), materials).unwrap();
        let config = runtime.config_path().to_owned();
        std::mem::forget(runtime);
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            stager.recover(),
            Err(WireGuardStagingError::UnsafeRuntime)
        ));
    }

    #[test]
    fn wireguard_cleanup_recovery_distinguishes_drained_from_unsafe_runtime() {
        let (root, stager) = wireguard_fixture();
        assert!(stager.recover_for_cleanup_if_present().unwrap().is_none());

        let resources = root.path().join("resources");
        std::fs::create_dir(&resources).unwrap();
        std::fs::set_permissions(&resources, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(&stager.runtime_directory).unwrap();
        std::fs::set_permissions(
            &stager.runtime_directory,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(stager.recover_for_cleanup_if_present().unwrap().is_none());

        std::fs::write(stager.runtime_directory.join("foreign"), b"unsafe").unwrap();
        assert!(matches!(
            stager.recover_for_cleanup_if_present(),
            Err(WireGuardStagingError::UnsafeRuntime)
        ));
    }

    fn certificate_materials() -> (Vec<tempfile::NamedTempFile>, OpenVpnDescriptorSet) {
        let (ca_source, ca) = descriptor(b"ca-certificate");
        let (cert_source, cert) = descriptor(b"client-certificate");
        let (key_source, key) = descriptor(b"private-key-secret");
        let materials = OpenVpnDescriptorSet::from_inherited_descriptors([
            (ProfileMaterialSlot::OpenVpnCaCertificate, ca),
            (ProfileMaterialSlot::OpenVpnClientCertificate, cert),
            (ProfileMaterialSlot::OpenVpnPrivateKey, key),
        ])
        .unwrap();
        (vec![ca_source, cert_source, key_source], materials)
    }

    #[test]
    fn interactive_credentials_are_descriptor_bound_decoded_and_redacted_before_staging() {
        let (root, runtime_stager) = fixture();
        let interactive = OpenVpnPlan::new(
            profile('a'),
            7,
            vec![OpenVpnRemote::dns("vpn.example.com", 1194, OpenVpnTransport::Udp).unwrap()],
            OpenVpnRemoteSelection::Ordered,
            OpenVpnAuthFactors::username_password(),
            Vec::new(),
        )
        .unwrap();
        let plan = ProtocolPlan::OpenVpn(interactive.clone());
        let (ca_source, ca) = descriptor(b"ca-certificate");
        let frame = crate::vortix_core::openvpn_credentials::encode("alice", "correct horse", None);
        let (credential_source, credentials) = descriptor(&frame);
        let TunnelMaterialSet::OpenVpn(materials) =
            TunnelMaterialSet::for_plan(&plan, vec![ca, credentials]).unwrap()
        else {
            panic!("expected OpenVPN material set");
        };
        let debug = format!("{materials:?}");
        assert!(!debug.contains("alice"));
        assert!(!debug.contains("correct horse"));

        let staged = runtime_stager.stage(&interactive, materials).unwrap();
        let (staged, credentials) = staged.into_parts();
        let (username, password, answer) = credentials.unwrap().into_parts();
        assert_eq!(username.as_str(), "alice");
        assert_eq!(password.as_str(), "correct horse");
        assert!(answer.is_empty());
        assert!(!format!("{staged:?}").contains("alice"));
        drop((ca_source, credential_source, root));
    }

    #[test]
    fn interactive_descriptor_count_and_malformed_credentials_fail_before_runtime_creation() {
        let (_root, runtime_stager) = fixture();
        let interactive = OpenVpnPlan::new(
            profile('a'),
            7,
            vec![OpenVpnRemote::dns("vpn.example.com", 1194, OpenVpnTransport::Udp).unwrap()],
            OpenVpnRemoteSelection::Ordered,
            OpenVpnAuthFactors::username_password(),
            Vec::new(),
        )
        .unwrap();
        let plan = ProtocolPlan::OpenVpn(interactive.clone());
        let (ca_source, ca) = descriptor(b"ca-certificate");
        assert!(matches!(
            TunnelMaterialSet::for_plan(&plan, vec![ca]),
            Err(TunnelMaterialError::CountMismatch)
        ));

        let (ca_source_2, ca) = descriptor(b"ca-certificate");
        let (credential_source, credentials) = descriptor(b"not-a-credential-frame");
        let TunnelMaterialSet::OpenVpn(materials) =
            TunnelMaterialSet::for_plan(&plan, vec![ca, credentials]).unwrap()
        else {
            panic!("expected OpenVPN material set");
        };
        assert!(matches!(
            runtime_stager.stage(&interactive, materials),
            Err(OpenVpnStagingError::InvalidCredentials)
        ));
        assert!(!runtime_stager.runtime_directory().exists());
        drop((ca_source, ca_source_2, credential_source));
    }

    #[test]
    fn exact_descriptor_set_stages_private_runtime_and_cleans_on_drop() {
        let (root, runtime_stager) = fixture();
        let (_sources, materials) = certificate_materials();

        let staged = runtime_stager
            .stage(&plan(), materials)
            .unwrap()
            .into_runtime();
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
            .into_runtime()
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
        let missing = OpenVpnDescriptorSet::from_inherited_descriptors([(
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
        let extra = OpenVpnDescriptorSet::from_inherited_descriptors(entries).unwrap();
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
            OpenVpnDescriptorSet::from_inherited_descriptors([
                (ProfileMaterialSlot::OpenVpnCaCertificate, first),
                (ProfileMaterialSlot::OpenVpnCaCertificate, second),
            ]),
            Err(OpenVpnStagingError::DuplicateDescriptor)
        ));
        drop((first_source, second_source));

        let (_root, runtime_stager) = fixture();
        let (ca_source, ca) = descriptor(b"ca");
        let (cert_source, cert) = descriptor(b"cert");
        let oversized = vec![b'x'; super::MAX_MATERIAL_BYTES + 1];
        let (key_source, key) = descriptor(&oversized);
        let materials = OpenVpnDescriptorSet::from_inherited_descriptors([
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
        let materials = OpenVpnDescriptorSet::from_inherited_descriptors([
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
        let materials = OpenVpnDescriptorSet::from_inherited_descriptors([
            (ProfileMaterialSlot::OpenVpnCaCertificate, ca),
            (ProfileMaterialSlot::OpenVpnClientCertificate, cert),
            (ProfileMaterialSlot::OpenVpnPrivateKey, key),
        ])
        .unwrap();

        let staged = runtime_stager
            .stage(&plan(), materials)
            .unwrap()
            .into_runtime();
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
        let mut staged = runtime_stager
            .stage(&plan(), materials)
            .unwrap()
            .into_runtime();
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

    #[test]
    fn recovered_runtime_removes_only_fixed_private_artifacts() {
        let (_root, runtime_stager) = fixture();
        let (_sources, materials) = certificate_materials();
        let staged = runtime_stager
            .stage(&plan(), materials)
            .unwrap()
            .into_runtime();
        let runtime = staged.runtime_directory().to_owned();
        std::mem::forget(staged);
        std::fs::write(runtime.join("openvpn.log"), b"started").unwrap();
        std::fs::set_permissions(
            runtime.join("openvpn.log"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        let mut recovered = runtime_stager.recover_for_cleanup().unwrap();
        recovered.cleanup_payload_after_child().unwrap();
        recovered.finish_cleanup().unwrap();

        assert!(!runtime.exists());
    }

    #[test]
    fn recovered_runtime_refuses_unknown_or_linked_artifacts() {
        for artifact in ["unknown", "openvpn.log"] {
            let (root, runtime_stager) = fixture();
            let (_sources, materials) = certificate_materials();
            let staged = runtime_stager
                .stage(&plan(), materials)
                .unwrap()
                .into_runtime();
            let runtime = staged.runtime_directory().to_owned();
            std::mem::forget(staged);
            if artifact == "unknown" {
                std::fs::write(runtime.join(artifact), b"foreign").unwrap();
            } else {
                let target = root.path().join("foreign-log");
                std::fs::write(&target, b"foreign").unwrap();
                symlink(target, runtime.join(artifact)).unwrap();
            }

            assert!(matches!(
                runtime_stager.recover_for_cleanup(),
                Err(OpenVpnStagingError::UnsafeRuntime)
            ));
            assert!(runtime.exists());
        }
    }

    #[test]
    fn openvpn_cleanup_recovery_accepts_missing_runtime_but_not_unknown_artifacts() {
        let (_root, runtime_stager) = fixture();
        assert!(runtime_stager
            .recover_for_cleanup_if_present()
            .unwrap()
            .is_none());

        let (_sources, materials) = certificate_materials();
        let staged = runtime_stager
            .stage(&plan(), materials)
            .unwrap()
            .into_runtime();
        let runtime = staged.runtime_directory().to_owned();
        std::mem::forget(staged);
        assert!(runtime_stager
            .recover_for_cleanup_if_present()
            .unwrap()
            .is_some());

        std::fs::write(runtime.join("foreign"), b"unsafe").unwrap();
        assert!(matches!(
            runtime_stager.recover_for_cleanup_if_present(),
            Err(OpenVpnStagingError::UnsafeRuntime)
        ));
    }
}
