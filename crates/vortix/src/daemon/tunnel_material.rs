//! Stored profile preparation for helper tunnel execution.
//!
//! Profile bodies are read through one bounded no-follow descriptor. Secret
//! key directives are compiled by the protocol adapter, written into anonymous
//! descriptors, and zeroized before this value returns. Only the public typed
//! plan is serializable.

#![allow(
    dead_code,
    reason = "helper tunnel material remains dormant until the helper-backed executor is complete"
)]
use std::fmt::{Debug, Formatter};
use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt as _;

use thiserror::Error;
use zeroize::Zeroizing;

use crate::vortix_core::privileged::ProtocolPlan;
use crate::vortix_core::profile::Profile;

pub(super) struct PreparedTunnelStart {
    plan: ProtocolPlan,
    descriptors: Vec<File>,
}

impl Debug for PreparedTunnelStart {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedTunnelStart")
            .field("protocol", &self.plan.protocol())
            .field("profile_id", self.plan.profile_id())
            .field("generation", &self.plan.generation())
            .field("descriptor_count", &self.descriptors.len())
            .finish_non_exhaustive()
    }
}

impl PreparedTunnelStart {
    pub(super) fn wireguard(
        profile: &Profile,
        generation: u64,
    ) -> Result<Self, TunnelMaterialPreparationError> {
        let body = read_profile_body(profile)?;
        let prepared = crate::vortix_protocol_wireguard::profile_plan::compile_helper_plan(
            profile, generation, &body,
        )?;
        let (plan, materials) = prepared.into_parts();
        let mut descriptors = Vec::with_capacity(materials.len());
        for material in &materials {
            descriptors.push(anonymous_material_descriptor(material)?);
        }
        Ok(Self {
            plan: ProtocolPlan::WireGuard(plan),
            descriptors,
        })
    }

    pub(super) const fn plan(&self) -> &ProtocolPlan {
        &self.plan
    }

    pub(super) fn raw_descriptors(&self) -> Vec<RawFd> {
        self.descriptors.iter().map(AsRawFd::as_raw_fd).collect()
    }

    pub(super) fn into_parts(self) -> (ProtocolPlan, Vec<File>) {
        (self.plan, self.descriptors)
    }

    #[cfg(test)]
    fn descriptors_mut_for_test(&mut self) -> &mut [File] {
        &mut self.descriptors
    }
}

fn read_profile_body(
    profile: &Profile,
) -> Result<Zeroizing<Vec<u8>>, TunnelMaterialPreparationError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&profile.config_path)
        .map_err(|_| TunnelMaterialPreparationError::ProfileRead)?;
    let before = file
        .metadata()
        .map_err(|_| TunnelMaterialPreparationError::ProfileRead)?;
    if !before.is_file()
        || before.len() == 0
        || before.len() > crate::constants::MAX_CONFIG_SIZE_BYTES
    {
        return Err(TunnelMaterialPreparationError::InvalidProfileFile);
    }
    let expected = usize::try_from(before.len())
        .map_err(|_| TunnelMaterialPreparationError::InvalidProfileFile)?;
    let mut body = Zeroizing::new(vec![0_u8; expected]);
    file.read_exact(&mut body)
        .map_err(|_| TunnelMaterialPreparationError::ProfileChanged)?;
    let mut trailing = [0_u8; 1];
    loop {
        match file.read(&mut trailing) {
            Ok(0) => break,
            Ok(_) => return Err(TunnelMaterialPreparationError::ProfileChanged),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(TunnelMaterialPreparationError::ProfileRead),
        }
    }
    let after = file
        .metadata()
        .map_err(|_| TunnelMaterialPreparationError::ProfileRead)?;
    if after.len() != before.len() {
        return Err(TunnelMaterialPreparationError::ProfileChanged);
    }
    Ok(body)
}

fn anonymous_material_descriptor(material: &[u8]) -> Result<File, TunnelMaterialPreparationError> {
    if material.is_empty()
        || u64::try_from(material.len()).unwrap_or(u64::MAX)
            > crate::constants::MAX_CONFIG_SIZE_BYTES
    {
        return Err(TunnelMaterialPreparationError::InvalidMaterial);
    }
    crate::platform::anonymous_material::create(material)
        .map_err(|_| TunnelMaterialPreparationError::DescriptorCreation)
}

#[derive(Debug, Error)]
pub(super) enum TunnelMaterialPreparationError {
    #[error("stored profile could not be read safely")]
    ProfileRead,
    #[error("stored profile must be a non-empty bounded regular file")]
    InvalidProfileFile,
    #[error("stored profile changed while it was being prepared")]
    ProfileChanged,
    #[error(transparent)]
    WireGuard(#[from] crate::vortix_protocol_wireguard::profile_plan::WireGuardProfilePlanError),
    #[error("protocol material is empty or oversized")]
    InvalidMaterial,
    #[error("anonymous protocol material descriptor could not be created")]
    DescriptorCreation,
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Seek as _, SeekFrom};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::MetadataExt as _;

    use base64::Engine as _;

    use crate::vortix_core::profile::{Profile, ProfileId, ProtocolKind, ResolvedEndpoint};

    use super::PreparedTunnelStart;

    fn key(byte: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    }

    #[test]
    fn stored_wireguard_profile_becomes_typed_plan_and_anonymous_descriptors() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("corp.conf");
        std::fs::write(
            &path,
            format!(
                "[Interface]\nPrivateKey = {}\nAddress = 10.8.0.2/24\nMTU = 1420\n\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nEndpoint = vpn.example.test:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
                key(1),
                key(2),
                key(3),
            ),
        )
        .unwrap();
        let profile = Profile::new(
            ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap(),
            "corp",
            ProtocolKind::WireGuard,
            path,
        )
        .with_endpoint_resolutions([ResolvedEndpoint::new(
            "vpn.example.test",
            51_820,
            "203.0.113.9".parse().unwrap(),
        )])
        .require_managed_endpoint_resolution();

        let mut prepared = PreparedTunnelStart::wireguard(&profile, 7).unwrap();

        assert_eq!(prepared.plan().profile_id(), &profile.id);
        assert_eq!(prepared.plan().generation(), 7);
        assert_eq!(prepared.raw_descriptors().len(), 2);
        let debug = format!("{prepared:?}");
        assert!(!debug.contains(&key(1)));
        assert!(!debug.contains(&key(3)));
        let serialized = serde_json::to_string(prepared.plan()).unwrap();
        assert!(!serialized.contains(&key(1)));
        assert!(!serialized.contains(&key(3)));
        for descriptor in prepared.descriptors_mut_for_test() {
            descriptor.seek(SeekFrom::Start(0)).unwrap();
            let mut material = String::new();
            descriptor.read_to_string(&mut material).unwrap();
            assert!(material == key(1) || material == key(3));
            let metadata = descriptor.metadata().unwrap();
            assert!(metadata.is_file());
            assert_eq!(metadata.nlink(), 0, "material descriptor must be anonymous");
            assert!(descriptor.as_raw_fd() >= 0);
        }
        assert!(!directory
            .path()
            .read_dir()
            .unwrap()
            .any(|entry| entry.unwrap().file_name() != "corp.conf"));
    }

    #[test]
    fn unsafe_or_unrepresentable_wireguard_profile_fails_before_material_creation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("corp.conf");
        std::fs::write(
            &path,
            format!(
                "[Interface]\nPrivateKey = {}\nPostUp = /tmp/evil\n\n[Peer]\nPublicKey = {}\nEndpoint = unresolved.example.test:51820\n",
                key(1),
                key(2),
            ),
        )
        .unwrap();
        let profile = Profile::new(
            ProfileId::parse("b".repeat(ProfileId::HEX_LEN)).unwrap(),
            "corp",
            ProtocolKind::WireGuard,
            path,
        )
        .require_managed_endpoint_resolution();

        let error = PreparedTunnelStart::wireguard(&profile, 7).unwrap_err();

        assert!(error.to_string().contains("executable lifecycle"));
        assert!(!directory
            .path()
            .read_dir()
            .unwrap()
            .any(|entry| entry.unwrap().file_name() != "corp.conf"));
    }

    #[test]
    fn stored_profile_reader_never_follows_a_config_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.conf");
        let link = directory.path().join("corp.conf");
        std::fs::write(
            &target,
            format!(
                "[Interface]\nPrivateKey = {}\n[Peer]\nPublicKey = {}\n",
                key(1),
                key(2),
            ),
        )
        .unwrap();
        symlink(target, &link).unwrap();
        let profile = Profile::new(
            ProfileId::parse("d".repeat(ProfileId::HEX_LEN)).unwrap(),
            "corp",
            ProtocolKind::WireGuard,
            link,
        );

        let error = PreparedTunnelStart::wireguard(&profile, 7).unwrap_err();

        assert!(error.to_string().contains("read safely"));
    }
}
