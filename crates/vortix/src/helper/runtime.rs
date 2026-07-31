//! Deterministic physical identity for helper-managed tunnel resources.

#![allow(
    dead_code,
    reason = "U12 physical identity remains dormant until production executors are enrolled"
)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::helper::validate::PlatformLayout;
use crate::vortix_core::privileged::{LeaseId, OperationDigest, ResourceKind, ResourceTag};

const KERNEL_ALIAS_PREFIX: &str = "vx";
const KERNEL_ALIAS_HASH_CHARS: usize = 13;
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Authority-fenced physical names derived only from root-ledger identity.
/// No caller-provided path or interface string participates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HelperRuntimeIdentity {
    runtime_dir: PathBuf,
    kernel_alias: String,
}

impl HelperRuntimeIdentity {
    pub(crate) fn derive(
        layout: PlatformLayout,
        lease_id: LeaseId,
        resource: &ResourceTag,
    ) -> Result<Self, RuntimeIdentityError> {
        if resource.kind() != ResourceKind::Tunnel {
            return Err(RuntimeIdentityError::NotTunnel);
        }
        let profile_id = resource
            .profile_id()
            .ok_or(RuntimeIdentityError::NotTunnel)?;
        let mut material = Vec::with_capacity(32 + profile_id.as_str().len() + 64);
        material.extend_from_slice(b"vortix-helper-runtime-v1\0");
        material.extend_from_slice(&lease_id.as_bytes());
        material.extend_from_slice(profile_id.as_str().as_bytes());
        material.extend_from_slice(&resource.generation().to_be_bytes());
        let digest = OperationDigest::of_bytes(&material).as_bytes();
        let runtime_dir = runtime_root(layout)
            .join("resources")
            .join(lower_hex(&digest));
        Ok(Self {
            runtime_dir,
            kernel_alias: format!("{KERNEL_ALIAS_PREFIX}{}", base32_prefix(&digest)),
        })
    }

    pub(crate) fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    pub(crate) fn kernel_alias(&self) -> &str {
        &self.kernel_alias
    }

    pub(crate) fn wireguard_config(&self) -> PathBuf {
        self.runtime_dir.join(format!("{}.conf", self.kernel_alias))
    }

    pub(crate) fn wireguard_name_evidence(&self) -> PathBuf {
        Path::new("/var/run/wireguard").join(format!("{}.name", self.kernel_alias))
    }

    pub(crate) fn openvpn_log(&self) -> PathBuf {
        self.runtime_dir.join("openvpn.log")
    }

    pub(crate) fn openvpn_pid(&self) -> PathBuf {
        self.runtime_dir.join("openvpn.pid")
    }

    pub(crate) fn interface_evidence(&self) -> PathBuf {
        self.runtime_dir.join("interface.name")
    }

    pub(crate) fn secret_dir(&self) -> PathBuf {
        self.runtime_dir.join("secrets")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum RuntimeIdentityError {
    #[error("helper runtime identity requires a tunnel resource")]
    NotTunnel,
}

fn runtime_root(layout: PlatformLayout) -> &'static Path {
    Path::new(layout.helper_runtime_dir())
}

fn lower_hex(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn base32_prefix(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(KERNEL_ALIAS_HASH_CHARS);
    let mut accumulator = 0_u16;
    let mut bits = 0_u8;
    for byte in bytes {
        accumulator = (accumulator << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 && output.len() < KERNEL_ALIAS_HASH_CHARS {
            bits -= 5;
            let index = usize::from((accumulator >> bits) & 0x1f);
            output.push(char::from(BASE32[index]));
            accumulator &= (1_u16 << bits).wrapping_sub(1);
        }
        if output.len() == KERNEL_ALIAS_HASH_CHARS {
            break;
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::validate::PlatformLayout;
    use crate::vortix_core::privileged::{LeaseId, ResourceTag};
    use crate::vortix_core::profile::ProfileId;

    fn tunnel(profile: &str, generation: u64) -> ResourceTag {
        ResourceTag::tunnel(
            ProfileId::parse(profile.repeat(ProfileId::HEX_LEN)).unwrap(),
            generation,
        )
        .unwrap()
    }

    #[test]
    fn same_lease_and_resource_derive_stable_runtime_identity() {
        let lease = LeaseId::new([7; 32]);
        let resource = tunnel("a", 3);

        let first = HelperRuntimeIdentity::derive(PlatformLayout::Linux, lease, &resource).unwrap();
        let second =
            HelperRuntimeIdentity::derive(PlatformLayout::Linux, lease, &resource).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.kernel_alias().len(), 15);
        assert!(first
            .kernel_alias()
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()));
        assert!(first.runtime_dir().starts_with("/run/vortix/resources"));
    }

    #[test]
    fn lease_profile_and_generation_each_fence_physical_identity() {
        let baseline = HelperRuntimeIdentity::derive(
            PlatformLayout::Linux,
            LeaseId::new([1; 32]),
            &tunnel("a", 1),
        )
        .unwrap();
        for candidate in [
            HelperRuntimeIdentity::derive(
                PlatformLayout::Linux,
                LeaseId::new([2; 32]),
                &tunnel("a", 1),
            )
            .unwrap(),
            HelperRuntimeIdentity::derive(
                PlatformLayout::Linux,
                LeaseId::new([1; 32]),
                &tunnel("b", 1),
            )
            .unwrap(),
            HelperRuntimeIdentity::derive(
                PlatformLayout::Linux,
                LeaseId::new([1; 32]),
                &tunnel("a", 2),
            )
            .unwrap(),
        ] {
            assert_ne!(candidate.kernel_alias(), baseline.kernel_alias());
            assert_ne!(candidate.runtime_dir(), baseline.runtime_dir());
        }
    }

    #[test]
    fn runtime_artifacts_are_fixed_beneath_platform_root() {
        let identity = HelperRuntimeIdentity::derive(
            PlatformLayout::MacOs,
            LeaseId::new([3; 32]),
            &tunnel("c", 9),
        )
        .unwrap();

        assert!(identity
            .runtime_dir()
            .starts_with("/var/run/vortix/resources"));
        assert_eq!(
            identity
                .wireguard_config()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap(),
            format!("{}.conf", identity.kernel_alias()),
        );
        assert_eq!(
            identity
                .wireguard_name_evidence()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap(),
            format!("{}.name", identity.kernel_alias()),
        );
        for artifact in [
            identity.openvpn_log(),
            identity.openvpn_pid(),
            identity.interface_evidence(),
            identity.secret_dir(),
        ] {
            assert!(artifact.starts_with(identity.runtime_dir()));
        }
    }

    #[test]
    fn non_tunnel_resources_cannot_receive_runtime_identity() {
        let resource = ResourceTag::profile(
            ProfileId::parse("d".repeat(ProfileId::HEX_LEN)).unwrap(),
            1,
            crate::vortix_core::privileged::ResourceKind::RuntimeSecret,
        )
        .unwrap();

        assert_eq!(
            HelperRuntimeIdentity::derive(PlatformLayout::Linux, LeaseId::new([4; 32]), &resource),
            Err(RuntimeIdentityError::NotTunnel)
        );
    }
}
