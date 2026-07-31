//! Read-only OS observation for authority-fenced helper resources.

#![allow(
    dead_code,
    reason = "U12 executor remains unreachable until U13 enrollment gates it"
)]

use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::helper::runtime::HelperRuntimeIdentity;
use crate::helper::server::{ObservationError, ObservationExecutor, ObservationOutcome};
use crate::helper::validate::PlatformLayout;
use crate::vortix_core::privileged::{
    LeaseId, ObservationState, ResourceKind, ResourceObservation, ResourceObservationTarget,
};
use crate::vortix_core::profile::ProtocolKind;

const MAX_INTERFACE_EVIDENCE_BYTES: u64 = 64;

/// Production read-back executor. It accepts only fixed identities derived
/// from the authenticated lease and resource tag.
pub(crate) struct SystemObservationExecutor {
    layout: PlatformLayout,
    lease_id: LeaseId,
}

impl SystemObservationExecutor {
    pub(crate) fn new(layout: PlatformLayout, lease_id: LeaseId) -> Result<Self, ObservationError> {
        if !platform_matches(layout) {
            return Err(ObservationError::InvalidResource);
        }
        Ok(Self { layout, lease_id })
    }

    fn observe_target(&self, target: &ResourceObservationTarget) -> ObservationState {
        observe_target_with_probe(self.layout, self.lease_id, target, &OsObservationProbe)
    }
}

impl ObservationExecutor for SystemObservationExecutor {
    fn observe(
        &mut self,
        targets: &[ResourceObservationTarget],
    ) -> Result<ObservationOutcome, ObservationError> {
        let observed_at_millis = OsObservationProbe.now_millis().max(1);
        let observations = targets
            .iter()
            .map(|target| {
                ResourceObservation::new(
                    target.resource().clone(),
                    self.observe_target(target),
                    observed_at_millis,
                )
                .map_err(|_| ObservationError::InvalidResource)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ObservationOutcome::new(observations, Vec::new()))
    }
}

fn observe_target_with_probe<P: ObservationProbe>(
    layout: PlatformLayout,
    lease_id: LeaseId,
    target: &ResourceObservationTarget,
    probe: &P,
) -> ObservationState {
    if target.resource().kind() != ResourceKind::Tunnel {
        return ObservationState::Unknown;
    }
    let Ok(identity) = HelperRuntimeIdentity::derive(layout, lease_id, target.resource()) else {
        return ObservationState::Drifted;
    };
    match (layout, target.protocol()) {
        (PlatformLayout::Linux, Some(ProtocolKind::WireGuard | ProtocolKind::OpenVpn)) => {
            probe.interface_state(identity.kernel_alias())
        }
        (PlatformLayout::MacOs, Some(ProtocolKind::WireGuard)) => {
            let direct = probe.interface_state(identity.kernel_alias());
            if direct == ObservationState::Present {
                direct
            } else {
                state_from_evidence(probe, &identity.wireguard_name_evidence())
            }
        }
        (PlatformLayout::MacOs, Some(ProtocolKind::OpenVpn)) => {
            state_from_evidence(probe, &identity.interface_evidence())
        }
        (_, None) => ObservationState::Drifted,
    }
}

fn state_from_evidence<P: ObservationProbe>(probe: &P, path: &Path) -> ObservationState {
    match probe.interface_name_evidence(path) {
        InterfaceNameEvidence::Name(name) => probe.interface_state(&name),
        InterfaceNameEvidence::Invalid => ObservationState::Drifted,
        InterfaceNameEvidence::Missing | InterfaceNameEvidence::Unavailable => {
            ObservationState::Unknown
        }
    }
}

trait ObservationProbe {
    fn interface_state(&self, name: &str) -> ObservationState;
    fn interface_name_evidence(&self, path: &Path) -> InterfaceNameEvidence;
    fn now_millis(&self) -> u64;
}

struct OsObservationProbe;

impl ObservationProbe for OsObservationProbe {
    fn interface_state(&self, name: &str) -> ObservationState {
        if !valid_interface_name(name) {
            return ObservationState::Drifted;
        }
        platform_interface_state(name)
    }

    fn interface_name_evidence(&self, path: &Path) -> InterfaceNameEvidence {
        read_interface_name_evidence(path)
    }

    fn now_millis(&self) -> u64 {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        u64::try_from(millis).unwrap_or(u64::MAX)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum InterfaceNameEvidence {
    Name(String),
    Missing,
    Unavailable,
    Invalid,
}

fn read_interface_name_evidence(path: &Path) -> InterfaceNameEvidence {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return InterfaceNameEvidence::Missing;
        }
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return InterfaceNameEvidence::Invalid;
        }
        Err(_) => return InterfaceNameEvidence::Unavailable,
    };
    read_validated_interface_name(file)
}

fn read_validated_interface_name(mut file: File) -> InterfaceNameEvidence {
    let Ok(metadata) = file.metadata() else {
        return InterfaceNameEvidence::Unavailable;
    };
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > MAX_INTERFACE_EVIDENCE_BYTES
    {
        return InterfaceNameEvidence::Invalid;
    }
    let Ok(capacity) = usize::try_from(metadata.len()) else {
        return InterfaceNameEvidence::Invalid;
    };
    let mut bytes = Vec::with_capacity(capacity);
    if file
        .by_ref()
        .take(MAX_INTERFACE_EVIDENCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return InterfaceNameEvidence::Unavailable;
    }
    if bytes.len() as u64 > MAX_INTERFACE_EVIDENCE_BYTES {
        return InterfaceNameEvidence::Invalid;
    }
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return InterfaceNameEvidence::Invalid;
    };
    let name = text.strip_suffix('\n').unwrap_or(text);
    if !valid_interface_name(name) {
        return InterfaceNameEvidence::Invalid;
    }
    InterfaceNameEvidence::Name(name.to_owned())
}

fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn platform_matches(layout: PlatformLayout) -> bool {
    matches!(
        (layout, crate::platform::current_platform_family()),
        (
            PlatformLayout::Linux,
            crate::platform::PlatformFamily::Linux
        ) | (
            PlatformLayout::MacOs,
            crate::platform::PlatformFamily::MacOs
        )
    )
}

fn platform_interface_state(name: &str) -> ObservationState {
    let interfaces = crate::platform::Platform::detect_current().available_network_interfaces();
    if interfaces.is_empty() {
        ObservationState::Unknown
    } else if interfaces.iter().any(|interface| interface == name) {
        ObservationState::Present
    } else {
        ObservationState::Absent
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    use super::*;
    use crate::vortix_core::privileged::{ResourceObservationTarget, ResourceTag};
    use crate::vortix_core::profile::ProfileId;

    struct FakeProbe {
        interfaces: BTreeMap<String, ObservationState>,
        evidence: InterfaceNameEvidence,
    }

    impl ObservationProbe for FakeProbe {
        fn interface_state(&self, name: &str) -> ObservationState {
            self.interfaces
                .get(name)
                .copied()
                .unwrap_or(ObservationState::Absent)
        }

        fn interface_name_evidence(&self, _path: &Path) -> InterfaceNameEvidence {
            self.evidence.clone()
        }

        fn now_millis(&self) -> u64 {
            42
        }
    }

    fn tunnel(protocol: ProtocolKind) -> ResourceObservationTarget {
        ResourceObservationTarget::new(
            ResourceTag::tunnel(ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap(), 7)
                .unwrap(),
            Some(protocol),
        )
        .unwrap()
    }

    #[test]
    fn linux_tunnels_use_only_the_authority_derived_kernel_alias() {
        let target = tunnel(ProtocolKind::WireGuard);
        let identity = HelperRuntimeIdentity::derive(
            PlatformLayout::Linux,
            LeaseId::new([4; 32]),
            target.resource(),
        )
        .unwrap();
        let probe = FakeProbe {
            interfaces: BTreeMap::from([(
                identity.kernel_alias().to_owned(),
                ObservationState::Present,
            )]),
            evidence: InterfaceNameEvidence::Invalid,
        };

        assert_eq!(
            observe_target_with_probe(
                PlatformLayout::Linux,
                LeaseId::new([4; 32]),
                &target,
                &probe,
            ),
            ObservationState::Present
        );
    }

    #[test]
    fn macos_tunnels_require_valid_fixed_name_evidence() {
        let target = tunnel(ProtocolKind::OpenVpn);
        for (evidence, expected) in [
            (
                InterfaceNameEvidence::Name("utun9".into()),
                ObservationState::Present,
            ),
            (InterfaceNameEvidence::Missing, ObservationState::Unknown),
            (InterfaceNameEvidence::Invalid, ObservationState::Drifted),
        ] {
            let probe = FakeProbe {
                interfaces: BTreeMap::from([("utun9".into(), ObservationState::Present)]),
                evidence,
            };
            assert_eq!(
                observe_target_with_probe(
                    PlatformLayout::MacOs,
                    LeaseId::new([4; 32]),
                    &target,
                    &probe,
                ),
                expected
            );
        }
    }

    #[test]
    fn unsupported_resource_families_remain_unknown_not_absent() {
        let group = ResourceTag::profile(
            ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap(),
            7,
            ResourceKind::ProcessGroup,
        )
        .unwrap();
        let target = ResourceObservationTarget::new(group, Some(ProtocolKind::OpenVpn)).unwrap();
        let probe = FakeProbe {
            interfaces: BTreeMap::new(),
            evidence: InterfaceNameEvidence::Missing,
        };

        assert_eq!(
            observe_target_with_probe(
                PlatformLayout::Linux,
                LeaseId::new([4; 32]),
                &target,
                &probe,
            ),
            ObservationState::Unknown
        );
    }

    #[test]
    fn interface_name_validation_rejects_paths_whitespace_and_overlong_names() {
        for invalid in [
            "",
            ".",
            "..",
            "../utun9",
            "utun 9",
            "interface-name-is-too-long",
            "utun9\nextra",
        ] {
            assert!(!valid_interface_name(invalid), "accepted {invalid:?}");
        }
        assert!(valid_interface_name("vxabc234def5678"));
        assert!(valid_interface_name("utun9"));
    }

    #[test]
    fn production_constructor_rejects_the_other_platform_layout() {
        let (current, other) = match crate::platform::current_platform_family() {
            crate::platform::PlatformFamily::Linux => {
                (PlatformLayout::Linux, PlatformLayout::MacOs)
            }
            crate::platform::PlatformFamily::MacOs => {
                (PlatformLayout::MacOs, PlatformLayout::Linux)
            }
        };

        assert!(SystemObservationExecutor::new(current, LeaseId::new([4; 32])).is_ok());
        assert_eq!(
            SystemObservationExecutor::new(other, LeaseId::new([4; 32])).err(),
            Some(ObservationError::InvalidResource)
        );
    }

    #[test]
    fn fixed_name_evidence_rejects_writable_files_and_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let evidence = directory.path().join("interface.name");
        std::fs::write(&evidence, b"utun9\n").unwrap();
        std::fs::set_permissions(&evidence, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            read_interface_name_evidence(&evidence),
            InterfaceNameEvidence::Invalid
        );

        let link = directory.path().join("interface-link.name");
        symlink(&evidence, &link).unwrap();
        assert_eq!(
            read_interface_name_evidence(&link),
            InterfaceNameEvidence::Invalid
        );
    }
}
