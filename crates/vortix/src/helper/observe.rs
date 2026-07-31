//! Read-only OS observation for authority-fenced helper resources.

#![allow(
    dead_code,
    reason = "U12 executor remains unreachable until U13 enrollment gates it"
)]

use std::fs::{File, OpenOptions};
use std::io::{self, Read as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::helper::runtime::HelperRuntimeIdentity;
use crate::helper::server::{ObservationError, ObservationExecutor, ObservationOutcome};
use crate::helper::validate::PlatformLayout;
use crate::vortix_core::ports::process::KernelProcessIdentity;
use crate::vortix_core::privileged::{
    LeaseId, ObservationState, ObservedChildIdentity, ResourceKind, ResourceObservation,
    ResourceObservationTarget, ResourceTag,
};
use crate::vortix_core::profile::ProtocolKind;

const MAX_INTERFACE_EVIDENCE_BYTES: u64 = 64;
const MAX_CHILD_EVIDENCE_BYTES: u64 = 4 * 1024;

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

    fn observe_target(&self, target: &ResourceObservationTarget) -> TargetObservation {
        observe_target_with_probe(self.layout, self.lease_id, target, &OsObservationProbe)
    }
}

impl ObservationExecutor for SystemObservationExecutor {
    fn observe(
        &mut self,
        targets: &[ResourceObservationTarget],
    ) -> Result<ObservationOutcome, ObservationError> {
        let observed_at_millis = OsObservationProbe.now_millis().max(1);
        let mut observations = Vec::with_capacity(targets.len());
        let mut child_observations = Vec::new();
        for target in targets {
            let observed = self.observe_target(target);
            observations.push(
                ResourceObservation::new(
                    target.resource().clone(),
                    observed.state,
                    observed_at_millis,
                )
                .map_err(|_| ObservationError::InvalidResource)?,
            );
            if let Some(child) = observed.child.filter(|child| {
                targets
                    .iter()
                    .any(|candidate| candidate.resource() == child.resource())
            }) {
                child_observations.push(child);
            }
        }
        Ok(ObservationOutcome::new(observations, child_observations))
    }
}

struct TargetObservation {
    state: ObservationState,
    child: Option<ObservedChildIdentity>,
}

impl TargetObservation {
    const fn state(state: ObservationState) -> Self {
        Self { state, child: None }
    }

    const fn with_child(state: ObservationState, child: ObservedChildIdentity) -> Self {
        Self {
            state,
            child: Some(child),
        }
    }
}

fn observe_target_with_probe<P: ObservationProbe>(
    layout: PlatformLayout,
    lease_id: LeaseId,
    target: &ResourceObservationTarget,
    probe: &P,
) -> TargetObservation {
    if target.resource().kind() == ResourceKind::ProcessGroup {
        return observe_process_group(layout, lease_id, target, probe);
    }
    if target.resource().kind() != ResourceKind::Tunnel {
        return TargetObservation::state(ObservationState::Unknown);
    }
    let Ok(identity) = HelperRuntimeIdentity::derive(layout, lease_id, target.resource()) else {
        return TargetObservation::state(ObservationState::Drifted);
    };
    let state = match (layout, target.protocol()) {
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
    };
    TargetObservation::state(state)
}

fn observe_process_group<P: ObservationProbe>(
    layout: PlatformLayout,
    lease_id: LeaseId,
    target: &ResourceObservationTarget,
    probe: &P,
) -> TargetObservation {
    if target.protocol() != Some(ProtocolKind::OpenVpn) {
        return TargetObservation::state(ObservationState::Drifted);
    }
    let Some(profile_id) = target.resource().profile_id().cloned() else {
        return TargetObservation::state(ObservationState::Drifted);
    };
    let Ok(tunnel) = ResourceTag::tunnel(profile_id, target.resource().generation()) else {
        return TargetObservation::state(ObservationState::Drifted);
    };
    let Ok(runtime) = HelperRuntimeIdentity::derive(layout, lease_id, &tunnel) else {
        return TargetObservation::state(ObservationState::Drifted);
    };
    let child = match probe.child_identity_evidence(&runtime.openvpn_child_evidence()) {
        ChildIdentityEvidence::Identity(child) => child,
        ChildIdentityEvidence::Invalid => {
            return TargetObservation::state(ObservationState::Drifted);
        }
        ChildIdentityEvidence::Missing | ChildIdentityEvidence::Unavailable => {
            return TargetObservation::state(ObservationState::Unknown);
        }
    };
    if child.resource() != &tunnel || child.containment() != runtime.containment() {
        return TargetObservation::state(ObservationState::Drifted);
    }
    match probe.process_identity(child.pid()) {
        Ok(None) => TargetObservation::state(ObservationState::Absent),
        Err(_) => TargetObservation::state(ObservationState::Unknown),
        Ok(Some(identity))
            if identity.start_token() != child.process_start_token()
                || !identity.is_process_group_leader() =>
        {
            TargetObservation::state(ObservationState::Drifted)
        }
        Ok(Some(_)) => TargetObservation::with_child(ObservationState::Present, child),
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
    fn child_identity_evidence(&self, path: &Path) -> ChildIdentityEvidence;
    fn process_identity(&self, pid: u32) -> io::Result<Option<KernelProcessIdentity>>;
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

    fn child_identity_evidence(&self, path: &Path) -> ChildIdentityEvidence {
        read_child_identity_evidence(path)
    }

    fn process_identity(&self, pid: u32) -> io::Result<Option<KernelProcessIdentity>> {
        crate::platform::observe_process_identity(pid)
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum ChildIdentityEvidence {
    Identity(ObservedChildIdentity),
    Missing,
    Unavailable,
    Invalid,
}

enum FixedEvidence {
    Bytes(Vec<u8>),
    Missing,
    Unavailable,
    Invalid,
}

fn read_interface_name_evidence(path: &Path) -> InterfaceNameEvidence {
    let bytes = match read_fixed_evidence(path, MAX_INTERFACE_EVIDENCE_BYTES) {
        FixedEvidence::Bytes(bytes) => bytes,
        FixedEvidence::Missing => return InterfaceNameEvidence::Missing,
        FixedEvidence::Unavailable => return InterfaceNameEvidence::Unavailable,
        FixedEvidence::Invalid => return InterfaceNameEvidence::Invalid,
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return InterfaceNameEvidence::Invalid;
    };
    let name = text.strip_suffix('\n').unwrap_or(text);
    if !valid_interface_name(name) {
        return InterfaceNameEvidence::Invalid;
    }
    InterfaceNameEvidence::Name(name.to_owned())
}

fn read_child_identity_evidence(path: &Path) -> ChildIdentityEvidence {
    match read_fixed_evidence(path, MAX_CHILD_EVIDENCE_BYTES) {
        FixedEvidence::Bytes(bytes) => serde_json::from_slice(&bytes).map_or(
            ChildIdentityEvidence::Invalid,
            ChildIdentityEvidence::Identity,
        ),
        FixedEvidence::Missing => ChildIdentityEvidence::Missing,
        FixedEvidence::Unavailable => ChildIdentityEvidence::Unavailable,
        FixedEvidence::Invalid => ChildIdentityEvidence::Invalid,
    }
}

fn read_fixed_evidence(path: &Path, max_bytes: u64) -> FixedEvidence {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return FixedEvidence::Missing;
        }
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return FixedEvidence::Invalid;
        }
        Err(_) => return FixedEvidence::Unavailable,
    };
    read_validated_evidence(file, max_bytes)
}

fn read_validated_evidence(mut file: File, max_bytes: u64) -> FixedEvidence {
    let Ok(metadata) = file.metadata() else {
        return FixedEvidence::Unavailable;
    };
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > max_bytes
    {
        return FixedEvidence::Invalid;
    }
    let Ok(capacity) = usize::try_from(metadata.len()) else {
        return FixedEvidence::Invalid;
    };
    let mut bytes = Vec::with_capacity(capacity);
    if file
        .by_ref()
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return FixedEvidence::Unavailable;
    }
    if bytes.len() as u64 > max_bytes {
        return FixedEvidence::Invalid;
    }
    FixedEvidence::Bytes(bytes)
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

        fn child_identity_evidence(&self, _path: &Path) -> ChildIdentityEvidence {
            ChildIdentityEvidence::Missing
        }

        fn process_identity(&self, _pid: u32) -> io::Result<Option<KernelProcessIdentity>> {
            Err(io::Error::other("unused fake process probe"))
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
            )
            .state,
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
                )
                .state,
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
            )
            .state,
            ObservationState::Unknown
        );
    }

    struct ProcessProbe {
        evidence: ChildIdentityEvidence,
        identity: Option<KernelProcessIdentity>,
        unavailable: bool,
    }

    impl ObservationProbe for ProcessProbe {
        fn interface_state(&self, _name: &str) -> ObservationState {
            ObservationState::Unknown
        }

        fn interface_name_evidence(&self, _path: &Path) -> InterfaceNameEvidence {
            InterfaceNameEvidence::Missing
        }

        fn child_identity_evidence(&self, _path: &Path) -> ChildIdentityEvidence {
            self.evidence.clone()
        }

        fn process_identity(&self, _pid: u32) -> io::Result<Option<KernelProcessIdentity>> {
            if self.unavailable {
                Err(io::Error::other("kernel process evidence unavailable"))
            } else {
                Ok(self.identity)
            }
        }

        fn now_millis(&self) -> u64 {
            42
        }
    }

    fn openvpn_group() -> (
        ResourceObservationTarget,
        ResourceTag,
        HelperRuntimeIdentity,
    ) {
        let profile = ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap();
        let tunnel = ResourceTag::tunnel(profile.clone(), 7).unwrap();
        let group = ResourceTag::profile(profile, 7, ResourceKind::ProcessGroup).unwrap();
        let target = ResourceObservationTarget::new(group, Some(ProtocolKind::OpenVpn)).unwrap();
        let runtime =
            HelperRuntimeIdentity::derive(PlatformLayout::Linux, LeaseId::new([4; 32]), &tunnel)
                .unwrap();
        (target, tunnel, runtime)
    }

    #[test]
    fn process_group_requires_matching_root_record_start_token_and_private_group() {
        let (target, tunnel, runtime) = openvpn_group();
        let child = ObservedChildIdentity::new(tunnel, 42, 99, runtime.containment()).unwrap();
        let exact = ProcessProbe {
            evidence: ChildIdentityEvidence::Identity(child.clone()),
            identity: KernelProcessIdentity::new(99, true),
            unavailable: false,
        };
        let observed = observe_target_with_probe(
            PlatformLayout::Linux,
            LeaseId::new([4; 32]),
            &target,
            &exact,
        );
        assert_eq!(observed.state, ObservationState::Present);
        assert_eq!(observed.child, Some(child.clone()));

        for identity in [
            KernelProcessIdentity::new(100, true),
            KernelProcessIdentity::new(99, false),
        ] {
            let drifted = ProcessProbe {
                evidence: ChildIdentityEvidence::Identity(child.clone()),
                identity,
                unavailable: false,
            };
            assert_eq!(
                observe_target_with_probe(
                    PlatformLayout::Linux,
                    LeaseId::new([4; 32]),
                    &target,
                    &drifted,
                )
                .state,
                ObservationState::Drifted
            );
        }
    }

    #[test]
    fn process_group_missing_or_unreadable_evidence_never_infers_absence() {
        let (target, tunnel, runtime) = openvpn_group();
        let child = ObservedChildIdentity::new(tunnel, 42, 99, runtime.containment()).unwrap();
        for probe in [
            ProcessProbe {
                evidence: ChildIdentityEvidence::Missing,
                identity: None,
                unavailable: false,
            },
            ProcessProbe {
                evidence: ChildIdentityEvidence::Identity(child),
                identity: None,
                unavailable: true,
            },
        ] {
            assert_eq!(
                observe_target_with_probe(
                    PlatformLayout::Linux,
                    LeaseId::new([4; 32]),
                    &target,
                    &probe,
                )
                .state,
                ObservationState::Unknown
            );
        }
    }

    #[test]
    fn process_group_absence_requires_valid_evidence_for_the_exact_containment() {
        let (target, tunnel, runtime) = openvpn_group();
        let child =
            ObservedChildIdentity::new(tunnel.clone(), 42, 99, runtime.containment()).unwrap();
        let absent = ProcessProbe {
            evidence: ChildIdentityEvidence::Identity(child),
            identity: None,
            unavailable: false,
        };
        assert_eq!(
            observe_target_with_probe(
                PlatformLayout::Linux,
                LeaseId::new([4; 32]),
                &target,
                &absent,
            )
            .state,
            ObservationState::Absent
        );

        let forged = ProcessProbe {
            evidence: ChildIdentityEvidence::Identity(
                ObservedChildIdentity::new(
                    tunnel,
                    42,
                    99,
                    crate::vortix_core::privileged::ContainmentId::new([9; 32]),
                )
                .unwrap(),
            ),
            identity: KernelProcessIdentity::new(99, true),
            unavailable: false,
        };
        assert_eq!(
            observe_target_with_probe(
                PlatformLayout::Linux,
                LeaseId::new([4; 32]),
                &target,
                &forged,
            )
            .state,
            ObservationState::Drifted
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
