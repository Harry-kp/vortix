//! Fixed-path packaging, enrollment-request, and service-identity validation.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::vortix_core::privileged::{
    OperationDigest, PeerProcessIdentity, PlatformVerifiedAuthority, ServiceInstanceClaim,
    ServiceManager,
};

pub const INSTALL_SCHEMA_VERSION: u16 = 1;
pub const HELPER_SOCKET_MODE: u32 = 0o600;
pub const HELPER_RUNTIME_DIR_MODE: u32 = 0o700;
pub const HELPER_LEDGER_MODE: u32 = 0o600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformLayout {
    Linux,
    MacOs,
}

impl PlatformLayout {
    #[must_use]
    pub const fn helper_path(self) -> &'static str {
        match self {
            Self::Linux => "/usr/libexec/vortix/vortix-helper",
            Self::MacOs => "/Library/PrivilegedHelperTools/com.vortix.helper",
        }
    }

    #[must_use]
    pub const fn bootstrap_path(self) -> &'static str {
        match self {
            Self::Linux => "/usr/libexec/vortix/vortix-bootstrap",
            Self::MacOs => "/Library/PrivilegedHelperTools/com.vortix.bootstrap",
        }
    }

    #[must_use]
    pub const fn daemon_path(self) -> &'static str {
        match self {
            Self::Linux => "/usr/libexec/vortix/vortix",
            Self::MacOs => "/Library/Application Support/Vortix/bin/vortix",
        }
    }

    #[must_use]
    pub const fn helper_socket(self) -> &'static str {
        match self {
            Self::Linux => "/run/vortix/helper.sock",
            Self::MacOs => "/var/run/vortix/helper.sock",
        }
    }

    #[must_use]
    pub const fn helper_runtime_dir(self) -> &'static str {
        match self {
            Self::Linux => "/run/vortix",
            Self::MacOs => "/var/run/vortix",
        }
    }

    #[must_use]
    pub const fn root_ledger(self) -> &'static str {
        match self {
            Self::Linux => "/var/lib/vortix/helper-ledger.json",
            Self::MacOs => "/Library/Application Support/Vortix/helper-ledger.json",
        }
    }

    #[must_use]
    pub const fn requires_platform_signature(self) -> bool {
        matches!(self, Self::MacOs)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageChannel {
    DistroPackage,
    MacOsSignedPackage,
    Homebrew,
    CargoInstall,
    SourceBuild,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentSupport {
    Supported,
    Unsupported,
}

impl PackageChannel {
    #[must_use]
    pub const fn enrollment_support(self) -> EnrollmentSupport {
        match self {
            Self::DistroPackage | Self::MacOsSignedPackage => EnrollmentSupport::Supported,
            Self::Homebrew | Self::CargoInstall | Self::SourceBuild => {
                EnrollmentSupport::Unsupported
            }
        }
    }

    #[must_use]
    pub const fn secure_guidance(self) -> &'static str {
        match self {
            Self::DistroPackage | Self::MacOsSignedPackage => {
                "use the package-supplied verified bootstrap"
            }
            Self::Homebrew => "install a signed Vortix package; Homebrew remains in Standard mode",
            Self::CargoInstall => {
                "install a system Vortix package; cargo-installed helpers are user-writable"
            }
            Self::SourceBuild => {
                "builds from source remain in Standard mode unless packaged by a trusted system administrator"
            }
        }
    }
}

fn validate_channel_layout(
    layout: PlatformLayout,
    channel: PackageChannel,
) -> Result<(), InstallError> {
    if channel.enrollment_support() == EnrollmentSupport::Unsupported {
        return Err(InstallError::UnsupportedChannel {
            guidance: channel.secure_guidance(),
        });
    }
    if matches!(layout, PlatformLayout::Linux) != matches!(channel, PackageChannel::DistroPackage) {
        return Err(InstallError::LayoutChannelMismatch);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Daemon,
    Helper,
    Bootstrap,
}

impl ArtifactKind {
    #[allow(
        dead_code,
        reason = "U12 artifact verifier consumes the frozen path map"
    )]
    fn expected_path(self, layout: PlatformLayout) -> &'static str {
        match self {
            Self::Daemon => layout.daemon_path(),
            Self::Helper => layout.helper_path(),
            Self::Bootstrap => layout.bootstrap_path(),
        }
    }
}

/// Immutable package identity recorded in the canonical release manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallManifest {
    schema_version: u16,
    release_version: String,
    generation: u64,
    daemon_digest: OperationDigest,
    helper_digest: OperationDigest,
    bootstrap_digest: OperationDigest,
    prior_manifest_digest: Option<OperationDigest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallManifestWire {
    schema_version: u16,
    release_version: String,
    generation: u64,
    daemon_digest: OperationDigest,
    helper_digest: OperationDigest,
    bootstrap_digest: OperationDigest,
    prior_manifest_digest: Option<OperationDigest>,
}

impl<'de> Deserialize<'de> for InstallManifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = InstallManifestWire::deserialize(deserializer)?;
        Self::new(
            wire.release_version,
            wire.generation,
            wire.daemon_digest,
            wire.helper_digest,
            wire.bootstrap_digest,
            wire.prior_manifest_digest,
        )
        .and_then(|manifest| {
            if wire.schema_version == INSTALL_SCHEMA_VERSION {
                Ok(manifest)
            } else {
                Err(InstallError::InvalidManifest)
            }
        })
        .map_err(serde::de::Error::custom)
    }
}

impl InstallManifest {
    pub fn new(
        release_version: String,
        generation: u64,
        daemon_digest: OperationDigest,
        helper_digest: OperationDigest,
        bootstrap_digest: OperationDigest,
        prior_manifest_digest: Option<OperationDigest>,
    ) -> Result<Self, InstallError> {
        let invalid_digest = |digest: OperationDigest| digest.as_bytes() == [0; 32];
        if release_version.is_empty()
            || release_version.len() > 64
            || !release_version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
            || generation == 0
            || invalid_digest(daemon_digest)
            || invalid_digest(helper_digest)
            || invalid_digest(bootstrap_digest)
            || prior_manifest_digest.is_some_and(invalid_digest)
            || generation == 1 && prior_manifest_digest.is_some()
            || generation > 1 && prior_manifest_digest.is_none()
        {
            return Err(InstallError::InvalidManifest);
        }
        Ok(Self {
            schema_version: INSTALL_SCHEMA_VERSION,
            release_version,
            generation,
            daemon_digest,
            helper_digest,
            bootstrap_digest,
            prior_manifest_digest,
        })
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[allow(
        dead_code,
        reason = "U12 artifact verifier consumes the signed manifest"
    )]
    fn digest_for(&self, kind: ArtifactKind) -> OperationDigest {
        match kind {
            ArtifactKind::Daemon => self.daemon_digest,
            ArtifactKind::Helper => self.helper_digest,
            ArtifactKind::Bootstrap => self.bootstrap_digest,
        }
    }
}

/// Sanitized request accepted by the package-owned bootstrap. It contains no
/// executable, path, environment, shell, profile, or operation field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallRequest {
    schema_version: u16,
    owner_uid: u32,
    layout: PlatformLayout,
    channel: PackageChannel,
    manifest_generation: u64,
    manifest_digest: OperationDigest,
    request_nonce: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallRequestWire {
    schema_version: u16,
    owner_uid: u32,
    layout: PlatformLayout,
    channel: PackageChannel,
    manifest_generation: u64,
    manifest_digest: OperationDigest,
    request_nonce: [u8; 32],
}

impl<'de> Deserialize<'de> for InstallRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = InstallRequestWire::deserialize(deserializer)?;
        if wire.schema_version != INSTALL_SCHEMA_VERSION {
            return Err(serde::de::Error::custom(InstallError::InvalidRequest));
        }
        Self::new(
            wire.owner_uid,
            wire.layout,
            wire.channel,
            wire.manifest_generation,
            wire.manifest_digest,
            wire.request_nonce,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl InstallRequest {
    pub fn new(
        owner_uid: u32,
        layout: PlatformLayout,
        channel: PackageChannel,
        manifest_generation: u64,
        manifest_digest: OperationDigest,
        request_nonce: [u8; 32],
    ) -> Result<Self, InstallError> {
        if owner_uid == 0
            || manifest_generation == 0
            || manifest_digest.as_bytes() == [0; 32]
            || request_nonce == [0; 32]
        {
            return Err(InstallError::InvalidRequest);
        }
        validate_channel_layout(layout, channel)?;
        Ok(Self {
            schema_version: INSTALL_SCHEMA_VERSION,
            owner_uid,
            layout,
            channel,
            manifest_generation,
            manifest_digest,
            request_nonce,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ArtifactFact {
    kind: ArtifactKind,
    path: PathBuf,
    owner_uid: u32,
    mode: u32,
    digest: OperationDigest,
    platform_signed: bool,
}

impl ArtifactFact {
    #[allow(
        dead_code,
        reason = "U12 OS verifier constructs immutable artifact facts"
    )]
    pub(super) fn from_os_verifier(
        kind: ArtifactKind,
        path: PathBuf,
        owner_uid: u32,
        mode: u32,
        digest: OperationDigest,
        platform_signed: bool,
    ) -> Self {
        Self {
            kind,
            path,
            owner_uid,
            mode,
            digest,
            platform_signed,
        }
    }

    #[allow(dead_code, reason = "U12 invokes this after reading OS-owned facts")]
    pub(super) fn validate(
        &self,
        layout: PlatformLayout,
        manifest: &InstallManifest,
    ) -> Result<(), InstallError> {
        if self.path != Path::new(self.kind.expected_path(layout))
            || self.owner_uid != 0
            || self.mode & 0o022 != 0
            || self.mode & 0o500 != 0o500
            || self.digest != manifest.digest_for(self.kind)
            || layout.requires_platform_signature() && !self.platform_signed
        {
            return Err(InstallError::UntrustedArtifact { kind: self.kind });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StagedAuthority {
    StagedUnenrolled,
}

/// One immutable installer plan shared by future CLI, TUI, and advanced
/// service-install entrypoints. Building it performs no filesystem or service
/// manager mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPlan {
    pub layout: PlatformLayout,
    pub channel: PackageChannel,
    pub authority: StagedAuthority,
    pub artifacts: [ArtifactKind; 3],
}

impl InstallPlan {
    pub fn build(layout: PlatformLayout, channel: PackageChannel) -> Result<Self, InstallError> {
        validate_channel_layout(layout, channel)?;
        Ok(Self {
            layout,
            channel,
            authority: StagedAuthority::StagedUnenrolled,
            artifacts: [
                ArtifactKind::Daemon,
                ArtifactKind::Helper,
                ArtifactKind::Bootstrap,
            ],
        })
    }
}

/// OS facts created only by the future helper-side service-manager verifier.
/// Scalar wire values cannot construct this type outside the crate.
#[allow(dead_code, reason = "U12 consumes the frozen OS-verification seam")]
pub(super) struct VerifiedServiceFacts {
    manager: ServiceManager,
    peer_uid: u32,
    peer_pid: u32,
    process_start_token: u64,
    executable_digest: OperationDigest,
    manager_instance_nonce: [u8; 32],
    root_owned_unit: bool,
    containment_matches: bool,
}

#[allow(dead_code, reason = "U12 OS verifier constructs service facts")]
impl VerifiedServiceFacts {
    #[allow(
        clippy::too_many_arguments,
        clippy::similar_names,
        reason = "the OS verifier must supply every independent identity fact explicitly"
    )]
    pub(super) const fn from_os_verifier(
        manager: ServiceManager,
        peer_uid: u32,
        peer_pid: u32,
        process_start_token: u64,
        executable_digest: OperationDigest,
        manager_instance_nonce: [u8; 32],
        root_owned_unit: bool,
        containment_matches: bool,
    ) -> Self {
        Self {
            manager,
            peer_uid,
            peer_pid,
            process_start_token,
            executable_digest,
            manager_instance_nonce,
            root_owned_unit,
            containment_matches,
        }
    }
}

#[allow(dead_code, reason = "U12 consumes the frozen OS-verification seam")]
pub(super) fn verify_service_instance(
    owner_uid: u32,
    claim: &ServiceInstanceClaim,
    facts: &VerifiedServiceFacts,
) -> Result<PlatformVerifiedAuthority, InstallError> {
    if !facts.root_owned_unit
        || !facts.containment_matches
        || facts.manager != claim.manager()
        || facts.peer_pid != claim.pid()
        || facts.process_start_token != claim.process_start_token()
        || facts.executable_digest != claim.executable_digest()
        || facts.manager_instance_nonce != claim.manager_instance_nonce()
    {
        return Err(InstallError::UntrustedServiceInstance);
    }
    let peer = PeerProcessIdentity::untrusted_claim(
        facts.peer_uid,
        facts.peer_pid,
        facts.process_start_token,
    )
    .map_err(|_| InstallError::UntrustedServiceInstance)?;
    PlatformVerifiedAuthority::from_platform_verifier(owner_uid, peer, claim)
        .map_err(|_| InstallError::UntrustedServiceInstance)
}

/// Kernel/filesystem facts for the helper peer observed by the unprivileged
/// daemon. The wire hello cannot construct these facts.
#[allow(
    dead_code,
    reason = "U13 platform transport constructs helper peer facts"
)]
pub(super) struct HelperPeerFacts {
    peer_uid: u32,
    peer_pid: u32,
    process_start_token: u64,
    socket_path: PathBuf,
    socket_owner_uid: u32,
    socket_mode: u32,
    helper_artifact: ArtifactFact,
}

#[allow(
    dead_code,
    reason = "U13 platform transport constructs helper peer facts"
)]
impl HelperPeerFacts {
    #[allow(
        clippy::too_many_arguments,
        clippy::similar_names,
        reason = "the OS verifier supplies each independent helper identity fact"
    )]
    pub(super) const fn from_os_verifier(
        peer_uid: u32,
        peer_pid: u32,
        process_start_token: u64,
        socket_path: PathBuf,
        socket_owner_uid: u32,
        socket_mode: u32,
        helper_artifact: ArtifactFact,
    ) -> Self {
        Self {
            peer_uid,
            peer_pid,
            process_start_token,
            socket_path,
            socket_owner_uid,
            socket_mode,
            helper_artifact,
        }
    }
}

/// Opaque daemon-side proof that the connected process and socket match the
/// installed root-owned helper for this enrolled owner. Scalar handshake data
/// cannot create this capability.
#[allow(dead_code, reason = "U13 passes this capability to the helper client")]
pub(crate) struct VerifiedHelperPeer {
    private: (),
}

#[allow(dead_code, reason = "U13 invokes this with kernel/filesystem facts")]
pub(super) fn verify_helper_peer(
    owner_uid: u32,
    layout: PlatformLayout,
    manifest: &InstallManifest,
    facts: &HelperPeerFacts,
) -> Result<VerifiedHelperPeer, InstallError> {
    if owner_uid == 0
        || facts.peer_uid != 0
        || facts.peer_pid == 0
        || facts.process_start_token == 0
        || facts.socket_path != Path::new(layout.helper_socket())
        || facts.socket_owner_uid != owner_uid
        || facts.socket_mode != HELPER_SOCKET_MODE
        || facts.helper_artifact.kind != ArtifactKind::Helper
    {
        return Err(InstallError::UntrustedHelperPeer);
    }
    facts
        .helper_artifact
        .validate(layout, manifest)
        .map_err(|_| InstallError::UntrustedHelperPeer)?;
    Ok(VerifiedHelperPeer { private: () })
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InstallError {
    #[error("invalid canonical release manifest")]
    InvalidManifest,
    #[error("invalid sanitized install request")]
    InvalidRequest,
    #[error("this package channel cannot enroll Background mode: {guidance}")]
    UnsupportedChannel { guidance: &'static str },
    #[error("package channel does not match the platform layout")]
    LayoutChannelMismatch,
    #[error("untrusted installed artifact: {kind:?}")]
    UntrustedArtifact { kind: ArtifactKind },
    #[error("daemon service instance did not match OS-owned facts")]
    UntrustedServiceInstance,
    #[error("helper peer, socket, or installed artifact did not match OS-owned facts")]
    UntrustedHelperPeer,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_os_facts_are_required_to_mint_platform_authority() {
        let digest = OperationDigest::of_bytes(b"daemon");
        let claim = ServiceInstanceClaim::systemd(42, 99, digest, [7; 32]).unwrap();
        let facts = VerifiedServiceFacts::from_os_verifier(
            ServiceManager::Systemd,
            501,
            42,
            99,
            digest,
            [7; 32],
            true,
            true,
        );
        assert!(verify_service_instance(501, &claim, &facts).is_ok());
    }

    #[test]
    fn helper_peer_requires_root_process_fixed_owner_socket_and_package_artifact() {
        let helper_digest = OperationDigest::of_bytes(b"helper");
        let manifest = InstallManifest::new(
            "0.4.3".into(),
            1,
            OperationDigest::of_bytes(b"daemon"),
            helper_digest,
            OperationDigest::of_bytes(b"bootstrap"),
            None,
        )
        .unwrap();
        let artifact = ArtifactFact::from_os_verifier(
            ArtifactKind::Helper,
            PathBuf::from(PlatformLayout::Linux.helper_path()),
            0,
            0o755,
            helper_digest,
            false,
        );
        let facts = HelperPeerFacts::from_os_verifier(
            0,
            77,
            91,
            PathBuf::from(PlatformLayout::Linux.helper_socket()),
            501,
            HELPER_SOCKET_MODE,
            artifact,
        );
        assert!(verify_helper_peer(501, PlatformLayout::Linux, &manifest, &facts).is_ok());

        let wrong_socket = HelperPeerFacts::from_os_verifier(
            0,
            77,
            91,
            PathBuf::from("/tmp/helper.sock"),
            501,
            HELPER_SOCKET_MODE,
            facts.helper_artifact.clone(),
        );
        assert!(verify_helper_peer(501, PlatformLayout::Linux, &manifest, &wrong_socket).is_err());

        let non_root = HelperPeerFacts::from_os_verifier(
            501,
            77,
            91,
            PathBuf::from(PlatformLayout::Linux.helper_socket()),
            501,
            HELPER_SOCKET_MODE,
            facts.helper_artifact.clone(),
        );
        assert!(verify_helper_peer(501, PlatformLayout::Linux, &manifest, &non_root).is_err());
    }

    #[test]
    fn changed_executable_or_containment_fails_closed() {
        let digest = OperationDigest::of_bytes(b"daemon");
        let claim = ServiceInstanceClaim::launchd(42, 99, digest, [7; 32]).unwrap();
        let facts = VerifiedServiceFacts::from_os_verifier(
            ServiceManager::Launchd,
            501,
            42,
            99,
            OperationDigest::of_bytes(b"replacement"),
            [7; 32],
            true,
            true,
        );
        assert!(matches!(
            verify_service_instance(501, &claim, &facts),
            Err(InstallError::UntrustedServiceInstance)
        ));
    }

    #[test]
    fn only_exact_root_owned_artifacts_validate() {
        let manifest = InstallManifest::new(
            "0.4.3".into(),
            1,
            OperationDigest::of_bytes(b"daemon"),
            OperationDigest::of_bytes(b"helper"),
            OperationDigest::of_bytes(b"bootstrap"),
            None,
        )
        .unwrap();
        let fact = ArtifactFact::from_os_verifier(
            ArtifactKind::Helper,
            PathBuf::from(PlatformLayout::Linux.helper_path()),
            0,
            0o755,
            OperationDigest::of_bytes(b"helper"),
            false,
        );
        fact.validate(PlatformLayout::Linux, &manifest).unwrap();

        let replaced = ArtifactFact::from_os_verifier(
            ArtifactKind::Helper,
            PathBuf::from("/home/alice/.local/bin/vortix-helper"),
            0,
            0o755,
            OperationDigest::of_bytes(b"helper"),
            false,
        );
        assert!(replaced.validate(PlatformLayout::Linux, &manifest).is_err());
        let writable = ArtifactFact::from_os_verifier(
            ArtifactKind::Helper,
            PathBuf::from(PlatformLayout::Linux.helper_path()),
            0,
            0o775,
            OperationDigest::of_bytes(b"helper"),
            false,
        );
        assert!(writable.validate(PlatformLayout::Linux, &manifest).is_err());
    }
}
