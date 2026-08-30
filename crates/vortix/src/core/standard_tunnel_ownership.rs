//! Root-owned, boot-scoped ownership for Standard-mode kernel tunnels.
//!
//! This store is deliberately separate from [`super::managed_wireguard`].
//! The latter is owner-readable display evidence; this module is a private
//! root capability used only by the short-lived local canonical authority.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::core::scanner::ActiveSession;
use crate::vortix_core::control::worker::TunnelRevision;
use crate::vortix_core::control::AuthorityEpoch;
use crate::vortix_core::control::OperationId;
use crate::vortix_core::ports::tunnel::{HandshakeEvidence, ProbeReceipt, TunnelTeardownConfig};
use crate::vortix_core::profile::{Profile, ProfileId, ProtocolKind};

const SCHEMA_VERSION: u8 = 1;
const MAX_LEDGER_BYTES: u64 = 128 * 1024;
const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_RUNTIME_DIR: &str = "/var/run/vortix-standard-tunnel-ownership";

#[derive(Debug, Error)]
pub enum StandardOwnershipError {
    #[error("Standard-mode tunnel ownership has an invalid invoking owner")]
    InvalidOwner,
    #[error("OS boot identity is unavailable")]
    MissingBootIdentity,
    #[error("unsafe Standard-mode ownership path")]
    UnsafePath,
    #[error("Standard-mode ownership record is missing")]
    Missing,
    #[error("Standard-mode ownership record is stale or does not match current evidence")]
    Stale,
    #[error("Standard-mode ownership record exceeds its fixed bound")]
    Capacity,
    #[error("Standard-mode ownership I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Standard-mode ownership record is malformed")]
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireGuardOwnershipRecord {
    schema_version: u8,
    boot_scope: String,
    owner_uid: u32,
    authority_epoch: u64,
    tunnel_generation: u64,
    operation_id: OperationId,
    profile_id: String,
    interface_name: String,
    teardown_config_identity: String,
    handshake: HandshakeEvidence,
    probe_receipts: Vec<ProbeReceipt>,
}

/// Validated exact capability used to reconstruct one kernel-tunnel handle.
#[derive(Debug, Clone)]
pub struct ValidatedWireGuardOwnership {
    pub authority_epoch: AuthorityEpoch,
    pub tunnel_generation: u64,
    pub operation_id: OperationId,
    pub interface_name: String,
    pub handshake: HandshakeEvidence,
    pub probe_receipts: Vec<ProbeReceipt>,
    pub teardown_config: TunnelTeardownConfig,
}

/// Private Standard-mode store. Background/helper code must not construct it.
#[derive(Debug, Clone)]
pub struct StandardTunnelOwnershipStore {
    root: PathBuf,
    expected_runtime_uid: u32,
    owner_uid: u32,
    boot_scope: String,
}

impl StandardTunnelOwnershipStore {
    /// Construct the production root-owned store for the invoking sudo owner.
    pub fn production(owner_uid: u32) -> Result<Self, StandardOwnershipError> {
        if !crate::utils::is_root() {
            return Err(StandardOwnershipError::InvalidOwner);
        }
        let boot_scope =
            crate::utils::boot_identity().ok_or(StandardOwnershipError::MissingBootIdentity)?;
        Self::new(DEFAULT_RUNTIME_DIR, 0, owner_uid, boot_scope)
    }

    /// Explicit constructor used by deterministic tests and local composition.
    pub fn new(
        root: impl Into<PathBuf>,
        expected_runtime_uid: u32,
        owner_uid: u32,
        boot_scope: impl Into<String>,
    ) -> Result<Self, StandardOwnershipError> {
        let boot_scope = boot_scope.into();
        if boot_scope.is_empty() || boot_scope.len() > 128 {
            return Err(StandardOwnershipError::InvalidOwner);
        }
        let store = Self {
            root: root.into(),
            expected_runtime_uid,
            owner_uid,
            boot_scope,
        };
        store.ensure_root()?;
        Ok(store)
    }

    /// Persist the exact successful `WireGuard` attempt before publication.
    #[allow(
        clippy::too_many_arguments,
        reason = "one ownership record binds the complete protocol receipt atomically"
    )]
    pub fn issue_wireguard(
        &self,
        profile: &Profile,
        revision: TunnelRevision,
        operation_id: OperationId,
        interface_name: &str,
        teardown_config: &TunnelTeardownConfig,
        handshake: HandshakeEvidence,
        probe_receipts: Vec<ProbeReceipt>,
    ) -> Result<ValidatedWireGuardOwnership, StandardOwnershipError> {
        if profile.protocol != ProtocolKind::WireGuard
            || revision.generation == 0
            || handshake.generation != revision.generation
            || interface_name.is_empty()
            || !teardown_config.managed
        {
            return Err(StandardOwnershipError::Stale);
        }
        let teardown_bytes = read_managed_config(&teardown_config.path, self.expected_runtime_uid)?;
        let teardown_config_identity = content_identity(&teardown_bytes);
        let profile_id = profile.id.as_str().to_owned();
        self.atomic_write_path(&self.teardown_path(&profile.id), &teardown_bytes)?;
        let record = WireGuardOwnershipRecord {
            schema_version: SCHEMA_VERSION,
            boot_scope: self.boot_scope.clone(),
            owner_uid: self.owner_uid,
            authority_epoch: revision.authority_epoch.0,
            tunnel_generation: revision.generation,
            operation_id,
            profile_id,
            interface_name: interface_name.to_owned(),
            teardown_config_identity,
            handshake,
            probe_receipts,
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| StandardOwnershipError::Malformed)?;
        if bytes.len() as u64 > MAX_LEDGER_BYTES {
            return Err(StandardOwnershipError::Capacity);
        }
        if let Err(error) = self.atomic_write_path(&self.record_path(&profile.id), &bytes) {
            let _ = std::fs::remove_file(self.teardown_path(&profile.id));
            return Err(error);
        }
        Ok(validated(record, self.teardown_path(&profile.id)))
    }

    /// Load only when disk identity and fresh typed protocol evidence agree.
    pub fn validate_wireguard(
        &self,
        profile: &Profile,
        session: &ActiveSession,
    ) -> Result<ValidatedWireGuardOwnership, StandardOwnershipError> {
        let record = self.load(&profile.id)?;
        let teardown_path = self.teardown_path(&profile.id);
        let teardown_bytes = read_managed_config(&teardown_path, self.expected_runtime_uid)?;
        let peer_matches = session.wireguard_peers.iter().any(|peer| {
            peer.public_key == record.handshake.peer_public_key
                && peer.allowed_routes == record.handshake.allowed_routes
                && (peer.evidence_generation == 0
                    || peer.evidence_generation == record.tunnel_generation)
                && peer.evidence_observed_at >= record.handshake.observed_at
                && peer
                    .latest_handshake
                    .is_some_and(|value| value >= record.handshake.handshake_at)
        });
        if profile.protocol != ProtocolKind::WireGuard
            || record.boot_scope != self.boot_scope
            || record.owner_uid != self.owner_uid
            || record.tunnel_generation == 0
            || record.handshake.generation != record.tunnel_generation
            || record.profile_id != profile.id.as_str()
            || record.interface_name != session.interface
            || !session.interface_authoritative
            || !peer_matches
            || record.teardown_config_identity != content_identity(&teardown_bytes)
        {
            return Err(StandardOwnershipError::Stale);
        }
        Ok(validated(record, teardown_path))
    }

    /// Remove only after a fresh scan proves the exact owned interface absent.
    pub fn remove_after_confirmed_absence(
        &self,
        profile_id: &ProfileId,
        active: &[ActiveSession],
    ) -> Result<bool, StandardOwnershipError> {
        let record = match self.load(profile_id) {
            Ok(record) => record,
            Err(StandardOwnershipError::Missing) => {
                if active.is_empty() {
                    let _ = std::fs::remove_file(self.teardown_path(profile_id));
                }
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        if record.boot_scope != self.boot_scope
            || record.owner_uid != self.owner_uid
            || active
                .iter()
                .any(|session| session.interface == record.interface_name)
        {
            return Ok(false);
        }
        match std::fs::remove_file(self.record_path(profile_id)) {
            Ok(()) => {
                match std::fs::remove_file(self.teardown_path(profile_id)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                File::open(&self.root)?.sync_all()?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn ensure_root(&self) -> Result<(), StandardOwnershipError> {
        let created = match std::fs::symlink_metadata(&self.root) {
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(&self.root)?;
                true
            }
            Err(error) => return Err(error.into()),
        };
        #[cfg(unix)]
        if created {
            std::fs::set_permissions(
                &self.root,
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
            )?;
        }
        #[cfg(not(unix))]
        let _ = created;
        let metadata = std::fs::symlink_metadata(&self.root)?;
        if !metadata.is_dir() {
            return Err(StandardOwnershipError::UnsafePath);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
            if metadata.uid() != self.expected_runtime_uid
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(StandardOwnershipError::UnsafePath);
            }
        }
        Ok(())
    }

    fn load(
        &self,
        profile_id: &ProfileId,
    ) -> Result<WireGuardOwnershipRecord, StandardOwnershipError> {
        self.ensure_root()?;
        let path = self.record_path(profile_id);
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(StandardOwnershipError::Missing)
            }
            Err(error) => return Err(error.into()),
        };
        validate_owned_file(&file, self.expected_runtime_uid, MAX_LEDGER_BYTES)?;
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take(MAX_LEDGER_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_LEDGER_BYTES {
            return Err(StandardOwnershipError::Capacity);
        }
        let record: WireGuardOwnershipRecord =
            serde_json::from_slice(&bytes).map_err(|_| StandardOwnershipError::Malformed)?;
        if record.schema_version != SCHEMA_VERSION || record.profile_id != profile_id.as_str() {
            return Err(StandardOwnershipError::Stale);
        }
        Ok(record)
    }

    fn atomic_write_path(
        &self,
        final_path: &Path,
        bytes: &[u8],
    ) -> Result<(), StandardOwnershipError> {
        self.ensure_root()?;
        let leaf = final_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(StandardOwnershipError::UnsafePath)?;
        let temporary = self
            .root
            .join(format!(".{leaf}.{}.tmp", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = options.open(&temporary)?;
        let result = (|| -> Result<(), StandardOwnershipError> {
            validate_owned_file(&file, self.expected_runtime_uid, MAX_CONFIG_BYTES)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            std::fs::rename(&temporary, final_path)?;
            File::open(&self.root)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }

    fn record_path(&self, profile_id: &ProfileId) -> PathBuf {
        self.root.join(format!("{}.json", record_key(profile_id)))
    }

    fn teardown_path(&self, profile_id: &ProfileId) -> PathBuf {
        self.root.join(format!("{}.conf", record_key(profile_id)))
    }
}

fn validated(
    record: WireGuardOwnershipRecord,
    teardown_path: PathBuf,
) -> ValidatedWireGuardOwnership {
    ValidatedWireGuardOwnership {
        authority_epoch: AuthorityEpoch(record.authority_epoch),
        tunnel_generation: record.tunnel_generation,
        operation_id: record.operation_id,
        interface_name: record.interface_name,
        handshake: record.handshake,
        probe_receipts: record.probe_receipts,
        teardown_config: TunnelTeardownConfig {
            path: teardown_path,
            managed: true,
        },
    }
}

fn record_key(profile_id: &ProfileId) -> String {
    let digest = Sha256::digest(profile_id.as_str().as_bytes());
    digest
        .iter()
        .take(16)
        .fold(String::with_capacity(32), |mut key, byte| {
            let _ = write!(key, "{byte:02x}");
            key
        })
}

fn read_managed_config(path: &Path, expected_uid: u32) -> Result<Vec<u8>, StandardOwnershipError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return Err(StandardOwnershipError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != expected_uid || metadata.permissions().mode() & 0o077 != 0 {
            return Err(StandardOwnershipError::UnsafePath);
        }
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path)?;
    validate_owned_file(&file, expected_uid, MAX_CONFIG_BYTES)?;
    let mut contents = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut contents)?;
    if contents.len() as u64 > MAX_CONFIG_BYTES {
        return Err(StandardOwnershipError::Capacity);
    }
    Ok(contents)
}

fn content_identity(contents: &[u8]) -> String {
    Sha256::digest(contents)
        .iter()
        .fold(String::with_capacity(64), |mut value, byte| {
            let _ = write!(value, "{byte:02x}");
            value
        })
}

fn validate_owned_file(
    file: &File,
    expected_uid: u32,
    max_bytes: u64,
) -> Result<(), StandardOwnershipError> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(StandardOwnershipError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != expected_uid || metadata.permissions().mode() & 0o077 != 0 {
            return Err(StandardOwnershipError::UnsafePath);
        }
    }
    #[cfg(not(unix))]
    let _ = expected_uid;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::ports::tunnel::TunnelPeerStatus;
    use std::time::SystemTime;

    fn uid() -> u32 {
        crate::utils::effective_user_group_ids().0
    }

    fn profile(root: &Path, byte: char) -> Profile {
        let path = root.join(format!("{byte}.conf"));
        std::fs::write(&path, "[Interface]\nPrivateKey = redacted\n").unwrap();
        Profile::new(
            ProfileId::parse(byte.to_string().repeat(ProfileId::HEX_LEN)).unwrap(),
            byte.to_string(),
            ProtocolKind::WireGuard,
            path,
        )
    }

    fn handshake(generation: u64) -> HandshakeEvidence {
        HandshakeEvidence {
            generation,
            peer_public_key: "peer-a".into(),
            handshake_at: SystemTime::now(),
            observed_at: SystemTime::now(),
            allowed_routes: vec!["10.0.0.0/24".into()],
        }
    }

    fn teardown_config(root: &Path, byte: char) -> TunnelTeardownConfig {
        let path = root.join(format!("managed-{byte}.conf"));
        std::fs::write(&path, "[Interface]\nPrivateKey = lifecycle-copy\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        TunnelTeardownConfig {
            path,
            managed: true,
        }
    }

    fn session(profile: &Profile, evidence: &HandshakeEvidence) -> ActiveSession {
        ActiveSession {
            name: profile.display_name.clone(),
            interface: "wg0".into(),
            interface_authoritative: true,
            wireguard_peers: vec![TunnelPeerStatus {
                public_key: evidence.peer_public_key.clone(),
                endpoint: None,
                allowed_routes: evidence.allowed_routes.clone(),
                latest_handshake: Some(evidence.handshake_at),
                evidence_observed_at: SystemTime::now(),
                evidence_generation: evidence.generation,
                persistent_keepalive: None,
                bytes_rx: 0,
                bytes_tx: 0,
            }],
            ..ActiveSession::default()
        }
    }

    #[test]
    fn exact_record_validates_and_is_removed_only_after_absence() {
        let temp = tempfile::tempdir().unwrap();
        let profile = profile(temp.path(), 'a');
        let store =
            StandardTunnelOwnershipStore::new(temp.path().join("runtime"), uid(), 501, "boot-a")
                .unwrap();
        let evidence = handshake(7);
        let teardown = teardown_config(temp.path(), 'a');
        store
            .issue_wireguard(
                &profile,
                TunnelRevision {
                    authority_epoch: AuthorityEpoch(3),
                    generation: 7,
                },
                serde_json::from_str("\"op-0000000000000003-0000000000000001\"").unwrap(),
                "wg0",
                &teardown,
                evidence.clone(),
                Vec::new(),
            )
            .unwrap();
        let active = session(&profile, &evidence);
        assert_eq!(
            store
                .validate_wireguard(&profile, &active)
                .unwrap()
                .operation_id,
            serde_json::from_str("\"op-0000000000000003-0000000000000001\"").unwrap()
        );
        let mut renamed = profile.clone();
        renamed.display_name = "renamed-with-stable-id".into();
        assert_eq!(
            store
                .validate_wireguard(&renamed, &active)
                .unwrap()
                .authority_epoch,
            AuthorityEpoch(3)
        );
        assert!(!store
            .remove_after_confirmed_absence(&profile.id, std::slice::from_ref(&active))
            .unwrap());
        assert!(store
            .remove_after_confirmed_absence(&profile.id, &[])
            .unwrap());
    }

    #[test]
    fn tamper_stale_boot_wrong_profile_and_missing_ownership_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let first = profile(temp.path(), 'a');
        let second = profile(temp.path(), 'b');
        let root = temp.path().join("runtime");
        let store = StandardTunnelOwnershipStore::new(&root, uid(), 501, "boot-a").unwrap();
        let evidence = handshake(7);
        let teardown = teardown_config(temp.path(), 'a');
        store
            .issue_wireguard(
                &first,
                TunnelRevision {
                    authority_epoch: AuthorityEpoch(3),
                    generation: 7,
                },
                serde_json::from_str("\"op-0000000000000003-0000000000000001\"").unwrap(),
                "wg0",
                &teardown,
                evidence.clone(),
                Vec::new(),
            )
            .unwrap();
        let active = session(&first, &evidence);

        let other_boot = StandardTunnelOwnershipStore::new(&root, uid(), 501, "boot-b").unwrap();
        assert!(matches!(
            other_boot.validate_wireguard(&first, &active),
            Err(StandardOwnershipError::Stale)
        ));
        assert!(matches!(
            store.validate_wireguard(&second, &active),
            Err(StandardOwnershipError::Missing)
        ));

        std::fs::write(&first.config_path, "[Interface]\nPrivateKey = changed\n").unwrap();
        assert!(store.validate_wireguard(&first, &active).is_ok());

        std::fs::write(store.teardown_path(&first.id), "tampered teardown config").unwrap();
        assert!(matches!(
            store.validate_wireguard(&first, &active),
            Err(StandardOwnershipError::Stale)
        ));
        std::fs::write(
            store.teardown_path(&first.id),
            "[Interface]\nPrivateKey = lifecycle-copy\n",
        )
        .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let record = store.record_path(&first.id);
            std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(
                store.validate_wireguard(&first, &active),
                Err(StandardOwnershipError::UnsafePath)
            ));
            std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        std::fs::write(store.record_path(&first.id), b"{tampered").unwrap();
        assert!(matches!(
            store.validate_wireguard(&first, &active),
            Err(StandardOwnershipError::Malformed)
        ));
        std::fs::remove_file(store.record_path(&first.id)).unwrap();
        assert!(matches!(
            store.validate_wireguard(&first, &active),
            Err(StandardOwnershipError::Missing)
        ));
    }

    #[test]
    fn direct_root_is_a_valid_bound_owner_identity() {
        let temp = tempfile::tempdir().unwrap();
        assert!(
            StandardTunnelOwnershipStore::new(temp.path().join("runtime"), uid(), 0, "boot-a")
                .is_ok()
        );
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_directory_mode_and_symlink_record_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let temp = tempfile::tempdir().unwrap();
        let runtime = temp.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            StandardTunnelOwnershipStore::new(&runtime, uid(), 501, "boot-a"),
            Err(StandardOwnershipError::UnsafePath)
        ));

        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = StandardTunnelOwnershipStore::new(&runtime, uid(), 501, "boot-a").unwrap();
        let profile = profile(temp.path(), 'a');
        symlink(&profile.config_path, store.record_path(&profile.id)).unwrap();
        assert!(store.load(&profile.id).is_err());
    }
}
