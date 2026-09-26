//! Root-owned, boot-scoped ownership for kernel tunnels.
//!
//! This store is deliberately separate from [`super::receipt`].
//! The latter is owner-readable display evidence; this module is a private
//! root capability used only by the short-lived local canonical authority.

use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::control::scanner::ActiveSession;
use crate::profile::{Profile, ProfileId, ProtocolKind};
use crate::tunnel::AuthorityEpoch;
use crate::tunnel::OperationId;
use crate::tunnel::TunnelRevision;
use crate::tunnel::{HandshakeEvidence, ProbeReceipt, TunnelTeardownConfig};

const SCHEMA_VERSION: u8 = 1;
const MAX_LEDGER_BYTES: u64 = 128 * 1024;
const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_RUNTIME_DIR: &str = "/var/run/vortix-standard-tunnel-ownership";
/// Routes, server pins and DNS resources the last run applied.
const HOST_STATE_FILE: &str = "host-state.json";

#[derive(Debug, Error)]
pub enum OwnershipError {
    #[error("tunnel ownership has an invalid invoking owner")]
    InvalidOwner,
    #[error("OS boot identity is unavailable")]
    MissingBootIdentity,
    #[error("unsafe tunnel ownership path")]
    UnsafePath,
    #[error("tunnel ownership record is missing")]
    Missing,
    #[error("tunnel ownership record is stale or does not match current evidence")]
    Stale,
    #[error("tunnel ownership record exceeds its fixed bound")]
    Capacity,
    #[error("tunnel ownership I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("tunnel ownership record is malformed")]
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
    #[serde(default)]
    wg_quick_interface: Option<String>,
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

/// Root-owned store of which kernel tunnels Vortix started.
#[derive(Debug, Clone)]
pub struct TunnelOwnershipStore {
    root: PathBuf,
    expected_runtime_uid: u32,
    owner_uid: u32,
    boot_scope: String,
}

impl TunnelOwnershipStore {
    /// Construct the production root-owned store for the invoking sudo owner.
    pub fn production(owner_uid: u32) -> Result<Self, OwnershipError> {
        if !crate::platform::is_root() {
            return Err(OwnershipError::InvalidOwner);
        }
        let boot_scope =
            crate::platform::boot_identity().ok_or(OwnershipError::MissingBootIdentity)?;
        Self::new(DEFAULT_RUNTIME_DIR, 0, owner_uid, boot_scope)
    }

    /// Explicit constructor used by deterministic tests and local composition.
    pub fn new(
        root: impl Into<PathBuf>,
        expected_runtime_uid: u32,
        owner_uid: u32,
        boot_scope: impl Into<String>,
    ) -> Result<Self, OwnershipError> {
        let boot_scope = boot_scope.into();
        if boot_scope.is_empty() || boot_scope.len() > 128 {
            return Err(OwnershipError::InvalidOwner);
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
    ) -> Result<ValidatedWireGuardOwnership, OwnershipError> {
        if profile.protocol != ProtocolKind::WireGuard
            || revision.generation == 0
            || handshake.generation != revision.generation
            || interface_name.is_empty()
            || !teardown_config.managed
        {
            return Err(OwnershipError::Stale);
        }
        let wg_quick_interface = profile_wg_quick_interface(profile)?;
        if teardown_config.wg_quick_interface.as_deref() != Some(&wg_quick_interface)
            || teardown_config
                .path
                .file_stem()
                .and_then(|value| value.to_str())
                != Some(&wg_quick_interface)
        {
            return Err(OwnershipError::Stale);
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
            wg_quick_interface: Some(wg_quick_interface.clone()),
            teardown_config_identity,
            handshake,
            probe_receipts,
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| OwnershipError::Malformed)?;
        if bytes.len() as u64 > MAX_LEDGER_BYTES {
            return Err(OwnershipError::Capacity);
        }
        if let Err(error) = self.atomic_write_path(&self.record_path(&profile.id), &bytes) {
            let _ = std::fs::remove_file(self.teardown_path(&profile.id));
            return Err(error);
        }
        Ok(validated(
            record,
            self.teardown_path(&profile.id),
            wg_quick_interface,
        ))
    }

    /// Load only when disk identity and fresh typed protocol evidence agree.
    pub fn validate_wireguard(
        &self,
        profile: &Profile,
        session: &ActiveSession,
    ) -> Result<ValidatedWireGuardOwnership, OwnershipError> {
        let record = self.load(&profile.id)?;
        let wg_quick_interface = profile_wg_quick_interface(profile)?;
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
            || record
                .wg_quick_interface
                .as_deref()
                .is_some_and(|recorded| recorded != wg_quick_interface)
            || record.interface_name != session.details.interface
            || !session.details.interface_authoritative
            || !peer_matches
            || record.teardown_config_identity != content_identity(&teardown_bytes)
        {
            return Err(OwnershipError::Stale);
        }
        Ok(validated(record, teardown_path, wg_quick_interface))
    }

    /// Remove only after a fresh scan proves the exact owned interface absent.
    pub fn remove_after_confirmed_absence(
        &self,
        profile_id: &ProfileId,
        active: &[ActiveSession],
    ) -> Result<bool, OwnershipError> {
        let record = match self.load(profile_id) {
            Ok(record) => record,
            Err(OwnershipError::Missing) => {
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
                .any(|session| session.details.interface == record.interface_name)
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

    fn ensure_root(&self) -> Result<(), OwnershipError> {
        let created = match std::fs::symlink_metadata(&self.root) {
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(&self.root)?;
                true
            }
            Err(error) => return Err(error.into()),
        };
        if created {
            std::fs::set_permissions(
                &self.root,
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
            )?;
        }
        let metadata = std::fs::symlink_metadata(&self.root)?;
        if !metadata.is_dir() {
            return Err(OwnershipError::UnsafePath);
        }
        {
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
            if metadata.uid() != self.expected_runtime_uid
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(OwnershipError::UnsafePath);
            }
        }
        Ok(())
    }

    /// Record what the host carries, root-owned and cleared by a reboot.
    pub fn save_host_state(&self, bytes: &[u8]) -> Result<(), OwnershipError> {
        self.atomic_write_path(&self.root.join(HOST_STATE_FILE), bytes)
    }

    /// What the last run recorded, if the record is present and root-owned.
    #[must_use]
    pub fn load_host_state(&self) -> Option<Vec<u8>> {
        self.ensure_root().ok()?;
        self.read_private(&self.root.join(HOST_STATE_FILE)).ok()
    }

    fn load(&self, profile_id: &ProfileId) -> Result<WireGuardOwnershipRecord, OwnershipError> {
        self.ensure_root()?;
        let bytes = self.read_private(&self.record_path(profile_id))?;
        let record: WireGuardOwnershipRecord =
            serde_json::from_slice(&bytes).map_err(|_| OwnershipError::Malformed)?;
        if record.schema_version != SCHEMA_VERSION || record.profile_id != profile_id.as_str() {
            return Err(OwnershipError::Stale);
        }
        Ok(record)
    }

    fn read_private(&self, path: &Path) -> Result<Vec<u8>, OwnershipError> {
        let mut options = OpenOptions::new();
        options.read(true);
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(OwnershipError::Missing)
            }
            Err(error) => return Err(error.into()),
        };
        validate_owned_file(&file, self.expected_runtime_uid, MAX_LEDGER_BYTES)?;
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take(MAX_LEDGER_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_LEDGER_BYTES {
            return Err(OwnershipError::Capacity);
        }
        Ok(bytes)
    }

    fn atomic_write_path(&self, final_path: &Path, bytes: &[u8]) -> Result<(), OwnershipError> {
        use crate::config::owned_file::{open_owned_directory, write_owned_atomic};
        self.ensure_root()?;
        let leaf = final_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(OwnershipError::UnsafePath)?;
        let (uid, gid) = (
            self.expected_runtime_uid,
            crate::platform::effective_user_group_ids().1,
        );
        let directory = open_owned_directory(&self.root, false, uid, gid)
            .map_err(|_| OwnershipError::UnsafePath)?
            .ok_or(OwnershipError::UnsafePath)?;
        write_owned_atomic(&directory, leaf, bytes, uid, gid).map_err(std::io::Error::other)?;
        Ok(())
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
    wg_quick_interface: String,
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
            wg_quick_interface: Some(wg_quick_interface),
        },
    }
}

fn profile_wg_quick_interface(profile: &Profile) -> Result<String, OwnershipError> {
    let interface = profile
        .config_path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or(OwnershipError::Stale)?;
    crate::profile::validate_wireguard_interface_name(interface)
        .map_err(|_| OwnershipError::Stale)?;
    Ok(interface.to_owned())
}

fn record_key(profile_id: &ProfileId) -> String {
    profile_id.digest_key(16)
}

fn read_managed_config(path: &Path, expected_uid: u32) -> Result<Vec<u8>, OwnershipError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return Err(OwnershipError::UnsafePath);
    }
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != expected_uid || metadata.permissions().mode() & 0o077 != 0 {
            return Err(OwnershipError::UnsafePath);
        }
    }
    let mut options = OpenOptions::new();
    options.read(true);
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
        return Err(OwnershipError::Capacity);
    }
    Ok(contents)
}

fn content_identity(contents: &[u8]) -> String {
    crate::profile::hex(&Sha256::digest(contents))
}

fn validate_owned_file(
    file: &File,
    expected_uid: u32,
    max_bytes: u64,
) -> Result<(), OwnershipError> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(OwnershipError::UnsafePath);
    }
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != expected_uid || metadata.permissions().mode() & 0o077 != 0 {
            return Err(OwnershipError::UnsafePath);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::TunnelPeerStatus;
    use std::time::SystemTime;

    fn uid() -> u32 {
        crate::platform::effective_user_group_ids().0
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
        // Production lifecycle copies preserve the reviewed profile basename
        // because that basename is `wg-quick`'s stable interface identity.
        let path = root.join(format!("{byte}.conf"));
        std::fs::write(&path, "[Interface]\nPrivateKey = lifecycle-copy\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        TunnelTeardownConfig {
            path,
            managed: true,
            wg_quick_interface: Some(byte.to_string()),
        }
    }

    fn session(profile: &Profile, evidence: &HandshakeEvidence) -> ActiveSession {
        ActiveSession {
            name: profile.display_name.clone(),
            details: crate::tunnel::DetailedConnectionInfo {
                interface: "wg0".into(),
                ..Default::default()
            },
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

    /// The record copies the handshake's routes and each probe's; at the
    /// profile's route limit it must still fit, or the connect fails.
    #[test]
    fn a_record_at_the_route_limit_fits() {
        let temp = tempfile::tempdir().unwrap();
        let profile = profile(temp.path(), 'a');
        let store =
            TunnelOwnershipStore::new(temp.path().join("runtime"), uid(), 501, "boot-a").unwrap();
        let routes = crate::cidr::test_routes(crate::wireguard::parser::MAX_ROUTES, true);
        let mut evidence = handshake(7);
        evidence.allowed_routes.clone_from(&routes);
        let probe = ProbeReceipt {
            peer_public_key: evidence.peer_public_key.clone(),
            target: "1.1.1.1".parse().unwrap(),
            allowed_routes: routes,
            issued_at: SystemTime::now(),
        };
        store
            .issue_wireguard(
                &profile,
                TunnelRevision {
                    authority_epoch: AuthorityEpoch(3),
                    generation: 7,
                },
                serde_json::from_str("\"op-0000000000000003-0000000000000001\"").unwrap(),
                "wg0",
                &teardown_config(temp.path(), 'a'),
                evidence,
                vec![probe],
            )
            .unwrap();
    }

    #[test]
    fn exact_record_validates_and_is_removed_only_after_absence() {
        let temp = tempfile::tempdir().unwrap();
        let profile = profile(temp.path(), 'a');
        let store =
            TunnelOwnershipStore::new(temp.path().join("runtime"), uid(), 501, "boot-a").unwrap();
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
    fn host_state_round_trips_in_the_private_root() {
        let temp = tempfile::tempdir().unwrap();
        let store =
            TunnelOwnershipStore::new(temp.path().join("runtime"), uid(), 501, "boot-a").unwrap();
        assert!(store.load_host_state().is_none());
        store.save_host_state(b"{\"routes\":[]}").unwrap();
        assert_eq!(store.load_host_state().unwrap(), b"{\"routes\":[]}");
    }

    #[test]
    fn legacy_record_without_alias_recovers_from_the_stable_profile_filename() {
        let temp = tempfile::tempdir().unwrap();
        let profile = profile(temp.path(), 'a');
        let store =
            TunnelOwnershipStore::new(temp.path().join("runtime"), uid(), 501, "boot-a").unwrap();
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
                "utun4",
                &teardown,
                evidence.clone(),
                Vec::new(),
            )
            .unwrap();
        let record_path = store.record_path(&profile.id);
        let mut record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
        record.as_object_mut().unwrap().remove("wg_quick_interface");
        std::fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
        let mut active = session(&profile, &evidence);
        active.details.interface = "utun4".into();

        let recovered = store.validate_wireguard(&profile, &active).unwrap();
        assert_eq!(
            recovered.teardown_config.wg_quick_interface.as_deref(),
            Some("a")
        );
    }

    #[test]
    fn tamper_stale_boot_wrong_profile_and_missing_ownership_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let first = profile(temp.path(), 'a');
        let second = profile(temp.path(), 'b');
        let root = temp.path().join("runtime");
        let store = TunnelOwnershipStore::new(&root, uid(), 501, "boot-a").unwrap();
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

        let other_boot = TunnelOwnershipStore::new(&root, uid(), 501, "boot-b").unwrap();
        assert!(matches!(
            other_boot.validate_wireguard(&first, &active),
            Err(OwnershipError::Stale)
        ));
        assert!(matches!(
            store.validate_wireguard(&second, &active),
            Err(OwnershipError::Missing)
        ));

        std::fs::write(&first.config_path, "[Interface]\nPrivateKey = changed\n").unwrap();
        assert!(store.validate_wireguard(&first, &active).is_ok());

        std::fs::write(store.teardown_path(&first.id), "tampered teardown config").unwrap();
        assert!(matches!(
            store.validate_wireguard(&first, &active),
            Err(OwnershipError::Stale)
        ));
        std::fs::write(
            store.teardown_path(&first.id),
            "[Interface]\nPrivateKey = lifecycle-copy\n",
        )
        .unwrap();

        {
            use std::os::unix::fs::PermissionsExt as _;
            let record = store.record_path(&first.id);
            std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(
                store.validate_wireguard(&first, &active),
                Err(OwnershipError::UnsafePath)
            ));
            std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        std::fs::write(store.record_path(&first.id), b"{tampered").unwrap();
        assert!(matches!(
            store.validate_wireguard(&first, &active),
            Err(OwnershipError::Malformed)
        ));
        std::fs::remove_file(store.record_path(&first.id)).unwrap();
        assert!(matches!(
            store.validate_wireguard(&first, &active),
            Err(OwnershipError::Missing)
        ));
    }

    #[test]
    fn direct_root_is_a_valid_bound_owner_identity() {
        let temp = tempfile::tempdir().unwrap();
        assert!(TunnelOwnershipStore::new(temp.path().join("runtime"), uid(), 0, "boot-a").is_ok());
    }

    #[test]
    fn unsafe_directory_mode_and_symlink_record_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let temp = tempfile::tempdir().unwrap();
        let runtime = temp.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            TunnelOwnershipStore::new(&runtime, uid(), 501, "boot-a"),
            Err(OwnershipError::UnsafePath)
        ));

        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = TunnelOwnershipStore::new(&runtime, uid(), 501, "boot-a").unwrap();
        let profile = profile(temp.path(), 'a');
        symlink(&profile.config_path, store.record_path(&profile.id)).unwrap();
        assert!(store.load(&profile.id).is_err());
    }
}
