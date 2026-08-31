//! Owner-readable receipts for successful Standard-mode `WireGuard` connects.
//!
//! A receipt is display/adoption evidence only. It is deliberately never
//! accepted as authority to remove an interface, change routes, or mutate
//! policy. Lifecycle cleanup still requires protocol ownership plus a fresh
//! kernel absence observation.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::core::scanner::ActiveSession;
use crate::vortix_core::engine::state::ConnectionHealth;
use crate::vortix_core::ports::tunnel::{HandshakeEvidence, ProbeReceipt};
use crate::vortix_core::profile::ProfileId;

const DIRECTORY: &str = "managed-wireguard";
const LOCK_FILE: &str = "managed-wireguard.lock";
const SCHEMA_VERSION: u8 = 1;
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
const MAX_TRACKED_RECEIPTS: usize = 512;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// A successful, generation-bound `WireGuard` connect issued by Vortix.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManagedWireGuardReceipt {
    schema_version: u8,
    profile_id: String,
    pub generation: u64,
    pub interface_name: String,
    pub handshake: HandshakeEvidence,
    pub probe_receipts: Vec<ProbeReceipt>,
    pub connected_at: SystemTime,
    #[serde(default)]
    pub last_health: ConnectionHealth,
}

impl ManagedWireGuardReceipt {
    /// Whether this receipt still matches a fresh protocol observation.
    /// Scanner presence alone is insufficient: stable profile identity,
    /// interface identity, peer identity, and non-regressing handshake proof
    /// must all agree.
    #[must_use]
    pub fn validates(&self, profile_id: &ProfileId, session: &ActiveSession) -> bool {
        self.schema_version == SCHEMA_VERSION
            && self.profile_id == profile_id.as_str()
            && self.generation > 0
            && self.handshake.generation == self.generation
            && !self.interface_name.is_empty()
            && self.interface_name == session.interface
            && session.wireguard_peers.iter().any(|peer| {
                peer.public_key == self.handshake.peer_public_key
                    && peer.allowed_routes == self.handshake.allowed_routes
                    && peer
                        .latest_handshake
                        .is_some_and(|at| at >= self.handshake.handshake_at)
            })
    }
}

/// Persist a successful current-generation connect before publishing it as
/// Connected. This file carries no teardown or privileged-policy capability.
pub fn issue(
    config_dir: &Path,
    profile_id: &ProfileId,
    interface_name: String,
    generation: u64,
    handshake: HandshakeEvidence,
    probe_receipts: Vec<ProbeReceipt>,
) -> std::io::Result<ManagedWireGuardReceipt> {
    if generation == 0 || handshake.generation != generation {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "WireGuard receipt requires exact non-zero generation evidence",
        ));
    }
    let receipt = ManagedWireGuardReceipt {
        schema_version: SCHEMA_VERSION,
        profile_id: profile_id.as_str().to_owned(),
        generation,
        interface_name,
        handshake,
        probe_receipts,
        connected_at: SystemTime::now(),
        // Ongoing expectation is evaluated from the next typed peer snapshot;
        // initial handshake success alone must not claim aggregate health.
        last_health: ConnectionHealth::Unknown,
    };
    let _lock = acquire_lock(config_dir)?;
    save(config_dir, &receipt)?;
    Ok(receipt)
}

/// Load an owner-readable receipt. Corrupt, oversized, mismatched, or unknown
/// schema content is treated as absent and can never grant lifecycle authority.
#[must_use]
pub fn load(config_dir: &Path, profile_id: &ProfileId) -> Option<ManagedWireGuardReceipt> {
    let path = receipt_path(config_dir, profile_id);
    let receipt = load_receipt_path(&path)?;
    (receipt.profile_id == profile_id.as_str()).then_some(receipt)
}

/// PIDs backed by a bounded managed receipt and a currently live interface.
///
/// This is advisory startup classification only. It does not grant teardown
/// authority; lifecycle recovery still validates the root-owned ownership
/// record and fresh protocol evidence before adopting or mutating a tunnel.
#[must_use]
pub fn tracked_wireguard_pids(config_dir: &Path) -> Vec<u32> {
    tracked_wireguard_pids_with(config_dir, |interface| {
        crate::platform::current_platform()
            .interface
            .get_wireguard_pid(interface)
    })
}

fn tracked_wireguard_pids_with(
    config_dir: &Path,
    resolve_pid: impl Fn(&str) -> Option<u32>,
) -> Vec<u32> {
    let directory = config_dir.join(DIRECTORY);
    let Ok(metadata) = std::fs::symlink_metadata(&directory) else {
        return Vec::new();
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(&directory) else {
        return Vec::new();
    };
    let entries = entries
        .filter_map(std::result::Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|value| value == "json")
        })
        .take(MAX_TRACKED_RECEIPTS + 1)
        .collect::<Vec<_>>();
    if entries.len() > MAX_TRACKED_RECEIPTS {
        return Vec::new();
    }

    entries
        .into_iter()
        .filter_map(|entry| {
            let path = entry.path();
            let receipt = load_receipt_path(&path)?;
            let profile_id = ProfileId::new(&receipt.profile_id);
            (receipt_path(config_dir, &profile_id).file_name() == path.file_name())
                .then_some(receipt)
        })
        .filter_map(|receipt| resolve_pid(&receipt.interface_name))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn load_receipt_path(path: &Path) -> Option<ManagedWireGuardReceipt> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_RECEIPT_BYTES
    {
        return None;
    }
    let file = File::open(path).ok()?;
    if file.metadata().ok()?.len() > MAX_RECEIPT_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return None;
    }
    let receipt: ManagedWireGuardReceipt = serde_json::from_slice(&bytes).ok()?;
    (receipt.schema_version == SCHEMA_VERSION
        && !receipt.profile_id.is_empty()
        && receipt.generation > 0
        && receipt.handshake.generation == receipt.generation)
        .then_some(receipt)
}

/// Persist a typed ongoing-health transition for cross-process status and
/// journal parity. Returns the prior value when it changed.
pub fn update_health(
    config_dir: &Path,
    receipt: &mut ManagedWireGuardReceipt,
    health: ConnectionHealth,
) -> std::io::Result<Option<ConnectionHealth>> {
    let _lock = acquire_lock(config_dir)?;
    let Some(mut current) = load(config_dir, &ProfileId::new(&receipt.profile_id)) else {
        return Ok(None);
    };
    if current.generation != receipt.generation || current.handshake != receipt.handshake {
        return Ok(None);
    }
    if current.last_health == health {
        return Ok(None);
    }
    let prior = std::mem::replace(&mut current.last_health, health);
    save(config_dir, &current)?;
    *receipt = current;
    Ok(Some(prior))
}

/// Remove a display receipt only after a scanner pass proves this profile's
/// interface absent. The receipt itself is never sufficient to tear down it.
pub fn remove_after_absence(
    config_dir: &Path,
    profile_id: &ProfileId,
    active: &[ActiveSession],
) -> std::io::Result<bool> {
    let _lock = acquire_lock(config_dir)?;
    let Some(receipt) = load(config_dir, profile_id) else {
        return Ok(false);
    };
    if active
        .iter()
        .any(|session| receipt.interface_name == session.interface)
    {
        return Ok(false);
    }
    let path = receipt_path(config_dir, profile_id);
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Remove after the caller has already established exact profile absence.
pub fn remove_after_confirmed_absence(
    config_dir: &Path,
    profile_id: &ProfileId,
) -> std::io::Result<bool> {
    let _lock = acquire_lock(config_dir)?;
    let path = receipt_path(config_dir, profile_id);
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Remove only when the platform's non-mutating interface resolver confirms
/// that the profile no longer maps to a kernel `WireGuard` interface.
pub fn remove_after_kernel_absence(
    config_dir: &Path,
    profile_id: &ProfileId,
    profile_name: &str,
) -> std::io::Result<bool> {
    if crate::platform::current_platform()
        .interface
        .resolve_wireguard_interface(profile_name)
        .is_some()
    {
        return Ok(false);
    }
    remove_after_confirmed_absence(config_dir, profile_id)
}

fn save(config_dir: &Path, receipt: &ManagedWireGuardReceipt) -> std::io::Result<()> {
    let directory = config_dir.join(DIRECTORY);
    if std::fs::symlink_metadata(&directory).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "managed WireGuard state directory must not be a symlink",
        ));
    }
    crate::utils::create_user_dir(&directory)?;
    let path = receipt_path(config_dir, &ProfileId::new(&receipt.profile_id));
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = directory.join(format!(".receipt-{}-{sequence}.tmp", std::process::id()));
    let bytes = serde_json::to_vec(receipt).map_err(std::io::Error::other)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    let result = (|| {
        file.write_all(&bytes)?;
        file.sync_all()?;
        chown_open_file_to_real_user(&file)?;
        std::fs::rename(&temp, &path)?;
        sync_directory(&directory)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> std::io::Result<()> {
    File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> std::io::Result<()> {
    Ok(())
}

fn acquire_lock(config_dir: &Path) -> std::io::Result<File> {
    crate::utils::create_user_dir(config_dir)?;
    let path = config_dir.join(LOCK_FILE);
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    chown_open_file_to_real_user(&file)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        // SAFETY: `file` owns a valid descriptor for the duration of the lock.
        #[allow(unsafe_code)]
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(file)
}

#[cfg(unix)]
fn chown_open_file_to_real_user(file: &File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    if !crate::utils::is_root() {
        return Ok(());
    }
    let (Ok(uid), Ok(gid)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) else {
        return Ok(());
    };
    let uid = uid
        .parse::<libc::uid_t>()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let gid = gid
        .parse::<libc::gid_t>()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    // SAFETY: `file` owns a valid descriptor and uid/gid are parsed values.
    #[allow(unsafe_code)]
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn chown_open_file_to_real_user(_file: &File) -> std::io::Result<()> {
    Ok(())
}

fn receipt_path(config_dir: &Path, profile_id: &ProfileId) -> PathBuf {
    let digest = Sha256::digest(profile_id.as_str().as_bytes());
    let key = digest
        .iter()
        .take(16)
        .fold(String::with_capacity(32), |mut key, byte| {
            let _ = write!(key, "{byte:02x}");
            key
        });
    config_dir.join(DIRECTORY).join(format!("{key}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::ports::tunnel::TunnelPeerStatus;
    use std::time::Duration;

    fn evidence(generation: u64, at: SystemTime) -> HandshakeEvidence {
        HandshakeEvidence {
            generation,
            peer_public_key: "peer-a".into(),
            handshake_at: at,
            observed_at: at,
            allowed_routes: vec!["0.0.0.0/0".into()],
        }
    }

    #[test]
    fn receipt_requires_matching_profile_interface_peer_and_non_regressing_handshake() {
        let dir = tempfile::tempdir().unwrap();
        let profile = ProfileId::new("stable-profile");
        let at = SystemTime::now() - Duration::from_secs(10);
        issue(
            dir.path(),
            &profile,
            "wg0".into(),
            7,
            evidence(7, at),
            vec![ProbeReceipt {
                peer_public_key: "peer-a".into(),
                target: "1.1.1.1".parse().unwrap(),
                allowed_routes: vec!["0.0.0.0/0".into()],
                issued_at: at,
            }],
        )
        .unwrap();
        let receipt = load(dir.path(), &profile).unwrap();
        let session = ActiveSession {
            name: "corp".into(),
            interface: "wg0".into(),
            wireguard_peers: vec![TunnelPeerStatus {
                public_key: "peer-a".into(),
                endpoint: None,
                allowed_routes: vec!["0.0.0.0/0".into()],
                latest_handshake: Some(at + Duration::from_secs(1)),
                evidence_observed_at: SystemTime::now(),
                evidence_generation: 0,
                persistent_keepalive: None,
                bytes_rx: 0,
                bytes_tx: 0,
            }],
            ..ActiveSession::default()
        };
        assert!(receipt.validates(&profile, &session));
        assert!(!receipt.validates(&ProfileId::new("other"), &session));
        let mut wrong_interface = session.clone();
        wrong_interface.interface = "wg1".into();
        assert!(!receipt.validates(&profile, &wrong_interface));
    }

    #[test]
    fn removal_requires_confirmed_absence() {
        let dir = tempfile::tempdir().unwrap();
        let profile = ProfileId::new("stable-profile");
        let at = SystemTime::now();
        issue(
            dir.path(),
            &profile,
            "wg0".into(),
            1,
            evidence(1, at),
            Vec::new(),
        )
        .unwrap();
        let present = ActiveSession {
            interface: "wg0".into(),
            ..ActiveSession::default()
        };
        assert!(!remove_after_absence(dir.path(), &profile, &[present]).unwrap());
        assert!(load(dir.path(), &profile).is_some());
        assert!(remove_after_absence(dir.path(), &profile, &[]).unwrap());
        assert!(load(dir.path(), &profile).is_none());
    }

    #[test]
    fn tracked_pids_include_only_live_interfaces_from_valid_managed_receipts() {
        let dir = tempfile::tempdir().unwrap();
        let profile = ProfileId::new("stable-profile");
        let at = SystemTime::now();
        issue(
            dir.path(),
            &profile,
            "utun4".into(),
            1,
            evidence(1, at),
            Vec::new(),
        )
        .unwrap();

        let resolved = std::cell::RefCell::new(Vec::new());
        let tracked = tracked_wireguard_pids_with(dir.path(), |interface| {
            resolved.borrow_mut().push(interface.to_owned());
            (interface == "utun4").then_some(4242)
        });
        assert_eq!(tracked, vec![4242]);
        assert_eq!(*resolved.borrow(), vec!["utun4"]);

        std::fs::write(
            dir.path()
                .join(DIRECTORY)
                .join("not-a-managed-receipt.json"),
            br#"{"interface_name":"utun9"}"#,
        )
        .unwrap();
        resolved.borrow_mut().clear();
        let tracked = tracked_wireguard_pids_with(dir.path(), |interface| {
            resolved.borrow_mut().push(interface.to_owned());
            Some(9999)
        });
        assert_eq!(tracked, vec![9999]);
        assert_eq!(*resolved.borrow(), vec!["utun4"]);
    }
}
