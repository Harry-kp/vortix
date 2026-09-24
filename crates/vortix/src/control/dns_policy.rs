//! Crash-safe local persistence for DNS desired/effective generations.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::owned_file;
use crate::control::dns::DnsPolicyCoordinator;

const DNS_POLICY_STATE_FILE: &str = "dns-policy.state";
const DNS_POLICY_LOCK_FILE: &str = "dns-policy.lock";
const DNS_POLICY_SCHEMA: u8 = 2;

/// Serialize all DNS policy writers across CLI and TUI processes. This lock
/// is intentionally distinct from the lifecycle lock so a CLI command that
/// already owns lifecycle authority cannot self-deadlock.
pub fn acquire_policy_lock(config_dir: &Path) -> std::io::Result<std::fs::File> {
    acquire_policy_lock_with_hook(config_dir, || {})
}

fn acquire_policy_lock_with_hook(
    config_dir: &Path,
    after_pin: impl FnOnce(),
) -> std::io::Result<std::fs::File> {
    use std::os::fd::AsRawFd as _;

    let (directory, uid, gid) = owned_file::pin_user_dir(config_dir)?;
    after_pin();
    let file = owned_file::open_owned_lock(&directory, DNS_POLICY_LOCK_FILE, uid, gid)
        .map_err(std::io::Error::other)?;
    #[allow(unsafe_code)]
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc == 0 {
        Ok(file)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[derive(Serialize, Deserialize)]
struct PersistedDnsPolicy {
    schema: u8,
    coordinator: DnsPolicyCoordinator,
}

#[must_use]
pub fn load(config_dir: &Path) -> Option<DnsPolicyCoordinator> {
    let content = std::fs::read_to_string(config_dir.join(DNS_POLICY_STATE_FILE)).ok()?;
    let persisted: PersistedDnsPolicy = serde_json::from_str(&content).ok()?;
    if persisted.schema != DNS_POLICY_SCHEMA {
        return None;
    }
    let mut coordinator = persisted.coordinator;
    coordinator.discard_persisted_authority();
    Some(coordinator)
}

pub fn save(config_dir: &Path, coordinator: &DnsPolicyCoordinator) -> std::io::Result<()> {
    let state = PersistedDnsPolicy {
        schema: DNS_POLICY_SCHEMA,
        coordinator: coordinator.clone(),
    };
    let content = serde_json::to_vec_pretty(&state).map_err(std::io::Error::other)?;
    atomic_write_user_file_with_hook(config_dir, &content, || {})
}

fn atomic_write_user_file_with_hook(
    config_dir: &Path,
    content: &[u8],
    after_pin: impl FnOnce(),
) -> std::io::Result<()> {
    let (directory, uid, gid) = owned_file::pin_user_dir(config_dir)?;
    after_pin();
    owned_file::write_owned_atomic(&directory, DNS_POLICY_STATE_FILE, content, uid, gid)
        .map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn policy_lock_serializes_writers() {
        let temp = tempfile::tempdir().unwrap();
        let first = acquire_policy_lock(temp.path()).unwrap();
        let path = temp.path().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let second = acquire_policy_lock(&path).unwrap();
            tx.send(()).unwrap();
            drop(second);
        });

        std::thread::sleep(Duration::from_millis(30));
        assert!(
            rx.try_recv().is_err(),
            "second writer bypassed DNS policy lock"
        );
        drop(first);
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
        waiter.join().unwrap();
    }

    #[test]
    fn policy_lock_never_follows_a_precreated_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let victim = temp.path().join("victim");
        std::fs::write(&victim, b"unchanged").unwrap();
        symlink(&victim, temp.path().join("dns-policy.lock")).unwrap();

        assert!(acquire_policy_lock(temp.path()).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"unchanged");
    }

    #[test]
    fn symlinked_config_directory_is_rejected_for_save_and_lock() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let victim = temp.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::write(victim.join("sentinel"), b"unchanged").unwrap();
        let config = temp.path().join("config");
        symlink(&victim, &config).unwrap();

        assert!(save(&config, &DnsPolicyCoordinator::default()).is_err());
        assert!(acquire_policy_lock(&config).is_err());
        assert_eq!(
            std::fs::read(victim.join("sentinel")).unwrap(),
            b"unchanged"
        );
        assert!(!victim.join(DNS_POLICY_STATE_FILE).exists());
        assert!(!victim.join("dns-policy.lock").exists());
    }

    #[test]
    fn pinned_directory_survives_path_swap_without_touching_victim() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("config");
        let pinned = temp.path().join("pinned");
        let victim = temp.path().join("victim");
        std::fs::create_dir(&config).unwrap();
        std::fs::create_dir(&victim).unwrap();

        atomic_write_user_file_with_hook(&config, b"pinned state", || {
            std::fs::rename(&config, &pinned).unwrap();
            symlink(&victim, &config).unwrap();
        })
        .unwrap();

        assert_eq!(
            std::fs::read(pinned.join(DNS_POLICY_STATE_FILE)).unwrap(),
            b"pinned state"
        );
        assert!(!victim.join(DNS_POLICY_STATE_FILE).exists());
    }

    #[test]
    fn policy_lock_uses_pinned_directory_after_path_swap() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("config");
        let pinned = temp.path().join("pinned");
        let victim = temp.path().join("victim");
        std::fs::create_dir(&config).unwrap();
        std::fs::create_dir(&victim).unwrap();

        let lock = acquire_policy_lock_with_hook(&config, || {
            std::fs::rename(&config, &pinned).unwrap();
            symlink(&victim, &config).unwrap();
        })
        .unwrap();

        assert!(pinned.join("dns-policy.lock").exists());
        assert!(!victim.join("dns-policy.lock").exists());
        drop(lock);
    }
    #[test]
    fn round_trip_is_atomic_and_owner_readable() {
        let temp = tempfile::tempdir().unwrap();
        let coordinator = DnsPolicyCoordinator::default();
        save(temp.path(), &coordinator).unwrap();
        let loaded = load(temp.path()).unwrap();
        assert_eq!(
            loaded.effective().status,
            crate::control::dns::DnsEffectiveStatus::Degraded
        );
        assert!(std::fs::read_dir(temp.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));
    }

    #[test]
    fn attacker_symlink_at_legacy_temp_name_is_never_followed() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let victim = temp.path().join("victim");
        std::fs::write(&victim, b"do not overwrite").unwrap();
        let trap = temp.path().join("dns-policy.state.tmp");
        symlink(&victim, &trap).unwrap();

        save(temp.path(), &DnsPolicyCoordinator::default()).unwrap();

        assert_eq!(std::fs::read(&victim).unwrap(), b"do not overwrite");
        assert_eq!(std::fs::read_link(&trap).unwrap(), victim);
    }

    #[test]
    fn user_owned_state_cannot_restore_privileged_ownership_authority() {
        let temp = tempfile::tempdir().unwrap();
        save(temp.path(), &DnsPolicyCoordinator::default()).unwrap();
        let path = temp.path().join(DNS_POLICY_STATE_FILE);
        let mut state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let attacker_profile = crate::profile::ProfileId::parse("a".repeat(64)).unwrap();
        state["coordinator"]["effective"]["applied_generation"] = serde_json::json!(7);
        state["coordinator"]["effective"]["status"] = serde_json::json!("Applied");
        state["coordinator"]["effective"]["owned"] = serde_json::json!([{
            "generation": 7,
            "id": "resolved:eth0",
            "profile_id": attacker_profile,
            "interface": "eth0"
        }]);
        std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();

        let loaded = load(temp.path()).unwrap();
        assert_eq!(loaded.effective().applied_generation, None);
        assert!(loaded.effective().owned.is_empty());
        assert_eq!(
            loaded.effective().status,
            crate::control::dns::DnsEffectiveStatus::Degraded
        );
    }
}
