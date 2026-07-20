//! Crash-safe local persistence for DNS desired/effective generations.

#[cfg(unix)]
use std::io::Write as _;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::vortix_core::ports::dns::DnsPolicyCoordinator;

const DNS_POLICY_STATE_FILE: &str = "dns-policy.state";
const DNS_POLICY_SCHEMA: u8 = 2;
#[cfg(unix)]
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Complete input for one global DNS policy reconciliation.
#[derive(Clone)]
pub struct DnsPolicyWork {
    pub revision: u64,
    pub intents: Vec<crate::vortix_core::ports::dns::DnsTunnelIntent>,
    pub external_sessions: usize,
    pub config_dir: PathBuf,
    pub persist: bool,
}

/// One-slot, latest-wins DNS policy worker. The UI only replaces the pending
/// value and nudges the worker; all subprocesses, lock waits, persistence and
/// retry delays remain off the event thread.
pub struct DnsPolicyWorker {
    latest: Arc<Mutex<Option<DnsPolicyWork>>>,
    nudge: mpsc::SyncSender<()>,
}

impl DnsPolicyWorker {
    /// Spawn the single long-lived DNS policy worker.
    ///
    /// # Panics
    ///
    /// Panics if the operating system refuses to create the worker thread.
    #[must_use]
    pub fn spawn(
        mut coordinator: DnsPolicyCoordinator,
        completion: mpsc::Sender<crate::message::Message>,
    ) -> Self {
        let latest = Arc::new(Mutex::new(None::<DnsPolicyWork>));
        let worker_latest = Arc::clone(&latest);
        let (nudge, wake) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("vortix-dns-policy".into())
            .spawn(move || {
                let mut retry: Option<DnsPolicyWork> = None;
                let mut backoff = Duration::from_secs(1);
                loop {
                    let wake_result = if retry.is_some() {
                        wake.recv_timeout(backoff)
                    } else {
                        wake.recv()
                            .map_err(|_| mpsc::RecvTimeoutError::Disconnected)
                    };
                    if matches!(wake_result, Err(mpsc::RecvTimeoutError::Disconnected)) {
                        break;
                    }
                    let pending = worker_latest.lock().ok().and_then(|mut slot| slot.take());
                    let Some(mut work) = pending.or_else(|| retry.take()) else {
                        continue;
                    };

                    let error = match acquire_policy_lock(&work.config_dir) {
                        Ok(_lock) => {
                            // Lock contention is another coalescing window.
                            // Replace a now-stale job before any platform
                            // mutation rather than applying every generation.
                            if let Some(newer) =
                                worker_latest.lock().ok().and_then(|mut slot| slot.take())
                            {
                                work = newer;
                            }
                            reconcile_under_lock(&mut coordinator, &work).err()
                        }
                        Err(error) => {
                            coordinator
                                .invalidate_effective(format!("DNS policy lock failed: {error}"));
                            Some(format!("Could not acquire DNS policy lock: {error}"))
                        }
                    };
                    let degraded = coordinator.effective().status
                        == crate::vortix_core::ports::dns::DnsEffectiveStatus::Degraded;
                    if completion
                        .send(crate::message::Message::DnsPolicyResult {
                            revision: work.revision,
                            coordinator: coordinator.clone(),
                            external_sessions: work.external_sessions,
                            error,
                        })
                        .is_err()
                    {
                        break;
                    }
                    if degraded {
                        retry = Some(work);
                        backoff = backoff.saturating_mul(2).min(Duration::from_secs(30));
                    } else {
                        retry = None;
                        backoff = Duration::from_secs(1);
                    }
                }
            })
            .expect("spawn DNS policy worker");
        Self { latest, nudge }
    }

    /// Replace any queued request. At most one work item and one wake token
    /// exist regardless of scanner frequency.
    pub fn schedule(&self, work: DnsPolicyWork) -> Result<(), String> {
        *self
            .latest
            .lock()
            .map_err(|_| "DNS policy queue is poisoned".to_string())? = Some(work);
        match self.nudge.try_send(()) {
            Ok(()) | Err(mpsc::TrySendError::Full(())) => Ok(()),
            Err(mpsc::TrySendError::Disconnected(())) => Err("DNS policy worker stopped".into()),
        }
    }
}

fn reconcile_under_lock(
    coordinator: &mut DnsPolicyCoordinator,
    work: &DnsPolicyWork,
) -> Result<(), String> {
    // An externally observed session is visibility, not authority. A local
    // process cannot compute a complete global policy while any session lacks
    // an ownership handle, so it must not mutate or release resolver state.
    if work.external_sessions > 0 {
        coordinator.invalidate_effective("external VPN session observed; DNS ownership is unknown");
        return Err("DNS policy unchanged: external session ownership is unknown".into());
    }
    let adapter = &crate::platform::current_platform().dns;
    let result = if work.persist {
        coordinator.reconcile_durable(&work.intents, adapter, |state| {
            save(&work.config_dir, state)
        })
    } else {
        coordinator.reconcile(&work.intents, adapter)
    };
    result.map(|_| ()).map_err(|error| error.to_string())
}

/// Serialize all DNS policy writers across CLI and TUI processes. This lock
/// is intentionally distinct from the lifecycle lock so a CLI command that
/// already owns lifecycle authority cannot self-deadlock.
#[cfg(unix)]
pub fn acquire_policy_lock(config_dir: &Path) -> std::io::Result<std::fs::File> {
    acquire_policy_lock_with_hook(config_dir, || {})
}

#[cfg(unix)]
fn acquire_policy_lock_with_hook(
    config_dir: &Path,
    after_pin: impl FnOnce(),
) -> std::io::Result<std::fs::File> {
    use std::os::fd::AsRawFd as _;

    let directory = open_pinned_config_dir(config_dir)?;
    after_pin();
    let file = openat_file(
        &directory,
        "dns-policy.lock",
        libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0o600,
    )?;
    require_regular_file(&file, "DNS policy lock")?;
    chown_open_file_to_real_user(&file)?;
    #[allow(unsafe_code)]
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc == 0 {
        Ok(file)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
pub fn acquire_policy_lock(config_dir: &Path) -> std::io::Result<std::fs::File> {
    crate::utils::create_user_dir(config_dir)?;
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(config_dir.join("dns-policy.lock"))
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
    atomic_write_user_file(config_dir, &content)
}

#[cfg(unix)]
fn atomic_write_user_file(config_dir: &Path, content: &[u8]) -> std::io::Result<()> {
    atomic_write_user_file_with_hook(config_dir, content, || {})
}

/// Pin the destination directory before creating any file. Every subsequent
/// operation is relative to that descriptor, so replacing any pathname with
/// a symlink cannot redirect a privileged writer.
#[cfg(unix)]
fn atomic_write_user_file_with_hook(
    config_dir: &Path,
    content: &[u8],
    after_pin: impl FnOnce(),
) -> std::io::Result<()> {
    let directory = open_pinned_config_dir(config_dir)?;
    after_pin();
    let (temp_name, mut file) = create_private_temp(&directory)?;
    let result = (|| {
        file.write_all(content)?;
        file.sync_all()?;
        chown_open_file_to_real_user(&file)?;
        renameat(&directory, &temp_name, DNS_POLICY_STATE_FILE)?;
        directory.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = unlinkat(&directory, &temp_name);
    }
    result
}

#[cfg(not(unix))]
fn atomic_write_user_file(config_dir: &Path, content: &[u8]) -> std::io::Result<()> {
    crate::utils::create_user_dir(config_dir)?;
    let path = config_dir.join(DNS_POLICY_STATE_FILE);
    let temp = config_dir.join(format!("{DNS_POLICY_STATE_FILE}.tmp"));
    crate::utils::write_user_file(&temp, content)?;
    std::fs::OpenOptions::new()
        .read(true)
        .open(&temp)?
        .sync_all()?;
    std::fs::rename(temp, path)
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn chown_open_file_to_real_user(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    if !crate::utils::is_root() {
        return Ok(());
    }
    let Some(uid) = std::env::var("SUDO_UID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return Ok(());
    };
    let Some(gid) = std::env::var("SUDO_GID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return Ok(());
    };
    // SAFETY: the descriptor remains live for this call and uid/gid are
    // plain values parsed from sudo's environment contract.
    let result = unsafe { libc::fchown(file.as_raw_fd(), uid, gid) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn create_private_temp(directory: &std::fs::File) -> std::io::Result<(String, std::fs::File)> {
    for _ in 0..128 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!(
            ".{DNS_POLICY_STATE_FILE}.{}.{}.tmp",
            std::process::id(),
            sequence
        );
        match openat_file(
            directory,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        ) {
            Ok(file) => return Ok((name, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a private DNS state temp file",
    ))
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn open_pinned_config_dir(path: &Path) -> std::io::Result<std::fs::File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;

    let path = canonical_parent_with_leaf(path)?;
    let root_path = CString::new("/").expect("static path");
    let fd = unsafe {
        libc::open(
            root_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut directory = unsafe { std::fs::File::from_raw_fd(fd) };

    for component in path.components() {
        use std::path::Component;
        let Component::Normal(component) = component else {
            if matches!(component, Component::RootDir | Component::CurDir) {
                continue;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "DNS config directory must not contain parent components",
            ));
        };
        let name = CString::new(component.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "DNS config directory contains a NUL byte",
            )
        })?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let mut child_fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        let mut created = false;
        if child_fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            let mkdir_result =
                unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) };
            if mkdir_result == 0 {
                created = true;
            } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                return Err(std::io::Error::last_os_error());
            }
            child_fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        }
        if child_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let child = unsafe { std::fs::File::from_raw_fd(child_fd) };
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(child.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let metadata = unsafe { metadata.assume_init() };
        if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                "DNS config path component is not a directory",
            ));
        }
        if created {
            chown_open_file_to_real_user(&child)?;
            directory.sync_all()?;
        }
        directory = child;
    }
    Ok(directory)
}

/// Resolve only the already-existing parent ancestry. The final config-dir
/// component remains unresolved and is opened with `O_NOFOLLOW`, so a
/// symlink at the authority boundary is rejected rather than canonicalized
/// into an attacker-selected directory.
#[cfg(unix)]
fn canonical_parent_with_leaf(path: &Path) -> std::io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let Some(leaf) = absolute.file_name().map(ToOwned::to_owned) else {
        return absolute.canonicalize();
    };
    let mut ancestor = absolute.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "DNS config directory has no parent",
        )
    })?;
    let mut missing = Vec::new();
    while !ancestor.exists() {
        let component = ancestor.file_name().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "DNS config directory has no existing ancestor",
            )
        })?;
        missing.push(component.to_os_string());
        ancestor = ancestor.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "DNS config directory has no existing ancestor",
            )
        })?;
    }
    let mut canonical = ancestor.canonicalize()?;
    for component in missing.into_iter().rev() {
        canonical.push(component);
    }
    canonical.push(leaf);
    Ok(canonical)
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn openat_file(
    directory: &std::fs::File,
    name: &str,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<std::fs::File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    let name = CString::new(name).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "file name contains a NUL byte",
        )
    })?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags,
            libc::c_uint::from(mode),
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn require_regular_file(file: &std::fs::File, label: &str) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT == libc::S_IFREG {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{label} is not a regular file"),
        ))
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn renameat(directory: &std::fs::File, from: &str, to: &str) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd as _;

    let from = CString::new(from).expect("generated temp name has no NUL");
    let to = CString::new(to).expect("static state name has no NUL");
    let result = unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn unlinkat(directory: &std::fs::File, name: &str) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd as _;

    let name = CString::new(name).expect("generated temp name has no NUL");
    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[cfg(unix)]
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

    #[cfg(unix)]
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

    #[cfg(unix)]
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

    #[cfg(unix)]
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
    fn worker_coalesces_to_latest_revision_without_touching_external_session() {
        let temp = tempfile::tempdir().unwrap();
        let blocker = acquire_policy_lock(temp.path()).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let external_profile =
            crate::vortix_core::profile::ProfileId::parse("e".repeat(64)).unwrap();
        let mut persisted: DnsPolicyCoordinator = serde_json::from_value(serde_json::json!({
            "desired": {
                "generation": 7,
                "assignments": [{
                    "profile_id": external_profile,
                    "interface": "wg-old",
                    "servers": ["10.0.0.53"],
                    "search_domains": ["corp.example"],
                    "scope": "CatchAll"
                }]
            },
            "effective": {
                "requested_generation": 7,
                "applied_generation": 7,
                "status": "Applied",
                "owned": [],
                "errors": []
            }
        }))
        .unwrap();
        persisted.discard_persisted_authority();
        let worker = DnsPolicyWorker::spawn(persisted, tx);
        let work = |revision| DnsPolicyWork {
            revision,
            intents: Vec::new(),
            external_sessions: 1,
            config_dir: temp.path().to_path_buf(),
            persist: false,
        };
        let scheduled_at = std::time::Instant::now();
        worker.schedule(work(1)).unwrap();
        assert!(
            scheduled_at.elapsed() < Duration::from_millis(50),
            "UI-side scheduling waited for the cross-process lock"
        );
        std::thread::sleep(Duration::from_millis(20));
        worker.schedule(work(2)).unwrap();
        worker.schedule(work(3)).unwrap();
        drop(blocker);

        let crate::message::Message::DnsPolicyResult {
            revision,
            coordinator,
            external_sessions,
            ..
        } = rx.recv_timeout(Duration::from_secs(1)).unwrap()
        else {
            panic!("worker returned the wrong message")
        };
        assert_eq!(revision, 3);
        assert_eq!(external_sessions, 1);
        assert_eq!(
            coordinator.effective().status,
            crate::vortix_core::ports::dns::DnsEffectiveStatus::Degraded
        );
        assert_eq!(coordinator.desired().unwrap().generation, 7);
        assert_eq!(coordinator.effective().applied_generation, None);
        assert_eq!(
            coordinator.desired().unwrap().assignments[0].interface,
            "wg-old",
            "scanner observation must not adopt or rewrite persisted DNS identity"
        );
        drop(worker);
    }

    #[test]
    fn round_trip_is_atomic_and_owner_readable() {
        let temp = tempfile::tempdir().unwrap();
        let coordinator = DnsPolicyCoordinator::default();
        save(temp.path(), &coordinator).unwrap();
        let loaded = load(temp.path()).unwrap();
        assert_eq!(
            loaded.effective().status,
            crate::vortix_core::ports::dns::DnsEffectiveStatus::Degraded
        );
        assert!(std::fs::read_dir(temp.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));
    }

    #[cfg(unix)]
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
        let attacker_profile =
            crate::vortix_core::profile::ProfileId::parse("a".repeat(64)).unwrap();
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
            crate::vortix_core::ports::dns::DnsEffectiveStatus::Degraded
        );
    }
}
