//! Redacted daemon diagnostics and advisory fallback persistence.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::broadcast;

use crate::vortix_core::control::diagnostics::{
    DEFAULT_FALLBACK_STALE_AFTER_MILLIS, MAX_FALLBACK_BYTES, MAX_FALLBACK_RECORDS,
    MAX_FALLBACK_STALE_AFTER_MILLIS,
};
use crate::vortix_core::control::{
    DiagnosticBuffer, DiagnosticCode, DiagnosticComponent, DiagnosticFields, DiagnosticSeverity,
    DiagnosticSnapshot, DiagnosticSource, DiagnosticStatus, DiagnosticView,
    FallbackDiagnosticState,
};

const EVENT_CAPACITY: usize = 64;
const FALLBACK_RETRY_INITIAL: Duration = Duration::from_millis(100);
const FALLBACK_RETRY_MAX: Duration = Duration::from_secs(5);

pub trait DiagnosticQueryProvider: Send + Sync + 'static {
    fn snapshot(&self) -> DiagnosticSnapshot;
    fn subscribe(&self) -> broadcast::Receiver<DiagnosticSnapshot>;
}

/// Create the owner-private directory used by the advisory fallback and then
/// verify the exact ownership contract the descriptor-relative writer uses.
pub fn prepare_fallback_directory(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_dir() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "diagnostic fallback directory is not a real directory",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    crate::utils::create_user_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_dir()
            || metadata.uid() != diagnostic_owner_uid()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "diagnostic fallback directory is not owner-private",
            ));
        }
    }
    Ok(())
}

struct HubState {
    buffer: DiagnosticBuffer,
    status: DiagnosticStatus,
    started: Instant,
    events: broadcast::Sender<DiagnosticSnapshot>,
    stale_after_millis: u64,
}

impl HubState {
    fn snapshot(&self) -> DiagnosticSnapshot {
        self.snapshot_at(monotonic_millis(self.started), unix_millis())
    }

    fn snapshot_at(&self, now_millis: u64, generated_at_unix_millis: u64) -> DiagnosticSnapshot {
        self.buffer.snapshot_with_stale_after(
            now_millis,
            generated_at_unix_millis,
            self.stale_after_millis,
            self.status,
        )
    }
}

pub struct DiagnosticHub {
    state: Arc<Mutex<HubState>>,
    fallback_writer: Option<FallbackWriter>,
}

impl DiagnosticHub {
    pub fn start(fallback_path: Option<PathBuf>) -> std::io::Result<Self> {
        Self::start_with_stale_after(
            fallback_path,
            std::time::Duration::from_millis(DEFAULT_FALLBACK_STALE_AFTER_MILLIS),
        )
    }

    pub fn start_with_stale_after(
        fallback_path: Option<PathBuf>,
        stale_after: std::time::Duration,
    ) -> std::io::Result<Self> {
        Self::start_with_fallback_store(fallback_path.map(FallbackStore::new), stale_after)
    }

    fn start_with_fallback_store(
        fallback_store: Option<FallbackStore>,
        stale_after: std::time::Duration,
    ) -> std::io::Result<Self> {
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        let started = Instant::now();
        let stale_after_millis: u64 = stale_after
            .as_millis()
            .try_into()
            .unwrap_or(MAX_FALLBACK_STALE_AFTER_MILLIS)
            .clamp(1, MAX_FALLBACK_STALE_AFTER_MILLIS);
        let mut buffer = DiagnosticBuffer::default();
        buffer.push(
            0,
            DiagnosticComponent::Daemon,
            DiagnosticSeverity::Info,
            DiagnosticCode::DaemonStarted,
            DiagnosticFields::None,
        );
        let state = Arc::new(Mutex::new(HubState {
            buffer,
            status: DiagnosticStatus::default(),
            started,
            events,
            stale_after_millis,
        }));
        let fallback = fallback_store
            .map(|store| FallbackWriter::start(store, Arc::clone(&state)))
            .transpose()?;
        let hub = Self {
            state,
            fallback_writer: fallback,
        };
        hub.queue_fallback();
        Ok(hub)
    }

    pub fn set_status(&self, status: DiagnosticStatus) {
        self.publish_update(|state| {
            let status = DiagnosticStatus {
                fallback: state.status.fallback,
                ..status
            };
            if state.status == status {
                return false;
            }
            state.status = status;
            let now_millis = monotonic_millis(state.started);
            state.buffer.push(
                now_millis,
                DiagnosticComponent::Reconciliation,
                DiagnosticSeverity::Info,
                DiagnosticCode::ReconciliationStateChanged,
                DiagnosticFields::Readiness {
                    authority_verified: status.authority_verified,
                    reconciliation_complete: status.reconciliation_complete,
                },
            );
            true
        });
    }

    pub fn record(
        &self,
        component: DiagnosticComponent,
        severity: DiagnosticSeverity,
        code: DiagnosticCode,
        fields: DiagnosticFields,
    ) {
        self.publish_update(|state| {
            let now_millis = monotonic_millis(state.started);
            state
                .buffer
                .push(now_millis, component, severity, code, fields);
            true
        });
    }

    pub(crate) fn mark_passive_observer_ready(&self, active_tunnels: u32) {
        self.publish_update(|state| {
            state.status.authority_verified = false;
            state.status.reconciliation_complete = true;
            let now_millis = monotonic_millis(state.started);
            state.buffer.push(
                now_millis,
                DiagnosticComponent::Reconciliation,
                DiagnosticSeverity::Info,
                DiagnosticCode::PassiveObservationChanged,
                DiagnosticFields::Count {
                    value: active_tunnels,
                },
            );
            true
        });
    }

    pub(crate) fn record_passive_observation(&self, active_tunnels: u32) {
        self.record(
            DiagnosticComponent::Reconciliation,
            DiagnosticSeverity::Info,
            DiagnosticCode::PassiveObservationChanged,
            DiagnosticFields::Count {
                value: active_tunnels,
            },
        );
    }

    fn queue_fallback(&self) {
        let Some(fallback) = &self.fallback_writer else {
            return;
        };
        fallback.queue();
    }

    fn publish_update(&self, update: impl FnOnce(&mut HubState) -> bool) {
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !update(&mut state) {
                return;
            }
            let now_millis = monotonic_millis(state.started);
            let generated_at = unix_millis();
            if state.events.receiver_count() > 0 {
                let _ = state
                    .events
                    .send(state.snapshot_at(now_millis, generated_at));
            }
        }
        if let Some(writer) = &self.fallback_writer {
            writer.queue();
        }
    }
}

impl DiagnosticQueryProvider for DiagnosticHub {
    fn snapshot(&self) -> DiagnosticSnapshot {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .snapshot()
    }

    fn subscribe(&self) -> broadcast::Receiver<DiagnosticSnapshot> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .events
            .subscribe()
    }
}

#[derive(Debug, Clone)]
pub struct FallbackStore {
    path: PathBuf,
    expected_uid: u32,
    #[cfg(test)]
    fail_writes: Arc<std::sync::atomic::AtomicUsize>,
}

impl FallbackStore {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            expected_uid: diagnostic_owner_uid(),
            #[cfg(test)]
            fail_writes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    #[cfg(test)]
    fn fail_next_writes_for_test(mut self, failures: usize) -> Self {
        self.fail_writes = Arc::new(std::sync::atomic::AtomicUsize::new(failures));
        self
    }

    pub fn write(&self, snapshot: &DiagnosticSnapshot) -> std::io::Result<()> {
        #[cfg(test)]
        if self
            .fail_writes
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |remaining| remaining.checked_sub(1),
            )
            .is_ok()
        {
            return Err(std::io::Error::other(
                "injected diagnostic fallback write failure",
            ));
        }
        let body = serde_json::to_vec(snapshot).map_err(std::io::Error::other)?;
        if snapshot.records.len() > MAX_FALLBACK_RECORDS || body.len() > MAX_FALLBACK_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "diagnostic fallback exceeds its fixed capacity",
            ));
        }
        write_private_atomic(&self.path, &body, || Ok(()))
    }

    pub fn read(&self, now_unix_millis: u64) -> std::io::Result<DiagnosticView> {
        let body = read_private_bounded(&self.path, self.expected_uid)?;
        let snapshot: DiagnosticSnapshot =
            serde_json::from_slice(&body).map_err(std::io::Error::other)?;
        if snapshot.records.len() > MAX_FALLBACK_RECORDS || !snapshot.is_compatible() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "diagnostic fallback failed bounded schema validation",
            ));
        }
        let age_millis = now_unix_millis.saturating_sub(snapshot.generated_at_unix_millis);
        Ok(DiagnosticView {
            source: DiagnosticSource::UnauthenticatedAdvisoryFallback,
            stale: age_millis > snapshot.stale_after_millis,
            age_millis,
            snapshot,
        })
    }
}

struct FallbackQueue {
    dirty: bool,
    stopping: bool,
    retry_at: Option<Instant>,
    retry_delay: Duration,
}

struct FallbackWriter {
    queue: Arc<(Mutex<FallbackQueue>, Condvar)>,
    worker: Option<JoinHandle<()>>,
}

impl FallbackWriter {
    fn start(store: FallbackStore, state: Arc<Mutex<HubState>>) -> std::io::Result<Self> {
        let queue = Arc::new((
            Mutex::new(FallbackQueue {
                dirty: false,
                stopping: false,
                retry_at: None,
                retry_delay: FALLBACK_RETRY_INITIAL,
            }),
            Condvar::new(),
        ));
        let worker_queue = Arc::clone(&queue);
        let worker = std::thread::Builder::new()
            .name("vortix-diagnostic-fallback".into())
            .spawn(move || fallback_loop(&store, &worker_queue, &state))?;
        Ok(Self {
            queue,
            worker: Some(worker),
        })
    }

    fn queue(&self) {
        let (queue, ready) = &*self.queue;
        let mut queue = queue.lock().expect("diagnostic fallback mutex poisoned");
        queue.dirty = true;
        // A fresh diagnostic update supersedes a delayed retry. It is safe to
        // coalesce both into one immediate snapshot because the writer always
        // captures state only after it owns the queue slot.
        queue.retry_at = None;
        ready.notify_one();
    }
}

impl Drop for FallbackWriter {
    fn drop(&mut self) {
        let (queue, ready) = &*self.queue;
        let mut queue = queue.lock().expect("diagnostic fallback mutex poisoned");
        queue.stopping = true;
        queue.retry_at = None;
        drop(queue);
        ready.notify_one();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn fallback_loop(
    store: &FallbackStore,
    queue: &(Mutex<FallbackQueue>, Condvar),
    state: &Mutex<HubState>,
) {
    loop {
        {
            let (queue, ready) = queue;
            let mut queue = queue.lock().expect("diagnostic fallback mutex poisoned");
            while !queue.stopping {
                if !queue.dirty {
                    queue = ready
                        .wait(queue)
                        .expect("diagnostic fallback mutex poisoned");
                    continue;
                }
                let Some(retry_at) = queue.retry_at else {
                    break;
                };
                let now = Instant::now();
                if now >= retry_at {
                    break;
                }
                let (next, _) = ready
                    .wait_timeout(queue, retry_at.saturating_duration_since(now))
                    .expect("diagnostic fallback mutex poisoned");
                queue = next;
            }
            if queue.stopping && !queue.dirty {
                return;
            }
            queue.dirty = false;
            queue.retry_at = None;
        }
        let snapshot = {
            let state = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.buffer.fallback_snapshot_with_stale_after(
                monotonic_millis(state.started),
                unix_millis(),
                state.stale_after_millis,
                state.status,
            )
        };
        let write_succeeded = store.write(&snapshot).is_ok();
        let mut status_changed = false;
        {
            let mut state = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let next = if write_succeeded {
                FallbackDiagnosticState::Healthy
            } else {
                FallbackDiagnosticState::Degraded
            };
            if state.status.fallback != next {
                let prior = state.status.fallback;
                state.status.fallback = next;
                let now_millis = monotonic_millis(state.started);
                if !write_succeeded {
                    state.buffer.push(
                        now_millis,
                        DiagnosticComponent::Daemon,
                        DiagnosticSeverity::Warning,
                        DiagnosticCode::FallbackWriteFailed,
                        DiagnosticFields::None,
                    );
                } else if prior == FallbackDiagnosticState::Degraded {
                    state.buffer.push(
                        now_millis,
                        DiagnosticComponent::Daemon,
                        DiagnosticSeverity::Info,
                        DiagnosticCode::FallbackWriteRecovered,
                        DiagnosticFields::None,
                    );
                }
                if state.events.receiver_count() > 0 {
                    let snapshot = state.snapshot();
                    let _ = state.events.send(snapshot);
                }
                status_changed = true;
            }
        }
        let (queue, ready) = queue;
        let mut queue = queue.lock().expect("diagnostic fallback mutex poisoned");
        if queue.stopping {
            continue;
        }
        if write_succeeded {
            queue.retry_delay = FALLBACK_RETRY_INITIAL;
            if !status_changed {
                continue;
            }
            // Persist the newly healthy/degraded status and its typed record.
            queue.dirty = true;
            queue.retry_at = None;
        } else {
            // Keep retry ownership inside this one worker. The deadline grows
            // exponentially and is capped, so a quiet daemon eventually
            // recovers from transient storage failures without a busy loop.
            queue.dirty = true;
            queue.retry_at = Some(Instant::now() + queue.retry_delay);
            queue.retry_delay = queue.retry_delay.saturating_mul(2).min(FALLBACK_RETRY_MAX);
        }
        drop(queue);
        ready.notify_one();
    }
}

fn write_private_atomic(
    path: &Path,
    body: &[u8],
    before_publish: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<()> {
    write_private_atomic_impl(path, body, before_publish)
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn write_private_atomic_impl(
    path: &Path,
    body: &[u8],
    before_publish: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "fallback path has no parent",
        )
    })?;
    let parent_c = std::ffi::CString::new(parent.as_os_str().as_bytes())?;
    let directory_fd = unsafe {
        libc::open(
            parent_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if directory_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let directory = unsafe { std::fs::File::from_raw_fd(directory_fd) };
    let parent_metadata = directory.metadata()?;
    if parent_metadata.uid() != diagnostic_owner_uid()
        || parent_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "fallback parent must be owner-controlled",
        ));
    }
    let destination = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "fallback path has no file name",
        )
    })?;
    let destination_c = std::ffi::CString::new(destination.as_bytes())?;
    let temporary = format!(".{}.tmp", destination.to_string_lossy());
    let temporary_c = std::ffi::CString::new(temporary.as_bytes())?;
    remove_stale_temporary(directory.as_raw_fd(), &temporary_c, diagnostic_owner_uid())?;
    let file_fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            temporary_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if file_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(file_fd) };
    let target_owner = diagnostic_owner_ids();
    let result = (|| {
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if crate::utils::effective_user_group_ids().0 == 0
            && unsafe { libc::fchown(file.as_raw_fd(), target_owner.0, target_owner.1) } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        file.write_all(body)?;
        file.sync_all()?;
        before_publish()?;
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temporary_c.as_ptr(),
                directory.as_raw_fd(),
                destination_c.as_ptr(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        directory.sync_all()
    })();
    if result.is_err() {
        let _ = unsafe { libc::unlinkat(directory.as_raw_fd(), temporary_c.as_ptr(), 0) };
    }
    result
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn remove_stale_temporary(
    directory_fd: std::os::fd::RawFd,
    name: &std::ffi::CStr,
    expected_uid: u32,
) -> std::io::Result<()> {
    use std::mem::MaybeUninit;

    let mut metadata = MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            directory_fd,
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(error);
    }
    // SAFETY: successful fstatat initialized the complete stat value.
    let metadata = unsafe { metadata.assume_init() };
    let is_regular = metadata.st_mode & libc::S_IFMT == libc::S_IFREG;
    if !is_regular || metadata.st_uid != expected_uid || metadata.st_mode & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "refusing untrusted diagnostic fallback temporary",
        ));
    }
    if unsafe { libc::unlinkat(directory_fd, name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn write_private_atomic_impl(
    path: &Path,
    body: &[u8],
    before_publish: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<()> {
    before_publish()?;
    crate::vortix_config::profile_store::write_atomic(path, body)
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn read_private_bounded(path: &Path, expected_uid: u32) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    use std::os::fd::FromRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let fd = unsafe {
        libc::open(
            path_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > MAX_FALLBACK_BYTES as u64
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "diagnostic fallback is not an owner-private bounded regular file",
        ));
    }
    let mut body = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.by_ref()
        .take((MAX_FALLBACK_BYTES + 1) as u64)
        .read_to_end(&mut body)?;
    if body.len() > MAX_FALLBACK_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "diagnostic fallback exceeds its fixed capacity",
        ));
    }
    Ok(body)
}

#[cfg(not(unix))]
fn read_private_bounded(path: &Path, _expected_uid: u32) -> std::io::Result<Vec<u8>> {
    let body = std::fs::read(path)?;
    if body.len() > MAX_FALLBACK_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "diagnostic fallback exceeds its fixed capacity",
        ));
    }
    Ok(body)
}

fn monotonic_millis(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

pub(crate) fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn diagnostic_owner_uid() -> u32 {
    #[cfg(unix)]
    {
        diagnostic_owner_ids().0
    }
    #[cfg(not(unix))]
    {
        0
    }
}

#[cfg(unix)]
fn diagnostic_owner_ids() -> (u32, u32) {
    let effective = crate::utils::effective_user_group_ids();
    if effective.0 != 0 {
        return effective;
    }
    let Some(uid) = std::env::var("SUDO_UID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return effective;
    };
    let Some(gid) = std::env::var("SUDO_GID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return effective;
    };
    (uid, gid)
}

#[cfg(not(unix))]
const fn diagnostic_owner_ids() -> (u32, u32) {
    (0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_tempdir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn snapshot(generation: u64) -> DiagnosticSnapshot {
        let mut buffer = DiagnosticBuffer::default();
        buffer.push(
            generation,
            DiagnosticComponent::Control,
            DiagnosticSeverity::Info,
            DiagnosticCode::DesiredStateChanged,
            DiagnosticFields::Generation { value: generation },
        );
        buffer.fallback_snapshot(generation, generation, DiagnosticStatus::default())
    }

    #[test]
    fn fallback_is_private_and_always_advisory() {
        let directory = private_tempdir();
        let store = FallbackStore::new(directory.path().join("diagnostics.json"));
        let mut payload = snapshot(10);
        payload.status.authority_verified = true;
        payload.status.reconciliation_complete = true;
        store.write(&payload).unwrap();
        let view = store.read(45_000).unwrap();
        assert_eq!(
            view.source,
            DiagnosticSource::UnauthenticatedAdvisoryFallback
        );
        assert!(view.stale);
        assert!(!view.may_establish_authority());
        assert!(!view.may_claim_protection());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(directory.path().join("diagnostics.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn configured_staleness_is_persisted_for_every_reader() {
        let directory = private_tempdir();
        let store = FallbackStore::new(directory.path().join("diagnostics.json"));
        let mut buffer = DiagnosticBuffer::default();
        buffer.push(
            1,
            DiagnosticComponent::Daemon,
            DiagnosticSeverity::Info,
            DiagnosticCode::DaemonStarted,
            DiagnosticFields::None,
        );
        let payload = buffer.fallback_snapshot_with_stale_after(
            1,
            1_000,
            10_000,
            DiagnosticStatus::default(),
        );
        store.write(&payload).unwrap();
        assert!(!store.read(10_999).unwrap().stale);
        assert!(store.read(11_001).unwrap().stale);
    }

    #[test]
    fn fallback_directory_mode_matches_the_writer_contract() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("control");
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o775)).unwrap();
        prepare_fallback_directory(&directory).unwrap();
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        FallbackStore::new(directory.join("diagnostics.json"))
            .write(&snapshot(1))
            .unwrap();
    }

    #[test]
    fn verified_stale_temporary_is_removed_before_atomic_publish() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = private_tempdir();
        let path = directory.path().join("diagnostics.json");
        let temporary = directory.path().join(".diagnostics.json.tmp");
        std::fs::write(&temporary, b"orphaned-private-snapshot").unwrap();
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).unwrap();
        let store = FallbackStore::new(path);
        store.write(&snapshot(2)).unwrap();
        assert!(!temporary.exists());
        assert_eq!(store.read(2).unwrap().snapshot.generation, 1);
    }

    #[test]
    fn interrupted_publish_leaves_prior_snapshot_readable() {
        let directory = private_tempdir();
        let path = directory.path().join("diagnostics.json");
        let store = FallbackStore::new(path.clone());
        store.write(&snapshot(1)).unwrap();
        let replacement = serde_json::to_vec(&snapshot(2)).unwrap();
        let interrupted = write_private_atomic(&path, &replacement, || {
            Err(std::io::Error::other(
                "simulated interruption before rename",
            ))
        });
        assert!(interrupted.is_err());
        assert_eq!(store.read(1).unwrap().snapshot.generation, 1);
    }

    #[test]
    fn fallback_refuses_symlinks_and_loose_permissions() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let directory = private_tempdir();
        let path = directory.path().join("diagnostics.json");
        let store = FallbackStore::new(path.clone());
        store.write(&snapshot(1)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            store.read(1).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        std::fs::remove_file(&path).unwrap();
        let target = directory.path().join("target.json");
        std::fs::write(&target, serde_json::to_vec(&snapshot(1)).unwrap()).unwrap();
        symlink(&target, &path).unwrap();
        assert!(store.read(1).is_err());
    }

    #[test]
    fn disk_failure_is_visible_only_as_a_typed_diagnostic() {
        let directory = tempfile::tempdir().unwrap();
        let hub = DiagnosticHub::start(Some(
            directory.path().join("missing-parent/diagnostics.json"),
        ))
        .unwrap();
        for _ in 0..100 {
            if hub
                .snapshot()
                .records
                .iter()
                .any(|record| record.code == DiagnosticCode::FallbackWriteFailed)
            {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("fallback failure was not published");
    }

    #[test]
    fn fallback_retries_quietly_after_injected_write_failures() {
        let directory = private_tempdir();
        let store = FallbackStore::new(directory.path().join("diagnostics.json"))
            .fail_next_writes_for_test(2);
        let hub = DiagnosticHub::start_with_fallback_store(
            Some(store),
            std::time::Duration::from_secs(30),
        )
        .unwrap();

        let deadline = Instant::now() + std::time::Duration::from_secs(3);
        while hub.snapshot().status.fallback != FallbackDiagnosticState::Degraded {
            assert!(
                Instant::now() < deadline,
                "injected failure was not published"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        // Do not publish another record here: recovery must come from the
        // fallback worker's bounded retry, not an unrelated state change.
        while hub.snapshot().status.fallback != FallbackDiagnosticState::Healthy {
            assert!(
                Instant::now() < deadline,
                "quiet fallback retry did not recover"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        let recovered = hub.snapshot();
        assert_eq!(recovered.status.fallback, FallbackDiagnosticState::Healthy);
        assert!(recovered
            .records
            .iter()
            .any(|record| record.code == DiagnosticCode::FallbackWriteRecovered));
    }
}
