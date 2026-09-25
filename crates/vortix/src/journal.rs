//! Engine event journal — JSONL persistence + broadcast channel.
//!
//! Two output paths in parallel:
//! - **Bounded mpsc to a writer task** that appends to
//!   `<config_dir>/sessions/<ISO>-<pid>.jsonl`. Each line is one
//!   [`EventEnvelope`] serialised as JSON. Saturation is returned and counted.
//! - **Lossy broadcast** (`tokio::sync::broadcast`, capacity 1024). Slow
//!   subscribers get `Lagged(N)`; they re-sync via [`Journal::tail`].
//!
//! Retention runs once at startup: delete files older than
//! `retention_days` AND beyond `retention_count` most-recent. The first
//! event of the new session is `JournalRetentionApplied { deleted }`.
//!
//! `[journal] disk = false` mode skips the writer task; events flow only
//! through the broadcast channel + the in-memory ring buffer.

mod retention {
    //! Retention pass — runs at startup, prunes stale session files.

    use std::path::Path;
    use std::time::{Duration, SystemTime};

    use tracing::warn;

    /// Outcome of a retention pass.
    #[derive(Debug, Default, Clone)]
    pub struct RetentionStats {
        pub deleted: u32,
        pub kept: u32,
    }

    /// Walk `journal_dir` and delete `.jsonl` files older than `retention_days`
    /// or beyond the `retention_count` most-recent (whichever rule prunes more).
    ///
    /// Errors during individual deletes are logged via `tracing` but do not
    /// abort the pass.
    pub fn prune(
        journal_dir: &Path,
        retention_days: u32,
        retention_count: u32,
    ) -> std::io::Result<RetentionStats> {
        let mut stats = RetentionStats::default();
        let entries = std::fs::read_dir(journal_dir)?;

        let mut sessions: Vec<(std::path::PathBuf, SystemTime)> = entries
            .filter_map(std::result::Result::ok)
            .filter_map(|e| {
                let path = e.path();
                if path.extension().and_then(|x| x.to_str()) != Some("jsonl") {
                    return None;
                }
                let modified = e.metadata().ok().and_then(|m| m.modified().ok())?;
                Some((path, modified))
            })
            .collect();

        // Sort newest-first so the count-based rule is simple.
        sessions.sort_by(|a, b| b.1.cmp(&a.1));

        let age_cutoff =
            SystemTime::now().checked_sub(Duration::from_secs(u64::from(retention_days) * 86_400));

        for (idx, (path, modified)) in sessions.iter().enumerate() {
            let too_old = age_cutoff.is_some_and(|cutoff| *modified < cutoff);
            let beyond_count = idx >= retention_count as usize;
            if too_old || beyond_count {
                match std::fs::remove_file(path) {
                    Ok(()) => stats.deleted = stats.deleted.saturating_add(1),
                    Err(e) => warn!(
                        target: "vortix::journal::retention",
                        path = %path.display(),
                        error = %e,
                        "failed to delete stale journal file"
                    ),
                }
            } else {
                stats.kept = stats.kept.saturating_add(1);
            }
        }

        Ok(stats)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs::File;
        use std::time::Duration;

        #[test]
        fn count_rule_prunes_oldest() {
            let tmp = tempfile::tempdir().unwrap();
            for i in 0u32..35 {
                let path = tmp
                    .path()
                    .join(format!("2026-05-{:02}T00:00:00Z-1.jsonl", i + 1));
                File::create(&path).unwrap();
                // Stagger mtimes so sorting works deterministically.
                let then = SystemTime::now() - Duration::from_secs(u64::from(35 - i) * 60);
                set_mtime(&path, then);
            }

            let stats = prune(tmp.path(), u32::MAX, 30).unwrap();
            assert_eq!(stats.kept, 30);
            assert_eq!(stats.deleted, 5);
        }

        #[test]
        fn day_rule_prunes_old() {
            let tmp = tempfile::tempdir().unwrap();
            let recent = tmp.path().join("recent.jsonl");
            let stale = tmp.path().join("stale.jsonl");
            File::create(&recent).unwrap();
            File::create(&stale).unwrap();
            set_mtime(&stale, SystemTime::now() - Duration::from_secs(60 * 86_400));

            let stats = prune(tmp.path(), 30, u32::MAX).unwrap();
            assert_eq!(stats.deleted, 1);
            assert!(recent.exists());
            assert!(!stale.exists());
        }

        #[test]
        fn ignores_non_jsonl_files() {
            let tmp = tempfile::tempdir().unwrap();
            File::create(tmp.path().join("session.jsonl")).unwrap();
            File::create(tmp.path().join("README.md")).unwrap();
            let stats = prune(tmp.path(), u32::MAX, u32::MAX).unwrap();
            // Both .jsonl files within budget — README is not counted at all.
            assert_eq!(stats.kept, 1);
            assert_eq!(stats.deleted, 0);
        }

        fn set_mtime(path: &std::path::Path, time: SystemTime) {
            let times = std::fs::FileTimes::new().set_modified(time);
            std::fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_times(times)
                .unwrap();
        }
    }
}
mod writer {
    //! Journal writer task — drains the mpsc and writes to disk + broadcast + tail.

    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use tokio::io::AsyncWriteExt;
    use tokio::sync::{broadcast, mpsc, watch};
    use tracing::warn;

    use super::EventEnvelope;

    use super::TailBuffer;

    /// Disk-backed writer. Appends one JSON line per event to `path`, fans out to
    /// broadcast subscribers, and pushes into the tail buffer.
    pub(crate) async fn run(
        path: PathBuf,
        mut mpsc_rx: mpsc::Receiver<EventEnvelope>,
        bcast_tx: broadcast::Sender<EventEnvelope>,
        tail: Arc<Mutex<TailBuffer>>,
        failure_count: Arc<AtomicU64>,
        failure_events: watch::Sender<u64>,
    ) {
        let mut file = match crate::config::owned_file::open_user_file(&path, true) {
            Ok(f) => tokio::fs::File::from_std(f),
            Err(e) => {
                record_failure(&failure_count, &failure_events);
                warn!(
                    target: "vortix::journal",
                    path = %path.display(),
                    error = %e,
                    "failed to open journal file; events will be dropped"
                );
                // Closing the receiver makes subsequent producer loss explicit as
                // WriterGone instead of accepting and silently discarding events.
                return;
            }
        };

        while let Some(env) = mpsc_rx.recv().await {
            // 1. Persist.
            match serde_json::to_vec(&env) {
                Ok(mut bytes) => {
                    bytes.push(b'\n');
                    if let Err(e) = file.write_all(&bytes).await {
                        record_failure(&failure_count, &failure_events);
                        warn!(
                            target: "vortix::journal",
                            path = %path.display(),
                            error = %e,
                            "journal write failed"
                        );
                    } else if let Err(e) = file.flush().await {
                        record_failure(&failure_count, &failure_events);
                        warn!(target: "vortix::journal", error = %e, "journal flush failed");
                    }
                }
                Err(e) => {
                    record_failure(&failure_count, &failure_events);
                    warn!(
                        target: "vortix::journal",
                        error = %e,
                        "failed to serialise journal record"
                    );
                }
            }

            // 2. Broadcast (lossy — fine if no subscribers).
            let _ = bcast_tx.send(env.clone());

            // 3. Tail buffer.
            tail.lock().unwrap().push(env);
        }
    }

    fn record_failure(count: &AtomicU64, events: &watch::Sender<u64>) {
        let next = count.fetch_add(1, Ordering::AcqRel).saturating_add(1);
        events.send_replace(next);
    }

    /// Disk-disabled writer. Same fan-out minus the file.
    pub(crate) async fn run_in_memory(
        mut mpsc_rx: mpsc::Receiver<EventEnvelope>,
        bcast_tx: broadcast::Sender<EventEnvelope>,
        tail: Arc<Mutex<TailBuffer>>,
    ) {
        while let Some(env) = mpsc_rx.recv().await {
            let _ = bcast_tx.send(env.clone());
            tail.lock().unwrap().push(env);
        }
    }
}

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{broadcast, mpsc, watch};

use serde::{Deserialize, Serialize};

use crate::profile::ProfileId;
use crate::tunnel::ConnectionHealth;

pub const SCHEMA_VERSION: u32 = 2;

/// One line in the session journal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum JournalEvent {
    /// Something the engine told the user.
    Notice {
        level: String,
        text: String,
    },
    IpChanged {
        old: Option<String>,
        new: String,
    },
    ConnectionHealthChanged {
        profile_id: ProfileId,
        old: ConnectionHealth,
        new: ConnectionHealth,
    },
    JournalRetentionApplied {
        deleted: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub schema_version: u32,
    pub timestamp: std::time::SystemTime,
    pub event: JournalEvent,
}

impl EventEnvelope {
    #[must_use]
    pub fn new(event: JournalEvent) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            timestamp: std::time::SystemTime::now(),
            event,
        }
    }
}

pub use retention::RetentionStats;

/// Default retention bounds matching the brainstorm: 30 days *or* 30 files,
/// whichever prunes more.
pub const DEFAULT_RETENTION_DAYS: u32 = 30;
pub const DEFAULT_RETENTION_COUNT: u32 = 30;
pub const DEFAULT_BROADCAST_CAPACITY: usize = 1024;
pub const DEFAULT_TAIL_BUFFER_CAPACITY: usize = 1000;
pub const DEFAULT_WRITER_CAPACITY: usize = 256;

// ───────────────────────────────────────────────────────────────────────────
// Process-global journal — installed by `main.rs`, read by bug-report and
// future EngineHandle integrations.
// ───────────────────────────────────────────────────────────────────────────

static GLOBAL_JOURNAL: std::sync::OnceLock<Journal> = std::sync::OnceLock::new();

/// Install the process-wide journal. First call wins.
pub fn set_global_journal(journal: Journal) {
    let _ = GLOBAL_JOURNAL.set(journal);
}

/// Get the process-wide journal, if installed.
#[must_use]
pub fn global_journal() -> Option<&'static Journal> {
    GLOBAL_JOURNAL.get()
}

/// Journal configuration knobs.
#[derive(Debug, Clone)]
pub struct JournalConfig {
    /// When `false`, the writer task is not spawned. Events still flow through
    /// the broadcast channel and the in-memory tail buffer.
    pub disk: bool,
    /// Files older than this are pruned at startup.
    pub retention_days: u32,
    /// At most this many session files are retained.
    pub retention_count: u32,
    /// Directory holding session files; the app passes
    /// `<config_dir>/sessions`. Falls back to `${XDG_DATA_HOME}/vortix/sessions/`.
    pub journal_dir: Option<PathBuf>,
    /// Capacity of the in-memory tail buffer.
    pub tail_capacity: usize,
    /// Capacity of the broadcast channel.
    pub broadcast_capacity: usize,
    /// Bounded writer queue. Saturation is returned to the producer and
    /// counted; records are never silently accepted and lost.
    pub writer_capacity: usize,
}

impl Default for JournalConfig {
    fn default() -> Self {
        Self {
            disk: true,
            retention_days: DEFAULT_RETENTION_DAYS,
            retention_count: DEFAULT_RETENTION_COUNT,
            journal_dir: None,
            tail_capacity: DEFAULT_TAIL_BUFFER_CAPACITY,
            broadcast_capacity: DEFAULT_BROADCAST_CAPACITY,
            writer_capacity: DEFAULT_WRITER_CAPACITY,
        }
    }
}

/// Handle a producer (`Engine`) uses to enqueue events; consumers subscribe
/// via [`Journal::subscribe`] / [`Journal::tail`].
///
/// Cheap to clone; all clones share the same broadcast / writer.
#[derive(Clone)]
pub struct Journal {
    sender: mpsc::Sender<EventEnvelope>,
    broadcaster: broadcast::Sender<EventEnvelope>,
    tail: Arc<Mutex<TailBuffer>>,
    /// `Some(path)` when disk persistence is active.
    pub session_path: Option<PathBuf>,
    overflow_count: Arc<AtomicU64>,
    writer_failure_count: Arc<AtomicU64>,
    writer_failure_events: watch::Receiver<u64>,
}

impl std::fmt::Debug for Journal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Journal")
            .field("session_path", &self.session_path)
            .field("subscribers", &self.broadcaster.receiver_count())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct TailBuffer {
    capacity: usize,
    items: std::collections::VecDeque<EventEnvelope>,
}

impl TailBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            items: std::collections::VecDeque::with_capacity(capacity),
        }
    }

    fn push(&mut self, env: EventEnvelope) {
        if self.items.len() == self.capacity {
            self.items.pop_front();
        }
        self.items.push_back(env);
    }

    fn snapshot(&self) -> Vec<EventEnvelope> {
        self.items.iter().cloned().collect()
    }
}

impl Journal {
    /// Construct a journal: spawn the writer task (when `disk = true`),
    /// run the retention pass, and emit `JournalRetentionApplied` as the
    /// first event of the new session.
    ///
    /// # Errors
    ///
    /// Returns `std::io::Error` if the session directory cannot be created.
    ///
    /// # Panics
    ///
    /// Panics only via an internal invariant marker — `journal_dir` is set
    /// when `config.disk` is true.
    #[allow(clippy::needless_pass_by_value)] // borrows would force callers to keep the config alive
    pub fn open(config: JournalConfig) -> std::io::Result<Self> {
        if config.writer_capacity == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "journal writer capacity must be non-zero",
            ));
        }
        let (mpsc_tx, mpsc_rx) = mpsc::channel::<EventEnvelope>(config.writer_capacity);
        let (bcast_tx, _) = broadcast::channel::<EventEnvelope>(config.broadcast_capacity);
        let tail = Arc::new(Mutex::new(TailBuffer::new(config.tail_capacity)));
        let writer_failure_count = Arc::new(AtomicU64::new(0));
        let (writer_failure_tx, writer_failure_events) = watch::channel(0);

        let mut session_path = None;

        // Resolve session directory (only matters when disk = true).
        let journal_dir = if config.disk {
            let dir = match config.journal_dir.clone() {
                Some(d) => d,
                None => default_journal_dir()?,
            };
            // Session journals record what was connected and when. Left at
            // the caller's umask these were 0775 on Debian derivatives, whose
            // default is 002 — parent included.
            crate::config::owned_file::create_user_dir(&dir)?;
            Some(dir)
        } else {
            None
        };

        // Retention runs synchronously at startup so the first journal event
        // can record what was pruned.
        let retention_stats = if let Some(dir) = &journal_dir {
            retention::prune(dir, config.retention_days, config.retention_count).unwrap_or_default()
        } else {
            RetentionStats::default()
        };

        if config.disk {
            let dir = journal_dir.expect("journal_dir resolved when disk=true");
            let pid = std::process::id();
            let stamp = iso_timestamp();
            let path = dir.join(format!("{stamp}-{pid}.jsonl"));
            session_path = Some(path.clone());

            // Spawn the writer task. It owns the mpsc receiver, the broadcast
            // sender, and the tail buffer — every accepted event reaches all
            // three sinks.
            tokio::spawn(writer::run(
                path,
                mpsc_rx,
                bcast_tx.clone(),
                Arc::clone(&tail),
                Arc::clone(&writer_failure_count),
                writer_failure_tx,
            ));
        } else {
            // Disk-disabled mode: still drain the mpsc into broadcast + tail.
            let bcast_for_task = bcast_tx.clone();
            let tail_for_task = Arc::clone(&tail);
            tokio::spawn(writer::run_in_memory(
                mpsc_rx,
                bcast_for_task,
                tail_for_task,
            ));
        }

        let journal = Self {
            sender: mpsc_tx,
            broadcaster: bcast_tx,
            tail,
            session_path,
            overflow_count: Arc::new(AtomicU64::new(0)),
            writer_failure_count,
            writer_failure_events,
        };

        // Emit the retention-applied event as the first record of the new
        // session.
        let _ = journal.append(JournalEvent::JournalRetentionApplied {
            deleted: retention_stats.deleted,
        });

        Ok(journal)
    }

    /// Enqueue an event for the journal. Saturation and writer termination are
    /// explicit errors; an accepted record is never silently discarded.
    pub fn append(&self, event: JournalEvent) -> Result<(), JournalError> {
        let env = EventEnvelope::new(event);
        self.sender.try_send(env).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => {
                self.overflow_count.fetch_add(1, Ordering::AcqRel);
                JournalError::Saturated
            }
            mpsc::error::TrySendError::Closed(_) => JournalError::WriterGone,
        })
    }

    /// Subscribe to live events. New subscribers receive only events emitted
    /// after `subscribe()` returns — combine with [`Self::tail`] for a
    /// catch-up window.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<EventEnvelope> {
        self.broadcaster.subscribe()
    }

    /// Snapshot the in-memory tail buffer, oldest first.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (unreachable in normal use).
    #[must_use]
    pub fn tail(&self) -> Vec<EventEnvelope> {
        self.tail.lock().unwrap().snapshot()
    }

    /// Number of records rejected due to bounded-queue saturation.
    #[must_use]
    pub fn overflow_count(&self) -> u64 {
        self.overflow_count.load(Ordering::Acquire)
    }

    /// Number of disk-open, serialization, write, or flush failures observed
    /// by the asynchronous writer.
    #[must_use]
    pub fn writer_failure_count(&self) -> u64 {
        self.writer_failure_count.load(Ordering::Acquire)
    }

    /// Wait until the disk writer reports its first asynchronous failure.
    ///
    /// This is an acknowledgment primitive for diagnostics and shutdown
    /// checks; event producers remain bounded and nonblocking.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::WriterGone`] if the writer closes without
    /// publishing a failure receipt.
    pub async fn wait_for_writer_failure(&self) -> Result<u64, JournalError> {
        let current = self.writer_failure_count();
        if current > 0 {
            return Ok(current);
        }
        let mut events = self.writer_failure_events.clone();
        events
            .changed()
            .await
            .map_err(|_| JournalError::WriterGone)?;
        let count = *events.borrow_and_update();
        if count == 0 {
            Err(JournalError::WriterGone)
        } else {
            Ok(count)
        }
    }

    /// Returns the per-session identifier — the `{ISO-timestamp}-{pid}` stem of
    /// the session log filename. `None` when journal disk persistence is
    /// disabled (no session file exists).
    ///
    /// Used to namespace per-session scratch directories (for example,
    /// `WireGuard` managed configs). Liveness is established separately by a
    /// process-held lease; distinct session names may legitimately coexist.
    #[must_use]
    pub fn session_id(&self) -> Option<String> {
        self.session_path
            .as_ref()
            .and_then(|p| p.file_stem())
            .and_then(|s| s.to_str())
            .map(std::string::ToString::to_string)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("journal writer queue is saturated; event was not accepted")]
    Saturated,
    #[error("journal writer task has terminated")]
    WriterGone,
}

fn default_journal_dir() -> std::io::Result<PathBuf> {
    use directories::ProjectDirs;
    let pd = ProjectDirs::from("", "", "vortix")
        .ok_or_else(|| std::io::Error::other("could not resolve XDG data dir"))?;
    Ok(pd.data_dir().join("sessions"))
}

fn iso_timestamp() -> String {
    use time::format_description::well_known::Iso8601;
    let now = time::OffsetDateTime::now_utc();
    now.format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "unknown".to_string())
        // Filenames with `:` are awkward on some filesystems.
        .replace(':', "")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> JournalEvent {
        JournalEvent::Notice {
            level: "info".into(),
            text: "Connected 'wg0'".into(),
        }
    }

    #[tokio::test]
    async fn disk_mode_writes_jsonl() {
        let tmp = tempfile::tempdir().unwrap();
        let journal = Journal::open(JournalConfig {
            disk: true,
            journal_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        })
        .unwrap();

        for _ in 0..5 {
            journal.append(sample_event()).unwrap();
        }

        // The tail is updated only after each record has been written and
        // flushed, so it is the deterministic completion signal for this
        // asynchronous writer.
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while journal.tail().len() < 6 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("journal writer should flush all accepted records");

        let path = journal.session_path.clone().expect("session path");
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        // 1 retention event + 5 sample events.
        assert_eq!(lines.len(), 6);
        for line in &lines {
            let _: EventEnvelope = serde_json::from_str(line).expect("each line is valid JSON");
        }
    }

    #[tokio::test]
    async fn disk_disabled_mode_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let journal = Journal::open(JournalConfig {
            disk: false,
            journal_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        })
        .unwrap();

        journal.append(sample_event()).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert!(journal.session_path.is_none());
        assert!(
            std::fs::read_dir(tmp.path()).unwrap().next().is_none(),
            "no files should have been written"
        );

        // But tail and subscribe still work.
        let tail = journal.tail();
        // First entry is the retention event; second is our sample.
        assert!(!tail.is_empty());
    }

    #[tokio::test]
    async fn subscribe_receives_events() {
        let tmp = tempfile::tempdir().unwrap();
        let journal = Journal::open(JournalConfig {
            disk: false,
            journal_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        })
        .unwrap();

        // Subscribe before appending. The retention event emitted by open()
        // may or may not have flushed through the writer task by now, so we
        // drain everything we see and assert the notice eventually appears.
        let mut rx = journal.subscribe();

        journal.append(sample_event()).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut saw_tunnel_up = false;
        while let Ok(env) = rx.try_recv() {
            if matches!(env.event, JournalEvent::Notice { .. }) {
                saw_tunnel_up = true;
            }
        }
        assert!(saw_tunnel_up, "subscriber should have received the notice");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bounded_writer_reports_saturation_without_silent_loss() {
        let journal = Journal::open(JournalConfig {
            disk: false,
            writer_capacity: 1,
            ..Default::default()
        })
        .unwrap();

        // `open` synchronously accepts the retention event before this
        // current-thread runtime lets the writer drain its sole queue slot.
        assert!(matches!(
            journal.append(sample_event()),
            Err(JournalError::Saturated)
        ));
        assert_eq!(journal.overflow_count(), 1);

        tokio::task::yield_now().await;
        journal
            .append(sample_event())
            .expect("writer drained after yielding");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn writer_open_failure_closes_transport_and_reports_loss() {
        let tmp = tempfile::tempdir().unwrap();
        let journal_dir = tmp.path().join("journal");
        let journal = Journal::open(JournalConfig {
            disk: true,
            journal_dir: Some(journal_dir.clone()),
            ..Default::default()
        })
        .unwrap();

        // The current-thread writer has not run yet. Removing its parent
        // deterministically injects an asynchronous open failure.
        std::fs::remove_dir_all(journal_dir).unwrap();
        assert_eq!(journal.wait_for_writer_failure().await.unwrap(), 1);
        assert!(matches!(
            journal.append(sample_event()),
            Err(JournalError::WriterGone)
        ));
    }
}
