//! Engine event journal — JSONL persistence + broadcast channel (plan #005 U3).
//!
//! Two output paths in parallel:
//! - **Non-lossy mpsc to a writer task** that appends to
//!   `${XDG_DATA_HOME}/vortix/sessions/<ISO>-<pid>.jsonl`. Each line is one
//!   [`EventEnvelope`] serialised as JSON.
//! - **Lossy broadcast** (`tokio::sync::broadcast`, capacity 1024). Slow
//!   subscribers get `Lagged(N)`; they re-sync via [`Journal::tail`].
//!
//! Retention runs once at startup: delete files older than
//! `retention_days` AND beyond `retention_count` most-recent. The first
//! event of the new session is `JournalRetentionApplied { deleted }`.
//!
//! `[journal] disk = false` mode skips the writer task; events flow only
//! through the broadcast channel + the in-memory ring buffer.

mod retention;
mod writer;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::sync::{broadcast, mpsc};

use crate::vortix_core::engine::event::{EngineEvent, EventEnvelope};

pub use retention::RetentionStats;

/// Default retention bounds matching the brainstorm: 30 days *or* 30 files,
/// whichever prunes more.
pub const DEFAULT_RETENTION_DAYS: u32 = 30;
pub const DEFAULT_RETENTION_COUNT: u32 = 30;
pub const DEFAULT_BROADCAST_CAPACITY: usize = 1024;
pub const DEFAULT_TAIL_BUFFER_CAPACITY: usize = 1000;

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
    /// Directory holding session files. Falls back to
    /// `${XDG_DATA_HOME}/vortix/sessions/` when unset.
    pub journal_dir: Option<PathBuf>,
    /// Capacity of the in-memory tail buffer.
    pub tail_capacity: usize,
    /// Capacity of the broadcast channel.
    pub broadcast_capacity: usize,
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
        }
    }
}

/// Handle a producer (`Engine`) uses to enqueue events; consumers subscribe
/// via [`Journal::subscribe`] / [`Journal::tail`].
///
/// Cheap to clone; all clones share the same broadcast / writer.
#[derive(Clone)]
pub struct Journal {
    sender: mpsc::UnboundedSender<EventEnvelope>,
    broadcaster: broadcast::Sender<EventEnvelope>,
    tail: Arc<Mutex<TailBuffer>>,
    /// `Some(path)` when disk persistence is active.
    pub session_path: Option<PathBuf>,
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
        let (mpsc_tx, mpsc_rx) = mpsc::unbounded_channel::<EventEnvelope>();
        let (bcast_tx, _) = broadcast::channel::<EventEnvelope>(config.broadcast_capacity);
        let tail = Arc::new(Mutex::new(TailBuffer::new(config.tail_capacity)));

        let mut session_path = None;

        // Resolve session directory (only matters when disk = true).
        let journal_dir = if config.disk {
            let dir = match config.journal_dir.clone() {
                Some(d) => d,
                None => default_journal_dir()?,
            };
            std::fs::create_dir_all(&dir)?;
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
        };

        // Emit the retention-applied event as the first record of the new
        // session.
        let _ = journal.append(EngineEvent::JournalRetentionApplied {
            deleted: retention_stats.deleted,
        });

        Ok(journal)
    }

    /// Enqueue an event for the journal. Returns `Err` only if the writer
    /// task has terminated (typically only at shutdown).
    pub fn append(&self, event: EngineEvent) -> Result<(), JournalError> {
        let env = EventEnvelope::new(event);
        self.sender
            .send(env)
            .map_err(|_| JournalError::WriterGone)?;
        Ok(())
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

    /// Returns the per-session identifier — the `{ISO-timestamp}-{pid}` stem of
    /// the session log filename. `None` when journal disk persistence is
    /// disabled (no session file exists).
    ///
    /// Used by per-session scratch directories (e.g. `WireGuard` secondary
    /// temp configs — plan #009 U13) so that crash-orphaned subdirs can be
    /// distinguished from the live session purely by name: every process gets
    /// a unique `{pid}` component, so a non-matching subdir is unambiguously
    /// an orphan regardless of file age.
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
    use crate::vortix_core::engine::event::EngineEvent;
    use crate::vortix_core::profile::{ProfileId, ProtocolKind};

    fn sample_event() -> EngineEvent {
        EngineEvent::TunnelUp {
            profile_id: ProfileId::new("corp"),
            protocol: ProtocolKind::WireGuard,
            interface_name: "wg0".into(),
            pid: None,
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

        // Let the writer drain.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

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
        // drain everything we see and assert the TunnelUp eventually appears.
        let mut rx = journal.subscribe();

        journal.append(sample_event()).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut saw_tunnel_up = false;
        while let Ok(env) = rx.try_recv() {
            if matches!(env.event, EngineEvent::TunnelUp { .. }) {
                saw_tunnel_up = true;
            }
        }
        assert!(
            saw_tunnel_up,
            "subscriber should have received the TunnelUp event"
        );
    }
}
