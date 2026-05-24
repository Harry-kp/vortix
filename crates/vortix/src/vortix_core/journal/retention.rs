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
