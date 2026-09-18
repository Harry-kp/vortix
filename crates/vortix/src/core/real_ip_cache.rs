//! Persisted real-IP cache — IPv4 + IPv6. Lets the Security Guard
//! populate the Real IPv4 / Real IPv6 rows on launch even when no
//! disconnected window has occurred in the current process.
//!
//! File format: `<ip>\n<unix-timestamp>\n`. Mode 0600 on Unix.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::constants::{REAL_IPV6_CACHE_FILE, REAL_IP_CACHE_FILE};

/// Cached real-IP record loaded from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedRealIp {
    /// The IP address as a string. No parsing is done — the
    /// Security Guard treats it as opaque text.
    pub ip: String,
    /// Unix timestamp when the cache was written. `None` if the
    /// file existed in a legacy format without a timestamp line.
    pub captured_at: Option<u64>,
}

impl CachedRealIp {
    /// Whether this record was written within `max_age`.
    ///
    /// An untimestamped record and a record from the future both answer
    /// `false`: neither can be shown to be recent.
    #[must_use]
    pub fn is_newer_than(&self, max_age: Duration) -> bool {
        let Some(captured_at) = self.captured_at else {
            return false;
        };
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return false;
        };
        let now = now.as_secs();
        now >= captured_at && now - captured_at <= max_age.as_secs()
    }
}

#[must_use]
pub fn load(config_dir: &Path) -> Option<CachedRealIp> {
    load_from(config_dir, REAL_IP_CACHE_FILE)
}

/// Load the cached IPv4 only while it is recent enough to mean anything.
///
/// A record with no timestamp predates the timestamped format; its age is
/// unknowable, so it is not trusted.
#[must_use]
pub fn load_recent(config_dir: &Path, max_age: Duration) -> Option<CachedRealIp> {
    load(config_dir).filter(|cached| cached.is_newer_than(max_age))
}

/// Load the cached IPv6 only while it is recent enough to mean anything.
#[must_use]
pub fn load_recent_ipv6(config_dir: &Path, max_age: Duration) -> Option<CachedRealIp> {
    load_ipv6(config_dir).filter(|cached| cached.is_newer_than(max_age))
}

pub fn save(config_dir: &Path, ip: &str) {
    save_to(config_dir, REAL_IP_CACHE_FILE, ip);
}

#[must_use]
pub fn load_ipv6(config_dir: &Path) -> Option<CachedRealIp> {
    load_from(config_dir, REAL_IPV6_CACHE_FILE)
}

pub fn save_ipv6(config_dir: &Path, ip: &str) {
    save_to(config_dir, REAL_IPV6_CACHE_FILE, ip);
}

fn load_from(config_dir: &Path, file: &str) -> Option<CachedRealIp> {
    let path = config_dir.join(file);
    let content = std::fs::read_to_string(&path).ok()?;
    let mut lines = content.lines();
    let ip = lines.next()?.trim().to_string();
    if ip.is_empty() {
        return None;
    }
    let captured_at = lines.next().and_then(|s| s.trim().parse::<u64>().ok());
    Some(CachedRealIp { ip, captured_at })
}

fn save_to(config_dir: &Path, file: &str, ip: &str) {
    let trimmed = ip.trim();
    if trimmed.is_empty() {
        return;
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let content = format!("{trimmed}\n{ts}\n");
    let path = config_dir.join(file);

    // Best-effort create the parent dir; silently skip on failure
    // (a misconfigured config dir doesn't deserve a crash here).
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
        {
            let _ = f.write_all(content.as_bytes());
            let _ = f.flush();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::write(&path, content);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// Fresh per-test scratch dir under the OS temp root, so
    /// parallel `cargo test` runs don't stomp on each other.
    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = env::temp_dir().join(format!("vortix-real-ip-cache-{name}-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[test]
    fn save_then_load_round_trips_the_ip() {
        let dir = scratch_dir("roundtrip");
        save(&dir, "203.0.113.5");
        let loaded = load(&dir).expect("cache must load after save");
        assert_eq!(loaded.ip, "203.0.113.5");
        assert!(loaded.captured_at.is_some(), "timestamp must be written");
    }

    /// The timestamp is written for a reason: an address last seen a long
    /// time ago is not evidence about the network the host is on today.
    #[test]
    fn an_old_record_is_not_returned_as_recent() {
        let dir = scratch_dir("expiry");
        let path = dir.join(REAL_IP_CACHE_FILE);
        let two_days_ago = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 2 * 24 * 60 * 60;
        std::fs::write(&path, format!("203.0.113.5\n{two_days_ago}\n")).unwrap();

        assert!(
            load(&dir).is_some(),
            "the raw record is still readable on disk"
        );
        assert_eq!(
            load_recent(&dir, Duration::from_secs(24 * 60 * 60)),
            None,
            "a two-day-old address must not be offered as recent"
        );
        assert!(
            load_recent(&dir, Duration::from_secs(7 * 24 * 60 * 60)).is_some(),
            "a wider window must still accept it"
        );
    }

    /// A record from before the timestamped format has an unknowable age.
    #[test]
    fn an_untimestamped_record_is_never_recent() {
        let dir = scratch_dir("legacy");
        std::fs::write(dir.join(REAL_IP_CACHE_FILE), "203.0.113.5\n").unwrap();

        assert!(load(&dir).is_some());
        assert_eq!(load_recent(&dir, Duration::from_secs(24 * 60 * 60)), None);
    }

    #[test]
    fn a_just_written_record_is_recent() {
        let dir = scratch_dir("fresh");
        save(&dir, "203.0.113.5");
        save_ipv6(&dir, "2001:db8::1");
        let window = Duration::from_secs(60);

        assert_eq!(
            load_recent(&dir, window).map(|c| c.ip),
            Some("203.0.113.5".to_string())
        );
        assert_eq!(
            load_recent_ipv6(&dir, window).map(|c| c.ip),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn load_returns_none_when_file_is_absent() {
        let dir = scratch_dir("absent");
        assert!(load(&dir).is_none());
    }

    #[test]
    fn load_returns_none_for_empty_file() {
        let dir = scratch_dir("empty");
        std::fs::write(dir.join(REAL_IP_CACHE_FILE), "").unwrap();
        assert!(load(&dir).is_none());
    }

    #[test]
    fn load_handles_legacy_format_without_timestamp() {
        // A file written by an older version (or by a user) that
        // only contains the IP must still parse — timestamp is
        // optional metadata, not correctness.
        let dir = scratch_dir("legacy");
        std::fs::write(dir.join(REAL_IP_CACHE_FILE), "1.2.3.4\n").unwrap();
        let loaded = load(&dir).expect("must accept legacy single-line file");
        assert_eq!(loaded.ip, "1.2.3.4");
        assert!(loaded.captured_at.is_none());
    }

    #[test]
    fn save_overwrites_an_existing_cache() {
        let dir = scratch_dir("overwrite");
        save(&dir, "1.1.1.1");
        save(&dir, "2.2.2.2");
        let loaded = load(&dir).expect("cache must load");
        assert_eq!(loaded.ip, "2.2.2.2", "later save must replace earlier");
    }

    #[test]
    fn save_refuses_empty_or_whitespace_ip() {
        let dir = scratch_dir("empty-ip");
        save(&dir, "");
        save(&dir, "   ");
        assert!(load(&dir).is_none(), "empty saves must be no-ops");
    }

    #[cfg(unix)]
    #[test]
    fn save_sets_mode_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir("perms");
        save(&dir, "10.0.0.1");
        let meta = std::fs::metadata(dir.join(REAL_IP_CACHE_FILE)).expect("file exists");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "cache must be mode 0600, got {mode:o}");
    }
}
