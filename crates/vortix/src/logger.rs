//! Centralized production-level logging system for Vortix.
//!
//! Provides thread-safe logging with multiple levels, color coding,
//! and integration with the TUI system.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::SystemTime;

use crate::constants;
use std::path::Path;
use time::OffsetDateTime;

/// Log severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Verbose debugging information (only for development)
    Debug = 0,
    /// Informational messages about normal operation
    Info = 1,
    /// Warning messages about potential issues
    Warning = 2,
    /// Error messages about failures
    Error = 3,
}

impl LogLevel {
    /// Get the prefix string for this log level
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO ",
            Self::Warning => "WARN ",
            Self::Error => "ERROR",
        }
    }
}

/// A single log entry
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: SystemTime,
    pub level: LogLevel,
    pub category: String,
    pub message: String,
}

impl LogEntry {
    /// Format the log entry as a structured line:
    /// `[HH:MM:SS] [LEVEL] CATEGORY: message`
    #[must_use]
    pub fn format(&self) -> String {
        let time_str = crate::ui::helpers::format_system_time_local(self.timestamp);
        format!(
            "[{}] [{}] {}: {}",
            time_str,
            self.level.prefix(),
            self.category,
            self.message
        )
    }
}

/// Global logger instance
pub struct Logger {
    entries: VecDeque<LogEntry>,
    max_entries: usize,
    min_level: LogLevel,
}

impl Logger {
    fn new() -> Self {
        let max = constants::DEFAULT_MAX_LOG_ENTRIES;
        Self {
            entries: VecDeque::with_capacity(max),
            max_entries: max,
            min_level: LogLevel::Info, // Default: show Info and above
        }
    }

    /// Add a log entry
    fn log(&mut self, level: LogLevel, category: &str, message: String) {
        // Filter by minimum level
        if level < self.min_level {
            return;
        }

        let entry = LogEntry {
            timestamp: SystemTime::now(),
            level,
            category: category.to_string(),
            message,
        };

        self.entries.push_back(entry);

        // Keep only the configured maximum number of entries
        while self.entries.len() > self.max_entries {
            self.entries.pop_front();
        }
    }

    /// Get all log entries
    fn get_entries(&self) -> Vec<LogEntry> {
        self.entries.iter().cloned().collect()
    }

    /// Set minimum log level
    fn set_min_level(&mut self, level: LogLevel) {
        self.min_level = level;
    }

    /// Set maximum number of log entries
    fn set_max_entries(&mut self, max: usize) {
        self.max_entries = max;
        while self.entries.len() > self.max_entries {
            self.entries.pop_front();
        }
    }

    /// Clear all log entries
    fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Global logger instance (thread-safe)
static LOGGER: std::sync::OnceLock<Mutex<Logger>> = std::sync::OnceLock::new();

/// Get the global logger instance, initializing if needed
fn get_logger() -> &'static Mutex<Logger> {
    LOGGER.get_or_init(|| Mutex::new(Logger::new()))
}

/// Log a message with the specified level and category
pub fn log(level: LogLevel, category: &str, message: impl Into<String>) {
    if let Ok(mut logger) = get_logger().lock() {
        logger.log(level, category, message.into());
    }
}

/// Get all log entries (for display in TUI)
#[must_use]
pub fn get_logs() -> Vec<LogEntry> {
    get_logger()
        .lock()
        .map(|logger| logger.get_entries())
        .unwrap_or_default()
}

/// Configure the logger from user settings.
///
/// Call once at startup after loading `AppConfig`.
/// - `log_level`: one of `"debug"`, `"info"`, `"warning"`, `"error"` (case-insensitive).
/// - `max_entries`: maximum number of log entries to keep in memory.
pub fn configure(log_level: &str, max_entries: usize) {
    if let Ok(mut logger) = get_logger().lock() {
        logger.set_min_level(parse_log_level(log_level));
        logger.set_max_entries(max_entries);
    }
}

/// Set the minimum log level (for filtering).
pub fn set_min_level(level: LogLevel) {
    if let Ok(mut logger) = get_logger().lock() {
        logger.set_min_level(level);
    }
}

/// Parse a log level string (case-insensitive) into a `LogLevel`.
///
/// Falls back to `LogLevel::Info` for unrecognised values.
#[must_use]
pub fn parse_log_level(s: &str) -> LogLevel {
    match s.trim().to_ascii_lowercase().as_str() {
        "debug" => LogLevel::Debug,
        "warning" | "warn" => LogLevel::Warning,
        "error" | "err" => LogLevel::Error,
        // "info" and anything unrecognized → Info
        _ => LogLevel::Info,
    }
}

/// Clear all logs
pub fn clear_logs() {
    if let Ok(mut logger) = get_logger().lock() {
        logger.clear();
    }
}

// Convenience macros for easy logging
#[macro_export]
macro_rules! log_debug {
    ($category:expr, $($arg:tt)*) => {
        $crate::logger::log($crate::logger::LogLevel::Debug, $category, format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_info {
    ($category:expr, $($arg:tt)*) => {
        $crate::logger::log($crate::logger::LogLevel::Info, $category, format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_warning {
    ($category:expr, $($arg:tt)*) => {
        $crate::logger::log($crate::logger::LogLevel::Warning, $category, format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_error {
    ($category:expr, $($arg:tt)*) => {
        $crate::logger::log($crate::logger::LogLevel::Error, $category, format!($($arg)*))
    };
}

/// Append log entry to file with automatic rotation
pub(crate) fn append_to_file(
    entries: &[String],
    config_dir: &std::path::Path,
    rotation_size: u64,
    retention_days: u64,
) {
    static CLEANUP_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    use std::io::Write;

    if entries.is_empty() {
        return;
    }
    let log_dir = config_dir.join(constants::LOGS_DIR_NAME);

    // Create log directory if needed
    if crate::config::owned_file::create_user_dir(&log_dir).is_err() {
        return;
    }

    // Use date-based log file
    let today = OffsetDateTime::now_local()
        .unwrap_or_else(|_| OffsetDateTime::now_utc())
        .date();
    let log_file = log_dir.join(format!("vortix-{today}.log"));

    let mut current_len = std::fs::metadata(&log_file).map_or(0, |metadata| metadata.len());
    let mut file = None;
    for entry in entries {
        let encoded_len = u64::try_from(entry.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        if current_len > 0 && current_len.saturating_add(encoded_len) > rotation_size {
            drop(file.take());
            rotate_log_file(&log_file, &log_dir, today);
            current_len = 0;
        }
        if file.is_none() {
            let is_new = !log_file.exists();
            file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_file)
                .ok();
            if is_new && file.is_some() {
                crate::config::fix_ownership(&log_file);
            }
        }
        let Some(writer) = file.as_mut() else {
            break;
        };
        if writeln!(writer, "{entry}").is_err() {
            break;
        }
        current_len = current_len.saturating_add(encoded_len);
    }

    // Clean up old logs periodically
    let added = u32::try_from(entries.len()).unwrap_or(u32::MAX);
    let count = CLEANUP_COUNTER.fetch_add(added, std::sync::atomic::Ordering::Relaxed);
    let last = count.saturating_add(added.saturating_sub(1));
    if count % constants::LOG_CLEANUP_INTERVAL == 0
        || count / constants::LOG_CLEANUP_INTERVAL != last / constants::LOG_CLEANUP_INTERVAL
    {
        cleanup_old_logs(&log_dir, retention_days);
    }
}

fn rotate_log_file(log_file: &Path, log_dir: &Path, today: time::Date) {
    if !log_file.exists() {
        return;
    }
    let rotated = (1_u32..=u32::from(u16::MAX))
        .map(|suffix| log_dir.join(format!("vortix-{today}.{suffix}.log")))
        .find(|candidate| !candidate.exists());
    if let Some(rotated) = rotated {
        let _ = std::fs::rename(log_file, rotated);
    }
}

/// Remove log files older than `retention_days` days.
fn cleanup_old_logs(log_dir: &Path, retention_days: u64) {
    use std::time::{Duration, SystemTime};

    let max_age = Duration::from_secs(retention_days * 24 * 60 * 60);
    let cutoff = SystemTime::now()
        .checked_sub(max_age)
        .unwrap_or(SystemTime::UNIX_EPOCH);

    if let Ok(entries) = std::fs::read_dir(log_dir) {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if let Ok(modified) = metadata.modified() {
                    if modified < cutoff {
                        let _ = std::fs::remove_file(entry.path());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Logger tests must run serially because they share global state.
    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_logging() {
        let _lock = TEST_MUTEX.lock().unwrap();
        clear_logs();

        log(LogLevel::Info, "TEST", "Test message");

        let logs = get_logs();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].category, "TEST");
        assert_eq!(logs[0].message, "Test message");
    }

    #[test]
    fn test_log_level_filtering() {
        let _lock = TEST_MUTEX.lock().unwrap();
        clear_logs();
        set_min_level(LogLevel::Warning);

        log(LogLevel::Debug, "TEST", "Debug");
        log(LogLevel::Info, "TEST", "Info");
        log(LogLevel::Warning, "TEST", "Warning");
        log(LogLevel::Error, "TEST", "Error");

        let logs = get_logs();
        assert_eq!(logs.len(), 2); // Only Warning and Error

        // Reset to default
        set_min_level(LogLevel::Debug);
    }

    #[test]
    fn test_max_entries() {
        let _lock = TEST_MUTEX.lock().unwrap();
        clear_logs();

        for i in 0..1500 {
            log(LogLevel::Info, "TEST", format!("Message {i}"));
        }

        let logs = get_logs();
        assert!(logs.len() <= constants::DEFAULT_MAX_LOG_ENTRIES);
    }
}
