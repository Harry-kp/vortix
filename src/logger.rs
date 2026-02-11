//! Centralized production-level logging system for Vortix.
//!
//! Provides thread-safe logging with multiple levels, color coding,
//! and integration with the TUI system.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::constants;

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

#[allow(dead_code)]
impl LogLevel {
    /// Get the prefix string for this log level
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO ",
            Self::Warning => "WARN ",
            Self::Error => "ERROR",
        }
    }

    /// Get the color for this log level (Nord theme)
    pub const fn color(self) -> ratatui::style::Color {
        use ratatui::style::Color;
        match self {
            Self::Debug => Color::DarkGray,
            Self::Info => Color::Cyan,
            Self::Warning => Color::Yellow,
            Self::Error => Color::Red,
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

#[allow(dead_code)]
impl LogEntry {
    /// Format the log entry as a structured line:
    /// `[HH:MM:SS] [LEVEL] CATEGORY: message`
    pub fn format(&self) -> String {
        let time_str = crate::utils::format_system_time_local(self.timestamp);
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
static LOGGER: std::sync::OnceLock<Arc<Mutex<Logger>>> = std::sync::OnceLock::new();

/// Get the global logger instance, initializing if needed
fn get_logger() -> &'static Arc<Mutex<Logger>> {
    LOGGER.get_or_init(|| Arc::new(Mutex::new(Logger::new())))
}

/// Log a message with the specified level and category
pub fn log(level: LogLevel, category: &str, message: impl Into<String>) {
    if let Ok(mut logger) = get_logger().lock() {
        logger.log(level, category, message.into());
    }
}

/// Get all log entries (for display in TUI)
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
#[allow(dead_code)]
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
