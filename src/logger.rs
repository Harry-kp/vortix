//! Centralized production-level logging system for Vortix.
//!
//! Provides thread-safe logging with multiple levels, color coding,
//! and integration with the TUI system.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// Maximum number of log entries to keep in memory
const MAX_LOG_ENTRIES: usize = 1000;

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
    /// Format the log entry for display
    pub fn format(&self) -> String {
        let elapsed = self.timestamp.elapsed().map(|d| d.as_secs()).unwrap_or(0);

        let time_str = if elapsed < 60 {
            format!("{elapsed}s")
        } else if elapsed < 3600 {
            format!("{}m", elapsed / 60)
        } else {
            format!("{}h", elapsed / 3600)
        };

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
    min_level: LogLevel,
}

impl Logger {
    fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(MAX_LOG_ENTRIES),
            min_level: LogLevel::Debug, // Show all logs by default
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

        // Keep only MAX_LOG_ENTRIES most recent entries
        while self.entries.len() > MAX_LOG_ENTRIES {
            self.entries.pop_front();
        }
    }

    /// Get all log entries
    fn get_entries(&self) -> Vec<LogEntry> {
        self.entries.iter().cloned().collect()
    }

    /// Set minimum log level
    #[allow(dead_code)]
    fn set_min_level(&mut self, level: LogLevel) {
        self.min_level = level;
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

/// Set the minimum log level (for filtering)
#[allow(dead_code)]
pub fn set_min_level(level: LogLevel) {
    if let Ok(mut logger) = get_logger().lock() {
        logger.set_min_level(level);
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

    #[test]
    fn test_logging() {
        clear_logs();

        log(LogLevel::Info, "TEST", "Test message");

        let logs = get_logs();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].category, "TEST");
        assert_eq!(logs[0].message, "Test message");
    }

    #[test]
    fn test_log_level_filtering() {
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
        clear_logs();

        for i in 0..1500 {
            log(LogLevel::Info, "TEST", format!("Message {}", i));
        }

        let logs = get_logs();
        assert!(logs.len() <= MAX_LOG_ENTRIES);
    }
}
