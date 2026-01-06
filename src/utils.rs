//! Utility functions for formatting and path management.
//!
//! This module provides helper functions for common operations like
//! formatting byte rates, durations, and managing configuration directories.

use std::process::Command;

/// Check if the current process is running as root (UID 0)
///
/// Uses the effective user ID from the OS instead of spawning an external command.
/// This avoids silent failures if `id` is unavailable or fails.
#[must_use]
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn is_root() -> bool {
    // SAFETY: geteuid() is a simple syscall that returns the effective user ID.
    // It has no side effects and always succeeds.
    unsafe { libc::geteuid() == 0 }
}

/// Check if the current process is running as root (UID 0)
///
/// On non-Unix platforms, this always returns `false` because there is no
/// portable concept of a root user.
#[must_use]
#[cfg(not(unix))]
pub fn is_root() -> bool {
    false
}

/// Formats bytes per second into a human-readable string.
///
/// # Arguments
///
/// * `bytes` - Number of bytes per second
///
/// # Returns
///
/// A formatted string with appropriate units (B/s, KB/s, or MB/s).
///
/// # Example
///
/// ```ignore
/// assert_eq!(format_bytes_speed(1_500_000), "1.5 MB/s");
/// assert_eq!(format_bytes_speed(1_500), "1.5 KB/s");
/// ```
pub fn format_bytes_speed(bytes: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    if bytes >= 1_000_000 {
        format!("{:.1} MB/s", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1} KB/s", bytes as f64 / 1_000.0)
    } else {
        format!("{bytes} B/s")
    }
}

/// Checks if an IP address belongs to a private network range (RFC1918).
///
/// # Arguments
///
/// * `ip` - The IP address to check
///
/// # Returns
///
/// `true` if the IP is in a private range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
pub fn is_private_ip(ip: &str) -> bool {
    // Parse IP octets
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    let octets: Result<Vec<u8>, _> = parts.iter().map(|p| p.parse::<u8>()).collect();
    let Ok(octets) = octets else {
        return false;
    };

    // Check private ranges
    match octets[0] {
        10 => true,                                    // 10.0.0.0/8
        172 if (16..=31).contains(&octets[1]) => true, // 172.16.0.0/12
        192 if octets[1] == 168 => true,               // 192.168.0.0/16
        _ => false,
    }
}

/// Returns the application configuration directory path.
///
/// Creates the directory at `~/.config/vortix` if it doesn't exist.
///
/// # Errors
///
/// Returns an error if the home directory cannot be determined or
/// if directory creation fails.
pub fn get_app_config_dir() -> std::io::Result<std::path::PathBuf> {
    let home = home_dir().ok_or(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "Home directory not found",
    ))?;
    let path = home.join(".config").join(crate::constants::APP_NAME);

    if !path.exists() {
        std::fs::create_dir_all(&path)?;
    }

    Ok(path)
}

/// Returns the VPN profiles directory path.
///
/// Creates the directory at `~/.config/vortix/profiles` if it doesn't exist.
///
/// # Errors
///
/// Returns an error if directory creation fails.
pub fn get_profiles_dir() -> std::io::Result<std::path::PathBuf> {
    let root = get_app_config_dir()?;
    let path = root.join(crate::constants::PROFILES_DIR_NAME);

    if !path.exists() {
        std::fs::create_dir_all(&path)?;
    }

    Ok(path)
}

/// Truncates a string to a maximum number of characters.
///
/// If the string exceeds `max_chars`, it is truncated and "..." is appended.
///
/// # Arguments
///
/// * `s` - The string to truncate
/// * `max_chars` - Maximum number of characters (including ellipsis)
pub fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() > max_chars {
        let mut t: String = s.chars().take(max_chars.saturating_sub(3)).collect();
        t.push_str("...");
        t
    } else {
        s.to_string()
    }
}

/// Returns the current local time formatted as HH:MM:SS.
///
/// Uses `std::process` to call `date` command for local time formatting.
pub fn format_local_time() -> String {
    Command::new("date").arg("+%H:%M:%S").output().map_or_else(
        |_| "00:00:00".to_string(),
        |o| String::from_utf8_lossy(&o.stdout).trim().to_string(),
    )
}

/// Formats a `SystemTime` into a compact relative time string (e.g., 1s, 2m, 3h, 4d).
pub fn format_relative_time(time: std::time::SystemTime) -> String {
    let now = std::time::SystemTime::now();
    match now.duration_since(time) {
        Ok(duration) => {
            let secs = duration.as_secs();
            if secs < 60 {
                format!("{secs}s")
            } else if secs < 3600 {
                format!("{}m", secs / 60)
            } else if secs < 86400 {
                format!("{}h", secs / 3600)
            } else if secs < 2_592_000 {
                // 30 days
                format!("{}d ago", secs / 86400)
            } else if secs < 31_536_000 {
                // 365 days
                format!("{}M ago", secs / 2_592_000)
            } else {
                format!("{}Y ago", secs / 31_536_000)
            }
        }
        Err(_) => "now".to_string(),
    }
}

/// Returns the user's home directory.
///
/// Uses the HOME environment variable on Unix systems.
pub fn home_dir() -> Option<std::path::PathBuf> {
    std::env::var("HOME").ok().map(std::path::PathBuf::from)
}

/// Profile metadata for persistence
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ProfileMetadata {
    #[serde(
        with = "systemtime_serde",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub last_used: Option<std::time::SystemTime>,
}

mod systemtime_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[allow(clippy::ref_option)]
    pub fn serialize<S>(time: &Option<SystemTime>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match time {
            Some(t) => {
                let duration = t
                    .duration_since(UNIX_EPOCH)
                    .map_err(serde::ser::Error::custom)?;
                duration.as_secs().serialize(serializer)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<SystemTime>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs: Option<u64> = Option::deserialize(deserializer)?;
        Ok(secs.map(|s| UNIX_EPOCH + std::time::Duration::from_secs(s)))
    }
}

/// Load profile metadata from disk
pub fn load_profile_metadata() -> Result<std::collections::HashMap<String, ProfileMetadata>, String>
{
    let metadata_path = get_app_config_dir()
        .map_err(|e| format!("Failed to get config dir: {e}"))?
        .join("metadata.json");

    if !metadata_path.exists() {
        return Ok(std::collections::HashMap::new());
    }

    let content = std::fs::read_to_string(&metadata_path)
        .map_err(|e| format!("Failed to read metadata: {e}"))?;

    serde_json::from_str(&content).or_else(|e| {
        crate::logger::log(
            crate::logger::LogLevel::Warning,
            "CONFIG",
            format!(
                "Failed to parse {}: {}. Using defaults.",
                crate::constants::METADATA_FILE_NAME,
                e
            ),
        );
        Ok(std::collections::HashMap::new())
    })
}

/// Save profile metadata to disk
pub fn save_profile_metadata(
    data: &std::collections::HashMap<String, ProfileMetadata>,
) -> Result<(), String> {
    let metadata_path = get_app_config_dir()
        .map_err(|e| format!("Failed to get config dir: {e}"))?
        .join("metadata.json");

    let json = serde_json::to_string_pretty(data)
        .map_err(|e| format!("Failed to serialize metadata: {e}"))?;

    std::fs::write(&metadata_path, json).map_err(|e| format!("Failed to write metadata: {e}"))?;

    Ok(())
}

/// Returns a unique path by appending (n) if the file already exists.
///
/// # Arguments
///
/// * `dir` - Directory to check in
/// * `filename` - Desired filename
///
/// # Returns
///
/// A `PathBuf` that does not currently exist.
pub fn get_unique_path(dir: &std::path::Path, filename: &str) -> std::path::PathBuf {
    let mut path = dir.join(filename);
    let mut counter = 1;

    let path_obj = std::path::Path::new(filename);
    let stem = path_obj
        .file_stem()
        .map_or(filename, |s| s.to_str().unwrap_or(filename));
    let ext = path_obj.extension().map(|e| e.to_str().unwrap_or(""));

    while path.exists() {
        let new_name = if let Some(e) = ext {
            if e.is_empty() {
                format!("{stem}({counter})")
            } else {
                format!("{stem}({counter}).{e}")
            }
        } else {
            format!("{stem}({counter})")
        };
        path = dir.join(new_name);
        counter += 1;
    }

    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn test_format_bytes_speed_bytes() {
        assert_eq!(format_bytes_speed(0), "0 B/s");
        assert_eq!(format_bytes_speed(500), "500 B/s");
        assert_eq!(format_bytes_speed(999), "999 B/s");
    }

    #[test]
    fn test_format_bytes_speed_kilobytes() {
        assert_eq!(format_bytes_speed(1_000), "1.0 KB/s");
        assert_eq!(format_bytes_speed(1_500), "1.5 KB/s");
        assert_eq!(format_bytes_speed(999_999), "1000.0 KB/s");
    }

    #[test]
    fn test_format_bytes_speed_megabytes() {
        assert_eq!(format_bytes_speed(1_000_000), "1.0 MB/s");
        assert_eq!(format_bytes_speed(1_500_000), "1.5 MB/s");
        assert_eq!(format_bytes_speed(100_000_000), "100.0 MB/s");
    }

    #[test]
    fn test_truncate_short_string() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("test", 4), "test");
    }

    #[test]
    fn test_truncate_exact_length() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_long_string() {
        assert_eq!(truncate("hello world", 8), "hello...");
        assert_eq!(truncate("this is a long string", 10), "this is...");
    }

    #[test]
    fn test_truncate_with_unicode() {
        // Unicode characters should be counted correctly
        assert_eq!(truncate("héllo", 5), "héllo");
        assert_eq!(truncate("héllo world", 8), "héllo...");
    }

    #[test]
    fn test_home_dir_exists() {
        // On most systems, HOME should be set
        let home = home_dir();
        assert!(home.is_some());
        assert!(home.unwrap().exists());
    }

    #[test]
    fn test_format_relative_time() {
        let now = SystemTime::now();

        // Seconds
        let just_now = now - Duration::from_secs(5);
        assert_eq!(format_relative_time(just_now), "5s");

        // Minutes
        let five_mins = now - Duration::from_secs(300);
        assert_eq!(format_relative_time(five_mins), "5m");

        // Hours
        let two_hours = now - Duration::from_secs(7200);
        assert_eq!(format_relative_time(two_hours), "2h");

        // Days
        let three_days = now - Duration::from_secs(86400 * 3);
        assert_eq!(format_relative_time(three_days), "3d ago");

        // Months
        let two_months = now - Duration::from_secs(2_592_000 * 2);
        assert_eq!(format_relative_time(two_months), "2M ago");

        // Years
        let three_years = now - Duration::from_secs(31_536_000 * 3);
        assert_eq!(format_relative_time(three_years), "3Y ago");

        // Future or now
        let future = now + Duration::from_secs(10);
        assert_eq!(format_relative_time(future), "now");
    }

    #[test]
    fn test_is_private_ip_class_a() {
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("10.255.255.255"));
        assert!(is_private_ip("10.1.2.3"));
    }

    #[test]
    fn test_is_private_ip_class_b() {
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("172.31.255.255"));
        assert!(is_private_ip("172.20.10.5"));
    }

    #[test]
    fn test_is_private_ip_class_c() {
        assert!(is_private_ip("192.168.0.1"));
        assert!(is_private_ip("192.168.255.255"));
        assert!(is_private_ip("192.168.1.100"));
    }

    #[test]
    fn test_is_private_ip_public() {
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("1.2.3.4"));
        assert!(!is_private_ip("172.15.0.1")); // Just outside 172.16.0.0/12
        assert!(!is_private_ip("172.32.0.1")); // Just outside 172.16.0.0/12
        assert!(!is_private_ip("192.169.0.1")); // Not 192.168
    }

    #[test]
    fn test_is_private_ip_invalid() {
        assert!(!is_private_ip("999.999.999.999"));
        assert!(!is_private_ip("not.an.ip.address"));
        assert!(!is_private_ip("10.0.0"));
        assert!(!is_private_ip(""));
    }
}
