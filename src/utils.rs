//! Utility functions for formatting and path management.
//!
//! This module provides helper functions for common operations like
//! formatting byte rates, durations, and managing configuration directories.

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

/// Run a system command with a timeout.
///
/// Spawns the command and polls for completion. If the command doesn't
/// finish within `timeout`, the child process is killed and `None` is
/// returned. This prevents the UI from freezing when system commands
/// hang (e.g. `lsof` or `netstat` with no network).
#[cfg(target_os = "macos")]
pub fn run_with_timeout(
    cmd: &mut std::process::Command,
    timeout: std::time::Duration,
) -> Option<std::process::Output> {
    use std::process::Stdio;

    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().ok(),
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
            Err(_) => return None,
        }
    }
}

/// Create a directory (and parents) owned by the real user.
///
/// Under sudo, `create_dir_all` produces root-owned dirs.
/// This wraps that call and hands ownership to the invoking user.
///
/// # Errors
///
/// Returns an error if directory creation fails.
pub fn create_user_dir(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    crate::config::fix_ownership(path);
    Ok(())
}

/// Write a file owned by the real user.
///
/// Under sudo, `fs::write` produces root-owned files.
/// This wraps that call and hands ownership to the invoking user.
///
/// # Errors
///
/// Returns an error if the write fails.
pub fn write_user_file(path: &std::path::Path, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(path, contents)?;
    crate::config::fix_ownership(path);
    Ok(())
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
/// Reads from the process-wide config dir set at startup via
/// [`crate::config::set_config_dir`], ensuring `--config-dir` is respected
/// everywhere. Falls back to default resolution if not yet set (e.g. tests).
///
/// # Errors
///
/// Returns an error if the home directory cannot be determined or
/// if directory creation fails.
pub fn get_app_config_dir() -> std::io::Result<std::path::PathBuf> {
    crate::config::get_config_dir()
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
        create_user_dir(&path)?;
    }

    Ok(path)
}

/// Returns the `OpenVPN` runtime directory path for a given profile.
///
/// Creates `~/.config/vortix/run/` if it doesn't exist.
/// Returns `(pid_path, log_path)` for the given profile name.
///
/// # Errors
///
/// Returns an error if directory creation fails.
pub fn get_openvpn_run_paths(
    profile_name: &str,
) -> std::io::Result<(std::path::PathBuf, std::path::PathBuf)> {
    let root = get_app_config_dir()?;
    let run_dir = root.join(crate::constants::OPENVPN_RUN_DIR);

    if !run_dir.exists() {
        create_user_dir(&run_dir)?;
    }

    // Sanitize profile name for use in filenames
    let safe_name: String = profile_name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();

    let pid_path = run_dir.join(format!("{safe_name}.pid"));
    let log_path = run_dir.join(format!("{safe_name}.log"));

    Ok((pid_path, log_path))
}

/// Cleans up `OpenVPN` runtime files (pid, log) for a given profile.
pub fn cleanup_openvpn_run_files(profile_name: &str) {
    if let Ok((pid_path, log_path)) = get_openvpn_run_paths(profile_name) {
        let _ = std::fs::remove_file(&pid_path);
        let _ = std::fs::remove_file(&log_path);
    }
}

/// Reads the PID from an `OpenVPN` pid file.
pub fn read_openvpn_pid(profile_name: &str) -> Option<u32> {
    let (pid_path, _) = get_openvpn_run_paths(profile_name).ok()?;
    let content = std::fs::read_to_string(&pid_path).ok()?;
    content.trim().parse::<u32>().ok()
}

/// Returns the path for an `OpenVPN` auth credentials file.
///
/// Creates `~/.config/vortix/auth/` if it doesn't exist.
///
/// # Errors
///
/// Returns an error if directory creation fails.
pub fn get_openvpn_auth_path(profile_name: &str) -> std::io::Result<std::path::PathBuf> {
    let root = get_app_config_dir()?;
    let auth_dir = root.join(crate::constants::OPENVPN_AUTH_DIR);

    if !auth_dir.exists() {
        create_user_dir(&auth_dir)?;
    }

    let safe_name: String = profile_name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();

    Ok(auth_dir.join(format!("{safe_name}.auth")))
}

/// Writes `OpenVPN` credentials to a file (username on line 1, password on line 2).
///
/// The file is created with `chmod 600` (owner read/write only).
///
/// # Errors
///
/// Returns an error if file write or permission setting fails.
#[cfg(unix)]
pub fn write_openvpn_auth_file(
    profile_name: &str,
    username: &str,
    password: &str,
) -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let auth_path = get_openvpn_auth_path(profile_name)?;
    write_user_file(&auth_path, format!("{username}\n{password}\n"))?;

    let mut perms = std::fs::metadata(&auth_path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&auth_path, perms)?;

    Ok(auth_path)
}

/// Writes `OpenVPN` credentials to a file (non-Unix fallback, no chmod).
#[cfg(not(unix))]
pub fn write_openvpn_auth_file(
    profile_name: &str,
    username: &str,
    password: &str,
) -> std::io::Result<std::path::PathBuf> {
    let auth_path = get_openvpn_auth_path(profile_name)?;
    write_user_file(&auth_path, format!("{username}\n{password}\n"))?;
    Ok(auth_path)
}

/// Reads saved `OpenVPN` credentials from the auth file.
///
/// Returns `Some((username, password))` if a valid auth file exists.
pub fn read_openvpn_saved_auth(profile_name: &str) -> Option<(String, String)> {
    let auth_path = get_openvpn_auth_path(profile_name).ok()?;
    let content = std::fs::read_to_string(&auth_path).ok()?;
    let mut lines = content.lines();
    let username = lines.next()?.to_string();
    let password = lines.next()?.to_string();
    if username.is_empty() || password.is_empty() {
        return None;
    }
    Some((username, password))
}

/// Deletes the saved `OpenVPN` auth credentials file for a profile.
pub fn delete_openvpn_auth_file(profile_name: &str) {
    if let Ok(auth_path) = get_openvpn_auth_path(profile_name) {
        let _ = std::fs::remove_file(&auth_path);
    }
}

/// Checks whether an `OpenVPN` config file contains `auth-user-pass` without a file argument.
///
/// Returns `true` if the config has a bare `auth-user-pass` directive (meaning
/// `OpenVPN` will prompt for credentials on stdin). Returns `false` if:
/// - The directive is absent
/// - The directive has a file path argument (`auth-user-pass /path/to/file`)
/// - The directive is commented out (`# auth-user-pass`)
pub fn openvpn_config_needs_auth(config_path: &std::path::Path) -> bool {
    let Ok(content) = std::fs::read_to_string(config_path) else {
        return false;
    };

    for line in content.lines() {
        let trimmed = line.trim();
        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        // Check for the directive
        if trimmed == crate::constants::OVPN_AUTH_USER_PASS {
            // Bare directive with no file argument
            return true;
        }
        if let Some(rest) = trimmed.strip_prefix(crate::constants::OVPN_AUTH_USER_PASS) {
            // Only whitespace after directive = bare (OpenVPN will prompt)
            if rest.trim().is_empty() {
                return true;
            }
            // Has a file argument = no prompt needed
            return false;
        }
    }

    false
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
/// Uses libc `localtime_r` for zero-overhead local time formatting
/// (called every tick, so avoiding a subprocess matters).
pub fn format_local_time() -> String {
    format_system_time_local(std::time::SystemTime::now())
}

/// Converts any `SystemTime` into a local `HH:MM:SS` string.
///
/// Used for both "right now" timestamps (via `format_local_time()`) and for
/// formatting historical log entries in the TUI.
#[must_use]
pub fn format_system_time_local(time: std::time::SystemTime) -> String {
    format_system_time_inner(time).unwrap_or_else(|| "00:00:00".to_string())
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn format_system_time_inner(time: std::time::SystemTime) -> Option<String> {
    let secs = time
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .ok()?
        .as_secs();

    // SAFETY: localtime_r writes into our stack-allocated `tm` and is
    // thread-safe (unlike localtime). We pass a valid pointer to both args.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // time_t is i64 on most platforms; u64→i64 is safe until year 2262
    #[allow(clippy::cast_possible_wrap)]
    let time_t = secs as libc::time_t;
    let result = unsafe { libc::localtime_r(&time_t, &mut tm) };
    if result.is_null() {
        return None;
    }

    Some(format!(
        "{:02}:{:02}:{:02}",
        tm.tm_hour, tm.tm_min, tm.tm_sec
    ))
}

#[cfg(not(unix))]
fn format_system_time_inner(time: std::time::SystemTime) -> Option<String> {
    // Non-Unix fallback: use current time via shell (ignoring the `time` param)
    let _ = time;
    std::process::Command::new("date")
        .arg("+%H:%M:%S")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
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
/// Checks `$HOME` first, then falls back to the system password database
/// via `getpwuid` for containers, cron jobs, and systemd services where
/// `$HOME` may be unset.
pub fn home_dir() -> Option<std::path::PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(home_dir_from_passwd)
}

/// Fallback: resolve home directory from /etc/passwd via libc.
#[cfg(unix)]
#[allow(unsafe_code)]
fn home_dir_from_passwd() -> Option<std::path::PathBuf> {
    // SAFETY: getuid() is always safe; getpwuid() returns a static pointer
    // that is valid until the next call to any getpw* function. We copy the
    // data immediately so the pointer is not held across calls.
    unsafe {
        let uid = libc::getuid();
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return None;
        }
        let home = std::ffi::CStr::from_ptr((*pw).pw_dir);
        home.to_str().ok().map(std::path::PathBuf::from)
    }
}

#[cfg(not(unix))]
fn home_dir_from_passwd() -> Option<std::path::PathBuf> {
    None
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
        .join(crate::constants::METADATA_FILE_NAME);

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
        .join(crate::constants::METADATA_FILE_NAME);

    let json = serde_json::to_string_pretty(data)
        .map_err(|e| format!("Failed to serialize metadata: {e}"))?;

    write_user_file(&metadata_path, json).map_err(|e| format!("Failed to write metadata: {e}"))?;

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

    // Use underscores instead of parentheses to keep filenames valid as
    // network interface names (wg-quick uses the filename as the interface).
    while path.exists() {
        let new_name = if let Some(e) = ext {
            if e.is_empty() {
                format!("{stem}_{counter}")
            } else {
                format!("{stem}_{counter}.{e}")
            }
        } else {
            format!("{stem}_{counter}")
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

    #[test]
    fn test_get_unique_path_no_collision() {
        let dir = std::env::temp_dir().join("vortix_test_unique_nocol");
        let _ = std::fs::create_dir_all(&dir);
        // Clean up any previous files
        let _ = std::fs::remove_file(dir.join("test.conf"));

        let path = get_unique_path(&dir, "test.conf");
        assert_eq!(path.file_name().unwrap(), "test.conf");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_get_unique_path_with_collision() {
        let dir = std::env::temp_dir().join("vortix_test_unique_col");
        let _ = std::fs::create_dir_all(&dir);

        // Create the file that will collide
        std::fs::write(dir.join("test.conf"), "existing").unwrap();

        let path = get_unique_path(&dir, "test.conf");
        assert_eq!(path.file_name().unwrap(), "test_1.conf");

        // Create that too
        std::fs::write(dir.join("test_1.conf"), "also existing").unwrap();
        let path2 = get_unique_path(&dir, "test.conf");
        assert_eq!(path2.file_name().unwrap(), "test_2.conf");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // === OpenVPN auth-user-pass detection tests ===

    #[test]
    fn test_openvpn_config_needs_auth_bare_directive() {
        let dir = std::env::temp_dir().join("vortix_test_auth_bare");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.ovpn");
        std::fs::write(
            &path,
            "client\nremote example.com 1194\nauth-user-pass\ndev tun\n",
        )
        .unwrap();
        assert!(openvpn_config_needs_auth(&path));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_openvpn_config_needs_auth_bare_with_trailing_space() {
        let dir = std::env::temp_dir().join("vortix_test_auth_trail");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.ovpn");
        std::fs::write(
            &path,
            "client\nremote example.com 1194\nauth-user-pass   \ndev tun\n",
        )
        .unwrap();
        assert!(openvpn_config_needs_auth(&path));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_openvpn_config_needs_auth_with_file_arg() {
        let dir = std::env::temp_dir().join("vortix_test_auth_file");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.ovpn");
        std::fs::write(
            &path,
            "client\nremote example.com 1194\nauth-user-pass /etc/openvpn/creds.txt\ndev tun\n",
        )
        .unwrap();
        assert!(!openvpn_config_needs_auth(&path));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_openvpn_config_needs_auth_absent() {
        let dir = std::env::temp_dir().join("vortix_test_auth_absent");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.ovpn");
        std::fs::write(
            &path,
            "client\nremote example.com 1194\ndev tun\nproto udp\n",
        )
        .unwrap();
        assert!(!openvpn_config_needs_auth(&path));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_openvpn_config_needs_auth_commented_out() {
        let dir = std::env::temp_dir().join("vortix_test_auth_comment");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.ovpn");
        std::fs::write(
            &path,
            "client\nremote example.com 1194\n# auth-user-pass\n; auth-user-pass\ndev tun\n",
        )
        .unwrap();
        assert!(!openvpn_config_needs_auth(&path));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_openvpn_config_needs_auth_nonexistent_file() {
        let path = std::path::PathBuf::from("/tmp/nonexistent_vortix_config_12345.ovpn");
        assert!(!openvpn_config_needs_auth(&path));
    }

    // === OpenVPN auth file write/read tests ===

    #[test]
    fn test_write_read_openvpn_auth_file() {
        let name = "test_auth_roundtrip";
        // Write
        let result = write_openvpn_auth_file(name, "myuser", "mypass");
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.exists());

        // Read
        let creds = read_openvpn_saved_auth(name);
        assert!(creds.is_some());
        let (user, pass) = creds.unwrap();
        assert_eq!(user, "myuser");
        assert_eq!(pass, "mypass");

        // Clean up
        delete_openvpn_auth_file(name);
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_auth_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let name = "test_auth_perms";
        let result = write_openvpn_auth_file(name, "user", "pass");
        assert!(result.is_ok());
        let path = result.unwrap();

        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);

        delete_openvpn_auth_file(name);
    }

    #[test]
    fn test_read_openvpn_saved_auth_missing_file() {
        let creds = read_openvpn_saved_auth("nonexistent_profile_xyz_12345");
        assert!(creds.is_none());
    }

    #[test]
    fn test_read_openvpn_saved_auth_empty_creds() {
        let name = "test_auth_empty_creds";
        // Write empty username
        let path = get_openvpn_auth_path(name).unwrap();
        std::fs::write(&path, "\npassword\n").unwrap();
        assert!(read_openvpn_saved_auth(name).is_none());

        // Write empty password
        std::fs::write(&path, "username\n\n").unwrap();
        assert!(read_openvpn_saved_auth(name).is_none());

        delete_openvpn_auth_file(name);
    }
}
