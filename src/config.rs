//! Application configuration management.
//!
//! Handles config directory resolution (CLI flag > `SUDO_USER`-aware home > XDG > default),
//! loading `config.toml`, and migration from legacy paths.
//!
//! The resolved config directory is stored in a process-wide global via [`set_config_dir`]
//! at startup, so that all utility functions (profile loading, auth, metadata, killswitch)
//! use the correct path without requiring a parameter change on every call site.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// Process-wide resolved config directory, set once at startup.
static CONFIG_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Stores the resolved config directory for the lifetime of the process.
///
/// Must be called exactly once from `main()` after resolving the directory.
/// Subsequent calls are ignored (first write wins).
pub fn set_config_dir(dir: PathBuf) {
    let _ = CONFIG_DIR.set(dir);
}

/// Returns the config directory set at startup, or falls back to default resolution.
///
/// All utility functions (`get_profiles_dir`, `get_openvpn_auth_path`, etc.)
/// go through this, so the `--config-dir` flag is respected everywhere.
pub fn get_config_dir() -> std::io::Result<PathBuf> {
    if let Some(dir) = CONFIG_DIR.get() {
        Ok(dir.clone())
    } else {
        // Fallback for early calls before set_config_dir (e.g. tests)
        resolve_config_dir(None)
    }
}

/// User-configurable application settings.
///
/// All fields have sensible defaults. Users can override any subset via
/// `config.toml` in the config directory -- missing fields use defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppConfig {
    /// UI refresh rate in milliseconds.
    pub tick_rate: u64,
    /// Telemetry polling interval in seconds.
    pub telemetry_poll_rate: u64,
    /// HTTP API timeout in seconds.
    pub api_timeout: u64,
    /// Ping command timeout in seconds.
    pub ping_timeout: u64,
    /// `OpenVPN` connection timeout in seconds.
    pub connect_timeout: u64,
    /// Ping targets for latency measurement (tried in order).
    pub ping_targets: Vec<String>,
    /// IPv6 leak detection endpoints.
    pub ipv6_check_apis: Vec<String>,
    /// Primary API endpoint for IP address and ISP lookup.
    pub ip_api_primary: String,
    /// Fallback API endpoints for IP lookup (tried in order).
    pub ip_api_fallbacks: Vec<String>,
    /// Maximum number of log entries kept in the TUI event log.
    pub max_log_entries: usize,
    /// Minimum log level shown in the event log (`"debug"`, `"info"`, `"warning"`, `"error"`).
    pub log_level: String,
    /// Maximum log file size in bytes before rotation (default: 5 MB).
    pub log_rotation_size: u64,
    /// Number of days to retain old log files (default: 7).
    pub log_retention_days: u64,
    /// Maximum seconds to wait for a VPN disconnect before force-killing (default: 30).
    pub disconnect_timeout: u64,
    /// `OpenVPN` daemon verbosity level (`--verb`). Range 0–11 (default: 3).
    pub openvpn_verbosity: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        use crate::constants;

        Self {
            tick_rate: constants::DEFAULT_TICK_RATE,
            telemetry_poll_rate: constants::DEFAULT_TELEMETRY_POLL_RATE,
            api_timeout: constants::DEFAULT_API_TIMEOUT,
            ping_timeout: constants::DEFAULT_PING_TIMEOUT,
            connect_timeout: constants::DEFAULT_CONNECT_TIMEOUT,
            ping_targets: constants::DEFAULT_PING_TARGETS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            ipv6_check_apis: constants::DEFAULT_IPV6_CHECK_APIS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            ip_api_primary: constants::DEFAULT_IP_API_PRIMARY.to_string(),
            ip_api_fallbacks: vec![
                constants::DEFAULT_IP_API_FALLBACK_1.to_string(),
                constants::DEFAULT_IP_API_FALLBACK_2.to_string(),
                constants::DEFAULT_IP_API_FALLBACK_3.to_string(),
            ],
            max_log_entries: constants::DEFAULT_MAX_LOG_ENTRIES,
            log_level: constants::DEFAULT_LOG_LEVEL.to_string(),
            log_rotation_size: constants::DEFAULT_LOG_ROTATION_SIZE,
            log_retention_days: constants::DEFAULT_LOG_RETENTION_DAYS,
            disconnect_timeout: constants::DEFAULT_DISCONNECT_TIMEOUT,
            openvpn_verbosity: constants::DEFAULT_OVPN_VERBOSITY.to_string(),
        }
    }
}

/// Resolves the config directory path.
///
/// Precedence: CLI flag / `VORTIX_CONFIG_DIR` > `SUDO_USER`-aware home > `XDG_CONFIG_HOME` > default.
///
/// # Errors
///
/// Returns an error if the config directory cannot be determined or created.
pub fn resolve_config_dir(cli_override: Option<&PathBuf>) -> std::io::Result<PathBuf> {
    let path = if let Some(dir) = cli_override {
        // Resolve relative paths to absolute so the config dir is stable
        // regardless of the working directory.
        if dir.is_relative() {
            std::env::current_dir()?.join(dir)
        } else {
            dir.clone()
        }
    } else {
        default_config_dir()?
    };

    if !path.exists() {
        // Track which ancestors already exist so we only chown dirs we create.
        let first_existing_ancestor = path.ancestors().find(|a| a.exists());
        std::fs::create_dir_all(&path)?;
        // When running under sudo the directory is created as root.
        // Chown newly-created dirs (e.g. ~/.config and ~/.config/vortix)
        // to the real user so normal-user sessions can read/write.
        if crate::utils::is_root() {
            // Chown each new directory from the config dir up to (but not
            // including) the first ancestor that already existed.
            let mut dir = Some(path.as_path());
            while let Some(d) = dir {
                if first_existing_ancestor.is_some_and(|a| a == d) {
                    break;
                }
                fix_ownership(d);
                dir = d.parent();
            }
        }
    }

    // Canonicalize to resolve symlinks and ".." components
    std::fs::canonicalize(&path)
}

/// Computes the default config directory (no CLI override).
///
/// Uses `SUDO_USER` to resolve the real user's home when running under sudo,
/// then checks `XDG_CONFIG_HOME`, and falls back to `~/.config/vortix`.
fn default_config_dir() -> std::io::Result<PathBuf> {
    let home = real_user_home().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "Home directory not found")
    })?;

    // Respect XDG_CONFIG_HOME on Linux
    #[cfg(target_os = "linux")]
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        let xdg_path = PathBuf::from(xdg);
        if xdg_path.is_absolute() {
            return Ok(xdg_path.join(crate::constants::APP_NAME));
        }
    }

    Ok(home.join(".config").join(crate::constants::APP_NAME))
}

/// Resolves the real user's home directory, accounting for sudo.
///
/// When running as root via `sudo`, `$HOME` points to `/root`. This function
/// checks `SUDO_USER` and looks up that user's actual home directory from
/// `/etc/passwd` so config files land in the invoking user's home.
fn real_user_home() -> Option<PathBuf> {
    if crate::utils::is_root() {
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            return home_dir_for_user(&sudo_user);
        }
    }
    dirs::home_dir()
}

/// Looks up a user's home directory from `/etc/passwd` via `getpwnam`.
#[cfg(unix)]
#[allow(unsafe_code)]
fn home_dir_for_user(username: &str) -> Option<PathBuf> {
    use std::ffi::{CStr, CString};
    let c_name = CString::new(username).ok()?;
    // SAFETY: getpwnam returns a pointer to a static struct. We copy the
    // home directory string immediately so the pointer is not held.
    unsafe {
        let pw = libc::getpwnam(c_name.as_ptr());
        if pw.is_null() {
            return None;
        }
        let home = CStr::from_ptr((*pw).pw_dir);
        home.to_str().ok().map(PathBuf::from)
    }
}

#[cfg(not(unix))]
fn home_dir_for_user(_username: &str) -> Option<PathBuf> {
    None
}

/// Loads `AppConfig` from `config.toml` in the given directory.
///
/// Returns defaults if the file doesn't exist. Returns an error if the file
/// exists but is malformed.
///
/// # Errors
///
/// Returns an error if the file exists but cannot be read or parsed.
pub fn load_config(config_dir: &Path) -> Result<AppConfig, String> {
    let config_path = config_dir.join("config.toml");

    if !config_path.exists() {
        return Ok(AppConfig::default());
    }

    let content = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read {}: {e}", config_path.display()))?;

    toml::from_str(&content)
        .map_err(|e| format!("Invalid config at {}: {e}", config_path.display()))
}

// ======================== Migration ========================

/// Marker file written after a successful migration so the prompt is not
/// repeated on subsequent runs.
const MIGRATION_DONE_MARKER: &str = ".migration-done";

/// Checks if data migration from an old config path is needed.
///
/// Returns `Some(old_path)` if migration should be offered, `None` otherwise.
///
/// Only relevant when:
/// 1. Running under `sudo` (not as actual root)
/// 2. Old path (`/root/.config/vortix`) has profile data
/// 3. New path is different and empty
/// 4. User hasn't previously declined migration
#[must_use]
pub fn check_migration(new_dir: &Path) -> Option<PathBuf> {
    // Only relevant when running under sudo
    if !crate::utils::is_root() {
        return None;
    }
    if std::env::var("SUDO_USER").is_err() {
        return None;
    }

    let old_dir = PathBuf::from("/root/.config/vortix");

    // Same path -- no migration needed
    if new_dir == old_dir {
        return None;
    }

    // Already migrated
    if old_dir.join(MIGRATION_DONE_MARKER).exists() {
        return None;
    }

    // Old path must have profiles
    if !old_dir.join("profiles").is_dir() {
        return None;
    }
    let has_old_data = std::fs::read_dir(old_dir.join("profiles"))
        .map(|mut d| d.next().is_some())
        .unwrap_or(false);
    if !has_old_data {
        return None;
    }

    // New path must be empty or nonexistent
    let new_has_profiles = new_dir.join("profiles").is_dir()
        && std::fs::read_dir(new_dir.join("profiles"))
            .map(|mut d| d.next().is_some())
            .unwrap_or(false);
    if new_has_profiles {
        return None;
    }

    Some(old_dir)
}

/// Migrates data from an old config directory to a new one.
///
/// Moves known subdirectories and files, then recursively chowns everything
/// to the real user via `SUDO_UID`/`SUDO_GID`.
///
/// # Errors
///
/// Returns an error if file operations fail.
pub fn migrate_data(old_dir: &Path, new_dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(new_dir)?;

    let items = [
        "profiles",
        "auth",
        "run",
        "logs",
        "metadata.json",
        "killswitch.state",
        "config.toml",
    ];

    let mut migrated = 0;
    for item in &items {
        let src = old_dir.join(item);
        let dst = new_dir.join(item);
        if !src.exists() {
            continue;
        }

        // If destination exists and is a non-empty directory or a file, skip it
        // (user already has data there). But if it's an empty directory, merge
        // into it -- empty dirs are leftovers from a previous incomplete migration
        // or from get_profiles_dir() auto-creating directories.
        if dst.exists() {
            let dst_is_empty_dir = dst.is_dir()
                && std::fs::read_dir(&dst)
                    .map(|mut d| d.next().is_none())
                    .unwrap_or(false);
            if !dst_is_empty_dir {
                eprintln!("  Skipping {item} (already has data at destination)");
                continue;
            }
            // Empty dir at destination -- remove it so rename can work,
            // or merge contents via copy if rename fails
            eprintln!("  Merging {item} (destination dir exists but is empty)...");
            let _ = std::fs::remove_dir(&dst);
        } else {
            eprintln!("  Moving {item}...");
        }

        // Try rename (atomic move); fall back to copy for cross-filesystem
        if let Err(rename_err) = std::fs::rename(&src, &dst) {
            eprintln!("  Rename failed ({rename_err}), copying instead...");
            if src.is_dir() {
                copy_dir_recursive(&src, &dst)?;
                if let Err(e) = std::fs::remove_dir_all(&src) {
                    eprintln!("  Warning: could not remove old {item}: {e}");
                }
            } else {
                std::fs::copy(&src, &dst)?;
                if let Err(e) = std::fs::remove_file(&src) {
                    eprintln!("  Warning: could not remove old {item}: {e}");
                }
            }
        }
        // Verify the destination exists after the move
        if dst.exists() {
            migrated += 1;
        } else {
            eprintln!("  Error: {item} not found at destination after move!");
        }
    }

    if migrated == 0 {
        eprintln!("  Nothing was migrated.");
    } else {
        eprintln!("  Migrated {migrated} item(s).");
    }

    // Chown everything to the real user
    if let Err(e) = chown_to_real_user(new_dir) {
        eprintln!("Warning: could not set file ownership: {e}");
        eprintln!("Files may still be owned by root.");
    }

    // Write a marker so the prompt doesn't repeat even if cleanup was partial
    let _ = std::fs::write(old_dir.join(MIGRATION_DONE_MARKER), "migrated");

    Ok(())
}

/// Recursively copies a directory tree.
fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

/// Chowns a directory (and its contents) to the real user.
///
/// Ensure a path (file or directory) is owned by the real user, not root.
///
/// Simple rule: anything under the user's home should be theirs.
/// When running under `sudo`, newly created files/dirs end up as root.
/// This fixes that. No-op when not running as root.
pub fn fix_ownership(path: &Path) {
    if !crate::utils::is_root() {
        return;
    }
    if let Err(e) = chown_to_real_user(path) {
        eprintln!(
            "Note: could not set ownership of {} to your user: {e}",
            path.display()
        );
    }
}

/// Recursively chowns a path to `SUDO_UID`:`SUDO_GID`.
#[cfg(unix)]
#[allow(unsafe_code)]
fn chown_to_real_user(path: &Path) -> std::io::Result<()> {
    let uid: u32 = std::env::var("SUDO_UID")
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "SUDO_UID not set"))?;
    let gid: u32 = std::env::var("SUDO_GID")
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "SUDO_GID not set"))?;

    chown_recursive(path, uid, gid)
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn chown_recursive(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    // SAFETY: chown is a standard POSIX call with no side effects beyond
    // changing file ownership. The CString is valid for the duration of the call.
    let ret = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }

    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            chown_recursive(&entry.path(), uid, gid)?;
        }
    }

    Ok(())
}

#[cfg(not(unix))]
fn chown_to_real_user(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- AppConfig defaults ----

    #[test]
    fn test_default_config_values() {
        let config = AppConfig::default();
        assert_eq!(config.tick_rate, 1000);
        assert_eq!(config.telemetry_poll_rate, 30);
        assert_eq!(config.api_timeout, 5);
        assert_eq!(config.ping_timeout, 2);
        assert_eq!(config.connect_timeout, 20);
        assert_eq!(config.ping_targets.len(), 4);
        assert_eq!(config.ipv6_check_apis.len(), 3);
        assert_eq!(config.ip_api_fallbacks.len(), 3);
    }

    // ---- load_config ----

    #[test]
    fn test_load_config_missing_file() {
        let dir = std::env::temp_dir().join("vortix_test_no_config");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::remove_file(dir.join("config.toml"));

        let config = load_config(&dir).unwrap();
        assert_eq!(config.tick_rate, 1000);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_config_partial() {
        let dir = std::env::temp_dir().join("vortix_test_partial_config");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("config.toml"), "tick_rate = 500\n").unwrap();

        let config = load_config(&dir).unwrap();
        assert_eq!(config.tick_rate, 500);
        assert_eq!(config.telemetry_poll_rate, 30); // default preserved

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_config_full_toml() {
        let dir = std::env::temp_dir().join("vortix_test_full_config");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let toml_content = r#"
tick_rate = 250
telemetry_poll_rate = 60
api_timeout = 10
ping_timeout = 5
connect_timeout = 45
ping_targets = ["4.4.4.4", "8.8.4.4"]
ipv6_check_apis = ["https://example.com/v6"]
ip_api_primary = "https://custom-api.example.com/json"
ip_api_fallbacks = ["https://fallback1.example.com"]
"#;
        std::fs::write(dir.join("config.toml"), toml_content).unwrap();

        let config = load_config(&dir).unwrap();
        assert_eq!(config.tick_rate, 250);
        assert_eq!(config.telemetry_poll_rate, 60);
        assert_eq!(config.api_timeout, 10);
        assert_eq!(config.ping_timeout, 5);
        assert_eq!(config.connect_timeout, 45);
        assert_eq!(config.ping_targets, vec!["4.4.4.4", "8.8.4.4"]);
        assert_eq!(config.ipv6_check_apis, vec!["https://example.com/v6"]);
        assert_eq!(config.ip_api_primary, "https://custom-api.example.com/json");
        assert_eq!(
            config.ip_api_fallbacks,
            vec!["https://fallback1.example.com"]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_config_invalid_toml() {
        let dir = std::env::temp_dir().join("vortix_test_bad_config");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("config.toml"), "tick_rate = [invalid\n").unwrap();

        assert!(load_config(&dir).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_config_unknown_field() {
        let dir = std::env::temp_dir().join("vortix_test_unknown_field");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("config.toml"), "nonexistent_field = true\n").unwrap();

        assert!(load_config(&dir).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- resolve_config_dir ----

    #[test]
    fn test_resolve_config_dir_with_override() {
        let custom = std::env::temp_dir().join("vortix_test_resolve_override");
        let _ = std::fs::remove_dir_all(&custom);

        // Directory should not exist yet
        assert!(!custom.exists());

        let result = resolve_config_dir(Some(&custom)).unwrap();
        // Compare canonicalized paths (macOS: /var -> /private/var)
        let expected = std::fs::canonicalize(&custom).unwrap();
        assert_eq!(result, expected);
        // resolve_config_dir must create the directory
        assert!(custom.is_dir());

        let _ = std::fs::remove_dir_all(&custom);
    }

    #[test]
    fn test_resolve_config_dir_default() {
        // Without override, should return a path ending in "vortix"
        let result = resolve_config_dir(None).unwrap();
        assert!(
            result
                .file_name()
                .is_some_and(|n| n == crate::constants::APP_NAME),
            "Default config dir should end with the app name, got: {}",
            result.display()
        );
        assert!(result.is_dir());
    }

    // ---- migration helpers ----

    #[test]
    fn test_check_migration_not_root() {
        // When not root, migration should never trigger
        let dir = PathBuf::from("/tmp/vortix_test_migration");
        assert!(check_migration(&dir).is_none());
    }

    // ---- copy_dir_recursive ----

    #[test]
    fn test_copy_dir_recursive() {
        let base = std::env::temp_dir().join("vortix_test_copy_dir");
        let _ = std::fs::remove_dir_all(&base);

        let src = base.join("src_dir");
        let dst = base.join("dst_dir");

        // Build a nested source tree:
        //   src_dir/
        //     file_a.txt
        //     sub/
        //       file_b.txt
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("file_a.txt"), "alpha").unwrap();
        std::fs::write(src.join("sub").join("file_b.txt"), "beta").unwrap();

        copy_dir_recursive(&src, &dst).unwrap();

        // Verify structure and contents
        assert!(dst.join("file_a.txt").is_file());
        assert!(dst.join("sub").is_dir());
        assert!(dst.join("sub").join("file_b.txt").is_file());
        assert_eq!(
            std::fs::read_to_string(dst.join("file_a.txt")).unwrap(),
            "alpha"
        );
        assert_eq!(
            std::fs::read_to_string(dst.join("sub").join("file_b.txt")).unwrap(),
            "beta"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    // ---- migrate_data ----

    #[test]
    fn test_migrate_data_moves_items() {
        let base = std::env::temp_dir().join("vortix_test_migrate");
        let _ = std::fs::remove_dir_all(&base);

        let old = base.join("old");
        let new = base.join("new");

        // Seed old directory with profiles dir and a metadata file
        std::fs::create_dir_all(old.join("profiles")).unwrap();
        std::fs::write(old.join("profiles").join("vpn.conf"), "interface = wg0").unwrap();
        std::fs::write(old.join("metadata.json"), r#"{"version":1}"#).unwrap();

        migrate_data(&old, &new).unwrap();

        // New dir should contain the migrated items
        assert!(new.join("profiles").is_dir());
        assert!(new.join("profiles").join("vpn.conf").is_file());
        assert_eq!(
            std::fs::read_to_string(new.join("profiles").join("vpn.conf")).unwrap(),
            "interface = wg0"
        );
        assert!(new.join("metadata.json").is_file());
        assert_eq!(
            std::fs::read_to_string(new.join("metadata.json")).unwrap(),
            r#"{"version":1}"#
        );

        // Source items should be gone (renamed away)
        assert!(!old.join("profiles").exists());
        assert!(!old.join("metadata.json").exists());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_migrate_data_merges_into_empty_dirs() {
        let base = std::env::temp_dir().join("vortix_test_migrate_empty");
        let _ = std::fs::remove_dir_all(&base);

        let old = base.join("old");
        let new = base.join("new");

        // Seed old directory with profiles
        std::fs::create_dir_all(old.join("profiles")).unwrap();
        std::fs::write(old.join("profiles").join("vpn.conf"), "interface = wg0").unwrap();
        std::fs::write(old.join("profiles").join("us.ovpn"), "remote us.vpn").unwrap();

        // Pre-create EMPTY profiles dir at new location (simulates
        // get_profiles_dir() auto-creating the directory on a prior run)
        std::fs::create_dir_all(new.join("profiles")).unwrap();
        assert!(new.join("profiles").is_dir());
        // Verify it's empty
        assert!(std::fs::read_dir(new.join("profiles"))
            .unwrap()
            .next()
            .is_none());

        migrate_data(&old, &new).unwrap();

        // Profiles should now be at the new location
        assert!(new.join("profiles").join("vpn.conf").is_file());
        assert!(new.join("profiles").join("us.ovpn").is_file());
        assert_eq!(
            std::fs::read_to_string(new.join("profiles").join("vpn.conf")).unwrap(),
            "interface = wg0"
        );

        // Source should be gone
        assert!(!old.join("profiles").join("vpn.conf").exists());

        let _ = std::fs::remove_dir_all(&base);
    }
}
