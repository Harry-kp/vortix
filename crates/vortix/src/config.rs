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

const CONFIG_FILE: &str = "config.toml";
const MAX_CONFIG_BYTES: u64 = 256 * 1024;

/// Result of publishing a live theme preference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThemePersistOutcome {
    /// The file and containing directory were durably synchronized.
    Durable,
    /// The replacement is visible, but the final directory sync failed.
    PublishedDurabilityUncertain(String),
}

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
/// All utility functions (profile, runtime, and transient artifact paths)
/// go through this, so the `--config-dir` flag is respected everywhere.
///
/// Resolution order: `set_config_dir()` > `VORTIX_CONFIG_DIR` env var > default.
/// The env var override is primarily useful for test isolation.
pub fn get_config_dir() -> std::io::Result<PathBuf> {
    if let Some(dir) = CONFIG_DIR.get() {
        return Ok(dir.clone());
    }
    if let Ok(dir) = std::env::var("VORTIX_CONFIG_DIR") {
        let path = PathBuf::from(dir);
        if !path.exists() {
            std::fs::create_dir_all(&path)?;
        }
        return Ok(path);
    }
    resolve_config_dir(None)
}

/// User-configurable application settings.
///
/// All fields have sensible defaults. Users can override any subset via
/// `config.toml` in the config directory -- missing fields use defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppConfig {
    /// Built-in TUI color palette; `"terminal"` inherits terminal colors.
    pub theme: crate::theme::ThemeChoice,
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
    /// Legacy `config.toml` compatibility value for the `WireGuard` handshake
    /// deadline. Effective runtime values are resolved through
    /// `vortix_config::EngineSettings`.
    pub wireguard_handshake_timeout_secs: u64,
    /// Legacy compatibility value for the `WireGuard` peer freshness
    /// threshold when traffic is expected.
    pub wireguard_handshake_stale_secs: u64,
    /// Ping targets for latency measurement and the legacy `WireGuard` health
    /// target list. `[engine].wireguard_health_targets` is authoritative when
    /// explicitly configured.
    pub ping_targets: Vec<String>,
    /// IPv6 leak detection endpoints.
    pub ipv6_check_apis: Vec<String>,
    /// Primary API endpoint for IP address and ISP lookup.
    pub ip_api_primary: String,
    /// Fallback API endpoints for IP lookup (tried in order).
    pub ip_api_fallbacks: Vec<String>,
    /// Fallback API endpoint for metadata about an exact public IP.
    pub geolocation_api_fallback: String,
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
    /// Maximum number of automatic retry attempts on connection failure (0 = disabled).
    pub connect_max_retries: u32,
    /// Base delay in seconds for exponential backoff between retries.
    /// Actual delay = base × 2^(attempt−1), i.e. 2s, 4s, 8s for base=2.
    pub connect_retry_base_delay_secs: u64,
    /// Maximum delay in seconds for retry backoff (prevents unbounded growth).
    pub connect_retry_max_delay_secs: u64,
    /// Automatically reconnect to the last VPN when the connection drops unexpectedly.
    pub auto_reconnect: bool,
    /// Seconds to wait after detecting a network change before auto-reconnecting.
    /// Gives the new network time to stabilize.
    pub auto_reconnect_delay_secs: u64,
}

impl Default for AppConfig {
    fn default() -> Self {
        use crate::constants;

        Self {
            theme: crate::theme::ThemeChoice::default(),
            tick_rate: constants::DEFAULT_TICK_RATE,
            telemetry_poll_rate: constants::DEFAULT_TELEMETRY_POLL_RATE,
            api_timeout: constants::DEFAULT_API_TIMEOUT,
            ping_timeout: constants::DEFAULT_PING_TIMEOUT,
            connect_timeout: constants::DEFAULT_CONNECT_TIMEOUT,
            wireguard_handshake_timeout_secs: constants::DEFAULT_WIREGUARD_HANDSHAKE_TIMEOUT,
            wireguard_handshake_stale_secs: 180,
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
            geolocation_api_fallback: constants::DEFAULT_GEOLOCATION_API_FALLBACK.to_string(),
            max_log_entries: constants::DEFAULT_MAX_LOG_ENTRIES,
            log_level: constants::DEFAULT_LOG_LEVEL.to_string(),
            log_rotation_size: constants::DEFAULT_LOG_ROTATION_SIZE,
            log_retention_days: constants::DEFAULT_LOG_RETENTION_DAYS,
            disconnect_timeout: constants::DEFAULT_DISCONNECT_TIMEOUT,
            openvpn_verbosity: constants::DEFAULT_OVPN_VERBOSITY.to_string(),
            connect_max_retries: constants::DEFAULT_CONNECT_MAX_RETRIES,
            connect_retry_base_delay_secs: constants::DEFAULT_CONNECT_RETRY_BASE_DELAY_SECS,
            connect_retry_max_delay_secs: constants::DEFAULT_CONNECT_RETRY_MAX_DELAY_SECS,
            auto_reconnect: constants::DEFAULT_AUTO_RECONNECT,
            auto_reconnect_delay_secs: constants::DEFAULT_AUTO_RECONNECT_DELAY_SECS,
        }
    }
}

impl AppConfig {
    /// Bound for one protocol connection attempt plus control publication.
    #[must_use]
    pub const fn connect_operation_timeout_secs(&self, protocol: crate::state::Protocol) -> u64 {
        let protocol_gate = match protocol {
            crate::state::Protocol::WireGuard => self.wireguard_handshake_timeout_secs,
            crate::state::Protocol::OpenVPN => self.connect_timeout,
        };
        protocol_gate.saturating_add(crate::constants::CONTROL_COMPLETION_GRACE_SECS)
    }

    /// Bound for one teardown plus control publication.
    #[must_use]
    pub const fn disconnect_operation_timeout_secs(&self) -> u64 {
        self.disconnect_timeout
            .saturating_add(crate::constants::CONTROL_COMPLETION_GRACE_SECS)
    }

    /// Bound for a teardown followed by a fresh protocol connection.
    #[must_use]
    pub const fn reconnect_operation_timeout_secs(&self, protocol: crate::state::Protocol) -> u64 {
        self.disconnect_timeout
            .saturating_add(self.connect_operation_timeout_secs(protocol))
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
        // `create_dir_all` applies the caller's umask. Ubuntu defaults to 002,
        // which yields a group-writable 0775 — and Vortix's own durable-state
        // checks reject any group- or world-writable directory, so a first run
        // as a normal user made every profile import fail with "persisted
        // control state is not a private owner-controlled file". macOS never
        // showed it: umask 022 happens to produce an acceptable 0755. The
        // directory holds credentials and control state, so 0700 is what it
        // should have been regardless of the inherited umask.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        }
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
    #[cfg(target_os = "linux")] // xtask:allow-platform-cfg: XDG paths are a Linux-only convention
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
    crate::utils::home_dir()
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
    let config_path = config_dir.join(CONFIG_FILE);

    if !config_path.exists() {
        return Ok(AppConfig::default());
    }

    let content = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read {}: {e}", config_path.display()))?;

    toml::from_str(&content)
        .map_err(|e| format!("Invalid config at {}: {e}", config_path.display()))
}

/// Persist only the selected TUI theme while preserving all other config
/// keys, comments, and ordering.
pub(crate) fn persist_theme_choice(
    config_dir: &Path,
    choice: crate::theme::ThemeChoice,
) -> Result<ThemePersistOutcome, String> {
    use std::str::FromStr as _;

    let owner = config_owner(config_dir)?;
    let directory = crate::vortix_config::control_state::open_control_directory(
        config_dir, false, owner.0, owner.1,
    )
    .map_err(|error| format!("cannot safely open the config directory: {error}"))?
    .ok_or_else(|| "the config directory no longer exists".to_string())?;
    let bytes = crate::vortix_config::control_state::read_owned_user_entry(
        &directory,
        CONFIG_FILE,
        owner.0,
        MAX_CONFIG_BYTES,
    )
    .map_err(|error| format!("cannot safely read config.toml: {error}"))?;
    let source = bytes
        .map(|bytes| {
            String::from_utf8(bytes)
                .map_err(|_| "config.toml is not valid UTF-8 and was not changed".to_string())
        })
        .transpose()?
        .unwrap_or_default();
    let mut document = if source.trim().is_empty() {
        toml_edit::DocumentMut::new()
    } else {
        toml_edit::DocumentMut::from_str(&source)
            .map_err(|error| format!("config.toml is invalid and was not changed: {error}"))?
    };
    document["theme"] = toml_edit::value(choice.config_value());
    let body = document.to_string();
    if body.len() as u64 > MAX_CONFIG_BYTES {
        return Err(format!(
            "config.toml would exceed the {MAX_CONFIG_BYTES}-byte safety limit"
        ));
    }

    #[cfg(unix)]
    {
        classify_theme_write(
            crate::vortix_config::control_state::write_owned_atomic_with_hook(
                &directory,
                CONFIG_FILE,
                body.as_bytes(),
                owner.0,
                owner.1,
                |_, _| Ok(()),
            ),
        )
    }

    #[cfg(not(unix))]
    crate::vortix_config::control_state::write_owned_atomic(
        &directory,
        CONFIG_FILE,
        body.as_bytes(),
        owner.0,
        owner.1,
    )
    .map(|()| ThemePersistOutcome::Durable)
    .map_err(|error| format!("could not save config.toml: {error}"))
}

#[cfg(unix)]
fn classify_theme_write(
    result: Result<(), crate::vortix_config::control_state::AtomicWriteError>,
) -> Result<ThemePersistOutcome, String> {
    use crate::vortix_config::control_state::AtomicWriteError;

    match result {
        Ok(()) => Ok(ThemePersistOutcome::Durable),
        Err(AtomicWriteError::NotPublished(error)) => {
            Err(format!("could not save config.toml: {error}"))
        }
        Err(AtomicWriteError::PublishedButDirectoryUnsynced(error)) => Ok(
            ThemePersistOutcome::PublishedDurabilityUncertain(error.to_string()),
        ),
    }
}

/// Resolve the principal that owns user configuration, including when the
/// process was launched through `sudo`.
#[cfg(unix)]
pub(crate) fn config_owner(config_dir: &Path) -> Result<(u32, u32), String> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::symlink_metadata(config_dir).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("configuration path is not a real directory".into());
    }
    let effective = crate::utils::effective_user_group_ids();
    if effective.0 != 0 {
        return (metadata.uid() == effective.0)
            .then_some(effective)
            .ok_or_else(|| "configuration owner mismatch".into());
    }
    let uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(metadata.uid());
    let gid = std::env::var("SUDO_GID")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(metadata.gid());
    (metadata.uid() == uid)
        .then_some((uid, gid))
        .ok_or_else(|| "sudo owner does not own configuration".into())
}

#[cfg(not(unix))]
pub(crate) fn config_owner(_config_dir: &Path) -> Result<(u32, u32), String> {
    Err("Standard-mode canonical control is unsupported on this platform".into())
}

/// Load the effective application configuration.
///
/// Engine settings have one authoritative resolution path:
/// `Settings` defaults, layered files and `VORTIX_ENGINE__*` environment
/// overrides. Existing `config.toml` values seed that defaults layer so old
/// partial files keep working until they are migrated to `settings.toml`.
/// The returned `AppConfig` is a compatibility carrier for the legacy App and
/// CLI runtime; tunnel factories must consume these resolved values rather
/// than reading `config.toml` again.
pub fn load_effective_config(config_dir: &Path) -> Result<AppConfig, String> {
    let config = load_config(config_dir)?;
    let legacy_engine = crate::vortix_config::EngineSettings {
        openvpn_verbosity: config.openvpn_verbosity.clone(),
        connect_timeout_secs: config.connect_timeout,
        wireguard_handshake_timeout_secs: config.wireguard_handshake_timeout_secs,
        wireguard_handshake_stale_secs: config.wireguard_handshake_stale_secs,
        wireguard_health_targets: config.ping_targets.clone(),
        ..crate::vortix_config::EngineSettings::default()
    };
    let settings = crate::vortix_config::Settings::load_from_config_dir_with_engine_defaults(
        config_dir,
        legacy_engine,
    )
    .map_err(|error| format!("Failed to resolve engine settings: {error}"))?;
    validate_engine_settings(&settings.engine)?;
    Ok(with_engine_settings(config, settings.engine))
}

fn validate_engine_settings(engine: &crate::vortix_config::EngineSettings) -> Result<(), String> {
    if !(1..=300).contains(&engine.wireguard_handshake_timeout_secs) {
        return Err("wireguard_handshake_timeout_secs must be between 1 and 300 seconds".into());
    }
    if !(1..=86_400).contains(&engine.wireguard_handshake_stale_secs) {
        return Err("wireguard_handshake_stale_secs must be between 1 and 86400 seconds".into());
    }
    if engine.wireguard_health_targets.len() > 64 {
        return Err("wireguard_health_targets accepts at most 64 addresses".into());
    }
    for target in &engine.wireguard_health_targets {
        target
            .parse::<std::net::IpAddr>()
            .map_err(|_| format!("wireguard_health_targets contains a non-IP address: {target}"))?;
    }
    Ok(())
}

fn with_engine_settings(
    mut config: AppConfig,
    engine: crate::vortix_config::EngineSettings,
) -> AppConfig {
    config.openvpn_verbosity = engine.openvpn_verbosity;
    config.connect_timeout = engine.connect_timeout_secs;
    config.wireguard_handshake_timeout_secs = engine.wireguard_handshake_timeout_secs;
    config.wireguard_handshake_stale_secs = engine.wireguard_handshake_stale_secs;
    config.ping_targets = engine.wireguard_health_targets;
    config
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
///
/// Logging policy: routes through `tracing` (never direct stdio) because
/// this can fire while the TUI owns the terminal — any `println!`/`eprintln!`
/// here would scramble ratatui's rendering. Two failure paths:
/// - `SUDO_UID` / `SUDO_GID` unset (vortix invoked as direct root, not via
///   sudo): chown is structurally impossible, no operator action available,
///   so we emit `tracing::debug!` only.
/// - chown call itself failed (`EPERM`, broken filesystem, etc.): real
///   failure the operator may want to know about — `tracing::warn!`.
pub fn fix_ownership(path: &Path) {
    if !crate::utils::is_root() {
        return;
    }
    if let Err(e) = chown_to_real_user(path) {
        if e.kind() == std::io::ErrorKind::NotFound {
            // SUDO_UID/SUDO_GID unset — running as direct root. The chown
            // is a no-op by design; nothing for the operator to act on.
            tracing::debug!(
                target: "vortix::config",
                path = %path.display(),
                "skipping chown: no SUDO_UID (direct-root invocation)"
            );
        } else {
            tracing::warn!(
                target: "vortix::config",
                path = %path.display(),
                err = %e,
                "failed to chown to invoking user; files may remain root-owned"
            );
        }
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
        assert_eq!(config.connect_timeout, 35);
        assert_eq!(config.ping_targets.len(), 4);
        assert_eq!(config.ipv6_check_apis.len(), 3);
        assert_eq!(config.ip_api_fallbacks.len(), 3);
        assert_eq!(
            config.geolocation_api_fallback,
            crate::constants::DEFAULT_GEOLOCATION_API_FALLBACK
        );
    }

    #[test]
    fn lifecycle_deadlines_keep_foreground_work_out_of_the_retry_budget() {
        let config = AppConfig::default();

        assert_eq!(
            config.connect_operation_timeout_secs(crate::state::Protocol::WireGuard),
            22
        );
        assert_eq!(
            config.connect_operation_timeout_secs(crate::state::Protocol::OpenVPN),
            37
        );
        assert_eq!(config.disconnect_operation_timeout_secs(), 32);
        assert_eq!(
            config.reconnect_operation_timeout_secs(crate::state::Protocol::WireGuard),
            52
        );
        assert_eq!(
            config.reconnect_operation_timeout_secs(crate::state::Protocol::OpenVPN),
            67
        );
        assert!(
            config.reconnect_operation_timeout_secs(crate::state::Protocol::OpenVPN)
                < crate::vortix_core::engine::state::DEFAULT_RETRY_BUDGET_SECS
        );
    }

    #[test]
    fn resolved_engine_values_are_the_factory_compatibility_carrier() {
        let resolved = with_engine_settings(
            AppConfig::default(),
            crate::vortix_config::EngineSettings {
                openvpn_verbosity: "6".into(),
                connect_timeout_secs: 17,
                wireguard_handshake_timeout_secs: 8,
                wireguard_handshake_stale_secs: 99,
                wireguard_health_targets: vec!["10.0.0.1".into()],
                ..crate::vortix_config::EngineSettings::default()
            },
        );
        assert_eq!(resolved.openvpn_verbosity, "6");
        assert_eq!(resolved.connect_timeout, 17);
        assert_eq!(resolved.wireguard_handshake_timeout_secs, 8);
        assert_eq!(resolved.wireguard_handshake_stale_secs, 99);
        assert_eq!(resolved.ping_targets, ["10.0.0.1"]);
    }

    #[test]
    fn invalid_wireguard_engine_settings_fail_before_factory_construction() {
        let invalid_timeout = crate::vortix_config::EngineSettings {
            wireguard_handshake_timeout_secs: 0,
            ..crate::vortix_config::EngineSettings::default()
        };
        assert!(validate_engine_settings(&invalid_timeout).is_err());

        let invalid_stale = crate::vortix_config::EngineSettings {
            wireguard_handshake_stale_secs: 0,
            ..crate::vortix_config::EngineSettings::default()
        };
        assert!(validate_engine_settings(&invalid_stale).is_err());

        let invalid_target = crate::vortix_config::EngineSettings {
            wireguard_health_targets: vec!["not-an-ip".into()],
            ..crate::vortix_config::EngineSettings::default()
        };
        assert!(validate_engine_settings(&invalid_target).is_err());

        let too_many_targets = crate::vortix_config::EngineSettings {
            wireguard_health_targets: (0..65).map(|_| "10.0.0.1".into()).collect(),
            ..crate::vortix_config::EngineSettings::default()
        };
        assert!(validate_engine_settings(&too_many_targets).is_err());
    }

    #[test]
    fn effective_config_reads_settings_from_supplied_directory() {
        let selected = tempfile::tempdir().unwrap();
        std::fs::write(
            selected.path().join("config.toml"),
            "wireguard_handshake_timeout_secs = 44\n",
        )
        .unwrap();
        std::fs::write(
            selected.path().join("settings.toml"),
            "[engine]\nwireguard_handshake_timeout_secs = 7\n",
        )
        .unwrap();

        let config = load_effective_config(selected.path()).unwrap();
        assert_eq!(config.wireguard_handshake_timeout_secs, 7);
    }

    // ---- load_config ----

    #[test]
    fn test_load_config_missing_file() {
        let dir = tempfile::Builder::new()
            .prefix("vortix_test_")
            .tempdir()
            .unwrap();

        let config = load_config(dir.path()).unwrap();
        assert_eq!(config.tick_rate, 1000);
    }

    #[test]
    fn test_load_config_partial() {
        let dir = tempfile::Builder::new()
            .prefix("vortix_test_")
            .tempdir()
            .unwrap();
        std::fs::write(dir.path().join("config.toml"), "tick_rate = 500\n").unwrap();

        let config = load_config(dir.path()).unwrap();
        assert_eq!(config.tick_rate, 500);
        assert_eq!(config.telemetry_poll_rate, 30); // default preserved
    }

    #[test]
    fn test_load_config_builtin_themes() {
        let dir = tempfile::Builder::new()
            .prefix("vortix_test_")
            .tempdir()
            .unwrap();
        for (value, expected) in [
            ("synthwave", crate::theme::ThemeChoice::Synthwave),
            ("terminal", crate::theme::ThemeChoice::Terminal),
            (
                "catppuccin-mocha",
                crate::theme::ThemeChoice::CatppuccinMocha,
            ),
            ("dracula", crate::theme::ThemeChoice::Dracula),
            ("nord", crate::theme::ThemeChoice::Nord),
            ("gruvbox-dark", crate::theme::ThemeChoice::GruvboxDark),
            ("tokyo-night", crate::theme::ThemeChoice::TokyoNight),
        ] {
            std::fs::write(
                dir.path().join("config.toml"),
                format!("theme = \"{value}\"\n"),
            )
            .unwrap();

            assert_eq!(load_config(dir.path()).unwrap().theme, expected);
        }
    }

    #[test]
    fn persist_theme_preserves_unrelated_config_and_comments() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(CONFIG_FILE);
        std::fs::write(
            &config_path,
            "# keep this comment\ntick_rate = 500\ntheme = \"synthwave\"\n",
        )
        .unwrap();
        persist_theme_choice(dir.path(), crate::theme::ThemeChoice::Terminal).unwrap();

        let saved = std::fs::read_to_string(&config_path).unwrap();
        assert!(saved.contains("# keep this comment"));
        assert!(saved.contains("tick_rate = 500"));
        assert!(saved.contains("theme = \"terminal\""));
        assert_eq!(
            load_config(dir.path()).unwrap().theme,
            crate::theme::ThemeChoice::Terminal
        );
    }

    #[test]
    fn persist_theme_creates_a_minimal_config() {
        let dir = tempfile::tempdir().unwrap();
        persist_theme_choice(dir.path(), crate::theme::ThemeChoice::Terminal).unwrap();

        assert_eq!(
            std::fs::read_to_string(dir.path().join(CONFIG_FILE)).unwrap(),
            "theme = \"terminal\"\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn persist_theme_refuses_a_symlinked_config() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "theme = \"synthwave\"\n").unwrap();
        symlink(outside.path(), dir.path().join(CONFIG_FILE)).unwrap();
        let error =
            persist_theme_choice(dir.path(), crate::theme::ThemeChoice::Terminal).unwrap_err();

        assert!(error.contains("safely read"));
        assert_eq!(
            std::fs::read_to_string(outside.path()).unwrap(),
            "theme = \"synthwave\"\n"
        );
    }

    #[test]
    fn persist_theme_leaves_invalid_config_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(CONFIG_FILE);
        let malformed = b"theme = [not valid toml";
        std::fs::write(&config_path, malformed).unwrap();

        let error =
            persist_theme_choice(dir.path(), crate::theme::ThemeChoice::Terminal).unwrap_err();

        assert!(error.contains("invalid"));
        assert_eq!(std::fs::read(&config_path).unwrap(), malformed);
    }

    #[test]
    fn persist_theme_leaves_non_utf8_config_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(CONFIG_FILE);
        let invalid_utf8 = [0xff, 0xfe, 0xfd];
        std::fs::write(&config_path, invalid_utf8).unwrap();

        let error =
            persist_theme_choice(dir.path(), crate::theme::ThemeChoice::Terminal).unwrap_err();

        assert!(error.contains("UTF-8"));
        assert_eq!(std::fs::read(&config_path).unwrap(), invalid_utf8);
    }

    #[test]
    fn persist_theme_refuses_to_publish_an_oversized_result() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(CONFIG_FILE);
        let framing = "note = \"\"\n";
        let payload_len = usize::try_from(MAX_CONFIG_BYTES).unwrap() - framing.len();
        let source = format!("note = \"{}\"\n", "a".repeat(payload_len));
        assert_eq!(source.len() as u64, MAX_CONFIG_BYTES);
        std::fs::write(&config_path, &source).unwrap();

        let error =
            persist_theme_choice(dir.path(), crate::theme::ThemeChoice::Terminal).unwrap_err();

        assert!(error.contains("would exceed"));
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), source);
    }

    #[cfg(unix)]
    #[test]
    fn published_theme_is_kept_when_directory_sync_is_uncertain() {
        let outcome = classify_theme_write(Err(
            crate::vortix_config::control_state::AtomicWriteError::PublishedButDirectoryUnsynced(
                crate::vortix_config::control_state::ControlStateError::Capacity,
            ),
        ))
        .unwrap();

        assert!(matches!(
            outcome,
            ThemePersistOutcome::PublishedDurabilityUncertain(_)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn persist_theme_refuses_writable_or_multiply_linked_config() {
        use std::os::unix::fs::PermissionsExt as _;

        let writable_dir = tempfile::tempdir().unwrap();
        let writable = writable_dir.path().join(CONFIG_FILE);
        std::fs::write(&writable, "theme = \"synthwave\"\n").unwrap();
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(
            persist_theme_choice(writable_dir.path(), crate::theme::ThemeChoice::Terminal)
                .unwrap_err()
                .contains("safely read")
        );

        let linked_dir = tempfile::tempdir().unwrap();
        let linked = linked_dir.path().join(CONFIG_FILE);
        std::fs::write(&linked, "theme = \"synthwave\"\n").unwrap();
        std::fs::hard_link(&linked, linked_dir.path().join("config.backup")).unwrap();
        assert!(
            persist_theme_choice(linked_dir.path(), crate::theme::ThemeChoice::Terminal)
                .unwrap_err()
                .contains("safely read")
        );
    }

    #[test]
    fn test_load_config_full_toml() {
        let dir = tempfile::Builder::new()
            .prefix("vortix_test_")
            .tempdir()
            .unwrap();

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
        std::fs::write(dir.path().join("config.toml"), toml_content).unwrap();

        let config = load_config(dir.path()).unwrap();
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
        assert_eq!(
            config.geolocation_api_fallback,
            crate::constants::DEFAULT_GEOLOCATION_API_FALLBACK,
            "existing configs must inherit the location fallback without migration"
        );
    }

    #[test]
    fn test_load_config_invalid_toml() {
        let dir = tempfile::Builder::new()
            .prefix("vortix_test_")
            .tempdir()
            .unwrap();
        std::fs::write(dir.path().join("config.toml"), "tick_rate = [invalid\n").unwrap();

        assert!(load_config(dir.path()).is_err());
    }

    #[test]
    fn test_load_config_unknown_field() {
        let dir = tempfile::Builder::new()
            .prefix("vortix_test_")
            .tempdir()
            .unwrap();
        std::fs::write(dir.path().join("config.toml"), "nonexistent_field = true\n").unwrap();

        assert!(load_config(dir.path()).is_err());
    }

    // ---- resolve_config_dir ----

    #[test]
    fn test_resolve_config_dir_with_override() {
        let tmp = tempfile::Builder::new()
            .prefix("vortix_test_")
            .tempdir()
            .unwrap();
        let custom = tmp.path().join("override_subdir");

        // Directory should not exist yet
        assert!(!custom.exists());

        let result = resolve_config_dir(Some(&custom)).unwrap();
        // Compare canonicalized paths (macOS: /var -> /private/var)
        let expected = std::fs::canonicalize(&custom).unwrap();
        assert_eq!(result, expected);
        // resolve_config_dir must create the directory
        assert!(custom.is_dir());
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
        let base = tempfile::Builder::new()
            .prefix("vortix_test_")
            .tempdir()
            .unwrap();

        let src = base.path().join("src_dir");
        let dst = base.path().join("dst_dir");

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
    }

    // ---- migrate_data ----

    #[test]
    fn test_migrate_data_moves_items() {
        let base = tempfile::Builder::new()
            .prefix("vortix_test_")
            .tempdir()
            .unwrap();

        let old = base.path().join("old");
        let new = base.path().join("new");

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
    }

    #[test]
    fn test_migrate_data_merges_into_empty_dirs() {
        let base = tempfile::Builder::new()
            .prefix("vortix_test_")
            .tempdir()
            .unwrap();

        let old = base.path().join("old");
        let new = base.path().join("new");

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
    }
}

#[cfg(all(test, unix))]
mod private_config_dir_tests {
    /// The config directory must be 0700 no matter what the umask allows.
    ///
    /// `create_dir_all` applies the caller's umask, so Ubuntu's default 002
    /// produced a group-writable 0775 that Vortix's own durable-state checks
    /// then rejected — every import failed on a fresh unprivileged first run
    /// with "persisted control state is not a private owner-controlled file".
    /// macOS hid it: 022 happens to yield an acceptable 0755.
    ///
    /// This deliberately does not set the umask: that is process-global and
    /// would race the rest of this binary's tests. It does not need to — any
    /// ordinary umask leaves `create_dir_all` short of 0700, so dropping the
    /// explicit `set_permissions` fails this assertion regardless.
    #[test]
    fn config_dir_is_created_private_regardless_of_umask() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("nested").join("vortix");
        let resolved = super::resolve_config_dir(Some(&target)).expect("config dir resolves");

        let mode = std::fs::metadata(&resolved).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "a group- or world-accessible config dir is refused by the durable-state checks"
        );
    }
}
