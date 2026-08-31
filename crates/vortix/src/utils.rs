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

/// Effective process uid/gid without a subprocess lookup.
#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) fn effective_user_group_ids() -> (u32, u32) {
    // SAFETY: these libc calls return scalar process credentials.
    unsafe { (libc::geteuid(), libc::getegid()) }
}

/// Stable OS boot identity shared by persisted authority and verification.
#[cfg(target_os = "linux")] // xtask:allow-platform-cfg: boot identity uses the OS kernel primitive until U12 moves it behind a platform port
pub(crate) fn boot_identity() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Stable OS boot identity shared by persisted authority and verification.
#[cfg(target_os = "macos")]
// xtask:allow-platform-cfg: boot identity uses the OS kernel primitive until U12 moves it behind a platform port
#[allow(unsafe_code)]
pub(crate) fn boot_identity() -> Option<String> {
    let mut boot_time = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut size = std::mem::size_of::<libc::timeval>();
    // SAFETY: `kern.boottime` writes one timeval into the correctly sized,
    // aligned output buffer; no input buffer is supplied.
    let result = unsafe {
        libc::sysctlbyname(
            c"kern.boottime".as_ptr(),
            (&raw mut boot_time).cast(),
            &raw mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if result == 0 {
        Some(format!(
            "macos-boot:{}:{}",
            boot_time.tv_sec, boot_time.tv_usec
        ))
    } else {
        None
    }
}

/// Stable OS boot identity shared by persisted authority and verification.
#[cfg(not(any(target_os = "linux", target_os = "macos")))] // xtask:allow-platform-cfg: unsupported targets need an explicit non-authoritative boot identity
pub(crate) fn boot_identity() -> Option<String> {
    None
}

/// Milliseconds on the OS monotonic clock, stable across process restarts
/// within one boot. Persisted deadlines must never use process-local time.
#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) fn boot_elapsed_millis() -> Option<u64> {
    let mut time = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: `clock_gettime` initializes the supplied timespec when it
    // returns zero. CLOCK_MONOTONIC is process-independent and non-adjustable.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, time.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: the successful syscall above initialized the complete value.
    let time = unsafe { time.assume_init() };
    let seconds = u64::try_from(time.tv_sec).ok()?;
    let nanos = u64::try_from(time.tv_nsec).ok()?;
    Some(
        seconds
            .saturating_mul(1_000)
            .saturating_add(nanos / 1_000_000),
    )
}

#[cfg(not(unix))]
pub(crate) fn boot_elapsed_millis() -> Option<u64> {
    None
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
#[must_use]
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
#[must_use]
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

/// Returns the per-session temp config directory `${config_dir}/tmp/${session_id}/`.
///
/// Both the `tmp/` parent and the per-session subdir are forced to mode
/// `0o700` — the default umask would yield `0o755`, allowing any local
/// process to enumerate active session IDs by listing the parent. Used by
/// `WireGuard` secondary connect-time DNS scoping: the
/// secondary's rewritten `.conf` (with `DNS =` stripped) is written under
/// this subdir so crashed disconnects leave isolated orphans that the
/// startup sweep cleans only after acquiring their process-lifetime lease.
///
/// The subdir name matches the journal's `session_id` (`{ISO}-{pid}`), so a
/// new Vortix process is guaranteed a fresh namespace without mistaking a
/// concurrently running session for a crash orphan.
///
/// # Errors
///
/// Returns an error if the config directory cannot be resolved or if the
/// per-session subdirectory cannot be created at the required mode.
#[cfg(unix)]
pub fn get_tmp_config_dir(session_id: &str) -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::fs::DirBuilderExt;

    let root = get_app_config_dir()?;
    let tmp_root = root.join(crate::constants::TMP_CONFIG_DIR);

    // Create `tmp/` and the per-session subdir at 0o700 explicitly.
    // `recursive(true)` is idempotent on existing dirs but does NOT re-chmod
    // them, so on first creation we set the mode through DirBuilder; on
    // existing dirs we leave the mode alone (the only writer is this
    // process's prior call, which used the same mode).
    if !tmp_root.exists() {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&tmp_root)?;
        crate::config::fix_ownership(&tmp_root);
    }

    let session_dir = tmp_root.join(session_id);
    if !session_dir.exists() {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&session_dir)?;
        crate::config::fix_ownership(&session_dir);
    }

    Ok(session_dir)
}

/// Process-lifetime lease for one per-session scratch directory.
///
/// The kernel releases the advisory lock on every process exit path,
/// including crashes and [`std::process::exit`]. Keeping this value alive is
/// what distinguishes a concurrently running Vortix session from a crash
/// orphan; a different journal session ID alone is not proof of death.
#[cfg(unix)]
#[derive(Debug)]
pub struct TempSessionLease {
    _file: std::fs::File,
}

/// Resolve the scratch-session identity used by protocol-owned temporary
/// files, including when journal disk persistence is disabled.
#[must_use]
pub fn temp_session_id() -> String {
    crate::vortix_core::journal::global_journal()
        .and_then(crate::vortix_core::journal::Journal::session_id)
        .unwrap_or_else(|| format!("nojournal-{}", std::process::id()))
}

/// Create and exclusively lease this process's scratch-session directory.
///
/// # Errors
///
/// Returns an I/O error when the private directory or its no-follow lease
/// file cannot be created, or when another process already holds the same
/// session identity.
#[cfg(unix)]
pub fn acquire_temp_session_lease(
    config_dir: &std::path::Path,
    session_id: &str,
) -> std::io::Result<TempSessionLease> {
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
    use std::os::unix::io::AsRawFd as _;

    let tmp_root = config_dir.join(crate::constants::TMP_CONFIG_DIR);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(&tmp_root)?;
    let session_dir = tmp_root.join(session_id);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(&session_dir)?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(session_dir.join(".lease"))?;
    // SAFETY: `file` owns a valid descriptor for the lifetime of the lease;
    // flock changes only the kernel lock associated with that descriptor.
    #[allow(unsafe_code)]
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    crate::config::fix_ownership(&tmp_root);
    crate::config::fix_ownership(&session_dir);
    crate::config::fix_ownership(&session_dir.join(".lease"));
    Ok(TempSessionLease { _file: file })
}

#[cfg(unix)]
fn legacy_temp_session_process_is_live(session_id: &str) -> bool {
    let Some(pid) = session_id
        .rsplit_once('-')
        .and_then(|(_, pid)| pid.parse::<i32>().ok())
        .filter(|pid| *pid > 0)
    else {
        return false;
    };
    // SAFETY: signal zero is a side-effect-free existence probe. Permission
    // denial also proves that a process currently owns the PID.
    #[allow(unsafe_code)]
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// Remove only scratch sessions proven not to have a live process lease.
///
/// Directories from older Vortix releases have no `.lease`; during the
/// upgrade window their PID suffix remains a conservative liveness fallback.
/// Unknown or inaccessible entries are retained rather than risking deletion
/// of a live tunnel's teardown capability.
#[cfg(unix)]
pub fn sweep_orphan_temp_configs(config_dir: &std::path::Path, current_session_id: &str) {
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::io::AsRawFd as _;

    let tmp_dir = config_dir.join(crate::constants::TMP_CONFIG_DIR);
    let Ok(entries) = std::fs::read_dir(&tmp_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name == current_session_id || !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let lease = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(entry.path().join(".lease"));
        match lease {
            Ok(file) => {
                // SAFETY: `file` is an owned valid descriptor. A failed
                // nonblocking lock means a live process still owns it.
                #[allow(unsafe_code)]
                let result =
                    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
                if result != 0 {
                    continue;
                }
                let _ = std::fs::remove_dir_all(entry.path());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !legacy_temp_session_process_is_live(&name) {
                    let _ = std::fs::remove_dir_all(entry.path());
                }
            }
            Err(_) => {}
        }
    }
}

/// Non-Unix fallback: no `chmod`, just `create_dir_all` via `create_user_dir`.
///
/// # Errors
///
/// Returns an error if the config directory cannot be resolved or directory
/// creation fails.
#[cfg(not(unix))]
pub fn get_tmp_config_dir(session_id: &str) -> std::io::Result<std::path::PathBuf> {
    let root = get_app_config_dir()?;
    let session_dir = root.join(crate::constants::TMP_CONFIG_DIR).join(session_id);
    if !session_dir.exists() {
        create_user_dir(&session_dir)?;
    }
    Ok(session_dir)
}

/// Strip a profile name down to ASCII `[A-Za-z0-9_-]` for safe use in
/// daemon names, filenames, and process-match patterns.
pub use crate::vortix_core::profile::sanitize_profile_name;
use crate::vortix_core::profile::unambiguous_legacy_artifact_key;

pub(crate) fn validate_openvpn_artifact_key(key: &str) -> std::io::Result<()> {
    if !key.is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "OpenVPN artifact key contains unsafe characters",
        ))
    }
}

/// Returns `(pid_path, log_path)` for an opaque profile artifact key.
///
/// Production callers pass [`crate::vortix_core::profile::ProfileId::as_str`].
/// Display names are accepted only by explicit legacy compatibility helpers.
///
/// # Errors
///
/// Returns an error if directory creation fails.
pub fn get_openvpn_run_paths(
    profile_key: &str,
) -> std::io::Result<(std::path::PathBuf, std::path::PathBuf)> {
    validate_openvpn_artifact_key(profile_key)?;
    let root = get_app_config_dir()?;
    let run_dir = root.join(crate::constants::OPENVPN_RUN_DIR);

    if !run_dir.exists() {
        create_user_dir(&run_dir)?;
    }

    let pid_path = run_dir.join(format!("{profile_key}.pid"));
    let log_path = run_dir.join(format!("{profile_key}.log"));

    Ok((pid_path, log_path))
}

/// PIDs recorded in `<config_dir>/run/*.pid` — the `OpenVPN` daemons a
/// vortix session is tracking. Reads only the run dir (no profile
/// parsing), so it's cheap enough for the startup orphan scan.
#[must_use]
pub fn tracked_openvpn_pids() -> Vec<u32> {
    let Ok(root) = get_app_config_dir() else {
        return Vec::new();
    };
    let run_dir = root.join(crate::constants::OPENVPN_RUN_DIR);
    let Ok(entries) = std::fs::read_dir(run_dir) else {
        return Vec::new();
    };
    entries
        .filter_map(std::result::Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "pid"))
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .filter_map(|content| content.trim().parse::<u32>().ok())
        .collect()
}

/// Cleans up `OpenVPN` runtime files (pid, log) for a given profile.
pub fn cleanup_openvpn_run_files(profile_key: &str) {
    if let Ok((pid_path, log_path)) = get_openvpn_run_paths(profile_key) {
        let _ = std::fs::remove_file(&pid_path);
        let _ = std::fs::remove_file(&log_path);
    }
}

/// Reads the PID from an `OpenVPN` pid file.
#[must_use]
pub fn read_openvpn_pid(profile_key: &str) -> Option<u32> {
    let (pid_path, _) = get_openvpn_run_paths(profile_key).ok()?;
    let content = std::fs::read_to_string(&pid_path).ok()?;
    content.trim().parse::<u32>().ok()
}

/// Read a canonical ID-keyed PID, falling back to an unambiguous legacy
/// name-keyed artifact created by an older Vortix release.
#[must_use]
pub fn read_openvpn_pid_compat(profile_id: &str, legacy_display_name: &str) -> Option<u32> {
    read_openvpn_pid(profile_id)
        .or_else(|| unambiguous_legacy_artifact_key(legacy_display_name).and_then(read_openvpn_pid))
}

/// Remove canonical ID-keyed run files and, when collision-free, legacy
/// name-keyed files. Ambiguous sanitized legacy names are deliberately left
/// for manual cleanup rather than risking another profile's active daemon.
pub fn cleanup_openvpn_run_files_compat(profile_id: &str, legacy_display_name: &str) {
    cleanup_openvpn_run_files(profile_id);
    if let Some(legacy_key) = unambiguous_legacy_artifact_key(legacy_display_name) {
        if legacy_key != profile_id {
            cleanup_openvpn_run_files(legacy_key);
        }
    }
}

/// Path of the transient SCRV1 envelope auth file used for
/// static-challenge connects.
///
/// The connect path writes the envelope here, openvpn consumes it via
/// `--auth-user-pass`, and the protocol layer deletes it immediately
/// after the daemon fork. The canonical `<safe>.auth` is never
/// touched during connect — no race window for async callers to lose
/// against.
///
/// # Errors
///
/// Returns an error if the auth directory cannot be resolved or created.
pub fn get_openvpn_scrv1_auth_path(profile_key: &str) -> std::io::Result<std::path::PathBuf> {
    validate_openvpn_artifact_key(profile_key)?;
    let root = get_app_config_dir()?;
    let auth_dir = root.join(crate::constants::OPENVPN_AUTH_DIR);

    if !auth_dir.exists() {
        create_user_dir(&auth_dir)?;
    }

    Ok(auth_dir.join(format!("{profile_key}.scrv1.auth")))
}

/// Write a transient 3-line credentials bundle for the `OpenVPN`
/// management-socket auth flow. The protocol layer reads this file, drives the
/// `--management` socket dance with the embedded user/pass/otp, then
/// deletes the file. Each line is `<value>` followed by `\n`:
///
/// ```text
/// <username>\n
/// <password>\n
/// <otp>\n
/// ```
///
/// This is NOT an `OpenVPN` auth-user-pass file — `OpenVPN` 2.7 doesn't
/// consult `--auth-user-pass <file>` for the static-challenge case
/// (the prompt fires before the file is read; see the spike
/// outcome in the plan). The credentials reach openvpn via the
/// management socket, not via the file.
///
/// # Errors
///
/// Returns an error if the file write fails.
#[cfg(unix)]
pub fn write_openvpn_scrv1_auth_file(
    profile_name: &str,
    username: &str,
    password: &str,
    otp: &str,
) -> std::io::Result<std::path::PathBuf> {
    use crate::vortix_core::secret_file::{write_secret_file, SecretFileError};

    let auth_path = get_openvpn_scrv1_auth_path(profile_name)?;

    match std::fs::remove_file(&auth_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let body = format!("{username}\n{password}\n{otp}\n");
    write_secret_file(&auth_path, body.as_bytes()).map_err(|e| match e {
        SecretFileError::Io(io) => io,
        other => std::io::Error::other(other.to_string()),
    })?;

    Ok(auth_path)
}

/// Non-Unix fallback: same 3-line bundle, no chmod.
#[cfg(not(unix))]
pub fn write_openvpn_scrv1_auth_file(
    profile_name: &str,
    username: &str,
    password: &str,
    otp: &str,
) -> std::io::Result<std::path::PathBuf> {
    let auth_path = get_openvpn_scrv1_auth_path(profile_name)?;
    let body = format!("{username}\n{password}\n{otp}\n");
    write_user_file(&auth_path, body)?;
    Ok(auth_path)
}

/// Delete the static-challenge SCRV1 auth file for a profile if present.
pub fn delete_openvpn_scrv1_auth_file(profile_name: &str) {
    if let Ok(auth_path) = get_openvpn_scrv1_auth_path(profile_name) {
        let _ = std::fs::remove_file(&auth_path);
    }
}

/// Read a .ovpn config and return the `static-challenge` prompt text if the
/// directive is present.
///
/// Helper for the auth-overlay construction sites that need to know whether
/// to render a third (OTP) field. Parse-on-demand symmetric with
/// [`openvpn_config_needs_auth`]: we read the file at use-time rather than
/// caching the parsed profile on `Profile`. Returns `None` on any read or
/// parse failure so callers always degrade to the existing two-field flow.
#[must_use]
pub fn read_openvpn_static_challenge_prompt(config_path: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(config_path).ok()?;
    let parsed = crate::vortix_protocol_openvpn::parser::parse_ovpn_conf(&text).ok()?;
    parsed.static_challenge.map(|sc| sc.prompt)
}

/// Scan the `OpenVPN` auth directory and delete any leftover transient
/// `<safe>.scrv1.auth` credentials bundle.
///
/// The bundle is a 3-line `user\npass\notp\n` file the submit handler
/// writes for the protocol layer to consume at the start of a
/// static-challenge connect. The protocol layer deletes the file
/// immediately on read; if it's still on disk at vortix startup,
/// something crashed mid-connect and the file is now an orphaned
/// plaintext OTP that should never persist. The OTP would also be
/// stale (TOTP expires in 30s), so the only correct cleanup is
/// deletion — the user re-enters credentials on the next connect.
///
/// Silently skips files it can't read or delete — the scrubber must
/// not block app startup. Each deletion is logged at warn level with
/// the file name (NOT the file contents).
pub fn scrub_stale_scrv1_auth_files() {
    let Ok(root) = get_app_config_dir() else {
        return;
    };
    let auth_dir = root.join(crate::constants::OPENVPN_AUTH_DIR);
    let Ok(entries) = std::fs::read_dir(&auth_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if name.to_ascii_lowercase().ends_with(".scrv1.auth") {
            tracing::warn!(
                file = %name,
                "AUTH: stale credentials bundle — clearing"
            );
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Checks whether an `OpenVPN` config file contains `auth-user-pass` without a file argument.
///
/// Returns `true` if the config has a bare `auth-user-pass` directive (meaning
/// `OpenVPN` will prompt for credentials on stdin). Returns `false` if:
/// - The directive is absent
/// - The directive has a file path argument (`auth-user-pass /path/to/file`)
/// - The directive is commented out (`# auth-user-pass`)
#[must_use]
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
#[must_use]
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
#[must_use]
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
    let result =
        unsafe { libc::localtime_r(std::ptr::from_ref(&time_t), std::ptr::from_mut(&mut tm)) };
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
    // Non-Unix fallback via the `time` crate (no subprocess shell-out).
    use time::format_description::well_known::iso8601;
    let odt = time::OffsetDateTime::from(time);
    let format = time::format_description::parse("[hour]:[minute]:[second]").ok()?;
    let _ = iso8601;
    odt.format(&format).ok()
}

/// Formats a `SystemTime` into a compact relative time string (e.g., 1s, 2m, 3h, 4d).
#[must_use]
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
/// Uses the same platform-aware base-directory resolver as settings and
/// journal persistence.
#[must_use]
pub fn home_dir() -> Option<std::path::PathBuf> {
    directories::BaseDirs::new().map(|dirs| dirs.home_dir().to_path_buf())
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
#[must_use]
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

/// Check whether a named executable exists somewhere on `PATH`.
///
/// Walks `$PATH` entries directly via `std::env::split_paths` and checks
/// each for the binary — does NOT shell out to `which`. The earlier
/// `which`-based implementation broke on Fedora minimal containers
/// (and any other distro where the `which` binary itself is in a
/// separate package), where it would falsely report system-installed
/// binaries as missing. Catching this was the first regression the
/// matrixed Fedora integration test surfaced.
///
/// On Unix, also requires the file to have an executable bit set; on
/// other platforms, presence as a regular file is sufficient.
pub(crate) fn binary_exists(name: &str) -> bool {
    use std::env;

    let Ok(path) = env::var("PATH") else {
        return false;
    };

    for dir in env::split_paths(&path) {
        let candidate = dir.join(name);
        if !candidate.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = candidate.metadata() {
                if meta.permissions().mode() & 0o111 != 0 {
                    return true;
                }
            }
        }
        #[cfg(not(unix))]
        {
            return true;
        }
    }
    false
}

/// Locate a named executable on `$PATH` and return the first matching path.
///
/// Same PATH-walking + exec-bit check as [`binary_exists`], but returns
/// the actual path (`Some(PathBuf)`) instead of `bool`. Used by diagnostic
/// output (`vortix doctor` / `vortix info`) that needs to print where a
/// tool is installed.
///
/// replaces the residual `cmd_stdout("which", ...)` shell-outs
/// in `cli/report.rs` so vortix doesn't break on minimal-install systems
/// where `which` itself isn't in the default package set (e.g. Fedora
/// minimal containers).
pub(crate) fn find_binary_path(name: &str) -> Option<std::path::PathBuf> {
    use std::env;

    let path = env::var("PATH").ok()?;

    for dir in env::split_paths(&path) {
        let candidate = dir.join(name);
        let Ok(metadata) = candidate.metadata() else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 != 0 {
                return Some(candidate);
            }
        }
        #[cfg(not(unix))]
        {
            return Some(candidate);
        }
    }
    None
}

/// Check whether `resolvconf` is installed and functional.
///
/// Returns `true` only when the `resolvconf` binary exists **and** can
/// operate on the current system.  `openresolv` will fail with a
/// "signature mismatch" error when `systemd-resolved` manages
/// `/etc/resolv.conf`, so a simple `which resolvconf` is not enough.
#[cfg(target_os = "linux")] // xtask:allow-platform-cfg: resolvconf-shim probing is Linux-only DNS plumbing
pub(crate) fn resolvconf_works() -> bool {
    use crate::vortix_process::CommandSpec;
    use std::time::Duration;
    if !binary_exists("resolvconf") {
        return false;
    }
    // Test with `--version` which works with both openresolv and systemd-resolvconf.
    // `resolvconf -l` (list) is not supported by systemd-resolvconf's shim.
    //
    // The 10s cap mirrors the openvpn version-probe defense in
    // `vpn_runtime/openvpn.rs`: this probe is called from
    // `check_dependencies` on the UI thread during a connect press,
    // so a hung subprocess (broken DNS plumbing, locked /etc/resolv.conf,
    // an openresolv shim stuck on a syscall) would freeze the TUI until
    // the user kills it. 10s is generous for any healthy probe; on
    // timeout we return `false`, which routes the user to the existing
    // "resolvconf not available" error path — strictly better than a
    // wedged panel.
    crate::vortix_process::run_to_output(
        CommandSpec::oneshot("resolvconf", vec!["--version".into()])
            .timeout(Duration::from_secs(10)),
    )
    .is_ok_and(|o| o.status.success())
}

/// Check whether `resolvectl` is installed and functional.
///
/// Returns `true` only when the `resolvectl` binary exists **and** a
/// `--version` probe succeeds. `resolvectl` ships with systemd itself, so
/// presence on PATH plus a working probe is a sufficient signal that the
/// resolved per-link DNS API is callable.
///
/// The 10s cap mirrors the [`resolvconf_works`] probe shape — a hung
/// resolved/DBus would otherwise wedge the connect-success path on the
/// UI thread.
#[cfg(target_os = "linux")] // xtask:allow-platform-cfg: resolvectl probing is Linux-only DNS plumbing
pub(crate) fn resolvectl_works() -> bool {
    use crate::vortix_process::CommandSpec;
    use std::time::Duration;
    if !binary_exists("resolvectl") {
        return false;
    }
    crate::vortix_process::run_to_output(
        CommandSpec::oneshot("resolvectl", vec!["--version".into()])
            .timeout(Duration::from_secs(10)),
    )
    .is_ok_and(|o| o.status.success())
}

/// Should the resolvectl-based DNS path be used on this Linux host?
///
/// True when systemd-resolved is detected ([`is_systemd_resolved`]) AND
/// `resolvectl` works ([`resolvectl_works`]). False otherwise — callers
/// fall back to the legacy resolvconf path (the existing `wg-quick`
/// behaviour) when this returns false.
///
/// All callers (dep-check, `WgTunnel::up`) MUST go through this single
/// accessor so a subtle drift between two predicates can't make
/// `check_dependencies` say "OK, no resolvconf needed" while the tunnel
/// path then takes the resolvconf branch.
#[cfg(target_os = "linux")] // xtask:allow-platform-cfg: trigger gate is Linux-only DNS plumbing
pub(crate) fn use_resolvectl_path() -> bool {
    is_systemd_resolved() && resolvectl_works()
}

/// Detect whether `systemd-resolved` is managing DNS on this system.
///
/// Checks if `/etc/resolv.conf` is a symlink pointing into a
/// `systemd`-owned path (e.g. `/run/systemd/resolve/`).
#[cfg(target_os = "linux")] // xtask:allow-platform-cfg: systemd-resolved detection is Linux-only
pub(crate) fn is_systemd_resolved() -> bool {
    match std::fs::read_link("/etc/resolv.conf") {
        Ok(target) => {
            let s = target.to_string_lossy();
            s.contains("systemd") || s.contains("resolvconf/run")
        }
        Err(_) => false,
    }
}

/// Check whether a `WireGuard` config file contains a `DNS =` directive.
///
/// When `DNS` is present, `wg-quick` on Linux will invoke `resolvconf` to
/// manage DNS, which may not be installed on all distributions (e.g. Arch,
/// Fedora, NixOS).  This helper lets callers detect that situation early.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn wireguard_config_has_dns(config_path: &std::path::Path) -> bool {
    let Ok(content) = std::fs::read_to_string(config_path) else {
        return false;
    };
    for line in content.lines() {
        let trimmed = line.trim().to_lowercase();
        if trimmed.starts_with("dns") {
            // Match "dns = …" with optional whitespace around '='
            if let Some(rest) = trimmed.strip_prefix("dns") {
                let rest = rest.trim_start();
                if rest.starts_with('=') {
                    return true;
                }
            }
        }
    }
    false
}

/// Detect whether the kernel has IPv6 disabled.
///
/// True when `/proc/sys/net/ipv6` is absent (booted with
/// `ipv6.disable=1`) or either the `all` or `default` `disable_ipv6`
/// sysctl reads `1`. `default` matters because `wg-quick` creates a
/// fresh interface, which inherits the `default` setting.
#[cfg(target_os = "linux")] // xtask:allow-platform-cfg: /proc sysctl probe is Linux-only
pub(crate) fn host_ipv6_disabled() -> bool {
    if !std::path::Path::new("/proc/sys/net/ipv6").exists() {
        return true;
    }
    ["all", "default"].iter().any(|scope| {
        std::fs::read_to_string(format!("/proc/sys/net/ipv6/conf/{scope}/disable_ipv6"))
            .is_ok_and(|v| v.trim() == "1")
    })
}

/// Serialize lifecycle mutations across concurrent Vortix writers.
/// Enrollment-capable packages install an owner-readable lock in a fixed
/// root-controlled directory. Current clients retain the legacy lock while
/// also holding the installed lock, which keeps mixed-version writers
/// serialized during the preparatory release. Without it, two `vortix up`
/// invocations of the same
/// `OpenVPN` profile both spawn daemons and the second clobbers the
/// first's pidfile, orphaning it.
///
/// The lock is held for the returned `File`'s lifetime and released by
/// the OS on process exit — safe across `std::process::exit` paths. It fails
/// with [`std::io::ErrorKind::WouldBlock`] when another writer owns the lock;
/// a TUI may hold it for its entire session, so waiting would be unbounded.
///
/// Unix-only mutual exclusion: the non-Unix build opens the lockfile
/// without locking (a placeholder — vortix tunnels are unsupported on
/// Windows, so there is no lifecycle to serialize there yet).
/// Process-lifetime guard for the legacy and installed writer locks.
#[cfg(unix)]
#[derive(Debug)]
pub struct LifecycleLock {
    _legacy: std::fs::File,
    _installed: Option<std::fs::File>,
}

/// Process-lifetime guard for the legacy writer lock.
#[cfg(not(unix))]
#[derive(Debug)]
pub struct LifecycleLock {
    _legacy: std::fs::File,
}

/// Turn a lifecycle-lock failure into concise, actionable user-facing copy.
#[must_use]
pub fn lifecycle_lock_user_message(error: &std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return "Another Vortix process is managing VPN state. Close the running Vortix session or wait for its command to finish, then try again."
            .to_string();
    }
    format!("Vortix could not open its session lock: {error}")
}

#[cfg(unix)]
pub fn acquire_lifecycle_lock() -> std::io::Result<LifecycleLock> {
    let root = get_app_config_dir()?;
    let owner_uid = invoking_owner_uid()?;
    acquire_lifecycle_lock_at(&root, owner_uid, crate::authority_lock::acquire_installed)
}

#[cfg(unix)]
fn acquire_lifecycle_lock_at(
    root: &std::path::Path,
    owner_uid: u32,
    acquire_installed: impl FnOnce(u32) -> std::io::Result<Option<std::fs::File>>,
) -> std::io::Result<LifecycleLock> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.uid() != owner_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "the Vortix config directory is not owned by the invoking user",
        ));
    }
    let legacy = acquire_nonblocking_lock(&root.join("lifecycle.lock"))?;
    let installed = acquire_installed(owner_uid)?;
    Ok(LifecycleLock {
        _legacy: legacy,
        _installed: installed,
    })
}

#[cfg(unix)]
#[allow(unsafe_code, reason = "geteuid returns the scalar effective uid")]
fn invoking_owner_uid() -> std::io::Result<u32> {
    let effective_uid = unsafe { libc::geteuid() };
    invoking_owner_uid_from(effective_uid, std::env::var_os("SUDO_UID").as_deref())
}

#[cfg(unix)]
fn invoking_owner_uid_from(
    effective_uid: u32,
    sudo_uid: Option<&std::ffi::OsStr>,
) -> std::io::Result<u32> {
    if effective_uid != 0 {
        return Ok(effective_uid);
    }
    let Some(sudo_uid) = sudo_uid else {
        return Ok(0);
    };
    sudo_uid
        .to_string_lossy()
        .parse::<u32>()
        .ok()
        .filter(|uid| *uid != 0)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "SUDO_UID must identify the non-root invoking user",
            )
        })
}

#[cfg(unix)]
fn acquire_nonblocking_lock(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::io::AsRawFd as _;

    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)?;

    // SAFETY: flock is a thin syscall wrapper over a valid owned fd; no
    // buffers, no aliasing. Same invariant analysis as libc::kill in the
    // OpenVPN teardown path.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(file)
}

#[cfg(not(unix))]
pub fn acquire_lifecycle_lock() -> std::io::Result<LifecycleLock> {
    let root = get_app_config_dir()?;
    let legacy = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(root.join("lifecycle.lock"))?;
    Ok(LifecycleLock { _legacy: legacy })
}

/// Check whether a `WireGuard` config declares an IPv6 entry on an
/// `Address =` line. `wg-quick` runs `ip -6 address add` for each such
/// entry, which fails outright when the kernel has IPv6 disabled
/// (issue #242).
#[cfg(any(target_os = "linux", test))]
pub(crate) fn wireguard_config_has_ipv6_address(config_path: &std::path::Path) -> bool {
    let Ok(content) = std::fs::read_to_string(config_path) else {
        return false;
    };
    for line in content.lines() {
        let trimmed = line.trim().to_lowercase();
        let Some(rest) = trimmed.strip_prefix("address") else {
            continue;
        };
        let Some(rhs) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        let rhs = rhs.split(['#', ';']).next().unwrap_or("");
        for entry in rhs.split(',') {
            let ip_part = entry.trim().split('/').next().unwrap_or("");
            if ip_part.parse::<std::net::Ipv6Addr>().is_ok() {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[cfg(unix)]
    #[test]
    fn lifecycle_selector_holds_legacy_and_installed_locks_together() {
        use std::os::unix::fs::MetadataExt as _;

        let directory = tempfile::tempdir().unwrap();
        let installed_path = directory.path().join("installed.lock");
        std::fs::write(&installed_path, []).unwrap();
        let owner_uid = directory.path().metadata().unwrap().uid();
        let _guard = acquire_lifecycle_lock_at(directory.path(), owner_uid, |_| {
            acquire_nonblocking_lock(&installed_path).map(Some)
        })
        .unwrap();

        assert_eq!(
            acquire_nonblocking_lock(&directory.path().join("lifecycle.lock"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(
            acquire_nonblocking_lock(&installed_path)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_selector_uses_legacy_only_when_package_marker_is_absent() {
        use std::os::unix::fs::MetadataExt as _;

        let directory = tempfile::tempdir().unwrap();
        let owner_uid = directory.path().metadata().unwrap().uid();
        let _guard = acquire_lifecycle_lock_at(directory.path(), owner_uid, |_| Ok(None)).unwrap();

        assert_eq!(
            acquire_nonblocking_lock(&directory.path().join("lifecycle.lock"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_selector_never_falls_back_after_installed_lock_error() {
        use std::os::unix::fs::MetadataExt as _;

        let directory = tempfile::tempdir().unwrap();
        let owner_uid = directory.path().metadata().unwrap().uid();
        let result = acquire_lifecycle_lock_at(directory.path(), owner_uid, |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "invalid installed lock",
            ))
        });

        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(acquire_nonblocking_lock(&directory.path().join("lifecycle.lock")).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_selector_rejects_a_config_directory_owned_by_another_uid() {
        use std::os::unix::fs::MetadataExt as _;

        let directory = tempfile::tempdir().unwrap();
        let different_uid = directory.path().metadata().unwrap().uid().wrapping_add(1);
        let result = acquire_lifecycle_lock_at(directory.path(), different_uid, |_| Ok(None));

        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(!directory.path().join("lifecycle.lock").exists());
    }

    #[cfg(unix)]
    #[test]
    fn invoking_owner_identity_is_independent_of_the_config_path() {
        assert_eq!(invoking_owner_uid_from(501, None).unwrap(), 501);
        assert_eq!(
            invoking_owner_uid_from(0, Some(std::ffi::OsStr::new("502"))).unwrap(),
            502
        );
        assert!(invoking_owner_uid_from(0, Some(std::ffi::OsStr::new("0"))).is_err());
        assert!(invoking_owner_uid_from(0, Some(std::ffi::OsStr::new("invalid"))).is_err());
    }

    #[test]
    fn busy_lifecycle_lock_has_a_plain_user_message() {
        let error = std::io::Error::from(std::io::ErrorKind::WouldBlock);

        let message = lifecycle_lock_user_message(&error);

        assert_eq!(
            message,
            "Another Vortix process is managing VPN state. Close the running Vortix session or wait for its command to finish, then try again."
        );
        assert!(!message.contains("Resource temporarily unavailable"));
    }

    // ───── binary_exists ─────────────────────────────────────────────────

    #[test]
    fn binary_exists_finds_a_known_present_unix_binary() {
        // `sh` is part of POSIX and present on every Unix CI runner we
        // support (macOS, Ubuntu, Fedora). On Windows the test simply
        // asserts the function doesn't panic — non-Unix runners don't
        // have a guaranteed binary at a known PATH location.
        #[cfg(unix)]
        assert!(
            binary_exists("sh"),
            "binary_exists should locate `sh` on Unix-like PATH"
        );
        #[cfg(not(unix))]
        let _ = binary_exists("sh");
    }

    #[test]
    fn binary_exists_returns_false_for_known_absent_binary() {
        // Pick a name that almost certainly won't exist on any runner.
        // If this ever flakes, the runner has a binary called
        // `vortix-nonexistent-xyz123` and we have bigger problems.
        assert!(!binary_exists("vortix-nonexistent-xyz123"));
    }

    // NOTE: Earlier draft had an "empty PATH" test that mutated
    // env::PATH and restored it. Dropped because:
    //   1. env::set_var / env::remove_var are unsafe in modern Rust
    //      (process-wide global state; not thread-safe under cargo
    //      test's parallel runner).
    //   2. The function's behavior on PATH=unset is trivially
    //      `false` via the `let Ok(path) = env::var("PATH") else`
    //      guard — covered by inspection, not worth a racy test.

    // ───── find_binary_path ─────────────────────────────────

    #[test]
    fn find_binary_path_returns_existing_path_for_known_unix_binary() {
        #[cfg(unix)]
        {
            let path =
                find_binary_path("sh").expect("`sh` should be locatable on every Unix CI runner");
            assert!(path.is_file(), "returned path must exist on disk: {path:?}");
            assert!(
                path.ends_with("sh"),
                "returned path's filename should be `sh`: {path:?}"
            );
        }
    }

    #[test]
    fn find_binary_path_returns_none_for_known_absent_binary() {
        assert!(find_binary_path("vortix-nonexistent-xyz123").is_none());
    }

    #[test]
    fn find_binary_path_and_binary_exists_agree() {
        // Invariant: `binary_exists(x)` must equal `find_binary_path(x).is_some()`
        // for every input. The two functions share PATH-walking logic; they
        // should never disagree.
        for name in ["sh", "vortix-nonexistent-xyz123", "cat", "another-fake"] {
            assert_eq!(
                binary_exists(name),
                find_binary_path(name).is_some(),
                "binary_exists and find_binary_path disagree on `{name}`"
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────

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
        let dir = tempfile::Builder::new()
            .prefix("vortix_test_")
            .tempdir()
            .unwrap();

        let path = get_unique_path(dir.path(), "test.conf");
        assert_eq!(path.file_name().unwrap(), "test.conf");
    }

    #[test]
    fn test_get_unique_path_with_collision() {
        let dir = tempfile::Builder::new()
            .prefix("vortix_test_")
            .tempdir()
            .unwrap();

        // Create the file that will collide
        std::fs::write(dir.path().join("test.conf"), "existing").unwrap();

        let path = get_unique_path(dir.path(), "test.conf");
        assert_eq!(path.file_name().unwrap(), "test_1.conf");

        // Create that too
        std::fs::write(dir.path().join("test_1.conf"), "also existing").unwrap();
        let path2 = get_unique_path(dir.path(), "test.conf");
        assert_eq!(path2.file_name().unwrap(), "test_2.conf");
    }

    // === OpenVPN auth-user-pass detection tests ===

    #[test]
    fn test_openvpn_config_needs_auth_bare_directive() {
        let dir = tempfile::Builder::new()
            .prefix("vortix_test_")
            .tempdir()
            .unwrap();
        let path = dir.path().join("test.ovpn");
        std::fs::write(
            &path,
            "client\nremote example.com 1194\nauth-user-pass\ndev tun\n",
        )
        .unwrap();
        assert!(openvpn_config_needs_auth(&path));
    }

    #[test]
    fn test_openvpn_config_needs_auth_bare_with_trailing_space() {
        let dir = tempfile::Builder::new()
            .prefix("vortix_test_")
            .tempdir()
            .unwrap();
        let path = dir.path().join("test.ovpn");
        std::fs::write(
            &path,
            "client\nremote example.com 1194\nauth-user-pass   \ndev tun\n",
        )
        .unwrap();
        assert!(openvpn_config_needs_auth(&path));
    }

    #[test]
    fn test_openvpn_config_needs_auth_with_file_arg() {
        let dir = tempfile::Builder::new()
            .prefix("vortix_test_")
            .tempdir()
            .unwrap();
        let path = dir.path().join("test.ovpn");
        std::fs::write(
            &path,
            "client\nremote example.com 1194\nauth-user-pass /etc/openvpn/creds.txt\ndev tun\n",
        )
        .unwrap();
        assert!(!openvpn_config_needs_auth(&path));
    }

    #[test]
    fn test_openvpn_config_needs_auth_absent() {
        let dir = tempfile::Builder::new()
            .prefix("vortix_test_")
            .tempdir()
            .unwrap();
        let path = dir.path().join("test.ovpn");
        std::fs::write(
            &path,
            "client\nremote example.com 1194\ndev tun\nproto udp\n",
        )
        .unwrap();
        assert!(!openvpn_config_needs_auth(&path));
    }

    #[test]
    fn test_openvpn_config_needs_auth_commented_out() {
        let dir = tempfile::Builder::new()
            .prefix("vortix_test_")
            .tempdir()
            .unwrap();
        let path = dir.path().join("test.ovpn");
        std::fs::write(
            &path,
            "client\nremote example.com 1194\n# auth-user-pass\n; auth-user-pass\ndev tun\n",
        )
        .unwrap();
        assert!(!openvpn_config_needs_auth(&path));
    }

    #[test]
    fn test_openvpn_config_needs_auth_nonexistent_file() {
        let path = std::path::PathBuf::from("/tmp/nonexistent_vortix_config_12345.ovpn");
        assert!(!openvpn_config_needs_auth(&path));
    }

    // === OpenVPN auth file write/read tests ===

    /// Global mutex serialising any test that mutates the process-wide
    /// config dir via `set_config_dir`. Without this, parallel test
    /// execution races on the shared global — one test's write returns
    /// a path under its temp dir, but a concurrent test resets the
    /// global before the metadata check, causing the original path to
    /// resolve to a now-deleted location. Hold the guard for the test's
    /// full lifetime.
    static CONFIG_DIR_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn set_temp_config_dir() -> (tempfile::TempDir, std::sync::MutexGuard<'static, ()>) {
        let guard = CONFIG_DIR_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::Builder::new()
            .prefix("vortix_utils_test_")
            .tempdir()
            .unwrap();
        crate::config::set_config_dir(dir.path().to_path_buf());
        (dir, guard)
    }

    #[test]
    fn scrub_deletes_scrv1_bundle_and_leaves_canonical_auth_alone() {
        let _tmp = set_temp_config_dir();
        // Plain canonical `<safe>.auth` (should survive scrub) and a
        // transient `<safe>.scrv1.auth` bundle (should be deleted).
        let auth_dir = get_app_config_dir()
            .unwrap()
            .join(crate::constants::OPENVPN_AUTH_DIR);
        create_user_dir(&auth_dir).unwrap();
        let plain = auth_dir.join("scrub-plain.auth");
        std::fs::write(&plain, "u\np\n").unwrap();
        let bundle = write_openvpn_scrv1_auth_file("scrub-bundle", "u", "p", "123456").unwrap();
        assert!(plain.exists());
        assert!(bundle.exists());

        scrub_stale_scrv1_auth_files();

        assert!(plain.exists(), "canonical .auth file must survive scrub");
        assert!(
            !bundle.exists(),
            ".scrv1.auth bundle must be deleted by scrub"
        );
        std::fs::remove_file(plain).unwrap();
    }

    #[test]
    fn scrub_no_op_when_auth_dir_missing() {
        // Set a temp config dir with no `auth/` subdir created. The scrub
        // must not panic or error.
        let _tmp = set_temp_config_dir();
        scrub_stale_scrv1_auth_files();
        // No assertion needed — the test passes by not panicking.
    }

    #[test]
    fn test_sanitize_profile_name_ascii() {
        assert_eq!(sanitize_profile_name("my-vpn_1"), "my-vpn_1");
    }

    #[test]
    fn test_sanitize_profile_name_spaces() {
        assert_eq!(sanitize_profile_name("my vpn server"), "my_vpn_server");
    }

    #[test]
    fn test_sanitize_profile_name_special_chars() {
        assert_eq!(sanitize_profile_name("vpn@home!#$"), "vpn_home___");
    }

    #[test]
    fn test_sanitize_profile_name_unicode_rejected() {
        assert_eq!(sanitize_profile_name("café-vpn"), "caf_-vpn");
        assert_eq!(sanitize_profile_name("München"), "M_nchen");
    }

    #[test]
    fn test_sanitize_profile_name_cjk() {
        assert_eq!(sanitize_profile_name("日本VPN"), "__VPN");
    }

    #[test]
    fn test_sanitize_profile_name_empty() {
        assert_eq!(sanitize_profile_name(""), "");
    }

    #[test]
    fn test_truncate_very_small_budget() {
        assert_eq!(truncate("hello world", 3), "...");
        assert_eq!(truncate("hello world", 2), "...");
        assert_eq!(truncate("hello world", 0), "...");
    }

    // --- wireguard_config_has_dns tests ---

    #[test]
    fn test_wg_config_has_dns_present() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg0.conf");
        std::fs::write(
            &path,
            "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/24\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = xyz\nEndpoint = 1.2.3.4:51820\n",
        )
        .unwrap();
        assert!(wireguard_config_has_dns(&path));
    }

    #[test]
    fn test_wg_config_has_dns_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg0.conf");
        std::fs::write(
            &path,
            "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/24\n\n[Peer]\nPublicKey = xyz\nEndpoint = 1.2.3.4:51820\n",
        )
        .unwrap();
        assert!(!wireguard_config_has_dns(&path));
    }

    #[test]
    fn test_wg_config_has_dns_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg0.conf");
        std::fs::write(
            &path,
            "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/24\ndns = 8.8.8.8\n\n[Peer]\nPublicKey = xyz\nEndpoint = 1.2.3.4:51820\n",
        )
        .unwrap();
        assert!(wireguard_config_has_dns(&path));
    }

    #[test]
    fn test_wg_config_has_dns_with_spaces() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg0.conf");
        std::fs::write(
            &path,
            "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/24\n  DNS  =  1.1.1.1, 8.8.8.8\n\n[Peer]\nPublicKey = xyz\nEndpoint = 1.2.3.4:51820\n",
        )
        .unwrap();
        assert!(wireguard_config_has_dns(&path));
    }

    #[test]
    fn test_wg_config_has_dns_nonexistent_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.conf");
        assert!(!wireguard_config_has_dns(&path));
    }

    #[test]
    fn test_wg_config_dns_in_comment_not_matched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg0.conf");
        // A comment like "# DNS = ..." should not be matched since it starts
        // with '#', not 'dns' after trimming.
        std::fs::write(
            &path,
            "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/24\n# DNS = 1.1.1.1\n\n[Peer]\nPublicKey = xyz\nEndpoint = 1.2.3.4:51820\n",
        )
        .unwrap();
        assert!(!wireguard_config_has_dns(&path));
    }

    // --- wireguard_config_has_ipv6_address tests (issue #242) ---

    fn write_wg_conf(address_line: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg0.conf");
        std::fs::write(
            &path,
            format!(
                "[Interface]\nPrivateKey = abc\n{address_line}\n\n[Peer]\nPublicKey = xyz\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 1.2.3.4:51820\n"
            ),
        )
        .unwrap();
        (dir, path)
    }

    #[test]
    fn test_wg_config_ipv6_address_v4_only_is_false() {
        let (_dir, path) = write_wg_conf("Address = 10.0.0.2/24");
        assert!(!wireguard_config_has_ipv6_address(&path));
    }

    #[test]
    fn test_wg_config_ipv6_address_mixed_v4_v6_is_true() {
        let (_dir, path) = write_wg_conf("Address = 10.0.0.2/24, fd00::2/64");
        assert!(wireguard_config_has_ipv6_address(&path));
    }

    #[test]
    fn test_wg_config_ipv6_address_v6_only_is_true() {
        let (_dir, path) = write_wg_conf("Address = fd00::2/128");
        assert!(wireguard_config_has_ipv6_address(&path));
    }

    #[test]
    fn test_wg_config_ipv6_address_no_address_line_is_false() {
        let (_dir, path) = write_wg_conf("MTU = 1420");
        assert!(!wireguard_config_has_ipv6_address(&path));
    }

    #[test]
    fn test_wg_config_ipv6_address_case_insensitive() {
        let (_dir, path) = write_wg_conf("address = FD00::2/64");
        assert!(wireguard_config_has_ipv6_address(&path));
    }

    #[test]
    fn test_wg_config_ipv6_address_trailing_comment_stripped() {
        let (_dir, path) = write_wg_conf("Address = 10.0.0.2/24 # fd00::2 mentioned in comment");
        assert!(!wireguard_config_has_ipv6_address(&path));
    }

    #[test]
    fn test_wg_config_ipv6_address_v6_allowed_ips_alone_is_false() {
        // Fixture's AllowedIPs carries ::/0; only the Address line
        // triggers `ip -6 address add`, so this must not fire.
        let (_dir, path) = write_wg_conf("Address = 10.0.0.2/24");
        assert!(!wireguard_config_has_ipv6_address(&path));
    }

    #[test]
    fn test_wg_config_ipv6_address_nonexistent_file_is_false() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!wireguard_config_has_ipv6_address(
            &dir.path().join("missing.conf")
        ));
    }

    // --- get_tmp_config_dir ---

    #[cfg(unix)]
    #[test]
    fn test_get_tmp_config_dir_creates_session_subdir_at_0700() {
        use std::os::unix::fs::PermissionsExt;

        // `set_temp_config_dir` writes via `set_config_dir`'s `OnceLock` —
        // first writer wins across the whole test binary. Sibling tests are
        // unaffected because each test passes a unique session_id; subdirs
        // therefore can't collide even when they share a `tmp/` root.
        let _tmp = set_temp_config_dir();
        let sid = format!("session-{}-{}", std::process::id(), line!());
        let session_dir = get_tmp_config_dir(&sid).unwrap();
        assert!(session_dir.ends_with(format!("tmp/{sid}")));

        let leaf_perms = std::fs::metadata(&session_dir).unwrap().permissions();
        assert_eq!(leaf_perms.mode() & 0o777, 0o700);

        // `tmp/` root is tightened to 0o700 — default umask would produce
        // 0o755 and leak session IDs via readdir.
        let tmp_root = session_dir.parent().unwrap();
        let root_perms = std::fs::metadata(tmp_root).unwrap().permissions();
        assert_eq!(root_perms.mode() & 0o777, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn test_get_tmp_config_dir_is_idempotent() {
        let _tmp = set_temp_config_dir();
        let sid = format!("idempotent-{}-{}", std::process::id(), line!());
        let a = get_tmp_config_dir(&sid).unwrap();
        let b = get_tmp_config_dir(&sid).unwrap();
        assert_eq!(a, b);
        assert!(a.exists());
    }
}
