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
/// `WireGuard` secondary connect-time DNS scoping (plan #009 U13): the
/// secondary's rewritten `.conf` (with `DNS =` stripped) is written under
/// this subdir so crashed disconnects leave isolated orphans that the
/// startup sweep cleans by session-liveness check (subdir name ≠ current
/// `session_id`).
///
/// The subdir name matches the journal's `session_id` (`{ISO}-{pid}`), so a
/// new vortix process is guaranteed a fresh subdir name; the prior session's
/// subdir is unambiguously an orphan regardless of age.
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

/// Returns the `OpenVPN` runtime directory path for a given profile.
///
/// Creates `~/.config/vortix/run/` if it doesn't exist.
/// Strip a profile name down to ASCII `[A-Za-z0-9_-]` so it is safe for use
/// in daemon names, filenames, and pkill regex patterns.
#[must_use]
pub fn sanitize_profile_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

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

    let safe_name = sanitize_profile_name(profile_name);

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
#[must_use]
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

    let safe_name = sanitize_profile_name(profile_name);
    Ok(auth_dir.join(format!("{safe_name}.auth")))
}

/// Build the auth-file body. Line 1 is the username; line 2 is the
/// plain password. The canonical `<safe>.auth` file is reserved for
/// non-MFA `auth-user-pass` flows — `OpenVPN` 2.7's static-challenge
/// path does NOT consume SCRV1 envelopes from this file (the OTP
/// prompt fires before the file is read; see the U0 spike outcome in
/// `docs/plans/2026-06-02-001-feat-openvpn-static-challenge-plan.md`).
/// MFA credentials flow through the transient sibling file (see
/// [`write_openvpn_scrv1_auth_file`]) and reach openvpn via the
/// management socket.
fn format_openvpn_auth_body(username: &str, password: &str) -> String {
    format!("{username}\n{password}\n")
}

/// Path of the transient SCRV1 envelope auth file used for
/// static-challenge connects (plan 2026-06-02-001 U3 / PF-2, #191).
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
pub fn get_openvpn_scrv1_auth_path(profile_name: &str) -> std::io::Result<std::path::PathBuf> {
    let root = get_app_config_dir()?;
    let auth_dir = root.join(crate::constants::OPENVPN_AUTH_DIR);

    if !auth_dir.exists() {
        create_user_dir(&auth_dir)?;
    }

    let safe_name = sanitize_profile_name(profile_name);
    Ok(auth_dir.join(format!("{safe_name}.scrv1.auth")))
}

/// Write a transient 3-line credentials bundle for the `OpenVPN`
/// management-socket auth flow (plan 2026-06-02-001, #191, Approach
/// B-minimal). The protocol layer reads this file, drives the
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
/// (the prompt fires before the file is read; see the U0 spike
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

/// Write the canonical `<safe>.auth` credentials file: line 1 username,
/// line 2 password, both in plain text.
///
/// Reserved for non-MFA `auth-user-pass` profiles. Static-challenge
/// (MFA) profiles route credentials through a transient sibling file
/// (see [`write_openvpn_scrv1_auth_file`]) and reach openvpn via the
/// management socket -- the canonical `.auth` file is never used for
/// SCRV1 envelopes because `OpenVPN` 2.7's static-challenge path
/// prompts stdin for the OTP before reading the file (see the U0
/// spike outcome in
/// `docs/plans/2026-06-02-001-feat-openvpn-static-challenge-plan.md`).
///
/// The file is created with `chmod 600` (owner read/write only) in a
/// single step via [`crate::vortix_core::secret_file::write_secret_file`],
/// which uses `openat(2)` against a held parent-directory fd to close
/// the parent-directory TOCTOU window. If the auth file already
/// exists from a previous run, it is removed first so the credential
/// rewrite succeeds.
///
/// # Errors
///
/// Returns an error if file write fails.
#[cfg(unix)]
pub fn write_openvpn_auth_file(
    profile_name: &str,
    username: &str,
    password: &str,
) -> std::io::Result<std::path::PathBuf> {
    use crate::vortix_core::secret_file::{write_secret_file, SecretFileError};

    let auth_path = get_openvpn_auth_path(profile_name)?;

    // The credential-safe helper refuses to overwrite. Remove any stale
    // file from a prior run so a credential rotation still lands. Ignore
    // NotFound — the file simply doesn't exist yet on first use.
    match std::fs::remove_file(&auth_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let body = format_openvpn_auth_body(username, password);
    write_secret_file(&auth_path, body.as_bytes()).map_err(|e| match e {
        SecretFileError::Io(io) => io,
        other => std::io::Error::other(other.to_string()),
    })?;

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
    let body = format_openvpn_auth_body(username, password);
    write_user_file(&auth_path, body)?;
    Ok(auth_path)
}

/// Reads saved `OpenVPN` credentials from the auth file.
///
/// Returns `Some((username, password))` if a valid auth file exists.
#[must_use]
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
/// `<safe>.scrv1.auth` credentials bundle (plan 2026-06-02-001 U6, #191).
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
/// Plan 002 U1: replaces the residual `cmd_stdout("which", ...)` shell-outs
/// in `cli/report.rs` so vortix doesn't break on minimal-install systems
/// where `which` itself isn't in the default package set (e.g. Fedora
/// minimal containers).
pub(crate) fn find_binary_path(name: &str) -> Option<std::path::PathBuf> {
    use std::env;

    let path = env::var("PATH").ok()?;

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
                    return Some(candidate);
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

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

    // ───── find_binary_path (plan 002 U1) ─────────────────────────────────

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
    fn test_write_read_openvpn_auth_file() {
        let _tmp = set_temp_config_dir();
        let name = "test_auth_roundtrip";
        let result = write_openvpn_auth_file(name, "myuser", "mypass");
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.exists());

        let creds = read_openvpn_saved_auth(name);
        assert!(creds.is_some());
        let (user, pass) = creds.unwrap();
        assert_eq!(user, "myuser");
        assert_eq!(pass, "mypass");

        delete_openvpn_auth_file(name);
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_auth_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let _tmp = set_temp_config_dir();
        let name = "test_auth_perms";
        let result = write_openvpn_auth_file(name, "user", "pass");
        assert!(result.is_ok());
        let path = result.unwrap();

        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);

        delete_openvpn_auth_file(name);
    }

    #[test]
    fn auth_file_format_is_username_then_password() {
        // Byte-for-byte: canonical `<safe>.auth` is always plain
        // `username\npassword\n`. Static-challenge OTPs go via the
        // transient sibling file + management socket -- never here.
        let body = format_openvpn_auth_body("u", "p");
        assert_eq!(body, "u\np\n");
    }

    #[test]
    fn scrub_deletes_scrv1_bundle_and_leaves_canonical_auth_alone() {
        let _tmp = set_temp_config_dir();
        // Plain canonical `<safe>.auth` (should survive scrub) and a
        // transient `<safe>.scrv1.auth` bundle (should be deleted).
        let plain = write_openvpn_auth_file("scrub-plain", "u", "p").unwrap();
        let bundle = write_openvpn_scrv1_auth_file("scrub-bundle", "u", "p", "123456").unwrap();
        assert!(plain.exists());
        assert!(bundle.exists());

        scrub_stale_scrv1_auth_files();

        assert!(plain.exists(), "canonical .auth file must survive scrub");
        assert!(
            !bundle.exists(),
            ".scrv1.auth bundle must be deleted by scrub"
        );

        delete_openvpn_auth_file("scrub-plain");
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

    #[test]
    fn test_read_openvpn_saved_auth_missing_file() {
        let creds = read_openvpn_saved_auth("nonexistent_profile_xyz_12345");
        assert!(creds.is_none());
    }

    #[test]
    fn test_read_openvpn_saved_auth_empty_creds() {
        let _tmp = set_temp_config_dir();
        let name = "test_auth_empty_creds";
        let path = get_openvpn_auth_path(name).unwrap();
        std::fs::write(&path, "\npassword\n").unwrap();
        assert!(read_openvpn_saved_auth(name).is_none());

        std::fs::write(&path, "username\n\n").unwrap();
        assert!(read_openvpn_saved_auth(name).is_none());

        delete_openvpn_auth_file(name);
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

    // --- get_tmp_config_dir (U13) ---

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
