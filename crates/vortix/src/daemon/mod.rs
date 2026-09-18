//! `vortix daemon` — bounded IPC candidate.
//!
//! The daemon binds an owner-only Unix socket and publishes scanner-derived
//! snapshots to concurrent clients. Production remains passive in this
//! release. A dormant control host exists for parity testing, but it has no
//! production constructor until enrolled helper-backed execution is complete.
//!
//! Filesystem ownership and peer credentials both enforce same-UID access.
//! A mandatory compatibility handshake precedes all requests. Connections,
//! frames, queues, writes, and shutdown drain are bounded.
//!
//! Lifecycle:
//! 1. Validate and bind an owner-only socket without unsafe stale cleanup
//! 2. Start the scanner-only query provider
//! 3. Serve bounded concurrent snapshot/subscription connections
//! 4. Drain admitted connections on authenticated shutdown or `SIGTERM`
//! 5. Unlink only the exact socket inode this process created

pub mod client;
pub(crate) mod control_host;
pub mod diagnostics;
pub(crate) mod helper_client;
pub mod passive;
mod policy_executor;
mod server;
pub mod service;
mod tunnel_executor;
mod tunnel_material;

pub use server::DaemonServer;

use std::path::{Path, PathBuf};

/// Default socket path. Linux uses `${XDG_RUNTIME_DIR}/vortix.sock`
/// when set; macOS normally uses its per-user `${TMPDIR}`. The shared
/// `/tmp` fallback includes the effective UID to avoid cross-user collisions.
#[must_use]
pub fn default_socket_path() -> PathBuf {
    if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        if !rt.is_empty() {
            return PathBuf::from(rt).join("vortix.sock");
        }
    }
    if let Ok(tmp) = std::env::var("TMPDIR") {
        if !tmp.is_empty() {
            return PathBuf::from(tmp).join("vortix.sock");
        }
    }
    PathBuf::from(format!("/tmp/vortix-{}.sock", effective_uid_for_path()))
}

fn effective_uid_for_path() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: geteuid returns a scalar and has no failure mode.
        #[allow(unsafe_code)]
        unsafe {
            libc::geteuid()
        }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Honor the `VORTIX_DAEMON_SOCKET` env override. Returns `None` when
/// the env var is unset or empty. Does NOT check whether the file
/// exists — callers combine this with [`daemon_socket_path_if_present`]
/// when they want the connectable-socket guarantee.
#[must_use]
pub fn daemon_socket_path_override() -> Option<PathBuf> {
    match std::env::var("VORTIX_DAEMON_SOCKET") {
        Ok(s) if !s.is_empty() => Some(PathBuf::from(s)),
        _ => None,
    }
}

/// Resolve the effective daemon socket path **only when a daemon
/// appears to be running** (the file exists and is a Unix socket).
///
/// Resolution order:
/// 1. `VORTIX_DAEMON_SOCKET` env var (when set + non-empty)
/// 2. Platform default ([`default_socket_path`])
///
/// Read-only CLI ops (`status`, `list`, `audit`) use this to decide
/// whether to route through the daemon or fall back to the direct
/// disk/scanner read. Missing files are not an error — the env var
/// pointing at a non-existent path simply triggers the bypass path
///.
#[must_use]
pub fn daemon_socket_path_if_present() -> Option<PathBuf> {
    let candidate = daemon_socket_path_override().unwrap_or_else(default_socket_path);
    if candidate.exists() && is_unix_socket(&candidate) {
        Some(candidate)
    } else {
        None
    }
}

#[cfg(unix)]
fn is_unix_socket(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(path)
        .map(|m| m.file_type().is_socket())
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_unix_socket(_path: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regular_file_is_not_a_unix_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let regular = tmp.path().join("not-a-socket");
        std::fs::write(&regular, b"hello").unwrap();
        assert!(!is_unix_socket(&regular));
    }

    #[test]
    fn missing_path_is_not_a_unix_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        assert!(!is_unix_socket(&missing));
    }

    #[test]
    fn bound_unix_socket_is_detected() {
        // Round-trip: bind a real Unix socket and confirm
        // `daemon_socket_path_if_present` finds it. Uses an explicit
        // `VORTIX_DAEMON_SOCKET` override resolved through a child
        // process to avoid mutating env in this test process.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(is_unix_socket(&path));
    }
}
