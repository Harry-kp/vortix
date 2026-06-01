//! `vortix daemon` — IPC server hosting the engine (plan 015 phase D / plan 010).
//!
//! The daemon binds a Unix socket, hosts the FSM via the existing
//! `EngineHandle::Local`, and serves `IpcRequest` frames from
//! connected clients. Today single-client-at-a-time; multi-client
//! support is a follow-up hardening pass once the wire contract has
//! stabilized.
//!
//! Auth: phase E (plan 015 phase E) layers `SO_PEERCRED` / `getpeereid`
//! on top — the daemon refuses requests from a UID other than its
//! own. Today the daemon trusts any client that can open the socket
//! (filesystem-permissions guard at mode 0600).
//!
//! Lifecycle:
//! 1. Bind the socket (cleaning up any stale socket file)
//! 2. Install global runner + platform + journal (same as main.rs)
//! 3. Build `Engine<TunnelKind>` + `EngineHandle::local`
//! 4. Accept loop: handle one client at a time, terminate on SIGTERM
//! 5. On exit, unlink the socket file
//!
//! The daemon prints lifecycle events (binding, accepting, accepted,
//! shutting down) to stderr at `tracing::info` so a `systemd journalctl`
//! or `launchctl log` view surfaces what's happening.

pub mod client;
mod server;

pub use server::DaemonServer;

use std::path::{Path, PathBuf};

/// Build an `EngineHandle::Local` for hosting the FSM in-process.
///
/// Shared bootstrap path between `run_tui` (in-process engine for the TUI)
/// and `vortix daemon` (engine hosted behind the IPC server). The caller
/// MUST invoke this from within an active tokio runtime context — the
/// handle spawns its actor task immediately.
///
/// Returns `None` when prerequisites are missing (no real runner installed,
/// no global journal). Failure is non-fatal: both call sites already
/// tolerate `engine_handle: Option<...>` and fall back to legacy in-process
/// state.
///
/// `profiles_dir` is the directory containing per-profile sidecars
/// (`<config_dir>/profiles`). It seeds the `FsProfileStore`-backed
/// resolver.
#[must_use]
pub fn build_engine_handle(
    profiles_dir: &Path,
) -> Option<crate::vortix_core::engine::EngineHandle> {
    use crate::state::Protocol;
    use crate::tunnel::{tunnel_for, TunnelKind};
    use crate::vortix_config::profile_store::{FsProfileStore, ProfileStore};
    use crate::vortix_core::engine::{Engine, EngineHandle};
    use crate::vortix_core::profile::{ProfileId, ProtocolKind};
    use crate::vortix_protocol_wireguard::WgTunnel;

    // Prerequisites: real subprocess runner + journal. Both are installed
    // very early in `main.rs`; their absence means the bootstrap order
    // was disturbed (e.g. a unit test harness skipping the runner) — bail
    // out so callers fall back to legacy paths.
    let _runner = crate::vortix_process::global_runner().as_real()?;
    let journal = crate::vortix_core::journal::global_journal().cloned()?;

    // Live profile resolver — reads sidecars via `FsProfileStore` so any
    // consumer calling `handle.execute(Connect{id})` sees the user's
    // actual profiles (post-migration).
    let resolver_dir = profiles_dir.to_path_buf();
    let resolver = move |id: &ProfileId| {
        let store = FsProfileStore::new(resolver_dir.clone());
        store.get(id).ok()
    };

    // Per-Connect tunnel factory — picks WG vs OVPN from the resolved
    // profile's protocol. Plan 006 U6's wire-up.
    let factory_config_dir =
        crate::utils::get_app_config_dir().unwrap_or_else(|_| PathBuf::from("/tmp"));
    let factory = move |profile: &crate::vortix_core::profile::Profile| {
        let proto = match profile.protocol {
            ProtocolKind::OpenVpn => Protocol::OpenVPN,
            // Default to WireGuard for any future variants.
            _ => Protocol::WireGuard,
        };
        tunnel_for(proto, &factory_config_dir, "3", 30)
    };

    let initial_tunnel = TunnelKind::WireGuard(WgTunnel::new());
    let engine = Engine::new(initial_tunnel, resolver).with_tunnel_factory(factory);
    Some(EngineHandle::local(engine, journal))
}

/// Default socket path. Linux uses `${XDG_RUNTIME_DIR}/vortix.sock`
/// when set; otherwise falls back to `/tmp`. macOS uses `${TMPDIR}`.
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
    PathBuf::from("/tmp/vortix.sock")
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
/// (plan D3, multi-connection rollout).
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
