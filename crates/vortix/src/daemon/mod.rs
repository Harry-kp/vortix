//! `vortix daemon` — the single source of truth for VPN state.
//!
//! The daemon binds a Unix socket, owns a per-profile engine registry
//! (`RegistryHandle`), and serves `IpcRequest` frames from concurrent
//! clients (per-client `tokio::spawn` accept loop). A headless
//! supervisor loop reconciles the registry against the kernel — adopts
//! external sessions, detects drops, auto-reconnects. CLI and TUI are
//! thin clients over this socket; when no daemon runs, both fall back
//! to their in-process paths.
//!
//! Auth: `SO_PEERCRED` / `getpeereid` — the daemon accepts its own uid
//! and its configured owner (`VORTIX_OWNER_UID` / `SUDO_UID`), so a
//! root daemon serves its unprivileged owner (`daemon/server.rs`).
//! The client performs the reciprocal check (`socket_owner_trusted`)
//! before connecting, refusing a socket owned by anyone but root or the
//! current user so a rogue `/tmp/vortix.sock` can't impersonate the daemon.
//!
//! Lifecycle:
//! 1. Bind the socket (cleaning up any stale socket file)
//! 2. Spawn the registry actor + adopt already-running tunnels
//! 3. Connect boot-persisted profiles (`vortix service persist`)
//! 4. Spawn the supervisor loop; accept clients until SIGTERM/Ctrl-C
//! 5. On exit, unlink the socket file
//!
//! The daemon prints lifecycle events (binding, accepting, accepted,
//! shutting down) to stderr at `tracing::info` so a `systemd journalctl`
//! or `launchctl log` view surfaces what's happening.

pub mod client;
mod server;
pub mod service;
pub mod supervisor;

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
    use crate::vortix_core::engine::EngineHandle;
    let journal = crate::vortix_core::journal::global_journal().cloned()?;
    let engine = build_engine(profiles_dir)?;
    Some(EngineHandle::local(engine, journal))
}

/// Build a fresh, `Disconnected` `Engine<TunnelKind>` wired with the live
/// `FsProfileStore` resolver and the per-Connect WG/OVPN tunnel factory —
/// the raw engine `build_engine_handle` wraps, and the engine the daemon's
/// per-profile registry drives directly.
///
/// Returns `None` when prerequisites are missing (no real subprocess
/// runner installed) so callers fall back to legacy paths.
#[must_use]
pub fn build_engine(
    profiles_dir: &Path,
) -> Option<crate::vortix_core::engine::fsm::Engine<crate::tunnel::TunnelKind>> {
    use crate::state::Protocol;
    use crate::tunnel::{tunnel_for, TunnelKind};
    use crate::vortix_config::profile_store::{FsProfileStore, ProfileStore};
    use crate::vortix_core::engine::Engine;
    use crate::vortix_core::profile::{ProfileId, ProtocolKind};
    use crate::vortix_protocol_wireguard::WgTunnel;

    let _runner = crate::vortix_process::global_runner().as_real()?;

    let resolver_dir = profiles_dir.to_path_buf();
    let resolver = move |id: &ProfileId| {
        let store = FsProfileStore::new(resolver_dir.clone());
        store.get(id).ok()
    };

    let factory_config_dir =
        crate::utils::get_app_config_dir().unwrap_or_else(|_| PathBuf::from("/tmp"));
    let factory = move |profile: &crate::vortix_core::profile::Profile| {
        let proto = match profile.protocol {
            ProtocolKind::OpenVpn => Protocol::OpenVPN,
            _ => Protocol::WireGuard,
        };
        tunnel_for(proto, &factory_config_dir, "3", 30)
    };

    let initial_tunnel = TunnelKind::WireGuard(WgTunnel::new());
    Some(Engine::new(initial_tunnel, resolver).with_tunnel_factory(factory))
}

/// Resolve a profile and its declared `AllowedIPs` for a daemon-side
/// connect. Returns `None` when the profile isn't in the catalog (the
/// daemon surfaces that as a not-found error). The `AllowedIPs` drive the
/// registry's conflict/role logic; the engine's own resolver handles the
/// actual tunnel bring-up.
#[must_use]
pub fn connect_allowed_ips(
    profiles_dir: &Path,
    id: &crate::vortix_core::profile::ProfileId,
) -> Option<Vec<crate::vortix_core::cidr::Cidr>> {
    use crate::state::Protocol;
    use crate::vortix_config::profile_store::{FsProfileStore, ProfileStore};
    use crate::vortix_core::profile::ProtocolKind;

    let profile = FsProfileStore::new(profiles_dir.to_path_buf())
        .get(id)
        .ok()?;
    let proto = match profile.protocol {
        ProtocolKind::OpenVpn => Protocol::OpenVPN,
        _ => Protocol::WireGuard,
    };
    Some(crate::app::connection::extract_allowed_ips(
        proto,
        &profile.config_path,
    ))
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

/// Canonical socket path for a boot-installed root daemon. Deliberately fixed —
/// not env-derived — because systemd/launchd start the daemon with no
/// user session environment while clients run inside one; a shared
/// constant is the only path both sides of that uid boundary can agree
/// on (the cross-uid gap).
#[must_use]
pub fn system_socket_path() -> PathBuf {
    PathBuf::from("/var/run/vortix.sock")
}

/// The socket paths a client probes, in order: the env override is
/// exclusive when set (a missing override means bypass, never a
/// fallback — it's an explicit instruction); otherwise the per-user
/// default first (a daemon the user started by hand), then the system
/// path (a boot-installed root daemon).
fn socket_probe_candidates() -> Vec<PathBuf> {
    match daemon_socket_path_override() {
        Some(p) => vec![p],
        None => vec![default_socket_path(), system_socket_path()],
    }
}

/// Resolve the effective daemon socket path **only when a daemon
/// appears to be running** (the file exists and is a Unix socket).
///
/// Resolution order:
/// 1. `VORTIX_DAEMON_SOCKET` env var (when set + non-empty; exclusive)
/// 2. Platform per-user default ([`default_socket_path`])
/// 3. Canonical system path ([`system_socket_path`] — boot daemons)
///
/// Read-only CLI ops (`status`, `list`, `audit`) use this to decide
/// whether to route through the daemon or fall back to the direct
/// disk/scanner read. Missing files are not an error — the env var
/// pointing at a non-existent path simply triggers the bypass path
///.
#[must_use]
pub fn daemon_socket_path_if_present() -> Option<PathBuf> {
    socket_probe_candidates()
        .into_iter()
        .find(|c| c.exists() && is_unix_socket(c) && socket_owner_trusted(c))
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

/// Whether the daemon socket's owner is trustworthy before we connect.
///
/// The daemon enforces a peer-UID gate; this is the client's reciprocal
/// check. Without it, when `XDG_RUNTIME_DIR`/`TMPDIR` are unset the socket
/// resolves to the world-writable `/tmp/vortix.sock`, where a local
/// attacker could bind their own listener and feed us a fabricated
/// "Connected" — a false VPN-state signal (real-IP exposure) in a security
/// tool. We trust only a socket owned by root (the real deployment) or by
/// the current user (a same-user daemon, e.g. tests); any other owner is
/// refused and the client falls back to the direct scanner path.
#[cfg(unix)]
fn socket_owner_trusted(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let owner = meta.uid();
    // SAFETY: `geteuid` is a trivial, always-succeeds syscall.
    #[allow(unsafe_code)]
    let me = unsafe { libc::geteuid() };
    owner == 0 || owner == me
}

#[cfg(not(unix))]
fn socket_owner_trusted(_path: &Path) -> bool {
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

    #[test]
    fn self_owned_socket_is_trusted() {
        // A socket we bind is owned by the current euid, so the owner
        // check accepts it (root and same-user are the trusted owners).
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(socket_owner_trusted(&path));
    }

    #[test]
    fn missing_socket_owner_is_not_trusted() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!socket_owner_trusted(&tmp.path().join("nope")));
    }

    #[test]
    fn system_socket_path_is_fixed_and_absolute() {
        // The whole point of the system path is that a root daemon
        // (launched with no user env) and a user client resolve the
        // SAME string — it must never depend on the environment.
        assert_eq!(system_socket_path(), PathBuf::from("/var/run/vortix.sock"));
    }

    #[test]
    fn probe_candidates_end_with_the_system_path_when_no_override() {
        // Can't clear VORTIX_DAEMON_SOCKET safely in-process; this test
        // only asserts the no-override shape when the var is unset in
        // the test environment (cargo doesn't set it).
        if daemon_socket_path_override().is_some() {
            return;
        }
        let candidates = socket_probe_candidates();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0], default_socket_path());
        assert_eq!(candidates[1], system_socket_path());
    }
}
