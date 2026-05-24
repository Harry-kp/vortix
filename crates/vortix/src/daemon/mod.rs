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

mod server;

pub use server::DaemonServer;

use std::path::PathBuf;

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
