//! macOS `SocketAudit` impl (plan 002 U7).
//!
//! Walks every live PID's socket FDs via the hand-rolled `libproc_ffi`
//! module (`proc_listpids` + `proc_pidinfo(PROC_PIDLISTFDS)` +
//! `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`) and emits a `SocketSnapshot`
//! for each IPv4/IPv6 TCP or UDP socket. Replaces the prior `lsof -i -P -n`
//! shell-out + tabular parser.
//!
//! Without root, the kernel returns `ESRCH` (and we silently skip) for
//! sockets owned by other users — matches the prior contract where
//! `lsof` invocations as a non-privileged user only saw their own
//! sockets.

#![allow(clippy::must_use_candidate)]

use crate::vortix_core::ports::socket_audit::{
    SocketAudit, SocketAuditResult, SocketProtocol, SocketSnapshot,
};

use super::libproc_ffi::{self, InetKind, SocketView};

#[derive(Debug, Clone, Copy, Default)]
pub struct LsofSocketAudit;

impl SocketAudit for LsofSocketAudit {
    fn snapshot() -> SocketAuditResult<Vec<SocketSnapshot>> {
        let mut out = Vec::new();
        for (pid, _fd, view) in libproc_ffi::iter_all_sockets() {
            let SocketView::Inet {
                kind,
                local,
                remote,
            } = view
            else {
                continue; // skip Unix domain sockets
            };
            let Ok(pid_u32) = u32::try_from(pid) else {
                continue;
            };
            let command = libproc_ffi::pid_path(pid)
                .as_deref()
                .map(short_command_name)
                .unwrap_or_default();
            out.push(SocketSnapshot {
                pid: pid_u32,
                command,
                local,
                remote,
                protocol: protocol_of(kind),
                interface: None,
            });
        }
        Ok(out)
    }
}

fn protocol_of(kind: InetKind) -> SocketProtocol {
    match kind {
        InetKind::Tcp4 => SocketProtocol::Tcp,
        InetKind::Udp4 => SocketProtocol::Udp,
        InetKind::Tcp6 => SocketProtocol::Tcp6,
        InetKind::Udp6 => SocketProtocol::Udp6,
    }
}

/// Extract the final path component of a binary path, matching the prior
/// `lsof` COMMAND column (e.g. `/usr/bin/curl` → `curl`).
fn short_command_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_command_name_strips_path() {
        assert_eq!(short_command_name("/usr/bin/curl"), "curl");
        assert_eq!(short_command_name("nc"), "nc");
        assert_eq!(short_command_name(""), "");
    }

    #[test]
    fn snapshot_returns_ok() {
        // Smoke test: kernel-level FFI path completes without error on
        // every macOS test runner. Empty Vec is acceptable on hermetic
        // runners; non-empty when the cargo test runner has open
        // sockets.
        let result = LsofSocketAudit::snapshot();
        assert!(result.is_ok(), "snapshot returned error: {result:?}");
    }
}
