//! `SocketAudit` capability port (plan 015 phase C / plan 013).
//!
//! Pull-based per-process socket inventory. Implementations live in
//! `vortix-platform-{linux,macos,windows}`. Consumers query via the
//! `Platform` aggregate (`vortix/src/platform/aggregate.rs`).

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The IP transport protocol of a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum SocketProtocol {
    Tcp,
    Udp,
    Tcp6,
    Udp6,
}

impl std::fmt::Display for SocketProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Tcp6 => "tcp6",
            Self::Udp6 => "udp6",
        };
        f.write_str(s)
    }
}

/// One socket as observed at snapshot time.
///
/// The vortix engine and audit CLI consume `Vec<SocketSnapshot>` from
/// the `SocketAudit::snapshot()` call. The shape is intentionally
/// simple — no continuous streaming, no diffing; future requirements
/// can extend the port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketSnapshot {
    /// Owning process id (or `0` when the impl can't resolve it,
    /// e.g. without root on Linux or when the socket belongs to
    /// another user).
    pub pid: u32,
    /// `comm` (Linux) or process name (macOS). Empty string when
    /// unknown.
    pub command: String,
    /// Local endpoint.
    pub local: SocketAddr,
    /// Remote endpoint. `None` for listening sockets.
    pub remote: Option<SocketAddr>,
    /// Transport protocol.
    pub protocol: SocketProtocol,
    /// Routing interface (e.g. `en0`, `wg0`, `tun0`). `None` when the
    /// platform impl can't resolve it for this socket; the audit CLI
    /// renders this as a useful hint for "is this traffic going
    /// through the tunnel?"
    pub interface: Option<String>,
}

/// Errors produced by [`SocketAudit::snapshot`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SocketAuditError {
    /// The platform impl is a stub (Windows in v0.3.0). The CLI
    /// surfaces this as "socket audit not available on this platform"
    /// without a panic.
    #[error("socket audit is not available on this platform")]
    Unsupported,
    /// The underlying tool (`ps`, `lsof`, file read) failed.
    #[error("socket audit command failed: {0}")]
    CommandFailed(String),
    /// Parsing the tool's output failed midway. The CLI surfaces this
    /// with the parser's diagnostic so a future contributor can
    /// reproduce.
    #[error("socket audit parse failed: {0}")]
    ParseFailed(String),
    /// I/O error reading `/proc` or running a command.
    #[error("socket audit I/O: {0}")]
    Io(#[from] std::io::Error),
}

/// Result alias for socket-audit operations.
pub type SocketAuditResult<T> = std::result::Result<T, SocketAuditError>;

/// Capability port: enumerate the system's open sockets.
///
/// Implementations are platform-specific:
/// - Linux: parses `/proc/net/{tcp,tcp6,udp,udp6}` + walks
///   `/proc/<pid>/fd/*` for PID resolution
/// - macOS: shells to `lsof -i -P -n -F` for machine-readable output
/// - Windows: returns [`SocketAuditError::Unsupported`]
pub trait SocketAudit {
    /// Snapshot the current socket inventory. Returns an empty list
    /// (not an error) when no sockets are visible to the caller.
    ///
    /// # Errors
    ///
    /// Returns [`SocketAuditError`] when the platform impl is
    /// unavailable or the underlying probe fails.
    fn snapshot() -> SocketAuditResult<Vec<SocketSnapshot>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_protocol_round_trips_through_json() {
        for proto in [
            SocketProtocol::Tcp,
            SocketProtocol::Udp,
            SocketProtocol::Tcp6,
            SocketProtocol::Udp6,
        ] {
            let json = serde_json::to_string(&proto).unwrap();
            let back: SocketProtocol = serde_json::from_str(&json).unwrap();
            assert_eq!(proto, back);
        }
    }

    #[test]
    fn socket_protocol_display() {
        assert_eq!(format!("{}", SocketProtocol::Tcp), "tcp");
        assert_eq!(format!("{}", SocketProtocol::Udp6), "udp6");
    }

    #[test]
    fn socket_snapshot_round_trips() {
        let snap = SocketSnapshot {
            pid: 1234,
            command: "curl".into(),
            local: "127.0.0.1:54321".parse().unwrap(),
            remote: Some("8.8.8.8:443".parse().unwrap()),
            protocol: SocketProtocol::Tcp,
            interface: Some("en0".into()),
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: SocketSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn listening_socket_has_no_remote() {
        let snap = SocketSnapshot {
            pid: 5678,
            command: "nc".into(),
            local: "0.0.0.0:8080".parse().unwrap(),
            remote: None,
            protocol: SocketProtocol::Tcp,
            interface: None,
        };
        let json = serde_json::to_string(&snap).unwrap();
        // Listening sockets serialize remote as null
        assert!(json.contains("\"remote\":null"));
    }
}
