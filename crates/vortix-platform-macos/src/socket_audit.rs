//! macOS `SocketAudit` impl (plan 015 phase C U12 / plan 013).
//!
//! Shells out to `lsof -i -P -n` and parses the human-friendly output.
//! Without root, only sockets owned by the current user are visible;
//! the contract returns `pid: 0` for foreign-user sockets where
//! resolution fails.
//!
//! Why human-friendly format instead of `-F`: lsof's `-F` machine-
//! parseable output is interleaved across processes and fds, which
//! makes a streaming parser more complex without buying clarity. The
//! human-friendly tabular output (with `-P -n` to suppress port-name +
//! host-name resolution) is byte-stable enough across macOS versions.

#![allow(clippy::must_use_candidate)]

use std::net::SocketAddr;

use vortix_core::ports::socket_audit::{
    SocketAudit, SocketAuditError, SocketAuditResult, SocketProtocol, SocketSnapshot,
};
use vortix_process::{CommandSpec, PrivilegeReq};

#[derive(Debug, Clone, Copy, Default)]
pub struct LsofSocketAudit;

impl SocketAudit for LsofSocketAudit {
    fn snapshot() -> SocketAuditResult<Vec<SocketSnapshot>> {
        // `-i` IPv4+IPv6 only; `-P` suppress port-name resolution;
        // `-n` suppress hostname resolution. Output is tabular.
        let spec = CommandSpec::oneshot("lsof", vec!["-i".into(), "-P".into(), "-n".into()])
            .privilege(PrivilegeReq::None);
        let output = vortix_process::run_to_output(spec)
            .map_err(|e| SocketAuditError::CommandFailed(format!("lsof: {e}")))?;
        if !output.status.success() {
            return Err(SocketAuditError::CommandFailed(format!(
                "lsof exited {}: {}",
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let body = String::from_utf8_lossy(&output.stdout);
        Ok(parse_lsof_output(&body))
    }
}

/// Parse the output of `lsof -i -P -n`. Public for tests.
///
/// Format (first line is header):
/// ```text
/// COMMAND   PID  USER  FD TYPE DEVICE  SIZE/OFF NODE NAME
/// curl    12345  alice 5u IPv4 0x...           0t0  TCP 127.0.0.1:54321->8.8.8.8:443 (ESTABLISHED)
/// ```
pub fn parse_lsof_output(body: &str) -> Vec<SocketSnapshot> {
    let mut out = Vec::new();
    for line in body.lines().skip(1) {
        if let Some(snap) = parse_one_line(line) {
            out.push(snap);
        }
    }
    out
}

fn parse_one_line(line: &str) -> Option<SocketSnapshot> {
    // Split on whitespace but keep the NAME column intact (it may
    // contain spaces inside `(STATE)` markers).
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 9 {
        return None;
    }
    let command = fields[0].to_string();
    let pid: u32 = fields[1].parse().ok()?;
    let type_field = fields[4]; // IPv4 | IPv6
    let node_field = fields[7]; // TCP | UDP
    let name_field = fields[8..].join(" "); // local->remote (STATE) or local

    let protocol = match (type_field, node_field) {
        ("IPv4", "TCP") => SocketProtocol::Tcp,
        ("IPv4", "UDP") => SocketProtocol::Udp,
        ("IPv6", "TCP") => SocketProtocol::Tcp6,
        ("IPv6", "UDP") => SocketProtocol::Udp6,
        _ => return None,
    };
    // Strip trailing `(STATE)`.
    let core: String = match name_field.split_once(" (") {
        Some((before, _)) => before.to_string(),
        None => name_field.clone(),
    };
    let (local_str, remote_opt) = match core.split_once("->") {
        Some((l, r)) => (l.to_string(), Some(r.to_string())),
        None => (core, None),
    };
    let local = parse_lsof_addr(&local_str)?;
    let remote = remote_opt.and_then(|r| parse_lsof_addr(&r));

    Some(SocketSnapshot {
        pid,
        command,
        local,
        remote,
        protocol,
        interface: None,
    })
}

fn parse_lsof_addr(s: &str) -> Option<SocketAddr> {
    // lsof renders v4 as `127.0.0.1:8080`, v6 as `[::1]:8080` or
    // `[fe80::1%en0]:8080`. The `%en0` scope id breaks `SocketAddr`
    // parsing on stable Rust — strip it.
    let s = s.trim();
    let cleaned = if let Some(start) = s.find('%') {
        let end = s[start..].find([']', ':']).unwrap_or(s.len() - start);
        let mut owned = String::with_capacity(s.len());
        owned.push_str(&s[..start]);
        owned.push_str(&s[start + end..]);
        owned
    } else {
        s.to_string()
    };
    // lsof sometimes uses `*` for unspecified (e.g. `*:8080`); turn
    // it into 0.0.0.0 / [::] so it parses.
    if let Some(port) = cleaned.strip_prefix("*:") {
        let port: u16 = port.parse().ok()?;
        return Some(SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            port,
        ));
    }
    cleaned.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_output_returns_empty() {
        let body = "COMMAND   PID  USER  FD TYPE DEVICE  SIZE/OFF NODE NAME\n";
        assert!(parse_lsof_output(body).is_empty());
    }

    #[test]
    fn listening_socket_no_remote() {
        let body = "\
COMMAND   PID  USER  FD TYPE DEVICE  SIZE/OFF NODE NAME
nc      55555  alice 3u IPv4 0xABC          0t0  TCP *:8080 (LISTEN)
";
        let snaps = parse_lsof_output(body);
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].pid, 55555);
        assert_eq!(snaps[0].command, "nc");
        assert_eq!(
            snaps[0].local,
            "0.0.0.0:8080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(snaps[0].remote, None);
    }

    #[test]
    fn established_tcp_socket_with_remote() {
        let body = "\
COMMAND   PID  USER  FD TYPE DEVICE  SIZE/OFF NODE NAME
curl    12345  alice 5u IPv4 0xABC          0t0  TCP 127.0.0.1:54321->8.8.8.8:443 (ESTABLISHED)
";
        let snaps = parse_lsof_output(body);
        assert_eq!(snaps.len(), 1);
        let s = &snaps[0];
        assert_eq!(s.pid, 12345);
        assert_eq!(s.local, "127.0.0.1:54321".parse::<SocketAddr>().unwrap());
        assert_eq!(s.remote, Some("8.8.8.8:443".parse::<SocketAddr>().unwrap()));
        assert_eq!(s.protocol, SocketProtocol::Tcp);
    }

    #[test]
    fn ipv6_with_zone_id_strips_it() {
        let body = "\
COMMAND   PID  USER  FD TYPE DEVICE  SIZE/OFF NODE NAME
proc    77777  alice 4u IPv6 0xABC          0t0  TCP [fe80::1%en0]:443->[fe80::2%en0]:54321 (ESTABLISHED)
";
        let snaps = parse_lsof_output(body);
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].protocol, SocketProtocol::Tcp6);
    }

    #[test]
    fn malformed_line_skipped_not_aborted() {
        let body = "\
COMMAND   PID  USER  FD TYPE DEVICE  SIZE/OFF NODE NAME
GARBAGE
curl    12345  alice 5u IPv4 0xABC          0t0  TCP 127.0.0.1:54321->8.8.8.8:443 (ESTABLISHED)
";
        let snaps = parse_lsof_output(body);
        assert_eq!(snaps.len(), 1);
    }
}
