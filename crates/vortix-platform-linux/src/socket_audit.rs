//! Linux `SocketAudit` impl (plan 015 phase C U11 / plan 013).
//!
//! Parses `/proc/net/{tcp,tcp6,udp,udp6}` for the socket inventory +
//! walks `/proc/<pid>/fd/*` to map socket inodes back to processes.
//! Without root, only sockets owned by the calling user are
//! resolvable; foreign-user sockets appear with `pid: 0` and
//! `command: ""` per the port contract.
//!
//! The parser is byte-careful — `/proc/net/tcp` reports addresses in
//! hex with byte-reversed order (Linux network-stack quirk). Tests
//! pin a known IPv4 + IPv6 layout so future refactors can't silently
//! regress the byte order.

#![allow(clippy::implicit_hasher)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::manual_let_else)]

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use vortix_core::ports::socket_audit::{
    SocketAudit, SocketAuditResult, SocketProtocol, SocketSnapshot,
};

/// Marker type implementing the [`SocketAudit`] trait for Linux.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcSocketAudit;

impl SocketAudit for ProcSocketAudit {
    fn snapshot() -> SocketAuditResult<Vec<SocketSnapshot>> {
        // Build an inode → (pid, command) map first; cheap when no
        // pids are visible, otherwise the snapshot lookup is O(1).
        let inode_owners = collect_socket_inode_owners();

        let mut out = Vec::new();
        for (path, proto) in [
            ("/proc/net/tcp", SocketProtocol::Tcp),
            ("/proc/net/tcp6", SocketProtocol::Tcp6),
            ("/proc/net/udp", SocketProtocol::Udp),
            ("/proc/net/udp6", SocketProtocol::Udp6),
        ] {
            let contents = match fs::read_to_string(path) {
                Ok(s) => s,
                Err(_) => continue, // file missing on this kernel? skip.
            };
            for snap in parse_proc_net(&contents, proto, &inode_owners) {
                out.push(snap);
            }
        }
        out.sort_by_key(|s| s.pid);
        Ok(out)
    }
}

/// Parse one `/proc/net/{tcp,udp}{,6}` body. Public for tests; the
/// `SocketAudit::snapshot` impl is the only production caller.
pub fn parse_proc_net(
    body: &str,
    proto: SocketProtocol,
    inode_owners: &HashMap<u64, (u32, String)>,
) -> Vec<SocketSnapshot> {
    let mut out = Vec::new();
    // First line is the header; skip.
    for line in body.lines().skip(1) {
        let Some(snap) = parse_one_line(line, proto, inode_owners) else {
            continue;
        };
        out.push(snap);
    }
    out
}

fn parse_one_line(
    line: &str,
    proto: SocketProtocol,
    inode_owners: &HashMap<u64, (u32, String)>,
) -> Option<SocketSnapshot> {
    // Columns: sl local_address rem_address st tx_q rx_q tr tm->when retrnsmt uid timeout inode ...
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 10 {
        return None;
    }
    let local = parse_hex_addr(fields[1], proto)?;
    let remote = parse_hex_addr(fields[2], proto)?;
    let inode: u64 = fields[9].parse().ok()?;
    let (pid, command) = inode_owners
        .get(&inode)
        .cloned()
        .unwrap_or_else(|| (0, String::new()));
    let remote_is_unspecified = remote.ip().is_unspecified() && remote.port() == 0;
    Some(SocketSnapshot {
        pid,
        command,
        local,
        remote: if remote_is_unspecified {
            None
        } else {
            Some(remote)
        },
        protocol: proto,
        interface: None, // /proc/net/tcp doesn't carry interface; resolution is left to a future hardening pass
    })
}

/// `1F90:0100007F` → `127.0.0.1:8080` (v4) or 32-hex-pair v6 form.
fn parse_hex_addr(s: &str, proto: SocketProtocol) -> Option<SocketAddr> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = match proto {
        SocketProtocol::Tcp6 | SocketProtocol::Udp6 => {
            if addr_hex.len() != 32 {
                return None;
            }
            let mut octets = [0u8; 16];
            for i in 0..4 {
                let chunk = &addr_hex[i * 8..(i + 1) * 8];
                let raw = u32::from_str_radix(chunk, 16).ok()?;
                let bytes = raw.to_le_bytes();
                for (j, b) in bytes.iter().enumerate() {
                    octets[i * 4 + j] = *b;
                }
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        // SocketProtocol::Tcp | SocketProtocol::Udp and future
        // additive non_exhaustive variants fall here. v4 layout is
        // the right default for unknown variants — failure is
        // explicit via `len != 8`.
        _ => {
            // 8 hex chars, little-endian bytes
            if addr_hex.len() != 8 {
                return None;
            }
            let raw = u32::from_str_radix(addr_hex, 16).ok()?;
            // The Linux /proc format is host-endian; the bytes
            // come out network-endian-reversed for x86. Treat the
            // bytes as little-endian and assemble the IPv4.
            let bytes = raw.to_le_bytes();
            IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
        }
    };
    Some(SocketAddr::new(ip, port))
}

/// Walk `/proc/<pid>/fd/*` and build inode → (pid, comm) map.
/// Best-effort: unreadable PID directories (different user, no perms)
/// are skipped silently.
fn collect_socket_inode_owners() -> HashMap<u64, (u32, String)> {
    let mut out = HashMap::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid_str) = name.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        let fd_dir = entry.path().join("fd");
        let comm = read_comm(&entry.path());
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
            let link = match fs::read_link(fd.path()) {
                Ok(l) => l,
                Err(_) => continue,
            };
            // Format: `socket:[<inode>]`
            let Some(rest) = link.to_str().and_then(|s| s.strip_prefix("socket:[")) else {
                continue;
            };
            let Some(inode_str) = rest.strip_suffix(']') else {
                continue;
            };
            let Ok(inode) = inode_str.parse::<u64>() else {
                continue;
            };
            out.insert(inode, (pid, comm.clone()));
        }
    }
    out
}

fn read_comm(pid_dir: &Path) -> String {
    let comm_path = pid_dir.join("comm");
    let mut f = match fs::File::open(&comm_path) {
        Ok(f) => f,
        Err(_) => return String::new(),
    };
    let mut buf = String::new();
    if f.read_to_string(&mut buf).is_err() {
        return String::new();
    }
    buf.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_owners() -> HashMap<u64, (u32, String)> {
        HashMap::new()
    }

    #[test]
    fn parse_proc_net_tcp_header_only_returns_empty() {
        let body = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
        let snaps = parse_proc_net(body, SocketProtocol::Tcp, &empty_owners());
        assert!(snaps.is_empty());
    }

    #[test]
    fn parse_one_tcp_line_with_known_loopback() {
        // 0100007F = 127.0.0.1 (little-endian), 1F90 = 8080
        // 00000000:0000 = listening (no remote)
        let body = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 99999 1 0000000000000000 100 0 0 10 0
";
        let snaps = parse_proc_net(body, SocketProtocol::Tcp, &empty_owners());
        assert_eq!(snaps.len(), 1);
        let s = &snaps[0];
        assert_eq!(s.local, "127.0.0.1:8080".parse::<SocketAddr>().unwrap());
        assert_eq!(s.remote, None);
        assert_eq!(s.protocol, SocketProtocol::Tcp);
        assert_eq!(s.pid, 0); // no owner mapping supplied
    }

    #[test]
    fn parse_one_tcp_line_with_established_remote() {
        // local 127.0.0.1:54321 (D431) ← rem 8.8.8.8:443 (01BB) (08080808 LE)
        let body = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   1: 0100007F:D431 08080808:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 100100 1 0000000000000000 100 0 0 10 0
";
        let snaps = parse_proc_net(body, SocketProtocol::Tcp, &empty_owners());
        assert_eq!(snaps.len(), 1);
        let s = &snaps[0];
        assert_eq!(s.local, "127.0.0.1:54321".parse::<SocketAddr>().unwrap());
        assert_eq!(s.remote, Some("8.8.8.8:443".parse::<SocketAddr>().unwrap()));
    }

    #[test]
    fn parse_owner_maps_inode_to_pid() {
        let mut owners = HashMap::new();
        owners.insert(99999, (1234u32, "curl".to_string()));
        let body = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 99999 1 0000000000000000 100 0 0 10 0
";
        let snaps = parse_proc_net(body, SocketProtocol::Tcp, &owners);
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].pid, 1234);
        assert_eq!(snaps[0].command, "curl");
    }

    #[test]
    fn malformed_line_in_middle_is_skipped_not_aborting() {
        let body = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   GARBAGE LINE
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 99999 1 0000000000000000 100 0 0 10 0
";
        let snaps = parse_proc_net(body, SocketProtocol::Tcp, &empty_owners());
        assert_eq!(snaps.len(), 1);
    }

    #[test]
    fn parse_one_tcp6_line_ipv6_byte_order() {
        // ::1 (loopback) in /proc/net/tcp6 format is
        // 00000000000000000000000001000000 (each 32-bit word is
        // little-endian written; assembling the 16 bytes yields
        // 0:0:0:0:0:0:0:1)
        let body = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 88888 1 0000000000000000 100 0 0 10 0
";
        let snaps = parse_proc_net(body, SocketProtocol::Tcp6, &empty_owners());
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].local, "[::1]:8080".parse::<SocketAddr>().unwrap());
        assert_eq!(snaps[0].remote, None);
    }
}
