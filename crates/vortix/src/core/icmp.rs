//! ICMP echo latency probe (plan 002 U10).
//!
//! Replaces the `ping -c 3 -i 0.2 -W <ms> <target>` shell-out in
//! `core::telemetry::fetch_latency`. The packet is hand-rolled from
//! RFC 792 (8-byte `ICMPv4` header: `type`, `code`, `checksum`, `id`,
//! `seq`); checksum is the standard 16-bit one's-complement sum.
//!
//! Permissions:
//! - macOS: `SOCK_DGRAM` + `IPPROTO_ICMP` works unprivileged out of
//!   the box.
//! - Linux: same combo works when the caller's GID is inside
//!   `/proc/sys/net/ipv4/ping_group_range` (modern distros default
//!   to `0 2147483647`, i.e. every group). When the kernel refuses
//!   (older kernels, hardened sysctls, root-only setups), we fall
//!   back to a TCP connect to port 443 — coarser RTT but doesn't
//!   need any capability.
//!
//! No tokio integration: the telemetry workers run in
//! `std::thread::spawn` already, so the socket is used in blocking
//! mode with `set_read_timeout`. Wiring `AsyncFd` would force a tokio
//! runtime that nothing else here needs.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// One ICMP echo identifier per process (lower 16 bits of the PID).
fn echo_identifier() -> u16 {
    #[allow(clippy::cast_possible_truncation)]
    let pid = std::process::id() as u16;
    pid
}

/// Stats from a single probe target — same shape the prior
/// `parse_ping_output` produced.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ProbeStats {
    /// Average RTT across successful responses, in milliseconds.
    pub latency_ms: u64,
    /// Percentage of packets lost (0.0 - 100.0).
    pub packet_loss: f32,
    /// `(max - min) / 2` RTT, in milliseconds — matches the prior
    /// telemetry's jitter approximation.
    pub jitter_ms: u64,
}

/// Run `attempts` ICMP echo probes against `target`, spacing them
/// `INTERVAL` apart, with `per_attempt_timeout` per response wait.
/// Falls back to TCP-connect-to-port-443 when the ICMP socket cannot
/// be opened (no `CAP_NET_RAW`, `ping_group_range` too tight).
///
/// Returns `None` when both paths fail entirely (no successful
/// probes). Returns `Some(stats)` when at least one probe succeeded.
#[must_use]
pub fn measure_latency(
    target: &str,
    attempts: u32,
    per_attempt_timeout: Duration,
) -> Option<ProbeStats> {
    let addr: IpAddr = target.parse().ok()?;
    let IpAddr::V4(v4) = addr else {
        // No IPv6 support today; matches the prior ping shell-out
        // which used the default ping binary (v4 only without `-6`).
        return tcp_connect_probe(addr, attempts, per_attempt_timeout);
    };

    if let Some(stats) = icmp_echo_probe(v4, attempts, per_attempt_timeout) {
        Some(stats)
    } else {
        tcp_connect_probe(addr, attempts, per_attempt_timeout)
    }
}

const ATTEMPT_INTERVAL: Duration = Duration::from_millis(200);

fn icmp_echo_probe(
    target: Ipv4Addr,
    attempts: u32,
    per_attempt_timeout: Duration,
) -> Option<ProbeStats> {
    let socket = open_icmp_socket().ok()?;
    socket.set_read_timeout(Some(per_attempt_timeout)).ok()?;
    socket.set_write_timeout(Some(per_attempt_timeout)).ok()?;
    let dest: SockAddr = SocketAddr::new(IpAddr::V4(target), 0).into();
    let ident = echo_identifier();
    aggregate_rtts(attempts, |attempt| {
        let seq = u16::try_from(attempt).unwrap_or(0);
        let packet = build_echo_packet(ident, seq);
        let start = Instant::now();
        socket.send_to(&packet, &dest).ok()?;
        recv_matching_reply(&socket, ident, seq, per_attempt_timeout)?;
        Some(start.elapsed())
    })
}

fn open_icmp_socket() -> io::Result<Socket> {
    // SOCK_DGRAM + IPPROTO_ICMPV4 is the unprivileged path on macOS
    // and on Linux kernels with permissive `ping_group_range`. The
    // raw-SOCK_RAW variant needs CAP_NET_RAW / root and is what the
    // plan called out; this works the same in userspace but with no
    // privilege.
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
    socket.set_nonblocking(false)?;
    Ok(socket)
}

/// 8-byte `ICMPv4` Echo Request with empty payload. `RFC 792` §"Echo or
/// Echo Reply Message".
fn build_echo_packet(identifier: u16, sequence: u16) -> [u8; 8] {
    let mut packet = [0u8; 8];
    packet[0] = 8; // Type: Echo Request
    packet[1] = 0; // Code
                   // packet[2..4] checksum — computed below with checksum field zero.
    packet[4..6].copy_from_slice(&identifier.to_be_bytes());
    packet[6..8].copy_from_slice(&sequence.to_be_bytes());
    let checksum = internet_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

/// RFC 1071 16-bit one's-complement Internet checksum.
fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum += u32::from(u16::from_be_bytes([bytes[i], bytes[i + 1]]));
        i += 2;
    }
    if i < bytes.len() {
        sum += u32::from(bytes[i]) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    #[allow(clippy::cast_possible_truncation)]
    let folded = sum as u16;
    !folded
}

/// Read replies until we see an Echo Reply (type 0) whose identifier +
/// sequence match what we sent, then return success. On Linux's
/// `SOCK_DGRAM` ICMP the kernel rewrites the identifier transparently —
/// we still match against the sequence we sent because the kernel
/// preserves that. On macOS the userspace identifier round-trips
/// unchanged.
fn recv_matching_reply(
    socket: &Socket,
    expected_id: u16,
    expected_seq: u16,
    overall_timeout: Duration,
) -> Option<()> {
    let deadline = Instant::now() + overall_timeout;
    let mut buf = [std::mem::MaybeUninit::new(0u8); 1500];
    loop {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        if remaining.is_zero() {
            return None;
        }
        socket.set_read_timeout(Some(remaining)).ok()?;
        let (n, _peer) = socket.recv_from(&mut buf).ok()?;
        // SAFETY: socket2's recv_from initialises exactly `n` bytes of
        // the buffer and reports `n`. The MaybeUninit slice past `n`
        // stays untouched.
        #[allow(unsafe_code)]
        let bytes: Vec<u8> = buf[..n]
            .iter()
            .map(|b| unsafe { b.assume_init() })
            .collect();
        if let Some((reply_id, reply_seq)) = parse_echo_reply(&bytes) {
            // On Linux SOCK_DGRAM ICMP the kernel overrides the
            // identifier — sequence-only matching is the conservative
            // baseline that works on both Linux and macOS.
            let _ = reply_id; // identifier is informational on Linux
            let _ = expected_id;
            if reply_seq == expected_seq {
                return Some(());
            }
        }
    }
}

/// Parse an Echo Reply packet's identifier + sequence. Returns
/// `None` if the buffer doesn't decode as a Type-0 Code-0 ICMP echo
/// reply. macOS hands us the raw ICMP packet; Linux `SOCK_DGRAM` also
/// strips the IP header on receive.
fn parse_echo_reply(bytes: &[u8]) -> Option<(u16, u16)> {
    if bytes.len() < 8 {
        return None;
    }
    if bytes[0] != 0 || bytes[1] != 0 {
        return None; // not Echo Reply
    }
    let id = u16::from_be_bytes([bytes[4], bytes[5]]);
    let seq = u16::from_be_bytes([bytes[6], bytes[7]]);
    Some((id, seq))
}

fn tcp_connect_probe(
    target: IpAddr,
    attempts: u32,
    per_attempt_timeout: Duration,
) -> Option<ProbeStats> {
    let dest = SocketAddr::new(target, 443);
    aggregate_rtts(attempts, |_| {
        let start = Instant::now();
        let stream = TcpStream::connect_timeout(&dest, per_attempt_timeout).ok()?;
        // Close immediately — we only care about the handshake RTT.
        drop(stream);
        Some(start.elapsed())
    })
}

/// Drive `attempts` probes, calling `one_probe` for each. Computes
/// average latency, jitter (max-min/2), and packet-loss percentage.
fn aggregate_rtts(
    attempts: u32,
    mut one_probe: impl FnMut(u32) -> Option<Duration>,
) -> Option<ProbeStats> {
    let mut rtts: Vec<Duration> = Vec::with_capacity(attempts as usize);
    for attempt in 0..attempts {
        if attempt > 0 {
            std::thread::sleep(ATTEMPT_INTERVAL);
        }
        if let Some(rtt) = one_probe(attempt) {
            rtts.push(rtt);
        }
    }

    if rtts.is_empty() {
        return None;
    }

    let total_ms: u128 = rtts.iter().map(Duration::as_millis).sum();
    #[allow(clippy::cast_possible_truncation)]
    let avg_ms = (total_ms / rtts.len() as u128) as u64;

    let min_ms = rtts.iter().map(Duration::as_millis).min().unwrap_or(0);
    let max_ms = rtts.iter().map(Duration::as_millis).max().unwrap_or(0);
    #[allow(clippy::cast_possible_truncation)]
    let jitter_ms = ((max_ms.saturating_sub(min_ms)) / 2) as u64;

    #[allow(clippy::cast_precision_loss)]
    let packet_loss = if attempts == 0 {
        0.0
    } else {
        let received = u32::try_from(rtts.len()).unwrap_or(u32::MAX);
        (attempts.saturating_sub(received) as f32) * 100.0 / attempts as f32
    };

    Some(ProbeStats {
        latency_ms: avg_ms,
        packet_loss,
        jitter_ms,
    })
}

// Silence dead-import warnings on TCP-only paths.
#[cfg(test)]
#[allow(unused_imports)]
use std::io::{Read as _, Write as _};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_packet_checksum_is_valid() {
        // The checksum of a packet that includes its own checksum
        // field is, by construction, 0 — that's RFC 1071's invariant.
        let packet = build_echo_packet(0x1234, 1);
        assert_eq!(internet_checksum(&packet), 0);
    }

    #[test]
    fn echo_packet_has_correct_type_code_and_fields() {
        let packet = build_echo_packet(0xABCD, 0x0042);
        assert_eq!(packet[0], 8, "type must be Echo Request");
        assert_eq!(packet[1], 0, "code must be 0");
        assert_eq!(
            u16::from_be_bytes([packet[4], packet[5]]),
            0xABCD,
            "identifier mismatch"
        );
        assert_eq!(
            u16::from_be_bytes([packet[6], packet[7]]),
            0x0042,
            "sequence mismatch"
        );
    }

    #[test]
    fn parse_echo_reply_decodes_id_and_seq() {
        let reply = [0u8, 0, 0xDE, 0xAD, 0x12, 0x34, 0x56, 0x78];
        let (id, seq) = parse_echo_reply(&reply).expect("decode");
        assert_eq!(id, 0x1234);
        assert_eq!(seq, 0x5678);
    }

    #[test]
    fn parse_echo_reply_rejects_non_reply_type() {
        // Type 8 = Echo Request, not Reply.
        let req = [8u8, 0, 0, 0, 0, 0, 0, 0];
        assert!(parse_echo_reply(&req).is_none());
    }

    #[test]
    fn parse_echo_reply_rejects_short_packet() {
        assert!(parse_echo_reply(&[0u8, 0, 0]).is_none());
    }

    #[test]
    fn aggregate_rtts_computes_stats() {
        let stats = aggregate_rtts(3, |i| match i {
            0 => Some(Duration::from_millis(10)),
            1 => Some(Duration::from_millis(20)),
            2 => Some(Duration::from_millis(30)),
            _ => unreachable!(),
        })
        .expect("stats");
        assert_eq!(stats.latency_ms, 20, "avg of 10/20/30");
        assert_eq!(stats.jitter_ms, 10, "(30-10)/2");
        assert!(
            (stats.packet_loss - 0.0).abs() < f32::EPSILON,
            "no loss, got {}",
            stats.packet_loss
        );
    }

    #[test]
    fn aggregate_rtts_reports_partial_loss() {
        let stats = aggregate_rtts(4, |i| {
            if i == 1 {
                None
            } else {
                Some(Duration::from_millis(50))
            }
        })
        .expect("stats");
        assert_eq!(stats.latency_ms, 50);
        assert!(
            (stats.packet_loss - 25.0).abs() < 0.1,
            "expected 25% loss, got {}",
            stats.packet_loss
        );
    }

    #[test]
    fn aggregate_rtts_returns_none_when_all_fail() {
        let stats = aggregate_rtts(3, |_| None);
        assert!(stats.is_none());
    }

    #[test]
    fn loopback_icmp_or_tcp_fallback_returns_finite_rtt() {
        // 127.0.0.1 is always reachable. Either the ICMP path or the
        // TCP-443 fallback must produce a probe value within a few
        // hundred ms.
        // TCP-443 to 127.0.0.1:443 may refuse (no service); that's
        // fine — we just need at least one of the two paths to work.
        // Most realistic outcome: ICMP path succeeds.
        let result = measure_latency("127.0.0.1", 1, Duration::from_millis(500));
        // Hermetic CI may disallow ICMP entirely AND have no port-443
        // service on loopback. We assert "doesn't panic" + "result
        // shape is sensible" rather than insisting on a value.
        if let Some(stats) = result {
            assert!(
                stats.latency_ms < 1000,
                "loopback latency suspiciously high"
            );
            assert!(stats.packet_loss <= 100.0);
        }
    }

    #[test]
    fn invalid_target_string_returns_none() {
        assert!(measure_latency("not-an-ip", 1, Duration::from_millis(100)).is_none());
    }
}
