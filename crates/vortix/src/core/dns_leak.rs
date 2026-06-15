//! DNS leak detector via recursor-IP echo probe — resolve
//! `o-o.myaddr.l.google.com` TXT and compare the returned recursor IP
//! to the configured DNS server.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsLeakStatus {
    Unknown,
    Protected {
        recursor: IpAddr,
        configured: IpAddr,
    },
    Leaking {
        recursor: IpAddr,
        configured: IpAddr,
    },
    ProbeFailed,
}

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const PROBE_NAME: &str = "o-o.myaddr.l.google.com";

#[must_use]
pub fn probe_recursor(configured_dns: IpAddr) -> Option<IpAddr> {
    let query = build_query(0x4242, PROBE_NAME, 16, 1);
    let bind = if configured_dns.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind).ok()?;
    sock.set_read_timeout(Some(PROBE_TIMEOUT)).ok()?;
    sock.send_to(&query, SocketAddr::new(configured_dns, 53))
        .ok()?;
    let mut buf = [0u8; 512];
    let (n, _) = sock.recv_from(&mut buf).ok()?;
    parse_first_txt(&buf[..n])
}

#[must_use]
pub fn check(configured_dns: Option<IpAddr>) -> DnsLeakStatus {
    let Some(configured) = configured_dns else {
        return DnsLeakStatus::Unknown;
    };
    let Some(recursor) = probe_recursor(configured) else {
        return DnsLeakStatus::ProbeFailed;
    };
    if same_provider(configured, recursor) {
        DnsLeakStatus::Protected {
            recursor,
            configured,
        }
    } else {
        DnsLeakStatus::Leaking {
            recursor,
            configured,
        }
    }
}

fn build_query(id: u16, name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    q.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    q.extend_from_slice(&[0; 6]); // ancount, nscount, arcount
    for label in name.split('.') {
        let len = u8::try_from(label.len().min(63)).unwrap_or(63);
        q.push(len);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&qclass.to_be_bytes());
    q
}

fn parse_first_txt(packet: &[u8]) -> Option<IpAddr> {
    if packet.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    if ancount == 0 {
        return None;
    }
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(packet, pos)?;
        pos = pos.checked_add(4)?;
    }
    for _ in 0..ancount {
        pos = skip_name(packet, pos)?;
        if pos + 10 > packet.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let rdlength = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > packet.len() {
            return None;
        }
        if rtype == 16 {
            let txt_len = packet[pos] as usize;
            if txt_len == 0 || pos + 1 + txt_len > packet.len() {
                return None;
            }
            let txt = std::str::from_utf8(&packet[pos + 1..pos + 1 + txt_len]).ok()?;
            return txt.trim().parse().ok();
        }
        pos += rdlength;
    }
    None
}

fn skip_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= packet.len() {
            return None;
        }
        let b = packet[pos];
        if b == 0 {
            return Some(pos + 1);
        }
        if b & 0xc0 == 0xc0 {
            return Some(pos + 2);
        }
        pos = pos.checked_add(1 + b as usize)?;
    }
}

fn same_provider(a: IpAddr, b: IpAddr) -> bool {
    if a == b {
        return true;
    }
    provider_of(a).is_some() && provider_of(a) == provider_of(b)
}

fn provider_of(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => provider_of_v4(v4),
        IpAddr::V6(v6) => provider_of_v6(v6),
    }
}

#[allow(clippy::unnested_or_patterns)]
fn provider_of_v4(ip: Ipv4Addr) -> Option<&'static str> {
    match ip.octets() {
        [1, 1, 1, _] | [1, 0, 0, _] => Some("cloudflare"),
        [8, 8, 8, _] | [8, 8, 4, _] => Some("google"),
        [9, 9, 9, _] | [149, 112, 112, _] => Some("quad9"),
        [208, 67, 220 | 222, _] => Some("opendns"),
        _ => None,
    }
}

fn provider_of_v6(ip: Ipv6Addr) -> Option<&'static str> {
    let s = ip.segments();
    match [s[0], s[1]] {
        // Cloudflare AS13335: 2606:4700::/32, 2400:cb00::/32, 2803:f800::/32, 2a06:98c0::/29.
        [0x2606, 0x4700] | [0x2400, 0xcb00] | [0x2803, 0xf800] => Some("cloudflare"),
        [0x2a06, x] if x & 0xfff8 == 0x98c0 => Some("cloudflare"),
        // Google Public DNS: 2001:4860:4860::/48.
        [0x2001, 0x4860] => Some("google"),
        // Quad9: 2620:fe::/48.
        [0x2620, 0x00fe] => Some("quad9"),
        // OpenDNS: 2620:119:35::/48, 2620:119:53::/48.
        [0x2620, 0x0119] => Some("opendns"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_when_no_dns_configured() {
        assert_eq!(check(None), DnsLeakStatus::Unknown);
    }

    #[test]
    fn build_query_has_correct_header_and_question() {
        let q = build_query(0x1234, "a.b", 16, 1);
        assert_eq!(&q[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(&q[2..4], &0x0100u16.to_be_bytes());
        assert_eq!(&q[4..6], &1u16.to_be_bytes());
        assert_eq!(q[12], 1);
        assert_eq!(q[13], b'a');
        assert_eq!(q[14], 1);
        assert_eq!(q[15], b'b');
        assert_eq!(q[16], 0);
        assert_eq!(&q[17..19], &16u16.to_be_bytes());
        assert_eq!(&q[19..21], &1u16.to_be_bytes());
    }

    #[test]
    fn same_provider_strict_equality() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(same_provider(ip, ip));
    }

    #[test]
    fn same_provider_cloudflare_anycast() {
        let a: IpAddr = "1.1.1.1".parse().unwrap();
        let b: IpAddr = "1.0.0.1".parse().unwrap();
        assert!(same_provider(a, b));
    }

    #[test]
    fn same_provider_google_anycast() {
        let a: IpAddr = "8.8.8.8".parse().unwrap();
        let b: IpAddr = "8.8.4.4".parse().unwrap();
        assert!(same_provider(a, b));
    }

    #[test]
    fn different_providers_arent_same() {
        let cf: IpAddr = "1.1.1.1".parse().unwrap();
        let isp: IpAddr = "218.248.42.7".parse().unwrap();
        assert!(!same_provider(cf, isp));
    }

    #[test]
    fn cloudflare_v4_configured_with_cloudflare_v6_recursor_is_same() {
        // Real wg-v6 case: configured 1.1.1.1, recursor came back as
        // Cloudflare's v6 anycast (2400:cb00::/32). Must classify as
        // same provider — without v6 ranges this was a false positive.
        let cf_v4: IpAddr = "1.1.1.1".parse().unwrap();
        let cf_v6: IpAddr = "2400:cb00:71:1024::6816:7bd5".parse().unwrap();
        assert!(same_provider(cf_v4, cf_v6));
    }

    #[test]
    fn cloudflare_v6_anycast_classified_as_cloudflare() {
        let modern: IpAddr = "2606:4700:4700::1111".parse().unwrap();
        let legacy: IpAddr = "2400:cb00::1".parse().unwrap();
        assert_eq!(provider_of(modern), Some("cloudflare"));
        assert_eq!(provider_of(legacy), Some("cloudflare"));
    }

    #[test]
    fn google_v6_anycast_classified_as_google() {
        let g: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        assert_eq!(provider_of(g), Some("google"));
    }

    #[test]
    fn parse_first_txt_extracts_ip() {
        // Hand-crafted DNS response: header + question + 1 TXT answer.
        let mut p = Vec::new();
        p.extend_from_slice(&0x4242u16.to_be_bytes());
        p.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RA=1
        p.extend_from_slice(&1u16.to_be_bytes()); // qd
        p.extend_from_slice(&1u16.to_be_bytes()); // an
        p.extend_from_slice(&[0; 4]);
        // Question: a.b TXT IN
        p.extend_from_slice(&[1, b'a', 1, b'b', 0]);
        p.extend_from_slice(&16u16.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        // Answer: name=ptr(c00c), type=TXT, class=IN, ttl=60, rdlen=N, rdata=<txt_len><txt>
        p.extend_from_slice(&[0xc0, 0x0c]);
        p.extend_from_slice(&16u16.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&60u32.to_be_bytes());
        let txt = b"218.248.42.7";
        let txt_len = u8::try_from(txt.len()).unwrap();
        let rdata_len = u16::from(txt_len) + 1;
        p.extend_from_slice(&rdata_len.to_be_bytes());
        p.push(txt_len);
        p.extend_from_slice(txt);

        let parsed = parse_first_txt(&p).expect("must parse");
        assert_eq!(parsed, "218.248.42.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_first_txt_returns_none_when_answer_is_a_record_not_txt() {
        let mut p = Vec::new();
        p.extend_from_slice(&0x4242u16.to_be_bytes());
        p.extend_from_slice(&0x8180u16.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&[0; 4]);
        p.extend_from_slice(&[1, b'a', 0]);
        p.extend_from_slice(&1u16.to_be_bytes()); // A
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&[0xc0, 0x0c]);
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&60u32.to_be_bytes());
        p.extend_from_slice(&4u16.to_be_bytes());
        p.extend_from_slice(&[1, 2, 3, 4]);

        assert!(parse_first_txt(&p).is_none());
    }
}
