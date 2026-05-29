//! Minimal `.conf` parser for `WireGuard` profiles.
//!
//! Extracts what the engine actually needs today: DNS servers (for
//! `resolvconf` dependency hinting), peer routing data (`AllowedIPs`,
//! `Endpoint`, `FwMark`) used by the multi-tunnel registry's conflict
//! detector and killswitch synthesis, a `has_hooks` flag derived from
//! the presence of `PreUp`/`PostUp`/`PreDown`/`PostDown` directives in
//! the `[Interface]` section, and a passthrough of the raw text. The
//! binary still hands `wg-quick` the on-disk path; this parser is only
//! used for pre-flight inspection.

use std::net::{IpAddr, SocketAddr};

use crate::vortix_core::ports::tunnel::{ParseError, ParsedProfile};

/// CIDR block: an IP address paired with a prefix length.
///
/// This is a small, local wrapper used by the `WireGuard` parser. A
/// workspace-wide `vortix_core::cidr` helper is planned (see plan U3);
/// when it lands, this type will be replaced by a re-export and the
/// rest of the WG parser will continue to compile unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl Cidr {
    /// Parse a `<addr>/<prefix_len>` CIDR string.
    ///
    /// Returns `None` for any malformed input (missing slash, invalid
    /// address, non-numeric prefix, or prefix-length out of range for
    /// the address family).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (addr_s, prefix_s) = s.split_once('/')?;
        let addr: IpAddr = addr_s.trim().parse().ok()?;
        let prefix_len: u8 = prefix_s.trim().parse().ok()?;
        let max_prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max_prefix {
            return None;
        }
        Some(Self { addr, prefix_len })
    }
}

/// One `[Peer]` block from a `WireGuard` configuration.
#[derive(Debug, Default, Clone)]
pub struct WgPeer {
    pub public_key: String,
    pub allowed_ips: Vec<Cidr>,
    pub endpoint: Option<SocketAddr>,
    pub fwmark: Option<u32>,
}

/// Parsed `WireGuard` profile body.
#[derive(Debug, Default, Clone)]
pub struct WgParsedProfile {
    pub dns_servers: Vec<String>,
    pub address: Option<String>,
    pub mtu: Option<u32>,
    pub peers: Vec<WgPeer>,
    /// True if the `[Interface]` section declares any of
    /// `PreUp`/`PostUp`/`PreDown`/`PostDown` (matched case-insensitively).
    pub has_hooks: bool,
    pub raw: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Interface,
    Peer,
}

impl ParsedProfile for WgParsedProfile {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn dns_servers(&self) -> Vec<String> {
        self.dns_servers.clone()
    }
}

/// Parse a `.conf` (INI-style) body into [`WgParsedProfile`].
///
/// # Errors
///
/// Currently returns errors only when the input contains a section header
/// that's neither `[Interface]` nor `[Peer]`; future stricter validation can
/// expand the error set.
#[allow(clippy::too_many_lines)]
pub fn parse_wg_conf(text: &str) -> Result<WgParsedProfile, ParseError> {
    let mut profile = WgParsedProfile {
        raw: text.to_string(),
        ..Default::default()
    };
    let mut section = Section::None;
    let mut current_peer: Option<WgPeer> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            // Finalize any in-flight peer before switching section.
            if let Some(peer) = current_peer.take() {
                profile.peers.push(peer);
            }
            let header = header.trim();
            if header.eq_ignore_ascii_case("Interface") {
                section = Section::Interface;
            } else if header.eq_ignore_ascii_case("Peer") {
                section = Section::Peer;
                current_peer = Some(WgPeer::default());
            } else {
                section = Section::None;
            }
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();

        match section {
            Section::Interface => {
                if key.eq_ignore_ascii_case("DNS") {
                    for entry in value.split(',') {
                        let entry = entry.trim();
                        if !entry.is_empty() {
                            profile.dns_servers.push(entry.to_string());
                        }
                    }
                } else if key.eq_ignore_ascii_case("Address") {
                    profile.address = Some(value.to_string());
                } else if key.eq_ignore_ascii_case("MTU") {
                    profile.mtu = value.parse::<u32>().ok();
                } else if key.eq_ignore_ascii_case("PreUp")
                    || key.eq_ignore_ascii_case("PostUp")
                    || key.eq_ignore_ascii_case("PreDown")
                    || key.eq_ignore_ascii_case("PostDown")
                {
                    profile.has_hooks = true;
                }
            }
            Section::Peer => {
                if let Some(peer) = current_peer.as_mut() {
                    if key.eq_ignore_ascii_case("PublicKey") {
                        peer.public_key = value.to_string();
                    } else if key.eq_ignore_ascii_case("AllowedIPs") {
                        for entry in value.split(',') {
                            let entry = entry.trim();
                            if entry.is_empty() {
                                continue;
                            }
                            match Cidr::parse(entry) {
                                Some(cidr) => peer.allowed_ips.push(cidr),
                                None => {
                                    tracing::warn!(
                                        cidr = entry,
                                        "dropping malformed AllowedIPs entry in [Peer]"
                                    );
                                }
                            }
                        }
                    } else if key.eq_ignore_ascii_case("Endpoint") {
                        // Endpoint may be `host:port`. We only capture
                        // resolved `SocketAddr` values here; DNS
                        // resolution is `wg-quick`'s job at up-time.
                        if let Ok(addr) = value.parse::<SocketAddr>() {
                            peer.endpoint = Some(addr);
                        }
                    } else if key.eq_ignore_ascii_case("FwMark") {
                        if value.eq_ignore_ascii_case("off") {
                            peer.fwmark = Some(0);
                        } else {
                            // Accept hex (0x...) or decimal forms.
                            let parsed = if let Some(hex) = value
                                .strip_prefix("0x")
                                .or_else(|| value.strip_prefix("0X"))
                            {
                                u32::from_str_radix(hex, 16).ok()
                            } else {
                                value.parse::<u32>().ok()
                            };
                            if let Some(mark) = parsed {
                                peer.fwmark = Some(mark);
                            } else {
                                tracing::warn!(value, "ignoring malformed FwMark value in [Peer]");
                            }
                        }
                    }
                }
            }
            Section::None => {}
        }
    }

    if let Some(peer) = current_peer.take() {
        profile.peers.push(peer);
    }

    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_dns_and_address() {
        let text = "\
[Interface]
PrivateKey = AAAA
Address = 10.0.0.2/32
DNS = 1.1.1.1, 8.8.8.8
MTU = 1420

[Peer]
PublicKey = BBBB
Endpoint = 203.0.113.5:51820
";
        let p = parse_wg_conf(text).unwrap();
        assert_eq!(p.dns_servers, vec!["1.1.1.1", "8.8.8.8"]);
        assert_eq!(p.address.as_deref(), Some("10.0.0.2/32"));
        assert_eq!(p.mtu, Some(1420));
    }

    #[test]
    fn ignores_peer_dns_keeps_interface_dns_with_peers_parsed() {
        // The old `ignores_peer_dns` test confirmed peer-section DNS
        // directives don't leak into Interface DNS. Now we also confirm
        // the peer itself is captured.
        let text = "\
[Interface]
DNS = 1.1.1.1

[Peer]
PublicKey = BBBB
DNS = 9.9.9.9
AllowedIPs = 10.0.0.0/8
";
        let p = parse_wg_conf(text).unwrap();
        assert_eq!(p.dns_servers, vec!["1.1.1.1"]);
        assert_eq!(p.peers.len(), 1);
        assert_eq!(p.peers[0].public_key, "BBBB");
        assert_eq!(p.peers[0].allowed_ips.len(), 1);
    }

    #[test]
    fn ignores_peer_dns_no_interface() {
        let text = "[Peer]\nDNS = 9.9.9.9\n";
        let p = parse_wg_conf(text).unwrap();
        assert!(p.dns_servers.is_empty());
    }

    #[test]
    fn no_dns_directive_is_empty() {
        let text = "[Interface]\nAddress = 10.0.0.2/32\n";
        let p = parse_wg_conf(text).unwrap();
        assert!(p.dns_servers.is_empty());
    }

    #[test]
    fn happy_single_peer_full_fields() {
        let text = "\
[Interface]
PrivateKey = AAAA
Address = 10.0.0.2/32

[Peer]
PublicKey = BBBB
AllowedIPs = 10.0.0.0/8, 192.168.0.0/16
Endpoint = 203.0.113.5:51820
FwMark = 51820
";
        let p = parse_wg_conf(text).unwrap();
        assert_eq!(p.peers.len(), 1);
        let peer = &p.peers[0];
        assert_eq!(peer.public_key, "BBBB");
        assert_eq!(peer.allowed_ips.len(), 2);
        assert_eq!(
            peer.allowed_ips[0].addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))
        );
        assert_eq!(peer.allowed_ips[0].prefix_len, 8);
        assert_eq!(
            peer.allowed_ips[1].addr,
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0))
        );
        assert_eq!(peer.allowed_ips[1].prefix_len, 16);
        assert_eq!(
            peer.endpoint,
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
                51820
            ))
        );
        assert_eq!(peer.fwmark, Some(51820));
    }

    #[test]
    fn happy_multiple_peers_preserve_order() {
        let text = "\
[Interface]
PrivateKey = AAAA

[Peer]
PublicKey = PEER1
AllowedIPs = 10.0.0.0/8

[Peer]
PublicKey = PEER2
AllowedIPs = 192.168.0.0/16

[Peer]
PublicKey = PEER3
AllowedIPs = 172.16.0.0/12
";
        let p = parse_wg_conf(text).unwrap();
        assert_eq!(p.peers.len(), 3);
        assert_eq!(p.peers[0].public_key, "PEER1");
        assert_eq!(p.peers[1].public_key, "PEER2");
        assert_eq!(p.peers[2].public_key, "PEER3");
    }

    #[test]
    fn allowed_ips_mixed_v4_and_v6_one_line() {
        let text = "\
[Interface]
PrivateKey = AAAA

[Peer]
PublicKey = BBBB
AllowedIPs = 10.0.0.0/8, fd00::/64
";
        let p = parse_wg_conf(text).unwrap();
        assert_eq!(p.peers.len(), 1);
        let peer = &p.peers[0];
        assert_eq!(peer.allowed_ips.len(), 2);
        assert!(peer.allowed_ips[0].addr.is_ipv4());
        assert_eq!(peer.allowed_ips[0].prefix_len, 8);
        assert!(peer.allowed_ips[1].addr.is_ipv6());
        assert_eq!(peer.allowed_ips[1].prefix_len, 64);
    }

    #[test]
    fn allowed_ips_both_default_routes() {
        let text = "\
[Interface]
PrivateKey = AAAA

[Peer]
PublicKey = BBBB
AllowedIPs = 0.0.0.0/0, ::/0
";
        let p = parse_wg_conf(text).unwrap();
        let peer = &p.peers[0];
        assert_eq!(peer.allowed_ips.len(), 2);
        assert_eq!(peer.allowed_ips[0].addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(peer.allowed_ips[0].prefix_len, 0);
        assert_eq!(peer.allowed_ips[1].addr, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(peer.allowed_ips[1].prefix_len, 0);
    }

    #[test]
    fn peer_without_endpoint_or_fwmark() {
        let text = "\
[Interface]
PrivateKey = AAAA

[Peer]
PublicKey = BBBB
AllowedIPs = 10.0.0.0/8
";
        let p = parse_wg_conf(text).unwrap();
        assert_eq!(p.peers.len(), 1);
        let peer = &p.peers[0];
        assert!(peer.endpoint.is_none());
        assert!(peer.fwmark.is_none());
        assert_eq!(peer.allowed_ips.len(), 1);
    }

    #[test]
    fn malformed_allowed_ips_dropped_rest_preserved() {
        let text = "\
[Interface]
PrivateKey = AAAA

[Peer]
PublicKey = BBBB
AllowedIPs = 10.0.0/8, 192.168.0.0/16, bogus
";
        let p = parse_wg_conf(text).unwrap();
        assert_eq!(p.peers.len(), 1);
        let peer = &p.peers[0];
        // Only the valid 192.168.0.0/16 should remain; `10.0.0/8` is a
        // malformed IPv4 (3 octets) and `bogus` has no slash.
        assert_eq!(peer.allowed_ips.len(), 1);
        assert_eq!(
            peer.allowed_ips[0].addr,
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0))
        );
        assert_eq!(peer.allowed_ips[0].prefix_len, 16);
    }

    #[test]
    fn fwmark_off_parses_as_zero() {
        let text = "\
[Interface]
PrivateKey = AAAA

[Peer]
PublicKey = BBBB
FwMark = off
";
        let p = parse_wg_conf(text).unwrap();
        assert_eq!(p.peers[0].fwmark, Some(0));
    }

    #[test]
    fn fwmark_hex_value_parses() {
        let text = "\
[Interface]
PrivateKey = AAAA

[Peer]
PublicKey = BBBB
FwMark = 0xca6c
";
        let p = parse_wg_conf(text).unwrap();
        assert_eq!(p.peers[0].fwmark, Some(0xca6c));
    }

    #[test]
    fn postup_sets_has_hooks() {
        let text = "\
[Interface]
PrivateKey = AAAA
Address = 10.0.0.2/32
PostUp = iptables -A FORWARD -i %i -j ACCEPT
";
        let p = parse_wg_conf(text).unwrap();
        assert!(p.has_hooks);
    }

    #[test]
    fn lowercase_postup_sets_has_hooks() {
        let text = "\
[Interface]
PrivateKey = AAAA
postup = iptables -A FORWARD -i %i -j ACCEPT
";
        let p = parse_wg_conf(text).unwrap();
        assert!(p.has_hooks);
    }

    #[test]
    fn comment_mentioning_preup_does_not_set_has_hooks() {
        let text = "\
[Interface]
PrivateKey = AAAA
# When PreUp is set, vortix warns about hook execution
Address = 10.0.0.2/32
";
        let p = parse_wg_conf(text).unwrap();
        assert!(!p.has_hooks);
    }

    #[test]
    fn profile_without_hooks_reports_false() {
        let text = "\
[Interface]
PrivateKey = AAAA
Address = 10.0.0.2/32

[Peer]
PublicKey = BBBB
AllowedIPs = 10.0.0.0/8
";
        let p = parse_wg_conf(text).unwrap();
        assert!(!p.has_hooks);
    }

    #[test]
    fn case_insensitive_section_headers() {
        let text = "\
[interface]
PrivateKey = AAAA

[peer]
PublicKey = BBBB
AllowedIPs = 10.0.0.0/8
";
        let p = parse_wg_conf(text).unwrap();
        assert_eq!(p.peers.len(), 1);
        assert_eq!(p.peers[0].public_key, "BBBB");
    }

    #[test]
    fn all_four_hook_directives_detected() {
        for directive in ["PreUp", "PostUp", "PreDown", "PostDown"] {
            let text = format!("[Interface]\n{directive} = echo hi\n");
            let p = parse_wg_conf(&text).unwrap();
            assert!(p.has_hooks, "directive {directive} should set has_hooks");
        }
    }
}
