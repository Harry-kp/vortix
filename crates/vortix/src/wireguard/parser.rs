//! Minimal `.conf` parser for `WireGuard` profiles.
//!
//! Extracts what the engine actually needs today: DNS servers (for
//! `resolvconf` dependency hinting), peer routing data (`AllowedIPs`,
//! `Endpoint`, `FwMark`) used by the multi-tunnel engine snapshot's conflict
//! detector and killswitch synthesis, a `has_hooks` flag derived from
//! rejection of `PreUp`/`PostUp`/`PreDown`/`PostDown` executable directives
//! in the `[Interface]` section, and a passthrough of the raw text. The
//! binary still hands `wg-quick` the on-disk path; this parser is only
//! used for pre-flight inspection.

use std::net::SocketAddr;

use crate::cidr::Cidr;
use crate::tunnel::ParseError;

const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_CONFIG_PEERS: usize = 256;
const MAX_CONFIG_ROUTES_PER_PEER: usize = 256;
const MAX_CONFIG_FIELD_BYTES: usize = 4096;

/// One `[Peer]` block from a `WireGuard` configuration.
#[derive(Debug, Default, Clone)]
pub struct WgPeer {
    pub public_key: String,
    pub allowed_ips: Vec<Cidr>,
    pub endpoint: Option<SocketAddr>,
    /// Original endpoint host and port, retained when DNS resolution is
    /// required before a firewall safety barrier is installed.
    pub endpoint_host: Option<String>,
    pub endpoint_port: Option<u16>,
    pub fwmark: Option<u32>,
    pub persistent_keepalive: Option<u16>,
}

/// Parsed `WireGuard` profile body.
#[derive(Debug, Default, Clone)]
pub struct WgParsedProfile {
    pub dns_servers: Vec<String>,
    pub dns_search_domains: Vec<String>,
    /// Every `Address =` entry, comments stripped.
    pub addresses: Vec<String>,
    /// An `[Interface]` section was present.
    pub has_interface: bool,
    /// The `[Interface]` section set a `PrivateKey`.
    pub has_private_key: bool,
    pub mtu: Option<u32>,
    pub peers: Vec<WgPeer>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Interface,
    Peer,
}

impl WgParsedProfile {
    /// Whether the profile asks for DNS (servers or search domains).
    #[must_use]
    pub fn has_dns(&self) -> bool {
        !self.dns_servers.is_empty() || !self.dns_search_domains.is_empty()
    }

    /// Whether any interface address is IPv6 (`wg-quick` then needs IPv6).
    #[must_use]
    pub fn has_ipv6_address(&self) -> bool {
        self.addresses.iter().any(|entry| {
            entry
                .split('/')
                .next()
                .is_some_and(|ip| ip.parse::<std::net::Ipv6Addr>().is_ok())
        })
    }

    #[must_use]
    pub fn dns_request(&self) -> crate::control::dns::DnsRequest {
        crate::control::dns::DnsRequest {
            servers: self
                .dns_servers
                .iter()
                .filter_map(|server| server.parse().ok())
                .collect(),
            search_domains: self.dns_search_domains.clone(),
        }
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
    if text.len() > MAX_CONFIG_BYTES {
        return Err(ParseError::MalformedField {
            field: "profile",
            detail: format!("exceeds {MAX_CONFIG_BYTES} bytes"),
        });
    }
    let mut profile = WgParsedProfile {
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
                if profile.peers.len() >= MAX_CONFIG_PEERS {
                    return Err(ParseError::MalformedField {
                        field: "Peer",
                        detail: format!("exceeds {MAX_CONFIG_PEERS} entries"),
                    });
                }
                profile.peers.push(peer);
            }
            let header = header.trim();
            if header.eq_ignore_ascii_case("Interface") {
                section = Section::Interface;
                profile.has_interface = true;
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
        if key.len() > MAX_CONFIG_FIELD_BYTES || value.len() > MAX_CONFIG_FIELD_BYTES {
            return Err(ParseError::MalformedField {
                field: "WireGuard directive",
                detail: format!("field exceeds {MAX_CONFIG_FIELD_BYTES} bytes"),
            });
        }

        match section {
            Section::Interface => {
                if key.eq_ignore_ascii_case("PrivateKey") {
                    profile.has_private_key |= !value.is_empty();
                } else if key.eq_ignore_ascii_case("DNS") {
                    // Strip valid trailing comments before comma
                    // tokenization. Otherwise `1.1.1.1 # note` is no
                    // longer an IP and is misclassified as a search domain.
                    let value = value
                        .find(['#', ';'])
                        .map_or(value, |comment| &value[..comment]);
                    for entry in value.split(',') {
                        let entry = entry.trim();
                        if !entry.is_empty() {
                            if entry.parse::<std::net::IpAddr>().is_ok() {
                                profile.dns_servers.push(entry.to_string());
                            } else {
                                profile.dns_search_domains.push(entry.to_string());
                            }
                        }
                    }
                } else if key.eq_ignore_ascii_case("Address") {
                    let value = value
                        .find(['#', ';'])
                        .map_or(value, |comment| &value[..comment]);
                    profile.addresses.extend(
                        value
                            .split(',')
                            .map(str::trim)
                            .filter(|entry| !entry.is_empty())
                            .map(str::to_string),
                    );
                } else if key.eq_ignore_ascii_case("MTU") {
                    profile.mtu = value.parse::<u32>().ok();
                } else if key.eq_ignore_ascii_case("PreUp")
                    || key.eq_ignore_ascii_case("PostUp")
                    || key.eq_ignore_ascii_case("PreDown")
                    || key.eq_ignore_ascii_case("PostDown")
                {
                    return Err(ParseError::Unsupported(format!(
                        "WireGuard `{key}` executable directives are not allowed: Vortix never runs profile commands as root; migrate this automation to a global lifecycle hook using an absolute executable plus argv"
                    )));
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
                            match entry.parse::<Cidr>().ok() {
                                Some(cidr) => {
                                    if peer.allowed_ips.len() >= MAX_CONFIG_ROUTES_PER_PEER {
                                        return Err(ParseError::MalformedField {
                                            field: "AllowedIPs",
                                            detail: format!(
                                                "peer exceeds {MAX_CONFIG_ROUTES_PER_PEER} routes"
                                            ),
                                        });
                                    }
                                    peer.allowed_ips.push(cidr);
                                }
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
                        if let Some((host, port)) = parse_endpoint_host(value) {
                            peer.endpoint_host = Some(host);
                            peer.endpoint_port = Some(port);
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
                    } else if key.eq_ignore_ascii_case("PersistentKeepalive") {
                        peer.persistent_keepalive = value
                            .split(['#', ';'])
                            .next()
                            .and_then(|seconds| seconds.trim().parse::<u16>().ok())
                            .filter(|seconds| *seconds > 0);
                    }
                }
            }
            Section::None => {}
        }
    }

    if let Some(peer) = current_peer.take() {
        if profile.peers.len() >= MAX_CONFIG_PEERS {
            return Err(ParseError::MalformedField {
                field: "Peer",
                detail: format!("exceeds {MAX_CONFIG_PEERS} entries"),
            });
        }
        profile.peers.push(peer);
    }

    Ok(profile)
}

pub(crate) fn parse_endpoint_host(value: &str) -> Option<(String, u16)> {
    let (host, port) = value.rsplit_once(':')?;
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    let port = port.parse::<u16>().ok().filter(|port| *port != 0)?;
    (!host.is_empty()).then(|| (host.to_owned(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_interface_line(line: &str) -> WgParsedProfile {
        parse_wg_conf(&format!(
            "[Interface]\nPrivateKey = abc\n{line}\n\n[Peer]\nPublicKey = xyz\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 1.2.3.4:51820\n"
        ))
        .unwrap()
    }

    #[test]
    fn dns_is_detected_in_any_spelling_but_not_in_comments() {
        assert!(with_interface_line("DNS = 1.1.1.1").has_dns());
        assert!(with_interface_line("dns = 8.8.8.8").has_dns());
        assert!(with_interface_line("  DNS  =  1.1.1.1, 8.8.8.8").has_dns());
        assert!(with_interface_line("DNS = corp.example").has_dns());
        assert!(!with_interface_line("# DNS = 1.1.1.1").has_dns());
        assert!(!with_interface_line("MTU = 1420").has_dns());
    }

    #[test]
    fn ipv6_address_detection_reads_every_address_entry() {
        assert!(!with_interface_line("Address = 10.0.0.2/24").has_ipv6_address());
        assert!(with_interface_line("Address = 10.0.0.2/24, fd00::2/64").has_ipv6_address());
        assert!(with_interface_line("Address = fd00::2/128").has_ipv6_address());
        assert!(with_interface_line("address = FD00::2/64").has_ipv6_address());
        assert!(!with_interface_line("MTU = 1420").has_ipv6_address());
        assert!(
            !with_interface_line("Address = 10.0.0.2/24 # fd00::2 in a comment").has_ipv6_address()
        );
        assert!(
            with_interface_line("Address = 10.0.0.2/24\nAddress = fd00::2/64").has_ipv6_address()
        );
    }
    use std::net::IpAddr;
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
        assert_eq!(p.addresses, ["10.0.0.2/32"]);
        assert_eq!(p.mtu, Some(1420));
    }

    #[test]
    fn parses_persistent_keepalive_as_peer_expectation() {
        let parsed = parse_wg_conf(
            "[Interface]\nPrivateKey = private\n[Peer]\nPublicKey = peer\nAllowedIPs = 10.0.0.0/24\nPersistentKeepalive = 25 # seconds\n",
        )
        .unwrap();
        assert_eq!(parsed.peers[0].persistent_keepalive, Some(25));
    }

    #[test]
    fn separates_resolver_addresses_from_search_domains() {
        let p = parse_wg_conf("[Interface]\nDNS = 1.1.1.1, corp.example\n").unwrap();
        assert_eq!(p.dns_servers, vec!["1.1.1.1"]);
        assert_eq!(p.dns_search_domains, vec!["corp.example"]);
    }

    #[test]
    fn strips_hash_comment_from_dns_value_before_classification() {
        let p = parse_wg_conf(
            "[Interface]\nDNS = 1.1.1.1, corp.example # primary resolver and search\n",
        )
        .unwrap();
        assert_eq!(p.dns_servers, vec!["1.1.1.1"]);
        assert_eq!(p.dns_search_domains, vec!["corp.example"]);
    }

    #[test]
    fn strips_semicolon_comment_from_dns_value_before_classification() {
        let p = parse_wg_conf(
            "[Interface]\nDNS = 2606:4700:4700::1111, internal.example ; office DNS\n",
        )
        .unwrap();
        assert_eq!(p.dns_servers, vec!["2606:4700:4700::1111"]);
        assert_eq!(p.dns_search_domains, vec!["internal.example"]);
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
    fn hostname_endpoint_is_retained_for_pre_block_resolution() {
        let parsed = parse_wg_conf(
            "[Interface]\nPrivateKey = AAAA\n[Peer]\nPublicKey = BBBB\nEndpoint = vpn.example.com:51820\n",
        )
        .unwrap();
        assert_eq!(parsed.peers[0].endpoint, None);
        assert_eq!(
            parsed.peers[0].endpoint_host.as_deref(),
            Some("vpn.example.com")
        );
        assert_eq!(parsed.peers[0].endpoint_port, Some(51820));
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
    fn postup_is_rejected_with_owner_hook_migration_guidance() {
        let text = "\
[Interface]
PrivateKey = AAAA
Address = 10.0.0.2/32
PostUp = iptables -A FORWARD -i %i -j ACCEPT
";
        let error = parse_wg_conf(text).unwrap_err().to_string();
        assert!(error.contains("PostUp"));
        assert!(error.contains("never runs profile commands as root"));
        assert!(error.contains("lifecycle hook"));
    }

    #[test]
    fn lowercase_postup_is_rejected() {
        let text = "\
[Interface]
PrivateKey = AAAA
postup = iptables -A FORWARD -i %i -j ACCEPT
";
        assert!(parse_wg_conf(text).is_err());
    }

    #[test]
    fn comment_mentioning_preup_remains_valid() {
        let text = "\
[Interface]
PrivateKey = AAAA
# When PreUp is set, vortix warns about hook execution
Address = 10.0.0.2/32
";
        let p = parse_wg_conf(text).unwrap();
        assert_eq!(p.addresses, ["10.0.0.2/32"]);
    }

    #[test]
    fn profile_without_executable_directives_remains_valid() {
        let text = "\
[Interface]
PrivateKey = AAAA
Address = 10.0.0.2/32

[Peer]
PublicKey = BBBB
AllowedIPs = 10.0.0.0/8
";
        let p = parse_wg_conf(text).unwrap();
        assert_eq!(p.peers.len(), 1);
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
    fn all_four_executable_directives_are_rejected() {
        for directive in ["PreUp", "PostUp", "PreDown", "PostDown"] {
            let text = format!("[Interface]\n{directive} = echo hi\n");
            let error = parse_wg_conf(&text).unwrap_err().to_string();
            assert!(
                error.contains(directive),
                "directive {directive} should be named in the error"
            );
        }
    }
}
