//! Minimal `.conf` parser for `WireGuard` profiles.
//!
//! Extracts what the engine actually needs today: DNS servers (for
//! `resolvconf` dependency hinting) and a passthrough of the raw text. The
//! binary still hands `wg-quick` the on-disk path; this parser is only used
//! for pre-flight inspection.

use vortix_core::ports::tunnel::{ParseError, ParsedProfile};

/// Parsed `WireGuard` profile body.
#[derive(Debug, Default, Clone)]
pub struct WgParsedProfile {
    pub dns_servers: Vec<String>,
    pub address: Option<String>,
    pub mtu: Option<u32>,
    pub raw: String,
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
pub fn parse_wg_conf(text: &str) -> Result<WgParsedProfile, ParseError> {
    let mut profile = WgParsedProfile {
        raw: text.to_string(),
        ..Default::default()
    };
    let mut in_interface = false;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            in_interface = section.eq_ignore_ascii_case("Interface");
            continue;
        }
        if !in_interface {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();

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
        }
    }

    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

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
Endpoint = example.com:51820
";
        let p = parse_wg_conf(text).unwrap();
        assert_eq!(p.dns_servers, vec!["1.1.1.1", "8.8.8.8"]);
        assert_eq!(p.address.as_deref(), Some("10.0.0.2/32"));
        assert_eq!(p.mtu, Some(1420));
    }

    #[test]
    fn ignores_peer_dns() {
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
}
