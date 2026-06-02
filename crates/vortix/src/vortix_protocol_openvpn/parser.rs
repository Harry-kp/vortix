//! Minimal `.ovpn` parser — enough to detect auth-user-pass mode and surface
//! the directives required by the multi-tunnel registry (remotes, default
//! route claim, explicit routes).

use std::net::IpAddr;
use std::str::FromStr;

use tracing::warn;

use crate::vortix_core::ports::tunnel::{ParseError, ParsedProfile};

/// IP-family CIDR. Local until U3 introduces `vortix_core::cidr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl Cidr {
    /// Build a `Cidr` from `<addr>/<prefix>` form. Returns `None` on parse
    /// failure or an out-of-range prefix.
    #[must_use]
    pub fn parse_slash(text: &str) -> Option<Self> {
        let (a, p) = text.split_once('/')?;
        let addr = IpAddr::from_str(a.trim()).ok()?;
        let prefix_len: u8 = p.trim().parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix_len > max {
            return None;
        }
        Some(Self { addr, prefix_len })
    }

    /// Build a `Cidr` from `<addr> <netmask>` IPv4 form. Returns `None` if the
    /// netmask isn't a contiguous-1s prefix or either token is not an IPv4
    /// address.
    #[must_use]
    pub fn parse_netmask_v4(addr: &str, mask: &str) -> Option<Self> {
        let addr = IpAddr::from_str(addr.trim()).ok()?;
        let mask = IpAddr::from_str(mask.trim()).ok()?;
        let (IpAddr::V4(_), IpAddr::V4(m)) = (addr, mask) else {
            return None;
        };
        let bits = u32::from(m);
        // Reject non-contiguous masks (e.g. 255.0.255.0).
        let prefix_len: u8 = bits.leading_ones().try_into().ok()?;
        let trailing_zeros = bits.trailing_zeros();
        if u32::from(prefix_len) + trailing_zeros != 32 {
            return None;
        }
        Some(Self { addr, prefix_len })
    }
}

/// One `remote` directive entry. Port defaults to 1194 if absent; `proto`
/// captured verbatim when present (e.g. `udp`, `tcp-client`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSpec {
    pub host: String,
    pub port: u16,
    pub proto: Option<String>,
}

/// One `route` directive entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OvpnRoute {
    pub destination: Cidr,
    pub gateway: Option<IpAddr>,
    pub metric: Option<u32>,
}

/// `static-challenge` directive: the server requests an inline second-factor
/// alongside the username/password. `prompt` is the user-facing text rendered
/// next to the OTP input; `echo` records the server-declared echo bit but is
/// not used to decide masking — vortix always masks OTP input (see plan
/// 2026-06-02-001 DEC-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticChallenge {
    pub prompt: String,
    pub echo: bool,
}

/// Parsed `OpenVPN` profile body.
#[derive(Debug, Default, Clone)]
pub struct OvpnParsedProfile {
    /// Whether the profile expects interactive auth (`auth-user-pass` directive
    /// without a file path).
    pub interactive_auth: bool,
    /// `static-challenge` directive when present. Drives the conditional OTP
    /// field in the auth overlay and the masked prompt in the CLI.
    pub static_challenge: Option<StaticChallenge>,
    /// Ordered list of `remote` directives.
    pub remotes: Vec<RemoteSpec>,
    /// `remote-random` flag — caller may shuffle `remotes` when true.
    pub remote_random: bool,
    /// `redirect-gateway` presence (any flag form: `def1`, `bypass-dhcp`, …).
    pub redirect_gateway: bool,
    /// Explicit `route` directives.
    pub routes: Vec<OvpnRoute>,
    /// The raw config text — `openvpn` consumes the on-disk file, so this is
    /// retained for introspection only.
    pub raw: String,
}

impl ParsedProfile for OvpnParsedProfile {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Parse a `.ovpn` body into [`OvpnParsedProfile`].
///
/// # Errors
///
/// Currently returns `Ok` for any UTF-8 input; future stricter validation
/// (key blocks, malformed directives) can add error variants.
pub fn parse_ovpn_conf(text: &str) -> Result<OvpnParsedProfile, ParseError> {
    let mut profile = OvpnParsedProfile {
        raw: text.to_string(),
        ..Default::default()
    };

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        // `auth-user-pass` alone (no file path) triggers interactive auth.
        if line == "auth-user-pass" {
            profile.interactive_auth = true;
            continue;
        }

        let mut tokens = line.split_whitespace();
        let Some(directive) = tokens.next() else {
            continue;
        };

        match directive {
            "remote" => {
                if let Some(spec) = parse_remote(&mut tokens) {
                    profile.remotes.push(spec);
                } else {
                    warn!(line = %line, "ovpn: malformed remote directive — skipping");
                }
            }
            "remote-random" => {
                profile.remote_random = true;
            }
            "redirect-gateway" | "redirect-private" => {
                // Presence-only: any flag form (def1, bypass-dhcp, autolocal, …)
                // means the tunnel claims the default route.
                profile.redirect_gateway = true;
            }
            "route" => {
                if let Some(route) = parse_route(&mut tokens) {
                    profile.routes.push(route);
                } else {
                    warn!(line = %line, "ovpn: malformed route directive — skipping");
                }
            }
            "static-challenge" => {
                if let Some(sc) = parse_static_challenge(line) {
                    profile.static_challenge = Some(sc);
                } else {
                    warn!(line = %line, "ovpn: malformed static-challenge directive — skipping");
                }
            }
            _ => {}
        }
    }

    Ok(profile)
}

/// Parse `static-challenge "<prompt>" <echo>` from a trimmed config line.
///
/// The prompt may be double-quoted (with backslash-escaped `\"` and `\\`) and
/// commonly contains spaces, so `split_whitespace` cannot tokenize it. We
/// re-parse the line after the `static-challenge` prefix:
///
/// 1. Strip the directive name and surrounding whitespace.
/// 2. If the remainder begins with `"`, extract the quoted span (honouring
///    escapes) as the prompt; otherwise take the next whitespace-delimited
///    token.
/// 3. Parse the next token as the echo bit (`1` → true, `0`/anything else →
///    false).
///
/// Returns `None` when the prompt is empty or absent. An unparseable echo bit
/// is degraded to `false` rather than rejected — most servers send `1`, but a
/// missing or malformed echo should not prevent the prompt from rendering.
fn parse_static_challenge(line: &str) -> Option<StaticChallenge> {
    let rest = line.strip_prefix("static-challenge")?.trim_start();
    let (prompt, after_prompt) = if let Some(after_quote) = rest.strip_prefix('"') {
        // Quoted: scan until the matching `"`, handling `\\` and `\"` escapes.
        let mut prompt = String::new();
        let mut chars = after_quote.char_indices();
        let mut closed_at: Option<usize> = None;
        while let Some((idx, ch)) = chars.next() {
            match ch {
                '\\' => {
                    if let Some((_, escaped)) = chars.next() {
                        prompt.push(escaped);
                    }
                }
                '"' => {
                    closed_at = Some(idx);
                    break;
                }
                _ => prompt.push(ch),
            }
        }
        let closed = closed_at?;
        let remainder = &after_quote[closed + 1..];
        (prompt, remainder)
    } else {
        // Unquoted: take next whitespace-delimited token.
        let mut tokens = rest.split_whitespace();
        let prompt = tokens.next()?.to_string();
        let remainder_start = rest.find(&prompt).map(|i| i + prompt.len())?;
        (prompt, &rest[remainder_start..])
    };
    if prompt.is_empty() {
        return None;
    }
    let echo_token = after_prompt.split_whitespace().next();
    let echo = matches!(echo_token, Some("1"));
    Some(StaticChallenge { prompt, echo })
}

fn parse_remote<'a, I>(tokens: &mut I) -> Option<RemoteSpec>
where
    I: Iterator<Item = &'a str>,
{
    let host = tokens.next()?.to_string();
    let port = match tokens.next() {
        Some(p) => p.parse::<u16>().ok()?,
        None => 1194,
    };
    let proto = tokens.next().map(str::to_string);
    Some(RemoteSpec { host, port, proto })
}

fn parse_route<'a, I>(tokens: &mut I) -> Option<OvpnRoute>
where
    I: Iterator<Item = &'a str>,
{
    let dest_tok = tokens.next()?;
    let second = tokens.next();

    let (destination, gateway_tok) = if dest_tok.contains('/') {
        // CIDR form: `route 10.0.0.0/8 [gateway] [metric]`
        (Cidr::parse_slash(dest_tok)?, second)
    } else {
        // Netmask form: `route 10.0.0.0 255.0.0.0 [gateway] [metric]`
        let mask = second?;
        (Cidr::parse_netmask_v4(dest_tok, mask)?, tokens.next())
    };

    // Gateway is optional. OpenVPN accepts the literal `default`, which we
    // model as "no explicit gateway" so callers fall back to the tunnel's
    // assigned gateway.
    let gateway = match gateway_tok {
        Some(tok) if tok.eq_ignore_ascii_case("default") => None,
        Some(tok) => Some(IpAddr::from_str(tok).ok()?),
        None => None,
    };

    let metric = tokens.next().and_then(|m| m.parse::<u32>().ok());

    Some(OvpnRoute {
        destination,
        gateway,
        metric,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn detects_interactive_auth() {
        let text = "client\nproto udp\nauth-user-pass\nremote example.com 1194\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert!(p.interactive_auth);
    }

    #[test]
    fn ignores_auth_with_file() {
        let text = "client\nauth-user-pass /etc/openvpn/creds.txt\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert!(!p.interactive_auth);
    }

    #[test]
    fn skips_comments() {
        let text = "# auth-user-pass\n; auth-user-pass\nclient\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert!(!p.interactive_auth);
    }

    #[test]
    fn parses_single_remote_with_port_and_proto() {
        let text = "client\nremote vpn.example.com 1194 udp\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert_eq!(p.remotes.len(), 1);
        assert_eq!(p.remotes[0].host, "vpn.example.com");
        assert_eq!(p.remotes[0].port, 1194);
        assert_eq!(p.remotes[0].proto.as_deref(), Some("udp"));
    }

    #[test]
    fn parses_remote_random_and_multiple_remotes() {
        let text = "client\nremote-random\nremote a.example.com 1194 udp\nremote b.example.com 443 tcp\nremote c.example.com\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert!(p.remote_random);
        assert_eq!(p.remotes.len(), 3);
        assert_eq!(p.remotes[0].host, "a.example.com");
        assert_eq!(p.remotes[1].port, 443);
        assert_eq!(p.remotes[2].host, "c.example.com");
        assert_eq!(p.remotes[2].port, 1194);
        assert!(p.remotes[2].proto.is_none());
    }

    #[test]
    fn redirect_gateway_def1_sets_flag() {
        let text = "client\nredirect-gateway def1\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert!(p.redirect_gateway);
    }

    #[test]
    fn redirect_gateway_bare_also_sets_flag() {
        let text = "client\nredirect-gateway\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert!(p.redirect_gateway);
    }

    #[test]
    fn no_redirect_with_two_routes() {
        let text = "client\nroute 10.0.0.0 255.0.0.0\nroute 192.168.1.0 255.255.255.0\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert!(!p.redirect_gateway);
        assert_eq!(p.routes.len(), 2);
        assert_eq!(p.routes[0].destination.prefix_len, 8);
        assert_eq!(p.routes[1].destination.prefix_len, 24);
    }

    #[test]
    fn remote_with_no_port_defaults_to_1194() {
        let text = "client\nremote vpn.example.com\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert_eq!(p.remotes.len(), 1);
        assert_eq!(p.remotes[0].port, 1194);
        assert!(p.remotes[0].proto.is_none());
    }

    #[test]
    fn remote_proto_tcp_client_captured_verbatim() {
        let text = "client\nremote vpn.example.com 443 tcp-client\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert_eq!(p.remotes[0].proto.as_deref(), Some("tcp-client"));
    }

    #[test]
    fn route_netmask_and_cidr_forms_are_equivalent() {
        let netmask = parse_ovpn_conf("route 10.0.0.0 255.0.0.0\n").unwrap();
        let cidr = parse_ovpn_conf("route 10.0.0.0/8\n").unwrap();
        assert_eq!(netmask.routes.len(), 1);
        assert_eq!(cidr.routes.len(), 1);
        assert_eq!(netmask.routes[0].destination, cidr.routes[0].destination);
        assert_eq!(
            netmask.routes[0].destination.addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))
        );
        assert_eq!(netmask.routes[0].destination.prefix_len, 8);
    }

    #[test]
    fn malformed_route_is_skipped_rest_preserved() {
        let text = "client\nroute\nroute 10.0.0.0/8\nremote vpn.example.com 1194 udp\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert_eq!(p.routes.len(), 1);
        assert_eq!(p.routes[0].destination.prefix_len, 8);
        assert_eq!(p.remotes.len(), 1);
    }

    #[test]
    fn route_with_gateway_and_metric() {
        let text = "route 10.0.0.0/8 192.168.1.1 100\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert_eq!(p.routes.len(), 1);
        assert_eq!(
            p.routes[0].gateway,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
        assert_eq!(p.routes[0].metric, Some(100));
    }

    #[test]
    fn route_default_keyword_yields_no_gateway() {
        let text = "route 10.0.0.0 255.0.0.0 default\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert_eq!(p.routes.len(), 1);
        assert!(p.routes[0].gateway.is_none());
    }

    #[test]
    fn non_contiguous_netmask_is_rejected() {
        let text = "route 10.0.0.0 255.0.255.0\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert!(p.routes.is_empty());
    }

    #[test]
    fn static_challenge_quoted_multi_word_with_echo_1() {
        let text = "client\nstatic-challenge \"Enter authenticator code\" 1\n";
        let p = parse_ovpn_conf(text).unwrap();
        let sc = p.static_challenge.expect("static-challenge parsed");
        assert_eq!(sc.prompt, "Enter authenticator code");
        assert!(sc.echo);
    }

    #[test]
    fn static_challenge_echo_zero() {
        let text = "static-challenge \"OTP\" 0\n";
        let p = parse_ovpn_conf(text).unwrap();
        let sc = p.static_challenge.unwrap();
        assert_eq!(sc.prompt, "OTP");
        assert!(!sc.echo);
    }

    #[test]
    fn static_challenge_unquoted_single_token() {
        let text = "static-challenge Code 1\n";
        let p = parse_ovpn_conf(text).unwrap();
        let sc = p.static_challenge.unwrap();
        assert_eq!(sc.prompt, "Code");
        assert!(sc.echo);
    }

    #[test]
    fn static_challenge_embedded_escaped_quote() {
        let text = "static-challenge \"Type \\\"code\\\" here\" 1\n";
        let p = parse_ovpn_conf(text).unwrap();
        let sc = p.static_challenge.unwrap();
        assert_eq!(sc.prompt, "Type \"code\" here");
        assert!(sc.echo);
    }

    #[test]
    fn static_challenge_apostrophe_in_prompt() {
        let text = "static-challenge \"Enter user's TOTP\" 1\n";
        let p = parse_ovpn_conf(text).unwrap();
        let sc = p.static_challenge.unwrap();
        assert_eq!(sc.prompt, "Enter user's TOTP");
    }

    #[test]
    fn static_challenge_empty_quoted_prompt_is_skipped() {
        let text = "static-challenge \"\" 1\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert!(p.static_challenge.is_none());
    }

    #[test]
    fn static_challenge_malformed_echo_defaults_to_false() {
        let text = "static-challenge \"OTP\" 2\n";
        let p = parse_ovpn_conf(text).unwrap();
        let sc = p.static_challenge.unwrap();
        assert_eq!(sc.prompt, "OTP");
        assert!(!sc.echo);
    }

    #[test]
    fn static_challenge_extra_whitespace_tolerated() {
        let text = "static-challenge   \"OTP\"   1   \n";
        let p = parse_ovpn_conf(text).unwrap();
        let sc = p.static_challenge.unwrap();
        assert_eq!(sc.prompt, "OTP");
        assert!(sc.echo);
    }

    #[test]
    fn static_challenge_absent_when_directive_missing() {
        let text = "client\nauth-user-pass\nremote vpn.example.com\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert!(p.static_challenge.is_none());
    }

    #[test]
    fn static_challenge_commented_out_is_skipped() {
        let text = "# static-challenge \"OTP\" 1\n; static-challenge \"OTP\" 1\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert!(p.static_challenge.is_none());
    }

    #[test]
    fn static_challenge_coexists_with_auth_user_pass() {
        let text = "auth-user-pass\nstatic-challenge \"Enter code\" 1\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert!(p.interactive_auth);
        let sc = p.static_challenge.unwrap();
        assert_eq!(sc.prompt, "Enter code");
        assert!(sc.echo);
    }

    #[test]
    fn static_challenge_unterminated_quote_is_skipped() {
        let text = "static-challenge \"unterminated 1\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert!(p.static_challenge.is_none());
    }
}
