//! Minimal `.ovpn` parser — enough to detect auth-user-pass mode and surface
//! the directives required by the multi-tunnel registry (remotes, default
//! route claim, explicit routes).

use std::net::IpAddr;
use std::str::FromStr;

use tracing::warn;

use crate::vortix_core::ports::tunnel::{ParseError, ParsedProfile};

/// IP-family CIDR. Local until a shared helper introduces `vortix_core::cidr`.
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
/// the parser decision record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticChallenge {
    pub prompt: String,
    pub echo: bool,
}

/// Credential behavior relevant to unattended boot connection.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum BootCredentialRequirement {
    #[default]
    NonInteractive,
    Interactive,
    UnsupportedKeyProvider,
}

/// Parsed `OpenVPN` profile body.
#[derive(Debug, Default, Clone)]
pub struct OvpnParsedProfile {
    /// Whether the profile expects interactive auth (`auth-user-pass` directive
    /// without a file path).
    pub interactive_auth: bool,
    /// Conservative boot-time credential requirement. Unlike
    /// `interactive_auth`, this treats file-backed username/password auth as
    /// password-dependent and therefore ineligible for pre-login startup.
    pub boot_credentials: BootCredentialRequirement,
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
    /// Resolver addresses requested with `dhcp-option DNS`.
    pub dns_servers: Vec<IpAddr>,
    /// Suffixes requested with `dhcp-option DOMAIN` / `DOMAIN-SEARCH`.
    pub dns_search_domains: Vec<String>,
    /// The raw config text — `openvpn` consumes the on-disk file, so this is
    /// retained for introspection only.
    pub raw: String,
}

impl ParsedProfile for OvpnParsedProfile {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn dns_request(&self) -> crate::vortix_core::ports::dns::DnsRequest {
        crate::vortix_core::ports::dns::DnsRequest {
            servers: self.dns_servers.clone(),
            search_domains: self.dns_search_domains.clone(),
        }
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

        reject_privileged_directive(line)?;

        let Some(tokens) = effective_option_tokens(line, 128) else {
            continue;
        };
        let Some((directive, arguments)) = tokens.split_first() else {
            continue;
        };
        let directive = directive.trim_start_matches('-').to_ascii_lowercase();
        let mut tokens = arguments.iter().map(String::as_str);

        match directive.as_str() {
            "auth-user-pass" => {
                profile.interactive_auth = tokens.next().is_none();
                profile.boot_credentials = BootCredentialRequirement::Interactive;
            }
            "askpass" | "management-query-passwords" => {
                profile.boot_credentials = BootCredentialRequirement::Interactive;
            }
            "pkcs11-id" | "pkcs11-id-management" | "cryptoapicert" | "pkcs12" => {
                profile.boot_credentials = BootCredentialRequirement::UnsupportedKeyProvider;
            }
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
            "dhcp-option" => match tokens.next() {
                Some(kind) if kind.eq_ignore_ascii_case("DNS") => {
                    if let Some(server) = tokens.next().and_then(|value| value.parse().ok()) {
                        profile.dns_servers.push(server);
                    }
                }
                Some(kind)
                    if kind.eq_ignore_ascii_case("DOMAIN")
                        || kind.eq_ignore_ascii_case("DOMAIN-SEARCH") =>
                {
                    profile
                        .dns_search_domains
                        .extend(tokens.map(str::to_string));
                }
                _ => {}
            },
            "static-challenge" => {
                profile.boot_credentials = BootCredentialRequirement::Interactive;
                if let Some(sc) = parse_static_challenge_tokens(&mut tokens) {
                    profile.static_challenge = Some(sc);
                } else {
                    warn!(line = %line, "ovpn: malformed static-challenge directive — skipping");
                }
            }
            "key" => {
                if !tokens
                    .next()
                    .is_some_and(|path| path.eq_ignore_ascii_case("[inline]"))
                {
                    // File-backed or malformed key material may require a
                    // prompt. Boot fails closed until the enrolled service
                    // can attest and inspect that file.
                    profile.boot_credentials = BootCredentialRequirement::UnsupportedKeyProvider;
                }
            }
            _ => {}
        }
    }

    if profile.boot_credentials != BootCredentialRequirement::UnsupportedKeyProvider
        && (text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
            || text.contains("Proc-Type: 4,ENCRYPTED"))
    {
        profile.boot_credentials = BootCredentialRequirement::Interactive;
    }

    Ok(profile)
}

fn is_forbidden_privileged_directive(directive: &str) -> bool {
    const FORBIDDEN: &[&str] = &[
        "daemon",
        "config",
        "include",
        "plugin",
        "up",
        "down",
        "route-up",
        "route-pre-down",
        "ipchange",
        "client-connect",
        "client-connect-deferred",
        "client-disconnect",
        "learn-address",
        "tls-verify",
        "tls-crypt-v2-verify",
        "auth-user-pass-verify",
        "iproute",
        "engine",
        "providers",
        "pkcs11-providers",
    ];
    FORBIDDEN
        .iter()
        .any(|forbidden| directive.eq_ignore_ascii_case(forbidden))
}

/// Return the privileged directive that `OpenVPN` would effectively parse.
///
/// `OpenVPN` dequotes option tokens before dispatch and treats `setenv opt X`
/// as though `X` were the directive. Inspecting only the first whitespace
/// token therefore leaves privileged aliases such as `"up"` and
/// `setenv opt plugin` unchecked.
pub(super) fn forbidden_effective_directive(line: &str) -> Option<String> {
    let tokens = effective_option_tokens(line, 3)?;
    let directive = tokens.first()?.trim_start_matches('-');
    is_forbidden_privileged_directive(directive).then(|| directive.to_ascii_lowercase())
}

/// Return the option tokens `OpenVPN` dispatches after dequoting aliases.
fn effective_option_tokens(line: &str, limit: usize) -> Option<Vec<String>> {
    let mut tokens = openvpn_option_tokens(line, limit.saturating_add(2))?;
    if tokens.len() >= 2
        && tokens[0]
            .trim_start_matches('-')
            .eq_ignore_ascii_case("setenv")
        && tokens[1].eq_ignore_ascii_case("opt")
    {
        tokens.drain(..2);
    }
    tokens.truncate(limit);
    Some(tokens)
}

/// Tokenize the security-relevant prefix using `OpenVPN`'s config-file quoting
/// rules. `None` means `OpenVPN` would reject the malformed line itself.
fn openvpn_option_tokens(line: &str, limit: usize) -> Option<Vec<String>> {
    let mut chars = line.chars().peekable();
    let mut tokens = Vec::with_capacity(limit.min(8));

    while tokens.len() < limit {
        while chars.next_if(|ch| ch.is_whitespace()).is_some() {}
        if chars.peek().is_none_or(|ch| matches!(ch, '#' | ';')) {
            break;
        }

        let quote = chars.next_if(|ch| matches!(ch, '\'' | '"'));
        let mut token = String::new();
        let mut closed = quote.is_none();
        while let Some(ch) = chars.next() {
            if quote == Some('\'') {
                if ch == '\'' {
                    closed = true;
                    break;
                }
                token.push(ch);
            } else if ch == '"' && quote == Some('"') {
                closed = true;
                break;
            } else if ch == '\\' {
                token.push(chars.next()?);
            } else if quote.is_none() && ch.is_whitespace() {
                break;
            } else {
                token.push(ch);
            }
        }
        if !closed {
            return None;
        }
        tokens.push(token);
    }

    Some(tokens)
}

fn reject_privileged_directive(line: &str) -> Result<(), ParseError> {
    if let Some(directive) = forbidden_effective_directive(line) {
        return Err(ParseError::Unsupported(format!(
            "OpenVPN `{directive}` privileged directive is not allowed: Vortix never runs profile commands as root or loads profile-selected crypto providers; migrate lifecycle automation to a global hook using an absolute executable plus argv"
        )));
    }
    Ok(())
}

fn parse_static_challenge_tokens<'a, I>(tokens: &mut I) -> Option<StaticChallenge>
where
    I: Iterator<Item = &'a str>,
{
    let prompt = tokens.next()?.to_string();
    if prompt.is_empty() {
        return None;
    }
    let echo = matches!(tokens.next(), Some("1"));
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
    fn executable_directives_fail_unprivileged_parsing_with_migration_guidance() {
        for directive in ["up ./up.sh", "--route-up ./route.sh", "plugin evil.so"] {
            let error = parse_ovpn_conf(&format!("client\n{directive}\n"))
                .unwrap_err()
                .to_string();
            assert!(error.contains("never runs profile commands as root"));
            assert!(error.contains("global hook"));
        }
    }

    #[test]
    fn external_crypto_provider_directives_fail_unprivileged_parsing() {
        for directive in [
            "providers legacy default",
            "--EnGiNe pkcs11",
            "pkcs11-providers /tmp/evil.so",
        ] {
            let error = parse_ovpn_conf(&format!("client\n{directive}\n"))
                .expect_err("provider-loading directives must not reach privileged OpenVPN")
                .to_string();
            assert!(
                error.contains("not allowed"),
                "unexpected error for {directive}: {error}"
            );
        }
    }

    #[test]
    fn effective_privileged_aliases_fail_unprivileged_parsing() {
        for directive in [
            "setenv opt plugin malicious.so",
            "--setenv opt up ./up.sh",
            "SeTeNv OpT providers legacy default",
            "setenv opt --config nested.ovpn",
            "\"up\" ./up.sh",
        ] {
            let error = parse_ovpn_conf(&format!("client\n{directive}\n"))
                .expect_err("effective privileged aliases must be rejected")
                .to_string();
            assert!(error.contains("not allowed"), "unexpected error: {error}");
        }

        parse_ovpn_conf("client\nsetenv opt block-outside-dns\n")
            .expect("safe forward-compatibility directives must remain supported");
    }

    #[test]
    fn detects_interactive_auth() {
        let text = "client\nproto udp\nauth-user-pass\nremote example.com 1194\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert!(p.interactive_auth);
    }

    #[test]
    fn parses_dns_intent_without_applying_it() {
        let p = parse_ovpn_conf(
            "dhcp-option DNS 10.8.0.1\ndhcp-option DOMAIN corp.example\ndhcp-option DOMAIN-SEARCH dev.example lab.example\n",
        )
        .unwrap();
        assert_eq!(
            p.dns_servers,
            vec!["10.8.0.1".parse::<std::net::IpAddr>().unwrap()]
        );
        assert_eq!(
            p.dns_search_domains,
            vec!["corp.example", "dev.example", "lab.example"]
        );
    }

    #[test]
    fn ignores_auth_with_file() {
        let text = "client\nauth-user-pass /etc/openvpn/creds.txt\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert!(!p.interactive_auth);
        assert_eq!(p.boot_credentials, BootCredentialRequirement::Interactive);
    }

    #[test]
    fn boot_credentials_reject_prompts_and_unsupported_key_providers() {
        for text in [
            "client\naskpass\n",
            "client\nmanagement-query-passwords\n",
            "client\n<key>\n-----BEGIN ENCRYPTED PRIVATE KEY-----\n</key>\n",
            "client\n<key>\nProc-Type: 4,ENCRYPTED\n</key>\n",
        ] {
            assert_eq!(
                parse_ovpn_conf(text).unwrap().boot_credentials,
                BootCredentialRequirement::Interactive,
                "{text}"
            );
        }
        assert_eq!(
            parse_ovpn_conf("client\npkcs11-id token\n")
                .unwrap()
                .boot_credentials,
            BootCredentialRequirement::UnsupportedKeyProvider
        );
    }

    #[test]
    fn boot_credentials_reject_effective_alias_forms() {
        for text in [
            "client\n\"auth-user-pass\" credentials.txt\n",
            "client\n--AsKpAsS secret.txt\n",
            "client\nsetenv opt management-query-passwords\n",
            "client\nsetenv opt static-challenge \"OTP code\" 1\n",
            "client\nsetenv opt cryptoapicert THUMB:abc\n",
        ] {
            assert_ne!(
                parse_ovpn_conf(text).unwrap().boot_credentials,
                BootCredentialRequirement::NonInteractive,
                "{text}"
            );
        }
    }

    #[test]
    fn boot_credentials_fail_closed_for_external_key_material() {
        for text in [
            "client\nkey client.key\n",
            "client\nkey\n",
            "client\npkcs12 client.p12\n",
            "client\nsetenv opt key encrypted.key\n",
        ] {
            assert_eq!(
                parse_ovpn_conf(text).unwrap().boot_credentials,
                BootCredentialRequirement::UnsupportedKeyProvider,
                "{text}"
            );
        }
        assert_eq!(
            parse_ovpn_conf("client\nkey [inline]\n<key>\n-----BEGIN PRIVATE KEY-----\n</key>\n")
                .unwrap()
                .boot_credentials,
            BootCredentialRequirement::NonInteractive
        );
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
