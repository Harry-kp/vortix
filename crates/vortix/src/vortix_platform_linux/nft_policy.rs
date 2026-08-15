//! Pure rendering and exact read-back for the Vortix-owned nft table.

use std::fmt::Write as _;
use std::net::IpAddr;

use super::POLICY_COMMENT_PREFIX;
use crate::vortix_core::cidr::{rfc1918_ranges, Cidr};
use crate::vortix_core::cidr_subtract::cidr_subtract;
use crate::vortix_core::ports::killswitch::ActiveTunnelInfo;

pub(super) const MISSING_ERROR: &str = "No such file or directory";

#[derive(Clone, Copy)]
pub(super) enum BatchMode {
    Create,
    Replace,
}

#[derive(Debug, PartialEq, Eq)]
enum AcceptRule {
    OutputInterface(String),
    Destination(Cidr),
    Dhcp,
}

pub(super) struct ExpectedPolicy {
    ruleset: String,
    accept_rules: Vec<AcceptRule>,
    digest: String,
}

impl ExpectedPolicy {
    pub(super) fn new(active: &[ActiveTunnelInfo], mode: BatchMode) -> Self {
        let digest = crate::core::killswitch::policy_digest(active);
        let ruleset = render(active, mode, &digest);
        let accept_rules = parse_accept_rules(&ruleset)
            .expect("the package-owned nft renderer emits canonical accept rules");
        Self {
            ruleset,
            accept_rules,
            digest,
        }
    }

    pub(super) fn matches(&self, observed: &ObservedPolicy) -> bool {
        observed.accept_rules.as_ref() == Some(&self.accept_rules)
            && observed.policy_drop
            && observed.terminal_digest.as_deref() == Some(self.digest.as_str())
    }
}

pub(super) struct ObservedPolicy {
    accept_rules: Option<Vec<AcceptRule>>,
    policy_drop: bool,
    terminal_digest: Option<String>,
}

impl ObservedPolicy {
    pub(super) fn parse(snapshot: &str) -> Self {
        let terminal_lines: Vec<&str> = snapshot
            .lines()
            .map(str::trim)
            .filter(|line| line.contains(POLICY_COMMENT_PREFIX))
            .collect();
        let terminal_digest = (terminal_lines.len() == 1 && terminal_lines[0].contains(" drop "))
            .then(|| {
                terminal_lines[0]
                    .split_once(POLICY_COMMENT_PREFIX)
                    .and_then(|(_, suffix)| suffix.split('"').next())
                    .map(str::to_string)
            })
            .flatten();
        Self {
            accept_rules: parse_accept_rules(snapshot),
            policy_drop: snapshot.contains("policy drop"),
            terminal_digest,
        }
    }
}

pub(super) fn ruleset(active: &[ActiveTunnelInfo], mode: BatchMode) -> String {
    ExpectedPolicy::new(active, mode).ruleset
}

pub(super) fn snapshot_matches(active: &[ActiveTunnelInfo], snapshot: &str) -> bool {
    ExpectedPolicy::new(active, BatchMode::Create).matches(&ObservedPolicy::parse(snapshot))
}

fn render(active: &[ActiveTunnelInfo], mode: BatchMode, digest: &str) -> String {
    let secondary_cidrs: Vec<Cidr> = active
        .iter()
        .filter(|tunnel| !tunnel.is_primary)
        .flat_map(|tunnel| tunnel.declared_cidrs.iter().copied())
        .collect();
    let local_ranges = cidr_subtract(&rfc1918_ranges(), &secondary_cidrs);

    let mut ruleset = String::new();
    if matches!(mode, BatchMode::Replace) {
        writeln!(
            ruleset,
            "delete table inet {}",
            crate::constants::NFT_TABLE_NAME
        )
        .unwrap();
    }
    write!(
        ruleset,
        r#"table inet {} {{
  chain output {{
    type filter hook output priority 0; policy drop;

    oifname "lo" accept
"#,
        crate::constants::NFT_TABLE_NAME,
    )
    .unwrap();
    for range in local_ranges {
        writeln!(ruleset, "    ip daddr {range} accept").unwrap();
    }
    writeln!(ruleset, "    udp sport 68 udp dport 67 accept").unwrap();
    for tunnel in active {
        if !tunnel.is_endpoint_allowlist() {
            writeln!(ruleset, "    oifname \"{}\" accept", tunnel.interface).unwrap();
        }
        for endpoint in &tunnel.server_ips {
            match endpoint {
                IpAddr::V4(ip) => writeln!(ruleset, "    ip daddr {ip} accept").unwrap(),
                IpAddr::V6(ip) => writeln!(ruleset, "    ip6 daddr {ip} accept").unwrap(),
            }
        }
    }
    writeln!(
        ruleset,
        "    counter drop comment \"{POLICY_COMMENT_PREFIX}{digest}\""
    )
    .unwrap();
    ruleset.push_str("  }\n}\n");
    ruleset
}

fn host_cidr(address: IpAddr) -> Cidr {
    let prefix_len = if address.is_ipv4() { 32 } else { 128 };
    Cidr::new(address, prefix_len).expect("a host prefix is valid for its address family")
}

fn parse_accept_rule(line: &str) -> Option<AcceptRule> {
    if line == "udp sport 68 udp dport 67 accept" {
        return Some(AcceptRule::Dhcp);
    }
    if let Some(interface) = line
        .strip_prefix("oifname \"")
        .and_then(|rest| rest.strip_suffix("\" accept"))
    {
        if interface.is_empty() || interface.contains('"') {
            return None;
        }
        return Some(AcceptRule::OutputInterface(interface.to_string()));
    }

    for (prefix, expect_v4) in [("ip daddr ", true), ("ip6 daddr ", false)] {
        let Some(address) = line
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix(" accept"))
        else {
            continue;
        };
        let destination = address
            .parse::<Cidr>()
            .ok()
            .or_else(|| address.parse::<IpAddr>().ok().map(host_cidr))?;
        if destination.is_v4() != expect_v4 {
            return None;
        }
        return Some(AcceptRule::Destination(destination));
    }
    None
}

fn has_unquoted_accept_verdict(line: &str) -> bool {
    const ACCEPT: &[u8] = b"accept";
    let bytes = line.as_bytes();
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        if byte == b'"' {
            quoted = true;
            continue;
        }
        let end = index + ACCEPT.len();
        if end <= bytes.len()
            && &bytes[index..end] == ACCEPT
            && (index == 0 || bytes[index - 1].is_ascii_whitespace())
            && (end == bytes.len() || bytes[end].is_ascii_whitespace())
        {
            return true;
        }
    }
    false
}

fn parse_accept_rules(ruleset: &str) -> Option<Vec<AcceptRule>> {
    ruleset
        .lines()
        .map(str::trim)
        .filter(|line| has_unquoted_accept_verdict(line))
        .map(parse_accept_rule)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_comment_does_not_create_an_accept_rule() {
        assert_eq!(
            parse_accept_rules("counter drop comment \"accept\""),
            Some(vec![])
        );
    }

    #[test]
    fn bare_and_host_prefix_destinations_are_equivalent() {
        assert_eq!(
            parse_accept_rule("ip daddr 10.0.0.1/32 accept"),
            parse_accept_rule("ip daddr 10.0.0.1 accept")
        );
        assert_eq!(
            parse_accept_rule("ip6 daddr 2001:db8::1/128 accept"),
            parse_accept_rule("ip6 daddr 2001:db8::1 accept")
        );
    }
}
