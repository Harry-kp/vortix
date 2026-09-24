//! Linux kill switch: one nftables `inet` table, replaced in a single
//! transaction so IPv4 and IPv6 change together. iptables code remains only
//! to clean up rules older releases installed.
//!
//! The output chain drops by default and accepts: loopback; the RFC1918
//! ranges minus every secondary tunnel's routes (a primary's `0.0.0.0/0` is
//! never subtracted, its interface rule covers it); DHCP; and per tunnel its
//! interface plus each server address, so it can reconnect after a drop.

use std::time::Duration;

use crate::control::killswitch::{ActiveTunnelInfo, KillswitchError, Result};
use crate::process::{CommandOutcome, CommandSpec, PrivilegeReq, ProcessError};
use tracing::{debug, error, info};

const CHAIN_NAME: &str = "VORTIX_KILLSWITCH";
const FIREWALL_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const FIREWALL_OUTPUT_LIMIT: usize = 1024 * 1024;
use super::POLICY_COMMENT_PREFIX;
use nft_policy::BatchMode;

/// Linux nftables firewall implementation with legacy iptables cleanup.
pub struct NftFirewall;

impl NftFirewall {
    fn nft_command(args: Vec<String>) -> CommandSpec {
        let mut command = Self::firewall_command("nft", args);
        command.env.insert("LC_ALL".to_string(), "C".to_string());
        command
    }

    fn firewall_command(program: &str, args: Vec<String>) -> CommandSpec {
        CommandSpec::oneshot(program, args)
            .timeout(FIREWALL_COMMAND_TIMEOUT)
            .output_limit(FIREWALL_OUTPUT_LIMIT)
            .contain_process_group()
    }

    fn backend_error(context: &str, error: &ProcessError) -> KillswitchError {
        if matches!(error, ProcessError::ProgramNotFound { .. }) {
            KillswitchError::NoBackendAvailable
        } else {
            KillswitchError::CommandFailed(format!("{context}: {error}"))
        }
    }

    // ─── iptables backend ───────────────────────────────────────────────

    /// Invoke `iptables-restore` with the given ruleset on stdin. The
    /// kernel performs an atomic ruleset replace — if the parse fails,
    /// the prior ruleset stays in force, no leak window.
    fn iptables_restore_stdin(program: &str, ruleset: &[u8]) -> std::result::Result<(), String> {
        let output = crate::process::run(
            Self::firewall_command(program, vec!["--noflush".into()])
                .privilege(PrivilegeReq::Root)
                .stdin(ruleset.to_vec()),
        )
        .map_err(|e| format!("Failed to spawn {program}: {e}"))?;

        if output.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    fn iptables_command(program: &str, args: &[&str]) -> std::result::Result<bool, String> {
        let args = args.iter().map(|arg| (*arg).to_string()).collect();
        let output = crate::process::run(
            Self::firewall_command(program, args).privilege(PrivilegeReq::Root),
        )
        .map_err(|e| format!("Failed to run {program}: {e}"))?;
        Ok(output.success())
    }

    fn iptables_snapshot(program: &str) -> std::result::Result<String, String> {
        let output = crate::process::run(
            Self::firewall_command(program, vec!["-t".into(), "filter".into()])
                .privilege(PrivilegeReq::Root),
        )
        .map_err(|e| format!("Failed to run {program}: {e}"))?;
        if !output.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned());
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn optional_iptables_listing(program: &str) -> Result<Option<String>> {
        let output = match crate::process::run(
            Self::firewall_command(program, vec!["-S".into()]).privilege(PrivilegeReq::Root),
        ) {
            Ok(output) => output,
            Err(ProcessError::ProgramNotFound { .. }) => return Ok(None),
            Err(error) => {
                return Err(KillswitchError::CommandFailed(format!(
                    "Failed to inspect {program}: {error}"
                )))
            }
        };
        if !output.success() {
            return Err(KillswitchError::CommandFailed(format!(
                "{program} inspection failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()))
    }

    fn is_legacy_global_policy(snapshot: &str, ipv6: bool) -> bool {
        if !snapshot.contains(":OUTPUT DROP ") || snapshot.contains(CHAIN_NAME) {
            return false;
        }
        let rules: Vec<&str> = snapshot
            .lines()
            .filter(|line| line.starts_with("-A "))
            .collect();
        if rules.is_empty()
            || rules
                .iter()
                .any(|line| !line.starts_with("-A OUTPUT ") || !line.ends_with("-j ACCEPT"))
            || !rules.iter().any(|line| line.contains(" -o lo "))
        {
            return false;
        }
        if ipv6 {
            rules
                .iter()
                .any(|line| line.contains(" -o ") && !line.contains(" -o lo "))
                && rules.iter().any(|line| line.contains(" -d "))
        } else {
            rules
                .iter()
                .any(|line| line.contains("--sport 68") && line.contains("--dport 67"))
        }
    }

    fn legacy_cleanup_ruleset() -> &'static str {
        "*filter\n:OUTPUT ACCEPT [0:0]\n-F OUTPUT\nCOMMIT\n"
    }

    /// Tear down iptables state. Restore the default-ACCEPT OUTPUT policy
    /// via a minimal `iptables-restore` ruleset, and remove any legacy
    /// `VORTIX_KILLSWITCH` chain the legacy implementation may have left
    /// behind.
    fn teardown_iptables() -> Result<bool> {
        let mut family_available = [false; 2];
        for (command, save, restore, ipv6) in [
            ("iptables", "iptables-save", "iptables-restore", false),
            ("ip6tables", "ip6tables-save", "ip6tables-restore", true),
        ] {
            let Some(initial) = Self::optional_iptables_listing(command)? else {
                continue;
            };
            family_available[usize::from(ipv6)] = true;
            let possible_legacy_global =
                initial.lines().any(|line| line.trim() == "-P OUTPUT DROP");
            while Self::iptables_command(command, &["-C", "OUTPUT", "-j", CHAIN_NAME])
                .map_err(KillswitchError::CommandFailed)?
            {
                if !Self::iptables_command(command, &["-D", "OUTPUT", "-j", CHAIN_NAME])
                    .map_err(KillswitchError::CommandFailed)?
                {
                    return Err(KillswitchError::CommandFailed(format!(
                        "{command} could not remove the Vortix OUTPUT jump"
                    )));
                }
            }
            let _ = Self::iptables_command(command, &["-F", CHAIN_NAME]);
            let _ = Self::iptables_command(command, &["-X", CHAIN_NAME]);
            if !possible_legacy_global {
                let listing = Self::optional_iptables_listing(command)?.ok_or_else(|| {
                    KillswitchError::CommandFailed(format!(
                        "{command} disappeared during legacy cleanup"
                    ))
                })?;
                if listing.contains(CHAIN_NAME) {
                    return Err(KillswitchError::CommandFailed(format!(
                        "{command} read-back still contains Vortix rules"
                    )));
                }
                continue;
            }

            let mut snapshot = Self::iptables_snapshot(save).map_err(|error| {
                KillswitchError::CommandFailed(format!(
                    "{save} is required to classify a legacy OUTPUT DROP policy: {error}"
                ))
            })?;
            if Self::is_legacy_global_policy(&snapshot, ipv6) {
                // v0.4.3 and earlier owned the global OUTPUT policy. Only
                // reset it after the strict legacy-shape check proves every
                // remaining OUTPUT rule belongs to that displaced design.
                // The policy change and flush share one restore transaction.
                Self::iptables_restore_stdin(restore, Self::legacy_cleanup_ruleset().as_bytes())
                    .map_err(KillswitchError::CommandFailed)?;
                snapshot = Self::iptables_snapshot(save).map_err(KillswitchError::CommandFailed)?;
                if !snapshot.contains(":OUTPUT ACCEPT ")
                    || snapshot.lines().any(|line| line.starts_with("-A OUTPUT "))
                {
                    return Err(KillswitchError::CommandFailed(format!(
                        "{save} did not fully remove the legacy Vortix OUTPUT policy"
                    )));
                }
            } else if snapshot.contains(":OUTPUT DROP ") {
                return Err(KillswitchError::CommandFailed(format!(
                    "{save} shows an unrecognized host-owned OUTPUT DROP policy; refusing to claim release"
                )));
            }
            if snapshot.contains(CHAIN_NAME) {
                return Err(KillswitchError::CommandFailed(format!(
                    "{save} read-back still contains Vortix rules"
                )));
            }
        }
        if family_available[0] != family_available[1] {
            return Err(KillswitchError::CommandFailed(
                "only one legacy iptables address family is inspectable; refusing to claim complete release"
                    .into(),
            ));
        }
        Ok(family_available[0])
    }

    fn verify_iptables_disabled() -> Result<bool> {
        let mut family_available = [false; 2];
        for (command, save, ipv6) in [
            ("iptables", "iptables-save", false),
            ("ip6tables", "ip6tables-save", true),
        ] {
            let Some(listing) = Self::optional_iptables_listing(command)? else {
                continue;
            };
            family_available[usize::from(ipv6)] = true;
            if listing.contains(CHAIN_NAME) {
                return Err(KillswitchError::CommandFailed(format!(
                    "{command} still contains Vortix-owned rules"
                )));
            }
            if listing.lines().any(|line| line.trim() == "-P OUTPUT DROP") {
                let snapshot = Self::iptables_snapshot(save).map_err(|error| {
                    KillswitchError::CommandFailed(format!(
                        "{save} is required to classify an OUTPUT DROP policy: {error}"
                    ))
                })?;
                if Self::is_legacy_global_policy(&snapshot, ipv6) {
                    return Err(KillswitchError::CommandFailed(format!(
                        "{save} still contains a legacy Vortix policy"
                    )));
                }
                return Err(KillswitchError::CommandFailed(format!(
                    "{save} shows an unrecognized host-owned OUTPUT DROP policy; refusing to claim release"
                )));
            }
        }
        if family_available[0] != family_available[1] {
            return Err(KillswitchError::CommandFailed(
                "only one legacy iptables address family is inspectable; Vortix-owned absence is unverified"
                    .into(),
            ));
        }
        Ok(family_available[0])
    }

    // ─── nftables backend ───────────────────────────────────────────────

    fn nft_table_snapshot() -> Result<Option<String>> {
        let output = crate::process::run(
            Self::nft_command(vec![
                "-n".into(),
                "list".into(),
                "table".into(),
                "inet".into(),
                crate::constants::NFT_TABLE_NAME.into(),
            ])
            .privilege(PrivilegeReq::Root),
        )
        .map_err(|error| Self::backend_error("nft read-back", &error))?;
        if output.success() {
            return Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()));
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains(nft_policy::MISSING_ERROR) {
            Ok(None)
        } else {
            Err(KillswitchError::CommandFailed(format!(
                "nft read-back failed ambiguously: {stderr}"
            )))
        }
    }

    fn apply_nft_batch(active: &[ActiveTunnelInfo], mode: BatchMode) -> Result<CommandOutcome> {
        let ruleset = nft_policy::ruleset(active, mode);
        crate::process::run(
            Self::nft_command(vec!["-f".into(), "-".into()])
                .privilege(PrivilegeReq::Root)
                .stdin(ruleset.into_bytes()),
        )
        .map_err(|error| Self::backend_error("nft spawn", &error))
    }

    fn setup_nftables(active: &[ActiveTunnelInfo]) -> Result<()> {
        let mut output = Self::apply_nft_batch(active, BatchMode::Replace)?;
        let mut verified_snapshot = None;
        if !output.success()
            && String::from_utf8_lossy(&output.stderr).contains(nft_policy::MISSING_ERROR)
        {
            output = Self::apply_nft_batch(active, BatchMode::Create)?;
            if !output.success() {
                match Self::nft_table_snapshot()? {
                    Some(snapshot) if nft_policy::snapshot_matches(active, &snapshot) => {
                        verified_snapshot = Some(snapshot);
                    }
                    Some(_) => {
                        output = Self::apply_nft_batch(active, BatchMode::Replace)?;
                    }
                    None => {}
                }
            }
        }

        if verified_snapshot.is_none() && !output.success() {
            return Err(KillswitchError::CommandFailed(format!(
                "nft failed to replace owned table: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let snapshot = match verified_snapshot {
            Some(snapshot) => snapshot,
            None => Self::nft_table_snapshot()?.ok_or_else(|| {
                KillswitchError::CommandFailed(
                    "nft read-back did not find the requested policy".to_string(),
                )
            })?,
        };
        if !nft_policy::snapshot_matches(active, &snapshot) {
            return Err(KillswitchError::CommandFailed(
                "nft read-back did not match the requested policy".to_string(),
            ));
        }

        Ok(())
    }

    /// Remove the kill switch nftables table.
    fn teardown_nftables() -> Result<()> {
        let delete = crate::process::run(
            Self::nft_command(vec![
                "delete".into(),
                "table".into(),
                "inet".into(),
                crate::constants::NFT_TABLE_NAME.into(),
            ])
            .privilege(PrivilegeReq::Root),
        )
        .map_err(|error| Self::backend_error("nft delete", &error))?;
        let delete_error = String::from_utf8_lossy(&delete.stderr);
        if !delete.success() && !delete_error.contains(nft_policy::MISSING_ERROR) {
            return Err(KillswitchError::CommandFailed(format!(
                "nft delete failed: {delete_error}"
            )));
        }
        if Self::nft_table_snapshot()?.is_some() {
            return Err(KillswitchError::CommandFailed(
                "nft read-back still contains the Vortix table".to_string(),
            ));
        }
        Ok(())
    }
}

impl NftFirewall {
    /// Engage the killswitch with one nftables `inet` transaction covering
    /// every tunnel in `active`. Both fresh enable and refresh with a changed
    /// active set go through this atomic dual-family path.
    ///
    /// Empty `active` slice installs the base block-all ruleset (rules
    /// 1-4 only) — used during early bring-up and on hard-fail Armed
    /// states.
    pub fn enable_blocking_multi(active: &[ActiveTunnelInfo]) -> Result<()> {
        if !crate::platform::is_root() {
            error!(target: "vortix::killswitch", "kill switch requires root privileges");
            return Err(KillswitchError::NotRoot);
        }

        crate::control::killswitch::validate_policy(active)?;

        info!(
            target: "vortix::killswitch",
            tunnels = active.len(),
            "killswitch.engage"
        );

        debug!(target: "vortix::killswitch", "using nftables backend");
        Self::setup_nftables(active)?;

        info!(
            target: "vortix::killswitch",
            tunnels = active.len(),
            "kill switch ACTIVE — blocking non-VPN traffic"
        );
        Ok(())
    }

    pub fn disable_blocking() -> Result<()> {
        info!(target: "vortix::killswitch", "disabling kill switch");

        if !crate::platform::is_root() {
            error!(target: "vortix::killswitch", "disabling kill switch requires root");
            return Err(KillswitchError::NotRoot);
        }

        let iptables_result = Self::teardown_iptables();
        let nft_result = Self::teardown_nftables();
        let nft_available = match nft_result {
            Ok(()) => true,
            Err(KillswitchError::NoBackendAvailable) => false,
            Err(nft_error) => {
                return match iptables_result {
                    Ok(_) => Err(nft_error),
                    Err(iptables_error) => Err(KillswitchError::CommandFailed(format!(
                        "legacy cleanup failed ({iptables_error}); nft cleanup failed ({nft_error})"
                    ))),
                };
            }
        };
        let iptables_available = iptables_result?;
        if !iptables_available && !nft_available {
            return Err(KillswitchError::NoBackendAvailable);
        }

        info!(target: "vortix::killswitch", "kill switch DISABLED — normal traffic restored");
        Ok(())
    }

    pub fn verify_blocking(active: &[ActiveTunnelInfo]) -> Result<()> {
        crate::control::killswitch::validate_policy(active)?;
        match Self::nft_table_snapshot()? {
            Some(snapshot) if nft_policy::snapshot_matches(active, &snapshot) => Ok(()),
            Some(_) | None => Err(KillswitchError::CommandFailed(
                "nft read-back did not match the requested Vortix policy".into(),
            )),
        }
    }

    pub fn verify_disabled() -> Result<()> {
        let iptables_result = Self::verify_iptables_disabled();
        let nft_result = Self::nft_table_snapshot();
        let nft_available = match nft_result {
            Ok(Some(_)) => {
                let nft_error = KillswitchError::CommandFailed(
                    "nft still contains the Vortix-owned table".into(),
                );
                return match iptables_result {
                    Ok(_) => Err(nft_error),
                    Err(iptables_error) => Err(KillswitchError::CommandFailed(format!(
                        "legacy verification failed ({iptables_error}); nft verification failed ({nft_error})"
                    ))),
                };
            }
            Ok(None) => true,
            Err(KillswitchError::NoBackendAvailable) => false,
            Err(nft_error) => {
                return match iptables_result {
                    Ok(_) => Err(nft_error),
                    Err(iptables_error) => Err(KillswitchError::CommandFailed(format!(
                        "legacy verification failed ({iptables_error}); nft verification failed ({nft_error})"
                    ))),
                };
            }
        };
        let iptables_available = iptables_result?;
        if !iptables_available && !nft_available {
            return Err(KillswitchError::NoBackendAvailable);
        }
        Ok(())
    }
}

mod nft_policy {
    //! Pure rendering and exact read-back for the Vortix-owned nft table.

    use std::fmt::Write as _;
    use std::net::IpAddr;

    use super::POLICY_COMMENT_PREFIX;
    use crate::cidr::cidr_subtract;
    use crate::cidr::{rfc1918_ranges, Cidr};
    use crate::control::killswitch::ActiveTunnelInfo;

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
            let digest = crate::control::killswitch::policy_digest(active);
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
            let terminal_digest = (terminal_lines.len() == 1
                && terminal_lines[0].contains(" drop "))
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cidr::Cidr;
    use std::net::IpAddr;

    fn cidr(s: &str) -> Cidr {
        s.parse().expect("valid cidr in test")
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("valid ip in test")
    }

    /// Convenience: build an `ActiveTunnelInfo`.
    fn tunnel(
        interface: &str,
        server_ips: &[&str],
        declared: &[&str],
        is_primary: bool,
    ) -> ActiveTunnelInfo {
        ActiveTunnelInfo {
            interface: interface.to_string(),
            server_ips: server_ips.iter().map(|s| ip(s)).collect(),
            declared_cidrs: declared.iter().map(|s| cidr(s)).collect(),
            is_primary,
        }
    }

    fn nft(active: &[ActiveTunnelInfo]) -> String {
        nft_policy::ruleset(active, BatchMode::Create)
    }

    #[test]
    fn empty_active_set_blocks_all_but_loopback_lan_and_dhcp() {
        let rules = nft(&[]);
        assert!(rules.contains("policy drop;"));
        assert!(rules.contains("oifname \"lo\" accept"));
        assert!(rules.contains("ip daddr 10.0.0.0/8 accept"));
        assert!(rules.contains("ip daddr 172.16.0.0/12 accept"));
        assert!(rules.contains("ip daddr 192.168.0.0/16 accept"));
        assert!(rules.contains("udp sport 68 udp dport 67 accept"));
        assert!(!rules.contains("oifname \"wg"));
    }

    #[test]
    fn a_full_primary_does_not_carve_the_lan() {
        // Subtracting the primary's 0/0 would remove the whole LAN allowance;
        // its interface allow already covers its egress.
        let rules = nft(&[tunnel("wg0", &["1.2.3.4"], &["0.0.0.0/0"], true)]);
        assert!(rules.contains("ip daddr 10.0.0.0/8 accept"));
        assert!(rules.contains("ip daddr 172.16.0.0/12 accept"));
        assert!(rules.contains("ip daddr 192.168.0.0/16 accept"));
        assert!(rules.contains("oifname \"wg0\" accept"));
        assert!(rules.contains("ip daddr 1.2.3.4 accept"));
    }

    #[test]
    fn secondary_routes_are_carved_from_the_lan_allowance() {
        let one = nft(&[tunnel("wg1", &["5.6.7.8"], &["10.0.0.0/8"], false)]);
        assert!(!one.contains("ip daddr 10.0.0.0/8 accept"));
        assert!(one.contains("ip daddr 172.16.0.0/12 accept"));
        assert!(one.contains("ip daddr 192.168.0.0/16 accept"));

        let two = nft(&[
            tunnel("wg1", &["1.1.1.1"], &["10.0.0.0/8"], false),
            tunnel("wg2", &["2.2.2.2"], &["192.168.0.0/16"], false),
        ]);
        assert!(!two.contains("ip daddr 10.0.0.0/8 accept"));
        assert!(two.contains("ip daddr 172.16.0.0/12 accept"));
        assert!(!two.contains("ip daddr 192.168.0.0/16 accept"));
        assert!(two.contains("oifname \"wg1\" accept"));
        assert!(two.contains("oifname \"wg2\" accept"));

        let overlapping = nft(&[
            tunnel("wg3", &["1.1.1.1"], &["10.0.0.0/8"], false),
            tunnel("wg4", &["2.2.2.2"], &["10.5.0.0/16"], false),
        ]);
        assert!(!overlapping.contains("ip daddr 10."));

        let mixed = nft(&[
            tunnel("wg0", &["9.9.9.9"], &["0.0.0.0/0"], true),
            tunnel("wg1", &["8.8.8.8"], &["10.0.0.0/8"], false),
        ]);
        assert!(!mixed.contains("ip daddr 10.0.0.0/8 accept"));
        assert!(mixed.contains("ip daddr 172.16.0.0/12 accept"));
    }

    #[test]
    fn every_endpoint_gets_one_rule_in_its_family() {
        let rules = nft(&[
            tunnel("wg5", &[], &[], true),
            tunnel("wg6", &["1.2.3.4", "5.6.7.8", "2001:db8::1"], &[], false),
        ]);
        assert_eq!(rules.matches("wg5").count(), 1);
        assert!(rules.contains("ip daddr 1.2.3.4 accept"));
        assert!(rules.contains("ip daddr 5.6.7.8 accept"));
        assert!(rules.contains("ip6 daddr 2001:db8::1 accept"));
    }

    #[test]
    fn endpoint_allowlist_emits_no_interface_rule() {
        let policy = ActiveTunnelInfo::endpoint_allowlist(vec!["1.2.3.4".parse().unwrap()]);
        let rules = nft(&[policy]);
        assert!(rules.contains("ip daddr 1.2.3.4 accept"));
        assert!(!rules.contains("oifname \"\" accept"));
    }

    #[test]
    fn legacy_global_policy_detection_is_strict() {
        let legacy_v4 = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT DROP [0:0]\n-A OUTPUT -o lo -j ACCEPT\n-A OUTPUT -p udp -m udp --sport 68 --dport 67 -j ACCEPT\nCOMMIT\n";
        assert!(NftFirewall::is_legacy_global_policy(legacy_v4, false));
        assert!(!NftFirewall::is_legacy_global_policy(
            &format!("{legacy_v4}-A INPUT -j ACCEPT\n"),
            false
        ));
        assert!(!NftFirewall::is_legacy_global_policy(
            &legacy_v4.replace(":OUTPUT DROP", ":OUTPUT ACCEPT"),
            false
        ));
        let host_owned_drop = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT DROP [0:0]\n-A OUTPUT -d 203.0.113.10 -j ACCEPT\nCOMMIT\n";
        assert!(!NftFirewall::is_legacy_global_policy(
            host_owned_drop,
            false
        ));
        assert_eq!(
            NftFirewall::legacy_cleanup_ruleset(),
            "*filter\n:OUTPUT ACCEPT [0:0]\n-F OUTPUT\nCOMMIT\n"
        );
    }

    #[test]
    fn nft_batches_support_old_clients_and_cover_two_tunnels_dual_stack() {
        let first = tunnel("wg0", &["1.2.3.4"], &["0.0.0.0/0"], true);
        let second = tunnel("wg1", &["2001:db8::1"], &["10.0.0.0/8"], false);
        let active = [first, second];
        let fresh = nft_policy::ruleset(&active, BatchMode::Create);
        let replacement = nft_policy::ruleset(&active, BatchMode::Replace);

        assert!(fresh.starts_with("table inet vortix_killswitch {\n"));
        assert!(!fresh.contains("delete table"));
        assert!(!fresh.contains("destroy table"));
        assert!(replacement.starts_with("delete table inet vortix_killswitch\n"));
        assert!(!replacement.contains("destroy table"));
        assert_eq!(
            replacement.matches("table inet vortix_killswitch").count(),
            2
        );
        assert!(fresh.contains("oifname \"wg0\" accept"));
        assert!(fresh.contains("oifname \"wg1\" accept"));
        assert!(fresh.contains("ip daddr 1.2.3.4 accept"));
        assert!(fresh.contains("ip6 daddr 2001:db8::1 accept"));
        assert!(!fresh.contains("ip daddr 10.0.0.0/8 accept"));
        assert!(nft_policy::snapshot_matches(&active, &fresh));
        assert!(!nft_policy::snapshot_matches(
            &active,
            &fresh.replace("    oifname \"wg1\" accept\n", "")
        ));
        assert!(!nft_policy::snapshot_matches(
            &active,
            &fresh.replace("counter drop comment", "counter accept comment")
        ));
        assert_eq!(
            NftFirewall::nft_command(vec!["list".into()])
                .env
                .get("LC_ALL")
                .map(String::as_str),
            Some("C")
        );
        let command = NftFirewall::nft_command(vec!["list".into()]);
        assert_eq!(command.timeout, Some(FIREWALL_COMMAND_TIMEOUT));
        assert_eq!(command.output_limit, Some(FIREWALL_OUTPUT_LIMIT));
        assert!(command.terminate_process_group);
        assert_eq!(
            NftFirewall::nft_command(vec![
                "-n".into(),
                "list".into(),
                "table".into(),
                "inet".into(),
                crate::constants::NFT_TABLE_NAME.into(),
            ])
            .args,
            [
                "-n",
                "list",
                "table",
                "inet",
                crate::constants::NFT_TABLE_NAME,
            ]
        );
    }

    #[test]
    fn legacy_firewall_commands_are_bounded_and_contain_descendants() {
        let command = NftFirewall::firewall_command("iptables-save", Vec::new());
        assert_eq!(command.timeout, Some(FIREWALL_COMMAND_TIMEOUT));
        assert_eq!(command.output_limit, Some(FIREWALL_OUTPUT_LIMIT));
        assert!(command.terminate_process_group);
    }

    #[test]
    fn nft_readback_compares_host_destinations_semantically_and_rejects_unknown_rules() {
        let host_route = tunnel("wg2", &[], &["10.0.0.1/32"], false);
        let host_rules = nft_policy::ruleset(std::slice::from_ref(&host_route), BatchMode::Create);
        assert!(host_rules.contains("ip daddr 10.0.0.0/32 accept"));
        let nft_readback =
            host_rules.replace("ip daddr 10.0.0.0/32 accept", "ip daddr 10.0.0.0 accept");
        assert!(nft_policy::snapshot_matches(
            std::slice::from_ref(&host_route),
            &nft_readback
        ));
        assert!(!nft_policy::snapshot_matches(
            std::slice::from_ref(&host_route),
            &nft_readback.replace(
                "    counter drop comment",
                "    meta skuid 1000 accept comment \"extra\"\n    counter drop comment",
            )
        ));
    }

    #[test]
    fn nft_snapshot_primary_plus_secondary() {
        let active = [
            tunnel("wg0", &["1.2.3.4"], &["0.0.0.0/0"], true),
            tunnel("wg1", &["5.6.7.8"], &["10.0.0.0/8"], false),
        ];
        let digest = crate::control::killswitch::policy_digest(&active);
        let expected = format!(
            "table inet {table} {{
  chain output {{
    type filter hook output priority 0; policy drop;

    oifname \"lo\" accept
    ip daddr 172.16.0.0/12 accept
    ip daddr 192.168.0.0/16 accept
    udp sport 68 udp dport 67 accept
    oifname \"wg0\" accept
    ip daddr 1.2.3.4 accept
    oifname \"wg1\" accept
    ip daddr 5.6.7.8 accept
    counter drop comment \"{POLICY_COMMENT_PREFIX}{digest}\"
  }}
}}
",
            table = crate::constants::NFT_TABLE_NAME,
        );
        assert_eq!(nft(&active), expected);
    }
}
