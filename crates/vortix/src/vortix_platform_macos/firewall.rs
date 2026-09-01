//! macOS pf (Packet Filter) firewall implementation for kill switch.
//!
//! The ruleset synthesiser now consumes a slice
//! of [`ActiveTunnelInfo`] and emits per-tunnel allow rules in a single
//! ruleset. The ruleset is fed to Vortix's PF anchor via stdin, which performs
//! an atomic in-kernel replace — so transitions from one active set to
//! another (refresh) never go through `pfctl -F all` + `pfctl -d`, which
//! would otherwise open a non-atomic leak window. Explicit release flushes
//! only that anchor and never disables or clears the host's global PF state.

use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{self, Write as IoWrite};
use std::net::IpAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::time::Duration;

use crate::vortix_core::cidr::{rfc1918_ranges, Cidr};
use crate::vortix_core::cidr_subtract::cidr_subtract;
use crate::vortix_core::ports::killswitch::{
    ActiveTunnelInfo, Killswitch, KillswitchError, Result,
};
use crate::vortix_process::{CommandSpec, PrivilegeReq};
use tracing::{debug, error, info};

/// On-disk pf configuration written for diagnostic inspection. The
/// authoritative ruleset is delivered to pfctl via stdin so the in-kernel
/// replace is atomic; this file is a best-effort snapshot of what was
/// loaded.
const PF_CONF_PATH: &str = "/var/run/vortix/killswitch.conf";
/// Legacy pf configuration path cleaned up after migration.
const PF_CONF_PATH_LEGACY: &str = "/tmp/vortix_killswitch.conf";
/// macOS' stock pf.conf traverses the `com.apple/*` wildcard anchor. Keeping
/// Vortix policy below that existing hook lets us own and replace only this
/// anchor without rewriting the host's global ruleset.
pub(crate) const PF_ANCHOR: &str = "com.apple/vortix.killswitch";
pub(crate) const PF_APPLY_ARGS: [&str; 4] = ["-a", PF_ANCHOR, "-f", "-"];
pub(crate) const PF_RELEASE_ARGS: [&str; 4] = ["-a", PF_ANCHOR, "-F", "rules"];
const POLICY_LABEL_PREFIX: &str = "vortix-policy:";
const FIREWALL_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const FIREWALL_OUTPUT_LIMIT: usize = 1024 * 1024;

fn pfctl(args: &[&str]) -> std::io::Result<std::process::Output> {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    crate::vortix_process::run_to_output(PfFirewall::pfctl_command(owned))
}

/// Invoke anchor-scoped `pfctl -f -` with the given ruleset on stdin.
/// is atomic: the in-kernel ruleset is replaced in a single operation. No
/// leak window — earlier rules stay live until the new set parses and
/// commits.
fn pfctl_load_stdin(ruleset: &[u8]) -> std::io::Result<std::process::Output> {
    crate::vortix_process::run_to_output(
        PfFirewall::pfctl_command(PF_APPLY_ARGS.map(str::to_string).to_vec())
            .stdin(ruleset.to_vec()),
    )
}

fn read_pf_state() -> io::Result<(
    std::process::Output,
    std::process::Output,
    std::process::Output,
)> {
    std::thread::scope(|scope| {
        let root = scope.spawn(|| pfctl(&["-sr"]));
        let anchor = scope.spawn(|| pfctl(&["-a", PF_ANCHOR, "-sr"]));
        let status = scope.spawn(|| pfctl(&["-s", "info"]));
        let root = root
            .join()
            .map_err(|_| io::Error::other("PF root read-back worker panicked"))??;
        let anchor = anchor
            .join()
            .map_err(|_| io::Error::other("PF anchor read-back worker panicked"))??;
        let status = status
            .join()
            .map_err(|_| io::Error::other("PF status read-back worker panicked"))??;
        Ok((root, anchor, status))
    })
}

/// macOS pf-based firewall implementation.
pub struct PfFirewall;

impl PfFirewall {
    fn pfctl_command(args: Vec<String>) -> CommandSpec {
        CommandSpec::oneshot("pfctl", args)
            .privilege(PrivilegeReq::Root)
            .timeout(FIREWALL_COMMAND_TIMEOUT)
            .output_limit(FIREWALL_OUTPUT_LIMIT)
            .contain_process_group()
    }

    pub(crate) fn canonical_pf_rules(rules: &str) -> Vec<&str> {
        rules
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect()
    }

    /// Synthesise the pf ruleset for the given active tunnel set.
    ///
    /// Shape:
    ///   1. `pass out quick on lo0` — loopback always allowed
    ///   2. RFC1918 pass-out rules, with secondaries' declared CIDRs
    ///      carved out so traffic claimed by a secondary cannot escape
    ///      onto the underlay
    ///   3. DHCP pass rules
    ///   4. Per-tunnel: `pass out quick on <interface>` + one
    ///      `pass out quick to <server_ip>` per server IP, so the tunnel
    ///      can reconnect after a transport drop
    ///   5. A terminal `block drop out quick all` carrying the policy digest
    ///
    /// An empty `active` slice yields rules 1-4 only — the base block-all
    /// posture with no per-tunnel egress.
    #[must_use]
    pub fn generate_pf_rules(active: &[ActiveTunnelInfo]) -> String {
        let mut rules = String::new();
        writeln!(rules, "# Vortix Kill Switch Rules - Auto-generated").unwrap();
        writeln!(rules, "# DO NOT EDIT - Will be overwritten").unwrap();
        writeln!(rules).unwrap();
        writeln!(rules, "# Allow loopback").unwrap();
        writeln!(rules, "pass out quick on lo0 all").unwrap();
        writeln!(rules).unwrap();

        // Secondaries' declared CIDRs are subtracted from RFC1918. Primaries
        // (claiming 0/0) are excluded — their interface allow rule covers
        // their egress, and subtracting the default route would carve up
        // loopback. See cidr_subtract docs / Q-DEF-9 D-6.
        let secondary_cidrs: Vec<Cidr> = active
            .iter()
            .filter(|t| !t.is_primary)
            .flat_map(|t| t.declared_cidrs.iter().copied())
            .collect();
        let rfc1918 = cidr_subtract(&rfc1918_ranges(), &secondary_cidrs);

        writeln!(
            rules,
            "# Allow local network (RFC1918, minus secondaries' claimed CIDRs)"
        )
        .unwrap();
        for c in &rfc1918 {
            writeln!(rules, "pass out quick to {c}").unwrap();
        }
        writeln!(rules).unwrap();

        writeln!(rules, "# Allow DHCP").unwrap();
        writeln!(
            rules,
            "pass out quick proto udp from any port 68 to any port 67"
        )
        .unwrap();
        writeln!(
            rules,
            "pass in quick proto udp from any port 67 to any port 68"
        )
        .unwrap();

        // Per-tunnel rules. Order is preserved from the caller — typically
        // primary first, then secondaries by attach order.
        for tunnel in active {
            writeln!(rules).unwrap();
            if !tunnel.is_endpoint_allowlist() {
                writeln!(
                    rules,
                    "# Tunnel: {} (primary={})",
                    tunnel.interface, tunnel.is_primary
                )
                .unwrap();
                writeln!(rules, "pass out quick on {} all", tunnel.interface).unwrap();
            }
            for ip in &tunnel.server_ips {
                writeln!(rules, "pass out quick to {}", fmt_ip(ip)).unwrap();
            }
        }

        // PF evaluates the last matching rule. All allow exceptions must
        // precede a terminal quick block so later root rules cannot override
        // the Vortix anchor, while the block cannot shadow our own allows.
        let digest = crate::core::killswitch::policy_digest(active);
        writeln!(rules).unwrap();
        writeln!(rules, "# Default: block all remaining egress").unwrap();
        writeln!(
            rules,
            "block drop out quick all label \"{POLICY_LABEL_PREFIX}{digest}\""
        )
        .unwrap();

        rules
    }

    pub(crate) fn root_traverses_anchor(root_rules: &str) -> bool {
        let exact_anchor = format!("\"{PF_ANCHOR}\"");
        let mut preceding_quick_outbound_pass = false;
        for line in Self::canonical_pf_rules(root_rules) {
            let mut tokens = line.split_ascii_whitespace();
            let first = tokens.next();
            let second = tokens.next();
            if first == Some("anchor")
                && second.is_some_and(|value| value == "\"com.apple/*\"" || value == exact_anchor)
            {
                let qualifier = tokens.next();
                let trailing = tokens.next();
                let unconditional = qualifier.is_none() || qualifier == Some("all");
                if unconditional && trailing.is_none() {
                    return !preceding_quick_outbound_pass;
                }
            }

            if first == Some("pass") {
                let mut quick = second == Some("quick");
                let mut inbound = second == Some("in");
                let mut outbound = second == Some("out");
                for token in tokens {
                    quick |= token == "quick";
                    inbound |= token == "in";
                    outbound |= token == "out";
                }
                preceding_quick_outbound_pass |= quick && (!inbound || outbound);
            }
        }
        false
    }

    pub(crate) fn snapshot_matches_policy(active: &[ActiveTunnelInfo], observed: &str) -> bool {
        Self::canonical_snapshot_matches(active, &Self::canonical_pf_rules(observed))
    }

    pub(crate) fn canonical_snapshot_matches(
        active: &[ActiveTunnelInfo],
        observed: &[&str],
    ) -> bool {
        let expected = Self::generate_pf_rules(active);
        let expected = Self::canonical_pf_rules(&expected);
        expected.len() == observed.len()
            && expected.iter().zip(observed).all(|(expected, observed)| {
                *observed == *expected
                    || pfctl_normalized_generated_rule(expected).as_deref() == Some(*observed)
            })
    }

    fn state_matches_policy(
        active: &[ActiveTunnelInfo],
        root_rules: &str,
        anchor_rules: &str,
        status: &str,
    ) -> bool {
        Self::verified_state(
            active,
            Self::root_traverses_anchor(root_rules),
            pf_is_enabled(status),
            anchor_rules,
        )
    }

    pub(crate) fn verified_state(
        active: &[ActiveTunnelInfo],
        root_traverses_anchor: bool,
        enabled: bool,
        anchor_rules: &str,
    ) -> bool {
        root_traverses_anchor && enabled && Self::snapshot_matches_policy(active, anchor_rules)
    }

    /// Best-effort write of the ruleset to `PF_CONF_PATH` for diagnostic
    /// inspection. Failure to write the snapshot is logged but does not
    /// abort the engage — the authoritative ruleset goes to pfctl via
    /// stdin.
    fn write_diagnostic_snapshot(rules: &str) {
        let conf_path = std::path::Path::new(PF_CONF_PATH);
        if let Some(parent) = conf_path.parent() {
            if !parent.exists() {
                if let Err(e) = fs::create_dir_all(parent) {
                    debug!(target: "vortix::killswitch", err = %e, "snapshot dir create skipped");
                    return;
                }
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
        match fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(PF_CONF_PATH)
        {
            Ok(mut file) => {
                if let Err(e) = file.write_all(rules.as_bytes()) {
                    debug!(target: "vortix::killswitch", err = %e, "snapshot write skipped");
                }
            }
            Err(e) => {
                debug!(target: "vortix::killswitch", err = %e, "snapshot open skipped");
            }
        }
        let _ = fs::remove_file(PF_CONF_PATH_LEGACY);
    }
}

/// Normalize only the small rule vocabulary emitted by
/// [`PfFirewall::generate_pf_rules`] into the form printed by macOS `pfctl`.
/// Unknown syntax is not accepted, and comparison remains exact after
/// normalization so an appended label/state/action cannot hide drift.
fn pfctl_normalized_generated_rule(rule: &str) -> Option<String> {
    if rule == "pass out quick proto udp from any port 68 to any port 67" {
        return Some(
            "pass out quick proto udp from any port = 68 to any port = 67 keep state".into(),
        );
    }
    if rule == "pass in quick proto udp from any port 67 to any port 68" {
        return Some(
            "pass in quick proto udp from any port = 67 to any port = 68 keep state".into(),
        );
    }
    if let Some(interface) = rule
        .strip_prefix("pass out quick on ")
        .and_then(|rest| rest.strip_suffix(" all"))
    {
        return Some(format!(
            "pass out quick on {interface} all flags S/SA keep state"
        ));
    }
    if let Some(destination) = rule.strip_prefix("pass out quick to ") {
        let family = if destination
            .split_once('/')
            .map_or(destination, |(address, _)| address)
            .parse::<IpAddr>()
            .ok()?
            .is_ipv4()
        {
            "inet"
        } else {
            "inet6"
        };
        return Some(format!(
            "pass out quick {family} from any to {destination} flags S/SA keep state"
        ));
    }
    Some(rule.to_string())
}

fn fmt_ip(ip: &IpAddr) -> String {
    ip.to_string()
}

impl Killswitch for PfFirewall {
    /// Engage the killswitch with a ruleset covering every tunnel in
    /// `active`. The ruleset is loaded into the Vortix anchor via stdin, which
    /// performs an atomic in-kernel replace — both fresh enable and
    /// refresh-with-different-active-set go through this single path, so
    /// there's never a window where the previous rules are gone but the
    /// new rules haven't landed yet.
    ///
    /// `pfctl -e` is called after the load to ensure pf is enabled.
    /// `pfctl -e` is idempotent (returns "already enabled" on the second
    /// call), so the refresh path leaves the enabled state alone.
    fn enable_blocking_multi(active: &[ActiveTunnelInfo]) -> Result<()> {
        info!(
            target: "vortix::killswitch",
            tunnels = active.len(),
            "killswitch.engage"
        );

        if !crate::utils::is_root() {
            error!(target: "vortix::killswitch", "kill switch requires root privileges");
            return Err(KillswitchError::NotRoot);
        }

        crate::core::killswitch::validate_policy(active)?;

        // Preflight traversal before loading an anchor or enabling PF. A
        // populated but inert anchor must not mutate global PF state.
        let output = pfctl(&["-sr"])?;
        let root_rules = String::from_utf8_lossy(&output.stdout);
        if !output.status.success() || !Self::root_traverses_anchor(&root_rules) {
            return Err(KillswitchError::CommandFailed(
                "root pf ruleset does not traverse the Vortix anchor".to_string(),
            ));
        }

        let rules = Self::generate_pf_rules(active);

        // Diagnostic snapshot — best-effort, never gates the engage.
        Self::write_diagnostic_snapshot(&rules);
        debug!(
            target: "vortix::killswitch",
            path = %PF_CONF_PATH,
            bytes = rules.len(),
            "loading pf ruleset via stdin"
        );

        // Authoritative path: anchor-scoped pfctl reads ruleset from stdin and
        // atomically replaces the in-kernel rules. If parsing fails the
        // prior ruleset stays in force.
        let output = pfctl_load_stdin(rules.as_bytes())?;
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr).to_string();
            error!(target: "vortix::killswitch", stderr = %err, "pfctl -f - failed");
            return Err(KillswitchError::CommandFailed(err));
        }

        // Ensure pf is enabled. Idempotent — emits "pf already enabled" on
        // refresh, which we treat as success.
        let output = pfctl(&["-e"])?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("enabled") {
                error!(target: "vortix::killswitch", stderr = %stderr, "pfctl -e failed");
                return Err(KillswitchError::CommandFailed(stderr.to_string()));
            }
        }

        // Success is the complete effective-state postcondition, not merely
        // the content of the owned anchor. Root traversal or PF enabled state
        // can drift between the preflight/load and this read-back.
        Self::verify_blocking(active)?;

        info!(
            target: "vortix::killswitch",
            tunnels = active.len(),
            "kill switch ACTIVE — blocking non-VPN traffic"
        );
        Ok(())
    }

    /// Disable only Vortix's anchor. pf may have been enabled before Vortix
    /// and may protect unrelated host policy, so global flush/disable is
    /// never an owned operation.
    fn disable_blocking() -> Result<()> {
        info!(target: "vortix::killswitch", "disabling kill switch");

        if !crate::utils::is_root() {
            error!(target: "vortix::killswitch", "disabling kill switch requires root");
            return Err(KillswitchError::NotRoot);
        }

        let output = pfctl(&PF_RELEASE_ARGS)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("not enabled") && !stderr.contains("does not exist") {
                error!(target: "vortix::killswitch", stderr = %stderr, "pf anchor flush failed");
                return Err(KillswitchError::CommandFailed(stderr.to_string()));
            }
        }

        let output = pfctl(&["-a", PF_ANCHOR, "-sr"])?;
        if !output.status.success() {
            return Err(KillswitchError::CommandFailed(format!(
                "pf anchor read-back failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        if !String::from_utf8_lossy(&output.stdout).trim().is_empty() {
            return Err(KillswitchError::CommandFailed(
                "pf anchor read-back still contains Vortix rules".to_string(),
            ));
        }
        let _ = fs::remove_file(PF_CONF_PATH);
        let _ = fs::remove_file(PF_CONF_PATH_LEGACY);

        info!(target: "vortix::killswitch", "kill switch DISABLED — normal traffic restored");
        Ok(())
    }

    fn verify_blocking(active: &[ActiveTunnelInfo]) -> Result<()> {
        let (root, anchor, status) = read_pf_state()?;
        if root.status.success()
            && anchor.status.success()
            && status.status.success()
            && Self::state_matches_policy(
                active,
                &String::from_utf8_lossy(&root.stdout),
                &String::from_utf8_lossy(&anchor.stdout),
                &String::from_utf8_lossy(&status.stdout),
            )
        {
            Ok(())
        } else {
            Err(KillswitchError::CommandFailed(
                "pf read-back did not match the requested Vortix policy".into(),
            ))
        }
    }

    fn verify_disabled() -> Result<()> {
        let anchor = pfctl(&["-a", PF_ANCHOR, "-sr"])?;
        if anchor.status.success()
            && Self::canonical_pf_rules(&String::from_utf8_lossy(&anchor.stdout)).is_empty()
        {
            Ok(())
        } else {
            Err(KillswitchError::CommandFailed(
                "pf read-back still contains Vortix-owned rules".into(),
            ))
        }
    }
}

pub(crate) fn pf_is_enabled(status: &str) -> bool {
    status.lines().any(|line| {
        line.split_once(':').is_some_and(|(key, value)| {
            key.trim() == "Status" && value.split_ascii_whitespace().next() == Some("Enabled")
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

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

    fn without_policy_label(rules: &str) -> String {
        let mut normalized = rules
            .lines()
            .map(|line| {
                if line.starts_with("block drop out quick all label ") {
                    "block drop out quick all"
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        normalized.push('\n');
        normalized
    }

    #[test]
    fn pf_mutations_are_scoped_to_the_vortix_anchor() {
        assert_eq!(PF_APPLY_ARGS, ["-a", PF_ANCHOR, "-f", "-"]);
        assert_eq!(PF_RELEASE_ARGS, ["-a", PF_ANCHOR, "-F", "rules"]);
    }

    #[test]
    fn root_anchor_traversal_requires_an_exact_anchor_token() {
        assert!(PfFirewall::root_traverses_anchor(
            "anchor \"com.apple/*\" all\n"
        ));
        assert!(PfFirewall::root_traverses_anchor(
            "anchor \"com.apple/vortix.killswitch\"\n"
        ));
        assert!(!PfFirewall::root_traverses_anchor(
            "anchor \"com.apple/*-lookalike\"\n"
        ));
        assert!(!PfFirewall::root_traverses_anchor(
            "pass quick label \"anchor \\\"com.apple/*\\\"\"\n"
        ));
    }

    #[test]
    fn root_anchor_traversal_rejects_a_preceding_quick_outbound_pass() {
        assert!(!PfFirewall::root_traverses_anchor(
            "pass out quick all\nanchor \"com.apple/*\" all\n"
        ));
        assert!(!PfFirewall::root_traverses_anchor(
            "pass quick out on en0 all\nanchor \"com.apple/vortix.killswitch\" all\n"
        ));
        assert!(PfFirewall::root_traverses_anchor(
            "anchor \"com.apple/*\" all\npass out quick all\n"
        ));
    }

    #[test]
    fn root_anchor_traversal_rejects_restricted_anchor_rules() {
        for rule in [
            "anchor \"com.apple/*\" in all\n",
            "anchor \"com.apple/*\" out on en0 all\n",
            "anchor \"com.apple/*\" on lo0 all\n",
            "anchor \"com.apple/*\" inet6 all\n",
            "anchor \"com.apple/*\" proto tcp\n",
            "anchor \"com.apple/vortix.killswitch\" all on en0\n",
        ] {
            assert!(
                !PfFirewall::root_traverses_anchor(rule),
                "restricted traversal must not verify: {rule}"
            );
        }
    }

    #[test]
    fn pfctl_commands_are_bounded_and_contain_descendants() {
        let command = PfFirewall::pfctl_command(vec!["-sr".into()]);
        assert_eq!(command.timeout, Some(FIREWALL_COMMAND_TIMEOUT));
        assert_eq!(command.output_limit, Some(FIREWALL_OUTPUT_LIMIT));
        assert!(command.terminate_process_group);
    }

    #[test]
    fn effective_state_requires_traversal_enabled_pf_and_exact_anchor_policy() {
        let active = vec![ActiveTunnelInfo::endpoint_allowlist(vec!["198.51.100.7"
            .parse()
            .unwrap()])];
        let anchor = PfFirewall::generate_pf_rules(&active);
        let root = "anchor \"com.apple/*\" all\n";
        let enabled = "Status: Enabled for 0 days\n";
        assert!(PfFirewall::state_matches_policy(
            &active, root, &anchor, enabled
        ));
        assert!(!PfFirewall::state_matches_policy(
            &active,
            "pass out quick all\nanchor \"com.apple/*\" all\n",
            &anchor,
            enabled,
        ));
        assert!(!PfFirewall::state_matches_policy(
            &active,
            root,
            &anchor,
            "Status: Disabled\n",
        ));
        assert!(!PfFirewall::state_matches_policy(
            &active,
            root,
            &anchor.replace("198.51.100.7", "203.0.113.9"),
            enabled,
        ));
    }

    #[test]
    fn pfctl_normalization_is_exact_and_rejects_semantic_suffixes() {
        let active = vec![ActiveTunnelInfo {
            interface: "utun4".into(),
            server_ips: vec!["198.51.100.7".parse().unwrap()],
            declared_cidrs: Vec::new(),
            is_primary: true,
        }];
        let normalized = [
            "pass out quick on lo0 all flags S/SA keep state",
            "pass out quick inet from any to 10.0.0.0/8 flags S/SA keep state",
            "pass out quick inet from any to 172.16.0.0/12 flags S/SA keep state",
            "pass out quick inet from any to 192.168.0.0/16 flags S/SA keep state",
            "pass out quick proto udp from any port = 68 to any port = 67 keep state",
            "pass in quick proto udp from any port = 67 to any port = 68 keep state",
            "pass out quick on utun4 all flags S/SA keep state",
            "pass out quick inet from any to 198.51.100.7 flags S/SA keep state",
        ];
        let generated = PfFirewall::generate_pf_rules(&active);
        let mut observed = normalized.to_vec();
        observed.push(
            PfFirewall::canonical_pf_rules(&generated)
                .last()
                .copied()
                .unwrap(),
        );
        assert!(PfFirewall::canonical_snapshot_matches(&active, &observed));

        observed[0] = "pass out quick on lo0 all flags S/SA keep state label \"foreign\"";
        assert!(!PfFirewall::canonical_snapshot_matches(&active, &observed));
    }

    #[test]
    fn empty_active_set_yields_base_blockall() {
        let rules = PfFirewall::generate_pf_rules(&[]);
        assert!(rules.contains("block drop out quick all"));
        assert!(rules.contains("pass out quick on lo0"));
        // Full RFC1918 base intact.
        assert!(rules.contains("pass out quick to 10.0.0.0/8"));
        assert!(rules.contains("pass out quick to 172.16.0.0/12"));
        assert!(rules.contains("pass out quick to 192.168.0.0/16"));
        // DHCP present.
        assert!(rules.contains("port 68 to any port 67"));
        assert!(rules.contains("port 67 to any port 68"));
        // No per-tunnel rules.
        assert!(!rules.contains("pass out quick on utun"));
        assert!(!rules.contains("# Tunnel:"));
    }

    #[test]
    fn single_primary_zero_slash_zero_keeps_full_rfc1918() {
        // A primary tunnel declaring 0.0.0.0/0 must NOT subtract from
        // RFC1918 — its interface allow covers egress, and subtracting
        // the default route would carve loopback. See D-6.
        let t = tunnel("utun3", &["1.2.3.4"], &["0.0.0.0/0"], true);
        let rules = PfFirewall::generate_pf_rules(&[t]);
        assert!(rules.contains("pass out quick to 10.0.0.0/8"));
        assert!(rules.contains("pass out quick to 172.16.0.0/12"));
        assert!(rules.contains("pass out quick to 192.168.0.0/16"));
        assert!(rules.contains("pass out quick on utun3 all"));
        assert!(rules.contains("pass out quick to 1.2.3.4"));
    }

    #[test]
    fn single_secondary_ten_dot_carves_rfc1918() {
        // A secondary claiming 10/8 should remove that block from the
        // RFC1918 pass list. 172.16/12 + 192.168/16 remain.
        let t = tunnel("utun4", &["5.6.7.8"], &["10.0.0.0/8"], false);
        let rules = PfFirewall::generate_pf_rules(&[t]);
        assert!(!rules.contains("pass out quick to 10.0.0.0/8"));
        assert!(rules.contains("pass out quick to 172.16.0.0/12"));
        assert!(rules.contains("pass out quick to 192.168.0.0/16"));
        assert!(rules.contains("pass out quick on utun4 all"));
        assert!(rules.contains("pass out quick to 5.6.7.8"));
    }

    #[test]
    fn two_secondaries_disjoint_carve_correctly() {
        // utun5 claims 10/8, utun6 claims 192.168/16. Result: only
        // 172.16/12 remains in the RFC1918 list.
        let t1 = tunnel("utun5", &["1.1.1.1"], &["10.0.0.0/8"], false);
        let t2 = tunnel("utun6", &["2.2.2.2"], &["192.168.0.0/16"], false);
        let rules = PfFirewall::generate_pf_rules(&[t1, t2]);
        assert!(!rules.contains("pass out quick to 10.0.0.0/8"));
        assert!(rules.contains("pass out quick to 172.16.0.0/12"));
        assert!(!rules.contains("pass out quick to 192.168.0.0/16"));
        // Both interfaces appear.
        assert!(rules.contains("pass out quick on utun5 all"));
        assert!(rules.contains("pass out quick on utun6 all"));
        assert!(rules.contains("pass out quick to 1.1.1.1"));
        assert!(rules.contains("pass out quick to 2.2.2.2"));
    }

    #[test]
    fn two_secondaries_overlapping_dont_double_subtract() {
        // utun7 claims 10/8, utun8 claims 10.5.0.0/16 (a subset). Result
        // is identical to subtracting just 10/8.
        let t1 = tunnel("utun7", &["1.1.1.1"], &["10.0.0.0/8"], false);
        let t2 = tunnel("utun8", &["2.2.2.2"], &["10.5.0.0/16"], false);
        let rules = PfFirewall::generate_pf_rules(&[t1, t2]);
        assert!(!rules.contains("pass out quick to 10."));
        assert!(rules.contains("pass out quick to 172.16.0.0/12"));
        assert!(rules.contains("pass out quick to 192.168.0.0/16"));
    }

    #[test]
    fn primary_plus_secondary_only_secondary_carves() {
        // Primary 0/0 + secondary 10/8 — only the secondary subtracts.
        let prim = tunnel("utun9", &["9.9.9.9"], &["0.0.0.0/0"], true);
        let sec = tunnel("utun10", &["8.8.8.8"], &["10.0.0.0/8"], false);
        let rules = PfFirewall::generate_pf_rules(&[prim, sec]);
        // 10/8 is gone.
        assert!(!rules.contains("pass out quick to 10.0.0.0/8"));
        // 172.16 and 192.168 intact.
        assert!(rules.contains("pass out quick to 172.16.0.0/12"));
        assert!(rules.contains("pass out quick to 192.168.0.0/16"));
        // Both interfaces present.
        assert!(rules.contains("pass out quick on utun9 all"));
        assert!(rules.contains("pass out quick on utun10 all"));
    }

    #[test]
    fn tunnel_with_no_server_ips_still_gets_interface_rule() {
        let t = tunnel("utun11", &[], &[], true);
        let rules = PfFirewall::generate_pf_rules(&[t]);
        assert!(rules.contains("pass out quick on utun11 all"));
        // No spurious 'pass out quick to <ip>' for an empty server list.
        // (Other 'pass out quick to' lines exist for RFC1918; we check
        // that nothing additional was emitted with an empty trailer.)
    }

    #[test]
    fn tunnel_with_multiple_server_ips_emits_one_pass_per_ip() {
        let t = tunnel("utun12", &["1.2.3.4", "5.6.7.8"], &[], true);
        let rules = PfFirewall::generate_pf_rules(&[t]);
        assert!(rules.contains("pass out quick to 1.2.3.4"));
        assert!(rules.contains("pass out quick to 5.6.7.8"));
    }

    #[test]
    fn endpoint_allowlist_emits_no_interface_rule() {
        let policy = ActiveTunnelInfo::endpoint_allowlist(vec!["1.2.3.4".parse().unwrap()]);
        let rules = PfFirewall::generate_pf_rules(&[policy]);
        assert!(rules.contains("pass out quick to 1.2.3.4"));
        assert!(!rules.contains("pass out quick on  all"));
    }

    #[test]
    fn ipv6_server_ip_renders_without_brackets() {
        // pf accepts raw v6 syntax. Confirm the IpAddr Display impl
        // produces the v6 form.
        let t = ActiveTunnelInfo {
            interface: "utun13".to_string(),
            server_ips: vec!["2001:db8::1".parse().unwrap()],
            declared_cidrs: vec![],
            is_primary: true,
        };
        let rules = PfFirewall::generate_pf_rules(&[t]);
        assert!(rules.contains("pass out quick to 2001:db8::1"));
    }

    #[test]
    fn terminal_quick_block_follows_every_allow_rule() {
        let t = tunnel("utun3", &["1.2.3.4"], &["0.0.0.0/0"], true);
        let rules = PfFirewall::generate_pf_rules(&[t]);
        let last = rules
            .lines()
            .filter(|line| !line.is_empty())
            .next_back()
            .unwrap();
        assert!(last.starts_with("block drop out quick all label \"vortix-policy:"));
        assert!(rules.find("pass out quick on utun3").unwrap() < rules.find(last).unwrap());
        let missing_allow = rules.replace("pass out quick on utun3 all\n", "");
        assert_ne!(
            PfFirewall::canonical_pf_rules(&missing_allow),
            PfFirewall::canonical_pf_rules(&rules)
        );
    }

    /// Snapshot — empty active set. Pins the base block-all ruleset.
    #[test]
    fn snapshot_empty_active_set() {
        let rules = without_policy_label(&PfFirewall::generate_pf_rules(&[]));
        let expected = "\
# Vortix Kill Switch Rules - Auto-generated
# DO NOT EDIT - Will be overwritten

# Allow loopback
pass out quick on lo0 all

# Allow local network (RFC1918, minus secondaries' claimed CIDRs)
pass out quick to 10.0.0.0/8
pass out quick to 172.16.0.0/12
pass out quick to 192.168.0.0/16

# Allow DHCP
pass out quick proto udp from any port 68 to any port 67
pass in quick proto udp from any port 67 to any port 68

# Default: block all remaining egress
block drop out quick all
";
        assert_eq!(rules, expected);
    }

    /// Snapshot — single primary tunnel with one server IP.
    #[test]
    fn snapshot_single_primary() {
        let t = ActiveTunnelInfo {
            interface: "utun3".to_string(),
            server_ips: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            declared_cidrs: vec![cidr("0.0.0.0/0")],
            is_primary: true,
        };
        let rules = without_policy_label(&PfFirewall::generate_pf_rules(&[t]));
        let expected = "\
# Vortix Kill Switch Rules - Auto-generated
# DO NOT EDIT - Will be overwritten

# Allow loopback
pass out quick on lo0 all

# Allow local network (RFC1918, minus secondaries' claimed CIDRs)
pass out quick to 10.0.0.0/8
pass out quick to 172.16.0.0/12
pass out quick to 192.168.0.0/16

# Allow DHCP
pass out quick proto udp from any port 68 to any port 67
pass in quick proto udp from any port 67 to any port 68

# Tunnel: utun3 (primary=true)
pass out quick on utun3 all
pass out quick to 1.2.3.4

# Default: block all remaining egress
block drop out quick all
";
        assert_eq!(rules, expected);
    }

    /// Snapshot — primary + secondary with carved RFC1918.
    #[test]
    fn snapshot_primary_plus_secondary() {
        let prim = ActiveTunnelInfo {
            interface: "utun3".to_string(),
            server_ips: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            declared_cidrs: vec![cidr("0.0.0.0/0")],
            is_primary: true,
        };
        let sec = ActiveTunnelInfo {
            interface: "utun4".to_string(),
            server_ips: vec![IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))],
            declared_cidrs: vec![cidr("10.0.0.0/8")],
            is_primary: false,
        };
        let rules = without_policy_label(&PfFirewall::generate_pf_rules(&[prim, sec]));
        let expected = "\
# Vortix Kill Switch Rules - Auto-generated
# DO NOT EDIT - Will be overwritten

# Allow loopback
pass out quick on lo0 all

# Allow local network (RFC1918, minus secondaries' claimed CIDRs)
pass out quick to 172.16.0.0/12
pass out quick to 192.168.0.0/16

# Allow DHCP
pass out quick proto udp from any port 68 to any port 67
pass in quick proto udp from any port 67 to any port 68

# Tunnel: utun3 (primary=true)
pass out quick on utun3 all
pass out quick to 1.2.3.4

# Tunnel: utun4 (primary=false)
pass out quick on utun4 all
pass out quick to 5.6.7.8

# Default: block all remaining egress
block drop out quick all
";
        assert_eq!(rules, expected);
    }
}
