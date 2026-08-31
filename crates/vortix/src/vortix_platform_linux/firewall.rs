//! Linux iptables/nftables firewall implementation for kill switch.
//!
//! Prefers iptables when available, falls back to nftables (nft).
//!
//! The iptables backend owns one chain per address family and updates it with
//! `iptables-restore --noflush`. Host filter tables and policies remain
//! untouched. The nftables backend owns one table and replaces it in a single
//! nft transaction.
//!
//! Ruleset shape (per active tunnel set):
//!   1. A Vortix-owned OUTPUT chain ending in DROP.
//!   2. Loopback always allowed.
//!   3. RFC1918 pass list, with secondaries' `declared_cidrs` subtracted
//!      via `cidr_subtract`. Primaries (`is_primary == true`) do NOT
//!      contribute to the remove list — their interface allow rule covers
//!      their egress, and subtracting `0.0.0.0/0` would carve loopback.
//!      See Q-DEF-9 / D-6.
//!   4. DHCP allowed (`udp --sport 68 --dport 67`).
//!   5. Per-tunnel: `-o <interface> -j ACCEPT` and one `-d <server-ip> -j
//!      ACCEPT` per server IP — so the tunnel can reconnect after a
//!      transport drop. IPv4 server IPs go into the v4 ruleset;
//!      IPv6 server IPs route to a parallel `ip6tables-restore` invocation.
//!
//! An empty `active` slice yields rules 1-4 only — the base block-all
//! posture with no per-tunnel egress.

use std::fmt::Write;
use std::net::IpAddr;

use crate::vortix_core::cidr::{rfc1918_ranges, Cidr};
use crate::vortix_core::cidr_subtract::cidr_subtract;
use crate::vortix_core::ports::killswitch::{
    ActiveTunnelInfo, Killswitch, KillswitchError, Result,
};
use crate::vortix_process::{CommandSpec, PrivilegeReq};
use tracing::{debug, error, info};

const CHAIN_NAME: &str = "VORTIX_KILLSWITCH";
const NFT_TABLE: &str = "vortix_killswitch";
const POLICY_COMMENT_PREFIX: &str = "vortix-policy:";
const NFT_MISSING_ERROR: &str = "No such file or directory";

/// Detected firewall backend on this system.
enum FirewallBackend {
    Iptables,
    Nftables,
}

#[derive(Clone, Copy)]
enum NftBatchMode {
    Create,
    Replace,
}

/// Linux firewall implementation supporting iptables and nftables.
pub struct IptablesFirewall;

impl IptablesFirewall {
    /// Detect which firewall backend is available, preferring iptables.
    fn detect_backend() -> Option<FirewallBackend> {
        if Self::has_iptables() {
            Some(FirewallBackend::Iptables)
        } else if Self::has_nft() {
            Some(FirewallBackend::Nftables)
        } else {
            None
        }
    }

    fn has_iptables() -> bool {
        crate::vortix_process::run_to_output(CommandSpec::oneshot(
            "iptables",
            vec!["--version".into()],
        ))
        .is_ok_and(|o| o.status.success())
    }

    fn has_nft() -> bool {
        crate::vortix_process::run_to_output(Self::nft_command(vec!["--version".into()]))
            .is_ok_and(|o| o.status.success())
    }

    fn nft_command(args: Vec<String>) -> CommandSpec {
        let mut command = CommandSpec::oneshot("nft", args);
        command.env.insert("LC_ALL".to_string(), "C".to_string());
        command
    }

    // ─── iptables backend ───────────────────────────────────────────────

    /// Synthesise the IPv4 `iptables-restore` ruleset for the given active
    /// tunnel set. Pure function — no side effects, deterministic for
    /// snapshot testing.
    ///
    /// Ruleset shape: see module-level docs. Empty `active` → rules 1-4
    /// only (base block-all).
    #[must_use]
    pub fn generate_v4_ruleset(active: &[ActiveTunnelInfo]) -> String {
        let mut rules = String::new();
        writeln!(rules, "# Vortix Kill Switch Rules - Auto-generated").unwrap();
        writeln!(rules, "# DO NOT EDIT - Will be overwritten").unwrap();
        writeln!(rules, "*filter").unwrap();
        writeln!(rules, ":{CHAIN_NAME} - [0:0]").unwrap();
        writeln!(rules, "-F {CHAIN_NAME}").unwrap();

        // Allow loopback.
        writeln!(rules, "-A {CHAIN_NAME} -o lo -j ACCEPT").unwrap();

        // RFC1918, with secondaries' declared CIDRs carved out. Primaries
        // (0/0) are excluded from the remove list per Q-DEF-9 / D-6 — their
        // interface allow rule covers egress, and subtracting the default
        // route would strip loopback.
        let secondary_cidrs: Vec<Cidr> = active
            .iter()
            .filter(|t| !t.is_primary)
            .flat_map(|t| t.declared_cidrs.iter().copied())
            .collect();
        let rfc1918 = cidr_subtract(&rfc1918_ranges(), &secondary_cidrs);
        for c in &rfc1918 {
            writeln!(rules, "-A {CHAIN_NAME} -d {c} -j ACCEPT").unwrap();
        }

        // DHCP — must precede the per-tunnel rules so a DHCP renew on the
        // underlay isn't dropped.
        writeln!(
            rules,
            "-A {CHAIN_NAME} -p udp --sport 68 --dport 67 -j ACCEPT"
        )
        .unwrap();

        // Per-tunnel rules. Order preserved from caller — typically
        // primary first, then secondaries by attach order.
        for tunnel in active {
            writeln!(
                rules,
                "# Tunnel: {} (primary={})",
                tunnel.interface, tunnel.is_primary
            )
            .unwrap();
            writeln!(rules, "-A {CHAIN_NAME} -o {} -j ACCEPT", tunnel.interface).unwrap();
            for ip in &tunnel.server_ips {
                if let IpAddr::V4(v4) = ip {
                    writeln!(rules, "-A {CHAIN_NAME} -d {v4} -j ACCEPT").unwrap();
                }
            }
        }

        let digest = crate::core::killswitch::policy_digest(active);
        writeln!(
            rules,
            "-A {CHAIN_NAME} -m comment --comment {POLICY_COMMENT_PREFIX}{digest} -j DROP"
        )
        .unwrap();

        writeln!(rules, "COMMIT").unwrap();
        rules
    }

    /// Synthesise the IPv6 `ip6tables-restore` ruleset. Same shape as v4
    /// but without RFC1918 carve-out (RFC1918 is v4-only). Only IPv6
    /// server IPs are emitted as owned-chain destination exceptions.
    ///
    #[must_use]
    pub fn generate_v6_ruleset(active: &[ActiveTunnelInfo]) -> String {
        let mut rules = String::new();
        writeln!(rules, "# Vortix Kill Switch Rules (IPv6) - Auto-generated").unwrap();
        writeln!(rules, "# DO NOT EDIT - Will be overwritten").unwrap();
        writeln!(rules, "*filter").unwrap();
        writeln!(rules, ":{CHAIN_NAME} - [0:0]").unwrap();
        writeln!(rules, "-F {CHAIN_NAME}").unwrap();

        // Loopback (v6 lo is the same interface name).
        writeln!(rules, "-A {CHAIN_NAME} -o lo -j ACCEPT").unwrap();

        // Every tunnel interface is allowed in both families. Endpoint
        // family only selects the reconnect exception.
        for tunnel in active {
            let v6_ips: Vec<&IpAddr> = tunnel.server_ips.iter().filter(|ip| ip.is_ipv6()).collect();
            writeln!(
                rules,
                "# Tunnel: {} (primary={})",
                tunnel.interface, tunnel.is_primary
            )
            .unwrap();
            writeln!(rules, "-A {CHAIN_NAME} -o {} -j ACCEPT", tunnel.interface).unwrap();
            for ip in v6_ips {
                if let IpAddr::V6(v6) = ip {
                    writeln!(rules, "-A {CHAIN_NAME} -d {v6} -j ACCEPT").unwrap();
                }
            }
        }

        let digest = crate::core::killswitch::policy_digest(active);
        writeln!(
            rules,
            "-A {CHAIN_NAME} -m comment --comment {POLICY_COMMENT_PREFIX}{digest} -j DROP"
        )
        .unwrap();

        writeln!(rules, "COMMIT").unwrap();
        rules
    }

    /// Invoke `iptables-restore` with the given ruleset on stdin. The
    /// kernel performs an atomic ruleset replace — if the parse fails,
    /// the prior ruleset stays in force, no leak window.
    fn iptables_restore_stdin(program: &str, ruleset: &[u8]) -> std::result::Result<(), String> {
        let output = crate::vortix_process::run_to_output(
            CommandSpec::oneshot(program, vec!["--noflush".into()])
                .privilege(PrivilegeReq::Root)
                .stdin(ruleset.to_vec()),
        )
        .map_err(|e| format!("Failed to spawn {program}: {e}"))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    fn iptables_command(program: &str, args: &[&str]) -> std::result::Result<bool, String> {
        let args = args.iter().map(|arg| (*arg).to_string()).collect();
        let output = crate::vortix_process::run_to_output(
            CommandSpec::oneshot(program, args).privilege(PrivilegeReq::Root),
        )
        .map_err(|e| format!("Failed to run {program}: {e}"))?;
        Ok(output.status.success())
    }

    fn iptables_snapshot(program: &str) -> std::result::Result<String, String> {
        let output = crate::vortix_process::run_to_output(
            CommandSpec::oneshot(program, vec!["-t".into(), "filter".into()])
                .privilege(PrivilegeReq::Root),
        )
        .map_err(|e| format!("Failed to run {program}: {e}"))?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned());
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn ensure_iptables_jump(program: &str) -> std::result::Result<(), String> {
        let listing = Self::iptables_listing(program, "OUTPUT")?;
        if Self::output_jump_is_first(&listing) {
            return Ok(());
        }
        // Insert the enforcing first-position jump before touching any stale
        // later duplicate. Removing the only live jump first would create a
        // leak window. Later duplicates are harmless and teardown removes all.
        if Self::iptables_command(program, &["-I", "OUTPUT", "1", "-j", CHAIN_NAME])? {
            let listing = Self::iptables_listing(program, "OUTPUT")?;
            if Self::output_jump_is_first(&listing) {
                Ok(())
            } else {
                Err(format!("{program} read-back did not place Vortix first"))
            }
        } else {
            Err(format!(
                "{program} could not install the Vortix OUTPUT jump"
            ))
        }
    }

    fn iptables_listing(program: &str, chain: &str) -> std::result::Result<String, String> {
        let output = crate::vortix_process::run_to_output(
            CommandSpec::oneshot(program, vec!["-S".into(), chain.into()])
                .privilege(PrivilegeReq::Root),
        )
        .map_err(|error| format!("Failed to run {program} -S {chain}: {error}"))?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned());
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn output_jump_is_first(listing: &str) -> bool {
        let expected = format!("-A OUTPUT -j {CHAIN_NAME}");
        listing.lines().find(|line| line.starts_with("-A OUTPUT ")) == Some(expected.as_str())
    }

    fn canonical_owned_iptables_rules(rules: &str) -> Vec<String> {
        rules
            .lines()
            .filter(|line| line.starts_with(&format!("-A {CHAIN_NAME} ")))
            .map(|line| {
                line.replace("--comment \"", "--comment ")
                    .replace("\" -j", " -j")
                    .replace("-p udp -m udp", "-p udp")
                    .replace("/32 ", " ")
                    .replace("/128 ", " ")
            })
            .collect()
    }

    fn snapshot_verifies_iptables(snapshot: &str, expected_ruleset: &str) -> bool {
        let expected_jump = format!("-A OUTPUT -j {CHAIN_NAME}");
        let jump_first = snapshot.lines().find(|line| line.starts_with("-A OUTPUT "))
            == Some(expected_jump.as_str());
        jump_first
            && snapshot.contains(&format!(":{CHAIN_NAME} "))
            && Self::canonical_owned_iptables_rules(snapshot)
                == Self::canonical_owned_iptables_rules(expected_ruleset)
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

    fn verify_iptables_policy(
        save_program: &str,
        expected_ruleset: &str,
        digest: &str,
    ) -> std::result::Result<(), String> {
        let snapshot = Self::iptables_snapshot(save_program)?;
        if Self::snapshot_verifies_iptables(&snapshot, expected_ruleset) {
            Ok(())
        } else {
            Err(format!(
                "{save_program} read-back did not match policy {digest}"
            ))
        }
    }

    /// Engage the killswitch via atomic `iptables-restore`. Both fresh
    /// enable and refresh-with-different-active-set go through this single
    /// path — no flush-then-rebuild window.
    fn setup_iptables(active: &[ActiveTunnelInfo]) -> Result<()> {
        let v4 = Self::generate_v4_ruleset(active);
        debug!(
            target: "vortix::killswitch",
            bytes = v4.len(),
            tunnels = active.len(),
            "loading iptables ruleset via iptables-restore stdin"
        );
        Self::iptables_restore_stdin("iptables-restore", v4.as_bytes()).map_err(|e| {
            error!(target: "vortix::killswitch", stderr = %e, "iptables-restore failed");
            KillswitchError::CommandFailed(format!("iptables-restore: {e}"))
        })?;

        Self::ensure_iptables_jump("iptables").map_err(KillswitchError::CommandFailed)?;

        let v6 = Self::generate_v6_ruleset(active);
        debug!(
            target: "vortix::killswitch",
            bytes = v6.len(),
            "loading ip6tables ruleset via ip6tables-restore stdin"
        );
        Self::iptables_restore_stdin("ip6tables-restore", v6.as_bytes()).map_err(|e| {
            error!(target: "vortix::killswitch", stderr = %e, "ip6tables-restore failed");
            KillswitchError::CommandFailed(format!("ip6tables-restore: {e}"))
        })?;
        Self::ensure_iptables_jump("ip6tables").map_err(KillswitchError::CommandFailed)?;

        let digest = crate::core::killswitch::policy_digest(active);
        Self::verify_iptables_policy("iptables-save", &v4, &digest)
            .map_err(KillswitchError::CommandFailed)?;
        Self::verify_iptables_policy("ip6tables-save", &v6, &digest)
            .map_err(KillswitchError::CommandFailed)?;

        Ok(())
    }

    /// Tear down iptables state. Restore the default-ACCEPT OUTPUT policy
    /// via a minimal `iptables-restore` ruleset, and remove any legacy
    /// `VORTIX_KILLSWITCH` chain the legacy implementation may have left
    /// behind.
    fn teardown_iptables() -> Result<()> {
        for (command, save) in [
            ("iptables", "iptables-save"),
            ("ip6tables", "ip6tables-save"),
        ] {
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
            let mut snapshot =
                Self::iptables_snapshot(save).map_err(KillswitchError::CommandFailed)?;
            let ipv6 = command == "ip6tables";
            if Self::is_legacy_global_policy(&snapshot, ipv6) {
                // v0.4.3 and earlier owned the global OUTPUT policy. Only
                // reset it after the strict legacy-shape check proves every
                // remaining OUTPUT rule belongs to that displaced design.
                // The policy change and flush share one restore transaction.
                let restore = if ipv6 {
                    "ip6tables-restore"
                } else {
                    "iptables-restore"
                };
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
        Ok(())
    }

    // ─── nftables backend ───────────────────────────────────────────────

    /// Build an nft transaction that creates the Vortix-owned table or
    /// atomically deletes and recreates an existing one. `destroy` is avoided
    /// because supported Ubuntu releases still ship nft clients older than
    /// 1.0.7, where that command was introduced.
    #[must_use]
    fn generate_nft_ruleset(active: &[ActiveTunnelInfo], mode: NftBatchMode) -> String {
        let secondary_cidrs: Vec<Cidr> = active
            .iter()
            .filter(|tunnel| !tunnel.is_primary)
            .flat_map(|tunnel| tunnel.declared_cidrs.iter().copied())
            .collect();
        let local_ranges = cidr_subtract(&rfc1918_ranges(), &secondary_cidrs);
        let digest = crate::core::killswitch::policy_digest(active);

        let mut ruleset = String::new();
        if matches!(mode, NftBatchMode::Replace) {
            writeln!(ruleset, "delete table inet {NFT_TABLE}").unwrap();
        }
        write!(
            ruleset,
            r#"table inet {NFT_TABLE} {{
  chain output {{
    type filter hook output priority 0; policy drop;

    oifname "lo" accept
"#,
        )
        .unwrap();
        for range in local_ranges {
            writeln!(ruleset, "    ip daddr {range} accept").unwrap();
        }
        writeln!(ruleset, "    udp sport 68 udp dport 67 accept").unwrap();
        for tunnel in active {
            writeln!(ruleset, "    oifname \"{}\" accept", tunnel.interface).unwrap();
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

    fn nft_table_snapshot() -> Result<Option<String>> {
        let output = crate::vortix_process::run_to_output(
            Self::nft_command(vec![
                "list".into(),
                "table".into(),
                "inet".into(),
                NFT_TABLE.into(),
            ])
            .privilege(PrivilegeReq::Root),
        )
        .map_err(|error| KillswitchError::CommandFailed(format!("nft read-back: {error}")))?;
        if output.status.success() {
            return Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()));
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains(NFT_MISSING_ERROR) {
            Ok(None)
        } else {
            Err(KillswitchError::CommandFailed(format!(
                "nft read-back failed ambiguously: {stderr}"
            )))
        }
    }

    fn apply_nft_batch(
        active: &[ActiveTunnelInfo],
        mode: NftBatchMode,
    ) -> Result<std::process::Output> {
        let ruleset = Self::generate_nft_ruleset(active, mode);
        crate::vortix_process::run_to_output(
            Self::nft_command(vec!["-f".into(), "-".into()])
                .privilege(PrivilegeReq::Root)
                .stdin(ruleset.into_bytes()),
        )
        .map_err(|error| KillswitchError::CommandFailed(format!("nft spawn: {error}")))
    }

    fn nft_snapshot_matches(active: &[ActiveTunnelInfo], snapshot: &str) -> bool {
        let secondary_cidrs: Vec<Cidr> = active
            .iter()
            .filter(|tunnel| !tunnel.is_primary)
            .flat_map(|tunnel| tunnel.declared_cidrs.iter().copied())
            .collect();
        let mut expected = vec!["oifname \"lo\" accept".to_string()];
        expected.extend(
            cidr_subtract(&rfc1918_ranges(), &secondary_cidrs)
                .into_iter()
                .map(|range| format!("ip daddr {range} accept")),
        );
        expected.push("udp sport 68 udp dport 67 accept".to_string());
        for tunnel in active {
            expected.push(format!("oifname \"{}\" accept", tunnel.interface));
            expected.extend(tunnel.server_ips.iter().map(|endpoint| match endpoint {
                IpAddr::V4(ip) => format!("ip daddr {ip} accept"),
                IpAddr::V6(ip) => format!("ip6 daddr {ip} accept"),
            }));
        }

        let accept_lines: Vec<&str> = snapshot
            .lines()
            .map(str::trim)
            .filter(|line| line.ends_with(" accept"))
            .collect();
        let ordered = accept_lines.len() == expected.len()
            && accept_lines
                .iter()
                .zip(&expected)
                .all(|(observed, expected)| observed == expected);
        let digest = crate::core::killswitch::policy_digest(active);
        let terminal_lines: Vec<&str> = snapshot
            .lines()
            .map(str::trim)
            .filter(|line| line.contains(POLICY_COMMENT_PREFIX))
            .collect();
        ordered
            && snapshot.contains("policy drop")
            && terminal_lines.len() == 1
            && terminal_lines[0].contains(" drop ")
            && terminal_lines[0].contains(&format!("{POLICY_COMMENT_PREFIX}{digest}"))
    }

    fn setup_nftables(active: &[ActiveTunnelInfo]) -> Result<()> {
        let mut output = Self::apply_nft_batch(active, NftBatchMode::Replace)?;
        let mut verified_snapshot = None;
        if !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains(NFT_MISSING_ERROR)
        {
            output = Self::apply_nft_batch(active, NftBatchMode::Create)?;
            if !output.status.success() {
                match Self::nft_table_snapshot()? {
                    Some(snapshot) if Self::nft_snapshot_matches(active, &snapshot) => {
                        verified_snapshot = Some(snapshot);
                    }
                    Some(_) => {
                        output = Self::apply_nft_batch(active, NftBatchMode::Replace)?;
                    }
                    None => {}
                }
            }
        }

        if verified_snapshot.is_none() && !output.status.success() {
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
        if !Self::nft_snapshot_matches(active, &snapshot) {
            return Err(KillswitchError::CommandFailed(
                "nft read-back did not match the requested policy".to_string(),
            ));
        }

        Ok(())
    }

    /// Remove the kill switch nftables table.
    fn teardown_nftables() -> Result<()> {
        let delete = crate::vortix_process::run_to_output(
            Self::nft_command(vec![
                "delete".into(),
                "table".into(),
                "inet".into(),
                NFT_TABLE.into(),
            ])
            .privilege(PrivilegeReq::Root),
        )
        .map_err(|error| KillswitchError::CommandFailed(format!("nft delete: {error}")))?;
        let delete_error = String::from_utf8_lossy(&delete.stderr);
        if !delete.status.success() && !delete_error.contains(NFT_MISSING_ERROR) {
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

impl Killswitch for IptablesFirewall {
    /// Engage the killswitch with a ruleset covering every tunnel in
    /// `active`. The iptables backend pipes a full ruleset through
    /// `iptables-restore` (and `ip6tables-restore` when any tunnel has
    /// IPv6 server IPs), producing an atomic in-kernel replace. Both
    /// fresh enable and refresh-with-different-active-set go through this
    /// single path — no flush-then-rebuild leak window.
    ///
    /// Empty `active` slice installs the base block-all ruleset (rules
    /// 1-4 only) — used during early bring-up and on hard-fail Armed
    /// states.
    fn enable_blocking_multi(active: &[ActiveTunnelInfo]) -> Result<()> {
        if !crate::utils::is_root() {
            error!(target: "vortix::killswitch", "kill switch requires root privileges");
            return Err(KillswitchError::NotRoot);
        }

        crate::core::killswitch::validate_policy(active)?;

        info!(
            target: "vortix::killswitch",
            tunnels = active.len(),
            "killswitch.engage"
        );

        match Self::detect_backend() {
            Some(FirewallBackend::Iptables) => {
                debug!(target: "vortix::killswitch", "using iptables backend (iptables-restore atomic)");
                Self::setup_iptables(active)?;
            }
            Some(FirewallBackend::Nftables) => {
                debug!(target: "vortix::killswitch", "using nftables backend");
                Self::setup_nftables(active)?;
            }
            None => {
                return Err(KillswitchError::NoBackendAvailable);
            }
        }

        info!(
            target: "vortix::killswitch",
            tunnels = active.len(),
            "kill switch ACTIVE — blocking non-VPN traffic"
        );
        Ok(())
    }

    fn disable_blocking() -> Result<()> {
        info!(target: "vortix::killswitch", "disabling kill switch");

        if !crate::utils::is_root() {
            error!(target: "vortix::killswitch", "disabling kill switch requires root");
            return Err(KillswitchError::NotRoot);
        }

        let mut found = false;
        if Self::has_iptables() {
            found = true;
            Self::teardown_iptables()?;
        }
        if Self::has_nft() {
            found = true;
            Self::teardown_nftables()?;
        }
        if !found {
            return Err(KillswitchError::NoBackendAvailable);
        }

        info!(target: "vortix::killswitch", "kill switch DISABLED — normal traffic restored");
        Ok(())
    }
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

    // ─── v4 ruleset generation ──────────────────────────────────────────

    #[test]
    fn empty_active_set_yields_base_blockall() {
        let rules = IptablesFirewall::generate_v4_ruleset(&[]);
        assert!(rules.contains("*filter"));
        assert!(rules.contains(":VORTIX_KILLSWITCH - [0:0]"));
        assert!(rules.contains("-A VORTIX_KILLSWITCH -o lo -j ACCEPT"));
        // Full RFC1918 base intact.
        assert!(rules.contains("-A VORTIX_KILLSWITCH -d 10.0.0.0/8 -j ACCEPT"));
        assert!(rules.contains("-A VORTIX_KILLSWITCH -d 172.16.0.0/12 -j ACCEPT"));
        assert!(rules.contains("-A VORTIX_KILLSWITCH -d 192.168.0.0/16 -j ACCEPT"));
        // DHCP present.
        assert!(rules.contains("--sport 68 --dport 67"));
        // No per-tunnel rules.
        assert!(!rules.contains("# Tunnel:"));
        assert!(rules.trim_end().ends_with("COMMIT"));
    }

    #[test]
    fn single_primary_zero_slash_zero_keeps_full_rfc1918() {
        // A primary tunnel declaring 0.0.0.0/0 must NOT subtract from
        // RFC1918 — its interface allow covers egress, and subtracting
        // the default route would carve loopback. See D-6.
        let t = tunnel("wg0", &["1.2.3.4"], &["0.0.0.0/0"], true);
        let rules = IptablesFirewall::generate_v4_ruleset(&[t]);
        assert!(rules.contains("-A VORTIX_KILLSWITCH -d 10.0.0.0/8 -j ACCEPT"));
        assert!(rules.contains("-A VORTIX_KILLSWITCH -d 172.16.0.0/12 -j ACCEPT"));
        assert!(rules.contains("-A VORTIX_KILLSWITCH -d 192.168.0.0/16 -j ACCEPT"));
        assert!(rules.contains("-A VORTIX_KILLSWITCH -o wg0 -j ACCEPT"));
        assert!(rules.contains("-A VORTIX_KILLSWITCH -d 1.2.3.4 -j ACCEPT"));
    }

    #[test]
    fn single_secondary_ten_dot_carves_rfc1918() {
        // A secondary claiming 10/8 should remove that block from the
        // RFC1918 pass list. 172.16/12 + 192.168/16 remain.
        let t = tunnel("wg1", &["5.6.7.8"], &["10.0.0.0/8"], false);
        let rules = IptablesFirewall::generate_v4_ruleset(&[t]);
        assert!(!rules.contains("-A VORTIX_KILLSWITCH -d 10.0.0.0/8 -j ACCEPT"));
        assert!(rules.contains("-A VORTIX_KILLSWITCH -d 172.16.0.0/12 -j ACCEPT"));
        assert!(rules.contains("-A VORTIX_KILLSWITCH -d 192.168.0.0/16 -j ACCEPT"));
        assert!(rules.contains("-A VORTIX_KILLSWITCH -o wg1 -j ACCEPT"));
        assert!(rules.contains("-A VORTIX_KILLSWITCH -d 5.6.7.8 -j ACCEPT"));
    }

    #[test]
    fn two_secondaries_disjoint_carve_correctly() {
        // wg1 claims 10/8, wg2 claims 192.168/16. Result: only 172.16/12
        // remains in the RFC1918 list.
        let t1 = tunnel("wg1", &["1.1.1.1"], &["10.0.0.0/8"], false);
        let t2 = tunnel("wg2", &["2.2.2.2"], &["192.168.0.0/16"], false);
        let rules = IptablesFirewall::generate_v4_ruleset(&[t1, t2]);
        assert!(!rules.contains("-A VORTIX_KILLSWITCH -d 10.0.0.0/8 -j ACCEPT"));
        assert!(rules.contains("-A VORTIX_KILLSWITCH -d 172.16.0.0/12 -j ACCEPT"));
        assert!(!rules.contains("-A VORTIX_KILLSWITCH -d 192.168.0.0/16 -j ACCEPT"));
        // Both interfaces appear.
        assert!(rules.contains("-A VORTIX_KILLSWITCH -o wg1 -j ACCEPT"));
        assert!(rules.contains("-A VORTIX_KILLSWITCH -o wg2 -j ACCEPT"));
        assert!(rules.contains("-A VORTIX_KILLSWITCH -d 1.1.1.1 -j ACCEPT"));
        assert!(rules.contains("-A VORTIX_KILLSWITCH -d 2.2.2.2 -j ACCEPT"));
    }

    #[test]
    fn two_secondaries_overlapping_dont_double_subtract() {
        // wg3 claims 10/8, wg4 claims 10.5/16 (a subset). Result is
        // identical to subtracting just 10/8.
        let t1 = tunnel("wg3", &["1.1.1.1"], &["10.0.0.0/8"], false);
        let t2 = tunnel("wg4", &["2.2.2.2"], &["10.5.0.0/16"], false);
        let rules = IptablesFirewall::generate_v4_ruleset(&[t1, t2]);
        // No 10.* leftover anywhere in the RFC1918 ACCEPT lines.
        assert!(!rules.contains("-A VORTIX_KILLSWITCH -d 10."));
        assert!(rules.contains("-A VORTIX_KILLSWITCH -d 172.16.0.0/12 -j ACCEPT"));
        assert!(rules.contains("-A VORTIX_KILLSWITCH -d 192.168.0.0/16 -j ACCEPT"));
    }

    #[test]
    fn primary_plus_secondary_only_secondary_carves() {
        // Primary 0/0 + secondary 10/8 — only the secondary subtracts.
        let prim = tunnel("wg0", &["9.9.9.9"], &["0.0.0.0/0"], true);
        let sec = tunnel("wg1", &["8.8.8.8"], &["10.0.0.0/8"], false);
        let rules = IptablesFirewall::generate_v4_ruleset(&[prim, sec]);
        // 10/8 is gone.
        assert!(!rules.contains("-A VORTIX_KILLSWITCH -d 10.0.0.0/8 -j ACCEPT"));
        // 172.16 and 192.168 intact.
        assert!(rules.contains("-A VORTIX_KILLSWITCH -d 172.16.0.0/12 -j ACCEPT"));
        assert!(rules.contains("-A VORTIX_KILLSWITCH -d 192.168.0.0/16 -j ACCEPT"));
        // Both interfaces present.
        assert!(rules.contains("-A VORTIX_KILLSWITCH -o wg0 -j ACCEPT"));
        assert!(rules.contains("-A VORTIX_KILLSWITCH -o wg1 -j ACCEPT"));
    }

    #[test]
    fn tunnel_with_no_server_ips_still_gets_interface_rule() {
        let t = tunnel("wg5", &[], &[], true);
        let rules = IptablesFirewall::generate_v4_ruleset(&[t]);
        assert!(rules.contains("-A VORTIX_KILLSWITCH -o wg5 -j ACCEPT"));
        // No spurious -d <ip> line for the empty server list — count
        // occurrences of "wg5" — should appear exactly once on its own
        // interface allow line plus once in the "# Tunnel:" comment.
        let occurrences = rules.matches("wg5").count();
        assert_eq!(
            occurrences, 2,
            "wg5 should appear exactly twice (comment + rule), got ruleset:\n{rules}"
        );
    }

    #[test]
    fn tunnel_with_multiple_server_ips_emits_one_pass_per_ip() {
        let t = tunnel("wg6", &["1.2.3.4", "5.6.7.8"], &[], true);
        let rules = IptablesFirewall::generate_v4_ruleset(&[t]);
        assert!(rules.contains("-A VORTIX_KILLSWITCH -d 1.2.3.4 -j ACCEPT"));
        assert!(rules.contains("-A VORTIX_KILLSWITCH -d 5.6.7.8 -j ACCEPT"));
    }

    // ─── v6 ruleset generation ──────────────────────────────────────────

    #[test]
    fn no_v6_server_ips_still_yields_default_deny_v6_ruleset() {
        // IPv6 must remain default-deny even when every tunnel endpoint is
        // IPv4. Endpoint family controls reconnect exceptions, never whether
        // the IPv6 policy exists.
        let t = tunnel("wg0", &["1.2.3.4"], &[], true);
        let with_tunnel = IptablesFirewall::generate_v6_ruleset(&[t]);
        assert!(with_tunnel.contains(":VORTIX_KILLSWITCH - [0:0]"));
        assert!(with_tunnel.contains("-A VORTIX_KILLSWITCH -o wg0 -j ACCEPT"));
        assert!(with_tunnel.contains("-j DROP"));

        let empty = IptablesFirewall::generate_v6_ruleset(&[]);
        assert!(empty.contains("-A VORTIX_KILLSWITCH -o lo -j ACCEPT"));
        assert!(empty.contains("-j DROP"));
    }

    #[test]
    fn v6_server_ip_routes_to_ip6tables_ruleset() {
        let t = ActiveTunnelInfo {
            interface: "wg7".to_string(),
            server_ips: vec!["2001:db8::1".parse().unwrap()],
            declared_cidrs: vec![],
            is_primary: true,
        };
        let v6 = IptablesFirewall::generate_v6_ruleset(&[t]);
        assert!(v6.contains("*filter"));
        assert!(v6.contains(":VORTIX_KILLSWITCH - [0:0]"));
        assert!(v6.contains("-A VORTIX_KILLSWITCH -o lo -j ACCEPT"));
        assert!(v6.contains("-A VORTIX_KILLSWITCH -o wg7 -j ACCEPT"));
        assert!(v6.contains("-A VORTIX_KILLSWITCH -d 2001:db8::1 -j ACCEPT"));
        assert!(v6.trim_end().ends_with("COMMIT"));
    }

    #[test]
    fn mixed_v4_and_v6_server_ips_emit_both_rulesets() {
        let t = ActiveTunnelInfo {
            interface: "wg8".to_string(),
            server_ips: vec![ip("1.2.3.4"), "2001:db8::1".parse().unwrap()],
            declared_cidrs: vec![],
            is_primary: true,
        };
        let v4 = IptablesFirewall::generate_v4_ruleset(std::slice::from_ref(&t));
        let v6 = IptablesFirewall::generate_v6_ruleset(std::slice::from_ref(&t));
        // v4 ruleset has the v4 server IP, not the v6 one.
        assert!(v4.contains("-A VORTIX_KILLSWITCH -d 1.2.3.4 -j ACCEPT"));
        assert!(!v4.contains("2001:db8"));
        // v6 ruleset has the v6 server IP, not the v4 one.
        assert!(v6.contains("-A VORTIX_KILLSWITCH -d 2001:db8::1 -j ACCEPT"));
        assert!(!v6.contains("1.2.3.4"));
    }

    #[test]
    fn v6_ruleset_allows_every_tunnel_interface_but_only_v6_endpoints() {
        let t9 = tunnel("wg9", &["1.2.3.4"], &[], true);
        let t10 = ActiveTunnelInfo {
            interface: "wg10".to_string(),
            server_ips: vec!["2001:db8::1".parse().unwrap()],
            declared_cidrs: vec![],
            is_primary: false,
        };
        let v6 = IptablesFirewall::generate_v6_ruleset(&[t9, t10]);
        assert!(v6.contains("-A VORTIX_KILLSWITCH -o wg9 -j ACCEPT"));
        assert!(v6.contains("-A VORTIX_KILLSWITCH -o wg10 -j ACCEPT"));
        assert!(v6.contains("-A VORTIX_KILLSWITCH -d 2001:db8::1 -j ACCEPT"));
    }

    #[test]
    fn iptables_rulesets_only_replace_vortix_owned_chains() {
        let tunnel = tunnel("wg0", &["1.2.3.4"], &["0.0.0.0/0"], true);
        for rules in [
            IptablesFirewall::generate_v4_ruleset(std::slice::from_ref(&tunnel)),
            IptablesFirewall::generate_v6_ruleset(std::slice::from_ref(&tunnel)),
        ] {
            assert!(rules.contains(":VORTIX_KILLSWITCH - [0:0]"));
            assert!(rules.contains("-F VORTIX_KILLSWITCH"));
            assert!(!rules.contains(":INPUT"));
            assert!(!rules.contains(":FORWARD"));
            assert!(!rules.contains(":OUTPUT"));
            assert!(!rules.contains("-F OUTPUT"));
        }
    }

    #[test]
    fn iptables_readback_requires_first_jump_and_marker_bound_drop() {
        let expected = "*filter\n:VORTIX_KILLSWITCH - [0:0]\n-A VORTIX_KILLSWITCH -o lo -j ACCEPT\n-A VORTIX_KILLSWITCH -m comment --comment vortix-policy:abc123 -j DROP\nCOMMIT\n";
        let valid = "*filter\n:VORTIX_KILLSWITCH - [0:0]\n-A OUTPUT -j VORTIX_KILLSWITCH\n-A OUTPUT -d 203.0.113.1 -j ACCEPT\n-A VORTIX_KILLSWITCH -o lo -j ACCEPT\n-A VORTIX_KILLSWITCH -m comment --comment \"vortix-policy:abc123\" -j DROP\nCOMMIT\n";
        assert!(IptablesFirewall::snapshot_verifies_iptables(
            valid, expected
        ));
        assert!(IptablesFirewall::output_jump_is_first(
            "-P OUTPUT ACCEPT\n-A OUTPUT -j VORTIX_KILLSWITCH\n-A OUTPUT -j ACCEPT\n"
        ));

        let bypass = valid.replace(
            "-A OUTPUT -j VORTIX_KILLSWITCH\n",
            "-A OUTPUT -j ACCEPT\n-A OUTPUT -j VORTIX_KILLSWITCH\n",
        );
        assert!(!IptablesFirewall::snapshot_verifies_iptables(
            &bypass, expected
        ));

        let false_marker = valid.replace(
            "--comment \"vortix-policy:abc123\" -j DROP",
            "--comment \"vortix-policy:abc123\" -j ACCEPT",
        );
        assert!(!IptablesFirewall::snapshot_verifies_iptables(
            &false_marker,
            expected
        ));
        let missing_allow = valid.replace("-A VORTIX_KILLSWITCH -o lo -j ACCEPT\n", "");
        assert!(!IptablesFirewall::snapshot_verifies_iptables(
            &missing_allow,
            expected
        ));
    }

    #[test]
    fn legacy_global_policy_detection_is_strict() {
        let legacy_v4 = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT DROP [0:0]\n-A OUTPUT -o lo -j ACCEPT\n-A OUTPUT -p udp -m udp --sport 68 --dport 67 -j ACCEPT\nCOMMIT\n";
        assert!(IptablesFirewall::is_legacy_global_policy(legacy_v4, false));
        assert!(!IptablesFirewall::is_legacy_global_policy(
            &format!("{legacy_v4}-A INPUT -j ACCEPT\n"),
            false
        ));
        assert!(!IptablesFirewall::is_legacy_global_policy(
            &legacy_v4.replace(":OUTPUT DROP", ":OUTPUT ACCEPT"),
            false
        ));
        let host_owned_drop = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT DROP [0:0]\n-A OUTPUT -d 203.0.113.10 -j ACCEPT\nCOMMIT\n";
        assert!(!IptablesFirewall::is_legacy_global_policy(
            host_owned_drop,
            false
        ));
        assert_eq!(
            IptablesFirewall::legacy_cleanup_ruleset(),
            "*filter\n:OUTPUT ACCEPT [0:0]\n-F OUTPUT\nCOMMIT\n"
        );
    }

    #[test]
    fn nft_batches_support_old_clients_and_cover_two_tunnels_dual_stack() {
        let first = tunnel("wg0", &["1.2.3.4"], &["0.0.0.0/0"], true);
        let second = tunnel("wg1", &["2001:db8::1"], &["10.0.0.0/8"], false);
        let active = [first, second];
        let fresh = IptablesFirewall::generate_nft_ruleset(&active, NftBatchMode::Create);
        let replacement = IptablesFirewall::generate_nft_ruleset(&active, NftBatchMode::Replace);

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
        assert!(IptablesFirewall::nft_snapshot_matches(&active, &fresh));
        assert!(!IptablesFirewall::nft_snapshot_matches(
            &active,
            &fresh.replace("    oifname \"wg1\" accept\n", "")
        ));
        assert!(!IptablesFirewall::nft_snapshot_matches(
            &active,
            &fresh.replace("counter drop comment", "counter accept comment")
        ));
        assert_eq!(
            IptablesFirewall::nft_command(vec!["list".into()])
                .env
                .get("LC_ALL")
                .map(String::as_str),
            Some("C")
        );
    }

    // ─── snapshot tests pinning ruleset shape ───────────────────────────

    #[test]
    fn snapshot_empty_active_set() {
        let rules = IptablesFirewall::generate_v4_ruleset(&[]);
        let digest = crate::core::killswitch::policy_digest(&[]);
        let expected = format!(
            "\
# Vortix Kill Switch Rules - Auto-generated
# DO NOT EDIT - Will be overwritten
*filter
:VORTIX_KILLSWITCH - [0:0]
-F VORTIX_KILLSWITCH
-A VORTIX_KILLSWITCH -o lo -j ACCEPT
-A VORTIX_KILLSWITCH -d 10.0.0.0/8 -j ACCEPT
-A VORTIX_KILLSWITCH -d 172.16.0.0/12 -j ACCEPT
-A VORTIX_KILLSWITCH -d 192.168.0.0/16 -j ACCEPT
-A VORTIX_KILLSWITCH -p udp --sport 68 --dport 67 -j ACCEPT
-A VORTIX_KILLSWITCH -m comment --comment vortix-policy:{digest} -j DROP
COMMIT
"
        );
        assert_eq!(rules, expected);
    }

    #[test]
    fn snapshot_single_primary() {
        let t = ActiveTunnelInfo {
            interface: "wg0".to_string(),
            server_ips: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            declared_cidrs: vec![cidr("0.0.0.0/0")],
            is_primary: true,
        };
        let active = [t];
        let rules = IptablesFirewall::generate_v4_ruleset(&active);
        let digest = crate::core::killswitch::policy_digest(&active);
        let expected = format!(
            "\
# Vortix Kill Switch Rules - Auto-generated
# DO NOT EDIT - Will be overwritten
*filter
:VORTIX_KILLSWITCH - [0:0]
-F VORTIX_KILLSWITCH
-A VORTIX_KILLSWITCH -o lo -j ACCEPT
-A VORTIX_KILLSWITCH -d 10.0.0.0/8 -j ACCEPT
-A VORTIX_KILLSWITCH -d 172.16.0.0/12 -j ACCEPT
-A VORTIX_KILLSWITCH -d 192.168.0.0/16 -j ACCEPT
-A VORTIX_KILLSWITCH -p udp --sport 68 --dport 67 -j ACCEPT
# Tunnel: wg0 (primary=true)
-A VORTIX_KILLSWITCH -o wg0 -j ACCEPT
-A VORTIX_KILLSWITCH -d 1.2.3.4 -j ACCEPT
-A VORTIX_KILLSWITCH -m comment --comment vortix-policy:{digest} -j DROP
COMMIT
"
        );
        assert_eq!(rules, expected);
    }

    #[test]
    fn snapshot_primary_plus_secondary() {
        let prim = ActiveTunnelInfo {
            interface: "wg0".to_string(),
            server_ips: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            declared_cidrs: vec![cidr("0.0.0.0/0")],
            is_primary: true,
        };
        let sec = ActiveTunnelInfo {
            interface: "wg1".to_string(),
            server_ips: vec![IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))],
            declared_cidrs: vec![cidr("10.0.0.0/8")],
            is_primary: false,
        };
        let active = [prim, sec];
        let rules = IptablesFirewall::generate_v4_ruleset(&active);
        let digest = crate::core::killswitch::policy_digest(&active);
        let expected = format!(
            "\
# Vortix Kill Switch Rules - Auto-generated
# DO NOT EDIT - Will be overwritten
*filter
:VORTIX_KILLSWITCH - [0:0]
-F VORTIX_KILLSWITCH
-A VORTIX_KILLSWITCH -o lo -j ACCEPT
-A VORTIX_KILLSWITCH -d 172.16.0.0/12 -j ACCEPT
-A VORTIX_KILLSWITCH -d 192.168.0.0/16 -j ACCEPT
-A VORTIX_KILLSWITCH -p udp --sport 68 --dport 67 -j ACCEPT
# Tunnel: wg0 (primary=true)
-A VORTIX_KILLSWITCH -o wg0 -j ACCEPT
-A VORTIX_KILLSWITCH -d 1.2.3.4 -j ACCEPT
# Tunnel: wg1 (primary=false)
-A VORTIX_KILLSWITCH -o wg1 -j ACCEPT
-A VORTIX_KILLSWITCH -d 5.6.7.8 -j ACCEPT
-A VORTIX_KILLSWITCH -m comment --comment vortix-policy:{digest} -j DROP
COMMIT
"
        );
        assert_eq!(rules, expected);
    }
}
