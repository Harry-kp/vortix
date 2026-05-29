//! Linux iptables/nftables firewall implementation for kill switch.
//!
//! Prefers iptables when available, falls back to nftables (nft).
//!
//! Plan multi-connection U9: the iptables backend now synthesises the full
//! ruleset in memory and feeds it to `iptables-restore` (and
//! `ip6tables-restore` for IPv6 server IPs) via stdin. iptables-restore
//! performs an atomic in-kernel replace, so there is no leak window between
//! the previous and new rulesets — mirrors the `nft -f -` pattern already
//! in the nftables branch and the macOS `pfctl -f -` pattern from U10.
//!
//! Ruleset shape (per active tunnel set):
//!   1. Default-drop egress on OUTPUT.
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

use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::cidr_subtract::cidr_subtract;
use crate::vortix_core::ports::killswitch::{
    ActiveTunnelInfo, Killswitch, KillswitchError, Result,
};
use crate::vortix_process::{CommandSpec, PrivilegeReq};
use tracing::{debug, error, info};

const CHAIN_NAME: &str = "VORTIX_KILLSWITCH";
const NFT_TABLE: &str = "vortix_killswitch";

/// Detected firewall backend on this system.
enum FirewallBackend {
    Iptables,
    Nftables,
}

/// Linux firewall implementation supporting iptables and nftables.
pub struct IptablesFirewall;

/// Format a `Cidr` as `addr/prefix` (e.g. `10.0.0.0/8`). Used for the v4
/// RFC1918 lines emitted into the iptables ruleset.
fn fmt_cidr(c: &Cidr) -> String {
    format!("{}/{}", c.addr, c.prefix_len)
}

/// RFC1918 base list — the v4 private-network space allowed to bypass the
/// killswitch onto the underlay. Secondaries' `declared_cidrs` are
/// subtracted from this; primaries are excluded from the remove list per
/// Q-DEF-9 D-6.
fn rfc1918_base() -> Vec<Cidr> {
    ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        .iter()
        .map(|s| s.parse().expect("static RFC1918 CIDRs parse"))
        .collect()
}

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
        crate::vortix_process::run_to_output(CommandSpec::oneshot("nft", vec!["--version".into()]))
            .is_ok_and(|o| o.status.success())
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
        writeln!(rules, ":INPUT ACCEPT [0:0]").unwrap();
        writeln!(rules, ":FORWARD ACCEPT [0:0]").unwrap();
        // Default-deny egress at the OUTPUT chain — no leak path if a
        // per-tunnel ACCEPT rule fails to match.
        writeln!(rules, ":OUTPUT DROP [0:0]").unwrap();

        // Allow loopback.
        writeln!(rules, "-A OUTPUT -o lo -j ACCEPT").unwrap();

        // RFC1918, with secondaries' declared CIDRs carved out. Primaries
        // (0/0) are excluded from the remove list per Q-DEF-9 / D-6 — their
        // interface allow rule covers egress, and subtracting the default
        // route would strip loopback.
        let secondary_cidrs: Vec<Cidr> = active
            .iter()
            .filter(|t| !t.is_primary)
            .flat_map(|t| t.declared_cidrs.iter().copied())
            .collect();
        let rfc1918 = cidr_subtract(&rfc1918_base(), &secondary_cidrs);
        for c in &rfc1918 {
            writeln!(rules, "-A OUTPUT -d {} -j ACCEPT", fmt_cidr(c)).unwrap();
        }

        // DHCP — must precede the per-tunnel rules so a DHCP renew on the
        // underlay isn't dropped.
        writeln!(rules, "-A OUTPUT -p udp --sport 68 --dport 67 -j ACCEPT").unwrap();

        // Per-tunnel rules. Order preserved from caller — typically
        // primary first, then secondaries by attach order.
        for tunnel in active {
            writeln!(
                rules,
                "# Tunnel: {} (primary={})",
                tunnel.interface, tunnel.is_primary
            )
            .unwrap();
            writeln!(rules, "-A OUTPUT -o {} -j ACCEPT", tunnel.interface).unwrap();
            for ip in &tunnel.server_ips {
                if let IpAddr::V4(v4) = ip {
                    writeln!(rules, "-A OUTPUT -d {v4} -j ACCEPT").unwrap();
                }
            }
        }

        writeln!(rules, "COMMIT").unwrap();
        rules
    }

    /// Synthesise the IPv6 `ip6tables-restore` ruleset. Same shape as v4
    /// but without RFC1918 carve-out (RFC1918 is v4-only). Only IPv6
    /// server IPs are emitted as `-A OUTPUT -d ... -j ACCEPT` lines.
    ///
    /// Returns `None` when no tunnel has any IPv6 server IP — in that case
    /// there's no v6 ruleset to apply and the caller skips
    /// `ip6tables-restore` entirely (the v4 ruleset is the authoritative
    /// state).
    #[must_use]
    pub fn generate_v6_ruleset(active: &[ActiveTunnelInfo]) -> Option<String> {
        let has_v6 = active
            .iter()
            .any(|t| t.server_ips.iter().any(IpAddr::is_ipv6));
        if !has_v6 {
            return None;
        }

        let mut rules = String::new();
        writeln!(rules, "# Vortix Kill Switch Rules (IPv6) - Auto-generated").unwrap();
        writeln!(rules, "# DO NOT EDIT - Will be overwritten").unwrap();
        writeln!(rules, "*filter").unwrap();
        writeln!(rules, ":INPUT ACCEPT [0:0]").unwrap();
        writeln!(rules, ":FORWARD ACCEPT [0:0]").unwrap();
        writeln!(rules, ":OUTPUT DROP [0:0]").unwrap();

        // Loopback (v6 lo is the same interface name).
        writeln!(rules, "-A OUTPUT -o lo -j ACCEPT").unwrap();

        // Per-tunnel v6 server IPs only. We don't emit interface allows
        // here — the v4 ruleset already permits the interface and the
        // tunnel transport itself is v4 (server endpoints we care about
        // for reconnect). If a tunnel has only v6 server IPs we still
        // emit the interface allow so reconnect works.
        for tunnel in active {
            let v6_ips: Vec<&IpAddr> = tunnel.server_ips.iter().filter(|ip| ip.is_ipv6()).collect();
            if v6_ips.is_empty() {
                continue;
            }
            writeln!(
                rules,
                "# Tunnel: {} (primary={})",
                tunnel.interface, tunnel.is_primary
            )
            .unwrap();
            writeln!(rules, "-A OUTPUT -o {} -j ACCEPT", tunnel.interface).unwrap();
            for ip in v6_ips {
                if let IpAddr::V6(v6) = ip {
                    writeln!(rules, "-A OUTPUT -d {v6} -j ACCEPT").unwrap();
                }
            }
        }

        writeln!(rules, "COMMIT").unwrap();
        Some(rules)
    }

    /// Invoke `iptables-restore` with the given ruleset on stdin. The
    /// kernel performs an atomic ruleset replace — if the parse fails,
    /// the prior ruleset stays in force, no leak window.
    fn iptables_restore_stdin(ruleset: &[u8]) -> std::result::Result<(), String> {
        let output = crate::vortix_process::run_to_output(
            CommandSpec::oneshot("iptables-restore", vec![])
                .privilege(PrivilegeReq::Root)
                .stdin(ruleset.to_vec()),
        )
        .map_err(|e| format!("Failed to spawn iptables-restore: {e}"))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    /// IPv6 counterpart. Same atomic semantics via `ip6tables-restore`.
    fn ip6tables_restore_stdin(ruleset: &[u8]) -> std::result::Result<(), String> {
        let output = crate::vortix_process::run_to_output(
            CommandSpec::oneshot("ip6tables-restore", vec![])
                .privilege(PrivilegeReq::Root)
                .stdin(ruleset.to_vec()),
        )
        .map_err(|e| format!("Failed to spawn ip6tables-restore: {e}"))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    /// Legacy per-rule iptables invocation, retained only for the
    /// teardown path (`iptables -D OUTPUT -j VORTIX_KILLSWITCH` etc.).
    /// New rulesets are installed via `iptables-restore` (see
    /// `iptables_restore_stdin`).
    fn iptables(args: &[&str]) -> std::result::Result<(), String> {
        let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let output = crate::vortix_process::run_to_output(
            CommandSpec::oneshot("iptables", owned).privilege(PrivilegeReq::Root),
        )
        .map_err(|e| format!("Failed to run iptables: {e}"))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
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
        Self::iptables_restore_stdin(v4.as_bytes()).map_err(|e| {
            error!(target: "vortix::killswitch", stderr = %e, "iptables-restore failed");
            KillswitchError::CommandFailed(format!("iptables-restore: {e}"))
        })?;

        if let Some(v6) = Self::generate_v6_ruleset(active) {
            debug!(
                target: "vortix::killswitch",
                bytes = v6.len(),
                "loading ip6tables ruleset via ip6tables-restore stdin"
            );
            Self::ip6tables_restore_stdin(v6.as_bytes()).map_err(|e| {
                error!(target: "vortix::killswitch", stderr = %e, "ip6tables-restore failed");
                KillswitchError::CommandFailed(format!("ip6tables-restore: {e}"))
            })?;
        }

        Ok(())
    }

    /// Tear down iptables state. Restore the default-ACCEPT OUTPUT policy
    /// via a minimal `iptables-restore` ruleset, and remove any legacy
    /// `VORTIX_KILLSWITCH` chain the pre-U9 implementation may have left
    /// behind.
    fn teardown_iptables() {
        // Reset OUTPUT policy and clear filter table via iptables-restore.
        let reset =
            "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n";
        let _ = Self::iptables_restore_stdin(reset.as_bytes());
        let _ = Self::ip6tables_restore_stdin(reset.as_bytes());

        // Best-effort: remove the legacy custom chain if a pre-U9 build
        // installed it. Errors ignored — chain may not exist.
        let _ = Self::iptables(&["-D", "OUTPUT", "-j", CHAIN_NAME]);
        let _ = Self::iptables(&["-F", CHAIN_NAME]);
        let _ = Self::iptables(&["-X", CHAIN_NAME]);
    }

    // ─── nftables backend ───────────────────────────────────────────────

    fn nft(args: &[&str]) -> std::result::Result<(), String> {
        let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let output = crate::vortix_process::run_to_output(
            CommandSpec::oneshot("nft", owned).privilege(PrivilegeReq::Root),
        )
        .map_err(|e| format!("Failed to run nft: {e}"))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    /// Set up the kill switch with nftables using an atomic ruleset load.
    /// Single-tunnel fallback shape — multi-tunnel synthesis on nftables
    /// lands in a follow-up unit; for now we install the first tunnel's
    /// rules when invoked from `enable_blocking_multi`.
    fn setup_nftables(vpn_interface: &str, vpn_server_ip: Option<&str>) -> Result<()> {
        use std::fmt::Write;

        let mut ruleset = format!(
            r#"table inet {NFT_TABLE} {{
  chain output {{
    type filter hook output priority 0; policy drop;

    # Allow loopback
    oifname "lo" accept

    # Allow VPN interface
    oifname "{vpn_interface}" accept

    # Allow local networks (RFC1918)
    ip daddr 192.168.0.0/16 accept
    ip daddr 10.0.0.0/8 accept
    ip daddr 172.16.0.0/12 accept

    # Allow DHCP
    udp sport 68 udp dport 67 accept
"#,
        );

        if let Some(ip) = vpn_server_ip {
            let _ = write!(
                ruleset,
                "\n    # Allow VPN server for reconnection\n    ip daddr {ip} accept\n"
            );
        }

        ruleset.push_str("  }\n}\n");

        // Delete existing table first (ignore error if not present)
        let _ = Self::nft(&["delete", "table", "inet", NFT_TABLE]);

        // Apply the full ruleset atomically via stdin
        let output = crate::vortix_process::run_to_output(
            CommandSpec::oneshot("nft", vec!["-f".into(), "-".into()])
                .privilege(PrivilegeReq::Root)
                .stdin(ruleset.into_bytes()),
        )
        .map_err(|e| KillswitchError::CommandFailed(format!("nft spawn: {e}")))?;

        if !output.status.success() {
            return Err(KillswitchError::CommandFailed(
                "nft failed to load ruleset".to_string(),
            ));
        }

        Ok(())
    }

    /// Remove the kill switch nftables table.
    fn teardown_nftables() {
        let _ = Self::nft(&["delete", "table", "inet", NFT_TABLE]);
    }
}

fn is_root() -> bool {
    // SAFETY: `geteuid` is a thread-safe getter with no side effects.
    #[allow(unsafe_code)]
    unsafe {
        libc::geteuid() == 0
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
        if !is_root() {
            error!(target: "vortix::killswitch", "kill switch requires root privileges");
            return Err(KillswitchError::NotRoot);
        }

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
                // nftables backend stays on the single-tunnel shape for
                // now — multi-tunnel synthesis on nft is tracked as a
                // follow-up. Apply the first tunnel's rules; empty active
                // set yields a base block-all (the existing `setup_nftables`
                // handles `vpn_interface = ""` gracefully via the default
                // drop policy).
                let first = active.first();
                let interface = first.map_or("lo", |t| t.interface.as_str());
                let server_ip_owned: Option<String> =
                    first.and_then(|t| t.server_ips.first().map(ToString::to_string));
                Self::setup_nftables(interface, server_ip_owned.as_deref())?;
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

        if !is_root() {
            error!(target: "vortix::killswitch", "disabling kill switch requires root");
            return Err(KillswitchError::NotRoot);
        }

        // Clean up both backends — safe to call on each even if not active
        Self::teardown_iptables();
        Self::teardown_nftables();

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
        assert!(rules.contains(":OUTPUT DROP [0:0]"));
        assert!(rules.contains("-A OUTPUT -o lo -j ACCEPT"));
        // Full RFC1918 base intact.
        assert!(rules.contains("-A OUTPUT -d 10.0.0.0/8 -j ACCEPT"));
        assert!(rules.contains("-A OUTPUT -d 172.16.0.0/12 -j ACCEPT"));
        assert!(rules.contains("-A OUTPUT -d 192.168.0.0/16 -j ACCEPT"));
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
        assert!(rules.contains("-A OUTPUT -d 10.0.0.0/8 -j ACCEPT"));
        assert!(rules.contains("-A OUTPUT -d 172.16.0.0/12 -j ACCEPT"));
        assert!(rules.contains("-A OUTPUT -d 192.168.0.0/16 -j ACCEPT"));
        assert!(rules.contains("-A OUTPUT -o wg0 -j ACCEPT"));
        assert!(rules.contains("-A OUTPUT -d 1.2.3.4 -j ACCEPT"));
    }

    #[test]
    fn single_secondary_ten_dot_carves_rfc1918() {
        // A secondary claiming 10/8 should remove that block from the
        // RFC1918 pass list. 172.16/12 + 192.168/16 remain.
        let t = tunnel("wg1", &["5.6.7.8"], &["10.0.0.0/8"], false);
        let rules = IptablesFirewall::generate_v4_ruleset(&[t]);
        assert!(!rules.contains("-A OUTPUT -d 10.0.0.0/8 -j ACCEPT"));
        assert!(rules.contains("-A OUTPUT -d 172.16.0.0/12 -j ACCEPT"));
        assert!(rules.contains("-A OUTPUT -d 192.168.0.0/16 -j ACCEPT"));
        assert!(rules.contains("-A OUTPUT -o wg1 -j ACCEPT"));
        assert!(rules.contains("-A OUTPUT -d 5.6.7.8 -j ACCEPT"));
    }

    #[test]
    fn two_secondaries_disjoint_carve_correctly() {
        // wg1 claims 10/8, wg2 claims 192.168/16. Result: only 172.16/12
        // remains in the RFC1918 list.
        let t1 = tunnel("wg1", &["1.1.1.1"], &["10.0.0.0/8"], false);
        let t2 = tunnel("wg2", &["2.2.2.2"], &["192.168.0.0/16"], false);
        let rules = IptablesFirewall::generate_v4_ruleset(&[t1, t2]);
        assert!(!rules.contains("-A OUTPUT -d 10.0.0.0/8 -j ACCEPT"));
        assert!(rules.contains("-A OUTPUT -d 172.16.0.0/12 -j ACCEPT"));
        assert!(!rules.contains("-A OUTPUT -d 192.168.0.0/16 -j ACCEPT"));
        // Both interfaces appear.
        assert!(rules.contains("-A OUTPUT -o wg1 -j ACCEPT"));
        assert!(rules.contains("-A OUTPUT -o wg2 -j ACCEPT"));
        assert!(rules.contains("-A OUTPUT -d 1.1.1.1 -j ACCEPT"));
        assert!(rules.contains("-A OUTPUT -d 2.2.2.2 -j ACCEPT"));
    }

    #[test]
    fn two_secondaries_overlapping_dont_double_subtract() {
        // wg3 claims 10/8, wg4 claims 10.5/16 (a subset). Result is
        // identical to subtracting just 10/8.
        let t1 = tunnel("wg3", &["1.1.1.1"], &["10.0.0.0/8"], false);
        let t2 = tunnel("wg4", &["2.2.2.2"], &["10.5.0.0/16"], false);
        let rules = IptablesFirewall::generate_v4_ruleset(&[t1, t2]);
        // No 10.* leftover anywhere in the RFC1918 ACCEPT lines.
        assert!(!rules.contains("-A OUTPUT -d 10."));
        assert!(rules.contains("-A OUTPUT -d 172.16.0.0/12 -j ACCEPT"));
        assert!(rules.contains("-A OUTPUT -d 192.168.0.0/16 -j ACCEPT"));
    }

    #[test]
    fn primary_plus_secondary_only_secondary_carves() {
        // Primary 0/0 + secondary 10/8 — only the secondary subtracts.
        let prim = tunnel("wg0", &["9.9.9.9"], &["0.0.0.0/0"], true);
        let sec = tunnel("wg1", &["8.8.8.8"], &["10.0.0.0/8"], false);
        let rules = IptablesFirewall::generate_v4_ruleset(&[prim, sec]);
        // 10/8 is gone.
        assert!(!rules.contains("-A OUTPUT -d 10.0.0.0/8 -j ACCEPT"));
        // 172.16 and 192.168 intact.
        assert!(rules.contains("-A OUTPUT -d 172.16.0.0/12 -j ACCEPT"));
        assert!(rules.contains("-A OUTPUT -d 192.168.0.0/16 -j ACCEPT"));
        // Both interfaces present.
        assert!(rules.contains("-A OUTPUT -o wg0 -j ACCEPT"));
        assert!(rules.contains("-A OUTPUT -o wg1 -j ACCEPT"));
    }

    #[test]
    fn tunnel_with_no_server_ips_still_gets_interface_rule() {
        let t = tunnel("wg5", &[], &[], true);
        let rules = IptablesFirewall::generate_v4_ruleset(&[t]);
        assert!(rules.contains("-A OUTPUT -o wg5 -j ACCEPT"));
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
        assert!(rules.contains("-A OUTPUT -d 1.2.3.4 -j ACCEPT"));
        assert!(rules.contains("-A OUTPUT -d 5.6.7.8 -j ACCEPT"));
    }

    // ─── v6 ruleset generation ──────────────────────────────────────────

    #[test]
    fn no_v6_server_ips_yields_none_v6_ruleset() {
        // Only v4 server IPs — v6 ruleset is None (caller skips
        // ip6tables-restore entirely).
        let t = tunnel("wg0", &["1.2.3.4"], &[], true);
        assert!(IptablesFirewall::generate_v6_ruleset(&[t]).is_none());
        assert!(IptablesFirewall::generate_v6_ruleset(&[]).is_none());
    }

    #[test]
    fn v6_server_ip_routes_to_ip6tables_ruleset() {
        let t = ActiveTunnelInfo {
            interface: "wg7".to_string(),
            server_ips: vec!["2001:db8::1".parse().unwrap()],
            declared_cidrs: vec![],
            is_primary: true,
        };
        let v6 = IptablesFirewall::generate_v6_ruleset(&[t]).expect("v6 ruleset present");
        assert!(v6.contains("*filter"));
        assert!(v6.contains(":OUTPUT DROP [0:0]"));
        assert!(v6.contains("-A OUTPUT -o lo -j ACCEPT"));
        assert!(v6.contains("-A OUTPUT -o wg7 -j ACCEPT"));
        assert!(v6.contains("-A OUTPUT -d 2001:db8::1 -j ACCEPT"));
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
        let v6 = IptablesFirewall::generate_v6_ruleset(std::slice::from_ref(&t))
            .expect("v6 ruleset present");
        // v4 ruleset has the v4 server IP, not the v6 one.
        assert!(v4.contains("-A OUTPUT -d 1.2.3.4 -j ACCEPT"));
        assert!(!v4.contains("2001:db8"));
        // v6 ruleset has the v6 server IP, not the v4 one.
        assert!(v6.contains("-A OUTPUT -d 2001:db8::1 -j ACCEPT"));
        assert!(!v6.contains("1.2.3.4"));
    }

    #[test]
    fn v6_ruleset_skips_tunnels_with_only_v4_ips() {
        // wg9 has only a v4 server IP; wg10 has a v6 one. The v6 ruleset
        // should contain wg10's allow rule but no wg9 entries.
        let t9 = tunnel("wg9", &["1.2.3.4"], &[], true);
        let t10 = ActiveTunnelInfo {
            interface: "wg10".to_string(),
            server_ips: vec!["2001:db8::1".parse().unwrap()],
            declared_cidrs: vec![],
            is_primary: false,
        };
        let v6 = IptablesFirewall::generate_v6_ruleset(&[t9, t10]).expect("v6 ruleset present");
        assert!(!v6.contains("wg9"));
        assert!(v6.contains("-A OUTPUT -o wg10 -j ACCEPT"));
        assert!(v6.contains("-A OUTPUT -d 2001:db8::1 -j ACCEPT"));
    }

    // ─── snapshot tests pinning ruleset shape ───────────────────────────

    #[test]
    fn snapshot_empty_active_set() {
        let rules = IptablesFirewall::generate_v4_ruleset(&[]);
        let expected = "\
# Vortix Kill Switch Rules - Auto-generated
# DO NOT EDIT - Will be overwritten
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT DROP [0:0]
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -d 10.0.0.0/8 -j ACCEPT
-A OUTPUT -d 172.16.0.0/12 -j ACCEPT
-A OUTPUT -d 192.168.0.0/16 -j ACCEPT
-A OUTPUT -p udp --sport 68 --dport 67 -j ACCEPT
COMMIT
";
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
        let rules = IptablesFirewall::generate_v4_ruleset(&[t]);
        let expected = "\
# Vortix Kill Switch Rules - Auto-generated
# DO NOT EDIT - Will be overwritten
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT DROP [0:0]
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -d 10.0.0.0/8 -j ACCEPT
-A OUTPUT -d 172.16.0.0/12 -j ACCEPT
-A OUTPUT -d 192.168.0.0/16 -j ACCEPT
-A OUTPUT -p udp --sport 68 --dport 67 -j ACCEPT
# Tunnel: wg0 (primary=true)
-A OUTPUT -o wg0 -j ACCEPT
-A OUTPUT -d 1.2.3.4 -j ACCEPT
COMMIT
";
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
        let rules = IptablesFirewall::generate_v4_ruleset(&[prim, sec]);
        let expected = "\
# Vortix Kill Switch Rules - Auto-generated
# DO NOT EDIT - Will be overwritten
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT DROP [0:0]
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -d 172.16.0.0/12 -j ACCEPT
-A OUTPUT -d 192.168.0.0/16 -j ACCEPT
-A OUTPUT -p udp --sport 68 --dport 67 -j ACCEPT
# Tunnel: wg0 (primary=true)
-A OUTPUT -o wg0 -j ACCEPT
-A OUTPUT -d 1.2.3.4 -j ACCEPT
# Tunnel: wg1 (primary=false)
-A OUTPUT -o wg1 -j ACCEPT
-A OUTPUT -d 5.6.7.8 -j ACCEPT
COMMIT
";
        assert_eq!(rules, expected);
    }
}
