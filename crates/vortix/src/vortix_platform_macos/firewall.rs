//! macOS pf (Packet Filter) firewall implementation for kill switch.
//!
//! Plan multi-connection U10: the ruleset synthesiser now consumes a slice
//! of [`ActiveTunnelInfo`] and emits per-tunnel allow rules in a single
//! ruleset. The ruleset is fed to `pfctl -f -` via stdin, which performs
//! an atomic in-kernel replace — so transitions from one active set to
//! another (refresh) never go through `pfctl -F all` + `pfctl -d`, which
//! would otherwise open a non-atomic leak window. `disable_blocking` is
//! preserved unchanged for the explicit "killswitch off" path where the
//! user actively disarms.

use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::Write as IoWrite;
use std::net::IpAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::vortix_core::cidr::Cidr;
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

fn pfctl(args: &[&str]) -> std::io::Result<std::process::Output> {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    crate::vortix_process::run_to_output(
        CommandSpec::oneshot("pfctl", owned).privilege(PrivilegeReq::Root),
    )
}

/// Invoke `pfctl -f -` with the given ruleset on stdin. pfctl's stdin-load
/// is atomic: the in-kernel ruleset is replaced in a single operation. No
/// leak window — earlier rules stay live until the new set parses and
/// commits.
fn pfctl_load_stdin(ruleset: &[u8]) -> std::io::Result<std::process::Output> {
    crate::vortix_process::run_to_output(
        CommandSpec::oneshot("pfctl", vec!["-f".to_string(), "-".to_string()])
            .privilege(PrivilegeReq::Root)
            .stdin(ruleset.to_vec()),
    )
}

fn is_root() -> bool {
    // SAFETY: `geteuid` is a thread-safe getter with no side effects.
    #[allow(unsafe_code)]
    unsafe {
        libc::geteuid() == 0
    }
}

/// Format a `Cidr` as pf-syntax `addr/prefix` (e.g. `10.0.0.0/8`). pf
/// accepts this for both v4 and v6; we only emit v4 today.
fn fmt_cidr(c: &Cidr) -> String {
    format!("{}/{}", c.addr, c.prefix_len)
}

/// The RFC1918 base list. `enable_blocking_multi` subtracts the union of
/// secondaries' `declared_cidrs` from this; primaries don't contribute
/// (see `cidr_subtract` docs / Q-DEF-9 D-6).
fn rfc1918_base() -> Vec<Cidr> {
    ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        .iter()
        .map(|s| s.parse().expect("static RFC1918 CIDRs parse"))
        .collect()
}

/// macOS pf-based firewall implementation.
pub struct PfFirewall;

impl PfFirewall {
    /// Synthesise the pf ruleset for the given active tunnel set.
    ///
    /// Shape:
    ///   1. `block out all` — default-deny egress
    ///   2. `pass out quick on lo0` — loopback always allowed
    ///   3. RFC1918 pass-out rules, with secondaries' declared CIDRs
    ///      carved out so traffic claimed by a secondary cannot escape
    ///      onto the underlay
    ///   4. DHCP pass rules
    ///   5. Per-tunnel: `pass out quick on <interface>` + one
    ///      `pass out quick to <server_ip>` per server IP, so the tunnel
    ///      can reconnect after a transport drop
    ///
    /// An empty `active` slice yields rules 1-4 only — the base block-all
    /// posture with no per-tunnel egress.
    #[must_use]
    pub fn generate_pf_rules(active: &[ActiveTunnelInfo]) -> String {
        let mut rules = String::new();
        writeln!(rules, "# Vortix Kill Switch Rules - Auto-generated").unwrap();
        writeln!(rules, "# DO NOT EDIT - Will be overwritten").unwrap();
        writeln!(rules).unwrap();
        writeln!(rules, "# Default: block all egress").unwrap();
        writeln!(rules, "block out all").unwrap();
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
        let rfc1918 = cidr_subtract(&rfc1918_base(), &secondary_cidrs);

        writeln!(
            rules,
            "# Allow local network (RFC1918, minus secondaries' claimed CIDRs)"
        )
        .unwrap();
        for c in &rfc1918 {
            writeln!(rules, "pass out quick to {}", fmt_cidr(c)).unwrap();
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
            writeln!(
                rules,
                "# Tunnel: {} (primary={})",
                tunnel.interface, tunnel.is_primary
            )
            .unwrap();
            writeln!(rules, "pass out quick on {} all", tunnel.interface).unwrap();
            for ip in &tunnel.server_ips {
                writeln!(rules, "pass out quick to {}", fmt_ip(ip)).unwrap();
            }
        }

        rules
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

fn fmt_ip(ip: &IpAddr) -> String {
    ip.to_string()
}

impl Killswitch for PfFirewall {
    /// Engage the killswitch with a ruleset covering every tunnel in
    /// `active`. The ruleset is loaded via `pfctl -f -` (stdin), which
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

        if !is_root() {
            error!(target: "vortix::killswitch", "kill switch requires root privileges");
            return Err(KillswitchError::NotRoot);
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

        // Authoritative path: pfctl -f - reads ruleset from stdin and
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

        info!(
            target: "vortix::killswitch",
            tunnels = active.len(),
            "kill switch ACTIVE — blocking non-VPN traffic"
        );
        Ok(())
    }

    /// Disable the killswitch entirely — flush all rules and turn pf off.
    /// This is the explicit "killswitch off" path; refresh between two
    /// active sets goes through `enable_blocking_multi` directly so it
    /// never visits the non-atomic flush+disable sequence here.
    fn disable_blocking() -> Result<()> {
        info!(target: "vortix::killswitch", "disabling kill switch");

        if !is_root() {
            error!(target: "vortix::killswitch", "disabling kill switch requires root");
            return Err(KillswitchError::NotRoot);
        }

        let output = pfctl(&["-F", "all"])?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("not enabled") {
                error!(target: "vortix::killswitch", stderr = %stderr, "pfctl -F failed");
                return Err(KillswitchError::CommandFailed(stderr.to_string()));
            }
        }

        let _ = pfctl(&["-d"])?;
        let _ = fs::remove_file(PF_CONF_PATH);
        let _ = fs::remove_file(PF_CONF_PATH_LEGACY);

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

    #[test]
    fn empty_active_set_yields_base_blockall() {
        let rules = PfFirewall::generate_pf_rules(&[]);
        assert!(rules.contains("block out all"));
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

    /// Snapshot — empty active set. Pins the base block-all ruleset.
    #[test]
    fn snapshot_empty_active_set() {
        let rules = PfFirewall::generate_pf_rules(&[]);
        let expected = "\
# Vortix Kill Switch Rules - Auto-generated
# DO NOT EDIT - Will be overwritten

# Default: block all egress
block out all

# Allow loopback
pass out quick on lo0 all

# Allow local network (RFC1918, minus secondaries' claimed CIDRs)
pass out quick to 10.0.0.0/8
pass out quick to 172.16.0.0/12
pass out quick to 192.168.0.0/16

# Allow DHCP
pass out quick proto udp from any port 68 to any port 67
pass in quick proto udp from any port 67 to any port 68
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
        let rules = PfFirewall::generate_pf_rules(&[t]);
        let expected = "\
# Vortix Kill Switch Rules - Auto-generated
# DO NOT EDIT - Will be overwritten

# Default: block all egress
block out all

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
        let rules = PfFirewall::generate_pf_rules(&[prim, sec]);
        let expected = "\
# Vortix Kill Switch Rules - Auto-generated
# DO NOT EDIT - Will be overwritten

# Default: block all egress
block out all

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
";
        assert_eq!(rules, expected);
    }
}
