//! Linux iptables/nftables firewall implementation for kill switch.
//!
//! Prefers iptables when available, falls back to nftables (nft).

use tracing::{debug, error, info};
use vortix_core::ports::killswitch::{Killswitch, KillswitchError, Result};
use vortix_process::{CommandSpec, PrivilegeReq};

const CHAIN_NAME: &str = "VORTIX_KILLSWITCH";
const NFT_TABLE: &str = "vortix_killswitch";

/// Detected firewall backend on this system.
enum FirewallBackend {
    Iptables,
    Nftables,
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
        vortix_process::run_to_output(CommandSpec::oneshot("iptables", vec!["--version".into()]))
            .is_ok_and(|o| o.status.success())
    }

    fn has_nft() -> bool {
        vortix_process::run_to_output(CommandSpec::oneshot("nft", vec!["--version".into()]))
            .is_ok_and(|o| o.status.success())
    }

    // ─── iptables backend ───────────────────────────────────────────────

    /// Run an iptables command and return success.
    fn iptables(args: &[&str]) -> std::result::Result<(), String> {
        let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let output = vortix_process::run_to_output(
            CommandSpec::oneshot("iptables", owned).privilege(PrivilegeReq::Root),
        )
        .map_err(|e| format!("Failed to run iptables: {e}"))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    /// Set up the kill switch chain with iptables.
    fn setup_iptables(vpn_interface: &str, vpn_server_ip: Option<&str>) -> Result<()> {
        // Create custom chain (ignore error if already exists)
        let _ = Self::iptables(&["-N", CHAIN_NAME]);

        // Flush existing rules in our chain
        Self::iptables(&["-F", CHAIN_NAME])
            .map_err(|e| KillswitchError::CommandFailed(format!("flush chain: {e}")))?;

        // Add rules to our chain

        // Allow loopback
        Self::iptables(&["-A", CHAIN_NAME, "-o", "lo", "-j", "ACCEPT"])
            .map_err(|e| KillswitchError::CommandFailed(format!("allow lo: {e}")))?;

        // Allow VPN interface
        Self::iptables(&["-A", CHAIN_NAME, "-o", vpn_interface, "-j", "ACCEPT"])
            .map_err(|e| KillswitchError::CommandFailed(format!("allow VPN iface: {e}")))?;

        // Allow local network (RFC1918)
        for net in &["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"] {
            Self::iptables(&["-A", CHAIN_NAME, "-d", net, "-j", "ACCEPT"])
                .map_err(|e| KillswitchError::CommandFailed(format!("allow {net}: {e}")))?;
        }

        // Allow DHCP
        Self::iptables(&[
            "-A", CHAIN_NAME, "-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT",
        ])
        .map_err(|e| KillswitchError::CommandFailed(format!("allow DHCP: {e}")))?;

        // Allow VPN server IP if known (for reconnection)
        if let Some(ip) = vpn_server_ip {
            Self::iptables(&["-A", CHAIN_NAME, "-d", ip, "-p", "udp", "-j", "ACCEPT"]).map_err(
                |e| KillswitchError::CommandFailed(format!("allow VPN server udp: {e}")),
            )?;
            Self::iptables(&["-A", CHAIN_NAME, "-d", ip, "-p", "tcp", "-j", "ACCEPT"]).map_err(
                |e| KillswitchError::CommandFailed(format!("allow VPN server tcp: {e}")),
            )?;
        }

        // Default: drop everything else
        Self::iptables(&["-A", CHAIN_NAME, "-j", "DROP"])
            .map_err(|e| KillswitchError::CommandFailed(format!("default drop: {e}")))?;

        // Insert jump to our chain at the top of OUTPUT
        // First remove any existing jump (ignore error)
        let _ = Self::iptables(&["-D", "OUTPUT", "-j", CHAIN_NAME]);
        Self::iptables(&["-I", "OUTPUT", "1", "-j", CHAIN_NAME])
            .map_err(|e| KillswitchError::CommandFailed(format!("insert jump: {e}")))?;

        Ok(())
    }

    /// Remove the kill switch chain from iptables.
    fn teardown_iptables() {
        // Remove jump from OUTPUT chain (ignore error if not present)
        let _ = Self::iptables(&["-D", "OUTPUT", "-j", CHAIN_NAME]);

        // Flush and delete our custom chain
        let _ = Self::iptables(&["-F", CHAIN_NAME]);
        let _ = Self::iptables(&["-X", CHAIN_NAME]);
    }

    // ─── nftables backend ───────────────────────────────────────────────

    fn nft(args: &[&str]) -> std::result::Result<(), String> {
        let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let output = vortix_process::run_to_output(
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
        let output = vortix_process::run_to_output(
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
    fn enable_blocking(vpn_interface: &str, vpn_server_ip: Option<&str>) -> Result<()> {
        info!(
            target: "vortix::killswitch",
            interface = %vpn_interface,
            server = ?vpn_server_ip,
            "killswitch.engage"
        );

        if !is_root() {
            error!(target: "vortix::killswitch", "kill switch requires root privileges");
            return Err(KillswitchError::NotRoot);
        }

        match Self::detect_backend() {
            Some(FirewallBackend::Iptables) => {
                debug!(target: "vortix::killswitch", "using iptables backend");
                Self::setup_iptables(vpn_interface, vpn_server_ip)?;
            }
            Some(FirewallBackend::Nftables) => {
                debug!(target: "vortix::killswitch", "using nftables backend");
                Self::setup_nftables(vpn_interface, vpn_server_ip)?;
            }
            None => {
                return Err(KillswitchError::NoBackendAvailable);
            }
        }

        info!(target: "vortix::killswitch", "kill switch ACTIVE — blocking non-VPN traffic");
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
