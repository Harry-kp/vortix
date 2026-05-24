//! Linux iptables/nftables firewall implementation for kill switch.
//!
//! Prefers iptables when available, falls back to nftables (nft).

use crate::constants;
use crate::core::killswitch::{KillSwitchError, Result};
use crate::logger::{self, LogLevel};
use crate::platform::Firewall;
use std::process::Command;

/// Alias for readability within this module.
const CHAIN_NAME: &str = constants::IPTABLES_CHAIN_NAME;
const NFT_TABLE: &str = constants::NFT_TABLE_NAME;

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

    /// Check if iptables is available on the system.
    fn has_iptables() -> bool {
        Command::new("iptables")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    /// Check if nftables (nft) is available on the system.
    fn has_nft() -> bool {
        Command::new("nft")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    // ─── iptables backend ───────────────────────────────────────────────

    /// Run an iptables command and return success.
    fn iptables(args: &[&str]) -> std::result::Result<(), String> {
        let output = Command::new("iptables")
            .args(args)
            .output()
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
            .map_err(|e| KillSwitchError::CommandFailed(format!("flush chain: {e}")))?;

        // Add rules to our chain

        // Allow loopback
        Self::iptables(&["-A", CHAIN_NAME, "-o", "lo", "-j", "ACCEPT"])
            .map_err(|e| KillSwitchError::CommandFailed(format!("allow lo: {e}")))?;

        // Allow VPN interface
        Self::iptables(&["-A", CHAIN_NAME, "-o", vpn_interface, "-j", "ACCEPT"])
            .map_err(|e| KillSwitchError::CommandFailed(format!("allow VPN iface: {e}")))?;

        // Allow local network (RFC1918)
        for net in &["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"] {
            Self::iptables(&["-A", CHAIN_NAME, "-d", net, "-j", "ACCEPT"])
                .map_err(|e| KillSwitchError::CommandFailed(format!("allow {net}: {e}")))?;
        }

        // Allow DHCP
        Self::iptables(&[
            "-A", CHAIN_NAME, "-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT",
        ])
        .map_err(|e| KillSwitchError::CommandFailed(format!("allow DHCP: {e}")))?;

        // Allow VPN server IP if known (for reconnection)
        if let Some(ip) = vpn_server_ip {
            Self::iptables(&["-A", CHAIN_NAME, "-d", ip, "-p", "udp", "-j", "ACCEPT"]).map_err(
                |e| KillSwitchError::CommandFailed(format!("allow VPN server udp: {e}")),
            )?;
            Self::iptables(&["-A", CHAIN_NAME, "-d", ip, "-p", "tcp", "-j", "ACCEPT"]).map_err(
                |e| KillSwitchError::CommandFailed(format!("allow VPN server tcp: {e}")),
            )?;
        }

        // Default: drop everything else
        Self::iptables(&["-A", CHAIN_NAME, "-j", "DROP"])
            .map_err(|e| KillSwitchError::CommandFailed(format!("default drop: {e}")))?;

        // Insert jump to our chain at the top of OUTPUT
        // First remove any existing jump (ignore error)
        let _ = Self::iptables(&["-D", "OUTPUT", "-j", CHAIN_NAME]);
        Self::iptables(&["-I", "OUTPUT", "1", "-j", CHAIN_NAME])
            .map_err(|e| KillSwitchError::CommandFailed(format!("insert jump: {e}")))?;

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

    /// Run an nft command and return success.
    fn nft(args: &[&str]) -> std::result::Result<(), String> {
        let output = Command::new("nft")
            .args(args)
            .output()
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

        // Build an atomic nft ruleset — applied in one shot so there's no
        // window where traffic could leak between rule additions.
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
        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| KillSwitchError::CommandFailed(format!("nft spawn: {e}")))?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin
                .write_all(ruleset.as_bytes())
                .map_err(|e| KillSwitchError::CommandFailed(format!("nft stdin: {e}")))?;
        }

        let status = child
            .wait()
            .map_err(|e| KillSwitchError::CommandFailed(format!("nft wait: {e}")))?;

        if !status.success() {
            return Err(KillSwitchError::CommandFailed(
                "nft failed to load ruleset".to_string(),
            ));
        }

        Ok(())
    }

    /// Remove the kill switch nftables table.
    fn teardown_nftables() {
        // Deleting the table removes all chains and rules inside it
        let _ = Self::nft(&["delete", "table", "inet", NFT_TABLE]);
    }
}

impl Firewall for IptablesFirewall {
    fn enable_blocking(vpn_interface: &str, vpn_server_ip: Option<&str>) -> Result<()> {
        logger::log(
            LogLevel::Info,
            "FIREWALL",
            format!(
                "Enabling kill switch on interface '{}'{}",
                vpn_interface,
                vpn_server_ip
                    .map(|ip| format!(", server: {ip}"))
                    .unwrap_or_default()
            ),
        );

        if !crate::utils::is_root() {
            logger::log(
                LogLevel::Error,
                "FIREWALL",
                "Kill switch requires root privileges",
            );
            return Err(KillSwitchError::NotRoot);
        }

        match Self::detect_backend() {
            Some(FirewallBackend::Iptables) => {
                logger::log(LogLevel::Debug, "FIREWALL", "Using iptables backend");
                Self::setup_iptables(vpn_interface, vpn_server_ip)?;
            }
            Some(FirewallBackend::Nftables) => {
                logger::log(LogLevel::Debug, "FIREWALL", "Using nftables backend");
                Self::setup_nftables(vpn_interface, vpn_server_ip)?;
            }
            None => {
                return Err(KillSwitchError::CommandFailed(
                    "Neither iptables nor nft found on this system".to_string(),
                ));
            }
        }

        logger::log(
            LogLevel::Info,
            "FIREWALL",
            "Kill switch ACTIVE - blocking non-VPN traffic",
        );
        Ok(())
    }

    fn disable_blocking() -> Result<()> {
        logger::log(LogLevel::Info, "FIREWALL", "Disabling kill switch...");

        if !crate::utils::is_root() {
            logger::log(
                LogLevel::Error,
                "FIREWALL",
                "Disabling kill switch requires root privileges",
            );
            return Err(KillSwitchError::NotRoot);
        }

        // Clean up both backends — safe to call on each even if not active
        Self::teardown_iptables();
        Self::teardown_nftables();

        logger::log(
            LogLevel::Info,
            "FIREWALL",
            "Kill switch DISABLED - normal traffic restored",
        );
        Ok(())
    }
}
