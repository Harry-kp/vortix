//! macOS pf (Packet Filter) firewall implementation for kill switch.

use crate::constants;
use crate::core::killswitch::{KillSwitchError, Result};
use crate::logger::{self, LogLevel};
use crate::platform::Firewall;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::Write as IoWrite;
use std::os::unix::fs::OpenOptionsExt;
use std::process::Command;

/// macOS pf-based firewall implementation.
pub struct PfFirewall;

impl PfFirewall {
    /// Generate pf rules that block all traffic except VPN.
    #[must_use]
    pub fn generate_pf_rules(vpn_interface: &str, vpn_server_ip: Option<&str>) -> String {
        let mut rules = format!(
            r"# Vortix Kill Switch Rules - Auto-generated
# DO NOT EDIT - Will be overwritten

# Default: block all
block all

# Allow loopback
pass quick on lo0 all

# Allow local network (RFC1918)
pass out quick to 192.168.0.0/16
pass in quick from 192.168.0.0/16
pass out quick to 10.0.0.0/8
pass in quick from 10.0.0.0/8
pass out quick to 172.16.0.0/12
pass in quick from 172.16.0.0/12

# Allow DHCP
pass out quick proto udp from any port 68 to any port 67
pass in quick proto udp from any port 67 to any port 68

# Allow all traffic on VPN interface
pass quick on {vpn_interface} all
"
        );

        if let Some(ip) = vpn_server_ip {
            writeln!(
                rules,
                "\n# Allow VPN server for reconnection\npass out quick proto udp to {ip}\npass out quick proto tcp to {ip}"
            )
            .unwrap();
        }

        rules
    }
}

impl Firewall for PfFirewall {
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

        let rules = Self::generate_pf_rules(vpn_interface, vpn_server_ip);

        let conf_path = std::path::Path::new(constants::PF_CONF_PATH);
        if let Some(parent) = conf_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
                }
            }
        }

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(constants::PF_CONF_PATH)?;
        file.write_all(rules.as_bytes())?;

        let _ = fs::remove_file(constants::PF_CONF_PATH_LEGACY);
        logger::log(
            LogLevel::Debug,
            "FIREWALL",
            format!("Wrote pf rules to {}", constants::PF_CONF_PATH),
        );

        let output = Command::new("pfctl")
            .args(["-f", constants::PF_CONF_PATH])
            .output()?;
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr).to_string();
            logger::log(
                LogLevel::Error,
                "FIREWALL",
                format!("pfctl -f failed: {err}"),
            );
            return Err(KillSwitchError::CommandFailed(err));
        }

        let output = Command::new("pfctl").args(["-e"]).output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("enabled") {
                logger::log(
                    LogLevel::Error,
                    "FIREWALL",
                    format!("pfctl -e failed: {stderr}"),
                );
                return Err(KillSwitchError::CommandFailed(stderr.to_string()));
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

        let output = Command::new("pfctl").args(["-F", "all"]).output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("not enabled") {
                logger::log(
                    LogLevel::Error,
                    "FIREWALL",
                    format!("pfctl -F failed: {stderr}"),
                );
                return Err(KillSwitchError::CommandFailed(stderr.to_string()));
            }
        }

        let _ = Command::new("pfctl").args(["-d"]).output()?;
        let _ = fs::remove_file(constants::PF_CONF_PATH);
        let _ = fs::remove_file(constants::PF_CONF_PATH_LEGACY);

        logger::log(
            LogLevel::Info,
            "FIREWALL",
            "Kill switch DISABLED - normal traffic restored",
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_pf_rules_with_server() {
        let rules = PfFirewall::generate_pf_rules("utun3", Some("1.2.3.4"));
        assert!(rules.contains("block all"));
        assert!(rules.contains("pass quick on lo0"));
        assert!(rules.contains("192.168.0.0/16"));
        assert!(rules.contains("pass out quick proto udp to 1.2.3.4"));
        assert!(rules.contains("pass quick on utun3"));
    }

    #[test]
    fn test_generate_pf_rules_without_server() {
        let rules = PfFirewall::generate_pf_rules("utun3", None);
        assert!(rules.contains("block all"));
        assert!(rules.contains("pass quick on utun3"));
        assert!(!rules.contains("1.2.3.4"));
    }
}
