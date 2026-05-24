//! macOS pf (Packet Filter) firewall implementation for kill switch.

use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::Write as IoWrite;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use tracing::{debug, error, info};
use vortix_core::ports::killswitch::{Killswitch, KillswitchError, Result};
use vortix_process::{CommandSpec, PrivilegeReq};

/// On-disk pf configuration written before each engage.
const PF_CONF_PATH: &str = "/var/run/vortix/killswitch.conf";
/// Legacy pf configuration path cleaned up after migration.
const PF_CONF_PATH_LEGACY: &str = "/tmp/vortix_killswitch.conf";

fn pfctl(args: &[&str]) -> std::io::Result<std::process::Output> {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    vortix_process::run_to_output(
        CommandSpec::oneshot("pfctl", owned).privilege(PrivilegeReq::Root),
    )
}

fn is_root() -> bool {
    // SAFETY: `geteuid` is a thread-safe getter with no side effects.
    #[allow(unsafe_code)]
    unsafe {
        libc::geteuid() == 0
    }
}

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

impl Killswitch for PfFirewall {
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

        let rules = Self::generate_pf_rules(vpn_interface, vpn_server_ip);

        let conf_path = std::path::Path::new(PF_CONF_PATH);
        if let Some(parent) = conf_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
        }

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(PF_CONF_PATH)?;
        file.write_all(rules.as_bytes())?;

        let _ = fs::remove_file(PF_CONF_PATH_LEGACY);
        debug!(target: "vortix::killswitch", path = %PF_CONF_PATH, "wrote pf rules");

        let output = pfctl(&["-f", PF_CONF_PATH])?;
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr).to_string();
            error!(target: "vortix::killswitch", stderr = %err, "pfctl -f failed");
            return Err(KillswitchError::CommandFailed(err));
        }

        let output = pfctl(&["-e"])?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("enabled") {
                error!(target: "vortix::killswitch", stderr = %stderr, "pfctl -e failed");
                return Err(KillswitchError::CommandFailed(stderr.to_string()));
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
