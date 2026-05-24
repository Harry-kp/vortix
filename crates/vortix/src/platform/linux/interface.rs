//! Linux VPN interface detection via `ip addr` and `wg show`.

use crate::core::telemetry::parse_ip_addr_output;
use crate::platform::InterfaceDetector;
use vortix_process::CommandSpec;

/// Run a command and return its output.
///
/// No timeout — called from the scanner's background thread, cannot block the UI.
/// All commands are read-only inspections that run unprivileged.
fn cmd_output(program: &str, args: &[&str]) -> Option<std::process::Output> {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    vortix_process::run_to_output(CommandSpec::oneshot(program, owned)).ok()
}

/// Linux interface detection using `ip addr`, `wg show`, and standard interface naming.
pub struct LinuxInterface;

impl InterfaceDetector for LinuxInterface {
    fn check_wireguard_interface(name: &str) -> bool {
        // On Linux, WireGuard creates interfaces directly (wg0, wg1, etc.)
        // Also check using `wg show` which works for kernel and userspace WireGuard
        check_wg_interface_exists(name)
    }

    fn resolve_wireguard_interface(name: &str) -> Option<String> {
        // Linux doesn't use /var/run/wireguard/*.name mapping files
        // The interface name IS the WireGuard interface
        if check_wg_interface_exists(name) {
            return Some(name.to_string());
        }

        // Fallback: try to find any active WireGuard interface via `wg show`
        // and match against the profile name
        if let Some(output) = cmd_output("wg", &["show"]) {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.starts_with("interface: ") {
                    let iface = line.trim_start_matches("interface: ").trim();
                    // Check if this interface matches the profile name (exact match only)
                    if iface == name {
                        return Some(iface.to_string());
                    }
                }
            }
        }

        None
    }

    fn get_wireguard_pid(interface: &str) -> Option<u32> {
        // On Linux, kernel WireGuard doesn't have a userspace process
        // For wireguard-go (userspace), search via ps
        if let Some(output) = cmd_output("ps", &["-eo", "pid,args"]) {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line_lower = line.to_lowercase();
                if line_lower.contains("wireguard")
                    && line_lower.contains(&interface.to_lowercase())
                {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if let Some(pid_str) = parts.first() {
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            return Some(pid);
                        }
                    }
                }
            }
        }

        None
    }

    fn get_interface_info(interface: &str) -> (String, String) {
        // Use `ip addr show {interface}` on Linux
        if let Some(output) = cmd_output("ip", &["addr", "show", interface]) {
            let stdout = String::from_utf8_lossy(&output.stdout);
            return parse_ip_addr_output(&stdout);
        }

        (String::new(), String::new())
    }
}

fn check_wg_interface_exists(name: &str) -> bool {
    cmd_output("wg", &["show", name, "public-key"]).is_some_and(|o| o.status.success())
}
