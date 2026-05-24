//! macOS VPN interface detection via ifconfig and /var/run/wireguard/.

use std::path::PathBuf;
use vortix_core::ports::interface::Interface;
use vortix_process::CommandSpec;

const WIREGUARD_RUN_DIR: &str = "/var/run/wireguard";

/// Run a command and return its output.
///
/// No timeout — called from the scanner's background thread, cannot block the UI.
/// All commands here are read-only inspections that run unprivileged.
fn cmd_output(program: &str, args: &[&str]) -> Option<std::process::Output> {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    vortix_process::run_to_output(CommandSpec::oneshot(program, owned)).ok()
}

/// macOS interface detection using ifconfig and /var/run/wireguard/*.name files.
pub struct MacInterface;

impl Interface for MacInterface {
    fn check_wireguard_interface(name: &str) -> bool {
        let pid_file = PathBuf::from(WIREGUARD_RUN_DIR).join(format!("{name}.name"));
        pid_file.exists() || check_wg_interface_exists(name)
    }

    fn resolve_wireguard_interface(name: &str) -> Option<String> {
        let pid_file = PathBuf::from(WIREGUARD_RUN_DIR).join(format!("{name}.name"));
        if pid_file.exists() {
            Some(
                std::fs::read_to_string(&pid_file)
                    .map_or_else(|_| name.to_string(), |s| s.trim().to_string()),
            )
        } else if check_wg_interface_exists(name) {
            Some(name.to_string())
        } else {
            None
        }
    }

    fn get_wireguard_pid(interface: &str) -> Option<u32> {
        let sock_path = format!("{WIREGUARD_RUN_DIR}/{interface}.sock");

        // Use lsof to get the PID of the process holding the socket
        if let Some(output) = cmd_output("lsof", &["-t", &sock_path]) {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !stdout.is_empty() {
                return stdout.parse::<u32>().ok();
            }
        }

        // Fallback: search via ps
        if let Some(output) = cmd_output("ps", &["-ax", "-o", "pid,command"]) {
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
        let mut ip = String::new();
        let mut mtu = String::new();

        if let Some(output) = cmd_output("ifconfig", &[interface]) {
            let out = String::from_utf8_lossy(&output.stdout);
            for line in out.lines() {
                let line = line.trim();
                if line.starts_with("inet ") && ip.is_empty() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        ip = parts[1].to_string();
                    }
                }
                if let Some(v) = line.split("mtu ").nth(1) {
                    if mtu.is_empty() {
                        mtu = v.split_whitespace().next().unwrap_or("").to_string();
                    }
                }
            }
        }

        (ip, mtu)
    }
}

fn check_wg_interface_exists(name: &str) -> bool {
    cmd_output("wg", &["show", name, "public-key"]).is_some_and(|o| o.status.success())
}
