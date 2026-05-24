//! macOS DNS resolver using scutil and networksetup.

use crate::constants;
use crate::platform::DnsResolver;

/// macOS DNS resolution via scutil --dns, networksetup, and /etc/resolv.conf.
pub struct MacDns;

impl DnsResolver for MacDns {
    fn get_dns_server() -> Option<String> {
        // scutil is the canonical macOS DNS source; resolv.conf can be stale
        try_get_dns_scutil()
            .or_else(try_get_dns_resolv_conf)
            .or_else(try_get_dns_networksetup)
    }
}

/// Try to get DNS from /etc/resolv.conf
fn try_get_dns_resolv_conf() -> Option<String> {
    let content = std::fs::read_to_string(constants::RESOLV_CONF_PATH).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("nameserver") {
            let dns = trimmed.trim_start_matches("nameserver").trim().to_string();
            if !dns.is_empty() {
                return Some(dns);
            }
        }
    }
    None
}

/// Try to get DNS from scutil (macOS)
fn try_get_dns_scutil() -> Option<String> {
    let output = std::process::Command::new("scutil")
        .args(["--dns"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("nameserver[0]") {
            if let Some(dns) = trimmed.split(':').nth(1) {
                let dns = dns.trim().to_string();
                if !dns.is_empty() {
                    return Some(dns);
                }
            }
        }
    }
    None
}

/// Try to get DNS from networksetup (macOS)
fn try_get_dns_networksetup() -> Option<String> {
    let output = std::process::Command::new("networksetup")
        .args(["-listallnetworkservices"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for service in ["Wi-Fi", "Ethernet", "USB 10/100/1000 LAN"] {
        if stdout.contains(service) {
            if let Ok(dns_output) = std::process::Command::new("networksetup")
                .args(["-getdnsservers", service])
                .output()
            {
                let dns_stdout = String::from_utf8_lossy(&dns_output.stdout);
                let first_line = dns_stdout.lines().next().unwrap_or("").trim();
                if !first_line.is_empty() && !first_line.contains("aren't") {
                    return Some(first_line.to_string());
                }
            }
        }
    }
    None
}
