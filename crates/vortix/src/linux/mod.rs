//! Linux adapters:
//! - firewall via one atomic nftables `inet` transaction.
//! - DNS via resolvectl → nmcli → /etc/resolv.conf.
//! - interfaces via direct kernel/sysfs observation.
//! - byte counters via /proc/net/dev.
//! - routes via `ip route show default`.

#![allow(clippy::missing_errors_doc)]

pub mod dns;
pub mod firewall;
pub mod interface;
pub mod process_identity;
pub mod route_table;
pub mod socket_audit;

pub use dns::LinuxDns;
pub use firewall::NftFirewall;
pub use interface::LinuxInterface;
pub use interface::LinuxNetworkStats;
pub use route_table::LinuxRouteTable;
pub use socket_audit::ProcSocketAudit;

const POLICY_COMMENT_PREFIX: &str = "vortix-policy:";

/// Report line for this OS, e.g. `Ubuntu 24.04 LTS (kernel 6.8.0)`.
#[must_use]
pub fn os_description() -> String {
    let distro = linux_distro_name().unwrap_or_else(|| "Linux".to_string());
    let kernel = crate::platform::uname_release().unwrap_or_default();
    if kernel.is_empty() {
        distro
    } else {
        format!("{distro} (kernel {kernel})")
    }
}

/// The kill-switch firewall tool and its version flag.
pub const FIREWALL_TOOL: (&str, &[&str]) = ("nft", &["--version"]);

/// Clipboard writers to try, in order: the session's own first.
#[must_use]
pub fn clipboard_commands() -> Vec<&'static str> {
    if std::env::var("WAYLAND_DISPLAY").is_ok() {
        vec!["wl-copy", "xclip", "xsel"]
    } else {
        vec!["xclip", "xsel", "wl-copy"]
    }
}

fn linux_distro_name() -> Option<String> {
    let content = std::fs::read_to_string("/etc/os-release").ok()?;
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("PRETTY_NAME=") {
            return Some(value.trim_matches('"').to_string());
        }
    }
    None
}
