//! Linux adapters:
//! - firewall via one atomic nftables `inet` transaction.
//! - DNS via resolvectl → nmcli → /etc/resolv.conf.
//! - interfaces via direct kernel/sysfs observation.
//! - byte counters via /proc/net/dev.
//! - routes via `ip route show default`.

#![allow(clippy::missing_errors_doc)]

pub mod autoconnect;
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

/// Opens a link in the user's default browser.
pub const BROWSER_OPENER: &str = "xdg-open";

/// Whether `uid` has a graphical desktop to open a browser on. Without one,
/// `xdg-open` falls back to a text browser in this very terminal.
#[must_use]
pub fn has_desktop(uid: u32) -> bool {
    session_display(uid).is_some()
}

/// The display of `uid`'s desktop session: from the environment when `sudo`
/// kept it, else that user's own Wayland socket or X socket.
fn session_display(uid: u32) -> Option<(&'static str, String)> {
    use std::os::unix::fs::MetadataExt as _;
    for name in ["WAYLAND_DISPLAY", "DISPLAY"] {
        if let Ok(value) = std::env::var(name) {
            return Some((name, value));
        }
    }
    let owned =
        |path: &std::path::Path| std::fs::metadata(path).is_ok_and(|meta| meta.uid() == uid);
    let socket = |dir: &str, prefix: &str| {
        std::fs::read_dir(dir).ok()?.flatten().find_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let lock = entry.path().extension().is_some_and(|ext| ext == "lock");
            (name.starts_with(prefix) && !lock && owned(&entry.path())).then_some(name)
        })
    };
    if let Some(wayland) = socket(&format!("/run/user/{uid}"), "wayland-") {
        return Some(("WAYLAND_DISPLAY", wayland));
    }
    socket("/tmp/.X11-unix", "X").map(|x| ("DISPLAY", format!(":{}", &x[1..])))
}

/// What a command run as `uid` needs to reach that user's desktop session,
/// which `sudo` strips from the environment.
#[must_use]
pub fn desktop_env(uid: u32) -> std::collections::HashMap<String, String> {
    let runtime = format!("/run/user/{uid}");
    let mut env = std::collections::HashMap::from([(
        "DBUS_SESSION_BUS_ADDRESS".to_string(),
        format!("unix:path={runtime}/bus"),
    )]);
    env.insert("XDG_RUNTIME_DIR".into(), runtime);
    if let Some((name, display)) = session_display(uid) {
        env.insert(name.into(), display);
    }
    env
}

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
