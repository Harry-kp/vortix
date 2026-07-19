//! Boot-service artifact generation + install locations (plan
//! 2026-07-19-001 P5 — `vortix service install/uninstall`).
//!
//! Generation is pure string-building over a [`ServiceSpec`] so golden
//! tests exercise BOTH platforms' artifacts on any host (a macOS dev
//! box can't run systemd, but it can assert the unit byte-for-byte).
//! Only [`ServiceManager::detect`] is platform-gated; everything else
//! is data.

use std::path::PathBuf;

/// Values baked into a generated service artifact.
#[derive(Debug, Clone)]
pub struct ServiceSpec {
    /// Absolute path of the vortix binary the service execs.
    pub binary: PathBuf,
    /// Unprivileged uid the root daemon serves (P2 owner auth —
    /// becomes `VORTIX_OWNER_UID` in the service environment).
    pub owner_uid: u32,
    /// The owner's config dir (profiles, settings) — the daemon must
    /// resolve the SAME catalog the owner's clients use.
    pub config_dir: PathBuf,
}

/// Which init system owns boot services on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceManager {
    Systemd,
    Launchd,
}

impl ServiceManager {
    /// The init system for the running OS. One cfg seam, mirroring
    /// `Platform::detect_current`'s detect-once pattern.
    #[must_use]
    pub fn detect() -> Option<Self> {
        // Which init system exists is a compile-time OS fact with no
        // runtime probe; generation stays pure over both variants so
        // goldens run on any host — only this seam is gated.
        #[cfg(target_os = "linux")] // xtask:allow-platform-cfg: init-system selection seam
        {
            Some(Self::Systemd)
        }
        #[cfg(target_os = "macos")] // xtask:allow-platform-cfg: init-system selection seam
        {
            Some(Self::Launchd)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            None
        }
    }

    /// Where the generated artifact is installed.
    #[must_use]
    pub fn install_path(self) -> PathBuf {
        match self {
            Self::Systemd => PathBuf::from("/etc/systemd/system/vortix-daemon.service"),
            Self::Launchd => PathBuf::from("/Library/LaunchDaemons/com.vortix.daemon.plist"),
        }
    }

    /// Render the artifact for `spec`.
    #[must_use]
    pub fn render(self, spec: &ServiceSpec) -> String {
        match self {
            Self::Systemd => systemd_unit(spec),
            Self::Launchd => launchd_plist(spec),
        }
    }
}

/// systemd unit for a root daemon serving `owner_uid` on the canonical
/// system socket. `--socket` is explicit — the boot environment has no
/// user session vars to resolve a path from.
#[must_use]
pub fn systemd_unit(spec: &ServiceSpec) -> String {
    let socket = super::system_socket_path();
    format!(
        "\
[Unit]
Description=Vortix VPN engine daemon
Documentation=https://github.com/Harry-kp/vortix
After=network.target

[Service]
Type=simple
ExecStart={binary} daemon --socket {socket}
Restart=on-failure
RestartSec=5
# The daemon runs as root for privileged subprocess work (wg-quick,
# openvpn, firewall rules) and serves its unprivileged owner over the
# peer-credential-authenticated Unix socket (P2 owner auth).
User=root
Group=root
Environment=VORTIX_OWNER_UID={owner_uid}
Environment=VORTIX_CONFIG_DIR={config_dir}
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
",
        binary = spec.binary.display(),
        socket = socket.display(),
        owner_uid = spec.owner_uid,
        config_dir = spec.config_dir.display(),
    )
}

/// launchd daemon plist — the macOS counterpart of [`systemd_unit`].
#[must_use]
pub fn launchd_plist(spec: &ServiceSpec) -> String {
    let socket = super::system_socket_path();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.vortix.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary}</string>
        <string>daemon</string>
        <string>--socket</string>
        <string>{socket}</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>VORTIX_OWNER_UID</key>
        <string>{owner_uid}</string>
        <key>VORTIX_CONFIG_DIR</key>
        <string>{config_dir}</string>
    </dict>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/vortix-daemon.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/vortix-daemon.log</string>
</dict>
</plist>
"#,
        binary = spec.binary.display(),
        socket = socket.display(),
        owner_uid = spec.owner_uid,
        config_dir = spec.config_dir.display(),
    )
}

/// Everything `vortix service uninstall` must remove for the R12
/// no-zombie guarantee, and `install`'s pre-flight overwrite check.
#[must_use]
pub fn managed_artifacts(manager: ServiceManager) -> Vec<PathBuf> {
    vec![manager.install_path(), super::system_socket_path()]
}

/// True when `path` looks like an artifact vortix generated (guards
/// uninstall against deleting a hand-written unit it doesn't own).
#[must_use]
pub fn is_vortix_artifact(content: &str) -> bool {
    content.contains("vortix") && content.contains("daemon")
}

#[allow(clippy::doc_markdown)]
#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ServiceSpec {
        ServiceSpec {
            binary: PathBuf::from("/usr/local/bin/vortix"),
            owner_uid: 501,
            config_dir: PathBuf::from("/Users/alice/.config/vortix"),
        }
    }

    #[test]
    fn systemd_unit_golden() {
        let unit = systemd_unit(&spec());
        let expected = "\
[Unit]
Description=Vortix VPN engine daemon
Documentation=https://github.com/Harry-kp/vortix
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/vortix daemon --socket /var/run/vortix.sock
Restart=on-failure
RestartSec=5
# The daemon runs as root for privileged subprocess work (wg-quick,
# openvpn, firewall rules) and serves its unprivileged owner over the
# peer-credential-authenticated Unix socket (P2 owner auth).
User=root
Group=root
Environment=VORTIX_OWNER_UID=501
Environment=VORTIX_CONFIG_DIR=/Users/alice/.config/vortix
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
";
        assert_eq!(unit, expected);
    }

    #[test]
    fn launchd_plist_golden_carries_socket_env_and_boot_keys() {
        let plist = launchd_plist(&spec());
        for needle in [
            "<string>/usr/local/bin/vortix</string>",
            "<string>--socket</string>",
            "<string>/var/run/vortix.sock</string>",
            "<key>VORTIX_OWNER_UID</key>",
            "<string>501</string>",
            "<key>VORTIX_CONFIG_DIR</key>",
            "<string>/Users/alice/.config/vortix</string>",
            "<key>RunAtLoad</key>",
            "<key>KeepAlive</key>",
        ] {
            assert!(plist.contains(needle), "missing {needle} in:\n{plist}");
        }
    }

    #[test]
    fn install_paths_are_the_canonical_system_locations() {
        assert_eq!(
            ServiceManager::Systemd.install_path(),
            PathBuf::from("/etc/systemd/system/vortix-daemon.service")
        );
        assert_eq!(
            ServiceManager::Launchd.install_path(),
            PathBuf::from("/Library/LaunchDaemons/com.vortix.daemon.plist")
        );
    }

    #[test]
    fn generated_artifacts_pass_the_ownership_probe() {
        assert!(is_vortix_artifact(&systemd_unit(&spec())));
        assert!(is_vortix_artifact(&launchd_plist(&spec())));
        assert!(!is_vortix_artifact("[Unit]\nDescription=nginx\n"));
    }

    #[test]
    fn managed_artifacts_cover_unit_and_socket() {
        let arts = managed_artifacts(ServiceManager::Systemd);
        assert!(arts.contains(&PathBuf::from("/etc/systemd/system/vortix-daemon.service")));
        assert!(arts.contains(&PathBuf::from("/var/run/vortix.sock")));
    }
}
