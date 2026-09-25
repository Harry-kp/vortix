//! What changed since the version that last ran here, shown once after an
//! upgrade. `state-version` in the config directory records that version.
//!
//! Each release adds one [`Release`] to [`RELEASES`]: the steps a user must
//! take (per OS) and a few highlights. The same text goes in CHANGELOG.md.

use std::io::Write as _;
use std::path::Path;

const MARKER: &str = "state-version";
/// Older versions wrote no marker; a config directory with profiles but no
/// marker was last run by one of them.
const UNMARKED: &str = "0.4.3";
pub const CHANGELOG_URL: &str =
    "https://github.com/Harry-kp/vortix/blob/main/crates/vortix/CHANGELOG.md";
const UPGRADE_URL: &str =
    "https://github.com/Harry-kp/vortix/blob/main/docs/MIGRATION.md#upgrading-from-043-to-050";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Any,
    MacOs,
    Linux,
}

#[derive(Debug)]
pub enum Cmd {
    Run(&'static str),
    /// Install this package with the machine's own package manager.
    Install(&'static str),
}

/// When a step applies, so the popup lists only what this machine needs.
#[derive(Debug)]
pub enum When {
    Always,
    /// This command is not installed.
    MissingTool(&'static str),
    /// This file exists.
    FileExists(&'static str),
}

#[derive(Debug)]
pub struct Step {
    pub os: Os,
    pub when: When,
    pub title: &'static str,
    pub why: &'static str,
    pub commands: &'static [Cmd],
}

#[derive(Debug)]
pub struct Release {
    pub version: &'static str,
    pub steps: &'static [Step],
    pub highlights: &'static [&'static str],
}

pub const RELEASES: &[Release] = &[Release {
    version: "0.5.0",
    steps: &[
        Step {
            os: Os::Any,
            when: When::Always,
            title: "If a VPN or the kill switch was on when you upgraded, restart your computer",
            why: "The previous version's tunnel and firewall rules can outlive it, and this version cannot remove them; on a Mac they can keep blocking your internet. A restart clears them. Skip this if nothing was on. Cannot restart now? The commands are on the Details page.",
            commands: &[],
        },
        Step {
            os: Os::Linux,
            when: When::MissingTool("nft"),
            title: "Install nftables",
            why: "The kill switch now needs it, and it is not installed.",
            commands: &[Cmd::Install("nftables")],
        },
        Step {
            os: Os::Linux,
            when: When::FileExists("/etc/systemd/system/vortix-daemon.service"),
            title: "Remove the old `vortix daemon` service",
            why: "That command no longer exists, so the service fails and restarts every few seconds.",
            commands: &[
                Cmd::Run("sudo systemctl disable --now vortix-daemon"),
                Cmd::Run("sudo rm /etc/systemd/system/vortix-daemon.service"),
            ],
        },
        Step {
            os: Os::MacOs,
            when: When::FileExists("/Library/LaunchDaemons/com.vortix.daemon.plist"),
            title: "Remove the old `vortix daemon` service",
            why: "That command no longer exists, so the service fails and restarts every few seconds.",
            commands: &[
                Cmd::Run("sudo launchctl bootout system/com.vortix.daemon"),
                Cmd::Run("sudo rm /Library/LaunchDaemons/com.vortix.daemon.plist"),
            ],
        },
    ],
    highlights: &[
        "Linux works end to end: Ubuntu, Debian, Fedora, Arch and CachyOS.",
        "Several VPNs at once: a switch brings the new tunnel up before stopping the old one.",
        "The kill switch reports what the firewall is really doing, and fails closed.",
        "The Logs panel shows each OpenVPN tunnel's own log (press f).",
        "Clearer messages that say what broke and what to do, and a smaller binary.",
    ],
}];

/// What the config directory's history says about this run.
#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    /// Fresh install, or the same version as last time.
    Current,
    Upgraded {
        from: String,
    },
    /// A newer Vortix last wrote these files.
    Downgraded {
        from: String,
    },
}

fn parse(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.trim().split('.').map(|part| part.parse().ok());
    Some((parts.next()??, parts.next()??, parts.next()??))
}

#[must_use]
pub fn status(config_dir: &Path, current: &str) -> Status {
    let recorded = std::fs::read_to_string(config_dir.join(MARKER)).ok();
    let from = match recorded {
        Some(version) => version.trim().to_owned(),
        None if has_profiles(config_dir) => UNMARKED.to_owned(),
        None => return Status::Current,
    };
    match (parse(&from), parse(current)) {
        (Some(old), Some(new)) if old < new => Status::Upgraded { from },
        (Some(old), Some(new)) if old > new => Status::Downgraded { from },
        _ => Status::Current,
    }
}

fn has_profiles(config_dir: &Path) -> bool {
    std::fs::read_dir(config_dir.join(crate::constants::PROFILES_DIR_NAME))
        .is_ok_and(|mut entries| entries.next().is_some())
}

/// Record that `current` has run here.
pub fn record(config_dir: &Path, current: &str) -> std::io::Result<()> {
    let path = config_dir.join(MARKER);
    if std::fs::read_to_string(&path).is_ok_and(|recorded| recorded.trim() == current) {
        return Ok(());
    }
    let mut file = crate::config::owned_file::open_user_file(&config_dir.join(MARKER), false)?;
    file.set_len(0)?;
    writeln!(file, "{current}")
}

/// Releases after `from` up to and including `current`.
#[must_use]
pub fn releases_since(from: &str, current: &str) -> Vec<&'static Release> {
    let (Some(from), Some(current)) = (parse(from), parse(current)) else {
        return Vec::new();
    };
    RELEASES
        .iter()
        .filter(|release| parse(release.version).is_some_and(|v| v > from && v <= current))
        .collect()
}

fn this_os() -> Os {
    match std::env::consts::OS {
        "macos" => Os::MacOs,
        "linux" => Os::Linux,
        _ => Os::Any,
    }
}

/// The steps in `releases` that apply to this machine.
#[must_use]
pub fn steps(releases: &[&'static Release]) -> Vec<&'static Step> {
    let os = this_os();
    releases
        .iter()
        .flat_map(|release| release.steps)
        .filter(|step| step.os == Os::Any || step.os == os)
        .filter(|step| match step.when {
            When::Always => true,
            When::MissingTool(tool) => !on_path(tool),
            When::FileExists(path) => Path::new(path).exists(),
        })
        .collect()
}

/// Whether upgrading from `from` asks this machine's user to do something.
#[must_use]
pub fn needs_action(from: &str, current: &str) -> bool {
    !steps(&releases_since(from, current)).is_empty()
}

fn on_path(tool: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path)
            .chain(["/usr/sbin".into(), "/sbin".into()])
            .any(|dir| dir.join(tool).is_file())
    })
}

#[must_use]
pub fn command_text(cmd: &Cmd) -> String {
    match cmd {
        Cmd::Run(text) => (*text).to_owned(),
        Cmd::Install(package) => crate::platform::install_hint(package),
    }
}

/// The upgrade steps as plain text, for the CLI.
#[must_use]
pub fn plain_text(from: &str, releases: &[&'static Release]) -> String {
    use std::fmt::Write as _;
    let mut out = format!("Vortix was upgraded from {from}.");
    let steps = steps(releases);
    if !steps.is_empty() {
        out.push_str(" Action needed:");
    }
    for (n, step) in steps.iter().enumerate() {
        let _ = write!(out, "\n  {}. {}\n     Why: {}", n + 1, step.title, step.why);
        for cmd in step.commands {
            let _ = write!(out, "\n     $ {}", command_text(cmd));
        }
    }
    if !steps.is_empty() {
        let _ = write!(out, "\n  Details: {UPGRADE_URL}");
    }
    let _ = write!(out, "\n  What's new: {CHANGELOG_URL}");
    out
}

#[must_use]
pub const fn upgrade_url() -> &'static str {
    UPGRADE_URL
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn a_fresh_install_is_current_and_an_unmarked_one_is_an_upgrade_from_043() {
        let d = dir();
        assert_eq!(status(d.path(), "0.5.0"), Status::Current);
        std::fs::create_dir(d.path().join(crate::constants::PROFILES_DIR_NAME)).unwrap();
        std::fs::write(d.path().join("profiles/wg0.conf"), "").unwrap();
        assert_eq!(
            status(d.path(), "0.5.0"),
            Status::Upgraded {
                from: "0.4.3".into()
            }
        );
    }

    #[test]
    fn the_marker_decides_upgrade_downgrade_and_current() {
        let d = dir();
        record(d.path(), "0.5.0").unwrap();
        assert_eq!(status(d.path(), "0.5.0"), Status::Current);
        assert_eq!(
            status(d.path(), "0.6.0"),
            Status::Upgraded {
                from: "0.5.0".into()
            }
        );
        assert_eq!(
            status(d.path(), "0.4.3"),
            Status::Downgraded {
                from: "0.5.0".into()
            }
        );
    }

    #[test]
    fn only_releases_after_the_recorded_version_are_shown() {
        assert_eq!(releases_since("0.4.3", "0.5.0").len(), 1);
        assert!(releases_since("0.5.0", "0.5.0").is_empty());
        assert!(releases_since("0.4.3", "0.4.3").is_empty());
    }

    #[test]
    fn every_step_has_a_reason() {
        for release in RELEASES {
            assert!(parse(release.version).is_some());
            for step in release.steps {
                assert!(!step.title.is_empty() && !step.why.is_empty());
            }
        }
    }
}
