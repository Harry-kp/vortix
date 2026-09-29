//! Connect a profile at boot: a oneshot systemd unit that runs `vortix up` once the network is
//! online, then exits. The unit file is the only state.

use std::path::Path;
use std::time::Duration;

use crate::process::{CommandSpec, PrivilegeReq};

const UNIT: &str = "vortix-autoconnect.service";
/// Where the boot unit lives.
pub const UNIT_PATH: &str = "/etc/systemd/system/vortix-autoconnect.service";
const PROFILE_KEY: &str = "X-VortixProfile=";

/// Write and enable the unit. It takes effect at the next boot.
pub fn install(command: &[String], env: &[(String, String)]) -> Result<(), String> {
    if !Path::new("/run/systemd/system").exists() {
        return Err("Connecting at boot needs systemd, which isn't running here".to_string());
    }
    let program = command.first().map_or("", String::as_str);
    if selinux_enforcing() && (program.starts_with("/home/") || program.starts_with("/root/")) {
        return Err(format!(
            "SELinux won't let a boot unit run {program} from a home directory. Install Vortix \
             system-wide (your distribution's package, or `sudo install -m 755 {program} \
             /usr/local/bin/vortix`) and run this again with that binary"
        ));
    }
    crate::platform::write_root_file(UNIT_PATH, &unit_text(command, env))?;
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", UNIT])
}

/// Disable and delete the unit; nothing to do when it is absent.
pub fn remove() -> Result<(), String> {
    if !Path::new(UNIT_PATH).exists() {
        return Ok(());
    }
    systemctl(&["disable", UNIT])?;
    std::fs::remove_file(UNIT_PATH)
        .map_err(|error| format!("Could not remove {UNIT_PATH}: {error}"))?;
    systemctl(&["daemon-reload"])
}

/// The profile the installed unit connects, if one is installed.
#[must_use]
pub fn installed_profile() -> Option<String> {
    profile_in(&std::fs::read_to_string(UNIT_PATH).ok()?)
}

/// Where the boot attempts log.
pub const LOG_HINT: &str = "journalctl -u vortix-autoconnect.service";

fn unit_text(command: &[String], env: &[(String, String)]) -> String {
    let profile = command.last().map_or("", String::as_str);
    let quoted = |items: Vec<String>| {
        items
            .iter()
            .map(|item| format!("\"{item}\""))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let env = quoted(
        env.iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect(),
    );
    let exec = quoted(command.to_vec());
    format!(
        "[Unit]
Description=Vortix: connect {profile} at boot
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=600
StartLimitBurst=10
{PROFILE_KEY}{profile}

[Service]
Type=oneshot
RemainAfterExit=yes
KillMode=process
Environment={env}
ExecStart={exec}
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
"
    )
}

fn selinux_enforcing() -> bool {
    std::fs::read_to_string("/sys/fs/selinux/enforce").is_ok_and(|mode| mode.trim() == "1")
}

fn profile_in(unit: &str) -> Option<String> {
    unit.lines()
        .find_map(|line| line.strip_prefix(PROFILE_KEY))
        .map(str::to_string)
}

fn systemctl(args: &[&str]) -> Result<(), String> {
    let spec = CommandSpec::oneshot("systemctl", args.iter().map(ToString::to_string).collect())
        .privilege(PrivilegeReq::Root)
        .timeout(Duration::from_secs(30));
    let outcome = crate::process::run(spec)
        .map_err(|error| format!("systemctl {}: {error}", args.join(" ")))?;
    if outcome.success() {
        Ok(())
    } else {
        Err(format!(
            "systemctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&outcome.stderr).trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_log_hint_names_the_unit() {
        assert!(LOG_HINT.ends_with(UNIT));
    }

    #[test]
    fn the_unit_runs_vortix_up_after_the_network_and_names_its_profile() {
        let command = [
            "/usr/bin/vortix",
            "-C",
            "/home/u/.config/vortix",
            "up",
            "Work VPN",
        ]
        .map(String::from);
        let env = [("SUDO_USER".to_string(), "u".to_string())];
        let unit = unit_text(&command, &env);
        assert!(unit.contains(
            "ExecStart=\"/usr/bin/vortix\" \"-C\" \"/home/u/.config/vortix\" \"up\" \"Work VPN\""
        ));
        assert!(unit.contains("Environment=\"SUDO_USER=u\""));
        assert!(unit.contains("After=network-online.target"));
        assert_eq!(profile_in(&unit).as_deref(), Some("Work VPN"));
    }
}
