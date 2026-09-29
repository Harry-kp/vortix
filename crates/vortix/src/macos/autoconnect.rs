//! Connect a profile at boot: a launchd daemon that runs `vortix up` once at load and again
//! only after a failed attempt. The plist is the only state.

use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

use crate::process::{CommandSpec, PrivilegeReq};

const LABEL: &str = "com.vortix.autoconnect";
/// Where the boot daemon's plist lives.
pub const UNIT_PATH: &str = "/Library/LaunchDaemons/com.vortix.autoconnect.plist";
const LOG_PATH: &str = "/var/log/vortix-autoconnect.log";

/// Write the plist. launchd loads it at the next boot.
pub fn install(command: &[String], env: &[(String, String)]) -> Result<(), String> {
    crate::platform::write_root_file(UNIT_PATH, &plist_text(command, env))
}

/// Unload and delete the plist; nothing to do when it is absent.
pub fn remove() -> Result<(), String> {
    if !Path::new(UNIT_PATH).exists() {
        return Ok(());
    }
    // Not loaded until the first boot after `install`, so a failed bootout is expected.
    let _ = crate::process::run(
        CommandSpec::oneshot(
            "launchctl",
            vec!["bootout".into(), format!("system/{LABEL}")],
        )
        .privilege(PrivilegeReq::Root)
        .timeout(Duration::from_secs(30)),
    );
    std::fs::remove_file(UNIT_PATH)
        .map_err(|error| format!("Could not remove {UNIT_PATH}: {error}"))
}

/// The profile the installed plist connects, if one is installed.
#[must_use]
pub fn installed_profile() -> Option<String> {
    profile_in(&std::fs::read_to_string(UNIT_PATH).ok()?)
}

/// Where the boot attempts log.
pub const LOG_HINT: &str = LOG_PATH;

fn plist_text(command: &[String], env: &[(String, String)]) -> String {
    let mut args = String::new();
    for item in command {
        let _ = writeln!(args, "\t\t<string>{item}</string>");
    }
    let mut vars = String::new();
    for (key, value) in env {
        let _ = writeln!(vars, "\t\t<key>{key}</key>\n\t\t<string>{value}</string>");
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{LABEL}</string>
	<key>ProgramArguments</key>
	<array>
{args}	</array>
	<key>EnvironmentVariables</key>
	<dict>
{vars}	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ThrottleInterval</key>
	<integer>30</integer>
	<key>AbandonProcessGroup</key>
	<true/>
	<key>StandardOutPath</key>
	<string>{LOG_PATH}</string>
	<key>StandardErrorPath</key>
	<string>{LOG_PATH}</string>
</dict>
</plist>
"#
    )
}

/// The profile is the last program argument, written on the line before `</array>`.
fn profile_in(plist: &str) -> Option<String> {
    let lines: Vec<&str> = plist.lines().collect();
    let end = lines.iter().position(|line| line.trim() == "</array>")?;
    let last = lines.get(end.checked_sub(1)?)?.trim();
    last.strip_prefix("<string>")?
        .strip_suffix("</string>")
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plist_is_valid_and_names_its_profile() {
        let command = [
            "/opt/homebrew/bin/vortix",
            "-C",
            "/Users/u/.config/vortix",
            "up",
            "Work VPN",
        ]
        .map(String::from);
        let env = [("SUDO_USER".to_string(), "u".to_string())];
        let plist = plist_text(&command, &env);
        assert_eq!(profile_in(&plist).as_deref(), Some("Work VPN"));

        let outcome = crate::process::run(
            CommandSpec::oneshot("plutil", vec!["-lint".into(), "-".into()])
                .stdin(plist.into_bytes()),
        )
        .expect("plutil runs");
        assert!(outcome.success(), "{}", outcome.stdout_lossy());
    }
}
