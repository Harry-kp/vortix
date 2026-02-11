//! CLI command handlers.

use crate::cli::args::Commands;
use color_eyre::Result;
use std::path::Path;

/// Handles CLI commands that don't require the TUI.
///
/// Returns `true` if the command was handled and the program should exit,
/// or `false` if the TUI should be started.
#[allow(clippy::unnecessary_wraps)]
pub fn handle_command(command: &Commands, config_dir: &Path, config_source: &str) -> Result<bool> {
    match command {
        Commands::Import { file } => {
            handle_import(file);
            Ok(true)
        }
        Commands::Info => {
            handle_info(config_dir, config_source);
            Ok(true)
        }
        Commands::Update => {
            handle_update();
            Ok(true)
        }
        Commands::ReleaseKillSwitch => {
            handle_release_killswitch();
            Ok(true)
        }
    }
}

use crate::constants;

/// Imports a VPN profile from the specified file path or directory.
fn handle_import(file: &str) {
    use crate::core::importer::{resolve_target, ImportTarget};

    match resolve_target(file) {
        Ok(ImportTarget::Url(url)) => {
            println!("{}", constants::CLI_MSG_DOWNLOADING);
            match crate::core::downloader::download_profile(&url) {
                Ok(downloaded_path) => {
                    // The downloaded path is a temp file
                    import_single_file(&downloaded_path);
                }
                Err(e) => {
                    eprintln!("{}{}", constants::CLI_MSG_IMPORT_FAILED, e);
                    std::process::exit(1);
                }
            }
        }
        Ok(ImportTarget::File(path)) => {
            import_single_file(&path);
        }
        Ok(ImportTarget::Directory(path)) => {
            import_from_directory(&path);
        }
        Err(e) => {
            eprintln!("{}{}", constants::CLI_MSG_ERROR, e);
            std::process::exit(1);
        }
    }
}

/// Import a single VPN profile file
fn import_single_file(path: &Path) {
    match crate::vpn::import_profile(path) {
        Ok(profile) => {
            println!("{}{}", constants::CLI_MSG_IMPORT_SUCCESS, profile.name);
            println!(
                "{}{}",
                constants::CLI_MSG_IMPORT_DETAILS_PROTO,
                profile.protocol
            );
            println!(
                "{}{}",
                constants::CLI_MSG_IMPORT_DETAILS_LOC,
                profile.location
            );
            println!(
                "{}{}",
                constants::CLI_MSG_IMPORT_DETAILS_PATH,
                profile.config_path.display()
            );
        }
        Err(e) => {
            eprintln!("{}{}", constants::CLI_MSG_IMPORT_FAILED, e);
            std::process::exit(1);
        }
    }
}

/// Bulk import all .conf and .ovpn files from a directory
fn import_from_directory(dir_path: &Path) {
    let mut imported = 0;
    let mut failed = 0;

    match std::fs::read_dir(dir_path) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();

                if path.is_file()
                    && path
                        .extension()
                        .is_some_and(|ext| ext == "conf" || ext == "ovpn")
                {
                    match crate::vpn::import_profile(&path) {
                        Ok(profile) => {
                            println!("  ✅ {}", profile.name); // Keeping checkmark list item simple
                            imported += 1;
                        }
                        Err(e) => {
                            eprintln!("  ❌ {} - {}", path.display(), e);
                            failed += 1;
                        }
                    }
                }
            }

            // Show summary
            println!("{}", constants::CLI_MSG_SUMMARY_HEADER);
            println!("{}{}", constants::CLI_MSG_SUMMARY_IMPORTED, imported);
            if failed > 0 {
                println!("{}{}", constants::CLI_MSG_SUMMARY_FAILED, failed);
            }

            if imported == 0 {
                eprintln!("{}", constants::CLI_MSG_NO_FILES);
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("{}{}", constants::CLI_MSG_DIR_ERROR, e);
            std::process::exit(1);
        }
    }
}

/// Counts VPN profiles in a directory, split by protocol.
///
/// Returns `(wireguard_count, openvpn_count)`.
fn count_profiles(profiles_dir: &Path) -> (u32, u32) {
    if !profiles_dir.is_dir() {
        return (0, 0);
    }
    let mut wg = 0u32;
    let mut ovpn = 0u32;
    if let Ok(entries) = std::fs::read_dir(profiles_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                match path.extension().and_then(|e| e.to_str()) {
                    Some("conf") => wg += 1,
                    Some("ovpn") => ovpn += 1,
                    _ => {}
                }
            }
        }
    }
    (wg, ovpn)
}

/// Handles the info command -- prints resolved paths and profile summary.
fn handle_info(config_dir: &Path, source: &str) {
    let profiles_dir = config_dir.join(constants::PROFILES_DIR_NAME);
    let (wg_count, ovpn_count) = count_profiles(&profiles_dir);
    let total = wg_count + ovpn_count;

    let config_file = config_dir.join("config.toml");
    let config_status = if config_file.is_file() {
        "loaded"
    } else {
        "not found, using defaults"
    };

    println!("vortix {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("  Config dir:  {} ({source})", config_dir.display());
    println!("  Config file: {} ({config_status})", config_file.display());
    println!("  Profiles:    {total} ({wg_count} WireGuard, {ovpn_count} OpenVPN)");
    println!("  Profiles at: {}", profiles_dir.display());
    println!(
        "  Logs at:     {}",
        config_dir.join(constants::LOGS_DIR_NAME).display()
    );
}

/// Handles the update command by running cargo install.
fn handle_update() {
    println!("{}", constants::CLI_MSG_UPDATE_START);

    let status = std::process::Command::new("cargo")
        .args(["install", "vortix", "--force"])
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("{}", constants::CLI_MSG_UPDATE_SUCCESS);
            println!("{}", constants::CLI_MSG_UPDATE_CHECK);
        }
        Ok(_) => {
            eprintln!("{}", constants::CLI_MSG_UPDATE_FAIL_MANUAL);
            eprintln!("{}", constants::CLI_MSG_UPDATE_CMD);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("{}{}", constants::CLI_MSG_UPDATE_FAIL_CARGO, e);
            eprintln!("{}", constants::CLI_MSG_UPDATE_PATH_HINT);
            std::process::exit(1);
        }
    }
}

/// Handles the release-killswitch command.
/// Emergency release of kill switch firewall rules.
fn handle_release_killswitch() {
    println!("Releasing kill switch...");

    // Attempt to disable blocking
    match crate::core::killswitch::disable_blocking() {
        Ok(()) => {
            println!("Kill switch firewall rules flushed.");
        }
        Err(e) => {
            eprintln!("Warning: Failed to flush firewall rules: {e}");
            eprintln!("{}", crate::platform::KILLSWITCH_EMERGENCY_MSG);
        }
    }

    // Clear persisted state
    crate::core::killswitch::clear_state();
    println!("Kill switch state cleared.");
    println!("Internet access should be restored.");
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- count_profiles ----

    #[test]
    fn test_count_profiles_empty_dir() {
        let dir = std::env::temp_dir().join("vortix_test_count_empty");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let (wg, ovpn) = count_profiles(&dir);
        assert_eq!(wg, 0);
        assert_eq!(ovpn, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_count_profiles_nonexistent_dir() {
        let dir = std::env::temp_dir().join("vortix_test_count_nodir");
        let _ = std::fs::remove_dir_all(&dir);

        let (wg, ovpn) = count_profiles(&dir);
        assert_eq!(wg, 0);
        assert_eq!(ovpn, 0);
    }

    #[test]
    fn test_count_profiles_mixed() {
        let dir = std::env::temp_dir().join("vortix_test_count_mixed");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // WireGuard profiles
        std::fs::write(dir.join("wg0.conf"), "[Interface]").unwrap();
        std::fs::write(dir.join("wg1.conf"), "[Interface]").unwrap();
        // OpenVPN profiles
        std::fs::write(dir.join("us.ovpn"), "remote us.vpn").unwrap();
        // Non-profile files (should be ignored)
        std::fs::write(dir.join("notes.txt"), "hello").unwrap();
        std::fs::write(dir.join("backup.bak"), "data").unwrap();
        // Subdirectory (should be ignored)
        std::fs::create_dir_all(dir.join("subdir")).unwrap();

        let (wg, ovpn) = count_profiles(&dir);
        assert_eq!(wg, 2);
        assert_eq!(ovpn, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- handle_info output ----

    #[test]
    fn test_handle_info_with_profiles() {
        let dir = std::env::temp_dir().join("vortix_test_info");
        let _ = std::fs::remove_dir_all(&dir);
        let profiles = dir.join("profiles");
        std::fs::create_dir_all(&profiles).unwrap();
        std::fs::write(profiles.join("vpn.conf"), "[Interface]").unwrap();
        std::fs::write(profiles.join("us.ovpn"), "remote us.vpn").unwrap();

        // Should not panic and prints to stdout
        handle_info(&dir, "default");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_handle_info_with_config_toml() {
        let dir = std::env::temp_dir().join("vortix_test_info_toml");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.toml"), "tick_rate = 500").unwrap();

        handle_info(&dir, "from --config-dir");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
