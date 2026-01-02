//! CLI command handlers.

use crate::cli::args::Commands;
use color_eyre::Result;
use std::path::Path;

/// Handles CLI commands that don't require the TUI.
///
/// Returns `true` if the command was handled and the program should exit,
/// or `false` if the TUI should be started.
#[allow(clippy::unnecessary_wraps)]
pub fn handle_command(command: &Commands) -> Result<bool> {
    match command {
        Commands::Import { file } => {
            handle_import(file);
            Ok(true)
        }
        Commands::Update => {
            handle_update();
            Ok(true)
        }
    }
}

/// Imports a VPN profile from the specified file path.
fn handle_import(file: &str) {
    let path = Path::new(file);

    // Expand ~ to home directory
    let expanded_path = if let Some(stripped) = file.strip_prefix("~/") {
        if let Some(home) = crate::utils::home_dir() {
            home.join(stripped)
        } else {
            path.to_path_buf()
        }
    } else {
        path.to_path_buf()
    };

    match crate::vpn::import_profile(&expanded_path) {
        Ok(profile) => {
            println!("✅ Imported profile: {}", profile.name);
            println!("   Protocol: {}", profile.protocol);
            println!("   Location: {}", profile.location);
            println!("   Saved to: {}", profile.config_path.display());
        }
        Err(e) => {
            eprintln!("❌ Import failed: {e}");
            std::process::exit(1);
        }
    }
}

/// Handles the update command by running cargo install.
fn handle_update() {
    println!("🔄 Updating vortix...\n");

    let status = std::process::Command::new("cargo")
        .args(["install", "vortix", "--force"])
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("\n✅ Successfully updated vortix!");
            println!("   Run 'vortix --version' to see the new version.");
        }
        Ok(_) => {
            eprintln!("\n❌ Update failed. Please try manually:");
            eprintln!("   cargo install vortix --force");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ Failed to run cargo: {e}");
            eprintln!("   Make sure cargo is installed and in your PATH.");
            std::process::exit(1);
        }
    }
}
