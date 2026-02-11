//! Command-line argument definitions.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Terminal UI for `WireGuard` and `OpenVPN` with real-time telemetry and leak guarding
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Override config directory (default: platform config dir, honors `XDG_CONFIG_HOME` and sudo)
    #[arg(
        short = 'C',
        long,
        value_name = "DIR",
        env = "VORTIX_CONFIG_DIR",
        global = true
    )]
    pub config_dir: Option<PathBuf>,

    /// Subcommand to execute
    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Available CLI commands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Import VPN profile(s) from a file, directory, or URL
    Import {
        /// Path to a .conf/.ovpn file, directory, or a URL (http/https)
        file: String,
    },
    /// Show config directory, profile count, and runtime info
    Info,
    /// Update vortix to the latest version from crates.io
    Update,
    /// Emergency release of kill switch (use if locked out)
    ReleaseKillSwitch,
}
