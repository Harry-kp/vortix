//! Command-line argument definitions.

use clap::{Parser, Subcommand};

/// Vortix - Professional TUI VPN Manager
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Subcommand to execute
    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Available CLI commands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Import a VPN profile from a file (.ovpn or .conf)
    Import {
        /// Path to the profile file
        file: String,
    },
    /// Update vortix to the latest version from crates.io
    Update,
}
