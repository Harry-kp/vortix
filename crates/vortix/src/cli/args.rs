//! Command-line argument definitions.
//!
//! Vortix CLI is designed after tailscale, gh, and rg:
//! - No subcommand → launch TUI dashboard
//! - Each subcommand is a headless CLI operation
//! - `-h` for concise help, `--help` for detailed help with examples
//! - `--json` on every command for machine-readable output

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueHint};

/// Terminal UI for `WireGuard` and `OpenVPN` — real-time telemetry, leak guarding, and kill switch.
///
/// Run without arguments to launch the interactive dashboard.
/// Use subcommands for headless CLI operations (ideal for scripts, cron, and AI agents).
///
/// EXAMPLES:
///     vortix                            Launch TUI dashboard
///     sudo vortix up work-vpn           Connect to 'work-vpn'
///     vortix status --json              Machine-readable connection status
///     vortix list --names-only          Profile names for scripting
///     vortix completions bash >> ~/.bashrc
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, after_long_help = GLOBAL_EXAMPLES)]
pub struct Args {
    /// Override config directory [env: `VORTIX_CONFIG_DIR`]
    #[arg(
        short = 'C',
        long,
        value_name = "DIR",
        env = "VORTIX_CONFIG_DIR",
        global = true,
        value_hint = ValueHint::DirPath,
    )]
    pub config_dir: Option<PathBuf>,

    /// Machine-readable JSON output
    #[arg(short = 'j', long, global = true)]
    pub json: bool,

    /// Suppress all output except errors (exit code only)
    #[arg(short = 'q', long, global = true)]
    pub quiet: bool,

    /// Verbose output (show debug details)
    #[arg(short = 'v', long, global = true)]
    pub verbose: bool,

    /// Subcommand to execute (omit for TUI)
    #[command(subcommand)]
    pub command: Option<Commands>,
}

const GLOBAL_EXAMPLES: &str = "\
GLOBAL FLAGS:
    -j, --json          Machine-readable JSON output
    -q, --quiet         Suppress all output except errors
    -v, --verbose       Verbose debug output
    -C, --config-dir    Override config directory

ENVIRONMENT VARIABLES:
    VORTIX_CONFIG_DIR   Override config directory

EXIT CODES:
    0  Success
    1  General error
    2  Permission denied (needs sudo)
    3  Not found (profile doesn't exist)
    4  State conflict (already connected/disconnected)
    5  Missing dependency (wg-quick, openvpn)
    6  Timeout";

/// Available CLI commands.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Connect to a VPN profile
    ///
    /// Connects to the specified profile, or reconnects to the last used profile
    /// if no name is given. Blocks until the connection is established or times out.
    ///
    /// EXAMPLES:
    ///     sudo vortix up work-vpn               Connect to 'work-vpn'
    ///     sudo vortix up work-vpn --json        Connect and get JSON result
    ///     sudo vortix up work-vpn --timeout 60  Connect with 60s timeout
    ///     sudo vortix up                        Reconnect to last used profile
    #[command(visible_alias = "connect")]
    Up {
        /// Profile name to connect to (omit to reconnect to last used)
        #[arg(value_hint = ValueHint::Other)]
        profile: Option<String>,

        /// Connection timeout in seconds
        #[arg(long, default_value = "20", value_name = "SECS")]
        timeout: u64,
    },

    /// Disconnect from VPN
    ///
    /// Gracefully disconnects the active VPN connection. If already disconnected,
    /// exits successfully (idempotent). Use --force to SIGKILL a stuck process.
    ///
    /// EXAMPLES:
    ///     sudo vortix down              Graceful disconnect
    ///     sudo vortix down --force      Force-kill if stuck
    ///     sudo vortix down --json       Disconnect with JSON result
    #[command(visible_alias = "disconnect")]
    Down {
        /// Force-kill the VPN process (SIGKILL)
        #[arg(short, long)]
        force: bool,
    },

    /// Reconnect to the last used VPN profile
    ///
    /// Disconnects (if connected) and reconnects to the most recently used profile.
    ///
    /// EXAMPLES:
    ///     sudo vortix reconnect         Reconnect to last used profile
    ///     sudo vortix reconnect --json  Reconnect with JSON result
    Reconnect,

    /// Show connection state and network telemetry
    ///
    /// Displays the current VPN connection status, network statistics, and
    /// security posture. Use --watch for continuous monitoring.
    ///
    /// EXAMPLES:
    ///     vortix status                          Human-readable status
    ///     vortix status --json                   Full status as JSON
    ///     vortix status --brief                  One-line summary
    ///     vortix status --watch                  Live updates every 2s
    ///     vortix status --watch --json           NDJSON stream for monitoring
    Status {
        /// Continuously update (streams NDJSON in --json mode)
        #[arg(short, long)]
        watch: bool,

        /// Watch interval in seconds
        #[arg(long, default_value = "2", value_name = "SECS")]
        interval: u64,

        /// One-line status summary
        #[arg(short, long)]
        brief: bool,
    },

    /// List imported VPN profiles
    ///
    /// Shows all imported profiles with their protocol and last-used timestamp.
    ///
    /// EXAMPLES:
    ///     vortix list                           Table with all profiles
    ///     vortix list --json                    JSON object with profiles in `.data`
    ///     vortix list --sort last-used          Most recently used first
    ///     vortix list --protocol wireguard      Only `WireGuard` profiles
    ///     vortix list --names-only              Profile names for scripting
    ///     vortix list --json | jq '.data[].name' Extract names via jq
    #[command(visible_alias = "ls")]
    List {
        /// Sort by: name, protocol, last-used [default: name]
        #[arg(short, long, value_name = "FIELD")]
        sort: Option<String>,

        /// Reverse sort order
        #[arg(short, long)]
        reverse: bool,

        /// Filter by protocol [wireguard|openvpn]
        #[arg(short, long, value_name = "PROTO")]
        protocol: Option<String>,

        /// Print profile names only (one per line)
        #[arg(short = '1', long)]
        names_only: bool,
    },

    /// Import VPN profile(s) from a file, directory, or URL
    ///
    /// Supports `.conf` (`WireGuard`), `.ovpn` (`OpenVPN`), directories for bulk import,
    /// and http/https URLs for remote config download.
    ///
    /// EXAMPLES:
    ///     vortix import ./work.conf             Import a `WireGuard` profile
    ///     vortix import ./configs/              Bulk import from directory
    ///     vortix import <https://example.com/vpn.conf>
    Import {
        /// Path to `.conf`/`.ovpn` file, directory, or URL
        #[arg(value_hint = ValueHint::AnyPath)]
        file: String,
    },

    /// Display the configuration of a VPN profile
    ///
    /// Shows parsed profile details with sensitive values masked by default.
    ///
    /// EXAMPLES:
    ///     vortix show work-vpn                  Parsed config with masked secrets
    ///     vortix show work-vpn --raw            Raw `.conf`/`.ovpn` file contents
    ///     vortix show work-vpn --json           Parsed config as JSON
    Show {
        /// Profile name
        #[arg(value_hint = ValueHint::Other)]
        profile: String,

        /// Show raw config file contents
        #[arg(long)]
        raw: bool,
    },

    /// Delete a VPN profile
    ///
    /// Removes the profile and its config file from disk. Cannot delete an
    /// active profile — disconnect first.
    ///
    /// EXAMPLES:
    ///     vortix delete old-vpn                 Delete with confirmation
    ///     vortix delete old-vpn --yes           Delete without prompting
    ///     vortix delete old-vpn --json          JSON result
    #[command(visible_alias = "rm")]
    Delete {
        /// Profile name to delete
        #[arg(value_hint = ValueHint::Other)]
        profile: String,

        /// Skip confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },

    /// Rename a VPN profile
    ///
    /// EXAMPLES:
    ///     vortix rename old-vpn new-vpn
    #[command(visible_alias = "mv")]
    Rename {
        /// Current profile name
        old: String,
        /// New profile name
        new: String,
    },

    /// Get or set the kill switch mode
    ///
    /// Without a mode argument, shows the current mode and state.
    /// Modes: off (disabled), auto (arm on connect, block on drop),
    /// always (block until VPN connects).
    ///
    /// EXAMPLES:
    ///     vortix killswitch                     Show current mode
    ///     sudo vortix killswitch auto           Set to auto
    ///     sudo vortix killswitch always         Set to always-on
    ///     sudo vortix killswitch off            Disable
    ///     vortix killswitch --json              JSON with mode and state
    #[command(name = "killswitch")]
    KillSwitch {
        /// Target mode: off, auto, always (omit to show current)
        mode: Option<String>,
    },

    /// Emergency release of kill switch firewall rules
    ///
    /// Use this if you're locked out of the internet after a crash.
    ///
    /// EXAMPLES:
    ///     sudo vortix release-killswitch
    ReleaseKillSwitch,

    /// Show config directory, profile count, and runtime info
    ///
    /// EXAMPLES:
    ///     vortix info
    ///     vortix info --json
    Info,

    /// Update vortix to the latest version from crates.io
    ///
    /// EXAMPLES:
    ///     vortix update
    Update,

    /// Generate a pre-filled bug report with system diagnostics
    ///
    /// EXAMPLES:
    ///     vortix report
    Report,

    /// Generate shell completions for vortix
    ///
    /// EXAMPLES:
    ///     vortix completions bash >> ~/.bashrc
    ///     vortix completions zsh > ~/.zfunc/_vortix
    ///     vortix completions fish > ~/.config/fish/completions/vortix.fish
    Completions {
        /// Target shell: bash, zsh, fish, powershell
        shell: clap_complete::Shell,
    },
}
