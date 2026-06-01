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
    /// Connects to the specified profile, or reconnects to the last used
    /// profile if no name is given. Blocks until the connection is
    /// established or times out.
    ///
    /// MULTI-TUNNEL CONFLICT GATE: connecting a profile that claims the
    /// kernel default route while another tunnel already holds it (or
    /// whose `AllowedIPs` overlap an active tunnel's routes) exits with
    /// code 4 (`StateConflict`). Pass `--yes` to bypass for scripted /
    /// non-interactive callers.
    ///
    /// EXAMPLES:
    ///     sudo vortix up work-vpn               Connect to 'work-vpn'
    ///     sudo vortix up work-vpn --json        Connect and get JSON result
    ///     sudo vortix up work-vpn --timeout 60  Connect with 60s timeout
    ///     sudo vortix up vpn-b --yes            Bypass conflict gate (scripts)
    ///     sudo vortix up                        Reconnect to last used profile
    #[command(visible_alias = "connect")]
    Up {
        /// Profile name to connect to (omit to reconnect to last used)
        #[arg(value_hint = ValueHint::Other)]
        profile: Option<String>,

        /// Connection timeout in seconds
        #[arg(long, default_value = "20", value_name = "SECS")]
        timeout: u64,

        /// Bypass the multi-tunnel conflict gate — default-route takeover
        /// or route overlap (multi-connection plan U7). Without this flag,
        /// conflicting connects exit with code 4 (`StateConflict`) so
        /// scripted callers can branch.
        #[arg(short, long)]
        yes: bool,
    },

    /// Disconnect from VPN
    ///
    /// Without arguments, disconnects every active tunnel (preserves
    /// single-tunnel semantics — for one-tunnel users, "down" still
    /// means "stop the one tunnel"). With a profile name, disconnects
    /// that profile only. `--all` is the explicit script-friendly form
    /// of the no-args behaviour. If already disconnected, exits
    /// successfully (idempotent). Use --force to SIGKILL a stuck process.
    ///
    /// EXAMPLES:
    ///     sudo vortix down              Disconnect every active tunnel
    ///     sudo vortix down corp         Disconnect only the 'corp' profile
    ///     sudo vortix down --all        Explicit "all" (script clarity)
    ///     sudo vortix down --force      Force-kill if stuck
    ///     sudo vortix down --json       Disconnect with JSON result
    #[command(visible_alias = "disconnect")]
    Down {
        /// Profile to disconnect. Omit (or use --all) to disconnect every
        /// active tunnel.
        #[arg(value_hint = ValueHint::Other, conflicts_with = "all")]
        profile: Option<String>,

        /// Disconnect every active tunnel. Equivalent to omitting the
        /// profile argument; the flag exists for script clarity.
        #[arg(long)]
        all: bool,

        /// Force-kill the VPN process (SIGKILL)
        #[arg(short, long)]
        force: bool,
    },

    /// Reconnect VPN tunnel(s)
    ///
    /// Without arguments, cycles every currently-Connected tunnel
    /// (disconnect then reconnect) — matches today's single-tunnel
    /// reconnect semantics applied across all active tunnels. With a
    /// profile name, cycles that profile only.
    ///
    /// EXAMPLES:
    ///     sudo vortix reconnect            Cycle every active tunnel
    ///     sudo vortix reconnect personal   Cycle only 'personal'
    ///     sudo vortix reconnect --json     Reconnect with JSON result
    Reconnect {
        /// Profile to cycle. Omit to cycle every currently-Connected
        /// tunnel.
        #[arg(value_hint = ValueHint::Other)]
        profile: Option<String>,
    },

    /// Show connection state and network telemetry
    ///
    /// Displays the current VPN connection status, network statistics, and
    /// security posture. Use --watch for continuous monitoring.
    ///
    /// JSON OUTPUT (v2 envelope, multi-tunnel aware):
    ///     data.connections  array of every active tunnel (one entry
    ///                       each for Connected / Connecting /
    ///                       Disconnecting profiles)
    ///     data.primary      profile name owning the kernel default
    ///                       route, or null
    ///     data.connection   back-compat single-tunnel object,
    ///                       populated only when exactly one tunnel is
    ///                       Connected (mirrors `data.connections[0]`);
    ///                       null in any other case
    ///
    /// EXAMPLES:
    ///     vortix status                          Human-readable status
    ///     vortix status --json                   Full v2 status envelope
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

        /// Always read state directly from disk + scanner, even if a
        /// daemon socket is connectable. Useful for testing the
        /// bypass path or working around a misbehaving daemon.
        #[arg(long)]
        no_daemon: bool,
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
    ///
    /// Modes (same labels shown in the TUI and JSON envelope):
    ///   off            — disabled; no firewall rules.
    ///   block-on-drop  — armed while a VPN is up; engages default-DROP
    ///                    egress only when the VPN drops unexpectedly.
    ///                    Allows non-VPN traffic while disconnected.
    ///   vpn-only       — firewall stays engaged whether VPN is up or
    ///                    down. Default-DROP egress + ACCEPT rules for
    ///                    active tunnels' interfaces + their server IPs.
    ///                    The gap between a drop and reconnect can
    ///                    never leak.
    ///
    /// EXAMPLES:
    ///     vortix killswitch                            Show current mode
    ///     sudo vortix killswitch off                   Disable
    ///     sudo vortix killswitch block-on-drop         Arm; block on unexpected drop
    ///     sudo vortix killswitch vpn-only              Always engaged
    ///     vortix killswitch --json                     JSON with mode and state
    #[command(name = "killswitch")]
    KillSwitch {
        /// Target mode: off, block-on-drop, vpn-only (omit to show current)
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

    /// Run the vortix daemon (plan 015 phase D / plan 010)
    ///
    /// Hosts the engine FSM as a long-running process and accepts
    /// client connections on a Unix domain socket. Set
    /// `VORTIX_DAEMON_SOCKET=<path>` in your TUI/CLI shell to route
    /// commands through the daemon instead of spawning a local engine.
    ///
    /// EXAMPLES:
    ///     vortix daemon                          Default socket path
    ///     vortix daemon --socket /tmp/vortix.sock Custom socket path
    ///
    /// Typically driven by systemd / launchd; see `examples/` for
    /// reference unit files.
    Daemon {
        /// Override the default socket path. Default: `${XDG_RUNTIME_DIR}/vortix.sock`
        /// (Linux), `${TMPDIR}/vortix.sock` (macOS), `/tmp/vortix.sock` (fallback).
        #[arg(long)]
        socket: Option<std::path::PathBuf>,
    },

    /// Audit open sockets and which interface routes them (plan 015 phase C / plan 013)
    ///
    /// Per-process snapshot of open TCP/UDP sockets visible to the
    /// calling user. Useful for answering "is this traffic actually
    /// going through the VPN tunnel?" — the `--vpn-only` flag filters
    /// to sockets bound to / routing via the active VPN interface.
    ///
    /// EXAMPLES:
    ///     vortix audit                          Tabular snapshot
    ///     vortix audit --json                   Structured JSON envelope
    ///     vortix audit --pid 12345              Filter to one process
    ///     vortix audit --vpn-only               Only sockets on the tunnel interface
    Audit {
        /// Filter results to a single PID.
        #[arg(long)]
        pid: Option<u32>,
        /// Only show sockets routing via the active VPN interface
        /// (requires an active connection; empty result otherwise).
        #[arg(long)]
        vpn_only: bool,
    },

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

#[cfg(test)]
mod tests {
    //! Multi-connection plan U20: CLI grammar additions for the
    //! down/reconnect/up subcommands. The runtime behaviour lives in
    //! `commands.rs` and depends on root + live tunnels, so we test
    //! only the clap parsing surface here — the contract that scripts
    //! depend on is grammatical (positional vs flag positions, mutual
    //! exclusion of `--all` with a positional, etc.).

    use super::{Args, Commands};
    use clap::Parser;

    fn parse(argv: &[&str]) -> Args {
        Args::try_parse_from(argv).unwrap_or_else(|e| panic!("parse failed for {argv:?}: {e}"))
    }

    fn parse_err(argv: &[&str]) -> clap::Error {
        Args::try_parse_from(argv).expect_err("expected parse to fail")
    }

    #[test]
    fn cli_down_no_args_means_all_active() {
        let args = parse(&["vortix", "down"]);
        match args.command {
            Some(Commands::Down {
                profile,
                all,
                force,
            }) => {
                assert!(profile.is_none());
                assert!(!all);
                assert!(!force);
            }
            other => panic!("expected Down, got {other:?}"),
        }
    }

    #[test]
    fn cli_down_with_profile_positional() {
        let args = parse(&["vortix", "down", "corp"]);
        let Some(Commands::Down { profile, all, .. }) = args.command else {
            panic!("expected Down");
        };
        assert_eq!(profile.as_deref(), Some("corp"));
        assert!(!all);
    }

    #[test]
    fn cli_down_all_flag_alone_parses() {
        let args = parse(&["vortix", "down", "--all"]);
        let Some(Commands::Down { profile, all, .. }) = args.command else {
            panic!("expected Down");
        };
        assert!(profile.is_none());
        assert!(all);
    }

    #[test]
    fn cli_down_all_flag_conflicts_with_positional() {
        // `--all` and a profile name are mutually exclusive — clap
        // should reject the combination so scripts can't accidentally
        // ask for both ("disconnect corp" + "disconnect all").
        let err = parse_err(&["vortix", "down", "corp", "--all"]);
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn cli_down_keeps_force_flag() {
        // SC8 single-tunnel scripts call `sudo vortix down --force` —
        // make sure that grammar still parses.
        let args = parse(&["vortix", "down", "--force"]);
        let Some(Commands::Down {
            profile,
            all,
            force,
        }) = args.command
        else {
            panic!("expected Down");
        };
        assert!(profile.is_none());
        assert!(!all);
        assert!(force);
    }

    #[test]
    fn cli_reconnect_no_args() {
        let args = parse(&["vortix", "reconnect"]);
        let Some(Commands::Reconnect { profile }) = args.command else {
            panic!("expected Reconnect");
        };
        assert!(profile.is_none());
    }

    #[test]
    fn cli_reconnect_with_profile() {
        let args = parse(&["vortix", "reconnect", "personal"]);
        let Some(Commands::Reconnect { profile }) = args.command else {
            panic!("expected Reconnect");
        };
        assert_eq!(profile.as_deref(), Some("personal"));
    }

    #[test]
    fn cli_up_accepts_yes_flag() {
        let args = parse(&["vortix", "up", "corp", "--yes"]);
        let Some(Commands::Up {
            profile,
            timeout,
            yes,
        }) = args.command
        else {
            panic!("expected Up");
        };
        assert_eq!(profile.as_deref(), Some("corp"));
        assert_eq!(timeout, 20);
        assert!(yes);
    }

    #[test]
    fn cli_up_yes_short_flag() {
        let args = parse(&["vortix", "up", "corp", "-y"]);
        let Some(Commands::Up { yes, .. }) = args.command else {
            panic!("expected Up");
        };
        assert!(yes);
    }

    #[test]
    fn cli_up_without_yes_defaults_false() {
        let args = parse(&["vortix", "up", "corp"]);
        let Some(Commands::Up {
            profile,
            timeout,
            yes,
        }) = args.command
        else {
            panic!("expected Up");
        };
        assert_eq!(profile.as_deref(), Some("corp"));
        assert_eq!(timeout, 20);
        assert!(
            !yes,
            "yes must default to false to keep current scripts unaffected"
        );
    }
}
