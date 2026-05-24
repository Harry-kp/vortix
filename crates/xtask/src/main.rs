//! `cargo xtask <task>` — workspace build chores.
//!
//! Today this is a minimal subcommand-dispatch scaffold; subsequent plans populate the
//! actual lint runners and packaging helpers.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "vortix workspace build chores", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify no raw `Command::new` outside `vortix-process` (plan 002 R12).
    CheckSubprocess,
    /// Verify no `cfg(target_os)` outside `vortix-platform-*` (plan 003 R12).
    CheckPlatformLeak,
    /// Verify no protocol-specific subprocess names outside their protocol crates (plan 004).
    CheckProtocolLeak,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::CheckSubprocess => {
            eprintln!("xtask check-subprocess: stub — implemented by plan 002");
            Ok(())
        }
        Command::CheckPlatformLeak => {
            eprintln!("xtask check-platform-leak: stub — implemented by plan 003");
            Ok(())
        }
        Command::CheckProtocolLeak => {
            eprintln!("xtask check-protocol-leak: stub — implemented by plan 004");
            Ok(())
        }
    }
}
