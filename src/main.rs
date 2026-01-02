//! # Vortix VPN Manager
//!
//! Vortix is a professional Terminal User Interface (TUI) for managing VPN connections (`WireGuard` & `OpenVPN`).
//! It provides real-time telemetry, profile management, and an intuitive dashboard interface.
//!
//! ## Modules
//! - [`app`]: Core application state and logic.
//! - [`cli`]: Command-line argument parsing.
//! - [`event`]: Event loop handling.
//! - [`scanner`]: System VPN connection detection.
//! - [`telemetry`]: Background network telemetry collection.
//! - [`ui`]: TUI rendering and widget definitions.
//! - [`vpn`]: Profile parsing and configuration management.

mod app;
mod cli;
mod constants;
mod event;
mod scanner;
mod telemetry;
mod theme;
mod ui;
mod utils;
mod vpn;

use app::App;
use clap::Parser;
use cli::args::Args;
use color_eyre::Result;
use event::{Event, EventHandler};

fn main() -> Result<()> {
    // Initialize error handling
    color_eyre::install()?;

    // Parse arguments
    let args = Args::parse();

    // Handle CLI commands (import, etc.)
    if let Some(command) = &args.command {
        if cli::commands::handle_command(command)? {
            return Ok(());
        }
    }

    // Run the TUI application
    let terminal = ratatui::init();
    let result = run_tui(terminal);
    ratatui::restore();

    result
}

/// Runs the main TUI event loop.
fn run_tui(mut terminal: ratatui::DefaultTerminal) -> Result<()> {
    let mut app = App::new();
    let events = EventHandler::new(crate::constants::DEFAULT_TICK_RATE);

    while !app.should_quit {
        terminal.draw(|frame| ui::render(frame, &mut app))?;

        match events.next()? {
            Event::Key(key_event) => app.handle_key(key_event),
            Event::Tick => app.on_tick(),
            Event::Resize(width, height) => app.on_resize(width, height),
        }
    }

    Ok(())
}
