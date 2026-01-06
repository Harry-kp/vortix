//! # Vortix VPN Manager
//!
//! Terminal UI for `WireGuard` and `OpenVPN` with real-time telemetry and leak guarding.
//! It provides profile management and an intuitive dashboard interface.
//!
//! ## Modules
//! - [`app`]: Core application state and logic.
//! - [`cli`]: Command-line argument parsing.
//! - [`core`]: Scanner and telemetry background workers.
//! - [`event`]: Event loop handling.
//! - [`ui`]: TUI rendering and widget definitions.
//! - [`vpn`]: Profile parsing and configuration management.

mod app;
mod cli;
mod constants;
mod core;
mod event;
mod logger;
mod message;
mod state;
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
    let terminal = init_terminal()?;
    let result = run_tui(terminal);
    restore_terminal();

    result
}

/// Runs the main TUI event loop.
fn run_tui(mut terminal: ratatui::DefaultTerminal) -> Result<()> {
    let mut app = App::new();
    let events = EventHandler::new(crate::constants::DEFAULT_TICK_RATE);

    // Initial draw
    app.process_external();
    terminal.draw(|frame| ui::render(frame, &mut app))?;

    while !app.should_quit {
        // Process event
        match events.next()? {
            Event::Key(key_event) => app.handle_key(key_event),
            Event::Mouse(mouse_event) => app.handle_mouse(mouse_event),
            Event::Tick => app.on_tick(),
            Event::Resize(width, height) => app.on_resize(width, height),
        }

        // Process any pending telemetry before drawing (for immediate log updates)
        app.process_external();
        terminal.draw(|frame| ui::render(frame, &mut app))?;
    }

    Ok(())
}

fn init_terminal() -> Result<ratatui::DefaultTerminal> {
    let mut terminal = ratatui::init();
    crossterm::execute!(std::io::stdout(), crossterm::event::EnableMouseCapture)?;
    terminal.clear()?;
    Ok(terminal)
}

fn restore_terminal() {
    let _ = crossterm::execute!(std::io::stdout(), crossterm::event::DisableMouseCapture);
    ratatui::restore();
}
