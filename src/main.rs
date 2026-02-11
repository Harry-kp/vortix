//! # Vortix VPN Manager
//!
//! Terminal UI for `WireGuard` and `OpenVPN` with real-time telemetry and leak guarding.
//! It provides profile management and an intuitive dashboard interface.
//!
//! ## Modules
//! - [`app`]: Core application state and logic.
//! - [`cli`]: Command-line argument parsing.
//! - [`config`]: Configuration management.
//! - [`core`]: Scanner and telemetry background workers.
//! - [`event`]: Event loop handling.
//! - [`ui`]: TUI rendering and widget definitions.
//! - [`vpn`]: Profile parsing and configuration management.

mod app;
mod cli;
mod config;
mod constants;
mod core;
mod event;
mod logger;
mod message;
mod platform;
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

    // Determine how config_dir was provided (for `info` command)
    let config_dir_source = if args.config_dir.is_some() {
        if std::env::var("VORTIX_CONFIG_DIR").is_ok() {
            // When both CLI and env are set, clap prefers CLI.
            // We can't distinguish perfectly, but env-only is the common case.
            // Check if the value matches the env var to decide.
            let env_val = std::env::var("VORTIX_CONFIG_DIR").unwrap_or_default();
            let cli_val = args
                .config_dir
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            if cli_val == env_val {
                "from VORTIX_CONFIG_DIR"
            } else {
                "from --config-dir"
            }
        } else {
            "from --config-dir"
        }
    } else {
        "default"
    };

    // Resolve config directory (CLI flag > SUDO_USER > XDG > default)
    let explicit_override = args.config_dir.is_some();
    let mut config_dir = config::resolve_config_dir(args.config_dir.as_ref())
        .map_err(|e| color_eyre::eyre::eyre!("Failed to resolve config directory: {e}"))?;

    // Migration check -- only when using default resolution (not explicit --config-dir)
    if !explicit_override {
        if let Some(old_dir) = config::check_migration(&config_dir) {
            config_dir = prompt_migration(&old_dir, &config_dir);
        }
    }

    // Store the resolved config dir globally so all utility functions use it
    config::set_config_dir(config_dir.clone());

    // Load config.toml (or use defaults)
    let app_config = match config::load_config(&config_dir) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!();
            eprintln!("Fix the file or remove it to use defaults:");
            eprintln!("  nano {}/config.toml", config_dir.display());
            eprintln!("  rm {}/config.toml", config_dir.display());
            std::process::exit(1);
        }
    };

    // Handle CLI commands (import, update, info, etc.)
    if let Some(command) = &args.command {
        if cli::commands::handle_command(command, &config_dir, config_dir_source)? {
            return Ok(());
        }
    }

    // Run the TUI application
    let terminal = init_terminal()?;
    let result = run_tui(terminal, app_config, config_dir);
    restore_terminal();

    result
}

/// Prompts the user to migrate data from an old config directory.
///
/// Returns the config directory to use for this session.
fn prompt_migration(old_dir: &std::path::Path, new_dir: &std::path::Path) -> std::path::PathBuf {
    use std::io::Write;

    eprintln!();
    eprintln!("  Old data found at: {}", old_dir.display());
    eprintln!("  New config dir:    {}", new_dir.display());
    eprintln!();
    eprintln!("  Vortix now stores config under your home directory instead of");
    eprintln!("  /root, so profiles are accessible without sudo.");
    eprintln!();
    eprintln!("  [Y] Move your existing profiles and settings to the new location.");
    eprintln!("      Files are copied first, then deleted from the old path.");
    eprintln!();
    eprintln!(
        "  [n] Start fresh. Your old data stays at {} but",
        old_dir.display()
    );
    eprintln!("      won't be used. You can import profiles again or copy manually.");
    eprintln!();
    eprint!("  Move data? [Y/n] ");
    // Flush stderr so the prompt appears before we block on stdin
    let _ = std::io::stderr().flush();

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        eprintln!("  Could not read input. Starting fresh.\n");
        return new_dir.to_path_buf();
    }
    let input = input.trim().to_lowercase();

    if input.is_empty() || input == "y" || input == "yes" {
        eprintln!();
        match config::migrate_data(old_dir, new_dir) {
            Ok(()) => {
                // Verify profiles were actually migrated
                let profiles_exist = new_dir.join("profiles").is_dir()
                    && std::fs::read_dir(new_dir.join("profiles"))
                        .map(|mut d| d.next().is_some())
                        .unwrap_or(false);
                if profiles_exist {
                    eprintln!("  Done! Data moved to {}\n", new_dir.display());
                } else {
                    eprintln!(
                        "  Warning: Move completed but no profiles found at {}",
                        new_dir.join("profiles").display()
                    );
                    eprintln!(
                        "  Check if your profiles are still at {}\n",
                        old_dir.display()
                    );
                }
                new_dir.to_path_buf()
            }
            Err(e) => {
                eprintln!("  Move failed: {e}");
                eprintln!("  Your original data is untouched at {}", old_dir.display());
                eprintln!("  Starting fresh at {}\n", new_dir.display());
                new_dir.to_path_buf()
            }
        }
    } else {
        eprintln!();
        eprintln!("  Starting fresh at {}", new_dir.display());
        eprintln!("  Old data is still at {}.", old_dir.display());
        eprintln!("  This prompt will appear until you migrate or the old data is removed.");
        eprintln!("  To silence it: --config-dir {}\n", old_dir.display());
        new_dir.to_path_buf()
    }
}

/// Runs the main TUI event loop.
fn run_tui(
    mut terminal: ratatui::DefaultTerminal,
    config: config::AppConfig,
    config_dir: std::path::PathBuf,
) -> Result<()> {
    let tick_rate = config.tick_rate;
    let mut app = App::new(config, config_dir);
    let events = EventHandler::new(tick_rate);

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
