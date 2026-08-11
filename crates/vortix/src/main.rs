use clap::Parser;
use cli::args::Args;
use color_eyre::Result;
use event::{Event, EventHandler};
use vortix::app::App;
use vortix::{cli, config, constants, event, ui};

#[allow(clippy::too_many_lines)] // main() carries the whole bootstrap sequence
fn main() -> Result<()> {
    // Private Standard-mode lifecycle actor. Handle this before error hooks,
    // configuration migration, argument parsing, or any user-facing startup
    // work: the custodian has exactly one child and only status/stop IPC.
    if let Some(exit_code) = vortix::vortix_process::custodian::maybe_run_hidden_entrypoint() {
        std::process::exit(exit_code);
    }

    // Initialize error handling first — color_eyre::install() sets its own
    // panic hook, so we must call it before installing ours.
    color_eyre::install()?;

    // Subprocess runner + tracing. Both live behind env-driven
    // toggles so production startup is silent; `RUST_LOG=vortix::process=info`
    // surfaces every subprocess invocation as a structured event.
    init_tracing();
    vortix::vortix_process::set_global_runner(vortix::vortix_process::CommandRunner::real());

    // Platform aggregate. Detect the OS variants once at startup;
    // consumers reach for `crate::platform::current_platform()` instead of
    // branching on `cfg(target_os)`.
    vortix::platform::set_global_platform(vortix::platform::Platform::detect_current());

    // Now capture color_eyre's hook and wrap it with terminal restoration
    // and recovery instructions. Drop glue on App will still run to release
    // kill switch rules and VPN processes.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        eprintln!();
        eprintln!("Vortix crashed unexpectedly.");
        eprintln!("If your network is broken, run:  vortix release-killswitch");
        eprintln!();
        default_hook(info);
    }));

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

    // Settings use the same authoritative directory as profiles and
    // config.toml. Resolve this only after clap/env/sudo-user selection so an
    // old default-path settings file can never silently override
    // `--config-dir` or `VORTIX_CONFIG_DIR`.
    let settings = match vortix::vortix_config::Settings::load_from_config_dir(&config_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("warning: failed to load settings ({e}); using defaults");
            vortix::vortix_config::Settings::default()
        }
    };

    // Journal — open the per-session JSONL writer using the runner's own
    // tokio runtime after the authoritative settings path is known.
    let runtime_handle = vortix::vortix_process::global_runner()
        .as_real()
        .map(|r| r.runtime().handle().clone());
    if let Some(handle) = runtime_handle.clone() {
        let _guard = handle.enter();
        match vortix::vortix_core::journal::Journal::open(
            vortix::vortix_core::journal::JournalConfig {
                disk: settings.journal.disk,
                retention_days: settings.journal.retention_days,
                retention_count: settings.journal.retention_count,
                ..Default::default()
            },
        ) {
            Ok(journal) => {
                vortix::vortix_core::journal::set_global_journal(journal);
            }
            Err(e) => {
                eprintln!("warning: failed to open journal ({e}); diagnostics will be limited");
            }
        }
    }
    let _ = runtime_handle;

    // Clear any SCRV1 envelopes left on
    // disk by a previous crash mid-connect. Runs once at startup before
    // the CLI/TUI fork so both paths see a clean auth dir. Cheap O(N)
    // scan; failures are swallowed.
    vortix::utils::scrub_stale_scrv1_auth_files();

    // Hold a process-lifetime scratch lease before sweeping. Concurrent CLI
    // and TUI processes intentionally have different journal session IDs;
    // only an acquirable lease proves that another session crashed.
    let temp_session_id = vortix::utils::temp_session_id();
    let _temp_session_lease =
        match vortix::utils::acquire_temp_session_lease(&config_dir, &temp_session_id) {
            Ok(lease) => {
                vortix::utils::sweep_orphan_temp_configs(&config_dir, &temp_session_id);
                Some(lease)
            }
            Err(error) => {
                eprintln!("warning: failed to lease temporary tunnel state ({error})");
                None
            }
        };

    // backfill profile sidecars for `.conf` / `.ovpn` files
    // imported before the sidecar scheme existed. Idempotent — no-ops once
    // every profile has a `.meta.toml`. The first canonical migration records
    // config-less sidecars left by legacy delete paths in its durable inventory,
    // archives those exact bytes, then marks the phase complete. Interrupted
    // archival resumes from that record. Identity ambiguity is still fatal
    // before any lifecycle path starts.
    //
    // VORTIX_SKIP_MIGRATION=<anything> bypasses the startup backfill for
    // users who need to disable it (see docs/MIGRATION.md).
    let profiles_dir = config_dir.join(constants::PROFILES_DIR_NAME);
    if std::env::var_os("VORTIX_SKIP_MIGRATION").is_some() {
        eprintln!("VORTIX_SKIP_MIGRATION set — skipping startup sidecar backfill.");
    } else {
        match vortix::vortix_config::migrate_legacy_profiles(&profiles_dir) {
            Ok(stats) => {
                if stats.created > 0 {
                    eprintln!(
                        "Migrated {} profile(s) to the new sidecar scheme.",
                        stats.created
                    );
                }
                if stats.archived_legacy_sidecars > 0 {
                    eprintln!(
                        "Archived {} stale legacy profile metadata file(s) under profiles/.vortix-legacy-sidecars-v1.",
                        stats.archived_legacy_sidecars
                    );
                }
                if stats.failed > 0 {
                    eprintln!(
                        "Warning: {} profile(s) failed to migrate; existing files untouched. Repair the profile files and restart vortix to retry.",
                        stats.failed
                    );
                }
            }
            Err(e) => {
                return Err(color_eyre::eyre::eyre!(
                    "profile identity migration refused startup: {e}. Restore the managed profile directory to its saved inventory before managing tunnels; add new profiles from outside that directory with `vortix import <path>`"
                ));
            }
        }
    }

    // orphan-daemon scan. If a previous vortix crashed
    // while a tunnel was up, the user's `wg-quick` / `openvpn` /
    // `wireguard-go` daemon is probably still running. Warn so they
    // know to clean up (no auto-adopt — adoption arrives with the
    // daemon IPC layer).
    //
    // PIDs recorded in `run/*.pid` belong to a tracked session (openvpn
    // daemons reparent to init, so the bare scan can't tell "mine" from
    // "leftover") — exclude them from the warning. Reads only the run
    // dir; profile files are never parsed here.
    let tracked_pids = vortix::utils::tracked_openvpn_pids();
    let orphans = vortix::vortix_process::filter_untracked(
        vortix::vortix_process::scan_orphans(),
        &tracked_pids,
    );
    if !orphans.is_empty() {
        eprintln!(
            "Warning: detected {} possible orphan VPN process(es) from a previous session:",
            orphans.len()
        );
        for o in &orphans {
            eprintln!("  - pid {} ({})", o.pid, o.command);
        }
        eprintln!(
            "  These may be leftovers from a previous vortix crash. Run `sudo kill <pid>` to clean up, or `sudo vortix down --force` to tear down via vortix."
        );
    }

    // Load config.toml (or use defaults)
    let app_config = match config::load_effective_config(&config_dir) {
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

    // Determine output mode from global flags
    let output_mode = if args.json {
        cli::output::OutputMode::Json
    } else if args.quiet {
        cli::output::OutputMode::Quiet
    } else {
        cli::output::OutputMode::Human
    };

    // Handle CLI commands (import, update, info, status, up, down, etc.)
    if let Some(command) = &args.command {
        let exit_code = cli::commands::handle_command(
            command,
            &config_dir,
            config_dir_source,
            &app_config,
            &settings,
            output_mode,
        );
        std::process::exit(exit_code);
    }

    // Standard-mode TUI and CLI share the same cross-process writer lock. The
    // TUI holds it for the lifetime of its one canonical in-process service.
    // Acquisition is fail-fast because a TUI session has no bounded duration.
    let _lifecycle_lock = vortix::utils::acquire_lifecycle_lock().map_err(|error| {
        color_eyre::eyre::eyre!(
            "another vortix lifecycle writer is active; close it or wait for its command to finish ({error})"
        )
    })?;

    // Run the TUI application
    let terminal = init_terminal()?;
    let result = run_tui(
        terminal,
        app_config,
        config_dir,
        settings.diagnostics.fallback_snapshot,
    );
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
    diagnostics_fallback: bool,
) -> Result<()> {
    let tick_rate = config.tick_rate;
    let mut app = App::new(config, config_dir);
    app.set_background_diagnostics_fallback(diagnostics_fallback);
    let control = vortix::cli::control::LocalControlSession::start(
        &app.runtime.config,
        &app.runtime.config_dir,
        app.runtime.profiles.clone(),
    )
    .map_err(|error| color_eyre::eyre::eyre!("cannot start TUI control service: {error}"))?;
    app.attach_client_control_session(vortix::cli::control::ClientControlSession::standard(
        control,
    ))
    .map_err(|error| color_eyre::eyre::eyre!("cannot attach TUI control service: {error}"))?;
    let events = EventHandler::new(tick_rate);
    let size = terminal.size()?;
    app.on_resize(size.width, size.height);

    // Initial draw
    app.process_external();
    terminal.draw(|frame| ui::render(frame, &mut app))?;

    while !app.should_quit {
        if app.has_active_animation() {
            while let Some(event) = events.try_next()? {
                dispatch_event(&mut app, event);
            }
            app.advance_animation();
        } else {
            // Block until at least one event lands (avoids busy-loop), then
            // drain every event that has already queued up while the
            // previous render frame was running. A fast trackpad or scroll
            // wheel can emit 30+ events per second; without this drain,
            // each event would trigger a full render even though only the
            // final scroll position matters. Coalescing them into one
            // render frame is the difference between smooth-scrolling and
            // the TUI feeling wedged for tens of seconds while it grinds
            // through a backlog the user already left behind.
            dispatch_event(&mut app, events.next()?);
            while let Some(event) = events.try_next()? {
                dispatch_event(&mut app, event);
            }
        }

        app.process_external();
        terminal.draw(|frame| ui::render(frame, &mut app))?;

        if app.has_active_animation() {
            std::thread::sleep(std::time::Duration::from_millis(
                constants::FLIP_ANIMATION_FRAME_MS,
            ));
        }
    }

    Ok(())
}

/// Initialise tracing-subscriber with an env-filter layer.
///
/// Silent by default; `RUST_LOG=vortix::process=info` enables the structured
/// Dispatch a single event into the App. Extracted from the main loop
/// so the loop body can call it once for the blocking-`next()` event
/// and N more times for each event that's queued up behind it (the
/// burst-coalescing path that turns rapid scroll-wheel events into a
/// single render frame).
///
/// The `event` is taken by value because the caller is done with it
/// after dispatch; clippy's `needless_pass_by_value` lint flags the
/// non-consuming `match` but moving the variant payloads into the
/// handlers is the right shape here.
#[allow(clippy::needless_pass_by_value)]
fn dispatch_event(app: &mut App, event: Event) {
    match event {
        Event::Key(key_event) => app.handle_key(key_event),
        Event::Mouse(mouse_event) => app.handle_mouse(mouse_event),
        Event::Tick => app.on_tick(),
        Event::Resize(w, h) => app.on_resize(w, h),
    }
}

/// subprocess events emitted by `RealRunner`. The TUI uses stderr for log
/// output since stdout drives the alternate-screen terminal.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off"));
    // Best-effort init: ignore the error from double-init in tests.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(true)
        .compact()
        .try_init();
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
