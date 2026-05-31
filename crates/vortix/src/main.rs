use clap::Parser;
use cli::args::Args;
use color_eyre::Result;
use event::{Event, EventHandler};
use vortix::app::App;
use vortix::{cli, config, constants, event, ui};

#[allow(clippy::too_many_lines)] // main() carries the whole bootstrap sequence
fn main() -> Result<()> {
    // Initialize error handling first — color_eyre::install() sets its own
    // panic hook, so we must call it before installing ours.
    color_eyre::install()?;

    // Subprocess runner + tracing (plan 002). Both live behind env-driven
    // toggles so production startup is silent; `RUST_LOG=vortix::process=info`
    // surfaces every subprocess invocation as a structured event.
    init_tracing();
    vortix::vortix_process::set_global_runner(vortix::vortix_process::CommandRunner::real());

    // Platform aggregate (plan 003 U7). Detect the OS variants once at startup;
    // consumers reach for `crate::platform::current_platform()` instead of
    // branching on `cfg(target_os)`.
    vortix::platform::set_global_platform(vortix::platform::Platform::detect_current());

    // Settings (plan 006 U7) — figment-layered: defaults → user file →
    // VORTIX_* env. CLI overrides currently bypass settings.
    let settings = match vortix::vortix_config::Settings::load() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("warning: failed to load settings ({e}); using defaults");
            vortix::vortix_config::Settings::default()
        }
    };

    // Journal (plan 005 U8 prep) — open the per-session JSONL writer using
    // the runner's own tokio runtime (writer task is spawn'd on it). We
    // borrow the runtime via Handle so the Journal stays alive after main()
    // exits to the TUI loop.
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
    let _ = runtime_handle; // suppress unused warning when no real runner installed

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

    // Plan #009 U13: session-liveness sweep of `${config_dir}/tmp/`. Any
    // per-session subdir whose name does not match the current journal
    // `session_id` is, by construction, a crash orphan — every session has a
    // unique `{ISO}-{pid}` ID. This is correct regardless of file age (a
    // crashed session 30 seconds ago is still definitively orphaned because
    // the pid differs from ours), so no time-based heuristic is used.
    // Best-effort: failures are swallowed; the temp dir is rebuildable from
    // the user's profiles on the next connect.
    if let Some(j) = vortix::vortix_core::journal::global_journal() {
        if let Some(sid) = j.session_id() {
            sweep_orphan_temp_configs(&config_dir, &sid);
        }
    }

    // Plan 006 U4: backfill profile sidecars for `.conf` / `.ovpn` files
    // imported before the sidecar scheme existed. Idempotent — no-ops once
    // every profile has a `.meta.toml`. Failures are logged + non-fatal:
    // startup MUST never abort because of migration trouble.
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
                if stats.failed > 0 {
                    eprintln!(
                        "Warning: {} profile(s) failed to migrate; existing files untouched. Run `vortix migrate` to retry.",
                        stats.failed
                    );
                }
            }
            Err(e) => {
                eprintln!(
                    "Warning: profile sidecar migration skipped — {e}. Startup continues; run `vortix migrate` once the issue is resolved."
                );
            }
        }
    }

    // Plan 008 U5: orphan-daemon scan. If a previous vortix crashed
    // while a tunnel was up, the user's `wg-quick` / `openvpn` /
    // `wireguard-go` daemon is probably still running. Warn so they
    // know to clean up (no auto-adopt — adoption arrives with the
    // plan 010 IPC layer).
    let orphans = vortix::vortix_process::scan_orphans();
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
            output_mode,
        );
        std::process::exit(exit_code);
    }

    // Run the TUI application
    let terminal = init_terminal()?;
    let result = run_tui(terminal, app_config, config_dir);
    restore_terminal();

    result
}

/// Sweep crash-orphaned per-session subdirs under `${config_dir}/tmp/`
/// (plan #009 U13).
///
/// Session IDs are `{ISO-timestamp}-{pid}` — guaranteed unique per process —
/// so any subdir whose name does not match the *current* session's ID is an
/// orphan from a previous (possibly crashed) run. This is session-liveness,
/// not age-based: a crash 30 seconds ago still leaves a definitively-orphan
/// directory, and an age threshold would incorrectly preserve it.
///
/// Best-effort: any I/O failure aborts the sweep for the failing entry but
/// does not prevent startup. The temp dir is fully rebuildable from the
/// user's profiles on the next secondary connect.
fn sweep_orphan_temp_configs(config_dir: &std::path::Path, current_session_id: &str) {
    let tmp_dir = config_dir.join(vortix::constants::TMP_CONFIG_DIR);
    if !tmp_dir.exists() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(&tmp_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name == current_session_id {
            continue;
        }
        let _ = std::fs::remove_dir_all(entry.path());
    }
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
    let profiles_dir_for_resolver = config_dir.join(constants::PROFILES_DIR_NAME);
    let mut app = App::new(config, config_dir);

    // Attach an `EngineHandle` (plan 005 U5/U6). The handle wraps the
    // FSM and gets a per-profile tunnel factory so a single
    // `Engine<TunnelKind>` drives both WG and OVPN. The actor spawns on
    // the bundled tokio runtime. Failure is non-fatal.
    //
    // The construction itself lives in `daemon::build_engine_handle` so
    // both the TUI bootstrap (here) and `vortix daemon` (`handle_daemon`)
    // produce the same shape.
    if let Some(runtime) = vortix::vortix_process::global_runner().as_real() {
        let _guard = runtime.runtime().handle().enter();
        if let Some(handle) = vortix::daemon::build_engine_handle(&profiles_dir_for_resolver) {
            app = app.with_engine_handle(handle);

            // Plan 005 U7: spawn a journal-subscriber task that reacts
            // to engine events. Today it nudges the legacy telemetry
            // worker on `TunnelUp` so connect → IP-refresh happens
            // promptly. Future units route more flows through here.
            // TUI-only side-effect — the daemon path doesn't need it.
            if let Some(j) = vortix::vortix_core::journal::global_journal() {
                let mut rx = j.subscribe();
                let nudge = app.runtime.telemetry_nudge.clone();
                tokio::spawn(async move {
                    use vortix::vortix_core::engine::EngineEvent;
                    while let Ok(envelope) = rx.recv().await {
                        if matches!(envelope.event, EngineEvent::TunnelUp { .. }) {
                            if let Some(n) = &nudge {
                                let _ = n.send(());
                            }
                        }
                    }
                });
            }
        }
    }
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
