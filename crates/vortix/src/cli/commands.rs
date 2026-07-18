//! CLI command handlers.
//!
//! Each handler operates headlessly via `VpnRuntime` (no TUI), produces
//! structured output via [`OutputMode`], and exits with semantic exit codes.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use serde::Serialize;

use crate::cli::args::Commands;
use crate::cli::output::{
    err_not_found, err_permission_denied, print_error_and_exit, print_success, CliError,
    ConnectionEntry, ExitCode, OutputMode,
};
use crate::config::AppConfig;
use crate::constants;
use crate::vpn_runtime::VpnRuntime;

/// Prompt for a 2FA code on the controlling tty with masked echo (each
/// character is replaced by `*`). Returns `Err` when stdin is not a tty —
/// the connect path treats this as a hard failure and exits non-zero with
/// an actionable message naming the prompt kind. Plan 2026-06-02-001 U4.
///
/// Implementation uses `crossterm`'s raw mode (already in the workspace,
/// no new dep) and reads byte-by-byte. A `RawModeGuard` ensures the
/// terminal returns to cooked mode on every exit path including panic.
struct RawModeGuard;
impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

fn prompt_masked_otp(prompt: &str) -> std::io::Result<String> {
    use crossterm::event::{self, Event, KeyCode, KeyModifiers};
    use crossterm::terminal::enable_raw_mode;

    if !crossterm::tty::IsTty::is_tty(&std::io::stdin()) {
        return Err(std::io::Error::other("stdin is not a tty"));
    }

    print!("{prompt}: ");
    std::io::stdout().flush().ok();

    enable_raw_mode()?;
    let _guard = RawModeGuard;

    let mut otp = String::new();
    loop {
        if let Event::Key(k) = event::read()? {
            match k.code {
                KeyCode::Enter => {
                    println!();
                    break;
                }
                KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                    println!();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "user cancelled",
                    ));
                }
                KeyCode::Char(c) => {
                    otp.push(c);
                    print!("*");
                    std::io::stdout().flush().ok();
                }
                KeyCode::Backspace => {
                    if otp.pop().is_some() {
                        print!("\u{08} \u{08}");
                        std::io::stdout().flush().ok();
                    }
                }
                KeyCode::Esc => {
                    println!();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "user cancelled",
                    ));
                }
                _ => {}
            }
        }
    }
    Ok(otp.trim().to_string())
}

/// Dispatch a CLI command. Returns `true` if handled (program should exit).
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn handle_command(
    command: &Commands,
    config_dir: &Path,
    config_source: &str,
    config: &AppConfig,
    mode: OutputMode,
) -> i32 {
    match command {
        Commands::Up {
            profile,
            timeout,
            yes,
        } => handle_up(profile.as_deref(), *timeout, *yes, config, config_dir, mode),
        Commands::Down {
            profile,
            all,
            force,
        } => handle_down(profile.as_deref(), *all, *force, config, config_dir, mode),
        Commands::Reconnect { profile } => {
            handle_reconnect(profile.as_deref(), config, config_dir, mode)
        }
        Commands::Status {
            watch,
            interval,
            brief,
            no_daemon,
        } => handle_status(
            *watch, *interval, *brief, *no_daemon, config, config_dir, mode,
        ),
        Commands::List {
            sort,
            reverse,
            protocol,
            names_only,
        } => handle_list(
            sort.as_deref(),
            *reverse,
            protocol.as_deref(),
            *names_only,
            config,
            config_dir,
            mode,
        ),
        Commands::Import { file } => handle_import(file, mode),
        Commands::Show { profile, raw } => handle_show(profile, *raw, config, config_dir, mode),
        Commands::Delete { profile, yes } => handle_delete(profile, *yes, config, config_dir, mode),
        Commands::Rename { old, new } => handle_rename(old, new, config, config_dir, mode),
        Commands::KillSwitch { mode: ks_mode } => {
            handle_killswitch(ks_mode.as_deref(), config, config_dir, mode)
        }
        Commands::ReleaseKillSwitch => {
            handle_release_killswitch(mode);
            0
        }
        Commands::Info => {
            handle_info(config_dir, config_source, mode);
            0
        }
        Commands::Update => {
            handle_update(mode);
            0
        }
        Commands::Report => {
            super::report::run(config_dir, config_source);
            0
        }
        Commands::Audit { pid, vpn_only } => handle_audit(*pid, *vpn_only, mode),
        Commands::Daemon { socket } => handle_daemon(socket.clone(), mode),
        Commands::Completions { shell } => {
            handle_completions(*shell);
            0
        }
    }
}

/// `vortix audit` — per-process socket snapshot (plan 015 phase C / plan 013).
#[derive(Serialize)]
struct AuditData {
    sockets: Vec<crate::vortix_core::ports::socket_audit::SocketSnapshot>,
}

fn handle_audit(pid_filter: Option<u32>, vpn_only: bool, mode: OutputMode) -> i32 {
    let platform = crate::platform::current_platform();
    let mut snapshots = match platform.socket_audit.snapshot() {
        Ok(s) => s,
        Err(crate::vortix_core::ports::socket_audit::SocketAuditError::Unsupported) => {
            print_error_and_exit(
                mode,
                "audit",
                CliError {
                    code: "platform_unsupported",
                    message: "Socket audit is not available on this platform yet".to_string(),
                    hint: Some(
                        "Linux + macOS are supported in v0.3.0; Windows support is on the roadmap"
                            .to_string(),
                    ),
                },
                ExitCode::DependencyMissing,
            );
        }
        Err(e) => {
            print_error_and_exit(
                mode,
                "audit",
                CliError {
                    code: "audit_failed",
                    message: format!("Socket audit failed: {e}"),
                    hint: None,
                },
                ExitCode::GeneralError,
            );
        }
    };

    if let Some(pid) = pid_filter {
        snapshots.retain(|s| s.pid == pid);
    }
    if vpn_only {
        // Best-effort: filter to sockets whose `interface` field matches the
        // active WireGuard interface (when resolvable). Today the
        // Linux /proc impl doesn't populate `interface`, so this filter is a
        // future-hardening hook — the doc warns users that v0.3.0 may show
        // an empty result.
        snapshots.retain(|s| s.interface.is_some());
    }
    snapshots.sort_by_key(|s| s.pid);

    match mode {
        OutputMode::Human => {
            println!("PID    COMMAND          PROTO   LOCAL                            REMOTE                           IFACE");
            for s in &snapshots {
                println!(
                    "{:<6} {:<16} {:<7} {:<32} {:<32} {}",
                    s.pid,
                    s.command,
                    s.protocol,
                    s.local,
                    s.remote.map_or_else(|| "*".to_string(), |r| r.to_string()),
                    s.interface.as_deref().unwrap_or("-")
                );
            }
            0
        }
        OutputMode::Json => {
            print_success(mode, "audit", &AuditData { sockets: snapshots }, vec![]);
            0
        }
        OutputMode::Quiet => 0,
    }
}

/// `vortix daemon` — host the engine as a long-running IPC server
/// (plan 015 phase D / plan 010).
/// Resolve when the daemon should shut down: SIGTERM (systemd/launchd
/// stop) or Ctrl-C (foreground run).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            // If the SIGTERM handler can't be installed, fall back to Ctrl-C.
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[allow(clippy::too_many_lines)]
fn handle_daemon(socket_override: Option<std::path::PathBuf>, mode: OutputMode) -> i32 {
    let socket_path = socket_override.unwrap_or_else(crate::daemon::default_socket_path);

    // Tokio-backed daemon socket binding must happen inside an active Tokio runtime.
    // Binding before runtime creation panics with:
    // "there is no reactor running, must be called from the context of a Tokio 1.x runtime".
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("vortix daemon: failed to build runtime: {e}");
            return 1;
        }
    };

    let server = match runtime
        .block_on(async { crate::daemon::DaemonServer::bind(socket_path.clone()) })
    {
        Ok(s) => s,
        Err(e) => {
            print_error_and_exit(
                mode,
                "daemon",
                CliError {
                    code: "daemon_bind_failed",
                    message: format!("Failed to bind daemon socket at {}: {e}", socket_path.display()),
                    hint: Some(
                        "Check parent directory exists and is writable. If a previous daemon left a stale socket, the bind path will be reused after the next start."
                            .to_string(),
                    ),
                },
                ExitCode::GeneralError,
            );
        }
    };

    eprintln!(
        "vortix daemon: ready. Set VORTIX_DAEMON_SOCKET={} in your shell to route through the daemon.",
        server.socket_path().display()
    );

    // Build the `EngineHandle::Local` inside the daemon's runtime context
    // (the actor task spawn lands on this runtime, not the runner's). The
    // factory reads the resolved global config dir for profile sidecars.
    let profiles_dir = crate::utils::get_app_config_dir().map_or_else(
        |_| std::path::PathBuf::from("/tmp/vortix-profiles"),
        |d| d.join(constants::PROFILES_DIR_NAME),
    );

    // Build the engine handle the IPC server uses for client-driven
    // Execute/Snapshot/Subscribe.
    let engine_handle =
        runtime.block_on(async { crate::daemon::build_engine_handle(&profiles_dir) });
    if engine_handle.is_none() {
        eprintln!(
            "vortix daemon: engine handle unavailable (journal or runner not installed) — Execute/Snapshot/Subscribe will return Internal errors"
        );
    }
    let server = if let Some(handle) = engine_handle {
        server.with_engine_handle(handle)
    } else {
        server
    };

    // The supervisor's auto-reconnect drives a FRESH engine per attempt —
    // never the shared server FSM, which tracks one tunnel and goes stale
    // on a drop. Each fresh engine starts Disconnected, so its Connect
    // actually brings the tunnel up and its result is truthful.
    let factory_profiles_dir = profiles_dir.clone();
    let engine_factory: crate::daemon::supervisor::EngineFactory =
        std::sync::Arc::new(move || crate::daemon::build_engine_handle(&factory_profiles_dir));

    // The daemon owns a multi-tunnel registry independent of the single
    // FSM engine handle. A headless supervisor loop keeps it in sync with
    // the kernel (adopt new sessions, detect drops, auto-reconnect), and
    // the server serves it over `IpcOp::RegistrySnapshot`. Reconcile runs
    // even when the engine handle is unavailable — read-only multi-tunnel
    // status doesn't need the FSM. (plan 2026-07-18-001 U2/U4)
    let registry: crate::vortix_core::engine::registry_handle::RegistryHandle<
        crate::tunnel::TunnelKind,
    > = runtime.block_on(async {
        crate::vortix_core::engine::registry_handle::RegistryHandle::spawn(
            crate::vortix_core::engine::registry::TunnelRegistry::new(),
        )
    });
    let server = server.with_registry_handle(registry.clone());

    // R7: adopt already-running tunnels ONCE before serving, so the first
    // snapshot a client reads includes restart-survivors (a daemon restart
    // issues zero connect commands — the tunnels were never torn down).
    // The periodic supervisor keeps them fresh afterward.
    runtime.block_on(async {
        let sessions = tokio::task::spawn_blocking(|| {
            let profiles = crate::vpn::load_profiles();
            crate::core::scanner::get_active_profiles(&profiles)
        })
        .await
        .unwrap_or_default();
        let view = crate::daemon::supervisor::ScannerView {
            sessions: sessions
                .iter()
                .map(crate::daemon::supervisor::ScannedSession::from)
                .collect(),
        };
        let _ = crate::daemon::supervisor::reconcile_tick(
            &registry,
            view,
            constants::DEFAULT_DISCONNECT_TIMEOUT,
        )
        .await;
    });

    // Retry/cadence knobs from config so the daemon and TUI behave alike.
    let cfg = crate::utils::get_app_config_dir()
        .ok()
        .and_then(|dir| crate::config::load_config(&dir).ok())
        .unwrap_or_default();
    let supervisor_config = crate::daemon::supervisor::SupervisorConfig {
        scan_interval_secs: constants::DAEMON_SCAN_INTERVAL_SECS,
        disconnect_timeout_secs: constants::DEFAULT_DISCONNECT_TIMEOUT,
        auto_reconnect: cfg.auto_reconnect,
        auto_reconnect_delay_secs: cfg.auto_reconnect_delay_secs,
        max_retries: cfg.connect_max_retries,
        retry_base_delay_secs: cfg.connect_retry_base_delay_secs,
        retry_max_delay_secs: cfg.connect_retry_max_delay_secs,
    };
    runtime.spawn(crate::daemon::supervisor::run_supervisor(
        registry,
        engine_factory,
        supervisor_config,
    ));

    // Run the accept loop until it ends or a shutdown signal arrives, so
    // SIGTERM/Ctrl-C stop the daemon cleanly and we can unlink the socket
    // (there is no Drop unlink; bind() cleans a stale socket on next start,
    // but a graceful stop shouldn't leave one behind).
    let socket_for_cleanup = server.socket_path().to_path_buf();
    runtime.block_on(async {
        tokio::select! {
            result = server.run() => {
                if let Err(e) = result {
                    eprintln!("vortix daemon: accept loop terminated: {e}");
                }
            }
            () = shutdown_signal() => {
                eprintln!("vortix daemon: shutdown signal received; exiting");
            }
        }
    });
    let _ = std::fs::remove_file(&socket_for_cleanup);

    0
}

// ── Connection ──────────────────────────────────────────────────────────

#[derive(Serialize)]
struct UpData {
    state: String,
    profile: String,
    protocol: String,
}

#[allow(clippy::too_many_lines)]
fn handle_up(
    profile: Option<&str>,
    timeout_secs: u64,
    yes: bool,
    config: &AppConfig,
    config_dir: &Path,
    mode: OutputMode,
) -> i32 {
    // `yes` bypasses the multi-tunnel conflict prompt that U7 lands on
    // the connect-path overlay. The CLI today goes directly through
    // `VpnRuntime::connect_and_wait` (no conflict check there), so `yes`
    // is a no-op in the current build — but the flag is wired so scripts
    // can adopt it ahead of U7's overlay shipping. Once U7 wires the
    // registry conflict-check into the CLI path, this flag will gate
    // the bypass.
    let _ = yes;
    let mut engine = VpnRuntime::new_headless(config.clone(), config_dir.to_path_buf());

    let profile_name = if let Some(name) = profile {
        name.to_string()
    } else {
        engine.load_metadata();
        match engine
            .profiles
            .iter()
            .filter(|p| p.last_used.is_some())
            .max_by_key(|p| p.last_used)
            .map(|p| p.name.clone())
        {
            Some(name) => name,
            None => {
                print_error_and_exit(
                    mode,
                    "up",
                    CliError {
                        code: "no_profile",
                        message: "No profile specified and no previously used profile found".into(),
                        hint: Some("Specify a profile: sudo vortix up <PROFILE>".into()),
                    },
                    ExitCode::GeneralError,
                );
            }
        }
    };

    // U3: when a daemon is running, drive the connect through it — the
    // root daemon holds privilege, so an unprivileged client connects
    // without sudo. 2FA profiles need the local tty prompt (in-band
    // credential delivery over IPC is a follow-up), so they're refused on
    // the daemon path with a pointer. If the daemon turns out unavailable,
    // we fall through to the local privileged path unchanged (R11).
    if let Some(socket) = crate::daemon::daemon_socket_path_if_present() {
        engine.load_metadata();
        let profile = engine
            .profiles
            .iter()
            .find(|p| p.name == profile_name)
            .cloned();
        if let Some(p) = &profile {
            let missing =
                crate::vpn_runtime::VpnRuntime::check_dependencies(p.protocol, &p.config_path);
            if !missing.is_empty() {
                let hint = missing
                    .iter()
                    .map(|tool| crate::platform::install_hint(tool))
                    .collect::<Vec<_>>()
                    .join("\n");
                print_error_and_exit(
                    mode,
                    "up",
                    CliError {
                        code: "dependency_missing",
                        message: format!(
                            "Missing dependencies: {}. Install with: {}",
                            missing.join(", "),
                            hint
                        ),
                        hint: None,
                    },
                    ExitCode::DependencyMissing,
                );
            }
            if crate::utils::read_openvpn_static_challenge_prompt(&p.config_path).is_some() {
                print_error_and_exit(
                    mode,
                    "up",
                    CliError {
                        code: "daemon_2fa_unsupported",
                        message: format!(
                            "Profile '{profile_name}' requires interactive 2FA, which the daemon connect path doesn't support yet."
                        ),
                        hint: Some(
                            "Connect via the TUI (Auth Manager handles the OTP prompt), or stop the daemon and run `sudo vortix up` locally.".into(),
                        ),
                    },
                    ExitCode::GeneralError,
                );
            }
        }
        let protocol = profile.map_or_else(|| "VPN".to_string(), |p| p.protocol.to_string());
        match daemon_execute(
            &socket,
            crate::vortix_core::engine::input::UserCommand::Connect {
                profile_id: crate::vortix_core::profile::ProfileId::new(&profile_name),
            },
            mode,
            "up",
        ) {
            // Daemon vanished mid-command — fall through to the local path.
            None => {}
            // Success ONLY when the daemon reports Connected to the
            // profile we asked for. A single-FSM daemon that is already
            // Connected to a *different* profile no-ops our Connect and
            // returns that other profile's state — matching bare
            // `Connected { .. }` here would falsely claim success.
            Some(crate::vortix_core::engine::state::Connection::Connected {
                profile_id, ..
            }) if profile_id.as_str() == profile_name => {
                match mode {
                    OutputMode::Human => {
                        println!("● Connected to {profile_name} ({protocol})");
                    }
                    OutputMode::Json => print_success(
                        mode,
                        "up",
                        &UpData {
                            state: "connected".into(),
                            profile: profile_name.clone(),
                            protocol: protocol.clone(),
                        },
                        vec!["vortix status --json".into(), "vortix down --json".into()],
                    ),
                    OutputMode::Quiet => {}
                }
                return 0;
            }
            Some(state) => {
                print_error_and_exit(
                    mode,
                    "up",
                    CliError {
                        code: "connect_failed",
                        message: daemon_connect_failure_message(&state, &profile_name),
                        hint: None,
                    },
                    ExitCode::GeneralError,
                );
            }
        }
    }

    // Local privileged path: the client-side lifecycle lock guards
    // concurrent up/down only here (the daemon arbitrates its own path).
    let _lifecycle_lock = acquire_lifecycle_lock_or_exit(mode, "up");
    if !engine.is_root {
        print_error_and_exit(
            mode,
            "up",
            err_permission_denied(&format!("vortix up {profile_name}")),
            ExitCode::PermissionDenied,
        );
    }

    // Check dependencies before attempting connection. Routes through
    // `VpnRuntime::check_dependencies` so the TUI and CLI refuse the
    // same dep set — including the OpenVPN 2.4+ probe that the
    // legacy inline CLI check used to skip (R13 / plan 001 U14).
    engine.load_metadata();
    if let Some(profile) = engine.profiles.iter().find(|p| p.name == profile_name) {
        let missing = crate::vpn_runtime::VpnRuntime::check_dependencies(
            profile.protocol,
            &profile.config_path,
        );
        if !missing.is_empty() {
            let hint = missing
                .iter()
                .map(|tool| crate::platform::install_hint(tool))
                .collect::<Vec<_>>()
                .join("\n");
            print_error_and_exit(
                mode,
                "up",
                CliError {
                    code: "dependency_missing",
                    message: format!(
                        "Missing dependencies: {}. Install with: {}",
                        missing.join(", "),
                        hint
                    ),
                    hint: None,
                },
                ExitCode::GeneralError,
            );
        }
    }

    // True idempotency: `up` of an already-connected profile is a
    // success no-op, mirroring `down`'s already-disconnected path.
    // Without this, a second `up` re-spawned the tunnel — for OpenVPN
    // that meant a duplicate daemon whose pidfile clobbered the first's.
    if crate::core::scanner::get_active_profiles(&engine.profiles)
        .iter()
        .any(|s| s.name == profile_name)
    {
        let protocol = engine
            .profiles
            .iter()
            .find(|p| p.name == profile_name)
            .map_or_else(|| "VPN".to_string(), |p| p.protocol.to_string());
        let data = UpData {
            state: "connected".into(),
            profile: profile_name.clone(),
            protocol: protocol.clone(),
        };
        let next = vec![
            "vortix status --json".into(),
            "sudo vortix down --json".to_string(),
        ];
        match mode {
            OutputMode::Human => {
                println!("● Already connected to {profile_name} ({protocol})");
            }
            OutputMode::Json => print_success(mode, "up", &data, next),
            OutputMode::Quiet => {}
        }
        return 0;
    }

    // Multi-connection plan #001 U7: route the CLI connect through the
    // registry's conflict gate before invoking the legacy tunnel-up path.
    // The CLI is headless and has no in-memory registry, so we build a
    // transient one from the scanner's active-session snapshot and ask it
    // whether the new profile's AllowedIPs collide with anything already
    // up. `--yes` bypasses the gate for scripted callers.
    if !yes {
        if let Some(conflict) = detect_conflict_for_cli(&engine, &profile_name) {
            let (code, message) = match &conflict {
                crate::vortix_core::engine::Conflict::DefaultRouteTakeover {
                    current,
                    new: _,
                } => (
                    "state_conflict_default_route",
                    format!(
                        "Profile '{profile_name}' would take over the default route from '{current}'"
                    ),
                ),
                crate::vortix_core::engine::Conflict::RouteOverlap {
                    with,
                    overlapping_cidrs,
                } => (
                    "state_conflict_route_overlap",
                    format!(
                        "Profile '{profile_name}' overlaps with '{with}' on {} CIDR(s)",
                        overlapping_cidrs.len()
                    ),
                ),
            };
            print_error_and_exit(
                mode,
                "up",
                CliError {
                    code,
                    message,
                    hint: Some(format!(
                        "Pass --yes to bypass the conflict gate: sudo vortix up {profile_name} --yes"
                    )),
                },
                ExitCode::StateConflict,
            );
        }
    }

    // Plan 2026-06-02-001 U4 (#191): if the profile declares a
    // `static-challenge` directive, prompt for the OTP on the
    // controlling tty (always masked, regardless of the directive's
    // echo flag — DEC-2), write the SCRV1 envelope into the canonical
    // auth file, run the connect, and restore plain text on every exit
    // path. Non-tty stdin and missing saved credentials produce
    // actionable non-zero exits.
    let static_challenge_prompt = engine
        .profiles
        .iter()
        .find(|p| p.name == profile_name)
        .and_then(|p| crate::utils::read_openvpn_static_challenge_prompt(&p.config_path));
    let mut scrv1_restore_needed: Option<String> = None;
    if let Some(prompt_text) = static_challenge_prompt {
        let saved = crate::utils::read_openvpn_saved_auth(&profile_name);
        let Some((user, pass)) = saved else {
            print_error_and_exit(
                mode,
                "up",
                CliError {
                    code: "auth_required",
                    message: format!(
                        "Profile '{profile_name}' requires 2FA ('{prompt_text}'). Save \
                         username/password first via the TUI (Auth Manager), then re-run; \
                         the OTP will be prompted at each connect."
                    ),
                    hint: Some("Open the TUI and use Auth Manager to save credentials.".into()),
                },
                ExitCode::PermissionDenied,
            );
        };
        let otp = match prompt_masked_otp(&prompt_text) {
            Ok(s) if !s.is_empty() => s,
            Ok(_) => {
                print_error_and_exit(
                    mode,
                    "up",
                    CliError {
                        code: "auth_required",
                        message: "OTP required for 2FA profile".into(),
                        hint: None,
                    },
                    ExitCode::GeneralError,
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                print_error_and_exit(
                    mode,
                    "up",
                    CliError {
                        code: "user_cancelled",
                        message: "OTP prompt cancelled".into(),
                        hint: None,
                    },
                    ExitCode::GeneralError,
                );
            }
            Err(_) => {
                print_error_and_exit(
                    mode,
                    "up",
                    CliError {
                        code: "auth_required",
                        message: format!(
                            "Profile '{profile_name}' requires 2FA but stdin is not a tty. \
                             Run the TUI instead, or invoke from an interactive terminal."
                        ),
                        hint: None,
                    },
                    ExitCode::GeneralError,
                );
            }
        };
        if let Err(e) =
            crate::utils::write_openvpn_scrv1_auth_file(&profile_name, &user, &pass, &otp)
        {
            print_error_and_exit(
                mode,
                "up",
                CliError {
                    code: "auth_write_failed",
                    message: format!("Failed to write SCRV1 auth file: {e}"),
                    hint: None,
                },
                ExitCode::GeneralError,
            );
        }
        scrv1_restore_needed = Some(profile_name.clone());
    }

    let result = engine.connect_and_wait(&profile_name, Duration::from_secs(timeout_secs));
    // The protocol layer deletes the SCRV1 envelope after openvpn forks
    // (plan 2026-06-02-001 U3 / PF-2). Belt-and-braces: if the connect
    // never reached spawn (early-failure path), clear the envelope
    // here so it doesn't linger.
    if let Some(name) = scrv1_restore_needed {
        crate::utils::delete_openvpn_scrv1_auth_file(&name);
    }

    match result {
        Ok(result) if result.success => {
            let data = UpData {
                state: "connected".into(),
                profile: result.profile.clone(),
                protocol: format!("{}", result.protocol),
            };
            let next = vec![
                "vortix status --json".into(),
                format!("sudo vortix down --json"),
            ];

            match mode {
                OutputMode::Human => {
                    println!("● Connected to {} ({})", result.profile, result.protocol);
                }
                OutputMode::Json => print_success(mode, "up", &data, next),
                OutputMode::Quiet => {}
            }
            0
        }
        Ok(result) => {
            let err_msg = result.error.unwrap_or_else(|| "Connection failed".into());
            let exit = if err_msg.contains("timed out") {
                ExitCode::Timeout
            } else {
                ExitCode::GeneralError
            };
            print_error_and_exit(
                mode,
                "up",
                CliError {
                    code: if err_msg.contains("timed out") {
                        "timeout"
                    } else {
                        "connect_failed"
                    },
                    message: err_msg,
                    hint: None,
                },
                exit,
            );
        }
        Err(e) => {
            let (code, exit) = if e.contains("not found") {
                ("not_found", ExitCode::NotFound)
            } else if e.contains("root") || e.contains("permission") {
                ("permission_denied", ExitCode::PermissionDenied)
            } else if e.contains("Missing dependencies") {
                ("dependency_missing", ExitCode::DependencyMissing)
            } else {
                ("connect_failed", ExitCode::GeneralError)
            };
            print_error_and_exit(
                mode,
                "up",
                CliError {
                    code,
                    message: e,
                    hint: None,
                },
                exit,
            );
        }
    }
}

/// Detect a multi-tunnel conflict for the CLI's `up` path (plan #001 U7).
///
/// The CLI doesn't share an in-memory `TunnelRegistry` with the running
/// session — active tunnels are discovered via
/// `scanner::get_active_profiles`. We inspect each active session's parsed
/// config and use the **shared** `vortix_core::cidr` and
/// `claims_default_route_*` helpers (same logic the TUI's
/// `TunnelRegistry::detect_conflict` uses) so the two surfaces refuse the
/// same set of takeovers. The route-overlap branch is a CLI-only
/// superset until R10 v2 brings route-overlap detection into the
/// registry.
/// Acquire the cross-process lifecycle lock or exit with a structured
/// error. Proceeding without the lock would reintroduce the concurrent
/// `up`/`down` interleaving the lock exists to prevent.
fn acquire_lifecycle_lock_or_exit(mode: OutputMode, command: &str) -> std::fs::File {
    match crate::utils::acquire_lifecycle_lock() {
        Ok(file) => file,
        Err(e) => print_error_and_exit(
            mode,
            command,
            CliError {
                code: "lock_failed",
                message: format!("Could not acquire the vortix lifecycle lock: {e}"),
                hint: Some("Check permissions on the vortix config directory.".into()),
            },
            ExitCode::GeneralError,
        ),
    }
}

fn detect_conflict_for_cli(
    engine: &VpnRuntime,
    target_name: &str,
) -> Option<crate::vortix_core::engine::Conflict> {
    use crate::app::connection::extract_allowed_ips;
    use crate::vortix_core::cidr::{
        claims_default_route_v4, claims_default_route_v6, overlapping_cidrs,
    };
    use crate::vortix_core::engine::Conflict;
    use crate::vortix_core::profile::ProfileId;

    let target_profile = engine.profiles.iter().find(|p| p.name == target_name)?;
    let target_allowed = extract_allowed_ips(target_profile.protocol, &target_profile.config_path);
    let target_claims_default =
        claims_default_route_v4(&target_allowed) || claims_default_route_v6(&target_allowed);

    let active = crate::core::scanner::get_active_profiles(&engine.profiles);
    for session in &active {
        if session.name == target_name {
            // Re-up of an already-up profile isn't a conflict — the
            // connect path is idempotent here.
            continue;
        }
        let Some(active_profile) = engine.profiles.iter().find(|p| p.name == session.name) else {
            continue;
        };
        let active_allowed =
            extract_allowed_ips(active_profile.protocol, &active_profile.config_path);
        let active_claims_default =
            claims_default_route_v4(&active_allowed) || claims_default_route_v6(&active_allowed);

        if target_claims_default && active_claims_default {
            return Some(Conflict::DefaultRouteTakeover {
                current: ProfileId::new(&session.name),
                new: ProfileId::new(target_name),
            });
        }
        let overlap = overlapping_cidrs(&target_allowed, &active_allowed);
        if !overlap.is_empty() {
            return Some(Conflict::RouteOverlap {
                with: ProfileId::new(&session.name),
                overlapping_cidrs: overlap,
            });
        }
    }
    None
}

#[derive(Serialize)]
struct DownData {
    state: String,
    /// Profile names that this invocation disconnected. Empty when
    /// nothing was active (idempotent success path).
    disconnected: Vec<String>,
}

#[allow(clippy::too_many_lines)]
fn handle_down(
    profile_filter: Option<&str>,
    all: bool,
    force: bool,
    config: &AppConfig,
    config_dir: &Path,
    mode: OutputMode,
) -> i32 {
    let _ = all; // `--all` is the explicit form of the no-profile case (already the default).
    let mut engine = VpnRuntime::new_headless(config.clone(), config_dir.to_path_buf());

    // NotFound (exit 3) takes precedence over idempotence: a typo'd
    // profile is a script error, not "already disconnected".
    if let Some(name) = profile_filter {
        if engine.find_profile(name).is_none() {
            print_error_and_exit(mode, "down", err_not_found(name), ExitCode::NotFound);
        }
    }

    // Discover every active tunnel, then filter to the requested target.
    let mut targets: Vec<crate::core::scanner::ActiveSession> =
        crate::core::scanner::get_active_profiles(&engine.profiles);
    if let Some(name) = profile_filter {
        targets.retain(|s| s.name == name);
    }

    if targets.is_empty() {
        // Idempotent: already disconnected = success. Matches U20
        // scenario "vortix down corp with corp not active → exit 0".
        let data = DownData {
            state: "disconnected".into(),
            disconnected: Vec::new(),
        };
        match mode {
            OutputMode::Human => println!("Already disconnected"),
            OutputMode::Json => print_success(mode, "down", &data, vec![]),
            OutputMode::Quiet => {}
        }
        return 0;
    }

    // U3: route the teardown through a running daemon (no sudo). The
    // client already discovered the targets from the kernel scanner;
    // the daemon owns the FSM teardown. Falls through to the local
    // privileged path if the daemon is unavailable (R11).
    if let Some(socket) = crate::daemon::daemon_socket_path_if_present() {
        let profile_id = profile_filter.map(crate::vortix_core::profile::ProfileId::new);
        let cmd = if force {
            crate::vortix_core::engine::input::UserCommand::ForceDisconnect { profile_id }
        } else {
            crate::vortix_core::engine::input::UserCommand::Disconnect { profile_id }
        };
        if daemon_execute(&socket, cmd, mode, "down").is_some() {
            // The single-FSM daemon can't reliably target a specific
            // profile (its Disconnect ignores the profile_id), so DON'T
            // trust the requested target set — verify against the kernel.
            // Re-scan and report only the requested tunnels that actually
            // went away; a request that tore down nothing is an error, not
            // a false "disconnected".
            let still_active: std::collections::HashSet<String> =
                crate::core::scanner::get_active_profiles(&engine.profiles)
                    .into_iter()
                    .map(|s| s.name)
                    .collect();
            let disconnected: Vec<String> = targets
                .iter()
                .map(|s| s.name.clone())
                .filter(|n| !still_active.contains(n))
                .collect();

            if disconnected.is_empty() {
                let requested: Vec<&str> = targets.iter().map(|s| s.name.as_str()).collect();
                print_error_and_exit(
                    mode,
                    "down",
                    CliError {
                        code: "disconnect_failed",
                        message: format!(
                            "daemon did not tear down {}; it may be managing a different tunnel",
                            requested.join(", ")
                        ),
                        hint: Some(
                            "Check `vortix status`; multi-tunnel teardown through the daemon is limited today.".into(),
                        ),
                    },
                    ExitCode::GeneralError,
                );
            }

            let data = DownData {
                state: "disconnected".into(),
                disconnected: disconnected.clone(),
            };
            match mode {
                OutputMode::Human => {
                    if disconnected.len() == 1 {
                        println!("Disconnected {}", disconnected[0]);
                    } else {
                        println!("Disconnected {} tunnels:", disconnected.len());
                        for name in &disconnected {
                            println!("  - {name}");
                        }
                    }
                }
                OutputMode::Json => print_success(
                    mode,
                    "down",
                    &data,
                    vec!["vortix status --json".into(), "vortix list --json".into()],
                ),
                OutputMode::Quiet => {}
            }
            return 0;
        }
        // Daemon unavailable — fall through to the local privileged path.
    }

    // Local privileged path only (the daemon arbitrates its own).
    let _lifecycle_lock = acquire_lifecycle_lock_or_exit(mode, "down");
    if !engine.is_root {
        print_error_and_exit(
            mode,
            "down",
            err_permission_denied("vortix down"),
            ExitCode::PermissionDenied,
        );
    }

    // Tear down each active tunnel sequentially. `disconnect_and_wait`
    // takes the profile name + pid explicitly, so we iterate the
    // scanner-discovered sessions and call it once per tunnel. A future
    // unit that adds a registry to `VpnRuntime` could collapse this
    // into a single `registry.disconnect_all` call.
    let mut disconnected: Vec<String> = Vec::new();
    let mut last_error: Option<String> = None;
    for session in &targets {
        match engine.disconnect_and_wait(&session.name, session.pid, force, Duration::from_secs(20))
        {
            Ok(()) => disconnected.push(session.name.clone()),
            Err(e) => last_error = Some(e),
        }
    }

    if disconnected.is_empty() {
        let msg = last_error.unwrap_or_else(|| "Disconnect failed".into());
        print_error_and_exit(
            mode,
            "down",
            CliError {
                code: "disconnect_failed",
                message: msg,
                hint: if force {
                    None
                } else {
                    Some("Try: sudo vortix down --force".into())
                },
            },
            ExitCode::GeneralError,
        );
    }

    let data = DownData {
        state: "disconnected".into(),
        disconnected: disconnected.clone(),
    };
    match mode {
        OutputMode::Human => {
            if disconnected.len() == 1 {
                println!("Disconnected {}", disconnected[0]);
            } else {
                println!("Disconnected {} tunnels:", disconnected.len());
                for name in &disconnected {
                    println!("  - {name}");
                }
            }
            if let Some(e) = &last_error {
                eprintln!("warning: one or more tunnels did not disconnect cleanly: {e}");
            }
        }
        OutputMode::Json => print_success(
            mode,
            "down",
            &data,
            vec!["vortix status --json".into(), "vortix list --json".into()],
        ),
        OutputMode::Quiet => {}
    }
    0
}

fn handle_reconnect(
    profile_filter: Option<&str>,
    config: &AppConfig,
    config_dir: &Path,
    mode: OutputMode,
) -> i32 {
    // No top-level lifecycle lock here: the local path delegates each
    // connect to `handle_up`, which self-locks per tunnel. Holding a lock
    // across those calls would self-deadlock (flock LOCK_EX on a second
    // fd blocks even within one process), and the daemon path must not
    // hold a client-side lock at all (the daemon arbitrates).
    let mut engine = VpnRuntime::new_headless(config.clone(), config_dir.to_path_buf());
    engine.load_metadata();

    // Validate the requested profile exists in the catalog before we
    // poke the system. NotFound (exit 3) > "no active" idempotency.
    if let Some(name) = profile_filter {
        if engine.find_profile(name).is_none() {
            print_error_and_exit(mode, "reconnect", err_not_found(name), ExitCode::NotFound);
        }
    }

    // U3: route the reconnect through a running daemon — it cycles the
    // tunnel(s) atomically via the FSM (disconnect then connect), so a
    // non-root client needs no sudo. 2FA profiles that require a fresh
    // OTP on reconnect aren't handled on this path yet (the daemon has no
    // tty); such a reconnect surfaces as a daemon error. Falls through to
    // the local per-tunnel loop if the daemon is unavailable (R11).
    if let Some(socket) = crate::daemon::daemon_socket_path_if_present() {
        let cmd = crate::vortix_core::engine::input::UserCommand::Reconnect {
            profile_id: profile_filter.map(crate::vortix_core::profile::ProfileId::new),
        };
        match daemon_execute(&socket, cmd, mode, "reconnect") {
            None => {} // daemon unavailable — fall through to the local loop
            // Success only when the daemon reports Connected to the
            // profile we asked for (or to whatever single tunnel it holds
            // when no filter was given). Report the ACTUAL connected
            // profile, never a blanket "all tunnels" the single FSM can't
            // deliver.
            Some(crate::vortix_core::engine::state::Connection::Connected {
                profile_id, ..
            }) if profile_filter.is_none() || profile_filter == Some(profile_id.as_str()) => {
                let label = profile_id.as_str();
                match mode {
                    OutputMode::Human => println!("Reconnected {label}"),
                    OutputMode::Json => print_success(
                        mode,
                        "reconnect",
                        &serde_json::json!({ "state": "reconnected", "target": label }),
                        vec!["vortix status --json".into()],
                    ),
                    OutputMode::Quiet => {}
                }
                return 0;
            }
            Some(state) => {
                let label = profile_filter.unwrap_or("tunnel");
                print_error_and_exit(
                    mode,
                    "reconnect",
                    CliError {
                        code: "reconnect_failed",
                        message: daemon_connect_failure_message(&state, label),
                        hint: None,
                    },
                    ExitCode::GeneralError,
                );
            }
        }
    }

    // Decide which profile(s) to cycle.
    // - With a filter: just that one (must currently be Connected;
    //   otherwise we fall back to a fresh `up` so the user gets the
    //   "reconnect named profile" intent even if it's currently down).
    // - Without: every currently-Connected tunnel. If none are
    //   currently active, fall back to the last-used profile so the
    //   single-tunnel `vortix reconnect` muscle memory still works.
    let active = crate::core::scanner::get_active_profiles(&engine.profiles);

    let to_cycle: Vec<String> = if let Some(name) = profile_filter {
        vec![name.to_string()]
    } else if !active.is_empty() {
        active.iter().map(|s| s.name.clone()).collect()
    } else {
        // No active tunnels and no explicit target — fall back to
        // last-used (preserves the single-tunnel behaviour).
        match engine
            .profiles
            .iter()
            .filter(|p| p.last_used.is_some())
            .max_by_key(|p| p.last_used)
            .map(|p| p.name.clone())
        {
            Some(name) => vec![name],
            None => {
                print_error_and_exit(
                    mode,
                    "reconnect",
                    CliError {
                        code: "no_profile",
                        message: "No previously used profile found".into(),
                        hint: Some("Connect to a profile first: sudo vortix up <PROFILE>".into()),
                    },
                    ExitCode::NotFound,
                );
            }
        }
    };

    // Cycle each profile: disconnect (if active) then connect. The CLI
    // walks the scanner-discovered sessions one tunnel at a time; a
    // future unit could route through `TunnelRegistry::reconnect` once
    // the headless engine carries a registry. `handle_up` calls
    // `print_error_and_exit` on failure, so a failing connect aborts
    // the whole cycle — matching the per-tunnel reconnect semantics
    // this command preserves.
    let mut last_exit: i32 = 0;
    for name in &to_cycle {
        if let Some(session) = active.iter().find(|s| &s.name == name) {
            let _ = engine.disconnect_and_wait(
                &session.name,
                session.pid,
                false,
                Duration::from_secs(15),
            );
        }
        last_exit = handle_up(Some(name), 20, false, config, config_dir, mode);
    }
    last_exit
}

// ── Status ──────────────────────────────────────────────────────────────

/// `status` command JSON payload.
///
/// Shape is pinned by the v2 schema (see [`crate::cli::output`] module
/// docs):
///
/// - `connections`: all currently active tunnels. Empty when nothing is
///   connected. v2 readers should prefer this field.
/// - `primary`: profile id of the primary tunnel, or `null` when no
///   primary is elected (no active tunnels, or only secondaries).
/// - `connection`: v1 back-compat. Set to the primary's [`ConnectionEntry`]
///   when a primary exists, `null` otherwise. v0.3.x consumers reading
///   `data.connection.{state,profile,protocol,uptime_secs}` continue to
///   work in the primary-only case.
///
/// U22 will replace the transitional single-entry construction below
/// with a registry-driven snapshot; U21's job is just to make the v2
/// envelope shape available.
#[derive(Serialize)]
struct StatusData {
    connections: Vec<ConnectionEntry>,
    primary: Option<String>,
    connection: Option<ConnectionEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<StatusNetwork>,
    security: StatusSecurity,
}

#[derive(Serialize)]
struct StatusNetwork {
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    internal_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    download: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upload: Option<String>,
}

#[derive(Serialize)]
struct StatusSecurity {
    killswitch_mode: String,
    killswitch_state: String,
}

#[allow(clippy::too_many_lines)]
fn handle_status(
    watch: bool,
    interval: u64,
    brief: bool,
    no_daemon: bool,
    config: &AppConfig,
    config_dir: &Path,
    mode: OutputMode,
) -> i32 {
    if watch {
        // Watch always uses the direct scanner path — it polls in a
        // tight loop and daemon round-trips would just add latency.
        return run_watch(interval, config, config_dir, mode);
    }

    // Read-only ops route through the daemon ONLY when its socket
    // exists and is connectable. Otherwise fall back to direct disk +
    // scanner reads (plan multi-connection D3: read-only ops bypass
    // daemon when socket absent). The `--no-daemon` flag forces the
    // bypass even when the daemon is up — useful for testing.
    let daemon_socket = if no_daemon {
        None
    } else {
        crate::daemon::daemon_socket_path_if_present()
    };

    let engine = VpnRuntime::new_headless(config.clone(), config_dir.to_path_buf());
    let mut snap = engine.scan_status();
    // When the daemon socket is connectable, overlay its authoritative
    // view onto the scanner-derived snapshot via the EngineHandle::Remote
    // seam. Prefer the full multi-tunnel registry snapshot (U2); fall back
    // to the single-FSM snapshot (U1) for an older daemon that doesn't
    // serve a registry. The scanner still owns live counters and
    // kill-switch state. Failure handling is deliberately split:
    // unavailable/protocol errors keep the scanner view silently
    // (bypass-on-error keeps `vortix status` reliable), but a version
    // mismatch is a loud typed exit — silent fallback there would mask a
    // real client/daemon skew (AE8).
    let mut daemon_registry: Option<crate::vortix_core::engine::registry_handle::RegistrySnapshot> =
        None;
    if let Some(socket) = daemon_socket {
        match daemon_registry_via_remote(&socket) {
            Ok(Some(reg)) => {
                // Reflect the daemon's primary onto the scanner snapshot so
                // the human summary + network block follow the daemon's view.
                match reg.primary.as_ref().and_then(|id| {
                    reg.tunnels
                        .iter()
                        .find(|t| &t.profile_id == id)
                        .map(|t| &t.state)
                }) {
                    Some(state) => overlay_daemon_state(&mut snap, state),
                    None => overlay_daemon_state(
                        &mut snap,
                        &crate::vortix_core::engine::state::Connection::Disconnected {
                            last_failure: None,
                        },
                    ),
                }
                daemon_registry = Some(reg);
            }
            Ok(None) => match daemon_snapshot_via_remote(&socket) {
                Ok(Some(state)) => overlay_daemon_state(&mut snap, &state),
                Ok(None) => {}
                Err((daemon, client)) => {
                    exit_daemon_version_mismatch(mode, "status", daemon, client)
                }
            },
            Err((daemon, client)) => exit_daemon_version_mismatch(mode, "status", daemon, client),
        }
    }

    let is_connected = snap.connection_state == "connected";

    // `connections[]` + `primary` come from the daemon registry when
    // present (full multi-tunnel view); otherwise they mirror the
    // scanner's single active tunnel. `connection` stays the primary
    // entry for v1 back-compat.
    let (connections, primary): (Vec<ConnectionEntry>, Option<String>) =
        if let Some(reg) = &daemon_registry {
            registry_status_entries(reg, snap.protocol.as_deref())
        } else if is_connected {
            let entry = ConnectionEntry {
                state: snap.connection_state.clone(),
                profile: snap.profile.clone(),
                protocol: snap.protocol.clone(),
                uptime_secs: snap.uptime_secs,
            };
            (vec![entry], snap.profile.clone())
        } else {
            (Vec::new(), None)
        };
    let primary_entry: Option<ConnectionEntry> = primary.as_deref().and_then(|p| {
        connections
            .iter()
            .find(|c| c.profile.as_deref() == Some(p))
            .cloned()
    });

    let data = StatusData {
        connections,
        primary,
        connection: primary_entry,
        network: if is_connected {
            Some(StatusNetwork {
                server: snap.server.clone(),
                interface: snap.interface.clone(),
                internal_ip: snap.internal_ip.clone(),
                download: snap.download_bytes.clone(),
                upload: snap.upload_bytes.clone(),
            })
        } else {
            None
        },
        security: StatusSecurity {
            killswitch_mode: snap.killswitch_mode.cli_verb().to_string(),
            killswitch_state: snap.killswitch_state.cli_verb().to_string(),
        },
    };

    match mode {
        OutputMode::Human => {
            if brief {
                if is_connected {
                    let profile = snap.profile.as_deref().unwrap_or("unknown");
                    let proto = snap.protocol.as_deref().unwrap_or("");
                    println!("● Connected to {profile} ({proto})");
                } else {
                    println!("○ Disconnected");
                }
            } else if is_connected {
                let profile = snap.profile.as_deref().unwrap_or("unknown");
                let proto = snap.protocol.as_deref().unwrap_or("");
                println!("● Connected to {profile} ({proto})");
                println!();
                if let Some(s) = &snap.server {
                    println!("  Server       {s}");
                }
                if let Some(i) = &snap.interface {
                    println!("  Interface    {i}");
                }
                if let Some(ip) = &snap.internal_ip {
                    println!("  Internal IP  {ip}");
                }
                if let Some(up) = &snap.uptime_secs {
                    let h = up / 3600;
                    let m = (up % 3600) / 60;
                    let s = up % 60;
                    println!("  Uptime       {h}h {m}m {s}s");
                }
                if let Some(dl) = &snap.download_bytes {
                    println!("  Transfer     ↓ {dl}");
                }
                if let Some(ul) = &snap.upload_bytes {
                    println!("               ↑ {ul}");
                }
                println!(
                    "  Kill Switch  {} ({})",
                    snap.killswitch_mode.display_name(),
                    snap.killswitch_state.display_status()
                );
            } else {
                println!("○ Disconnected");
                println!();
                println!(
                    "  Kill Switch  {} ({})",
                    snap.killswitch_mode.display_name(),
                    snap.killswitch_state.display_status()
                );
            }
        }
        OutputMode::Json => {
            let next = if is_connected {
                vec![
                    "sudo vortix down --json".into(),
                    "vortix list --json".into(),
                ]
            } else {
                vec![
                    "vortix list --json".into(),
                    "sudo vortix up <PROFILE> --json".into(),
                ]
            };
            print_success(mode, "status", &data, next);
        }
        OutputMode::Quiet => {}
    }
    0
}

/// Merge an authoritative `Connection` from the daemon onto a
/// scanner-derived `StatusSnapshot`. The daemon owns the FSM state
/// (which profile is connecting/connected, since when, retry budget);
/// the scanner owns the live counters (transfer bytes, kill-switch
/// state). Today we overlay just the connection-state vocabulary so
/// the daemon's view of "what's the active profile" beats whatever
/// the scanner inferred from sockets — relevant when the daemon is
/// driving a tunnel the local-engine scanner doesn't recognize.
/// Fetch the daemon's FSM state through `EngineHandle::Remote`.
///
/// Returns `Ok(Some(state))` on success, `Ok(None)` for every
/// degradation that should silently fall back to the scanner view
/// (daemon unreachable, protocol hiccup, no async runtime available),
/// and `Err((daemon, client))` for a version mismatch — the one
/// failure that must surface loudly instead of degrading.
fn daemon_snapshot_via_remote(
    socket: &Path,
) -> Result<Option<crate::vortix_core::engine::state::Connection>, (u32, u32)> {
    use crate::vortix_core::engine::handle::RemoteHandle;
    use crate::vortix_core::ipc::TransportError;
    use std::sync::Arc;

    let Some(runtime) = crate::vortix_process::global_runner()
        .as_real()
        .map(|r| r.runtime().handle().clone())
    else {
        return Ok(None);
    };

    let transport = Arc::new(crate::daemon::client::UnixTransport::new(
        socket.to_path_buf(),
    ));
    let remote = RemoteHandle::new(transport);
    match runtime.block_on(remote.snapshot_remote()) {
        Ok(snapshot) => Ok(Some(snapshot.state)),
        Err(TransportError::VersionMismatch { daemon, client }) => Err((daemon, client)),
        // A read that's unavailable or slow just falls back to the scanner.
        Err(TransportError::Unavailable(_) | TransportError::Timeout(_)) => Ok(None),
        Err(TransportError::Protocol(e)) => {
            tracing::warn!(error = %e, "daemon snapshot protocol failure; using scanner view");
            Ok(None)
        }
    }
}

fn overlay_daemon_state(
    snap: &mut crate::vpn_runtime::connection::StatusSnapshot,
    state: &crate::vortix_core::engine::state::Connection,
) {
    use crate::vortix_core::engine::state::Connection;
    match state {
        Connection::Disconnected { .. } => {
            snap.connection_state = "disconnected".into();
            snap.profile = None;
            snap.protocol = None;
            snap.uptime_secs = None;
        }
        Connection::Connecting { profile_id, .. }
        | Connection::Reconnecting { profile_id, .. }
        | Connection::AwaitingUserInput { profile_id, .. } => {
            snap.connection_state = "connecting".into();
            snap.profile = Some(profile_id.as_str().to_string());
        }
        Connection::Disconnecting { profile_id, .. } => {
            snap.connection_state = "disconnecting".into();
            snap.profile = Some(profile_id.as_str().to_string());
        }
        Connection::Connected {
            profile_id, since, ..
        } => {
            snap.connection_state = "connected".into();
            snap.profile = Some(profile_id.as_str().to_string());
            if let Ok(elapsed) = std::time::SystemTime::now().duration_since(*since) {
                snap.uptime_secs = Some(elapsed.as_secs());
            }
        }
    }
}

/// Fetch the daemon's full multi-tunnel registry snapshot through
/// `EngineHandle::Remote` (plan 2026-07-18-001 U2). Same tri-state
/// contract as [`daemon_snapshot_via_remote`]: `Ok(Some)` on success,
/// `Ok(None)` for silent-fallback degradations (unreachable, or an older
/// daemon that doesn't serve a registry), and `Err((daemon, client))`
/// for a version mismatch that must surface loudly.
fn daemon_registry_via_remote(
    socket: &Path,
) -> Result<Option<crate::vortix_core::engine::registry_handle::RegistrySnapshot>, (u32, u32)> {
    use crate::vortix_core::engine::handle::RemoteHandle;
    use crate::vortix_core::ipc::TransportError;
    use std::sync::Arc;

    let Some(runtime) = crate::vortix_process::global_runner()
        .as_real()
        .map(|r| r.runtime().handle().clone())
    else {
        return Ok(None);
    };

    let transport = Arc::new(crate::daemon::client::UnixTransport::new(
        socket.to_path_buf(),
    ));
    let remote = RemoteHandle::new(transport);
    match runtime.block_on(remote.registry_snapshot_remote()) {
        Ok(snapshot) => Ok(Some(snapshot)),
        Err(TransportError::VersionMismatch { daemon, client }) => Err((daemon, client)),
        Err(TransportError::Unavailable(_) | TransportError::Timeout(_)) => Ok(None),
        Err(TransportError::Protocol(e)) => {
            tracing::warn!(error = %e, "daemon registry snapshot unavailable; trying single-FSM snapshot");
            Ok(None)
        }
    }
}

/// The `connection_state` string vocabulary shared by the scanner
/// snapshot and the daemon overlay.
fn connection_state_label(state: &crate::vortix_core::engine::state::Connection) -> &'static str {
    use crate::vortix_core::engine::state::Connection;
    match state {
        Connection::Disconnected { .. } => "disconnected",
        Connection::Connecting { .. }
        | Connection::Reconnecting { .. }
        | Connection::AwaitingUserInput { .. } => "connecting",
        Connection::Disconnecting { .. } => "disconnecting",
        Connection::Connected { .. } => "connected",
    }
}

/// Best-effort per-tunnel protocol from the interface name. Only a `wg`
/// prefix is an unambiguous signal (`WireGuard`); `utun`/`tun` collide
/// across protocols, so we report nothing rather than guess wrong.
fn protocol_from_interface(interface: Option<&str>) -> Option<String> {
    match interface {
        Some(i) if i.starts_with("wg") => Some("wireguard".to_string()),
        _ => None,
    }
}

/// Seconds since a tunnel came up, from the FSM `since` when Connected,
/// else the registry's `started_at`.
fn tunnel_uptime_secs(t: &crate::vortix_core::engine::registry::TunnelSnapshot) -> Option<u64> {
    use crate::vortix_core::engine::state::Connection;
    let since = match &t.state {
        Connection::Connected { since, .. } => Some(*since),
        _ => t.started_at,
    };
    since
        .and_then(|s| std::time::SystemTime::now().duration_since(s).ok())
        .map(|d| d.as_secs())
}

/// Build the v2 `connections[]` + `primary` from a daemon registry
/// snapshot. Disconnected entries are omitted (the array is "active
/// tunnels"). For the primary, the scanner's protocol (authoritative,
/// passed in) wins over the interface-name heuristic.
fn registry_status_entries(
    reg: &crate::vortix_core::engine::registry_handle::RegistrySnapshot,
    scanner_protocol: Option<&str>,
) -> (Vec<ConnectionEntry>, Option<String>) {
    let primary = reg.primary.as_ref().map(|p| p.as_str().to_string());
    let mut connections = Vec::with_capacity(reg.tunnels.len());
    for t in &reg.tunnels {
        let label = connection_state_label(&t.state);
        if label == "disconnected" {
            continue;
        }
        let profile = t.profile_id.as_str().to_string();
        let is_primary = primary.as_deref() == Some(profile.as_str());
        let heuristic = protocol_from_interface(t.interface_name.as_deref());
        let protocol = if is_primary {
            scanner_protocol.map(str::to_string).or(heuristic)
        } else {
            heuristic
        };
        connections.push(ConnectionEntry {
            state: label.to_string(),
            profile: Some(profile),
            protocol,
            uptime_secs: tunnel_uptime_secs(t),
        });
    }
    (connections, primary)
}

/// Loud exit for a client/daemon IPC version skew (AE8) — never a silent
/// fallback, since it masks real skew bugs.
fn exit_daemon_version_mismatch(
    mode: OutputMode,
    command: &'static str,
    daemon: u32,
    client: u32,
) -> ! {
    print_error_and_exit(
        mode,
        command,
        CliError {
            code: "daemon_version_mismatch",
            message: format!(
                "daemon speaks IPC protocol v{daemon}, this vortix speaks v{client} — upgrade the older binary so both match"
            ),
            hint: Some(
                "Restart the daemon after upgrading (sudo systemctl restart vortix-daemon, or relaunch `vortix daemon`).".into(),
            ),
        },
        ExitCode::GeneralError,
    );
}

/// Route a write command through a running daemon (plan 2026-07-18-001
/// U3). A non-root client drives the privileged operation via the root
/// daemon — no sudo. Returns:
///
/// - `Some(conn)` after the daemon executed the command, where `conn` is
///   the resulting FSM state (fetched via a follow-up snapshot so callers
///   can tell a real connect from a failed one — `Accepted` alone only
///   means "the FSM processed it"),
/// - `None` when the daemon turned out to be unavailable at send time, so
///   the caller should fall back to the local (privileged) path,
/// - never returns for a version mismatch or a daemon-side error — both
///   are terminal loud exits.
fn daemon_execute(
    socket: &Path,
    cmd: crate::vortix_core::engine::input::UserCommand,
    mode: OutputMode,
    command: &'static str,
) -> Option<crate::vortix_core::engine::state::Connection> {
    use crate::vortix_core::engine::handle::RemoteHandle;
    use crate::vortix_core::engine::state::Connection;
    use crate::vortix_core::ipc::TransportError;
    use std::sync::Arc;

    let runtime = crate::vortix_process::global_runner()
        .as_real()
        .map(|r| r.runtime().handle().clone())?;
    let transport = Arc::new(crate::daemon::client::UnixTransport::new(
        socket.to_path_buf(),
    ));
    let remote = RemoteHandle::new(transport);
    match runtime.block_on(remote.execute_remote(cmd)) {
        Ok(()) => {
            // `Accepted` only says the FSM processed the command. Fetch
            // the resulting state so the caller renders the truth (a
            // failed connect leaves the FSM Disconnected with a reason).
            // If the follow-up read fails, fall back to Disconnected —
            // the caller treats that as "not confirmed connected".
            let state = runtime
                .block_on(remote.snapshot_remote())
                .map(|s| s.state)
                .unwrap_or(Connection::Disconnected { last_failure: None });
            Some(state)
        }
        Err(TransportError::Unavailable(_)) => None,
        // A timeout is NOT a fall-through: the daemon received the command
        // and may still be executing it (a slow connect). Falling back to
        // the local path here would double-act on the same profile. Exit
        // loud and point the user at status instead.
        Err(TransportError::Timeout(_)) => print_error_and_exit(
            mode,
            command,
            CliError {
                code: "daemon_timeout",
                message: "the daemon accepted the command but did not report a result in time — it may still be working".into(),
                hint: Some(
                    "Check `vortix status`; do not retry blindly (the operation may still be in flight).".into(),
                ),
            },
            ExitCode::Timeout,
        ),
        Err(TransportError::VersionMismatch { daemon, client }) => {
            exit_daemon_version_mismatch(mode, command, daemon, client)
        }
        Err(TransportError::Protocol(e)) => print_error_and_exit(
            mode,
            command,
            CliError {
                code: "daemon_execute_failed",
                message: e,
                hint: Some(
                    "The daemon refused or failed the command. Check `journalctl -u vortix-daemon` (or the daemon's stderr).".into(),
                ),
                },
            ExitCode::GeneralError,
        ),
    }
}

/// Human-readable reason a daemon-routed connect didn't end `Connected`.
fn daemon_connect_failure_message(
    state: &crate::vortix_core::engine::state::Connection,
    profile: &str,
) -> String {
    use crate::vortix_core::engine::state::{Connection, FailureReason};
    match state {
        Connection::Disconnected {
            last_failure: Some(reason),
        } => match reason {
            FailureReason::RetryBudgetExhausted { attempts, .. } => {
                format!("Connection to '{profile}' failed after {attempts} attempt(s)")
            }
            FailureReason::HandshakeFailed(e) => format!("Handshake failed for '{profile}': {e}"),
            FailureReason::AuthFailed(e) => format!("Authentication failed for '{profile}': {e}"),
            FailureReason::ConfigInvalid(e) => {
                format!("Profile '{profile}' has an invalid config: {e}")
            }
            FailureReason::Timeout(_) => format!("Connection to '{profile}' timed out"),
            FailureReason::NoNetworkLink => {
                format!("No network link while connecting '{profile}'")
            }
            FailureReason::ProfileGone(_) => {
                format!("Profile '{profile}' was removed during the connect")
            }
            FailureReason::Other(e) => format!("Connection to '{profile}' failed: {e}"),
        },
        // The daemon reports Connected to a DIFFERENT profile: its single
        // FSM is already occupied, so our request no-op'd. Say so plainly
        // rather than a vague "did not complete".
        Connection::Connected { profile_id, .. } if profile_id.as_str() != profile => format!(
            "daemon is currently managing '{}', not '{profile}' — multi-tunnel connect through the daemon isn't supported yet",
            profile_id.as_str()
        ),
        _ => format!("Connection to '{profile}' did not complete"),
    }
}

fn run_watch(interval: u64, config: &AppConfig, config_dir: &Path, mode: OutputMode) -> i32 {
    loop {
        let engine = VpnRuntime::new_headless(config.clone(), config_dir.to_path_buf());
        let snap = engine.scan_status();

        match mode {
            OutputMode::Json => {
                #[derive(Serialize)]
                struct WatchLine {
                    ts: String,
                    state: String,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    profile: Option<String>,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    uptime_secs: Option<u64>,
                }
                let line = WatchLine {
                    ts: chrono_now(),
                    state: snap.connection_state,
                    profile: snap.profile,
                    uptime_secs: snap.uptime_secs,
                };
                println!("{}", serde_json::to_string(&line).unwrap_or_default());
            }
            OutputMode::Human => {
                use std::io::Write;
                if snap.connection_state == "connected" {
                    let profile = snap.profile.as_deref().unwrap_or("?");
                    print!("\r● {profile}");
                    if let Some(up) = snap.uptime_secs {
                        let m = up / 60;
                        let s = up % 60;
                        print!(" ({m}m{s}s)");
                    }
                    print!("    ");
                } else {
                    print!("\r○ Disconnected    ");
                }
                let _ = std::io::stdout().flush();
            }
            OutputMode::Quiet => {}
        }

        std::thread::sleep(Duration::from_secs(interval));
    }
}

#[allow(clippy::cast_possible_wrap)]
fn chrono_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // ISO 8601 UTC — computed without extra crate features
    let secs_per_min = 60u64;
    let secs_per_hour = 3600u64;
    let secs_per_day = 86_400u64;

    let total_days = now / secs_per_day;
    let time_of_day = now % secs_per_day;
    let hour = time_of_day / secs_per_hour;
    let minute = (time_of_day % secs_per_hour) / secs_per_min;
    let second = time_of_day % secs_per_min;

    // Days since epoch → year/month/day (civil calendar from days)
    let (y, m, d) = days_to_ymd(total_days as i64);
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless
)]
fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    // Algorithm from Howard Hinnant's date library (public domain)
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ── Profile Management ──────────────────────────────────────────────────

#[derive(Serialize)]
struct ProfileEntry {
    name: String,
    protocol: String,
    /// Multi-tunnel-aware: `true` when the scanner sees a kernel
    /// interface for this profile. Set per-entry from the scanner's
    /// full session list — not just `active.first()`.
    connected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_used: Option<String>,
    /// Stable profile ID from the `.meta.toml` sidecar (plan 006 U2/U4).
    /// `None` when the profile predates the migration.
    #[serde(skip_serializing_if = "Option::is_none")]
    profile_id: Option<String>,
    /// Optional group label from the sidecar.
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<String>,
}

#[allow(clippy::too_many_lines)]
fn handle_list(
    sort: Option<&str>,
    reverse: bool,
    protocol_filter: Option<&str>,
    names_only: bool,
    config: &AppConfig,
    config_dir: &Path,
    mode: OutputMode,
) -> i32 {
    let mut engine = VpnRuntime::new_headless(config.clone(), config_dir.to_path_buf());
    engine.load_metadata();

    // Sort
    match sort.unwrap_or("name") {
        "protocol" => engine.sort_order = crate::state::ProfileSortOrder::Protocol,
        "last-used" => engine.sort_order = crate::state::ProfileSortOrder::LastUsed,
        _ => engine.sort_order = crate::state::ProfileSortOrder::NameAsc,
    }
    engine.sort_profiles();

    let mut profiles: Vec<_> = engine.profiles.iter().collect();

    if reverse {
        profiles.reverse();
    }

    if let Some(proto) = protocol_filter {
        let proto_lower = proto.to_lowercase();
        profiles.retain(|p| format!("{}", p.protocol).to_lowercase() == proto_lower);
    }

    if profiles.is_empty() {
        match mode {
            OutputMode::Human => println!("No profiles found. Import one: vortix import <PATH>"),
            OutputMode::Json => print_success(
                mode,
                "list",
                &Vec::<ProfileEntry>::new(),
                vec!["vortix import <PATH> --json".into()],
            ),
            OutputMode::Quiet => {}
        }
        return 0;
    }

    if names_only {
        match mode {
            OutputMode::Human => {
                for p in &profiles {
                    println!("{}", p.name);
                }
            }
            OutputMode::Json => {
                let names: Vec<&str> = profiles.iter().map(|p| p.name.as_str()).collect();
                print_success(mode, "list", &names, vec![]);
            }
            OutputMode::Quiet => {}
        }
        return 0;
    }

    // Index sidecars by display_name so we can enrich each entry with the
    // stable profile_id + group label (plan 006 U2/U4). The lookup is
    // O(N + M) which is fine for the typical handful of profiles.
    let sidecars_by_name: std::collections::HashMap<String, _> = {
        use crate::vortix_config::profile_store::{FsProfileStore, ProfileStore};
        let store = FsProfileStore::new(config_dir.join(constants::PROFILES_DIR_NAME));
        store
            .list()
            .unwrap_or_default()
            .into_iter()
            .map(|s| (s.display_name.clone(), s))
            .collect()
    };

    // Multi-tunnel: every kernel-visible session counts. Built as a
    // HashSet so per-entry membership lookup is O(1) and every
    // active profile gets its dot — not just the first one (the
    // pre-fix `active.first()` was single-tunnel-era legacy).
    let active_names: std::collections::HashSet<String> =
        crate::core::scanner::get_active_profiles(&engine.profiles)
            .into_iter()
            .map(|s| s.name)
            .collect();

    let entries: Vec<ProfileEntry> = profiles
        .iter()
        .map(|p| {
            let sidecar = sidecars_by_name.get(&p.name);
            build_profile_entry(p, &active_names, sidecar)
        })
        .collect();

    match mode {
        OutputMode::Human => {
            // Calculate column widths
            let max_name = entries
                .iter()
                .map(|e| e.name.len())
                .max()
                .unwrap_or(4)
                .max(4);
            let max_proto = entries
                .iter()
                .map(|e| e.protocol.len())
                .max()
                .unwrap_or(8)
                .max(8);
            println!(
                "  {:<width_n$}  {:<width_p$}  LAST USED",
                "NAME",
                "PROTOCOL",
                width_n = max_name,
                width_p = max_proto,
            );
            for entry in &entries {
                let marker = if entry.connected { "●" } else { " " };
                let last = entry.last_used.as_deref().unwrap_or("never");
                println!(
                    "{marker} {:<width_n$}  {:<width_p$}  {last}",
                    entry.name,
                    entry.protocol,
                    width_n = max_name,
                    width_p = max_proto,
                );
            }
        }
        OutputMode::Json => {
            print_success(
                mode,
                "list",
                &entries,
                vec![
                    "vortix show <PROFILE> --json".into(),
                    "sudo vortix up <PROFILE> --json".into(),
                ],
            );
        }
        OutputMode::Quiet => {}
    }
    0
}

fn format_elapsed(secs: u64) -> String {
    if secs < 60 {
        return "just now".into();
    }
    if secs < 3600 {
        return format!("{} min ago", secs / 60);
    }
    if secs < 86_400 {
        return format!("{} hours ago", secs / 3600);
    }
    format!("{} days ago", secs / 86_400)
}

/// Build a single `ProfileEntry` for `handle_list`. Pulled out as a
/// pure function so the multi-tunnel connected-flag behaviour can be
/// regression-tested without filesystem / scanner setup.
///
/// `active_names` MUST contain every profile name the scanner sees as
/// active (a `HashSet` of strings). The pre-fix code used
/// `Option<&str>` from `active.first()` here, which silently lost
/// every active tunnel after the first — that's the bug this test
/// guards against.
fn build_profile_entry(
    profile: &crate::state::VpnProfile,
    active_names: &std::collections::HashSet<String>,
    sidecar: Option<&crate::vortix_config::profile_store::ProfileSummary>,
) -> ProfileEntry {
    ProfileEntry {
        name: profile.name.clone(),
        protocol: format!("{}", profile.protocol),
        connected: active_names.contains(&profile.name),
        last_used: profile
            .last_used
            .map(|t| match t.duration_since(std::time::UNIX_EPOCH) {
                Ok(d) => {
                    let secs = d.as_secs();
                    let elapsed = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|n| n.as_secs().saturating_sub(secs))
                        .unwrap_or(0);
                    format_elapsed(elapsed)
                }
                Err(_) => "unknown".into(),
            }),
        profile_id: sidecar.map(|s| s.id.as_str().to_string()),
        group: sidecar.and_then(|s| s.group.clone()),
    }
}

#[cfg(test)]
mod list_tests {
    //! Regression tests for the `vortix list` connected-flag bug
    //! (commit `d595e8d`). The pre-fix code used `active.first()` to
    //! find "the" connected profile and tag exactly one row with a
    //! dot. Multi-tunnel users saw the TUI sidebar correctly show
    //! N tunnels connected but `vortix list` would mark only one.
    //!
    //! Tests run against `build_profile_entry` (pure, no IO) — the
    //! actual `handle_list` is hard to unit-test because of the
    //! sidecar filesystem read + scanner subprocess, but the policy
    //! decision (per-row connected flag) lives in this helper.
    use super::*;
    use crate::state::{Protocol, VpnProfile};
    use std::collections::HashSet;

    fn profile(name: &str) -> VpnProfile {
        VpnProfile {
            name: name.to_string(),
            protocol: Protocol::WireGuard,
            config_path: std::path::PathBuf::from(format!("/tmp/{name}.conf")),
            location: String::new(),
            last_used: None,
        }
    }

    #[test]
    fn every_active_profile_gets_connected_true() {
        // Two profiles active simultaneously (the user's bug report
        // scenario: AWS_VPN + DATA_VPN both connected, but only
        // AWS_VPN got the dot pre-fix).
        let active: HashSet<String> = ["aws_vpn", "data_vpn"]
            .into_iter()
            .map(String::from)
            .collect();
        let profiles = [profile("aws_vpn"), profile("data_vpn"), profile("idle_vpn")];

        let entries: Vec<_> = profiles
            .iter()
            .map(|p| build_profile_entry(p, &active, None))
            .collect();

        // Both active profiles report connected=true. Pre-fix only
        // one would have been true.
        let connected_count = entries.iter().filter(|e| e.connected).count();
        assert_eq!(
            connected_count,
            2,
            "BOTH active profiles must report connected=true; got entries: {:?}",
            entries
                .iter()
                .map(|e| (&e.name, e.connected))
                .collect::<Vec<_>>()
        );

        // The idle profile reports connected=false.
        let idle = entries.iter().find(|e| e.name == "idle_vpn").unwrap();
        assert!(
            !idle.connected,
            "profile not in active set must report connected=false"
        );
    }

    #[test]
    fn no_active_profiles_yields_no_connected_flags() {
        let active = HashSet::new();
        let profiles = [profile("alpha"), profile("beta")];
        let entries: Vec<_> = profiles
            .iter()
            .map(|p| build_profile_entry(p, &active, None))
            .collect();
        assert!(
            entries.iter().all(|e| !e.connected),
            "empty active set must mark every entry connected=false"
        );
    }

    #[test]
    fn connected_flag_is_always_serialized_for_machine_consumers() {
        // The `connected` field must be present in JSON output even
        // when false — otherwise machine consumers can't tell apart
        // "absent → don't know" from "present → false → disconnected".
        // Compile-time check via the struct definition: no
        // `skip_serializing_if` on `connected`. Run-time check via
        // serde round-trip.
        let entry = build_profile_entry(&profile("alpha"), &HashSet::new(), None);
        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(
            json.contains("\"connected\":false"),
            "connected=false must serialize explicitly; got: {json}"
        );
    }
}

fn handle_import(file: &str, mode: OutputMode) -> i32 {
    use crate::core::importer::{resolve_target, ImportTarget};

    match resolve_target(file) {
        Ok(ImportTarget::Url(url)) => {
            if matches!(mode, OutputMode::Human) {
                println!("Downloading...");
            }
            match crate::core::downloader::download_profile(&url) {
                Ok(downloaded_path) => {
                    let result = crate::vpn::import_profile(&downloaded_path);
                    crate::core::downloader::cleanup_temp_download(&downloaded_path);
                    match result {
                        Ok(profile) => {
                            print_import_success(&profile, mode);
                            0
                        }
                        Err(e) => {
                            print_error_and_exit(
                                mode,
                                "import",
                                CliError {
                                    code: "import_failed",
                                    message: format!("Import failed: {e}"),
                                    hint: None,
                                },
                                ExitCode::GeneralError,
                            );
                        }
                    }
                }
                Err(e) => {
                    print_error_and_exit(
                        mode,
                        "import",
                        CliError {
                            code: "download_failed",
                            message: format!("Download failed: {e}"),
                            hint: None,
                        },
                        ExitCode::GeneralError,
                    );
                }
            }
        }
        Ok(ImportTarget::File(path)) => match crate::vpn::import_profile(&path) {
            Ok(profile) => {
                print_import_success(&profile, mode);
                0
            }
            Err(e) => {
                print_error_and_exit(
                    mode,
                    "import",
                    CliError {
                        code: "import_failed",
                        message: format!("Import failed: {e}"),
                        hint: None,
                    },
                    ExitCode::GeneralError,
                );
            }
        },
        Ok(ImportTarget::Directory(path)) => import_from_directory(&path, mode),
        Err(e) => {
            print_error_and_exit(
                mode,
                "import",
                CliError {
                    code: "invalid_path",
                    message: e,
                    hint: None,
                },
                ExitCode::GeneralError,
            );
        }
    }
}

#[derive(Serialize)]
struct ImportData {
    name: String,
    protocol: String,
    location: String,
    config_path: String,
}

fn print_import_success(profile: &crate::state::VpnProfile, mode: OutputMode) {
    let data = ImportData {
        name: profile.name.clone(),
        protocol: format!("{}", profile.protocol),
        location: profile.location.clone(),
        config_path: profile.config_path.to_string_lossy().to_string(),
    };
    match mode {
        OutputMode::Human => {
            println!("✓ Imported '{}'", profile.name);
            println!("  Protocol:  {}", profile.protocol);
            println!("  Location:  {}", profile.location);
            println!("  Config:    {}", profile.config_path.display());
        }
        OutputMode::Json => print_success(
            mode,
            "import",
            &data,
            vec![
                format!("sudo vortix up {} --json", profile.name),
                "vortix list --json".into(),
            ],
        ),
        OutputMode::Quiet => {}
    }
}

fn import_from_directory(dir_path: &Path, mode: OutputMode) -> i32 {
    let mut imported = Vec::new();
    let mut failed = 0;

    match std::fs::read_dir(dir_path) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file()
                    && path
                        .extension()
                        .is_some_and(|ext| ext == "conf" || ext == "ovpn")
                {
                    match crate::vpn::import_profile(&path) {
                        Ok(profile) => {
                            if matches!(mode, OutputMode::Human) {
                                println!("  ✓ {}", profile.name);
                            }
                            imported.push(ImportData {
                                name: profile.name,
                                protocol: format!("{}", profile.protocol),
                                location: profile.location,
                                config_path: profile.config_path.to_string_lossy().to_string(),
                            });
                        }
                        Err(e) => {
                            if matches!(mode, OutputMode::Human) {
                                eprintln!("  ✗ {} - {}", path.display(), e);
                            }
                            failed += 1;
                        }
                    }
                }
            }
        }
        Err(e) => {
            print_error_and_exit(
                mode,
                "import",
                CliError {
                    code: "io_error",
                    message: format!("Cannot read directory: {e}"),
                    hint: None,
                },
                ExitCode::GeneralError,
            );
        }
    }

    if imported.is_empty() && failed == 0 {
        print_error_and_exit(
            mode,
            "import",
            CliError {
                code: "no_files",
                message: "No .conf or .ovpn files found in directory".into(),
                hint: None,
            },
            ExitCode::NotFound,
        );
    }

    match mode {
        OutputMode::Human => {
            println!(
                "\nImported {} profile(s){}",
                imported.len(),
                if failed > 0 {
                    format!(", {failed} failed")
                } else {
                    String::new()
                }
            );
        }
        OutputMode::Json => {
            print_success(mode, "import", &imported, vec!["vortix list --json".into()]);
        }
        OutputMode::Quiet => {}
    }

    i32::from(failed > 0)
}

#[derive(Serialize)]
struct ShowData {
    name: String,
    protocol: String,
    location: String,
    config_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_config: Option<String>,
}

fn handle_show(
    profile_name: &str,
    raw: bool,
    config: &AppConfig,
    config_dir: &Path,
    mode: OutputMode,
) -> i32 {
    let engine = VpnRuntime::new_headless(config.clone(), config_dir.to_path_buf());
    let Some(profile) = engine.profiles.iter().find(|p| p.name == profile_name) else {
        print_error_and_exit(
            mode,
            "show",
            err_not_found(profile_name),
            ExitCode::NotFound,
        );
    };

    let raw_content = if raw {
        match std::fs::read_to_string(&profile.config_path) {
            Ok(content) => Some(content),
            Err(e) => {
                print_error_and_exit(
                    mode,
                    "show",
                    CliError {
                        code: "io_error",
                        message: format!("Cannot read config file: {e}"),
                        hint: None,
                    },
                    ExitCode::GeneralError,
                );
            }
        }
    } else {
        None
    };

    let data = ShowData {
        name: profile.name.clone(),
        protocol: format!("{}", profile.protocol),
        location: profile.location.clone(),
        config_path: profile.config_path.to_string_lossy().to_string(),
        raw_config: raw_content.clone(),
    };

    match mode {
        OutputMode::Human => {
            println!("Profile: {}", profile.name);
            println!("Protocol: {}", profile.protocol);
            println!("Location: {}", profile.location);
            println!("Config: {}", profile.config_path.display());
            if let Some(content) = &raw_content {
                println!("\n--- Raw Config ---\n{content}");
            }
        }
        OutputMode::Json => print_success(
            mode,
            "show",
            &data,
            vec![format!("sudo vortix up {} --json", profile.name)],
        ),
        OutputMode::Quiet => {}
    }
    0
}

#[derive(Serialize)]
struct DeleteData {
    deleted: String,
}

fn handle_delete(
    profile_name: &str,
    yes: bool,
    config: &AppConfig,
    config_dir: &Path,
    mode: OutputMode,
) -> i32 {
    let mut engine = VpnRuntime::new_headless(config.clone(), config_dir.to_path_buf());

    let Some(idx) = engine.find_profile(profile_name) else {
        print_error_and_exit(
            mode,
            "delete",
            err_not_found(profile_name),
            ExitCode::NotFound,
        );
    };

    // Check if profile is active
    let active = crate::core::scanner::get_active_profiles(&engine.profiles);
    if active.iter().any(|s| s.name == profile_name) {
        print_error_and_exit(
            mode,
            "delete",
            CliError {
                code: "state_conflict",
                message: format!(
                    "Cannot delete active profile '{profile_name}' — disconnect first"
                ),
                hint: Some(format!("sudo vortix down && vortix delete {profile_name}")),
            },
            ExitCode::StateConflict,
        );
    }

    if !yes && !matches!(mode, OutputMode::Json | OutputMode::Quiet) {
        use std::io::Write;
        eprint!("Delete profile '{profile_name}'? [y/N] ");
        let _ = std::io::stderr().flush();
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_err()
            || !input.trim().eq_ignore_ascii_case("y")
        {
            eprintln!("Cancelled");
            return 0;
        }
    }

    let config_path = engine.profiles[idx].config_path.clone();
    let protocol = engine.profiles[idx].protocol;
    engine.profiles.remove(idx);
    if config_path.exists() {
        let _ = std::fs::remove_file(&config_path);
    }
    if matches!(protocol, crate::state::Protocol::OpenVPN) {
        crate::utils::delete_openvpn_auth_file(profile_name);
        crate::utils::cleanup_openvpn_run_files(profile_name);
    }

    let data = DeleteData {
        deleted: profile_name.to_string(),
    };

    match mode {
        OutputMode::Human => println!("Deleted '{profile_name}'"),
        OutputMode::Json => print_success(mode, "delete", &data, vec!["vortix list --json".into()]),
        OutputMode::Quiet => {}
    }
    0
}

#[derive(Serialize)]
struct RenameData {
    old_name: String,
    new_name: String,
}

fn handle_rename(
    old: &str,
    new: &str,
    config: &AppConfig,
    config_dir: &Path,
    mode: OutputMode,
) -> i32 {
    let mut engine = VpnRuntime::new_headless(config.clone(), config_dir.to_path_buf());

    let Some(idx) = engine.find_profile(old) else {
        print_error_and_exit(mode, "rename", err_not_found(old), ExitCode::NotFound);
    };

    let active = crate::core::scanner::get_active_profiles(&engine.profiles);
    if active.iter().any(|s| s.name == old) {
        print_error_and_exit(
            mode,
            "rename",
            CliError {
                code: "state_conflict",
                message: format!("Cannot rename active profile '{old}' — disconnect first"),
                hint: Some(format!("sudo vortix down && vortix rename {old} {new}")),
            },
            ExitCode::StateConflict,
        );
    }

    let trimmed = new.trim();
    if trimmed.is_empty()
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || trimmed.starts_with('.')
    {
        print_error_and_exit(
            mode,
            "rename",
            CliError {
                code: "invalid_name",
                message: "Invalid name: must not contain path separators or '..'".into(),
                hint: None,
            },
            ExitCode::GeneralError,
        );
    }

    let old_path = engine.profiles[idx].config_path.clone();
    if let Some(parent) = old_path.parent() {
        let ext = old_path
            .extension()
            .map_or("conf", |e| e.to_str().unwrap_or("conf"));
        let new_file = parent.join(format!("{trimmed}.{ext}"));

        if new_file.exists() {
            print_error_and_exit(
                mode,
                "rename",
                CliError {
                    code: "already_exists",
                    message: format!("A profile named '{trimmed}' already exists"),
                    hint: None,
                },
                ExitCode::StateConflict,
            );
        }

        if let Err(e) = std::fs::rename(&old_path, &new_file) {
            print_error_and_exit(
                mode,
                "rename",
                CliError {
                    code: "io_error",
                    message: format!("Rename failed: {e}"),
                    hint: None,
                },
                ExitCode::GeneralError,
            );
        }

        engine.profiles[idx].name = trimmed.to_string();
        engine.profiles[idx].config_path = new_file;
        engine.save_metadata();
    } else {
        print_error_and_exit(
            mode,
            "rename",
            CliError {
                code: "invalid_path",
                message: "Cannot determine parent directory for profile config path".into(),
                hint: None,
            },
            ExitCode::GeneralError,
        );
    }

    let data = RenameData {
        old_name: old.into(),
        new_name: trimmed.into(),
    };

    match mode {
        OutputMode::Human => println!("Renamed '{old}' → '{trimmed}'"),
        OutputMode::Json => print_success(mode, "rename", &data, vec!["vortix list --json".into()]),
        OutputMode::Quiet => {}
    }
    0
}

// ── Security ────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct KsData {
    mode: String,
    state: String,
}

fn handle_killswitch(
    mode_arg: Option<&str>,
    config: &AppConfig,
    config_dir: &Path,
    output_mode: OutputMode,
) -> i32 {
    let mut engine = VpnRuntime::new_headless(config.clone(), config_dir.to_path_buf());

    if let Some(new_mode) = mode_arg {
        let Some(ks_mode) = crate::state::KillSwitchMode::from_cli_verb(new_mode) else {
            print_error_and_exit(
                output_mode,
                "killswitch",
                CliError {
                    code: "invalid_mode",
                    message: format!(
                        "Unknown mode '{new_mode}'. Use: off, block-on-drop, vpn-only"
                    ),
                    hint: None,
                },
                ExitCode::GeneralError,
            );
        };

        if !engine.is_root && ks_mode != crate::state::KillSwitchMode::Off {
            print_error_and_exit(
                output_mode,
                "killswitch",
                err_permission_denied(&format!("vortix killswitch {}", ks_mode.cli_verb())),
                ExitCode::PermissionDenied,
            );
        }

        engine.killswitch_mode = ks_mode;
        let (is_connected, active_tunnels) = engine.killswitch_view_from_scanner();
        engine.sync_killswitch(is_connected, &active_tunnels);
    }

    // JSON envelope carries the canonical slug — the same string
    // users type as a CLI verb (`off` / `block-on-drop` / `vpn-only`).
    // Human-facing rendering uses the title-cased prose form from
    // `display_name`; the two are derived from one vocabulary.
    let data = KsData {
        mode: engine.killswitch_mode.cli_verb().to_string(),
        state: engine.killswitch_state.cli_verb().to_string(),
    };

    match output_mode {
        OutputMode::Human => {
            let mode = engine.killswitch_mode;
            let (up, down) = mode.behavior_lines();
            println!(
                "Kill Switch: {} — currently {}",
                mode.display_name(),
                engine.killswitch_state.display_status()
            );
            println!("  {up}");
            println!("  {down}");
            println!();
            println!("Other modes:");
            for other in [
                crate::state::KillSwitchMode::Off,
                crate::state::KillSwitchMode::Auto,
                crate::state::KillSwitchMode::AlwaysOn,
            ] {
                if other == mode {
                    continue;
                }
                println!(
                    "  vortix killswitch {:<14}  {} — {}",
                    other.cli_verb(),
                    other.display_name(),
                    other.one_liner()
                );
            }
        }
        OutputMode::Json => print_success(output_mode, "killswitch", &data, vec![]),
        OutputMode::Quiet => {}
    }
    0
}

#[derive(Serialize)]
struct ReleaseData {
    released: bool,
}

fn handle_release_killswitch(mode: OutputMode) {
    match crate::core::killswitch::disable_blocking() {
        Ok(()) => {
            crate::core::killswitch::clear_state();
            match mode {
                OutputMode::Human => {
                    println!("Kill switch released. Internet access restored.");
                }
                OutputMode::Json => {
                    print_success(
                        mode,
                        "release-killswitch",
                        &ReleaseData { released: true },
                        vec![],
                    );
                }
                OutputMode::Quiet => {}
            }
        }
        Err(e) => {
            eprintln!("Warning: {e}");
            eprintln!("{}", crate::platform::KILLSWITCH_EMERGENCY_MSG);
        }
    }
}

// ── System ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct InfoData {
    version: String,
    config_dir: String,
    config_source: String,
    config_status: String,
    profiles_dir: String,
    profile_count: u32,
    wireguard_count: u32,
    openvpn_count: u32,
    is_root: bool,
    /// Path of the current session's JSONL journal file, or `None`
    /// when disk persistence is disabled (`[journal] disk = false` in
    /// settings.toml) or the journal isn't installed in this process.
    #[serde(skip_serializing_if = "Option::is_none")]
    journal_session: Option<String>,
}

fn handle_info(config_dir: &Path, source: &str, mode: OutputMode) {
    let profiles_dir = config_dir.join(constants::PROFILES_DIR_NAME);
    let (wg_count, ovpn_count) = count_profiles(&profiles_dir);
    let total = wg_count + ovpn_count;

    let config_file = config_dir.join("config.toml");
    let config_status = if config_file.is_file() {
        "loaded"
    } else {
        "defaults"
    };

    // Session-journal path (plan 005). Folded into `vortix info` as part
    // of the v0.3.0 CLI surface cleanup — `vortix journal path` was
    // dropped in favour of surfacing the path here.
    let journal_session = crate::vortix_core::journal::global_journal()
        .and_then(|j| j.session_path.as_ref().map(|p| p.display().to_string()));

    let data = InfoData {
        version: env!("CARGO_PKG_VERSION").to_string(),
        config_dir: config_dir.to_string_lossy().to_string(),
        config_source: source.to_string(),
        config_status: config_status.to_string(),
        profiles_dir: profiles_dir.to_string_lossy().to_string(),
        profile_count: total,
        wireguard_count: wg_count,
        openvpn_count: ovpn_count,
        is_root: crate::utils::is_root(),
        journal_session: journal_session.clone(),
    };

    match mode {
        OutputMode::Human => {
            println!("vortix {}", env!("CARGO_PKG_VERSION"));
            println!();
            println!("  Config dir:  {} ({source})", config_dir.display());
            println!("  Config file: {} ({config_status})", config_file.display());
            println!("  Profiles:    {total} ({wg_count} WireGuard, {ovpn_count} OpenVPN)");
            println!("  Profiles at: {}", profiles_dir.display());
            println!(
                "  Logs at:     {}",
                config_dir.join(constants::LOGS_DIR_NAME).display()
            );
            match &journal_session {
                Some(path) => println!("  Session journal: {path}"),
                None => println!("  Session journal: (disk persistence disabled)"),
            }
        }
        OutputMode::Json => print_success(
            mode,
            "info",
            &data,
            vec!["vortix list --json".into(), "vortix status --json".into()],
        ),
        OutputMode::Quiet => {}
    }
}

fn handle_update(mode: OutputMode) {
    if matches!(mode, OutputMode::Human) {
        println!("Updating vortix...");
    }

    let result = crate::vortix_process::run_to_output(crate::vortix_process::CommandSpec::oneshot(
        "cargo",
        vec!["install".into(), "vortix".into(), "--force".into()],
    ));

    match result {
        Ok(s) if s.status.success() => match mode {
            OutputMode::Human => {
                println!("Updated successfully!");
                println!("Verify: vortix --version");
            }
            OutputMode::Json => {
                #[derive(Serialize)]
                struct D {
                    updated: bool,
                }
                print_success(mode, "update", &D { updated: true }, vec![]);
            }
            OutputMode::Quiet => {}
        },
        _ => {
            print_error_and_exit(
                mode,
                "update",
                CliError {
                    code: "update_failed",
                    message: "Update failed. Try manually: cargo install vortix --force".into(),
                    hint: None,
                },
                ExitCode::GeneralError,
            );
        }
    }
}

fn handle_completions(shell: clap_complete::Shell) {
    use clap::CommandFactory;
    clap_complete::generate(
        shell,
        &mut crate::cli::args::Args::command(),
        "vortix",
        &mut std::io::stdout(),
    );
}

/// Counts VPN profiles in a directory by extension.
pub(crate) fn count_profiles(profiles_dir: &Path) -> (u32, u32) {
    if !profiles_dir.is_dir() {
        return (0, 0);
    }
    let mut wg = 0u32;
    let mut ovpn = 0u32;
    if let Ok(entries) = std::fs::read_dir(profiles_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                match path.extension().and_then(|e| e.to_str()) {
                    Some("conf") => wg += 1,
                    Some("ovpn") => ovpn += 1,
                    _ => {}
                }
            }
        }
    }
    (wg, ovpn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_profiles_empty_dir() {
        let dir = tempfile::Builder::new()
            .prefix("vortix_test_")
            .tempdir()
            .unwrap();
        let (wg, ovpn) = count_profiles(dir.path());
        assert_eq!(wg, 0);
        assert_eq!(ovpn, 0);
    }

    #[test]
    fn test_count_profiles_nonexistent_dir() {
        let dir = tempfile::Builder::new()
            .prefix("vortix_test_")
            .tempdir()
            .unwrap();
        let (wg, ovpn) = count_profiles(&dir.path().join("no_such"));
        assert_eq!(wg, 0);
        assert_eq!(ovpn, 0);
    }

    #[test]
    fn test_count_profiles_mixed() {
        let dir = tempfile::Builder::new()
            .prefix("vortix_test_")
            .tempdir()
            .unwrap();
        std::fs::write(dir.path().join("wg0.conf"), "[Interface]").unwrap();
        std::fs::write(dir.path().join("wg1.conf"), "[Interface]").unwrap();
        std::fs::write(dir.path().join("us.ovpn"), "remote us.vpn").unwrap();
        std::fs::write(dir.path().join("notes.txt"), "hello").unwrap();
        let (wg, ovpn) = count_profiles(dir.path());
        assert_eq!(wg, 2);
        assert_eq!(ovpn, 1);
    }

    #[test]
    fn test_format_elapsed() {
        assert_eq!(format_elapsed(30), "just now");
        assert_eq!(format_elapsed(120), "2 min ago");
        assert_eq!(format_elapsed(7200), "2 hours ago");
        assert_eq!(format_elapsed(172_800), "2 days ago");
    }

    // ===== daemon registry -> status envelope (plan 2026-07-18-001 U2) =====

    use crate::vortix_core::engine::registry::{Role, TunnelSnapshot};
    use crate::vortix_core::engine::registry_handle::RegistrySnapshot;
    use crate::vortix_core::engine::state::{Connection, ConnectionHealth};
    use crate::vortix_core::profile::ProfileId;
    use crate::vortix_core::state::KillSwitchState;

    fn connected_tunnel(name: &str, iface: &str) -> TunnelSnapshot {
        TunnelSnapshot {
            profile_id: ProfileId::new(name),
            state: Connection::Connected {
                profile_id: ProfileId::new(name),
                since: std::time::SystemTime::now(),
                health: ConnectionHealth::Healthy,
                details: Box::default(),
            },
            role: Role::Primary {
                allowed_ips: Vec::new(),
            },
            health: ConnectionHealth::Healthy,
            interface_name: Some(iface.into()),
            started_at: Some(std::time::SystemTime::now()),
        }
    }

    #[test]
    fn protocol_from_interface_only_confident_for_wireguard() {
        assert_eq!(
            protocol_from_interface(Some("wg0")),
            Some("wireguard".into())
        );
        assert_eq!(protocol_from_interface(Some("utun4")), None);
        assert_eq!(protocol_from_interface(Some("tun0")), None);
        assert_eq!(protocol_from_interface(None), None);
    }

    #[test]
    fn registry_entries_lists_all_active_tunnels_with_primary() {
        let reg = RegistrySnapshot {
            tunnels: vec![
                connected_tunnel("corp", "wg0"),
                connected_tunnel("home", "tun0"),
            ],
            primary: Some(ProfileId::new("corp")),
            killswitch: KillSwitchState::Disabled,
        };
        let (connections, primary) = registry_status_entries(&reg, None);
        assert_eq!(connections.len(), 2);
        assert_eq!(primary.as_deref(), Some("corp"));
        // wg interface -> wireguard; tun -> unknown (omitted).
        let corp = connections
            .iter()
            .find(|c| c.profile.as_deref() == Some("corp"))
            .unwrap();
        assert_eq!(corp.protocol.as_deref(), Some("wireguard"));
        assert_eq!(corp.state, "connected");
        let home = connections
            .iter()
            .find(|c| c.profile.as_deref() == Some("home"))
            .unwrap();
        assert_eq!(home.protocol, None);
    }

    #[test]
    fn registry_entries_scanner_protocol_wins_for_primary() {
        // Primary interface is a utun (protocol ambiguous from iface),
        // but the scanner knows it's openvpn — that must win.
        let reg = RegistrySnapshot {
            tunnels: vec![connected_tunnel("corp", "utun5")],
            primary: Some(ProfileId::new("corp")),
            killswitch: KillSwitchState::Disabled,
        };
        let (connections, _) = registry_status_entries(&reg, Some("openvpn"));
        assert_eq!(connections[0].protocol.as_deref(), Some("openvpn"));
    }

    #[test]
    fn daemon_connect_failure_message_maps_reasons() {
        use crate::vortix_core::engine::state::{Connection, FailureReason};
        let auth = Connection::Disconnected {
            last_failure: Some(FailureReason::AuthFailed("bad otp".into())),
        };
        assert!(daemon_connect_failure_message(&auth, "corp").contains("Authentication failed"));

        let gone = Connection::Disconnected {
            last_failure: Some(FailureReason::ProfileGone(ProfileId::new("corp"))),
        };
        assert!(daemon_connect_failure_message(&gone, "corp").contains("removed"));

        // No recorded reason → a generic "did not complete".
        let bare = Connection::Disconnected { last_failure: None };
        assert!(daemon_connect_failure_message(&bare, "corp").contains("did not complete"));

        // A non-terminal state also reads as "did not complete".
        let connecting = Connection::Connecting {
            profile_id: ProfileId::new("corp"),
            started_at: std::time::SystemTime::now(),
            attempt: 1,
            retry_budget_remaining: std::time::Duration::from_secs(30),
        };
        assert!(daemon_connect_failure_message(&connecting, "corp").contains("did not complete"));
    }

    #[test]
    fn registry_entries_omit_disconnected_and_report_empty() {
        let reg = RegistrySnapshot {
            tunnels: vec![TunnelSnapshot {
                profile_id: ProfileId::new("corp"),
                state: Connection::Disconnected { last_failure: None },
                role: Role::Primary {
                    allowed_ips: Vec::new(),
                },
                health: ConnectionHealth::Unknown,
                interface_name: None,
                started_at: None,
            }],
            primary: None,
            killswitch: KillSwitchState::Disabled,
        };
        let (connections, primary) = registry_status_entries(&reg, None);
        assert!(connections.is_empty());
        assert_eq!(primary, None);
    }
}
