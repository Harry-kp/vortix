//! CLI command handlers.
//!
//! Each handler operates headlessly via `VpnRuntime` (no TUI), produces
//! structured output via [`OutputMode`], and exits with semantic exit codes.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use serde::Serialize;
use zeroize::Zeroize;

use crate::cli::args::{BackgroundCommands, Commands};
use crate::cli::output::{
    err_not_found, err_permission_denied, print_background_diagnostics,
    print_background_unavailable, print_background_view, print_error_and_exit,
    print_stream_error_and_exit, print_success, CliError, ConnectionEntry, ConnectionHealthEntry,
    ExitCode, OutputMode,
};
use crate::config::AppConfig;
use crate::constants;
use crate::vortix_config::profile_store::{FsProfileStore, ProfileStore};
use crate::vpn_runtime::VpnRuntime;

/// Leaves the actor enough time to persist and publish a settled protocol
/// result after the protocol gate and its configured teardown budget.
const CONTROL_COMPLETION_GRACE_SECS: u64 = 5;

fn connect_operation_timeout_secs(
    explicit: Option<u64>,
    protocol: crate::state::Protocol,
    config: &AppConfig,
) -> u64 {
    explicit.unwrap_or_else(|| {
        let protocol_gate = match protocol {
            crate::state::Protocol::WireGuard => config.wireguard_handshake_timeout_secs,
            crate::state::Protocol::OpenVPN => config.connect_timeout,
        };
        protocol_gate
            .saturating_add(config.disconnect_timeout)
            .saturating_add(CONTROL_COMPLETION_GRACE_SECS)
    })
}

/// Prompt for a 2FA code on the controlling tty with masked echo (each
/// character is replaced by `*`). Returns `Err` when stdin is not a tty —
/// the connect path treats this as a hard failure and exits non-zero with
/// an actionable message naming the prompt kind. .
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

fn prompt_masked_otp(prompt: &str, expires_at_millis: u64) -> std::io::Result<String> {
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
        if crate::utils::boot_elapsed_millis().is_some_and(|now| now >= expires_at_millis) {
            println!();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "challenge expired",
            ));
        }
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
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
    settings: &crate::vortix_config::Settings,
    mode: OutputMode,
) -> i32 {
    match command {
        Commands::Setup { boot, yes } => handle_background_setup(boot, *yes, config_dir, mode),
        Commands::Background { command } => {
            handle_background(command, config_dir, &settings.diagnostics, mode)
        }
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
            operation,
        } => operation.as_deref().map_or_else(
            || {
                handle_status(
                    *watch, *interval, *brief, *no_daemon, config, config_dir, mode,
                )
            },
            |operation| handle_operation_status(operation, config_dir, mode),
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
        Commands::Import { file } => handle_import(file, config, config_dir, mode),
        Commands::Show { profile, raw } => handle_show(profile, *raw, config, config_dir, mode),
        Commands::Delete { profile, yes } => handle_delete(profile, *yes, config, config_dir, mode),
        Commands::Rename { old, new } => handle_rename(old, new, config, config_dir, mode),
        Commands::KillSwitch { mode: ks_mode } => {
            handle_killswitch(ks_mode.as_deref(), config, config_dir, mode)
        }
        Commands::ReleaseKillSwitch => {
            handle_release_killswitch(config, config_dir, mode);
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
        Commands::Daemon { socket } => {
            handle_daemon(socket.clone(), mode, config_dir, &settings.diagnostics)
        }
        Commands::Completions { shell } => {
            handle_completions(*shell);
            0
        }
    }
}

fn handle_background_setup(
    boot_profiles: &[String],
    confirmed: bool,
    config_dir: &Path,
    mode: OutputMode,
) -> i32 {
    let profiles = (!boot_profiles.is_empty()).then(|| {
        load_setup_profiles(config_dir).unwrap_or_else(|error| {
            print_error_and_exit(
                mode,
                "setup",
                CliError {
                    code: "profile_catalog_unavailable",
                    message: format!("Cannot inspect the authenticated profile catalog: {error}"),
                    hint: Some(
                        "Repair the profile catalog or wait for the other Vortix process, then retry; no boot intent was saved."
                            .into(),
                    ),
                },
                ExitCode::GeneralError,
            )
        })
    });
    for requested in boot_profiles {
        let profile = profiles
            .as_ref()
            .and_then(|profiles| profiles.get(requested))
            .unwrap_or_else(|| {
                print_error_and_exit(mode, "setup", err_not_found(requested), ExitCode::NotFound)
            });
        require_boot_eligible(profile, mode);
    }

    let mut preview = vec![
        "Runs persistent Vortix processes for live CLI/TUI sync, automatic drop recovery, boot connections, and continuous policy verification.".into(),
        "Uses a narrower privileged helper after one trusted package bootstrap; Standard mode keeps its existing root-assisted client boundary.".into(),
    ];
    if !boot_profiles.is_empty() {
        preview.push(format!(
            "Boot-eligible profiles checked (intent not persisted): {}",
            boot_profiles.join(", ")
        ));
    }
    if confirmed {
        return print_background_unavailable(mode, "setup").code();
    }
    preview.push(
        crate::background::BackgroundWorkflow::Setup
            .cancelled_preview()
            .into(),
    );
    print_background_view(
        mode,
        "setup",
        &crate::background::BackgroundCommandView::prepared(preview),
    );
    0
}

fn require_boot_eligible(profile: &crate::state::VpnProfile, mode: OutputMode) {
    let eligibility =
        crate::topology_policy::boot_eligibility_for_profile(profile).unwrap_or_else(|error| {
            print_error_and_exit(
                mode,
                "setup",
                CliError {
                    code: "boot_profile_unsupported",
                    message: format!("Cannot inspect boot profile '{}': {error}", profile.name),
                    hint: Some(
                        "Repair or replace the profile, then retry setup; no boot intent was saved."
                            .into(),
                    ),
                },
                ExitCode::GeneralError,
            )
        });
    let (code, message, hint) = match eligibility {
        crate::vortix_core::control::BootEligibility::Eligible => return,
        crate::vortix_core::control::BootEligibility::InteractiveCredentials => (
            "boot_profile_interactive",
            format!(
                "Profile '{}' depends on credentials (a password file, prompt, OTP, challenge, or key) and cannot connect unattended at boot",
                profile.name
            ),
            "Leave it out of --boot and connect it after login; no credential or boot intent was saved.",
        ),
        crate::vortix_core::control::BootEligibility::UnsupportedKeyProvider => (
            "boot_profile_unsupported",
            format!(
                "Profile '{}' uses external or unsupported key material that is not eligible for unattended boot",
                profile.name
            ),
            "Connect it after login or use a reviewed unencrypted inline key profile.",
        ),
    };
    print_error_and_exit(
        mode,
        "setup",
        CliError {
            code,
            message,
            hint: Some(hint.into()),
        },
        ExitCode::StateConflict,
    );
}

fn load_setup_profiles(
    config_dir: &Path,
) -> Result<
    std::collections::BTreeMap<String, crate::state::VpnProfile>,
    crate::vortix_config::profile_store::ProfileStoreError,
> {
    let profiles_dir = config_dir.join(constants::PROFILES_DIR_NAME);
    let store = FsProfileStore::new(profiles_dir.clone());
    store.list().map(|summaries| {
        summaries
            .into_iter()
            .map(|summary| {
                let protocol = match summary.protocol {
                    crate::vortix_core::profile::ProtocolKind::WireGuard => {
                        crate::state::Protocol::WireGuard
                    }
                    crate::vortix_core::profile::ProtocolKind::OpenVpn => {
                        crate::state::Protocol::OpenVPN
                    }
                };
                let profile = crate::state::VpnProfile {
                    id: summary.id,
                    name: summary.display_name.clone(),
                    protocol,
                    location: "Unknown".into(),
                    config_path: profiles_dir.join(summary.config_file),
                    last_used: summary.last_used,
                };
                (summary.display_name, profile)
            })
            .collect()
    })
}

fn handle_background(
    command: &BackgroundCommands,
    config_dir: &Path,
    settings: &crate::vortix_config::DiagnosticsSettings,
    mode: OutputMode,
) -> i32 {
    match command {
        BackgroundCommands::Status => {
            print_background_view(
                mode,
                "background status",
                &crate::background::BackgroundCommandView::prepared(vec![
                    crate::background::BackgroundWorkflow::Status
                        .cancelled_preview()
                        .into(),
                ]),
            );
            0
        }
        BackgroundCommands::Recover { yes } => {
            if *yes {
                return print_background_unavailable(mode, "background recover").code();
            }
            print_background_view(
                mode,
                "background recover",
                &crate::background::BackgroundCommandView::prepared(vec![
                    crate::background::BackgroundWorkflow::Recover
                        .cancelled_preview()
                        .into(),
                ]),
            );
            0
        }
        BackgroundCommands::Disable { yes } => {
            if *yes {
                return print_background_unavailable(mode, "background disable").code();
            }
            print_background_view(
                mode,
                "background disable",
                &crate::background::BackgroundCommandView::prepared(vec![
                    crate::background::BackgroundWorkflow::Disable
                        .cancelled_preview()
                        .into(),
                ]),
            );
            0
        }
        BackgroundCommands::Diagnostics { follow } => {
            handle_background_diagnostics(*follow, config_dir, settings, mode)
        }
    }
}

fn handle_background_diagnostics(
    follow: bool,
    config_dir: &Path,
    settings: &crate::vortix_config::DiagnosticsSettings,
    mode: OutputMode,
) -> i32 {
    let socket = crate::daemon::daemon_socket_path_override()
        .unwrap_or_else(crate::daemon::default_socket_path);
    if follow {
        let mut subscription = crate::daemon::client::subscribe_diagnostics(&socket)
            .unwrap_or_else(|error| background_diagnostics_error(mode, &error, true));
        let mut last_sequence = newest_diagnostic_sequence(subscription.initial()).unwrap_or(0);
        print_background_diagnostics(mode, subscription.initial(), true);
        loop {
            let view = match subscription.recv() {
                Ok(view) => view,
                Err(crate::daemon::client::ClientError::ResyncRequired { .. }) => {
                    subscription = reconnect_diagnostics(&socket)
                        .unwrap_or_else(|error| background_diagnostics_error(mode, &error, true));
                    subscription.initial().clone()
                }
                Err(error) => background_diagnostics_error(mode, &error, true),
            };
            if let Some(delta) = diagnostic_delta(view, &mut last_sequence) {
                print_background_diagnostics(mode, &delta, true);
            }
        }
    }

    let fallback = config_dir.join("control").join("diagnostics.json");
    let view = crate::background::load_diagnostics(
        &socket,
        &fallback,
        settings.fallback_snapshot,
        crate::daemon::diagnostics::unix_millis(),
    )
    .unwrap_or_else(|error| background_diagnostics_error(mode, &error, false));
    print_background_diagnostics(mode, &view, false);
    0
}

fn reconnect_diagnostics(
    socket: &Path,
) -> Result<crate::daemon::client::DiagnosticSubscription, crate::daemon::client::ClientError> {
    let mut last_error = None;
    for attempt in 0..3 {
        match crate::daemon::client::subscribe_diagnostics(socket) {
            Ok(subscription) => return Ok(subscription),
            Err(error) => last_error = Some(error),
        }
        std::thread::sleep(Duration::from_millis(50_u64 << attempt));
    }
    Err(last_error.expect("bounded reconnect always attempts at least once"))
}

fn newest_diagnostic_sequence(view: &crate::vortix_core::control::DiagnosticView) -> Option<u64> {
    view.snapshot.records.last().map(|record| record.sequence)
}

fn diagnostic_delta(
    mut view: crate::vortix_core::control::DiagnosticView,
    last_sequence: &mut u64,
) -> Option<crate::vortix_core::control::DiagnosticView> {
    let newest = newest_diagnostic_sequence(&view)?;
    if newest < *last_sequence {
        *last_sequence = 0;
    }
    view.snapshot
        .records
        .retain(|record| record.sequence > *last_sequence);
    *last_sequence = newest;
    (!view.snapshot.records.is_empty()).then_some(view)
}

fn background_diagnostics_error(
    mode: OutputMode,
    error: &crate::daemon::client::ClientError,
    stream: bool,
) -> ! {
    let cli_error = CliError {
        code: "diagnostics_unavailable",
        message: format!("Background diagnostics are unavailable: {error}"),
        hint: Some(
            "Run `vortix background status`; fallback diagnostics exist only after the passive service has published one."
                .into(),
        ),
    };
    if stream {
        print_stream_error_and_exit(
            mode,
            "background diagnostics",
            cli_error,
            ExitCode::GeneralError,
        )
    } else {
        print_error_and_exit(
            mode,
            "background diagnostics",
            cli_error,
            ExitCode::GeneralError,
        )
    }
}

/// `vortix audit` — per-process socket snapshot.
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

/// `vortix daemon` — run the bounded, read-only IPC candidate.
fn handle_daemon(
    socket_override: Option<std::path::PathBuf>,
    mode: OutputMode,
    config_directory: &Path,
    settings: &crate::vortix_config::DiagnosticsSettings,
) -> i32 {
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
        "vortix daemon: passive read-only candidate ready at {}. Set VORTIX_DAEMON_SOCKET to this path to use snapshot queries.",
        server.socket_path().display()
    );

    let fallback_path = if settings.fallback_snapshot {
        let diagnostic_directory = config_directory.join("control");
        if let Err(error) =
            crate::daemon::diagnostics::prepare_fallback_directory(&diagnostic_directory)
        {
            eprintln!("vortix daemon: failed to prepare diagnostics: {error}");
            return 1;
        }
        Some(diagnostic_directory.join("diagnostics.json"))
    } else {
        None
    };
    let diagnostics = match crate::daemon::diagnostics::DiagnosticHub::start_with_stale_after(
        fallback_path,
        std::time::Duration::from_secs(settings.stale_after_secs.clamp(1, 86_400)),
    ) {
        Ok(diagnostics) => std::sync::Arc::new(diagnostics),
        Err(error) => {
            eprintln!("vortix daemon: failed to start diagnostics: {error}");
            return 1;
        }
    };
    // The candidate is deliberately passive: it polls scanner truth for
    // queries/subscriptions but never constructs an engine, loads desired
    // intent, acquires lifecycle authority, or exposes mutation capability.
    // Its typed observation transitions feed the same bounded diagnostics
    // provider served over IPC; raw scanner data never enters that provider.
    let diagnostic_sink: std::sync::Arc<dyn crate::daemon::passive::PassiveDiagnosticSink> =
        diagnostics.clone();
    let provider = match crate::daemon::passive::ScannerQueryProvider::start_with_diagnostics(
        crate::vpn::load_profiles(),
        std::time::Duration::from_secs(1),
        Some(diagnostic_sink),
    ) {
        Ok(provider) => std::sync::Arc::new(provider),
        Err(error) => {
            eprintln!("vortix daemon: failed to start passive observer: {error}");
            return 1;
        }
    };
    let server = server
        .with_query_provider(provider)
        .with_diagnostic_provider(diagnostics);

    runtime.block_on(async {
        if let Err(e) = server.run().await {
            eprintln!("vortix daemon: accept loop terminated: {e}");
        }
    });

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
    timeout_secs: Option<u64>,
    yes: bool,
    config: &AppConfig,
    config_dir: &Path,
    mode: OutputMode,
) -> i32 {
    // `--yes` explicitly bypasses the shared route-conflict admission check.
    let _lifecycle_lock = acquire_lifecycle_lock_or_exit(mode, "up");
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
    // legacy inline CLI check used to skip.
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

    // route the CLI connect through the
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

    let target = engine
        .profiles
        .iter()
        .find(|profile| profile.name == profile_name)
        .cloned()
        .unwrap_or_else(|| {
            print_error_and_exit(mode, "up", err_not_found(&profile_name), ExitCode::NotFound)
        });
    let timeout_secs = connect_operation_timeout_secs(timeout_secs, target.protocol, config);
    let control = crate::cli::control::ClientControlSession::start_production(
        config,
        config_dir,
        engine.profiles.clone(),
    )
    .unwrap_or_else(|error| local_control_error_or_exit(mode, "up", &error));
    if control.is_canonically_owned_active(&target.id) {
        let data = UpData {
            state: "connected".into(),
            profile: target.name.clone(),
            protocol: target.protocol.to_string(),
        };
        match mode {
            OutputMode::Human => println!(
                "● Already connected to {} ({})",
                target.name, target.protocol
            ),
            OutputMode::Json => print_success(
                mode,
                "up",
                &data,
                vec![
                    "vortix status --json".into(),
                    "sudo vortix down --json".into(),
                ],
            ),
            OutputMode::Quiet => {}
        }
        return 0;
    }
    let command = crate::vortix_core::control::UserCommand::Connect {
        profile_id: target.id.clone(),
        conflict_acknowledgement: None,
    };
    control
        .validate(&command)
        .unwrap_or_else(|error| local_control_error_or_exit(mode, "up", &error));

    validate_openvpn_static_challenge_credentials(&target)
        .unwrap_or_else(|(error, exit)| print_error_and_exit(mode, "up", error, exit));

    let challenge_profiles = engine.profiles.clone();
    let result = control.run_with_challenges(
        command,
        Duration::from_secs(timeout_secs),
        local_idempotency_key("up", Some(&target.id)),
        move |challenge| answer_openvpn_static_challenge(challenge, &challenge_profiles),
    );

    match result {
        Ok(result) if result.status == crate::vortix_core::control::OperationStatus::Succeeded => {
            let _ = FsProfileStore::new(config_dir.join(constants::PROFILES_DIR_NAME))
                .touch(&target.id);
            let data = UpData {
                state: "connected".into(),
                profile: target.name.clone(),
                protocol: target.protocol.to_string(),
            };
            let next = vec![
                "vortix status --json".into(),
                format!("sudo vortix down --json"),
            ];

            match mode {
                OutputMode::Human => {
                    println!("● Connected to {} ({})", target.name, target.protocol);
                }
                OutputMode::Json => print_success(mode, "up", &data, next),
                OutputMode::Quiet => {}
            }
            0
        }
        Ok(result) => {
            let (code, exit, err_msg) = operation_failure("connect", &result);
            print_error_and_exit(
                mode,
                "up",
                CliError {
                    code,
                    message: err_msg,
                    hint: None,
                },
                exit,
            );
        }
        Err(error) => local_control_error_or_exit(mode, "up", &error),
    }
}

/// Detect a multi-tunnel conflict for the CLI's `up` path.
///
/// The CLI doesn't share an in-memory `TunnelRegistry` with the running
/// session — active tunnels are discovered via
/// `scanner::get_active_profiles`. We inspect each active session's parsed
/// config and use the **shared** `vortix_core::cidr` and
/// `claims_default_route_*` helpers (same logic the TUI's
/// `TunnelRegistry::detect_conflict` uses) so the two surfaces refuse the
/// same set of takeovers. The route-overlap branch is a CLI-only
/// superset until a follow-up brings route-overlap detection into the
/// registry.
/// Acquire the cross-process lifecycle lock or exit with a structured
/// error. Proceeding without the lock would reintroduce the concurrent
/// `up`/`down` interleaving the lock exists to prevent.
fn acquire_lifecycle_lock_or_exit(mode: OutputMode, command: &str) -> crate::utils::LifecycleLock {
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

fn local_idempotency_key(
    command: &str,
    profile_id: Option<&crate::vortix_core::profile::ProfileId>,
) -> String {
    let profile = profile_id.map_or("all", crate::vortix_core::profile::ProfileId::as_str);
    let nonce = crate::utils::boot_elapsed_millis().unwrap_or_default();
    format!("cli-{command}-{profile}-{}-{nonce}", std::process::id())
}

fn local_control_error_or_exit(
    mode: OutputMode,
    command: &str,
    error: &crate::cli::control::LocalControlError,
) -> ! {
    let (code, exit) = local_control_error_category(error);
    print_error_and_exit(
        mode,
        command,
        CliError {
            code,
            message: error.to_string(),
            hint: None,
        },
        exit,
    )
}

fn local_control_error_category(
    error: &crate::cli::control::LocalControlError,
) -> (&'static str, ExitCode) {
    match error {
        crate::cli::control::LocalControlError::Admission(
            crate::vortix_core::control::AdmissionError::RouteConflict,
        )
        | crate::cli::control::LocalControlError::Remote(
            crate::daemon::service::RemoteControlError::Admission(
                crate::vortix_core::control::AdmissionError::RouteConflict,
            ),
        ) => ("state_conflict_route_overlap", ExitCode::StateConflict),
        crate::cli::control::LocalControlError::Admission(
            crate::vortix_core::control::AdmissionError::DeadlineExpired,
        )
        | crate::cli::control::LocalControlError::Remote(
            crate::daemon::service::RemoteControlError::Admission(
                crate::vortix_core::control::AdmissionError::DeadlineExpired,
            )
            | crate::daemon::service::RemoteControlError::Challenge(
                crate::vortix_core::control::ChallengeError::Expired,
            ),
        )
        | crate::cli::control::LocalControlError::ChallengeExpired => {
            ("timeout", ExitCode::Timeout)
        }
        crate::cli::control::LocalControlError::Ownership(_)
        | crate::cli::control::LocalControlError::Owner(_) => {
            ("permission_denied", ExitCode::PermissionDenied)
        }
        crate::cli::control::LocalControlError::ChallengeCancelled
        | crate::cli::control::LocalControlError::Remote(
            crate::daemon::service::RemoteControlError::Challenge(
                crate::vortix_core::control::ChallengeError::Cancelled,
            ),
        ) => ("user_cancelled", ExitCode::GeneralError),
        crate::cli::control::LocalControlError::ChallengeNonInteractive { .. }
        | crate::cli::control::LocalControlError::ChallengeEmpty { .. } => {
            ("auth_required", ExitCode::GeneralError)
        }
        _ => ("control_failed", ExitCode::GeneralError),
    }
}

fn operation_failure(
    action: &str,
    outcome: &crate::cli::control::ClientOperationOutcome,
) -> (&'static str, ExitCode, String) {
    use crate::vortix_core::control::{OperationFailure, OperationResult, OperationStatus};

    let operation = &outcome.operation_id;
    match (outcome.status, outcome.result.as_ref()) {
        (_, Some(OperationResult::ProfileMutationAppliedAfterDeadline)) => (
            "completed_after_deadline",
            ExitCode::Timeout,
            format!(
                "{action} completed after its deadline; operation {operation} was applied and must not be retried"
            ),
        ),
        (OperationStatus::Expired, _)
        | (
            _,
            Some(OperationResult::Expired | OperationResult::Failed(OperationFailure::Timeout)),
        ) => (
            "timeout",
            ExitCode::Timeout,
            format!(
                "{action} timed out; operation {operation} remains recorded for reconciliation"
            ),
        ),
        (_, Some(OperationResult::Failed(OperationFailure::HandshakeFailed))) => (
            "connect_failed",
            ExitCode::GeneralError,
            format!("WireGuard handshake failed for operation {operation}"),
        ),
        (OperationStatus::Cancelled, _) | (_, Some(OperationResult::Cancelled)) => (
            "user_cancelled",
            ExitCode::GeneralError,
            format!("{action} operation {operation} was cancelled"),
        ),
        _ => (
            if action == "disconnect" {
                "disconnect_failed"
            } else {
                "connect_failed"
            },
            ExitCode::GeneralError,
            format!("{action} operation {operation} failed"),
        ),
    }
}

fn detect_conflict_for_cli(
    engine: &VpnRuntime,
    target_name: &str,
) -> Option<crate::vortix_core::engine::Conflict> {
    use crate::vortix_core::cidr::{
        claims_default_route_v4, claims_default_route_v6, overlapping_cidrs,
    };
    use crate::vortix_core::engine::Conflict;
    let target_profile = engine.profiles.iter().find(|p| p.name == target_name)?;
    let target_allowed = crate::topology_policy::declared_routes(
        target_profile.protocol,
        &target_profile.config_path,
    );
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
        let active_allowed = crate::topology_policy::declared_routes(
            active_profile.protocol,
            &active_profile.config_path,
        );
        let active_claims_default =
            claims_default_route_v4(&active_allowed) || claims_default_route_v6(&active_allowed);

        if target_claims_default && active_claims_default {
            return Some(Conflict::DefaultRouteTakeover {
                current: active_profile.id.clone(),
                new: target_profile.id.clone(),
            });
        }
        let overlap = overlapping_cidrs(&target_allowed, &active_allowed);
        if !overlap.is_empty() {
            return Some(Conflict::RouteOverlap {
                with: active_profile.id.clone(),
                overlapping_cidrs: overlap,
            });
        }
    }
    None
}

fn validate_openvpn_static_challenge_credentials(
    profile: &crate::state::VpnProfile,
) -> Result<(), (CliError, ExitCode)> {
    let Some(prompt_text) =
        crate::utils::read_openvpn_static_challenge_prompt(&profile.config_path)
    else {
        return Ok(());
    };
    let Some((mut user, mut pass)) =
        crate::utils::read_openvpn_saved_auth_compat(profile.id.as_str(), &profile.name)
    else {
        return Err((
            CliError {
                code: "auth_required",
                message: format!(
                    "Profile '{}' requires 2FA ('{prompt_text}'). Save username/password first \
                     via the TUI (Auth Manager), then re-run; the OTP will be prompted at each \
                     connect.",
                    profile.name
                ),
                hint: Some("Open the TUI and use Auth Manager to save credentials.".into()),
            },
            ExitCode::PermissionDenied,
        ));
    };
    user.zeroize();
    pass.zeroize();
    Ok(())
}

fn answer_openvpn_static_challenge(
    challenge: &crate::vortix_core::control::ChallengeRecord,
    profiles: &[crate::state::VpnProfile],
) -> Result<crate::vortix_core::control::Secret, crate::cli::control::LocalControlError> {
    let profile_name = profiles
        .iter()
        .find(|profile| profile.id == challenge.profile_id)
        .map_or_else(
            || challenge.profile_id.to_string(),
            |profile| profile.name.clone(),
        );
    match prompt_masked_otp(&challenge.label, challenge.expires_at_millis) {
        Ok(otp) if !otp.is_empty() => {
            Ok(crate::vortix_core::control::Secret::new(otp.into_bytes()))
        }
        Ok(_) => Err(crate::cli::control::LocalControlError::ChallengeEmpty {
            profile: profile_name,
        }),
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
            Err(crate::cli::control::LocalControlError::ChallengeCancelled)
        }
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
            Err(crate::cli::control::LocalControlError::ChallengeExpired)
        }
        Err(_) => Err(
            crate::cli::control::LocalControlError::ChallengeNonInteractive {
                profile: profile_name,
            },
        ),
    }
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
    let _lifecycle_lock = acquire_lifecycle_lock_or_exit(mode, "down");
    let engine = VpnRuntime::new_headless(config.clone(), config_dir.to_path_buf());

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

    let requested_profiles = profile_filter
        .and_then(|name| engine.profiles.iter().find(|profile| profile.name == name))
        .map(|profile| BTreeSet::from([profile.id.clone()]))
        .unwrap_or_default();
    let durable_disconnect_required = if targets.is_empty() {
        crate::cli::control::durable_disconnect_required(config_dir, &requested_profiles)
            .unwrap_or_else(|error| local_control_error_or_exit(mode, "down", &error))
    } else {
        false
    };

    if targets.is_empty() && !durable_disconnect_required {
        // Idempotent: already disconnected = success. Matches the
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

    if !engine.is_root {
        print_error_and_exit(
            mode,
            "down",
            err_permission_denied("vortix down"),
            ExitCode::PermissionDenied,
        );
    }

    let profile_id = profile_filter.and_then(|name| {
        engine
            .profiles
            .iter()
            .find(|profile| profile.name == name)
            .map(|profile| profile.id.clone())
    });
    let control = crate::cli::control::ClientControlSession::start_production(
        config,
        config_dir,
        engine.profiles.clone(),
    )
    .unwrap_or_else(|error| local_control_error_or_exit(mode, "down", &error));
    let command = if force {
        crate::vortix_core::control::UserCommand::ForceDisconnect {
            profile_id: profile_id.clone(),
        }
    } else {
        crate::vortix_core::control::UserCommand::Disconnect {
            profile_id: profile_id.clone(),
        }
    };
    let result = control.run(
        command,
        Duration::from_secs(config.disconnect_timeout),
        local_idempotency_key("down", profile_id.as_ref()),
    );
    let outcome = result.unwrap_or_else(|error| local_control_error_or_exit(mode, "down", &error));
    if outcome.status != crate::vortix_core::control::OperationStatus::Succeeded {
        let (code, exit, message) = operation_failure("disconnect", &outcome);
        print_error_and_exit(
            mode,
            "down",
            CliError {
                code,
                message,
                hint: if force {
                    None
                } else {
                    Some("Try: sudo vortix down --force".into())
                },
            },
            exit,
        );
    }

    let disconnected = targets
        .iter()
        .map(|session| session.name.clone())
        .collect::<Vec<_>>();

    let data = DownData {
        state: "disconnected".into(),
        disconnected: disconnected.clone(),
    };
    match mode {
        OutputMode::Human => {
            if disconnected.is_empty() {
                println!("Already disconnected");
            } else if disconnected.len() == 1 {
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
    0
}

#[allow(clippy::too_many_lines)]
fn handle_reconnect(
    profile_filter: Option<&str>,
    config: &AppConfig,
    config_dir: &Path,
    mode: OutputMode,
) -> i32 {
    let _lifecycle_lock = acquire_lifecycle_lock_or_exit(mode, "reconnect");
    let mut engine = VpnRuntime::new_headless(config.clone(), config_dir.to_path_buf());
    engine.load_metadata();

    // Validate the requested profile exists in the catalog before we
    // poke the system. NotFound (exit 3) > "no active" idempotency.
    if let Some(name) = profile_filter {
        if engine.find_profile(name).is_none() {
            print_error_and_exit(mode, "reconnect", err_not_found(name), ExitCode::NotFound);
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

    if !engine.is_root {
        print_error_and_exit(
            mode,
            "reconnect",
            err_permission_denied("vortix reconnect"),
            ExitCode::PermissionDenied,
        );
    }
    for name in &to_cycle {
        let profile = engine
            .profiles
            .iter()
            .find(|profile| &profile.name == name)
            .expect("reconnect targets were resolved from the profile catalog");
        let missing = VpnRuntime::check_dependencies(profile.protocol, &profile.config_path);
        if !missing.is_empty() {
            print_error_and_exit(
                mode,
                "reconnect",
                CliError {
                    code: "dependency_missing",
                    message: format!("Missing dependencies: {}", missing.join(", ")),
                    hint: None,
                },
                ExitCode::DependencyMissing,
            );
        }
    }

    let requested_id = profile_filter.and_then(|name| {
        engine
            .profiles
            .iter()
            .find(|profile| profile.name == name)
            .map(|profile| profile.id.clone())
    });
    let fallback_id = (active.is_empty() && requested_id.is_none()).then(|| {
        engine
            .profiles
            .iter()
            .find(|profile| profile.name == to_cycle[0])
            .expect("last-used reconnect target exists")
            .id
            .clone()
    });
    let target_id = requested_id.or(fallback_id);
    let control = crate::cli::control::ClientControlSession::start_production(
        config,
        config_dir,
        engine.profiles.clone(),
    )
    .unwrap_or_else(|error| local_control_error_or_exit(mode, "reconnect", &error));
    let command = crate::vortix_core::control::UserCommand::Reconnect {
        profile_id: target_id.clone(),
    };
    control
        .validate(&command)
        .unwrap_or_else(|error| local_control_error_or_exit(mode, "reconnect", &error));
    for name in &to_cycle {
        let profile = engine
            .profiles
            .iter()
            .find(|profile| &profile.name == name)
            .expect("reconnect target exists");
        validate_openvpn_static_challenge_credentials(profile)
            .unwrap_or_else(|(error, exit)| print_error_and_exit(mode, "reconnect", error, exit));
    }
    let challenge_profiles = engine.profiles.clone();
    let result = control.run_with_challenges(
        command,
        Duration::from_secs(
            config
                .connect_timeout
                .saturating_add(config.disconnect_timeout),
        ),
        local_idempotency_key("reconnect", target_id.as_ref()),
        move |challenge| answer_openvpn_static_challenge(challenge, &challenge_profiles),
    );
    let outcome =
        result.unwrap_or_else(|error| local_control_error_or_exit(mode, "reconnect", &error));
    if outcome.status != crate::vortix_core::control::OperationStatus::Succeeded {
        let (code, exit, message) = operation_failure("reconnect", &outcome);
        print_error_and_exit(
            mode,
            "reconnect",
            CliError {
                code,
                message,
                hint: None,
            },
            exit,
        );
    }

    for name in &to_cycle {
        let profile = engine
            .profiles
            .iter()
            .find(|profile| &profile.name == name)
            .expect("reconnect target exists");
        let _ =
            FsProfileStore::new(config_dir.join(constants::PROFILES_DIR_NAME)).touch(&profile.id);
        let data = UpData {
            state: "connected".into(),
            profile: profile.name.clone(),
            protocol: profile.protocol.to_string(),
        };
        match mode {
            OutputMode::Human => println!("● Connected to {} ({})", profile.name, profile.protocol),
            OutputMode::Json => print_success(
                mode,
                "up",
                &data,
                vec![
                    "vortix status --json".into(),
                    "sudo vortix down --json".into(),
                ],
            ),
            OutputMode::Quiet => {}
        }
    }
    0
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
/// A follow-up will replace the transitional single-entry construction below
/// with a registry-driven snapshot; this stage's job is just to make the v2
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
    // scanner reads. The `--no-daemon` flag forces the
    // bypass even when the daemon is up — useful for testing.
    let daemon_socket = if no_daemon {
        None
    } else {
        crate::daemon::daemon_socket_path_if_present()
    };

    let engine = VpnRuntime::new_headless(config.clone(), config_dir.to_path_buf());
    let snap = engine.scan_status();
    // The candidate is shadow-only: compare its passive observation with the
    // local scanner but never let it override local control or status truth.
    // Any error or rollout mismatch leaves user-visible output unchanged.
    if let Some(socket) = daemon_socket {
        if let Ok(crate::vortix_core::ipc::IpcResult::PassiveSnapshot { snapshot }) =
            crate::daemon::client::request(&socket, crate::vortix_core::ipc::IpcOp::PassiveSnapshot)
        {
            if !passive_projection_matches(&snap, &snapshot) {
                tracing::debug!(
                    local_state = %snap.connection_state,
                    local_profile = ?snap.profile,
                    local_interface = ?snap.interface,
                    remote_generation = snapshot.generation,
                    remote_tunnels = snapshot.tunnels.len(),
                    "passive daemon shadow projection differs from local scanner"
                );
            }
        }
    }

    let is_connected = snap.connection_state == "connected";
    let is_present = snap.connection_state != "disconnected";

    // Transitional shape: the registry-driven multi-tunnel snapshot
    // lands later. Until then, "primary" is the single active tunnel
    // (when connected), and `connections` is a one-element vec mirroring
    // it. When disconnected, `connections` is empty and `primary` /
    // `connection` are both `null`.
    let visible_entry = if is_present {
        Some(ConnectionEntry {
            state: snap.connection_state.clone(),
            profile: snap.profile.clone(),
            protocol: snap.protocol.clone(),
            uptime_secs: snap.uptime_secs,
            health: snap.health.as_ref().map(connection_health_entry),
            generation: snap.generation,
        })
    } else {
        None
    };
    let connections: Vec<ConnectionEntry> = visible_entry.iter().cloned().collect();
    let primary: Option<String> = if is_connected {
        snap.profile.clone()
    } else {
        None
    };

    let data = StatusData {
        connections,
        primary,
        connection: if is_connected {
            visible_entry.clone()
        } else {
            None
        },
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
                println!("{}", human_status_headline(&snap));
            } else if is_connected {
                let profile = snap.profile.as_deref().unwrap_or("unknown");
                let protocol = snap.protocol.as_deref().unwrap_or("");
                println!("● Connected to {profile} ({protocol})");
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
                if let Some(health) = &snap.health {
                    println!("  Health       {}", connection_health_human(health));
                }
            } else {
                println!("{}", human_status_headline(&snap));
                println!();
                println!(
                    "  Kill Switch  {} ({})",
                    snap.killswitch_mode.display_name(),
                    snap.killswitch_state.display_status()
                );
            }
        }
        OutputMode::Json => {
            let next = if is_present {
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
    ExitCode::Success.code()
}

#[derive(Serialize)]
struct OperationStatusData {
    id: crate::vortix_core::control::OperationId,
    status: crate::vortix_core::control::OperationStatus,
    result: Option<crate::vortix_core::control::OperationResult>,
    desired_generation: u64,
}

fn handle_operation_status(operation: &str, config_dir: &Path, mode: OutputMode) -> i32 {
    let Some(operation_id) = crate::vortix_core::control::OperationId::parse(operation) else {
        print_error_and_exit(
            mode,
            "status",
            CliError {
                code: "invalid_operation",
                message: format!("Invalid Vortix operation ID: {operation}"),
                hint: Some("Use the exact operation ID printed by the timed-out command.".into()),
            },
            ExitCode::GeneralError,
        );
    };
    let (uid, gid) = crate::cli::control::config_owner(config_dir)
        .unwrap_or_else(|error| local_control_error_or_exit(mode, "status", &error));
    let boot_id = crate::utils::boot_identity().unwrap_or_else(|| {
        print_error_and_exit(
            mode,
            "status",
            CliError {
                code: "control_failed",
                message: "OS boot identity is unavailable".into(),
                hint: None,
            },
            ExitCode::GeneralError,
        )
    });
    let store = crate::vortix_config::control_state::FsControlStateStore::for_owner(
        config_dir.join("control"),
        uid,
        gid,
    );
    let record = store
        .operation(&boot_id, &operation_id)
        .unwrap_or_else(|error| {
            print_error_and_exit(
                mode,
                "status",
                CliError {
                    code: "control_failed",
                    message: format!("Could not read durable operation state: {error}"),
                    hint: None,
                },
                ExitCode::GeneralError,
            )
        })
        .unwrap_or_else(|| {
            print_error_and_exit(
                mode,
                "status",
                CliError {
                    code: "operation_not_found",
                    message: format!("Operation {operation_id} was not found"),
                    hint: None,
                },
                ExitCode::NotFound,
            )
        });
    let data = OperationStatusData {
        id: record.id,
        status: record.status,
        result: record.result,
        desired_generation: record.desired_generation,
    };
    match mode {
        OutputMode::Human => println!("Operation {}: {}", data.id, data.status.as_str()),
        OutputMode::Json => print_success(mode, "status", &data, Vec::new()),
        OutputMode::Quiet => {}
    }
    0
}

fn passive_projection_matches(
    local: &crate::vpn_runtime::connection::StatusSnapshot,
    remote: &crate::vortix_core::ipc::PassiveSnapshot,
) -> bool {
    if local.connection_state == "disconnected" {
        return remote.tunnels.is_empty();
    }
    remote.tunnels.iter().any(|tunnel| {
        local.profile.as_deref() == Some(tunnel.display_name.as_str())
            && local
                .interface
                .as_deref()
                .is_none_or(|name| name == tunnel.interface_name)
    })
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
                    #[serde(skip_serializing_if = "Option::is_none")]
                    health: Option<ConnectionHealthEntry>,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    generation: Option<u64>,
                }
                let line = WatchLine {
                    ts: chrono_now(),
                    state: snap.connection_state,
                    profile: snap.profile,
                    uptime_secs: snap.uptime_secs,
                    health: snap.health.as_ref().map(connection_health_entry),
                    generation: snap.generation,
                };
                println!("{}", serde_json::to_string(&line).unwrap_or_default());
            }
            OutputMode::Human => {
                use std::io::Write;
                if snap.connection_state == "connected" {
                    print!("\r{}", human_status_headline(&snap));
                    if let Some(up) = snap.uptime_secs {
                        let m = up / 60;
                        let s = up % 60;
                        print!(" ({m}m{s}s)");
                    }
                    print!("    ");
                } else {
                    print!("\r{}    ", human_status_headline(&snap));
                }
                let _ = std::io::stdout().flush();
            }
            OutputMode::Quiet => {}
        }

        std::thread::sleep(Duration::from_secs(interval));
    }
}

fn human_status_headline(snap: &crate::vpn_runtime::connection::StatusSnapshot) -> String {
    let profile = snap.profile.as_deref().unwrap_or("unknown");
    let protocol = snap.protocol.as_deref().unwrap_or("");
    match snap.connection_state.as_str() {
        "connected" => snap.health.as_ref().map_or_else(
            || format!("● Connected to {profile} ({protocol})"),
            |health| match health {
                crate::vortix_core::engine::state::ConnectionHealth::Degraded { .. } => format!(
                    "⚠ Connected to {profile} ({protocol}) — {}",
                    connection_health_human(health)
                ),
                _ => format!("● Connected to {profile} ({protocol})"),
            },
        ),
        "handshaking" => format!("◐ Handshaking with {profile} (WireGuard)"),
        "connecting" => format!("◐ Connecting to {profile} (OpenVPN)"),
        "reconnecting" => format!("↻ Reconnecting to {profile} ({protocol})"),
        "disconnecting" => format!("◑ Disconnecting {profile} ({protocol})"),
        "awaiting_input" => format!("? Awaiting input for {profile} ({protocol})"),
        _ => "○ Disconnected".to_string(),
    }
}

fn connection_health_entry(
    health: &crate::vortix_core::engine::state::ConnectionHealth,
) -> ConnectionHealthEntry {
    use crate::vortix_core::engine::state::ConnectionHealth;
    match health {
        ConnectionHealth::Unknown => ConnectionHealthEntry {
            status: "unknown".into(),
            reason: None,
        },
        ConnectionHealth::Healthy => ConnectionHealthEntry {
            status: "healthy".into(),
            reason: None,
        },
        ConnectionHealth::Degraded { reason } => ConnectionHealthEntry {
            status: "degraded".into(),
            reason: Some(degraded_reason_human(reason)),
        },
    }
}

fn connection_health_human(health: &crate::vortix_core::engine::state::ConnectionHealth) -> String {
    use crate::vortix_core::engine::state::ConnectionHealth;
    match health {
        ConnectionHealth::Unknown => "Unknown (measuring)".into(),
        ConnectionHealth::Healthy => "Healthy".into(),
        ConnectionHealth::Degraded { reason } => {
            format!("Degraded: {}", degraded_reason_human(reason))
        }
    }
}

fn degraded_reason_human(reason: &crate::vortix_core::engine::state::DegradedReason) -> String {
    use crate::vortix_core::engine::state::DegradedReason;
    match reason {
        DegradedReason::HandshakeStale {
            seconds_since_last_handshake,
        } => format!("handshake stale for {seconds_since_last_handshake}s"),
        DegradedReason::WireGuardPeerStale {
            peer_public_key,
            allowed_routes,
            seconds_since_last_handshake,
        } => format!(
            "peer {} stale for {}s on {}",
            short_peer(peer_public_key),
            seconds_since_last_handshake,
            allowed_routes.join(",")
        ),
        DegradedReason::WireGuardPeerNeverObserved {
            peer_public_key,
            allowed_routes,
        } => format!(
            "peer {} has no handshake on {}",
            short_peer(peer_public_key),
            allowed_routes.join(",")
        ),
        DegradedReason::HighPacketLoss { loss_percent } => {
            format!("{loss_percent:.1}% packet loss")
        }
        DegradedReason::HighLatency { latency_ms } => format!("{latency_ms}ms latency"),
    }
}

fn short_peer(peer: &str) -> &str {
    peer.get(..peer.len().min(8)).unwrap_or(peer)
}

#[cfg(test)]
mod handshake_status_tests {
    use super::*;
    use crate::state::{KillSwitchMode, KillSwitchState};
    use crate::vortix_core::ipc::{PassiveSnapshot, PassiveTunnel};
    use crate::vortix_core::profile::ProfileId;

    fn snapshot(state: &str, protocol: &str) -> crate::vpn_runtime::connection::StatusSnapshot {
        crate::vpn_runtime::connection::StatusSnapshot {
            connection_state: state.into(),
            health: None,
            generation: None,
            profile: Some("corp".into()),
            protocol: Some(protocol.into()),
            uptime_secs: None,
            public_ip: None,
            server: None,
            interface: None,
            internal_ip: None,
            latency_ms: None,
            jitter_ms: None,
            packet_loss_pct: None,
            quality: None,
            download_bytes: None,
            upload_bytes: None,
            killswitch_mode: KillSwitchMode::Off,
            killswitch_state: KillSwitchState::Disabled,
            dns_leak: None,
            encryption: None,
            location: None,
            isp: None,
        }
    }

    #[test]
    fn human_and_watch_headline_distinguish_wireguard_from_openvpn() {
        assert_eq!(
            human_status_headline(&snapshot("handshaking", "WireGuard")),
            "◐ Handshaking with corp (WireGuard)"
        );
        assert_eq!(
            human_status_headline(&snapshot("connecting", "OpenVPN")),
            "◐ Connecting to corp (OpenVPN)"
        );
    }

    #[test]
    fn human_projection_preserves_typed_health_generation() {
        let degraded = crate::vortix_core::engine::state::ConnectionHealth::Degraded {
            reason: crate::vortix_core::engine::state::DegradedReason::WireGuardPeerStale {
                peer_public_key: "peer-public-key".into(),
                allowed_routes: vec!["10.0.0.0/24".into()],
                seconds_since_last_handshake: 181,
            },
        };
        let mut snap = snapshot("connected", "WireGuard");
        snap.health = Some(degraded.clone());
        snap.generation = Some(7);
        assert!(human_status_headline(&snap).contains("stale for 181s"));
        let projected = connection_health_entry(snap.health.as_ref().unwrap());
        assert_eq!(projected.status, "degraded");
        assert!(projected.reason.unwrap().contains("peer-pub"));
        snap.health = Some(crate::vortix_core::engine::state::ConnectionHealth::Healthy);
        assert_eq!(
            connection_health_entry(snap.health.as_ref().unwrap()).status,
            "healthy"
        );
    }

    #[test]
    fn passive_shadow_comparison_never_requires_authority() {
        let tunnel = PassiveTunnel {
            profile_id: ProfileId::new("corp"),
            display_name: "corp".into(),
            protocol: crate::vortix_core::profile::ProtocolKind::WireGuard,
            interface_name: "wg0".into(),
            observed_at_millis: 1,
        };
        let remote = PassiveSnapshot {
            generation: 1,
            observed_at_millis: 1,
            tunnels: vec![tunnel],
            authoritative: false,
        };
        let mut local = snapshot("connected", "WireGuard");
        local.interface = Some("wg0".into());
        assert!(passive_projection_matches(&local, &remote));
        local.interface = Some("wg1".into());
        assert!(!passive_projection_matches(&local, &remote));
    }

    #[test]
    fn json_v2_adds_handshaking_without_claiming_a_primary() {
        let entry = ConnectionEntry {
            state: "handshaking".into(),
            profile: Some("corp".into()),
            protocol: Some("WireGuard".into()),
            uptime_secs: None,
            health: None,
            generation: None,
        };
        let data = StatusData {
            connections: vec![entry],
            primary: None,
            connection: None,
            network: None,
            security: StatusSecurity {
                killswitch_mode: "off".into(),
                killswitch_state: "disabled".into(),
            },
        };
        let value = serde_json::to_value(data).unwrap();
        assert_eq!(value["connections"][0]["state"], "handshaking");
        assert!(value["primary"].is_null());
        assert!(value["connection"].is_null());
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
    /// Stable profile ID from the `.meta.toml` sidecar.
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
    // stable profile_id + group label. The lookup is
    // O(N + M) which is fine for the typical handful of profiles.
    let sidecars_by_name: std::collections::HashMap<String, _> = {
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
            id: crate::vortix_core::profile::ProfileId::new(name),
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

fn handle_import(file: &str, config: &AppConfig, config_dir: &Path, mode: OutputMode) -> i32 {
    use crate::core::importer::{resolve_target, ImportTarget};

    match resolve_target(file) {
        Ok(ImportTarget::Url(url)) => {
            if matches!(mode, OutputMode::Human) {
                println!("Downloading...");
            }
            match crate::core::downloader::download_profile(&url) {
                Ok(downloaded_path) => {
                    let _lifecycle_lock = acquire_lifecycle_lock_or_exit(mode, "import");
                    let result = import_profile_via_control(&downloaded_path, config, config_dir);
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
        Ok(ImportTarget::File(path)) => {
            let _lifecycle_lock = acquire_lifecycle_lock_or_exit(mode, "import");
            match import_profile_via_control(&path, config, config_dir) {
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
        Ok(ImportTarget::Directory(path)) => {
            let _lifecycle_lock = acquire_lifecycle_lock_or_exit(mode, "import");
            import_from_directory(&path, config, config_dir, mode)
        }
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

fn import_profile_via_control(
    path: &Path,
    config: &AppConfig,
    config_dir: &Path,
) -> Result<crate::state::VpnProfile, String> {
    let profiles_dir = config_dir.join(constants::PROFILES_DIR_NAME);
    let engine = VpnRuntime::new_headless(config.clone(), config_dir.to_path_buf());
    let (control, profile_id) =
        crate::cli::control::ClientControlSession::start_production_profile_import(
            config_dir,
            &engine.profiles,
            path,
        )
        .map_err(|error| error.to_string())?;
    let outcome = control
        .run(
            crate::vortix_core::control::UserCommand::ImportProfile {
                profile_id: profile_id.clone(),
            },
            Duration::from_secs(5),
            local_idempotency_key("import", Some(&profile_id)),
        )
        .map_err(|error| error.to_string())?;
    if outcome.status != crate::vortix_core::control::OperationStatus::Succeeded {
        return Err(operation_failure("import", &outcome).2);
    }
    match outcome.profile_mutation {
        Some(Ok(crate::cli::control::LocalProfileMutationReceipt::Imported(profile))) => {
            Ok(profile)
        }
        Some(Ok(crate::cli::control::LocalProfileMutationReceipt::RemoteApplied { .. })) => {
            crate::vpn::load_profiles_from(&profiles_dir)
                .into_iter()
                .find(|profile| profile.id == profile_id)
                .ok_or_else(|| {
                    "remote control applied import but the shared profile catalog did not refresh"
                        .to_owned()
                })
        }
        Some(Err(failure)) => Err(format!("profile storage rejected import: {failure:?}")),
        _ => Err("control service returned no import receipt".to_owned()),
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

fn import_from_directory(
    dir_path: &Path,
    config: &AppConfig,
    config_dir: &Path,
    mode: OutputMode,
) -> i32 {
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
                    match import_profile_via_control(&path, config, config_dir) {
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

fn require_profile_inactive(
    engine: &VpnRuntime,
    active_name: &str,
    requested_name: &str,
    command: &str,
    retry_command: &str,
    mode: OutputMode,
) {
    let active = crate::core::scanner::get_active_profiles(&engine.profiles);
    if active.iter().any(|session| session.name == active_name) {
        print_error_and_exit(
            mode,
            command,
            CliError {
                code: "state_conflict",
                message: format!(
                    "Cannot {command} active profile '{requested_name}' — disconnect first"
                ),
                hint: Some(format!("sudo vortix down && {retry_command}")),
            },
            ExitCode::StateConflict,
        );
    }
}

fn handle_delete(
    profile_name: &str,
    yes: bool,
    config: &AppConfig,
    config_dir: &Path,
    mode: OutputMode,
) -> i32 {
    let engine = VpnRuntime::new_headless(config.clone(), config_dir.to_path_buf());

    let Some(idx) = engine.find_profile(profile_name) else {
        print_error_and_exit(
            mode,
            "delete",
            err_not_found(profile_name),
            ExitCode::NotFound,
        );
    };
    let profile_id = engine.profiles[idx].id.clone();

    require_profile_inactive(
        &engine,
        profile_name,
        profile_name,
        "delete",
        &format!("vortix delete {profile_name}"),
        mode,
    );

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

    // Profile mutation shares the same cross-process lifecycle authority as
    // up/down. Reload under the lock and re-check kernel state immediately
    // before deleting so a tunnel started while the prompt was open cannot
    // lose its profile.
    let _lifecycle_lock = acquire_lifecycle_lock_or_exit(mode, "delete");
    let fresh_engine = VpnRuntime::new_headless(config.clone(), config_dir.to_path_buf());
    let Some(fresh_profile) = fresh_engine
        .profiles
        .iter()
        .find(|profile| profile.id == profile_id)
    else {
        print_error_and_exit(
            mode,
            "delete",
            err_not_found(profile_name),
            ExitCode::NotFound,
        );
    };
    let fresh_name = fresh_profile.name.clone();
    require_profile_inactive(
        &fresh_engine,
        &fresh_name,
        profile_name,
        "delete",
        &format!("vortix delete {profile_name}"),
        mode,
    );

    let control = crate::cli::control::ClientControlSession::start_production_profile(
        config_dir,
        &fresh_engine.profiles,
        Vec::new(),
    )
    .unwrap_or_else(|error| local_control_error_or_exit(mode, "delete", &error));
    let outcome = control
        .run(
            crate::vortix_core::control::UserCommand::DeleteProfile {
                profile_id: profile_id.clone(),
            },
            Duration::from_secs(5),
            local_idempotency_key("delete", Some(&profile_id)),
        )
        .unwrap_or_else(|error| local_control_error_or_exit(mode, "delete", &error));
    if outcome.status != crate::vortix_core::control::OperationStatus::Succeeded {
        let message = outcome.profile_mutation.as_ref().map_or_else(
            || operation_failure("delete", &outcome).2,
            |result| format!("Delete failed: {result:?}"),
        );
        print_error_and_exit(
            mode,
            "delete",
            CliError {
                code: "io_error",
                message,
                hint: None,
            },
            ExitCode::GeneralError,
        );
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

#[allow(
    clippy::too_many_lines,
    reason = "rename preserves validation, active-state recheck, typed mutation, and output contracts"
)]
fn handle_rename(
    old: &str,
    new: &str,
    config: &AppConfig,
    config_dir: &Path,
    mode: OutputMode,
) -> i32 {
    let engine = VpnRuntime::new_headless(config.clone(), config_dir.to_path_buf());

    let Some(idx) = engine.find_profile(old) else {
        print_error_and_exit(mode, "rename", err_not_found(old), ExitCode::NotFound);
    };
    let profile_id = engine.profiles[idx].id.clone();

    require_profile_inactive(
        &engine,
        old,
        old,
        "rename",
        &format!("vortix rename {old} {new}"),
        mode,
    );

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
    // Preserve the established CLI contract: renaming a profile to its
    // current display name is reported as the same collision as any other
    // occupied target, even though the storage port treats it as idempotent.
    if trimmed == old {
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

    let _lifecycle_lock = acquire_lifecycle_lock_or_exit(mode, "rename");
    let fresh_engine = VpnRuntime::new_headless(config.clone(), config_dir.to_path_buf());
    let Some(fresh_profile) = fresh_engine
        .profiles
        .iter()
        .find(|profile| profile.id == profile_id)
    else {
        print_error_and_exit(mode, "rename", err_not_found(old), ExitCode::NotFound);
    };
    require_profile_inactive(
        &fresh_engine,
        &fresh_profile.name,
        old,
        "rename",
        &format!("vortix rename {old} {new}"),
        mode,
    );

    let control = crate::cli::control::ClientControlSession::start_production_profile(
        config_dir,
        &fresh_engine.profiles,
        Vec::new(),
    )
    .unwrap_or_else(|error| local_control_error_or_exit(mode, "rename", &error));
    let outcome = control
        .run(
            crate::vortix_core::control::UserCommand::RenameProfile {
                profile_id: profile_id.clone(),
                new_display_name: trimmed.to_owned(),
            },
            Duration::from_secs(5),
            local_idempotency_key("rename", Some(&profile_id)),
        )
        .unwrap_or_else(|error| local_control_error_or_exit(mode, "rename", &error));
    match outcome.profile_mutation {
        Some(Ok(
            crate::cli::control::LocalProfileMutationReceipt::Renamed(_)
            | crate::cli::control::LocalProfileMutationReceipt::RemoteApplied { .. },
        )) if outcome.status == crate::vortix_core::control::OperationStatus::Succeeded => {}
        Some(Err(crate::vortix_core::control::ProfileMutationFailure::AlreadyExists)) => {
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
        result => print_error_and_exit(
            mode,
            "rename",
            CliError {
                code: "io_error",
                message: format!("Rename failed: {result:?}"),
                hint: None,
            },
            ExitCode::GeneralError,
        ),
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

        let _lifecycle_lock = acquire_lifecycle_lock_or_exit(output_mode, "killswitch");
        let control = crate::cli::control::ClientControlSession::start_production(
            config,
            config_dir,
            engine.profiles.clone(),
        )
        .unwrap_or_else(|error| local_control_error_or_exit(output_mode, "killswitch", &error));
        let outcome = control
            .run(
                crate::vortix_core::control::UserCommand::SetKillSwitch { mode: ks_mode },
                Duration::from_secs(config.disconnect_timeout),
                local_idempotency_key("killswitch", None),
            )
            .unwrap_or_else(|error| local_control_error_or_exit(output_mode, "killswitch", &error));
        if outcome.status != crate::vortix_core::control::OperationStatus::Succeeded {
            let (_, exit, message) = operation_failure("kill-switch", &outcome);
            print_error_and_exit(
                output_mode,
                "killswitch",
                CliError {
                    code: "protection_degraded",
                    message: format!("{message}; protection is degraded"),
                    hint: Some(
                        "Inspect firewall permissions/backend health, then retry the command"
                            .to_string(),
                    ),
                },
                exit,
            );
        }
        if let Some(persisted) = crate::core::killswitch::load_state() {
            engine.killswitch_mode = persisted.mode;
            engine.killswitch_state = persisted.effective_state.unwrap_or(persisted.state);
        } else {
            engine.killswitch_mode = outcome.snapshot.desired.kill_switch;
        }
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

fn handle_release_killswitch(config: &AppConfig, config_dir: &Path, mode: OutputMode) {
    let _lifecycle_lock = acquire_lifecycle_lock_or_exit(mode, "release-killswitch");
    let engine = VpnRuntime::new_headless(config.clone(), config_dir.to_path_buf());
    if !engine.is_root {
        print_error_and_exit(
            mode,
            "release-killswitch",
            err_permission_denied("vortix release-killswitch"),
            ExitCode::PermissionDenied,
        );
    }
    let control = crate::cli::control::ClientControlSession::start_production(
        config,
        config_dir,
        engine.profiles.clone(),
    )
    .unwrap_or_else(|error| local_control_error_or_exit(mode, "release-killswitch", &error));
    let outcome = control
        .run(
            crate::vortix_core::control::UserCommand::SetKillSwitch {
                mode: crate::state::KillSwitchMode::Off,
            },
            Duration::from_secs(config.disconnect_timeout),
            local_idempotency_key("release-killswitch", None),
        )
        .unwrap_or_else(|error| local_control_error_or_exit(mode, "release-killswitch", &error));
    if outcome.status != crate::vortix_core::control::OperationStatus::Succeeded {
        let (_, exit, message) = operation_failure("kill-switch release", &outcome);
        print_error_and_exit(
            mode,
            "release-killswitch",
            CliError {
                code: "release_failed",
                message,
                hint: Some(crate::platform::KILLSWITCH_EMERGENCY_MSG.to_string()),
            },
            exit,
        );
    }
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

    // Session-journal path. Folded into `vortix info` as part
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
    fn default_connect_budget_covers_protocol_cleanup_and_control_settlement() {
        let config = AppConfig {
            wireguard_handshake_timeout_secs: 20,
            connect_timeout: 30,
            disconnect_timeout: 12,
            ..AppConfig::default()
        };

        assert_eq!(
            connect_operation_timeout_secs(None, crate::state::Protocol::WireGuard, &config),
            37
        );
        assert_eq!(
            connect_operation_timeout_secs(None, crate::state::Protocol::OpenVPN, &config),
            47
        );
    }

    #[test]
    fn explicit_connect_budget_remains_the_users_hard_cap() {
        assert_eq!(
            connect_operation_timeout_secs(
                Some(7),
                crate::state::Protocol::WireGuard,
                &AppConfig::default(),
            ),
            7
        );
    }

    #[test]
    fn late_profile_mutation_cli_result_forbids_a_blind_retry() {
        let outcome = crate::cli::control::ClientOperationOutcome {
            operation_id: serde_json::from_str("\"op-0000000000000001-0000000000000001\"").unwrap(),
            status: crate::vortix_core::control::OperationStatus::Expired,
            result: Some(
                crate::vortix_core::control::OperationResult::ProfileMutationAppliedAfterDeadline,
            ),
            snapshot: crate::vortix_core::control::ControlSnapshot::default(),
            profile_mutation: None,
        };

        let (code, exit, message) = operation_failure("import", &outcome);

        assert_eq!(code, "completed_after_deadline");
        assert_eq!(exit.code(), ExitCode::Timeout.code());
        assert!(message.contains("was applied and must not be retried"));
    }

    #[test]
    fn remote_challenge_categories_match_standard_cli_output() {
        use crate::daemon::service::RemoteControlError;
        use crate::vortix_core::control::ChallengeError;

        let cases = [
            (
                crate::cli::control::LocalControlError::ChallengeCancelled,
                crate::cli::control::LocalControlError::Remote(RemoteControlError::Challenge(
                    ChallengeError::Cancelled,
                )),
                "user_cancelled",
                ExitCode::GeneralError,
            ),
            (
                crate::cli::control::LocalControlError::ChallengeExpired,
                crate::cli::control::LocalControlError::Remote(RemoteControlError::Challenge(
                    ChallengeError::Expired,
                )),
                "timeout",
                ExitCode::Timeout,
            ),
        ];

        for (standard, remote, expected_code, expected_exit) in cases {
            let standard_category = local_control_error_category(&standard);
            let remote_category = local_control_error_category(&remote);
            assert_eq!(standard_category.0, expected_code);
            assert_eq!(remote_category.0, expected_code);
            assert_eq!(standard_category.1.code(), expected_exit.code());
            assert_eq!(remote_category.1.code(), expected_exit.code());
        }

        let unauthorized = crate::cli::control::LocalControlError::Remote(
            RemoteControlError::Challenge(ChallengeError::Unauthorized),
        );
        let (code, exit) = local_control_error_category(&unauthorized);
        assert_eq!(code, "control_failed");
        assert_eq!(exit.code(), ExitCode::GeneralError.code());
    }

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

    #[test]
    fn diagnostic_follow_emits_only_new_records_and_resets_after_restart() {
        use crate::vortix_core::control::diagnostics::DIAGNOSTIC_SCHEMA_VERSION;
        use crate::vortix_core::control::{
            DiagnosticCode, DiagnosticComponent, DiagnosticFields, DiagnosticRecord,
            DiagnosticSeverity, DiagnosticSnapshot, DiagnosticSource, DiagnosticStatus,
            DiagnosticView,
        };

        let view = |sequences: &[u64]| DiagnosticView {
            source: DiagnosticSource::AuthenticatedLive,
            stale: false,
            age_millis: 0,
            snapshot: DiagnosticSnapshot {
                schema_version: DIAGNOSTIC_SCHEMA_VERSION,
                generation: *sequences.last().unwrap_or(&0),
                generated_at_unix_millis: 1,
                stale_after_millis: 30_000,
                product_version: "test".into(),
                status: DiagnosticStatus::default(),
                records: sequences
                    .iter()
                    .map(|sequence| DiagnosticRecord {
                        sequence: *sequence,
                        age_millis: 0,
                        component: DiagnosticComponent::Daemon,
                        severity: DiagnosticSeverity::Info,
                        code: DiagnosticCode::DaemonStarted,
                        fields: DiagnosticFields::None,
                    })
                    .collect(),
            },
        };

        let mut last = 2;
        let delta = diagnostic_delta(view(&[1, 2, 3, 4]), &mut last).unwrap();
        assert_eq!(
            delta
                .snapshot
                .records
                .iter()
                .map(|record| record.sequence)
                .collect::<Vec<_>>(),
            vec![3, 4]
        );
        assert_eq!(last, 4);
        assert!(diagnostic_delta(view(&[1, 2, 3, 4]), &mut last).is_none());

        let restarted = diagnostic_delta(view(&[1]), &mut last).unwrap();
        assert_eq!(restarted.snapshot.records[0].sequence, 1);
        assert_eq!(last, 1);
    }

    #[test]
    fn setup_catalog_preserves_identity_validation_errors() {
        let config = tempfile::tempdir().unwrap();
        let profiles = config.path().join(constants::PROFILES_DIR_NAME);
        std::fs::create_dir_all(&profiles).unwrap();
        std::fs::write(
            profiles.join("orphan.conf"),
            "[Interface]\nPrivateKey = x\n",
        )
        .unwrap();

        let error = load_setup_profiles(config.path()).unwrap_err();
        assert!(matches!(
            error,
            crate::vortix_config::profile_store::ProfileStoreError::MissingSidecar { .. }
        ));
    }
}
