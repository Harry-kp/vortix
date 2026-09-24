//! CLI command handlers.
//!
//! Each handler runs headlessly (no TUI), produces
//! structured output via [`OutputMode`], and exits with semantic exit codes.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use serde::Serialize;

use crate::cli::args::Commands;
use crate::cli::output::{
    err_not_found, err_permission_denied, print_error_and_exit, print_success, CliError,
    ConnectionEntry, ConnectionHealthEntry, ExitCode, OutputMode,
};
use crate::config::profile_store::FsProfileStore;
use crate::config::AppConfig;
use crate::constants;

fn lifecycle_progress_message(
    mode: OutputMode,
    action: &str,
    profile: &str,
    protocol: Option<&str>,
    timeout_secs: u64,
) -> Option<String> {
    if mode != OutputMode::Human {
        return None;
    }
    let protocol = protocol.map_or_else(String::new, |value| format!(" ({value})"));
    // Nothing here installs a SIGINT handler, so Ctrl-C only stops this
    // process waiting — the admitted operation carries on and can still
    // bring the tunnel up. Saying "cancels" left people believing an
    // interrupted connect had been called off while it was completing.
    Some(format!(
        "◐ {action} {profile}{protocol} — verifying the tunnel and network policy; this may take up to {timeout_secs}s (Ctrl-C stops waiting, not the {action_lower})…",
        action_lower = action.to_lowercase()
    ))
}

fn show_lifecycle_progress(
    mode: OutputMode,
    action: &str,
    profile: &str,
    protocol: Option<&str>,
    timeout_secs: u64,
) {
    if let Some(message) = lifecycle_progress_message(mode, action, profile, protocol, timeout_secs)
    {
        eprintln!("{message}");
    }
}

fn connect_operation_timeout_secs(
    explicit: Option<u64>,
    protocol: crate::profile::ProtocolKind,
    config: &AppConfig,
) -> u64 {
    explicit.unwrap_or_else(|| config.connect_operation_timeout_secs(protocol))
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
        if crate::platform::boot_elapsed_millis().is_some_and(|now| now >= expires_at_millis) {
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
        } => handle_status(*watch, *interval, *brief, config, config_dir, mode),
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
            mode,
        ),
        Commands::Import { file } => handle_import(file, config, config_dir, mode),
        Commands::Show { profile, raw } => handle_show(profile, *raw, mode),
        Commands::Delete { profile, yes } => handle_delete(profile, *yes, config_dir, mode),
        Commands::Rename { old, new } => handle_rename(old, new, config_dir, mode),
        Commands::KillSwitch { mode: ks_mode } => {
            handle_killswitch(ks_mode.as_deref(), config, config_dir, mode)
        }
        Commands::ReleaseKillSwitch => handle_release_killswitch(config_dir, mode),
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
        Commands::Completions { shell } => {
            handle_completions(*shell);
            0
        }
    }
}

/// `vortix audit` — per-process socket snapshot.
#[derive(Serialize)]
struct AuditData {
    sockets: Vec<crate::platform::SocketSnapshot>,
}

fn handle_audit(pid_filter: Option<u32>, vpn_only: bool, mode: OutputMode) -> i32 {
    let mut snapshots = match crate::platform::SocketAudit::snapshot() {
        Ok(s) => s,
        Err(crate::platform::SocketAuditError::Unsupported) => {
            print_error_and_exit(
                mode,
                "audit",
                CliError {
                    code: "platform_unsupported",
                    message: "Socket audit is not available on this platform yet".to_string(),
                    hint: Some(
                        "Linux and macOS are supported; Windows support is on the roadmap"
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
                // An unresolved owner came out as a bare `0`, which reads as
                // the kernel rather than "not known" — and stays 0 for many
                // sockets even under sudo. `-` matches the IFACE column's
                // existing convention for the same situation.
                let pid = if s.pid == 0 {
                    "-".to_string()
                } else {
                    s.pid.to_string()
                };
                let command = if s.command.is_empty() {
                    "-"
                } else {
                    s.command.as_str()
                };
                println!(
                    "{:<6} {:<16} {:<7} {:<32} {:<32} {}",
                    pid,
                    command,
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
    let profiles = crate::config::profiles::load_profiles();

    let profile_name = if let Some(name) = profile {
        name.to_string()
    } else {
        match profiles
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

    if !crate::platform::is_root() {
        print_error_and_exit(
            mode,
            "up",
            err_permission_denied(&format!("vortix up {profile_name}")),
            ExitCode::PermissionDenied,
        );
    }

    // Check dependencies before attempting connection. Routes through
    // `platform::check_dependencies` so the TUI and CLI refuse the
    // same dep set — including the OpenVPN 2.4+ probe that the
    // legacy inline CLI check used to skip.
    if let Some(profile) = profiles.iter().find(|p| p.name == profile_name) {
        let missing = crate::platform::check_dependencies(profile.protocol, &profile.config_path);
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
        if let Some(conflict) = detect_conflict_for_cli(&profiles, config_dir, &profile_name) {
            // Conflicts carry opaque profile IDs; the reader needs the name
            // they typed, so resolve through the catalog before formatting.
            let named = |id: &crate::profile::ProfileId| {
                profiles
                    .iter()
                    .find(|profile| &profile.id == id)
                    .map_or_else(|| id.to_string(), |profile| profile.name.clone())
            };
            let (code, message) = match &conflict {
                crate::app::registry::Conflict::DefaultRouteTakeover { current, new: _ } => (
                    "state_conflict_default_route",
                    format!(
                        "Profile '{profile_name}' would take over the default route from '{}'",
                        named(current)
                    ),
                ),
                crate::app::registry::Conflict::RouteOverlap {
                    with,
                    overlapping_cidrs,
                } => (
                    "state_conflict_route_overlap",
                    format!(
                        "Profile '{profile_name}' overlaps with '{}' on {} CIDR(s)",
                        named(with),
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

    let target = profiles
        .iter()
        .find(|profile| profile.name == profile_name)
        .cloned()
        .unwrap_or_else(|| {
            print_error_and_exit(mode, "up", err_not_found(&profile_name), ExitCode::NotFound)
        });
    let timeout_secs = connect_operation_timeout_secs(timeout_secs, target.protocol, config);
    let protocol = target.protocol.to_string();
    show_lifecycle_progress(
        mode,
        "Connecting",
        &target.name,
        Some(&protocol),
        timeout_secs,
    );
    if let Err(error) = run_engine_command(
        config,
        config_dir,
        profiles.clone(),
        crate::control::Command::Connect(target.id.clone()),
        Duration::from_secs(timeout_secs),
    ) {
        engine_failure_or_exit(mode, "up", error);
    }
    let data = UpData {
        state: "connected".into(),
        profile: target.name.clone(),
        protocol: target.protocol.to_string(),
    };
    match mode {
        OutputMode::Human => println!("● Connected to {} ({})", target.name, target.protocol),
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
    0
}

/// Start the engine, run one command to completion, and answer credential
/// prompts on the terminal.
fn run_engine_command(
    config: &AppConfig,
    config_dir: &Path,
    profiles: Vec<crate::config::profiles::VpnProfile>,
    command: crate::control::Command,
    timeout: Duration,
) -> Result<std::sync::Arc<crate::control::Snapshot>, String> {
    let control = crate::control::Control::start(config, config_dir, profiles)?;
    let ticket = control.send(command);
    let expires = crate::platform::boot_elapsed_millis()
        .unwrap_or_default()
        .saturating_add(u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX));
    control.wait(ticket, timeout, |prompt| {
        let saved = control
            .load_credentials(&prompt.profile_id, &prompt.name)
            .ok()
            .flatten()?;
        let otp = match &prompt.otp_label {
            Some(label) => Some(
                prompt_masked_otp(label, expires)
                    .ok()
                    .filter(|otp| !otp.is_empty())?,
            ),
            None => None,
        };
        Some(crate::control::Credentials {
            username: saved.username().to_owned(),
            password: saved.password().to_owned(),
            otp,
            remember: false,
        })
    })?;
    Ok(control.snapshot())
}

fn engine_failure_or_exit(mode: OutputMode, command: &str, message: String) -> ! {
    let (code, exit) = if message.contains("timed out") {
        ("timeout", ExitCode::Timeout)
    } else if message.contains("rejected the credentials") {
        ("authentication_failed", ExitCode::GeneralError)
    } else if message == "cancelled" {
        ("auth_required", ExitCode::GeneralError)
    } else {
        ("control_failed", ExitCode::GeneralError)
    };
    let message = if message == "cancelled" {
        "This profile needs saved credentials. Save them in the TUI (Auth Manager) first."
            .to_owned()
    } else {
        message
    };
    print_error_and_exit(
        mode,
        command,
        CliError {
            code,
            message,
            hint: None,
        },
        exit,
    )
}

/// Detect a multi-tunnel conflict for the CLI's `up` path.
///
/// The CLI doesn't share an in-memory `TunnelRegistry` with the running
/// session — active tunnels are discovered via
/// `scanner::get_active_profiles`. We inspect each active session's parsed
/// config and use the **shared** `cidr` and
/// `claims_default_route_*` helpers (same logic the TUI's
/// `TunnelRegistry::detect_conflict` uses) so the two surfaces refuse the
/// same set of takeovers. The route-overlap branch is a CLI-only
/// superset until a follow-up brings route-overlap detection into the
/// registry.
/// Acquire the cross-process lifecycle lock or exit with a structured
/// error. Proceeding without the lock would reintroduce the concurrent
/// `up`/`down` interleaving the lock exists to prevent.
fn acquire_lifecycle_lock_or_exit(mode: OutputMode, command: &str) -> crate::config::LifecycleLock {
    match crate::config::acquire_lifecycle_lock() {
        Ok(file) => file,
        Err(error) => {
            let busy = error.kind() == std::io::ErrorKind::WouldBlock;
            print_error_and_exit(
                mode,
                command,
                CliError {
                    code: if busy {
                        "already_running"
                    } else {
                        "lock_failed"
                    },
                    message: crate::config::lifecycle_lock_user_message(&error),
                    hint: (!busy).then(|| "Check ownership of the Vortix config directory.".into()),
                },
                if busy {
                    ExitCode::StateConflict
                } else {
                    ExitCode::GeneralError
                },
            )
        }
    }
}

fn detect_conflict_for_cli(
    profiles: &[crate::config::profiles::VpnProfile],
    config_dir: &Path,
    target_name: &str,
) -> Option<crate::app::registry::Conflict> {
    let target_profile = profiles.iter().find(|p| p.name == target_name)?;
    let specs = crate::control::profiles::load(config_dir, profiles.to_vec());
    let routes = |id: &crate::profile::ProfileId| {
        specs
            .get(id)
            .and_then(|entry| entry.spec.as_ref().ok())
            .map(|spec| spec.routes.iter().copied().collect::<Vec<_>>())
            .unwrap_or_default()
    };
    let target_allowed = routes(&target_profile.id);

    let active = crate::control::scanner::get_active_profiles(profiles);
    for session in &active {
        if session.name == target_name {
            // Re-up of an already-up profile isn't a conflict — the
            // connect path is idempotent here.
            continue;
        }
        let Some(active_profile) = profiles.iter().find(|p| p.name == session.name) else {
            continue;
        };
        let active_allowed = routes(&active_profile.id);
        if let Some(conflict) = crate::app::registry::classify_route_conflict(
            &target_allowed,
            &active_allowed,
            &active_profile.id,
            &target_profile.id,
        ) {
            return Some(conflict);
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
    let _lifecycle_lock = acquire_lifecycle_lock_or_exit(mode, "down");
    let profiles = crate::config::profiles::load_profiles();

    // NotFound (exit 3) takes precedence over idempotence: a typo'd
    // profile is a script error, not "already disconnected".
    if let Some(name) = profile_filter {
        if !profiles.iter().any(|p| p.name == name) {
            print_error_and_exit(mode, "down", err_not_found(name), ExitCode::NotFound);
        }
    }

    // Discover every active tunnel, then filter to the requested target.
    let mut targets: Vec<crate::control::scanner::ActiveSession> =
        crate::control::scanner::get_active_profiles(&profiles);
    if let Some(name) = profile_filter {
        targets.retain(|s| s.name == name);
    }

    let profile_id = profile_filter.and_then(|name| {
        profiles
            .iter()
            .find(|profile| profile.name == name)
            .map(|profile| profile.id.clone())
    });
    if targets.is_empty() {
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

    if !crate::platform::is_root() {
        print_error_and_exit(
            mode,
            "down",
            err_permission_denied("vortix down"),
            ExitCode::PermissionDenied,
        );
    }

    let _ = force;
    let command = profile_id.map_or(
        crate::control::Command::DisconnectAll,
        crate::control::Command::Disconnect,
    );
    let timeout_secs = config.disconnect_operation_timeout_secs();
    show_lifecycle_progress(
        mode,
        "Disconnecting",
        profile_filter.unwrap_or("active VPNs"),
        None,
        timeout_secs,
    );
    if let Err(error) = run_engine_command(
        config,
        config_dir,
        profiles.clone(),
        command,
        Duration::from_secs(timeout_secs),
    ) {
        engine_failure_or_exit(mode, "down", error);
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
    let profiles = crate::config::profiles::load_profiles();

    // Validate the requested profile exists in the catalog before we
    // poke the system. NotFound (exit 3) > "no active" idempotency.
    if let Some(name) = profile_filter {
        if !profiles.iter().any(|p| p.name == name) {
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
    let active = crate::control::scanner::get_active_profiles(&profiles);

    let to_cycle: Vec<String> = if let Some(name) = profile_filter {
        vec![name.to_string()]
    } else if !active.is_empty() {
        active.iter().map(|s| s.name.clone()).collect()
    } else {
        // No active tunnels and no explicit target — fall back to
        // last-used (preserves the single-tunnel behaviour).
        match profiles
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

    if !crate::platform::is_root() {
        print_error_and_exit(
            mode,
            "reconnect",
            err_permission_denied("vortix reconnect"),
            ExitCode::PermissionDenied,
        );
    }
    for name in &to_cycle {
        let profile = profiles
            .iter()
            .find(|profile| &profile.name == name)
            .expect("reconnect targets were resolved from the profile catalog");
        let missing = crate::platform::check_dependencies(profile.protocol, &profile.config_path);
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
        profiles
            .iter()
            .find(|profile| profile.name == name)
            .map(|profile| profile.id.clone())
    });
    let fallback_id = (active.is_empty() && requested_id.is_none()).then(|| {
        profiles
            .iter()
            .find(|profile| profile.name == to_cycle[0])
            .expect("last-used reconnect target exists")
            .id
            .clone()
    });
    let target_id = requested_id.or(fallback_id);
    let timeout_secs = to_cycle
        .iter()
        .filter_map(|name| {
            profiles
                .iter()
                .find(|profile| &profile.name == name)
                .map(|profile| config.reconnect_operation_timeout_secs(profile.protocol))
        })
        .max()
        .unwrap_or(crate::constants::DEFAULT_CONTROL_COMMAND_TIMEOUT_SECS);
    let targets = target_id.map_or_else(
        || {
            to_cycle
                .iter()
                .filter_map(|name| profiles.iter().find(|p| &p.name == name))
                .map(|profile| profile.id.clone())
                .collect::<Vec<_>>()
        },
        |id| vec![id],
    );
    for target in targets {
        if let Err(error) = run_engine_command(
            config,
            config_dir,
            profiles.clone(),
            crate::control::Command::Reconnect(target),
            Duration::from_secs(timeout_secs),
        ) {
            engine_failure_or_exit(mode, "reconnect", error);
        }
    }

    for name in &to_cycle {
        let profile = profiles
            .iter()
            .find(|profile| &profile.name == name)
            .expect("reconnect target exists");
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
    config: &AppConfig,
    config_dir: &Path,
    mode: OutputMode,
) -> i32 {
    if watch {
        // Watch always uses the direct scanner path — it polls in a
        // tight loop and daemon round-trips would just add latency.
        return run_watch(interval, config, config_dir, mode);
    }

    let profiles = crate::config::profiles::load_profiles();
    let snap = crate::cli::status::scan_status(&profiles, config, config_dir);
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

fn run_watch(interval: u64, config: &AppConfig, config_dir: &Path, mode: OutputMode) -> i32 {
    loop {
        let profiles = crate::config::profiles::load_profiles();
        let snap = crate::cli::status::scan_status(&profiles, config, config_dir);

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

fn human_status_headline(snap: &crate::cli::status::StatusSnapshot) -> String {
    let profile = snap.profile.as_deref().unwrap_or("unknown");
    let protocol = snap.protocol.as_deref().unwrap_or("");
    match snap.connection_state.as_str() {
        "connected" => snap.health.as_ref().map_or_else(
            || format!("● Connected to {profile} ({protocol})"),
            |health| match health {
                crate::tunnel::ConnectionHealth::Degraded { .. } => format!(
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

fn connection_health_entry(health: &crate::tunnel::ConnectionHealth) -> ConnectionHealthEntry {
    use crate::tunnel::ConnectionHealth;
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

fn connection_health_human(health: &crate::tunnel::ConnectionHealth) -> String {
    use crate::tunnel::ConnectionHealth;
    match health {
        ConnectionHealth::Unknown => "Unknown (measuring)".into(),
        ConnectionHealth::Healthy => "Healthy".into(),
        ConnectionHealth::Degraded { reason } => {
            format!("Degraded: {}", degraded_reason_human(reason))
        }
    }
}

fn degraded_reason_human(reason: &crate::tunnel::DegradedReason) -> String {
    use crate::tunnel::DegradedReason;
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

    #[test]
    fn watch_timestamps_are_whole_second_utc() {
        let ts = chrono_now();
        assert_eq!(ts.len(), 20, "{ts}");
        assert!(ts.ends_with('Z') && ts.as_bytes()[10] == b'T', "{ts}");
    }
    use crate::control::killswitch::{KillSwitchMode, KillSwitchState};

    fn snapshot(state: &str, protocol: &str) -> crate::cli::status::StatusSnapshot {
        crate::cli::status::StatusSnapshot {
            connection_state: state.into(),
            health: None,
            generation: None,
            profile: Some("corp".into()),
            protocol: Some(protocol.into()),
            uptime_secs: None,
            server: None,
            interface: None,
            internal_ip: None,
            download_bytes: None,
            upload_bytes: None,
            killswitch_mode: KillSwitchMode::Off,
            killswitch_state: KillSwitchState::Disabled,
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
    fn lifecycle_progress_explains_silent_verification_without_spamming() {
        assert_eq!(
            lifecycle_progress_message(
                OutputMode::Human,
                "Connecting",
                "wg13",
                Some("WireGuard"),
                60,
            ),
            Some("◐ Connecting wg13 (WireGuard) — verifying the tunnel and network policy; this may take up to 60s (Ctrl-C stops waiting, not the connecting)…".into())
        );
        assert_eq!(
            lifecycle_progress_message(
                OutputMode::Human,
                "Disconnecting",
                "wg12",
                None,
                30,
            ),
            Some("◐ Disconnecting wg12 — verifying the tunnel and network policy; this may take up to 30s (Ctrl-C stops waiting, not the disconnecting)…".into())
        );
        assert!(lifecycle_progress_message(
            OutputMode::Json,
            "Connecting",
            "wg13",
            Some("WireGuard"),
            60,
        )
        .is_none());
        assert!(lifecycle_progress_message(
            OutputMode::Quiet,
            "Connecting",
            "wg13",
            Some("WireGuard"),
            60,
        )
        .is_none());
    }

    #[test]
    fn human_projection_preserves_typed_health_generation() {
        let degraded = crate::tunnel::ConnectionHealth::Degraded {
            reason: crate::tunnel::DegradedReason::WireGuardPeerStale {
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
        snap.health = Some(crate::tunnel::ConnectionHealth::Healthy);
        assert_eq!(
            connection_health_entry(snap.health.as_ref().unwrap()).status,
            "healthy"
        );
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
/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ`.
fn chrono_now() -> String {
    time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .ok()
        .and_then(|now| {
            now.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
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
    mode: OutputMode,
) -> i32 {
    let mut all = crate::config::profiles::load_profiles();

    // Sort
    let order = match sort.unwrap_or("name") {
        "protocol" => crate::app::state::ProfileSortOrder::Protocol,
        "last-used" => crate::app::state::ProfileSortOrder::LastUsed,
        _ => crate::app::state::ProfileSortOrder::NameAsc,
    };
    order.sort(&mut all);

    let mut profiles: Vec<_> = all.iter().collect();

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

    // Multi-tunnel: every kernel-visible session counts. Built as a
    // HashSet so per-entry membership lookup is O(1) and every
    // active profile gets its dot — not just the first one (the
    // pre-fix `active.first()` was single-tunnel-era legacy).
    let active_names: std::collections::HashSet<String> =
        crate::control::scanner::get_active_profiles(&all)
            .into_iter()
            .map(|s| s.name)
            .collect();

    let entries: Vec<ProfileEntry> = profiles
        .iter()
        .map(|p| build_profile_entry(p, &active_names))
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
    profile: &crate::config::profiles::VpnProfile,
    active_names: &std::collections::HashSet<String>,
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
        profile_id: Some(profile.id.as_str().to_string()),
        group: profile.group.clone(),
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
    use crate::config::profiles::VpnProfile;
    use crate::profile::ProtocolKind;
    use std::collections::HashSet;

    fn profile(name: &str) -> VpnProfile {
        VpnProfile {
            id: crate::profile::ProfileId::new(name),
            name: name.to_string(),
            protocol: ProtocolKind::WireGuard,
            config_path: std::path::PathBuf::from(format!("/tmp/{name}.conf")),
            location: String::new(),
            last_used: None,
            group: None,
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
            .map(|p| build_profile_entry(p, &active))
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
            .map(|p| build_profile_entry(p, &active))
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
        let entry = build_profile_entry(&profile("alpha"), &HashSet::new());
        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(
            json.contains("\"connected\":false"),
            "connected=false must serialize explicitly; got: {json}"
        );
    }
}

fn handle_import(file: &str, config: &AppConfig, config_dir: &Path, mode: OutputMode) -> i32 {
    use crate::config::import::{resolve_target, ImportTarget};

    match resolve_target(file) {
        Ok(ImportTarget::Url(url)) => {
            if matches!(mode, OutputMode::Human) {
                println!("Downloading...");
            }
            match crate::config::import::download_profile(&url) {
                Ok(downloaded_path) => {
                    let _lifecycle_lock = acquire_lifecycle_lock_or_exit(mode, "import");
                    let result = import_profile_via_control(&downloaded_path, config, config_dir);
                    crate::config::import::cleanup_temp_download(&downloaded_path);
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
) -> Result<crate::config::profiles::VpnProfile, String> {
    let _ = config;
    let profiles_dir = config_dir.join(constants::PROFILES_DIR_NAME);
    let prepared = crate::config::profiles::prepare_profile_import(path, &profiles_dir)?;
    crate::config::profiles::commit_profile_import(prepared, &profiles_dir)
}

#[derive(Serialize)]
struct ImportData {
    name: String,
    protocol: String,
    location: String,
    config_path: String,
}

fn print_import_success(profile: &crate::config::profiles::VpnProfile, mode: OutputMode) {
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

fn handle_show(profile_name: &str, raw: bool, mode: OutputMode) -> i32 {
    let profiles = crate::config::profiles::load_profiles();
    let Some(profile) = profiles.iter().find(|p| p.name == profile_name) else {
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
    profiles: &[crate::config::profiles::VpnProfile],
    active_name: &str,
    requested_name: &str,
    command: &str,
    retry_command: &str,
    mode: OutputMode,
) {
    let active = crate::control::scanner::get_active_profiles(profiles);
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

fn handle_delete(profile_name: &str, yes: bool, config_dir: &Path, mode: OutputMode) -> i32 {
    let profiles = crate::config::profiles::load_profiles();

    let Some(idx) = profiles.iter().position(|p| p.name == profile_name) else {
        print_error_and_exit(
            mode,
            "delete",
            err_not_found(profile_name),
            ExitCode::NotFound,
        );
    };
    let profile_id = profiles[idx].id.clone();

    require_profile_inactive(
        &profiles,
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
    let fresh_profiles = crate::config::profiles::load_profiles();
    let Some(fresh_profile) = fresh_profiles
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
        &fresh_profiles,
        &fresh_name,
        profile_name,
        "delete",
        &format!("vortix delete {profile_name}"),
        mode,
    );

    if let Err(error) =
        FsProfileStore::new(config_dir.join(constants::PROFILES_DIR_NAME)).delete(&profile_id)
    {
        print_error_and_exit(
            mode,
            "delete",
            CliError {
                code: "io_error",
                message: format!("Delete failed: {error}"),
                hint: None,
            },
            ExitCode::GeneralError,
        );
    }
    if fresh_profile.protocol == crate::profile::ProtocolKind::OpenVpn {
        crate::openvpn::cleanup_openvpn_run_files_compat(profile_id.as_str(), &fresh_name);
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
fn handle_rename(old: &str, new: &str, config_dir: &Path, mode: OutputMode) -> i32 {
    let profiles = crate::config::profiles::load_profiles();

    let Some(idx) = profiles.iter().position(|p| p.name == old) else {
        print_error_and_exit(mode, "rename", err_not_found(old), ExitCode::NotFound);
    };
    let profile_id = profiles[idx].id.clone();

    require_profile_inactive(
        &profiles,
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
    let fresh_profiles = crate::config::profiles::load_profiles();
    let Some(fresh_profile) = fresh_profiles
        .iter()
        .find(|profile| profile.id == profile_id)
    else {
        print_error_and_exit(mode, "rename", err_not_found(old), ExitCode::NotFound);
    };
    require_profile_inactive(
        &fresh_profiles,
        &fresh_profile.name,
        old,
        "rename",
        &format!("vortix rename {old} {new}"),
        mode,
    );

    if fresh_profile.protocol == crate::profile::ProtocolKind::WireGuard
        && crate::profile::validate_wireguard_interface_name(trimmed).is_err()
    {
        print_error_and_exit(
            mode,
            "rename",
            CliError {
                code: "invalid_name",
                message: format!(
                    "'{trimmed}' is not a usable profile name. WireGuard names must be 1–15 characters using only letters, numbers, _, =, +, ., or -."
                ),
                hint: None,
            },
            ExitCode::GeneralError,
        );
    }
    if let Err(error) = FsProfileStore::new(config_dir.join(constants::PROFILES_DIR_NAME))
        .rename(&profile_id, trimmed)
    {
        let (code, message, exit) = match error {
            crate::config::profile_store::ProfileStoreError::NameCollision { .. } => (
                "already_exists",
                format!("A profile named '{trimmed}' already exists"),
                ExitCode::StateConflict,
            ),
            crate::config::profile_store::ProfileStoreError::InvalidName(_) => (
                "invalid_name",
                format!("'{trimmed}' is not a usable profile name"),
                ExitCode::GeneralError,
            ),
            other => (
                "io_error",
                format!("Could not rename '{old}' to '{trimmed}': {other}"),
                ExitCode::GeneralError,
            ),
        };
        print_error_and_exit(
            mode,
            "rename",
            CliError {
                code,
                message,
                hint: None,
            },
            exit,
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

/// Print the active mode, what it is doing right now, and the other choices.
fn print_killswitch_status(
    mode: crate::control::killswitch::KillSwitchMode,
    state: crate::control::killswitch::KillSwitchState,
) {
    println!(
        "Kill Switch: {} — currently {}",
        mode.display_name(),
        state.display_status()
    );
    // Degraded means this mode's rules are not in place. Printing the mode's
    // behaviour here read as a description of what is happening, so "no
    // internet at all" appeared over a working connection.
    if state == crate::control::killswitch::KillSwitchState::Degraded {
        // Degraded is "this process cannot prove the rules are in place",
        // which is not the same as "they are not". Proof is bound to the
        // process that applied it, so a separate CLI invocation reaches
        // this branch even while the policy is installed and enforcing.
        // Claiming the rules were missing sent readers to re-apply a
        // working kill switch.
        println!("  Vortix cannot confirm this mode's firewall rules from here,");
        println!("  so it will not claim you are protected. Traffic may or may not");
        println!("  be blocked — check the rules directly to be sure:");
        println!("    {}", crate::platform::firewall_inspect_hint());
        println!(
            "  Re-apply with `vortix killswitch {}`, or clear it with `vortix release-killswitch`.",
            mode.cli_verb()
        );
    } else {
        let (up, down) = mode.behavior_lines();
        println!("  {up}");
        println!("  {down}");
    }
    println!();
    println!("Other modes:");
    for other in [
        crate::control::killswitch::KillSwitchMode::Off,
        crate::control::killswitch::KillSwitchMode::Auto,
        crate::control::killswitch::KillSwitchMode::AlwaysOn,
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

fn handle_killswitch(
    mode_arg: Option<&str>,
    config: &AppConfig,
    config_dir: &Path,
    output_mode: OutputMode,
) -> i32 {
    let profiles = crate::config::profiles::load_profiles();
    let (mut mode, mut state) = crate::control::killswitch::persisted();

    if let Some(new_mode) = mode_arg {
        let Some(ks_mode) = crate::control::killswitch::KillSwitchMode::from_cli_verb(new_mode)
        else {
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

        if !crate::platform::is_root() && ks_mode != crate::control::killswitch::KillSwitchMode::Off
        {
            print_error_and_exit(
                output_mode,
                "killswitch",
                err_permission_denied(&format!("vortix killswitch {}", ks_mode.cli_verb())),
                ExitCode::PermissionDenied,
            );
        }

        let _lifecycle_lock = acquire_lifecycle_lock_or_exit(output_mode, "killswitch");
        match run_engine_command(
            config,
            config_dir,
            profiles.clone(),
            crate::control::Command::SetKillSwitch(ks_mode),
            Duration::from_secs(config.disconnect_operation_timeout_secs()),
        ) {
            Ok(snapshot) => {
                mode = snapshot.kill_switch;
                state = snapshot.kill_switch_state;
            }
            Err(message) => print_error_and_exit(
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
                ExitCode::GeneralError,
            ),
        }
    }

    // JSON envelope carries the canonical slug — the same string
    // users type as a CLI verb (`off` / `block-on-drop` / `vpn-only`).
    // Human-facing rendering uses the title-cased prose form from
    // `display_name`; the two are derived from one vocabulary.
    let data = KsData {
        mode: mode.cli_verb().to_string(),
        state: state.cli_verb().to_string(),
    };

    match output_mode {
        OutputMode::Human => {
            print_killswitch_status(mode, state);
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

/// Run the emergency kill-switch release without normal application startup.
///
/// This path requires root, durably records mode `off`, removes only
/// Vortix-owned firewall state, and verifies that state is absent before
/// reporting success.
#[must_use]
pub fn handle_release_killswitch(config_dir: &Path, mode: OutputMode) -> i32 {
    if !crate::platform::is_root() {
        print_error_and_exit(
            mode,
            "release-killswitch",
            err_permission_denied("vortix release-killswitch"),
            ExitCode::PermissionDenied,
        );
    }

    // Emergency release is still a global mutation. Refuse to race a live
    // canonical authority that could immediately reconcile the old policy
    // back into the kernel or overwrite the durable `off` intent.
    let _lifecycle_lock = acquire_lifecycle_lock_or_exit(mode, "release-killswitch");

    // Persist the emergency intent before touching the kernel. If the
    // process is interrupted after firewall release, the next startup must
    // not recover an older vpn-only intent and re-engage blocking.
    persist_emergency_release_off(config_dir).unwrap_or_else(|error| {
        print_error_and_exit(
            mode,
            "release-killswitch",
            CliError {
                code: "persistence_failed",
                message: format!("Could not durably save kill switch mode off: {error}"),
                hint: Some(crate::constants::KILLSWITCH_EMERGENCY_MSG.to_string()),
            },
            ExitCode::GeneralError,
        )
    });

    crate::control::killswitch::disable_blocking().unwrap_or_else(|error| {
        emergency_release_failed(
            mode,
            format!("Could not remove Vortix firewall state: {error}"),
        )
    });
    crate::control::killswitch::verify_disabled().unwrap_or_else(|error| {
        emergency_release_failed(
            mode,
            format!("Vortix firewall state was not proven absent: {error}"),
        )
    });

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
    0
}

fn persist_emergency_release_off(config_dir: &Path) -> Result<(), String> {
    crate::control::killswitch::save_emergency_release_state(config_dir)
        .map_err(|error| error.to_string())
}

fn emergency_release_failed(mode: OutputMode, message: String) -> ! {
    print_error_and_exit(
        mode,
        "release-killswitch",
        CliError {
            code: "release_failed",
            message,
            hint: Some(crate::constants::KILLSWITCH_EMERGENCY_MSG.to_string()),
        },
        ExitCode::GeneralError,
    )
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
    let journal_session = crate::journal::global_journal()
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
        is_root: crate::platform::is_root(),
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

    let result = crate::process::run_to_output(crate::process::CommandSpec::oneshot(
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
/// The protocol a profile's metadata sidecar declares, when it has one.
fn sidecar_protocol(config: &Path) -> Option<String> {
    let sidecar = config.with_extension("meta.toml");
    let text = std::fs::read_to_string(sidecar).ok()?;
    text.lines()
        .find_map(|line| line.trim().strip_prefix("protocol = "))
        .map(|value| value.trim().trim_matches('"').to_owned())
}

pub(crate) fn count_profiles(profiles_dir: &Path) -> (u32, u32) {
    if !profiles_dir.is_dir() {
        return (0, 0);
    }
    let mut wg = 0u32;
    let mut ovpn = 0u32;
    if let Ok(entries) = std::fs::read_dir(profiles_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            // Rendered tunnel configs are staged beside the profiles as
            // dotfiles. The profile list already skips them; counting them
            // here reported more profiles than the user has.
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with('.'))
            {
                continue;
            }
            if !path.is_file() {
                continue;
            }
            match path.extension().and_then(|e| e.to_str()) {
                // An OpenVPN profile may be imported as `.conf`, so the
                // extension alone put it in the WireGuard column. The sidecar
                // records what it actually is.
                Some("conf") => {
                    if sidecar_protocol(&path).as_deref() == Some("OpenVpn") {
                        ovpn += 1;
                    } else {
                        wg += 1;
                    }
                }
                Some("ovpn") => ovpn += 1,
                _ => {}
            }
        }
    }
    (wg, ovpn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreadable_control_history_does_not_block_emergency_release_persistence() {
        let config = tempfile::tempdir().unwrap();
        let control_dir = config.path().join("control");
        std::fs::create_dir(&control_dir).unwrap();
        std::fs::write(control_dir.join("control-state.json"), b"corrupt").unwrap();
        std::fs::write(control_dir.join("control-state.previous.json"), b"corrupt").unwrap();

        persist_emergency_release_off(config.path()).unwrap();

        let saved =
            std::fs::read_to_string(config.path().join(crate::constants::KILLSWITCH_STATE_FILE))
                .unwrap();
        let state: crate::control::killswitch::PersistedState =
            serde_json::from_str(&saved).unwrap();
        assert_eq!(state.mode, crate::control::killswitch::KillSwitchMode::Off);
        assert_eq!(
            state.state,
            crate::control::killswitch::KillSwitchState::Disabled
        );
        assert!(state.emergency_release_fence);
    }

    #[test]
    fn default_connect_budget_covers_protocol_and_control_settlement() {
        let config = AppConfig {
            wireguard_handshake_timeout_secs: 20,
            connect_timeout: 30,
            disconnect_timeout: 12,
            ..AppConfig::default()
        };

        assert_eq!(
            connect_operation_timeout_secs(None, crate::profile::ProtocolKind::WireGuard, &config),
            22
        );
        assert_eq!(
            connect_operation_timeout_secs(None, crate::profile::ProtocolKind::OpenVpn, &config),
            32
        );
    }

    #[test]
    fn explicit_connect_budget_remains_the_users_hard_cap() {
        assert_eq!(
            connect_operation_timeout_secs(
                Some(7),
                crate::profile::ProtocolKind::WireGuard,
                &AppConfig::default(),
            ),
            7
        );
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
}
