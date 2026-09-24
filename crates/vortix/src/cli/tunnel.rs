//! Tunnel lifecycle commands: up, down, reconnect.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use serde::Serialize;

use super::commands::{acquire_lifecycle_lock_or_exit, engine_failure_or_exit, run_engine_command};
use crate::cli::output::{
    err_not_found, err_permission_denied, print_error_and_exit, print_success, CliError, ExitCode,
    OutputMode,
};
use crate::config::AppConfig;
pub(super) fn lifecycle_progress_message(
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

pub(super) fn prompt_masked_otp(prompt: &str, expires_at_millis: u64) -> std::io::Result<String> {
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

#[derive(Serialize)]
struct UpData {
    state: String,
    profile: String,
    protocol: String,
}

#[allow(clippy::too_many_lines)]
pub(super) fn handle_up(
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
                crate::control::Conflict::DefaultRouteTakeover { current, new: _ } => (
                    "state_conflict_default_route",
                    format!(
                        "Profile '{profile_name}' would take over the default route from '{}'",
                        named(current)
                    ),
                ),
                crate::control::Conflict::RouteOverlap {
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

fn detect_conflict_for_cli(
    profiles: &[crate::config::profiles::VpnProfile],
    config_dir: &Path,
    target_name: &str,
) -> Option<crate::control::Conflict> {
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
        if let Some(conflict) = crate::control::classify_route_conflict(
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
pub(super) fn handle_down(
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
pub(super) fn handle_reconnect(
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
