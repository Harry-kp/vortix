//! CLI command handlers.
//!
//! Each handler runs headlessly (no TUI), produces
//! structured output via [`OutputMode`], and exits with semantic exit codes.

use std::path::Path;
use std::time::Duration;

use serde::Serialize;

use super::profiles::{handle_delete, handle_import, handle_list, handle_rename, handle_show};
use super::status::handle_status;
use super::tunnel::{handle_down, handle_reconnect, handle_up, prompt_masked_otp};
use crate::cli::args::Commands;
use crate::cli::output::{
    err_permission_denied, print_error_and_exit, print_success, CliError, ExitCode, OutputMode,
};
use crate::config::AppConfig;
use crate::constants;

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

/// Start the engine, run one command to completion, and answer credential
/// prompts on the terminal.
pub(super) fn run_engine_command(
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

pub(super) fn engine_failure_or_exit(mode: OutputMode, command: &str, message: String) -> ! {
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
/// The CLI doesn't share an in-memory engine with the running
/// session — active tunnels are discovered via
/// `scanner::get_active_profiles`. We inspect each active session's parsed
/// config and use the **shared** `cidr` and
/// `claims_default_route_*` helpers (same logic the TUI's
/// the engine uses) so the two surfaces refuse the
/// same set of takeovers. The route-overlap branch is a CLI-only
/// superset until a follow-up brings route-overlap detection into the
/// registry.
/// Acquire the cross-process lifecycle lock or exit with a structured
/// error. Proceeding without the lock would reintroduce the concurrent
/// `up`/`down` interleaving the lock exists to prevent.
pub(super) fn acquire_lifecycle_lock_or_exit(
    mode: OutputMode,
    command: &str,
) -> crate::config::LifecycleLock {
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

// ── Status ──────────────────────────────────────────────────────────────

// ── Profile Management ──────────────────────────────────────────────────

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
    let (wg_count, ovpn_count) = super::profiles::count_profiles(&profiles_dir);
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

    let result = crate::process::run(crate::process::CommandSpec::oneshot(
        "cargo",
        vec!["install".into(), "vortix".into(), "--force".into()],
    ));

    match result {
        Ok(s) if s.success() => match mode {
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
}
