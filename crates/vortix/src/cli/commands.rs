//! CLI command handlers.
//!
//! Each handler operates headlessly via `VpnEngine` (no TUI), produces
//! structured output via [`OutputMode`], and exits with semantic exit codes.

use std::path::Path;
use std::time::Duration;

use serde::Serialize;

use crate::cli::args::Commands;
use crate::cli::output::{
    err_not_found, err_permission_denied, print_error_and_exit, print_success, CliError, ExitCode,
    OutputMode,
};
use crate::config::AppConfig;
use crate::constants;
use crate::engine::VpnEngine;
use crate::state::Protocol;

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
        Commands::Up { profile, timeout } => {
            handle_up(profile.as_deref(), *timeout, config, config_dir, mode)
        }
        Commands::Down { force } => handle_down(*force, config, config_dir, mode),
        Commands::Reconnect => handle_reconnect(config, config_dir, mode),
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
        Commands::Completions { shell } => {
            handle_completions(*shell);
            0
        }
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
    timeout_secs: u64,
    config: &AppConfig,
    config_dir: &Path,
    mode: OutputMode,
) -> i32 {
    let mut engine = VpnEngine::new_headless(config.clone(), config_dir.to_path_buf());

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

    // Check dependencies before attempting connection (same check as TUI)
    engine.load_metadata();
    if let Some(profile) = engine.profiles.iter().find(|p| p.name == profile_name) {
        let protocol = profile.protocol;
        let mut missing = Vec::new();

        match protocol {
            Protocol::WireGuard => {
                if !crate::utils::binary_exists("wg-quick") {
                    missing.push("wg-quick".to_string());
                }
                if !crate::utils::binary_exists("wg") {
                    missing.push("wireguard-tools".to_string());
                }
                // Check for resolvconf on Linux when DNS is configured
                #[cfg(target_os = "linux")]
                {
                    let config_path = &profile.config_path;
                    if crate::utils::wireguard_config_has_dns(config_path)
                        && !crate::utils::resolvconf_works()
                    {
                        if crate::utils::is_systemd_resolved() {
                            missing.push("resolvconf (systemd)".to_string());
                        } else {
                            missing.push("resolvconf".to_string());
                        }
                    }
                }
            }
            Protocol::OpenVPN => {
                if !crate::utils::binary_exists("openvpn") {
                    missing.push("openvpn".to_string());
                }
            }
        }

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

    match engine.connect_and_wait(&profile_name, Duration::from_secs(timeout_secs)) {
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

#[derive(Serialize)]
struct DownData {
    state: String,
}

fn handle_down(force: bool, config: &AppConfig, config_dir: &Path, mode: OutputMode) -> i32 {
    let mut engine = VpnEngine::new_headless(config.clone(), config_dir.to_path_buf());

    // Discover active connections via scanner
    let active = crate::core::scanner::get_active_profiles(&engine.profiles);
    if active.is_empty() {
        // Idempotent: already disconnected = success
        let data = DownData {
            state: "disconnected".into(),
        };
        match mode {
            OutputMode::Human => println!("Already disconnected"),
            OutputMode::Json => print_success(mode, "down", &data, vec![]),
            OutputMode::Quiet => {}
        }
        return 0;
    }

    // Set engine state to Connected so disconnect_and_wait works
    if let Some(session) = active.first() {
        engine.connection_state = crate::state::ConnectionState::Connected {
            profile: session.name.clone(),
            server_location: String::new(),
            since: std::time::Instant::now(),
            latency_ms: 0,
            details: Box::new(crate::state::DetailedConnectionInfo {
                pid: session.pid,
                interface: session.interface.clone(),
                endpoint: session.endpoint.clone(),
                ..Default::default()
            }),
        };
    }

    if !engine.is_root {
        print_error_and_exit(
            mode,
            "down",
            err_permission_denied("vortix down"),
            ExitCode::PermissionDenied,
        );
    }

    match engine.disconnect_and_wait(force, Duration::from_secs(20)) {
        Ok(()) => {
            let data = DownData {
                state: "disconnected".into(),
            };
            match mode {
                OutputMode::Human => println!("Disconnected"),
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
        Err(e) => {
            print_error_and_exit(
                mode,
                "down",
                CliError {
                    code: "disconnect_failed",
                    message: e,
                    hint: if force {
                        None
                    } else {
                        Some("Try: sudo vortix down --force".into())
                    },
                },
                ExitCode::GeneralError,
            );
        }
    }
}

fn handle_reconnect(config: &AppConfig, config_dir: &Path, mode: OutputMode) -> i32 {
    let mut engine = VpnEngine::new_headless(config.clone(), config_dir.to_path_buf());
    engine.load_metadata();

    let last = engine
        .profiles
        .iter()
        .filter(|p| p.last_used.is_some())
        .max_by_key(|p| p.last_used)
        .map(|p| p.name.clone());

    match last {
        Some(name) => {
            // Disconnect first if needed
            let active = crate::core::scanner::get_active_profiles(&engine.profiles);
            if !active.is_empty() {
                if let Some(session) = active.first() {
                    engine.connection_state = crate::state::ConnectionState::Connected {
                        profile: session.name.clone(),
                        server_location: String::new(),
                        since: std::time::Instant::now(),
                        latency_ms: 0,
                        details: Box::new(crate::state::DetailedConnectionInfo {
                            pid: session.pid,
                            interface: session.interface.clone(),
                            ..Default::default()
                        }),
                    };
                    let _ = engine.disconnect_and_wait(false, Duration::from_secs(15));
                }
            }
            handle_up(Some(&name), 20, config, config_dir, mode)
        }
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
}

// ── Status ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct StatusData {
    connection: StatusConnection,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<StatusNetwork>,
    security: StatusSecurity,
}

#[derive(Serialize)]
struct StatusConnection {
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uptime_secs: Option<u64>,
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

fn handle_status(
    watch: bool,
    interval: u64,
    brief: bool,
    config: &AppConfig,
    config_dir: &Path,
    mode: OutputMode,
) -> i32 {
    let engine = VpnEngine::new_headless(config.clone(), config_dir.to_path_buf());
    let snap = engine.scan_status();

    if watch {
        return run_watch(interval, config, config_dir, mode);
    }

    let is_connected = snap.connection_state == "connected";

    let data = StatusData {
        connection: StatusConnection {
            state: snap.connection_state.clone(),
            profile: snap.profile.clone(),
            protocol: snap.protocol.clone(),
            uptime_secs: snap.uptime_secs,
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
            killswitch_mode: snap.killswitch_mode.clone(),
            killswitch_state: snap.killswitch_state.clone(),
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
                    snap.killswitch_mode, snap.killswitch_state
                );
            } else {
                println!("○ Disconnected");
                println!();
                println!(
                    "  Kill Switch  {} ({})",
                    snap.killswitch_mode, snap.killswitch_state
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

fn run_watch(interval: u64, config: &AppConfig, config_dir: &Path, mode: OutputMode) -> i32 {
    loop {
        let engine = VpnEngine::new_headless(config.clone(), config_dir.to_path_buf());
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
    #[serde(skip_serializing_if = "Option::is_none")]
    last_used: Option<String>,
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
    let mut engine = VpnEngine::new_headless(config.clone(), config_dir.to_path_buf());
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

    let entries: Vec<ProfileEntry> = profiles
        .iter()
        .map(|p| ProfileEntry {
            name: p.name.clone(),
            protocol: format!("{}", p.protocol),
            last_used: p
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
        })
        .collect();

    // Discover which profile is currently active
    let active = crate::core::scanner::get_active_profiles(&engine.profiles);
    let active_name = active.first().map(|s| s.name.as_str());

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
                let marker = if active_name == Some(entry.name.as_str()) {
                    "●"
                } else {
                    " "
                };
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
    let engine = VpnEngine::new_headless(config.clone(), config_dir.to_path_buf());
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
    let mut engine = VpnEngine::new_headless(config.clone(), config_dir.to_path_buf());

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
    let mut engine = VpnEngine::new_headless(config.clone(), config_dir.to_path_buf());

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
    let mut engine = VpnEngine::new_headless(config.clone(), config_dir.to_path_buf());

    if let Some(new_mode) = mode_arg {
        let ks_mode = match new_mode.to_lowercase().as_str() {
            "off" => crate::state::KillSwitchMode::Off,
            "auto" => crate::state::KillSwitchMode::Auto,
            "always" | "always-on" => crate::state::KillSwitchMode::AlwaysOn,
            other => {
                print_error_and_exit(
                    output_mode,
                    "killswitch",
                    CliError {
                        code: "invalid_mode",
                        message: format!("Unknown mode '{other}'. Use: off, auto, always"),
                        hint: None,
                    },
                    ExitCode::GeneralError,
                );
            }
        };

        if !engine.is_root && ks_mode != crate::state::KillSwitchMode::Off {
            print_error_and_exit(
                output_mode,
                "killswitch",
                err_permission_denied(&format!("vortix killswitch {new_mode}")),
                ExitCode::PermissionDenied,
            );
        }

        engine.killswitch_mode = ks_mode;
        engine.sync_killswitch();
    }

    let data = KsData {
        mode: format!("{:?}", engine.killswitch_mode).to_lowercase(),
        state: format!("{:?}", engine.killswitch_state).to_lowercase(),
    };

    match output_mode {
        OutputMode::Human => {
            println!("Kill Switch: {} ({})", data.mode, data.state);
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

    let status = std::process::Command::new("cargo")
        .args(["install", "vortix", "--force"])
        .status();

    match status {
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
}
