//! Profile commands: list, import, show, delete, rename.

use std::path::Path;

use serde::Serialize;

use super::commands::acquire_lifecycle_lock_or_exit;
use crate::cli::output::{
    err_not_found, print_error_and_exit, print_success, CliError, ExitCode, OutputMode,
};
use crate::config::profile_store::FsProfileStore;
use crate::config::AppConfig;
use crate::constants;
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
pub(super) fn handle_list(
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

pub(super) fn handle_import(
    file: &str,
    config: &AppConfig,
    config_dir: &Path,
    mode: OutputMode,
) -> i32 {
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
                if path.is_file() && crate::profile::has_profile_extension(&path) {
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

pub(super) fn handle_show(profile_name: &str, raw: bool, mode: OutputMode) -> i32 {
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

pub(super) fn require_profile_inactive(
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

pub(super) fn handle_delete(
    profile_name: &str,
    yes: bool,
    config_dir: &Path,
    mode: OutputMode,
) -> i32 {
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
pub(super) fn handle_rename(old: &str, new: &str, config_dir: &Path, mode: OutputMode) -> i32 {
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
                    "'{trimmed}' is not a usable profile name. WireGuard names must be 1–15 characters using only letters, numbers, _, ., or -."
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
