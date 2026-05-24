//! CLI integration tests.
//!
//! These tests verify the CLI output layer, `VpnEngine` headless mode, and
//! command handlers without requiring root, VPN tools, or network access.

use vortix::cli::output::{error_response, CliError, CliResponse, ExitCode, OutputMode};
use vortix::engine::VpnEngine;
use vortix::state::{ConnectionState, KillSwitchMode, KillSwitchState, Protocol, VpnProfile};

// ============================================================================
// VpnEngine headless mode
// ============================================================================

#[test]
fn engine_new_headless_starts_disconnected() {
    let config = vortix::config::AppConfig::default();
    let dir = tempfile::tempdir().unwrap();
    let engine = VpnEngine::new_headless(config, dir.path().to_path_buf());
    assert!(matches!(
        engine.connection_state,
        ConnectionState::Disconnected
    ));
    assert!(!engine.is_root); // tests run unprivileged
}

#[test]
fn engine_new_test_has_empty_profiles() {
    let engine = VpnEngine::new_test();
    assert!(engine.profiles.is_empty());
    assert!(engine.session_start.is_none());
    assert_eq!(engine.killswitch_mode, KillSwitchMode::Off);
    assert_eq!(engine.killswitch_state, KillSwitchState::Disabled);
}

#[test]
fn engine_find_profile_by_name() {
    let mut engine = VpnEngine::new_test();
    engine.profiles.push(VpnProfile {
        name: "work-vpn".into(),
        protocol: Protocol::WireGuard,
        config_path: "/tmp/work.conf".into(),
        location: "US".into(),
        last_used: None,
    });
    engine.profiles.push(VpnProfile {
        name: "personal".into(),
        protocol: Protocol::OpenVPN,
        config_path: "/tmp/personal.ovpn".into(),
        location: "EU".into(),
        last_used: None,
    });

    assert_eq!(engine.find_profile("work-vpn"), Some(0));
    assert_eq!(engine.find_profile("personal"), Some(1));
    assert_eq!(engine.find_profile("nonexistent"), None);
}

#[test]
fn engine_sort_profiles_by_name() {
    let mut engine = VpnEngine::new_test();
    for name in &["charlie", "alpha", "bravo"] {
        engine.profiles.push(VpnProfile {
            name: (*name).into(),
            protocol: Protocol::WireGuard,
            config_path: format!("/tmp/{name}.conf").into(),
            location: "Test".into(),
            last_used: None,
        });
    }

    engine.sort_order = vortix::state::ProfileSortOrder::NameAsc;
    engine.sort_profiles();
    assert_eq!(engine.profiles[0].name, "alpha");
    assert_eq!(engine.profiles[1].name, "bravo");
    assert_eq!(engine.profiles[2].name, "charlie");

    engine.sort_order = vortix::state::ProfileSortOrder::NameDesc;
    engine.sort_profiles();
    assert_eq!(engine.profiles[0].name, "charlie");
}

#[test]
fn engine_sort_profiles_by_protocol() {
    let mut engine = VpnEngine::new_test();
    engine.profiles.push(VpnProfile {
        name: "ovpn-profile".into(),
        protocol: Protocol::OpenVPN,
        config_path: "/tmp/a.ovpn".into(),
        location: "EU".into(),
        last_used: None,
    });
    engine.profiles.push(VpnProfile {
        name: "wg-profile".into(),
        protocol: Protocol::WireGuard,
        config_path: "/tmp/b.conf".into(),
        location: "US".into(),
        last_used: None,
    });

    engine.sort_order = vortix::state::ProfileSortOrder::Protocol;
    engine.sort_profiles();
    assert_eq!(engine.profiles[0].protocol, Protocol::WireGuard);
    assert_eq!(engine.profiles[1].protocol, Protocol::OpenVPN);
}

#[test]
fn engine_check_dependencies_wireguard() {
    // Use a dummy config path — the resolvconf check only matters on Linux
    let dummy = std::path::Path::new("/dev/null");
    let missing = VpnEngine::check_dependencies(Protocol::WireGuard, dummy);
    // In test env, wg-quick/wg may or may not be available; just ensure no panic
    assert!(missing.len() <= 3); // wg-quick, wg, and possibly resolvconf on Linux
}

#[test]
fn engine_scan_status_when_disconnected() {
    let engine = VpnEngine::new_test();
    let snap = engine.scan_status();
    assert_eq!(snap.connection_state, "disconnected");
    assert!(snap.profile.is_none());
    assert!(snap.uptime_secs.is_none());
}

// ============================================================================
// CLI Output layer
// ============================================================================

#[test]
fn cli_response_success_serializes() {
    #[derive(serde::Serialize)]
    struct TestData {
        value: u32,
    }
    let resp = CliResponse::success("test", TestData { value: 42 }, vec!["next".into()]);
    assert!(resp.ok);
    assert_eq!(resp.command, "test");
    assert!(resp.error.is_none());
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("\"ok\":true"));
    assert!(json.contains("\"value\":42"));
    assert!(json.contains("next"));
}

#[test]
fn cli_response_error_serializes() {
    let resp = error_response(
        "up",
        CliError {
            code: "permission_denied",
            message: "Needs root".into(),
            hint: Some("sudo vortix up".into()),
        },
    );
    assert!(!resp.ok);
    assert_eq!(resp.command, "up");
    assert!(resp.data.is_none());
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("\"ok\":false"));
    assert!(json.contains("permission_denied"));
    assert!(json.contains("sudo vortix up"));
}

#[test]
fn exit_codes_are_semantic() {
    assert_eq!(ExitCode::Success.code(), 0);
    assert_eq!(ExitCode::GeneralError.code(), 1);
    assert_eq!(ExitCode::PermissionDenied.code(), 2);
    assert_eq!(ExitCode::NotFound.code(), 3);
    assert_eq!(ExitCode::StateConflict.code(), 4);
    assert_eq!(ExitCode::DependencyMissing.code(), 5);
    assert_eq!(ExitCode::Timeout.code(), 6);
}

#[test]
fn output_mode_variants() {
    assert_eq!(OutputMode::Human, OutputMode::Human);
    assert_ne!(OutputMode::Human, OutputMode::Json);
    assert_ne!(OutputMode::Json, OutputMode::Quiet);
}

#[test]
fn err_not_found_helper() {
    let err = vortix::cli::output::err_not_found("my-vpn");
    assert_eq!(err.code, "not_found");
    assert!(err.message.contains("my-vpn"));
    assert!(err.hint.is_some());
}

#[test]
fn err_permission_denied_helper() {
    let err = vortix::cli::output::err_permission_denied("vortix up test");
    assert_eq!(err.code, "permission_denied");
    assert!(err.hint.unwrap().contains("sudo"));
}

// ============================================================================
// CLI command handler tests (non-privileged)
// ============================================================================

#[test]
fn cli_list_empty_profiles() {
    use vortix::cli::args::Commands;
    use vortix::cli::commands::handle_command;

    let dir = tempfile::tempdir().unwrap();
    let config = vortix::config::AppConfig::default();

    let exit = handle_command(
        &Commands::List {
            sort: None,
            reverse: false,
            protocol: None,
            names_only: false,
        },
        dir.path(),
        "test",
        &config,
        OutputMode::Quiet,
    );
    assert_eq!(exit, 0);
}

#[test]
fn cli_info_runs_without_error() {
    use vortix::cli::args::Commands;
    use vortix::cli::commands::handle_command;

    let dir = tempfile::tempdir().unwrap();
    let config = vortix::config::AppConfig::default();

    let exit = handle_command(
        &Commands::Info,
        dir.path(),
        "test",
        &config,
        OutputMode::Quiet,
    );
    assert_eq!(exit, 0);
}

#[test]
fn cli_status_disconnected() {
    use vortix::cli::args::Commands;
    use vortix::cli::commands::handle_command;

    let dir = tempfile::tempdir().unwrap();
    let config = vortix::config::AppConfig::default();

    let exit = handle_command(
        &Commands::Status {
            watch: false,
            interval: 2,
            brief: true,
        },
        dir.path(),
        "test",
        &config,
        OutputMode::Quiet,
    );
    assert_eq!(exit, 0);
}

#[test]
fn cli_killswitch_show_mode() {
    use vortix::cli::args::Commands;
    use vortix::cli::commands::handle_command;

    let dir = tempfile::tempdir().unwrap();
    let config = vortix::config::AppConfig::default();

    let exit = handle_command(
        &Commands::KillSwitch { mode: None },
        dir.path(),
        "test",
        &config,
        OutputMode::Quiet,
    );
    assert_eq!(exit, 0);
}

#[test]
fn cli_release_killswitch() {
    use vortix::cli::args::Commands;
    use vortix::cli::commands::handle_command;

    let dir = tempfile::tempdir().unwrap();
    let config = vortix::config::AppConfig::default();

    let exit = handle_command(
        &Commands::ReleaseKillSwitch,
        dir.path(),
        "test",
        &config,
        OutputMode::Quiet,
    );
    assert_eq!(exit, 0);
}

#[test]
fn cli_import_single_file() {
    use vortix::cli::args::Commands;
    use vortix::cli::commands::handle_command;

    let dir = tempfile::tempdir().unwrap();
    let config_dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("test.conf");
    std::fs::write(
        &conf,
        "[Interface]\nPrivateKey = abc=\nAddress = 10.0.0.1/24\n\n[Peer]\nPublicKey = xyz=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n",
    )
    .unwrap();

    // Point the global config dir to a temp directory so import_profile()
    // doesn't write to the real ~/.config/vortix/profiles/.
    std::env::set_var("VORTIX_CONFIG_DIR", config_dir.path());

    let config = vortix::config::AppConfig::default();
    let exit = handle_command(
        &Commands::Import {
            file: conf.to_string_lossy().to_string(),
        },
        config_dir.path(),
        "test",
        &config,
        OutputMode::Quiet,
    );

    std::env::remove_var("VORTIX_CONFIG_DIR");
    assert_eq!(exit, 0, "Importing a valid profile should succeed");

    // Verify the profile landed in the temp dir, not the real config
    let profiles_dir = config_dir.path().join("profiles");
    assert!(profiles_dir.join("test.conf").exists());
}

// ============================================================================
// Clap argument parsing
// ============================================================================

#[test]
fn clap_parses_no_args() {
    use clap::Parser;
    use vortix::cli::args::Args;

    let args = Args::try_parse_from(["vortix"]).unwrap();
    assert!(args.command.is_none());
    assert!(!args.json);
    assert!(!args.quiet);
}

#[test]
fn clap_parses_status_json() {
    use clap::Parser;
    use vortix::cli::args::Args;

    let args = Args::try_parse_from(["vortix", "--json", "status"]).unwrap();
    assert!(args.json);
    assert!(args.command.is_some());
}

#[test]
fn clap_parses_up_with_options() {
    use clap::Parser;
    use vortix::cli::args::{Args, Commands};

    let args = Args::try_parse_from(["vortix", "up", "work-vpn", "--timeout", "60"]).unwrap();
    if let Some(Commands::Up {
        profile, timeout, ..
    }) = args.command
    {
        assert_eq!(profile.as_deref(), Some("work-vpn"));
        assert_eq!(timeout, 60);
    } else {
        panic!("Expected Up command");
    }
}

#[test]
fn clap_parses_list_with_filters() {
    use clap::Parser;
    use vortix::cli::args::{Args, Commands};

    let args = Args::try_parse_from([
        "vortix",
        "list",
        "--sort",
        "last-used",
        "--protocol",
        "wireguard",
        "--names-only",
    ])
    .unwrap();
    if let Some(Commands::List {
        sort,
        protocol,
        names_only,
        ..
    }) = args.command
    {
        assert_eq!(sort.as_deref(), Some("last-used"));
        assert_eq!(protocol.as_deref(), Some("wireguard"));
        assert!(names_only);
    } else {
        panic!("Expected List command");
    }
}

#[test]
fn clap_parses_down_force() {
    use clap::Parser;
    use vortix::cli::args::{Args, Commands};

    let args = Args::try_parse_from(["vortix", "down", "--force"]).unwrap();
    if let Some(Commands::Down { force, .. }) = args.command {
        assert!(force);
    } else {
        panic!("Expected Down command");
    }
}

#[test]
fn clap_parses_delete_with_yes() {
    use clap::Parser;
    use vortix::cli::args::{Args, Commands};

    let args = Args::try_parse_from(["vortix", "delete", "old-vpn", "--yes"]).unwrap();
    if let Some(Commands::Delete { profile, yes }) = args.command {
        assert_eq!(profile, "old-vpn");
        assert!(yes);
    } else {
        panic!("Expected Delete command");
    }
}

#[test]
fn clap_parses_rename() {
    use clap::Parser;
    use vortix::cli::args::{Args, Commands};

    let args = Args::try_parse_from(["vortix", "rename", "old", "new"]).unwrap();
    if let Some(Commands::Rename { old, new }) = args.command {
        assert_eq!(old, "old");
        assert_eq!(new, "new");
    } else {
        panic!("Expected Rename command");
    }
}

#[test]
fn clap_parses_completions() {
    use clap::Parser;
    use vortix::cli::args::{Args, Commands};

    let args = Args::try_parse_from(["vortix", "completions", "bash"]).unwrap();
    assert!(matches!(args.command, Some(Commands::Completions { .. })));
}

#[test]
fn clap_visible_aliases_work() {
    use clap::Parser;
    use vortix::cli::args::{Args, Commands};

    // "connect" is an alias for "up"
    let args = Args::try_parse_from(["vortix", "connect", "test-vpn"]).unwrap();
    assert!(matches!(args.command, Some(Commands::Up { .. })));

    // "disconnect" is an alias for "down"
    let args = Args::try_parse_from(["vortix", "disconnect"]).unwrap();
    assert!(matches!(args.command, Some(Commands::Down { .. })));

    // "ls" is an alias for "list"
    let args = Args::try_parse_from(["vortix", "ls"]).unwrap();
    assert!(matches!(args.command, Some(Commands::List { .. })));

    // "rm" is an alias for "delete"
    let args = Args::try_parse_from(["vortix", "rm", "test"]).unwrap();
    assert!(matches!(args.command, Some(Commands::Delete { .. })));

    // "mv" is an alias for "rename"
    let args = Args::try_parse_from(["vortix", "mv", "old", "new"]).unwrap();
    assert!(matches!(args.command, Some(Commands::Rename { .. })));
}

#[test]
fn clap_global_flags_propagate() {
    use clap::Parser;
    use vortix::cli::args::Args;

    let args =
        Args::try_parse_from(["vortix", "--json", "--quiet", "--verbose", "status"]).unwrap();
    assert!(args.json);
    assert!(args.quiet);
    assert!(args.verbose);
}
