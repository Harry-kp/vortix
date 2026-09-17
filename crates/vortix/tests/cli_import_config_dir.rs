//! Import/rename/delete against a temp config dir.
//!
//! Lives in its own binary on purpose. It points `VORTIX_CONFIG_DIR` at a
//! temp directory because the control-plane import resolves the profiles
//! directory through it, and `set_var` mutates state shared by every thread
//! in the process. Rust runs a binary's tests concurrently, so alongside
//! other tests this races their `getenv`; on macOS that aborted the whole
//! `cli_integration` binary with exit status 4 rather than failing a test.
//! One test per binary means there is no concurrent reader to race.

use vortix::cli::output::OutputMode;

#[test]
fn cli_import_single_file() {
    use vortix::cli::args::Commands;
    use vortix::cli::commands::handle_command;
    use vortix::vortix_config::profile_store::FsProfileStore;
    use vortix::vortix_config::ProfileStore as _;

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
        &vortix::vortix_config::Settings::default(),
        OutputMode::Quiet,
    );

    assert_eq!(exit, 0, "Importing a valid profile should succeed");

    // Verify the profile landed in the temp dir, not the real config
    let profiles_dir = config_dir.path().join("profiles");
    assert!(profiles_dir.join("test.conf").exists());
    let persisted = std::fs::read_to_string(config_dir.path().join("control/control-state.json"))
        .expect("typed import persists its terminal operation");
    assert!(
        persisted.contains("\"status\": \"succeeded\""),
        "terminal import must be durable before CLI success: {persisted}"
    );

    let store = FsProfileStore::new(profiles_dir.clone());
    let stable_id = store.resolve_display_name("test").unwrap();
    let persisted_json: serde_json::Value = serde_json::from_str(&persisted).unwrap();
    assert!(
        persisted_json["requested_resources"]
            .get(stable_id.as_str())
            .is_some(),
        "terminal import must persist canonical requested resources"
    );
    let rename = handle_command(
        &Commands::Rename {
            old: "test".to_owned(),
            new: "work".to_owned(),
        },
        config_dir.path(),
        "test",
        &config,
        &vortix::vortix_config::Settings::default(),
        OutputMode::Quiet,
    );
    assert_eq!(rename, 0, "typed rename should preserve the CLI result");
    assert_eq!(store.resolve_display_name("work").unwrap(), stable_id);
    assert!(profiles_dir.join("work.conf").exists());

    let delete = handle_command(
        &Commands::Delete {
            profile: "work".to_owned(),
            yes: true,
        },
        config_dir.path(),
        "test",
        &config,
        &vortix::vortix_config::Settings::default(),
        OutputMode::Quiet,
    );
    assert_eq!(delete, 0, "typed delete should preserve the CLI result");
    assert!(!profiles_dir.join("work.conf").exists());
    std::env::remove_var("VORTIX_CONFIG_DIR");
}
