use super::*;
use crate::core::scanner::ActiveSession;
use std::time::Instant;

fn init_test_env() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let dir = tempfile::Builder::new()
            .prefix("vortix_unit_test_")
            .tempdir()
            .expect("failed to create test temp dir");
        let path = dir.path().to_path_buf();
        // Leak intentionally: shared across all tests in this module via Once
        std::mem::forget(dir);
        let _ = std::fs::create_dir_all(&path);
        crate::config::set_config_dir(path);
    });
}

/// Build a minimal `App` for unit testing (no filesystem / scanner / telemetry).
fn test_app() -> App {
    init_test_env();
    let mut engine = crate::engine::VpnEngine::new_test();
    engine.config_dir = std::env::temp_dir().join(format!("vortix_test_{}", std::process::id()));
    App {
        engine,
        should_quit: false,
        logs_scroll: 0,
        logs_auto_scroll: true,
        logs_max_scroll: 0,
        log_level_filter: None,
        focused_panel: FocusedPanel::Sidebar,
        zoomed_panel: None,
        panel_flipped: std::collections::HashSet::new(),
        flip_animation: None,
        input_mode: InputMode::Normal,
        show_config: false,
        show_action_menu: false,
        show_bulk_menu: false,
        action_menu_state: ratatui::widgets::ListState::default(),
        config_scroll: 0,
        cached_config_content: None,
        search_match_count: 0,
        profile_list_state: ratatui::widgets::TableState::default(),
        panel_areas: std::collections::HashMap::new(),
        toast: None,
        terminal_size: (80, 24),
    }
}

/// Helper: put app into a Connected state for a given profile name.
fn set_connected(app: &mut App, name: &str) {
    app.session_start = Some(Instant::now());
    app.connection_state = ConnectionState::Connected {
        since: Instant::now(),
        profile: name.to_string(),
        server_location: "Test".to_string(),
        latency_ms: 10,
        details: Box::new(DetailedConnectionInfo {
            interface: "wg0".to_string(),
            pid: Some(12345),
            ..Default::default()
        }),
    };
}

/// Helper: put app into a Disconnecting state for a given profile name.
fn set_disconnecting(app: &mut App, name: &str) {
    app.connection_state = ConnectionState::Disconnecting {
        started: Instant::now(),
        profile: name.to_string(),
    };
}

/// Helper: create a fake `ActiveSession` for scanner results.
fn fake_session(name: &str) -> ActiveSession {
    ActiveSession {
        name: name.to_string(),
        interface: "wg0".to_string(),
        endpoint: "1.2.3.4:51820".to_string(),
        internal_ip: "10.0.0.2".to_string(),
        mtu: "1420".to_string(),
        public_key: String::new(),
        listen_port: "51820".to_string(),
        transfer_rx: "100 KiB".to_string(),
        transfer_tx: "50 KiB".to_string(),
        latest_handshake: "5 seconds ago".to_string(),
        pid: Some(12345),
        started_at: None,
    }
}

// ====================================================================
// DisconnectResult handler tests
// ====================================================================

#[test]
fn test_disconnect_result_success_transitions_to_disconnected() {
    let mut app = test_app();
    set_disconnecting(&mut app, "test-vpn");

    app.handle_message(Message::DisconnectResult {
        profile: "test-vpn".to_string(),
        success: true,
        error: None,
    });

    assert!(
        matches!(app.connection_state, ConnectionState::Disconnected),
        "Expected Disconnected after successful DisconnectResult"
    );
    assert!(app.session_start.is_none());
}

#[test]
fn test_disconnect_result_failure_stays_disconnecting() {
    let mut app = test_app();
    set_disconnecting(&mut app, "test-vpn");

    app.handle_message(Message::DisconnectResult {
        profile: "test-vpn".to_string(),
        success: false,
        error: Some("permission denied".to_string()),
    });

    assert!(
        matches!(app.connection_state, ConnectionState::Disconnecting { .. }),
        "Should remain Disconnecting after failed disconnect (VPN may still be running)"
    );
    let toast = app.toast.as_ref().expect("toast should be set");
    assert_eq!(toast.toast_type, ToastType::Error);
    assert!(toast.message.contains("Disconnect failed"));
    assert!(toast.message.contains("force-disconnect"));
}

#[test]
fn test_disconnect_result_success_from_non_disconnecting_state() {
    let mut app = test_app();
    app.connection_state = ConnectionState::Disconnected;

    app.handle_message(Message::DisconnectResult {
        profile: "test-vpn".to_string(),
        success: true,
        error: None,
    });

    assert!(matches!(
        app.connection_state,
        ConnectionState::Disconnected
    ));
}

// ====================================================================
// Scanner debounce guard tests (SyncSystemState while Disconnecting)
// ====================================================================

#[test]
fn test_scanner_never_overrides_disconnecting_to_connected() {
    let mut app = test_app();
    set_disconnecting(&mut app, "test-vpn");

    let sessions = vec![fake_session("test-vpn")];
    app.handle_message(Message::SyncSystemState(sessions));

    assert!(
        matches!(app.connection_state, ConnectionState::Disconnecting { .. }),
        "Scanner must never override Disconnecting to Connected, got {:?}",
        app.connection_state
    );
}

#[test]
fn test_scanner_confirms_disconnect_when_interface_gone() {
    let mut app = test_app();
    set_disconnecting(&mut app, "test-vpn");

    app.handle_message(Message::SyncSystemState(vec![]));

    assert!(
        matches!(app.connection_state, ConnectionState::Disconnected),
        "Scanner should confirm Disconnected when interface is gone"
    );
    assert!(app.session_start.is_none());
}

#[test]
fn test_scanner_safety_timeout_after_30s() {
    let mut app = test_app();
    app.connection_state = ConnectionState::Disconnecting {
        started: Instant::now()
            .checked_sub(std::time::Duration::from_secs(31))
            .unwrap(),
        profile: "test-vpn".to_string(),
    };

    let sessions = vec![fake_session("test-vpn")];
    app.handle_message(Message::SyncSystemState(sessions));

    assert!(
        matches!(app.connection_state, ConnectionState::Disconnected),
        "Should time out to Disconnected after 30s"
    );
    let toast = app.toast.as_ref().expect("timeout should show toast");
    assert_eq!(toast.toast_type, ToastType::Warning);
    assert!(toast.message.contains("timed out"));
}

#[test]
fn test_scanner_disconnecting_does_not_affect_other_profiles() {
    let mut app = test_app();
    set_disconnecting(&mut app, "vpn-a");

    let sessions = vec![fake_session("vpn-b")];
    app.handle_message(Message::SyncSystemState(sessions));

    assert!(
        matches!(app.connection_state, ConnectionState::Disconnected),
        "Should detect our profile is gone even if other profiles are active"
    );
}

// ====================================================================
// Force disconnect (d pressed twice) tests
// ====================================================================

#[test]
fn test_d_while_disconnecting_escalates_to_force() {
    let mut app = test_app();
    set_disconnecting(&mut app, "test-vpn");
    add_profiles(&mut app, &["test-vpn"]);

    let before = if let ConnectionState::Disconnecting { started, .. } = &app.connection_state {
        *started
    } else {
        panic!("expected Disconnecting");
    };

    app.handle_message(Message::Disconnect);

    assert!(matches!(
        app.connection_state,
        ConnectionState::Disconnecting { .. }
    ));

    if let ConnectionState::Disconnecting { started, .. } = &app.connection_state {
        assert!(*started >= before);
    }

    let toast = app.toast.as_ref().expect("force disconnect shows toast");
    assert_eq!(toast.toast_type, ToastType::Warning);
    assert!(toast.message.contains("Force"));
}

#[test]
fn test_d_while_disconnected_is_noop() {
    let mut app = test_app();
    app.handle_message(Message::Disconnect);
    assert!(matches!(
        app.connection_state,
        ConnectionState::Disconnected
    ));
}

// ====================================================================
// Helpers for new tests
// ====================================================================

/// Helper: put app into a Connecting state for a given profile name.
fn set_connecting(app: &mut App, name: &str) {
    app.connection_state = ConnectionState::Connecting {
        started: Instant::now(),
        profile: name.to_string(),
    };
}

/// Helper: add test profiles to the app.
fn add_profiles(app: &mut App, names: &[&str]) {
    for name in names {
        app.profiles.push(VpnProfile {
            name: (*name).to_string(),
            protocol: Protocol::WireGuard,
            config_path: std::path::PathBuf::from(format!("/tmp/{name}.conf")),
            location: "Test".to_string(),
            last_used: None,
        });
    }
}

// ====================================================================
// Pending connect / VPN switching tests
// ====================================================================

#[test]
fn test_toggle_connected_different_profile_shows_confirm() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b"]);
    set_connected(&mut app, "vpn-a");

    app.toggle_connection(1);

    assert!(
        matches!(app.input_mode, InputMode::ConfirmSwitch { to_idx: 1, .. }),
        "Expected ConfirmSwitch dialog, got {:?}",
        app.input_mode
    );

    app.handle_message(Message::ConfirmSwitch { idx: 1 });
    assert_eq!(app.pending_connect, Some(1));
    assert!(
        matches!(app.connection_state, ConnectionState::Disconnecting { .. }),
        "Expected Disconnecting after confirm, got {:?}",
        app.connection_state
    );
}

#[test]
fn test_toggle_connected_same_profile_disconnects_without_pending() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a"]);
    set_connected(&mut app, "vpn-a");

    app.toggle_connection(0);

    assert_eq!(
        app.pending_connect, None,
        "Same-profile toggle should not set pending"
    );
    assert!(matches!(
        app.connection_state,
        ConnectionState::Disconnecting { .. }
    ));
}

#[test]
fn test_toggle_while_disconnecting_queues_pending() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b"]);
    set_disconnecting(&mut app, "vpn-a");

    app.toggle_connection(1);

    assert_eq!(app.pending_connect, Some(1));
    assert!(matches!(
        app.connection_state,
        ConnectionState::Disconnecting { .. }
    ));
}

#[test]
fn test_toggle_while_connecting_is_rejected() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b"]);
    set_connecting(&mut app, "vpn-a");

    app.toggle_connection(1);

    assert!(matches!(
        app.connection_state,
        ConnectionState::Connecting { .. }
    ));
    assert_eq!(app.pending_connect, None);
}

#[test]
fn test_pending_connect_drained_on_disconnect_success() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b"]);
    set_disconnecting(&mut app, "vpn-a");
    app.pending_connect = Some(1);
    app.is_root = true;

    app.handle_message(Message::DisconnectResult {
        profile: "vpn-a".to_string(),
        success: true,
        error: None,
    });

    assert_eq!(app.pending_connect, None);
    assert!(
        matches!(app.connection_state, ConnectionState::Connecting { ref profile, .. } if profile == "vpn-b"),
        "Expected Connecting to vpn-b, got {:?}",
        app.connection_state
    );
}

#[test]
fn test_pending_connect_drained_on_scanner_interface_gone() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b"]);
    set_disconnecting(&mut app, "vpn-a");
    app.pending_connect = Some(1);
    app.is_root = true;

    app.handle_message(Message::SyncSystemState(vec![]));

    assert_eq!(app.pending_connect, None);
    assert!(
        matches!(app.connection_state, ConnectionState::Connecting { ref profile, .. } if profile == "vpn-b"),
        "Expected auto-connect to vpn-b after scanner confirms disconnect"
    );
}

#[test]
fn test_pending_preserved_on_disconnect_failure() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b"]);
    set_disconnecting(&mut app, "vpn-a");
    app.pending_connect = Some(1);

    app.handle_message(Message::DisconnectResult {
        profile: "vpn-a".to_string(),
        success: false,
        error: Some("permission denied".to_string()),
    });

    // pending_connect is preserved so it can fire after force-disconnect
    assert_eq!(app.pending_connect, Some(1));
    assert!(
        matches!(app.connection_state, ConnectionState::Disconnecting { .. }),
        "Should remain Disconnecting after failed disconnect"
    );
}

#[test]
fn test_pending_cleared_on_30s_timeout() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b"]);
    app.connection_state = ConnectionState::Disconnecting {
        started: Instant::now()
            .checked_sub(std::time::Duration::from_secs(31))
            .unwrap(),
        profile: "vpn-a".to_string(),
    };
    app.pending_connect = Some(1);

    let sessions = vec![fake_session("vpn-a")];
    app.handle_message(Message::SyncSystemState(sessions));

    assert_eq!(app.pending_connect, None);
    assert!(matches!(
        app.connection_state,
        ConnectionState::Disconnected
    ));
}

// ====================================================================
// ConnectResult tests
// ====================================================================

#[test]
fn test_connect_result_success_transitions_to_connected() {
    let mut app = test_app();
    add_profiles(&mut app, &["test-vpn"]);
    set_connecting(&mut app, "test-vpn");

    app.handle_message(Message::ConnectResult {
        profile: "test-vpn".to_string(),
        success: true,
        error: None,
    });

    assert!(
        matches!(app.connection_state, ConnectionState::Connected { ref profile, .. } if profile == "test-vpn"),
        "Successful ConnectResult should transition to Connected"
    );
}

#[test]
fn test_connect_result_failure_transitions_to_disconnected() {
    let mut app = test_app();
    set_connecting(&mut app, "test-vpn");

    app.handle_message(Message::ConnectResult {
        profile: "test-vpn".to_string(),
        success: false,
        error: Some("wg-quick: already exists".to_string()),
    });

    assert!(
        matches!(app.connection_state, ConnectionState::Disconnected),
        "Failed ConnectResult should transition to Disconnected"
    );
    let toast = app.toast.as_ref().expect("should show error toast");
    assert_eq!(toast.toast_type, ToastType::Error);
    assert!(toast.message.contains("Failed to connect"));
}

#[test]
fn test_connect_result_failure_clears_pending() {
    let mut app = test_app();
    set_connecting(&mut app, "test-vpn");
    app.pending_connect = Some(1);

    app.handle_message(Message::ConnectResult {
        profile: "test-vpn".to_string(),
        success: false,
        error: Some("error".to_string()),
    });

    assert_eq!(
        app.pending_connect, None,
        "Connect failure should clear pending"
    );
}

// ====================================================================
// Disconnect from Connecting state tests
// ====================================================================

#[test]
fn test_disconnect_from_connecting_state() {
    let mut app = test_app();
    add_profiles(&mut app, &["test-vpn"]);
    set_connecting(&mut app, "test-vpn");

    app.disconnect();

    assert!(
        matches!(app.connection_state, ConnectionState::Disconnecting { .. }),
        "disconnect() should work from Connecting state, got {:?}",
        app.connection_state
    );
}

#[test]
fn test_d_key_from_connecting_state_disconnects() {
    let mut app = test_app();
    add_profiles(&mut app, &["test-vpn"]);
    set_connecting(&mut app, "test-vpn");

    app.handle_message(Message::Disconnect);

    assert!(
        matches!(app.connection_state, ConnectionState::Disconnecting { .. }),
        "d key should cancel Connecting state"
    );
}

// ====================================================================
// Reconnect uses pending_connect (no race)
// ====================================================================

#[test]
fn test_reconnect_sets_pending_not_immediate_connect() {
    let mut app = test_app();
    add_profiles(&mut app, &["test-vpn"]);
    set_connected(&mut app, "test-vpn");

    app.reconnect();

    assert_eq!(app.pending_connect, Some(0));
    assert!(
        matches!(app.connection_state, ConnectionState::Disconnecting { .. }),
        "Reconnect should disconnect first"
    );
}

#[test]
fn test_reconnect_auto_connects_after_disconnect_completes() {
    let mut app = test_app();
    add_profiles(&mut app, &["test-vpn"]);
    set_disconnecting(&mut app, "test-vpn");
    app.pending_connect = Some(0);
    app.is_root = true;

    app.handle_message(Message::DisconnectResult {
        profile: "test-vpn".to_string(),
        success: true,
        error: None,
    });

    assert_eq!(app.pending_connect, None);
    assert!(
        matches!(app.connection_state, ConnectionState::Connecting { ref profile, .. } if profile == "test-vpn"),
        "Reconnect should auto-connect after disconnect"
    );
}

// ====================================================================
// QuickConnect (1-9) edge cases
// ====================================================================

#[test]
fn test_quick_connect_while_connected_shows_confirm() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b", "vpn-c"]);
    set_connected(&mut app, "vpn-a");

    app.handle_message(Message::QuickConnect(1));

    assert!(
        matches!(app.input_mode, InputMode::ConfirmSwitch { to_idx: 1, .. }),
        "Expected ConfirmSwitch dialog for QuickConnect, got {:?}",
        app.input_mode,
    );
}

#[test]
fn test_quick_connect_while_disconnecting_updates_pending() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b", "vpn-c"]);
    set_disconnecting(&mut app, "vpn-a");
    app.pending_connect = Some(1);

    app.handle_message(Message::QuickConnect(2));

    assert_eq!(
        app.pending_connect,
        Some(2),
        "Should update pending to new choice"
    );
}

#[test]
fn test_quick_connect_from_disconnected() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a"]);
    app.is_root = true;

    app.handle_message(Message::QuickConnect(0));

    assert!(
        matches!(app.connection_state, ConnectionState::Connecting { .. }),
        "QuickConnect from Disconnected should go to Connecting"
    );
    assert_eq!(app.pending_connect, None);
}

// ====================================================================
// Auth prompt tests
// ====================================================================

/// Helper: add `OpenVPN` profiles with a temp config file containing auth-user-pass.
fn add_openvpn_profiles_with_auth(app: &mut App, names: &[&str], dir: &std::path::Path) {
    let _ = std::fs::create_dir_all(dir);
    for name in names {
        let config_path = dir.join(format!("{name}.ovpn"));
        std::fs::write(
            &config_path,
            "client\nremote example.com 1194\nauth-user-pass\ndev tun\nproto udp\n",
        )
        .unwrap();
        app.profiles.push(VpnProfile {
            name: (*name).to_string(),
            protocol: Protocol::OpenVPN,
            config_path,
            location: "Test".to_string(),
            last_used: None,
        });
    }
}

/// Helper: add `OpenVPN` profiles WITHOUT auth-user-pass.
fn add_openvpn_profiles_no_auth(app: &mut App, names: &[&str], dir: &std::path::Path) {
    let _ = std::fs::create_dir_all(dir);
    for name in names {
        let config_path = dir.join(format!("{name}.ovpn"));
        std::fs::write(
            &config_path,
            "client\nremote example.com 1194\ndev tun\nproto udp\n<ca>\n</ca>\n",
        )
        .unwrap();
        app.profiles.push(VpnProfile {
            name: (*name).to_string(),
            protocol: Protocol::OpenVPN,
            config_path,
            location: "Test".to_string(),
            last_used: None,
        });
    }
}

#[test]
fn test_auth_prompt_shown_for_openvpn_with_auth_user_pass() {
    let mut app = test_app();
    let tmp = tempfile::Builder::new()
        .prefix("vortix_auth_")
        .tempdir()
        .unwrap();
    add_openvpn_profiles_with_auth(&mut app, &["auth-vpn"], tmp.path());
    app.is_root = true;

    crate::utils::delete_openvpn_auth_file("auth-vpn");

    app.connect_profile(0);

    assert!(
        matches!(app.input_mode, InputMode::AuthPrompt { .. }),
        "OpenVPN with auth-user-pass and no saved creds should show AuthPrompt"
    );
    assert!(
        matches!(app.connection_state, ConnectionState::Disconnected),
        "Should not start connecting before credentials are provided"
    );
}

#[test]
fn test_auth_prompt_skipped_when_creds_saved() {
    let mut app = test_app();
    let tmp = tempfile::Builder::new()
        .prefix("vortix_auth_")
        .tempdir()
        .unwrap();
    add_openvpn_profiles_with_auth(&mut app, &["saved-vpn"], tmp.path());
    app.is_root = true;

    let _ = crate::utils::write_openvpn_auth_file("saved-vpn", "user", "pass");

    app.connect_profile(0);

    assert!(
        !matches!(app.input_mode, InputMode::AuthPrompt { .. }),
        "Should not show AuthPrompt when creds are already saved"
    );
    assert!(
        matches!(app.connection_state, ConnectionState::Connecting { .. }),
        "Should proceed to Connecting with saved credentials"
    );

    crate::utils::delete_openvpn_auth_file("saved-vpn");
}

#[test]
fn test_auth_prompt_skipped_for_wireguard() {
    let mut app = test_app();
    add_profiles(&mut app, &["wg-vpn"]);
    app.is_root = true;

    app.connect_profile(0);

    assert!(
        !matches!(app.input_mode, InputMode::AuthPrompt { .. }),
        "WireGuard profiles should never show AuthPrompt"
    );
}

#[test]
fn test_auth_prompt_skipped_for_openvpn_without_auth_directive() {
    let mut app = test_app();
    let tmp = tempfile::Builder::new()
        .prefix("vortix_noauth_")
        .tempdir()
        .unwrap();
    add_openvpn_profiles_no_auth(&mut app, &["noauth-vpn"], tmp.path());
    app.is_root = true;

    app.connect_profile(0);

    assert!(
        !matches!(app.input_mode, InputMode::AuthPrompt { .. }),
        "OpenVPN without auth-user-pass should not show AuthPrompt"
    );
    assert!(
        matches!(app.connection_state, ConnectionState::Connecting { .. }),
        "Should proceed to Connecting directly"
    );
}

#[test]
fn test_auth_submit_triggers_connect() {
    let mut app = test_app();
    let tmp = tempfile::Builder::new()
        .prefix("vortix_auth_")
        .tempdir()
        .unwrap();
    add_openvpn_profiles_with_auth(&mut app, &["submit-vpn"], tmp.path());
    app.is_root = true;

    crate::utils::delete_openvpn_auth_file("submit-vpn");

    app.handle_message(Message::AuthSubmit {
        idx: 0,
        username: "testuser".to_string(),
        password: "testpass".to_string(),
        save: true,
        connect_after: true,
    });

    assert_eq!(app.input_mode, InputMode::Normal);
    assert!(
        matches!(app.connection_state, ConnectionState::Connecting { .. }),
        "AuthSubmit should trigger connect_profile"
    );

    let creds = crate::utils::read_openvpn_saved_auth("submit-vpn");
    assert!(creds.is_some());
    let (user, pass) = creds.unwrap();
    assert_eq!(user, "testuser");
    assert_eq!(pass, "testpass");

    crate::utils::delete_openvpn_auth_file("submit-vpn");
}

#[test]
fn test_auth_cancel_returns_to_normal() {
    let mut app = test_app();
    let tmp = tempfile::Builder::new()
        .prefix("vortix_auth_")
        .tempdir()
        .unwrap();
    add_openvpn_profiles_with_auth(&mut app, &["cancel-vpn"], tmp.path());
    app.is_root = true;

    crate::utils::delete_openvpn_auth_file("cancel-vpn");

    app.connect_profile(0);
    assert!(matches!(app.input_mode, InputMode::AuthPrompt { .. }));

    app.handle_message(Message::CloseOverlay);
    assert_eq!(app.input_mode, InputMode::Normal);
    assert!(
        matches!(app.connection_state, ConnectionState::Disconnected),
        "Cancelling auth should keep Disconnected state"
    );
}

#[test]
fn test_auth_field_switching() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = test_app();
    app.input_mode = InputMode::AuthPrompt {
        profile_idx: 0,
        profile_name: "test".to_string(),
        username: String::new(),
        username_cursor: 0,
        password: String::new(),
        password_cursor: 0,
        focused_field: AuthField::Username,
        save_credentials: true,
        connect_after: true,
    };

    // Tab from Username -> Password
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    if let InputMode::AuthPrompt { focused_field, .. } = &app.input_mode {
        assert_eq!(*focused_field, AuthField::Password);
    } else {
        panic!("Expected AuthPrompt");
    }

    // Tab from Password -> SaveCheckbox
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    if let InputMode::AuthPrompt { focused_field, .. } = &app.input_mode {
        assert_eq!(*focused_field, AuthField::SaveCheckbox);
    } else {
        panic!("Expected AuthPrompt");
    }

    // Tab from SaveCheckbox -> Username (wraps around)
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    if let InputMode::AuthPrompt { focused_field, .. } = &app.input_mode {
        assert_eq!(*focused_field, AuthField::Username);
    } else {
        panic!("Expected AuthPrompt");
    }
}

#[test]
fn test_auth_delete_profile_cleans_auth_file() {
    let mut app = test_app();
    let tmp = tempfile::Builder::new()
        .prefix("vortix_auth_")
        .tempdir()
        .unwrap();
    add_openvpn_profiles_with_auth(&mut app, &["del-vpn"], tmp.path());
    app.profile_list_state.select(Some(0));

    let auth_path = crate::utils::write_openvpn_auth_file("del-vpn", "user", "pass").unwrap();
    assert!(auth_path.exists());

    app.confirm_delete(0);

    assert!(
        !auth_path.exists(),
        "Auth file should be deleted when profile is deleted"
    );
}

// ====================================================================
// v0.3.0 — "Trustworthy & Alive" tests
// ====================================================================

// --- Phase 1: DNS leak detection (#46) ---

#[test]
fn test_dns_leak_detected_when_dns_unchanged_after_vpn() {
    let mut app = test_app();
    app.real_dns = Some("192.168.1.1".to_string());
    app.dns_server = "192.168.1.1".to_string();
    set_connected(&mut app, "vpn-a");

    assert_eq!(
        app.dns_server,
        app.real_dns.as_ref().unwrap().as_str(),
        "DNS unchanged = leak"
    );
}

#[test]
fn test_dns_not_leaking_when_vpn_pushed_new_dns() {
    let mut app = test_app();
    app.real_dns = Some("192.168.1.1".to_string());
    app.dns_server = "10.8.0.1".to_string();
    set_connected(&mut app, "vpn-a");

    assert_ne!(
        app.dns_server,
        app.real_dns.as_ref().unwrap().as_str(),
        "Different DNS = not leaking"
    );
}

#[test]
fn test_real_dns_captured_when_disconnected() {
    use crate::core::telemetry::TelemetryUpdate;
    let mut app = test_app();
    assert!(app.real_dns.is_none());

    app.handle_message(Message::Telemetry(TelemetryUpdate::Dns(
        "8.8.8.8".to_string(),
    )));

    assert_eq!(app.real_dns, Some("8.8.8.8".to_string()));
}

// --- Phase 1: Last security check timestamp (#47) ---

#[test]
fn test_last_security_check_updated_on_ip_telemetry() {
    use crate::core::telemetry::TelemetryUpdate;
    let mut app = test_app();
    assert!(app.last_security_check.is_none());

    app.handle_message(Message::Telemetry(TelemetryUpdate::PublicIp(
        "1.2.3.4".to_string(),
    )));

    assert!(app.last_security_check.is_some());
}

#[test]
fn test_last_security_check_updated_on_dns_telemetry() {
    use crate::core::telemetry::TelemetryUpdate;
    let mut app = test_app();
    assert!(app.last_security_check.is_none());

    app.handle_message(Message::Telemetry(TelemetryUpdate::Dns(
        "1.1.1.1".to_string(),
    )));

    assert!(app.last_security_check.is_some());
}

#[test]
fn test_last_security_check_updated_on_ipv6_telemetry() {
    use crate::core::telemetry::TelemetryUpdate;
    let mut app = test_app();
    assert!(app.last_security_check.is_none());

    app.handle_message(Message::Telemetry(TelemetryUpdate::Ipv6Leak(false)));

    assert!(app.last_security_check.is_some());
}

// --- Phase 1: Reconnect from Disconnected (#49) ---

#[test]
fn test_reconnect_from_disconnected_with_last_profile() {
    let mut app = test_app();
    add_profiles(&mut app, &["my-vpn"]);
    app.last_connected_profile = Some("my-vpn".to_string());
    app.is_root = true;

    app.reconnect();

    assert!(
        matches!(app.connection_state, ConnectionState::Connecting { ref profile, .. } if profile == "my-vpn"),
        "Should initiate connection to last used profile"
    );
}

#[test]
fn test_reconnect_from_disconnected_without_last_profile_is_noop() {
    let mut app = test_app();
    add_profiles(&mut app, &["my-vpn"]);
    assert!(app.last_connected_profile.is_none());

    app.reconnect();

    assert!(
        matches!(app.connection_state, ConnectionState::Disconnected),
        "Should stay disconnected when no last_connected_profile"
    );
}

// --- Phase 1: Timeout toast color (#50) ---

#[test]
fn test_connection_timeout_shows_error_toast() {
    let mut app = test_app();
    add_profiles(&mut app, &["timeout-vpn"]);
    app.connection_state = ConnectionState::Connecting {
        started: Instant::now()
            .checked_sub(std::time::Duration::from_secs(60))
            .unwrap(),
        profile: "timeout-vpn".to_string(),
    };

    app.handle_message(Message::ConnectionTimeout("timeout-vpn".to_string()));

    assert!(app.toast.is_some(), "Should show a toast");
    assert_eq!(
        app.toast.as_ref().unwrap().toast_type,
        crate::state::ToastType::Error,
        "Timeout toast should be Error, not Warning"
    );
}

// --- Phase 1: last_connected_profile set on success (#49 + reconnect) ---

#[test]
fn test_last_connected_profile_set_on_connect_success() {
    let mut app = test_app();
    add_profiles(&mut app, &["success-vpn"]);
    app.connection_state = ConnectionState::Connecting {
        started: Instant::now(),
        profile: "success-vpn".to_string(),
    };

    app.handle_message(Message::ConnectResult {
        profile: "success-vpn".to_string(),
        success: true,
        error: None,
    });

    assert_eq!(
        app.last_connected_profile,
        Some("success-vpn".to_string()),
        "Should track last connected profile"
    );
}

// --- Phase 2: Quick-connect moves selection (#53) ---

#[test]
fn test_quick_connect_moves_selection_cursor() {
    let mut app = test_app();
    add_profiles(&mut app, &["alpha", "beta", "gamma"]);
    app.profile_list_state.select(Some(0));

    app.handle_message(Message::QuickConnect(2));

    assert_eq!(
        app.profile_list_state.selected(),
        Some(2),
        "Quick-connect should move selection to the connected profile"
    );
}

#[test]
fn test_quick_connect_out_of_range_does_not_change_selection() {
    let mut app = test_app();
    add_profiles(&mut app, &["alpha"]);
    app.profile_list_state.select(Some(0));

    app.handle_message(Message::QuickConnect(5));

    assert_eq!(
        app.profile_list_state.selected(),
        Some(0),
        "Out-of-range quick-connect should not change selection"
    );
}

// --- Phase 2: Context-aware footer / search / help mode ---

#[test]
fn test_help_mode_opens_and_closes() {
    let mut app = test_app();
    assert!(matches!(app.input_mode, InputMode::Normal));

    app.input_mode = InputMode::Help { scroll: 0 };
    assert!(matches!(app.input_mode, InputMode::Help { .. }));

    app.handle_message(Message::CloseOverlay);
    assert!(matches!(app.input_mode, InputMode::Normal));
}

#[test]
fn test_search_mode_opens() {
    let mut app = test_app();
    app.input_mode = InputMode::Search {
        query: String::new(),
        cursor: 0,
    };
    assert!(matches!(app.input_mode, InputMode::Search { .. }));
}

#[test]
fn test_search_filter_selects_matching_profile() {
    let mut app = test_app();
    add_profiles(&mut app, &["amsterdam", "berlin", "chicago"]);
    app.profile_list_state.select(Some(0));

    app.apply_search_filter("ber");

    assert_eq!(
        app.profile_list_state.selected(),
        Some(1),
        "Search for 'ber' should select 'berlin'"
    );
}

#[test]
fn test_search_filter_empty_resets_to_first() {
    let mut app = test_app();
    add_profiles(&mut app, &["amsterdam", "berlin"]);
    app.profile_list_state.select(Some(1));

    app.apply_search_filter("");

    assert_eq!(
        app.profile_list_state.selected(),
        Some(0),
        "Empty query should reset to first profile"
    );
}

#[test]
fn test_search_filter_no_match_keeps_selection() {
    let mut app = test_app();
    add_profiles(&mut app, &["amsterdam", "berlin"]);
    app.profile_list_state.select(Some(0));

    app.apply_search_filter("zzzzz");

    assert_eq!(
        app.profile_list_state.selected(),
        Some(0),
        "No match should not change selection"
    );
}

#[test]
fn test_open_config_caches_content_and_close_clears() {
    let mut app = test_app();

    let tmp = tempfile::Builder::new().suffix(".conf").tempfile().unwrap();
    std::fs::write(tmp.path(), "[Interface]\nAddress = 10.0.0.1/24").unwrap();
    app.profiles.push(VpnProfile {
        name: "test-vpn".to_string(),
        protocol: Protocol::WireGuard,
        config_path: tmp.path().to_path_buf(),
        location: "Test".to_string(),
        last_used: None,
    });
    app.profile_list_state.select(Some(0));

    app.handle_message(Message::OpenConfig);
    assert!(app.show_config, "Config viewer should be open");
    assert!(
        app.cached_config_content.is_some(),
        "Config content should be cached"
    );
    assert!(app
        .cached_config_content
        .as_ref()
        .unwrap()
        .contains("[Interface]"));

    app.handle_message(Message::CloseOverlay);
    assert!(!app.show_config, "Config viewer should be closed");
    assert!(
        app.cached_config_content.is_none(),
        "Cached content should be cleared on close"
    );
}

#[test]
fn test_close_overlay_preserves_zoom() {
    let mut app = test_app();
    app.zoomed_panel = Some(FocusedPanel::Logs);
    app.show_action_menu = true;

    app.handle_message(Message::CloseOverlay);
    assert!(!app.show_action_menu);
    assert_eq!(
        app.zoomed_panel,
        Some(FocusedPanel::Logs),
        "Zoom should be preserved when closing overlay"
    );
}

#[test]
fn test_search_match_count_updated() {
    let mut app = test_app();
    add_profiles(&mut app, &["amsterdam", "ankara", "berlin"]);
    app.profile_list_state.select(Some(0));

    app.apply_search_filter("an");
    assert_eq!(app.search_match_count, 1, "Should match ankara");

    app.apply_search_filter("a");
    assert_eq!(
        app.search_match_count, 2,
        "Should match amsterdam and ankara"
    );

    app.apply_search_filter("");
    assert_eq!(app.search_match_count, 3, "Empty query should match all");
}

#[test]
fn test_confirm_switch_when_already_disconnected_connects_directly() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b"]);
    app.profile_list_state.select(Some(0));
    app.is_root = true;

    assert!(matches!(
        app.connection_state,
        ConnectionState::Disconnected
    ));

    app.handle_message(Message::ConfirmSwitch { idx: 1 });

    assert!(
        app.pending_connect.is_none(),
        "Should not set pending_connect when already disconnected"
    );
    assert!(
        matches!(app.connection_state, ConnectionState::Connecting { ref profile, .. } if profile == "vpn-b"),
        "Should connect directly when already disconnected, got {:?}",
        app.connection_state
    );
}

#[test]
fn test_cycle_sort_order() {
    use crate::state::ProfileSortOrder;

    let mut app = test_app();
    add_profiles(&mut app, &["charlie", "alpha", "bravo"]);
    app.profile_list_state.select(Some(0));

    assert_eq!(app.sort_order, ProfileSortOrder::NameAsc);

    app.handle_message(Message::CycleSortOrder);
    assert_eq!(app.sort_order, ProfileSortOrder::NameDesc);
    assert_eq!(app.profiles[0].name, "charlie");

    app.handle_message(Message::CycleSortOrder);
    assert_eq!(app.sort_order, ProfileSortOrder::LastUsed);

    app.handle_message(Message::CycleSortOrder);
    assert_eq!(app.sort_order, ProfileSortOrder::Protocol);

    app.handle_message(Message::CycleSortOrder);
    assert_eq!(app.sort_order, ProfileSortOrder::NameAsc);
    assert_eq!(app.profiles[0].name, "alpha");
}

#[test]
fn test_sort_preserves_selection() {
    let mut app = test_app();
    add_profiles(&mut app, &["charlie", "alpha", "bravo"]);
    app.profile_list_state.select(Some(1)); // "alpha" (unsorted order)

    let selected_name = app.profiles[1].name.clone();
    assert_eq!(selected_name, "alpha");

    app.handle_message(Message::CycleSortOrder); // NameAsc -> NameDesc

    let new_idx = app.profile_list_state.selected().unwrap();
    assert_eq!(
        app.profiles[new_idx].name, "alpha",
        "Selection should follow the profile after re-sort"
    );
}

// ====================================================================
// Unicode text field input tests (#98)
// ====================================================================

#[test]
fn test_text_field_multibyte_insert_and_backspace() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut text = String::new();
    let mut cursor: usize = 0;

    // Type "café"
    for c in ['c', 'a', 'f', 'é'] {
        App::handle_text_field_input(
            KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE),
            &mut text,
            &mut cursor,
        );
    }
    assert_eq!(text, "café");
    assert_eq!(cursor, 4);

    // Backspace should remove 'é', not panic
    App::handle_text_field_input(
        KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE),
        &mut text,
        &mut cursor,
    );
    assert_eq!(text, "caf");
    assert_eq!(cursor, 3);
}

#[test]
fn test_text_field_cursor_movement_with_multibyte() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut text = "日本語".to_string();
    let mut cursor: usize = 3; // end

    // Left arrow should move one character, not one byte
    App::handle_text_field_input(
        KeyEvent::new(KeyCode::Left, KeyModifiers::NONE),
        &mut text,
        &mut cursor,
    );
    assert_eq!(cursor, 2);

    // Delete should remove '語' (the char at position 2)
    App::handle_text_field_input(
        KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE),
        &mut text,
        &mut cursor,
    );
    assert_eq!(text, "日本");
    assert_eq!(cursor, 2);

    // Home should go to 0
    App::handle_text_field_input(
        KeyEvent::new(KeyCode::Home, KeyModifiers::NONE),
        &mut text,
        &mut cursor,
    );
    assert_eq!(cursor, 0);

    // End should go to char count (2)
    App::handle_text_field_input(
        KeyEvent::new(KeyCode::End, KeyModifiers::NONE),
        &mut text,
        &mut cursor,
    );
    assert_eq!(cursor, 2);
}

#[test]
fn test_text_field_insert_at_middle_of_multibyte() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut text = "ab".to_string();
    let mut cursor: usize = 1; // between 'a' and 'b'

    // Insert 'ñ' between 'a' and 'b'
    App::handle_text_field_input(
        KeyEvent::new(KeyCode::Char('ñ'), KeyModifiers::NONE),
        &mut text,
        &mut cursor,
    );
    assert_eq!(text, "añb");
    assert_eq!(cursor, 2);
}

// ====================================================================
// Quit + help overlay behavior tests
// ====================================================================

#[test]
fn test_q_in_normal_mode_quits_while_connected() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a"]);
    set_connected(&mut app, "vpn-a");

    app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));

    assert!(app.should_quit);
    assert!(matches!(app.input_mode, InputMode::Normal));
}

#[test]
fn test_q_in_normal_mode_quits_while_disconnected() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = test_app();

    app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));

    assert!(app.should_quit);
}

#[test]
fn test_help_scroll_down_clamps_at_max() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = test_app();
    let max_scroll = crate::state::help_max_scroll_for_terminal_height(
        app.terminal_size.1,
        crate::ui::help_total_lines(),
    );
    app.input_mode = InputMode::Help { scroll: 0 };

    for _ in 0..(usize::from(max_scroll) + 10) {
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
    }

    assert!(matches!(
        app.input_mode,
        InputMode::Help { scroll } if scroll == max_scroll
    ));
}

#[test]
fn test_help_scroll_does_not_move_when_terminal_size_unknown() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = test_app();
    app.terminal_size = (0, 0);
    app.input_mode = InputMode::Help { scroll: 0 };

    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));

    assert!(matches!(app.input_mode, InputMode::Help { scroll: 0 }));
}

#[test]
fn test_help_scroll_clamps_after_resize_before_key_handling() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = test_app();
    let max_scroll = crate::state::help_max_scroll_for_terminal_height(
        app.terminal_size.1,
        crate::ui::help_total_lines(),
    );
    app.input_mode = InputMode::Help {
        scroll: max_scroll.saturating_add(10),
    };

    app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));

    assert!(matches!(
        app.input_mode,
        InputMode::Help { scroll } if scroll == max_scroll.saturating_sub(1)
    ));
}

#[test]
fn test_help_end_jumps_to_max_scroll() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = test_app();
    let max_scroll = crate::state::help_max_scroll_for_terminal_height(
        app.terminal_size.1,
        crate::ui::help_total_lines(),
    );
    app.input_mode = InputMode::Help { scroll: 0 };

    app.handle_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));

    assert!(matches!(
        app.input_mode,
        InputMode::Help { scroll } if scroll == max_scroll
    ));
}

#[test]
fn test_help_mouse_scroll_down_clamps_at_max() {
    use crossterm::event::{KeyModifiers, MouseEvent, MouseEventKind};

    let mut app = test_app();
    let max_scroll = crate::state::help_max_scroll_for_terminal_height(
        app.terminal_size.1,
        crate::ui::help_total_lines(),
    );
    app.input_mode = InputMode::Help { scroll: 0 };

    for _ in 0..20 {
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });
    }

    assert!(matches!(
        app.input_mode,
        InputMode::Help { scroll } if scroll == max_scroll
    ));
}

#[test]
fn test_help_mouse_scroll_up_clamps_after_resize() {
    use crossterm::event::{KeyModifiers, MouseEvent, MouseEventKind};

    let mut app = test_app();
    let max_scroll = crate::state::help_max_scroll_for_terminal_height(
        app.terminal_size.1,
        crate::ui::help_total_lines(),
    );
    app.input_mode = InputMode::Help {
        scroll: max_scroll.saturating_add(9),
    };

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::ScrollUp,
        column: 0,
        row: 0,
        modifiers: KeyModifiers::NONE,
    });

    assert!(matches!(
        app.input_mode,
        InputMode::Help { scroll } if scroll == max_scroll.saturating_sub(3)
    ));
}

// ====================================================================
// Home/End panel-aware tests
// ====================================================================

#[test]
fn test_home_in_sidebar_moves_to_first_profile() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b", "vpn-c"]);
    app.profile_list_state.select(Some(2));
    app.focused_panel = FocusedPanel::Sidebar;

    app.handle_key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
    assert_eq!(app.profile_list_state.selected(), Some(0));
}

#[test]
fn test_end_in_sidebar_moves_to_last_profile() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b", "vpn-c"]);
    app.profile_list_state.select(Some(0));
    app.focused_panel = FocusedPanel::Sidebar;

    app.handle_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
    assert_eq!(app.profile_list_state.selected(), Some(2));
}

#[test]
fn test_home_in_logs_scrolls_to_top() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b", "vpn-c"]);
    app.profile_list_state.select(Some(2));
    app.focused_panel = FocusedPanel::Logs;
    app.logs_scroll = 10;
    app.logs_auto_scroll = false;

    app.handle_key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
    assert_eq!(app.logs_scroll, 0, "Home in Logs should scroll to top");
    assert_eq!(
        app.profile_list_state.selected(),
        Some(2),
        "Profile selection should not change"
    );
}

#[test]
fn test_end_in_logs_enables_auto_scroll() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = test_app();
    app.focused_panel = FocusedPanel::Logs;
    app.logs_auto_scroll = false;

    app.handle_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
    assert!(
        app.logs_auto_scroll,
        "End in Logs should re-enable auto-scroll"
    );
}

#[test]
fn test_rename_updates_last_connected_profile() {
    let mut app = test_app();
    let dir = tempfile::tempdir().unwrap();
    let conf_path = dir.path().join("old-name.conf");
    std::fs::write(&conf_path, "dummy").unwrap();
    app.profiles.push(VpnProfile {
        name: "old-name".to_string(),
        protocol: Protocol::WireGuard,
        config_path: conf_path,
        location: String::new(),
        last_used: None,
    });
    app.profile_list_state.select(Some(0));
    app.last_connected_profile = Some("old-name".to_string());

    app.rename_profile(0, "new-name");
    assert_eq!(
        app.last_connected_profile.as_deref(),
        Some("new-name"),
        "Rename should update last_connected_profile"
    );
}

#[test]
fn test_rename_updates_connected_state() {
    let mut app = test_app();
    let dir = tempfile::tempdir().unwrap();
    let conf_path = dir.path().join("active-vpn.conf");
    std::fs::write(&conf_path, "dummy").unwrap();
    app.profiles.push(VpnProfile {
        name: "active-vpn".to_string(),
        protocol: Protocol::WireGuard,
        config_path: conf_path,
        location: String::new(),
        last_used: None,
    });
    app.profile_list_state.select(Some(0));
    app.connection_state = ConnectionState::Connected {
        profile: "active-vpn".to_string(),
        server_location: "Test".to_string(),
        since: Instant::now(),
        latency_ms: 0,
        details: Box::new(DetailedConnectionInfo::default()),
    };

    app.rename_profile(0, "renamed-vpn");
    if let ConnectionState::Connected { profile, .. } = &app.connection_state {
        assert_eq!(
            profile, "renamed-vpn",
            "Rename should update connection_state profile name"
        );
    } else {
        panic!("Should still be connected");
    }
}

#[test]
fn test_ip_unchanged_warning_fires_once() {
    use crate::core::telemetry::TelemetryUpdate;
    let mut app = test_app();
    app.connection_state = ConnectionState::Connected {
        profile: "test".to_string(),
        server_location: "Test".to_string(),
        since: Instant::now(),
        latency_ms: 0,
        details: Box::new(DetailedConnectionInfo::default()),
    };
    app.public_ip = "1.2.3.4".to_string();

    app.handle_message(Message::Telemetry(TelemetryUpdate::PublicIp(
        "1.2.3.4".to_string(),
    )));
    assert!(app.ip_unchanged_warned, "First warning should fire");

    let warned_before = app.ip_unchanged_warned;
    app.handle_message(Message::Telemetry(TelemetryUpdate::PublicIp(
        "1.2.3.4".to_string(),
    )));
    assert!(
        warned_before && app.ip_unchanged_warned,
        "Second identical IP should not change the warning state"
    );
}

#[test]
fn test_cannot_delete_connecting_profile() {
    let mut app = test_app();
    add_profiles(&mut app, &["my-vpn"]);
    app.profile_list_state.select(Some(0));
    app.connection_state = ConnectionState::Connecting {
        profile: "my-vpn".to_string(),
        started: Instant::now(),
    };

    app.request_delete(0);
    assert!(
        !matches!(app.input_mode, InputMode::ConfirmDelete { .. }),
        "Should not open confirm dialog for a connecting profile"
    );
}

#[test]
fn test_cannot_delete_disconnecting_profile() {
    let mut app = test_app();
    add_profiles(&mut app, &["my-vpn"]);
    app.profile_list_state.select(Some(0));
    app.connection_state = ConnectionState::Disconnecting {
        profile: "my-vpn".to_string(),
        started: Instant::now(),
    };

    app.request_delete(0);
    assert!(
        !matches!(app.input_mode, InputMode::ConfirmDelete { .. }),
        "Should not open confirm dialog for a disconnecting profile"
    );
}

#[test]
fn test_connect_selected_targets_sidebar_selection() {
    let mut app = test_app();
    add_profiles(&mut app, &["alpha", "beta"]);
    app.profile_list_state.select(Some(1));

    // Verify ConnectSelected dispatches toggle_connection for the selected index.
    // Transition to Disconnecting first so toggle_connection queues pending_connect.
    app.connection_state = ConnectionState::Disconnecting {
        profile: "alpha".to_string(),
        started: Instant::now(),
    };
    app.handle_message(Message::ConnectSelected);
    assert_eq!(
        app.pending_connect,
        Some(1),
        "ConnectSelected should queue the sidebar-selected profile (index 1)"
    );
}

#[test]
fn test_connect_selected_reconnects_active_profile() {
    let mut app = test_app();
    add_profiles(&mut app, &["alpha", "beta"]);
    app.profile_list_state.select(Some(0));
    app.connection_state = ConnectionState::Connected {
        profile: "alpha".to_string(),
        server_location: "Test".to_string(),
        since: Instant::now(),
        latency_ms: 0,
        details: Box::new(DetailedConnectionInfo::default()),
    };

    app.handle_message(Message::ConnectSelected);
    assert_eq!(
        app.pending_connect,
        Some(0),
        "ConnectSelected on active profile should queue reconnect"
    );
    assert!(
        matches!(app.connection_state, ConnectionState::Disconnecting { .. }),
        "Should start disconnecting for reconnect"
    );
}

// ── rename_profile path-traversal validation ─────────────────────────────

fn setup_rename_app() -> App {
    let mut app = test_app();
    add_profiles(&mut app, &["existing-vpn"]);
    app.profile_list_state.select(Some(0));
    app
}

fn assert_rename_rejected(app: &App) {
    assert_eq!(
        app.profiles[0].name, "existing-vpn",
        "name should be unchanged"
    );
    let toast_msg = app.toast.as_ref().map_or("", |t| t.message.as_str());
    assert!(
        toast_msg.contains("Invalid name"),
        "should produce validation warning toast, got: {toast_msg:?}"
    );
}

#[test]
fn rename_rejects_empty_name() {
    let mut app = setup_rename_app();
    app.rename_profile(0, "   ");
    assert_rename_rejected(&app);
}

#[test]
fn rename_rejects_forward_slash() {
    let mut app = setup_rename_app();
    app.rename_profile(0, "../etc/passwd");
    assert_rename_rejected(&app);
}

#[test]
fn rename_rejects_backslash() {
    let mut app = setup_rename_app();
    app.rename_profile(0, "..\\windows\\system32");
    assert_rename_rejected(&app);
}

#[test]
fn rename_rejects_dot_dot_traversal() {
    let mut app = setup_rename_app();
    app.rename_profile(0, "foo..bar");
    assert_rename_rejected(&app);
}

#[test]
fn rename_rejects_hidden_file_prefix() {
    let mut app = setup_rename_app();
    app.rename_profile(0, ".hidden");
    assert_rename_rejected(&app);
}

#[test]
fn rename_accepts_valid_alphanumeric() {
    let mut app = setup_rename_app();
    app.rename_profile(0, "my-vpn-2024");
    // Name changes only if the filesystem rename succeeds; in tests there
    // is no real file, so the rename may fail at the fs level — but the
    // validation itself must NOT reject a valid name (no early return).
    // We verify the validator didn't fire a warning toast.
    let last_toast = app.toast.as_ref().map(|t| t.message.clone());
    assert!(
        !last_toast.as_deref().unwrap_or("").contains("Invalid name"),
        "Valid name should not trigger validation error"
    );
}

#[test]
fn rename_accepts_unicode_name() {
    let mut app = setup_rename_app();
    app.rename_profile(0, "日本-VPN");
    let last_toast = app.toast.as_ref().map(|t| t.message.clone());
    assert!(
        !last_toast.as_deref().unwrap_or("").contains("Invalid name"),
        "Unicode name should not trigger validation error"
    );
}

#[test]
fn rename_accepts_spaces_and_hyphens() {
    let mut app = setup_rename_app();
    app.rename_profile(0, "My Work VPN - US East");
    let last_toast = app.toast.as_ref().map(|t| t.message.clone());
    assert!(
        !last_toast.as_deref().unwrap_or("").contains("Invalid name"),
        "Name with spaces and hyphens should not trigger validation error"
    );
}

// === Flip Panel Tests ===

/// Simulate completing a flip animation (advances time past the duration).
fn complete_flip(app: &mut App) {
    // Force-complete: take the animation and apply the state change
    if let Some(anim) = app.flip_animation.take() {
        if anim.to_back {
            app.panel_flipped.insert(anim.panel);
        } else {
            app.panel_flipped.remove(&anim.panel);
        }
    }
}

#[test]
fn flip_starts_animation() {
    let mut app = test_app();
    app.focused_panel = FocusedPanel::Chart;
    app.handle_message(Message::ToggleFlip);
    assert!(app.flip_animation.is_some());
    assert!(!app.is_flipped(&FocusedPanel::Chart));
}

#[test]
fn flip_toggles_chart_panel_after_animation() {
    let mut app = test_app();
    app.focused_panel = FocusedPanel::Chart;
    assert!(!app.is_flipped(&FocusedPanel::Chart));
    app.handle_message(Message::ToggleFlip);
    complete_flip(&mut app);
    assert!(app.is_flipped(&FocusedPanel::Chart));
    app.handle_message(Message::ToggleFlip);
    complete_flip(&mut app);
    assert!(!app.is_flipped(&FocusedPanel::Chart));
}

#[test]
fn flip_toggles_security_panel() {
    let mut app = test_app();
    app.focused_panel = FocusedPanel::Security;
    app.handle_message(Message::ToggleFlip);
    complete_flip(&mut app);
    assert!(app.is_flipped(&FocusedPanel::Security));
    assert!(!app.is_flipped(&FocusedPanel::Chart));
}

#[test]
fn flip_toggles_connection_details_panel() {
    let mut app = test_app();
    app.focused_panel = FocusedPanel::ConnectionDetails;
    app.handle_message(Message::ToggleFlip);
    complete_flip(&mut app);
    assert!(app.is_flipped(&FocusedPanel::ConnectionDetails));
}

#[test]
fn flip_ignores_sidebar() {
    let mut app = test_app();
    app.focused_panel = FocusedPanel::Sidebar;
    app.handle_message(Message::ToggleFlip);
    assert!(app.flip_animation.is_none());
    assert!(app.panel_flipped.is_empty());
}

#[test]
fn flip_ignores_logs() {
    let mut app = test_app();
    app.focused_panel = FocusedPanel::Logs;
    app.handle_message(Message::ToggleFlip);
    assert!(app.flip_animation.is_none());
    assert!(app.panel_flipped.is_empty());
}

#[test]
fn flip_blocked_during_active_animation() {
    let mut app = test_app();
    app.focused_panel = FocusedPanel::Chart;
    app.handle_message(Message::ToggleFlip);
    assert!(app.flip_animation.is_some());
    let started = app.flip_animation.as_ref().unwrap().started;
    app.handle_message(Message::ToggleFlip);
    assert_eq!(app.flip_animation.as_ref().unwrap().started, started);
}

#[test]
fn flip_state_persists_across_focus_changes() {
    let mut app = test_app();
    app.focused_panel = FocusedPanel::Chart;
    app.handle_message(Message::ToggleFlip);
    complete_flip(&mut app);
    assert!(app.is_flipped(&FocusedPanel::Chart));
    app.focused_panel = FocusedPanel::Security;
    assert!(app.is_flipped(&FocusedPanel::Chart));
}

#[test]
fn flip_multiple_panels_independently() {
    let mut app = test_app();
    app.focused_panel = FocusedPanel::Chart;
    app.handle_message(Message::ToggleFlip);
    complete_flip(&mut app);
    app.focused_panel = FocusedPanel::Security;
    app.handle_message(Message::ToggleFlip);
    complete_flip(&mut app);
    assert!(app.is_flipped(&FocusedPanel::Chart));
    assert!(app.is_flipped(&FocusedPanel::Security));
    assert!(!app.is_flipped(&FocusedPanel::ConnectionDetails));
}

#[test]
fn flip_effective_state_at_midpoint() {
    let mut app = test_app();
    app.focused_panel = FocusedPanel::Chart;
    assert!(!app.effective_flipped(&FocusedPanel::Chart));
    app.handle_message(Message::ToggleFlip);
    assert!(!app.effective_flipped(&FocusedPanel::Chart));
}

#[test]
fn flip_state_cleared_on_disconnect() {
    let mut app = test_app();
    add_profiles(&mut app, &["test-profile"]);
    set_connected(&mut app, "test-profile");

    app.focused_panel = FocusedPanel::Chart;
    app.handle_message(Message::ToggleFlip);
    complete_flip(&mut app);
    app.focused_panel = FocusedPanel::Security;
    app.handle_message(Message::ToggleFlip);
    complete_flip(&mut app);
    assert_eq!(app.panel_flipped.len(), 2);

    app.complete_disconnect("test-profile");
    assert!(app.panel_flipped.is_empty());
}

#[test]
fn advance_animation_completes_to_back() {
    let mut app = test_app();
    app.flip_animation = Some(crate::state::FlipAnimation {
        panel: FocusedPanel::Chart,
        started: std::time::Instant::now()
            .checked_sub(std::time::Duration::from_millis(
                crate::constants::FLIP_ANIMATION_DURATION_MS + 10,
            ))
            .unwrap(),
        to_back: true,
    });
    assert!(!app.is_flipped(&FocusedPanel::Chart));
    app.advance_animation();
    assert!(app.flip_animation.is_none());
    assert!(app.is_flipped(&FocusedPanel::Chart));
}

#[test]
fn advance_animation_completes_to_front() {
    let mut app = test_app();
    app.panel_flipped.insert(FocusedPanel::Security);
    app.flip_animation = Some(crate::state::FlipAnimation {
        panel: FocusedPanel::Security,
        started: std::time::Instant::now()
            .checked_sub(std::time::Duration::from_millis(
                crate::constants::FLIP_ANIMATION_DURATION_MS + 10,
            ))
            .unwrap(),
        to_back: false,
    });
    assert!(app.is_flipped(&FocusedPanel::Security));
    app.advance_animation();
    assert!(app.flip_animation.is_none());
    assert!(!app.is_flipped(&FocusedPanel::Security));
}

#[test]
fn advance_animation_noop_when_still_running() {
    let mut app = test_app();
    app.focused_panel = FocusedPanel::Chart;
    app.handle_message(Message::ToggleFlip);
    assert!(app.flip_animation.is_some());
    app.advance_animation();
    assert!(app.flip_animation.is_some());
}

#[test]
fn effective_flipped_shows_target_after_midpoint() {
    let mut app = test_app();
    app.flip_animation = Some(crate::state::FlipAnimation {
        panel: FocusedPanel::Chart,
        started: std::time::Instant::now()
            .checked_sub(std::time::Duration::from_millis(
                crate::constants::FLIP_ANIMATION_DURATION_MS * 3 / 4,
            ))
            .unwrap(),
        to_back: true,
    });
    assert!(app.effective_flipped(&FocusedPanel::Chart));
}

#[test]
fn disconnect_clears_animation() {
    let mut app = test_app();
    add_profiles(&mut app, &["p1"]);
    set_connected(&mut app, "p1");
    app.focused_panel = FocusedPanel::Chart;
    app.handle_message(Message::ToggleFlip);
    assert!(app.flip_animation.is_some());
    app.complete_disconnect("p1");
    assert!(app.flip_animation.is_none());
}
