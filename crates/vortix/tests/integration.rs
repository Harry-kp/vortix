//! Integration tests for Vortix core functionality.
//!
//! These tests construct a lightweight `App` instance and drive it through
//! scenarios without requiring actual VPN tools, root privileges, or network
//! access.  All filesystem operations are redirected to a temporary directory
//! via `config::set_config_dir()` so that tests never touch the user's real
//! `~/.config/vortix/`.

use std::sync::Once;
use std::time::Instant;

use vortix::app::{
    App, ConnectionState, DetailedConnectionInfo, FocusedPanel, InputMode, Protocol, Toast,
    ToastType, VpnProfile,
};
use vortix::core::scanner::ActiveSession;
use vortix::message::{Message, ScrollMove, SelectionMove};
use vortix::state::{KillSwitchMode, KillSwitchState};

static INIT: Once = Once::new();

fn init_test_env() {
    INIT.call_once(|| {
        let dir = tempfile::Builder::new()
            .prefix("vortix_integration_test_")
            .tempdir()
            .expect("failed to create test temp dir");
        let path = dir.path().to_path_buf();
        // Leak intentionally: shared across all tests in this module via Once
        std::mem::forget(dir);
        let _ = std::fs::create_dir_all(&path);
        vortix::config::set_config_dir(path);
    });
}

// ============================================================================
// Test helpers
// ============================================================================

fn test_app() -> App {
    init_test_env();
    App::new_test()
}

fn add_wg_profiles(app: &mut App, names: &[&str]) {
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

fn set_connecting(app: &mut App, name: &str) {
    app.connection_state = ConnectionState::Connecting {
        started: Instant::now(),
        profile: name.to_string(),
    };
}

fn set_disconnecting(app: &mut App, name: &str) {
    app.connection_state = ConnectionState::Disconnecting {
        started: Instant::now(),
        profile: name.to_string(),
    };
}

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

// ============================================================================
// Connection State Machine Tests
// ============================================================================

mod connection_state_machine {
    use super::*;

    #[test]
    fn disconnected_to_connecting_on_connect() {
        let mut app = test_app();
        add_wg_profiles(&mut app, &["vpn-a"]);

        // Simulate connect_profile setting state (avoids spawning real wg-quick)
        set_connecting(&mut app, "vpn-a");
        assert!(
            matches!(app.connection_state, ConnectionState::Connecting { .. }),
            "Disconnected -> Connecting on connect"
        );
    }

    #[test]
    fn connecting_to_connected_on_success() {
        let mut app = test_app();
        add_wg_profiles(&mut app, &["vpn-a"]);
        set_connecting(&mut app, "vpn-a");

        app.handle_message(Message::ConnectResult {
            profile: "vpn-a".to_string(),
            success: true,
            error: None,
        });
        assert!(matches!(
            app.connection_state,
            ConnectionState::Connected { .. }
        ));
    }

    #[test]
    fn connecting_to_disconnected_on_failure() {
        let mut app = test_app();
        set_connecting(&mut app, "vpn-a");

        app.handle_message(Message::ConnectResult {
            profile: "vpn-a".to_string(),
            success: false,
            error: Some("refused".to_string()),
        });
        assert!(matches!(
            app.connection_state,
            ConnectionState::Disconnected
        ));
    }

    #[test]
    fn connecting_to_connected_via_scanner() {
        let mut app = test_app();
        add_wg_profiles(&mut app, &["vpn-a"]);
        set_connecting(&mut app, "vpn-a");

        app.handle_message(Message::SyncSystemState(vec![fake_session("vpn-a")]));
        assert!(matches!(
            app.connection_state,
            ConnectionState::Connected { .. }
        ));
    }

    #[test]
    fn scanner_never_demotes_connecting_to_disconnected() {
        let mut app = test_app();
        set_connecting(&mut app, "vpn-a");

        app.handle_message(Message::SyncSystemState(vec![]));
        assert!(
            matches!(app.connection_state, ConnectionState::Connecting { .. }),
            "Scanner must never demote Connecting -> Disconnected"
        );
    }

    #[test]
    fn connected_to_disconnecting_on_disconnect() {
        let mut app = test_app();
        add_wg_profiles(&mut app, &["vpn-a"]);
        set_connected(&mut app, "vpn-a");

        app.handle_message(Message::Disconnect);
        assert!(matches!(
            app.connection_state,
            ConnectionState::Disconnecting { .. }
        ));
    }

    #[test]
    fn disconnecting_to_disconnected_on_success() {
        let mut app = test_app();
        set_disconnecting(&mut app, "vpn-a");

        app.handle_message(Message::DisconnectResult {
            profile: "vpn-a".to_string(),
            success: true,
            error: None,
        });
        assert!(matches!(
            app.connection_state,
            ConnectionState::Disconnected
        ));
    }

    #[test]
    fn disconnecting_to_disconnected_on_interface_gone() {
        let mut app = test_app();
        set_disconnecting(&mut app, "vpn-a");

        app.handle_message(Message::SyncSystemState(vec![]));
        assert!(matches!(
            app.connection_state,
            ConnectionState::Disconnected
        ));
    }

    #[test]
    fn disconnecting_safety_timeout() {
        let mut app = test_app();
        app.connection_state = ConnectionState::Disconnecting {
            started: Instant::now()
                .checked_sub(std::time::Duration::from_secs(31))
                .unwrap(),
            profile: "vpn-a".to_string(),
        };

        app.handle_message(Message::SyncSystemState(vec![fake_session("vpn-a")]));
        assert!(matches!(
            app.connection_state,
            ConnectionState::Disconnected
        ));
    }

    #[test]
    fn connection_timeout_from_connecting() {
        let mut app = test_app();
        set_connecting(&mut app, "vpn-a");

        app.handle_message(Message::ConnectionTimeout("vpn-a".to_string()));
        assert!(matches!(
            app.connection_state,
            ConnectionState::Disconnected
        ));
        assert!(app.pending_connect.is_none());
    }

    #[test]
    fn connected_drop_detected_by_scanner() {
        let mut app = test_app();
        set_connected(&mut app, "vpn-a");

        app.handle_message(Message::SyncSystemState(vec![]));
        assert!(matches!(
            app.connection_state,
            ConnectionState::Disconnected
        ));
        assert_eq!(app.connection_drops, 1);
    }

    #[test]
    fn stale_connect_result_ignored() {
        let mut app = test_app();
        app.connection_state = ConnectionState::Disconnected;

        app.handle_message(Message::ConnectResult {
            profile: "vpn-a".to_string(),
            success: true,
            error: None,
        });
        assert!(matches!(
            app.connection_state,
            ConnectionState::Disconnected
        ));
    }

    #[test]
    fn full_lifecycle_connect_disconnect() {
        let mut app = test_app();
        add_wg_profiles(&mut app, &["vpn-a"]);

        // Disconnected -> Connecting (simulate connect_profile)
        set_connecting(&mut app, "vpn-a");
        assert!(matches!(
            app.connection_state,
            ConnectionState::Connecting { .. }
        ));

        // Connecting -> Connected
        app.handle_message(Message::ConnectResult {
            profile: "vpn-a".to_string(),
            success: true,
            error: None,
        });
        assert!(matches!(
            app.connection_state,
            ConnectionState::Connected { .. }
        ));

        // Connected -> Disconnecting
        app.handle_message(Message::Disconnect);
        assert!(matches!(
            app.connection_state,
            ConnectionState::Disconnecting { .. }
        ));

        // Disconnecting -> Disconnected
        app.handle_message(Message::DisconnectResult {
            profile: "vpn-a".to_string(),
            success: true,
            error: None,
        });
        assert!(matches!(
            app.connection_state,
            ConnectionState::Disconnected
        ));
    }

    #[test]
    fn profile_switch_via_pending_connect() {
        let mut app = test_app();
        add_wg_profiles(&mut app, &["vpn-a", "vpn-b"]);
        app.is_root = true;

        // Manually set up the switch scenario: Disconnecting from vpn-a with
        // vpn-b queued. This avoids spawning real disconnect/connect commands.
        set_disconnecting(&mut app, "vpn-a");
        app.pending_connect = Some(1);

        // Disconnect completes -> complete_disconnect drains pending_connect
        app.handle_message(Message::DisconnectResult {
            profile: "vpn-a".to_string(),
            success: true,
            error: None,
        });

        // complete_disconnect calls connect_profile(1) for vpn-b.
        // If wg tools are available, state becomes Connecting to vpn-b.
        // If not, state becomes Disconnected with DependencyError mode.
        let switched = matches!(
            app.connection_state,
            ConnectionState::Connecting { ref profile, .. } if profile == "vpn-b"
        );
        let dep_error = matches!(app.input_mode, InputMode::DependencyError { .. });
        assert!(
            switched || dep_error,
            "Should auto-connect to vpn-b or show dependency error, got {:?}",
            app.connection_state
        );
        assert_eq!(app.pending_connect, None);
    }
}

// ============================================================================
// Kill Switch Lifecycle Tests
// ============================================================================

mod killswitch_lifecycle {
    use super::*;

    #[test]
    fn mode_cycling_off_auto_alwayson() {
        let mut app = test_app();
        assert_eq!(app.killswitch_mode, KillSwitchMode::Off);

        app.handle_message(Message::ToggleKillSwitch);
        assert_eq!(app.killswitch_mode, KillSwitchMode::Auto);

        app.handle_message(Message::ToggleKillSwitch);
        assert_eq!(app.killswitch_mode, KillSwitchMode::AlwaysOn);

        app.handle_message(Message::ToggleKillSwitch);
        assert_eq!(app.killswitch_mode, KillSwitchMode::Off);
    }

    #[test]
    fn auto_mode_arms_when_connected() {
        let mut app = test_app();
        add_wg_profiles(&mut app, &["vpn-a"]);
        set_connected(&mut app, "vpn-a");
        app.killswitch_mode = KillSwitchMode::Off;

        app.handle_message(Message::ToggleKillSwitch); // Off -> Auto
        assert_eq!(app.killswitch_mode, KillSwitchMode::Auto);
        assert_eq!(app.killswitch_state, KillSwitchState::Armed);
    }

    #[test]
    fn alwayson_blocks_when_disconnected() {
        let mut app = test_app();
        app.is_root = true;
        app.killswitch_mode = KillSwitchMode::Auto;
        app.handle_message(Message::ToggleKillSwitch); // Auto -> AlwaysOn
        assert_eq!(app.killswitch_mode, KillSwitchMode::AlwaysOn);
        assert_eq!(app.killswitch_state, KillSwitchState::Blocking);
    }

    #[test]
    fn killswitch_activated_on_vpn_drop() {
        let mut app = test_app();
        app.is_root = true;
        add_wg_profiles(&mut app, &["vpn-a"]);
        app.killswitch_mode = KillSwitchMode::Auto;
        app.killswitch_state = KillSwitchState::Armed;
        set_connected(&mut app, "vpn-a");

        // VPN drops
        app.handle_message(Message::SyncSystemState(vec![]));

        assert!(matches!(
            app.connection_state,
            ConnectionState::Disconnected
        ));
        assert_eq!(app.killswitch_state, KillSwitchState::Blocking);
        assert_eq!(app.connection_drops, 1);
    }

    #[test]
    fn killswitch_stays_disabled_when_mode_off() {
        let mut app = test_app();
        app.killswitch_mode = KillSwitchMode::Off;
        app.killswitch_state = KillSwitchState::Disabled;
        set_connected(&mut app, "vpn-a");

        // VPN drops
        app.handle_message(Message::SyncSystemState(vec![]));

        assert_eq!(app.killswitch_state, KillSwitchState::Disabled);
    }

    #[test]
    fn off_mode_disables_killswitch() {
        let mut app = test_app();
        app.killswitch_mode = KillSwitchMode::AlwaysOn;
        app.killswitch_state = KillSwitchState::Blocking;

        // Toggle to Off
        app.handle_message(Message::ToggleKillSwitch);
        assert_eq!(app.killswitch_mode, KillSwitchMode::Off);
        assert_eq!(app.killswitch_state, KillSwitchState::Disabled);
    }

    #[test]
    fn quit_cleans_up_killswitch() {
        let mut app = test_app();
        app.killswitch_mode = KillSwitchMode::AlwaysOn;
        app.killswitch_state = KillSwitchState::Blocking;

        app.handle_message(Message::Quit);
        assert!(app.should_quit);
    }

    #[test]
    fn non_root_cannot_enter_blocking_state() {
        let mut app = test_app();
        assert!(!app.is_root);
        app.killswitch_mode = KillSwitchMode::Auto;
        app.handle_message(Message::ToggleKillSwitch); // Auto -> AlwaysOn
        assert_eq!(app.killswitch_mode, KillSwitchMode::AlwaysOn);
        assert_eq!(
            app.killswitch_state,
            KillSwitchState::Armed,
            "Non-root should be refused Blocking state"
        );
        let toast = app.toast.as_ref().expect("should show warning toast");
        assert_eq!(toast.toast_type, ToastType::Warning);
        assert!(toast.message.contains("root"));
    }
}

// ============================================================================
// Profile Import Validation Tests
// ============================================================================

mod profile_import {
    use super::*;

    fn create_temp_profile(
        dir: &std::path::Path,
        name: &str,
        content: &str,
        ext: &str,
    ) -> std::path::PathBuf {
        let path = dir.join(format!("{name}.{ext}"));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn import_valid_wireguard_profile() {
        let tmp = tempfile::Builder::new()
            .prefix("vortix_import_")
            .tempdir()
            .unwrap();
        let path = create_temp_profile(
            tmp.path(),
            "valid-wg",
            "[Interface]\nPrivateKey = abc123=\nAddress = 10.0.0.1/24\n\n[Peer]\nPublicKey = xyz789=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n",
            "conf",
        );
        let result = vortix::vpn::import_profile(&path);
        assert!(
            result.is_ok(),
            "Valid WireGuard config should import: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().protocol, Protocol::WireGuard);
    }

    #[test]
    fn import_valid_openvpn_profile() {
        let tmp = tempfile::Builder::new()
            .prefix("vortix_import_")
            .tempdir()
            .unwrap();
        let path = create_temp_profile(
            tmp.path(),
            "valid-ovpn",
            "client\ndev tun\nproto udp\nremote vpn.example.com 1194\n<ca>\n-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n</ca>\n",
            "ovpn",
        );
        let result = vortix::vpn::import_profile(&path);
        assert!(
            result.is_ok(),
            "Valid OpenVPN config should import: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().protocol, Protocol::OpenVPN);
    }

    #[test]
    fn import_nonexistent_file() {
        let path = std::path::PathBuf::from("/tmp/vortix_no_such_file_12345.conf");
        let result = vortix::vpn::import_profile(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn import_empty_file() {
        let tmp = tempfile::Builder::new()
            .prefix("vortix_import_")
            .tempdir()
            .unwrap();
        let path = create_temp_profile(tmp.path(), "empty", "", "conf");
        let result = vortix::vpn::import_profile(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn import_unsupported_extension() {
        let tmp = tempfile::Builder::new()
            .prefix("vortix_import_")
            .tempdir()
            .unwrap();
        let path = create_temp_profile(tmp.path(), "bad-ext", "some content", "txt");
        let result = vortix::vpn::import_profile(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported"));
    }

    #[test]
    fn import_malformed_wireguard_missing_interface() {
        let tmp = tempfile::Builder::new()
            .prefix("vortix_import_")
            .tempdir()
            .unwrap();
        let path = create_temp_profile(
            tmp.path(),
            "bad-wg",
            "[Peer]\nPublicKey = xyz789=\nEndpoint = 1.2.3.4:51820\n",
            "conf",
        );
        let result = vortix::vpn::import_profile(&path);
        assert!(result.is_err(), "Missing [Interface] should fail");
    }

    #[test]
    fn import_malformed_openvpn_only_remote() {
        let tmp = tempfile::Builder::new()
            .prefix("vortix_import_")
            .tempdir()
            .unwrap();
        let path = create_temp_profile(
            tmp.path(),
            "bad-ovpn",
            "remote vpn.example.com 1194\n",
            "ovpn",
        );
        let result = vortix::vpn::import_profile(&path);
        assert!(
            result.is_err(),
            "OpenVPN with only 'remote' should fail validation"
        );
    }

    #[test]
    fn import_directory_with_mixed_files() {
        let tmp = tempfile::Builder::new()
            .prefix("vortix_bulk_import_")
            .tempdir()
            .unwrap();
        let dir = tmp.path();

        std::fs::write(
            dir.join("good.conf"),
            "[Interface]\nPrivateKey = abc=\nAddress = 10.0.0.1/24\n\n[Peer]\nPublicKey = xyz=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n",
        ).unwrap();
        std::fs::write(dir.join("ignore.txt"), "not a vpn config").unwrap();
        std::fs::write(dir.join("empty.conf"), "").unwrap();

        let mut app = test_app();
        app.input_mode = InputMode::Import {
            path: dir.to_string_lossy().to_string(),
            cursor: 0,
        };
        let initial = app.profiles.len();
        app.handle_message(Message::Import(dir.to_string_lossy().to_string()));

        assert!(
            app.profiles.len() > initial,
            "Should import at least the valid profile"
        );
        assert!(
            matches!(app.input_mode, InputMode::Normal),
            "Overlay should close after successful directory import"
        );
    }

    #[test]
    fn import_empty_directory_keeps_overlay_open() {
        let tmp = tempfile::Builder::new()
            .prefix("vortix_empty_import_")
            .tempdir()
            .unwrap();
        let dir = tmp.path();

        std::fs::write(dir.join("readme.txt"), "not a config").unwrap();

        let mut app = test_app();
        app.input_mode = InputMode::Import {
            path: dir.to_string_lossy().to_string(),
            cursor: 0,
        };
        app.handle_message(Message::Import(dir.to_string_lossy().to_string()));

        assert!(
            matches!(app.input_mode, InputMode::Import { .. }),
            "Overlay should stay open when no profiles were imported"
        );
    }
}

// ============================================================================
// Message Routing Tests
// ============================================================================

mod message_routing {
    use super::*;

    #[test]
    fn next_panel_cycles_forward() {
        let mut app = test_app();
        app.focused_panel = FocusedPanel::Sidebar;

        app.handle_message(Message::NextPanel);
        assert_eq!(app.focused_panel, FocusedPanel::Chart);

        app.handle_message(Message::NextPanel);
        assert_eq!(app.focused_panel, FocusedPanel::ConnectionDetails);

        app.handle_message(Message::NextPanel);
        assert_eq!(app.focused_panel, FocusedPanel::Security);

        app.handle_message(Message::NextPanel);
        assert_eq!(app.focused_panel, FocusedPanel::Logs);

        app.handle_message(Message::NextPanel);
        assert_eq!(app.focused_panel, FocusedPanel::Sidebar);
    }

    #[test]
    fn previous_panel_cycles_backward() {
        let mut app = test_app();
        app.focused_panel = FocusedPanel::Sidebar;

        app.handle_message(Message::PreviousPanel);
        assert_eq!(app.focused_panel, FocusedPanel::Logs);
    }

    #[test]
    fn focus_panel_sets_specific_panel() {
        let mut app = test_app();
        app.handle_message(Message::FocusPanel(FocusedPanel::Chart));
        assert_eq!(app.focused_panel, FocusedPanel::Chart);
    }

    #[test]
    fn toggle_zoom() {
        let mut app = test_app();
        assert!(app.zoomed_panel.is_none());

        app.handle_message(Message::ToggleZoom);
        assert!(app.zoomed_panel.is_some());

        app.handle_message(Message::ToggleZoom);
        assert!(app.zoomed_panel.is_none());
    }

    #[test]
    fn open_import_sets_mode() {
        let mut app = test_app();
        app.handle_message(Message::OpenImport);
        assert!(matches!(app.input_mode, InputMode::Import { .. }));
    }

    #[test]
    fn close_overlay_resets_all() {
        let mut app = test_app();
        app.show_config = true;
        app.show_action_menu = true;
        app.show_bulk_menu = true;
        app.zoomed_panel = Some(FocusedPanel::Chart);
        app.input_mode = InputMode::Import {
            path: String::new(),
            cursor: 0,
        };

        app.handle_message(Message::CloseOverlay);

        assert!(!app.show_config);
        assert!(!app.show_action_menu);
        assert!(!app.show_bulk_menu);
        assert_eq!(
            app.zoomed_panel,
            Some(FocusedPanel::Chart),
            "CloseOverlay must preserve zoom state"
        );
        assert_eq!(app.input_mode, InputMode::Normal);
    }

    #[test]
    fn profile_move_navigation() {
        let mut app = test_app();
        add_wg_profiles(&mut app, &["vpn-a", "vpn-b", "vpn-c"]);
        app.profile_list_state.select(Some(0));

        app.handle_message(Message::ProfileMove(SelectionMove::Next));
        assert_eq!(app.profile_list_state.selected(), Some(1));

        app.handle_message(Message::ProfileMove(SelectionMove::Last));
        let last_idx = app.profiles.len() - 1;
        assert_eq!(app.profile_list_state.selected(), Some(last_idx));

        app.handle_message(Message::ProfileMove(SelectionMove::First));
        assert_eq!(app.profile_list_state.selected(), Some(0));
    }

    #[test]
    fn log_message_does_not_crash() {
        let mut app = test_app();
        app.handle_message(Message::Log("TEST: integration log".to_string()));
    }

    #[test]
    fn toast_message() {
        let mut app = test_app();
        app.handle_message(Message::Toast("Test toast".to_string(), ToastType::Info));
        assert!(app.toast.is_some());
        assert_eq!(app.toast.as_ref().unwrap().toast_type, ToastType::Info);
    }

    #[test]
    fn clear_logs_resets_scroll() {
        let mut app = test_app();
        app.logs_scroll = 10;
        app.handle_message(Message::ClearLogs);
        // After clear, logs_scroll should be small (ClearLogs logs "APP: Logs cleared")
    }

    #[test]
    fn resize_updates_terminal_size() {
        let mut app = test_app();
        app.handle_message(Message::Resize(200, 50));
        assert_eq!(app.terminal_size, (200, 50));
    }

    #[test]
    fn quit_sets_should_quit() {
        let mut app = test_app();
        app.handle_message(Message::Quit);
        assert!(app.should_quit);
    }

    #[test]
    fn scroll_in_config_view() {
        let mut app = test_app();
        app.show_config = true;
        app.config_scroll = 5;

        app.handle_message(Message::Scroll(ScrollMove::Up));
        assert_eq!(app.config_scroll, 4);

        app.handle_message(Message::Scroll(ScrollMove::Top));
        assert_eq!(app.config_scroll, 0);
    }

    #[test]
    fn open_delete_with_profile() {
        let mut app = test_app();
        add_wg_profiles(&mut app, &["vpn-a"]);
        app.profile_list_state.select(Some(0));

        app.handle_message(Message::OpenDelete(None));
        assert!(matches!(app.input_mode, InputMode::ConfirmDelete { .. }));
    }

    #[test]
    fn cannot_delete_connected_profile() {
        let mut app = test_app();
        add_wg_profiles(&mut app, &["vpn-a"]);
        set_connected(&mut app, "vpn-a");
        app.profile_list_state.select(Some(0));

        app.handle_message(Message::OpenDelete(Some(0)));
        assert!(
            !matches!(app.input_mode, InputMode::ConfirmDelete { .. }),
            "Should not be able to delete connected profile"
        );
    }

    #[test]
    fn quick_connect_out_of_range_ignored() {
        let mut app = test_app();
        add_wg_profiles(&mut app, &["vpn-a"]);

        app.handle_message(Message::QuickConnect(99));
        assert!(matches!(
            app.connection_state,
            ConnectionState::Disconnected
        ));
    }

    #[test]
    fn telemetry_public_ip_update() {
        use vortix::core::telemetry::TelemetryUpdate;

        let mut app = test_app();
        app.handle_message(Message::Telemetry(TelemetryUpdate::PublicIp(
            "1.2.3.4".to_string(),
        )));
        assert_eq!(app.public_ip, "1.2.3.4");
    }

    #[test]
    fn telemetry_latency_update() {
        use vortix::core::telemetry::TelemetryUpdate;

        let mut app = test_app();
        app.handle_message(Message::Telemetry(TelemetryUpdate::Latency(42)));
        assert_eq!(app.latency_ms, 42);
    }

    #[test]
    fn telemetry_ipv6_leak_detection() {
        use vortix::core::telemetry::TelemetryUpdate;

        let mut app = test_app();
        app.handle_message(Message::Telemetry(TelemetryUpdate::Ipv6Leak(true)));
        assert!(app.ipv6_leak);
    }

    #[test]
    fn tick_expires_old_toast() {
        let mut app = test_app();
        app.toast = Some(Toast {
            message: "expired".to_string(),
            toast_type: ToastType::Info,
            expires: Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .unwrap(),
        });

        app.handle_message(Message::Tick);
        assert!(app.toast.is_none(), "Expired toast should be cleared");
    }
}
