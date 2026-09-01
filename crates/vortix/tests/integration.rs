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
    App, ConnectionState, FocusedPanel, InputMode, Protocol, Toast, ToastType, VpnProfile,
};
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
        app.runtime.profiles.push(VpnProfile {
            id: vortix::vortix_core::profile::ProfileId::new(*name),
            name: (*name).to_string(),
            protocol: Protocol::WireGuard,
            config_path: std::path::PathBuf::from(format!("/tmp/{name}.conf")),
            location: "Test".to_string(),
            last_used: None,
        });
    }
}

fn set_connected(app: &mut App, name: &str) {
    if !app.runtime.profiles.iter().any(|p| p.name == name) {
        add_wg_profiles(app, &[name]);
    }
    app.runtime.session_start = Some(Instant::now());
    let details = vortix::vortix_core::engine::DetailedConnectionInfo {
        interface: "wg0".to_string(),
        interface_authoritative: true,
        pid: Some(12345),
        ..Default::default()
    };
    set_projection(
        app,
        name,
        vortix::vortix_core::engine::state::Connection::Connected {
            profile_id: vortix::vortix_core::profile::ProfileId::new(name),
            since: std::time::SystemTime::now(),
            health: vortix::vortix_core::engine::state::ConnectionHealth::Healthy,
            details: Box::new(details),
        },
    );
}

fn set_connecting(app: &mut App, name: &str) {
    if !app.runtime.profiles.iter().any(|p| p.name == name) {
        add_wg_profiles(app, &[name]);
    }
    set_projection(
        app,
        name,
        vortix::vortix_core::engine::state::Connection::Connecting {
            profile_id: vortix::vortix_core::profile::ProfileId::new(name),
            started_at: std::time::SystemTime::now(),
            attempt: 1,
            retry_budget_remaining: std::time::Duration::ZERO,
        },
    );
}

fn set_disconnecting(app: &mut App, name: &str) {
    use vortix::vortix_core::profile::ProfileId;
    if app.registry.snapshot(&ProfileId::new(name)).is_none() {
        set_connected(app, name);
    }
    set_projection(
        app,
        name,
        vortix::vortix_core::engine::state::Connection::Disconnecting {
            profile_id: vortix::vortix_core::profile::ProfileId::new(name),
            started_at: std::time::SystemTime::now(),
        },
    );
}

fn set_projection(
    app: &mut App,
    name: &str,
    state: vortix::vortix_core::engine::state::Connection,
) {
    use vortix::vortix_core::engine::{ConnectionHealth, Role, TunnelSnapshot};
    use vortix::vortix_core::profile::ProfileId;

    let profile_id = ProfileId::new(name);
    let mut snapshot = app.control_snapshot.clone();
    snapshot.generation = snapshot.generation.saturating_add(1);
    snapshot.primary = Some(profile_id.clone());
    snapshot.tunnels.insert(
        profile_id.clone(),
        TunnelSnapshot {
            profile_id,
            state,
            role: Role::Primary {
                allowed_ips: Vec::new(),
            },
            health: ConnectionHealth::Healthy,
            interface_name: Some("wg0".into()),
            started_at: Some(std::time::SystemTime::now()),
        },
    );
    app.handle_message(Message::ControlSnapshot(Box::new(snapshot)));
}

mod canonical_control_projection {
    use super::*;
    #[test]
    fn lifecycle_is_rendered_only_from_successive_snapshots() {
        let mut app = test_app();
        set_connecting(&mut app, "vpn-a");
        assert!(matches!(
            app.legacy_state(),
            ConnectionState::Connecting { .. }
        ));

        set_connected(&mut app, "vpn-a");
        assert!(matches!(
            app.legacy_state(),
            ConnectionState::Connected { .. }
        ));

        set_disconnecting(&mut app, "vpn-a");
        assert!(matches!(
            app.legacy_state(),
            ConnectionState::Disconnecting { .. }
        ));

        let mut snapshot = app.control_snapshot.clone();
        snapshot.generation = snapshot.generation.saturating_add(1);
        snapshot.tunnels.clear();
        snapshot.primary = None;
        app.handle_message(Message::ControlSnapshot(Box::new(snapshot)));
        assert!(matches!(app.legacy_state(), ConnectionState::Disconnected));
    }

    #[test]
    fn unknown_effective_policy_is_degraded_unless_the_desired_mode_is_off() {
        let mut app = test_app();
        let mut snapshot = app.control_snapshot.clone();
        snapshot.generation = 1;
        snapshot.desired.kill_switch = KillSwitchMode::AlwaysOn;
        snapshot.effective.kill_switch = None;
        app.handle_message(Message::ControlSnapshot(Box::new(snapshot)));
        assert_eq!(app.registry.killswitch_mode(), KillSwitchMode::AlwaysOn);
        assert_eq!(app.registry.killswitch_state(), KillSwitchState::Degraded);

        let mut off = app.control_snapshot.clone();
        off.generation = off.generation.saturating_add(1);
        off.desired.kill_switch = KillSwitchMode::Off;
        off.effective.kill_switch = None;
        app.handle_message(Message::ControlSnapshot(Box::new(off)));
        assert_eq!(app.registry.killswitch_mode(), KillSwitchMode::Off);
        assert_eq!(app.registry.killswitch_state(), KillSwitchState::Disabled);
    }

    #[test]
    fn protected_auto_is_armed_only_while_a_tunnel_is_connected() {
        let mut app = test_app();
        set_connected(&mut app, "vpn-a");
        let mut snapshot = app.control_snapshot.clone();
        snapshot.generation = snapshot.generation.saturating_add(1);
        snapshot.desired.kill_switch = KillSwitchMode::Auto;
        snapshot.effective.kill_switch = Some(KillSwitchState::Armed);
        app.handle_message(Message::ControlSnapshot(Box::new(snapshot)));
        assert_eq!(app.runtime.killswitch_state, KillSwitchState::Armed);

        let mut blocked = app.control_snapshot.clone();
        blocked.generation = blocked.generation.saturating_add(1);
        blocked.effective.kill_switch = Some(KillSwitchState::Blocking);
        blocked.tunnels.clear();
        blocked.primary = None;
        app.handle_message(Message::ControlSnapshot(Box::new(blocked)));
        assert_eq!(app.runtime.killswitch_state, KillSwitchState::Blocking);
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
        let initial = app.runtime.profiles.len();
        app.handle_message(Message::Import(dir.to_string_lossy().to_string()));

        assert!(
            app.runtime.profiles.len() > initial,
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
        let last_idx = app.runtime.profiles.len() - 1;
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
        assert!(matches!(app.legacy_state(), ConnectionState::Disconnected));
    }

    #[test]
    fn telemetry_public_ip_update() {
        use vortix::core::telemetry::TelemetryUpdate;

        let mut app = test_app();
        app.handle_message(Message::Telemetry(TelemetryUpdate::PublicIp(
            "1.2.3.4".to_string(),
        )));
        assert_eq!(app.runtime.public_ip, "1.2.3.4");
    }

    #[test]
    fn telemetry_network_quality_update_is_atomic() {
        use vortix::core::telemetry::TelemetryUpdate;

        let mut app = test_app();
        app.handle_message(Message::Telemetry(TelemetryUpdate::NetworkQuality {
            latency_ms: 42,
            packet_loss: 1.5,
            jitter_ms: 7,
        }));
        assert_eq!(app.runtime.latency_ms, 42);
        assert!((app.runtime.packet_loss - 1.5).abs() < f32::EPSILON);
        assert_eq!(app.runtime.jitter_ms, 7);
    }

    #[test]
    fn telemetry_publicipv6_leak_detection() {
        use vortix::core::telemetry::TelemetryUpdate;

        let mut app = test_app();
        app.runtime.scanner_first_tick_done = true;
        app.runtime.last_kernel_session_count = 0;

        let ip = "2401:4900:1c61:23c4::1".to_string();
        app.handle_message(Message::Telemetry(TelemetryUpdate::PublicIpv6(Some(
            ip.clone(),
        ))));
        assert_eq!(app.runtime.real_ipv6.as_ref(), Some(&ip));
        assert_eq!(app.runtime.public_ipv6.as_ref(), Some(&ip));
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
