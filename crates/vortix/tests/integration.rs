//! Integration tests for Vortix core functionality.
//!
//! These tests construct a lightweight `App` instance and drive it through
//! scenarios without requiring actual VPN tools, root privileges, or network
//! access.  All filesystem operations are redirected to a temporary directory
//! via `config::set_config_dir()` so that tests never touch the user's real
//! `~/.config/vortix/`.
//!
//! That redirection is installed by `init_test_env()`, and it is not
//! automatic: `config::set_config_dir` is a `OnceLock`, so whichever test runs
//! first decides where every later one writes. A test that touches the
//! filesystem without calling it wrote into the developer's real profile
//! directory whenever it happened to win that race — leaving stray sidecars
//! behind and failing under load. Every test here must call it, directly or
//! through `test_app()`.

use std::sync::Once;
use std::time::Instant;

use vortix::profile::ProtocolKind;

use vortix::app::{App, FocusedPanel, InputMode, Toast, ToastType};
use vortix::config::profiles::VpnProfile;
use vortix::message::{Message, ScrollMove, SelectionMove};

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
            id: vortix::profile::ProfileId::new(*name),
            name: (*name).to_string(),
            protocol: ProtocolKind::WireGuard,
            config_path: std::path::PathBuf::from(format!("/tmp/{name}.conf")),
            location: "Test".to_string(),
            last_used: None,
            group: None,
        });
    }
}

fn set_connected(app: &mut App, name: &str) {
    if !app.runtime.profiles.iter().any(|p| p.name == name) {
        add_wg_profiles(app, &[name]);
    }
    let details = vortix::tunnel::DetailedConnectionInfo {
        interface: "wg0".to_string(),
        interface_authoritative: true,
        pid: Some(12345),
        ..Default::default()
    };
    set_projection(
        app,
        name,
        &vortix::tunnel::Connection::Connected {
            profile_id: vortix::profile::ProfileId::new(name),
            since: std::time::SystemTime::now(),
            details: Box::new(details),
        },
    );
}

fn set_projection(app: &mut App, name: &str, state: &vortix::tunnel::Connection) {
    use vortix::control::{Phase, TunnelView};
    use vortix::profile::ProfileId;
    use vortix::tunnel::Connection;

    let phase = match state {
        Connection::Connected { .. } => Phase::Up,
        Connection::Disconnecting { .. } => Phase::Stopping,
        Connection::Reconnecting { .. } => Phase::Waiting { retry_at: None },
        Connection::AwaitingUserInput { .. } => Phase::AwaitingCredentials,
        _ => Phase::Starting,
    };
    let profile_id = ProfileId::new(name);
    let mut snapshot = (*app.control_snapshot).clone();
    snapshot.version += 1;
    snapshot.primary = Some(profile_id.clone());
    snapshot
        .tunnels
        .retain(|tunnel| tunnel.profile_id != profile_id);
    snapshot.tunnels.push(TunnelView {
        profile_id,
        name: name.to_owned(),
        phase,
        interface: Some("wg0".into()),
        since: std::time::SystemTime::now(),
        routes: Vec::new(),
        dns: Vec::new(),
        details: vortix::tunnel::DetailedConnectionInfo {
            interface: "wg0".into(),
            ..Default::default()
        },
        health: vortix::tunnel::ConnectionHealth::default(),
    });
    app.apply_control_snapshot(std::sync::Arc::new(snapshot));
}

// ============================================================================
// Profile Import Validation Tests
// ============================================================================

mod profile_import {
    use super::*;

    /// Every test in this binary shares one config dir: `init_test_env` sets it
    /// through a `Once`, and `set_config_dir` is first-write-wins, so there is no
    /// per-test directory to fall back on. Imports therefore contend for a single
    /// profile-storage lock, and on a loaded CI runner the losers time out with
    /// "profile storage is busy". Serialising them removes the contention.
    static IMPORT_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn import_serialised(
        path: &std::path::Path,
    ) -> Result<vortix::config::profiles::VpnProfile, String> {
        let _guard = IMPORT_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        vortix::config::profiles::import_profile(path)
    }

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
        init_test_env();
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
        let result = import_serialised(&path);
        assert!(
            result.is_ok(),
            "Valid WireGuard config should import: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().protocol, ProtocolKind::WireGuard);
    }

    #[test]
    fn import_valid_openvpn_profile() {
        init_test_env();
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
        let result = import_serialised(&path);
        assert!(
            result.is_ok(),
            "Valid OpenVPN config should import: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().protocol, ProtocolKind::OpenVpn);
    }

    #[test]
    fn import_nonexistent_file() {
        init_test_env();
        let path = std::path::PathBuf::from("/tmp/vortix_no_such_file_12345.conf");
        let result = import_serialised(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn import_empty_file() {
        init_test_env();
        let tmp = tempfile::Builder::new()
            .prefix("vortix_import_")
            .tempdir()
            .unwrap();
        let path = create_temp_profile(tmp.path(), "empty", "", "conf");
        let result = import_serialised(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn import_unsupported_extension() {
        init_test_env();
        let tmp = tempfile::Builder::new()
            .prefix("vortix_import_")
            .tempdir()
            .unwrap();
        let path = create_temp_profile(tmp.path(), "bad-ext", "some content", "txt");
        let result = import_serialised(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported"));
    }

    #[test]
    fn import_malformed_wireguard_missing_interface() {
        init_test_env();
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
        let result = import_serialised(&path);
        assert!(result.is_err(), "Missing [Interface] should fail");
    }

    #[test]
    fn import_malformed_openvpn_only_remote() {
        init_test_env();
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
        let result = import_serialised(&path);
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
        assert!(app
            .current_tunnel()
            .is_none_or(|t| matches!(t.state, vortix::tunnel::Connection::Disconnected)));
    }

    #[test]
    fn telemetry_public_ip_update() {
        use vortix::telemetry::TelemetryUpdate;

        let mut app = test_app();
        app.handle_message(Message::Telemetry(TelemetryUpdate::EgressIdentity(
            vortix::telemetry::EgressIdentity {
                public_ip: "1.2.3.4".to_string(),
                isp: None,
                location: None,
            },
        )));
        assert_eq!(app.runtime.public_ip, "1.2.3.4");
    }

    #[test]
    fn telemetry_network_quality_update_is_atomic() {
        use vortix::telemetry::TelemetryUpdate;

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
        use vortix::telemetry::TelemetryUpdate;

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
