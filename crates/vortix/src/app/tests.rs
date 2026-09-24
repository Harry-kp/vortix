use super::*;
use crate::config::profiles::VpnProfile;
use crate::profile::ProtocolKind;

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
    let mut app = App::new_test();
    app.runtime.config_dir =
        std::env::temp_dir().join(format!("vortix_test_{}", std::process::id()));
    app.terminal_size = (80, 24);
    app
}

fn set_phase(app: &mut App, name: &str, phase: crate::control::Phase) {
    if !app
        .runtime
        .profiles
        .iter()
        .any(|profile| profile.name == name)
    {
        add_profiles(app, &[name]);
    }
    let profile_id = crate::profile::ProfileId::new(name);
    let mut snapshot = (*app.control_snapshot).clone();
    snapshot
        .tunnels
        .retain(|tunnel| tunnel.profile_id != profile_id);
    snapshot.tunnels.push(crate::control::TunnelView {
        profile_id,
        name: name.to_owned(),
        phase,
        interface: Some("wg0".to_owned()),
        since: std::time::SystemTime::UNIX_EPOCH,
        routes: Vec::new(),
        dns: Vec::new(),
        details: crate::tunnel::DetailedConnectionInfo {
            interface: "wg0".to_owned(),
            interface_authoritative: true,
            pid: Some(12_345),
            ..Default::default()
        },
        health: crate::tunnel::ConnectionHealth::default(),
    });
    snapshot
        .tunnels
        .sort_by(|a, b| a.profile_id.cmp(&b.profile_id));
    snapshot.version += 1;
    app.apply_control_snapshot(std::sync::Arc::new(snapshot));
}

fn set_connected(app: &mut App, name: &str) {
    set_phase(app, name, crate::control::Phase::Up);
}

#[test]
fn u1_multi_tunnel_no_primary_projection_is_stable_and_sorted() {
    let mut app = test_app();
    set_connected(&mut app, "zeta");
    set_connected(&mut app, "alpha");

    let snapshots = app.tunnels();
    let names: Vec<&str> = snapshots
        .iter()
        .map(|snapshot| snapshot.profile_id.as_str())
        .collect();
    assert_eq!(names, ["alpha", "zeta"]);
    assert!(app.primary_id().is_none());
    let current = app
        .current_tunnel()
        .expect("with no primary the first active tunnel is current");
    assert!(current.phase == crate::control::Phase::Up);
    assert_eq!(app.profile_display_name(&current.profile_id), "alpha");
}
fn set_disconnecting(app: &mut App, name: &str) {
    set_phase(app, name, crate::control::Phase::Stopping);
}

// ====================================================================
// DisconnectResult handler tests
// ====================================================================

// ====================================================================
// Scanner debounce guard tests (SyncSystemState while Disconnecting)
// ====================================================================

// ====================================================================
// Force disconnect (d pressed twice) tests
// ====================================================================
#[test]
fn test_d_while_disconnected_is_noop() {
    let mut app = test_app();
    app.handle_message(Message::Disconnect);
    assert!(app.current_tunnel().is_none());
}

// ====================================================================
// Helpers for new tests
// ====================================================================
fn set_connecting(app: &mut App, name: &str) {
    set_phase(app, name, crate::control::Phase::Starting);
}

/// Helper: add test profiles to the app.
fn add_profiles(app: &mut App, names: &[&str]) {
    for name in names {
        app.runtime.profiles.push(VpnProfile {
            id: crate::profile::ProfileId::new(*name),
            name: (*name).to_string(),
            protocol: ProtocolKind::WireGuard,
            config_path: std::path::PathBuf::from(format!("/tmp/{name}.conf")),
            location: "Test".to_string(),
            last_used: None,
            group: None,
        });
    }
}

fn add_stored_profile(
    app: &mut App,
    store: &crate::config::profile_store::FsProfileStore,
    directory: &std::path::Path,
    name: &str,
) -> crate::profile::ProfileId {
    static NEXT_TEST_PROFILE_ID: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(1);
    let sequence = NEXT_TEST_PROFILE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let profile_id = crate::profile::ProfileId::parse(format!("{sequence:064x}"))
        .expect("test profile ID must be valid");
    let config_path = directory.join(format!("{name}.conf"));
    let profile = crate::profile::Profile::new(
        profile_id.clone(),
        name,
        crate::profile::ProtocolKind::WireGuard,
        config_path.clone(),
    );
    store.insert(&profile, b"dummy").unwrap();
    app.runtime.profiles.push(VpnProfile {
        id: profile_id.clone(),
        name: name.to_string(),
        protocol: ProtocolKind::WireGuard,
        config_path,
        location: "Test".to_string(),
        last_used: None,
        group: None,
    });
    profile_id
}
// ====================================================================
// VPN switching tests
// ====================================================================
fn takeover_overlay(to: &str) -> InputMode {
    InputMode::ConfirmDefaultRouteTakeover {
        from: "vpn-a".to_string(),
        to_profile_id: crate::profile::ProfileId::new(to),
        to_name: to.to_string(),
        confirm_selected: true,
    }
}
#[test]
fn takeover_overlay_ignores_the_b_key() {
    // "Keep both" was removed: two tunnels cannot both hold the default
    // route. [b]/[B] is no longer a shortcut, so the overlay stays open and
    // waits for Switch or Cancel rather than forcing an unsatisfiable
    // both-default-route topology.
    for key in [key_char('b'), key_shift_char('B')] {
        let mut app = test_app();
        add_profiles(&mut app, &["vpn-a", "vpn-b"]);
        app.input_mode = takeover_overlay("vpn-b");

        app.handle_key(key);

        assert!(
            matches!(
                app.input_mode,
                InputMode::ConfirmDefaultRouteTakeover { .. }
            ),
            "[b]/[B] must be inert now; got {:?}",
            app.input_mode
        );
    }
}
#[test]
fn takeover_overlay_esc_cancels() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b"]);
    app.input_mode = takeover_overlay("vpn-b");

    app.handle_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Esc,
        crossterm::event::KeyModifiers::NONE,
    ));

    assert!(matches!(app.input_mode, InputMode::Normal));
}
#[test]
fn test_toggle_while_connecting_is_rejected() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b"]);
    set_connecting(&mut app, "vpn-a");

    app.toggle_connection(1);

    assert!(app.current_tunnel().is_some_and(|t| matches!(
        t.phase,
        crate::control::Phase::Starting
            | crate::control::Phase::Waiting { .. }
            | crate::control::Phase::AwaitingCredentials
    )));
}

// ====================================================================
// ConnectResult tests
// ====================================================================

// ====================================================================
// Disconnect from Connecting state tests
// ====================================================================
// ====================================================================
// Reconnect is one canonical command (no client-side race)
// ====================================================================
// ====================================================================
// QuickConnect (1-9) edge cases
// ====================================================================
// ====================================================================
// Auth prompt tests
// ====================================================================

#[test]
fn test_auth_field_otp_appears_in_tab_cycle_for_static_challenge_profile() {
    // : tab cycle becomes a 4-stop cycle when
    // static_challenge_prompt.is_some() — Username -> Password -> Otp ->
    // SaveCheckbox -> Username.
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let mut app = test_app();
    app.input_mode = InputMode::AuthPrompt {
        profile_id: crate::profile::ProfileId::new("mfa"),
        profile_name: "mfa".to_string(),
        username: String::new().into(),
        username_cursor: 0,
        password: String::new().into(),
        password_cursor: 0,
        otp: String::new().into(),
        otp_cursor: 0,
        focused_field: AuthField::Username,
        save_credentials: true,
        connect_after: true,
        static_challenge_prompt: Some("Enter code".to_string()),
        reveal_secrets: false,
    };

    // Username -> Password -> Otp -> SaveCheckbox -> Username
    let expected = [
        AuthField::Password,
        AuthField::Otp,
        AuthField::SaveCheckbox,
        AuthField::Username,
    ];
    for expected_field in &expected {
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        if let InputMode::AuthPrompt { focused_field, .. } = &app.input_mode {
            assert_eq!(focused_field, expected_field, "tab cycle drifted");
        } else {
            panic!("Expected AuthPrompt");
        }
    }
}

#[test]
fn test_auth_field_switching() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = test_app();
    app.input_mode = InputMode::AuthPrompt {
        profile_id: crate::profile::ProfileId::new("test"),
        profile_name: "test".to_string(),
        username: String::new().into(),
        username_cursor: 0,
        password: String::new().into(),
        password_cursor: 0,
        otp: String::new().into(),
        otp_cursor: 0,
        focused_field: AuthField::Username,
        save_credentials: true,
        connect_after: true,
        static_challenge_prompt: None,
        reveal_secrets: false,
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

// ====================================================================
// v0.3.0 — "Trustworthy & Alive" tests
// ====================================================================

// --- Phase 1: Last security check timestamp (#47) ---

/// Each field is refreshed by its own probe. A shared "last checked" stamp
/// let a healthy probe vouch for a stalled one, so each observation now
/// carries its own timestamp and only its own probe advances it.
#[test]
fn each_telemetry_observation_carries_its_own_timestamp() {
    use crate::telemetry::TelemetryUpdate;
    let mut app = test_app();
    assert!(app.runtime.last_egress_check.is_none());
    assert!(app.runtime.last_dns_check.is_none());
    assert!(app.runtime.last_ipv6_check.is_none());

    app.handle_message(Message::Telemetry(TelemetryUpdate::EgressIdentity(
        crate::telemetry::EgressIdentity {
            public_ip: "1.2.3.4".to_string(),
            isp: None,
            location: None,
        },
    )));
    assert!(app.runtime.last_egress_check.is_some());
    assert!(
        app.runtime.last_dns_check.is_none(),
        "a public-address reading must not vouch for the resolver reading"
    );
    assert!(
        app.runtime.last_ipv6_check.is_none(),
        "a public-address reading must not vouch for the IPv6 probe"
    );

    app.handle_message(Message::Telemetry(TelemetryUpdate::Dns(
        "9.9.9.9".to_string(),
    )));
    assert!(app.runtime.last_dns_check.is_some());
    assert!(app.runtime.last_ipv6_check.is_none());

    app.handle_message(Message::Telemetry(TelemetryUpdate::PublicIpv6(None)));
    assert!(app.runtime.last_ipv6_check.is_some());
}

/// A reading that has aged out is reported as unknown, not left on screen as
/// though it were current.
#[test]
fn a_stale_observation_is_never_presented_as_current() {
    use std::time::{Duration, Instant};
    let mut app = test_app();
    let window = app.telemetry_stale_after();

    assert!(!app.observation_is_stale(None), "never observed is pending");
    app.runtime.last_egress_check = Some(Instant::now());
    assert!(!app.observation_is_stale(app.runtime.last_egress_check));

    app.runtime.last_egress_check = Instant::now().checked_sub(window + Duration::from_secs(1));
    assert!(
        app.observation_is_stale(app.runtime.last_egress_check),
        "a reading older than the staleness window must not stand for the present"
    );
}

/// An address restored from the cache is what Vortix remembers, not what it
/// has just seen. Only an unprotected observation may promote it.
#[test]
fn a_remembered_real_address_is_promoted_only_by_a_live_observation() {
    use crate::telemetry::TelemetryUpdate;
    let mut app = test_app();
    app.runtime.real_ip = Some("203.0.113.5".to_string());
    app.runtime.real_ip_from_cache = true;

    // Nothing has proved the host is unprotected yet, so the flag stands.
    app.handle_message(Message::Telemetry(TelemetryUpdate::EgressIdentity(
        crate::telemetry::EgressIdentity {
            public_ip: "203.0.113.5".to_string(),
            isp: None,
            location: None,
        },
    )));
    assert!(
        app.runtime.real_ip_from_cache,
        "without proof of an unprotected window the value stays remembered"
    );

    app.runtime.scanner_first_tick_done = true;
    app.runtime.last_kernel_session_count = 0;
    app.handle_message(Message::Telemetry(TelemetryUpdate::EgressIdentity(
        crate::telemetry::EgressIdentity {
            public_ip: "203.0.113.5".to_string(),
            isp: None,
            location: None,
        },
    )));
    assert!(
        !app.runtime.real_ip_from_cache,
        "an unprotected observation confirms the address as current"
    );
}

#[test]
fn test_last_security_check_updated_on_ip_telemetry() {
    use crate::telemetry::TelemetryUpdate;
    let mut app = test_app();
    assert!(app.runtime.last_security_check.is_none());

    app.handle_message(Message::Telemetry(TelemetryUpdate::EgressIdentity(
        crate::telemetry::EgressIdentity {
            public_ip: "1.2.3.4".to_string(),
            isp: None,
            location: None,
        },
    )));

    assert!(app.runtime.last_security_check.is_some());
}

#[test]
fn test_last_security_check_updated_on_dns_telemetry() {
    use crate::telemetry::TelemetryUpdate;
    let mut app = test_app();
    assert!(app.runtime.last_security_check.is_none());

    app.handle_message(Message::Telemetry(TelemetryUpdate::Dns(
        "1.1.1.1".to_string(),
    )));

    assert!(app.runtime.last_security_check.is_some());
}

#[test]
fn test_last_security_check_updated_on_ipv6_telemetry() {
    use crate::telemetry::TelemetryUpdate;
    let mut app = test_app();
    assert!(app.runtime.last_security_check.is_none());

    app.handle_message(Message::Telemetry(TelemetryUpdate::PublicIpv6(None)));

    assert!(app.runtime.last_security_check.is_some());
    assert!(app.runtime.last_ipv6_check.is_some());
}

#[test]
fn test_publicipv6_caches_real_ipv6_when_safe_to_cache() {
    use crate::telemetry::TelemetryUpdate;
    let mut app = test_app();
    app.runtime.scanner_first_tick_done = true;
    app.runtime.last_kernel_session_count = 0;

    app.handle_message(Message::Telemetry(TelemetryUpdate::PublicIpv6(Some(
        "2401:4900::1".to_string(),
    ))));

    assert_eq!(
        app.runtime.real_ipv6.as_deref(),
        Some("2401:4900::1"),
        "real_ipv6 should be cached when fully disconnected"
    );
    assert_eq!(
        app.runtime.public_ipv6.as_deref(),
        Some("2401:4900::1"),
        "public_ipv6 should always update"
    );
}

#[test]
fn test_publicipv6_clears_when_probe_returns_none() {
    use crate::telemetry::TelemetryUpdate;
    let mut app = test_app();
    app.runtime.public_ipv6 = Some("2401:4900::1".to_string());

    app.handle_message(Message::Telemetry(TelemetryUpdate::PublicIpv6(None)));

    assert!(
        app.runtime.public_ipv6.is_none(),
        "public_ipv6 should reset when probe fails"
    );
}

// --- Phase 1: Reconnect from Disconnected (#49) ---
#[test]
fn test_reconnect_from_disconnected_without_last_profile_is_noop() {
    let mut app = test_app();
    add_profiles(&mut app, &["my-vpn"]);
    assert!(app.last_control_connected_profile.is_none());

    app.reconnect();

    assert!(
        app.current_tunnel().is_none(),
        "Should stay disconnected when no last_connected_profile"
    );
}

// --- Phase 1: Timeout toast color (#50) ---

// --- Phase 1: last_connected_profile set on success (#49 + reconnect) ---

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

    app.input_mode = InputMode::Help {
        scroll: 0,
        tab: crate::app::state::HelpTab::Keys,
    };
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
    app.runtime.profiles.push(VpnProfile {
        id: crate::profile::ProfileId::new("test-vpn"),
        name: "test-vpn".to_string(),
        protocol: ProtocolKind::WireGuard,
        config_path: tmp.path().to_path_buf(),
        location: "Test".to_string(),
        last_used: None,
        group: None,
    });
    app.profile_list_state.select(Some(0));

    app.handle_message(Message::OpenConfig);
    assert!(app.show_config, "Config viewer should be open");
    assert!(
        app.cached_config.is_some(),
        "Config content should be cached"
    );
    assert!(app
        .cached_config
        .as_ref()
        .unwrap()
        .content
        .contains("[Interface]"));

    app.handle_message(Message::CloseOverlay);
    assert!(!app.show_config, "Config viewer should be closed");
    assert!(
        app.cached_config.is_none(),
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
fn test_cycle_sort_order() {
    use crate::app::state::ProfileSortOrder;

    let mut app = test_app();
    add_profiles(&mut app, &["charlie", "alpha", "bravo"]);
    app.profile_list_state.select(Some(0));

    assert_eq!(app.runtime.sort_order, ProfileSortOrder::NameAsc);

    app.handle_message(Message::CycleSortOrder);
    assert_eq!(app.runtime.sort_order, ProfileSortOrder::NameDesc);
    assert_eq!(app.runtime.profiles[0].name, "charlie");

    app.handle_message(Message::CycleSortOrder);
    assert_eq!(app.runtime.sort_order, ProfileSortOrder::LastUsed);

    app.handle_message(Message::CycleSortOrder);
    assert_eq!(app.runtime.sort_order, ProfileSortOrder::Protocol);

    app.handle_message(Message::CycleSortOrder);
    assert_eq!(app.runtime.sort_order, ProfileSortOrder::NameAsc);
    assert_eq!(app.runtime.profiles[0].name, "alpha");
}

#[test]
fn test_sort_preserves_selection() {
    let mut app = test_app();
    add_profiles(&mut app, &["charlie", "alpha", "bravo"]);
    app.profile_list_state.select(Some(1)); // "alpha" (unsorted order)

    let selected_name = app.runtime.profiles[1].name.clone();
    assert_eq!(selected_name, "alpha");

    app.handle_message(Message::CycleSortOrder); // NameAsc -> NameDesc

    let new_idx = app.profile_list_state.selected().unwrap();
    assert_eq!(
        app.runtime.profiles[new_idx].name, "alpha",
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
    let max_scroll = crate::app::state::help_max_scroll_for_terminal_height(
        app.terminal_size.1,
        crate::ui::help_total_lines(crate::app::state::HelpTab::Keys),
    );
    app.input_mode = InputMode::Help {
        scroll: 0,
        tab: crate::app::state::HelpTab::Keys,
    };

    for _ in 0..(usize::from(max_scroll) + 10) {
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
    }

    assert!(matches!(
        app.input_mode,
        InputMode::Help { scroll, .. } if scroll == max_scroll
    ));
}

#[test]
fn test_help_scroll_does_not_move_when_terminal_size_unknown() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = test_app();
    app.terminal_size = (0, 0);
    app.input_mode = InputMode::Help {
        scroll: 0,
        tab: crate::app::state::HelpTab::Keys,
    };

    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));

    assert!(matches!(
        app.input_mode,
        InputMode::Help {
            scroll: 0,
            tab: crate::app::state::HelpTab::Keys
        }
    ));
}

#[test]
fn test_help_scroll_clamps_after_resize_before_key_handling() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = test_app();
    let max_scroll = crate::app::state::help_max_scroll_for_terminal_height(
        app.terminal_size.1,
        crate::ui::help_total_lines(crate::app::state::HelpTab::Keys),
    );
    app.input_mode = InputMode::Help {
        scroll: max_scroll.saturating_add(10),
        tab: crate::app::state::HelpTab::Keys,
    };

    app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));

    assert!(matches!(
        app.input_mode,
        InputMode::Help { scroll, .. } if scroll == max_scroll.saturating_sub(1)
    ));
}

#[test]
fn test_help_end_jumps_to_max_scroll() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = test_app();
    let max_scroll = crate::app::state::help_max_scroll_for_terminal_height(
        app.terminal_size.1,
        crate::ui::help_total_lines(crate::app::state::HelpTab::Keys),
    );
    app.input_mode = InputMode::Help {
        scroll: 0,
        tab: crate::app::state::HelpTab::Keys,
    };

    app.handle_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));

    assert!(matches!(
        app.input_mode,
        InputMode::Help { scroll, .. } if scroll == max_scroll
    ));
}

#[test]
fn test_help_mouse_scroll_down_clamps_at_max() {
    use crossterm::event::{KeyModifiers, MouseEvent, MouseEventKind};

    let mut app = test_app();
    let max_scroll = crate::app::state::help_max_scroll_for_terminal_height(
        app.terminal_size.1,
        crate::ui::help_total_lines(crate::app::state::HelpTab::Keys),
    );
    app.input_mode = InputMode::Help {
        scroll: 0,
        tab: crate::app::state::HelpTab::Keys,
    };

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
        InputMode::Help { scroll, .. } if scroll == max_scroll
    ));
}

#[test]
fn test_help_mouse_scroll_up_clamps_after_resize() {
    use crossterm::event::{KeyModifiers, MouseEvent, MouseEventKind};

    let mut app = test_app();
    let max_scroll = crate::app::state::help_max_scroll_for_terminal_height(
        app.terminal_size.1,
        crate::ui::help_total_lines(crate::app::state::HelpTab::Keys),
    );
    app.input_mode = InputMode::Help {
        scroll: max_scroll.saturating_add(9),
        tab: crate::app::state::HelpTab::Keys,
    };

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::ScrollUp,
        column: 0,
        row: 0,
        modifiers: KeyModifiers::NONE,
    });

    assert!(matches!(
        app.input_mode,
        InputMode::Help { scroll, .. } if scroll == max_scroll.saturating_sub(3)
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
fn rename_dialog_keeps_its_profile_when_background_sorting_reorders_the_list() {
    let mut app = test_app();
    let directory = tempfile::tempdir().unwrap();
    let store = crate::config::profile_store::FsProfileStore::new(directory.path().to_path_buf());
    let target_id = add_stored_profile(&mut app, &store, directory.path(), "target");
    let other_id = add_stored_profile(&mut app, &store, directory.path(), "other");
    app.profile_list_state.select(Some(0));

    app.handle_message(Message::OpenRename);
    let InputMode::Rename { profile_id, .. } = app.input_mode.clone() else {
        panic!("rename dialog did not open");
    };
    assert_eq!(profile_id, target_id);

    app.runtime.profiles.swap(0, 1);
    app.rename_profile_by_id(&profile_id, "renamed-target");

    assert_eq!(
        app.runtime
            .profiles
            .iter()
            .find(|profile| profile.id == target_id)
            .map(|profile| profile.name.as_str()),
        Some("renamed-target")
    );
    assert_eq!(
        app.runtime
            .profiles
            .iter()
            .find(|profile| profile.id == other_id)
            .map(|profile| profile.name.as_str()),
        Some("other")
    );
}

#[test]
fn delete_dialog_keeps_its_profile_when_background_sorting_reorders_the_list() {
    let mut app = test_app();
    let directory = tempfile::tempdir().unwrap();
    let store = crate::config::profile_store::FsProfileStore::new(directory.path().to_path_buf());
    let target_id = add_stored_profile(&mut app, &store, directory.path(), "target-delete");
    let other_id = add_stored_profile(&mut app, &store, directory.path(), "other-delete");
    app.profile_list_state.select(Some(0));

    app.request_delete(0);
    let InputMode::ConfirmDelete { profile_id, .. } = app.input_mode.clone() else {
        panic!("delete dialog did not open");
    };
    assert_eq!(profile_id, target_id);

    app.runtime.profiles.swap(0, 1);
    app.handle_message(Message::ConfirmDelete);

    assert!(app
        .runtime
        .profiles
        .iter()
        .all(|profile| profile.id != target_id));
    assert!(app
        .runtime
        .profiles
        .iter()
        .any(|profile| profile.id == other_id));
}

#[test]
fn test_rename_on_active_profile_is_refused_at_overlay() {
    // The rename path no longer mutates an in-flight state. Active
    // profiles are blocked at the overlay-open step
    // (`handle_open_rename` consults `is_profile_active`); the test
    // here exercises that guard.
    let mut app = test_app();
    let dir = tempfile::tempdir().unwrap();
    let conf_path = dir.path().join("active-vpn.conf");
    std::fs::write(&conf_path, "dummy").unwrap();
    app.runtime.profiles.push(VpnProfile {
        id: crate::profile::ProfileId::new("active-vpn"),
        name: "active-vpn".to_string(),
        protocol: ProtocolKind::WireGuard,
        config_path: conf_path,
        location: String::new(),
        last_used: None,
        group: None,
    });
    app.profile_list_state.select(Some(0));
    set_connected(&mut app, "active-vpn");

    app.handle_message(Message::OpenRename);
    assert!(
        !matches!(app.input_mode, InputMode::Rename { .. }),
        "Rename overlay must refuse to open for an active profile"
    );
}
#[test]
fn repeated_vpn_exit_ip_does_not_report_a_leak() {
    use crate::telemetry::TelemetryUpdate;
    let mut app = test_app();
    set_connected(&mut app, "test");
    app.runtime.real_ip = Some("1.2.3.4".to_string());
    app.runtime.public_ip = "5.6.7.8".to_string();

    app.handle_message(Message::Telemetry(TelemetryUpdate::EgressIdentity(
        crate::telemetry::EgressIdentity {
            public_ip: "5.6.7.8".to_string(),
            isp: None,
            location: None,
        },
    )));
    assert!(
        !app.runtime.ip_unchanged_warned,
        "an unchanged VPN exit is not evidence of an IPv4 leak"
    );
}

#[test]
fn public_ip_matching_pre_vpn_ip_reports_a_leak() {
    use crate::telemetry::TelemetryUpdate;
    let mut app = test_app();
    set_connected(&mut app, "test");
    app.runtime.real_ip = Some("1.2.3.4".to_string());
    app.runtime.public_ip = "5.6.7.8".to_string();

    app.handle_message(Message::Telemetry(TelemetryUpdate::EgressIdentity(
        crate::telemetry::EgressIdentity {
            public_ip: "1.2.3.4".to_string(),
            isp: None,
            location: None,
        },
    )));
    assert!(
        app.runtime.ip_unchanged_warned,
        "a current IPv4 matching the pre-VPN baseline must report a leak"
    );
}

#[test]
fn test_cannot_delete_connecting_profile() {
    let mut app = test_app();
    add_profiles(&mut app, &["my-vpn"]);
    app.profile_list_state.select(Some(0));
    set_connecting(&mut app, "my-vpn");

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
    // Disconnecting transitions off Connected; the engine snapshot's
    // set_disconnecting is a no-op without a prior Connected entry, so
    // seed Connected first.
    set_connected(&mut app, "my-vpn");
    set_disconnecting(&mut app, "my-vpn");

    app.request_delete(0);
    assert!(
        !matches!(app.input_mode, InputMode::ConfirmDelete { .. }),
        "Should not open confirm dialog for a disconnecting profile"
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
        app.runtime.profiles[0].name, "existing-vpn",
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

/// Simulate completing a flip by setting the showing-back state directly.
fn complete_flip(app: &mut App, panel: FocusedPanel) {
    let target = !app.is_flipped(&panel);
    app.flip_state_mut(panel).set_showing_back(target);
}

#[test]
fn flip_starts_animation() {
    let mut app = test_app();
    app.focused_panel = FocusedPanel::Chart;
    app.handle_message(Message::ToggleFlip);
    assert!(app.has_active_animation());
    assert!(!app.is_flipped(&FocusedPanel::Chart));
}

#[test]
fn flip_toggles_chart_panel_after_animation() {
    let mut app = test_app();
    app.focused_panel = FocusedPanel::Chart;
    assert!(!app.is_flipped(&FocusedPanel::Chart));
    app.handle_message(Message::ToggleFlip);
    complete_flip(&mut app, FocusedPanel::Chart);
    assert!(app.is_flipped(&FocusedPanel::Chart));
    app.handle_message(Message::ToggleFlip);
    complete_flip(&mut app, FocusedPanel::Chart);
    assert!(!app.is_flipped(&FocusedPanel::Chart));
}

#[test]
fn flip_toggles_security_panel() {
    let mut app = test_app();
    app.focused_panel = FocusedPanel::Security;
    app.handle_message(Message::ToggleFlip);
    complete_flip(&mut app, FocusedPanel::Security);
    assert!(app.is_flipped(&FocusedPanel::Security));
    assert!(!app.is_flipped(&FocusedPanel::Chart));
}

#[test]
fn flip_toggles_connection_details_panel() {
    let mut app = test_app();
    app.focused_panel = FocusedPanel::ConnectionDetails;
    app.handle_message(Message::ToggleFlip);
    complete_flip(&mut app, FocusedPanel::ConnectionDetails);
    assert!(app.is_flipped(&FocusedPanel::ConnectionDetails));
}

#[test]
fn flip_ignores_sidebar() {
    let mut app = test_app();
    app.focused_panel = FocusedPanel::Sidebar;
    app.handle_message(Message::ToggleFlip);
    assert!(!app.has_active_animation());
    assert!(app.flip_states.is_empty());
}

#[test]
fn flip_ignores_logs() {
    let mut app = test_app();
    app.focused_panel = FocusedPanel::Logs;
    app.handle_message(Message::ToggleFlip);
    assert!(!app.has_active_animation());
    assert!(app.flip_states.is_empty());
}

#[test]
fn flip_blocked_during_active_animation() {
    let mut app = test_app();
    app.focused_panel = FocusedPanel::Chart;
    app.handle_message(Message::ToggleFlip);
    assert!(app.has_active_animation());
    // Second toggle while animating should be a no-op; the in-flight
    // flip from the first toggle proceeds unchanged.
    app.handle_message(Message::ToggleFlip);
    assert!(app.has_active_animation());
    assert!(!app.is_flipped(&FocusedPanel::Chart));
}

#[test]
fn flip_state_persists_across_focus_changes() {
    let mut app = test_app();
    app.focused_panel = FocusedPanel::Chart;
    app.handle_message(Message::ToggleFlip);
    complete_flip(&mut app, FocusedPanel::Chart);
    assert!(app.is_flipped(&FocusedPanel::Chart));
    app.focused_panel = FocusedPanel::Security;
    assert!(app.is_flipped(&FocusedPanel::Chart));
}

#[test]
fn flip_multiple_panels_independently() {
    let mut app = test_app();
    app.focused_panel = FocusedPanel::Chart;
    app.handle_message(Message::ToggleFlip);
    complete_flip(&mut app, FocusedPanel::Chart);
    app.focused_panel = FocusedPanel::Security;
    app.handle_message(Message::ToggleFlip);
    complete_flip(&mut app, FocusedPanel::Security);
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
    // Just-started animation hasn't passed the midpoint yet.
    assert!(!app.effective_flipped(&FocusedPanel::Chart));
}

#[test]
fn advance_animation_completes_to_back() {
    use std::time::Duration;
    let mut app = test_app();
    let mut state = crate::app::state::FlipState::new(Duration::from_millis(20));
    state.flip();
    app.flip_states.insert(FocusedPanel::Chart, state);
    std::thread::sleep(Duration::from_millis(80));
    app.advance_animation();
    assert!(!app.has_active_animation());
    assert!(app.is_flipped(&FocusedPanel::Chart));
}

#[test]
fn advance_animation_completes_to_front() {
    use std::time::Duration;
    let mut app = test_app();
    let mut state = crate::app::state::FlipState::new(Duration::from_millis(20));
    state.set_showing_back(true);
    state.flip();
    app.flip_states.insert(FocusedPanel::Security, state);
    std::thread::sleep(Duration::from_millis(80));
    app.advance_animation();
    assert!(!app.has_active_animation());
    assert!(!app.is_flipped(&FocusedPanel::Security));
}

#[test]
fn advance_animation_noop_when_still_running() {
    let mut app = test_app();
    app.focused_panel = FocusedPanel::Chart;
    app.handle_message(Message::ToggleFlip);
    assert!(app.has_active_animation());
    app.advance_animation();
    assert!(app.has_active_animation());
}

#[test]
fn effective_flipped_shows_target_after_midpoint() {
    use std::time::Duration;
    let mut app = test_app();
    let mut state = crate::app::state::FlipState::new(Duration::from_millis(100));
    state.flip();
    app.flip_states.insert(FocusedPanel::Chart, state);
    std::thread::sleep(Duration::from_millis(75));
    assert!(app.effective_flipped(&FocusedPanel::Chart));
}

// ====================================================================
// Connect/disconnect flow
// ====================================================================

/// Helper: dispatch a `KeyEvent` matching the given char in `Normal` mode.
fn key_char(c: char) -> crossterm::event::KeyEvent {
    crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char(c),
        crossterm::event::KeyModifiers::NONE,
    )
}

fn key_shift_char(c: char) -> crossterm::event::KeyEvent {
    crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char(c),
        crossterm::event::KeyModifiers::SHIFT,
    )
}
#[test]
fn u19_disconnect_profile_idempotent_for_inactive_row() {
    // `d` on a Disconnected sidebar row is a no-op (we never enter the
    // disconnect path because is_profile_connected returns false). The
    // input layer's gate prevents the message from being dispatched at
    // all; but if it were, `DisconnectProfile` itself short-circuits.
    let mut app = test_app();
    add_profiles(&mut app, &["p1", "p2"]);
    set_connected(&mut app, "p1");

    // p2 is not the active profile — direct DisconnectProfile must not
    // touch p1's connection state.
    app.handle_message(Message::DisconnectProfile { idx: 1 });

    assert!(
        app.current_tunnel()
            .is_some_and(|t| t.phase == crate::control::Phase::Up),
        "DisconnectProfile on inactive row must leave Connected state intact, got {:?}",
        app.current_tunnel().map(|t| t.phase),
    );
}

#[test]
fn sidebar_d_on_inactive_row_never_disconnects_another_tunnel() {
    let mut app = test_app();
    add_profiles(&mut app, &["active", "inactive"]);
    set_connected(&mut app, "active");
    app.profile_list_state.select(Some(1));
    app.focused_panel = FocusedPanel::Sidebar;

    app.handle_key(key_char('d'));

    assert!(app.toast.is_none(), "inactive-row d must be a quiet no-op");
    assert_eq!(
        app.tunnel(&crate::profile::ProfileId::new("active"))
            .unwrap()
            .phase,
        crate::control::Phase::Up
    );
}

#[test]
fn error_toast_expires_and_routine_info_does_not_replace_it_early() {
    let mut app = test_app();
    app.show_toast("Connection failed".to_string(), ToastType::Error);
    app.show_toast("Background refresh complete".to_string(), ToastType::Info);

    let toast = app.toast.as_ref().expect("error remains visible initially");
    assert_eq!(toast.toast_type, ToastType::Error);
    assert_eq!(toast.message, "Connection failed");

    app.toast.as_mut().unwrap().expires = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_millis(1))
        .unwrap();

    app.handle_message(Message::Tick);
    assert!(
        app.toast.is_none(),
        "error must expire without requiring Esc"
    );

    app.show_toast("Review the changed route".to_string(), ToastType::Warning);
    assert_eq!(
        app.toast.as_ref().unwrap().message,
        "Review the changed route"
    );

    app.show_toast("Connected".to_string(), ToastType::Success);
    assert_eq!(app.toast.as_ref().unwrap().message, "Connected");

    app.show_toast("New failure".to_string(), ToastType::Error);
    assert_eq!(app.toast.as_ref().unwrap().message, "New failure");
}

#[test]
fn uppercase_d_remains_global_when_the_only_active_tunnel_is_not_focused() {
    let mut app = test_app();
    add_profiles(&mut app, &["p1", "inactive"]);
    set_connected(&mut app, "p1");
    app.profile_list_state.select(Some(1));
    app.focused_panel = FocusedPanel::Sidebar;

    app.handle_key(key_shift_char('D'));

    assert!(
        !matches!(app.input_mode, InputMode::ConfirmDisconnectAll { .. }),
        "uppercase D with one tunnel must skip confirmation, got {:?}",
        app.input_mode
    );
    assert_eq!(
        app.toast.as_ref().map(|toast| toast.message.as_str()),
        Some(super::connection::CONTROL_STARTING_MESSAGE),
        "the global disconnect path must run even when another row is focused"
    );
}

#[test]
fn overlay_escape_closes_the_overlay_before_dismissing_a_dashboard_toast() {
    let mut app = test_app();
    app.show_toast("Connection failed".to_string(), ToastType::Error);
    app.input_mode = InputMode::Import {
        path: String::new(),
        cursor: 0,
    };

    app.handle_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Esc,
        crossterm::event::KeyModifiers::NONE,
    ));

    assert_eq!(app.input_mode, InputMode::Normal);
    assert!(
        app.toast.is_some(),
        "closing an overlay must not eat the error"
    );
}

#[test]
fn u19_request_disconnect_all_opens_confirm_when_multi() {
    let mut app = test_app();
    add_profiles(&mut app, &["p1", "p2"]);
    set_connected(&mut app, "p1");
    set_connected(&mut app, "p2");
    assert_eq!(app.tunnel_count(), 2);

    app.handle_message(Message::RequestDisconnectAll);

    assert!(matches!(
        app.input_mode,
        InputMode::ConfirmDisconnectAll {
            count: 2,
            confirm_selected: true
        }
    ));
}
#[test]
fn u19_connection_details_follows_sidebar_selection() {
    // Tab is reserved for panel navigation; Connection Details panel
    // always mirrors the sidebar selection (no separate focus override).
    // Earlier multi-tunnel iteration tried Tab-in-Details to cycle
    // across active tunnels — that hijacked global panel navigation,
    // so the binding was removed. `connection_details_focused_idx`
    // now always returns the sidebar's selected profile.
    let mut app = test_app();
    add_profiles(&mut app, &["alpha", "beta"]);
    set_connected(&mut app, "alpha");
    set_connected(&mut app, "beta");
    app.profile_list_state.select(Some(1)); // beta
    assert_eq!(
        app.connection_details_focused_idx(),
        Some(1),
        "Connection Details should follow sidebar selection"
    );
    app.profile_list_state.select(Some(0)); // alpha
    assert_eq!(
        app.connection_details_focused_idx(),
        Some(0),
        "Switching sidebar selection should switch the Details focus"
    );
}
#[test]
fn u19_tunnel_count_reflects_the_engine_after_connect() {
    let mut app = test_app();
    add_profiles(&mut app, &["p1"]);
    assert_eq!(app.tunnel_count(), 0);
    set_connected(&mut app, "p1");
    assert_eq!(app.tunnel_count(), 1);
}

#[test]
fn u19_confirm_disconnect_all_overlay_y_key_confirms() {
    // The Y key on the ConfirmDisconnectAll overlay confirms — the
    // overlay closes and disconnect_all_active runs.
    let mut app = test_app();
    add_profiles(&mut app, &["p1"]);
    set_connected(&mut app, "p1");
    app.input_mode = InputMode::ConfirmDisconnectAll {
        count: 2,
        confirm_selected: true,
    };

    app.handle_key(key_char('y'));

    assert!(matches!(app.input_mode, InputMode::Normal));
}

#[test]
fn u19_confirm_disconnect_all_overlay_n_key_cancels() {
    let mut app = test_app();
    add_profiles(&mut app, &["p1"]);
    set_connected(&mut app, "p1");
    app.input_mode = InputMode::ConfirmDisconnectAll {
        count: 3,
        confirm_selected: true,
    };

    app.handle_key(key_char('n'));

    assert!(matches!(app.input_mode, InputMode::Normal));
    // Connection state untouched.
    assert!(app
        .current_tunnel()
        .is_some_and(|t| t.phase == crate::control::Phase::Up));
}

/// `CachedConfigView::from_content` pre-counts lines and pre-highlights
/// every line so the scroll path doesn't have to re-iterate the file.
/// Aggressive scrolling on a large inline-cert `.ovpn` used to wedge the
/// TUI because both `get_config_max_scroll` and the renderer each did
/// `content.lines().count()` / `.map(highlight).collect()` per keystroke.
#[test]
fn cached_config_view_precomputes_total_lines_and_highlighted_vec() {
    use crate::app::CachedConfigView;

    let content = "[Interface]\nAddress = 10.0.0.2/24\nPrivateKey = abc\n\n[Peer]\nPublicKey = def\nAllowedIPs = 0.0.0.0/0\n";
    let view = CachedConfigView::from_content(
        content.to_string(),
        crate::ui::theme::ThemeChoice::Synthwave,
    );

    assert_eq!(view.total_lines, 7, "total_lines must be pre-computed");
    assert_eq!(
        view.highlighted_lines.len(),
        7,
        "highlighted_lines must have one entry per content line"
    );
    assert_eq!(view.content, content, "raw content preserved verbatim");
}

/// `get_config_max_scroll` must read from the cache, NOT iterate the
/// content string. Regression guard for the O(N²)-on-keypress wedge.
#[test]
fn get_config_max_scroll_reads_from_cache() {
    use crate::app::CachedConfigView;

    let mut app = test_app();
    // Synthesize a long enough content that max_scroll would diverge from
    // zero even after subtracting the viewport height.
    let mut content = String::new();
    for i in 0..200 {
        use std::fmt::Write;
        let _ = writeln!(content, "line {i}");
    }
    app.terminal_size = (120, 40);
    app.cached_config = Some(CachedConfigView::from_content(
        content,
        crate::ui::theme::ThemeChoice::Synthwave,
    ));

    let max = app.get_config_max_scroll();
    assert!(
        max > 0,
        "200 lines must produce a positive max-scroll on a 40-row terminal"
    );
    // Calling again must be cheap — same value, no observable side effects
    // (caching invariant; can't directly time but assert idempotency).
    assert_eq!(app.get_config_max_scroll(), max);
}

// ====================================================================
// Real-IP cache gate — startup-race regression suite
// ====================================================================
//
// Bug: vortix opened while a VPN tunnel is already up cached the
// VPN's exit IP as `real_ip`. Cause: telemetry's first PublicIp
// poll fires before the scanner's first SyncSystemState tick, so
// the engine snapshot is briefly empty, `!is_connected` is true, and the
// VPN exit IP gets baked into `real_ip`. Fix: require positive
// proof of zero VPN sessions (scanner has ticked AND kernel
// reports zero sessions AND engine snapshot has zero Connected) before
// caching. The tests below pin each branch of that gate.

#[test]
fn real_ip_not_cached_when_scanner_has_not_ticked_yet() {
    // Telemetry fires before scanner. The bug: this used to cache
    // the IP unconditionally because `!is_connected` was true.
    // Fix: scanner_first_tick_done starts false → cache withheld.
    use crate::telemetry::TelemetryUpdate;
    let mut app = test_app();
    assert!(!app.runtime.scanner_first_tick_done);
    assert!(app.runtime.real_ip.is_none());

    app.handle_message(Message::Telemetry(TelemetryUpdate::EgressIdentity(
        crate::telemetry::EgressIdentity {
            public_ip: "46.101.235.146".to_string(),
            isp: None,
            location: None,
        },
    )));

    assert!(
        app.runtime.real_ip.is_none(),
        "real_ip must stay None until scanner reports kernel state"
    );
}

#[test]
fn routine_packet_loss_and_jitter_samples_do_not_flood_the_event_log() {
    use crate::telemetry::TelemetryUpdate;

    crate::logger::clear_logs();
    let mut app = test_app();
    app.handle_message(Message::Telemetry(TelemetryUpdate::NetworkQuality {
        latency_ms: 400,
        packet_loss: 12.3,
        jitter_ms: 77,
    }));
    app.handle_message(Message::Telemetry(TelemetryUpdate::NetworkQuality {
        latency_ms: 420,
        packet_loss: 15.0,
        jitter_ms: 80,
    }));
    app.handle_message(Message::Telemetry(TelemetryUpdate::NetworkQuality {
        latency_ms: 30,
        packet_loss: 0.0,
        jitter_ms: 2,
    }));
    app.handle_message(Message::Telemetry(TelemetryUpdate::NetworkQuality {
        latency_ms: 35,
        packet_loss: 0.0,
        jitter_ms: 3,
    }));

    assert!(app.runtime.packet_loss.abs() < f32::EPSILON);
    assert_eq!(app.runtime.jitter_ms, 3);
    assert!(crate::logger::get_logs().iter().all(|entry| {
        !entry.message.contains("Packet loss: 12.3%") && !entry.message.contains("Jitter: 77ms")
    }));
    assert_eq!(
        crate::logger::get_logs()
            .iter()
            .filter(|entry| entry.message.contains("Network quality degraded: poor"))
            .count(),
        1,
        "unchanged quality categories must emit at most one log entry"
    );
    assert_eq!(
        crate::logger::get_logs()
            .iter()
            .filter(|entry| entry.message.contains("Network quality: excellent"))
            .count(),
        1,
        "recovery and subsequent healthy samples must emit one transition"
    );
}

#[test]
fn theme_toggle_persists_restyles_cached_content_and_reports_success() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = test_app();
    app.runtime.config_dir = temp.path().to_path_buf();
    app.runtime.config.theme = crate::ui::theme::ThemeChoice::Synthwave;
    app.cached_config = Some(CachedConfigView::from_content(
        "[Interface]\nAddress = 10.0.0.2/24\n".to_string(),
        crate::ui::theme::ThemeChoice::Synthwave,
    ));

    app.handle_key(key_char('p'));

    // The palette changes immediately; durable config I/O finishes on the
    // command worker so it cannot stall input or rendering.
    assert_eq!(
        app.runtime.config.theme,
        crate::ui::theme::ThemeChoice::Terminal
    );
    assert!(!app.show_bulk_menu);
    assert!(app.pending_theme_change.is_some());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while app.pending_theme_change.is_some() && std::time::Instant::now() < deadline {
        app.process_external();
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(app.pending_theme_change.is_none());
    assert_eq!(
        crate::config::load_config(temp.path()).unwrap().theme,
        crate::ui::theme::ThemeChoice::Terminal
    );
    assert_eq!(
        app.cached_config.as_ref().unwrap().highlighted_lines[0].spans[0]
            .style
            .fg,
        Some(crate::ui::theme::TERMINAL.yellow)
    );
    let toast = app.toast.as_ref().unwrap();
    assert_eq!(toast.toast_type, ToastType::Success);
    assert_eq!(toast.message, "Color theme: Terminal");
}

#[test]
fn theme_toggle_failure_keeps_the_current_theme() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = test_app();
    app.runtime.config_dir = temp.path().join("missing");
    app.runtime.config.theme = crate::ui::theme::ThemeChoice::Synthwave;

    app.handle_message(Message::ToggleTheme);

    assert_eq!(
        app.runtime.config.theme,
        crate::ui::theme::ThemeChoice::Terminal
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while app.pending_theme_change.is_some() && std::time::Instant::now() < deadline {
        app.process_external();
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(app.pending_theme_change.is_none());
    assert_eq!(
        app.runtime.config.theme,
        crate::ui::theme::ThemeChoice::Synthwave
    );
    assert_eq!(app.toast.as_ref().unwrap().toast_type, ToastType::Error);
}

#[test]
fn second_theme_toggle_waits_for_the_pending_save() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = test_app();
    app.runtime.config_dir = temp.path().to_path_buf();
    app.runtime.config.theme = crate::ui::theme::ThemeChoice::Synthwave;

    app.handle_message(Message::ToggleTheme);
    let pending = app.pending_theme_change;
    app.handle_message(Message::ToggleTheme);

    assert_eq!(
        app.runtime.config.theme,
        crate::ui::theme::ThemeChoice::Terminal
    );
    assert_eq!(app.pending_theme_change, pending);
    assert_eq!(app.toast.as_ref().unwrap().toast_type, ToastType::Info);
    assert_eq!(
        app.toast.as_ref().unwrap().message,
        "The color theme is still being saved"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while app.pending_theme_change.is_some() && std::time::Instant::now() < deadline {
        app.process_external();
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(app.pending_theme_change.is_none());
}

#[test]
fn quit_waits_for_in_flight_theme_persistence() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = test_app();
    app.runtime.config_dir = temp.path().to_path_buf();
    app.runtime.config.theme = crate::ui::theme::ThemeChoice::Synthwave;

    app.handle_message(Message::ToggleTheme);
    app.handle_message(Message::Quit);

    assert!(!app.should_quit);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while !app.should_quit && std::time::Instant::now() < deadline {
        app.process_external();
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(app.should_quit);
    assert_eq!(
        crate::config::load_config(temp.path()).unwrap().theme,
        crate::ui::theme::ThemeChoice::Terminal
    );
}

#[test]
fn second_quit_does_not_wait_for_theme_persistence() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = test_app();
    app.runtime.config_dir = temp.path().to_path_buf();

    app.handle_message(Message::ToggleTheme);
    app.handle_message(Message::Quit);
    assert!(!app.should_quit);

    app.handle_message(Message::Quit);
    assert!(app.should_quit);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while app.pending_theme_change.is_some() && std::time::Instant::now() < deadline {
        app.process_external();
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[test]
fn ip_only_refresh_for_same_exit_keeps_known_location() {
    let mut app = test_app();
    app.runtime.public_ip = "203.0.113.7".to_string();
    app.runtime.isp = "Example ISP".to_string();
    app.runtime.location = "Agra, IN".to_string();

    app.handle_message(Message::Telemetry(
        crate::telemetry::TelemetryUpdate::EgressIdentity(crate::telemetry::EgressIdentity {
            public_ip: "203.0.113.7".to_string(),
            isp: None,
            location: None,
        }),
    ));

    assert_eq!(app.runtime.isp, "Example ISP");
    assert_eq!(app.runtime.location, "Agra, IN");
}

#[test]
fn ip_only_refresh_for_changed_exit_clears_stale_location() {
    let mut app = test_app();
    app.runtime.public_ip = "203.0.113.7".to_string();
    app.runtime.isp = "Old ISP".to_string();
    app.runtime.location = "Agra, IN".to_string();

    app.handle_message(Message::Telemetry(
        crate::telemetry::TelemetryUpdate::EgressIdentity(crate::telemetry::EgressIdentity {
            public_ip: "198.51.100.9".to_string(),
            isp: None,
            location: None,
        }),
    ));

    assert_eq!(app.runtime.isp, "Unknown");
    assert_eq!(app.runtime.location, "Unknown");
}

#[test]
fn unavailable_egress_probe_never_replaces_the_real_ip_cache() {
    let mut app = test_app();
    app.runtime.scanner_first_tick_done = true;
    app.runtime.last_kernel_session_count = 0;
    app.runtime.real_ip = Some("203.0.113.7".to_string());

    app.handle_message(Message::Telemetry(
        crate::telemetry::TelemetryUpdate::EgressUnavailable,
    ));

    assert_eq!(app.runtime.public_ip, constants::MSG_UNAVAILABLE);
    assert_eq!(app.runtime.real_ip.as_deref(), Some("203.0.113.7"));
}

#[test]
fn ctrl_r_reveals_the_password_without_typing_into_the_field() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = test_app();
    app.input_mode = InputMode::AuthPrompt {
        profile_id: crate::profile::ProfileId::new("reveal-profile"),
        profile_name: "reveal".into(),
        username: "vortix".into(),
        username_cursor: 6,
        password: "secret".into(),
        password_cursor: 6,
        otp: crate::app::state::SecretText::default(),
        otp_cursor: 0,
        focused_field: AuthField::Password,
        save_credentials: true,
        connect_after: true,
        static_challenge_prompt: None,
        reveal_secrets: false,
    };

    app.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));
    assert!(matches!(
        &app.input_mode,
        InputMode::AuthPrompt {
            reveal_secrets: true,
            password,
            password_cursor: 6,
            ..
        } if password.expose() == "secret"
    ));

    // Toggling back hides it again.
    app.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));
    assert!(matches!(
        &app.input_mode,
        InputMode::AuthPrompt {
            reveal_secrets: false,
            ..
        }
    ));

    // A bare 'r' is still a password character, not a toggle.
    app.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
    assert!(matches!(
        &app.input_mode,
        InputMode::AuthPrompt {
            reveal_secrets: false,
            password,
            ..
        } if password.expose() == "secretr"
    ));
}

#[test]
fn diagnostic_log_batch_rotates_before_crossing_the_boundary() {
    let config = tempfile::tempdir().unwrap();
    let entries = vec![
        "first-01".to_string(),
        "second02".to_string(),
        "third-03".to_string(),
    ];
    App::append_to_log_file_batch(&entries, config.path(), 10, 7);

    let log_dir = config.path().join(crate::constants::LOGS_DIR_NAME);
    let files = std::fs::read_dir(&log_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(files.len(), entries.len());
    let mut persisted = files
        .iter()
        .flat_map(|path| {
            assert!(std::fs::metadata(path).unwrap().len() <= 10);
            std::fs::read_to_string(path)
                .unwrap()
                .lines()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    persisted.sort();
    let mut expected = entries;
    expected.sort();
    assert_eq!(persisted, expected);
}

#[test]
fn test_auth_delete_profile_cleans_auth_file() {
    let mut app = test_app();
    let tmp = tempfile::Builder::new()
        .prefix("vortix_auth_")
        .tempdir()
        .unwrap();
    let profiles_dir = tmp.path().join(crate::constants::PROFILES_DIR_NAME);
    std::fs::create_dir(&profiles_dir).unwrap();
    let stable_id = crate::profile::ProfileId::parse("11".repeat(32)).unwrap();
    let config_path = profiles_dir.join("del-vpn.ovpn");
    let stored = crate::profile::Profile::new(
        stable_id.clone(),
        "del-vpn",
        crate::profile::ProtocolKind::OpenVpn,
        config_path.clone(),
    );
    crate::config::profile_store::FsProfileStore::new(profiles_dir)
        .insert(
            &stored,
            b"client\nremote example.com 1194\nauth-user-pass\ndev tun\nproto udp\n",
        )
        .unwrap();
    app.runtime.profiles.push(VpnProfile {
        id: stable_id.clone(),
        name: "del-vpn".to_string(),
        protocol: ProtocolKind::OpenVpn,
        config_path,
        location: "Test".to_string(),
        last_used: None,
        group: None,
    });
    app.runtime.config_dir = tmp.path().to_path_buf();
    let (uid, gid) = crate::config::config_owner(tmp.path()).unwrap();
    let store = crate::config::openvpn_credentials::FsOpenVpnCredentialStore::for_standard_owner(
        tmp.path(),
        uid,
        gid,
    );
    let credentials =
        crate::config::openvpn_credentials::RememberedOpenVpnCredentials::new("user", "pass")
            .unwrap();
    store.replace(&stable_id, &credentials).unwrap();

    app.confirm_delete_profile(&stable_id);

    assert!(app.runtime.profiles.is_empty());
    assert!(store.load(&stable_id, "del-vpn").unwrap().is_none());
}

#[test]
fn focused_lifecycle_states_route_to_the_exact_sidebar_action() {
    use crate::app::{focused_tunnel_action, FocusedTunnelAction};
    use crate::control::Phase;

    for phase in [
        Phase::Starting,
        Phase::Waiting { retry_at: None },
        Phase::AwaitingCredentials,
    ] {
        assert_eq!(
            focused_tunnel_action(Some(phase)),
            FocusedTunnelAction::Cancel
        );
    }
    assert_eq!(
        focused_tunnel_action(Some(Phase::Up)),
        FocusedTunnelAction::Disconnect
    );
    assert_eq!(
        focused_tunnel_action(Some(Phase::Stopping)),
        FocusedTunnelAction::Stopping
    );
    assert_eq!(focused_tunnel_action(None), FocusedTunnelAction::Connect);
}

#[test]
fn scanner_statistics_refresh_the_dashboard_without_nudging_egress_telemetry() {
    use std::sync::mpsc;

    let mut app = test_app();
    let (nudge_tx, nudge_rx) = mpsc::channel();
    app.runtime.telemetry_nudge = Some(nudge_tx);
    set_connected(&mut app, "primary");
    nudge_rx
        .try_recv()
        .expect("initial connection must refresh egress telemetry");

    let profile_id = crate::profile::ProfileId::new("primary");
    let edit = |app: &App, change: &dyn Fn(&mut crate::control::Snapshot)| {
        let mut next = (*app.control_snapshot).clone();
        change(&mut next);
        next.version += 1;
        std::sync::Arc::new(next)
    };
    let statistics = edit(&app, &|snapshot| {
        let tunnel = &mut snapshot.tunnels[0];
        tunnel.details.transfer_rx = "12.0 MiB".to_string();
        tunnel.details.transfer_tx = "3.0 MiB".to_string();
    });
    app.apply_control_snapshot(statistics);
    assert_eq!(
        nudge_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty),
        "presentation-only transfer counters must not wake public-IP probes"
    );
    let rendered = app.tunnel(&profile_id).unwrap();
    assert_eq!(rendered.phase, crate::control::Phase::Up);
    assert_eq!(rendered.details.transfer_rx, "12.0 MiB");

    let new_path = edit(&app, &|snapshot| {
        snapshot.tunnels[0].interface = Some("utun8".to_string());
    });
    app.apply_control_snapshot(new_path);
    nudge_rx
        .try_recv()
        .expect("an interface change must refresh egress telemetry");

    set_connected(&mut app, "secondary");
    nudge_rx
        .try_recv()
        .expect("a new active tunnel must refresh egress telemetry");

    let handoff = edit(&app, &|snapshot| {
        snapshot.primary = Some(profile_id.clone());
    });
    app.apply_control_snapshot(handoff);
    nudge_rx
        .try_recv()
        .expect("a primary handoff must refresh egress telemetry");
}

/// Both real-IP cache gates read these fields, and for a long time nothing in
/// production wrote either one: `scanner_first_tick_done` stayed false, so the
/// address was never cached, and `last_kernel_session_count == 0` was
/// vacuously true. The suite did not notice because the tests set the flags by
/// hand. This asserts the control snapshot actually establishes them.
#[test]
fn a_control_snapshot_establishes_the_real_ip_cache_gates() {
    let mut app = test_app();
    assert!(!app.runtime.scanner_first_tick_done, "starts unproven");
    set_connected(&mut app, "carrying-traffic");
    assert!(
        app.runtime.scanner_first_tick_done,
        "a published snapshot proves the scan ran"
    );
    assert_eq!(
        app.runtime.last_kernel_session_count, 1,
        "an active tunnel must be counted, or the cache gate lets the VPN \
         address be saved as the real one"
    );
}

/// The real-IP gate proved only that *Vortix* owned no tunnel. A VPN started
/// outside Vortix still carries the egress, so the probe returned that VPN's
/// exit address and the gate — scanner ticked, no managed session, engine snapshot
/// disconnected — cached it as the user's real IP. Security Guard then showed
/// Real IP equal to Exit IP and flagged a leak that was its own bookkeeping.
#[test]
fn an_unmanaged_tunnel_on_the_default_route_blocks_real_ip_caching() {
    for (interface, cacheable) in [
        ("en0", true),
        ("eth0", true),
        ("utun4", false),
        ("wg0", false),
        ("tun0", false),
    ] {
        let mut app = test_app();
        app.apply_control_snapshot(std::sync::Arc::new(crate::control::Snapshot {
            default_route: Some(interface.to_string()),
            ..crate::control::Snapshot::default()
        }));
        assert_eq!(
            !app.default_route_is_tunnel(),
            cacheable,
            "default route via {interface} must {} caching the real address",
            if cacheable { "allow" } else { "block" }
        );
    }
}

#[test]
fn a_stale_wireguard_handshake_reaches_the_dashboard() {
    use crate::tunnel::{ConnectionHealth, DegradedReason};
    let mut app = test_app();
    add_profiles(&mut app, &["corp"]);
    set_connected(&mut app, "corp");
    let mut snapshot = (*app.control_snapshot).clone();
    let stale = ConnectionHealth::Degraded {
        reason: DegradedReason::WireGuardPeerStale {
            peer_public_key: "peer".into(),
            allowed_routes: vec!["10.0.0.0/24".into()],
            seconds_since_last_handshake: 300,
        },
    };
    snapshot.tunnels[0].health = stale.clone();
    snapshot.version += 1;
    let profile_id = snapshot.tunnels[0].profile_id.clone();
    app.apply_control_snapshot(std::sync::Arc::new(snapshot));
    assert_eq!(app.tunnel(&profile_id).unwrap().health, stale);
}

#[test]
fn an_egress_sample_from_before_a_tunnel_change_is_dropped() {
    use crate::telemetry::{EgressIdentity, TelemetryUpdate};
    let mut app = test_app();
    let (tx, rx) = std::sync::mpsc::channel();
    app.runtime.telemetry_rx = Some(rx);
    app.runtime.telemetry_epoch = 1;
    let sample = |ip: &str| {
        TelemetryUpdate::EgressIdentity(EgressIdentity {
            public_ip: ip.into(),
            isp: None,
            location: None,
        })
    };
    tx.send((0, sample("139.59.71.126"))).unwrap();
    app.process_telemetry();
    assert_ne!(app.runtime.public_ip, "139.59.71.126");
    tx.send((1, sample("203.0.113.9"))).unwrap();
    app.process_telemetry();
    assert_eq!(app.runtime.public_ip, "203.0.113.9");
}

#[test]
fn an_unexpected_drop_counts_once() {
    use crate::control::state::Phase;
    use crate::control::{Snapshot, TunnelView};
    let mut app = test_app();
    add_profiles(&mut app, &["corp"]);
    let details = app.runtime.profiles[0].id.clone();
    let view = |phase| TunnelView {
        profile_id: details.clone(),
        name: "corp".into(),
        phase,
        interface: Some("utun4".into()),
        since: std::time::SystemTime::UNIX_EPOCH,
        routes: Vec::new(),
        dns: Vec::new(),
        details: crate::tunnel::DetailedConnectionInfo::default(),
        health: crate::tunnel::ConnectionHealth::default(),
    };
    for phase in [
        Phase::Up,
        Phase::Waiting { retry_at: None },
        Phase::Waiting { retry_at: None },
    ] {
        app.apply_control_snapshot(std::sync::Arc::new(Snapshot {
            tunnels: vec![view(phase)],
            ..Snapshot::default()
        }));
    }
    assert_eq!(app.runtime.connection_drops, 1);
}

#[test]
fn canonical_snapshot_updates_profile_last_connected_time() {
    let mut app = test_app();
    add_profiles(&mut app, &["corp"]);
    let profile_id = app.runtime.profiles[0].id.clone();
    let connected_at = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_234);
    app.runtime.profiles[0].last_used = Some(connected_at + std::time::Duration::from_secs(1));
    let mut snapshot = (*app.control_snapshot).clone();
    snapshot.last_connected.insert(profile_id, connected_at);
    app.apply_control_snapshot(std::sync::Arc::new(snapshot));
    assert_eq!(app.runtime.profiles[0].last_used, Some(connected_at));
}

#[test]
fn actions_during_control_startup_explain_the_wait_without_an_error_alarm() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn"]);
    app.profile_list_state.select(Some(0));
    app.control_starting = true;

    app.handle_message(Message::ToggleConnect(None));

    let toast = app
        .toast
        .as_ref()
        .expect("startup action must have feedback");
    assert_eq!(toast.toast_type, ToastType::Info);
    assert!(toast.message.contains("still starting"));
}

fn with_prompt(app: &mut App, name: &str) {
    add_profiles(app, &[name]);
    let mut snapshot = (*app.control_snapshot).clone();
    snapshot.prompts = vec![crate::control::Prompt {
        id: 7,
        profile_id: crate::profile::ProfileId::new(name),
        name: name.to_owned(),
        otp_label: None,
    }];
    snapshot.version += 1;
    app.apply_control_snapshot(std::sync::Arc::new(snapshot));
}

#[test]
fn a_credential_prompt_waits_for_an_open_dialog_then_shows() {
    let mut app = test_app();
    app.input_mode = InputMode::Import {
        path: "/tmp/half-typed".into(),
        cursor: 3,
    };
    with_prompt(&mut app, "corp");
    assert!(
        matches!(app.input_mode, InputMode::Import { .. }),
        "the open dialog is not replaced"
    );
    assert!(app.control_prompt.is_none());

    app.input_mode = InputMode::Normal;
    app.handle_message(Message::Tick);
    assert!(matches!(app.input_mode, InputMode::AuthPrompt { .. }));
    assert_eq!(app.control_prompt, Some(7));
}

#[test]
fn a_credential_prompt_is_drawn_above_every_overlay() {
    let mut app = test_app();
    app.show_config = true;
    app.show_action_menu = true;
    app.zoomed_panel = Some(FocusedPanel::Logs);
    with_prompt(&mut app, "corp");
    assert!(matches!(app.input_mode, InputMode::AuthPrompt { .. }));
    assert!(!app.show_config && !app.show_action_menu && app.zoomed_panel.is_none());
}

#[test]
fn a_reconnecting_full_tunnel_with_no_other_exit_is_still_primary() {
    let mut app = test_app();
    let mut tunnel = crate::app::connection::test_view(
        "corp",
        crate::control::Phase::Waiting { retry_at: None },
    );
    tunnel.routes = vec!["0.0.0.0/0".parse().unwrap()];
    app.set_tunnels_for_test(vec![tunnel.clone()], None);
    assert!(matches!(
        app.role(&tunnel),
        crate::app::Role::Primary { .. }
    ));

    let other = crate::app::connection::test_view("home", crate::control::Phase::Up);
    app.set_tunnels_for_test(
        vec![tunnel.clone(), other],
        Some(crate::profile::ProfileId::new("home")),
    );
    assert!(matches!(
        app.role(&tunnel),
        crate::app::Role::AddressableSuppressed { .. }
    ));
}
