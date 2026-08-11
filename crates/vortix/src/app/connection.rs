//! VPN connection lifecycle management and kill switch control.

#[cfg(test)]
use super::Protocol;
use super::{App, InputMode, ToastType};
use crate::utils;
use crate::vortix_core::engine::Conflict;
use crate::vortix_core::profile::ProfileId;

impl App {
    /// Attach the one Standard-mode control owner used for the entire TUI
    /// session and immediately render its current immutable publication.
    pub fn attach_control_session(
        &mut self,
        control: crate::cli::control::LocalControlSession,
    ) -> Result<(), crate::cli::control::LocalControlError> {
        control.progress()?;
        let snapshot = control.current_snapshot();
        self.control_session = Some(control);
        self.apply_control_snapshot(snapshot);
        Ok(())
    }

    pub(crate) fn issue_control_command(
        &mut self,
        command: crate::vortix_core::control::UserCommand,
    ) -> Option<()> {
        let (wait, idempotency_key) = self.next_control_request();
        let result = self
            .control_session
            .as_ref()
            .expect("control command requires an attached session")
            .enqueue_tui_command(command, wait, idempotency_key);
        self.report_control_enqueue(result)
    }

    pub(crate) fn issue_control_import(&mut self, path: &std::path::Path) -> Option<String> {
        let (wait, idempotency_key) = self.next_control_request();
        let result = self
            .control_session
            .as_ref()
            .expect("control import requires an attached session")
            .enqueue_tui_profile_import(path, wait, idempotency_key);
        match result {
            Ok(display_name) => Some(display_name),
            Err(error) => {
                self.log(&format!("ERR: Control command refused: {error}"));
                self.show_toast(format!("Control command failed: {error}"), ToastType::Error);
                None
            }
        }
    }

    fn next_control_request(&mut self) -> (std::time::Duration, String) {
        self.control_request_sequence = self.control_request_sequence.saturating_add(1);
        let idempotency_key = format!(
            "tui-{}-{}",
            std::process::id(),
            self.control_request_sequence
        );
        let wait = std::time::Duration::from_secs(
            self.runtime
                .config
                .connect_timeout
                .max(crate::vortix_core::engine::state::DEFAULT_RETRY_BUDGET_SECS)
                .max(30),
        );
        (wait, idempotency_key)
    }

    fn report_control_enqueue(
        &mut self,
        result: Result<(), crate::cli::control::LocalControlError>,
    ) -> Option<()> {
        match result {
            Ok(()) => Some(()),
            Err(error) => {
                self.log(&format!("ERR: Control command refused: {error}"));
                self.show_toast(format!("Control command failed: {error}"), ToastType::Error);
                None
            }
        }
    }

    pub(crate) fn handle_control_admission_results(
        &mut self,
        results: Vec<crate::cli::control::LocalTuiAdmissionResult>,
    ) {
        for result in results {
            match result.operation_id {
                Ok(operation_id) => self.log(&format!(
                    "CONTROL: Durable command admitted as {operation_id:?}"
                )),
                Err(error) => {
                    if let crate::vortix_core::control::UserCommand::SetKillSwitch { mode } =
                        result.command
                    {
                        if self.pending_control_killswitch_mode == Some(mode) {
                            self.pending_control_killswitch_mode = None;
                        }
                    }
                    let subject = result
                        .import_display_name
                        .as_deref()
                        .map_or_else(|| "command".to_owned(), |name| format!("import '{name}'"));
                    self.log(&format!("ERR: Control {subject} refused: {error}"));
                    self.show_toast(
                        format!("Control {subject} failed: {error}"),
                        ToastType::Error,
                    );
                }
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn apply_control_snapshot(
        &mut self,
        snapshot: crate::vortix_core::control::ControlSnapshot,
    ) {
        use crate::state::KillSwitchState;

        let tunnel_projection_changed = self.control_snapshot.tunnels != snapshot.tunnels
            || self.control_snapshot.primary != snapshot.primary;
        if tunnel_projection_changed {
            self.registry
                .replace_control_projection(&snapshot.tunnels, snapshot.primary.clone());
        }
        if let Some(profile_id) = snapshot.primary.clone().or_else(|| {
            snapshot.tunnels.values().find_map(|tunnel| {
                matches!(
                    tunnel.state,
                    crate::vortix_core::engine::state::Connection::Connected { .. }
                )
                .then(|| tunnel.profile_id.clone())
            })
        }) {
            self.last_control_connected_profile = Some(profile_id);
        }
        self.runtime.killswitch_mode = snapshot.desired.kill_switch;
        if self.pending_control_killswitch_mode == Some(snapshot.desired.kill_switch) {
            self.pending_control_killswitch_mode = None;
        }
        self.registry
            .set_killswitch_mode(snapshot.desired.kill_switch);
        let kill_switch_state = snapshot
            .effective
            .kill_switch
            .unwrap_or(KillSwitchState::Disabled);
        self.runtime.killswitch_state = kill_switch_state;
        self.registry.set_killswitch_state(kill_switch_state);

        let pending_challenge = snapshot.challenges.values().next().cloned();
        match pending_challenge {
            Some(challenge) if self.control_challenge != Some(challenge.id) => {
                if let Some((idx, profile)) = self
                    .runtime
                    .profiles
                    .iter()
                    .enumerate()
                    .find(|(_, profile)| profile.id == challenge.profile_id)
                {
                    self.control_challenge = Some(challenge.id);
                    let (username, password) =
                        utils::read_openvpn_saved_auth_compat(profile.id.as_str(), &profile.name)
                            .unwrap_or_default();
                    self.input_mode = InputMode::AuthPrompt {
                        profile_idx: idx,
                        profile_name: profile.name.clone(),
                        username_cursor: username.chars().count(),
                        password_cursor: password.chars().count(),
                        username,
                        password,
                        otp: String::new(),
                        otp_cursor: 0,
                        focused_field: if matches!(
                            &challenge.kind,
                            crate::vortix_core::control::ChallengeKind::TwoFactorCode
                        ) {
                            crate::state::AuthField::Otp
                        } else {
                            crate::state::AuthField::Username
                        },
                        save_credentials: true,
                        connect_after: true,
                        static_challenge_prompt: matches!(
                            &challenge.kind,
                            crate::vortix_core::control::ChallengeKind::TwoFactorCode
                        )
                        .then_some(challenge.label),
                    };
                } else {
                    let cancelled = self
                        .control_session
                        .as_ref()
                        .expect("snapshot challenge requires attached control session")
                        .cancel_challenge(challenge.id);
                    self.log(&format!(
                        "ERR: Cancelled challenge for missing profile {}: {}",
                        challenge.profile_id,
                        cancelled.err().map_or_else(
                            || "profile unavailable".to_owned(),
                            |error| error.to_string()
                        )
                    ));
                }
            }
            None if self.control_challenge.take().is_some() => {
                if matches!(self.input_mode, InputMode::AuthPrompt { .. }) {
                    self.input_mode = InputMode::Normal;
                }
            }
            _ => {}
        }
        self.control_snapshot = snapshot;
        if tunnel_projection_changed {
            self.refresh_telemetry();
        }
    }

    pub(crate) fn apply_local_catalog_update(
        &mut self,
        update: crate::cli::control::LocalCatalogUpdate,
    ) {
        let selected_id = self
            .profile_list_state
            .selected()
            .and_then(|index| self.runtime.profiles.get(index))
            .map(|profile| profile.id.clone());
        self.runtime.profiles = update.profiles;
        self.runtime.sort_profiles();
        self.profile_list_state.select(
            selected_id
                .and_then(|profile_id| {
                    self.runtime
                        .profiles
                        .iter()
                        .position(|profile| profile.id == profile_id)
                })
                .or_else(|| (!self.runtime.profiles.is_empty()).then_some(0)),
        );
        for outcome in update.outcomes {
            match outcome {
                Ok(_) => self.show_toast(
                    format!("Profile catalog updated (revision {})", update.revision),
                    ToastType::Success,
                ),
                Err(failure) => self.show_toast(
                    format!("Profile update failed: {failure:?}"),
                    ToastType::Error,
                ),
            }
        }
    }

    fn control_connect_profile(&mut self, idx: usize, acknowledge_conflict: bool) {
        let Some(profile) = self.runtime.profiles.get(idx).cloned() else {
            return;
        };
        let conflict = self.control_snapshot.topology_conflict(&profile.id);
        if let Some(conflict) = conflict.clone() {
            if !acknowledge_conflict {
                self.fire_conflict_overlay(conflict, idx, profile.id, profile.name);
                return;
            }
        } else if acknowledge_conflict {
            self.show_toast(
                "Tunnel topology changed; review the connection again".to_string(),
                ToastType::Warning,
            );
            return;
        }
        self.issue_control_command(crate::vortix_core::control::UserCommand::Connect {
            profile_id: profile.id,
            conflict_acknowledgement: conflict,
        });
    }

    /// Connect or disconnect the selected profile through the canonical owner.
    pub(crate) fn toggle_connection(&mut self, idx: usize) {
        let Some(profile) = self.runtime.profiles.get(idx) else {
            return;
        };
        let profile_id = profile.id.clone();
        if self.control_session.is_none() {
            self.show_toast(
                "Control service is not attached".to_string(),
                ToastType::Error,
            );
            return;
        }
        let active = self.registry.snapshot(&profile_id).is_some_and(|snapshot| {
            !matches!(
                snapshot.state,
                crate::vortix_core::engine::state::Connection::Disconnected { .. }
            )
        });
        if active {
            self.issue_control_command(crate::vortix_core::control::UserCommand::Disconnect {
                profile_id: Some(profile_id),
            });
        } else {
            self.control_connect_profile(idx, false);
        }
    }

    /// Check for system-wide dependencies at startup and warn the user.
    pub(crate) fn check_system_dependencies(&mut self) {
        let mut missing: Vec<&str> = Vec::new();

        if !utils::binary_exists("openvpn") {
            missing.push("openvpn");
        }

        // wg / wg-quick both ship in wireguard-tools — single label so the
        // install hint doesn't duplicate when both are absent.
        if !utils::binary_exists("wg-quick") || !utils::binary_exists("wg") {
            missing.push("wireguard-tools");
        }

        if missing.is_empty() {
            return;
        }

        for tool in &missing {
            self.log(&format!(
                "WARN: '{}' not found - run: {}",
                tool,
                crate::platform::install_hint(tool)
            ));
        }

        self.show_toast(
            format!(
                "Missing tools: {}. Telemetry/VPN features may not work.",
                missing.join(", ")
            ),
            ToastType::Warning,
        );
    }
    /// Retry a connect after the user acknowledges the current topology conflict.
    pub(crate) fn connect_profile_forced(&mut self, idx: usize) {
        if self.control_session.is_some() {
            self.control_connect_profile(idx, true);
        } else {
            self.show_toast(
                "Control service is not attached".to_string(),
                ToastType::Error,
            );
        }
    }
    /// Disconnect the primary canonical tunnel, or the first active tunnel.
    pub(crate) fn disconnect(&mut self) {
        if self.control_session.is_none() {
            self.show_toast(
                "Control service is not attached".to_string(),
                ToastType::Error,
            );
            return;
        }
        let profile_id = self.registry.primary().cloned().or_else(|| {
            self.registry
                .snapshot_all()
                .first()
                .map(|snapshot| snapshot.profile_id.clone())
        });
        if let Some(profile_id) = profile_id {
            self.issue_control_command(crate::vortix_core::control::UserCommand::Disconnect {
                profile_id: Some(profile_id),
            });
        }
    }
    /// Force-disconnect the exact primary canonical tunnel.
    pub(crate) fn force_disconnect(&mut self) {
        if self.control_session.is_none() {
            self.show_toast(
                "Control service is not attached".to_string(),
                ToastType::Error,
            );
            return;
        }
        let profile_id = self.registry.primary().cloned().or_else(|| {
            self.registry
                .snapshot_all()
                .first()
                .map(|snapshot| snapshot.profile_id.clone())
        });
        let Some(profile_id) = profile_id else {
            self.show_toast(
                "No exact tunnel is available to force-disconnect".to_string(),
                ToastType::Warning,
            );
            return;
        };
        self.issue_control_command(crate::vortix_core::control::UserCommand::ForceDisconnect {
            profile_id: Some(profile_id),
        });
    }

    /// Fire the appropriate confirm overlay for a registry-reported
    /// conflict. Logs an ACTION line so the activity panel
    /// reflects the blocked attempt.
    fn fire_conflict_overlay(
        &mut self,
        conflict: Conflict,
        _idx: usize,
        target_id: ProfileId,
        target_name: String,
    ) {
        match conflict {
            Conflict::DefaultRouteTakeover { current, new } => {
                let current_name = self
                    .runtime
                    .profiles
                    .iter()
                    .find(|profile| profile.id == current)
                    .map_or_else(
                        || format!("ProfileMissing:{current}"),
                        |profile| profile.name.clone(),
                    );
                self.log(&format!(
                    "ACTION: Connect to '{target_name}' blocked by default-route takeover ('{current_name}' holds 0/0)"
                ));
                self.input_mode = InputMode::ConfirmDefaultRouteTakeover {
                    from: current_name,
                    to_profile_id: new,
                    to_name: target_name,
                    confirm_selected: true,
                };
            }
            Conflict::RouteOverlap {
                with,
                overlapping_cidrs,
            } => {
                self.log(&format!(
                    "ACTION: Connect to '{target_name}' blocked by route-overlap with '{with}' ({} CIDR(s))",
                    overlapping_cidrs.len()
                ));
                self.input_mode = InputMode::ConfirmRouteOverlap {
                    with_profile_id: with,
                    overlapping_cidrs,
                    to_profile_id: target_id,
                    to_name: target_name,
                    confirm_selected: true,
                };
            }
        }
    }
    /// Disconnect the selected profile through the canonical owner.
    pub(crate) fn disconnect_profile_by_idx(&mut self, idx: usize) {
        if self.control_session.is_none() {
            self.show_toast(
                "Control service is not attached".to_string(),
                ToastType::Error,
            );
            return;
        }
        let Some(profile_id) = self
            .runtime
            .profiles
            .get(idx)
            .map(|profile| profile.id.clone())
        else {
            return;
        };
        if self.registry.snapshot(&profile_id).is_some() {
            self.issue_control_command(crate::vortix_core::control::UserCommand::Disconnect {
                profile_id: Some(profile_id),
            });
        }
    }
    /// Disconnect every active tunnel through the canonical owner.
    pub(crate) fn disconnect_all_active(&mut self) {
        if self.control_session.is_some() {
            self.issue_control_command(crate::vortix_core::control::UserCommand::Disconnect {
                profile_id: None,
            });
        } else {
            self.show_toast(
                "Control service is not attached".to_string(),
                ToastType::Error,
            );
        }
    }
    /// Cancel the selected in-flight connect through the canonical owner.
    pub(crate) fn cancel_connect(&mut self, idx: usize) {
        let Some(profile_id) = self
            .runtime
            .profiles
            .get(idx)
            .map(|profile| profile.id.clone())
        else {
            return;
        };
        if self.control_session.is_some() {
            self.issue_control_command(crate::vortix_core::control::UserCommand::Disconnect {
                profile_id: Some(profile_id),
            });
        } else {
            self.show_toast(
                "Control service is not attached".to_string(),
                ToastType::Error,
            );
        }
    }
    /// Reconnect the primary or most recently connected canonical tunnel.
    pub(crate) fn reconnect(&mut self) {
        if self.control_session.is_none() {
            self.show_toast(
                "Control service is not attached".to_string(),
                ToastType::Error,
            );
            return;
        }
        let profile_id = self
            .registry
            .primary()
            .cloned()
            .or_else(|| {
                self.registry
                    .snapshot_all()
                    .first()
                    .map(|snapshot| snapshot.profile_id.clone())
            })
            .or_else(|| self.last_control_connected_profile.clone());
        let Some(profile_id) = profile_id else {
            self.show_toast(
                "No previously connected tunnel is available".to_string(),
                ToastType::Warning,
            );
            return;
        };
        self.issue_control_command(crate::vortix_core::control::UserCommand::Reconnect {
            profile_id: Some(profile_id),
        });
    }
}

#[cfg(test)]
mod u7_conflict_tests {
    //!
    //! Coverage focuses on the App's role: extracting `AllowedIPs` from a
    //! profile config and translating a `Conflict` variant into the right
    //! `InputMode` overlay. The registry's `detect_conflict` itself is
    //! tested in `vortix_core::engine::registry`.
    use super::Protocol;
    use crate::vortix_core::cidr::claims_default_route_v4;
    use std::io::Write;

    fn write_tmp(name: &str, body: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("vortix_u7_tests");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).expect("create tmp config");
        f.write_all(body.as_bytes()).expect("write tmp config");
        path
    }

    #[test]
    fn wg_parser_extracts_default_route_v4() {
        let body = "\
[Interface]
PrivateKey = aGVsbG8=
Address = 10.0.0.2/32

[Peer]
PublicKey = d29ybGQ=
AllowedIPs = 0.0.0.0/0
Endpoint = 1.2.3.4:51820
";
        let path = write_tmp("default-route.conf", body);
        let cidrs = crate::topology_policy::declared_routes(Protocol::WireGuard, &path);
        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0].prefix_len, 0);
    }

    #[test]
    fn wg_parser_extracts_disjoint_subnet() {
        let body = "\
[Interface]
PrivateKey = aGVsbG8=

[Peer]
PublicKey = d29ybGQ=
AllowedIPs = 10.0.0.0/24, 192.168.5.0/24
Endpoint = 1.2.3.4:51820
";
        let path = write_tmp("disjoint.conf", body);
        let cidrs = crate::topology_policy::declared_routes(Protocol::WireGuard, &path);
        assert_eq!(cidrs.len(), 2);
        // Disjoint /24s — neither claims the default route.
        assert!(!claims_default_route_v4(&cidrs));
    }

    #[test]
    fn ovpn_redirect_gateway_yields_default_route() {
        let body = "\
client
dev tun
remote vpn.example.com 1194
redirect-gateway def1
";
        let path = write_tmp("default-route.ovpn", body);
        let cidrs = crate::topology_policy::declared_routes(Protocol::OpenVPN, &path);
        assert!(!cidrs.is_empty());
        assert!(claims_default_route_v4(&cidrs));
    }

    #[test]
    fn ovpn_route_with_netmask_parses_to_prefix() {
        let body = "\
client
dev tun
route 10.0.0.0 255.255.255.0
";
        let path = write_tmp("specific-route.ovpn", body);
        let cidrs = crate::topology_policy::declared_routes(Protocol::OpenVPN, &path);
        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0].prefix_len, 24);
    }

    #[test]
    fn unreadable_path_returns_empty() {
        let p = std::path::PathBuf::from("/nonexistent/vortix_u7/never.conf");
        let cidrs = crate::topology_policy::declared_routes(Protocol::WireGuard, &p);
        assert!(cidrs.is_empty());
    }

    #[test]
    fn fire_default_route_takeover_sets_overlay() {
        use super::App;
        use crate::vortix_core::engine::Conflict;
        use crate::vortix_core::profile::ProfileId;

        let mut app = App::new_test();
        app.runtime.profiles.push(crate::state::VpnProfile {
            id: ProfileId::new("home"),
            name: "home".to_string(),
            protocol: Protocol::WireGuard,
            location: String::new(),
            config_path: "/tmp/home.conf".into(),
            last_used: None,
        });
        let conflict = Conflict::DefaultRouteTakeover {
            current: ProfileId::new("home"),
            new: ProfileId::new("corp"),
        };
        app.fire_conflict_overlay(conflict, 0, ProfileId::new("corp"), "corp".to_string());
        assert!(matches!(
            app.input_mode,
            crate::state::InputMode::ConfirmDefaultRouteTakeover { ref from, .. }
                if from == "home"
        ));
    }

    #[test]
    fn fire_route_overlap_sets_overlay() {
        use super::App;
        use crate::vortix_core::cidr::Cidr;
        use crate::vortix_core::engine::Conflict;
        use crate::vortix_core::profile::ProfileId;

        let mut app = App::new_test();
        let cidr: Cidr = "10.0.0.0/8".parse().unwrap();
        let conflict = Conflict::RouteOverlap {
            with: ProfileId::new("home"),
            overlapping_cidrs: vec![cidr],
        };
        app.fire_conflict_overlay(conflict, 1, ProfileId::new("corp"), "corp".to_string());
        match &app.input_mode {
            crate::state::InputMode::ConfirmRouteOverlap {
                with_profile_id,
                overlapping_cidrs,
                ..
            } => {
                assert_eq!(with_profile_id.as_str(), "home");
                assert_eq!(overlapping_cidrs.len(), 1);
            }
            other => panic!("expected ConfirmRouteOverlap, got {other:?}"),
        }
    }

    #[test]
    fn connect_with_empty_registry_skips_overlay() {
        // until the registry migration populates the
        // registry, detect_conflict against an empty registry always
        // returns None — the connect path proceeds without firing the
        // overlay. This locks in the "no false-positive" invariant.
        use super::App;
        use crate::state::InputMode;
        let path = write_tmp("u7_skip.conf", "[Interface]\nPrivateKey = a=\n");
        let app = App::new_test();
        let allowed = crate::topology_policy::declared_routes(Protocol::WireGuard, &path);
        let conflict = app.registry.detect_conflict(
            &crate::vortix_core::profile::ProfileId::new("any"),
            &allowed,
        );
        assert!(conflict.is_none());
        assert!(matches!(app.input_mode, InputMode::Normal));
    }
}
