//! TUI side of the connection engine: sends commands, renders snapshots.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::{App, InputMode, ToastType};
use crate::control::{Command, Level, Phase, Snapshot, TunnelView};
use crate::core::engine::registry::{Role, TunnelSnapshot};
use crate::core::engine::state::{Connection, ConnectionHealth, PromptKind};
use crate::core::engine::Conflict;
use crate::core::profile::ProfileId;
use crate::utils;

pub(super) const CONTROL_STARTING_MESSAGE: &str =
    "The VPN service is still starting. Try again in a moment.";

/// Where the cursor starts in the credential overlay: the one-time code when
/// the pair above it is already filled in, otherwise the username.
fn initial_auth_focus(otp: bool, credentials_prefilled: bool) -> crate::app::state::AuthField {
    if otp && credentials_prefilled {
        crate::app::state::AuthField::Otp
    } else {
        crate::app::state::AuthField::Username
    }
}

/// The renderer still reads the registry; this is its only feed.
fn projection(snapshot: &Snapshot) -> BTreeMap<ProfileId, TunnelSnapshot> {
    snapshot
        .tunnels
        .iter()
        .map(|tunnel| (tunnel.profile_id.clone(), tunnel_snapshot(snapshot, tunnel)))
        .collect()
}

fn tunnel_snapshot(snapshot: &Snapshot, tunnel: &TunnelView) -> TunnelSnapshot {
    let profile_id = tunnel.profile_id.clone();
    let allowed_ips = tunnel.routes.clone();
    let role = if snapshot.primary.as_ref() == Some(&profile_id) {
        Role::Primary { allowed_ips }
    } else if tunnel.is_full() {
        Role::AddressableSuppressed { allowed_ips }
    } else {
        Role::Addressable { allowed_ips }
    };
    let state = match tunnel.phase {
        Phase::Starting => Connection::Connecting {
            profile_id,
            started_at: tunnel.since,
        },
        Phase::AwaitingCredentials => Connection::AwaitingUserInput {
            profile_id,
            prompt_kind: PromptKind::Generic {
                label: "OpenVPN credentials".into(),
            },
            since: tunnel.since,
        },
        Phase::Up => Connection::Connected {
            profile_id,
            since: tunnel.since,
            details: Box::new(tunnel.details.clone()),
        },
        Phase::Waiting { .. } => Connection::Reconnecting {
            profile_id,
            started_at: tunnel.since,
        },
        Phase::Stopping => Connection::Disconnecting {
            profile_id,
            started_at: tunnel.since,
        },
    };
    let role = if matches!(tunnel.phase, Phase::Waiting { .. }) {
        Role::Reconnecting {
            prior_role: Box::new(role),
        }
    } else {
        role
    };
    TunnelSnapshot {
        profile_id: tunnel.profile_id.clone(),
        state,
        role,
        health: ConnectionHealth::default(),
        interface_name: tunnel.interface.clone(),
        started_at: Some(tunnel.since),
    }
}

impl App {
    pub fn attach_control(&mut self, control: crate::control::Control) {
        let snapshot = control.snapshot();
        self.control = Some(control);
        self.control_starting = false;
        self.apply_control_snapshot(snapshot);
        self.log("SUCCESS: VPN service ready. Press [x] for actions.");
    }

    pub(crate) fn send(&mut self, command: Command) {
        match &self.control {
            Some(control) => {
                control.send(command);
            }
            None => self.show_toast(CONTROL_STARTING_MESSAGE.to_string(), ToastType::Info),
        }
    }

    pub fn apply_control_snapshot(&mut self, snapshot: Arc<Snapshot>) {
        self.sync_last_used(&snapshot);
        let drops = snapshot
            .tunnels
            .iter()
            .filter(|tunnel| {
                matches!(tunnel.phase, Phase::Waiting { .. })
                    && self
                        .control_snapshot
                        .tunnel(&tunnel.profile_id)
                        .is_some_and(|old| old.phase == Phase::Up)
            })
            .count();
        self.runtime.connection_drops = self
            .runtime
            .connection_drops
            .saturating_add(u32::try_from(drops).unwrap_or(u32::MAX));

        let egress_changed = self.control_snapshot.primary != snapshot.primary
            || self
                .control_snapshot
                .tunnels
                .iter()
                .map(|t| (&t.profile_id, t.phase, &t.interface))
                .ne(snapshot
                    .tunnels
                    .iter()
                    .map(|t| (&t.profile_id, t.phase, &t.interface)));
        self.registry
            .replace_control_projection(&projection(&snapshot), snapshot.primary.clone());
        if let Some(profile_id) = snapshot.primary.clone().or_else(|| {
            snapshot
                .tunnels
                .iter()
                .find(|tunnel| tunnel.phase == Phase::Up)
                .map(|tunnel| tunnel.profile_id.clone())
        }) {
            self.last_control_connected_profile = Some(profile_id);
        }

        if self.pending_control_killswitch_mode == Some(snapshot.kill_switch) {
            self.pending_control_killswitch_mode = None;
        }

        self.show_prompt(&snapshot);
        self.show_notices(&snapshot);

        self.runtime.scanner_first_tick_done = true;
        self.runtime
            .default_route_interface
            .clone_from(&snapshot.default_route);
        self.registry
            .feed_default_route_interface(snapshot.default_route.clone());
        self.runtime.last_kernel_session_count = snapshot
            .tunnels
            .iter()
            .filter(|tunnel| tunnel.phase == Phase::Up)
            .count()
            + snapshot.external.len();
        let came_up = snapshot
            .tunnels
            .iter()
            .filter(|tunnel| tunnel.phase == Phase::Up)
            .filter(|tunnel| snapshot.primary.as_ref() == Some(&tunnel.profile_id))
            .filter(|tunnel| {
                self.control_snapshot
                    .tunnel(&tunnel.profile_id)
                    .is_none_or(|before| before.phase != Phase::Up)
            })
            .map(|tunnel| (tunnel.profile_id.clone(), tunnel.name.clone()))
            .collect::<Vec<_>>();
        self.control_snapshot = snapshot;
        // A server can push a full-tunnel route the profile never declared;
        // only now is the takeover known, so offer the switch now.
        for (profile_id, name) in came_up {
            let late = self
                .control_snapshot
                .conflicts(&profile_id)
                .into_iter()
                .find(|conflict| matches!(conflict, Conflict::DefaultRouteTakeover { .. }));
            if let Some(conflict) = late {
                if self.input_mode == InputMode::Normal {
                    self.fire_conflict_overlay(conflict, profile_id, name);
                }
            }
        }
        if egress_changed {
            self.refresh_telemetry();
        }
    }

    fn sync_last_used(&mut self, snapshot: &Snapshot) {
        let mut resort = false;
        for profile in &mut self.runtime.profiles {
            if let Some(at) = snapshot.last_connected.get(&profile.id) {
                if profile.last_used != Some(*at) {
                    profile.last_used = Some(*at);
                    resort = true;
                }
            }
        }
        if resort && self.runtime.sort_order == crate::app::state::ProfileSortOrder::LastUsed {
            let selected = self.selected_profile_id();
            self.runtime.sort_profiles();
            self.profile_list_state
                .select(selected.and_then(|profile_id| self.profile_index(&profile_id)));
        }
    }

    fn show_notices(&mut self, snapshot: &Snapshot) {
        let seen = self.notices_seen;
        for notice in snapshot.notices.iter().filter(|notice| notice.seq > seen) {
            let toast = match notice.level {
                Level::Info => ToastType::Info,
                Level::Success => ToastType::Success,
                Level::Warning => ToastType::Warning,
                Level::Error => ToastType::Error,
            };
            self.show_toast(notice.text.clone(), toast);
        }
        if let Some(last) = snapshot.notices.last() {
            self.notices_seen = self.notices_seen.max(last.seq);
        }
    }

    fn show_prompt(&mut self, snapshot: &Snapshot) {
        match snapshot.prompts.first() {
            Some(prompt) if self.control_prompt != Some(prompt.id) => {
                self.control_prompt = Some(prompt.id);
                let (username, password) = match self
                    .control
                    .as_ref()
                    .map(|control| control.load_credentials(&prompt.profile_id, &prompt.name))
                {
                    Some(Ok(Some(saved))) => (
                        crate::app::state::SecretText::from(saved.username()),
                        crate::app::state::SecretText::from(saved.password()),
                    ),
                    _ => Default::default(),
                };
                let prefilled = !username.is_empty() && !password.is_empty();
                self.input_mode = InputMode::AuthPrompt {
                    profile_id: prompt.profile_id.clone(),
                    profile_name: prompt.name.clone(),
                    username_cursor: username.chars().count(),
                    password_cursor: password.chars().count(),
                    username,
                    password,
                    otp: crate::app::state::SecretText::default(),
                    otp_cursor: 0,
                    focused_field: initial_auth_focus(prompt.otp_label.is_some(), prefilled),
                    save_credentials: true,
                    connect_after: true,
                    static_challenge_prompt: prompt.otp_label.clone(),
                    reveal_secrets: false,
                };
            }
            None if self.control_prompt.take().is_some() => {
                if matches!(self.input_mode, InputMode::AuthPrompt { .. }) {
                    self.input_mode = InputMode::Normal;
                }
            }
            _ => {}
        }
    }

    fn selected_profile_id(&self) -> Option<ProfileId> {
        self.profile_list_state
            .selected()
            .and_then(|index| self.runtime.profiles.get(index))
            .map(|profile| profile.id.clone())
    }

    pub(crate) fn profile_index(&self, profile_id: &ProfileId) -> Option<usize> {
        self.runtime
            .profiles
            .iter()
            .position(|profile| &profile.id == profile_id)
    }

    fn tunnel_active(&self, profile_id: &ProfileId) -> bool {
        self.control_snapshot.tunnel(profile_id).is_some()
    }

    /// Connect or disconnect the selected profile.
    pub(crate) fn toggle_connection(&mut self, idx: usize) {
        let Some(profile) = self.runtime.profiles.get(idx).cloned() else {
            return;
        };
        if self.control.is_none() {
            self.show_toast(CONTROL_STARTING_MESSAGE.to_string(), ToastType::Info);
            return;
        }
        if self.tunnel_active(&profile.id) {
            self.send(Command::Disconnect(profile.id));
            return;
        }
        // A conflict needs a decision: switch (stop the other once this one
        // is up) or cancel.
        if let Some(conflict) = self
            .control_snapshot
            .conflicts(&profile.id)
            .into_iter()
            .next()
        {
            self.fire_conflict_overlay(conflict, profile.id, profile.name);
            return;
        }
        self.log(&format!("CONTROL: Connecting '{}'", profile.name));
        self.send(Command::Connect(profile.id));
    }

    fn fire_conflict_overlay(
        &mut self,
        conflict: Conflict,
        target_id: ProfileId,
        target_name: String,
    ) {
        match conflict {
            Conflict::DefaultRouteTakeover { current, new } => {
                let current_name = self.profile_display_name(&current);
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
                    "ACTION: Connect to '{target_name}' blocked by route-overlap with '{}' ({} CIDR(s))",
                    self.profile_display_name(&with),
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

    /// Check for system-wide dependencies at startup and warn the user.
    pub(crate) fn check_system_dependencies(&mut self) {
        let mut missing: Vec<&str> = Vec::new();
        if !utils::binary_exists("openvpn") {
            missing.push("openvpn");
        }
        // wg / wg-quick both ship in wireguard-tools.
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

    fn primary_or_first(&self) -> Option<ProfileId> {
        self.control_snapshot.primary.clone().or_else(|| {
            self.control_snapshot
                .tunnels
                .first()
                .map(|tunnel| tunnel.profile_id.clone())
        })
    }

    /// Disconnect the primary tunnel, or the first one.
    pub(crate) fn disconnect(&mut self) {
        if let Some(profile_id) = self.primary_or_first() {
            self.send(Command::Disconnect(profile_id));
        }
    }

    pub(crate) fn disconnect_profile_by_idx(&mut self, idx: usize) {
        if let Some(profile_id) = self.runtime.profiles.get(idx).map(|p| p.id.clone()) {
            if self.tunnel_active(&profile_id) {
                self.send(Command::Disconnect(profile_id));
            }
        }
    }

    pub(crate) fn disconnect_all_active(&mut self) {
        self.send(Command::DisconnectAll);
    }

    /// Reconnect the primary or most recently connected tunnel.
    pub(crate) fn reconnect(&mut self) {
        let Some(profile_id) = self
            .primary_or_first()
            .or_else(|| self.last_control_connected_profile.clone())
        else {
            self.show_toast(
                "No previously connected tunnel is available".to_string(),
                ToastType::Warning,
            );
            return;
        };
        self.send(Command::Reconnect(profile_id));
    }
}

#[cfg(test)]
mod tests {
    use super::initial_auth_focus;
    use crate::app::state::AuthField;

    #[test]
    fn an_empty_two_factor_form_starts_at_the_username() {
        assert_eq!(initial_auth_focus(true, false), AuthField::Username);
        assert_eq!(initial_auth_focus(true, true), AuthField::Otp);
    }
}
