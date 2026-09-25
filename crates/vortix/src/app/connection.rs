//! TUI side of the connection engine: sends commands, renders snapshots.

use std::sync::Arc;

use super::{App, InputMode, ToastType};
use crate::cidr::Cidr;
use crate::control::Conflict;
use crate::control::{Command, Level, Phase, Snapshot, TunnelView};
use crate::profile::ProfileId;

/// A transition label shows at least this long, even when the change is
/// faster; people cannot read a label that lasts a tenth of a second.
const TRANSITION_MIN_VISIBLE: std::time::Duration = std::time::Duration::from_millis(600);

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

/// Which traffic a tunnel carries, from its routes and the current primary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    /// Owns the default route.
    Primary { allowed_ips: Vec<Cidr> },
    /// Carries only its own routes.
    Addressable { allowed_ips: Vec<Cidr> },
    /// Claims `0/0`, but another tunnel holds the default route.
    AddressableSuppressed { allowed_ips: Vec<Cidr> },
}

impl App {
    /// Every tunnel, in stable profile order so panels do not flicker.
    #[must_use]
    pub fn tunnels(&self) -> Vec<&TunnelView> {
        let mut tunnels: Vec<_> = self.control_snapshot.tunnels.iter().collect();
        tunnels.sort_by(|a, b| a.profile_id.cmp(&b.profile_id));
        tunnels
    }

    #[must_use]
    pub fn tunnel(&self, profile_id: &ProfileId) -> Option<&TunnelView> {
        self.control_snapshot.tunnel(profile_id)
    }

    #[must_use]
    pub fn role(&self, tunnel: &TunnelView) -> Role {
        let allowed_ips = tunnel.routes.clone();
        let primary = self.primary_id();
        if primary == Some(&tunnel.profile_id) || (primary.is_none() && tunnel.is_full()) {
            // A full tunnel with no other default-route owner is the exit,
            // including while it reconnects.
            Role::Primary { allowed_ips }
        } else if tunnel.is_full() {
            Role::AddressableSuppressed { allowed_ips }
        } else {
            Role::Addressable { allowed_ips }
        }
    }

    /// The tunnel that owns the default route.
    #[must_use]
    pub fn primary_id(&self) -> Option<&ProfileId> {
        self.control_snapshot.primary.as_ref()
    }

    #[must_use]
    pub fn tunnel_count(&self) -> usize {
        self.control_snapshot.tunnels.len()
    }

    /// Replace the engine's tunnel list; renderer tests only.
    #[cfg(test)]
    pub(crate) fn set_tunnels_for_test(
        &mut self,
        tunnels: Vec<TunnelView>,
        primary: Option<ProfileId>,
    ) {
        let snapshot = Arc::make_mut(&mut self.control_snapshot);
        snapshot.tunnels = tunnels;
        snapshot.primary = primary;
    }

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
        if let Some(until) = self.transition_hold(&snapshot) {
            self.held_snapshot = Some((snapshot, until));
            return;
        }
        self.held_snapshot = None;
        let now = std::time::Instant::now();
        for tunnel in &snapshot.tunnels {
            let before = self.control_snapshot.tunnel(&tunnel.profile_id);
            let transition = matches!(tunnel.phase, Phase::Starting | Phase::Stopping);
            if transition && before.map(|t| t.phase) != Some(tunnel.phase) {
                self.transition_shown.insert(tunnel.profile_id.clone(), now);
            }
        }
        self.sync_last_used(&snapshot);
        self.runtime.connection_drops = snapshot.drops;

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
                .find(Conflict::is_takeover);
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

    /// Until when to keep the current screen: a Connecting or Disconnecting
    /// label that `snapshot` would end before anyone could read it.
    fn transition_hold(&self, snapshot: &Snapshot) -> Option<std::time::Instant> {
        self.transition_shown
            .iter()
            .filter(|(profile_id, _)| {
                let old = self.control_snapshot.tunnel(profile_id).map(|t| t.phase);
                old != snapshot.tunnel(profile_id).map(|t| t.phase)
            })
            .map(|(_, shown)| *shown + TRANSITION_MIN_VISIBLE)
            .filter(|until| *until > std::time::Instant::now())
            .max()
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

    /// Show a pending engine prompt once no other dialog owns the screen.
    pub(crate) fn show_pending_prompt(&mut self) {
        let snapshot = Arc::clone(&self.control_snapshot);
        self.show_prompt(&snapshot);
    }

    fn show_prompt(&mut self, snapshot: &Snapshot) {
        match snapshot.prompts.first() {
            // Another dialog is open: the prompt waits instead of replacing it.
            Some(prompt)
                if self.control_prompt != Some(prompt.id)
                    && self.answered_prompt < prompt.id
                    && matches!(self.input_mode, InputMode::Normal) =>
            {
                // It must be seen to be answered: nothing may draw over it.
                self.show_config = false;
                self.cached_config = None;
                self.show_action_menu = false;
                self.show_bulk_menu = false;
                self.zoomed_panel = None;
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

    /// Answer (or, with `None`, cancel) the open engine prompt. Prompt ids
    /// only grow, so a stale snapshot still listing it cannot reopen it.
    pub(crate) fn answer_prompt(&mut self, answer: Option<crate::control::Credentials>) {
        if let Some(prompt) = self.control_prompt.take() {
            self.answered_prompt = prompt;
            if let Some(control) = &self.control {
                control.answer(prompt, answer);
            }
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
        let Conflict {
            with: current_id,
            shared,
        } = conflict;
        let what = if shared.is_empty() {
            "all traffic".to_owned()
        } else {
            format!("{} network(s)", shared.len())
        };
        self.log(&format!(
            "ACTION: Connect to '{target_name}' conflicts with '{}' over {what}",
            self.profile_display_name(&current_id)
        ));
        self.input_mode = InputMode::ConfirmSwitch {
            current_id,
            to_profile_id: target_id,
            to_name: target_name,
            shared,
            confirm_selected: true,
        };
    }

    /// Check for system-wide dependencies at startup and warn the user.
    pub(crate) fn check_system_dependencies(&mut self) {
        let mut missing: Vec<&str> = Vec::new();
        if !crate::platform::binary_exists("openvpn") {
            missing.push("openvpn");
        }
        // wg / wg-quick both ship in wireguard-tools.
        if !crate::platform::binary_exists("wg-quick") || !crate::platform::binary_exists("wg") {
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

    /// The tunnel global actions target; the same one the dashboard shows as
    /// current.
    pub(crate) fn primary_or_first(&self) -> Option<ProfileId> {
        self.current_tunnel()
            .map(|tunnel| tunnel.profile_id.clone())
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

/// A tunnel as the engine reports it; renderer tests only.
#[cfg(test)]
pub(crate) fn test_view(name: &str, phase: Phase) -> TunnelView {
    TunnelView {
        profile_id: ProfileId::new(name),
        name: name.into(),
        protocol: crate::profile::ProtocolKind::WireGuard,
        phase,
        interface: None,
        since: std::time::SystemTime::UNIX_EPOCH,
        routes: Vec::new(),
        dns: Vec::new(),
        details: crate::tunnel::DetailedConnectionInfo::default(),
        health: crate::tunnel::ConnectionHealth::default(),
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
