//! VPN connection lifecycle management and kill switch control.

#[cfg(test)]
use super::Protocol;
use super::{App, InputMode, ToastType};
use crate::utils;
use crate::vortix_core::engine::Conflict;
use crate::vortix_core::profile::ProfileId;

pub(super) const CONTROL_STARTING_MESSAGE: &str =
    "The VPN service is still starting. Try again in a moment.";

#[derive(Clone, Copy)]
pub(crate) enum PendingControlSubject {
    Connection,
    Reconnection,
    Disconnection,
    DisconnectAll,
    KillSwitch,
}

#[derive(Clone, Copy)]
enum ProfileDisconnectKind {
    Normal,
    Force,
}

impl PendingControlSubject {
    const fn label(self) -> &'static str {
        match self {
            Self::Connection => "connection",
            Self::Reconnection => "reconnection",
            Self::Disconnection => "disconnection",
            Self::DisconnectAll => "disconnect all",
            Self::KillSwitch => "kill switch change",
        }
    }

    const fn queued_message(self) -> &'static str {
        match self {
            Self::Connection => "Connection queued",
            Self::Reconnection => "Reconnection queued",
            Self::Disconnection => "Disconnection queued",
            Self::DisconnectAll => "Disconnecting all VPNs",
            Self::KillSwitch => "Kill switch change queued",
        }
    }

    fn dns_failure_message(self, detail: Option<&str>) -> String {
        let message = match self {
            Self::Connection | Self::Reconnection => {
                "VPN DNS could not be applied safely. Your previous network settings were restored."
            }
            Self::Disconnection | Self::DisconnectAll => {
                "Disconnect could not finish safely. Your previous network settings were restored."
            }
            Self::KillSwitch => {
                "The kill switch could not be changed safely. Your previous network settings were restored."
            }
        };
        friendly_dns_failure_explanation(detail).map_or_else(
            || message.to_string(),
            |explanation| format!("{message} {explanation}"),
        )
    }

    const fn authentication_failure_message(self) -> &'static str {
        match self {
            Self::Connection | Self::Reconnection => {
                "The VPN server rejected this profile. Check its certificate or username and password; if they are correct, the server may not authorize this profile."
            }
            Self::Disconnection | Self::DisconnectAll | Self::KillSwitch => {
                "The VPN server rejected the requested authentication."
            }
        }
    }

    fn failure_message(self, failure: crate::vortix_core::control::OperationFailure) -> String {
        use crate::vortix_core::control::OperationFailure;
        match failure {
            OperationFailure::Timeout => format!("{} timed out", self.label()),
            OperationFailure::Rejected => format!(
                "{} could not start because another action or route conflict is still active. Try again in a moment.",
                self.label()
            ),
            OperationFailure::AuthenticationFailed => {
                self.authentication_failure_message().to_string()
            }
            OperationFailure::DnsPolicyFailed => self.dns_failure_message(None),
            OperationFailure::HandshakeFailed => {
                "No WireGuard handshake was received. Check the server endpoint, keys, and network reachability."
                    .to_string()
            }
            OperationFailure::InvalidProfile => {
                "This WireGuard profile has an invalid filename. Delete it, rename the original file to 1–15 characters (for example, wg07.conf), and import it again."
                    .to_string()
            }
            OperationFailure::ObservationFailed => format!(
                "Vortix could not verify the system state after the {}. Check the Event Log and try again.",
                self.label()
            ),
            OperationFailure::Internal => format!(
                "Vortix could not complete the {}. Check the Event Log and try again.",
                self.label()
            ),
        }
    }
}

fn friendly_dns_failure_explanation(detail: Option<&str>) -> Option<&'static str> {
    let detail = detail?.to_ascii_lowercase();
    if detail.contains("another vpn or network service") || detail.contains("instead of this vpn") {
        Some(
            "Another VPN or network service is routing this profile's DNS traffic. Disconnect it and try again. The Event Log shows the conflicting interface and a command to inspect it.",
        )
    } else if [
        "owner",
        "owned",
        "ownership",
        "backup",
        "earlier generation",
        "interrupted",
    ]
    .iter()
    .any(|needle| detail.contains(needle))
    {
        Some("Vortix found unfinished DNS state from an earlier connection.")
    } else if detail.contains("route") || detail.contains("through tunnel") {
        Some("The VPN's DNS server could not be verified through the tunnel.")
    } else if detail.contains("lock") || detail.contains("busy") {
        Some("Another Vortix process was updating DNS.")
    } else if detail.contains("restore") || detail.contains("rollback") {
        Some("Vortix could not verify restoration of the previous DNS settings.")
    } else {
        None
    }
}

fn profile_mutation_failure_message(
    failure: crate::vortix_core::control::ProfileMutationFailure,
) -> &'static str {
    use crate::vortix_core::control::ProfileMutationFailure;
    match failure {
        ProfileMutationFailure::NotFound => "The profile no longer exists",
        ProfileMutationFailure::AlreadyExists => "A profile with that name already exists",
        ProfileMutationFailure::InvalidName => "The profile name is invalid",
        ProfileMutationFailure::Busy => "The profile is busy; try again in a moment",
        ProfileMutationFailure::DeadlineExpired => "The profile update timed out",
        ProfileMutationFailure::Storage => "The profile could not be saved safely",
        ProfileMutationFailure::Internal => "The profile update could not be completed",
    }
}

fn remote_profile_failure_message(
    failure: crate::vortix_core::control::OperationFailure,
) -> &'static str {
    use crate::vortix_core::control::OperationFailure;
    match failure {
        OperationFailure::Timeout => "The profile update timed out",
        OperationFailure::Rejected => "The profile update was refused because the profile is busy",
        OperationFailure::AuthenticationFailed => "The profile update could not be authorized",
        OperationFailure::InvalidProfile => "The profile is invalid",
        OperationFailure::ObservationFailed => "Vortix could not verify the profile update",
        OperationFailure::DnsPolicyFailed
        | OperationFailure::HandshakeFailed
        | OperationFailure::Internal => "The profile update could not be completed",
    }
}

fn control_error_message(error: &crate::cli::control::LocalControlError) -> String {
    use crate::cli::control::LocalControlError;
    use crate::vortix_core::control::AdmissionError;
    match error {
        LocalControlError::Busy | LocalControlError::Admission(AdmissionError::Busy) => {
            "Another action is still finishing. Try again in a moment.".to_string()
        }
        LocalControlError::Admission(AdmissionError::NotReady) => {
            CONTROL_STARTING_MESSAGE.to_string()
        }
        LocalControlError::Admission(AdmissionError::RouteConflict) => {
            "This VPN overlaps an active route. Review the confirmation and try again.".to_string()
        }
        LocalControlError::Admission(AdmissionError::ProfileActive) => {
            "Disconnect this profile before changing it.".to_string()
        }
        LocalControlError::Admission(AdmissionError::ProfileBusy) => {
            "Another action is still using this profile. Try again in a moment.".to_string()
        }
        LocalControlError::Admission(AdmissionError::ProfileNotFound) => {
            "This profile no longer exists.".to_string()
        }
        LocalControlError::Admission(AdmissionError::ProfileAlreadyExists) => {
            "A profile with this identity already exists.".to_string()
        }
        LocalControlError::Admission(AdmissionError::DeadlineExpired)
        | LocalControlError::ChallengeExpired => "The action timed out. Try again.".to_string(),
        LocalControlError::Stopped | LocalControlError::Admission(AdmissionError::Stopped) => {
            "The VPN service stopped. Restart Vortix and try again.".to_string()
        }
        LocalControlError::Admission(AdmissionError::Persistence) => {
            "Vortix could not save this change safely. No action was applied.".to_string()
        }
        LocalControlError::Profile { reason, .. } | LocalControlError::ProfileImport(reason) => {
            reason.clone()
        }
        _ => "Vortix could not start this action. See Event Log for details.".to_string(),
    }
}

pub(crate) struct PendingControlOperation {
    subject: PendingControlSubject,
    profile_name: Option<String>,
    admitted_after_generation: u64,
    recovery_retry: bool,
}

pub(crate) struct CatalogFeedback {
    applied_count: usize,
    first_applied_name: Option<String>,
    failed_count: usize,
    first_failure: Option<String>,
    updated_at: std::time::Instant,
}

const CATALOG_FEEDBACK_QUIET_WINDOW: std::time::Duration = std::time::Duration::from_millis(300);

fn control_command_subject(
    command: Option<&crate::vortix_core::control::UserCommand>,
) -> Option<PendingControlSubject> {
    use crate::vortix_core::control::UserCommand;
    match command? {
        UserCommand::Connect { .. } | UserCommand::ConnectExclusive { .. } => {
            Some(PendingControlSubject::Connection)
        }
        UserCommand::Reconnect { .. } => Some(PendingControlSubject::Reconnection),
        UserCommand::Disconnect { profile_id: None }
        | UserCommand::ForceDisconnect { profile_id: None } => {
            Some(PendingControlSubject::DisconnectAll)
        }
        UserCommand::Disconnect {
            profile_id: Some(_),
        }
        | UserCommand::ForceDisconnect {
            profile_id: Some(_),
        } => Some(PendingControlSubject::Disconnection),
        UserCommand::SetKillSwitch { .. } => Some(PendingControlSubject::KillSwitch),
        UserCommand::ImportProfile { .. }
        | UserCommand::RenameProfile { .. }
        | UserCommand::DeleteProfile { .. } => None,
    }
}

#[cfg(test)]
mod control_command_subject_tests {
    use super::{control_command_subject, PendingControlSubject};
    use crate::vortix_core::control::UserCommand;
    use crate::vortix_core::profile::ProfileId;

    #[test]
    fn distinguishes_bulk_from_profile_disconnects() {
        assert!(matches!(
            control_command_subject(Some(&UserCommand::Disconnect { profile_id: None })),
            Some(PendingControlSubject::DisconnectAll)
        ));
        assert!(matches!(
            control_command_subject(Some(&UserCommand::Disconnect {
                profile_id: Some(ProfileId::new("profile")),
            })),
            Some(PendingControlSubject::Disconnection)
        ));
    }
}

fn lifecycle_command_profile_id(
    command: Option<&crate::vortix_core::control::UserCommand>,
) -> Option<&ProfileId> {
    use crate::vortix_core::control::UserCommand;
    match command? {
        UserCommand::Connect { profile_id, .. }
        | UserCommand::ConnectExclusive { profile_id }
        | UserCommand::Reconnect {
            profile_id: Some(profile_id),
        }
        | UserCommand::Disconnect {
            profile_id: Some(profile_id),
        }
        | UserCommand::ForceDisconnect {
            profile_id: Some(profile_id),
        } => Some(profile_id),
        UserCommand::Reconnect { profile_id: None }
        | UserCommand::Disconnect { profile_id: None }
        | UserCommand::ForceDisconnect { profile_id: None }
        | UserCommand::SetKillSwitch { .. }
        | UserCommand::ImportProfile { .. }
        | UserCommand::RenameProfile { .. }
        | UserCommand::DeleteProfile { .. } => None,
    }
}

fn active_egress_paths(
    snapshot: &crate::vortix_core::control::ControlSnapshot,
) -> impl Iterator<Item = (&ProfileId, &crate::vortix_core::engine::Role, Option<&str>)> {
    snapshot.tunnels.iter().filter_map(|(profile_id, tunnel)| {
        matches!(
            tunnel.state,
            crate::vortix_core::engine::Connection::Connected { .. }
                | crate::vortix_core::engine::Connection::Disconnecting { .. }
        )
        .then_some((profile_id, &tunnel.role, tunnel.interface_name.as_deref()))
    })
}

fn egress_path_changed(
    current: &crate::vortix_core::control::ControlSnapshot,
    next: &crate::vortix_core::control::ControlSnapshot,
) -> bool {
    current.primary != next.primary || active_egress_paths(current).ne(active_egress_paths(next))
}

fn late_route_conflict_for_operation(
    snapshot: &crate::vortix_core::control::ControlSnapshot,
    operation: &crate::vortix_core::control::OperationRecord,
) -> Option<(ProfileId, Conflict)> {
    use crate::vortix_core::control::{OperationIntent, RequestedTunnelState};

    let tunnels = match &operation.intent {
        OperationIntent::DesiredSubset { tunnels, .. }
        | OperationIntent::UnexpectedRecovery { tunnels, .. } => tunnels,
        OperationIntent::GenerationScoped | OperationIntent::ProfileMutation { .. } => {
            return None;
        }
    };
    tunnels
        .iter()
        .filter(|(_, requested)| **requested == RequestedTunnelState::Connected)
        .find_map(|(profile_id, _)| {
            snapshot
                .pending_route_conflicts
                .get(profile_id)
                .cloned()
                .map(|conflict| (profile_id.clone(), conflict))
        })
}

fn terminal_control_notification(
    subject: PendingControlSubject,
    recovery_retry: bool,
    status: crate::vortix_core::control::OperationStatus,
    result: Option<crate::vortix_core::control::OperationResult>,
    has_owned_retry: bool,
    failure_detail: Option<&str>,
) -> Option<(String, ToastType)> {
    use crate::vortix_core::control::{OperationFailure, OperationResult, OperationStatus};

    match (status, result) {
        (
            OperationStatus::Failed,
            Some(OperationResult::Failed(OperationFailure::DnsPolicyFailed)),
        ) => Some((
            subject.dns_failure_message(failure_detail),
            ToastType::Error,
        )),
        (
            OperationStatus::Failed,
            Some(OperationResult::Failed(OperationFailure::AuthenticationFailed)),
        ) => Some((
            subject.authentication_failure_message().to_string(),
            ToastType::Error,
        )),
        (
            OperationStatus::Failed,
            Some(OperationResult::Failed(OperationFailure::InvalidProfile)),
        ) => Some((
            "This WireGuard profile has an invalid filename. Delete it, rename the original file to 1–15 characters (for example, wg07.conf), and import it again."
                .to_string(),
            ToastType::Error,
        )),
        (
            OperationStatus::Failed,
            Some(OperationResult::Failed(OperationFailure::HandshakeFailed)),
        ) if has_owned_retry => Some((
            "No WireGuard handshake was received. Vortix is retrying once; if the peer still does not respond, this profile will return to disconnected."
                .to_string(),
            ToastType::Warning,
        )),
        (OperationStatus::Failed, Some(OperationResult::Failed(failure))) => {
            Some((subject.failure_message(failure), ToastType::Error))
        }
        (OperationStatus::Cancelled, _) => {
            Some((format!("{} cancelled", subject.label()), ToastType::Info))
        }
        (OperationStatus::Expired, _) => {
            Some((format!("{} timed out", subject.label()), ToastType::Error))
        }
        (OperationStatus::Succeeded, _)
            if matches!(subject, PendingControlSubject::DisconnectAll) =>
        {
            Some((
                "All VPN connections disconnected".to_string(),
                ToastType::Success,
            ))
        }
        (OperationStatus::Succeeded, _) if recovery_retry => Some((
            format!("{} succeeded after retry", subject.label()),
            ToastType::Success,
        )),
        _ => None,
    }
}

impl App {
    /// Attach the one Standard-mode control owner used for the entire TUI
    /// session and immediately render its current immutable publication.
    pub fn attach_control_session(
        &mut self,
        control: crate::cli::control::LocalControlSession,
    ) -> Result<(), crate::cli::control::LocalControlError> {
        self.attach_client_control_session(crate::cli::control::ClientControlSession::standard(
            control,
        ))
    }

    /// Attach the already-selected client adapter. Production startup passes
    /// only the Standard variant until U13 atomically opens the enrollment
    /// gate; command handlers never choose or fall back between authorities.
    pub fn attach_client_control_session(
        &mut self,
        control: crate::cli::control::ClientControlSession,
    ) -> Result<(), crate::cli::control::LocalControlError> {
        control.progress()?;
        let snapshot = control.current_snapshot();
        self.control_session = Some(control);
        self.control_starting = false;
        self.apply_control_snapshot(snapshot);
        self.log("SUCCESS: VPN service ready. Press [x] for actions.");
        Ok(())
    }

    /// Test-only/preparatory attachment seam for U19's dormant remote
    /// adapter. Production startup continues to call
    /// [`Self::attach_control_session`] and therefore remains Standard-only.
    #[doc(hidden)]
    pub fn attach_remote_control_session(
        &mut self,
        control: crate::daemon::service::RemoteControlSession,
    ) -> Result<(), crate::cli::control::LocalControlError> {
        self.attach_client_control_session(
            crate::cli::control::ClientControlSession::remote_for_parity(control),
        )
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
        let result = self.try_issue_control_import(path);
        self.report_control_enqueue(result)
    }

    pub(crate) fn try_issue_control_import(
        &mut self,
        path: &std::path::Path,
    ) -> Result<String, crate::cli::control::LocalControlError> {
        let (wait, idempotency_key) = self.next_control_request();
        self.control_session
            .as_ref()
            .expect("control import requires an attached session")
            .enqueue_tui_profile_import(path, wait, idempotency_key)
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

    fn report_control_enqueue<T>(
        &mut self,
        result: Result<T, crate::cli::control::LocalControlError>,
    ) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(crate::cli::control::LocalControlError::Profile { profile, reason })
                if reason.contains("WireGuard name must be") =>
            {
                self.log(&format!(
                    "ERR: WireGuard profile '{profile}' was rejected: {reason}"
                ));
                self.show_toast(reason, ToastType::Error);
                None
            }
            Err(error) => {
                self.log(&format!("ERR: Control command refused: {error}"));
                self.show_toast(control_error_message(&error), ToastType::Error);
                None
            }
        }
    }

    pub(crate) fn handle_control_admission_results(
        &mut self,
        results: Vec<crate::cli::control::LocalTuiAdmissionResult>,
    ) {
        for result in results {
            match result.completion {
                crate::cli::control::TuiControlCompletion::Admission(Ok(operation_id)) => {
                    let control_subject = control_command_subject(result.command.as_ref());
                    let profile_name = lifecycle_command_profile_id(result.command.as_ref())
                        .and_then(|profile_id| {
                            self.runtime
                                .profiles
                                .iter()
                                .find(|profile| profile.id == *profile_id)
                                .map(|profile| profile.name.clone())
                        });
                    let activity = result.import_display_name.as_deref().map_or_else(
                        || {
                            control_subject.map_or_else(
                                || "Profile update queued".to_string(),
                                |subject| {
                                    profile_name.as_deref().map_or_else(
                                        || subject.queued_message().to_string(),
                                        |name| format!("{} for '{name}'", subject.queued_message()),
                                    )
                                },
                            )
                        },
                        |name| format!("Profile import queued: '{name}'"),
                    );
                    self.log(&format!("CONTROL: {activity}"));
                    if let Some(subject) = control_subject {
                        self.track_control_operation_with_profile(
                            operation_id,
                            subject,
                            profile_name,
                        );
                    }
                }
                crate::cli::control::TuiControlCompletion::Admission(Err(error)) => {
                    if let Some(crate::vortix_core::control::UserCommand::SetKillSwitch { mode }) =
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
                    self.show_toast(control_error_message(&error), ToastType::Error);
                }
                crate::cli::control::TuiControlCompletion::ChallengeResponse {
                    challenge_id,
                    result: Ok(()),
                } => self.log(&format!(
                    "AUTH: Service accepted challenge response {challenge_id:?}"
                )),
                crate::cli::control::TuiControlCompletion::ChallengeCancellation {
                    challenge_id,
                    result: Ok(()),
                } => self.log(&format!(
                    "AUTH: Service cancelled challenge {challenge_id:?}"
                )),
                crate::cli::control::TuiControlCompletion::ChallengeResponse {
                    challenge_id,
                    result: Err(error),
                } => {
                    self.log(&format!(
                        "ERR: Challenge response {challenge_id:?} failed: {error}"
                    ));
                    self.show_toast(
                        "Credentials could not be submitted. Your entries are still available; try again."
                            .to_string(),
                        ToastType::Error,
                    );
                }
                crate::cli::control::TuiControlCompletion::ChallengeCancellation {
                    challenge_id,
                    result: Err(error),
                } => {
                    self.log(&format!(
                        "WARN: Challenge cancellation {challenge_id:?} failed: {error}"
                    ));
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

        if self.control_snapshot.last_connected_at != snapshot.last_connected_at {
            let mut activity_changed = false;
            for profile in &mut self.runtime.profiles {
                let Some(connected_at) = snapshot.last_connected_at.get(&profile.id).copied()
                else {
                    continue;
                };
                if profile.last_used != Some(connected_at) {
                    profile.last_used = Some(connected_at);
                    activity_changed = true;
                }
            }
            if activity_changed
                && self.runtime.sort_order == crate::state::ProfileSortOrder::LastUsed
            {
                let selected_profile = self.selected_profile_id();
                self.runtime.sort_profiles();
                self.profile_list_state.select(
                    selected_profile.and_then(|profile_id| self.profile_index(&profile_id)),
                );
            }
        }

        let tunnel_projection_changed = self.control_snapshot.tunnels != snapshot.tunnels
            || self.control_snapshot.primary != snapshot.primary;
        let egress_path_changed =
            tunnel_projection_changed && egress_path_changed(&self.control_snapshot, &snapshot);
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
        let kill_switch_state = snapshot.effective.kill_switch.unwrap_or_else(|| {
            if snapshot.desired.kill_switch == crate::state::KillSwitchMode::Off {
                KillSwitchState::Disabled
            } else {
                KillSwitchState::Degraded
            }
        });
        self.runtime.killswitch_state = kill_switch_state;
        self.registry.set_killswitch_state(kill_switch_state);

        let pending_challenge = snapshot.challenges.values().next().cloned();
        match pending_challenge {
            Some(challenge) if self.control_challenge != Some(challenge.id) => {
                if let Some(profile) = self
                    .runtime
                    .profiles
                    .iter()
                    .find(|profile| profile.id == challenge.profile_id)
                {
                    self.control_challenge = Some(challenge.id);
                    let profile_id = profile.id.clone();
                    let profile_name = profile.name.clone();
                    let credentials = self
                        .control_session
                        .as_ref()
                        .expect("snapshot challenge requires attached control session")
                        .load_openvpn_credentials(&profile_id, &profile_name);
                    let (username, password) = match credentials {
                        Ok(Some(credentials)) => (
                            crate::state::SecretText::from(credentials.username()),
                            crate::state::SecretText::from(credentials.password()),
                        ),
                        Ok(None) => Default::default(),
                        Err(error) => {
                            self.log(&format!(
                                "WARN: Remembered OpenVPN credentials are unavailable: {error}"
                            ));
                            self.show_toast(
                                "Saved credentials couldn't be used. Enter them again to continue."
                                    .to_string(),
                                ToastType::Warning,
                            );
                            Default::default()
                        }
                    };
                    self.input_mode = InputMode::AuthPrompt {
                        profile_id,
                        profile_name,
                        username_cursor: username.chars().count(),
                        password_cursor: password.chars().count(),
                        username,
                        password,
                        otp: crate::state::SecretText::default(),
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
                    // Mark it before asynchronous cancellation so repeated
                    // snapshots cannot enqueue the same cancellation again.
                    self.control_challenge = Some(challenge.id);
                    let cancelled = self
                        .control_session
                        .as_ref()
                        .expect("snapshot challenge requires attached control session")
                        .cancel_challenge(challenge.id);
                    match cancelled {
                        Ok(()) => self.log(&format!(
                            "AUTH: Requested cancellation for missing profile {}",
                            challenge.profile_id
                        )),
                        Err(error) => self.log(&format!(
                            "ERR: Could not queue challenge cancellation for missing profile {}: {error}",
                            challenge.profile_id
                        )),
                    }
                }
            }
            None if self.control_challenge.take().is_some() => {
                if matches!(self.input_mode, InputMode::AuthPrompt { .. }) {
                    self.input_mode = InputMode::Normal;
                }
            }
            _ => {}
        }
        self.report_terminal_control_operations(&snapshot);
        self.control_snapshot = snapshot;
        if egress_path_changed {
            self.refresh_telemetry();
        }
    }

    pub(crate) fn track_control_operation_with_profile(
        &mut self,
        operation_id: crate::vortix_core::control::OperationId,
        subject: PendingControlSubject,
        profile_name: Option<String>,
    ) {
        let already_terminal = self
            .control_snapshot
            .operations
            .get(&operation_id)
            .is_some_and(|operation| operation.status.is_terminal());
        self.pending_control_operations.insert(
            operation_id,
            PendingControlOperation {
                subject,
                profile_name,
                admitted_after_generation: self.control_snapshot.generation,
                recovery_retry: false,
            },
        );
        // The actor may reach terminal truth before the admission worker's
        // result is drained. Recheck the already-held publication so that
        // notification does not depend on channel scheduling order.
        if already_terminal {
            let current = self.control_snapshot.clone();
            self.report_terminal_control_operations(&current);
        }
    }

    fn present_late_route_conflict(
        &mut self,
        subject: PendingControlSubject,
        status: crate::vortix_core::control::OperationStatus,
        result: Option<crate::vortix_core::control::OperationResult>,
        late_route_conflict: Option<(ProfileId, Conflict)>,
    ) -> bool {
        use crate::vortix_core::control::{OperationFailure, OperationResult, OperationStatus};

        if !matches!(
            (subject, status, result),
            (
                PendingControlSubject::Connection | PendingControlSubject::Reconnection,
                OperationStatus::Failed,
                Some(OperationResult::Failed(OperationFailure::Rejected))
            )
        ) {
            return false;
        }
        let Some((profile_id, conflict)) = late_route_conflict else {
            return false;
        };
        let Some(idx) = self.profile_index(&profile_id) else {
            return false;
        };
        let target_name = self.runtime.profiles[idx].name.clone();
        self.fire_conflict_overlay(conflict, idx, profile_id, target_name);
        true
    }

    fn report_terminal_control_operations(
        &mut self,
        snapshot: &crate::vortix_core::control::ControlSnapshot,
    ) {
        let disconnect_all_in_flight = self
            .pending_control_operations
            .values()
            .any(|pending| matches!(pending.subject, PendingControlSubject::DisconnectAll));
        let completed = self
            .pending_control_operations
            .iter()
            .filter_map(|(operation_id, pending)| {
                snapshot
                    .operations
                    .get(operation_id)
                    .filter(|operation| operation.status.is_terminal())
                    .map(|operation| {
                        let owned_retry = snapshot
                            .operations
                            .values()
                            .find(|candidate| {
                                candidate.id != operation.id
                                    && !candidate.status.is_terminal()
                                    && candidate.desired_generation == operation.desired_generation
                                    && candidate.client_id.sequence() == Some(0)
                            })
                            .map(|candidate| candidate.id.clone());
                        (
                            operation_id.clone(),
                            pending.subject,
                            pending.profile_name.clone(),
                            pending.recovery_retry,
                            operation.status,
                            operation.result,
                            operation.failure_detail.clone(),
                            owned_retry,
                            late_route_conflict_for_operation(snapshot, operation),
                        )
                    })
            })
            .collect::<Vec<_>>();

        for (
            operation_id,
            subject,
            profile_name,
            recovery_retry,
            status,
            result,
            failure_detail,
            owned_retry,
            late_route_conflict,
        ) in completed
        {
            self.pending_control_operations.remove(&operation_id);
            if self.present_late_route_conflict(subject, status, result, late_route_conflict) {
                continue;
            }
            let superseded_connection_cancellation = disconnect_all_in_flight
                && status == crate::vortix_core::control::OperationStatus::Cancelled
                && matches!(
                    subject,
                    PendingControlSubject::Connection | PendingControlSubject::Reconnection
                );
            let notification = if superseded_connection_cancellation {
                None
            } else {
                terminal_control_notification(
                    subject,
                    recovery_retry,
                    status,
                    result,
                    owned_retry.is_some(),
                    failure_detail.as_deref(),
                )
            };
            if let Some((message, toast_type)) = notification {
                self.show_toast(message, toast_type);
            }
            if let Some(detail) = failure_detail {
                let profile = profile_name
                    .as_deref()
                    .map_or_else(String::new, |name| format!(" for '{name}'"));
                self.log(&format!(
                    "ERR: Control {} failed{profile}: {detail}",
                    subject.label(),
                ));
            }
            if let Some(retry_id) = owned_retry {
                self.pending_control_operations.insert(
                    retry_id,
                    PendingControlOperation {
                        subject,
                        profile_name,
                        admitted_after_generation: snapshot.generation,
                        recovery_retry: true,
                    },
                );
            }
        }

        self.pending_control_operations
            .retain(|operation_id, pending| {
                snapshot.operations.contains_key(operation_id)
                    || snapshot.generation <= pending.admitted_after_generation
            });
    }

    pub(crate) fn apply_local_catalog_update(
        &mut self,
        update: crate::cli::control::LocalCatalogUpdate,
    ) {
        let revision = update.revision;
        let selected_id = self.selected_profile_id();
        if let Some(profiles) = update.profiles {
            self.runtime.profiles = profiles;
            self.runtime.sort_profiles();
            self.profile_list_state.select(
                selected_id
                    .and_then(|profile_id| self.profile_index(&profile_id))
                    .or_else(|| (!self.runtime.profiles.is_empty()).then_some(0)),
            );
            if self.presented_catalog_revision != Some(revision) {
                self.log(&format!(
                    "APP: Profile catalog updated (revision {revision})"
                ));
                self.presented_catalog_revision = Some(revision);
            }
        }
        let mut applied_names = Vec::new();
        let mut applied_count = 0usize;
        let mut failures = Vec::new();
        for outcome in update.outcomes {
            match outcome {
                crate::cli::control::LocalCatalogOutcome::Applied(receipt) => {
                    applied_count += 1;
                    let display_name = match receipt {
                        crate::cli::control::LocalProfileMutationReceipt::Imported(profile)
                        | crate::cli::control::LocalProfileMutationReceipt::Renamed(profile) => {
                            Some(profile.name)
                        }
                        crate::cli::control::LocalProfileMutationReceipt::Deleted {
                            display_name,
                            ..
                        } => Some(display_name),
                        crate::cli::control::LocalProfileMutationReceipt::RemoteApplied {
                            display_name,
                        } => display_name,
                    };
                    if let Some(display_name) = display_name {
                        applied_names.push(display_name);
                    }
                }
                crate::cli::control::LocalCatalogOutcome::Failed(failure) => {
                    failures.push(profile_mutation_failure_message(failure).to_string());
                }
                crate::cli::control::LocalCatalogOutcome::RemoteTerminal { status, result } => {
                    let message = match result {
                        Some(crate::vortix_core::control::OperationResult::Failed(failure)) => {
                            remote_profile_failure_message(failure).to_string()
                        }
                        _ if status == crate::vortix_core::control::OperationStatus::Expired => {
                            "The profile update timed out".to_string()
                        }
                        _ => "The profile update could not be completed".to_string(),
                    };
                    failures.push(message);
                }
            }
        }
        for failure in &failures {
            self.log(&format!("ERR: Profile update failed: {failure}"));
        }
        if applied_count > 0 || !failures.is_empty() {
            let feedback = self
                .catalog_feedback
                .get_or_insert_with(|| CatalogFeedback {
                    applied_count: 0,
                    first_applied_name: None,
                    failed_count: 0,
                    first_failure: None,
                    updated_at: std::time::Instant::now(),
                });
            feedback.applied_count = feedback.applied_count.saturating_add(applied_count);
            feedback.first_applied_name = feedback
                .first_applied_name
                .take()
                .or_else(|| applied_names.into_iter().next());
            feedback.failed_count = feedback.failed_count.saturating_add(failures.len());
            feedback.first_failure = feedback
                .first_failure
                .take()
                .or_else(|| failures.into_iter().next());
            feedback.updated_at = std::time::Instant::now();
        }
    }

    pub(crate) fn flush_catalog_feedback(&mut self, force: bool) {
        let ready = self.catalog_feedback.as_ref().is_some_and(|feedback| {
            force || feedback.updated_at.elapsed() >= CATALOG_FEEDBACK_QUIET_WINDOW
        });
        if !ready {
            return;
        }
        let feedback = self
            .catalog_feedback
            .take()
            .expect("ready catalog feedback must exist");
        let (message, toast_type) = match (feedback.applied_count, feedback.failed_count) {
            (1, 0) => (
                feedback.first_applied_name.map_or_else(
                    || "Profile updated".to_string(),
                    |name| format!("Profile '{name}' updated"),
                ),
                ToastType::Success,
            ),
            (applied, 0) => (format!("{applied} profiles updated"), ToastType::Success),
            (0, 1) => (
                feedback
                    .first_failure
                    .unwrap_or_else(|| "The profile update failed".to_string()),
                ToastType::Error,
            ),
            (0, failed) => (
                format!("{failed} profile updates failed. See Event Log."),
                ToastType::Error,
            ),
            (applied, failed) => (
                format!("{applied} profile updates completed; {failed} failed. See Event Log."),
                ToastType::Error,
            ),
        };
        self.show_toast(message, toast_type);
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
            self.show_toast(CONTROL_STARTING_MESSAGE.to_string(), ToastType::Info);
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
            self.show_toast(CONTROL_STARTING_MESSAGE.to_string(), ToastType::Info);
        }
    }
    /// Disconnect the primary canonical tunnel, or the first active tunnel.
    pub(crate) fn disconnect(&mut self) {
        if self.control_session.is_none() {
            self.show_toast(CONTROL_STARTING_MESSAGE.to_string(), ToastType::Info);
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
            self.show_toast(CONTROL_STARTING_MESSAGE.to_string(), ToastType::Info);
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
        self.disconnect_profile_by_idx_with_kind(idx, ProfileDisconnectKind::Normal);
    }

    fn disconnect_profile_by_idx_with_kind(&mut self, idx: usize, kind: ProfileDisconnectKind) {
        if self.control_session.is_none() {
            self.show_toast(CONTROL_STARTING_MESSAGE.to_string(), ToastType::Info);
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
            let command = match kind {
                ProfileDisconnectKind::Normal => {
                    crate::vortix_core::control::UserCommand::Disconnect {
                        profile_id: Some(profile_id),
                    }
                }
                ProfileDisconnectKind::Force => {
                    crate::vortix_core::control::UserCommand::ForceDisconnect {
                        profile_id: Some(profile_id),
                    }
                }
            };
            self.issue_control_command(command);
        }
    }
    /// Force-disconnect the exact selected profile without falling back to a
    /// different primary tunnel.
    pub(crate) fn force_disconnect_profile_by_idx(&mut self, idx: usize) {
        self.disconnect_profile_by_idx_with_kind(idx, ProfileDisconnectKind::Force);
    }
    /// Disconnect every active tunnel through the canonical owner.
    pub(crate) fn disconnect_all_active(&mut self) {
        if self.control_session.is_some() {
            self.issue_control_command(crate::vortix_core::control::UserCommand::Disconnect {
                profile_id: None,
            });
        } else {
            self.show_toast(CONTROL_STARTING_MESSAGE.to_string(), ToastType::Info);
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
            self.show_toast(CONTROL_STARTING_MESSAGE.to_string(), ToastType::Info);
        }
    }
    /// Reconnect the primary or most recently connected canonical tunnel.
    pub(crate) fn reconnect(&mut self) {
        if self.control_session.is_none() {
            self.show_toast(CONTROL_STARTING_MESSAGE.to_string(), ToastType::Info);
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
