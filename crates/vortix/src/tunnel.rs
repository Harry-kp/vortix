//! `TunnelKind` aggregate — runtime-selectable tunnel dispatcher.
//!
//! The engine routes `profile.protocol → TunnelKind` exactly once via
//! [`tunnel_for`]; everything downstream calls the trait without protocol
//! match arms.
//!
//! The aggregate lives in the binary (not `vortix-core`) for the same
//! Cargo-cycle reason as `Platform`: the protocol crates already
//! depend on `vortix-core`.

use std::collections::BTreeMap;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::vortix_core::ports::tunnel::{
    ParseError, ParsedProfile, Tunnel, TunnelCapabilities, TunnelError, TunnelExecutionContext,
    TunnelHandle, TunnelKindTag, TunnelStatus,
};
use crate::vortix_core::profile::{Profile, ProfileId, ProtocolKind};
use crate::vortix_protocol_openvpn::OvpnTunnel;
use crate::vortix_protocol_wireguard::WgTunnel;

use crate::state::{Protocol, VpnProfile};

type RememberedOpenVpnCredentialResolver = dyn Fn(&ProfileId, &str) -> Result<Option<crate::vortix_core::control::Secret>, String>
    + Send
    + Sync;

/// Runtime-selectable carrier over the closed protocol set.
///
/// Mock variant uses `crate::vortix_core::ports::tunnel::mock::MockTunnel` so tests
/// can substitute scripted behaviour without touching the real impls.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum TunnelKind {
    WireGuard(WgTunnel),
    OpenVpn(OvpnTunnel),
    Mock(crate::vortix_core::ports::tunnel::mock::MockTunnel),
}

impl TunnelKind {
    #[must_use]
    pub fn for_generation(self, generation: u64) -> Self {
        match self {
            Self::WireGuard(tunnel) => Self::WireGuard(tunnel.for_generation(generation)),
            Self::OpenVpn(tunnel) => Self::OpenVpn(tunnel.for_generation(generation)),
            other => other,
        }
    }

    #[must_use]
    pub fn for_operation(self, operation_id: crate::vortix_core::control::OperationId) -> Self {
        match self {
            Self::OpenVpn(tunnel) => Self::OpenVpn(tunnel.for_operation(operation_id)),
            other => other,
        }
    }

    #[must_use]
    pub fn with_execution_context(self, context: TunnelExecutionContext) -> Self {
        match self {
            Self::WireGuard(tunnel) => Self::WireGuard(tunnel.with_execution_context(context)),
            other => other,
        }
    }

    #[must_use]
    pub fn with_openvpn_static_challenge(
        self,
        credentials: crate::vortix_protocol_openvpn::tunnel::OpenVpnStaticChallengeCredentials,
    ) -> Self {
        match self {
            Self::OpenVpn(tunnel) => {
                Self::OpenVpn(tunnel.with_static_challenge_credentials(credentials))
            }
            other => other,
        }
    }
    pub fn up(&mut self, profile: &Profile) -> Result<TunnelHandle, TunnelError> {
        match self {
            Self::WireGuard(t) => t.up(profile),
            Self::OpenVpn(t) => t.up(profile),
            Self::Mock(t) => t.up(profile),
        }
    }

    pub fn down(&mut self, handle: TunnelHandle) -> Result<(), TunnelError> {
        match self {
            Self::WireGuard(t) => t.down(handle),
            Self::OpenVpn(t) => t.down(handle),
            Self::Mock(t) => t.down(handle),
        }
    }

    pub fn status(&self, handle: &TunnelHandle) -> Result<TunnelStatus, TunnelError> {
        match self {
            Self::WireGuard(t) => t.status(handle),
            Self::OpenVpn(t) => t.status(handle),
            Self::Mock(t) => t.status(handle),
        }
    }

    pub fn parse_profile(&self, raw: &[u8]) -> Result<Box<dyn ParsedProfile>, ParseError> {
        match self {
            Self::WireGuard(t) => t.parse_profile(raw),
            Self::OpenVpn(t) => t.parse_profile(raw),
            Self::Mock(t) => t.parse_profile(raw),
        }
    }

    #[must_use]
    pub fn capabilities(&self) -> TunnelCapabilities {
        match self {
            Self::WireGuard(t) => t.capabilities(),
            Self::OpenVpn(t) => t.capabilities(),
            Self::Mock(t) => t.capabilities(),
        }
    }

    #[must_use]
    pub fn kind_tag(&self) -> TunnelKindTag {
        match self {
            Self::WireGuard(t) => t.kind_tag(),
            Self::OpenVpn(t) => t.kind_tag(),
            Self::Mock(t) => t.kind_tag(),
        }
    }

    /// Compensate a protocol attempt that unwound before returning a handle.
    pub fn compensate_inflight(&mut self) -> Result<(), String> {
        match self {
            Self::WireGuard(tunnel) => tunnel
                .compensate_inflight()
                .map_err(|error| error.to_string()),
            Self::OpenVpn(_) | Self::Mock(_) => {
                Err("protocol did not retain an exact in-flight capability".into())
            }
        }
    }
}

/// Immutable production settings for canonical tunnel workers.
#[derive(Debug, Clone)]
pub struct CanonicalTunnelSettings {
    pub config_dir: PathBuf,
    pub openvpn_verbosity: String,
    pub connect_timeout_secs: u64,
    pub wireguard_handshake_timeout_secs: u64,
    pub wireguard_health_targets: Vec<String>,
}

type CanonicalProfileResolver = dyn Fn(&ProfileId) -> Option<Profile> + Send + Sync;
type CanonicalSessionResolver =
    dyn Fn(&ProfileId) -> Option<crate::core::scanner::ActiveSession> + Send + Sync;
type CanonicalOwnedLifecycleObserver = dyn Fn(&ProfileId, bool) + Send + Sync;

pub(crate) struct StandardOpenVpnOwner {
    custody: crate::vortix_process::CustodianHandshake,
    protocol_pid: u32,
}

impl StandardOpenVpnOwner {
    #[must_use]
    pub(crate) const fn generation(&self) -> u64 {
        self.custody.identity.generation
    }

    #[must_use]
    pub(crate) fn operation_id(&self) -> Option<&crate::vortix_core::control::OperationId> {
        self.custody.operation_id.as_ref()
    }
}

pub(crate) fn standard_openvpn_owner(
    profile_id: &ProfileId,
    session: &crate::core::scanner::ActiveSession,
) -> Result<Option<StandardOpenVpnOwner>, String> {
    let Some(custody) = crate::vortix_process::custodian::load_handshake(profile_id)
        .map_err(|error| format!("OpenVPN ownership receipt rejected: {error}"))?
    else {
        return Ok(None);
    };
    let alive = crate::vortix_process::custodian::remote_status(&custody.identity)
        .map_err(|error| format!("OpenVPN custodian status failed: {error}"))?;
    if !alive {
        return Ok(None);
    }
    let scanner_pid = session
        .pid
        .ok_or_else(|| "active OpenVPN target has no scanner process PID".to_string())?;
    if !crate::vortix_process::custodian::contains_protocol_pid(&custody, scanner_pid)
        .map_err(|error| format!("OpenVPN process-group ownership check failed: {error}"))?
    {
        return Err(
            "OpenVPN scanner PID is not contained by the authenticated custodian group".into(),
        );
    }
    Ok(Some(StandardOpenVpnOwner {
        custody,
        protocol_pid: scanner_pid,
    }))
}

/// Production adapter from bounded canonical work to the concrete protocol
/// implementations. Successful `WireGuard` receipts are generated only from
/// the exact generation-bound handle returned by `WgTunnel::up`.
pub struct CanonicalTunnelExecutor {
    settings: CanonicalTunnelSettings,
    profiles: Arc<CanonicalProfileResolver>,
    active: Mutex<BTreeMap<ProfileId, (TunnelKind, TunnelHandle)>>,
    standard_ownership:
        Option<Arc<crate::core::standard_tunnel_ownership::StandardTunnelOwnershipStore>>,
    sessions: Option<Arc<CanonicalSessionResolver>>,
    owned_lifecycle_observer: Option<Arc<CanonicalOwnedLifecycleObserver>>,
    remembered_openvpn_credentials: Option<Arc<RememberedOpenVpnCredentialResolver>>,
    challenge_issuer: Mutex<Option<std::sync::Weak<crate::vortix_core::control::CompleterHandle>>>,
}

impl CanonicalTunnelExecutor {
    #[must_use]
    pub fn new(
        settings: CanonicalTunnelSettings,
        profiles: impl Fn(&ProfileId) -> Option<Profile> + Send + Sync + 'static,
    ) -> Self {
        Self {
            settings,
            profiles: Arc::new(profiles),
            active: Mutex::new(BTreeMap::new()),
            standard_ownership: None,
            sessions: None,
            owned_lifecycle_observer: None,
            remembered_openvpn_credentials: None,
            challenge_issuer: Mutex::new(None),
        }
    }

    /// Construct the short-lived Standard-mode executor with durable local
    /// ownership recovery. Background/helper composition must use [`Self::new`].
    #[must_use]
    pub fn new_standard(
        settings: CanonicalTunnelSettings,
        profiles: impl Fn(&ProfileId) -> Option<Profile> + Send + Sync + 'static,
        ownership: Arc<crate::core::standard_tunnel_ownership::StandardTunnelOwnershipStore>,
        sessions: impl Fn(&ProfileId) -> Option<crate::core::scanner::ActiveSession>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        Self {
            settings,
            profiles: Arc::new(profiles),
            active: Mutex::new(BTreeMap::new()),
            standard_ownership: Some(ownership),
            sessions: Some(Arc::new(sessions)),
            owned_lifecycle_observer: None,
            remembered_openvpn_credentials: None,
            challenge_issuer: Mutex::new(None),
        }
    }

    /// Observe exact changes to the executor-owned live-tunnel ledger. The
    /// Standard-mode scanner uses this boundary to invalidate snapshots that
    /// began before a protocol-owned connect or teardown completed.
    #[must_use]
    pub(crate) fn with_owned_lifecycle_observer(
        mut self,
        observer: impl Fn(&ProfileId, bool) + Send + Sync + 'static,
    ) -> Self {
        self.owned_lifecycle_observer = Some(Arc::new(observer));
        self
    }

    fn notify_owned_lifecycle(&self, profile_id: &ProfileId, active: bool) {
        if let Some(observer) = &self.owned_lifecycle_observer {
            observer(profile_id, active);
        }
    }

    /// Return whether the session is the exact live handle owned by this
    /// executor process. This is stronger than a scanner-only classification:
    /// the handle enters this ledger only after protocol success and durable
    /// Standard-mode ownership have both completed.
    pub(crate) fn owns_live_session(
        &self,
        profile_id: &ProfileId,
        session: &crate::core::scanner::ActiveSession,
    ) -> Result<bool, String> {
        let active = self
            .active
            .lock()
            .map_err(|_| "canonical active-tunnel ledger poisoned".to_string())?;
        let Some((_, handle)) = active.get(profile_id) else {
            return Ok(false);
        };
        if handle.profile_id != *profile_id
            || !session.interface_authoritative
            || handle.interface_name != session.interface
        {
            return Ok(false);
        }
        Ok(match handle.kind {
            // On macOS WireGuard runs in userspace, so the scanner reports
            // the `wireguard-go` PID. The canonical ownership proof is this
            // executor's exact profile/interface-bound live handle; unlike
            // OpenVPN, `TunnelHandle::pid` is intentionally absent for
            // WireGuard and the scanner PID must not make the session look
            // external.
            TunnelKindTag::WireGuard => true,
            TunnelKindTag::OpenVpn => handle.pid.is_some() && handle.pid == session.pid,
            TunnelKindTag::Mock => false,
        })
    }

    /// Supply the session-owned live resolver for reusable `OpenVPN`
    /// credentials. The executor receives one memory-only value per attempt
    /// and never opens the remembered-credential store itself.
    #[must_use]
    pub fn with_remembered_openvpn_credentials(
        mut self,
        resolver: impl Fn(&ProfileId, &str) -> Result<Option<crate::vortix_core::control::Secret>, String>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.remembered_openvpn_credentials = Some(Arc::new(resolver));
        self
    }

    /// Install the service-owned challenge capability after the cyclic
    /// service/supervisor/executor graph has been constructed.
    pub fn install_challenge_issuer(
        &self,
        issuer: &Arc<crate::vortix_core::control::CompleterHandle>,
    ) -> Result<(), String> {
        let mut slot = self
            .challenge_issuer
            .lock()
            .map_err(|_| "challenge issuer slot poisoned".to_string())?;
        if slot.is_some() {
            return Err("challenge issuer was already installed".into());
        }
        *slot = Some(Arc::downgrade(issuer));
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one bounded secret handoff keeps challenge issuance, cancellation, and decoding adjacent"
    )]
    fn openvpn_interactive_credentials(
        &self,
        work: &crate::vortix_core::control::worker::TunnelWork,
        profile: &Profile,
        cancellation: &crate::vortix_core::control::worker::CancellationToken,
    ) -> Result<
        Option<crate::vortix_protocol_openvpn::tunnel::OpenVpnStaticChallengeCredentials>,
        String,
    > {
        if work.protocol != TunnelKindTag::OpenVpn {
            return Ok(None);
        }
        if !crate::utils::openvpn_config_needs_auth(&profile.config_path) {
            return Ok(None);
        }
        let static_prompt =
            crate::utils::read_openvpn_static_challenge_prompt(&profile.config_path);
        let saved_credentials = self
            .remembered_openvpn_credentials
            .as_ref()
            .map(|resolver| resolver(&profile.id, &profile.display_name))
            .transpose()?
            .flatten()
            .map(|secret| {
                secret.decode_openvpn_credentials().ok_or_else(|| {
                    "remembered OpenVPN credential authority returned an invalid value".to_string()
                })
            })
            .transpose()?;
        if static_prompt.is_none() {
            if let Some((username, password, answer)) = saved_credentials {
                return Ok(Some(
                    crate::vortix_protocol_openvpn::tunnel::OpenVpnStaticChallengeCredentials::new(
                        username.to_string(),
                        password.to_string(),
                        answer,
                    ),
                ));
            }
        }
        let challenge_capability = self
            .challenge_issuer
            .lock()
            .map_err(|_| "interactive challenge issuer slot poisoned".to_string())?
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .ok_or_else(|| {
                "interactive challenge is unavailable outside an admitted control operation"
                    .to_string()
            })?;
        let remaining = work
            .deadline
            .saturating_duration_since(std::time::Instant::now());
        let remaining_millis: u64 = remaining.as_millis().try_into().unwrap_or(u64::MAX);
        let expires_at = challenge_capability
            .now_millis()
            .saturating_add(remaining_millis);
        let challenge_kind = if static_prompt.is_some() {
            crate::vortix_core::control::ChallengeKind::TwoFactorCode
        } else {
            crate::vortix_core::control::ChallengeKind::Generic {
                label: "OpenVPN credentials".to_string(),
            }
        };
        let challenge_label = static_prompt
            .clone()
            .unwrap_or_else(|| "OpenVPN username and password".to_string());
        let issued_challenge = challenge_capability
            .issue_challenge_blocking(
                work.operation_id.clone(),
                work.profile_id.clone(),
                challenge_kind,
                challenge_label,
                expires_at,
            )
            .map_err(|error| format!("interactive challenge issuance failed: {error}"))?;
        loop {
            if cancellation.is_cancelled() {
                return Err("interactive challenge was cancelled".into());
            }
            if std::time::Instant::now() >= work.deadline {
                return Err("interactive challenge timed out".into());
            }
            match issued_challenge
                .response
                .receive_timeout(std::time::Duration::from_millis(50))
            {
                Ok(Some(answer)) => {
                    if let Some((username, password, challenge_answer)) =
                        answer.decode_openvpn_credentials()
                    {
                        return Ok(Some(
                            crate::vortix_protocol_openvpn::tunnel::OpenVpnStaticChallengeCredentials::new(
                                username.to_string(),
                                password.to_string(),
                                challenge_answer,
                            ),
                        ));
                    }
                    let Some((username, password, _)) = saved_credentials.as_ref() else {
                        return Err(
                            "interactive credential response did not contain username/password"
                                .to_string(),
                        );
                    };
                    if static_prompt.is_none() {
                        return Err(
                            "OpenVPN credential response used an unsupported legacy format"
                                .to_string(),
                        );
                    }
                    return Ok(Some(
                        crate::vortix_protocol_openvpn::tunnel::OpenVpnStaticChallengeCredentials::new(
                            username.to_string(),
                            password.to_string(),
                            answer,
                        ),
                    ));
                }
                Ok(None) => {}
                Err(_) => return Err("interactive challenge was cancelled or expired".into()),
            }
        }
    }

    /// Restore one persisted Standard-mode owner into both the executor and
    /// supervisor before the local service admits mutations. The caller
    /// supplies the durable control revision/operation; `WireGuard`'s private
    /// record must match both, while `OpenVPN`'s custodian capability supplies
    /// exact child ownership for that durable control intent.
    pub fn restore_standard_profile(
        &self,
        supervisor: &crate::vortix_core::control::supervisor::Supervisor,
        profile_id: &ProfileId,
        revision: crate::vortix_core::control::worker::TunnelRevision,
        operation_id: crate::vortix_core::control::OperationId,
    ) -> Result<bool, String> {
        let Some(resolve_session) = &self.sessions else {
            return Err("Standard-mode session resolver is unavailable".into());
        };
        let Some(session) = resolve_session(profile_id) else {
            return Ok(false);
        };
        let profile = (self.profiles)(profile_id)
            .ok_or_else(|| format!("profile {profile_id} no longer exists"))?;
        let protocol = match profile.protocol {
            ProtocolKind::WireGuard => TunnelKindTag::WireGuard,
            ProtocolKind::OpenVpn => TunnelKindTag::OpenVpn,
        };
        if protocol == TunnelKindTag::WireGuard {
            let store = self.standard_ownership.as_ref().ok_or_else(|| {
                "active WireGuard target has no Standard-mode ownership store".to_string()
            })?;
            let owned = store
                .validate_wireguard(&profile, &session)
                .map_err(|error| format!("active WireGuard ownership refused: {error}"))?;
            if owned.authority_epoch != revision.authority_epoch
                || owned.tunnel_generation != revision.generation
                || owned.operation_id != operation_id
            {
                return Err("WireGuard ownership does not match durable control intent".into());
            }
        }
        let recovery_work = crate::vortix_core::control::worker::TunnelWork {
            profile_id: profile_id.clone(),
            operation_id: operation_id.clone(),
            revision,
            resource_revision: revision,
            mutation: crate::vortix_core::control::worker::TunnelMutation::Connect,
            protocol,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(5),
        };
        let Some((tunnel, handle)) = self.recover_standard_handle(&recovery_work)? else {
            return Ok(false);
        };
        let receipt = Self::receipt_for(&recovery_work, &handle)?;
        supervisor
            .restore_owned_tunnel(
                receipt
                    .adoption
                    .ok_or_else(|| "recovered owner has no adoption evidence".to_string())?,
                receipt.handshake,
                receipt.probe_receipts,
                handle.process_ownership.as_ref(),
                revision,
                operation_id,
            )
            .map_err(|error| format!("supervisor refused recovered ownership: {error:?}"))?;
        self.active
            .lock()
            .map_err(|_| "canonical active-tunnel ledger poisoned".to_string())?
            .insert(profile_id.clone(), (tunnel, handle));
        Ok(true)
    }

    fn protocol_for(kind: TunnelKindTag) -> Result<Protocol, String> {
        match kind {
            TunnelKindTag::WireGuard => Ok(Protocol::WireGuard),
            TunnelKindTag::OpenVpn => Ok(Protocol::OpenVPN),
            TunnelKindTag::Mock => Err("mock protocol cannot execute in production".into()),
        }
    }

    fn execute_connect(
        &self,
        work: &crate::vortix_core::control::worker::TunnelWork,
        cancellation: &crate::vortix_core::control::worker::CancellationToken,
    ) -> Result<crate::vortix_core::control::worker::TunnelExecutionReceipt, String> {
        let profile = (self.profiles)(&work.profile_id)
            .ok_or_else(|| format!("profile {} no longer exists", work.profile_id))?;
        let protocol = Self::protocol_for(work.protocol)?;
        let expected_protocol = match profile.protocol {
            ProtocolKind::WireGuard => Protocol::WireGuard,
            ProtocolKind::OpenVpn => Protocol::OpenVPN,
        };
        if protocol != expected_protocol {
            return Err("canonical work protocol did not match profile".into());
        }
        let context = TunnelExecutionContext {
            cancellation: cancellation.clone(),
            deadline: work.deadline,
        };
        let interactive_credentials =
            self.openvpn_interactive_credentials(work, &profile, cancellation)?;
        let mut tunnel = tunnel_for_with_wireguard_policy(
            protocol,
            &self.settings.config_dir,
            &self.settings.openvpn_verbosity,
            self.settings.connect_timeout_secs,
            self.settings.wireguard_handshake_timeout_secs,
            &self.settings.wireguard_health_targets,
        )
        .for_generation(work.revision.generation)
        .for_operation(work.operation_id.clone())
        .with_execution_context(context);
        if let Some(credentials) = interactive_credentials {
            tunnel = tunnel.with_openvpn_static_challenge(credentials);
        }
        let mut handle = match panic::catch_unwind(AssertUnwindSafe(|| tunnel.up(&profile))) {
            Ok(result) => result.map_err(|error| error.to_string())?,
            Err(_) => {
                return Err(match tunnel.compensate_inflight() {
                    Ok(()) => "canonical tunnel executor panicked; exact attempt removed".into(),
                    Err(error) => format!(
                        "canonical tunnel executor panicked and ownership is ambiguous: {error}"
                    ),
                });
            }
        };
        if cancellation.is_cancelled() || std::time::Instant::now() >= work.deadline {
            let cleanup = tunnel.down(handle);
            return Err(match cleanup {
                Ok(()) => "canonical tunnel work was cancelled; owned attempt removed".into(),
                Err(error) => format!(
                    "canonical tunnel work was cancelled and ownership is ambiguous: {error}"
                ),
            });
        }
        let receipt = Self::receipt_for(work, &handle);
        let receipt = match receipt {
            Ok(receipt) => receipt,
            Err(error) => {
                let cleanup = tunnel.down(handle);
                return Err(match cleanup {
                    Ok(()) => error,
                    Err(cleanup) => format!(
                        "{error}; receipt failure cleanup left ownership ambiguous: {cleanup}"
                    ),
                });
            }
        };
        if let Err(error) = self.persist_standard_wireguard_ownership(work, &mut handle) {
            let cleanup = tunnel.down(handle);
            if cleanup.is_ok() {
                self.remove_standard_wireguard_ownership(&work.profile_id);
            }
            return Err(match cleanup {
                Ok(()) => format!("{error}; owned attempt removed"),
                Err(cleanup) => format!("{error}; ownership is ambiguous: {cleanup}"),
            });
        }
        self.active
            .lock()
            .map_err(|_| "canonical active-tunnel ledger poisoned".to_string())?
            .insert(work.profile_id.clone(), (tunnel, handle));
        self.notify_owned_lifecycle(&work.profile_id, true);
        Ok(receipt)
    }

    fn receipt_for(
        work: &crate::vortix_core::control::worker::TunnelWork,
        handle: &TunnelHandle,
    ) -> Result<crate::vortix_core::control::worker::TunnelExecutionReceipt, String> {
        use crate::vortix_core::control::worker::TunnelExecutionReceipt;
        if work.protocol != TunnelKindTag::WireGuard {
            let receipt = TunnelExecutionReceipt::attested(
                work.profile_id.clone(),
                handle.interface_name.clone(),
                work.protocol,
                handle.pid,
                format!("openvpn-generation:{}", work.revision.generation),
            )
            .map(|receipt| receipt.with_openvpn_dns(handle.dns_request.clone()))?;
            return Ok(match handle.openvpn_routes.clone() {
                Some(routes) => receipt.with_openvpn_routes(routes),
                None => receipt,
            });
        }
        let handshake = handle
            .handshake
            .clone()
            .filter(|evidence| evidence.generation == work.revision.generation)
            .ok_or_else(|| {
                "WireGuard returned without exact current-generation handshake evidence".to_string()
            })?;
        TunnelExecutionReceipt::wireguard(
            work.profile_id.clone(),
            handle.interface_name.clone(),
            format!(
                "wg-generation:{}:peer:{}",
                work.revision.generation, handshake.peer_public_key
            ),
            handshake,
        )
        .map(|receipt| receipt.with_probe_receipts(handle.probe_receipts.clone()))
    }

    fn execute_disconnect(
        &self,
        work: &crate::vortix_core::control::worker::TunnelWork,
    ) -> Result<crate::vortix_core::control::worker::TunnelExecutionReceipt, String> {
        use crate::vortix_core::control::worker::TunnelExecutionReceipt;
        let owned = self
            .active
            .lock()
            .map_err(|_| "canonical active-tunnel ledger poisoned".to_string())?
            .remove(&work.profile_id);
        let (mut tunnel, handle) = if let Some(owned) = owned {
            owned
        } else {
            let Some(recovered) = self.recover_standard_handle(work)? else {
                if let Some(store) = &self.standard_ownership {
                    store
                        .remove_after_confirmed_absence(&work.profile_id, &[])
                        .map_err(|error| error.to_string())?;
                    crate::core::managed_wireguard::remove_after_confirmed_absence(
                        &self.settings.config_dir,
                        &work.profile_id,
                    )
                    .map_err(|error| error.to_string())?;
                }
                self.notify_owned_lifecycle(&work.profile_id, false);
                return Ok(TunnelExecutionReceipt::default());
            };
            recovered
        };
        match tunnel.down(handle.clone()) {
            Ok(()) => {
                if handle.kind == TunnelKindTag::WireGuard {
                    if let Some(store) = &self.standard_ownership {
                        // `WgTunnel::down` returns success only after its own
                        // exact interface-absence probe. A cached scanner
                        // snapshot may still contain the just-removed
                        // interface, so it cannot veto ownership cleanup.
                        store
                            .remove_after_confirmed_absence(&work.profile_id, &[])
                            .map_err(|error| error.to_string())?;
                        crate::core::managed_wireguard::remove_after_confirmed_absence(
                            &self.settings.config_dir,
                            &work.profile_id,
                        )
                        .map_err(|error| error.to_string())?;
                    }
                }
                self.notify_owned_lifecycle(&work.profile_id, false);
                Ok(TunnelExecutionReceipt::default())
            }
            Err(error) => {
                self.active
                    .lock()
                    .map_err(|_| "canonical active-tunnel ledger poisoned".to_string())?
                    .insert(work.profile_id.clone(), (tunnel, handle));
                Err(error.to_string())
            }
        }
    }

    fn persist_standard_wireguard_ownership(
        &self,
        work: &crate::vortix_core::control::worker::TunnelWork,
        handle: &mut TunnelHandle,
    ) -> Result<(), String> {
        if work.protocol != TunnelKindTag::WireGuard {
            return Ok(());
        }
        let Some(store) = &self.standard_ownership else {
            return Ok(());
        };
        let profile = (self.profiles)(&work.profile_id)
            .ok_or_else(|| format!("profile {} no longer exists", work.profile_id))?;
        let handshake = handle.handshake.clone().ok_or_else(|| {
            "WireGuard connected without exact handshake ownership evidence".to_string()
        })?;
        let teardown_config = handle.teardown_config.as_ref().ok_or_else(|| {
            "WireGuard connected without an exact managed teardown config".to_string()
        })?;
        let original_teardown_path = teardown_config.path.clone();
        let ownership = store
            .issue_wireguard(
                &profile,
                work.revision,
                work.operation_id.clone(),
                &handle.interface_name,
                teardown_config,
                handshake.clone(),
                handle.probe_receipts.clone(),
            )
            .map_err(|error| {
                format!("WireGuard ownership capability could not be persisted: {error}")
            })?;
        handle.teardown_config = Some(ownership.teardown_config);
        if original_teardown_path
            != handle
                .teardown_config
                .as_ref()
                .expect("installed teardown config")
                .path
        {
            let _ = std::fs::remove_file(original_teardown_path);
        }
        crate::core::managed_wireguard::issue(
            &self.settings.config_dir,
            &work.profile_id,
            handle.interface_name.clone(),
            work.revision.generation,
            handshake,
            handle.probe_receipts.clone(),
        )
        .map(|_| ())
        .map_err(|error| format!("WireGuard display receipt could not be persisted: {error}"))
    }

    fn remove_standard_wireguard_ownership(&self, profile_id: &ProfileId) {
        if let Some(store) = &self.standard_ownership {
            let _ = store.remove_after_confirmed_absence(profile_id, &[]);
            let _ = crate::core::managed_wireguard::remove_after_confirmed_absence(
                &self.settings.config_dir,
                profile_id,
            );
        }
    }

    fn recover_standard_handle(
        &self,
        work: &crate::vortix_core::control::worker::TunnelWork,
    ) -> Result<Option<(TunnelKind, TunnelHandle)>, String> {
        let Some(resolve_session) = &self.sessions else {
            return Err("canonical disconnect has no active ownership ledger".into());
        };
        let Some(session) = resolve_session(&work.profile_id) else {
            // A fresh protocol observation proved the requested target absent.
            return Ok(None);
        };
        let profile = (self.profiles)(&work.profile_id)
            .ok_or_else(|| format!("profile {} no longer exists", work.profile_id))?;
        let protocol = Self::protocol_for(work.protocol)?;
        let profile_protocol = match profile.protocol {
            ProtocolKind::WireGuard => Protocol::WireGuard,
            ProtocolKind::OpenVpn => Protocol::OpenVPN,
        };
        if protocol != profile_protocol {
            return Err("canonical work protocol did not match recovered profile".into());
        }
        match protocol {
            Protocol::WireGuard => {
                let store = self.standard_ownership.as_ref().ok_or_else(|| {
                    "active WireGuard target has no Standard-mode ownership store".to_string()
                })?;
                let owned = store
                    .validate_wireguard(&profile, &session)
                    .map_err(|error| format!("active WireGuard ownership refused: {error}"))?;
                let handle = TunnelHandle {
                    profile_id: work.profile_id.clone(),
                    display_name: profile.display_name.clone(),
                    interface_name: owned.interface_name,
                    pid: None,
                    started_at: std::time::SystemTime::now(),
                    kind: TunnelKindTag::WireGuard,
                    generation: owned.tunnel_generation,
                    handshake: Some(owned.handshake),
                    probe_receipts: owned.probe_receipts,
                    process_ownership: None,
                    teardown_config: Some(owned.teardown_config),
                    dns_request: crate::vortix_core::ports::dns::DnsRequest::default(),
                    openvpn_routes: None,
                };
                Ok(Some((
                    tunnel_for(
                        protocol,
                        &self.settings.config_dir,
                        &self.settings.openvpn_verbosity,
                        self.settings.connect_timeout_secs,
                    ),
                    handle,
                )))
            }
            Protocol::OpenVPN => self
                .recover_standard_openvpn_handle(work, profile, session)
                .map(Some),
        }
    }

    fn recover_standard_openvpn_handle(
        &self,
        work: &crate::vortix_core::control::worker::TunnelWork,
        profile: Profile,
        session: crate::core::scanner::ActiveSession,
    ) -> Result<(TunnelKind, TunnelHandle), String> {
        if !session.interface_authoritative {
            return Err("active OpenVPN target has no authoritative interface observation".into());
        }
        let owner = standard_openvpn_owner(&work.profile_id, &session)?.ok_or_else(|| {
            "active OpenVPN target has no live PID-matched custodian receipt".to_string()
        })?;
        let protocol_pid = owner.protocol_pid;
        let custody = owner.custody;
        if custody.identity.generation != work.revision.generation {
            return Err(
                "OpenVPN custodian generation does not match durable control intent".into(),
            );
        }
        if custody
            .operation_id
            .as_ref()
            .is_some_and(|operation| operation != &work.operation_id)
        {
            return Err("OpenVPN custodian operation does not match durable control intent".into());
        }
        let tunnel = tunnel_for(
            Protocol::OpenVPN,
            &self.settings.config_dir,
            &self.settings.openvpn_verbosity,
            self.settings.connect_timeout_secs,
        );
        let runtime_evidence = match &tunnel {
            TunnelKind::OpenVpn(openvpn) => openvpn
                .requested_runtime_evidence(&profile)
                .map_err(|error| error.to_string())?,
            _ => return Err("OpenVPN recovery constructed the wrong protocol adapter".into()),
        };
        let dns_request = match runtime_evidence.dns {
            crate::vortix_protocol_openvpn::OvpnDnsEvidence::Observed(request)
            | crate::vortix_protocol_openvpn::OvpnDnsEvidence::ExplicitlyEmpty(request) => request,
            crate::vortix_protocol_openvpn::OvpnDnsEvidence::Unavailable { reason, .. } => {
                return Err(format!(
                    "recovered OpenVPN DNS negotiation evidence is unavailable: {reason}"
                ));
            }
        };
        let handle = TunnelHandle {
            profile_id: work.profile_id.clone(),
            display_name: profile.display_name,
            interface_name: session.interface,
            pid: Some(protocol_pid),
            started_at: std::time::SystemTime::now(),
            kind: TunnelKindTag::OpenVpn,
            generation: custody.identity.generation,
            handshake: None,
            probe_receipts: Vec::new(),
            process_ownership: Some(custody.identity),
            teardown_config: None,
            dns_request,
            openvpn_routes: Some(runtime_evidence.routes),
        };
        Ok((tunnel, handle))
    }
}

impl crate::vortix_core::control::worker::TunnelExecutor for CanonicalTunnelExecutor {
    fn execute(
        &self,
        work: &crate::vortix_core::control::worker::TunnelWork,
        cancellation: &crate::vortix_core::control::worker::CancellationToken,
    ) -> Result<crate::vortix_core::control::worker::TunnelExecutionReceipt, String> {
        use crate::vortix_core::control::worker::TunnelMutation;
        if cancellation.is_cancelled() || std::time::Instant::now() >= work.deadline {
            return Err("canonical tunnel work was cancelled or expired".into());
        }
        match work.mutation {
            TunnelMutation::Connect => self.execute_connect(work, cancellation),
            TunnelMutation::Disconnect => self.execute_disconnect(work),
        }
    }

    fn classify_failure(&self, error: &str) -> crate::vortix_core::control::worker::WorkFailure {
        use crate::vortix_core::control::worker::WorkFailure;
        if error.contains("ownership is ambiguous")
            || error.contains("outcome is ambiguous")
            || error.contains("ambiguous-owned")
        {
            WorkFailure::OutcomeUnknown
        } else if error.starts_with("authentication failed:") {
            WorkFailure::AuthenticationFailed
        } else if error.contains("interactive challenge") {
            WorkFailure::ChallengeFailed
        } else if error.contains("panicked") {
            WorkFailure::Panicked
        } else if error.contains("cancelled") {
            WorkFailure::Cancelled
        } else if error.contains("handshake") || error.contains("Handshake") {
            // A bounded health probe can report a transport timeout while the
            // semantic failure is still an exact WireGuard handshake gate.
            // This check must precede the generic operation-timeout fallback.
            WorkFailure::HandshakeFailed
        } else if error.contains("WireGuard name must be")
            || error.contains("WireGuard config has no valid name")
        {
            WorkFailure::InvalidProfile
        } else if error.contains("expired") || error.contains("timed out") {
            WorkFailure::TimedOut
        } else {
            WorkFailure::EffectFailed
        }
    }

    fn compensate_unaccepted_success(
        &self,
        work: &crate::vortix_core::control::worker::TunnelWork,
    ) -> Result<(), String> {
        if work.mutation != crate::vortix_core::control::worker::TunnelMutation::Connect {
            return Ok(());
        }
        let owned = self
            .active
            .lock()
            .map_err(|_| "canonical active-tunnel ledger poisoned".to_string())?
            .remove(&work.profile_id);
        let Some((mut tunnel, handle)) = owned else {
            return Ok(());
        };
        if handle.generation != work.revision.generation {
            self.active
                .lock()
                .map_err(|_| "canonical active-tunnel ledger poisoned".to_string())?
                .insert(work.profile_id.clone(), (tunnel, handle));
            return Err("late completion did not own the active generation".into());
        }
        tunnel.down(handle).map_err(|error| error.to_string())?;
        self.notify_owned_lifecycle(&work.profile_id, false);
        Ok(())
    }

    fn compensate_uncertain(
        &self,
        work: &crate::vortix_core::control::worker::TunnelWork,
    ) -> Result<(), String> {
        self.compensate_unaccepted_success(work)
    }
}

// Implement the `Tunnel` trait by delegating to the inherent methods.
// Plan 005's `Engine<T: Tunnel>` requires this so the binary can construct
// `Engine<TunnelKind>` and drive the FSM with the existing dispatch.
impl crate::vortix_core::ports::tunnel::Tunnel for TunnelKind {
    fn up(&mut self, profile: &Profile) -> Result<TunnelHandle, TunnelError> {
        TunnelKind::up(self, profile)
    }
    fn down(&mut self, handle: TunnelHandle) -> Result<(), TunnelError> {
        TunnelKind::down(self, handle)
    }
    fn status(&self, handle: &TunnelHandle) -> Result<TunnelStatus, TunnelError> {
        TunnelKind::status(self, handle)
    }
    fn parse_profile(&self, raw: &[u8]) -> Result<Box<dyn ParsedProfile>, ParseError> {
        TunnelKind::parse_profile(self, raw)
    }
    fn capabilities(&self) -> TunnelCapabilities {
        TunnelKind::capabilities(self)
    }
    fn kind_tag(&self) -> TunnelKindTag {
        TunnelKind::kind_tag(self)
    }
}

/// THE single routing function: protocol → `TunnelKind`.
///
/// Engine and CLI call this once per connect/disconnect and never branch on
/// protocol again. Adding a third protocol means adding one variant here.
#[must_use]
pub fn tunnel_for(
    protocol: Protocol,
    config_dir: &Path,
    ovpn_verbosity: &str,
    connect_timeout_secs: u64,
) -> TunnelKind {
    match protocol {
        Protocol::WireGuard => TunnelKind::WireGuard(WgTunnel::new()),
        Protocol::OpenVPN => TunnelKind::OpenVpn(
            OvpnTunnel::new(config_dir.join(crate::constants::OPENVPN_RUN_DIR))
                .with_auth_dir(config_dir.join(crate::constants::OPENVPN_AUTH_DIR))
                .with_verbosity(ovpn_verbosity)
                .with_connect_timeout(connect_timeout_secs),
        ),
    }
}

/// Construct a tunnel with the configured `WireGuard` handshake gate.
#[must_use]
pub fn tunnel_for_with_wireguard_policy(
    protocol: Protocol,
    config_dir: &Path,
    ovpn_verbosity: &str,
    connect_timeout_secs: u64,
    wireguard_handshake_timeout_secs: u64,
    wireguard_health_targets: &[String],
) -> TunnelKind {
    match protocol {
        Protocol::WireGuard => TunnelKind::WireGuard(
            WgTunnel::new().with_handshake_policy(
                std::time::Duration::from_secs(wireguard_handshake_timeout_secs),
                wireguard_health_targets
                    .iter()
                    .filter_map(|target| target.parse().ok()),
            ),
        ),
        Protocol::OpenVPN => tunnel_for(protocol, config_dir, ovpn_verbosity, connect_timeout_secs),
    }
}

/// Build a `vortix-core` [`Profile`] view from the binary-side `VpnProfile`.
///
/// Plan 007 reconciles the two profile types; until then the engine
/// translates at the trait boundary.
#[must_use]
pub fn profile_view(p: &VpnProfile) -> Profile {
    Profile::new(
        p.id.clone(),
        &p.name,
        match p.protocol {
            Protocol::WireGuard => ProtocolKind::WireGuard,
            Protocol::OpenVPN => ProtocolKind::OpenVpn,
        },
        p.config_path.clone(),
    )
}

#[cfg(test)]
mod canonical_tests {
    use super::*;
    use crate::vortix_core::control::model::{AuthorityEpoch, OperationId};
    use crate::vortix_core::control::worker::{TunnelMutation, TunnelRevision, TunnelWork};
    use crate::vortix_core::ports::dns::DnsRequest;
    use crate::vortix_core::ports::tunnel::mock::MockTunnel;
    use crate::vortix_core::ports::tunnel::{HandshakeEvidence, TunnelTeardownConfig};
    use std::time::{Duration, Instant, SystemTime};

    struct NoopPolicy;
    impl crate::vortix_core::control::worker::PolicyExecutor for NoopPolicy {
        fn apply(
            &self,
            _: &crate::vortix_core::control::worker::TopologyPolicy,
            _: crate::vortix_core::control::worker::PolicyBarrier,
        ) -> Result<(), String> {
            Ok(())
        }

        fn compensate(
            &self,
            _: &crate::vortix_core::control::worker::TopologyPolicy,
            _: crate::vortix_core::control::worker::PolicyBarrier,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    fn work(generation: u64) -> TunnelWork {
        TunnelWork {
            profile_id: ProfileId::new("corp"),
            operation_id: serde_json::from_str::<OperationId>(
                "\"op-0000000000000001-0000000000000001\"",
            )
            .unwrap(),
            revision: TunnelRevision {
                authority_epoch: AuthorityEpoch(1),
                generation,
            },
            resource_revision: TunnelRevision {
                authority_epoch: AuthorityEpoch(1),
                generation,
            },
            mutation: TunnelMutation::Connect,
            protocol: TunnelKindTag::WireGuard,
            deadline: Instant::now() + Duration::from_secs(1),
        }
    }

    fn handle(generation: u64) -> TunnelHandle {
        TunnelHandle {
            profile_id: ProfileId::new("corp"),
            display_name: "corp".into(),
            interface_name: "wg0".into(),
            pid: None,
            started_at: SystemTime::now(),
            kind: TunnelKindTag::WireGuard,
            generation,
            handshake: Some(HandshakeEvidence {
                generation,
                peer_public_key: "peer".into(),
                handshake_at: SystemTime::now(),
                observed_at: SystemTime::now(),
                allowed_routes: vec!["10.0.0.0/24".into()],
            }),
            probe_receipts: Vec::new(),
            process_ownership: None,
            teardown_config: None::<TunnelTeardownConfig>,
            dns_request: DnsRequest::default(),
            openvpn_routes: None,
        }
    }

    #[test]
    fn canonical_wireguard_receipt_requires_exact_generation() {
        let exact = CanonicalTunnelExecutor::receipt_for(&work(7), &handle(7)).unwrap();
        assert_eq!(exact.handshake.unwrap().generation, 7);
        assert!(CanonicalTunnelExecutor::receipt_for(&work(8), &handle(7)).is_err());
    }

    #[test]
    fn canonical_executor_owns_kernel_and_userspace_wireguard_sessions() {
        let executor = CanonicalTunnelExecutor::new(
            CanonicalTunnelSettings {
                config_dir: std::env::temp_dir(),
                openvpn_verbosity: "3".into(),
                connect_timeout_secs: 1,
                wireguard_handshake_timeout_secs: 1,
                wireguard_health_targets: Vec::new(),
            },
            |_| None,
        );
        let profile_id = ProfileId::new("corp");
        let live_handle = handle(7);
        executor.active.lock().unwrap().insert(
            profile_id.clone(),
            (TunnelKind::Mock(MockTunnel::new()), live_handle),
        );
        let kernel_session = crate::core::scanner::ActiveSession {
            name: "corp".into(),
            interface: "wg0".into(),
            interface_authoritative: true,
            wireguard_peers: Vec::new(),
            ..crate::core::scanner::ActiveSession::default()
        };

        assert!(executor
            .owns_live_session(&profile_id, &kernel_session)
            .unwrap());

        // macOS userspace WireGuard is represented by a live
        // `wireguard-go` process. Its PID is scanner metadata, not a
        // contradiction of this executor's in-memory ownership.
        let userspace_session = crate::core::scanner::ActiveSession {
            pid: Some(12_345),
            ..kernel_session
        };
        assert!(executor
            .owns_live_session(&profile_id, &userspace_session)
            .unwrap());
    }

    #[test]
    fn canonical_openvpn_receipt_retains_negotiated_runtime_evidence() {
        let mut work = work(7);
        work.protocol = TunnelKindTag::OpenVpn;
        let mut handle = handle(7);
        handle.kind = TunnelKindTag::OpenVpn;
        handle.handshake = None;
        handle.pid = Some(123);
        handle.dns_request = DnsRequest {
            servers: vec!["1.1.1.1".parse().unwrap()],
            ..DnsRequest::default()
        };
        handle.openvpn_routes = Some(
            crate::vortix_protocol_openvpn::push::openvpn_route_evidence(
                &crate::vortix_protocol_openvpn::parser::parse_ovpn_conf("client\n").unwrap(),
                "PUSH_REPLY,redirect-gateway def1\nInitialization Sequence Completed\n",
                false,
            )
            .unwrap(),
        );

        let receipt = CanonicalTunnelExecutor::receipt_for(&work, &handle).unwrap();

        assert_eq!(receipt.openvpn_dns, Some(handle.dns_request));
        assert_eq!(receipt.openvpn_routes, handle.openvpn_routes);
    }

    #[test]
    fn canonical_openvpn_resolves_remembered_credentials_through_injected_authority() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("corp.ovpn");
        std::fs::write(&config_path, "client\nauth-user-pass\n").unwrap();
        let profile = Profile::new(
            ProfileId::new("corp"),
            "renamed corp",
            ProtocolKind::OpenVpn,
            config_path,
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&calls);
        let executor = CanonicalTunnelExecutor::new(
            CanonicalTunnelSettings {
                config_dir: temp.path().to_path_buf(),
                openvpn_verbosity: "3".into(),
                connect_timeout_secs: 1,
                wireguard_handshake_timeout_secs: 1,
                wireguard_health_targets: Vec::new(),
            },
            |_| None,
        )
        .with_remembered_openvpn_credentials(move |profile_id, legacy_display_name| {
            resolver_calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(profile_id, &ProfileId::new("corp"));
            assert_eq!(legacy_display_name, "renamed corp");
            Ok(Some(
                crate::vortix_core::control::Secret::openvpn_credentials(
                    "alice",
                    "correct horse",
                    None,
                ),
            ))
        });
        let mut connect = work(7);
        connect.protocol = TunnelKindTag::OpenVpn;

        let credentials = executor
            .openvpn_interactive_credentials(
                &connect,
                &profile,
                &crate::vortix_core::control::worker::CancellationToken::default(),
            )
            .unwrap();

        let credentials = credentials.expect("remembered credentials should be resolved");
        assert_eq!(
            credentials.username_password_for_test(),
            ("alice", "correct horse")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn successful_wireguard_down_does_not_trust_a_stale_scanner_snapshot() {
        use crate::core::standard_tunnel_ownership::StandardTunnelOwnershipStore;
        use crate::vortix_core::ports::tunnel::mock::MockTunnel;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let temp = tempfile::tempdir().unwrap();
        let uid = crate::utils::effective_user_group_ids().0;
        let store = Arc::new(
            StandardTunnelOwnershipStore::new(temp.path().join("runtime"), uid, uid, "boot-a")
                .unwrap(),
        );
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&resolver_calls);
        let lifecycle_changes = Arc::new(Mutex::new(Vec::new()));
        let recorded_changes = Arc::clone(&lifecycle_changes);
        let executor = CanonicalTunnelExecutor::new_standard(
            CanonicalTunnelSettings {
                config_dir: temp.path().to_path_buf(),
                openvpn_verbosity: "3".into(),
                connect_timeout_secs: 1,
                wireguard_handshake_timeout_secs: 1,
                wireguard_health_targets: Vec::new(),
            },
            |_| None,
            store,
            move |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Some(crate::core::scanner::ActiveSession {
                    name: "corp".into(),
                    interface: "wg0".into(),
                    interface_authoritative: true,
                    ..crate::core::scanner::ActiveSession::default()
                })
            },
        )
        .with_owned_lifecycle_observer(move |profile_id, active| {
            recorded_changes
                .lock()
                .unwrap()
                .push((profile_id.clone(), active));
        });
        executor.active.lock().unwrap().insert(
            ProfileId::new("corp"),
            (TunnelKind::Mock(MockTunnel::new()), handle(7)),
        );
        let mut disconnect = work(7);
        disconnect.mutation = TunnelMutation::Disconnect;

        executor.execute_disconnect(&disconnect).unwrap();

        assert_eq!(
            resolver_calls.load(Ordering::SeqCst),
            0,
            "a successful protocol-owned teardown is exact absence evidence"
        );
        assert_eq!(
            *lifecycle_changes.lock().unwrap(),
            vec![(ProfileId::new("corp"), false)],
            "the exact teardown must invalidate scanner state before policy verification"
        );
    }

    #[test]
    fn service_challenge_failure_has_a_distinct_supervisor_outcome() {
        use crate::vortix_core::control::worker::{TunnelExecutor as _, WorkFailure};

        let executor = CanonicalTunnelExecutor::new(
            CanonicalTunnelSettings {
                config_dir: PathBuf::new(),
                openvpn_verbosity: "3".into(),
                connect_timeout_secs: 1,
                wireguard_handshake_timeout_secs: 1,
                wireguard_health_targets: Vec::new(),
            },
            |_| None,
        );
        assert_eq!(
            executor.classify_failure("interactive challenge was cancelled or expired"),
            WorkFailure::ChallengeFailed
        );
        assert_eq!(
            executor
                .classify_failure("OpenVPN startup teardown is ambiguous-owned for generation 7"),
            WorkFailure::OutcomeUnknown
        );
        assert_eq!(
            executor.classify_failure("authentication failed: AUTH_FAILED"),
            WorkFailure::AuthenticationFailed
        );
    }

    #[test]
    fn wireguard_handshake_context_outranks_generic_probe_timeout_wording() {
        use crate::vortix_core::control::worker::{TunnelExecutor as _, WorkFailure};

        let executor = CanonicalTunnelExecutor::new(
            CanonicalTunnelSettings {
                config_dir: PathBuf::new(),
                openvpn_verbosity: "3".into(),
                connect_timeout_secs: 1,
                wireguard_handshake_timeout_secs: 1,
                wireguard_health_targets: Vec::new(),
            },
            |_| None,
        );

        assert_eq!(
            executor.classify_failure(
                "WireGuard handshake probe failed: ping timed out before peer response"
            ),
            WorkFailure::HandshakeFailed
        );
        assert_eq!(
            executor.classify_failure("canonical tunnel operation timed out"),
            WorkFailure::TimedOut
        );
        assert_eq!(
            executor.classify_failure("subprocess failure: WireGuard name must be 1–15 characters"),
            WorkFailure::InvalidProfile
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the cross-process fixture keeps the private record, typed scan, restore, and assertions together"
    )]
    fn standard_executor_recovers_exact_wireguard_handle_across_processes() {
        use crate::core::scanner::ActiveSession;
        use crate::core::standard_tunnel_ownership::StandardTunnelOwnershipStore;
        use crate::vortix_core::ports::tunnel::TunnelPeerStatus;

        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("wg0.conf");
        std::fs::write(&config, "[Interface]\nPrivateKey = redacted\n").unwrap();
        let lifecycle = temp.path().join("lifecycle");
        std::fs::create_dir(&lifecycle).unwrap();
        let managed_config = lifecycle.join("wg0.conf");
        std::fs::write(
            &managed_config,
            "[Interface]\nPrivateKey = lifecycle-copy\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&managed_config, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let profile = Profile::new(
            ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap(),
            "corp",
            ProtocolKind::WireGuard,
            config,
        );
        let profile_id = profile.id.clone();
        let evidence = HandshakeEvidence {
            generation: 7,
            peer_public_key: "peer".into(),
            handshake_at: SystemTime::now(),
            observed_at: SystemTime::now(),
            allowed_routes: vec!["10.0.0.0/24".into()],
        };
        let uid = crate::utils::effective_user_group_ids().0;
        let store = Arc::new(
            StandardTunnelOwnershipStore::new(temp.path().join("runtime"), uid, 0, "boot-a")
                .unwrap(),
        );
        store
            .issue_wireguard(
                &profile,
                TunnelRevision {
                    authority_epoch: AuthorityEpoch(1),
                    generation: 7,
                },
                work(7).operation_id,
                "wg0",
                &TunnelTeardownConfig {
                    path: managed_config,
                    managed: true,
                    wg_quick_interface: Some("wg0".into()),
                },
                evidence.clone(),
                Vec::new(),
            )
            .unwrap();
        let session = ActiveSession {
            name: "corp".into(),
            interface: "wg0".into(),
            interface_authoritative: true,
            wireguard_peers: vec![TunnelPeerStatus {
                public_key: "peer".into(),
                endpoint: None,
                allowed_routes: vec!["10.0.0.0/24".into()],
                latest_handshake: Some(evidence.handshake_at),
                evidence_observed_at: SystemTime::now(),
                evidence_generation: 7,
                persistent_keepalive: None,
                bytes_rx: 0,
                bytes_tx: 0,
            }],
            ..ActiveSession::default()
        };
        let profile_for_resolver = profile.clone();
        let session_for_resolver = session.clone();
        let executor = Arc::new(CanonicalTunnelExecutor::new_standard(
            CanonicalTunnelSettings {
                config_dir: temp.path().to_path_buf(),
                openvpn_verbosity: "3".into(),
                connect_timeout_secs: 1,
                wireguard_handshake_timeout_secs: 1,
                wireguard_health_targets: Vec::new(),
            },
            move |id| (id == &profile_for_resolver.id).then(|| profile_for_resolver.clone()),
            store,
            move |id| (id == &profile.id).then(|| session_for_resolver.clone()),
        ));
        let mut disconnect = work(7);
        disconnect.profile_id = profile_id;
        disconnect.mutation = TunnelMutation::Disconnect;
        let supervisor = crate::vortix_core::control::supervisor::Supervisor::new(
            AuthorityEpoch(1),
            executor.clone(),
            Arc::new(NoopPolicy),
            1,
            4,
        );
        let wrong_operation =
            serde_json::from_str::<OperationId>("\"op-0000000000000001-0000000000000002\"")
                .unwrap();
        assert!(executor
            .restore_standard_profile(
                &supervisor,
                &disconnect.profile_id,
                disconnect.revision,
                wrong_operation,
            )
            .is_err());
        assert!(executor
            .restore_standard_profile(
                &supervisor,
                &disconnect.profile_id,
                disconnect.revision,
                disconnect.operation_id.clone(),
            )
            .unwrap());
        let recovered = executor
            .active
            .lock()
            .unwrap()
            .get(&disconnect.profile_id)
            .unwrap()
            .1
            .clone();
        assert_eq!(recovered.profile_id, disconnect.profile_id);
        assert_eq!(recovered.interface_name, "wg0");
        assert_eq!(recovered.generation, 7);
        assert_eq!(recovered.handshake.unwrap().generation, 7);
        let recovered_teardown = recovered.teardown_config.unwrap();
        assert!(recovered_teardown.managed);
        assert_eq!(
            std::fs::read_to_string(recovered_teardown.path).unwrap(),
            "[Interface]\nPrivateKey = lifecycle-copy\n"
        );
    }

    #[test]
    fn standard_executor_refuses_active_wireguard_without_private_ownership() {
        use crate::core::scanner::ActiveSession;
        use crate::core::standard_tunnel_ownership::StandardTunnelOwnershipStore;

        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("corp.conf");
        std::fs::write(&config, "[Interface]\nPrivateKey = redacted\n").unwrap();
        let profile = Profile::new(
            ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap(),
            "corp",
            ProtocolKind::WireGuard,
            config,
        );
        let profile_id = profile.id.clone();
        let uid = crate::utils::effective_user_group_ids().0;
        let store = Arc::new(
            StandardTunnelOwnershipStore::new(temp.path().join("runtime"), uid, 0, "boot-a")
                .unwrap(),
        );
        let profile_for_session = profile.clone();
        let profile_for_resolver = profile.clone();
        let executor = CanonicalTunnelExecutor::new_standard(
            CanonicalTunnelSettings {
                config_dir: temp.path().to_path_buf(),
                openvpn_verbosity: "3".into(),
                connect_timeout_secs: 1,
                wireguard_handshake_timeout_secs: 1,
                wireguard_health_targets: Vec::new(),
            },
            move |id| (id == &profile_for_resolver.id).then(|| profile_for_resolver.clone()),
            store,
            move |id| {
                (id == &profile_for_session.id).then(|| ActiveSession {
                    name: "corp".into(),
                    interface: "wg0".into(),
                    interface_authoritative: true,
                    ..ActiveSession::default()
                })
            },
        );
        let mut disconnect = work(7);
        disconnect.profile_id = profile_id;
        disconnect.mutation = TunnelMutation::Disconnect;
        assert!(executor.recover_standard_handle(&disconnect).is_err());
    }
}
