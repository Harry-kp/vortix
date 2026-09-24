//! Start, stop and adopt protocol processes. No routing or DNS here: the
//! protocols run with their own route and DNS changes suppressed and report
//! what the server asked for; the planner decides what the host gets.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::cidr::Cidr;
use crate::control::dns::DnsRequest;
use crate::control::scanner::ActiveSession;
use crate::openvpn::routes::OpenVpnRouteEvidence;
use crate::openvpn::tunnel::OpenVpnStaticChallengeCredentials;
use crate::profile::{Profile, ProfileId, ProtocolKind};
use crate::tunnel::TunnelRevision;
use crate::tunnel::{AuthorityEpoch, OperationId};
use crate::tunnel::{TunnelCancellation, TunnelExecutionContext, TunnelHandle, TunnelKindTag};
use crate::wireguard::ownership::StandardTunnelOwnershipStore;

use crate::openvpn::OvpnTunnel;
use crate::tunnel::{TunnelError, TunnelStatus};
use crate::wireguard::WgTunnel;

const EPOCH: AuthorityEpoch = AuthorityEpoch(1);

#[derive(Debug, Clone)]
pub struct Settings {
    pub config_dir: PathBuf,
    pub openvpn_verbosity: String,
    pub connect_timeout_secs: u64,
    pub wireguard_handshake_timeout_secs: u64,
    pub wireguard_health_targets: Vec<String>,
}

/// A running protocol process and what it negotiated.
pub struct Live {
    pub kind: TunnelKind,
    pub handle: TunnelHandle,
}

impl Live {
    /// Routes the server pushed on top of the profile's own.
    #[must_use]
    pub fn pushed_routes(&self) -> BTreeSet<Cidr> {
        self.handle
            .openvpn_routes
            .as_ref()
            .map(route_claims)
            .unwrap_or_default()
    }

    #[must_use]
    pub fn pushed_servers(&self) -> Option<IpAddr> {
        self.handle
            .openvpn_routes
            .as_ref()
            .and_then(OpenVpnRouteEvidence::selected_remote)
    }

    /// DNS the tunnel negotiated. `WireGuard` DNS comes from its profile.
    #[must_use]
    pub fn dns(&self) -> Option<DnsRequest> {
        (self.handle.kind == TunnelKindTag::OpenVpn).then(|| self.handle.dns_request.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    AuthFailed,
    Handshake(String),
    Timeout,
    Failed(String),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthFailed => f.write_str("the server rejected the credentials"),
            Self::Handshake(detail) => write!(f, "no handshake from the server: {detail}"),
            Self::Timeout => f.write_str("the tunnel did not come up in time"),
            Self::Failed(detail) => f.write_str(detail),
        }
    }
}

fn classify(error: &str) -> StartError {
    if error.starts_with("authentication failed") || error.contains("AUTH_FAILED") {
        StartError::AuthFailed
    } else if error.to_ascii_lowercase().contains("handshake") {
        StartError::Handshake(error.to_owned())
    } else if error.contains("timed out") || error.contains("expired") {
        StartError::Timeout
    } else {
        StartError::Failed(error.to_owned())
    }
}

fn revision(generation: u64) -> TunnelRevision {
    TunnelRevision {
        authority_epoch: EPOCH,
        generation,
    }
}

/// Bring a tunnel up. Blocks until it is up, failed, or `deadline` passes.
pub fn start(
    settings: &Settings,
    ownership: &StandardTunnelOwnershipStore,
    profile: &Profile,
    generation: u64,
    credentials: Option<OpenVpnStaticChallengeCredentials>,
    cancellation: TunnelCancellation,
    timeout: Duration,
) -> Result<Live, StartError> {
    let deadline = Instant::now() + timeout;
    let mut kind = TunnelKind::new(profile.protocol, settings).for_start(
        generation,
        TunnelExecutionContext {
            cancellation,
            deadline,
        },
        credentials,
    );
    let Ok(result) = panic::catch_unwind(AssertUnwindSafe(|| kind.up(profile))) else {
        let _ = kind.compensate_inflight();
        return Err(StartError::Failed("the protocol adapter panicked".into()));
    };
    let mut handle = result.map_err(|error| classify(&error.to_string()))?;
    if handle.kind == TunnelKindTag::WireGuard {
        if let Err(error) = record_wireguard(settings, ownership, profile, generation, &mut handle)
        {
            let _ = kind.down(&handle);
            return Err(StartError::Failed(error));
        }
    }
    Ok(Live { kind, handle })
}

/// Take a tunnel down and forget its ownership records.
pub fn stop(
    settings: &Settings,
    ownership: &StandardTunnelOwnershipStore,
    live: Live,
) -> Result<(), String> {
    let Live { mut kind, handle } = live;
    let profile_id = handle.profile_id.clone();
    let wireguard = handle.kind == TunnelKindTag::WireGuard;
    kind.down(&handle).map_err(|error| error.to_string())?;
    if wireguard {
        let _ = ownership.remove_after_confirmed_absence(&profile_id, &[]);
        let _ = crate::wireguard::receipt::remove_after_confirmed_absence(
            &settings.config_dir,
            &profile_id,
        );
    }
    Ok(())
}

/// Take over a tunnel Vortix started in an earlier run. `Ok(None)` means the
/// session is not ours.
pub fn adopt(
    settings: &Settings,
    ownership: &StandardTunnelOwnershipStore,
    profile: &Profile,
    session: &ActiveSession,
) -> Result<Option<Live>, String> {
    if !session.details.interface_authoritative || session.details.interface.is_empty() {
        return Ok(None);
    }
    match profile.protocol {
        ProtocolKind::WireGuard => {
            let Ok(owned) = ownership.validate_wireguard(profile, session) else {
                return Ok(None);
            };
            let handle = TunnelHandle {
                profile_id: profile.id.clone(),
                display_name: profile.display_name.clone(),
                interface_name: owned.interface_name,
                pid: None,
                started_at: session
                    .started_at
                    .unwrap_or_else(std::time::SystemTime::now),
                kind: TunnelKindTag::WireGuard,
                generation: owned.tunnel_generation,
                handshake: Some(owned.handshake),
                probe_receipts: owned.probe_receipts,
                process_ownership: None,
                teardown_config: Some(owned.teardown_config),
                dns_request: DnsRequest::default(),
                openvpn_routes: None,
            };
            Ok(Some(Live {
                kind: TunnelKind::new(ProtocolKind::WireGuard, settings),
                handle,
            }))
        }
        ProtocolKind::OpenVpn => {
            let Some(owner) = standard_openvpn_owner(&profile.id, session)? else {
                return Ok(None);
            };
            let kind = TunnelKind::new(ProtocolKind::OpenVpn, settings);
            let TunnelKind::OpenVpn(openvpn) = &kind else {
                return Err("OpenVPN adoption built the wrong adapter".into());
            };
            let evidence = openvpn
                .requested_runtime_evidence(profile)
                .map_err(|error| error.to_string())?;
            let dns_request = match evidence.dns {
                crate::openvpn::OvpnDnsEvidence::Observed(request)
                | crate::openvpn::OvpnDnsEvidence::ExplicitlyEmpty(request) => request,
                crate::openvpn::OvpnDnsEvidence::Unavailable { configured, .. } => configured,
            };
            let handle = TunnelHandle {
                profile_id: profile.id.clone(),
                display_name: profile.display_name.clone(),
                interface_name: session.details.interface.clone(),
                pid: Some(owner.protocol_pid()),
                started_at: session
                    .started_at
                    .unwrap_or_else(std::time::SystemTime::now),
                kind: TunnelKindTag::OpenVpn,
                generation: owner.generation(),
                handshake: None,
                probe_receipts: Vec::new(),
                process_ownership: Some(owner.identity()),
                teardown_config: None,
                dns_request,
                openvpn_routes: Some(evidence.routes),
            };
            Ok(Some(Live { kind, handle }))
        }
    }
}

fn record_wireguard(
    settings: &Settings,
    ownership: &StandardTunnelOwnershipStore,
    profile: &Profile,
    generation: u64,
    handle: &mut TunnelHandle,
) -> Result<(), String> {
    let handshake = handle
        .handshake
        .clone()
        .ok_or("WireGuard came up without handshake evidence")?;
    let teardown = handle
        .teardown_config
        .clone()
        .ok_or("WireGuard came up without a teardown config")?;
    let owned = ownership
        .issue_wireguard(
            profile,
            revision(generation),
            OperationId::from_parts(EPOCH, generation),
            &handle.interface_name,
            &teardown,
            handshake.clone(),
            handle.probe_receipts.clone(),
        )
        .map_err(|error| format!("WireGuard ownership could not be recorded: {error}"))?;
    if owned.teardown_config.path != teardown.path {
        let _ = std::fs::remove_file(&teardown.path);
    }
    handle.teardown_config = Some(owned.teardown_config);
    crate::wireguard::receipt::issue(
        &settings.config_dir,
        &profile.id,
        handle.interface_name.clone(),
        generation,
        handshake,
        handle.probe_receipts.clone(),
    )
    .map(|_| ())
    .map_err(|error| format!("WireGuard receipt could not be recorded: {error}"))
}

fn route_claims(evidence: &OpenVpnRouteEvidence) -> BTreeSet<Cidr> {
    let mut routes = evidence
        .configured()
        .routes()
        .iter()
        .chain(evidence.pushed().routes())
        .map(|route| route.destination().canonical_network())
        .collect::<BTreeSet<_>>();
    for redirect in [
        evidence.configured().redirect_gateway(),
        evidence.pushed().redirect_gateway(),
    ]
    .into_iter()
    .flatten()
    {
        if redirect.ipv4() {
            routes
                .insert(Cidr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0).expect("v4 default"));
        }
        if redirect.ipv6() {
            routes
                .insert(Cidr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0).expect("v6 default"));
        }
    }
    routes
}

/// Runtime-selectable carrier over the closed protocol set.
#[derive(Debug, Clone)]
pub enum TunnelKind {
    WireGuard(WgTunnel),
    OpenVpn(OvpnTunnel),
}

impl TunnelKind {
    #[must_use]
    pub fn new(protocol: ProtocolKind, settings: &Settings) -> Self {
        let config_dir = &settings.config_dir;
        match protocol {
            ProtocolKind::WireGuard => Self::WireGuard(
                WgTunnel::new().with_handshake_policy(
                    Duration::from_secs(settings.wireguard_handshake_timeout_secs),
                    settings
                        .wireguard_health_targets
                        .iter()
                        .filter_map(|target| target.parse().ok()),
                ),
            ),
            ProtocolKind::OpenVpn => Self::OpenVpn(OvpnTunnel::new(
                config_dir.join(crate::constants::OPENVPN_RUN_DIR),
                config_dir.join(crate::constants::OPENVPN_AUTH_DIR),
                &settings.openvpn_verbosity,
                settings.connect_timeout_secs,
            )),
        }
    }

    #[must_use]
    fn for_start(
        self,
        generation: u64,
        context: TunnelExecutionContext,
        credentials: Option<OpenVpnStaticChallengeCredentials>,
    ) -> Self {
        match self {
            Self::WireGuard(tunnel) => Self::WireGuard(
                tunnel
                    .for_generation(generation)
                    .with_execution_context(context),
            ),
            Self::OpenVpn(tunnel) => {
                let tunnel = tunnel
                    .for_generation(generation)
                    .for_operation(OperationId::from_parts(EPOCH, generation))
                    .with_execution_context(context);
                Self::OpenVpn(match credentials {
                    Some(credentials) => tunnel.with_static_challenge_credentials(credentials),
                    None => tunnel,
                })
            }
        }
    }

    pub fn up(&mut self, profile: &Profile) -> Result<TunnelHandle, TunnelError> {
        match self {
            Self::WireGuard(t) => t.up(profile),
            Self::OpenVpn(t) => t.up(profile),
        }
    }

    pub fn down(&mut self, handle: &TunnelHandle) -> Result<(), TunnelError> {
        match self {
            Self::WireGuard(t) => t.down(handle),
            Self::OpenVpn(t) => t.down(handle),
        }
    }

    pub fn status(&self, handle: &TunnelHandle) -> Result<TunnelStatus, TunnelError> {
        match self {
            Self::WireGuard(t) => t.status(handle),
            Self::OpenVpn(t) => t.status(handle),
        }
    }

    /// Compensate a protocol attempt that unwound before returning a handle.
    pub fn compensate_inflight(&mut self) -> Result<(), String> {
        match self {
            Self::WireGuard(tunnel) => tunnel
                .compensate_inflight()
                .map_err(|error| error.to_string()),
            Self::OpenVpn(_) => Err("protocol did not retain an exact in-flight capability".into()),
        }
    }
}

pub(crate) struct StandardOpenVpnOwner {
    custody: crate::process::CustodianHandshake,
    protocol_pid: u32,
}

impl StandardOpenVpnOwner {
    #[must_use]
    pub(crate) const fn generation(&self) -> u64 {
        self.custody.identity.generation
    }

    #[must_use]
    pub(crate) const fn protocol_pid(&self) -> u32 {
        self.protocol_pid
    }

    #[must_use]
    pub(crate) fn identity(&self) -> crate::process::ManagedProcessId {
        self.custody.identity.clone()
    }
}

pub(crate) fn standard_openvpn_owner(
    profile_id: &ProfileId,
    session: &crate::control::scanner::ActiveSession,
) -> Result<Option<StandardOpenVpnOwner>, String> {
    let Some(custody) = crate::process::custodian::load_handshake(profile_id)
        .map_err(|error| format!("OpenVPN ownership receipt rejected: {error}"))?
    else {
        return Ok(None);
    };
    let alive = crate::process::custodian::remote_status(&custody.identity)
        .map_err(|error| format!("OpenVPN custodian status failed: {error}"))?;
    if !alive {
        return Ok(None);
    }
    let scanner_pid = session
        .details
        .pid
        .ok_or_else(|| "active OpenVPN target has no scanner process PID".to_string())?;
    if !crate::process::custodian::contains_protocol_pid(&custody, scanner_pid)
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
