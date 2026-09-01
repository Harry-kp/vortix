//! Production adapter for canonical topology policy barriers.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::net::ToSocketAddrs as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::core::scanner::ActiveSession;
use crate::state::{Protocol, VpnProfile};
use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::control::service::ProfileTopology;
use crate::vortix_core::control::worker::{
    PolicyBarrier, PolicyExecutionEvidence, PolicyExecutor, PolicyStage, TopologyPolicy,
    TopologyState,
};
use crate::vortix_core::control::BootEligibility;
use crate::vortix_core::control::PolicyDigest;
use crate::vortix_core::ports::dns::{
    DnsEffectiveStatus, DnsPolicyCoordinator, DnsTunnelIntent, DnsTunnelRole,
};
use crate::vortix_core::ports::killswitch::ActiveTunnelInfo;
use crate::vortix_core::ports::route_table::DefaultRouteObservation;
use crate::vortix_core::ports::tunnel::ParsedProfile as _;
use crate::vortix_core::privileged::OpenVpnRedirectGateway;
use crate::vortix_core::profile::ProfileId;
use crate::vortix_core::profile::ResolvedEndpoint;
use crate::vortix_core::state::killswitch::{KillSwitchMode, KillSwitchState};

type SessionResolver = dyn Fn(&ProfileId) -> Option<ActiveSession> + Send + Sync;
type ExternalSessionCount = dyn Fn() -> usize + Send + Sync;

const MAX_PROFILE_BYTES: u64 = 4 * 1024 * 1024;
const ENDPOINT_CACHE_SCHEMA: u8 = 1;
const MAX_CACHED_PROFILES: usize = 512;
const MAX_ENDPOINTS_PER_PROFILE: usize = 256;
/// Each exact policy-routing query can consume the platform subprocess's
/// one-second budget. Reject unbounded plans before the first query while the
/// policy deadline remains the tighter runtime bound.
const MAX_ROUTE_PROBES_PER_BARRIER: usize = 256;

/// Read route declarations for the compatibility conflict prompt.
/// Canonical admission still consumes the complete [`ProfileTopology`].
pub(crate) fn declared_routes(protocol: Protocol, config_path: &std::path::Path) -> Vec<Cidr> {
    let Ok(text) = std::fs::read_to_string(config_path) else {
        return Vec::new();
    };
    match protocol {
        Protocol::WireGuard => crate::vortix_protocol_wireguard::parser::parse_wg_conf(&text)
            .map(|parsed| {
                parsed
                    .peers
                    .iter()
                    .flat_map(|peer| &peer.allowed_ips)
                    .filter_map(|route| Cidr::new(route.addr, route.prefix_len))
                    .collect()
            })
            .unwrap_or_default(),
        Protocol::OpenVPN => crate::vortix_protocol_openvpn::parser::parse_ovpn_conf(&text)
            .map(|parsed| {
                let mut routes = parsed
                    .routes
                    .iter()
                    .filter_map(|route| {
                        Cidr::new(route.destination.addr, route.destination.prefix_len)
                    })
                    .collect::<Vec<_>>();
                if parsed
                    .redirect_gateway
                    .as_ref()
                    .is_some_and(OpenVpnRedirectGateway::ipv4)
                {
                    routes.push(
                        Cidr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0)
                            .expect("zero prefix is valid"),
                    );
                }
                routes
            })
            .unwrap_or_default(),
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
/// Bounded profile-digest-bound endpoint selections used while DNS is blocked.
pub struct EndpointResolutionCache {
    #[serde(default = "endpoint_cache_schema")]
    schema_version: u8,
    #[serde(default)]
    profiles: std::collections::BTreeMap<String, CachedProfileEndpoints>,
}

impl Default for EndpointResolutionCache {
    fn default() -> Self {
        Self {
            schema_version: ENDPOINT_CACHE_SCHEMA,
            profiles: std::collections::BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CachedProfileEndpoints {
    profile_digest: String,
    endpoints: Vec<ResolvedEndpoint>,
}

const fn endpoint_cache_schema() -> u8 {
    ENDPOINT_CACHE_SCHEMA
}

impl EndpointResolutionCache {
    /// Decode and validate the complete cache, or construct an empty cache.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, future, oversized, or ambiguous data.
    pub fn decode(bytes: Option<&[u8]>) -> Result<Self, String> {
        let Some(bytes) = bytes else {
            return Ok(Self::default());
        };
        let cache: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("endpoint-resolution cache is malformed: {error}"))?;
        cache.validate()?;
        Ok(cache)
    }

    /// Validate and encode the complete cache for atomic persistence.
    ///
    /// # Errors
    ///
    /// Returns an error when the cache violates its fixed bounds.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec_pretty(self).map_err(|error| error.to_string())
    }

    /// Remove records for profiles no longer present in the authenticated catalog.
    pub fn retain_profiles(&mut self, profiles: &BTreeSet<ProfileId>) {
        self.profiles.retain(|profile, _| {
            profiles
                .iter()
                .any(|candidate| candidate.as_str() == profile)
        });
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema_version != ENDPOINT_CACHE_SCHEMA {
            return Err("endpoint-resolution cache schema is unsupported".into());
        }
        if self.profiles.len() > MAX_CACHED_PROFILES {
            return Err("endpoint-resolution cache profile limit exceeded".into());
        }
        for (profile_id, cached) in &self.profiles {
            if profile_id.is_empty()
                || !PolicyDigest(cached.profile_digest.clone()).is_valid()
                || cached.endpoints.len() > MAX_ENDPOINTS_PER_PROFILE
            {
                return Err("endpoint-resolution cache contains an invalid profile".into());
            }
            let mut keys = BTreeSet::new();
            for endpoint in &cached.endpoints {
                if endpoint.hostname.is_empty()
                    || endpoint.hostname.len() > 253
                    || endpoint.port == 0
                    || !keys.insert((endpoint.hostname.to_ascii_lowercase(), endpoint.port))
                {
                    return Err("endpoint-resolution cache contains an ambiguous endpoint".into());
                }
            }
        }
        Ok(())
    }

    fn lookup(
        &self,
        profile: &ProfileId,
        digest: &str,
        hostname: &str,
        port: u16,
    ) -> Option<std::net::IpAddr> {
        let cached = self.profiles.get(profile.as_str())?;
        (cached.profile_digest == digest)
            .then(|| {
                cached.endpoints.iter().find_map(|endpoint| {
                    (endpoint.port == port && endpoint.hostname.eq_ignore_ascii_case(hostname))
                        .then_some(endpoint.address)
                })
            })
            .flatten()
    }

    fn replace_profile(
        &mut self,
        profile: &ProfileId,
        digest: String,
        endpoints: Vec<ResolvedEndpoint>,
    ) {
        self.profiles.insert(
            profile.as_str().to_owned(),
            CachedProfileEndpoints {
                profile_digest: digest,
                endpoints,
            },
        );
    }
}

/// Parse one saved profile into immutable policy resources before admitting
/// lifecycle work. Hostname resolution is best-effort here; if `vpn-only`
/// already blocks DNS, only an owner-authenticated host/port mapping bound to
/// the exact profile digest may be reused. Modes that need pre-blocking
/// otherwise reject an unresolved endpoint before touching the firewall.
#[allow(
    clippy::too_many_lines,
    reason = "one bounded profile parse binds routes, DNS, endpoints, and the exact cache digest"
)]
pub fn topology_for_profile(
    profile: &VpnProfile,
    cache: &mut EndpointResolutionCache,
) -> Result<ProfileTopology, String> {
    let body = read_bounded_profile(profile)?;
    build_topology_for_profile(profile, &body, cache)
}

/// Determine whether a profile is eligible for pre-login boot connection
/// using the same bounded read and reviewed protocol parsers as canonical
/// admission. This deliberately performs no DNS resolution, cache update, or
/// policy construction. Credential mechanisms not represented by the
/// reviewed parser fail with the parser rather than being guessed here.
pub fn boot_eligibility_for_profile(profile: &VpnProfile) -> Result<BootEligibility, String> {
    let body = read_bounded_profile(profile)?;
    match profile.protocol {
        Protocol::WireGuard => {
            crate::vortix_protocol_wireguard::parser::parse_wg_conf(&body)
                .map_err(|error| error.to_string())?;
            Ok(BootEligibility::Eligible)
        }
        Protocol::OpenVPN => {
            let parsed = crate::vortix_protocol_openvpn::parser::parse_ovpn_conf(&body)
                .map_err(|error| error.to_string())?;
            Ok(openvpn_boot_eligibility(&parsed))
        }
    }
}

fn openvpn_boot_eligibility(
    parsed: &crate::vortix_protocol_openvpn::parser::OvpnParsedProfile,
) -> BootEligibility {
    match parsed.boot_credentials {
        crate::vortix_protocol_openvpn::parser::BootCredentialRequirement::NonInteractive => {
            BootEligibility::Eligible
        }
        crate::vortix_protocol_openvpn::parser::BootCredentialRequirement::Interactive => {
            BootEligibility::InteractiveCredentials
        }
        crate::vortix_protocol_openvpn::parser::BootCredentialRequirement::UnsupportedKeyProvider => {
            BootEligibility::UnsupportedKeyProvider
        }
    }
}

fn read_bounded_profile(profile: &VpnProfile) -> Result<String, String> {
    let file = std::fs::File::open(&profile.config_path)
        .map_err(|error| format!("open profile: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("read profile metadata: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_PROFILE_BYTES {
        return Err("profile is not a bounded regular file".into());
    }
    let mut body = String::new();
    file.take(MAX_PROFILE_BYTES + 1)
        .read_to_string(&mut body)
        .map_err(|error| format!("read profile: {error}"))?;
    if body.len() as u64 > MAX_PROFILE_BYTES {
        return Err("profile is not a bounded regular file".into());
    }
    Ok(body)
}

fn build_topology_for_profile(
    profile: &VpnProfile,
    body: &str,
    cache: &mut EndpointResolutionCache,
) -> Result<ProfileTopology, String> {
    let mut routes = BTreeSet::new();
    let mut server_ips = BTreeSet::new();
    let profile_digest = PolicyDigest::sha256(body.as_bytes()).0;
    let mut endpoint_resolutions = Vec::new();
    let (protocol, interface_name, dns_request, interactive_credentials) = match profile.protocol {
        Protocol::WireGuard => {
            let parsed = crate::vortix_protocol_wireguard::parser::parse_wg_conf(body)
                .map_err(|error| error.to_string())?;
            for peer in &parsed.peers {
                routes.extend(
                    peer.allowed_ips
                        .iter()
                        .map(|route| format!("{}/{}", route.addr, route.prefix_len)),
                );
                if let Some(endpoint) = peer.endpoint {
                    server_ips.insert(endpoint.ip());
                }
                if let (Some(host), Some(port)) = (&peer.endpoint_host, peer.endpoint_port) {
                    resolve_endpoint(
                        profile,
                        &profile_digest,
                        host,
                        port,
                        cache,
                        &mut endpoint_resolutions,
                        &mut server_ips,
                    );
                }
            }
            (
                crate::vortix_core::profile::ProtocolKind::WireGuard,
                None,
                parsed.dns_request(),
                false,
            )
        }
        Protocol::OpenVPN => {
            let parsed = crate::vortix_protocol_openvpn::parser::parse_ovpn_conf(body)
                .map_err(|error| error.to_string())?;
            if parsed
                .redirect_gateway
                .as_ref()
                .is_some_and(OpenVpnRedirectGateway::ipv4)
            {
                routes.insert("0.0.0.0/0".into());
            }
            routes.extend(parsed.routes.iter().map(|route| {
                format!(
                    "{}/{}",
                    route.destination.addr, route.destination.prefix_len
                )
            }));
            for remote in &parsed.remotes {
                resolve_endpoint(
                    profile,
                    &profile_digest,
                    &remote.host,
                    remote.port,
                    cache,
                    &mut endpoint_resolutions,
                    &mut server_ips,
                );
            }
            (
                crate::vortix_core::profile::ProtocolKind::OpenVpn,
                None,
                parsed.dns_request(),
                openvpn_boot_eligibility(&parsed) == BootEligibility::InteractiveCredentials,
            )
        }
    };
    endpoint_resolutions.sort();
    endpoint_resolutions.dedup();
    cache.replace_profile(&profile.id, profile_digest, endpoint_resolutions.clone());
    let dns_digest = digest_of(&dns_request)?;
    let firewall_digest = digest_of(&(routes.clone(), server_ips.clone()))?;
    Ok(ProfileTopology {
        protocol: Some(protocol),
        interactive_credentials,
        display_name: Some(profile.name.clone()),
        interface_name,
        routes,
        server_ips,
        resolved_endpoints: endpoint_resolutions,
        dns_request,
        dns_digest,
        firewall_digest,
        ..ProfileTopology::default()
    })
}

fn resolve_endpoint(
    profile: &VpnProfile,
    digest: &str,
    host: &str,
    port: u16,
    cache: &EndpointResolutionCache,
    resolutions: &mut Vec<ResolvedEndpoint>,
    output: &mut BTreeSet<std::net::IpAddr>,
) {
    if let Ok(address) = host.parse::<std::net::IpAddr>() {
        output.insert(address);
        return;
    }
    let live = (host, port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addresses| addresses.next())
        .map(|address| address.ip());
    if let Some(address) = live.or_else(|| cache.lookup(&profile.id, digest, host, port)) {
        output.insert(address);
        resolutions.push(ResolvedEndpoint::new(host, port, address));
    }
}

fn digest_of(value: &impl serde::Serialize) -> Result<PolicyDigest, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    Ok(PolicyDigest::sha256(&bytes))
}

/// Only protection-installing transitions need exclusive global authority.
/// Root-authenticated `off` and `block-on-drop` transitions reduce or remove
/// Vortix-owned blocking and remain available as recovery operations.
const fn firewall_transition_requires_authority(mode: KillSwitchMode) -> bool {
    matches!(mode, KillSwitchMode::AlwaysOn)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyKey {
    generation: u64,
    operation_id: crate::vortix_core::control::OperationId,
    stage: PolicyStage,
}

#[derive(Debug, Clone)]
struct Readback {
    key: PolicyKey,
    evidence: PolicyExecutionEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteProbeExpectation {
    target: std::net::IpAddr,
    interface: String,
    claims: Vec<(ProfileId, crate::vortix_core::control::worker::RouteClaim)>,
}

/// Executes the global barriers against the real route, DNS, and firewall
/// adapters. Protocol lifecycle remains owned by `CanonicalTunnelExecutor`.
pub struct CanonicalPolicyExecutor {
    config_dir: PathBuf,
    sessions: Arc<SessionResolver>,
    external_sessions: Arc<ExternalSessionCount>,
    dns: Mutex<DnsPolicyCoordinator>,
    readback: Mutex<Option<Readback>>,
}

impl CanonicalPolicyExecutor {
    #[must_use]
    pub fn new(
        config_dir: PathBuf,
        sessions: impl Fn(&ProfileId) -> Option<ActiveSession> + Send + Sync + 'static,
        external_sessions: impl Fn() -> usize + Send + Sync + 'static,
    ) -> Self {
        Self {
            dns: Mutex::new(crate::core::dns_policy::load(&config_dir).unwrap_or_default()),
            config_dir,
            sessions: Arc::new(sessions),
            external_sessions: Arc::new(external_sessions),
            readback: Mutex::new(None),
        }
    }

    fn key(policy: &TopologyPolicy) -> PolicyKey {
        PolicyKey {
            generation: policy.generation,
            operation_id: policy.operation_id.clone(),
            stage: policy.stage,
        }
    }

    fn with_readback(
        &self,
        policy: &TopologyPolicy,
        update: impl FnOnce(&mut PolicyExecutionEvidence),
    ) {
        let key = Self::key(policy);
        let mut state = self
            .readback
            .lock()
            .expect("policy readback mutex poisoned");
        if state.as_ref().is_none_or(|state| state.key != key) {
            *state = Some(Readback {
                key,
                evidence: PolicyExecutionEvidence {
                    observed_at_millis: 0,
                    interface_verified: false,
                    route_verified: false,
                    dns_verified: false,
                    firewall_verified: false,
                },
            });
        }
        update(&mut state.as_mut().expect("readback installed").evidence);
    }

    fn require_global_authority(&self) -> Result<(), String> {
        let external = (self.external_sessions)();
        if external == 0 {
            Ok(())
        } else {
            Err(format!(
                "global policy refused while {external} external VPN session(s) lack ownership"
            ))
        }
    }

    fn session_interface(
        &self,
        state: &TopologyState,
        profile: &ProfileId,
    ) -> Result<String, String> {
        let session = (self.sessions)(profile)
            .ok_or_else(|| format!("profile {profile} has no current tunnel observation"))?;
        if !session.interface_authoritative || session.interface.is_empty() {
            return Err(format!(
                "profile {profile} has no authoritative interface observation"
            ));
        }
        if state
            .interfaces
            .get(profile)
            .is_some_and(|expected| expected != &session.interface)
        {
            return Err(format!(
                "profile {profile} interface changed during the topology transaction"
            ));
        }
        Ok(session.interface)
    }

    fn verify_tunnels(&self, policy: &TopologyPolicy) -> Result<(), String> {
        for profile in &policy.target.profiles {
            self.session_interface(&policy.target, profile)?;
        }
        for profile in policy.prior.profiles.difference(&policy.target.profiles) {
            if (self.sessions)(profile).is_some() {
                return Err(format!(
                    "profile {profile} remained present after requested teardown"
                ));
            }
        }
        Ok(())
    }

    fn route_probe_plan(
        &self,
        policy: &TopologyPolicy,
    ) -> Result<Vec<RouteProbeExpectation>, String> {
        // The current cross-platform port can prove policy routing only by
        // asking the kernel about one concrete destination. Inferring many
        // claims from a route-table dump would be wrong in the presence of
        // Linux rules/tables or macOS scoped routes, so only byte-equivalent
        // target/interface expectations are safe to collapse.
        let mut unique = BTreeMap::<
            (std::net::IpAddr, String),
            Vec<(ProfileId, crate::vortix_core::control::worker::RouteClaim)>,
        >::new();
        for profile in &policy.target.profiles {
            let interface = self.session_interface(&policy.target, profile)?;
            for claim in policy.target.routes.get(profile).into_iter().flatten() {
                let mut probe = claim.probe_address();
                if policy
                    .target
                    .server_ips
                    .get(profile)
                    .is_some_and(|endpoints| endpoints.contains(&probe))
                    && claim.is_default()
                {
                    probe = if probe.is_ipv4() {
                        "8.8.8.8".parse().expect("fixed IPv4 route probe")
                    } else {
                        "2001:4860:4860::8888"
                            .parse()
                            .expect("fixed IPv6 route probe")
                    };
                }
                unique
                    .entry((probe, interface.clone()))
                    .or_default()
                    .push((profile.clone(), *claim));
                if unique.len() > MAX_ROUTE_PROBES_PER_BARRIER {
                    return Err(format!(
                        "route verification requires more than {MAX_ROUTE_PROBES_PER_BARRIER} distinct probes"
                    ));
                }
            }
        }
        Ok(unique
            .into_iter()
            .map(|((target, interface), claims)| RouteProbeExpectation {
                target,
                interface,
                claims,
            })
            .collect())
    }

    fn verify_routes(&self, policy: &TopologyPolicy) -> Result<(), String> {
        // Route and Observation invoke this separately on purpose: the latter
        // is the fresh final read-back required for protection publication.
        let plan = self.route_probe_plan(policy)?;
        let total = plan.len();
        let route_table = &crate::platform::current_platform().route_table;
        for (index, expectation) in plan.into_iter().enumerate() {
            if std::time::Instant::now() >= policy.deadline {
                return Err(format!(
                    "route verification deadline expired after {index} of {total} probes"
                ));
            }
            let observation = route_table.route_interface_for(expectation.target);
            if std::time::Instant::now() >= policy.deadline {
                return Err(format!(
                    "route verification deadline expired during probe {} of {total}",
                    index + 1
                ));
            }
            if !matches!(
                &observation,
                DefaultRouteObservation::Interface(observed)
                    if observed == &expectation.interface
            ) {
                let (profile, claim) = expectation
                    .claims
                    .first()
                    .expect("route probe expectation has at least one claim");
                return Err(format!(
                    "route {claim} for profile {profile} did not resolve through {}: {observation:?}",
                    expectation.interface
                ));
            }
        }
        Ok(())
    }

    fn dns_intents(&self, state: &TopologyState) -> Result<Vec<DnsTunnelIntent>, String> {
        let mut intents = Vec::new();
        for profile in &state.profiles {
            let Some(request) = state.dns_requests.get(profile) else {
                continue;
            };
            if request.is_empty() {
                continue;
            }
            let role = if state
                .routes
                .get(profile)
                .is_some_and(|routes| routes.iter().any(|route| route.is_default()))
            {
                DnsTunnelRole::Primary
            } else {
                DnsTunnelRole::Secondary
            };
            intents.push(DnsTunnelIntent {
                profile_id: profile.clone(),
                interface: self.session_interface(state, profile)?,
                role,
                request: request.clone(),
            });
        }
        Ok(intents)
    }

    fn reconcile_dns(&self, state: &TopologyState, force_verify: bool) -> Result<(), String> {
        self.require_global_authority()?;
        let intents = self.dns_intents(state)?;
        let _lock = crate::core::dns_policy::acquire_policy_lock(&self.config_dir)
            .map_err(|error| format!("DNS policy lock failed: {error}"))?;
        let mut coordinator = self.dns.lock().map_err(|_| "DNS policy mutex poisoned")?;
        if force_verify {
            coordinator.invalidate_verification();
        }
        coordinator
            .reconcile_durable(
                &intents,
                &crate::platform::current_platform().dns,
                |state| crate::core::dns_policy::save(&self.config_dir, state),
            )
            .map_err(|error| error.to_string())?;
        if matches!(
            coordinator.effective().status,
            DnsEffectiveStatus::Applied | DnsEffectiveStatus::Released
        ) {
            Ok(())
        } else {
            Err(format!(
                "DNS read-back is degraded: {}",
                coordinator.effective().errors.join("; ")
            ))
        }
    }

    fn verify_dns(&self, policy: &TopologyPolicy) -> Result<(), String> {
        self.require_global_authority()?;
        let intents = self.dns_intents(&policy.target)?;
        let dns_policy = {
            let coordinator = self.dns.lock().map_err(|_| "DNS policy mutex poisoned")?;
            coordinator
                .verify_current(&intents, &crate::platform::current_platform().dns)
                .map_err(|errors| format!("DNS read-back is degraded: {}", errors.join("; ")))?;
            coordinator
                .desired()
                .cloned()
                .ok_or_else(|| "DNS desired policy is unavailable".to_string())?
        };
        crate::core::dns_protection::verify_dns_routes(&dns_policy, policy.deadline)
    }

    fn verify_current_dns_routes(&self, deadline: Instant) -> Result<(), String> {
        let policy = self
            .dns
            .lock()
            .map_err(|_| "DNS policy mutex poisoned")?
            .desired()
            .cloned()
            .ok_or_else(|| "DNS desired policy is unavailable".to_string())?;
        crate::core::dns_protection::verify_dns_routes(&policy, deadline)
    }

    fn active_tunnels(
        &self,
        state: &TopologyState,
        require_endpoints: bool,
    ) -> Result<Vec<ActiveTunnelInfo>, String> {
        state
            .profiles
            .iter()
            .map(|profile| {
                let server_ips = state
                    .server_ips
                    .get(profile)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .collect::<Vec<_>>();
                if require_endpoints && server_ips.is_empty() {
                    return Err(format!(
                        "profile {profile} has no resolved server endpoint for firewall policy"
                    ));
                }
                let declared_cidrs = state
                    .routes
                    .get(profile)
                    .into_iter()
                    .flatten()
                    .map(ToString::to_string)
                    .map(|route| route.parse().map_err(|_| format!("invalid route {route}")))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(ActiveTunnelInfo {
                    interface: self.session_interface(state, profile)?,
                    server_ips,
                    declared_cidrs,
                    is_primary: state
                        .routes
                        .get(profile)
                        .is_some_and(|routes| routes.iter().any(|route| route.is_default())),
                })
            })
            .collect()
    }

    fn pre_block_tunnels(&self, policy: &TopologyPolicy) -> Result<Vec<ActiveTunnelInfo>, String> {
        let mut active = self.active_tunnels(&policy.prior, true)?;
        let already_allowed = active
            .iter()
            .flat_map(|tunnel| tunnel.server_ips.iter().copied())
            .collect::<BTreeSet<_>>();
        let pending = policy
            .target
            .server_ips
            .values()
            .flatten()
            .copied()
            .filter(|endpoint| !already_allowed.contains(endpoint))
            .collect::<BTreeSet<_>>();
        let newly_connecting = policy
            .target
            .profiles
            .difference(&policy.prior.profiles)
            .collect::<Vec<_>>();
        if newly_connecting.iter().any(|profile| {
            policy
                .target
                .server_ips
                .get(*profile)
                .is_none_or(BTreeSet::is_empty)
        }) {
            return Err("a connecting profile has no resolved endpoint for pre-blocking".into());
        }
        if !pending.is_empty() {
            active.push(ActiveTunnelInfo::endpoint_allowlist(
                pending.into_iter().collect(),
            ));
        }
        Ok(active)
    }

    fn enable_blocking(&self, active: &[ActiveTunnelInfo]) -> Result<(), String> {
        self.require_global_authority()?;
        crate::core::killswitch::enable_blocking_multi(active).map_err(|error| error.to_string())
    }

    fn final_firewall_tunnels(
        &self,
        policy: &TopologyPolicy,
    ) -> Result<Vec<ActiveTunnelInfo>, String> {
        let require_endpoints = policy.target.kill_switch == KillSwitchMode::AlwaysOn;
        let mut active = self.active_tunnels(&policy.target, require_endpoints)?;
        if !require_endpoints {
            return Ok(active);
        }

        // A disconnected `vpn-only` policy keeps the last endpoint IPs
        // reachable so a managed config rendered from the separately
        // profile-bound resolution cache can start transport without DNS.
        let target_endpoints = active
            .iter()
            .flat_map(|tunnel| tunnel.server_ips.iter().copied())
            .collect::<BTreeSet<_>>();
        let retained = policy
            .prior
            .server_ips
            .values()
            .flatten()
            .copied()
            .filter(|endpoint| !target_endpoints.contains(endpoint))
            .collect::<Vec<_>>();
        if !retained.is_empty() {
            active.push(ActiveTunnelInfo::endpoint_allowlist(retained));
        }
        Ok(active)
    }

    fn persist_firewall_state(
        mode: KillSwitchMode,
        state: KillSwitchState,
        active: &[ActiveTunnelInfo],
        verified: bool,
    ) -> Result<(), String> {
        let verification = verified.then(|| crate::core::killswitch::local_verification(active));
        crate::core::killswitch::save_state_with_verification(
            mode,
            state,
            crate::core::killswitch::persisted_from_active(active),
            verification,
        )
        .map_err(|error| error.to_string())
    }

    fn install_pre_tunnel_blocking(&self, policy: &TopologyPolicy) -> Result<(), String> {
        let active = self.pre_block_tunnels(policy)?;
        if let Err(apply_error) = self.enable_blocking(&active) {
            return match self.restore_firewall(&policy.prior) {
                Ok(()) => Err(apply_error),
                Err(restore_error) => {
                    let persist_error = Self::persist_firewall_state(
                        policy.target.kill_switch,
                        KillSwitchState::Degraded,
                        &active,
                        false,
                    )
                    .err();
                    Err(format!(
                        "pre-tunnel blocking failed ({apply_error}); prior firewall restoration failed ({restore_error}); degraded blocking state retained{}",
                        persist_error.map_or_else(String::new, |error| format!(
                            "; degraded state persistence failed ({error})"
                        ))
                    ))
                }
            };
        }

        if let Err(persist_error) = Self::persist_firewall_state(
            policy.target.kill_switch,
            KillSwitchState::Blocking,
            &active,
            true,
        ) {
            // The kernel has already accepted and read back the emergency
            // barrier. A disk failure must not turn that verified protection
            // into a fail-open rollback. The control operation remains failed
            // and reconciliation can retry persistence while blocking stays
            // in force.
            return Err(format!(
                "pre-tunnel blocking state persistence failed ({persist_error}); verified blocking remains fail-closed"
            ));
        }
        Ok(())
    }

    fn apply_final_firewall(&self, policy: &TopologyPolicy) -> Result<(), String> {
        if firewall_transition_requires_authority(policy.target.kill_switch) {
            self.require_global_authority()?;
        }
        let active = self.final_firewall_tunnels(policy)?;
        let (state, verification) = match policy.target.kill_switch {
            KillSwitchMode::AlwaysOn => {
                crate::core::killswitch::enable_blocking_multi(&active)
                    .map_err(|error| error.to_string())?;
                (
                    KillSwitchState::Blocking,
                    Some(crate::core::killswitch::local_verification(&active)),
                )
            }
            KillSwitchMode::Auto => {
                crate::core::killswitch::disable_blocking().map_err(|error| error.to_string())?;
                (KillSwitchState::Armed, None)
            }
            KillSwitchMode::Off => {
                crate::core::killswitch::disable_blocking().map_err(|error| error.to_string())?;
                (KillSwitchState::Disabled, None)
            }
        };
        crate::core::killswitch::save_state_with_verification(
            policy.target.kill_switch,
            state,
            crate::core::killswitch::persisted_from_active(&active),
            verification,
        )
        .map_err(|error| error.to_string())
    }

    fn verify_final_firewall(&self, policy: &TopologyPolicy) -> Result<(), String> {
        if firewall_transition_requires_authority(policy.target.kill_switch) {
            self.require_global_authority()?;
        }
        match policy.target.kill_switch {
            KillSwitchMode::AlwaysOn => {
                let active = self.final_firewall_tunnels(policy)?;
                crate::core::killswitch::verify_blocking(&active).map_err(|error| error.to_string())
            }
            KillSwitchMode::Auto | KillSwitchMode::Off => {
                crate::core::killswitch::verify_disabled().map_err(|error| error.to_string())
            }
        }
    }

    fn restore_firewall(&self, state: &TopologyState) -> Result<(), String> {
        let active = self.active_tunnels(state, state.kill_switch == KillSwitchMode::AlwaysOn)?;
        if firewall_transition_requires_authority(state.kill_switch) {
            self.enable_blocking(&active)?;
            Self::persist_firewall_state(
                state.kill_switch,
                KillSwitchState::Blocking,
                &active,
                true,
            )
        } else {
            crate::core::killswitch::disable_blocking().map_err(|error| error.to_string())?;
            let effective = if state.kill_switch == KillSwitchMode::Auto {
                KillSwitchState::Armed
            } else {
                KillSwitchState::Disabled
            };
            Self::persist_firewall_state(state.kill_switch, effective, &active, false)
        }
    }
}

impl PolicyExecutor for CanonicalPolicyExecutor {
    fn apply(&self, policy: &TopologyPolicy, barrier: PolicyBarrier) -> Result<(), String> {
        self.with_readback(policy, |_| {});
        match barrier {
            PolicyBarrier::Blocking if policy.stage == PolicyStage::PreTunnelBlocking => {
                self.install_pre_tunnel_blocking(policy)
            }
            PolicyBarrier::Blocking => {
                self.apply_final_firewall(policy)?;
                self.with_readback(policy, |evidence| evidence.firewall_verified = true);
                Ok(())
            }
            PolicyBarrier::Tunnel => {
                self.verify_tunnels(policy)?;
                self.with_readback(policy, |evidence| evidence.interface_verified = true);
                Ok(())
            }
            PolicyBarrier::Route => {
                self.verify_routes(policy)?;
                self.with_readback(policy, |evidence| evidence.route_verified = true);
                Ok(())
            }
            PolicyBarrier::Dns => {
                self.reconcile_dns(&policy.target, false)?;
                self.verify_current_dns_routes(policy.deadline)?;
                self.with_readback(policy, |evidence| evidence.dns_verified = true);
                Ok(())
            }
            PolicyBarrier::Observation => {
                self.verify_tunnels(policy)?;
                self.verify_routes(policy)?;
                self.reconcile_dns(&policy.target, true)?;
                self.verify_current_dns_routes(policy.deadline)?;
                self.with_readback(policy, |evidence| {
                    evidence.interface_verified = true;
                    evidence.route_verified = true;
                    evidence.dns_verified = true;
                });
                Ok(())
            }
            PolicyBarrier::EffectivePublication => {
                self.apply_final_firewall(policy)?;
                let observed_at_millis = crate::utils::boot_elapsed_millis().ok_or_else(|| {
                    "OS boot clock is unavailable for policy evidence".to_string()
                })?;
                self.with_readback(policy, |evidence| {
                    evidence.firewall_verified = true;
                    evidence.observed_at_millis = observed_at_millis;
                });
                Ok(())
            }
        }
    }

    fn compensate(&self, policy: &TopologyPolicy, barrier: PolicyBarrier) -> Result<(), String> {
        match barrier {
            PolicyBarrier::Dns => self.reconcile_dns(&policy.prior, false),
            PolicyBarrier::Blocking | PolicyBarrier::EffectivePublication => {
                match firewall_compensation_target(policy, barrier) {
                    FirewallCompensationTarget::Prior => self.restore_firewall(&policy.prior),
                    FirewallCompensationTarget::PreTunnelBlocking => {
                        self.install_pre_tunnel_blocking(policy)
                    }
                }
            }
            PolicyBarrier::Tunnel | PolicyBarrier::Route | PolicyBarrier::Observation => Ok(()),
        }
    }

    fn audit(&self, policy: &TopologyPolicy) -> Result<PolicyExecutionEvidence, String> {
        if policy.stage != PolicyStage::Final {
            return Err("only a final topology policy can be audited".into());
        }
        self.verify_tunnels(policy)?;
        self.verify_routes(policy)?;
        self.verify_dns(policy)?;
        self.verify_final_firewall(policy)?;
        let observed_at_millis = crate::utils::boot_elapsed_millis()
            .ok_or_else(|| "OS boot clock is unavailable for policy evidence".to_string())?;
        Ok(PolicyExecutionEvidence {
            observed_at_millis,
            interface_verified: true,
            route_verified: true,
            dns_verified: true,
            firewall_verified: true,
        })
    }

    fn verification(&self, policy: &TopologyPolicy) -> Option<PolicyExecutionEvidence> {
        let state = self.readback.lock().ok()?;
        let readback = state.as_ref()?;
        (readback.key == Self::key(policy)
            && readback.evidence.interface_verified
            && readback.evidence.route_verified
            && readback.evidence.dns_verified
            && readback.evidence.firewall_verified)
            .then_some(readback.evidence)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirewallCompensationTarget {
    Prior,
    PreTunnelBlocking,
}

fn firewall_compensation_target(
    policy: &TopologyPolicy,
    barrier: PolicyBarrier,
) -> FirewallCompensationTarget {
    if policy.stage == PolicyStage::Final
        && policy.required_blocking
        && matches!(barrier, PolicyBarrier::EffectivePublication)
    {
        FirewallCompensationTarget::PreTunnelBlocking
    } else {
        FirewallCompensationTarget::Prior
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::control::worker::{RouteClaim, TopologyTransitionKind};
    use crate::vortix_core::control::{AuthorityEpoch, OperationId, PolicyDigest};
    use crate::vortix_core::ports::dns::DnsRequest;
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    fn operation() -> OperationId {
        serde_json::from_str("\"op-0000000000000001-0000000000000001\"").unwrap()
    }

    fn policy(prior: TopologyState, target: TopologyState) -> TopologyPolicy {
        TopologyPolicy {
            generation: 1,
            authority_epoch: AuthorityEpoch(1),
            digest: PolicyDigest("policy".into()),
            operation_id: operation(),
            deadline: Instant::now() + Duration::from_secs(1),
            prior,
            target,
            prior_tunnel_revisions: BTreeMap::new(),
            tunnel_revisions: BTreeMap::new(),
            transition: TopologyTransitionKind::Connect,
            required_blocking: true,
            stage: PolicyStage::PreTunnelBlocking,
        }
    }

    fn target(profile: &ProfileId) -> TopologyState {
        TopologyState {
            profiles: BTreeSet::from([profile.clone()]),
            routes: BTreeMap::from([(
                profile.clone(),
                BTreeSet::from([RouteClaim::parse("0.0.0.0/0").unwrap()]),
            )]),
            server_ips: BTreeMap::from([(
                profile.clone(),
                BTreeSet::from(["203.0.113.7".parse().unwrap()]),
            )]),
            dns_requests: BTreeMap::from([(
                profile.clone(),
                DnsRequest {
                    servers: vec!["10.0.0.53".parse().unwrap()],
                    search_domains: Vec::new(),
                },
            )]),
            ..TopologyState::default()
        }
    }

    #[test]
    fn pre_block_allows_resolved_endpoint_before_interface_exists() {
        let temp = tempfile::tempdir().unwrap();
        let profile = ProfileId::new("corp");
        let executor = CanonicalPolicyExecutor::new(temp.path().into(), |_| None, || 0);
        let policy = policy(TopologyState::default(), target(&profile));
        let active = executor.pre_block_tunnels(&policy).unwrap();
        assert_eq!(active.len(), 1);
        assert!(active[0].is_endpoint_allowlist());
        assert_eq!(
            active[0].server_ips,
            vec!["203.0.113.7".parse::<std::net::IpAddr>().unwrap()]
        );
    }

    #[test]
    fn protection_reducing_firewall_transitions_do_not_require_session_authority() {
        assert!(!firewall_transition_requires_authority(KillSwitchMode::Off));
        assert!(!firewall_transition_requires_authority(
            KillSwitchMode::Auto
        ));
        assert!(firewall_transition_requires_authority(
            KillSwitchMode::AlwaysOn
        ));
    }

    #[test]
    fn failed_final_publication_preserves_required_pre_tunnel_blocking() {
        let profile = ProfileId::new("corp");
        let mut final_policy = policy(TopologyState::default(), target(&profile));
        final_policy.stage = PolicyStage::Final;
        final_policy.transition = TopologyTransitionKind::Recovery;
        final_policy.required_blocking = true;

        assert_eq!(
            firewall_compensation_target(&final_policy, PolicyBarrier::EffectivePublication),
            FirewallCompensationTarget::PreTunnelBlocking
        );
    }

    #[test]
    fn hostname_topology_reuses_only_exact_profile_digest_cache_entry() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("corp.conf");
        let body = "[Interface]\nPrivateKey = AAAA\n[Peer]\nPublicKey = BBBB\nAllowedIPs = 0.0.0.0/0\nEndpoint = endpoint.invalid:51820\n";
        std::fs::write(&path, body).unwrap();
        let profile = VpnProfile {
            id: ProfileId::new("corp"),
            name: "Corporate".into(),
            protocol: Protocol::WireGuard,
            location: String::new(),
            config_path: path,
            last_used: None,
        };
        let retained = "203.0.113.19".parse().unwrap();
        let mut cache = EndpointResolutionCache::default();
        cache.replace_profile(
            &profile.id,
            PolicyDigest::sha256(body.as_bytes()).0,
            vec![ResolvedEndpoint::new("endpoint.invalid", 51820, retained)],
        );
        let topology = topology_for_profile(&profile, &mut cache).unwrap();
        assert_eq!(topology.server_ips, BTreeSet::from([retained]));
        assert_eq!(topology.resolved_endpoints.len(), 1);
    }

    #[test]
    fn static_challenge_profile_is_explicitly_interactive() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("corp.ovpn");
        std::fs::write(
            &path,
            "client\nremote 203.0.113.7 1194\nauth-user-pass\nstatic-challenge \"OTP\" 0\n",
        )
        .unwrap();
        let profile = VpnProfile {
            id: ProfileId::new("corp"),
            name: "Corporate".into(),
            protocol: Protocol::OpenVPN,
            location: String::new(),
            config_path: path,
            last_used: None,
        };

        let topology =
            topology_for_profile(&profile, &mut EndpointResolutionCache::default()).unwrap();

        assert!(topology.interactive_credentials);
    }

    #[test]
    fn username_password_profile_is_explicitly_interactive() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("corp.ovpn");
        std::fs::write(&path, "client\nremote 203.0.113.7 1194\nauth-user-pass\n").unwrap();
        let profile = VpnProfile {
            id: ProfileId::new("corp"),
            name: "Corporate".into(),
            protocol: Protocol::OpenVPN,
            location: String::new(),
            config_path: path,
            last_used: None,
        };

        let topology =
            topology_for_profile(&profile, &mut EndpointResolutionCache::default()).unwrap();

        assert!(topology.interactive_credentials);
        assert_eq!(
            boot_eligibility_for_profile(&profile).unwrap(),
            BootEligibility::InteractiveCredentials
        );
    }

    #[test]
    fn boot_eligibility_does_not_resolve_or_update_endpoint_cache() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("corp.ovpn");
        std::fs::write(&path, "client\nremote definitely.invalid.example 1194\n").unwrap();
        let profile = VpnProfile {
            id: ProfileId::new("corp"),
            name: "Corporate".into(),
            protocol: Protocol::OpenVPN,
            location: String::new(),
            config_path: path,
            last_used: None,
        };

        assert_eq!(
            boot_eligibility_for_profile(&profile).unwrap(),
            BootEligibility::Eligible
        );
    }

    #[test]
    fn boot_eligibility_rejects_file_backed_passwords_and_key_providers() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("corp.ovpn");
        let profile = VpnProfile {
            id: ProfileId::new("corp"),
            name: "Corporate".into(),
            protocol: Protocol::OpenVPN,
            location: String::new(),
            config_path: path.clone(),
            last_used: None,
        };

        std::fs::write(&path, "client\nauth-user-pass credentials.txt\n").unwrap();
        assert_eq!(
            boot_eligibility_for_profile(&profile).unwrap(),
            BootEligibility::InteractiveCredentials
        );

        std::fs::write(&path, "client\npkcs11-id token\n").unwrap();
        assert_eq!(
            boot_eligibility_for_profile(&profile).unwrap(),
            BootEligibility::UnsupportedKeyProvider
        );
    }

    #[test]
    fn hostname_topology_rejects_stale_or_ambiguous_cache_entries() {
        let mut cache = EndpointResolutionCache::default();
        cache.profiles.insert(
            "corp".into(),
            CachedProfileEndpoints {
                profile_digest: "0".repeat(64),
                endpoints: vec![
                    ResolvedEndpoint::new(
                        "endpoint.invalid",
                        51820,
                        "203.0.113.19".parse().unwrap(),
                    ),
                    ResolvedEndpoint::new(
                        "ENDPOINT.INVALID",
                        51820,
                        "203.0.113.20".parse().unwrap(),
                    ),
                ],
            },
        );
        assert!(cache.validate().is_err());

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("corp.conf");
        std::fs::write(
            &path,
            "[Interface]\nPrivateKey = changed\n[Peer]\nPublicKey = BBBB\nEndpoint = endpoint.invalid:51820\n",
        )
        .unwrap();
        let profile = VpnProfile {
            id: ProfileId::new("corp"),
            name: "Corporate".into(),
            protocol: Protocol::WireGuard,
            location: String::new(),
            config_path: path,
            last_used: None,
        };
        let mut stale = EndpointResolutionCache::default();
        stale.replace_profile(
            &profile.id,
            "0".repeat(64),
            vec![ResolvedEndpoint::new(
                "endpoint.invalid",
                51820,
                "203.0.113.19".parse().unwrap(),
            )],
        );
        let topology = topology_for_profile(&profile, &mut stale).unwrap();
        assert!(topology.server_ips.is_empty());
        assert!(topology.resolved_endpoints.is_empty());
    }

    #[test]
    fn disconnected_vpn_only_retains_prior_endpoint_allowances() {
        let temp = tempfile::tempdir().unwrap();
        let profile = ProfileId::new("corp");
        let executor = CanonicalPolicyExecutor::new(temp.path().into(), |_| None, || 0);
        let mut prior = target(&profile);
        prior.kill_switch = KillSwitchMode::AlwaysOn;
        let target = TopologyState {
            kill_switch: KillSwitchMode::AlwaysOn,
            ..TopologyState::default()
        };
        let policy = policy(prior, target);
        let active = executor.final_firewall_tunnels(&policy).unwrap();
        assert_eq!(active.len(), 1);
        assert!(active[0].is_endpoint_allowlist());
        assert_eq!(
            active[0].server_ips,
            vec!["203.0.113.7".parse::<std::net::IpAddr>().unwrap()]
        );
    }

    #[test]
    fn final_inputs_use_authoritative_interface_route_role_and_dns() {
        let temp = tempfile::tempdir().unwrap();
        let profile = ProfileId::new("corp");
        let session_profile = profile.clone();
        let executor = CanonicalPolicyExecutor::new(
            temp.path().into(),
            move |candidate| {
                (candidate == &session_profile).then(|| ActiveSession {
                    interface: "wg0".into(),
                    interface_authoritative: true,
                    ..ActiveSession::default()
                })
            },
            || 0,
        );
        let state = target(&profile);
        let active = executor.active_tunnels(&state, true).unwrap();
        assert_eq!(active[0].interface, "wg0");
        assert!(active[0].is_primary);
        assert_eq!(active[0].declared_cidrs[0].to_string(), "0.0.0.0/0");
        let dns = executor.dns_intents(&state).unwrap();
        assert_eq!(dns[0].interface, "wg0");
        assert_eq!(dns[0].role, DnsTunnelRole::Primary);
    }

    #[test]
    fn route_plan_deduplicates_equivalent_exact_kernel_probes() {
        let temp = tempfile::tempdir().unwrap();
        let profile = ProfileId::new("corp");
        let observed_profile = profile.clone();
        let executor = CanonicalPolicyExecutor::new(
            temp.path().into(),
            move |candidate| {
                (candidate == &observed_profile).then(|| ActiveSession {
                    interface: "wg0".into(),
                    interface_authoritative: true,
                    ..ActiveSession::default()
                })
            },
            || 0,
        );
        let mut state = target(&profile);
        state
            .routes
            .get_mut(&profile)
            .unwrap()
            .insert(RouteClaim::parse("1.1.1.0/24").unwrap());

        let plan = executor
            .route_probe_plan(&policy(TopologyState::default(), state))
            .unwrap();

        assert_eq!(plan.len(), 1);
        assert_eq!(
            plan[0].target,
            "1.1.1.1".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(plan[0].claims.len(), 2);
    }

    #[test]
    fn route_plan_rejects_unbounded_distinct_probe_work_before_execution() {
        let temp = tempfile::tempdir().unwrap();
        let profile = ProfileId::new("corp");
        let observed_profile = profile.clone();
        let executor = CanonicalPolicyExecutor::new(
            temp.path().into(),
            move |candidate| {
                (candidate == &observed_profile).then(|| ActiveSession {
                    interface: "wg0".into(),
                    interface_authoritative: true,
                    ..ActiveSession::default()
                })
            },
            || 0,
        );
        let routes = (0..=MAX_ROUTE_PROBES_PER_BARRIER)
            .map(|offset| {
                let offset = u32::try_from(offset).unwrap();
                let address = std::net::Ipv4Addr::from(0x0a00_0000_u32 + offset);
                RouteClaim::parse(&format!("{address}/32")).unwrap()
            })
            .collect();
        let mut state = target(&profile);
        state.routes.insert(profile.clone(), routes);

        let error = executor
            .route_probe_plan(&policy(TopologyState::default(), state))
            .unwrap_err();

        assert!(error.contains("more than 256 distinct probes"));
    }

    #[test]
    fn expired_route_verification_stops_before_platform_probe() {
        let temp = tempfile::tempdir().unwrap();
        let profile = ProfileId::new("corp");
        let observed_profile = profile.clone();
        let executor = CanonicalPolicyExecutor::new(
            temp.path().into(),
            move |candidate| {
                (candidate == &observed_profile).then(|| ActiveSession {
                    interface: "wg0".into(),
                    interface_authoritative: true,
                    ..ActiveSession::default()
                })
            },
            || 0,
        );
        let mut expired = policy(TopologyState::default(), target(&profile));
        expired.deadline = Instant::now();

        let error = executor.verify_routes(&expired).unwrap_err();

        assert!(error.contains("deadline expired after 0 of 1 probes"));
    }

    #[test]
    fn profile_topology_extracts_wireguard_policy_resources() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("corp.conf");
        std::fs::write(
            &path,
            "[Interface]\nPrivateKey = AAAA\nDNS = 10.0.0.53, corp.example\n[Peer]\nPublicKey = BBBB\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.7:51820\n",
        )
        .unwrap();
        let topology = topology_for_profile(
            &VpnProfile {
                id: ProfileId::new("corp"),
                name: "Corporate".into(),
                protocol: Protocol::WireGuard,
                location: String::new(),
                config_path: path,
                last_used: None,
            },
            &mut EndpointResolutionCache::default(),
        )
        .unwrap();
        assert_eq!(topology.interface_name, None);
        assert!(topology.routes.contains("0.0.0.0/0"));
        assert!(topology
            .server_ips
            .contains(&"203.0.113.7".parse().unwrap()));
        assert_eq!(topology.dns_request.search_domains, vec!["corp.example"]);
    }

    #[test]
    fn wireguard_basename_does_not_override_authoritative_macos_interface() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("corp.conf");
        std::fs::write(
            &path,
            "[Interface]\nPrivateKey = AAAA\n[Peer]\nPublicKey = BBBB\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.7:51820\n",
        )
        .unwrap();
        let profile = ProfileId::new("corp");
        let topology = topology_for_profile(
            &VpnProfile {
                id: profile.clone(),
                name: "Corporate".into(),
                protocol: Protocol::WireGuard,
                location: String::new(),
                config_path: path,
                last_used: None,
            },
            &mut EndpointResolutionCache::default(),
        )
        .unwrap();
        let observed_profile = profile.clone();
        let executor = CanonicalPolicyExecutor::new(
            temp.path().into(),
            move |candidate| {
                (candidate == &observed_profile).then(|| ActiveSession {
                    interface: "utun7".into(),
                    interface_authoritative: true,
                    ..ActiveSession::default()
                })
            },
            || 0,
        );
        let mut state = target(&profile);
        if let Some(interface) = topology.interface_name {
            state.interfaces.insert(profile, interface);
        }

        executor
            .verify_tunnels(&policy(TopologyState::default(), state))
            .unwrap();
    }

    #[test]
    fn profile_topology_extracts_openvpn_policy_resources() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("corp.ovpn");
        std::fs::write(
            &path,
            "client\nremote 203.0.113.9 1194 udp\nredirect-gateway def1\nroute 10.0.0.0 255.0.0.0\ndhcp-option DNS 10.0.0.53\n",
        )
        .unwrap();
        let topology = topology_for_profile(
            &VpnProfile {
                id: ProfileId::new("corp"),
                name: "Corporate".into(),
                protocol: Protocol::OpenVPN,
                location: String::new(),
                config_path: path,
                last_used: None,
            },
            &mut EndpointResolutionCache::default(),
        )
        .unwrap();
        assert_eq!(topology.interface_name, None);
        assert!(topology.routes.contains("0.0.0.0/0"));
        assert!(topology.routes.contains("10.0.0.0/8"));
        assert!(topology
            .server_ips
            .contains(&"203.0.113.9".parse().unwrap()));
        assert_eq!(
            topology.dns_request.servers,
            vec!["10.0.0.53".parse::<std::net::IpAddr>().unwrap()]
        );
    }
}
