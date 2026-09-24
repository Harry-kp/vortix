//! Read each profile into the [`Spec`] the engine plans with.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::net::{IpAddr, ToSocketAddrs as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::core::cidr::Cidr;
use crate::core::openvpn_routes::OpenVpnRedirectGateway;
use crate::core::profile::{Profile, ProfileId, ProtocolKind, ResolvedEndpoint};
use crate::state::VpnProfile;

use super::state::Spec;

const MAX_PROFILE_BYTES: u64 = 4 * 1024 * 1024;
const CACHE_FILE: &str = "endpoints.json";

/// One profile, parsed.
#[derive(Debug, Clone)]
pub struct Entry {
    pub profile: VpnProfile,
    pub spec: Result<Spec, String>,
    endpoints: Vec<ResolvedEndpoint>,
}

impl Entry {
    /// The protocol-side view, pinned to the addresses resolved here so a
    /// blocked resolver cannot stop a connect.
    #[must_use]
    pub fn core_profile(&self) -> Profile {
        crate::control::tunnels::profile_view(&self.profile)
            .with_endpoint_resolutions(self.endpoints.clone())
            .require_managed_endpoint_resolution()
    }
}

/// Hostname → address answers from earlier runs, used when live resolution
/// fails (for example while `vpn-only` blocks DNS).
#[derive(Debug, Default, Serialize, Deserialize)]
struct EndpointCache(BTreeMap<String, IpAddr>);

impl EndpointCache {
    fn load(config_dir: &Path) -> Self {
        std::fs::read(config_dir.join(CACHE_FILE))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    fn save(&self, config_dir: &Path) {
        if let Ok(bytes) = serde_json::to_vec_pretty(self) {
            let _ = crate::utils::write_user_file(&config_dir.join(CACHE_FILE), &bytes);
        }
    }

    fn resolve(&mut self, host: &str, port: u16) -> Option<IpAddr> {
        if let Ok(address) = host.parse() {
            return Some(address);
        }
        let key = format!("{}:{port}", host.to_ascii_lowercase());
        let live = (host, port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut addresses| addresses.next())
            .map(|address| address.ip());
        if let Some(address) = live {
            self.0.insert(key, address);
            return Some(address);
        }
        self.0.get(&key).copied()
    }
}

/// Parse every profile. A profile that cannot be parsed stays listed with
/// its error so the UI can say why it will not connect.
#[must_use]
pub fn load(config_dir: &Path, profiles: Vec<VpnProfile>) -> BTreeMap<ProfileId, Entry> {
    let mut cache = EndpointCache::load(config_dir);
    let entries = profiles
        .into_iter()
        .map(|profile| {
            let mut endpoints = Vec::new();
            let spec = read(&profile.config_path)
                .and_then(|body| parse(&profile, &body, &mut cache, &mut endpoints));
            (
                profile.id.clone(),
                Entry {
                    profile,
                    spec,
                    endpoints,
                },
            )
        })
        .collect();
    cache.save(config_dir);
    entries
}

fn read(path: &PathBuf) -> Result<String, String> {
    let file = std::fs::File::open(path).map_err(|error| format!("open profile: {error}"))?;
    let mut body = String::new();
    file.take(MAX_PROFILE_BYTES + 1)
        .read_to_string(&mut body)
        .map_err(|error| format!("read profile: {error}"))?;
    if body.len() as u64 > MAX_PROFILE_BYTES {
        return Err("profile is larger than 4 MiB".into());
    }
    Ok(body)
}

fn parse(
    profile: &VpnProfile,
    body: &str,
    cache: &mut EndpointCache,
    endpoints: &mut Vec<ResolvedEndpoint>,
) -> Result<Spec, String> {
    let mut routes = BTreeSet::new();
    let mut server_ips = BTreeSet::new();
    let mut resolve = |host: &str, port: u16, servers: &mut BTreeSet<IpAddr>| {
        if let Some(address) = cache.resolve(host, port) {
            servers.insert(address);
            if host.parse::<IpAddr>().is_err() {
                endpoints.push(ResolvedEndpoint::new(host, port, address));
            }
        }
    };
    let (protocol, dns) = match profile.protocol {
        ProtocolKind::WireGuard => {
            let parsed =
                crate::wireguard::parser::parse_wg_conf(body).map_err(|error| error.to_string())?;
            for peer in &parsed.peers {
                routes.extend(
                    peer.allowed_ips
                        .iter()
                        .filter_map(|route| Cidr::new(route.addr, route.prefix_len)),
                );
                if let Some(endpoint) = peer.endpoint {
                    server_ips.insert(endpoint.ip());
                }
                if let (Some(host), Some(port)) = (&peer.endpoint_host, peer.endpoint_port) {
                    resolve(host, port, &mut server_ips);
                }
            }
            (ProtocolKind::WireGuard, parsed.dns_request())
        }
        ProtocolKind::OpenVpn => {
            let parsed =
                crate::openvpn::parser::parse_ovpn_conf(body).map_err(|error| error.to_string())?;
            if parsed
                .redirect_gateway
                .as_ref()
                .is_some_and(OpenVpnRedirectGateway::ipv4)
            {
                routes.insert(
                    Cidr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0).expect("v4 default"),
                );
            }
            routes.extend(parsed.routes.iter().filter_map(|route| {
                Cidr::new(route.destination.addr, route.destination.prefix_len)
            }));
            for remote in &parsed.remotes {
                resolve(&remote.host, remote.port, &mut server_ips);
            }
            (ProtocolKind::OpenVpn, parsed.dns_request())
        }
    };
    endpoints.sort();
    endpoints.dedup();
    Ok(Spec {
        profile_id: profile.id.clone(),
        name: profile.name.clone(),
        protocol,
        routes: routes.into_iter().map(Cidr::canonical_network).collect(),
        server_ips,
        dns,
    })
}
