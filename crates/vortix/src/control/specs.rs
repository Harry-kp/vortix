//! Read each profile into the [`Spec`] the engine plans with.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::net::{IpAddr, ToSocketAddrs as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::cidr::Cidr;
use crate::config::profiles::VpnProfile;
use crate::control::dns::DnsRequest;
use crate::openvpn::routes::OpenVpnRedirectGateway;
use crate::profile::{Profile, ProfileId, ProtocolKind, ResolvedEndpoint};

use super::state::Spec;

const MAX_PROFILE_BYTES: u64 = 4 * 1024 * 1024;
const CACHE_FILE: &str = "endpoints.json";
/// How long one hostname lookup may take before the cached address is used. A resolver behind a
/// dead tunnel or a blocking kill switch otherwise holds every load for its full timeout.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

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
        let p = &self.profile;
        Profile::new(p.id.clone(), &p.name, p.protocol, p.config_path.clone())
            .with_endpoint_resolutions(self.endpoints.clone())
            .require_managed_endpoint_resolution()
    }
}

/// Hostname → address answers from earlier runs, used when live resolution
/// fails (for example while `vpn-only` blocks DNS).
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
struct EndpointCache {
    addresses: BTreeMap<String, IpAddr>,
    /// Set after one lookup times out, so the rest of this load uses cached addresses at once.
    #[serde(skip)]
    resolver_down: bool,
}

impl EndpointCache {
    fn load(config_dir: &Path) -> Self {
        std::fs::read(config_dir.join(CACHE_FILE))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    fn save(&self, config_dir: &Path) {
        if let Ok(bytes) = serde_json::to_vec_pretty(self) {
            let _ =
                crate::config::owned_file::write_user_file_atomic(config_dir, CACHE_FILE, &bytes);
        }
    }

    fn resolve(&mut self, host: &str, port: u16) -> Option<IpAddr> {
        if let Ok(address) = host.parse() {
            return Some(address);
        }
        let key = format!("{}:{port}", host.to_ascii_lowercase());
        // With a cached address to fall back on, a resolver may not hold the load for longer
        // than LOOKUP_TIMEOUT; without one, wait for the answer however slow.
        let live = match self.addresses.get(&key) {
            Some(_) if self.resolver_down => None,
            Some(_) => lookup(host, port).unwrap_or_else(|_| {
                self.resolver_down = true;
                None
            }),
            None => resolve_now(host, port),
        };
        if let Some(address) = live {
            self.addresses.insert(key, address);
            return Some(address);
        }
        self.addresses.get(&key).copied()
    }
}

fn resolve_now(host: &str, port: u16) -> Option<IpAddr> {
    (host, port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addresses| addresses.next())
        .map(|address| address.ip())
}

/// [`resolve_now`], or an error if the resolver gave no answer within [`LOOKUP_TIMEOUT`].
// ponytail: a lookup that times out keeps its thread until the OS resolver gives up; at most one
// per load, since a timeout stops the rest of the load from asking.
fn lookup(host: &str, port: u16) -> Result<Option<IpAddr>, std::sync::mpsc::RecvTimeoutError> {
    let (tx, rx) = std::sync::mpsc::channel();
    let host = host.to_owned();
    std::thread::spawn(move || {
        let _ = tx.send(resolve_now(&host, port));
    });
    rx.recv_timeout(LOOKUP_TIMEOUT)
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
    let mut group = None;
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
                routes.extend(peer.allowed_ips.iter().copied());
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
            routes.extend(parsed.routes.iter().map(|route| route.destination));
            for remote in &parsed.remotes {
                resolve(&remote.host, remote.port, &mut server_ips);
            }
            (ProtocolKind::OpenVpn, parsed.dns_request())
        }
        // The daemon installs its own routes and DNS.
        ProtocolKind::Mesh(driver) => {
            let (host, port) = crate::mesh::MeshProfile::parse(body)?.server()?;
            resolve(&host, port, &mut server_ips);
            group = Some(crate::control::killswitch::TRANSPORT_GROUP);
            (ProtocolKind::Mesh(driver), DnsRequest::default())
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
        group,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache_with(entry: &str) -> EndpointCache {
        serde_json::from_str(entry).unwrap()
    }

    /// The daemon owns its routes and DNS; Vortix only needs the management server.
    #[test]
    fn a_mesh_profile_plans_no_routes_or_dns() {
        let profile = VpnProfile {
            id: ProfileId::new("a".repeat(64)),
            name: "mesh".into(),
            protocol: ProtocolKind::Mesh(crate::mesh::MeshDriver::NetBird),
            location: String::new(),
            config_path: PathBuf::new(),
            last_used: None,
            group: None,
        };
        let spec = parse(
            &profile,
            "server_url = \"https://127.0.0.1:33073\"\nauth_key = \"K\"",
            &mut EndpointCache::default(),
            &mut Vec::new(),
        )
        .unwrap();
        assert!(spec.routes.is_empty());
        assert!(spec.dns.is_empty());
        assert_eq!(
            spec.group,
            Some(crate::control::killswitch::TRANSPORT_GROUP)
        );
        assert_eq!(
            spec.server_ips.into_iter().collect::<Vec<_>>(),
            ["127.0.0.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn the_cache_file_keeps_its_format() {
        let cache = cache_with(r#"{"vpn.example.com:51820":"203.0.113.7"}"#);
        assert_eq!(
            cache.addresses.get("vpn.example.com:51820"),
            Some(&"203.0.113.7".parse().unwrap())
        );
        assert_eq!(
            serde_json::to_string(&cache).unwrap(),
            r#"{"vpn.example.com:51820":"203.0.113.7"}"#
        );
    }

    /// Without a cached address there is nothing to fall back to: wait for the answer, however slow.
    #[test]
    fn an_uncached_host_is_resolved_even_after_a_timeout() {
        let mut cache = EndpointCache {
            resolver_down: true,
            ..EndpointCache::default()
        };
        let address = cache.resolve("localhost", 51820).unwrap();
        assert!(address.is_loopback(), "{address}");
    }

    #[test]
    fn a_working_resolver_wins_over_the_cache() {
        let mut cache = cache_with(r#"{"localhost:51820":"10.9.9.9"}"#);
        let address = cache.resolve("localhost", 51820).unwrap();
        assert!(address.is_loopback(), "{address}");
    }

    /// With the resolver behind a dead tunnel, every lookup waited out its timeout and the
    /// dashboard took 20 s to start. After one timeout the load stops asking.
    #[test]
    fn a_resolver_that_timed_out_is_not_asked_again() {
        let mut cache = cache_with(r#"{"localhost:51820":"10.9.9.9"}"#);
        cache.resolver_down = true;
        assert_eq!(
            cache.resolve("localhost", 51820),
            Some("10.9.9.9".parse().unwrap())
        );
    }
}
