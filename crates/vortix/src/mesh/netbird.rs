//! The `NetBird` driver: its client's commands and output, mapped onto the
//! mesh model. Nothing outside this file names `NetBird`'s CLI or formats.

use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use super::{AppInstall, Launch, MeshProfile, MeshState, MeshStatus};
use crate::tunnel::{MeshPeer, RoutedNetwork};

/// `NetBird`'s own default, pinned so every connect listens on the same port.
const WIREGUARD_PORT: u16 = 51820;

pub(super) const APP: AppInstall = AppInstall {
    state_dir: "/var/lib/netbird",
    socket: "/var/run/netbird.sock",
    identity: "default.json",
    stop: [&["service", "stop"], &["service", "uninstall"]],
};

pub(super) fn daemon(state_dir: &Path) -> Launch {
    Launch {
        program: "netbird",
        args: vec![
            "service".into(),
            "run".into(),
            "--log-file".into(),
            state_dir.join("netbird.log").to_string_lossy().into(),
        ],
        env: vec![("NB_STATE_DIR", state_dir.to_string_lossy().into())],
    }
}

pub(super) fn control(socket: &Path) -> Vec<String> {
    vec![
        "--daemon-addr".into(),
        format!("unix://{}", socket.display()),
    ]
}

pub(super) fn up(profile: &MeshProfile, key_file: Option<&Path>, interface: &str) -> Vec<String> {
    let mut args = vec![
        "up".to_string(),
        "--management-url".into(),
        profile.server_url.clone(),
        "--interface-name".into(),
        interface.into(),
        "--wireguard-port".into(),
        WIREGUARD_PORT.to_string(),
    ];
    match key_file {
        Some(key_file) => {
            args.push("--setup-key-file".into());
            args.push(key_file.to_string_lossy().into());
        }
        // Without a key, a device that must log in prints a link and waits.
        None => args.push("--no-browser".into()),
    }
    args
}

/// `NetBird`'s control-plane mark on Linux: its management, signal, relay and
/// STUN traffic, and every packet its kernel `WireGuard` socket sends.
pub(super) const MARK: u32 = 0x1BD00;

pub(super) const DOWN: &[&str] = &["down"];
pub(super) const STATUS: &[&str] = &["status", "--json"];
pub(super) const NETWORKS: &[&str] = &["networks", "list"];

/// The part of `netbird status --json` Vortix reads.
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Report {
    daemon_status: String,
    netbird_ip: String,
    management: Server,
    peers: Peers,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Server {
    url: String,
    error: String,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Peers {
    #[serde(deserialize_with = "null_as_empty")]
    details: Vec<Peer>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Peer {
    fqdn: String,
    netbird_ip: String,
    status: String,
    connection_type: String,
    transfer_received: u64,
    transfer_sent: u64,
    /// Nanoseconds.
    latency: u64,
}

/// Go encodes an empty list as `null`.
fn null_as_empty<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

pub(super) fn parse_status(json: &[u8]) -> Result<MeshStatus, String> {
    let status: Report = serde_json::from_slice(json).map_err(|error| error.to_string())?;
    let peers = &status.peers.details;
    Ok(MeshStatus {
        state: match status.daemon_status.as_str() {
            "Connected" => MeshState::Connected,
            "NeedsLogin" | "LoginFailed" | "SessionExpired" => {
                MeshState::NeedsLogin(status.daemon_status.clone())
            }
            other => MeshState::Other(other.to_string()),
        },
        address: status.netbird_ip,
        server: status
            .management
            .url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .to_string(),
        error: status.management.error,
        rx: peers.iter().map(|peer| peer.transfer_received).sum(),
        tx: peers.iter().map(|peer| peer.transfer_sent).sum(),
        peers: peers
            .iter()
            .map(|peer| MeshPeer {
                name: peer
                    .fqdn
                    .split('.')
                    .next()
                    .filter(|name| !name.is_empty())
                    .unwrap_or(&peer.netbird_ip)
                    .to_string(),
                address: peer.netbird_ip.clone(),
                connected: peer.status == "Connected",
                relayed: peer.connection_type == "Relayed",
                latency: (peer.latency > 0).then(|| Duration::from_nanos(peer.latency)),
            })
            .collect(),
    })
}

/// `netbird networks list` has no JSON: blocks of `- ID:`, then `Network:` or
/// `Domains:`, then `Status:`.
pub(super) fn parse_networks(text: &str) -> Vec<RoutedNetwork> {
    let mut networks: Vec<RoutedNetwork> = Vec::new();
    for line in text.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix("- ID: ") {
            networks.push(RoutedNetwork {
                name: name.to_string(),
                ..Default::default()
            });
        } else if let Some(network) = networks.last_mut() {
            if let Some(range) = line
                .strip_prefix("Network: ")
                .or_else(|| line.strip_prefix("Domains: "))
            {
                network.range = range.to_string();
            } else if let Some(status) = line.strip_prefix("Status: ") {
                network.selected = status == "Selected";
            }
        }
    }
    networks
}

/// The app's active network: `active_profile.json` names it, `default.json`
/// or `<user>/<id>.json` holds its identity and management server.
pub(super) fn profile_from_app(dir: &Path) -> Result<MeshProfile, String> {
    #[derive(Deserialize)]
    struct Active {
        name: String,
        #[serde(default)]
        username: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Url {
        scheme: String,
        host: String,
    }
    #[derive(Deserialize)]
    struct Config {
        #[serde(rename = "ManagementURL")]
        management_url: Url,
    }
    let active_path = dir.join("active_profile.json");
    let active = match std::fs::read(&active_path) {
        Ok(bytes) => serde_json::from_slice::<Active>(&bytes)
            .map_err(|error| format!("NetBird's active profile is unreadable: {error}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Active {
            name: "default".into(),
            username: String::new(),
        },
        Err(error) => return Err(format!("cannot read {}: {error}", active_path.display())),
    };
    let safe = |part: &str| !part.contains('/') && !part.contains("..");
    let identity = if active.name == "default" {
        dir.join(APP.identity)
    } else if safe(&active.name) && safe(&active.username) {
        dir.join(&active.username)
            .join(format!("{}.json", active.name))
    } else {
        return Err(format!(
            "NetBird's active profile has a bad name: {}",
            active.name
        ));
    };
    let bytes = std::fs::read(&identity)
        .map_err(|error| format!("cannot read {}: {error}", identity.display()))?;
    let config: Config = serde_json::from_slice(&bytes)
        .map_err(|error| format!("{} is not a NetBird profile: {error}", identity.display()))?;
    Ok(MeshProfile {
        server_url: format!(
            "{}://{}",
            config.management_url.scheme, config.management_url.host
        ),
        auth_key: None,
        identity: Some(identity),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONNECTED: &str = r#"{
        "peers": {"total": 2, "connected": 1, "details": [
            {"fqdn": "db.netbird.cloud", "netbirdIp": "100.90.1.2", "publicKey": "a=",
             "status": "Connected", "connectionType": "P2P", "transferReceived": 10,
             "transferSent": 20, "latency": 3000000, "networks": ["10.0.0.0/24"]},
            {"fqdn": "", "netbirdIp": "100.90.1.3", "publicKey": "b=", "status": "Idle"}
        ]},
        "daemonStatus": "Connected", "netbirdIp": "100.90.1.1/16",
        "management": {"url": "https://api.netbird.io:443", "connected": true, "error": ""},
        "unknownFutureField": {"x": 1}
    }"#;

    /// One short name per peer, direct or relayed, and the management server
    /// as the network's server.
    #[test]
    fn status_maps_onto_the_mesh_model() {
        let status = parse_status(CONNECTED.as_bytes()).unwrap();
        assert_eq!(status.state, MeshState::Connected);
        assert_eq!(status.address, "100.90.1.1/16");
        assert_eq!(status.server, "api.netbird.io:443");
        assert_eq!((status.rx, status.tx), (10, 20));
        assert_eq!(status.peers[0].name, "db");
        assert!(status.peers[0].connected && !status.peers[0].relayed);
        assert_eq!(status.peers[0].latency, Some(Duration::from_millis(3)));
        assert_eq!(status.peers[1].name, "100.90.1.3");
        assert!(!status.peers[1].connected);
    }

    #[test]
    fn status_names_every_login_state() {
        for state in ["NeedsLogin", "LoginFailed", "SessionExpired"] {
            let json = format!(r#"{{"daemonStatus": "{state}"}}"#);
            assert_eq!(
                parse_status(json.as_bytes()).unwrap().state,
                MeshState::NeedsLogin(state.into())
            );
        }
        let idle =
            parse_status(br#"{"daemonStatus": "Idle", "peers": {"details": null}}"#).unwrap();
        assert!(idle.peers.is_empty());
        assert_eq!(idle.state, MeshState::Other("Idle".into()));
        assert!(parse_status(b"not json").is_err());
    }

    #[test]
    fn networks_are_read_from_the_plain_list() {
        let text = "Available Networks:\n\n  - ID: office\n    Network: 10.20.0.0/16\n    Status: Selected\n\n  - ID: exit\n    Network: 0.0.0.0/0\n    Status: Not Selected\n\n  - ID: wiki\n    Domains: wiki.corp.example, git.corp.example\n    Status: Selected\n    Resolved IPs:\n      [wiki.corp.example]: 10.1.1.1\n";
        let networks = parse_networks(text);
        assert_eq!(networks.len(), 3);
        assert_eq!(
            (networks[0].name.as_str(), networks[0].range.as_str()),
            ("office", "10.20.0.0/16")
        );
        assert!(networks[0].selected && !networks[0].is_exit_node());
        assert!(!networks[1].selected && networks[1].is_exit_node());
        assert_eq!(networks[2].range, "wiki.corp.example, git.corp.example");
        assert!(parse_networks("No networks available.").is_empty());
    }

    const APP_CONFIG: &str = r#"{"PrivateKey": "secret", "ManagementURL":
        {"Scheme": "https", "Host": "nb.corp.example:443", "Path": ""}}"#;

    #[test]
    fn the_app_default_profile_is_the_one_moved() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("default.json"), APP_CONFIG).unwrap();
        let profile = profile_from_app(dir.path()).unwrap();
        assert_eq!(profile.server_url, "https://nb.corp.example:443");
        assert_eq!(profile.identity, Some(dir.path().join("default.json")));
        assert_eq!(profile.auth_key, None);
    }

    #[test]
    fn the_app_active_user_profile_is_the_one_moved() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("default.json"), "{}").unwrap();
        std::fs::create_dir(dir.path().join("alice")).unwrap();
        std::fs::write(dir.path().join("alice/work.json"), APP_CONFIG).unwrap();
        let active = |json: &str| {
            std::fs::write(dir.path().join("active_profile.json"), json).unwrap();
            profile_from_app(dir.path())
        };
        let profile = active(r#"{"name": "work", "username": "alice"}"#).unwrap();
        assert_eq!(profile.identity, Some(dir.path().join("alice/work.json")));
        assert!(active(r#"{"name": "../work", "username": "alice"}"#).is_err());
        assert!(active(r#"{"name": "default", "username": ""}"#)
            .unwrap_err()
            .contains("is not a NetBird profile"));
    }

    #[test]
    fn a_key_logs_in_and_no_key_waits_for_a_link() {
        let profile = MeshProfile {
            server_url: "https://api.netbird.io".into(),
            auth_key: None,
            identity: None,
        };
        let keyed = up(&profile, Some(Path::new("/k")), "wt0");
        assert!(keyed.ends_with(&["--setup-key-file".into(), "/k".into()]));
        assert!(up(&profile, None, "wt0").ends_with(&["--no-browser".into()]));
    }
}
