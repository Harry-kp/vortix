//! `NetBird` mesh networks, run by Vortix through the `netbird` binary.
//!
//! Each `.netbird` profile gets its own daemon (`netbird service run`) under a
//! Vortix custodian, with its identity in a private state directory and a
//! private control socket, so it never meets `NetBird`'s own system service.
//! The daemon installs its own routes, DNS and firewall tables; Vortix plans
//! none for it.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use serde::Deserialize;

use crate::process::{CommandSpec, ManagedProcessId, PrivilegeReq};
use crate::profile::{Profile, ProfileId};
use crate::tunnel::{
    TunnelError, TunnelExecutionContext, TunnelHandle, TunnelKindTag, TunnelPeerStatus,
    TunnelStatus,
};

/// `NetBird`'s own default; pinned so the kill switch can name the port.
const WIREGUARD_PORT: u16 = 51820;
/// Root-only, like `NetBird`'s own `/var/lib/netbird`: it holds each network's identity.
const STATE_ROOT: &str = "/var/lib/vortix/netbird";
const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// What a `.netbird` profile file holds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetBirdProfile {
    pub management_url: String,
    /// Registers this device on first connect; unused once it has an identity.
    #[serde(default)]
    pub setup_key: Option<String>,
}

impl NetBirdProfile {
    pub fn parse(content: &str) -> Result<Self, String> {
        let profile: Self =
            toml::from_str(content).map_err(|error| format!("Invalid NetBird profile: {error}"))?;
        profile.management_host()?;
        Ok(profile)
    }

    /// Host and port of the management server.
    pub fn management_host(&self) -> Result<(String, u16), String> {
        let url = &self.management_url;
        let (rest, default_port) = url
            .strip_prefix("https://")
            .map(|rest| (rest, 443))
            .or_else(|| url.strip_prefix("http://").map(|rest| (rest, 80)))
            .ok_or("management_url must start with https:// or http://")?;
        let authority = rest.split('/').next().unwrap_or_default();
        let (host, port) = match authority.strip_prefix('[') {
            Some(v6) => v6.split_once(']').unwrap_or((v6, "")),
            None => authority.split_once(':').unwrap_or((authority, "")),
        };
        let port = match port.trim_start_matches(':') {
            "" => default_port,
            port => port
                .parse()
                .map_err(|_| format!("management_url has a bad port: {port}"))?,
        };
        if host.is_empty() {
            return Err("management_url has no host".into());
        }
        Ok((host.to_string(), port))
    }
}

/// The part of `netbird status --json` Vortix reads.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Status {
    pub daemon_status: String,
    pub management: Server,
    pub peers: Peers,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Server {
    pub error: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Peers {
    #[serde(deserialize_with = "null_as_empty")]
    pub details: Vec<Peer>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Peer {
    pub fqdn: String,
    pub netbird_ip: String,
    pub public_key: String,
    pub transfer_received: u64,
    pub transfer_sent: u64,
    #[serde(deserialize_with = "null_as_empty")]
    pub networks: Vec<String>,
}

/// Go encodes an empty list as `null`.
fn null_as_empty<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

impl Status {
    pub fn parse(json: &[u8]) -> Result<Self, TunnelError> {
        serde_json::from_slice(json)
            .map_err(|error| TunnelError::MalformedStatus(format!("netbird status: {error}")))
    }

    #[must_use]
    pub fn connected(&self) -> bool {
        self.daemon_status == "Connected"
    }

    /// The daemon has no identity, or the network refused the one it has.
    #[must_use]
    pub fn needs_login(&self) -> bool {
        matches!(
            self.daemon_status.as_str(),
            "NeedsLogin" | "LoginFailed" | "SessionExpired"
        )
    }

    fn tunnel_peers(&self, generation: u64, observed_at: SystemTime) -> Vec<TunnelPeerStatus> {
        self.peers
            .details
            .iter()
            .map(|peer| TunnelPeerStatus {
                public_key: peer.public_key.clone(),
                endpoint: (!peer.fqdn.is_empty()).then(|| peer.fqdn.clone()),
                allowed_routes: std::iter::once(peer.netbird_ip.clone())
                    .chain(peer.networks.iter().cloned())
                    .filter(|route| !route.is_empty())
                    .collect(),
                latest_handshake: None,
                evidence_observed_at: observed_at,
                evidence_generation: generation,
                persistent_keepalive: None,
                bytes_rx: peer.transfer_received,
                bytes_tx: peer.transfer_sent,
            })
            .collect()
    }
}

/// The `NetBird` transport for one connect or disconnect.
#[derive(Debug, Clone)]
pub struct NbTunnel {
    connect_timeout: Duration,
    generation: Option<u64>,
    execution_context: Option<TunnelExecutionContext>,
}

impl NbTunnel {
    #[must_use]
    pub fn new(connect_timeout_secs: u64) -> Self {
        Self {
            connect_timeout: Duration::from_secs(connect_timeout_secs),
            generation: None,
            execution_context: None,
        }
    }

    #[must_use]
    pub fn for_generation(mut self, generation: u64) -> Self {
        self.generation = Some(generation);
        self
    }

    #[must_use]
    pub fn with_execution_context(mut self, context: TunnelExecutionContext) -> Self {
        self.execution_context = Some(context);
        self
    }

    fn remaining(&self) -> Result<Duration, TunnelError> {
        let Some(context) = &self.execution_context else {
            return Ok(self.connect_timeout);
        };
        if context.cancellation.is_cancelled() {
            return Err(TunnelError::Cancelled);
        }
        let remaining = self
            .connect_timeout
            .min(context.deadline.saturating_duration_since(Instant::now()));
        if remaining.is_zero() {
            return Err(TunnelError::Timeout(self.connect_timeout));
        }
        Ok(remaining)
    }

    pub fn up(&mut self, profile: &Profile) -> Result<TunnelHandle, TunnelError> {
        self.remaining()?;
        let content = std::fs::read_to_string(&profile.config_path)?;
        let settings = NetBirdProfile::parse(&content).map_err(TunnelError::Other)?;
        let binary = binary()?;
        let state_dir = Path::new(STATE_ROOT).join(profile.id.digest_key(8));
        create_private_dir(&state_dir)?;
        let socket = socket_path(&profile.id);
        let _ = std::fs::remove_file(&socket);

        let mut identity = ManagedProcessId::generate(profile.id.clone())
            .map_err(|error| TunnelError::Subprocess(format!("allocate ownership: {error}")))?;
        if let Some(generation) = self.generation {
            identity.generation = generation;
        }
        let mut daemon = command(
            &binary,
            &socket,
            [
                "service",
                "run",
                "--log-file",
                &state_dir.join("netbird.log").to_string_lossy(),
            ],
        );
        daemon
            .env
            .insert("NB_STATE_DIR".into(), state_dir.to_string_lossy().into());
        let custody = crate::process::custodian::spawn_custodian(
            identity.clone(),
            daemon,
            vec![socket.clone()],
            None,
        )
        .map_err(|error| TunnelError::Subprocess(format!("netbird custody: {error}")))?;

        let started = (|| {
            wait_for(&socket, self.remaining()?)?;
            let before = status(&binary, &socket)?;
            // A fresh daemon reports Idle, not NeedsLogin, so the key goes with
            // every connect; NetBird logs a registered peer in by its own key.
            let key_file = match &settings.setup_key {
                Some(key) => Some(write_key_file(&state_dir, key)?),
                None if before.needs_login() => {
                    return Err(TunnelError::AuthFailed(format!(
                        "'{}' has no NetBird identity yet: add `setup_key` to its profile",
                        profile.display_name
                    )));
                }
                None => None,
            };
            let mut args = vec![
                "up".to_string(),
                "--management-url".into(),
                settings.management_url.clone(),
                "--interface-name".into(),
                crate::platform::NETBIRD_INTERFACE.into(),
                "--wireguard-port".into(),
                WIREGUARD_PORT.to_string(),
            ];
            if let Some(key_file) = &key_file {
                args.push("--setup-key-file".into());
                args.push(key_file.to_string_lossy().into());
            }
            let mut up = command(&binary, &socket, args);
            up.timeout = Some(self.remaining()?);
            let outcome = crate::process::run(up);
            if let Some(key_file) = &key_file {
                let _ = std::fs::remove_file(key_file);
            }
            let outcome = outcome.map_err(|error| TunnelError::Subprocess(error.to_string()))?;
            let after = status(&binary, &socket)?;
            if !outcome.success() || !after.connected() {
                return Err(up_failure(
                    &after,
                    &String::from_utf8_lossy(&outcome.stderr),
                ));
            }
            Ok(())
        })();
        if let Err(error) = started {
            return Err(
                match crate::process::custodian::remote_stop_after_startup(&custody) {
                    Ok(()) => error,
                    Err(stop) => TunnelError::Subprocess(format!(
                        "{error}; stopping the NetBird daemon also failed: {stop}"
                    )),
                },
            );
        }
        Ok(TunnelHandle {
            profile_id: profile.id.clone(),
            display_name: profile.display_name.clone(),
            interface_name: crate::platform::NETBIRD_INTERFACE.into(),
            pid: Some(custody.pid),
            started_at: SystemTime::now(),
            kind: TunnelKindTag::NetBird,
            generation: identity.generation,
            handshake: None,
            probe_receipts: Vec::new(),
            process_ownership: Some(identity),
            teardown_config: None,
            dns_request: crate::control::dns::DnsRequest::default(),
            openvpn_routes: None,
        })
    }

    pub fn down(&mut self, handle: &TunnelHandle) -> Result<(), TunnelError> {
        let identity = match handle.process_ownership.clone() {
            Some(identity) => Some(identity),
            None => crate::process::custodian::load_identity(&handle.profile_id)
                .map_err(|error| TunnelError::Subprocess(format!("NetBird ownership: {error}")))?,
        };
        let Some(identity) = identity else {
            return Ok(());
        };
        // Stopping the daemon also takes the network down; `down` first
        // makes that quick enough for the custodian's grace period.
        if let Ok(binary) = binary() {
            let mut down = command(&binary, &socket_path(&handle.profile_id), ["down"]);
            down.timeout = Some(Duration::from_secs(10));
            let _ = crate::process::run(down);
        }
        crate::process::custodian::remote_stop(&identity).map_err(|error| {
            TunnelError::Subprocess(format!("NetBird daemon did not stop: {error}"))
        })
    }

    pub fn status(&self, handle: &TunnelHandle) -> Result<TunnelStatus, TunnelError> {
        if let Some(identity) = &handle.process_ownership {
            let alive = crate::process::custodian::remote_status(identity)
                .map_err(|error| TunnelError::Subprocess(format!("NetBird custody: {error}")))?;
            if !alive {
                return Err(TunnelError::DaemonExited(
                    "the NetBird daemon exited".into(),
                ));
            }
        }
        let observed_at = SystemTime::now();
        let status = status(&binary()?, &socket_path(&handle.profile_id))?;
        let peers = status.tunnel_peers(handle.generation, observed_at);
        Ok(TunnelStatus {
            handle: handle.clone(),
            bytes_rx: peers.iter().map(|peer| peer.bytes_rx).sum(),
            bytes_tx: peers.iter().map(|peer| peer.bytes_tx).sum(),
            last_handshake: None,
            observed_at,
            peers,
        })
    }
}

/// The custodian's receipt for a daemon Vortix started earlier, if it is still
/// running.
#[must_use]
pub fn running_owner(profile_id: &ProfileId) -> Option<crate::process::CustodianHandshake> {
    let custody = crate::process::custodian::load_handshake(profile_id).ok()??;
    crate::process::custodian::remote_status(&custody.identity)
        .unwrap_or(false)
        .then_some(custody)
}

/// One socket per profile, outside `/var/run/netbird/`, where the `netbird`
/// CLI looks for a daemon on its own.
fn socket_path(profile_id: &ProfileId) -> PathBuf {
    PathBuf::from(format!(
        "/var/run/vortix-netbird-{}.sock",
        profile_id.digest_key(8)
    ))
}

fn binary() -> Result<PathBuf, TunnelError> {
    crate::platform::find_binary_path("netbird")
        .ok_or_else(|| {
            TunnelError::Subprocess(
                "netbird was not found on PATH (install it: https://docs.netbird.io/get-started/install)"
                    .into(),
            )
        })?
        .canonicalize()
        .map_err(TunnelError::Io)
}

fn command<I, S>(binary: &Path, socket: &Path, args: I) -> CommandSpec
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter().map(Into::into).collect::<Vec<String>>();
    args.push("--daemon-addr".into());
    args.push(format!("unix://{}", socket.display()));
    let mut spec =
        CommandSpec::oneshot(binary.to_string_lossy(), args).privilege(PrivilegeReq::Root);
    spec.env_clear = true;
    spec.env.insert("PATH".into(), PATH.into());
    spec
}

fn status(binary: &Path, socket: &Path) -> Result<Status, TunnelError> {
    let mut spec = command(binary, socket, ["status", "--json"]);
    spec.timeout = Some(Duration::from_secs(10));
    let outcome =
        crate::process::run(spec).map_err(|error| TunnelError::Subprocess(error.to_string()))?;
    if !outcome.success() {
        return Err(TunnelError::Subprocess(format!(
            "netbird status: {}",
            String::from_utf8_lossy(&outcome.stderr).trim()
        )));
    }
    Status::parse(&outcome.stdout)
}

fn up_failure(status: &Status, stderr: &str) -> TunnelError {
    if status.needs_login() {
        return TunnelError::AuthFailed(format!(
            "NetBird refused this device ({})",
            status.daemon_status
        ));
    }
    if !status.management.error.is_empty() {
        return TunnelError::Subprocess(format!(
            "NetBird management server: {}",
            status.management.error
        ));
    }
    let detail = stderr.trim();
    TunnelError::Subprocess(if detail.is_empty() {
        format!("NetBird did not connect ({})", status.daemon_status)
    } else {
        format!("netbird up: {detail}")
    })
}

fn wait_for(socket: &Path, timeout: Duration) -> Result<(), TunnelError> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if socket.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(TunnelError::Timeout(timeout))
}

fn create_private_dir(dir: &Path) -> Result<(), TunnelError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn write_key_file(state_dir: &Path, key: &str) -> Result<PathBuf, TunnelError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let path = state_dir.join("setup-key");
    let _ = std::fs::remove_file(&path);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?
        .write_all(key.trim().as_bytes())?;
    Ok(path)
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

    #[test]
    fn status_reads_connected_daemon_and_peers() {
        let status = Status::parse(CONNECTED.as_bytes()).unwrap();
        assert!(status.connected());
        assert!(!status.needs_login());
        let peers = status.tunnel_peers(7, SystemTime::UNIX_EPOCH);
        assert_eq!(peers[0].endpoint.as_deref(), Some("db.netbird.cloud"));
        assert_eq!(peers[0].allowed_routes, ["100.90.1.2", "10.0.0.0/24"]);
        assert_eq!((peers[0].bytes_rx, peers[0].bytes_tx), (10, 20));
        assert_eq!(peers[1].endpoint, None);
        assert!(peers.iter().all(|peer| peer.evidence_generation == 7));
    }

    #[test]
    fn status_names_every_login_state() {
        for state in ["NeedsLogin", "LoginFailed", "SessionExpired"] {
            let json = format!(r#"{{"daemonStatus": "{state}"}}"#);
            let status = Status::parse(json.as_bytes()).unwrap();
            assert!(status.needs_login() && !status.connected(), "{state}");
            assert!(matches!(
                up_failure(&status, ""),
                TunnelError::AuthFailed(_)
            ));
        }
        let idle =
            Status::parse(br#"{"daemonStatus": "Idle", "peers": {"details": null}}"#).unwrap();
        assert!(idle.peers.details.is_empty());
        assert!(!idle.needs_login());
        assert!(Status::parse(b"not json").is_err());
    }

    #[test]
    fn up_failure_prefers_the_management_error() {
        let status = Status::parse(
            br#"{"daemonStatus": "Connecting", "management": {"error": "dial tcp: refused"}}"#,
        )
        .unwrap();
        assert!(up_failure(&status, "ignored")
            .to_string()
            .contains("dial tcp: refused"));
        let status = Status::parse(br#"{"daemonStatus": "Connecting"}"#).unwrap();
        assert!(up_failure(&status, "context deadline exceeded\n")
            .to_string()
            .ends_with("netbird up: context deadline exceeded"));
    }

    #[test]
    fn profile_parses_management_host_and_port() {
        let host = |url: &str| {
            NetBirdProfile::parse(&format!("management_url = \"{url}\""))
                .and_then(|profile| profile.management_host())
        };
        assert_eq!(
            host("https://api.netbird.io").unwrap(),
            ("api.netbird.io".into(), 443)
        );
        assert_eq!(
            host("https://nb.corp:33073/x").unwrap(),
            ("nb.corp".into(), 33073)
        );
        assert_eq!(host("http://10.0.0.5").unwrap(), ("10.0.0.5".into(), 80));
        assert_eq!(
            host("https://[fd00::1]:8443").unwrap(),
            ("fd00::1".into(), 8443)
        );
        assert!(host("ftp://x").is_err());
        assert!(host("https://").is_err());
        assert!(host("https://nb.corp:port").is_err());
        assert!(NetBirdProfile::parse("management_url = \"https://a\"\nsetupkey = \"x\"").is_err());
        let keyed =
            NetBirdProfile::parse("management_url = \"https://a\"\nsetup_key = \"K\"").unwrap();
        assert_eq!(keyed.setup_key.as_deref(), Some("K"));
    }
}
