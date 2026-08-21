//! Canonical helper-owned `WireGuard` runtime configuration.
//!
//! Only validated protocol plans and descriptor-backed key material reach
//! this renderer. It produces one private `wg-quick` file beneath the fixed
//! helper runtime identity; it never accepts hooks, scripts, paths, DNS, or
//! arbitrary `WireGuard` directives from the user profile.

#![allow(
    unsafe_code,
    reason = "private process-group setup and exact containment teardown require pre_exec and kill"
)]

use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use base64::engine::{general_purpose::STANDARD as BASE64, Engine as _};
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::process::CommandExt as _;

use crate::vortix_core::privileged::{ProtocolEndpoint, WireGuardPlan};

const KEY_BYTES: usize = 32;
const ENCODED_KEY_BYTES: usize = 44;
const WAIT_INTERVAL: Duration = Duration::from_millis(25);
const WG_CANDIDATES: &[&str] = &["/usr/bin/wg"];

pub(crate) struct WireGuardMaterial<'a> {
    private_key: &'a [u8],
    preshared_keys: BTreeMap<[u8; 32], &'a [u8]>,
}

impl<'a> WireGuardMaterial<'a> {
    pub(crate) fn new(private_key: &'a [u8], preshared_keys: BTreeMap<[u8; 32], &'a [u8]>) -> Self {
        Self {
            private_key,
            preshared_keys,
        }
    }
}

pub(crate) struct WireGuardExecutionSpec {
    config_path: PathBuf,
    config: Zeroizing<String>,
}

impl Debug for WireGuardExecutionSpec {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireGuardExecutionSpec")
            .field("config_bytes", &self.config.len())
            .finish_non_exhaustive()
    }
}

impl WireGuardExecutionSpec {
    pub(crate) fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub(crate) fn config(&self) -> &[u8] {
        self.config.as_bytes()
    }
}

pub(crate) fn render_helper_execution(
    plan: &WireGuardPlan,
    config_path: &Path,
    materials: &WireGuardMaterial<'_>,
) -> Result<WireGuardExecutionSpec, WireGuardExecutionError> {
    if !config_path.is_absolute()
        || config_path.file_name().is_none()
        || config_path.extension().and_then(|value| value.to_str()) != Some("conf")
    {
        return Err(WireGuardExecutionError::UnsafeConfigPath);
    }
    let private_key = canonical_key(materials.private_key)?;
    let required_preshared = plan
        .peers()
        .iter()
        .filter_map(|peer| {
            peer.preshared_key()
                .map(crate::vortix_core::privileged::WireGuardPresharedKeyRef::peer_public_key)
        })
        .collect::<Vec<_>>();
    if required_preshared.len() != materials.preshared_keys.len()
        || required_preshared
            .iter()
            .any(|key| !materials.preshared_keys.contains_key(key))
    {
        return Err(WireGuardExecutionError::MaterialSetMismatch);
    }

    let mut config = Zeroizing::new(String::with_capacity(1024));
    config.push_str("[Interface]\nPrivateKey = ");
    config.push_str(private_key);
    config.push('\n');
    // Canonical helper mode gives one writer—the root-owned policy route
    // transaction—exclusive ownership of every AllowedIPs route.
    config.push_str("Table = off\n");
    if !plan.addresses().is_empty() {
        config.push_str("Address = ");
        write_joined(&mut config, plan.addresses().iter())?;
        config.push('\n');
    }
    let options = plan.interface_options();
    if let Some(mtu) = options.mtu() {
        writeln!(config, "MTU = {mtu}").map_err(|_| WireGuardExecutionError::Render)?;
    }
    if let Some(port) = options.listen_port() {
        writeln!(config, "ListenPort = {port}").map_err(|_| WireGuardExecutionError::Render)?;
    }
    if let Some(mark) = options.fwmark() {
        writeln!(config, "FwMark = {mark}").map_err(|_| WireGuardExecutionError::Render)?;
    }

    for peer in plan.peers() {
        config.push_str("\n[Peer]\nPublicKey = ");
        config.push_str(&BASE64.encode(peer.public_key()));
        config.push('\n');
        if let Some(key_ref) = peer.preshared_key() {
            let value = materials
                .preshared_keys
                .get(&key_ref.peer_public_key())
                .ok_or(WireGuardExecutionError::MaterialSetMismatch)?;
            config.push_str("PresharedKey = ");
            config.push_str(canonical_key(value)?);
            config.push('\n');
        }
        if let Some(endpoint) = peer.endpoint() {
            config.push_str("Endpoint = ");
            write_endpoint(&mut config, endpoint)?;
            config.push('\n');
        }
        if !peer.allowed_routes().is_empty() {
            config.push_str("AllowedIPs = ");
            write_joined(&mut config, peer.allowed_routes().iter())?;
            config.push('\n');
        }
        if let Some(seconds) = peer.persistent_keepalive_seconds() {
            writeln!(config, "PersistentKeepalive = {seconds}")
                .map_err(|_| WireGuardExecutionError::Render)?;
        }
    }

    Ok(WireGuardExecutionSpec {
        config_path: config_path.to_owned(),
        config,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WgQuickAction {
    Up,
    Down,
}

impl WgQuickAction {
    const fn argument(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
        }
    }
}

/// Run the fixed `wg-quick` lifecycle child in a private process group.
/// The binary and config paths must already be authenticated by the helper.
pub(crate) fn run_wg_quick(
    binary: &Path,
    action: WgQuickAction,
    config_path: &Path,
    timeout: Duration,
) -> Result<(), WireGuardCommandError> {
    if !binary.is_absolute() || !config_path.is_absolute() || timeout.is_zero() {
        return Err(WireGuardCommandError::InvalidInvocation);
    }
    run_bounded(
        binary,
        &[action.argument().into(), config_path.as_os_str().to_owned()],
        timeout,
    )
}

/// Read one helper-derived interface using only the fixed `wg` vocabulary.
/// The dump contains the interface private key in its first field, so the
/// complete buffer is zeroized immediately after the typed parser returns.
pub(crate) fn observe_helper_interface(
    interface_name: &str,
    generation: u64,
    timeout: Duration,
) -> Result<
    (
        crate::vortix_protocol_wireguard::tunnel::WgStatus,
        SystemTime,
    ),
    WireGuardCommandError,
> {
    if generation == 0 || !valid_interface_name(interface_name) || timeout.is_zero() {
        return Err(WireGuardCommandError::InvalidInvocation);
    }
    let output = crate::platform::fixed_root_command::run_with_timeout(
        WG_CANDIDATES,
        &["show", interface_name, "dump"],
        None,
        0,
        timeout,
    )
    .map_err(|error| match error {
        crate::platform::fixed_root_command::FixedCommandError::FailedBeforeSpawn => {
            WireGuardCommandError::Spawn
        }
        crate::platform::fixed_root_command::FixedCommandError::OutcomeUnknown => {
            WireGuardCommandError::Wait
        }
    })?;
    if !output.status.success() {
        return Err(WireGuardCommandError::NonZeroExit);
    }
    let observed_at = SystemTime::now();
    let dump = Zeroizing::new(output.stdout);
    let status = crate::vortix_protocol_wireguard::tunnel::parse_wg_dump(
        interface_name,
        &dump,
        observed_at,
        generation,
    )
    .map_err(|_| WireGuardCommandError::InvalidOutput)?;
    Ok((status, observed_at))
}

fn valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn run_bounded(
    binary: &Path,
    arguments: &[std::ffi::OsString],
    timeout: Duration,
) -> Result<(), WireGuardCommandError> {
    let mut command = Command::new(binary);
    command
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let mut child = command.spawn().map_err(|_| WireGuardCommandError::Spawn)?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) => return Err(WireGuardCommandError::NonZeroExit),
            Ok(None) if Instant::now() < deadline => thread::sleep(WAIT_INTERVAL),
            Ok(None) => {
                terminate_process_group(&mut child);
                return Err(WireGuardCommandError::Timeout);
            }
            Err(_) => {
                terminate_process_group(&mut child);
                return Err(WireGuardCommandError::Wait);
            }
        }
    }
}

fn terminate_process_group(child: &mut std::process::Child) {
    if let Ok(pid) = libc::pid_t::try_from(child.id()) {
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.wait();
}

fn canonical_key(bytes: &[u8]) -> Result<&str, WireGuardExecutionError> {
    canonical_key_parts(bytes).map(|(value, _)| value)
}

fn canonical_key_parts(bytes: &[u8]) -> Result<(&str, [u8; 32]), WireGuardExecutionError> {
    let value = std::str::from_utf8(bytes)
        .map_err(|_| WireGuardExecutionError::InvalidKeyMaterial)?
        .trim_ascii();
    if value.len() != ENCODED_KEY_BYTES {
        return Err(WireGuardExecutionError::InvalidKeyMaterial);
    }
    let decoded = Zeroizing::new(
        BASE64
            .decode(value)
            .map_err(|_| WireGuardExecutionError::InvalidKeyMaterial)?,
    );
    let key: [u8; KEY_BYTES] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| WireGuardExecutionError::InvalidKeyMaterial)?;
    let canonical = Zeroizing::new(BASE64.encode(key));
    if canonical.as_str() != value {
        return Err(WireGuardExecutionError::InvalidKeyMaterial);
    }
    Ok((value, key))
}

pub(crate) fn decode_public_key(value: &str) -> Result<[u8; 32], WireGuardExecutionError> {
    canonical_key_parts(value.as_bytes()).map(|(_, key)| key)
}

fn write_endpoint(
    output: &mut String,
    endpoint: &ProtocolEndpoint,
) -> Result<(), WireGuardExecutionError> {
    if let Some(address) = endpoint.socket_addr() {
        write!(output, "{}", CanonicalSocket(address)).map_err(|_| WireGuardExecutionError::Render)
    } else {
        let hostname = endpoint.hostname().ok_or(WireGuardExecutionError::Render)?;
        write!(output, "{}:{}", hostname.as_str(), endpoint.port())
            .map_err(|_| WireGuardExecutionError::Render)
    }
}

struct CanonicalSocket(SocketAddr);

impl std::fmt::Display for CanonicalSocket {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

fn write_joined<T: std::fmt::Display>(
    output: &mut String,
    values: impl Iterator<Item = T>,
) -> Result<(), WireGuardExecutionError> {
    for (index, value) in values.enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        write!(output, "{value}").map_err(|_| WireGuardExecutionError::Render)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum WireGuardExecutionError {
    #[error("WireGuard helper config path is unsafe")]
    UnsafeConfigPath,
    #[error("WireGuard key material is not one canonical 32-byte key")]
    InvalidKeyMaterial,
    #[error("WireGuard preshared-key material does not exactly match the plan")]
    MaterialSetMismatch,
    #[error("WireGuard helper configuration could not be rendered")]
    Render,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum WireGuardCommandError {
    #[error("WireGuard helper invocation is invalid")]
    InvalidInvocation,
    #[error("WireGuard helper child could not be spawned")]
    Spawn,
    #[error("WireGuard helper child exited unsuccessfully")]
    NonZeroExit,
    #[error("WireGuard helper child exceeded its deadline")]
    Timeout,
    #[error("WireGuard helper child could not be reaped")]
    Wait,
    #[error("WireGuard helper returned malformed status")]
    InvalidOutput,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::cidr::Cidr;
    use crate::vortix_core::privileged::{
        ProtocolEndpoint, WireGuardInterfaceOptions, WireGuardPeerPlan, WireGuardPresharedKeyRef,
    };
    use crate::vortix_core::profile::ProfileId;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    fn id() -> ProfileId {
        ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap()
    }

    fn key(byte: u8) -> String {
        BASE64.encode([byte; 32])
    }

    fn plan(with_psk: bool) -> WireGuardPlan {
        let public = [2; 32];
        let endpoint =
            ProtocolEndpoint::ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 51820)).unwrap();
        let peer = if with_psk {
            WireGuardPeerPlan::with_preshared_key(
                public,
                Some(endpoint),
                vec![Cidr::new("0.0.0.0".parse().unwrap(), 0).unwrap()],
                Some(25),
                WireGuardPresharedKeyRef::for_peer(public).unwrap(),
            )
            .unwrap()
        } else {
            WireGuardPeerPlan::new(public, Some(endpoint), Vec::new(), None).unwrap()
        };
        WireGuardPlan::new(
            id(),
            4,
            vec![Cidr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 24).unwrap()],
            vec![peer],
            WireGuardInterfaceOptions::new(Some(1420), Some(51821), Some(42)).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn canonical_plan_renders_only_allowlisted_wg_quick_vocabulary() {
        let private = key(1);
        let psk = key(3);
        let material = WireGuardMaterial::new(
            private.as_bytes(),
            BTreeMap::from([([2; 32], psk.as_bytes())]),
        );
        let execution = render_helper_execution(
            &plan(true),
            Path::new("/run/vortix/resources/abc/vxabc.conf"),
            &material,
        )
        .unwrap();
        let rendered = std::str::from_utf8(execution.config()).unwrap();

        assert_eq!(
            rendered,
            format!(
                "[Interface]\nPrivateKey = {private}\nTable = off\nAddress = 10.0.0.2/24\nMTU = 1420\nListenPort = 51821\nFwMark = 42\n\n[Peer]\nPublicKey = {}\nPresharedKey = {psk}\nEndpoint = [::1]:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n",
                key(2)
            )
        );
        for forbidden in ["DNS", "PreUp", "PostUp", "PreDown", "PostDown"] {
            assert!(!rendered.contains(forbidden));
        }
    }

    #[test]
    fn material_set_and_key_encoding_are_exact() {
        let private = key(1);
        let missing = WireGuardMaterial::new(private.as_bytes(), BTreeMap::new());
        assert_eq!(
            render_helper_execution(
                &plan(true),
                Path::new("/run/vortix/resources/abc/vxabc.conf"),
                &missing,
            )
            .unwrap_err(),
            WireGuardExecutionError::MaterialSetMismatch
        );

        let invalid = WireGuardMaterial::new(b"not-a-key", BTreeMap::new());
        assert_eq!(
            render_helper_execution(
                &plan(false),
                Path::new("/run/vortix/resources/abc/vxabc.conf"),
                &invalid,
            )
            .unwrap_err(),
            WireGuardExecutionError::InvalidKeyMaterial
        );
        assert_eq!(decode_public_key(&key(7)).unwrap(), [7; 32]);
    }

    #[test]
    fn relative_or_non_config_path_is_rejected() {
        let private = key(1);
        let material = WireGuardMaterial::new(private.as_bytes(), BTreeMap::new());
        for path in ["relative.conf", "/run/vortix/resources/abc/config.txt"] {
            assert_eq!(
                render_helper_execution(&plan(false), Path::new(path), &material).unwrap_err(),
                WireGuardExecutionError::UnsafeConfigPath
            );
        }
    }

    #[test]
    fn bounded_child_uses_deadline_and_reaps_its_process_group() {
        let started = Instant::now();
        let result = run_bounded(
            Path::new("/bin/sleep"),
            &["10".into()],
            Duration::from_millis(50),
        );

        assert_eq!(result, Err(WireGuardCommandError::Timeout));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn helper_status_rejects_option_shaped_or_oversized_interface_names() {
        for interface in ["-all", "vx/interface", "abcdefghijklmnop"] {
            assert_eq!(
                observe_helper_interface(interface, 4, Duration::from_secs(1)).unwrap_err(),
                WireGuardCommandError::InvalidInvocation
            );
        }
        assert_eq!(
            observe_helper_interface("vx-safe", 0, Duration::from_secs(1)).unwrap_err(),
            WireGuardCommandError::InvalidInvocation
        );
        assert_eq!(
            observe_helper_interface("vx-safe", 4, Duration::ZERO).unwrap_err(),
            WireGuardCommandError::InvalidInvocation
        );
    }
}
