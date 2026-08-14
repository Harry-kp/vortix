//! Canonical helper-owned `OpenVPN` runtime configuration.
//!
//! This module converts the already-validated privileged plan into fixed-path
//! runtime artifacts and argv, then executes only the absolute binary selected
//! by the helper's package verifier. It never selects a binary itself, and the
//! helper remains dormant until enrollment in U13.

#![allow(
    dead_code,
    reason = "U12 execution specs remain dormant until helper enrollment"
)]
#![allow(
    unsafe_code,
    reason = "foreground process-group containment requires pre_exec and exact group signals"
)]

use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter, Write as _};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;

#[cfg(unix)]
use std::os::unix::process::CommandExt as _;

use crate::vortix_core::privileged::{
    OpenVpnChallengeKind, OpenVpnPlan, OpenVpnRemoteSelection, OpenVpnTransport,
    ProfileMaterialSlot,
};

pub(crate) const CONFIG_FILE: &str = "openvpn.conf";
pub(crate) const LOG_FILE: &str = "openvpn.log";
pub(crate) const MANAGEMENT_SOCKET: &str = "m.sock";
pub(crate) const SECRET_DIRECTORY: &str = "secrets";
const FIXED_VERBOSITY: &str = "3";
const STATIC_CHALLENGE_PROMPT: &str = "Vortix second factor";
const HELPER_RESOURCE_ROOTS: [&str; 2] = ["/run/vortix/resources", "/var/run/vortix/resources"];
const RESOURCE_DIGEST_LEN: usize = 64;
const MIN_WAIT_INTERVAL: Duration = Duration::from_millis(25);
const MAX_WAIT_INTERVAL: Duration = Duration::from_millis(250);
const MATERIAL_DIRECTIVES: [MaterialDirective; 5] = [
    MaterialDirective::new(ProfileMaterialSlot::OpenVpnCaCertificate, "ca", "ca.pem"),
    MaterialDirective::new(
        ProfileMaterialSlot::OpenVpnClientCertificate,
        "cert",
        "client.crt",
    ),
    MaterialDirective::new(ProfileMaterialSlot::OpenVpnPrivateKey, "key", "client.key"),
    MaterialDirective::new(
        ProfileMaterialSlot::OpenVpnTlsAuthKey,
        "tls-auth",
        "tls-auth.key",
    ),
    MaterialDirective::new(
        ProfileMaterialSlot::OpenVpnTlsCryptKey,
        "tls-crypt",
        "tls-crypt.key",
    ),
];

#[derive(Clone, Copy)]
struct MaterialDirective {
    slot: ProfileMaterialSlot,
    directive: &'static str,
    filename: &'static str,
}

impl MaterialDirective {
    const fn new(
        slot: ProfileMaterialSlot,
        directive: &'static str,
        filename: &'static str,
    ) -> Self {
        Self {
            slot,
            directive,
            filename,
        }
    }
}

pub(crate) fn supports_material_slot(slot: ProfileMaterialSlot) -> bool {
    MATERIAL_DIRECTIVES
        .iter()
        .any(|material| material.slot == slot)
}

pub(crate) fn is_helper_material_filename(filename: &str) -> bool {
    MATERIAL_DIRECTIVES
        .iter()
        .any(|material| material.filename == filename)
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct OpenVpnExecutionSpec {
    config_path: PathBuf,
    log_path: PathBuf,
    management_socket: PathBuf,
    material_paths: BTreeMap<ProfileMaterialSlot, PathBuf>,
    config: String,
    arguments: Vec<String>,
}

impl Debug for OpenVpnExecutionSpec {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenVpnExecutionSpec")
            .field("config_bytes", &self.config.len())
            .field("argument_count", &self.arguments.len())
            .field("material_count", &self.material_paths.len())
            .finish_non_exhaustive()
    }
}

impl OpenVpnExecutionSpec {
    pub(crate) fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub(crate) fn log_path(&self) -> &Path {
        &self.log_path
    }

    pub(crate) fn management_socket(&self) -> &Path {
        &self.management_socket
    }

    pub(crate) fn material_path(&self, slot: ProfileMaterialSlot) -> Option<&Path> {
        self.material_paths.get(&slot).map(PathBuf::as_path)
    }

    pub(crate) fn material_paths(&self) -> impl Iterator<Item = &Path> {
        self.material_paths.values().map(PathBuf::as_path)
    }

    pub(crate) fn config(&self) -> &str {
        &self.config
    }

    pub(crate) fn arguments(&self) -> &[String] {
        &self.arguments
    }
}

pub(crate) fn spawn_helper_foreground(
    binary: &Path,
    execution: &OpenVpnExecutionSpec,
) -> Result<Child, OpenVpnCommandError> {
    if !binary.is_absolute()
        || execution.arguments.is_empty()
        || execution.arguments.iter().any(String::is_empty)
    {
        return Err(OpenVpnCommandError::InvalidInvocation);
    }
    let mut command = Command::new(binary);
    command
        .args(&execution.arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    // xtask:allow-platform-cfg: PR_SET_PDEATHSIG is a Linux child-setup ABI; macOS execution stays disabled
    #[cfg(target_os = "linux")]
    let helper_pid = std::process::id();
    unsafe {
        command.pre_exec(move || {
            libc::umask(0o077);
            // xtask:allow-platform-cfg: PR_SET_PDEATHSIG is a Linux child-setup ABI; macOS execution stays disabled
            #[cfg(target_os = "linux")]
            {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid()
                    != libc::pid_t::try_from(helper_pid)
                        .map_err(|_| std::io::Error::other("invalid helper process id"))?
                {
                    return Err(std::io::Error::other(
                        "helper exited before child containment armed",
                    ));
                }
            }
            Ok(())
        });
    }
    command.spawn().map_err(|_| OpenVpnCommandError::Spawn)
}

pub(crate) fn terminate_helper_foreground(
    child: &mut Child,
    timeout: Duration,
) -> Result<(), OpenVpnCommandError> {
    if timeout.is_zero() {
        return Err(OpenVpnCommandError::InvalidInvocation);
    }
    signal_helper_process_group(child.id(), HelperGroupSignal::Terminate)?;
    let deadline = Instant::now() + timeout;
    let mut wait_interval = MIN_WAIT_INTERVAL;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(wait_interval);
                wait_interval = (wait_interval * 2).min(MAX_WAIT_INTERVAL);
            }
            Ok(None) => {
                signal_helper_process_group(child.id(), HelperGroupSignal::Kill)?;
                child.wait().map_err(|_| OpenVpnCommandError::Wait)?;
                return Ok(());
            }
            Err(_) => return Err(OpenVpnCommandError::Wait),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HelperGroupSignal {
    Terminate,
    Kill,
}

pub(crate) fn signal_helper_process_group(
    pid: u32,
    signal: HelperGroupSignal,
) -> Result<(), OpenVpnCommandError> {
    let pid = libc::pid_t::try_from(pid).map_err(|_| OpenVpnCommandError::InvalidChild)?;
    let signal = match signal {
        HelperGroupSignal::Terminate => libc::SIGTERM,
        HelperGroupSignal::Kill => libc::SIGKILL,
    };
    if unsafe { libc::kill(-pid, signal) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(OpenVpnCommandError::Terminate)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum OpenVpnExecutionError {
    #[error("OpenVPN runtime directory is not a safe absolute helper path")]
    UnsafeRuntimeDirectory,
    #[error("OpenVPN helper interface name is unsafe")]
    UnsafeInterfaceName,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum OpenVpnCommandError {
    #[error("OpenVPN helper invocation is invalid")]
    InvalidInvocation,
    #[error("OpenVPN helper child could not be spawned")]
    Spawn,
    #[error("OpenVPN helper child identity is invalid")]
    InvalidChild,
    #[error("OpenVPN helper process group could not be terminated")]
    Terminate,
    #[error("OpenVPN helper child could not be reaped")]
    Wait,
}

#[cfg(test)]
fn render_helper_execution(
    plan: &OpenVpnPlan,
    runtime_directory: &Path,
) -> Result<OpenVpnExecutionSpec, OpenVpnExecutionError> {
    validate_runtime_directory(runtime_directory, &HELPER_RESOURCE_ROOTS.map(Path::new))?;
    Ok(render_validated_execution(
        plan,
        runtime_directory,
        "vxtest0",
    ))
}

/// Render beneath one already-authenticated helper resource root. The caller
/// owns verification of the root itself; this function still requires one
/// exact lower-hex resource directory directly beneath it.
pub(crate) fn render_helper_execution_under(
    plan: &OpenVpnPlan,
    runtime_directory: &Path,
    resource_root: &Path,
    interface_name: &str,
) -> Result<OpenVpnExecutionSpec, OpenVpnExecutionError> {
    if !valid_interface_name(interface_name) {
        return Err(OpenVpnExecutionError::UnsafeInterfaceName);
    }
    validate_runtime_directory(runtime_directory, &[resource_root])?;
    Ok(render_validated_execution(
        plan,
        runtime_directory,
        interface_name,
    ))
}

fn render_validated_execution(
    plan: &OpenVpnPlan,
    runtime_directory: &Path,
    interface_name: &str,
) -> OpenVpnExecutionSpec {
    let config_path = runtime_directory.join(CONFIG_FILE);
    let log_path = runtime_directory.join(LOG_FILE);
    let management_socket = runtime_directory.join(MANAGEMENT_SOCKET);
    let secret_directory = runtime_directory.join(SECRET_DIRECTORY);
    let mut material_paths = BTreeMap::new();
    let mut config = format!(
        "client\n\
         dev {interface_name}\n\
         nobind\n\
         remote-cert-tls server\n\
         script-security 0\n\
         route-noexec\n\
         pull-filter ignore \"dhcp-option DNS\"\n\
         pull-filter ignore \"dhcp-option DOMAIN\"\n\
         pull-filter ignore \"dhcp-option DOMAIN-SEARCH\"\n",
    );

    for remote in plan.remotes() {
        let endpoint = remote.endpoint();
        let host = endpoint.socket_addr().map_or_else(
            || {
                endpoint
                    .hostname()
                    .expect("validated DNS endpoint has a hostname")
                    .as_str()
                    .to_owned()
            },
            |address| address.ip().to_string(),
        );
        let transport = match remote.transport() {
            OpenVpnTransport::Udp => "udp",
            OpenVpnTransport::Tcp => "tcp-client",
        };
        writeln!(config, "remote {host} {} {transport}", endpoint.port())
            .expect("writing to String cannot fail");
    }
    if plan.remote_selection() == OpenVpnRemoteSelection::Randomized {
        config.push_str("remote-random\n");
    }

    for material in MATERIAL_DIRECTIVES {
        if !plan.materials().contains(&material.slot) {
            continue;
        }
        let path = secret_directory.join(material.filename);
        append_material_directive(&mut config, material, &path, plan.tls_auth_direction());
        material_paths.insert(material.slot, path);
    }

    let authentication = plan.authentication();
    if authentication.uses_username_password() {
        config.push_str("auth-user-pass\nauth-nocache\n");
    }
    if authentication.challenge() == Some(OpenVpnChallengeKind::Static) {
        writeln!(config, "static-challenge \"{STATIC_CHALLENGE_PROMPT}\" 0")
            .expect("writing to String cannot fail");
    }

    let mut arguments = vec![
        "--config".to_owned(),
        path_text(&config_path).to_owned(),
        "--log".to_owned(),
        path_text(&log_path).to_owned(),
        "--verb".to_owned(),
        FIXED_VERBOSITY.to_owned(),
    ];
    if authentication.uses_username_password() {
        arguments.extend([
            "--management".to_owned(),
            path_text(&management_socket).to_owned(),
            "unix".to_owned(),
            "--management-hold".to_owned(),
            "--management-query-passwords".to_owned(),
        ]);
    }

    OpenVpnExecutionSpec {
        config_path,
        log_path,
        management_socket,
        material_paths,
        config,
        arguments,
    }
}

fn valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn append_material_directive(
    config: &mut String,
    material: MaterialDirective,
    path: &Path,
    tls_auth_direction: Option<crate::vortix_core::privileged::OpenVpnKeyDirection>,
) {
    if material.slot == ProfileMaterialSlot::OpenVpnTlsAuthKey {
        if let Some(direction) = tls_auth_direction {
            writeln!(
                config,
                "{} {} {}",
                material.directive,
                path_text(path),
                direction.as_openvpn_value()
            )
            .expect("writing to String cannot fail");
            return;
        }
    }
    writeln!(config, "{} {}", material.directive, path_text(path))
        .expect("writing to String cannot fail");
}

fn validate_runtime_directory(
    path: &Path,
    resource_roots: &[&Path],
) -> Result<(), OpenVpnExecutionError> {
    for root in resource_roots {
        let Ok(relative) = path.strip_prefix(root) else {
            continue;
        };
        let mut components = relative.components();
        let Some(Component::Normal(digest)) = components.next() else {
            continue;
        };
        if components.next().is_none()
            && digest.to_str().is_some_and(|digest| {
                digest.len() == RESOURCE_DIGEST_LEN
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            return Ok(());
        }
    }
    Err(OpenVpnExecutionError::UnsafeRuntimeDirectory)
}

fn path_text(path: &Path) -> &str {
    path.to_str()
        .expect("validated helper runtime paths remain UTF-8")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::path::Path;

    use crate::vortix_core::cidr::Cidr;
    use crate::vortix_core::privileged::{
        OpenVpnAuthFactors, OpenVpnChallengeKind, OpenVpnKeyDirection, OpenVpnPlan, OpenVpnRemote,
        OpenVpnRemoteSelection, OpenVpnRoute, OpenVpnTransport, ProfileMaterialSlot,
    };
    use crate::vortix_core::profile::ProfileId;

    use super::{
        render_helper_execution, spawn_helper_foreground, terminate_helper_foreground, Duration,
        OpenVpnExecutionError,
    };

    fn profile_id() -> ProfileId {
        ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap()
    }

    fn runtime(root: &str, digit: char) -> String {
        format!("{root}/{}", digit.to_string().repeat(64))
    }

    #[test]
    fn certificate_plan_renders_minimal_foreground_execution() {
        let materials = BTreeSet::from([
            ProfileMaterialSlot::OpenVpnCaCertificate,
            ProfileMaterialSlot::OpenVpnClientCertificate,
            ProfileMaterialSlot::OpenVpnPrivateKey,
            ProfileMaterialSlot::OpenVpnTlsAuthKey,
        ]);
        let plan = OpenVpnPlan::with_materials(
            profile_id(),
            7,
            vec![
                OpenVpnRemote::dns("vpn.example.com", 1194, OpenVpnTransport::Udp).unwrap(),
                OpenVpnRemote::new(
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
                    OpenVpnTransport::Tcp,
                )
                .unwrap(),
            ],
            OpenVpnRemoteSelection::Randomized,
            OpenVpnAuthFactors::certificate(),
            vec![OpenVpnRoute::new(
                Cidr::new(Ipv4Addr::new(10, 0, 0, 0).into(), 8).unwrap(),
                None,
                None,
            )
            .unwrap()],
            materials,
        )
        .unwrap()
        .with_tls_auth_direction(OpenVpnKeyDirection::One)
        .unwrap();
        let encoded = serde_json::to_value(&plan).unwrap();
        assert_eq!(encoded["tls_auth_direction"], "one");
        let plan: OpenVpnPlan = serde_json::from_value(encoded).unwrap();

        let runtime = runtime("/run/vortix/resources", 'a');
        let execution = render_helper_execution(&plan, Path::new(&runtime))
            .expect("canonical plan should render");

        assert_eq!(
            execution.config(),
            format!(
                concat!(
                    "client\n",
                    "dev vxtest0\n",
                    "nobind\n",
                    "remote-cert-tls server\n",
                    "script-security 0\n",
                    "route-noexec\n",
                    "pull-filter ignore \"dhcp-option DNS\"\n",
                    "pull-filter ignore \"dhcp-option DOMAIN\"\n",
                    "pull-filter ignore \"dhcp-option DOMAIN-SEARCH\"\n",
                    "remote vpn.example.com 1194 udp\n",
                    "remote ::1 443 tcp-client\n",
                    "remote-random\n",
                    "ca {runtime}/secrets/ca.pem\n",
                    "cert {runtime}/secrets/client.crt\n",
                    "key {runtime}/secrets/client.key\n",
                    "tls-auth {runtime}/secrets/tls-auth.key 1\n",
                ),
                runtime = runtime
            )
        );
        assert_eq!(
            execution.arguments(),
            vec![
                "--config".to_owned(),
                format!("{runtime}/openvpn.conf"),
                "--log".to_owned(),
                format!("{runtime}/openvpn.log"),
                "--verb".to_owned(),
                "3".to_owned(),
            ]
        );
        assert!(!execution.config().contains("route 10."));
        assert!(!execution.arguments().iter().any(|arg| arg == "--daemon"));
        assert!(!execution.arguments().iter().any(|arg| arg == "--writepid"));
        let debug = format!("{execution:?}");
        assert!(!debug.contains("vpn.example.com"));
        assert!(!debug.contains("::1"));
        assert!(!debug.contains("/run/vortix"));
    }

    #[test]
    fn interactive_plan_uses_management_without_embedding_credentials() {
        let plan = OpenVpnPlan::new(
            profile_id(),
            9,
            vec![OpenVpnRemote::new(
                SocketAddr::from(([203, 0, 113, 9], 1194)),
                OpenVpnTransport::Udp,
            )
            .unwrap()],
            OpenVpnRemoteSelection::Ordered,
            OpenVpnAuthFactors::username_password()
                .with_challenge(OpenVpnChallengeKind::Static)
                .unwrap(),
            Vec::new(),
        )
        .unwrap();

        let runtime = runtime("/var/run/vortix/resources", 'b');
        let execution = render_helper_execution(&plan, Path::new(&runtime))
            .expect("interactive plan should render");

        assert!(execution.config().contains("auth-user-pass\n"));
        assert!(execution.config().contains("auth-nocache\n"));
        assert!(execution
            .config()
            .contains("static-challenge \"Vortix second factor\" 0\n"));
        assert!(execution
            .arguments()
            .windows(3)
            .any(|args| args == ["--management", &format!("{runtime}/m.sock"), "unix"]));
        assert!(!execution.config().contains("password"));
        assert!(!execution.config().contains("username"));
    }

    #[test]
    fn unsafe_runtime_directories_are_rejected_before_rendering() {
        for path in [
            "relative/path",
            "/run/vortix/bad\nplugin evil.so",
            "/run/vortix/../tmp",
            "/etc",
            "/run/vortix/resources/abc",
            "/run/vortix/resources/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "/run/vortix/resources/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/nested",
        ] {
            let plan = OpenVpnPlan::new(
                profile_id(),
                1,
                vec![OpenVpnRemote::new(
                    SocketAddr::from(([203, 0, 113, 9], 1194)),
                    OpenVpnTransport::Udp,
                )
                .unwrap()],
                OpenVpnRemoteSelection::Ordered,
                OpenVpnAuthFactors::certificate(),
                Vec::new(),
            )
            .unwrap();

            assert_eq!(
                render_helper_execution(&plan, Path::new(path)),
                Err(OpenVpnExecutionError::UnsafeRuntimeDirectory)
            );
        }
    }

    #[test]
    fn tls_crypt_uses_its_exclusive_fixed_material_slot() {
        let plan = OpenVpnPlan::with_materials(
            profile_id(),
            3,
            vec![OpenVpnRemote::dns("vpn.example.com", 443, OpenVpnTransport::Tcp).unwrap()],
            OpenVpnRemoteSelection::Ordered,
            OpenVpnAuthFactors::certificate(),
            Vec::new(),
            BTreeSet::from([
                ProfileMaterialSlot::OpenVpnCaCertificate,
                ProfileMaterialSlot::OpenVpnClientCertificate,
                ProfileMaterialSlot::OpenVpnPrivateKey,
                ProfileMaterialSlot::OpenVpnTlsCryptKey,
            ]),
        )
        .unwrap();
        assert_eq!(
            plan.clone()
                .with_tls_auth_direction(OpenVpnKeyDirection::One),
            Err(crate::vortix_core::privileged::ProtocolPlanError::InvalidMaterialSlots)
        );

        let runtime = runtime("/run/vortix/resources", 'c');
        let execution = render_helper_execution(&plan, Path::new(&runtime)).unwrap();

        assert!(execution
            .config()
            .contains(&format!("tls-crypt {runtime}/secrets/tls-crypt.key\n")));
        assert!(!execution.config().contains("tls-auth "));
        assert!(!execution.config().contains("remote-random"));
    }

    #[test]
    fn foreground_child_is_contained_and_reaped_as_one_process_group() {
        let plan = OpenVpnPlan::new(
            profile_id(),
            1,
            vec![OpenVpnRemote::new(
                SocketAddr::from(([203, 0, 113, 9], 1194)),
                OpenVpnTransport::Udp,
            )
            .unwrap()],
            OpenVpnRemoteSelection::Ordered,
            OpenVpnAuthFactors::certificate(),
            Vec::new(),
        )
        .unwrap();
        let runtime = runtime("/run/vortix/resources", 'd');
        let execution = render_helper_execution(&plan, Path::new(&runtime)).unwrap();
        let mut child = spawn_helper_foreground(Path::new("/usr/bin/yes"), &execution).unwrap();

        terminate_helper_foreground(&mut child, Duration::from_secs(1)).unwrap();
        assert!(child.try_wait().unwrap().is_some());
    }
}
