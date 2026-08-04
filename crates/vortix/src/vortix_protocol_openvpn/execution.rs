//! Canonical helper-owned `OpenVPN` runtime configuration.
//!
//! This module converts the already-validated privileged plan into fixed-path
//! runtime artifacts and argv. It deliberately does not choose or execute a
//! binary: the helper's package verifier owns that decision, and the helper
//! remains dormant until enrollment in U13.

#![allow(
    dead_code,
    reason = "U12 execution specs remain dormant until helper enrollment"
)]

use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter, Write as _};
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

use crate::vortix_core::privileged::{
    OpenVpnChallengeKind, OpenVpnPlan, OpenVpnRemoteSelection, OpenVpnTransport,
    ProfileMaterialSlot,
};

const CONFIG_FILE: &str = "openvpn.conf";
const LOG_FILE: &str = "openvpn.log";
const MANAGEMENT_SOCKET: &str = "m.sock";
const SECRET_DIRECTORY: &str = "secrets";
const FIXED_VERBOSITY: &str = "3";
const STATIC_CHALLENGE_PROMPT: &str = "Vortix second factor";
const HELPER_RESOURCE_ROOTS: [&str; 2] = ["/run/vortix/resources", "/var/run/vortix/resources"];
const RESOURCE_DIGEST_LEN: usize = 64;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum OpenVpnExecutionError {
    #[error("OpenVPN runtime directory is not a safe absolute helper path")]
    UnsafeRuntimeDirectory,
}

pub(crate) fn render_helper_execution(
    plan: &OpenVpnPlan,
    runtime_directory: &Path,
) -> Result<OpenVpnExecutionSpec, OpenVpnExecutionError> {
    validate_runtime_directory(runtime_directory, &HELPER_RESOURCE_ROOTS.map(Path::new))?;
    Ok(render_validated_execution(plan, runtime_directory))
}

/// Render beneath one already-authenticated helper resource root. The caller
/// owns verification of the root itself; this function still requires one
/// exact lower-hex resource directory directly beneath it.
pub(crate) fn render_helper_execution_under(
    plan: &OpenVpnPlan,
    runtime_directory: &Path,
    resource_root: &Path,
) -> Result<OpenVpnExecutionSpec, OpenVpnExecutionError> {
    validate_runtime_directory(runtime_directory, &[resource_root])?;
    Ok(render_validated_execution(plan, runtime_directory))
}

fn render_validated_execution(
    plan: &OpenVpnPlan,
    runtime_directory: &Path,
) -> OpenVpnExecutionSpec {
    let config_path = runtime_directory.join(CONFIG_FILE);
    let log_path = runtime_directory.join(LOG_FILE);
    let management_socket = runtime_directory.join(MANAGEMENT_SOCKET);
    let secret_directory = runtime_directory.join(SECRET_DIRECTORY);
    let mut material_paths = BTreeMap::new();
    let mut config = String::from(
        "client\n\
         dev tun\n\
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

    let arguments = vec![
        "--config".to_owned(),
        path_text(&config_path).to_owned(),
        "--log".to_owned(),
        path_text(&log_path).to_owned(),
        "--verb".to_owned(),
        FIXED_VERBOSITY.to_owned(),
        "--management".to_owned(),
        path_text(&management_socket).to_owned(),
        "unix".to_owned(),
        "--management-hold".to_owned(),
        "--management-query-passwords".to_owned(),
    ];

    OpenVpnExecutionSpec {
        config_path,
        log_path,
        management_socket,
        material_paths,
        config,
        arguments,
    }
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

    use super::{render_helper_execution, OpenVpnExecutionError};

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
                    "dev tun\n",
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
                "--management".to_owned(),
                format!("{runtime}/m.sock"),
                "unix".to_owned(),
                "--management-hold".to_owned(),
                "--management-query-passwords".to_owned(),
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
}
