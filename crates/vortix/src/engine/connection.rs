//! Blocking connection lifecycle for CLI use.
//!
//! These methods block the calling thread until the operation completes,
//! making them suitable for CLI commands (as opposed to the async/channel
//! pattern used by the TUI event loop).

use std::time::{Duration, Instant};

use crate::core::scanner;
use crate::message::Message;
use crate::state::{ConnectionState, DetailedConnectionInfo, Protocol};
use crate::utils;

use super::VpnEngine;

/// Result of a CLI connect operation.
#[derive(Debug)]
pub struct ConnectResult {
    pub profile: String,
    pub protocol: Protocol,
    pub success: bool,
    pub error: Option<String>,
}

/// Result of a CLI status scan.
#[derive(Debug)]
pub struct StatusSnapshot {
    pub connection_state: String,
    pub profile: Option<String>,
    pub protocol: Option<String>,
    pub uptime_secs: Option<u64>,
    pub public_ip: Option<String>,
    pub server: Option<String>,
    pub interface: Option<String>,
    pub internal_ip: Option<String>,
    pub latency_ms: Option<u64>,
    pub jitter_ms: Option<u64>,
    pub packet_loss_pct: Option<f32>,
    pub quality: Option<String>,
    pub download_bytes: Option<String>,
    pub upload_bytes: Option<String>,
    pub killswitch_mode: String,
    pub killswitch_state: String,
    pub dns_leak: Option<bool>,
    pub ipv6_leak: Option<bool>,
    pub encryption: Option<String>,
    pub location: Option<String>,
    pub isp: Option<String>,
}

impl VpnEngine {
    /// Validate preconditions for a connect and return profile metadata.
    fn validate_connect(
        &self,
        profile_name: &str,
    ) -> Result<(String, Protocol, std::path::PathBuf), String> {
        let idx = self
            .find_profile(profile_name)
            .ok_or_else(|| format!("Profile '{profile_name}' not found"))?;

        let profile = &self.profiles[idx];
        let name = profile.name.clone();
        let protocol = profile.protocol;
        let config_path = profile.config_path.clone();

        let missing = Self::check_dependencies(protocol, &config_path);
        if !missing.is_empty() {
            return Err(format!(
                "Missing dependencies: {}. Install with: {}",
                missing.join(", "),
                missing
                    .iter()
                    .map(|m| crate::platform::install_hint(m))
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }

        if !self.is_root {
            return Err(
                "VPN operations require root privileges. Re-run with: sudo vortix up".into(),
            );
        }

        if matches!(protocol, Protocol::OpenVPN)
            && utils::openvpn_config_needs_auth(&config_path)
            && utils::read_openvpn_saved_auth(&name).is_none()
        {
            return Err(format!(
                "OpenVPN profile '{name}' requires auth credentials. \
                 Save credentials via the TUI first, or provide an auth-user-pass file in the config."
            ));
        }

        Ok((name, protocol, config_path))
    }

    /// Blocking connect for CLI — waits until connected or timeout.
    pub fn connect_and_wait(
        &mut self,
        profile_name: &str,
        timeout: Duration,
    ) -> Result<ConnectResult, String> {
        let (name, protocol, config_path) = self.validate_connect(profile_name)?;

        let cmd_tx = self.cmd_tx.clone();
        let connect_timeout_secs = timeout.as_secs();
        let ovpn_verbosity = self.config.openvpn_verbosity.clone();
        let name_for_thread = name.clone();

        std::thread::spawn(move || {
            Self::run_connect(
                &name_for_thread,
                protocol,
                &config_path,
                connect_timeout_secs,
                &ovpn_verbosity,
                &cmd_tx,
            );
        });

        self.connection_state = ConnectionState::Connecting {
            started: Instant::now(),
            profile: name.clone(),
        };

        let deadline = Instant::now() + timeout + Duration::from_secs(5);
        loop {
            match self.cmd_rx.recv_timeout(Duration::from_millis(500)) {
                Ok(Message::ConnectResult {
                    profile,
                    success,
                    error,
                }) => {
                    if success {
                        self.connection_state = ConnectionState::Connected {
                            profile: profile.clone(),
                            server_location: self
                                .profiles
                                .iter()
                                .find(|p| p.name == profile)
                                .map_or_else(|| "Unknown".into(), |p| p.location.clone()),
                            since: Instant::now(),
                            latency_ms: 0,
                            details: Box::new(DetailedConnectionInfo::default()),
                        };
                        self.session_start = Some(Instant::now());
                        self.last_connected_profile = Some(profile.clone());

                        if let Some(p) = self.profiles.iter_mut().find(|p| p.name == name) {
                            p.last_used = Some(std::time::SystemTime::now());
                        }
                        self.save_metadata();
                        self.sync_killswitch();
                    } else {
                        self.connection_state = ConnectionState::Disconnected;
                        self.cleanup_vpn_resources(&profile);
                    }

                    return Ok(ConnectResult {
                        profile,
                        protocol,
                        success,
                        error,
                    });
                }
                Ok(_) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if Instant::now() >= deadline {
                        self.cleanup_vpn_resources(&name);
                        self.connection_state = ConnectionState::Disconnected;
                        return Ok(ConnectResult {
                            profile: name,
                            protocol,
                            success: false,
                            error: Some(format!(
                                "Connection timed out after {connect_timeout_secs}s"
                            )),
                        });
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("Internal channel disconnected".into());
                }
            }
        }
    }

    /// Blocking disconnect for CLI.
    #[allow(clippy::too_many_lines)]
    pub fn disconnect_and_wait(&mut self, force: bool, timeout: Duration) -> Result<(), String> {
        let (profile_name, protocol, config_path, pid) = match &self.connection_state {
            ConnectionState::Connected {
                profile, details, ..
            } => {
                let p = self.profiles.iter().find(|p| p.name == *profile);
                if let Some(prof) = p {
                    (
                        profile.clone(),
                        prof.protocol,
                        prof.config_path.clone(),
                        details.pid,
                    )
                } else {
                    return Err(format!("Profile '{profile}' not found in loaded profiles"));
                }
            }
            ConnectionState::Disconnected => return Ok(()), // Idempotent
            ConnectionState::Connecting { profile, .. } => {
                let p = self.profiles.iter().find(|p| p.name == *profile);
                if let Some(prof) = p {
                    (
                        profile.clone(),
                        prof.protocol,
                        prof.config_path.clone(),
                        None,
                    )
                } else {
                    return Err("Cannot disconnect: profile not found".into());
                }
            }
            ConnectionState::Disconnecting { .. } => {
                return Err("Already disconnecting".into());
            }
        };

        let cmd_tx = self.cmd_tx.clone();
        let pn = profile_name.clone();

        self.connection_state = ConnectionState::Disconnecting {
            started: Instant::now(),
            profile: profile_name.clone(),
        };

        // Plan #004 U4: a single Tunnel::down call replaces the previous
        // ~80-line per-protocol match arm. The interface name carried on the
        // synthetic handle preserves the existing wg-quick semantics
        // (config-path-based lookup) for WireGuard.
        let iface_for_handle = match protocol {
            Protocol::WireGuard => config_path.to_string_lossy().into_owned(),
            Protocol::OpenVPN => format!("openvpn-{}", utils::sanitize_profile_name(&pn)),
        };
        let pid_for_handle = match protocol {
            Protocol::OpenVPN => utils::read_openvpn_pid(&pn).or(pid),
            Protocol::WireGuard => None,
        };
        let _ = force; // SIGTERM vs SIGKILL handled inside OvpnTunnel::down today.

        std::thread::spawn(move || {
            use crate::vortix_core::ports::tunnel::{TunnelHandle, TunnelKindTag};
            use crate::vortix_core::profile::ProfileId;

            let handle = TunnelHandle {
                profile_id: ProfileId::new(&pn),
                interface_name: iface_for_handle,
                pid: pid_for_handle,
                started_at: std::time::SystemTime::now(),
                kind: match protocol {
                    Protocol::WireGuard => TunnelKindTag::WireGuard,
                    Protocol::OpenVPN => TunnelKindTag::OpenVpn,
                },
            };

            let config_dir = crate::utils::get_app_config_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));
            let mut tunnel = crate::tunnel::tunnel_for(protocol, &config_dir, "3", 30);

            match tunnel.down(handle) {
                Ok(()) => {
                    if matches!(protocol, Protocol::OpenVPN) {
                        utils::cleanup_openvpn_run_files(&pn);
                    }
                    let _ = cmd_tx.send(Message::DisconnectResult {
                        profile: pn,
                        success: true,
                        error: None,
                    });
                }
                Err(err) => {
                    let _ = cmd_tx.send(Message::DisconnectResult {
                        profile: pn,
                        success: false,
                        error: Some(format!("{protocol}: {err}")),
                    });
                }
            }
        });

        // Block and wait
        let deadline = Instant::now() + timeout;
        loop {
            match self.cmd_rx.recv_timeout(Duration::from_millis(500)) {
                Ok(Message::DisconnectResult { success, error, .. }) => {
                    self.connection_state = ConnectionState::Disconnected;
                    self.session_start = None;
                    self.sync_killswitch();

                    if success {
                        return Ok(());
                    }
                    return Err(error.unwrap_or_else(|| "Disconnect failed".into()));
                }
                Ok(_) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if Instant::now() >= deadline {
                        self.cleanup_vpn_resources(&profile_name);
                        self.connection_state = ConnectionState::Disconnected;
                        self.session_start = None;
                        return Err("Disconnect timed out".into());
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("Internal channel disconnected".into());
                }
            }
        }
    }

    /// One-shot status scan for CLI.
    #[must_use]
    pub fn scan_status(&self) -> StatusSnapshot {
        let active = scanner::get_active_profiles(&self.profiles);
        let session = active.first();

        let (state, profile, protocol, uptime, server, interface, internal_ip, dl, ul, encryption) =
            if let Some(s) = session {
                let proto = self
                    .profiles
                    .iter()
                    .find(|p| p.name == s.name)
                    .map(|p| p.protocol);

                let enc = match proto {
                    Some(Protocol::WireGuard) => Some("ChaCha20-Poly1305".into()),
                    Some(Protocol::OpenVPN) => Some("AES-256-GCM".into()),
                    None => None,
                };

                let uptime = s.started_at.and_then(|started| {
                    std::time::SystemTime::now()
                        .duration_since(started)
                        .ok()
                        .map(|d| d.as_secs())
                });

                (
                    "connected".to_string(),
                    Some(s.name.clone()),
                    proto.map(|p| format!("{p}")),
                    uptime,
                    if s.endpoint.is_empty() {
                        None
                    } else {
                        Some(s.endpoint.clone())
                    },
                    if s.interface.is_empty() {
                        None
                    } else {
                        Some(s.interface.clone())
                    },
                    if s.internal_ip.is_empty() {
                        None
                    } else {
                        Some(s.internal_ip.clone())
                    },
                    if s.transfer_rx.is_empty() {
                        None
                    } else {
                        Some(s.transfer_rx.clone())
                    },
                    if s.transfer_tx.is_empty() {
                        None
                    } else {
                        Some(s.transfer_tx.clone())
                    },
                    enc,
                )
            } else {
                (
                    "disconnected".to_string(),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            };

        StatusSnapshot {
            connection_state: state,
            profile,
            protocol,
            uptime_secs: uptime,
            public_ip: None, // requires telemetry worker; populated by caller if needed
            server,
            interface,
            internal_ip,
            latency_ms: None,
            jitter_ms: None,
            packet_loss_pct: None,
            quality: None,
            download_bytes: dl,
            upload_bytes: ul,
            killswitch_mode: format!("{:?}", self.killswitch_mode).to_lowercase(),
            killswitch_state: format!("{:?}", self.killswitch_state).to_lowercase(),
            dns_leak: None,
            ipv6_leak: None,
            encryption,
            location: None,
            isp: None,
        }
    }

    /// Internal: run the VPN connect subprocess (shared between TUI and CLI paths).
    ///
    /// Plan #004 U4: a single call to `TunnelKind::up` replaces the previous
    /// 200-line per-protocol match arm. Routing happens once in
    /// [`crate::tunnel::tunnel_for`].
    fn run_connect(
        name: &str,
        protocol: Protocol,
        config_path: &std::path::Path,
        connect_timeout_secs: u64,
        ovpn_verbosity: &str,
        cmd_tx: &std::sync::mpsc::Sender<Message>,
    ) {
        use crate::vortix_core::profile::{ProfileId, ProtocolKind};

        let name = name.to_string();
        let cmd_tx = cmd_tx.clone();
        let config_dir =
            crate::utils::get_app_config_dir().unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));

        let profile = crate::vortix_core::profile::Profile::new(
            ProfileId::new(&name),
            &name,
            match protocol {
                Protocol::WireGuard => ProtocolKind::WireGuard,
                Protocol::OpenVPN => ProtocolKind::OpenVpn,
            },
            config_path.to_path_buf(),
        );

        let mut tunnel =
            crate::tunnel::tunnel_for(protocol, &config_dir, ovpn_verbosity, connect_timeout_secs);

        match tunnel.up(&profile) {
            Ok(_handle) => {
                let _ = cmd_tx.send(Message::ConnectResult {
                    profile: name,
                    success: true,
                    error: None,
                });
            }
            Err(err) => {
                let _ = cmd_tx.send(Message::ConnectResult {
                    profile: name,
                    success: false,
                    error: Some(format!("{protocol}: {err}")),
                });
            }
        }
    }
}
