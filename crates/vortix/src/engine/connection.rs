//! Blocking connection lifecycle for CLI use.
//!
//! These methods block the calling thread until the operation completes,
//! making them suitable for CLI commands (as opposed to the async/channel
//! pattern used by the TUI event loop).

use std::time::{Duration, Instant};

use crate::constants;
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

        std::thread::spawn(move || {
            let output = match protocol {
                Protocol::WireGuard => std::process::Command::new("wg-quick")
                    .args(["down", config_path.to_str().unwrap_or("")])
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .output(),
                Protocol::OpenVPN => {
                    let target_pid = utils::read_openvpn_pid(&pn).or(pid);
                    let signal = if force { "-9" } else { "-15" };
                    let kill_result = if let Some(p) = target_pid {
                        let result = std::process::Command::new("kill")
                            .args([signal, &p.to_string()])
                            .stdout(std::process::Stdio::piped())
                            .stderr(std::process::Stdio::piped())
                            .output();

                        // `kill` returns success when the signal is delivered, but
                        // the daemon may still be alive. Poll until it's gone.
                        if result.as_ref().is_ok_and(|o| o.status.success()) {
                            let deadline = Instant::now()
                                + Duration::from_secs(constants::OVPN_KILL_WAIT_SECS);
                            while Instant::now() < deadline {
                                std::thread::sleep(Duration::from_millis(200));
                                let alive = std::process::Command::new("kill")
                                    .args(["-0", &p.to_string()])
                                    .output()
                                    .is_ok_and(|o| o.status.success());
                                if !alive {
                                    break;
                                }
                            }
                        }
                        result
                    } else {
                        let safe = utils::sanitize_profile_name(&pn);
                        std::process::Command::new("pkill")
                            .args([signal, "-f", &format!("openvpn.*--daemon vortix-{safe}")])
                            .stdout(std::process::Stdio::piped())
                            .stderr(std::process::Stdio::piped())
                            .output()
                    };
                    kill_result
                }
            };

            match output {
                Ok(out) if out.status.success() => {
                    if matches!(protocol, Protocol::OpenVPN) {
                        utils::cleanup_openvpn_run_files(&pn);
                    }
                    let _ = cmd_tx.send(Message::DisconnectResult {
                        profile: pn,
                        success: true,
                        error: None,
                    });
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                    let _ = cmd_tx.send(Message::DisconnectResult {
                        profile: pn,
                        success: false,
                        error: Some(stderr),
                    });
                }
                Err(e) => {
                    let _ = cmd_tx.send(Message::DisconnectResult {
                        profile: pn,
                        success: false,
                        error: Some(format!("Failed to execute: {e}")),
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
    #[allow(clippy::too_many_lines)]
    fn run_connect(
        name: &str,
        protocol: Protocol,
        config_path: &std::path::Path,
        connect_timeout_secs: u64,
        ovpn_verbosity: &str,
        cmd_tx: &std::sync::mpsc::Sender<Message>,
    ) {
        let name = name.to_string();
        let config_path_str = config_path.to_str().unwrap_or("").to_string();
        let ovpn_verbosity = ovpn_verbosity.to_string();
        let cmd_tx = cmd_tx.clone();

        match protocol {
            Protocol::WireGuard => {
                match std::process::Command::new("wg-quick")
                    .args(["up", &config_path_str])
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .output()
                {
                    Ok(out) if out.status.success() => {
                        let _ = cmd_tx.send(Message::ConnectResult {
                            profile: name,
                            success: true,
                            error: None,
                        });
                    }
                    Ok(out) => {
                        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                        let _ = cmd_tx.send(Message::ConnectResult {
                            profile: name,
                            success: false,
                            error: Some(format!("WireGuard: {stderr}")),
                        });
                    }
                    Err(e) => {
                        let _ = cmd_tx.send(Message::ConnectResult {
                            profile: name,
                            success: false,
                            error: Some(format!("Failed to execute wg-quick: {e}")),
                        });
                    }
                }
            }
            Protocol::OpenVPN => {
                let run_paths = utils::get_openvpn_run_paths(&name);
                let (pid_path, log_path) = match run_paths {
                    Ok(paths) => paths,
                    Err(e) => {
                        let _ = cmd_tx.send(Message::ConnectResult {
                            profile: name,
                            success: false,
                            error: Some(format!("Failed to create run directory: {e}")),
                        });
                        return;
                    }
                };

                let _ = std::fs::remove_file(&pid_path);
                let _ = std::fs::remove_file(&log_path);

                let safe_name = utils::sanitize_profile_name(&name);
                let mut args = vec![
                    "--config".to_string(),
                    config_path_str,
                    "--daemon".to_string(),
                    format!("vortix-{safe_name}"),
                    "--writepid".to_string(),
                    pid_path.to_str().unwrap_or("").to_string(),
                    "--log".to_string(),
                    log_path.to_str().unwrap_or("").to_string(),
                    "--verb".to_string(),
                    ovpn_verbosity,
                ];

                if let Ok(auth_path) = utils::get_openvpn_auth_path(&name) {
                    if auth_path.exists() {
                        args.push("--auth-user-pass".to_string());
                        args.push(auth_path.to_str().unwrap_or("").to_string());
                    }
                }

                let output = std::process::Command::new("openvpn")
                    .args(&args)
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .output();

                match output {
                    Ok(out) if !out.status.success() => {
                        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                        let error_detail = if stderr.trim().is_empty() {
                            std::fs::read_to_string(&log_path)
                                .ok()
                                .filter(|s| !s.trim().is_empty())
                                .map_or_else(
                                    || "unknown error (no stderr or log output)".to_string(),
                                    |log| {
                                        log.lines()
                                            .rev()
                                            .take(constants::OVPN_ERROR_LOG_TAIL_LINES)
                                            .collect::<Vec<_>>()
                                            .into_iter()
                                            .rev()
                                            .collect::<Vec<_>>()
                                            .join("\n")
                                    },
                                )
                        } else {
                            stderr.trim().to_string()
                        };
                        let _ = cmd_tx.send(Message::ConnectResult {
                            profile: name,
                            success: false,
                            error: Some(format!("OpenVPN: {error_detail}")),
                        });
                        return;
                    }
                    Err(e) => {
                        let _ = cmd_tx.send(Message::ConnectResult {
                            profile: name,
                            success: false,
                            error: Some(format!("Failed to start OpenVPN: {e}")),
                        });
                        return;
                    }
                    Ok(_) => {}
                }

                std::thread::sleep(Duration::from_millis(constants::OVPN_CHOWN_DELAY_MS));
                crate::config::fix_ownership(
                    pid_path.parent().unwrap_or(std::path::Path::new("/")),
                );

                let timeout = Duration::from_secs(connect_timeout_secs);
                let poll_interval = Duration::from_millis(constants::OVPN_LOG_POLL_MS);
                let start = Instant::now();

                loop {
                    std::thread::sleep(poll_interval);

                    if start.elapsed()
                        > Duration::from_secs(constants::OVPN_HEALTH_CHECK_DELAY_SECS)
                    {
                        if let Ok(content) = std::fs::read_to_string(&pid_path) {
                            if let Ok(pid) = content.trim().parse::<u32>() {
                                let alive = std::process::Command::new("kill")
                                    .args(["-0", &pid.to_string()])
                                    .output()
                                    .is_ok_and(|o| o.status.success());
                                if !alive {
                                    let log =
                                        std::fs::read_to_string(&log_path).unwrap_or_default();
                                    let last_lines: String = log
                                        .lines()
                                        .rev()
                                        .take(constants::OVPN_ERROR_LOG_TAIL_LINES)
                                        .collect::<Vec<_>>()
                                        .into_iter()
                                        .rev()
                                        .collect::<Vec<_>>()
                                        .join("\n");
                                    let _ = cmd_tx.send(Message::ConnectResult {
                                        profile: name,
                                        success: false,
                                        error: Some(format!(
                                            "OpenVPN daemon exited:\n{last_lines}"
                                        )),
                                    });
                                    return;
                                }
                            }
                        } else if start.elapsed()
                            > Duration::from_secs(constants::OVPN_PID_FILE_TIMEOUT_SECS)
                        {
                            let log = std::fs::read_to_string(&log_path)
                                .unwrap_or_else(|_| "No log output".to_string());
                            let _ = cmd_tx.send(Message::ConnectResult {
                                profile: name,
                                success: false,
                                error: Some(format!("OpenVPN: no PID file. Log:\n{log}")),
                            });
                            return;
                        }
                    }

                    if let Ok(log_content) = std::fs::read_to_string(&log_path) {
                        if log_content.contains(constants::OVPN_LOG_SUCCESS) {
                            let _ = cmd_tx.send(Message::ConnectResult {
                                profile: name,
                                success: true,
                                error: None,
                            });
                            return;
                        }

                        for pattern in constants::OVPN_LOG_ERRORS {
                            if log_content.contains(pattern) {
                                let error_line = log_content
                                    .lines()
                                    .find(|l| l.contains(pattern))
                                    .unwrap_or(pattern);
                                let _ = cmd_tx.send(Message::ConnectResult {
                                    profile: name,
                                    success: false,
                                    error: Some(format!("OpenVPN: {error_line}")),
                                });
                                return;
                            }
                        }
                    }

                    if start.elapsed() >= timeout {
                        let _ = cmd_tx.send(Message::ConnectResult {
                            profile: name.clone(),
                            success: false,
                            error: Some(format!(
                                "Connection timed out after {connect_timeout_secs}s"
                            )),
                        });
                        return;
                    }
                }
            }
        }
    }
}
