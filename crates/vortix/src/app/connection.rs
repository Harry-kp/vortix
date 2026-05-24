//! VPN connection lifecycle management and kill switch control.

use std::time::Instant;

use super::{App, ConnectionState, InputMode, Protocol, ToastType};
use crate::constants;
use crate::message::Message;
use crate::utils;

impl App {
    /// Smart connection toggle: Connect, Disconnect, or Switch.
    ///
    /// Uses `pending_connect` to queue a connection that fires automatically
    /// after the current disconnect completes, avoiding the race condition
    /// of starting connect while disconnect is still in-flight.
    pub(crate) fn toggle_connection(&mut self, idx: usize) {
        // Cancel any in-flight retry/auto-reconnect when user initiates a new action
        self.retry_count = 0;
        self.retry_profile_idx = None;
        self.auto_reconnect_profile = None;

        if let Some(target_profile) = self.profiles.get(idx) {
            let target_name = target_profile.name.clone();
            match &self.connection_state {
                // If connecting, ignore to prevent races
                ConnectionState::Connecting { .. } => {}
                // If disconnecting, queue the connection for after disconnect completes
                ConnectionState::Disconnecting { .. } => {
                    if let Some(old) = self.pending_connect {
                        if old != idx {
                            if let Some(old_profile) = self.profiles.get(old) {
                                self.log(&format!(
                                    "ACTION: Switched queue from '{}' to '{target_name}'",
                                    old_profile.name
                                ));
                            }
                        }
                    }
                    self.pending_connect = Some(idx);
                }
                ConnectionState::Connected {
                    profile: current_name,
                    ..
                } => {
                    if *current_name == target_name {
                        self.pending_connect = None;
                        self.disconnect();
                    } else {
                        self.input_mode = InputMode::ConfirmSwitch {
                            from: current_name.clone(),
                            to_idx: idx,
                            to_name: target_name,
                            confirm_selected: true,
                        };
                    }
                }
                // If disconnected -> Connect immediately
                ConnectionState::Disconnected => {
                    self.connect_profile(idx);
                }
            }
        }
    }

    /// Check if required binaries are available for a given protocol.
    /// Uses `which` to locate binaries — avoids running them directly since
    /// some tools (e.g. `wg-quick --version`) hang on macOS.
    fn check_dependencies(protocol: Protocol, config_path: &std::path::Path) -> Vec<String> {
        let mut missing = Vec::new();
        match protocol {
            Protocol::WireGuard => {
                if !utils::binary_exists("wg-quick") {
                    missing.push("wg-quick".to_string());
                }
                if !utils::binary_exists("wg") {
                    missing.push("wireguard-tools".to_string());
                }
                // On Linux, wg-quick uses `resolvconf` to set DNS when the
                // config contains a DNS directive.  We must verify that a
                // working resolvconf is present — `openresolv` installed on
                // a systemd-resolved system will exist but fail at runtime
                // with "signature mismatch".
                #[cfg(target_os = "linux")]
                if utils::wireguard_config_has_dns(config_path) && !utils::resolvconf_works() {
                    // Point the user to the right package for their system.
                    if utils::is_systemd_resolved() {
                        missing.push("resolvconf (systemd)".to_string());
                    } else {
                        missing.push("resolvconf".to_string());
                    }
                }
                #[cfg(not(target_os = "linux"))]
                let _ = config_path; // suppress unused warning on non-Linux
            }
            Protocol::OpenVPN => {
                if !utils::binary_exists("openvpn") {
                    missing.push("openvpn".to_string());
                }
            }
        }
        missing
    }

    /// Check for system-wide dependencies at startup and warn the user.
    pub(crate) fn check_system_dependencies(&mut self) {
        let mut missing: Vec<&str> = Vec::new();

        if !utils::binary_exists("curl") {
            missing.push("curl");
        }

        if !utils::binary_exists("openvpn") {
            missing.push("openvpn");
        }

        if !utils::binary_exists("wg-quick") {
            missing.push("wg-quick");
        }

        if missing.is_empty() {
            return;
        }

        for tool in &missing {
            self.log(&format!(
                "WARN: '{}' not found - run: {}",
                tool,
                crate::platform::install_hint(tool)
            ));
        }

        self.show_toast(
            format!(
                "Missing tools: {}. Telemetry/VPN features may not work.",
                missing.join(", ")
            ),
            ToastType::Warning,
        );
    }

    /// Connect to a profile
    #[allow(clippy::too_many_lines)]
    pub(crate) fn connect_profile(&mut self, idx: usize) {
        // Clone needed data to release borrow on self
        let (name, protocol, config_path, cmd_tx) = if let Some(profile) = self.profiles.get(idx) {
            (
                profile.name.clone(),
                profile.protocol,
                profile.config_path.clone(),
                self.cmd_tx.clone(),
            )
        } else {
            return;
        };

        // Check dependencies FIRST (no point asking for root if tool is missing)
        let missing = Self::check_dependencies(protocol, &config_path);
        if !missing.is_empty() {
            self.input_mode = InputMode::DependencyError { protocol, missing };
            return;
        }

        // Check root second
        if !self.is_root {
            self.input_mode = InputMode::PermissionDenied {
                action: format!("Manage {protocol}"),
            };
            return;
        }

        // Check if OpenVPN config needs auth credentials
        if matches!(protocol, Protocol::OpenVPN) && utils::openvpn_config_needs_auth(&config_path) {
            // Check for saved credentials first
            if utils::read_openvpn_saved_auth(&name).is_none() {
                // No saved creds -- show the auth prompt overlay
                self.input_mode = InputMode::AuthPrompt {
                    profile_idx: idx,
                    profile_name: name,
                    username: String::new(),
                    username_cursor: 0,
                    password: String::new(),
                    password_cursor: 0,
                    focused_field: crate::state::AuthField::Username,
                    save_credentials: true,
                    connect_after: true,
                };
                return;
            }
            // Saved creds exist -- they'll be picked up in the thread below
        }

        // Start connecting
        self.connection_state = ConnectionState::Connecting {
            started: Instant::now(),
            profile: name.clone(),
        };
        self.log(&format!("ACTION: Connecting to '{name}' [{protocol}]..."));

        let connect_timeout_secs = self.config.connect_timeout;
        let ovpn_verbosity = self.config.openvpn_verbosity.clone();

        // Execute command in background to prevent TUI freeze
        std::thread::spawn(move || match protocol {
            Protocol::WireGuard => {
                // wg-quick is a one-shot command: sets up interface and exits
                match std::process::Command::new("wg-quick")
                    .args(["up", config_path.to_str().unwrap_or("")])
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
                let run_paths = crate::utils::get_openvpn_run_paths(&name);
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

                // Clean up stale files from previous runs
                let _ = std::fs::remove_file(&pid_path);
                let _ = std::fs::remove_file(&log_path);

                let safe_name = crate::utils::sanitize_profile_name(&name);

                // Build openvpn args
                let mut args = vec![
                    "--config".to_string(),
                    config_path.to_str().unwrap_or("").to_string(),
                    "--daemon".to_string(),
                    format!("vortix-{safe_name}"),
                    "--writepid".to_string(),
                    pid_path.to_str().unwrap_or("").to_string(),
                    "--log".to_string(),
                    log_path.to_str().unwrap_or("").to_string(),
                    "--verb".to_string(),
                    ovpn_verbosity,
                ];

                // If auth credentials exist, pass them via --auth-user-pass
                if let Ok(auth_path) = crate::utils::get_openvpn_auth_path(&name) {
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
                            // `--daemon --log` redirects all output away from stderr.
                            // On pre-fork failures (missing certs, bad options) stderr
                            // is empty — fall back to the log file for the real error.
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
                    Ok(_) => {} // Fork succeeded, daemon is running
                }

                // Chown the run files so normal users can read PID/log status.
                std::thread::sleep(std::time::Duration::from_millis(
                    constants::OVPN_CHOWN_DELAY_MS,
                ));
                crate::config::fix_ownership(
                    pid_path.parent().unwrap_or(std::path::Path::new("/")),
                );

                // Poll the log file for definitive success/failure from the daemon.
                let timeout = std::time::Duration::from_secs(connect_timeout_secs);
                let poll_interval = std::time::Duration::from_millis(constants::OVPN_LOG_POLL_MS);
                let start = std::time::Instant::now();

                loop {
                    std::thread::sleep(poll_interval);

                    // Check if the daemon died (pid file gone or process not running)
                    if start.elapsed()
                        > std::time::Duration::from_secs(constants::OVPN_HEALTH_CHECK_DELAY_SECS)
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
                            > std::time::Duration::from_secs(constants::OVPN_PID_FILE_TIMEOUT_SECS)
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

                    // Read the log file and check for markers
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
                                "Connection timed out after {connect_timeout_secs}s waiting for handshake"
                            )),
                        });
                        return;
                    }
                }
            }
        });
    }

    /// Synchronizes the kill switch state with the current mode and connection status.
    /// This is the single source of truth for kill switch state transitions and firewall control.
    pub(crate) fn sync_killswitch(&mut self) {
        use crate::state::{KillSwitchMode, KillSwitchState};

        let old_state = self.killswitch_state;

        // 1. Determine the target state
        self.killswitch_state = match self.killswitch_mode {
            KillSwitchMode::Off => KillSwitchState::Disabled,
            KillSwitchMode::Auto => {
                if matches!(self.connection_state, ConnectionState::Connected { .. }) {
                    KillSwitchState::Armed
                } else if old_state == KillSwitchState::Blocking {
                    KillSwitchState::Blocking
                } else {
                    KillSwitchState::Armed
                }
            }
            KillSwitchMode::AlwaysOn => {
                if matches!(self.connection_state, ConnectionState::Connected { .. }) {
                    KillSwitchState::Armed
                } else {
                    KillSwitchState::Blocking
                }
            }
        };

        // 2. Refuse Blocking state when not running as root — firewall rules
        //    require elevated privileges and the UI must not claim a security
        //    posture that isn't enforced.
        if self.killswitch_state.is_blocking() && !self.is_root {
            self.killswitch_state = KillSwitchState::Armed;
            self.show_toast(
                "Kill switch requires root — run with sudo".to_string(),
                ToastType::Warning,
            );
            self.log("WARN: Kill switch blocked — not running as root");
        }

        // 3. Sync physical firewall state if target state changed or if forcing sync
        if self.killswitch_state != old_state || self.killswitch_state == KillSwitchState::Blocking
        {
            if self.killswitch_state.is_blocking() {
                let (interface, server_ip) = match &self.connection_state {
                    ConnectionState::Connected { details, .. } => (
                        details.interface.as_str(),
                        Some(details.endpoint.split(':').next().unwrap_or("")),
                    ),
                    _ => (crate::platform::DEFAULT_VPN_INTERFACE, None),
                };

                if let Err(e) = crate::core::killswitch::enable_blocking(interface, server_ip) {
                    self.log(&format!("WARN: Failed to enable kill switch: {e}"));
                }
            } else if old_state.is_blocking() {
                if let Err(e) = crate::core::killswitch::disable_blocking() {
                    self.log(&format!("WARN: Failed to release kill switch: {e}"));
                }
            }
        }

        // 4. Persist state
        let _ = crate::core::killswitch::save_state(
            self.killswitch_mode,
            self.killswitch_state,
            None,
            None,
        );
    }

    /// Kill any running VPN process and remove run files for a profile.
    pub(crate) fn cleanup_vpn_resources(&self, profile_name: &str) {
        if let Some(profile) = self.profiles.iter().find(|p| p.name == profile_name) {
            match profile.protocol {
                Protocol::OpenVPN => {
                    if let Some(pid) = utils::read_openvpn_pid(profile_name) {
                        let _ = std::process::Command::new("kill")
                            .arg(pid.to_string())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .output();
                    }
                    utils::cleanup_openvpn_run_files(profile_name);
                }
                Protocol::WireGuard => {
                    let _ = std::process::Command::new("wg-quick")
                        .args(["down", profile.config_path.to_str().unwrap_or("")])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .output();
                }
            }
        }
    }

    /// Finalize a disconnect: transition to `Disconnected`, sync kill switch,
    /// and drain `pending_connect` (auto-connect to the queued profile, if any).
    pub(crate) fn complete_disconnect(&mut self, profile_name: &str) {
        self.session_start = None;
        self.scanner_rx = None; // discard stale scanner data pre-disconnect
        self.panel_flipped.clear();
        self.flip_animation = None;

        self.public_ip = crate::constants::MSG_DETECTING.to_string();
        self.location = crate::constants::MSG_DETECTING.to_string();
        self.isp = crate::constants::MSG_DETECTING.to_string();
        self.dns_server = crate::constants::MSG_DETECTING.to_string();
        self.ipv6_leak = false;
        self.latency_ms = 0;
        self.packet_loss = 0.0;
        self.jitter_ms = 0;
        self.last_security_check = None;
        self.ip_unchanged_warned = false;
        self.current_down = 0;
        self.current_up = 0;

        // Clean up OpenVPN runtime files if this was an OpenVPN profile
        if self
            .profiles
            .iter()
            .any(|p| p.name == profile_name && matches!(p.protocol, Protocol::OpenVPN))
        {
            crate::utils::cleanup_openvpn_run_files(profile_name);
        }

        // Drain pending_connect: switch directly to the next profile
        if let Some(idx) = self.pending_connect.take() {
            if idx < self.profiles.len() {
                let next_name = self.profiles[idx].name.clone();
                self.log(&format!(
                    "STATUS: Disconnected from '{profile_name}', connecting to '{next_name}'..."
                ));
                self.connection_state = ConnectionState::Disconnected;
                self.sync_killswitch();
                self.connect_profile(idx);
                return;
            }
        }

        // Normal disconnect (no pending switch)
        self.log(&format!("STATUS: Disconnected from '{profile_name}'"));
        self.connection_state = ConnectionState::Disconnected;
        self.sync_killswitch();
        self.refresh_telemetry();
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn disconnect(&mut self) {
        self.retry_count = 0;
        self.retry_profile_idx = None;
        self.auto_reconnect_profile = None;
        // Discard any in-flight scanner result captured before this disconnect;
        // stale data showing the interface "up" would otherwise re-promote to
        // Connected and trigger a spurious "VPN dropped" auto-reconnect.
        self.scanner_rx = None;
        // Extract connection info from Connected or Connecting state
        let connection_info = match &self.connection_state {
            ConnectionState::Connected {
                profile: ref profile_name,
                details,
                ..
            } => self
                .profiles
                .iter()
                .find(|p| p.name == *profile_name)
                .map(|profile| {
                    (
                        profile.name.clone(),
                        profile.protocol,
                        profile.config_path.clone(),
                        details.pid,
                        self.cmd_tx.clone(),
                    )
                }),
            ConnectionState::Connecting {
                profile: ref profile_name,
                ..
            } => self
                .profiles
                .iter()
                .find(|p| p.name == *profile_name)
                .map(|profile| {
                    (
                        profile.name.clone(),
                        profile.protocol,
                        profile.config_path.clone(),
                        None, // no PID yet while connecting
                        self.cmd_tx.clone(),
                    )
                }),
            _ => None,
        };

        if let Some((profile_name, protocol, config_path, pid, cmd_tx)) = connection_info {
            self.log(&format!("ACTION: Disconnecting from '{profile_name}'..."));

            // Set disconnecting state
            self.connection_state = ConnectionState::Disconnecting {
                started: Instant::now(),
                profile: profile_name.clone(),
            };

            // KILL SWITCH: Sync state after changing connection state
            self.sync_killswitch();

            if self.killswitch_state.is_blocking() {
                self.show_toast(
                    "Kill Switch blocking - Strict mode active".to_string(),
                    ToastType::Warning,
                );
            }

            std::thread::spawn(move || {
                let output = match protocol {
                    Protocol::WireGuard => std::process::Command::new("wg-quick")
                        .args(["down", config_path.to_str().unwrap_or("")])
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .output(),
                    Protocol::OpenVPN => {
                        let target_pid = crate::utils::read_openvpn_pid(&profile_name).or(pid);
                        if let Some(p) = target_pid {
                            std::process::Command::new("kill")
                                .arg(p.to_string())
                                .stdout(std::process::Stdio::piped())
                                .stderr(std::process::Stdio::piped())
                                .output()
                        } else {
                            let safe = crate::utils::sanitize_profile_name(&profile_name);
                            std::process::Command::new("pkill")
                                .args(["-f", &format!("openvpn.*--daemon vortix-{safe}")])
                                .stdout(std::process::Stdio::piped())
                                .stderr(std::process::Stdio::piped())
                                .output()
                        }
                    }
                };

                match output {
                    Ok(out) if out.status.success() => {
                        if matches!(protocol, Protocol::OpenVPN) {
                            crate::utils::cleanup_openvpn_run_files(&profile_name);
                        }
                        let _ = cmd_tx.send(Message::DisconnectResult {
                            profile: profile_name,
                            success: true,
                            error: None,
                        });
                    }
                    Ok(out) => {
                        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                        let _ = cmd_tx.send(Message::DisconnectResult {
                            profile: profile_name,
                            success: false,
                            error: Some(format!("{protocol}: {stderr}")),
                        });
                    }
                    Err(e) => {
                        let _ = cmd_tx.send(Message::DisconnectResult {
                            profile: profile_name,
                            success: false,
                            error: Some(format!("Failed to execute: {e}")),
                        });
                    }
                }
            });
        }
    }

    /// Force-disconnect: escalates a stuck disconnect.
    pub(crate) fn force_disconnect(&mut self) {
        let profile_name =
            if let ConnectionState::Disconnecting { profile, .. } = &self.connection_state {
                profile.clone()
            } else {
                return;
            };

        self.scanner_rx = None; // discard stale scanner data

        let force_info = self
            .profiles
            .iter()
            .find(|p| p.name == profile_name)
            .map(|profile| {
                (
                    profile.name.clone(),
                    profile.protocol,
                    profile.config_path.clone(),
                    self.cmd_tx.clone(),
                )
            });

        if let Some((name, protocol, config_path, cmd_tx)) = force_info {
            self.log(&format!("ACTION: Force-disconnecting '{name}'..."));
            self.show_toast(
                format!("Force-disconnecting '{name}'..."),
                ToastType::Warning,
            );

            // Reset the Disconnecting timer so the 30s safety timeout starts fresh
            self.connection_state = ConnectionState::Disconnecting {
                started: Instant::now(),
                profile: name.clone(),
            };

            std::thread::spawn(move || {
                let output = match protocol {
                    Protocol::WireGuard => std::process::Command::new("wg-quick")
                        .args(["down", config_path.to_str().unwrap_or("")])
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .output(),
                    Protocol::OpenVPN => {
                        let target_pid = crate::utils::read_openvpn_pid(&name);
                        if let Some(p) = target_pid {
                            std::process::Command::new("kill")
                                .args(["-9", &p.to_string()])
                                .stdout(std::process::Stdio::piped())
                                .stderr(std::process::Stdio::piped())
                                .output()
                        } else {
                            let safe = crate::utils::sanitize_profile_name(&name);
                            std::process::Command::new("pkill")
                                .args(["-9", "-f", &format!("openvpn.*--daemon vortix-{safe}")])
                                .stdout(std::process::Stdio::piped())
                                .stderr(std::process::Stdio::piped())
                                .output()
                        }
                    }
                };

                match output {
                    Ok(out) if out.status.success() => {
                        if matches!(protocol, Protocol::OpenVPN) {
                            crate::utils::cleanup_openvpn_run_files(&name);
                        }
                        let _ = cmd_tx.send(Message::DisconnectResult {
                            profile: name,
                            success: true,
                            error: None,
                        });
                    }
                    Ok(out) => {
                        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                        let _ = cmd_tx.send(Message::DisconnectResult {
                            profile: name,
                            success: false,
                            error: Some(format!("Force {protocol}: {stderr}")),
                        });
                    }
                    Err(e) => {
                        let _ = cmd_tx.send(Message::DisconnectResult {
                            profile: name,
                            success: false,
                            error: Some(format!("Force-kill failed: {e}")),
                        });
                    }
                }
            });
        }
    }

    /// Reconnect to VPN: queues the same profile for auto-connect after disconnect.
    pub(crate) fn reconnect(&mut self) {
        match &self.connection_state {
            ConnectionState::Connected { profile, .. } => {
                let profile_name = profile.clone();
                if let Some(idx) = self.profiles.iter().position(|p| p.name == profile_name) {
                    self.pending_connect = Some(idx);
                    self.disconnect();
                }
            }
            ConnectionState::Disconnected => {
                if let Some(ref last) = self.last_connected_profile {
                    if let Some(idx) = self.profiles.iter().position(|p| p.name == *last) {
                        self.log(&format!("STATUS: Reconnecting to '{last}'"));
                        self.connect_profile(idx);
                    }
                }
            }
            _ => {}
        }
    }
}
