//! VPN connection lifecycle management and kill switch control.

use std::time::Instant;

use super::{App, ConnectionState, InputMode, Protocol, ToastType};
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
        self.engine.retry_count = 0;
        self.engine.retry_profile_idx = None;
        self.engine.auto_reconnect_profile = None;

        if let Some(target_profile) = self.engine.profiles.get(idx) {
            let target_name = target_profile.name.clone();
            match &self.engine.connection_state {
                // If connecting, ignore to prevent races
                ConnectionState::Connecting { .. } => {}
                // If disconnecting, queue the connection for after disconnect completes
                ConnectionState::Disconnecting { .. } => {
                    if let Some(old) = self.engine.pending_connect {
                        if old != idx {
                            if let Some(old_profile) = self.engine.profiles.get(old) {
                                self.log(&format!(
                                    "ACTION: Switched queue from '{}' to '{target_name}'",
                                    old_profile.name
                                ));
                            }
                        }
                    }
                    self.engine.pending_connect = Some(idx);
                }
                ConnectionState::Connected {
                    profile: current_name,
                    ..
                } => {
                    if *current_name == target_name {
                        self.engine.pending_connect = None;
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
                // xtask:allow-platform-cfg: resolvconf detection is Linux-only DNS plumbing
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
        let (name, protocol, config_path, cmd_tx) =
            if let Some(profile) = self.engine.profiles.get(idx) {
                (
                    profile.name.clone(),
                    profile.protocol,
                    profile.config_path.clone(),
                    self.engine.cmd_tx.clone(),
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
        if !self.engine.is_root {
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
        self.engine.connection_state = ConnectionState::Connecting {
            started: Instant::now(),
            profile: name.clone(),
        };
        self.log(&format!("ACTION: Connecting to '{name}' [{protocol}]..."));

        let connect_timeout_secs = self.engine.config.connect_timeout;
        let ovpn_verbosity = self.engine.config.openvpn_verbosity.clone();

        // Plan #004 U4: route once via TunnelKind, no protocol match arm.
        std::thread::spawn(move || {
            use crate::vortix_core::profile::{Profile, ProfileId, ProtocolKind};

            let config_dir = crate::utils::get_app_config_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));
            let profile = Profile::new(
                ProfileId::new(&name),
                &name,
                match protocol {
                    Protocol::WireGuard => ProtocolKind::WireGuard,
                    Protocol::OpenVPN => ProtocolKind::OpenVpn,
                },
                config_path,
            );
            let mut tunnel = crate::tunnel::tunnel_for(
                protocol,
                &config_dir,
                &ovpn_verbosity,
                connect_timeout_secs,
            );

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
        });
    }

    /// Synchronizes the kill switch state with the current mode and connection status.
    /// This is the single source of truth for kill switch state transitions and firewall control.
    pub(crate) fn sync_killswitch(&mut self) {
        use crate::state::{KillSwitchMode, KillSwitchState};

        let old_state = self.engine.killswitch_state;

        // 1. Determine the target state
        self.engine.killswitch_state = match self.engine.killswitch_mode {
            KillSwitchMode::Off => KillSwitchState::Disabled,
            KillSwitchMode::Auto => {
                if matches!(
                    self.engine.connection_state,
                    ConnectionState::Connected { .. }
                ) {
                    KillSwitchState::Armed
                } else if old_state == KillSwitchState::Blocking {
                    KillSwitchState::Blocking
                } else {
                    KillSwitchState::Armed
                }
            }
            KillSwitchMode::AlwaysOn => {
                if matches!(
                    self.engine.connection_state,
                    ConnectionState::Connected { .. }
                ) {
                    KillSwitchState::Armed
                } else {
                    KillSwitchState::Blocking
                }
            }
        };

        // 2. Refuse Blocking state when not running as root — firewall rules
        //    require elevated privileges and the UI must not claim a security
        //    posture that isn't enforced.
        if self.engine.killswitch_state.is_blocking() && !self.engine.is_root {
            self.engine.killswitch_state = KillSwitchState::Armed;
            self.show_toast(
                "Kill switch requires root — run with sudo".to_string(),
                ToastType::Warning,
            );
            self.log("WARN: Kill switch blocked — not running as root");
        }

        // 3. Sync physical firewall state if target state changed or if forcing sync
        if self.engine.killswitch_state != old_state
            || self.engine.killswitch_state == KillSwitchState::Blocking
        {
            if self.engine.killswitch_state.is_blocking() {
                let (interface, server_ip) = match &self.engine.connection_state {
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
            self.engine.killswitch_mode,
            self.engine.killswitch_state,
            None,
            None,
        );
    }

    /// Kill any running VPN process and remove run files for a profile.
    ///
    /// Plan #004 U4: routes through the `TunnelKind` dispatch so this no
    /// longer match-branches on protocol.
    pub(crate) fn cleanup_vpn_resources(&self, profile_name: &str) {
        if let Some(profile) = self.engine.profiles.iter().find(|p| p.name == profile_name) {
            use crate::vortix_core::ports::tunnel::{TunnelHandle, TunnelKindTag};
            use crate::vortix_core::profile::ProfileId;

            let iface = match profile.protocol {
                Protocol::WireGuard => profile.config_path.to_string_lossy().into_owned(),
                Protocol::OpenVPN => {
                    format!("openvpn-{}", utils::sanitize_profile_name(profile_name))
                }
            };
            let pid = match profile.protocol {
                Protocol::OpenVPN => utils::read_openvpn_pid(profile_name),
                Protocol::WireGuard => None,
            };
            let handle = TunnelHandle {
                profile_id: ProfileId::new(profile_name),
                interface_name: iface,
                pid,
                started_at: std::time::SystemTime::now(),
                kind: match profile.protocol {
                    Protocol::WireGuard => TunnelKindTag::WireGuard,
                    Protocol::OpenVPN => TunnelKindTag::OpenVpn,
                },
            };

            let config_dir =
                utils::get_app_config_dir().unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));
            let mut tunnel = crate::tunnel::tunnel_for(profile.protocol, &config_dir, "3", 30);
            let _ = tunnel.down(handle);

            if matches!(profile.protocol, Protocol::OpenVPN) {
                utils::cleanup_openvpn_run_files(profile_name);
            }
        }
    }

    /// Finalize a disconnect: transition to `Disconnected`, sync kill switch,
    /// and drain `pending_connect` (auto-connect to the queued profile, if any).
    pub(crate) fn complete_disconnect(&mut self, profile_name: &str) {
        self.engine.session_start = None;
        self.engine.scanner_rx = None; // discard stale scanner data pre-disconnect
        self.panel_flipped.clear();
        self.flip_animation = None;

        self.engine.public_ip = crate::constants::MSG_DETECTING.to_string();
        self.engine.location = crate::constants::MSG_DETECTING.to_string();
        self.engine.isp = crate::constants::MSG_DETECTING.to_string();
        self.engine.dns_server = crate::constants::MSG_DETECTING.to_string();
        self.engine.ipv6_leak = false;
        self.engine.latency_ms = 0;
        self.engine.packet_loss = 0.0;
        self.engine.jitter_ms = 0;
        self.engine.last_security_check = None;
        self.engine.ip_unchanged_warned = false;
        self.engine.current_down = 0;
        self.engine.current_up = 0;

        // Clean up OpenVPN runtime files if this was an OpenVPN profile
        if self
            .engine
            .profiles
            .iter()
            .any(|p| p.name == profile_name && matches!(p.protocol, Protocol::OpenVPN))
        {
            crate::utils::cleanup_openvpn_run_files(profile_name);
        }

        // Drain pending_connect: switch directly to the next profile
        if let Some(idx) = self.engine.pending_connect.take() {
            if idx < self.engine.profiles.len() {
                let next_name = self.engine.profiles[idx].name.clone();
                self.log(&format!(
                    "STATUS: Disconnected from '{profile_name}', connecting to '{next_name}'..."
                ));
                self.engine.connection_state = ConnectionState::Disconnected;
                self.sync_killswitch();
                self.connect_profile(idx);
                return;
            }
        }

        // Normal disconnect (no pending switch)
        self.log(&format!("STATUS: Disconnected from '{profile_name}'"));
        self.engine.connection_state = ConnectionState::Disconnected;
        self.sync_killswitch();
        self.refresh_telemetry();
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn disconnect(&mut self) {
        self.engine.retry_count = 0;
        self.engine.retry_profile_idx = None;
        self.engine.auto_reconnect_profile = None;
        // Discard any in-flight scanner result captured before this disconnect;
        // stale data showing the interface "up" would otherwise re-promote to
        // Connected and trigger a spurious "VPN dropped" auto-reconnect.
        self.engine.scanner_rx = None;
        // Extract connection info from Connected or Connecting state
        let connection_info = match &self.engine.connection_state {
            ConnectionState::Connected {
                profile: ref profile_name,
                details,
                ..
            } => self
                .engine
                .profiles
                .iter()
                .find(|p| p.name == *profile_name)
                .map(|profile| {
                    (
                        profile.name.clone(),
                        profile.protocol,
                        profile.config_path.clone(),
                        details.pid,
                        self.engine.cmd_tx.clone(),
                    )
                }),
            ConnectionState::Connecting {
                profile: ref profile_name,
                ..
            } => self
                .engine
                .profiles
                .iter()
                .find(|p| p.name == *profile_name)
                .map(|profile| {
                    (
                        profile.name.clone(),
                        profile.protocol,
                        profile.config_path.clone(),
                        None, // no PID yet while connecting
                        self.engine.cmd_tx.clone(),
                    )
                }),
            _ => None,
        };

        if let Some((profile_name, protocol, config_path, pid, cmd_tx)) = connection_info {
            self.log(&format!("ACTION: Disconnecting from '{profile_name}'..."));

            // Set disconnecting state
            self.engine.connection_state = ConnectionState::Disconnecting {
                started: Instant::now(),
                profile: profile_name.clone(),
            };

            // KILL SWITCH: Sync state after changing connection state
            self.sync_killswitch();

            if self.engine.killswitch_state.is_blocking() {
                self.show_toast(
                    "Kill Switch blocking - Strict mode active".to_string(),
                    ToastType::Warning,
                );
            }

            // Plan #004 U4: route the disconnect through TunnelKind.
            std::thread::spawn(move || {
                use crate::vortix_core::ports::tunnel::{TunnelHandle, TunnelKindTag};
                use crate::vortix_core::profile::ProfileId;

                let iface = match protocol {
                    Protocol::WireGuard => config_path.to_string_lossy().into_owned(),
                    Protocol::OpenVPN => {
                        format!(
                            "openvpn-{}",
                            crate::utils::sanitize_profile_name(&profile_name)
                        )
                    }
                };
                let pid_for_handle = match protocol {
                    Protocol::OpenVPN => crate::utils::read_openvpn_pid(&profile_name).or(pid),
                    Protocol::WireGuard => None,
                };
                let handle = TunnelHandle {
                    profile_id: ProfileId::new(&profile_name),
                    interface_name: iface,
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
                            crate::utils::cleanup_openvpn_run_files(&profile_name);
                        }
                        let _ = cmd_tx.send(Message::DisconnectResult {
                            profile: profile_name,
                            success: true,
                            error: None,
                        });
                    }
                    Err(err) => {
                        let _ = cmd_tx.send(Message::DisconnectResult {
                            profile: profile_name,
                            success: false,
                            error: Some(format!("{protocol}: {err}")),
                        });
                    }
                }
            });
        }
    }

    /// Force-disconnect: escalates a stuck disconnect.
    pub(crate) fn force_disconnect(&mut self) {
        let profile_name =
            if let ConnectionState::Disconnecting { profile, .. } = &self.engine.connection_state {
                profile.clone()
            } else {
                return;
            };

        self.engine.scanner_rx = None; // discard stale scanner data

        let force_info = self
            .engine
            .profiles
            .iter()
            .find(|p| p.name == profile_name)
            .map(|profile| {
                (
                    profile.name.clone(),
                    profile.protocol,
                    profile.config_path.clone(),
                    self.engine.cmd_tx.clone(),
                )
            });

        if let Some((name, protocol, config_path, cmd_tx)) = force_info {
            self.log(&format!("ACTION: Force-disconnecting '{name}'..."));
            self.show_toast(
                format!("Force-disconnecting '{name}'..."),
                ToastType::Warning,
            );

            // Reset the Disconnecting timer so the 30s safety timeout starts fresh
            self.engine.connection_state = ConnectionState::Disconnecting {
                started: Instant::now(),
                profile: name.clone(),
            };

            // Plan #004 U4: force-disconnect now routes through TunnelKind.
            // The OvpnTunnel's down() path already escalates to pkill if the
            // pid file is stale; treating the force-flag as equivalent to a
            // regular down preserves the existing semantics on macOS where
            // SIGKILL was used (TODO plan #005: add a force flag to Tunnel
            // trait to escalate to SIGKILL where supported).
            std::thread::spawn(move || {
                use crate::vortix_core::ports::tunnel::{TunnelHandle, TunnelKindTag};
                use crate::vortix_core::profile::ProfileId;

                let iface = match protocol {
                    Protocol::WireGuard => config_path.to_string_lossy().into_owned(),
                    Protocol::OpenVPN => {
                        format!("openvpn-{}", crate::utils::sanitize_profile_name(&name))
                    }
                };
                let pid_for_handle = match protocol {
                    Protocol::OpenVPN => crate::utils::read_openvpn_pid(&name),
                    Protocol::WireGuard => None,
                };
                let handle = TunnelHandle {
                    profile_id: ProfileId::new(&name),
                    interface_name: iface,
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
                            crate::utils::cleanup_openvpn_run_files(&name);
                        }
                        let _ = cmd_tx.send(Message::DisconnectResult {
                            profile: name,
                            success: true,
                            error: None,
                        });
                    }
                    Err(err) => {
                        let _ = cmd_tx.send(Message::DisconnectResult {
                            profile: name,
                            success: false,
                            error: Some(format!("Force {protocol}: {err}")),
                        });
                    }
                }
            });
        }
    }

    /// Reconnect to VPN: queues the same profile for auto-connect after disconnect.
    pub(crate) fn reconnect(&mut self) {
        match &self.engine.connection_state {
            ConnectionState::Connected { profile, .. } => {
                let profile_name = profile.clone();
                if let Some(idx) = self
                    .engine
                    .profiles
                    .iter()
                    .position(|p| p.name == profile_name)
                {
                    self.engine.pending_connect = Some(idx);
                    self.disconnect();
                }
            }
            ConnectionState::Disconnected => {
                if let Some(ref last) = self.engine.last_connected_profile {
                    if let Some(idx) = self.engine.profiles.iter().position(|p| p.name == *last) {
                        self.log(&format!("STATUS: Reconnecting to '{last}'"));
                        self.connect_profile(idx);
                    }
                }
            }
            _ => {}
        }
    }
}
