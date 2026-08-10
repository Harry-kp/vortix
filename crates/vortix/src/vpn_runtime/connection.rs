//! Read-only connection status projection used by CLI compatibility output.

use std::time::Duration;

use crate::core::scanner;
use crate::state::Protocol;

use super::VpnRuntime;

/// Result of a CLI status scan.
#[derive(Debug)]
pub struct StatusSnapshot {
    pub connection_state: String,
    /// Typed health for a Vortix-issued connected generation. Scanner-only
    /// observations intentionally leave this absent.
    pub health: Option<crate::vortix_core::engine::state::ConnectionHealth>,
    /// Exact successful attempt generation when durable managed evidence is
    /// available.
    pub generation: Option<u64>,
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
    /// Kill switch mode — the typed enum. Call sites format it via
    /// [`crate::state::KillSwitchMode::display_name`] (prose for humans:
    /// `Off` / `Block on drop` / `VPN-only`) or
    /// [`crate::state::KillSwitchMode::cli_verb`] (slug for the CLI verb +
    /// JSON envelope: `off` / `block-on-drop` / `vpn-only`). One
    /// vocabulary, two casings, no duplicated string fields.
    pub killswitch_mode: crate::state::KillSwitchMode,
    /// Kill switch state — typed enum. See the helpers
    /// [`crate::state::KillSwitchState::display_status`] (prose) and
    /// [`crate::state::KillSwitchState::cli_verb`] (slug).
    pub killswitch_state: crate::state::KillSwitchState,
    pub dns_leak: Option<bool>,
    pub encryption: Option<String>,
    pub location: Option<String>,
    pub isp: Option<String>,
}

impl VpnRuntime {
    /// One-shot status scan for CLI.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn scan_status(&self) -> StatusSnapshot {
        let active = scanner::get_active_profiles(&self.profiles);
        let session = active.first();
        let (
            mut state,
            profile,
            protocol,
            uptime,
            server,
            interface,
            internal_ip,
            dl,
            ul,
            encryption,
        ) = if let Some(s) = session {
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
            // Direct scanner state is observation-only. Even a fresh or
            // historically non-zero handshake timestamp cannot recreate
            // the current attempt generation and ownership receipt.
            let observed_state = if matches!(proto, Some(Protocol::WireGuard)) {
                "handshaking"
            } else {
                "connected"
            };

            let uptime = s.started_at.and_then(|started| {
                std::time::SystemTime::now()
                    .duration_since(started)
                    .ok()
                    .map(|d| d.as_secs())
            });

            (
                observed_state.to_string(),
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

        let mut health = None;
        let mut generation = None;
        if let Some(session) = session {
            if let Some(profile) = self.profiles.iter().find(|profile| {
                profile.name == session.name && profile.protocol == Protocol::WireGuard
            }) {
                if let Some(mut receipt) =
                    crate::core::managed_wireguard::load(&self.config_dir, &profile.id)
                        .filter(|receipt| receipt.validates(&profile.id, session))
                {
                    let mut activity = std::collections::HashMap::new();
                    let current = crate::app::connection::wireguard_health_from_session(
                        &session.wireguard_peers,
                        &mut activity,
                        &receipt.probe_receipts,
                        Duration::from_secs(self.config.wireguard_handshake_stale_secs),
                    );
                    if let Ok(Some(old)) = crate::core::managed_wireguard::update_health(
                        &self.config_dir,
                        &mut receipt,
                        current.clone(),
                    ) {
                        if let Some(journal) = crate::vortix_core::journal::global_journal() {
                            let _ = journal.append(
                                crate::vortix_core::engine::EngineEvent::ConnectionHealthChanged {
                                    profile_id: profile.id.clone(),
                                    old,
                                    new: current.clone(),
                                },
                            );
                        }
                    }
                    state = "connected".into();
                    generation = Some(receipt.generation);
                    health = Some(current);
                }
            }
        }

        StatusSnapshot {
            connection_state: state,
            health,
            generation,
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
            killswitch_mode: self.killswitch_mode,
            killswitch_state: self.killswitch_state,
            dns_leak: None,
            encryption,
            location: None,
            isp: None,
        }
    }
}
