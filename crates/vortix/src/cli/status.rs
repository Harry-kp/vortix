//! `vortix status`: a read-only scan of the kernel for the CLI.

use std::time::Duration;

use crate::core::profile::ProtocolKind;
use crate::core::scanner;

use crate::config::profiles::VpnProfile;
use crate::config::AppConfig;

/// Result of a CLI status scan.
#[derive(Debug)]
pub struct StatusSnapshot {
    pub connection_state: String,
    /// Typed health for a Vortix-issued connected generation. Scanner-only
    /// observations intentionally leave this absent.
    pub health: Option<crate::core::engine::state::ConnectionHealth>,
    /// Exact successful attempt generation when durable managed evidence is
    /// available.
    pub generation: Option<u64>,
    pub profile: Option<String>,
    pub protocol: Option<String>,
    pub uptime_secs: Option<u64>,
    pub server: Option<String>,
    pub interface: Option<String>,
    pub internal_ip: Option<String>,
    pub download_bytes: Option<String>,
    pub upload_bytes: Option<String>,
    /// Kill switch mode — the typed enum. Call sites format it via
    /// [`crate::core::killswitch::KillSwitchMode::display_name`] (prose for humans:
    /// `Off` / `Block on drop` / `VPN-only`) or
    /// [`crate::core::killswitch::KillSwitchMode::cli_verb`] (slug for the CLI verb +
    /// JSON envelope: `off` / `block-on-drop` / `vpn-only`). One
    /// vocabulary, two casings, no duplicated string fields.
    pub killswitch_mode: crate::core::killswitch::KillSwitchMode,
    /// Kill switch state — typed enum. See the helpers
    /// [`crate::core::killswitch::KillSwitchState::display_status`] (prose) and
    /// [`crate::core::killswitch::KillSwitchState::cli_verb`] (slug).
    pub killswitch_state: crate::core::killswitch::KillSwitchState,
}

/// One-shot status scan for CLI.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn scan_status(
    profiles: &[VpnProfile],
    config: &AppConfig,
    config_dir: &std::path::Path,
) -> StatusSnapshot {
    let (killswitch_mode, killswitch_state) = crate::core::killswitch::persisted();
    let active = scanner::get_active_profiles(profiles);
    let session = active.first();
    let (mut state, profile, protocol, uptime, server, interface, internal_ip, dl, ul) =
        if let Some(s) = session {
            let proto = profiles
                .iter()
                .find(|p| p.name == s.name)
                .map(|p| p.protocol);

            // Direct scanner state is observation-only. Even a fresh or
            // historically non-zero handshake timestamp cannot recreate
            // the current attempt generation and ownership receipt.
            let observed_state = if matches!(proto, Some(ProtocolKind::WireGuard)) {
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
            )
        };

    let mut health = None;
    let mut generation = None;
    if let Some(session) = session {
        if let Some(profile) = profiles.iter().find(|profile| {
            profile.name == session.name && profile.protocol == ProtocolKind::WireGuard
        }) {
            if let Some(mut receipt) = crate::core::managed_wireguard::load(config_dir, &profile.id)
                .filter(|receipt| receipt.validates(&profile.id, session))
            {
                let mut activity = crate::core::managed_wireguard::PeerActivity::new();
                let current = crate::core::managed_wireguard::health_from_peers(
                    &session.wireguard_peers,
                    &mut activity,
                    &receipt.probe_receipts,
                    Duration::from_secs(config.wireguard_handshake_stale_secs),
                );
                if let Ok(Some(old)) = crate::core::managed_wireguard::update_health(
                    config_dir,
                    &mut receipt,
                    current.clone(),
                ) {
                    if let Some(journal) = crate::core::journal::global_journal() {
                        let _ = journal.append(
                            crate::core::journal::JournalEvent::ConnectionHealthChanged {
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
        server,
        interface,
        internal_ip,
        download_bytes: dl,
        upload_bytes: ul,
        killswitch_mode,
        killswitch_state,
    }
}
