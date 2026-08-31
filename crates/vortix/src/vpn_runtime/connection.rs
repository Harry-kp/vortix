//! Read-only connection status projection used by CLI compatibility output.

use std::time::Duration;

use crate::core::scanner;
use crate::state::Protocol;

use super::VpnRuntime;

fn wireguard_health_from_session(
    peers: &[crate::vortix_core::ports::tunnel::TunnelPeerStatus],
    activity: &mut std::collections::HashMap<String, crate::vpn_runtime::WireGuardPeerActivity>,
    probe_receipts: &[crate::vortix_core::ports::tunnel::ProbeReceipt],
    stale_after: std::time::Duration,
) -> crate::vortix_core::engine::state::ConnectionHealth {
    use crate::vortix_core::engine::state::{ConnectionHealth, DegradedReason};
    use crate::vortix_core::ports::tunnel::{
        classify_peer_handshake_health, PeerHandshakeHealth, PeerTrafficExpectation,
    };

    let now = std::time::SystemTime::now();
    let expectation_window = stale_after.saturating_mul(2);
    let mut expected_peers = 0_usize;
    for peer in peers {
        let peer_activity = activity.entry(peer.public_key.clone()).or_insert(
            crate::vpn_runtime::WireGuardPeerActivity {
                bytes_rx: peer.bytes_rx,
                bytes_tx: peer.bytes_tx,
                observed_at: peer.evidence_observed_at,
                last_transfer_at: None,
            },
        );
        if peer.evidence_observed_at > peer_activity.observed_at {
            if peer.bytes_rx > peer_activity.bytes_rx || peer.bytes_tx > peer_activity.bytes_tx {
                peer_activity.last_transfer_at = Some(peer.evidence_observed_at);
            }
            peer_activity.bytes_rx = peer.bytes_rx;
            peer_activity.bytes_tx = peer.bytes_tx;
            peer_activity.observed_at = peer.evidence_observed_at;
        }

        let recent_transfer = peer_activity.last_transfer_at.is_some_and(|at| {
            now.duration_since(at)
                .is_ok_and(|age| age <= expectation_window)
        });
        // An actually-issued probe is durable connection metadata. Aging the
        // issue timestamp out would silently turn a stale expected peer into
        // Unknown even though the connection policy still expects that peer
        // to remain fresh. Absence/explicit replacement removes the receipt;
        // a fresh handshake clears the degraded result naturally.
        let configured_probe = probe_receipts.iter().find(|record| {
            record.peer_public_key == peer.public_key
                && record.allowed_routes == peer.allowed_routes
        });
        let expectation = if peer.keepalive_expected() {
            PeerTrafficExpectation::PersistentKeepalive
        } else if recent_transfer {
            PeerTrafficExpectation::RoutedTraffic
        } else if let Some(record) = configured_probe {
            PeerTrafficExpectation::ConfiguredProbe {
                target: record.target,
            }
        } else {
            PeerTrafficExpectation::Idle
        };
        if !matches!(expectation, PeerTrafficExpectation::Idle) {
            expected_peers += 1;
        }
        match classify_peer_handshake_health(peer, now, &expectation, stale_after) {
            PeerHandshakeHealth::Stale { age } => {
                return ConnectionHealth::Degraded {
                    reason: DegradedReason::WireGuardPeerStale {
                        peer_public_key: peer.public_key.clone(),
                        allowed_routes: peer.allowed_routes.clone(),
                        seconds_since_last_handshake: age.as_secs(),
                    },
                };
            }
            PeerHandshakeHealth::NeverObserved => {
                return ConnectionHealth::Degraded {
                    reason: DegradedReason::WireGuardPeerNeverObserved {
                        peer_public_key: peer.public_key.clone(),
                        allowed_routes: peer.allowed_routes.clone(),
                    },
                };
            }
            PeerHandshakeHealth::Healthy { .. } | PeerHandshakeHealth::InformationalIdle { .. } => {
            }
        }
    }
    if expected_peers > 0 {
        ConnectionHealth::Healthy
    } else {
        ConnectionHealth::Unknown
    }
}

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
                    let current = wireguard_health_from_session(
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
