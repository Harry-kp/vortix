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

/// One active tunnel in a CLI status scan.
///
/// `StatusSnapshot` keeps scalar fields describing the primary tunnel for
/// back-compatible output, but a host can carry several at once and the
/// scalars cannot say so. Anything that reports what is running reads this.
#[derive(Debug, Clone)]
pub struct TunnelStatus {
    pub state: String,
    pub profile: String,
    pub protocol: Option<String>,
    pub health: Option<crate::vortix_core::engine::state::ConnectionHealth>,
    pub generation: Option<u64>,
    pub uptime_secs: Option<u64>,
    pub server: Option<String>,
    pub interface: Option<String>,
    pub internal_ip: Option<String>,
    pub download_bytes: Option<String>,
    pub upload_bytes: Option<String>,
    pub encryption: Option<String>,
}

/// Result of a CLI status scan.
#[derive(Debug)]
pub struct StatusSnapshot {
    /// Every active tunnel, primary first. Empty when disconnected.
    pub tunnels: Vec<TunnelStatus>,
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
    ///
    /// Scalar fields describe the primary tunnel; `tunnels` carries every
    /// one. Reading only the scalars reports a single tunnel on a host that
    /// has several, which is what `vortix status` used to do.
    #[must_use]
    pub fn scan_status(&self) -> StatusSnapshot {
        let tunnels = self.scan_tunnels();
        let primary = tunnels.first();
        StatusSnapshot {
            connection_state: primary
                .map_or_else(|| "disconnected".to_string(), |tunnel| tunnel.state.clone()),
            health: primary.and_then(|tunnel| tunnel.health.clone()),
            generation: primary.and_then(|tunnel| tunnel.generation),
            profile: primary.map(|tunnel| tunnel.profile.clone()),
            protocol: primary.and_then(|tunnel| tunnel.protocol.clone()),
            uptime_secs: primary.and_then(|tunnel| tunnel.uptime_secs),
            public_ip: None, // requires telemetry worker; populated by caller if needed
            server: primary.and_then(|tunnel| tunnel.server.clone()),
            interface: primary.and_then(|tunnel| tunnel.interface.clone()),
            internal_ip: primary.and_then(|tunnel| tunnel.internal_ip.clone()),
            latency_ms: None,
            jitter_ms: None,
            packet_loss_pct: None,
            quality: None,
            download_bytes: primary.and_then(|tunnel| tunnel.download_bytes.clone()),
            upload_bytes: primary.and_then(|tunnel| tunnel.upload_bytes.clone()),
            killswitch_mode: self.killswitch_mode,
            killswitch_state: self.killswitch_state,
            dns_leak: None,
            encryption: primary.and_then(|tunnel| tunnel.encryption.clone()),
            location: None,
            isp: None,
            tunnels,
        }
    }

    /// Every active tunnel, the one owning the default route first.
    ///
    /// Ordering matters because callers that still read one tunnel should
    /// describe the one a user means by "my VPN" — the tunnel carrying
    /// general egress — rather than whichever profile sorts first in the
    /// catalogue.
    fn scan_tunnels(&self) -> Vec<TunnelStatus> {
        let mut active = scanner::get_active_profiles(&self.profiles);
        let default_interface = crate::platform::current_platform()
            .route_table
            .default_route_interface();
        active.sort_by_key(|session| {
            usize::from(default_interface.as_deref() != Some(session.interface.as_str()))
        });
        active
            .iter()
            .map(|session| self.tunnel_status(session))
            .collect()
    }

    fn tunnel_status(&self, session: &crate::core::scanner::ActiveSession) -> TunnelStatus {
        let profile = self
            .profiles
            .iter()
            .find(|entry| entry.name == session.name);
        let protocol = profile.map(|entry| entry.protocol);
        let encryption = match protocol {
            Some(Protocol::WireGuard) => Some("ChaCha20-Poly1305".into()),
            Some(Protocol::OpenVPN) => Some("AES-256-GCM".into()),
            None => None,
        };
        // Direct scanner state is observation-only. Even a fresh or
        // historically non-zero handshake timestamp cannot recreate
        // the current attempt generation and ownership receipt.
        let mut state = if matches!(protocol, Some(Protocol::WireGuard)) {
            "handshaking".to_string()
        } else {
            "connected".to_string()
        };
        let uptime_secs = session.started_at.and_then(|started| {
            std::time::SystemTime::now()
                .duration_since(started)
                .ok()
                .map(|elapsed| elapsed.as_secs())
        });
        let mut health = None;
        let mut generation = None;
        if let Some(profile) = profile.filter(|entry| entry.protocol == Protocol::WireGuard) {
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
        let present = |value: &String| (!value.is_empty()).then(|| value.clone());
        TunnelStatus {
            state,
            profile: session.name.clone(),
            protocol: protocol.map(|entry| format!("{entry}")),
            health,
            generation,
            uptime_secs,
            server: present(&session.endpoint),
            interface: present(&session.interface),
            internal_ip: present(&session.internal_ip),
            download_bytes: present(&session.transfer_rx),
            upload_bytes: present(&session.transfer_tx),
            encryption,
        }
    }
}
