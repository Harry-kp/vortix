//! `vortix status`: a read-only scan of the kernel for the CLI.

use std::time::Duration;

use crate::control::scanner;
use crate::profile::ProtocolKind;

use crate::cli::output::{
    print_success, ConnectionEntry, ConnectionHealthEntry, ExitCode, OutputMode,
};
use crate::config::profiles::VpnProfile;
use crate::config::AppConfig;
use serde::Serialize;
use std::path::Path;

/// Result of a CLI status scan.
#[derive(Debug)]
pub struct StatusSnapshot {
    pub connection_state: String,
    /// Typed health for a Vortix-issued connected generation. Scanner-only
    /// observations intentionally leave this absent.
    pub health: Option<crate::tunnel::ConnectionHealth>,
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
    /// [`crate::control::killswitch::KillSwitchMode::display_name`] (prose for humans:
    /// `Off` / `Block on drop` / `VPN-only`) or
    /// [`crate::control::killswitch::KillSwitchMode::cli_verb`] (slug for the CLI verb +
    /// JSON envelope: `off` / `block-on-drop` / `vpn-only`). One
    /// vocabulary, two casings, no duplicated string fields.
    pub killswitch_mode: crate::control::killswitch::KillSwitchMode,
    /// Kill switch state — typed enum. See the helpers
    /// [`crate::control::killswitch::KillSwitchState::display_status`] (prose) and
    /// [`crate::control::killswitch::KillSwitchState::cli_verb`] (slug).
    pub killswitch_state: crate::control::killswitch::KillSwitchState,
}

/// One-shot status scan for CLI.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn scan_status(
    profiles: &[VpnProfile],
    config: &AppConfig,
    config_dir: &std::path::Path,
) -> StatusSnapshot {
    let (killswitch_mode, killswitch_state) = crate::control::killswitch::persisted();
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
                if s.details.endpoint.is_empty() {
                    None
                } else {
                    Some(s.details.endpoint.clone())
                },
                if s.details.interface.is_empty() {
                    None
                } else {
                    Some(s.details.interface.clone())
                },
                if s.details.internal_ip.is_empty() {
                    None
                } else {
                    Some(s.details.internal_ip.clone())
                },
                if s.details.transfer_rx.is_empty() {
                    None
                } else {
                    Some(s.details.transfer_rx.clone())
                },
                if s.details.transfer_tx.is_empty() {
                    None
                } else {
                    Some(s.details.transfer_tx.clone())
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
            if let Some(mut receipt) = crate::wireguard::receipt::load(config_dir, &profile.id)
                .filter(|receipt| receipt.validates(&profile.id, session))
            {
                let mut activity = crate::wireguard::receipt::PeerActivity::new();
                let current = crate::wireguard::receipt::health_from_peers(
                    &session.wireguard_peers,
                    &mut activity,
                    &receipt.probe_receipts,
                    Duration::from_secs(config.wireguard_handshake_stale_secs),
                );
                if let Ok(Some(old)) = crate::wireguard::receipt::update_health(
                    config_dir,
                    &mut receipt,
                    current.clone(),
                ) {
                    if let Some(journal) = crate::journal::global_journal() {
                        let _ =
                            journal.append(crate::journal::JournalEvent::ConnectionHealthChanged {
                                profile_id: profile.id.clone(),
                                old,
                                new: current.clone(),
                            });
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

/// `status` command JSON payload.
///
/// Shape is pinned by the v2 schema (see [`crate::cli::output`] module
/// docs):
///
/// - `connections`: all currently active tunnels. Empty when nothing is
///   connected. v2 readers should prefer this field.
/// - `primary`: profile id of the primary tunnel, or `null` when no
///   primary is elected (no active tunnels, or only secondaries).
/// - `connection`: v1 back-compat. Set to the primary's [`ConnectionEntry`]
///   when a primary exists, `null` otherwise. v0.3.x consumers reading
///   `data.connection.{state,profile,protocol,uptime_secs}` continue to
///   work in the primary-only case.
///
/// A follow-up will replace the transitional single-entry construction below
/// with a engine snapshot-driven snapshot; this stage's job is just to make the v2
/// envelope shape available.
#[derive(Serialize)]
struct StatusData {
    connections: Vec<ConnectionEntry>,
    primary: Option<String>,
    connection: Option<ConnectionEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<StatusNetwork>,
    security: StatusSecurity,
}

#[derive(Serialize)]
struct StatusNetwork {
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    internal_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    download: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upload: Option<String>,
}

#[derive(Serialize)]
struct StatusSecurity {
    killswitch_mode: String,
    killswitch_state: String,
}

#[allow(clippy::too_many_lines)]
pub(super) fn handle_status(
    watch: bool,
    interval: u64,
    brief: bool,
    config: &AppConfig,
    config_dir: &Path,
    mode: OutputMode,
) -> i32 {
    if watch {
        // Watch always uses the direct scanner path — it polls in a
        // tight loop and daemon round-trips would just add latency.
        return run_watch(interval, config, config_dir, mode);
    }

    let profiles = crate::config::profiles::load_profiles();
    let snap = crate::cli::status::scan_status(&profiles, config, config_dir);
    let is_connected = snap.connection_state == "connected";
    let is_present = snap.connection_state != "disconnected";

    // Transitional shape: the engine snapshot-driven multi-tunnel snapshot
    // lands later. Until then, "primary" is the single active tunnel
    // (when connected), and `connections` is a one-element vec mirroring
    // it. When disconnected, `connections` is empty and `primary` /
    // `connection` are both `null`.
    let visible_entry = if is_present {
        Some(ConnectionEntry {
            state: snap.connection_state.clone(),
            profile: snap.profile.clone(),
            protocol: snap.protocol.clone(),
            uptime_secs: snap.uptime_secs,
            health: snap.health.as_ref().map(connection_health_entry),
            generation: snap.generation,
        })
    } else {
        None
    };
    let connections: Vec<ConnectionEntry> = visible_entry.iter().cloned().collect();
    let primary: Option<String> = if is_connected {
        snap.profile.clone()
    } else {
        None
    };

    let data = StatusData {
        connections,
        primary,
        connection: if is_connected {
            visible_entry.clone()
        } else {
            None
        },
        network: if is_connected {
            Some(StatusNetwork {
                server: snap.server.clone(),
                interface: snap.interface.clone(),
                internal_ip: snap.internal_ip.clone(),
                download: snap.download_bytes.clone(),
                upload: snap.upload_bytes.clone(),
            })
        } else {
            None
        },
        security: StatusSecurity {
            killswitch_mode: snap.killswitch_mode.cli_verb().to_string(),
            killswitch_state: snap.killswitch_state.cli_verb().to_string(),
        },
    };

    match mode {
        OutputMode::Human => {
            if brief {
                println!("{}", human_status_headline(&snap));
            } else if is_connected {
                let profile = snap.profile.as_deref().unwrap_or("unknown");
                let protocol = snap.protocol.as_deref().unwrap_or("");
                println!("● Connected to {profile} ({protocol})");
                println!();
                if let Some(s) = &snap.server {
                    println!("  Server       {s}");
                }
                if let Some(i) = &snap.interface {
                    println!("  Interface    {i}");
                }
                if let Some(ip) = &snap.internal_ip {
                    println!("  Internal IP  {ip}");
                }
                if let Some(up) = &snap.uptime_secs {
                    let h = up / 3600;
                    let m = (up % 3600) / 60;
                    let s = up % 60;
                    println!("  Uptime       {h}h {m}m {s}s");
                }
                if let Some(dl) = &snap.download_bytes {
                    println!("  Transfer     ↓ {dl}");
                }
                if let Some(ul) = &snap.upload_bytes {
                    println!("               ↑ {ul}");
                }
                println!(
                    "  Kill Switch  {} ({})",
                    snap.killswitch_mode.display_name(),
                    snap.killswitch_state.display_status()
                );
                if let Some(health) = &snap.health {
                    println!("  Health       {}", connection_health_human(health));
                }
            } else {
                println!("{}", human_status_headline(&snap));
                println!();
                println!(
                    "  Kill Switch  {} ({})",
                    snap.killswitch_mode.display_name(),
                    snap.killswitch_state.display_status()
                );
            }
        }
        OutputMode::Json => {
            let next = if is_present {
                vec![
                    "sudo vortix down --json".into(),
                    "vortix list --json".into(),
                ]
            } else {
                vec![
                    "vortix list --json".into(),
                    "sudo vortix up <PROFILE> --json".into(),
                ]
            };
            print_success(mode, "status", &data, next);
        }
        OutputMode::Quiet => {}
    }
    ExitCode::Success.code()
}

fn run_watch(interval: u64, config: &AppConfig, config_dir: &Path, mode: OutputMode) -> i32 {
    loop {
        let profiles = crate::config::profiles::load_profiles();
        let snap = crate::cli::status::scan_status(&profiles, config, config_dir);

        match mode {
            OutputMode::Json => {
                #[derive(Serialize)]
                struct WatchLine {
                    ts: String,
                    state: String,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    profile: Option<String>,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    uptime_secs: Option<u64>,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    health: Option<ConnectionHealthEntry>,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    generation: Option<u64>,
                }
                let line = WatchLine {
                    ts: chrono_now(),
                    state: snap.connection_state,
                    profile: snap.profile,
                    uptime_secs: snap.uptime_secs,
                    health: snap.health.as_ref().map(connection_health_entry),
                    generation: snap.generation,
                };
                println!("{}", serde_json::to_string(&line).unwrap_or_default());
            }
            OutputMode::Human => {
                use std::io::Write;
                if snap.connection_state == "connected" {
                    print!("\r{}", human_status_headline(&snap));
                    if let Some(up) = snap.uptime_secs {
                        let m = up / 60;
                        let s = up % 60;
                        print!(" ({m}m{s}s)");
                    }
                    print!("    ");
                } else {
                    print!("\r{}    ", human_status_headline(&snap));
                }
                let _ = std::io::stdout().flush();
            }
            OutputMode::Quiet => {}
        }

        std::thread::sleep(Duration::from_secs(interval));
    }
}

pub(super) fn human_status_headline(snap: &crate::cli::status::StatusSnapshot) -> String {
    let profile = snap.profile.as_deref().unwrap_or("unknown");
    let protocol = snap.protocol.as_deref().unwrap_or("");
    match snap.connection_state.as_str() {
        "connected" => snap.health.as_ref().map_or_else(
            || format!("● Connected to {profile} ({protocol})"),
            |health| match health {
                crate::tunnel::ConnectionHealth::Degraded { .. } => format!(
                    "⚠ Connected to {profile} ({protocol}) — {}",
                    connection_health_human(health)
                ),
                _ => format!("● Connected to {profile} ({protocol})"),
            },
        ),
        "handshaking" => format!("◐ Handshaking with {profile} (WireGuard)"),
        "connecting" => format!("◐ Connecting to {profile} (OpenVPN)"),
        "reconnecting" => format!("↻ Reconnecting to {profile} ({protocol})"),
        "disconnecting" => format!("◑ Disconnecting {profile} ({protocol})"),
        "awaiting_input" => format!("? Awaiting input for {profile} ({protocol})"),
        _ => "○ Disconnected".to_string(),
    }
}

pub(super) fn connection_health_entry(
    health: &crate::tunnel::ConnectionHealth,
) -> ConnectionHealthEntry {
    use crate::tunnel::ConnectionHealth;
    match health {
        ConnectionHealth::Unknown => ConnectionHealthEntry {
            status: "unknown".into(),
            reason: None,
        },
        ConnectionHealth::Healthy => ConnectionHealthEntry {
            status: "healthy".into(),
            reason: None,
        },
        ConnectionHealth::Degraded { reason } => ConnectionHealthEntry {
            status: "degraded".into(),
            reason: Some(degraded_reason_human(reason)),
        },
    }
}

pub(super) fn connection_health_human(health: &crate::tunnel::ConnectionHealth) -> String {
    use crate::tunnel::ConnectionHealth;
    match health {
        ConnectionHealth::Unknown => "Unknown (measuring)".into(),
        ConnectionHealth::Healthy => "Healthy".into(),
        ConnectionHealth::Degraded { reason } => {
            format!("Degraded: {}", degraded_reason_human(reason))
        }
    }
}

fn degraded_reason_human(reason: &crate::tunnel::DegradedReason) -> String {
    use crate::tunnel::DegradedReason;
    match reason {
        DegradedReason::HandshakeStale {
            seconds_since_last_handshake,
        } => format!("handshake stale for {seconds_since_last_handshake}s"),
        DegradedReason::WireGuardPeerStale {
            peer_public_key,
            allowed_routes,
            seconds_since_last_handshake,
        } => format!(
            "peer {} stale for {}s on {}",
            short_peer(peer_public_key),
            seconds_since_last_handshake,
            allowed_routes.join(",")
        ),
        DegradedReason::WireGuardPeerNeverObserved {
            peer_public_key,
            allowed_routes,
        } => format!(
            "peer {} has no handshake on {}",
            short_peer(peer_public_key),
            allowed_routes.join(",")
        ),
        DegradedReason::HighPacketLoss { loss_percent } => {
            format!("{loss_percent:.1}% packet loss")
        }
        DegradedReason::HighLatency { latency_ms } => format!("{latency_ms}ms latency"),
    }
}

fn short_peer(peer: &str) -> &str {
    peer.get(..peer.len().min(8)).unwrap_or(peer)
}

#[allow(clippy::cast_possible_wrap)]
/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ`.
pub(super) fn chrono_now() -> String {
    time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .ok()
        .and_then(|now| {
            now.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod handshake_status_tests {
    use super::*;
    use crate::cli::tunnel::lifecycle_progress_message;

    #[test]
    fn watch_timestamps_are_whole_second_utc() {
        let ts = chrono_now();
        assert_eq!(ts.len(), 20, "{ts}");
        assert!(ts.ends_with('Z') && ts.as_bytes()[10] == b'T', "{ts}");
    }
    use crate::control::killswitch::{KillSwitchMode, KillSwitchState};

    fn snapshot(state: &str, protocol: &str) -> crate::cli::status::StatusSnapshot {
        crate::cli::status::StatusSnapshot {
            connection_state: state.into(),
            health: None,
            generation: None,
            profile: Some("corp".into()),
            protocol: Some(protocol.into()),
            uptime_secs: None,
            server: None,
            interface: None,
            internal_ip: None,
            download_bytes: None,
            upload_bytes: None,
            killswitch_mode: KillSwitchMode::Off,
            killswitch_state: KillSwitchState::Disabled,
        }
    }

    #[test]
    fn human_and_watch_headline_distinguish_wireguard_from_openvpn() {
        assert_eq!(
            human_status_headline(&snapshot("handshaking", "WireGuard")),
            "◐ Handshaking with corp (WireGuard)"
        );
        assert_eq!(
            human_status_headline(&snapshot("connecting", "OpenVPN")),
            "◐ Connecting to corp (OpenVPN)"
        );
    }

    #[test]
    fn lifecycle_progress_explains_silent_verification_without_spamming() {
        assert_eq!(
            lifecycle_progress_message(
                OutputMode::Human,
                "Connecting",
                "wg13",
                Some("WireGuard"),
                60,
            ),
            Some("◐ Connecting wg13 (WireGuard) — verifying the tunnel and network policy; this may take up to 60s (Ctrl-C stops waiting, not the connecting)…".into())
        );
        assert_eq!(
            lifecycle_progress_message(
                OutputMode::Human,
                "Disconnecting",
                "wg12",
                None,
                30,
            ),
            Some("◐ Disconnecting wg12 — verifying the tunnel and network policy; this may take up to 30s (Ctrl-C stops waiting, not the disconnecting)…".into())
        );
        assert!(lifecycle_progress_message(
            OutputMode::Json,
            "Connecting",
            "wg13",
            Some("WireGuard"),
            60,
        )
        .is_none());
        assert!(lifecycle_progress_message(
            OutputMode::Quiet,
            "Connecting",
            "wg13",
            Some("WireGuard"),
            60,
        )
        .is_none());
    }

    #[test]
    fn human_projection_preserves_typed_health_generation() {
        let degraded = crate::tunnel::ConnectionHealth::Degraded {
            reason: crate::tunnel::DegradedReason::WireGuardPeerStale {
                peer_public_key: "peer-public-key".into(),
                allowed_routes: vec!["10.0.0.0/24".into()],
                seconds_since_last_handshake: 181,
            },
        };
        let mut snap = snapshot("connected", "WireGuard");
        snap.health = Some(degraded.clone());
        snap.generation = Some(7);
        assert!(human_status_headline(&snap).contains("stale for 181s"));
        let projected = connection_health_entry(snap.health.as_ref().unwrap());
        assert_eq!(projected.status, "degraded");
        assert!(projected.reason.unwrap().contains("peer-pub"));
        snap.health = Some(crate::tunnel::ConnectionHealth::Healthy);
        assert_eq!(
            connection_health_entry(snap.health.as_ref().unwrap()).status,
            "healthy"
        );
    }

    #[test]
    fn json_v2_adds_handshaking_without_claiming_a_primary() {
        let entry = ConnectionEntry {
            state: "handshaking".into(),
            profile: Some("corp".into()),
            protocol: Some("WireGuard".into()),
            uptime_secs: None,
            health: None,
            generation: None,
        };
        let data = StatusData {
            connections: vec![entry],
            primary: None,
            connection: None,
            network: None,
            security: StatusSecurity {
                killswitch_mode: "off".into(),
                killswitch_state: "disabled".into(),
            },
        };
        let value = serde_json::to_value(data).unwrap();
        assert_eq!(value["connections"][0]["state"], "handshaking");
        assert!(value["primary"].is_null());
        assert!(value["connection"].is_null());
    }
}
