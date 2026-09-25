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

/// One active tunnel as the CLI scan sees it.
#[derive(Debug, Clone)]
pub struct SessionStatus {
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
}

/// Result of a CLI status scan.
#[derive(Debug)]
pub struct StatusSnapshot {
    /// Every active tunnel, in scanner order.
    pub sessions: Vec<SessionStatus>,
    /// Index into `sessions` of the tunnel carrying the default route.
    pub primary: Option<usize>,
    pub killswitch_mode: crate::control::killswitch::KillSwitchMode,
    pub killswitch_state: crate::control::killswitch::KillSwitchState,
    /// False when the scan could not see every tunnel (without root,
    /// `WireGuard` state cannot be read).
    pub observation_complete: bool,
}

/// Printed instead of "Disconnected" when nothing was seen but the scan was
/// incomplete: an unprivileged `status` cannot see `WireGuard` tunnels.
const UNKNOWN_HEADLINE: &str =
    "? Tunnel state unknown: WireGuard tunnels are only visible to root. Run: sudo vortix status";

impl StatusSnapshot {
    /// Nothing seen, but the scan could not see everything.
    #[must_use]
    pub fn state_unknown(&self) -> bool {
        self.sessions.is_empty() && !self.observation_complete
    }

    /// The tunnel a one-line summary describes: the primary, else the first.
    #[must_use]
    pub fn focus(&self) -> Option<&SessionStatus> {
        self.primary
            .and_then(|index| self.sessions.get(index))
            .or_else(|| self.sessions.first())
    }
}

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

/// One-shot status scan for CLI.
#[must_use]
pub fn scan_status(
    profiles: &[VpnProfile],
    config: &AppConfig,
    config_dir: &std::path::Path,
) -> StatusSnapshot {
    let (killswitch_mode, killswitch_state) = crate::control::killswitch::persisted();
    let (active, observation_complete) = scanner::scan_active_profiles(profiles);
    let default_interface = if active.is_empty() {
        None
    } else {
        crate::platform::Routes::default_route_observation()
            .interface()
            .map(str::to_string)
    };
    let sessions: Vec<SessionStatus> = active
        .iter()
        .map(|session| session_status(session, profiles, config, config_dir))
        .collect();
    let primary = default_interface.and_then(|interface| {
        sessions
            .iter()
            .position(|session| session.interface.as_deref() == Some(interface.as_str()))
    });
    StatusSnapshot {
        sessions,
        primary,
        killswitch_mode,
        killswitch_state,
        observation_complete,
    }
}

fn session_status(
    session: &scanner::ActiveSession,
    profiles: &[VpnProfile],
    config: &AppConfig,
    config_dir: &std::path::Path,
) -> SessionStatus {
    let profile = profiles.iter().find(|p| p.name == session.name);
    let proto = profile.map(|p| p.protocol);
    // Direct scanner state is observation-only. Even a fresh or historically
    // non-zero handshake timestamp cannot recreate the current attempt
    // generation and ownership receipt.
    let mut status = SessionStatus {
        connection_state: if matches!(proto, Some(ProtocolKind::WireGuard)) {
            "handshaking"
        } else {
            "connected"
        }
        .to_string(),
        health: None,
        generation: None,
        profile: Some(session.name.clone()),
        protocol: proto.map(|p| format!("{p}")),
        uptime_secs: session.started_at.and_then(|started| {
            std::time::SystemTime::now()
                .duration_since(started)
                .ok()
                .map(|d| d.as_secs())
        }),
        server: nonempty(&session.details.endpoint),
        interface: nonempty(&session.details.interface),
        internal_ip: nonempty(&session.details.internal_ip),
        download_bytes: nonempty(&session.details.transfer_rx),
        upload_bytes: nonempty(&session.details.transfer_tx),
    };
    let Some(profile) = profile.filter(|profile| profile.protocol == ProtocolKind::WireGuard)
    else {
        return status;
    };
    let Some(mut receipt) = crate::wireguard::receipt::load(config_dir, &profile.id)
        .filter(|receipt| receipt.validates(&profile.id, session))
    else {
        return status;
    };
    let mut activity = crate::wireguard::receipt::PeerActivity::new();
    let current = crate::wireguard::receipt::health_from_peers(
        &session.wireguard_peers,
        &mut activity,
        &receipt.probe_receipts,
        Duration::from_secs(config.wireguard_handshake_stale_secs),
    );
    if let Ok(Some(old)) =
        crate::wireguard::receipt::update_health(config_dir, &mut receipt, current.clone())
    {
        if let Some(journal) = crate::journal::global_journal() {
            let _ = journal.append(crate::journal::JournalEvent::ConnectionHealthChanged {
                profile_id: profile.id.clone(),
                old,
                new: current.clone(),
            });
        }
    }
    status.connection_state = "connected".into();
    status.generation = Some(receipt.generation);
    status.health = Some(current);
    status
}

/// `status` command JSON payload.
///
/// Shape is pinned by the v2 schema (see [`crate::cli::output`] module
/// docs):
///
/// - `connections`: all currently active tunnels. Empty when nothing is
///   connected. v2 readers should prefer this field.
/// - `primary`: profile of the tunnel carrying the default route, or `null`
///   when none does (no tunnels, or only split tunnels).
/// - `connection`: v1 back-compat. The focused tunnel (primary, else the
///   first) when it is connected, `null` otherwise.
#[derive(Serialize)]
struct StatusData {
    connections: Vec<ConnectionEntry>,
    primary: Option<String>,
    connection: Option<ConnectionEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<StatusNetwork>,
    security: StatusSecurity,
    observation_complete: bool,
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
    let focus = snap.focus();
    let is_connected = focus.is_some_and(|session| session.connection_state == "connected");
    let is_present = focus.is_some();

    let data = status_data(&snap);

    match mode {
        OutputMode::Human => {
            if brief {
                println!("{}", snapshot_headline(&snap));
            } else if let Some(session) = focus.filter(|_| is_connected) {
                let profile = session.profile.as_deref().unwrap_or("unknown");
                let protocol = session.protocol.as_deref().unwrap_or("");
                println!("● Connected to {profile} ({protocol})");
                println!();
                if let Some(s) = &session.server {
                    println!("  Server       {s}");
                }
                if let Some(i) = &session.interface {
                    println!("  Interface    {i}");
                }
                if let Some(ip) = &session.internal_ip {
                    println!("  Internal IP  {ip}");
                }
                if let Some(up) = &session.uptime_secs {
                    let h = up / 3600;
                    let m = (up % 3600) / 60;
                    let s = up % 60;
                    println!("  Uptime       {h}h {m}m {s}s");
                }
                if let Some(dl) = &session.download_bytes {
                    println!("  Transfer     ↓ {dl}");
                }
                if let Some(ul) = &session.upload_bytes {
                    println!("               ↑ {ul}");
                }
                println!(
                    "  Kill Switch  {} ({})",
                    snap.killswitch_mode.display_name(),
                    snap.killswitch_state.display_status()
                );
                if let Some(health) = &session.health {
                    println!("  Health       {}", connection_health_human(health));
                }
            } else {
                println!("{}", snapshot_headline(&snap));
                println!();
                println!(
                    "  Kill Switch  {} ({})",
                    snap.killswitch_mode.display_name(),
                    snap.killswitch_state.display_status()
                );
            }
            if !brief {
                for line in other_tunnel_lines(&snap) {
                    println!("{line}");
                }
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

fn status_data(snap: &StatusSnapshot) -> StatusData {
    let focus = snap.focus();
    let is_connected = focus.is_some_and(|session| session.connection_state == "connected");
    let entry = |session: &SessionStatus| ConnectionEntry {
        state: session.connection_state.clone(),
        profile: session.profile.clone(),
        protocol: session.protocol.clone(),
        uptime_secs: session.uptime_secs,
        health: session.health.as_ref().map(connection_health_entry),
        generation: session.generation,
    };
    StatusData {
        observation_complete: snap.observation_complete,
        connections: snap.sessions.iter().map(entry).collect(),
        primary: snap
            .primary
            .and_then(|index| snap.sessions.get(index))
            .and_then(|session| session.profile.clone()),
        connection: focus.filter(|_| is_connected).map(entry),
        network: focus.filter(|_| is_connected).map(|session| StatusNetwork {
            server: session.server.clone(),
            interface: session.interface.clone(),
            internal_ip: session.internal_ip.clone(),
            download: session.download_bytes.clone(),
            upload: session.upload_bytes.clone(),
        }),
        security: StatusSecurity {
            killswitch_mode: snap.killswitch_mode.cli_verb().to_string(),
            killswitch_state: snap.killswitch_state.cli_verb().to_string(),
        },
    }
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
                    tunnels: usize,
                }
                let focus = snap.focus();
                let line = WatchLine {
                    ts: chrono_now(),
                    state: focus.map_or_else(
                        || {
                            if snap.state_unknown() {
                                "unknown"
                            } else {
                                "disconnected"
                            }
                            .to_string()
                        },
                        |session| session.connection_state.clone(),
                    ),
                    profile: focus.and_then(|session| session.profile.clone()),
                    uptime_secs: focus.and_then(|session| session.uptime_secs),
                    health: focus
                        .and_then(|session| session.health.as_ref())
                        .map(connection_health_entry),
                    generation: focus.and_then(|session| session.generation),
                    tunnels: snap.sessions.len(),
                };
                println!("{}", serde_json::to_string(&line).unwrap_or_default());
            }
            OutputMode::Human => {
                use std::io::Write;
                let focus = snap.focus();
                if let Some(session) =
                    focus.filter(|session| session.connection_state == "connected")
                {
                    print!("\r{}", human_status_headline(focus));
                    if let Some(up) = session.uptime_secs {
                        let m = up / 60;
                        let s = up % 60;
                        print!(" ({m}m{s}s)");
                    }
                    print!("    ");
                } else {
                    print!("\r{}    ", snapshot_headline(&snap));
                }
                let _ = std::io::stdout().flush();
            }
            OutputMode::Quiet => {}
        }

        std::thread::sleep(Duration::from_secs(interval));
    }
}

/// One line per tunnel besides the focused one, so a multi-tunnel host is
/// not reported as a single connection.
fn other_tunnel_lines(snap: &StatusSnapshot) -> Vec<String> {
    let focus = snap.focus().and_then(|focus| focus.profile.clone());
    let others: Vec<&SessionStatus> = snap
        .sessions
        .iter()
        .filter(|session| session.profile != focus)
        .collect();
    if others.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![String::new(), "  Also active".to_string()];
    for session in others {
        let profile = session.profile.as_deref().unwrap_or("unknown");
        let protocol = session.protocol.as_deref().unwrap_or("");
        let interface = session
            .interface
            .as_deref()
            .map_or_else(String::new, |interface| format!(" [{interface}]"));
        lines.push(format!(
            "    {profile} ({protocol}){interface} — {}",
            session.connection_state
        ));
    }
    lines
}

fn snapshot_headline(snap: &StatusSnapshot) -> String {
    if snap.state_unknown() {
        UNKNOWN_HEADLINE.to_string()
    } else {
        human_status_headline(snap.focus())
    }
}

pub(super) fn human_status_headline(session: Option<&SessionStatus>) -> String {
    let Some(snap) = session else {
        return "○ Disconnected".to_string();
    };
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

    fn snapshot(state: &str, protocol: &str) -> SessionStatus {
        SessionStatus {
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
        }
    }

    fn tunnels(sessions: Vec<SessionStatus>, primary: Option<usize>) -> StatusSnapshot {
        StatusSnapshot {
            sessions,
            primary,
            killswitch_mode: KillSwitchMode::Off,
            killswitch_state: KillSwitchState::Disabled,
            observation_complete: true,
        }
    }

    /// Without root `wg show` fails, so an empty scan is not "Disconnected":
    /// saying so while a `WireGuard` tunnel was up misreported protection.
    #[test]
    fn an_incomplete_empty_scan_is_unknown_not_disconnected() {
        let mut snap = tunnels(Vec::new(), None);
        assert_eq!(snapshot_headline(&snap), "○ Disconnected");
        snap.observation_complete = false;
        assert!(snapshot_headline(&snap).starts_with("? Tunnel state unknown"));
        assert!(snapshot_headline(&snap).contains("sudo vortix status"));
    }

    fn session(name: &str, interface: &str) -> SessionStatus {
        SessionStatus {
            profile: Some(name.into()),
            interface: Some(interface.into()),
            ..snapshot("connected", "OpenVPN")
        }
    }

    #[test]
    fn status_lists_every_tunnel_and_only_the_route_owner_is_primary() {
        let snap = tunnels(
            vec![session("split", "utun5"), session("full", "utun4")],
            Some(1),
        );
        let value = serde_json::to_value(status_data(&snap)).unwrap();
        assert_eq!(value["connections"].as_array().unwrap().len(), 2);
        assert_eq!(value["primary"], "full");
        assert_eq!(value["connection"]["profile"], "full");
        assert_eq!(value["network"]["interface"], "utun4");
        let others = other_tunnel_lines(&snap).join("\n");
        assert!(others.contains("split (OpenVPN) [utun5]"), "{others}");
        assert!(!others.contains("full"), "{others}");
    }

    #[test]
    fn a_split_tunnel_alone_is_not_primary() {
        let snap = tunnels(vec![session("split", "utun5")], None);
        let value = serde_json::to_value(status_data(&snap)).unwrap();
        assert!(value["primary"].is_null());
        assert_eq!(value["connection"]["profile"], "split");
        assert!(other_tunnel_lines(&snap).is_empty());
    }

    #[test]
    fn human_and_watch_headline_distinguish_wireguard_from_openvpn() {
        assert_eq!(
            human_status_headline(Some(&snapshot("handshaking", "WireGuard"))),
            "◐ Handshaking with corp (WireGuard)"
        );
        assert_eq!(
            human_status_headline(Some(&snapshot("connecting", "OpenVPN"))),
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
        assert!(human_status_headline(Some(&snap)).contains("stale for 181s"));
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
            observation_complete: true,
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
