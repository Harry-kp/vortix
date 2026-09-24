//! Headless VPN runtime — owns telemetry, profiles, config, and worker channels.
//!
//! `VpnRuntime` holds connection-state mirror (CLI-only — TUI consults
//! `TunnelRegistry`), profiles, telemetry data, kill switch state, retry
//! logic, and background worker channels. It has **zero** ratatui
//! dependencies, making it usable from both the TUI ([`crate::app::App`])
//! and the CLI without pulling in any terminal rendering code.
//!
//! The TUI embeds `VpnRuntime` as `App.runtime` (no `Deref`); field
//! accesses go through `self.runtime.X` or `app.runtime.X` explicitly.

pub mod connection {
    //! Read-only connection status projection used by CLI compatibility output.

    use std::time::Duration;

    use crate::core::profile::ProtocolKind;
    use crate::core::scanner;

    use super::VpnRuntime;

    fn wireguard_health_from_session(
        peers: &[crate::core::ports::tunnel::TunnelPeerStatus],
        activity: &mut std::collections::HashMap<String, crate::vpn_runtime::WireGuardPeerActivity>,
        probe_receipts: &[crate::core::ports::tunnel::ProbeReceipt],
        stale_after: std::time::Duration,
    ) -> crate::core::engine::state::ConnectionHealth {
        use crate::core::engine::state::{ConnectionHealth, DegradedReason};
        use crate::core::ports::tunnel::{
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
                if peer.bytes_rx > peer_activity.bytes_rx || peer.bytes_tx > peer_activity.bytes_tx
                {
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
                PeerHandshakeHealth::Healthy { .. }
                | PeerHandshakeHealth::InformationalIdle { .. } => {}
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
    }

    impl VpnRuntime {
        /// One-shot status scan for CLI.
        #[must_use]
        #[allow(clippy::too_many_lines)]
        pub fn scan_status(&self) -> StatusSnapshot {
            let (killswitch_mode, killswitch_state) = crate::core::killswitch::persisted();
            let active = scanner::get_active_profiles(&self.profiles);
            let session = active.first();
            let (mut state, profile, protocol, uptime, server, interface, internal_ip, dl, ul) =
                if let Some(s) = session {
                    let proto = self
                        .profiles
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
                if let Some(profile) = self.profiles.iter().find(|profile| {
                    profile.name == session.name && profile.protocol == ProtocolKind::WireGuard
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
    }
}
pub mod connection_state {
    //! Single-tunnel `ConnectionState` enum retained only as the derived return
    //! type of `App::legacy_state()`.
    //!
    //! After plan P5d the canonical source of truth for active VPN state on
    //! the App side is the [`crate::core::engine::TunnelRegistry`] that
    //! lives on [`crate::app::App`]. The `connection_state` field on
    //! `VpnRuntime` is gone; every panel renderer reads `app.registry`
    //! snapshots directly.
    //!
    //! [`crate::app::App::legacy_state`] returns this enum as a derived
    //!    view of the registry primary so the few residual single-tunnel-
    //!    shaped reads (kill-switch sync, profile-delete safety,
    //!    scanner-dispatch helpers) keep working without a stored field.
    //!
    //! Visibility: still re-exported from [`crate::vpn_runtime`] for that
    //! compatibility view, but **not** from [`crate::state`] — panels never see it.

    use std::time::Instant;

    /// The canonical tunnel details. This module used to carry its own copy with
    /// the same field names and types, and a hand-written copy in `app/helpers.rs`
    /// moved values between the two.
    pub use crate::core::engine::state::DetailedConnectionInfo;

    /// VPN connection state machine (legacy single-tunnel mirror).
    ///
    /// A follow-up will retire this in favour of the per-tunnel
    /// [`crate::core::engine::state::Connection`] FSM owned by
    /// [`crate::core::engine::TunnelRegistry`].
    #[derive(Clone, Debug, PartialEq, Default)]
    pub enum ConnectionState {
        /// No active VPN connection.
        #[default]
        Disconnected,
        /// Connection attempt in progress.
        Connecting {
            /// When the connection attempt started.
            started: Instant,
            /// Name of the profile being connected.
            profile: String,
        },
        /// Active VPN connection established.
        Connected {
            /// When the connection was established.
            since: Instant,
            /// Name of the connected profile.
            profile: String,
            /// Geographic location of the server.
            server_location: String,
            /// Current latency in milliseconds.
            latency_ms: u64,
            /// Detailed connection information.
            details: Box<DetailedConnectionInfo>,
        },
        /// Disconnection in progress.
        Disconnecting {
            /// When the disconnection attempt started.
            started: Instant,
            /// Name of the profile being disconnected.
            profile: String,
        },
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_default_state_is_disconnected() {
            let state = ConnectionState::default();
            assert!(matches!(state, ConnectionState::Disconnected));
        }

        #[test]
        fn test_connecting_state() {
            let state = ConnectionState::Connecting {
                started: Instant::now(),
                profile: "test-vpn".to_string(),
            };
            if let ConnectionState::Connecting { profile, .. } = &state {
                assert_eq!(profile, "test-vpn");
            } else {
                panic!("Expected Connecting state");
            }
        }

        #[test]
        fn test_connected_state() {
            let state = ConnectionState::Connected {
                since: Instant::now(),
                profile: "test-vpn".to_string(),
                server_location: "US".to_string(),
                latency_ms: 42,
                details: Box::new(DetailedConnectionInfo {
                    interface: "utun3".to_string(),
                    internal_ip: "10.0.0.2".to_string(),
                    endpoint: "1.2.3.4:51820".to_string(),
                    ..Default::default()
                }),
            };
            if let ConnectionState::Connected {
                profile, details, ..
            } = &state
            {
                assert_eq!(profile, "test-vpn");
                assert_eq!(details.interface, "utun3");
                assert_eq!(details.internal_ip, "10.0.0.2");
            } else {
                panic!("Expected Connected state");
            }
        }

        #[test]
        fn test_disconnecting_state() {
            let state = ConnectionState::Disconnecting {
                started: Instant::now(),
                profile: "test-vpn".to_string(),
            };
            assert!(matches!(state, ConnectionState::Disconnecting { .. }));
        }

        #[test]
        fn test_detailed_connection_info_default() {
            let info = DetailedConnectionInfo::default();
            assert!(info.interface.is_empty());
            assert!(info.internal_ip.is_empty());
            assert!(info.endpoint.is_empty());
            assert!(info.pid.is_none());
        }

        #[test]
        fn test_state_equality() {
            let s1 = ConnectionState::Disconnected;
            let s2 = ConnectionState::Disconnected;
            assert_eq!(s1, s2);
        }

        #[test]
        fn test_state_transitions_are_valid() {
            let mut state = ConnectionState::Disconnected;
            assert!(matches!(state, ConnectionState::Disconnected));

            state = ConnectionState::Connecting {
                started: Instant::now(),
                profile: "vpn".to_string(),
            };
            assert!(matches!(state, ConnectionState::Connecting { .. }));

            state = ConnectionState::Connected {
                since: Instant::now(),
                profile: "vpn".to_string(),
                server_location: "US".to_string(),
                latency_ms: 10,
                details: Box::new(DetailedConnectionInfo::default()),
            };
            assert!(matches!(state, ConnectionState::Connected { .. }));

            state = ConnectionState::Disconnecting {
                started: Instant::now(),
                profile: "vpn".to_string(),
            };
            assert!(matches!(state, ConnectionState::Disconnecting { .. }));

            state = ConnectionState::Disconnected;
            assert!(matches!(state, ConnectionState::Disconnected));
        }
    }
}
pub mod openvpn {
    //! `OpenVPN` version detection + the multi-tunnel `--pull-filter` baseline
    //! probe.
    //!
    //! Both the TUI and the CLI need to assert `OpenVPN` ≥ 2.4 before a
    //! connect can proceed — older builds silently
    //! ignore `--pull-filter` and leak pushed DNS into the primary tunnel's
    //! resolver. The probe lives here so both surfaces resolve through the
    //! same `VpnRuntime::check_dependencies` call site instead of one
    //! running the gate (TUI) and the other skipping it (CLI).

    use std::sync::OnceLock;
    use std::time::Duration;

    use crate::process::{self, CommandSpec};

    /// Semantic version of an installed `openvpn` binary, as reported by
    /// `openvpn --version`. Used by `check_dependencies` to assert the
    /// `--pull-filter` multi-tunnel-DNS-suppression baseline.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub struct OvpnVersion {
        pub major: u32,
        pub minor: u32,
        pub patch: u32,
    }

    impl OvpnVersion {
        /// Minimum `OpenVPN` release supporting `--pull-filter` reliably. Anything
        /// older fails multi-tunnel's DNS-scoping precondition.
        const MIN_MULTI_TUNNEL: Self = Self {
            major: 2,
            minor: 4,
            patch: 0,
        };

        #[must_use]
        pub fn supports_multi_tunnel_dns(self) -> bool {
            self >= Self::MIN_MULTI_TUNNEL
        }
    }

    impl std::fmt::Display for OvpnVersion {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        }
    }

    /// Outcome of probing `openvpn --version`.
    #[derive(Debug, Clone)]
    pub enum OvpnVersionProbe {
        /// Parsed a usable semantic version from `--version` stdout.
        Parsed(OvpnVersion),
        /// `--version` ran but its first line did not contain a parseable
        /// `OpenVPN <X.Y.Z>` token. The `--help` fallback was consulted and
        /// confirmed `--pull-filter` is present.
        HelpFallbackOk,
        /// Both `--version` parsing and the `--help` fallback failed — we cannot
        /// confirm the binary supports `--pull-filter`. Treated as a missing
        /// dependency for multi-tunnel.
        Unparseable,
    }

    /// Parse the `OpenVPN` semantic version from the first line of `openvpn --version`.
    ///
    /// The stable format across `OpenVPN` 2.x / 3.x releases is:
    /// `OpenVPN <major>.<minor>.<patch>[<suffix>] ...`. Vendor-patched builds
    /// occasionally prefix the line (e.g. `Vendor-OpenVPN 2.5.8 ...`) — we scan
    /// for the `OpenVPN ` token rather than anchoring to the start so those still
    /// parse.
    #[must_use]
    pub fn parse_openvpn_version(stdout: &str) -> Option<OvpnVersion> {
        let first_line = stdout.lines().next()?;
        let after = first_line.find("OpenVPN ").map(|i| i + "OpenVPN ".len())?;
        let rest = &first_line[after..];
        let token = rest.split_whitespace().next()?;
        let core: String = token
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        let mut parts = core.split('.');
        let major = parts.next()?.parse::<u32>().ok()?;
        let minor = parts.next()?.parse::<u32>().ok()?;
        let patch = parts.next().unwrap_or("0").parse::<u32>().unwrap_or(0);
        Some(OvpnVersion {
            major,
            minor,
            patch,
        })
    }

    /// Cached outcome of probing `openvpn --version`. The subprocess
    /// runs at most once per process lifetime; subsequent dependency checks reuse
    /// the cached value.
    static OVPN_VERSION_PROBE: OnceLock<OvpnVersionProbe> = OnceLock::new();

    /// Probe the installed `openvpn` for its version, falling back to a `--help`
    /// grep when `--version` is unparseable. Cached for the process lifetime.
    #[must_use]
    pub fn probe_openvpn_version() -> OvpnVersionProbe {
        OVPN_VERSION_PROBE
            .get_or_init(probe_openvpn_version_uncached)
            .clone()
    }

    /// Upper bound on the version-probe subprocess. The probe runs on the UI
    /// thread (via `check_dependencies` on every connect attempt), so a slow or
    /// hung `openvpn --version` would freeze the TUI. 10 seconds is generous
    /// for a first-run launch (Gatekeeper / antivirus / Spotlight on macOS;
    /// cold cache on Linux) and short enough that the user notices a UX bug
    /// rather than concluding vortix is broken. On timeout we fall through to
    /// `Unparseable` (fail-open with a tracing warning) — same as if `openvpn`
    /// returned malformed output.
    const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

    fn probe_openvpn_version_uncached() -> OvpnVersionProbe {
        // xtask:allow-protocol-leak: dependency-version probe runs before any tunnel exists; pre-flight gate
        let version_output = process::run_to_output(
            CommandSpec::oneshot("openvpn", vec!["--version".into()]).timeout(PROBE_TIMEOUT),
        );
        if let Ok(out) = version_output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if let Some(v) = parse_openvpn_version(&stdout) {
                return OvpnVersionProbe::Parsed(v);
            }
            let stderr = String::from_utf8_lossy(&out.stderr);
            if let Some(v) = parse_openvpn_version(&stderr) {
                return OvpnVersionProbe::Parsed(v);
            }
        }

        // xtask:allow-protocol-leak: dependency-feature probe runs before any tunnel exists; pre-flight gate
        let help_output = process::run_to_output(
            CommandSpec::oneshot("openvpn", vec!["--help".into()]).timeout(PROBE_TIMEOUT),
        );
        if let Ok(out) = help_output {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            );
            if combined.contains("--pull-filter") {
                return OvpnVersionProbe::HelpFallbackOk;
            }
        }

        OvpnVersionProbe::Unparseable
    }

    #[cfg(test)]
    mod tests {
        //! Tests for the `OpenVPN` `--version` parsing and the 2.4+
        //! precondition assertion. The parse helper is pure so we can cover the
        //! happy path, the major-bump edge case, and the malformed-output
        //! fallback without spawning a subprocess.
        use super::{parse_openvpn_version, OvpnVersion};

        #[test]
        fn parses_standard_first_line() {
            let stdout =
            "OpenVPN 2.5.8 [git:release/2.5/...] x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4]";
            let v = parse_openvpn_version(stdout).expect("should parse");
            assert_eq!(
                v,
                OvpnVersion {
                    major: 2,
                    minor: 5,
                    patch: 8
                }
            );
            assert!(v.supports_multi_tunnel_dns());
        }

        #[test]
        fn parses_exact_2_4_0_as_passing() {
            let v = parse_openvpn_version("OpenVPN 2.4.0 amd64-pc-linux").expect("should parse");
            assert_eq!(
                v,
                OvpnVersion {
                    major: 2,
                    minor: 4,
                    patch: 0
                }
            );
            assert!(v.supports_multi_tunnel_dns());
        }

        #[test]
        fn rejects_2_3_18_below_baseline() {
            let v = parse_openvpn_version("OpenVPN 2.3.18 x86_64").expect("should parse");
            assert_eq!(
                v,
                OvpnVersion {
                    major: 2,
                    minor: 3,
                    patch: 18
                }
            );
            assert!(!v.supports_multi_tunnel_dns());
        }

        #[test]
        fn accepts_major_version_3() {
            let v = parse_openvpn_version("OpenVPN 3.0.0 something").expect("should parse");
            assert_eq!(
                v,
                OvpnVersion {
                    major: 3,
                    minor: 0,
                    patch: 0
                }
            );
            assert!(v.supports_multi_tunnel_dns());
        }

        #[test]
        fn handles_vendor_prefix_via_token_scan() {
            let v =
                parse_openvpn_version("vendor-patched OpenVPN 2.6.10 abc").expect("should parse");
            assert_eq!(
                v,
                OvpnVersion {
                    major: 2,
                    minor: 6,
                    patch: 10
                }
            );
        }

        #[test]
        fn strips_trailing_non_numeric_suffix() {
            let v = parse_openvpn_version("OpenVPN 2.5.8-git build").expect("should parse");
            assert_eq!(
                v,
                OvpnVersion {
                    major: 2,
                    minor: 5,
                    patch: 8
                }
            );
        }

        #[test]
        fn returns_none_on_malformed_output() {
            // No `OpenVPN ` marker → unparseable → caller's `--help` fallback fires.
            assert!(parse_openvpn_version("Custom-VPN-Tool 1.2.3").is_none());
            assert!(parse_openvpn_version("").is_none());
            assert!(parse_openvpn_version("OpenVPN notaversion").is_none());
        }

        #[test]
        fn major_minor_only_accepts_with_zero_patch() {
            // Some banners only emit major.minor — accept with implicit .0 patch.
            let v = parse_openvpn_version("OpenVPN 2.5 something").expect("should parse");
            assert_eq!(
                v,
                OvpnVersion {
                    major: 2,
                    minor: 5,
                    patch: 0
                }
            );
        }

        #[test]
        fn ordering_is_semver_like() {
            let a = OvpnVersion {
                major: 2,
                minor: 4,
                patch: 0,
            };
            let b = OvpnVersion {
                major: 2,
                minor: 3,
                patch: 99,
            };
            assert!(a > b);
            let c = OvpnVersion {
                major: 3,
                minor: 0,
                patch: 0,
            };
            assert!(c > a);
        }
    }
}

pub use connection_state::{ConnectionState, DetailedConnectionInfo};

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::config::AppConfig;
use crate::constants;
use crate::core::profile::ProtocolKind;
use crate::core::telemetry::{self, TelemetryUpdate};
use crate::message::Message;
use crate::state::{ProfileSortOrder, VpnProfile};

use crate::utils;

/// Last accepted counter sample for one `WireGuard` peer. Cumulative byte
/// totals are not activity by themselves: only a positive delta between two
/// ordered observations advances `last_transfer_at`.
#[derive(Debug, Clone)]
pub(crate) struct WireGuardPeerActivity {
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub observed_at: std::time::SystemTime,
    pub last_transfer_at: Option<std::time::SystemTime>,
}

/// Core VPN engine — all VPN-related state, no UI dependencies.
///
/// Created by [`VpnRuntime::new`] for TUI use (spawns background workers) or
/// [`VpnRuntime::new_headless`] for CLI one-shot commands (no background threads).
#[allow(clippy::struct_excessive_bools)]
pub struct VpnRuntime {
    // === VPN State ===
    pub profiles: Vec<VpnProfile>,

    // === Network Telemetry ===
    pub down_history: VecDeque<f64>,
    pub up_history: VecDeque<f64>,
    pub current_down: u64,
    pub current_up: u64,
    pub latency_ms: u64,
    pub packet_loss: f32,
    pub jitter_ms: u64,
    pub location: String,
    pub isp: String,
    pub dns_server: String,

    // === System Info ===
    pub public_ip: String,
    pub real_ip: Option<String>,
    pub public_ipv6: Option<String>,
    pub real_ipv6: Option<String>,
    /// True while `real_ip` is only the address the cache remembers, with no
    /// unprotected observation in this session to confirm it. The Security
    /// Guard must not present such a value as a current fact.
    pub real_ip_from_cache: bool,
    /// Same, for `real_ipv6`.
    pub real_ipv6_from_cache: bool,
    pub last_ipv6_check: Option<Instant>,
    /// When the public-address probe last landed — the observation behind
    /// `public_ip`, `isp` and `location`.
    pub last_egress_check: Option<Instant>,
    /// When the resolver read last landed — the observation behind
    /// `dns_server`.
    pub last_dns_check: Option<Instant>,
    /// Most recent of any telemetry observation. Useful as "something is
    /// alive"; never as the age of a particular field, because each field is
    /// refreshed by its own probe on its own schedule.
    pub last_security_check: Option<Instant>,
    pub ip_unchanged_warned: bool,

    /// True once the scanner has completed at least one
    /// `Message::SyncSystemState` tick. Until then we don't know
    /// whether the kernel has any active VPN interfaces, so the
    /// real-IP cache gate must withhold trust on the first
    /// telemetry sample. Without this flag, vortix opened while a
    /// VPN is already up races: telemetry returns the VPN's exit
    /// IP, the registry is briefly empty (adoption hasn't run
    /// yet), and the wrong IP gets cached as `real_ip`.
    pub scanner_first_tick_done: bool,

    /// Number of kernel-visible VPN sessions observed at the most
    /// recent scanner tick. Reading raw kernel state (not the
    /// registry) catches tunnels that have not yet been adopted —
    /// e.g. an OVPN process running outside vortix on macOS where
    /// adoption needs the lsof Method A probe to attribute the
    /// iface to the PID. Real-IP caching requires this to be zero.
    pub last_kernel_session_count: usize,
    /// Interface the kernel's default route currently uses, as last observed.
    /// The real-IP gate needs this because a tunnel Vortix does not manage
    /// still carries the egress it would otherwise record as the real address.
    pub default_route_interface: Option<String>,

    // === Configuration ===
    pub config: AppConfig,
    pub config_dir: PathBuf,
    pub is_root: bool,

    // === Connection Management ===
    pub connection_drops: u32,
    pub sort_order: ProfileSortOrder,

    // === Async Communication ===
    pub(crate) telemetry_rx: Option<mpsc::Receiver<TelemetryUpdate>>,
    pub telemetry_nudge: Option<mpsc::Sender<()>>,
    pub(crate) cmd_tx: mpsc::Sender<Message>,
    pub(crate) cmd_rx: mpsc::Receiver<Message>,
    pub(crate) netstats_rx: Option<mpsc::Receiver<(u64, u64)>>,
    pub(crate) last_bytes_in: u64,
    pub(crate) last_bytes_out: u64,
}

/// The real addresses Vortix remembers from an earlier unprotected session.
///
/// A record older than the cache ceiling describes a network the host may
/// have left days ago. Restoring it would put a stale address in the leak
/// indicator, so an expired record is not restored at all — the field reads
/// unknown until a live observation replaces it.
fn remembered_real_addresses(config_dir: &std::path::Path) -> (Option<String>, Option<String>) {
    let max_age = Duration::from_secs(constants::REAL_IP_CACHE_MAX_AGE_SECS);
    (
        crate::core::real_ip_cache::load_recent(config_dir, max_age).map(|cached| cached.ip),
        crate::core::real_ip_cache::load_recent_ipv6(config_dir, max_age).map(|cached| cached.ip),
    )
}
impl VpnRuntime {
    /// Every field, with nothing detected and no background work started.
    ///
    /// The three public constructors differ by a handful of fields and what
    /// they do afterwards, so they share this and apply their own deltas. A
    /// new field is added here once instead of in three literals that have to
    /// be kept in step.
    fn blank(config: AppConfig, config_dir: PathBuf) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel::<Message>();
        let history_size = constants::NETWORK_HISTORY_SIZE;
        Self {
            profiles: Vec::new(),

            down_history: VecDeque::from(vec![0.0; history_size]),
            up_history: VecDeque::from(vec![0.0; history_size]),
            current_down: 0,
            current_up: 0,
            latency_ms: 0,
            packet_loss: 0.0,
            jitter_ms: 0,
            location: String::new(),
            isp: String::new(),
            dns_server: String::new(),

            public_ip: String::new(),
            real_ip: None,
            public_ipv6: None,
            real_ipv6: None,
            real_ip_from_cache: false,
            real_ipv6_from_cache: false,
            last_ipv6_check: None,
            last_egress_check: None,
            last_dns_check: None,
            last_security_check: None,
            ip_unchanged_warned: false,
            scanner_first_tick_done: false,
            last_kernel_session_count: 0,
            default_route_interface: None,

            config,
            config_dir,
            is_root: utils::is_root(),

            connection_drops: 0,
            sort_order: ProfileSortOrder::default(),

            telemetry_rx: None,
            telemetry_nudge: None,
            cmd_tx,
            cmd_rx,
            netstats_rx: None,
            last_bytes_in: 0,
            last_bytes_out: 0,
        }
    }

    /// Long-lived engine for the TUI: detects telemetry and runs background workers.
    #[must_use]
    pub fn new(config: AppConfig, config_dir: PathBuf) -> Self {
        let mut engine = Self::blank(config, config_dir);
        engine.location = constants::MSG_DETECTING.to_string();
        engine.isp = constants::MSG_DETECTING.to_string();
        engine.dns_server = constants::MSG_DETECTING.to_string();
        engine.public_ip = constants::MSG_DETECTING.to_string();

        // Remembered only until reconfirmed, so launch-with-VPN-up still shows a real IP.
        let (remembered_ipv4, remembered_ipv6) = remembered_real_addresses(&engine.config_dir);
        if let Some(ip) = remembered_ipv4 {
            engine.real_ip = Some(ip);
            engine.real_ip_from_cache = true;
        }
        if let Some(ip) = remembered_ipv6 {
            engine.real_ipv6 = Some(ip);
            engine.real_ipv6_from_cache = true;
        }

        engine.profiles = crate::vpn::load_profiles();
        engine.start_background_workers();
        engine
    }

    /// One-shot engine for the CLI: no telemetry placeholders, no background threads.
    #[must_use]
    pub fn new_headless(config: AppConfig, config_dir: PathBuf) -> Self {
        let mut engine = Self::blank(config, config_dir);
        engine.profiles = crate::vpn::load_profiles();
        engine
    }

    /// Lightweight constructor for testing — no background threads, no disk I/O.
    #[must_use]
    pub fn new_test() -> Self {
        let mut engine = Self::blank(
            AppConfig::default(),
            std::env::temp_dir().join("vortix_test"),
        );
        engine.is_root = false;
        engine
    }

    /// Start presentation-only telemetry workers.
    pub fn start_background_workers(&mut self) {
        let telemetry_config = telemetry::TelemetryConfig::from(&self.config);
        let (telem_rx, telem_nudge) = telemetry::spawn_telemetry_worker(telemetry_config);
        self.telemetry_rx = Some(telem_rx);
        self.telemetry_nudge = Some(telem_nudge);
    }

    /// Find a profile by name, returning its index.
    #[must_use]
    pub fn find_profile(&self, name: &str) -> Option<usize> {
        self.profiles.iter().position(|p| p.name == name)
    }

    /// Sort profiles according to the current `sort_order`.
    pub fn sort_profiles(&mut self) {
        match self.sort_order {
            ProfileSortOrder::NameAsc => {
                self.profiles.sort_by(|a, b| a.name.cmp(&b.name));
            }
            ProfileSortOrder::NameDesc => {
                self.profiles.sort_by(|a, b| b.name.cmp(&a.name));
            }
            ProfileSortOrder::LastUsed => {
                self.profiles.sort_by(|a, b| {
                    b.last_used
                        .unwrap_or(std::time::UNIX_EPOCH)
                        .cmp(&a.last_used.unwrap_or(std::time::UNIX_EPOCH))
                });
            }
            ProfileSortOrder::Protocol => {
                fn proto_rank(p: ProtocolKind) -> u8 {
                    match p {
                        ProtocolKind::WireGuard => 0,
                        ProtocolKind::OpenVpn => 1,
                    }
                }
                self.profiles.sort_by(|a, b| {
                    proto_rank(a.protocol)
                        .cmp(&proto_rank(b.protocol))
                        .then_with(|| a.name.cmp(&b.name))
                });
            }
        }
    }

    /// Load profile metadata (`last_used` timestamps) from disk.
    pub fn load_metadata(&mut self) {
        if let Ok(metadata) = utils::load_profile_metadata() {
            for profile in &mut self.profiles {
                let key = profile.config_path.to_string_lossy().to_string();
                if let Some(meta) = metadata.get(&key) {
                    profile.last_used = profile.last_used.max(meta.last_used);
                }
            }
        }
    }

    /// Save profile metadata to disk.
    pub fn save_metadata(&self) {
        use std::collections::HashMap;

        let mut metadata = HashMap::new();
        for profile in &self.profiles {
            let key = profile.config_path.to_string_lossy().to_string();
            metadata.insert(
                key,
                utils::ProfileMetadata {
                    last_used: profile.last_used,
                },
            );
        }

        let _ = utils::save_profile_metadata(&metadata);
    }

    /// Check if required binaries are available for a given protocol.
    ///
    /// Shared between TUI and CLI so both surfaces refuse the same
    /// missing-dep set (and run the same `OpenVPN` 2.4+ probe — older
    /// builds silently drop `--pull-filter`, breaking multi-tunnel DNS
    /// scoping).
    #[must_use]
    pub fn check_dependencies(
        protocol: ProtocolKind,
        config_path: &std::path::Path,
    ) -> Vec<String> {
        let mut missing = Vec::new();
        match protocol {
            ProtocolKind::WireGuard => {
                // Both `wg` and `wg-quick` ship in the wireguard-tools
                // package on every supported distro — report them under
                // a single label so the install hint isn't duplicated.
                if !utils::binary_exists("wg-quick") || !utils::binary_exists("wg") {
                    missing.push("wireguard-tools".to_string());
                }
                // On Linux, wg-quick uses `resolvconf` to set DNS when the
                // config contains a DNS directive. Two escape hatches:
                //   1. systemd-resolved + working `resolvectl` →
                //      `WgTunnel::up` takes over per-link DNS via
                //      `resolvectl` itself; no resolvconf shim needed.
                //   2. A working `resolvconf` (openresolv on non-resolved
                //      hosts; systemd-resolvconf shim on resolved hosts).
                //
                // Otherwise emit the missing-dep label with a hint at
                // which shim the user actually needs.
                #[cfg(target_os = "linux")]
                // xtask:allow-platform-cfg: resolvconf check is Linux-only DNS plumbing
                if let Some(label) = wireguard_dns_missing_dep(WireguardDnsGateInputs {
                    has_dns_directive: utils::wireguard_config_has_dns(config_path),
                    resolvectl_path_available: utils::use_resolvectl_path(),
                    resolvconf_works: utils::resolvconf_works(),
                    is_systemd_resolved: utils::is_systemd_resolved(),
                }) {
                    missing.push(label);
                }
                #[cfg(target_os = "linux")]
                // xtask:allow-platform-cfg: /proc sysctl gate is Linux-only (issue #242)
                if let Some(label) = wireguard_ipv6_missing_dep(
                    utils::wireguard_config_has_ipv6_address(config_path),
                    utils::host_ipv6_disabled,
                ) {
                    missing.push(label);
                }
                #[cfg(not(target_os = "linux"))]
                let _ = config_path; // suppress unused warning on non-Linux
            }
            ProtocolKind::OpenVpn => {
                if utils::binary_exists("openvpn") {
                    // Assert OpenVPN ≥ 2.4 so `--pull-filter` (multi-tunnel
                    // DNS scoping) is available. Older builds silently
                    // ignore the flag and leak pushed DNS into the primary
                    // tunnel's resolver. Unparseable probe = fail-open with
                    // a tracing warning so vendor-patched or sandboxed
                    // environments aren't blocked.
                    use openvpn::OvpnVersionProbe;
                    match openvpn::probe_openvpn_version() {
                        OvpnVersionProbe::Parsed(v) if v.supports_multi_tunnel_dns() => {}
                        OvpnVersionProbe::Parsed(v) => {
                            missing.push(format!(
                                "openvpn 2.4+ required for multi-tunnel DNS scoping (found {v})"
                            ));
                        }
                        OvpnVersionProbe::HelpFallbackOk => {}
                        OvpnVersionProbe::Unparseable => {
                            tracing::warn!(
                                target: "vortix::vpn_runtime",
                                "openvpn version could not be determined; \
                                 multi-tunnel DNS scoping may not work if the \
                                 installed binary is older than 2.4"
                            );
                        }
                    }
                } else {
                    missing.push("openvpn".to_string());
                }
            }
        }
        missing
    }
}

/// Inputs to the `WireGuard` DNS-shim missing-dep decision. Wrapping the
/// four booleans in a struct keeps the call-site readable (named fields)
/// and dodges the `fn_params_excessive_bools` lint while staying purely
/// declarative — no behavior moves into the struct itself.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_excessive_bools)] // intentional flag record; mirrors TunnelCapabilities
#[cfg(target_os = "linux")] // xtask:allow-platform-cfg: WG DNS-shim gate is Linux-only
pub(crate) struct WireguardDnsGateInputs {
    pub has_dns_directive: bool,
    pub resolvectl_path_available: bool,
    pub resolvconf_works: bool,
    pub is_systemd_resolved: bool,
}

/// Pure decision logic for the `WireGuard` DNS-shim missing-dep label on Linux.
///
/// Returns `Some(label)` when the user must install a DNS-management shim,
/// `None` when the connect can proceed. Split out so the four-quadrant
/// gate can be unit-tested without depending on host state (each input
/// helper — `is_systemd_resolved`, `resolvconf_works`, `resolvectl_works`
/// — probes real OS state and would make these tests host-dependent).
#[must_use]
#[cfg(target_os = "linux")] // xtask:allow-platform-cfg: gate decision is Linux-only DNS plumbing
pub(crate) fn wireguard_dns_missing_dep(inputs: WireguardDnsGateInputs) -> Option<String> {
    if !inputs.has_dns_directive {
        return None;
    }
    if inputs.resolvectl_path_available {
        return None;
    }
    if inputs.resolvconf_works {
        return None;
    }
    Some(
        if inputs.is_systemd_resolved {
            "resolvconf (systemd)"
        } else {
            "resolvconf"
        }
        .to_string(),
    )
}

/// Pure decision logic for the host-IPv6 pre-flight gate on Linux (#242).
///
/// `wg-quick` runs `ip -6 address add` for each IPv6 entry on the
/// profile's `Address =` line, which aborts the whole bring-up when
/// kernel IPv6 is disabled. Refuse up front instead of surfacing raw
/// wg-quick stderr; never silently strip the user's IPv6 entry.
///
/// The host probe is a closure so its `/proc` reads only happen for
/// profiles that actually declare an IPv6 address.
#[must_use]
#[cfg(target_os = "linux")] // xtask:allow-platform-cfg: gate decision is Linux-only (issue #242)
pub(crate) fn wireguard_ipv6_missing_dep(
    profile_has_ipv6_address: bool,
    host_ipv6_disabled: impl FnOnce() -> bool,
) -> Option<String> {
    (profile_has_ipv6_address && host_ipv6_disabled())
        .then(|| "host IPv6 (kernel disabled)".to_string())
}

impl Drop for VpnRuntime {
    fn drop(&mut self) {
        // VPN connections are independent OS processes (wg-quick, openvpn) that
        // should survive UI process exit. Only explicit user actions (disconnect
        // button, `vortix down`) should tear them down. This matches the TUI's
        // confirm dialog: "VPN connection may still be active. Quit anyway?"
        //
        // Kill switch firewall rules also persist — the next launch recovers
        // them via `load_state()`.
    }
}

#[cfg(all(test, target_os = "linux"))]
mod dns_gate_tests {
    use super::{wireguard_dns_missing_dep, WireguardDnsGateInputs};

    #[allow(clippy::fn_params_excessive_bools)] // test fixture mirrors the WireguardDnsGateInputs shape
    fn inputs(
        has_dns_directive: bool,
        resolvectl_path_available: bool,
        resolvconf_works: bool,
        is_systemd_resolved: bool,
    ) -> WireguardDnsGateInputs {
        WireguardDnsGateInputs {
            has_dns_directive,
            resolvectl_path_available,
            resolvconf_works,
            is_systemd_resolved,
        }
    }

    #[test]
    fn no_dns_directive_returns_none_regardless_of_host_state() {
        // Every host-state combination with `has_dns = false` must return None.
        for resolvectl in [false, true] {
            for resolvconf in [false, true] {
                for resolved in [false, true] {
                    assert_eq!(
                        wireguard_dns_missing_dep(inputs(false, resolvectl, resolvconf, resolved)),
                        None,
                        "has_dns=false resolvectl={resolvectl} resolvconf={resolvconf} resolved={resolved}"
                    );
                }
            }
        }
    }

    #[test]
    fn resolved_with_resolvectl_returns_none() {
        // The headline behaviour change: a resolved host with a working
        // resolvectl no longer needs a resolvconf shim, even when the
        // .conf carries `DNS = ...`.
        assert_eq!(
            wireguard_dns_missing_dep(inputs(true, true, false, true)),
            None
        );
    }

    #[test]
    fn resolved_without_resolvectl_falls_back_to_systemd_label() {
        // Edge case: resolved is detected but resolvectl probe fails
        // (service crashed, broken systemd install). The user genuinely
        // needs the `systemd-resolvconf` shim; emit the resolved-flavoured
        // missing-dep label.
        assert_eq!(
            wireguard_dns_missing_dep(inputs(true, false, false, true)),
            Some("resolvconf (systemd)".to_string())
        );
    }

    #[test]
    fn non_resolved_without_resolvconf_returns_plain_label() {
        // Classic missing-resolvconf on a non-resolved Linux host.
        assert_eq!(
            wireguard_dns_missing_dep(inputs(true, false, false, false)),
            Some("resolvconf".to_string())
        );
    }

    #[test]
    fn non_resolved_with_resolvconf_returns_none() {
        // Ubuntu / Debian-shaped happy path: resolvconf is installed and
        // the host doesn't use systemd-resolved. Unchanged from today.
        assert_eq!(
            wireguard_dns_missing_dep(inputs(true, false, true, false)),
            None
        );
    }

    #[test]
    fn resolved_with_both_paths_prefers_resolvectl_over_resolvconf() {
        // Belt-and-braces: even if resolvconf is also installed, the
        // resolvectl path takes precedence. This avoids double-management
        // surprises and matches the WgTunnel::up wiring (which always
        // uses resolvectl when use_resolvectl_path() is true).
        assert_eq!(
            wireguard_dns_missing_dep(inputs(true, true, true, true)),
            None
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod ipv6_gate_tests {
    use super::wireguard_ipv6_missing_dep;

    #[test]
    fn fires_only_when_profile_declares_v6_and_host_disabled() {
        assert_eq!(
            wireguard_ipv6_missing_dep(true, || true),
            Some("host IPv6 (kernel disabled)".to_string())
        );
    }

    #[test]
    fn silent_when_profile_is_v4_only() {
        assert_eq!(wireguard_ipv6_missing_dep(false, || true), None);
    }

    #[test]
    fn silent_when_host_ipv6_enabled() {
        assert_eq!(wireguard_ipv6_missing_dep(true, || false), None);
    }

    #[test]
    fn silent_when_neither() {
        assert_eq!(wireguard_ipv6_missing_dep(false, || false), None);
    }

    #[test]
    fn host_probe_not_evaluated_for_v4_only_profiles() {
        let called = std::cell::Cell::new(false);
        let result = wireguard_ipv6_missing_dep(false, || {
            called.set(true);
            true
        });
        assert_eq!(result, None);
        assert!(!called.get(), "host probe ran for a v4-only profile");
    }

    #[test]
    fn label_maps_to_the_sysctl_hint_not_the_generic_package_fallback() {
        // The label lives here; the hint arm lives in platform::install_hint.
        // Pin the pair so a rename on either side fails loudly instead of
        // rendering "sudo apt install host IPv6 (kernel disabled)".
        let label = wireguard_ipv6_missing_dep(true, || true).unwrap();
        let hint = crate::platform::install_hint(&label);
        assert!(
            hint.contains("sysctl"),
            "hint fell back to generic package install: {hint}"
        );
    }
}

#[cfg(test)]
mod remembered_address_tests {
    use super::*;
    use crate::constants::{REAL_IPV6_CACHE_FILE, REAL_IP_CACHE_FILE};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vortix-remembered-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn seconds_ago(seconds: u64) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs()
            - seconds
    }

    /// Startup must go through the age-checked load. Reading the raw record
    /// would put an address the host has not seen for days into the leak
    /// indicator, presented as the real address it is being compared against.
    #[test]
    fn an_expired_cache_record_is_not_remembered_at_startup() {
        let dir = scratch("expired");
        let stale = seconds_ago(constants::REAL_IP_CACHE_MAX_AGE_SECS + 60 * 60);
        std::fs::write(
            dir.join(REAL_IP_CACHE_FILE),
            format!("203.0.113.5\n{stale}\n"),
        )
        .expect("write v4 record");
        std::fs::write(
            dir.join(REAL_IPV6_CACHE_FILE),
            format!("2001:db8::1\n{stale}\n"),
        )
        .expect("write v6 record");

        assert!(
            crate::core::real_ip_cache::load(&dir).is_some(),
            "the record is on disk; the point is that startup declines it"
        );
        assert_eq!(
            remembered_real_addresses(&dir),
            (None, None),
            "an expired record must not be restored as a remembered address"
        );
    }

    #[test]
    fn a_recent_cache_record_is_remembered_at_startup() {
        let dir = scratch("recent");
        crate::core::real_ip_cache::save(&dir, "203.0.113.5");
        crate::core::real_ip_cache::save_ipv6(&dir, "2001:db8::1");

        assert_eq!(
            remembered_real_addresses(&dir),
            (
                Some("203.0.113.5".to_string()),
                Some("2001:db8::1".to_string())
            )
        );
    }
}
