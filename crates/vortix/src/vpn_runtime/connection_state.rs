//! Single-tunnel `ConnectionState` enum — surviving as the CLI's local
//! state shape and as the return type of `App::legacy_state()`.
//!
//! After plan P5d the canonical source of truth for active VPN state on
//! the App side is the [`crate::vortix_core::engine::TunnelRegistry`] that
//! lives on [`crate::app::App`]. The `connection_state` field on
//! `VpnRuntime` is gone; every panel renderer reads `app.registry`
//! snapshots directly.
//!
//! Two remaining users of this enum:
//!
//! 1. The CLI's blocking helpers in
//!    [`crate::vpn_runtime::connection`] (`connect_and_wait`,
//!    `disconnect_and_wait`) used to carry their own local
//!    `ConnectionState` value during the lifetime of one CLI
//!    invocation. They now derive the active-tunnel slice for the
//!    kill switch directly from the scanner via
//!    `VpnRuntime::killswitch_view_from_scanner` (every kernel-visible
//!    tunnel contributes, not just the one this CLI call touched).
//!
//! 2. [`crate::app::App::legacy_state`] returns this enum as a derived
//!    view of the registry primary so the few residual single-tunnel-
//!    shaped reads (kill-switch sync, profile-delete safety,
//!    scanner-dispatch helpers) keep working without a stored field.
//!
//! Visibility: still re-exported from [`crate::vpn_runtime`] for those
//! two callers, but **not** from [`crate::state`] — panels never see it.

use std::time::Instant;

/// Technical details parsed from the VPN interface.
///
/// Companion to [`crate::vortix_core::engine::state::DetailedConnectionInfo`]
/// — the registry's snapshot panels read; this one is the CLI-local
/// shape carried by [`ConnectionState::Connected`] and the return type
/// of [`crate::app::App::legacy_state`]. Both shapes have identical
/// field names + types; `legacy_to_core_details` in `app/connection.rs`
/// translates between them when populating the registry.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DetailedConnectionInfo {
    /// System interface name (e.g., utun3, wg0).
    pub interface: String,
    /// Internal IP address assigned by the VPN.
    pub internal_ip: String,
    /// Remote server endpoint (IP:port).
    pub endpoint: String,
    /// Maximum Transmission Unit size.
    pub mtu: String,
    /// `WireGuard` public key (empty for `OpenVPN`).
    pub public_key: String,
    /// Local listening port.
    pub listen_port: String,
    /// Total bytes received.
    pub transfer_rx: String,
    /// Total bytes transmitted.
    pub transfer_tx: String,
    /// Time since last successful handshake.
    pub latest_handshake: String,
    /// Process ID (for targeted termination).
    pub pid: Option<u32>,
}

/// VPN connection state machine (legacy single-tunnel mirror).
///
/// Plan #001 U7 will retire this in favour of the per-tunnel
/// [`crate::vortix_core::engine::state::Connection`] FSM owned by
/// [`crate::vortix_core::engine::TunnelRegistry`].
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
