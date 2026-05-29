//! Legacy single-tunnel `ConnectionState` enum (relocated from
//! `crate::state::connection`).
//!
//! Multi-connection plan #001 U6 Stage B: the canonical source of truth
//! for active tunnels is the [`crate::vortix_core::engine::TunnelRegistry`]
//! that lives on [`crate::app::App`]. UI panels read snapshots from there.
//!
//! This enum still lives on [`crate::vpn_runtime::VpnRuntime`] because the
//! legacy connect/disconnect/retry/scanner flow in `app/connection.rs`,
//! `app/update.rs`, and the CLI's blocking connect/disconnect helpers in
//! `vpn_runtime/connection.rs` still drive a single-tunnel state machine.
//! Plan U7 rewires the connect path to drive the registry directly; once
//! that lands the enum can be retired entirely.
//!
//! Visibility: re-exported from `crate::vpn_runtime` so the legacy flow can
//! reach it, but **not** from `crate::state` — the latter no longer carries
//! a `ConnectionState` type. Panels that previously imported
//! `crate::state::ConnectionState` or `crate::app::ConnectionState` must
//! migrate to `app.registry` snapshot reads.

use std::time::Instant;

/// Technical details parsed from the VPN interface.
///
/// Mirror of [`crate::vortix_core::engine::state::DetailedConnectionInfo`]
/// kept for the legacy `ConnectionState` flow. Panels read the registry
/// version through their tunnel snapshots; this one feeds the
/// `connection_state` mirror on `VpnRuntime`.
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
