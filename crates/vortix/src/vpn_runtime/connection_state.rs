//! Single-tunnel `ConnectionState` enum retained only as the derived return
//! type of `App::legacy_state()`.
//!
//! After plan P5d the canonical source of truth for active VPN state on
//! the App side is the [`crate::vortix_core::engine::TunnelRegistry`] that
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
pub use crate::vortix_core::engine::state::DetailedConnectionInfo;

/// VPN connection state machine (legacy single-tunnel mirror).
///
/// A follow-up will retire this in favour of the per-tunnel
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
