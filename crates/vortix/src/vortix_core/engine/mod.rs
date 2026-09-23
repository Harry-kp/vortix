//! Tunnel state vocabulary and the dashboard's render cache.

pub mod registry;
pub mod state;

pub use registry::{classify_route_conflict, Conflict, Role, TunnelRegistry, TunnelSnapshot};
pub use state::{
    Connection, ConnectionHealth, DegradedReason, DetailedConnectionInfo, FailureReason,
};
