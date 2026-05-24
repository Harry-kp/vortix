//! Engine errors (plan #005 U1).

use thiserror::Error;

use crate::ports::tunnel::TunnelError;
use crate::profile::ProfileId;

/// What `Engine::handle` and the `EngineHandle` API can return as errors.
///
/// Plan #005 U2/U4 may extend this; the variants here are the ones the
/// brainstorm called out by name.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EngineError {
    /// A profile referenced by an in-flight command no longer exists.
    #[error("profile {0} not found")]
    ProfileNotFound(ProfileId),
    /// Caller requested a capability the active tunnel impl doesn't support.
    #[error("capability `{0}` not supported by the active tunnel")]
    CapabilityUnsupported(&'static str),
    /// FSM is in a state where the requested input doesn't apply (e.g.
    /// Connect while Connected).
    #[error("invalid input for current state: {0}")]
    InvalidInput(String),
    /// Bubbles up from `Tunnel::up` / `down` / `status`.
    #[error("tunnel error: {0}")]
    Tunnel(#[from] TunnelError),
    /// Bubbles up from journal writer / read paths.
    #[error("journal I/O error: {0}")]
    Journal(#[from] std::io::Error),
    /// Catch-all for plumbing errors (channel closed, runtime gone, etc.).
    #[error("{0}")]
    Other(String),
}
