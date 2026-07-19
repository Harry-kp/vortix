//! Kill switch state types — relocated to `vortix-core::state::killswitch`.
//!
//! This shim re-exports the canonical types so existing imports in the
//! binary crate keep working without a full sweep. A later sweep removes the
//! shim once consumers are updated.

pub use crate::vortix_core::state::killswitch::{KillSwitchMode, KillSwitchState};
