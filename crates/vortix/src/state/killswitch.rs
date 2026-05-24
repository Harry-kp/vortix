//! Kill switch state types — relocated to `vortix-core::state::killswitch` (plan 003 U1).
//!
//! This shim re-exports the canonical types so existing imports in the
//! binary crate keep working without a full sweep. Plan 003 U4 removes the
//! shim once consumers are updated.

pub use vortix_core::state::killswitch::{KillSwitchMode, KillSwitchState};
