//! Domain state types shared across the workspace.
//!
//! These types travel through the engine FSM, the persistence layer, and the
//! TUI/CLI without dragging UI or runtime dependencies.

pub mod killswitch;

pub use killswitch::{KillSwitchMode, KillSwitchState};
