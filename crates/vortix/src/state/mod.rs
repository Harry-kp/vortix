//! Domain state types for the Vortix application.
//!
//! This module contains all core state types separated by domain:
//! - `connection`: VPN connection state machine and details
//! - `profile`: VPN profile configuration and protocol types
//! - `ui`: UI-specific state like focus, input mode, and toasts
//! - `killswitch`: Kill switch mode and state

mod connection;
mod killswitch;
mod profile;
mod ui;

// Re-export all types for easy access
pub use connection::{ConnectionState, DetailedConnectionInfo};
pub use killswitch::{KillSwitchMode, KillSwitchState};
pub use profile::{Protocol, VpnProfile};
pub use ui::{
    help_max_scroll_for_terminal_height, AuthField, FlipAnimation, FocusedPanel, InputMode,
    ProfileSortOrder, QualityLevel, Toast, ToastType, DISMISS_DURATION, HELP_OVERLAY_MAX_HEIGHT,
};
