//! Domain state types for the Vortix application.
//!
//! This module contains UI-facing state types separated by domain:
//! - `profile`: VPN profile configuration and protocol types
//! - `ui`: UI-specific state like focus, input mode, and toasts
//! - `killswitch`: Kill switch mode and state
//!
//! Multi-connection plan #001 U6 Stage B retired the legacy
//! `state::ConnectionState` enum. UI panels read active tunnel state
//! from `crate::app::App::registry` (a
//! `crate::vortix_core::engine::TunnelRegistry`); the legacy mirror that
//! the connect/disconnect flow still drives lives at
//! `crate::vpn_runtime::ConnectionState` (not re-exported here).

mod killswitch;
mod profile;
mod retry;
mod ui;

// Re-export all types for easy access
pub use killswitch::{KillSwitchMode, KillSwitchState};
pub use profile::{Protocol, VpnProfile};
pub use retry::RetryState;
pub use ui::{
    help_max_scroll_for_terminal_height, AuthField, FlipAnimation, FocusedPanel, HelpTab,
    InputMode, ProfileSortOrder, QualityLevel, Toast, ToastType, DISMISS_DURATION,
    HELP_OVERLAY_MAX_HEIGHT,
};
