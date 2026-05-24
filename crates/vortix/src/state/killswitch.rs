//! Kill switch state types.
//!
//! The kill switch prevents traffic leakage when VPN connection drops unexpectedly.

use serde::{Deserialize, Serialize};

/// Kill switch operating mode.
///
/// Determines when the kill switch should activate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum KillSwitchMode {
    /// Disabled - no traffic blocking
    #[default]
    Off,
    /// Auto mode - blocks only on unexpected VPN drops, releases on manual disconnect
    Auto,
    /// Always-on - blocks all traffic until VPN connects (strict mode)
    AlwaysOn,
}

impl KillSwitchMode {
    /// Cycle to next mode: Off → Auto → `AlwaysOn` → Off
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Self::Off => Self::Auto,
            Self::Auto => Self::AlwaysOn,
            Self::AlwaysOn => Self::Off,
        }
    }
}

/// Current kill switch operational state.
///
/// Represents what the kill switch is actively doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum KillSwitchState {
    /// Kill switch is disabled (mode = Off)
    #[default]
    Disabled,
    /// Armed and ready to block (VPN connected or waiting, mode != Off)
    Armed,
    /// Actively blocking all non-VPN traffic
    Blocking,
}

impl KillSwitchState {
    /// Check if currently blocking traffic
    #[must_use]
    pub const fn is_blocking(self) -> bool {
        matches!(self, Self::Blocking)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode_cycle() {
        assert_eq!(KillSwitchMode::Off.next(), KillSwitchMode::Auto);
        assert_eq!(KillSwitchMode::Auto.next(), KillSwitchMode::AlwaysOn);
        assert_eq!(KillSwitchMode::AlwaysOn.next(), KillSwitchMode::Off);
    }

    #[test]
    fn test_state_is_blocking() {
        assert!(!KillSwitchState::Disabled.is_blocking());
        assert!(!KillSwitchState::Armed.is_blocking());
        assert!(KillSwitchState::Blocking.is_blocking());
    }
}
