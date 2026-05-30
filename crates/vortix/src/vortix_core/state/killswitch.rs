//! Kill switch state types.
//!
//! The kill switch prevents traffic leakage when the VPN connection
//! drops unexpectedly (`Auto` mode) or keeps the firewall engaged at
//! all times (`AlwaysOn` mode).
//!
//! # Naming convention — enum variants vs UI labels
//!
//! The enum variants below (`Off` / `Auto` / `AlwaysOn`) are the
//! **stable** names — they appear in:
//!
//! - the CLI grammar (`vortix killswitch off|auto|always`)
//! - the JSON output envelope (`{"mode": "off|auto|alwayson"}`)
//! - on-disk persisted state in `killswitch.toml`
//! - every code reference (matches, log strings, etc.)
//!
//! The user-facing rendering layer uses friendlier labels via
//! [`KillSwitchMode::display_name`] / [`KillSwitchMode::one_liner`] /
//! [`KillSwitchMode::behavior_lines`]:
//!
//! | Enum variant   | UI label          | What it means                                       |
//! |----------------|-------------------|-----------------------------------------------------|
//! | `Off`          | `Off`             | No firewall rules. Real IP exposed if VPN drops.    |
//! | `Auto`         | `Block on drop`   | Watch the VPN; block if it drops unexpectedly.      |
//! | `AlwaysOn`     | `VPN-only`        | Only VPN traffic permitted. No internet without VPN.|
//!
//! **Don't rename the enum variants** — that breaks the JSON schema
//! and the CLI grammar (back-compat shim required). Only change the
//! `display_name` / `one_liner` / `behavior_lines` strings if you
//! want to tune the UI copy.

use serde::{Deserialize, Serialize};

/// Kill switch operating mode.
///
/// Determines when the kill switch should activate. See the module
/// docs for the variant ↔ UI label mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum KillSwitchMode {
    /// Disabled - no traffic blocking. UI label: `Off`.
    #[default]
    Off,
    /// Auto mode - blocks only on unexpected VPN drops, releases on
    /// manual disconnect. UI label: `Block on drop`.
    Auto,
    /// Always-on - keeps the firewall engaged whether VPN is up or
    /// down (default-DROP egress + per-tunnel ACCEPT rules). UI label:
    /// `VPN-only`.
    AlwaysOn,
}

impl KillSwitchMode {
    /// Friendly UI label — what this mode means in plain English.
    /// See the module docs for the full mapping. Don't use this for
    /// CLI/JSON serialisation; use the `Debug` impl or a hand-rolled
    /// `to_lowercase()` for those (the names are the stable contract).
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Off => "Off",
            Self::Auto => "Block on drop",
            Self::AlwaysOn => "VPN-only",
        }
    }

    /// One-sentence behaviour summary for hover-style help / toasts.
    #[must_use]
    pub const fn one_liner(self) -> &'static str {
        match self {
            Self::Off => "All traffic flows. If the VPN drops, your real IP is exposed.",
            Self::Auto => "If the VPN drops unexpectedly, block all traffic until you reconnect.",
            Self::AlwaysOn => "Only traffic through active VPN tunnels. No internet without a VPN.",
        }
    }

    /// Two-line "what happens when …" explainer, suitable for the
    /// Security Guard panel.
    ///
    /// Returns `(vpn_up_line, vpn_down_line)`.
    #[must_use]
    pub const fn behavior_lines(self) -> (&'static str, &'static str) {
        match self {
            Self::Off => (
                "VPN up: all traffic flows freely.",
                "VPN down: real IP exposed.",
            ),
            Self::Auto => (
                "VPN up: browse normally.",
                "VPN down: traffic blocks until reconnect or `release-killswitch`.",
            ),
            Self::AlwaysOn => (
                "VPN up: only tunnel traffic permitted.",
                "VPN down: no internet at all (canonical kill-switch shape).",
            ),
        }
    }
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
/// Represents what the kill switch is actively doing. Like
/// [`KillSwitchMode`], the variant names are the stable contract for
/// JSON/log output; the UI uses [`KillSwitchState::display_status`]
/// for friendlier labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum KillSwitchState {
    /// Kill switch is disabled (mode = Off). UI label: `inactive`.
    #[default]
    Disabled,
    /// Armed and ready to block, but the firewall is not yet engaged.
    /// Reached when mode = Auto and a VPN is up — we're watching for
    /// a drop. UI label: `watching`.
    Armed,
    /// Firewall is actively engaged. Reached either by `AlwaysOn` mode
    /// (steady state) or by `Auto` mode after detecting a VPN drop.
    /// UI label: `blocking`.
    Blocking,
}

impl KillSwitchState {
    /// Check if currently blocking traffic
    #[must_use]
    pub const fn is_blocking(self) -> bool {
        matches!(self, Self::Blocking)
    }

    /// Friendly UI label. See the module docs for the variant ↔ label
    /// mapping convention.
    #[must_use]
    pub const fn display_status(self) -> &'static str {
        match self {
            Self::Disabled => "inactive",
            Self::Armed => "watching",
            Self::Blocking => "blocking",
        }
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
