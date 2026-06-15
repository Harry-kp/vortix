//! Kill switch state types.
//!
//! The kill switch prevents traffic leakage when the VPN connection
//! drops unexpectedly (`block-on-drop`) or keeps the firewall
//! engaged at all times (`vpn-only`).
//!
//! # One vocabulary, used everywhere
//!
//! Every surface — TUI panels, header bar, `vortix status` /
//! `vortix report` / `vortix killswitch` output, the JSON envelope,
//! and the CLI input verb — uses the same three slugs. Rust enum
//! variants (`Off` / `Auto` / `AlwaysOn`) stay idiomatic for the
//! language; every display path routes through
//! [`KillSwitchMode::display_name`] / [`KillSwitchMode::cli_verb`] /
//! [`KillSwitchState::display_status`] so the enum names never leak
//! into output.
//!
//! | Rust enum    | Slug              | What it does                                        |
//! |--------------|-------------------|-----------------------------------------------------|
//! | `Off`        | `off`             | No firewall rules. Real IP exposed if VPN drops.    |
//! | `Auto`       | `block-on-drop`   | Block traffic only if the VPN drops unexpectedly.   |
//! | `AlwaysOn`   | `vpn-only`        | Only VPN traffic permitted. No internet without VPN.|
//!
//! [`KillSwitchMode::display_name`] returns the title-cased prose form
//! of the same slug (`Off` / `Block on drop` / `VPN-only`) for
//! long-form rendering. No old verbs (`auto`, `always`,
//! `always-on`) are accepted — the CLI parser returns an explicit
//! "Use: off, block-on-drop, vpn-only" error.

use serde::{Deserialize, Serialize};

/// Kill switch operating mode.
///
/// Determines when the kill switch should activate. See the module
/// docs for the variant ↔ UI label mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum KillSwitchMode {
    /// No traffic blocking. Slug: `off`.
    #[default]
    Off,
    /// Blocks only on unexpected VPN drops, releases on manual
    /// disconnect. Slug: `block-on-drop`.
    Auto,
    /// Keeps the firewall engaged whether VPN is up or down
    /// (default-DROP egress + per-tunnel ACCEPT rules). Slug:
    /// `vpn-only`.
    AlwaysOn,
}

impl KillSwitchMode {
    /// The label users read for this mode — same string in TUI,
    /// `vortix status`, `vortix killswitch`, and the JSON envelope.
    /// See the module docs for the full mapping. Every display path
    /// must route through this helper (don't hardcode strings).
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Off => "Off",
            Self::Auto => "Block on drop",
            Self::AlwaysOn => "VPN-only",
        }
    }

    /// CLI input verb — the kebab-case slug accepted by
    /// `vortix killswitch <verb>` and shown in `--help`. Same
    /// vocabulary as `display_name`, just typing-friendly.
    #[must_use]
    pub const fn cli_verb(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Auto => "block-on-drop",
            Self::AlwaysOn => "vpn-only",
        }
    }

    /// Parse a user-typed CLI verb back into [`KillSwitchMode`].
    /// Case-insensitive over the slugs returned by [`Self::cli_verb`].
    /// Returns `None` for any other string — callers should surface a
    /// "Use: off, block-on-drop, vpn-only" hint.
    #[must_use]
    pub fn from_cli_verb(verb: &str) -> Option<Self> {
        match verb.to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "block-on-drop" => Some(Self::Auto),
            "vpn-only" => Some(Self::AlwaysOn),
            _ => None,
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

    /// The desired `KillSwitchState` for this mode given the current
    /// connection status and the previous state. Pure function —
    /// `sync_killswitch` adds a `!is_root` downgrade (Blocking →
    /// Armed) on top of this, but the policy decision lives here.
    ///
    /// | Mode       | `is_connected` | `old_state`   | result     |
    /// |------------|----------------|---------------|------------|
    /// | `Off`      | (any)          | (any)         | `Disabled` |
    /// | `Auto`     | true           | (any)         | `Armed`    |
    /// | `Auto`     | false          | `Blocking`    | `Blocking` |
    /// | `Auto`     | false          | not Blocking  | `Armed`    |
    /// | `AlwaysOn` | (any)          | (any)         | `Blocking` |
    ///
    /// `AlwaysOn` always resolves to `Blocking` — the firewall stays
    /// engaged whether the VPN is up or down. That's the canonical
    /// Linux killswitch shape; tested by
    /// `tests/integration/killswitch.sh`.
    #[must_use]
    pub const fn desired_state(
        self,
        old_state: KillSwitchState,
        is_connected: bool,
    ) -> KillSwitchState {
        match self {
            Self::Off => KillSwitchState::Disabled,
            Self::Auto => {
                if is_connected {
                    KillSwitchState::Armed
                } else if matches!(old_state, KillSwitchState::Blocking) {
                    KillSwitchState::Blocking
                } else {
                    KillSwitchState::Armed
                }
            }
            Self::AlwaysOn => KillSwitchState::Blocking,
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
                "VPN down: real IPv4 (and IPv6, if present) exposed.",
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
/// Like [`KillSwitchMode`], renders through helper methods rather
/// than the variant name. [`Self::display_status`] is the prose form
/// shown to humans; [`Self::cli_verb`] is the slug used in the JSON
/// envelope and log lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum KillSwitchState {
    /// Kill switch is disabled (mode = Off). Slug: `inactive`.
    #[default]
    Disabled,
    /// Armed and ready to block, but the firewall is not yet engaged.
    /// Reached when mode = Auto and a VPN is up — we're watching for
    /// a drop. Slug: `watching`.
    Armed,
    /// Firewall is actively engaged. Reached either by `AlwaysOn` mode
    /// (steady state) or by `Auto` mode after detecting a VPN drop.
    /// Slug: `blocking`.
    Blocking,
}

impl KillSwitchState {
    /// Check if currently blocking traffic
    #[must_use]
    pub const fn is_blocking(self) -> bool {
        matches!(self, Self::Blocking)
    }

    /// Prose form shown to humans (`Inactive` / `Watching` /
    /// `Blocking`). One vocabulary across TUI, CLI, and JSON — same
    /// letters as [`Self::cli_verb`], just capitalised.
    #[must_use]
    pub const fn display_status(self) -> &'static str {
        match self {
            Self::Disabled => "Inactive",
            Self::Armed => "Watching",
            Self::Blocking => "Blocking",
        }
    }

    /// Slug used in the JSON envelope and log lines. Lower-cased
    /// form of [`Self::display_status`].
    #[must_use]
    pub const fn cli_verb(self) -> &'static str {
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

    #[test]
    fn off_mode_always_disabled() {
        for old in [
            KillSwitchState::Disabled,
            KillSwitchState::Armed,
            KillSwitchState::Blocking,
        ] {
            for is_connected in [false, true] {
                assert_eq!(
                    KillSwitchMode::Off.desired_state(old, is_connected),
                    KillSwitchState::Disabled,
                    "Off should always resolve to Disabled (old={old:?}, is_connected={is_connected})"
                );
            }
        }
    }

    #[test]
    fn auto_mode_is_armed_when_connected_blocking_when_dropped() {
        // Connected → Armed (watching).
        assert_eq!(
            KillSwitchMode::Auto.desired_state(KillSwitchState::Armed, true),
            KillSwitchState::Armed
        );
        // Not connected from a fresh state → Armed.
        assert_eq!(
            KillSwitchMode::Auto.desired_state(KillSwitchState::Disabled, false),
            KillSwitchState::Armed
        );
        assert_eq!(
            KillSwitchMode::Auto.desired_state(KillSwitchState::Armed, false),
            KillSwitchState::Armed
        );
        // Not connected from a Blocking state → stays Blocking (preserves
        // the post-drop block until user reconnects or releases).
        assert_eq!(
            KillSwitchMode::Auto.desired_state(KillSwitchState::Blocking, false),
            KillSwitchState::Blocking
        );
    }

    /// Regression for the `AlwaysOn` killswitch semantic fix (commit
    /// `34f07e3`). Pre-fix, `AlwaysOn + is_connected → Armed` left the
    /// firewall NOT engaged — the gap between a drop and reconnect
    /// could leak. The integration test `tests/integration/killswitch.sh`
    /// catches the kernel-level miss; this test catches the policy
    /// decision at the pure-function level so a regression fires
    /// here first.
    #[test]
    fn always_on_resolves_to_blocking_regardless_of_connection_or_history() {
        for old in [
            KillSwitchState::Disabled,
            KillSwitchState::Armed,
            KillSwitchState::Blocking,
        ] {
            for is_connected in [false, true] {
                assert_eq!(
                    KillSwitchMode::AlwaysOn.desired_state(old, is_connected),
                    KillSwitchState::Blocking,
                    "AlwaysOn must always resolve to Blocking — that's the \
                     whole point of the mode. old={old:?}, \
                     is_connected={is_connected}"
                );
            }
        }
    }

    /// `cli_verb` ↔ `from_cli_verb` round-trip on every variant. Pins
    /// the canonical CLI vocabulary so a future rename can't silently
    /// drift the user-typed grammar away from what the help text and
    /// docs advertise.
    #[test]
    fn cli_verb_roundtrips_for_every_variant() {
        for mode in [
            KillSwitchMode::Off,
            KillSwitchMode::Auto,
            KillSwitchMode::AlwaysOn,
        ] {
            assert_eq!(
                KillSwitchMode::from_cli_verb(mode.cli_verb()),
                Some(mode),
                "cli_verb / from_cli_verb must round-trip for {mode:?}"
            );
        }
        // The three canonical slugs are exactly what the help text
        // promises. If you change one of these, change the help text,
        // the README mapping table, and CLAUDE.md in the same commit.
        assert_eq!(KillSwitchMode::Off.cli_verb(), "off");
        assert_eq!(KillSwitchMode::Auto.cli_verb(), "block-on-drop");
        assert_eq!(KillSwitchMode::AlwaysOn.cli_verb(), "vpn-only");
    }

    /// Case-insensitive on the canonical slugs; everything else is
    /// rejected with `None`. In particular, the legacy verbs
    /// (`auto`, `always`, `always-on`) and the title-cased UI prose
    /// (`VPN-only`) are NOT accepted — the parser only takes the
    /// kebab-case slugs.
    #[test]
    fn from_cli_verb_rejects_legacy_and_prose_forms() {
        assert_eq!(
            KillSwitchMode::from_cli_verb("VPN-ONLY"),
            Some(KillSwitchMode::AlwaysOn),
            "slugs must be case-insensitive"
        );
        assert_eq!(
            KillSwitchMode::from_cli_verb("Block-On-Drop"),
            Some(KillSwitchMode::Auto)
        );
        for rejected in [
            "auto",
            "always",
            "always-on",
            "alwayson",
            "VPN only", // space, not dash
            "blockondrop",
            "",
            "vpn-only-extra",
        ] {
            assert!(
                KillSwitchMode::from_cli_verb(rejected).is_none(),
                "must reject '{rejected}' — only the canonical slugs are valid"
            );
        }
    }
}
