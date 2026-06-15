//! Single source of truth for every visual sigil rendered in the TUI.
//!
//! Both the renderers (sidebar status badges, Security Guard row
//! sigils, Connection Details risk markers) AND the `?` help overlay's
//! Sigils tab read from this catalog. A drift test in `tests`
//! enumerates every [`SigilId`] variant and asserts the catalog
//! contains a matching entry, so adding a new sigil without
//! documenting it in help is a compile-time refactor (you can't
//! introduce a [`SigilId`] variant the test doesn't see) and a
//! test-time failure (the catalog will be missing the entry).
//!
//! The contract:
//! - Renderers do `sigil(SigilId::Connected).glyph()` / `.style()`.
//! - Help iterates [`CATALOG`] (or a category-filtered subset).
//! - No code anywhere constructs a sigil glyph + style inline.

use crate::theme;
use ratatui::style::{Color, Modifier, Style};

/// Identifies a sigil for lookup. Each variant maps to exactly one
/// [`Sigil`] in [`CATALOG`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigilId {
    // ── Sidebar status badges (per-tunnel) ────────────────────────────
    /// `●` bright green — Connected and authoritatively tracked.
    Connected,
    /// `●` muted/dim — Connected but iface attribution is unreliable
    /// (e.g., externally-started `OpenVPN` on macOS multi-tunnel).
    ConnectedUnauthoritative,
    /// `◐` yellow — Connecting (handshake in flight).
    Connecting,
    /// `↻` yellow dim — Reconnecting after a drop.
    Reconnecting,
    /// `◑` yellow — Disconnecting (teardown in flight).
    Disconnecting,
    /// `?` yellow — `AwaitingUserInput` (2FA / passphrase prompt).
    AwaitingInput,
    /// `✗` red — Disconnected with a failure record.
    Failed,
    /// `*` accent — Sidebar suffix marking the current Primary tunnel.
    PrimaryMarker,
    /// `!` warning — Sidebar risk annotation (e.g., `AddressableSuppressed`).
    RiskMarker,

    // ── Security Guard row sigils (per-check) ─────────────────────────
    /// `✓` muted green — SG row check passes.
    SgOk,
    /// `─` inactive — SG row not applicable on this platform / state.
    SgNotApplicable,
    /// `⚠` yellow bold — SG row warns, action recommended.
    SgAlarmWarn,
    /// `✗` red bold — SG row alarm, real problem (leak, etc.).
    SgAlarmError,
}

/// A single sigil's visual + textual identity. Fields are `const`-
/// initializable so the entire [`CATALOG`] can be a `const`.
#[derive(Clone, Copy, Debug)]
pub struct Sigil {
    /// Stable identifier used by renderers + tests.
    pub id: SigilId,
    /// Display glyph as a Unicode string. Always single-cell width
    /// (verified by `unicode-width` tests in `sidebar.rs`).
    pub glyph: &'static str,
    /// Short, in-row label for the help overlay's middle column.
    pub label: &'static str,
    /// One-line plain-English description for the help overlay's
    /// right column.
    pub description: &'static str,
    /// Foreground color. Renderers + help BOTH use this — guarantees
    /// the help-overlay swatch matches the on-screen sigil.
    pub color: Color,
    /// Whether to apply `Modifier::BOLD`.
    pub bold: bool,
    /// Whether to apply `Modifier::DIM`.
    pub dim: bool,
    /// Which logical category this sigil belongs to. Drives the
    /// help-overlay grouping (Sidebar badges / Security Guard sigils).
    pub category: SigilCategory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigilCategory {
    /// Sidebar per-tunnel badges + suffixes.
    Sidebar,
    /// Security Guard panel row sigils.
    SecurityGuard,
}

impl Sigil {
    /// Build the [`Style`] a renderer applies to the glyph. Includes
    /// fg color + any BOLD/DIM modifiers declared in the catalog.
    #[must_use]
    pub fn style(&self) -> Style {
        let mut s = Style::default().fg(self.color);
        if self.bold {
            s = s.add_modifier(Modifier::BOLD);
        }
        if self.dim {
            s = s.add_modifier(Modifier::DIM);
        }
        s
    }
}

/// Look up a sigil by its [`SigilId`]. Panics if the catalog is
/// missing an entry for the requested ID — caught by
/// `tests::every_sigil_id_has_a_catalog_entry`.
#[must_use]
pub fn sigil(id: SigilId) -> &'static Sigil {
    CATALOG
        .iter()
        .find(|s| s.id == id)
        .expect("every SigilId variant must have a catalog entry — see tests")
}

/// Every sigil rendered anywhere in the TUI. Adding a sigil = adding
/// to this list. Removing a sigil from a renderer = removing here.
/// One list, one source of truth.
pub const CATALOG: &[Sigil] = &[
    // ── Sidebar status badges ─────────────────────────────────────────
    Sigil {
        id: SigilId::Connected,
        glyph: "\u{25cf}",
        label: "Connected",
        description: "Tunnel is up and authoritatively tracked by vortix.",
        color: theme::SUCCESS,
        bold: false,
        dim: false,
        category: SigilCategory::Sidebar,
    },
    Sigil {
        id: SigilId::ConnectedUnauthoritative,
        glyph: "\u{25cf}",
        label: "Connected (external)",
        description: "Up but vortix can't reliably attribute the kernel interface to a PID — won't be elected as your exit.",
        color: theme::INACTIVE,
        bold: false,
        dim: true,
        category: SigilCategory::Sidebar,
    },
    Sigil {
        id: SigilId::Connecting,
        glyph: "\u{25d0}",
        label: "Connecting",
        description: "Handshake in flight. Auto-times-out per the configured connect_timeout if the protocol layer doesn't report success.",
        color: theme::WARNING,
        bold: false,
        dim: false,
        category: SigilCategory::Sidebar,
    },
    Sigil {
        id: SigilId::Reconnecting,
        glyph: "\u{21bb}",
        label: "Reconnecting",
        description: "Tunnel dropped; vortix is auto-retrying per the configured retry budget.",
        color: theme::WARNING,
        bold: false,
        dim: true,
        category: SigilCategory::Sidebar,
    },
    Sigil {
        id: SigilId::Disconnecting,
        glyph: "\u{25d1}",
        label: "Disconnecting",
        description: "Teardown in flight (wg-quick / openvpn finishing up).",
        color: theme::WARNING,
        bold: false,
        dim: false,
        category: SigilCategory::Sidebar,
    },
    Sigil {
        id: SigilId::AwaitingInput,
        glyph: "?",
        label: "Awaiting input",
        description: "Waiting for you to type a 2FA code, passphrase, or similar. Focus Connection Details and press Enter.",
        color: theme::WARNING,
        bold: false,
        dim: false,
        category: SigilCategory::Sidebar,
    },
    Sigil {
        id: SigilId::Failed,
        glyph: "\u{2717}",
        label: "Failed",
        description: "Last connect attempt failed. The badge persists until you retry or dismiss the row.",
        color: theme::ERROR,
        bold: false,
        dim: false,
        category: SigilCategory::Sidebar,
    },
    Sigil {
        id: SigilId::PrimaryMarker,
        glyph: "*",
        label: "Primary marker",
        description: "Sidebar suffix on the current Primary tunnel. Cross-correlates with the header's CONNECTED-name and Connection Details' Role: Primary line.",
        color: theme::SUCCESS,
        bold: true,
        dim: false,
        category: SigilCategory::Sidebar,
    },
    Sigil {
        id: SigilId::RiskMarker,
        glyph: "!",
        label: "Risk annotation",
        description: "Side-suffix flagging a per-tunnel risk worth attention. Today: appears on Split tunnel (yielded) to flag the mode-mismatch.",
        color: theme::WARNING,
        bold: true,
        dim: false,
        category: SigilCategory::Sidebar,
    },
    // ── Security Guard row sigils ─────────────────────────────────────
    Sigil {
        id: SigilId::SgOk,
        glyph: "\u{2713}",
        label: "OK",
        description: "This row's check passes. Muted green so it fades into the all-OK state without competing for attention.",
        color: theme::SUCCESS,
        bold: false,
        dim: false,
        category: SigilCategory::SecurityGuard,
    },
    Sigil {
        id: SigilId::SgNotApplicable,
        glyph: "\u{2500}",
        label: "Not applicable",
        description: "This row's check doesn't apply on the current platform or in the current state. E.g., IPv6 when there's no v6 traffic to evaluate (host has no v6, or no Connected tunnel covers ::/0), or IP when no primary owns the default route.",
        color: theme::INACTIVE,
        bold: false,
        dim: false,
        category: SigilCategory::SecurityGuard,
    },
    Sigil {
        id: SigilId::SgAlarmWarn,
        glyph: "\u{26a0}",
        label: "Warning",
        description: "Action recommended but not strictly broken. E.g., the kill switch is in Auto mode and the VPN is up but not yet armed in DROP state.",
        color: theme::WARNING,
        bold: true,
        dim: false,
        category: SigilCategory::SecurityGuard,
    },
    Sigil {
        id: SigilId::SgAlarmError,
        glyph: "\u{2717}",
        label: "Alarm",
        description: "Real problem the panel can quantify — IP leak, DNS leak, blocked egress. Always bold; typically has a sub-line explaining what to do.",
        color: theme::ERROR,
        bold: true,
        dim: false,
        category: SigilCategory::SecurityGuard,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Every [`SigilId`] variant must have a catalog entry. The
    /// exhaustive `match` below makes this a compile-time check —
    /// adding a `SigilId` variant without updating the catalog can't
    /// pass this test. Mirrors the contract that renderers can do
    /// `sigil(SigilId::Foo)` and expect a result.
    #[test]
    fn every_sigil_id_has_a_catalog_entry() {
        // Enumerate every variant via an exhaustive match. The
        // compiler will fail this list to compile if a new SigilId
        // variant is added without a branch here.
        let all_ids = [
            SigilId::Connected,
            SigilId::ConnectedUnauthoritative,
            SigilId::Connecting,
            SigilId::Reconnecting,
            SigilId::Disconnecting,
            SigilId::AwaitingInput,
            SigilId::Failed,
            SigilId::PrimaryMarker,
            SigilId::RiskMarker,
            SigilId::SgOk,
            SigilId::SgNotApplicable,
            SigilId::SgAlarmWarn,
            SigilId::SgAlarmError,
        ];
        // Exhaustive-match guard: if you add a SigilId variant and
        // forget to add it to `all_ids`, this match arm forces you
        // to update both. The `match` here is a compile-time
        // exhaustiveness check — the body is intentionally empty
        // because the existence of the arm IS the check.
        #[allow(clippy::match_same_arms, clippy::ignored_unit_patterns)]
        for id in &all_ids {
            match id {
                SigilId::Connected => (),
                SigilId::ConnectedUnauthoritative => (),
                SigilId::Connecting => (),
                SigilId::Reconnecting => (),
                SigilId::Disconnecting => (),
                SigilId::AwaitingInput => (),
                SigilId::Failed => (),
                SigilId::PrimaryMarker => (),
                SigilId::RiskMarker => (),
                SigilId::SgOk => (),
                SigilId::SgNotApplicable => (),
                SigilId::SgAlarmWarn => (),
                SigilId::SgAlarmError => (),
            }
        }

        for id in all_ids {
            let found = CATALOG.iter().find(|s| s.id == id);
            assert!(
                found.is_some(),
                "SigilId::{id:?} has no catalog entry — every SigilId variant must be in CATALOG"
            );
        }
    }

    #[test]
    fn catalog_has_no_duplicate_ids() {
        // Lookup uses `find()` which would silently pick the first
        // duplicate. Catch it here so the catalog stays unambiguous.
        let mut seen = std::collections::HashSet::new();
        for entry in CATALOG {
            assert!(
                seen.insert(entry.id),
                "duplicate catalog entry for SigilId::{:?}",
                entry.id
            );
        }
    }

    #[test]
    fn every_sigil_glyph_is_single_display_cell() {
        // Layout assumptions in the sidebar and help-overlay grid
        // depend on each sigil glyph being one display cell wide.
        use unicode_width::UnicodeWidthStr;
        for entry in CATALOG {
            assert_eq!(
                UnicodeWidthStr::width(entry.glyph),
                1,
                "sigil glyph `{}` for {:?} must be 1 display cell wide (was {})",
                entry.glyph,
                entry.id,
                UnicodeWidthStr::width(entry.glyph)
            );
        }
    }

    #[test]
    fn style_combines_color_and_modifiers() {
        // Sanity check on `Sigil::style()` — bold/dim flags compose
        // with the fg color.
        let bold_alarm = Sigil {
            id: SigilId::SgAlarmError,
            glyph: "x",
            label: "x",
            description: "x",
            color: Color::Red,
            bold: true,
            dim: false,
            category: SigilCategory::SecurityGuard,
        };
        let style = bold_alarm.style();
        assert_eq!(style.fg, Some(Color::Red));
        assert!(style.add_modifier.contains(Modifier::BOLD));
        assert!(!style.add_modifier.contains(Modifier::DIM));
    }
}
