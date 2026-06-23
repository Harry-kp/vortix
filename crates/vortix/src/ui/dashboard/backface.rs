//! `BackFace` v1 shared spec — verdict band, scope footer, nav-hint band.
//!
//! Every dashboard back face built on the v1 contract uses the same
//! verdict vocabulary, the same severity glyphs, and the same scope
//! footer rendering. This module owns those types and the three render
//! helpers that paint them onto a `ratatui` frame.
//!
//! # One vocabulary, used everywhere
//!
//! Like [`KillSwitchMode`](crate::state::KillSwitchMode), every
//! display path here routes through helper methods (`display_name`,
//! `short_label`, `color`, `glyph`) so the variant names never leak
//! into output. Future back faces (Chart #166, Connection Details
//! #167) consume the same helpers — there is no second copy of these
//! strings anywhere in the binary.
//!
//! | Rust enum               | Slug        | What it signals                                          |
//! |-------------------------|-------------|----------------------------------------------------------|
//! | `VerdictMode::Pass`     | `pass`      | All checks clean. Nothing to investigate.                |
//! | `VerdictMode::Watch`    | `watch`     | Approaching a threshold; surfaced but no action needed.  |
//! | `VerdictMode::Fail`     | `fail`      | A check tripped. The ribbon names the offending entity.  |
//! | `VerdictMode::Unknown`  | `unknown`   | Data unavailable (first-render, unsupported, partial).   |
//!
//! Severity glyphs follow the EICAS convention used in transport
//! cockpits (Boeing 757+, ARP 4102/4): a single character per row,
//! sorted most-severe-first so the eye lands on the loudest entry.

use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::theme;

/// Top-level verdict for a back-face. The four-way set is fixed —
/// `Watch` is reserved for future approaching-threshold logic so the
/// enum doesn't grow a breaking variant later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerdictMode {
    /// All checks clean. Slug: `pass`.
    Pass,
    /// Approaching a threshold; no action required yet. Slug: `watch`.
    Watch,
    /// A check tripped. Slug: `fail`.
    Fail,
    /// Data unavailable. Slug: `unknown`.
    Unknown,
}

impl VerdictMode {
    /// Long-form prose label rendered alongside the headline.
    /// `Pass` / `Watch` / `Fail` / `Unknown`. v1 callers only use
    /// `short_label`; this method is kept for future surfaces (JSON
    /// envelope, accessibility readers) and is exercised by the unit
    /// tests.
    #[allow(dead_code)]
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Pass => "Pass",
            Self::Watch => "Watch",
            Self::Fail => "Fail",
            Self::Unknown => "Unknown",
        }
    }

    /// Three- or four-character upper-case label for the verdict band.
    /// `PASS` / `WATCH` / `FAIL` / `???`. The Unknown slug uses `???`
    /// rather than `UNKN` so first-render and unsupported states read
    /// as "data missing" rather than "data is OK".
    #[must_use]
    pub const fn short_label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Watch => "WATCH",
            Self::Fail => "FAIL",
            Self::Unknown => "???",
        }
    }

    /// Color used to render the short label on the verdict band.
    /// Routes through the theme module so a future palette switch
    /// re-skins every back face at once.
    #[must_use]
    pub fn color(self) -> Color {
        match self {
            Self::Pass => theme::SUCCESS,
            Self::Watch => theme::WARNING,
            Self::Fail => theme::ERROR,
            Self::Unknown => theme::TEXT_SECONDARY,
        }
    }
}

/// Severity tier for an EICAS-style alert ribbon row. Variants are
/// declared most-severe first so the derived [`Ord`] gives ascending
/// sort = surface alarms before status. Direct EICAS borrow.
///
/// v1 only emits `Warning` (the only severity Security Guard's leak
/// rows produce); `Caution`, `Advisory`, and `Status` are reserved so
/// future back faces can land without an enum-breaking change. The
/// variants are exercised by the unit tests in this module.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Top-tier alarm — red, demands attention.
    Warning,
    /// Mid-tier — amber, action recommended but not immediate.
    Caution,
    /// Informational anomaly — cyan, worth knowing.
    Advisory,
    /// Routine status row — white/dim, no anomaly.
    Status,
}

impl Severity {
    /// Single-character glyph rendered at the start of a ribbon row.
    /// Per EICAS tiering: filled disc → half disc → ring → dot.
    #[must_use]
    pub const fn glyph(self) -> char {
        match self {
            Self::Warning => '\u{25CF}',
            Self::Caution => '\u{25D0}',
            Self::Advisory => '\u{25CB}',
            Self::Status => '\u{00B7}',
        }
    }

    /// Color used for the glyph + headline on a ribbon row. Routes
    /// through the theme module to stay re-skinnable.
    #[must_use]
    pub fn color(self) -> Color {
        match self {
            Self::Warning => theme::ERROR,
            Self::Caution => theme::WARNING,
            Self::Advisory => theme::ACCENT_PRIMARY,
            Self::Status => theme::TEXT_PRIMARY,
        }
    }
}

/// Where the back-face's data applies. Rendered as a right-aligned
/// `scope: …` footer on every v1 back face so the operator always
/// knows which entity the verdict above belongs to.
///
/// `FocusedSecondary` is reserved for the Connection Details back face
/// migration (#167); v1 Security Guard renders only `Primary` /
/// `ExternalAdopted` / `Unsupported` / `Partial`. Exercised by the
/// unit tests below.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// The primary tunnel — owns the default route, full telemetry.
    Primary { interface: String },
    /// A non-primary tunnel currently focused by the user. Telemetry
    /// is reduced (per-tunnel rather than route-attributed).
    FocusedSecondary { interface: String },
    /// A tunnel adopted from outside vortix (`wg-quick up` run by
    /// hand, etc.). Attribution is best-effort and unauthoritative.
    ExternalAdopted { interface: Option<String> },
    /// The current platform doesn't support the data this back-face
    /// renders. Used for Windows socket audit, etc.
    Unsupported { platform: &'static str },
    /// The data is available but partial — non-root inventory,
    /// incomplete probe, etc. The `reason` names the limitation.
    Partial { reason: &'static str },
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Primary { interface } => write!(f, "scope: primary {interface}"),
            Self::FocusedSecondary { interface } => {
                write!(
                    f,
                    "scope: {interface} \u{2014} focused secondary, reduced telemetry"
                )
            }
            Self::ExternalAdopted { .. } => {
                // v1 omits the interface name from the rendered scope;
                // attribution is unauthoritative so naming the iface
                // could mislead. The field stays in the struct for
                // future surfaces (e.g. JSON envelope).
                write!(f, "scope: external-adopted, unauthoritative")
            }
            Self::Unsupported { platform } => write!(f, "scope: unsupported on {platform}"),
            Self::Partial { reason } => write!(f, "scope: partial \u{2014} {reason}"),
        }
    }
}

/// Render the verdict band: `<short_label>  <headline>` in the
/// verdict's color. The label sits at the left margin; the headline
/// follows after two spaces of breath.
pub fn render_verdict_band(frame: &mut Frame, area: Rect, verdict: VerdictMode, headline: &str) {
    let color = verdict.color();
    let line = Line::from(vec![
        Span::styled(
            verdict.short_label().to_string(),
            Style::default().fg(color),
        ),
        Span::raw("  "),
        Span::styled(headline.to_string(), Style::default().fg(color)),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

/// Render the scope footer right-aligned in the area, in a dim
/// secondary-text color so it recedes behind the verdict and ribbon.
pub fn render_scope_footer(frame: &mut Frame, area: Rect, scope: &Scope) {
    let line = Line::from(Span::styled(
        scope.to_string(),
        Style::default().fg(theme::TEXT_SECONDARY),
    ))
    .alignment(Alignment::Right);
    frame.render_widget(Paragraph::new(line), area);
}

/// Render a nav-hint band as right-aligned `<key> <label>` pairs
/// joined by three spaces. Empty `hints` produces an empty line so
/// callers can claim a row unconditionally without a branch.
#[allow(dead_code)] // first consumer arrives with #166 / #167
pub fn render_nav_hint_band(frame: &mut Frame, area: Rect, hints: &[(&str, &str)]) {
    let mut spans: Vec<Span<'static>> = Vec::with_capacity(hints.len().saturating_mul(4));
    for (i, (key, label)) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("   "));
        }
        spans.push(Span::styled(
            (*key).to_string(),
            Style::default().fg(theme::KEY_HINT),
        ));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            (*label).to_string(),
            Style::default().fg(theme::KEY_HINT_DESC),
        ));
    }
    let line = Line::from(spans).alignment(Alignment::Right);
    frame.render_widget(Paragraph::new(line), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn render_into<F: FnOnce(&mut Frame, Rect)>(
        width: u16,
        height: u16,
        draw: F,
    ) -> Terminal<TestBackend> {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| {
                let area = Rect::new(0, 0, width, height);
                draw(frame, area);
            })
            .expect("draw");
        terminal
    }

    fn row_text(terminal: &Terminal<TestBackend>, row: u16) -> String {
        let buf = terminal.backend().buffer();
        let mut s = String::new();
        for x in 0..buf.area.width {
            s.push_str(buf[(x, row)].symbol());
        }
        s
    }

    #[test]
    fn verdict_mode_display_name_returns_canonical_label() {
        assert_eq!(VerdictMode::Pass.display_name(), "Pass");
        assert_eq!(VerdictMode::Watch.display_name(), "Watch");
        assert_eq!(VerdictMode::Fail.display_name(), "Fail");
        assert_eq!(VerdictMode::Unknown.display_name(), "Unknown");
    }

    #[test]
    fn verdict_mode_short_label_returns_three_or_four_chars() {
        assert_eq!(VerdictMode::Pass.short_label(), "PASS");
        assert_eq!(VerdictMode::Watch.short_label(), "WATCH");
        assert_eq!(VerdictMode::Fail.short_label(), "FAIL");
        assert_eq!(VerdictMode::Unknown.short_label(), "???");
        for v in [
            VerdictMode::Pass,
            VerdictMode::Watch,
            VerdictMode::Fail,
            VerdictMode::Unknown,
        ] {
            let n = v.short_label().chars().count();
            assert!(
                (3..=5).contains(&n),
                "short_label for {v:?} should be 3-5 chars, got {n}"
            );
        }
    }

    #[test]
    fn verdict_mode_serde_round_trip_via_lowercase_slug() {
        for (mode, slug) in [
            (VerdictMode::Pass, "\"pass\""),
            (VerdictMode::Watch, "\"watch\""),
            (VerdictMode::Fail, "\"fail\""),
            (VerdictMode::Unknown, "\"unknown\""),
        ] {
            let encoded = serde_json::to_string(&mode).expect("serialize");
            assert_eq!(encoded, slug, "serialize mismatch for {mode:?}");
            let decoded: VerdictMode = serde_json::from_str(slug).expect("deserialize");
            assert_eq!(decoded, mode, "deserialize mismatch for {slug}");
        }
    }

    #[test]
    fn severity_glyph_matches_eicas_table() {
        assert_eq!(Severity::Warning.glyph(), '\u{25CF}');
        assert_eq!(Severity::Caution.glyph(), '\u{25D0}');
        assert_eq!(Severity::Advisory.glyph(), '\u{25CB}');
        assert_eq!(Severity::Status.glyph(), '\u{00B7}');
    }

    #[test]
    fn severity_ordering_surfaces_most_severe_first() {
        let mut v = vec![
            Severity::Status,
            Severity::Warning,
            Severity::Advisory,
            Severity::Caution,
        ];
        v.sort();
        assert_eq!(
            v,
            vec![
                Severity::Warning,
                Severity::Caution,
                Severity::Advisory,
                Severity::Status,
            ]
        );
    }

    #[test]
    fn scope_display_primary_renders_with_interface() {
        let scope = Scope::Primary {
            interface: "utun3".into(),
        };
        assert_eq!(scope.to_string(), "scope: primary utun3");
    }

    #[test]
    fn scope_display_focused_secondary_renders_with_reduced_telemetry_label() {
        let scope = Scope::FocusedSecondary {
            interface: "utun5".into(),
        };
        assert_eq!(
            scope.to_string(),
            "scope: utun5 \u{2014} focused secondary, reduced telemetry"
        );
    }

    #[test]
    fn scope_display_external_adopted_renders_unauthoritative_label() {
        let scope = Scope::ExternalAdopted {
            interface: Some("utun7".into()),
        };
        assert_eq!(
            scope.to_string(),
            "scope: external-adopted, unauthoritative"
        );

        let scope_none = Scope::ExternalAdopted { interface: None };
        assert_eq!(
            scope_none.to_string(),
            "scope: external-adopted, unauthoritative"
        );
    }

    #[test]
    fn scope_display_unsupported_renders_platform_label() {
        let scope = Scope::Unsupported {
            platform: "Windows",
        };
        assert_eq!(scope.to_string(), "scope: unsupported on Windows");
    }

    #[test]
    fn scope_display_partial_renders_reason() {
        let scope = Scope::Partial { reason: "non-root" };
        assert_eq!(scope.to_string(), "scope: partial \u{2014} non-root");
    }

    #[test]
    fn render_verdict_band_uses_verdict_color() {
        let terminal = render_into(20, 1, |frame, area| {
            render_verdict_band(frame, area, VerdictMode::Pass, "all good");
        });
        let buf = terminal.backend().buffer();
        let row = row_text(&terminal, 0);
        assert!(
            row.starts_with("PASS  all good"),
            "verdict band layout wrong: {row:?}"
        );
        for x in 0..4 {
            assert_eq!(
                buf[(x, 0)].fg,
                VerdictMode::Pass.color(),
                "PASS cell at x={x} should match verdict color"
            );
        }
    }

    #[test]
    fn render_scope_footer_right_aligns_text() {
        let scope = Scope::Primary {
            interface: "utun3".into(),
        };
        let terminal = render_into(40, 1, |frame, area| {
            render_scope_footer(frame, area, &scope);
        });
        let row = row_text(&terminal, 0);
        let expected = "scope: primary utun3";
        assert!(
            row.ends_with(expected),
            "scope footer should be right-aligned: {row:?}"
        );
        let lead_spaces = row.len() - row.trim_start().len();
        assert!(
            lead_spaces > 0,
            "scope footer should have leading padding (right-aligned): {row:?}"
        );
    }

    #[test]
    fn render_nav_hint_band_omits_keys_not_passed() {
        let terminal = render_into(40, 1, |frame, area| {
            render_nav_hint_band(frame, area, &[("Esc", "back")]);
        });
        let row = row_text(&terminal, 0);
        assert!(
            row.ends_with("Esc back"),
            "nav hint should render only Esc back, right-aligned: {row:?}"
        );
        for forbidden in ["Tab", "Enter", "Space", "Shift", "Ctrl"] {
            assert!(
                !row.contains(forbidden),
                "nav hint must omit '{forbidden}' when not passed: {row:?}"
            );
        }
        let trimmed = row.trim();
        assert_eq!(
            trimmed, "Esc back",
            "nav hint band must render only the passed pair: {row:?}"
        );
    }
}
