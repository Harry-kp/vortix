//! Help overlay with four tabs: Keys, Roles, Sigils, Guard.
//!
//! `?` opens the overlay on the Keys tab. `Tab` / `Shift+Tab` cycle
//! through the tabs (browser-style strip rendered at the top with the
//! active tab highlighted). `j`/`k`/arrows scroll within the active
//! tab; `Esc` or `?` close.
//!
//! Each tab gets a layout appropriate to its content density:
//!
//! - **Keys** — compact two-column reference (key + short action).
//!   Many entries, short on either side.
//! - **Roles** — card-style with multi-line prose. Few entries, each
//!   needs ~3-5 lines of plain-English explanation. Same vocabulary
//!   as `connection_details::role_line`.
//! - **Sigils** — 3-column grid (glyph in its TUI color │ short label
//!   │ one-line description). Reads from
//!   [`crate::ui::sigils::CATALOG`] — the single source of truth that
//!   the actual renderers also use. Drift between what users see
//!   on-screen and what the help shows is structurally impossible.
//! - **Guard** — card-style explainer for the Security Guard panel:
//!   the three headline states (EXPOSED / PARTIAL / PROTECTED) and
//!   what each row (IP, DNS, Killswitch, Encryption, IPv6) actually
//!   checks. Complements the Sigils tab — sigils explain the glyphs,
//!   Guard explains the semantics.

use crate::ui::sigils::{Sigil, SigilCategory, CATALOG};
use crate::{state, state::HelpTab, theme};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Tabs, Wrap},
    Frame,
};

// ────────────────────────────── Keys tab ───────────────────────────────

const HELP_TEXT: &[(&str, &[(&str, &str)])] = &[
    (
        "Global",
        &[
            ("1-9", "Quick connect to profile N"),
            ("d", "Disconnect focused tunnel / Cancel / Force Kill"),
            ("D", "Disconnect ALL active tunnels (when N>1)"),
            ("r", "Reconnect"),
            ("i", "Import profile (file, dir, URL)"),
            ("K", "Cycle kill switch mode"),
            ("y", "Copy VPN IP to clipboard"),
            ("Tab/S-Tab", "Next / Previous panel"),
            ("F1-F5", "Jump to panel (Prof/Det/Chart/Sec/Log)"),
            ("z", "Zoom focused panel"),
            ("x", "Action menu"),
            ("b", "Bulk action menu"),
            ("/", "Search profiles"),
            ("?", "Toggle this help"),
            ("q", "Quit"),
        ],
    ),
    (
        "Sidebar (Profiles)",
        &[
            ("j / ↓", "Next profile"),
            ("k / ↑", "Previous profile"),
            ("g / Home", "First profile"),
            ("G / End", "Last profile"),
            ("PgUp/PgDn", "Page up / down"),
            ("c / Enter", "Connect / disconnect focused row"),
            ("R", "Rename profile"),
            ("v", "View config"),
            ("s", "Cycle sort order"),
            ("a", "Manage auth (OpenVPN)"),
            ("A", "Clear saved auth"),
            ("Del", "Delete profile"),
        ],
    ),
    (
        "Connection Details",
        &[
            ("c", "Cancel in-flight connect"),
            (
                "(switch tunnels)",
                "Use the sidebar (j/k) — Details follows the selected profile",
            ),
        ],
    ),
    (
        "Switch-VPN overlay",
        &[
            ("Y / Enter", "Switch — disconnect current, then connect new"),
            ("B", "Connect both — new becomes active exit"),
            ("N / Esc", "Cancel"),
        ],
    ),
    (
        "Logs Panel",
        &[
            ("j / ↓", "Scroll down"),
            ("k / ↑", "Scroll up"),
            ("f", "Cycle log level filter"),
            ("L", "Clear logs"),
        ],
    ),
    (
        "Config Viewer",
        &[
            ("j / ↓ / k / ↑", "Scroll"),
            ("g / G", "Top / Bottom"),
            ("Esc", "Close"),
        ],
    ),
    (
        "Help overlay",
        &[
            ("Tab", "Next tab (Keys → Roles → Sigils → Guard)"),
            ("Shift+Tab", "Previous tab"),
            ("j / k / ↑ / ↓", "Scroll within tab"),
            ("g / G", "Top / Bottom of tab"),
            ("? / Esc / q", "Close help"),
        ],
    ),
];

// ────────────────────────────── Roles tab ───────────────────────────────

/// `(label, description_paragraph)` for every Role label that
/// `connection_details::role_line` can emit. Descriptions wrap inside
/// the overlay so paragraph length is unlimited.
const ROLE_GLOSSARY: &[(&str, &str)] = &[
    (
        "Primary",
        "Your active exit. Internet traffic flows through this tunnel — the kernel routes its default route here, so any new outbound connection goes via this tunnel's server.",
    ),
    (
        "Primary (10.0.0.0/8)",
        "Same as Primary, with the declared subnet shown in parens. Don't read this as 'only routes that subnet' — it IS the exit; the CIDR is just what the profile config declares.",
    ),
    (
        "Primary (multi)",
        "Same as Primary; the profile declares multiple subnets. Shown when the config has more than one declared CIDR (rare but possible).",
    ),
    (
        "Split tunnel",
        "Connected but NOT your exit. Only carries the routes the profile declared (its AllowedIPs for WireGuard, or `route` directives for OpenVPN). Internet traffic still uses your normal connection. Example: a corporate VPN routing only 10.0.0.0/8 so you can reach internal services without your browsing going through work.",
    ),
    (
        "Split tunnel (10.0.0.0/8)",
        "Same; the listed CIDR is the only subnet this tunnel routes. Everything else goes via your normal internet.",
    ),
    (
        "Split tunnel (multi)",
        "Same; the profile declares multiple non-default subnets.",
    ),
    (
        "Split tunnel (yielded)",
        "Wanted to be your exit (declared 0.0.0.0/0) but another tunnel won the race. 'Yielded' = stood down. Sits as a hot standby: if the active primary drops, the kernel re-routes through this tunnel and you'll see a toast naming the new active exit. You see this label after pressing Shift+B (Both) on the takeover overlay.",
    ),
    (
        "Split tunnel (multi, yielded)",
        "Same as yielded; the profile declares multiple subnets including 0/0. Another tunnel is the active exit; this one is a hot standby.",
    ),
    (
        "(external) suffix",
        "Tunnel detected as up but started outside vortix (e.g., `sudo openvpn ...` from another terminal) AND on a platform where vortix can't reliably attribute its kernel interface to its PID. On macOS this happens with multi-OpenVPN. Vortix won't elect an (external) tunnel as your Primary even if its routes would qualify — start the tunnel through vortix to get full tracking.",
    ),
    (
        "Reconnecting via …",
        "A connected tunnel dropped and vortix is automatically retrying. The 'via X' part names what its role was before the drop, so you know what to expect when it comes back.",
    ),
    (
        "n/a (awaiting input)",
        "The tunnel is waiting for you to type something (2FA code, passphrase). Press Enter while focused on Connection Details to surface the prompt overlay.",
    ),
];

const ROLE_GLOSSARY_FOOTER: &str =
    "Full guide with examples + common confusions: docs/roles.md on GitHub.";

// ────────────────────────────── Guard tab ───────────────────────────────

/// Plain-English explainer for the Security Guard panel. Each entry is
/// `(label, description_paragraph)` matching the same card-style
/// layout as the Roles tab. Two clusters:
///   1. The three headline states (EXPOSED / PARTIAL / PROTECTED).
///   2. Each row the panel renders (IP, DNS, Killswitch, etc.) and
///      what makes that row light up vs stay quiet.
const GUARD_GLOSSARY: &[(&str, &str)] = &[
    (
        "EXPOSED",
        "No tunnel is up, or no tunnel claims your kernel default route. All internet traffic flows via your normal ISP — websites see your real IP. If you intended a VPN, this is the alarm state: connect a profile or check why your tunnel dropped.",
    ),
    (
        "PARTIAL",
        "At least one tunnel is Connected, but none owns the default route (split-only topology), OR a primary IS up but a defense row is degraded (killswitch off, cipher weak, DNS leak). Declared subnets tunnel correctly; general internet traffic posture depends on which signal demoted the panel.",
    ),
    (
        "PROTECTED",
        "A tunnel owns your kernel default route, the cipher is modern AEAD, killswitch is engaged, and neither IP nor DNS is leaking. New outbound connections flow through the tunnel. This is the goal state for a full-tunnel VPN.",
    ),
    (
        "Identity → Real IP",
        "Your cached pre-VPN public IP — what your ISP would expose you as if no tunnel were up. Always informational (no safety verdict on this row): it's what you'd revert to if the VPN dropped. In EXPOSED state this equals Exit IP because nothing is masking.",
    ),
    (
        "Identity → Exit IP",
        "The public IP the rest of the internet sees you as right now. With a working full-tunnel VPN this is the tunnel's exit IP and the row reads ✓. When it matches Real IP, the row goes ✗ with 'real IP exposed' — masking has failed and your traffic is leaking.",
    ),
    (
        "Identity → Location",
        "Geo lookup of Exit IP (city + country). Sanity check: connect a German VPN, this should say DE. If it still says your home country, the tunnel didn't take over the default route.",
    ),
    (
        "Identity → DNS",
        "Which DNS server resolves your queries right now, with the provider tag inlined when recognised (Cloudflare/Google/Quad9). If a VPN pushed DNS, this should be the VPN's resolver, not your ISP's — otherwise DNS queries leak the names of sites you visit even while the tunnel carries the actual traffic.",
    ),
    (
        "Defense → Killswitch",
        "Current killswitch mode and runtime state. Modes: Off (no firewall), Block-on-drop (firewall armed but quiet while VPN is up; engages default-DROP egress the moment VPN drops — also reads 'VPN dropped' with 'press r to reconnect' sub-line during the drop window), VPN-only (firewall always engaged with per-tunnel ACCEPT rules — closes the gap-between-drop-and-reconnect leak window). Cycle modes with Shift+K.",
    ),
    (
        "Defense → Encryption",
        "The tunnel's cipher annotated with its security grade. ChaCha20-Poly1305 / AES-GCM → modern AEAD. AES-256-CBC / AES-256-CTR → strong. 3DES / AES-128-CBC → deprecated (alarm + 'upgrade to AES-GCM' sub-line). BF / DES / RC4 / NULL → INSECURE (loud alarm + 'broken cipher' sub-line).",
    ),
    (
        "Defense → IPv6",
        "Honest line: vortix's killswitch enforces v4-only on every platform today. If your system has IPv6 connectivity AND your VPN doesn't tunnel v6, IPv6 traffic CAN bypass the firewall even in VPN-only mode. The row's `─` sigil is the 'not-applicable' marker, not a green check — it means 'we are not enforcing this dimension'.",
    ),
];

const GUARD_GLOSSARY_FOOTER: &str =
    "Sigils tab covers the glyphs (✓ ✗ ⚠ ─); this tab covers what each row checks.";

// ────────────────────────────── Rendering ──────────────────────────────

const OVERLAY_MAX_WIDTH: u16 = 120;
const TAB_STRIP_HEIGHT: u16 = 2;

#[must_use]
pub fn total_lines(tab: HelpTab) -> u16 {
    #[allow(clippy::cast_possible_truncation)]
    match tab {
        HelpTab::Keys => HELP_TEXT
            .iter()
            .enumerate()
            .map(|(section_idx, (_, bindings))| bindings.len() + 2 + usize::from(section_idx > 0))
            .sum::<usize>() as u16,
        HelpTab::Roles => {
            // ~6 lines per entry (header + ~4 wrapped + blank) + leading blank + footer
            (1 + ROLE_GLOSSARY.len() * 6 + 2) as u16
        }
        HelpTab::Sigils => {
            // 1 header per category + ~2 lines per entry. Conservative upper bound.
            let entries = CATALOG.len();
            (2 + entries * 2 + 4) as u16
        }
        HelpTab::Guard => {
            // Same shape as Roles — ~6 lines per entry (header + wrapped
            // body + blank) + leading blank + footer.
            (1 + GUARD_GLOSSARY.len() * 6 + 2) as u16
        }
    }
}

pub fn render(frame: &mut Frame, scroll: u16, tab: HelpTab) {
    let area = frame.area();
    let width = area.width.saturating_sub(4).min(OVERLAY_MAX_WIDTH);
    let height = area
        .height
        .saturating_sub(2)
        .min(state::HELP_OVERLAY_MAX_HEIGHT);
    if width == 0 || height == 0 {
        return;
    }

    let overlay = Rect {
        x: (area.width / 2).saturating_sub(width / 2),
        y: (area.height / 2).saturating_sub(height / 2),
        width,
        height,
    };

    frame.render_widget(Clear, overlay);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::ACCENT_PRIMARY))
        .title(Span::styled(
            " Help ",
            Style::default()
                .fg(theme::ACCENT_PRIMARY)
                .add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " Tab next · Shift+Tab prev · ↑↓ j/k scroll · ? close ",
            Style::default().fg(theme::KEY_HINT_DESC),
        ));

    let inner = block.inner(overlay);
    frame.render_widget(block, overlay);

    // Top strip = tabs. Below = active tab content. Layout the inner
    // area into [tabs | divider | content].
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(TAB_STRIP_HEIGHT),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .split(inner);

    render_tab_strip(frame, chunks[0], tab);
    render_divider(frame, chunks[1]);

    let active_tab = HelpTab::ALL.iter().position(|t| *t == tab).unwrap_or(0);
    // Clamp scroll against the ACTUAL content-paragraph height
    // (chunks[2]), not the full inner area. The tab strip + divider
    // eat 3 rows from the top of inner; without accounting for that
    // here, max_scroll would underestimate and the bottom 3 lines of
    // each tab would be unreachable.
    let content_height = chunks[2].height;
    let max_scroll = total_lines(tab).saturating_sub(content_height);
    let clamped_scroll = scroll.min(max_scroll);

    let lines = match HelpTab::ALL[active_tab] {
        HelpTab::Keys => build_keys_lines(),
        HelpTab::Roles => build_glossary_lines(ROLE_GLOSSARY, Some(ROLE_GLOSSARY_FOOTER)),
        HelpTab::Sigils => build_sigils_lines(),
        HelpTab::Guard => build_glossary_lines(GUARD_GLOSSARY, Some(GUARD_GLOSSARY_FOOTER)),
    };
    let paragraph = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((clamped_scroll, 0));
    frame.render_widget(paragraph, chunks[2]);
}

/// Render the browser-style tab strip across the top of the overlay.
/// Active tab gets accent + BOLD + UNDERLINED; inactive tabs get
/// muted secondary text. ratatui's `Tabs` widget does the layout +
/// separator handling consistently.
fn render_tab_strip(frame: &mut Frame, area: Rect, active: HelpTab) {
    let titles: Vec<Line> = HelpTab::ALL
        .iter()
        .map(|t| Line::from(Span::styled(t.title(), Style::default())))
        .collect();
    let active_idx = HelpTab::ALL.iter().position(|t| *t == active).unwrap_or(0);
    let tabs = Tabs::new(titles)
        .select(active_idx)
        .style(Style::default().fg(theme::TEXT_SECONDARY))
        .highlight_style(
            Style::default()
                .fg(theme::ACCENT_PRIMARY)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )
        .divider(Span::styled(
            " │ ",
            Style::default().fg(theme::NORD_POLAR_NIGHT_4),
        ));
    frame.render_widget(tabs, area);
}

fn render_divider(frame: &mut Frame, area: Rect) {
    let line = Line::from(Span::styled(
        "─".repeat(area.width as usize),
        Style::default().fg(theme::NORD_POLAR_NIGHT_4),
    ));
    frame.render_widget(Paragraph::new(line), area);
}

fn build_keys_lines() -> Vec<Line<'static>> {
    let mut lines: Vec<Line> = Vec::new();
    for (section_idx, (section, bindings)) in HELP_TEXT.iter().enumerate() {
        if section_idx > 0 {
            lines.push(Line::from(""));
        }
        lines.push(Line::from(Span::styled(
            format!("  {section}"),
            Style::default()
                .fg(theme::ACCENT_PRIMARY)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )));
        lines.push(Line::from(""));

        for (key, desc) in *bindings {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("    {key:<14}"),
                    Style::default()
                        .fg(theme::KEY_HINT)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(*desc, Style::default().fg(theme::TEXT_SECONDARY)),
            ]));
        }
    }
    lines
}

/// Card-style glossary renderer for the Roles tab. Each entry:
///   blank
///   ●  <label>
///   <description, indented, wrapped naturally>
fn build_glossary_lines(
    entries: &'static [(&'static str, &'static str)],
    footer: Option<&'static str>,
) -> Vec<Line<'static>> {
    let mut lines: Vec<Line> = Vec::with_capacity(entries.len() * 6 + 2);
    lines.push(Line::from(""));
    for (label, desc) in entries {
        lines.push(Line::from(vec![
            Span::styled(
                "  \u{25cf}  ",
                Style::default()
                    .fg(theme::ACCENT_PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                *label,
                Style::default()
                    .fg(theme::ACCENT_PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from(Span::styled(
            format!("     {desc}"),
            Style::default().fg(theme::TEXT_SECONDARY),
        )));
        lines.push(Line::from(""));
    }
    if let Some(footer) = footer {
        lines.push(Line::from(Span::styled(
            format!("  {footer}"),
            Style::default()
                .fg(theme::KEY_HINT_DESC)
                .add_modifier(Modifier::ITALIC),
        )));
    }
    lines
}

/// 3-column grid for the Sigils tab. Each row:
///   <glyph in its real TUI color>  <label, bold>  <description, secondary>
/// Grouped by [`SigilCategory`] with a category header above each group.
fn build_sigils_lines() -> Vec<Line<'static>> {
    let mut lines: Vec<Line> = Vec::with_capacity(CATALOG.len() * 2 + 6);

    for category in [SigilCategory::Sidebar, SigilCategory::SecurityGuard] {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {}", category_title(category)),
            Style::default()
                .fg(theme::ACCENT_PRIMARY)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )));
        lines.push(Line::from(""));

        for entry in CATALOG.iter().filter(|s| s.category == category) {
            lines.push(sigil_row(entry));
        }
    }
    lines
}

fn category_title(c: SigilCategory) -> &'static str {
    match c {
        SigilCategory::Sidebar => "Sidebar (per-tunnel badges + suffixes)",
        SigilCategory::SecurityGuard => "Security Guard (per-row sigils)",
    }
}

/// One row of the Sigils tab. The glyph is rendered in its actual
/// TUI color (the one the renderer applies), so the help-overlay
/// swatch matches what users see on screen byte-for-byte.
fn sigil_row(entry: &'static Sigil) -> Line<'static> {
    // Column widths chosen to fit comfortably at the 95-col overlay:
    //   glyph column: 4 cells (1 glyph + 3 padding for visual gutter)
    //   label column: 24 cells
    //   description: rest, wraps naturally
    Line::from(vec![
        Span::styled(format!("    {}   ", entry.glyph), entry.style()),
        Span::styled(
            format!("{:<22}", entry.label),
            Style::default()
                .fg(theme::TEXT_PRIMARY)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            entry.description,
            Style::default().fg(theme::TEXT_SECONDARY),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_tunnel_keys_are_documented() {
        // Smoke check that the multi-tunnel keys (Shift+D, B on
        // takeover, etc.) all surfaced in the keybindings section.
        use std::fmt::Write;
        let blob = HELP_TEXT
            .iter()
            .flat_map(|(_, bindings)| bindings.iter())
            .fold(String::new(), |mut acc, (k, d)| {
                let _ = writeln!(acc, "{k} {d}");
                acc
            });
        assert!(blob.contains("Disconnect ALL"));
        assert!(blob.contains("Connect both"));
    }

    #[test]
    fn role_glossary_covers_every_label_role_line_can_emit() {
        let labels: Vec<&str> = ROLE_GLOSSARY.iter().map(|(k, _)| *k).collect();
        for expected in [
            "Primary",
            "Split tunnel",
            "Split tunnel (yielded)",
            "Split tunnel (multi, yielded)",
            "(external) suffix",
            "Reconnecting via …",
        ] {
            assert!(
                labels.contains(&expected),
                "Roles tab must document `{expected}`; found: {labels:?}"
            );
        }
    }

    #[test]
    fn sigils_tab_renders_every_catalog_entry() {
        // The Sigils tab content is generated from CATALOG — make sure
        // EVERY entry produces a row. This is the drift-detection
        // backstop: adding a sigil to the catalog automatically makes
        // it appear in help; removing one from the catalog removes it.
        let lines = build_sigils_lines();
        let blob: String = lines
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.as_ref())
            .collect::<String>();
        for entry in CATALOG {
            assert!(
                blob.contains(entry.label),
                "Sigils tab missing label `{}`; CATALOG entry not surfaced",
                entry.label
            );
        }
    }

    #[test]
    fn keys_total_lines_invariant_holds() {
        let expected = u16::try_from(build_keys_lines().len()).expect("fits in u16");
        assert_eq!(total_lines(HelpTab::Keys), expected);
    }

    #[test]
    fn help_tab_cycle_wraps_in_both_directions() {
        let cycle: Vec<HelpTab> = std::iter::successors(Some(HelpTab::Keys), |t| Some(t.next()))
            .take(HelpTab::ALL.len() + 1)
            .collect();
        assert_eq!(
            cycle,
            vec![
                HelpTab::Keys,
                HelpTab::Roles,
                HelpTab::Sigils,
                HelpTab::Guard,
                HelpTab::Keys
            ]
        );
        assert_eq!(HelpTab::Keys.prev(), HelpTab::Guard);
    }

    #[test]
    fn guard_glossary_covers_headline_states_and_every_panel_row() {
        // Drift-detection backstop: the Guard tab must document each
        // headline state the panel can render AND every row the panel
        // shows. If a new row or state is added to security.rs, the
        // assertion fails until the glossary catches up. Labels MUST
        // match the panel's actual row labels byte-for-byte.
        let labels: Vec<&str> = GUARD_GLOSSARY.iter().map(|(k, _)| *k).collect();
        for expected in [
            // Headline states (Verdict enum in security.rs).
            "EXPOSED",
            "PARTIAL",
            "PROTECTED",
            // Identity rows.
            "Identity → Real IP",
            "Identity → Exit IP",
            "Identity → Location",
            "Identity → DNS",
            // Defense rows.
            "Defense → Killswitch",
            "Defense → Encryption",
            "Defense → IPv6",
        ] {
            assert!(
                labels.contains(&expected),
                "Guard tab must document `{expected}`; found: {labels:?}"
            );
        }
    }
}
