//! Help overlay showing all keybindings

use crate::{state, theme};
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

const HELP_TEXT: &[(&str, &[(&str, &str)])] = &[
    (
        "Global",
        &[
            ("1-9", "Quick connect to profile N"),
            ("d", "Disconnect focused tunnel / Cancel / Force Kill"),
            ("D", "Disconnect ALL active tunnels (when N>1)"),
            ("r", "Reconnect"),
            ("u", "Revert auto-promote (when banner is showing)"),
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
        "Security Guard sigils",
        &[
            ("✓", "OK — check passes"),
            ("✗", "Alarm — leak or unprotected"),
            ("⚠", "Warning — action recommended"),
            ("─", "Not enforced on this platform"),
        ],
    ),
    (
        "Connection Details: Role labels",
        &[
            ("Primary", "This tunnel is your active exit — internet traffic flows through it"),
            ("Primary (10.0.0.0/8)", "Primary; only the listed subnet routes through it"),
            ("Primary (multi)", "Primary; routes multiple declared subnets"),
            ("Split tunnel", "Connected but not your exit — only carries the routes it declared"),
            ("Split tunnel (10.0.0.0/8)", "Same; the listed subnet is the only thing it routes"),
            ("Split tunnel (multi)", "Same; routes multiple declared subnets"),
            ("Split tunnel (yielded)", "Wanted to be exit (declared 0.0.0.0/0) but another tunnel won the race"),
            ("Split tunnel (multi, yielded)", "Same; declared multiple subnets including 0/0, another tunnel is exit"),
            ("(external)", "External tunnel that vortix can't reliably attribute — won't be elected exit"),
            ("Full guide", "docs/roles.md"),
        ],
    ),
];

#[must_use]
pub fn total_lines() -> u16 {
    #[allow(clippy::cast_possible_truncation)]
    {
        HELP_TEXT
            .iter()
            .enumerate()
            .map(|(section_idx, (_, bindings))| bindings.len() + 2 + usize::from(section_idx > 0))
            .sum::<usize>() as u16
    }
}

pub fn render(frame: &mut Frame, scroll: u16) {
    let area = frame.area();
    let width = area.width.saturating_sub(4).min(65);
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

    debug_assert_eq!(u16::try_from(lines.len()), Ok(total_lines()));

    let max_scroll = state::help_max_scroll_for_terminal_height(area.height, total_lines());
    let clamped_scroll = scroll.min(max_scroll);

    let can_scroll_down = clamped_scroll < max_scroll;
    let can_scroll_up = clamped_scroll > 0;
    let scroll_hint = match (can_scroll_up, can_scroll_down) {
        (true, true) => " ↑↓ scroll · ? close ",
        (false, true) => " ↓ scroll · ? close ",
        (true, false) => " ↑ scroll · ? close ",
        (false, false) => " ? or Esc to close ",
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::ACCENT_PRIMARY))
        .title(Span::styled(
            " Keybindings ",
            Style::default()
                .fg(theme::ACCENT_PRIMARY)
                .add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            scroll_hint,
            Style::default().fg(theme::KEY_HINT_DESC),
        ));

    let inner = block.inner(overlay);
    frame.render_widget(block, overlay);

    let paragraph = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((clamped_scroll, 0));
    frame.render_widget(paragraph, inner);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Flatten the help text into one big string so we can grep it.
    fn flatten() -> String {
        let mut out = String::new();
        for (section, bindings) in HELP_TEXT {
            out.push_str(section);
            out.push('\n');
            for (key, desc) in *bindings {
                out.push_str(key);
                out.push(' ');
                out.push_str(desc);
                out.push('\n');
            }
        }
        out
    }

    #[test]
    fn multi_tunnel_keys_are_documented() {
        // Regression: every multi-tunnel keybinding must be
        // discoverable via `?`. Tab inside Connection Details was
        // removed (it hijacked panel navigation — Tab is sacred for
        // moving between panels). The help now points users at the
        // sidebar j/k for switching which tunnel's details are shown.
        let help = flatten();

        // `D` Shift+d for disconnect-all.
        assert!(
            help.contains("Disconnect ALL"),
            "help must document Shift+D disconnect-all:\n{help}"
        );

        // Connection Details should point users at the sidebar for
        // tunnel switching, since Tab is reserved for panel nav.
        assert!(
            help.contains("Details follows the selected profile"),
            "help must document that Connection Details follows sidebar selection:\n{help}"
        );

        // `c` in Connection Details for canceling in-flight connect.
        assert!(
            help.contains("Cancel in-flight connect"),
            "help must document c cancel-in-flight:\n{help}"
        );

        // `u` for reverting auto-promote.
        assert!(
            help.contains("Revert auto-promote"),
            "help must document u revert-auto-promote:\n{help}"
        );

        // Takeover overlay keys.
        assert!(
            help.contains("Switch — disconnect current"),
            "help must document Y/Enter takeover-switch path:\n{help}"
        );
        assert!(
            help.contains("Connect both"),
            "help must document B multi-connect path:\n{help}"
        );
    }

    #[test]
    fn role_glossary_section_is_present_and_covers_every_label() {
        // Users press `?` to remember what they're looking at. The
        // Role labels section MUST cover every label that
        // `connection_details::role_line` can emit, otherwise the
        // help is a lie and users have to ask in chat instead.
        let (_, bindings) = HELP_TEXT
            .iter()
            .find(|(title, _)| *title == "Connection Details: Role labels")
            .expect("Role labels section missing from help overlay");
        let labels: Vec<&str> = bindings.iter().map(|(k, _)| *k).collect();

        // Spot-check the labels that ce-brainstorm + the connection-
        // details render produce. The full set lives in
        // `connection_details::role_line` and `role_kind_label`.
        for expected in [
            "Primary",
            "Split tunnel",
            "Split tunnel (yielded)",
            "Split tunnel (multi, yielded)",
            "(external)",
        ] {
            assert!(
                labels.contains(&expected),
                "help overlay must document the `{expected}` label; found: {labels:?}"
            );
        }

        // And the link to the full guide must be in the section so
        // users curious for more detail know where to go.
        assert!(
            bindings
                .iter()
                .any(|(_, desc)| desc.contains("docs/roles.md")),
            "Role labels section must reference docs/roles.md for the verbose guide"
        );
    }

    #[test]
    fn total_lines_invariant_holds() {
        // The render path debug-asserts that the rendered line count
        // matches `total_lines()`. Recompute the expected count from
        // HELP_TEXT directly and verify the helper agrees — guards
        // against off-by-one drift when sections are added/removed.
        let expected: usize = HELP_TEXT
            .iter()
            .enumerate()
            .map(|(idx, (_, bindings))| {
                // Per-section: 1 header line + 1 blank below + N
                // binding lines. Between-section blank applies for
                // section_idx > 0.
                bindings.len() + 2 + usize::from(idx > 0)
            })
            .sum();
        assert_eq!(usize::from(total_lines()), expected);
    }
}
