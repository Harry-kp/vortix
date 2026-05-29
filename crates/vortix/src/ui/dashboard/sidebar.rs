use crate::app::App;
use crate::vortix_core::engine::state::Connection;
use crate::vortix_core::engine::TunnelSnapshot;
use crate::{theme, utils};
use ratatui::{
    layout::{Alignment, Constraint, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
        Table,
    },
    Frame,
};

/// Active-tunnel marker derived from a registry snapshot for a given profile name.
///
/// Stage A of plan #001 U6 wires sidebar reads through `TunnelRegistry` for the
/// "who is active" derivation while leaving the row list itself on
/// `engine.profiles`. The mapping from `VpnProfile.name` to `ProfileId` is the
/// profile name — see `cleanup_vpn_resources` for the existing convention.
fn active_marker_for(snapshots: &[TunnelSnapshot], profile_name: &str) -> Option<(Color, &'static str)> {
    let snap = snapshots
        .iter()
        .find(|s| s.profile_id.as_str() == profile_name)?;
    let (color, badge) = match &snap.state {
        Connection::Connected { .. } => (theme::SUCCESS, " ✓"),
        Connection::Connecting { .. } => (theme::WARNING, " …"),
        Connection::Reconnecting { .. } => (theme::WARNING, " ↻"),
        Connection::Disconnecting { .. } => (theme::WARNING, " ⏻"),
        Connection::AwaitingUserInput { .. } => (theme::WARNING, " ?"),
        Connection::Disconnected { .. } => return None,
    };
    Some((color, badge))
}

#[allow(clippy::too_many_lines)]
pub(super) fn render(frame: &mut Frame, app: &mut App, area: Rect) {
    let is_focused = app.should_draw_focus(&crate::app::FocusedPanel::Sidebar);
    let border_style = if is_focused {
        Style::default().fg(theme::BORDER_FOCUSED)
    } else {
        Style::default().fg(theme::BORDER_DEFAULT)
    };

    let sort_label = app.engine.sort_order.label();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(format!(" Profiles [{sort_label}] "));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // U6 Stage A: snapshots come from the registry; profile catalog still on engine.
    let snapshots = app.registry.snapshot_all();
    let _primary = app.registry.primary(); // reserved for the primary marker in Stage B

    if app.engine.profiles.is_empty() && snapshots.is_empty() {
        let empty_msg = vec![
            Line::from(""),
            Line::from(Span::styled(
                "No profiles yet",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("Press ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    "[i]",
                    Style::default()
                        .fg(theme::ACCENT_PRIMARY)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" to import", Style::default().fg(Color::DarkGray)),
            ]),
        ];
        frame.render_widget(
            Paragraph::new(empty_msg).alignment(Alignment::Center),
            inner,
        );
        return;
    }

    let fixed_cols: u16 = 2 + 4 + 10 + 3; // status + proto + time + gaps
    let name_budget = (inner.width.saturating_sub(fixed_cols)) as usize;

    let items: Vec<Row> = app
        .engine
        .profiles
        .iter()
        .enumerate()
        .map(|(idx, p)| {
            let is_selected = app.profile_list_state.selected() == Some(idx);
            let marker = active_marker_for(&snapshots, &p.name);
            let is_active = marker.is_some();
            let active_color = marker.map_or(Color::Reset, |(c, _)| c);
            let active_badge = marker.map_or("", |(_, b)| b);
            let is_never_used = p.last_used.is_none();

            let (status_char, status_color) = if idx < 9 {
                (
                    format!("{}", idx + 1),
                    if is_active {
                        active_color
                    } else {
                        theme::TEXT_SECONDARY
                    },
                )
            } else if is_active {
                ("●".to_string(), active_color)
            } else {
                (" ".to_string(), Color::Reset)
            };

            let name_style = if is_selected && is_active {
                Style::default()
                    .fg(active_color)
                    .add_modifier(Modifier::BOLD)
            } else if is_selected {
                Style::default()
                    .fg(theme::ROW_SELECTED_FG)
                    .add_modifier(Modifier::BOLD)
            } else if is_active {
                Style::default().fg(active_color)
            } else if is_never_used {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default().fg(theme::INACTIVE)
            };

            let proto_icon = match p.protocol {
                crate::app::Protocol::WireGuard => "WG",
                crate::app::Protocol::OpenVPN => "OV",
            };
            let proto_color = if is_active {
                active_color
            } else if is_selected {
                theme::ACCENT_PRIMARY
            } else {
                theme::TEXT_SECONDARY
            };

            // Last used time
            let time_str = if let Some(last_used) = p.last_used {
                let relative = utils::format_relative_time(last_used);
                if !relative.ends_with("ago") && !relative.is_empty() {
                    format!("{relative} ago")
                } else {
                    relative
                }
            } else {
                "never".to_string()
            };

            let row_style = if is_selected {
                Style::default().bg(theme::ROW_SELECTED_BG)
            } else {
                Style::default()
            };

            // Create cells for each column
            let status_cell = Cell::from(Span::styled(
                status_char.clone(),
                Style::default().fg(status_color),
            ));
            let state_badge = if is_active { active_badge } else { "" };
            let badge_len = state_badge.chars().count();
            let display_name =
                utils::truncate(&p.name, name_budget.saturating_sub(badge_len).max(3));
            let name_cell = Cell::from(Line::from(vec![
                Span::styled(display_name, name_style),
                Span::styled(state_badge, Style::default().fg(active_color)),
            ]));
            let proto_cell = Cell::from(Span::styled(proto_icon, Style::default().fg(proto_color)));
            let time_cell =
                Cell::from(Span::styled(time_str, Style::default().fg(Color::DarkGray)));

            Row::new(vec![status_cell, name_cell, proto_cell, time_cell]).style(row_style)
        })
        .collect();

    let table = Table::new(
        items,
        [
            Constraint::Length(2),  // Status column (● or space)
            Constraint::Min(8),     // Profile name (flexible)
            Constraint::Length(4),  // Protocol (WG/OV)
            Constraint::Length(10), // Last used time
        ],
    );
    frame.render_stateful_widget(table, inner, &mut app.profile_list_state);

    // Scrollbar Logic
    let scrollbar = Scrollbar::default()
        .orientation(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("↑"))
        .end_symbol(Some("↓"))
        .style(Style::default().fg(theme::NORD_POLAR_NIGHT_4))
        .thumb_style(Style::default().fg(theme::ACCENT_PRIMARY));

    let mut scrollbar_state = ScrollbarState::new(
        app.engine
            .profiles
            .len()
            .saturating_sub(inner.height as usize),
    )
    .position(app.profile_list_state.selected().unwrap_or(0));

    frame.render_stateful_widget(
        scrollbar,
        area.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut scrollbar_state,
    );
}

#[cfg(test)]
mod tests {
    //! Stage A smoke tests for plan #001 U6. Verify the sidebar renders the
    //! "No profiles" empty state when both registry and engine profiles are
    //! empty, and that N profiles produce N rendered rows. Full registry-
    //! population tests land with Stage B once `App.engine` retires.
    use super::*;
    use crate::app::App;
    use crate::state::{Protocol, VpnProfile};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;

    fn make_profile(name: &str) -> VpnProfile {
        VpnProfile {
            name: name.to_string(),
            protocol: Protocol::WireGuard,
            location: String::new(),
            config_path: PathBuf::from(format!("/tmp/{name}.conf")),
            last_used: None,
        }
    }

    fn render_to_string(app: &mut App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| {
                let area = Rect::new(0, 0, width, height);
                render(frame, app, area);
            })
            .expect("draw");
        let buf = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn empty_registry_and_empty_profiles_renders_no_profiles_empty_state() {
        let mut app = App::new_test();
        // Sanity: both sides are empty.
        assert_eq!(app.registry.tunnel_count(), 0);
        assert!(app.engine.profiles.is_empty());

        let out = render_to_string(&mut app, 40, 10);
        assert!(
            out.contains("No profiles yet"),
            "expected empty-state copy, got:\n{out}"
        );
    }

    #[test]
    fn n_profiles_render_n_rows() {
        let mut app = App::new_test();
        app.engine.profiles = vec![
            make_profile("alpha"),
            make_profile("bravo"),
            make_profile("charlie"),
        ];

        let out = render_to_string(&mut app, 60, 10);
        // Empty-state must not appear when there are profiles in the catalog.
        assert!(
            !out.contains("No profiles yet"),
            "did not expect empty state, got:\n{out}"
        );
        // Each profile name should appear in the rendered output.
        assert!(out.contains("alpha"), "alpha row missing:\n{out}");
        assert!(out.contains("bravo"), "bravo row missing:\n{out}");
        assert!(out.contains("charlie"), "charlie row missing:\n{out}");
    }

    #[test]
    fn empty_registry_yields_no_active_marker_for_any_profile() {
        // Stage A invariant: when the registry has no entries, every profile
        // row is inactive — the engine's legacy `connection_state` is *not*
        // consulted by the sidebar anymore.
        let snapshots: Vec<TunnelSnapshot> = Vec::new();
        assert!(active_marker_for(&snapshots, "anything").is_none());
    }
}
