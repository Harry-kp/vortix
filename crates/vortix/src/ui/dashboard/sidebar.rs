use crate::app::{App, ConnectionState};
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

#[allow(clippy::too_many_lines)]
pub(super) fn render(frame: &mut Frame, app: &mut App, area: Rect) {
    let is_focused = app.should_draw_focus(&crate::app::FocusedPanel::Sidebar);
    let border_style = if is_focused {
        Style::default().fg(theme::BORDER_FOCUSED)
    } else {
        Style::default().fg(theme::BORDER_DEFAULT)
    };

    let sort_label = app.sort_order.label();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(format!(" Profiles [{sort_label}] "));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.profiles.is_empty() {
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

    let (active_profile, active_color) = match &app.connection_state {
        ConnectionState::Connected { profile, .. } => (Some(profile.clone()), theme::SUCCESS),
        ConnectionState::Connecting { profile, .. }
        | ConnectionState::Disconnecting { profile, .. } => (Some(profile.clone()), theme::WARNING),
        ConnectionState::Disconnected => (None, Color::Reset),
    };

    let fixed_cols: u16 = 2 + 4 + 10 + 3; // status + proto + time + gaps
    let name_budget = (inner.width.saturating_sub(fixed_cols)) as usize;

    let items: Vec<Row> = app
        .profiles
        .iter()
        .enumerate()
        .map(|(idx, p)| {
            let is_selected = app.profile_list_state.selected() == Some(idx);
            let is_active = active_profile.as_ref() == Some(&p.name);
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
            let state_badge = if is_active {
                match &app.connection_state {
                    ConnectionState::Connected { .. } => " ✓",
                    ConnectionState::Connecting { .. } => " …",
                    ConnectionState::Disconnecting { .. } => " ⏻",
                    ConnectionState::Disconnected => "",
                }
            } else {
                ""
            };
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

    let mut scrollbar_state =
        ScrollbarState::new(app.profiles.len().saturating_sub(inner.height as usize))
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
