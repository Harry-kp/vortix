use crate::app::{App, ConnectionState};
use crate::{constants, theme, utils};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{
        canvas::{Canvas, Line as CanvasLine},
        Block, Borders, Paragraph,
    },
    Frame,
};

#[allow(clippy::too_many_lines)]
pub(super) fn render(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.should_draw_focus(&crate::app::FocusedPanel::Chart);
    let border_style = if is_focused {
        Style::default().fg(theme::BORDER_FOCUSED)
    } else {
        Style::default().fg(theme::BORDER_DEFAULT)
    };

    if app.effective_flipped(&crate::app::FocusedPanel::Chart) {
        render_back(frame, app, area, border_style);
        return;
    }

    // Peak detection for dynamic Y-axis scaling (calculate first for title)
    let max_down = app.down_history.iter().copied().fold(0.0, f64::max);
    let max_up = app.up_history.iter().copied().fold(0.0, f64::max);
    let peak = (max_down.max(max_up) * 1.2).max(1024.0 * 1024.0 * 0.5);
    let (scale_val, scale_unit) = if peak >= 1024.0 * 1024.0 * 1024.0 {
        (peak / 1024.0 / 1024.0 / 1024.0, "GB/s")
    } else if peak >= 1024.0 * 1024.0 {
        (peak / 1024.0 / 1024.0, "MB/s")
    } else {
        (peak / 1024.0, "KB/s")
    };
    let peak_label = format!(" Peak: {scale_val:.1} {scale_unit} ");

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(" Network Throughput ")
        .title(
            Line::from(Span::styled(
                peak_label,
                Style::default().fg(theme::NORD_POLAR_NIGHT_4),
            ))
            .right_aligned(),
        )
        .title_bottom(
            Line::from(Span::styled(
                format!(" Scale: 0 – {scale_val:.1} {scale_unit} "),
                Style::default().fg(theme::KEY_HINT_DESC),
            ))
            .right_aligned(),
        );

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Layout: Stats+Legend (Top) | Chart (Bottom)
    let chunks = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(inner);

    // Calculate session totals from connection details if available
    let (session_rx, session_tx) = match &app.connection_state {
        ConnectionState::Connected { details, .. } => {
            let rx = if details.transfer_rx.is_empty() {
                "0B".to_string()
            } else {
                details.transfer_rx.clone()
            };
            let tx = if details.transfer_tx.is_empty() {
                "0B".to_string()
            } else {
                details.transfer_tx.clone()
            };
            (rx, tx)
        }
        _ => ("0B".to_string(), "0B".to_string()),
    };

    let stats_line = Line::from(vec![
        Span::styled(" ▲ UP: ", Style::default().fg(theme::NORD_GREEN)),
        Span::styled(
            format!("{:<10}", utils::format_bytes_speed(app.current_up)),
            Style::default().fg(theme::TEXT_PRIMARY),
        ),
        Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
        Span::styled(" ▼ DOWN: ", Style::default().fg(theme::NORD_FROST_2)),
        Span::styled(
            format!("{:<10}", utils::format_bytes_speed(app.current_down)),
            Style::default().fg(theme::TEXT_PRIMARY),
        ),
        Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
        Span::styled(" Session: ", Style::default().fg(theme::TEXT_SECONDARY)),
        Span::styled("↓", Style::default().fg(theme::NORD_FROST_3)),
        Span::styled(&session_rx, Style::default().fg(theme::TEXT_PRIMARY)),
        Span::styled(" ↑", Style::default().fg(theme::NORD_GREEN)),
        Span::styled(&session_tx, Style::default().fg(theme::TEXT_PRIMARY)),
    ]);
    frame.render_widget(
        Paragraph::new(stats_line).alignment(Alignment::Center),
        chunks[0],
    );

    let hist_len = app.down_history.len();
    #[allow(clippy::cast_precision_loss)]
    let x_max = constants::NETWORK_HISTORY_SIZE as f64;
    let canvas = Canvas::default()
        .block(Block::default())
        .x_bounds([0.0, x_max])
        .y_bounds([0.0, peak])
        .paint(|ctx| {
            if hist_len > 1 {
                #[allow(clippy::cast_precision_loss)]
                for i in 0..hist_len - 1 {
                    let x1 = i as f64;
                    let x2 = (i + 1) as f64;

                    let dy1 = app.down_history[i];
                    let dy2 = app.down_history[i + 1];
                    if dy1 > 0.0 || dy2 > 0.0 {
                        ctx.draw(&CanvasLine {
                            x1,
                            y1: dy1,
                            x2,
                            y2: dy2,
                            color: theme::ACCENT_PRIMARY,
                        });
                    }

                    let uy1 = app.up_history[i];
                    let uy2 = app.up_history[i + 1];
                    if uy1 > 0.0 || uy2 > 0.0 {
                        ctx.draw(&CanvasLine {
                            x1,
                            y1: uy1,
                            x2,
                            y2: uy2,
                            color: theme::SUCCESS,
                        });
                    }
                }
            }
        });
    frame.render_widget(canvas, chunks[1]);
}

fn render_back(frame: &mut Frame, app: &App, area: Rect, border_style: Style) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(constants::TITLE_FLIP_NETWORK_ACTIVITY)
        .title_bottom(
            Line::from(Span::styled(
                constants::FLIP_BACK_HINT,
                Style::default().fg(theme::KEY_HINT_DESC),
            ))
            .right_aligned(),
        );

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let current_down_str = utils::format_bytes_speed(app.current_down);
    let current_up_str = utils::format_bytes_speed(app.current_up);

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            "Per-Process Network Usage",
            Style::default()
                .fg(theme::ACCENT_PRIMARY)
                .add_modifier(ratatui::style::Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Total ▼ ", Style::default().fg(theme::NORD_FROST_2)),
            Span::styled(&current_down_str, Style::default().fg(theme::TEXT_PRIMARY)),
            Span::styled("  ▲ ", Style::default().fg(theme::NORD_GREEN)),
            Span::styled(&current_up_str, Style::default().fg(theme::TEXT_PRIMARY)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Process table with sorting & filtering",
            Style::default().fg(theme::TEXT_SECONDARY),
        )),
        Line::from(Span::styled(
            "  will be available in a future release.",
            Style::default().fg(theme::TEXT_SECONDARY),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  See: github.com/Harry-kp/vortix/issues/166",
            Style::default().fg(theme::NORD_POLAR_NIGHT_4),
        )),
    ];

    frame.render_widget(Paragraph::new(text).alignment(Alignment::Left), inner);
}
