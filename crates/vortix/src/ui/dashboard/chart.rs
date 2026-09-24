use crate::app::App;
use crate::tunnel::Connection;
use crate::ui::helpers;
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

/// Render the Network Throughput chart, scoped to the primary tunnel.
///
/// Stage B: session-transfer totals come from
/// the primary tunnel's snapshot. Rate history (`down/up_history`) stays
/// on `app.runtime` because it's measured from the host's network stats
/// rather than per-tunnel — secondary tunnels add to the same byte
/// counters per H7.
/// Current up/down rates and the session's cumulative transfer.
fn stats_line<'a>(app: &App, session_rx: &'a str, session_tx: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(" ▲ UP: ", Style::default().fg(theme::current().success)),
        Span::styled(
            format!("{:<10}", utils::format_bytes_speed(app.runtime.current_up)),
            Style::default().fg(theme::current().text_primary),
        ),
        Span::styled(
            " │ ",
            Style::default().fg(theme::current().nord_polar_night_4),
        ),
        Span::styled(
            " ▼ DOWN: ",
            Style::default().fg(theme::current().accent_primary),
        ),
        Span::styled(
            format!(
                "{:<10}",
                utils::format_bytes_speed(app.runtime.current_down)
            ),
            Style::default().fg(theme::current().text_primary),
        ),
        Span::styled(
            " │ ",
            Style::default().fg(theme::current().nord_polar_night_4),
        ),
        Span::styled(
            " Session: ",
            Style::default().fg(theme::current().text_secondary),
        ),
        Span::styled("↓", Style::default().fg(theme::current().nord_frost_3)),
        Span::styled(
            session_rx,
            Style::default().fg(theme::current().text_primary),
        ),
        Span::styled(" ↑", Style::default().fg(theme::current().success)),
        Span::styled(
            session_tx,
            Style::default().fg(theme::current().text_primary),
        ),
    ])
}

pub(super) fn render(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.should_draw_focus(&crate::app::FocusedPanel::Chart);
    let border_style = if is_focused {
        Style::default().fg(theme::current().border_focused)
    } else {
        Style::default().fg(theme::current().border_default)
    };

    if app.effective_flipped(&crate::app::FocusedPanel::Chart) {
        render_back(frame, app, area, border_style);
        return;
    }

    let max_down = app.runtime.down_history.iter().copied().fold(0.0, f64::max);
    let max_up = app.runtime.up_history.iter().copied().fold(0.0, f64::max);
    let peak = (max_down.max(max_up) * 1.2).max(500_000.0);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let scale = crate::utils::format_bytes_speed(peak as u64);
    let peak_label = format!(" Peak: {scale} ");

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(" Network Throughput ")
        .title(
            Line::from(Span::styled(
                peak_label,
                Style::default().fg(theme::current().nord_polar_night_4),
            ))
            .right_aligned(),
        )
        .title_bottom(
            Line::from(Span::styled(
                format!(" Scale: 0 – {scale} "),
                Style::default().fg(theme::current().key_hint_desc),
            ))
            .right_aligned(),
        );

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(inner);

    // Session totals derived from the primary tunnel's snapshot.
    let primary_snap = app
        .registry
        .primary()
        .and_then(|id| app.registry.snapshot(id));
    let (session_rx, session_tx) = match primary_snap.as_ref().map(|s| &s.state) {
        Some(Connection::Connected { details, .. }) => (
            helpers::nonempty_or(&details.transfer_rx, "0B").to_string(),
            helpers::nonempty_or(&details.transfer_tx, "0B").to_string(),
        ),
        _ => ("0B".to_string(), "0B".to_string()),
    };

    frame.render_widget(
        Paragraph::new(stats_line(app, &session_rx, &session_tx)).alignment(Alignment::Center),
        chunks[0],
    );

    let hist_len = app.runtime.down_history.len();
    #[allow(clippy::cast_precision_loss)]
    let x_max = constants::NETWORK_HISTORY_SIZE as f64;
    let canvas = Canvas::default()
        .block(Block::default())
        .background_color(theme::current().panel_bg)
        .x_bounds([0.0, x_max])
        .y_bounds([0.0, peak])
        .paint(|ctx| {
            // Down first so the up series wins wherever the two overlap.
            for (history, color) in [
                (&app.runtime.down_history, theme::current().accent_primary),
                (&app.runtime.up_history, theme::current().success),
            ] {
                #[allow(clippy::cast_precision_loss)]
                for i in 0..hist_len.saturating_sub(1) {
                    let (y1, y2) = (history[i], history[i + 1]);
                    if y1 > 0.0 || y2 > 0.0 {
                        ctx.draw(&CanvasLine {
                            x1: i as f64,
                            y1,
                            x2: (i + 1) as f64,
                            y2,
                            color,
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
                Style::default().fg(theme::current().key_hint_desc),
            ))
            .right_aligned(),
        );

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let current_down_str = utils::format_bytes_speed(app.runtime.current_down);
    let current_up_str = utils::format_bytes_speed(app.runtime.current_up);

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            "Per-Process Network Usage",
            Style::default()
                .fg(theme::current().accent_primary)
                .add_modifier(ratatui::style::Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  Total ▼ ",
                Style::default().fg(theme::current().accent_primary),
            ),
            Span::styled(
                &current_down_str,
                Style::default().fg(theme::current().text_primary),
            ),
            Span::styled("  ▲ ", Style::default().fg(theme::current().success)),
            Span::styled(
                &current_up_str,
                Style::default().fg(theme::current().text_primary),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Process table with sorting & filtering",
            Style::default().fg(theme::current().text_secondary),
        )),
        Line::from(Span::styled(
            "  will be available in a future release.",
            Style::default().fg(theme::current().text_secondary),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  See: github.com/Harry-kp/vortix/issues/166",
            Style::default().fg(theme::current().nord_polar_night_4),
        )),
    ];

    frame.render_widget(Paragraph::new(text).alignment(Alignment::Left), inner);
}
