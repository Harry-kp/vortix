use crate::app::App;
use crate::theme;
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

pub fn render(frame: &mut Frame, app: &App, query: &str, cursor: usize, total: usize) {
    let area = frame.area();
    let bar_area = Rect {
        x: 1,
        y: area.height.saturating_sub(3),
        width: area.width.saturating_sub(2).min(60),
        height: 3,
    };

    frame.render_widget(Clear, bar_area);

    let match_count = app.search_match_count;

    let count_text = if query.is_empty() {
        format!("{total} profiles")
    } else if match_count == 0 {
        "no matches".to_string()
    } else {
        format!("{match_count} of {total}")
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::ACCENT_PRIMARY))
        .title(Span::styled(
            " Search ",
            Style::default()
                .fg(theme::ACCENT_PRIMARY)
                .add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Line::from(Span::styled(
            format!(" {count_text} "),
            Style::default().fg(Color::DarkGray),
        )));

    let inner = block.inner(bar_area);
    frame.render_widget(block, bar_area);

    let before: String = query.chars().take(cursor).collect();
    let cursor_char: String = query
        .chars()
        .nth(cursor)
        .map_or_else(|| "\u{2588}".to_string(), |c| c.to_string());
    let after: String = query.chars().skip(cursor + 1).collect();

    let mut spans = vec![
        Span::styled("/", Style::default().fg(theme::ACCENT_PRIMARY)),
        Span::styled(before, Style::default().fg(theme::TEXT_PRIMARY)),
        Span::styled(
            cursor_char,
            Style::default()
                .fg(theme::ACCENT_SECONDARY)
                .add_modifier(Modifier::REVERSED)
                .add_modifier(Modifier::SLOW_BLINK),
        ),
    ];
    if !after.is_empty() {
        spans.push(Span::styled(
            after,
            Style::default().fg(theme::TEXT_PRIMARY),
        ));
    }

    if query.is_empty() {
        spans.push(Span::styled(
            "type to filter...",
            Style::default().fg(Color::DarkGray),
        ));
    }

    frame.render_widget(Paragraph::new(Line::from(spans)), inner);
}
