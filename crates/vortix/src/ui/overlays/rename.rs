use crate::theme;
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

pub fn render(frame: &mut Frame, name: &str, cursor: usize) {
    let area = frame.area();
    let width = 45u16.min(area.width.saturating_sub(4));
    let height = 5u16;
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
            " Rename Profile ",
            Style::default()
                .fg(theme::ACCENT_PRIMARY)
                .add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " Enter confirm │ Esc cancel ",
            Style::default().fg(ratatui::style::Color::DarkGray),
        ));

    let inner = block.inner(overlay);
    frame.render_widget(block, overlay);

    let before: String = name.chars().take(cursor).collect();
    let cursor_char: String = name
        .chars()
        .nth(cursor)
        .map_or_else(|| "\u{2588}".to_string(), |c| c.to_string());
    let after: String = name.chars().skip(cursor + 1).collect();

    let mut spans = vec![
        Span::styled("> ", Style::default().fg(theme::ACCENT_PRIMARY)),
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

    frame.render_widget(
        Paragraph::new(Line::from(spans)).alignment(ratatui::layout::Alignment::Left),
        inner,
    );
}
