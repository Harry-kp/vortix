use crate::{constants, theme};
use ratatui::{
    layout::{Alignment, Constraint, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

pub fn render(frame: &mut Frame, path: &str, cursor: usize) {
    let area = frame.area();
    let popup_layout = Layout::vertical([
        Constraint::Percentage(30),
        Constraint::Percentage(40),
        Constraint::Percentage(30),
    ])
    .split(area);

    let popup_area = Layout::horizontal([
        Constraint::Percentage(15),
        Constraint::Percentage(70),
        Constraint::Percentage(15),
    ])
    .split(popup_layout[1])[1];

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::ACCENT_PRIMARY))
        .title(constants::TITLE_IMPORT_PROFILE)
        .title_bottom(Line::from(constants::TITLE_IMPORT_FOOTER).centered());

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let before = path.chars().take(cursor).collect::<String>();
    let cursor_char = path
        .chars()
        .nth(cursor)
        .map_or_else(|| "█".to_string(), |c| c.to_string());
    let after = path.chars().skip(cursor + 1).collect::<String>();

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            constants::PROMPT_IMPORT_PATH,
            Style::default().fg(theme::TEXT_PRIMARY),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" > ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(before, Style::default().fg(theme::TEXT_PRIMARY)),
            Span::styled(
                cursor_char,
                Style::default()
                    .fg(theme::ACCENT_SECONDARY)
                    .add_modifier(Modifier::REVERSED)
                    .add_modifier(Modifier::SLOW_BLINK),
            ),
            Span::styled(after, Style::default().fg(theme::TEXT_PRIMARY)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            constants::HINT_IMPORT_BULK,
            Style::default().fg(theme::ACCENT_SECONDARY),
        )),
        Line::from(""),
        Line::from(Span::styled(
            constants::LABEL_SUPPORTED_FORMATS,
            Style::default().fg(theme::TEXT_SECONDARY),
        )),
        Line::from(vec![
            Span::styled(
                format!("  {}", constants::EXT_CONF),
                Style::default().fg(theme::NORD_PURPLE),
            ),
            Span::styled(
                format!(" → {}", constants::PROTO_WIREGUARD),
                Style::default().fg(theme::TEXT_SECONDARY),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                format!("  {}", constants::EXT_OVPN),
                Style::default().fg(theme::WARNING),
            ),
            Span::styled(
                format!(" → {}", constants::PROTO_OPENVPN),
                Style::default().fg(theme::TEXT_SECONDARY),
            ),
        ]),
    ];

    frame.render_widget(Paragraph::new(text).alignment(Alignment::Left), inner);
}
