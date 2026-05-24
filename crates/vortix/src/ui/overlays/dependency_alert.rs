use crate::app::Protocol;
use ratatui::{
    layout::{Alignment, Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

pub fn render(frame: &mut Frame, protocol: Protocol, missing: &[String]) {
    let area = frame.area();
    let popup_layout = Layout::vertical([
        Constraint::Percentage(25),
        Constraint::Percentage(50),
        Constraint::Percentage(25),
    ])
    .split(area);

    let popup_area = Layout::horizontal([
        Constraint::Percentage(25),
        Constraint::Percentage(50),
        Constraint::Percentage(25),
    ])
    .split(popup_layout[1])[1];

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red))
        .title(" System Dependency Missing ");

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let mut text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " ERROR: ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "Missing system tools required for {protocol} sessions."
            )),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw(" Missing: "),
            Span::styled(missing.join(", "), Style::default().fg(Color::Yellow)),
        ]),
        Line::from(""),
        Line::from(vec![Span::raw(
            " To fix this, please run the following in your terminal:",
        )]),
    ];

    // Show install hints per missing tool
    for tool in missing {
        let hint = crate::platform::install_hint(tool);
        for hint_line in hint.lines() {
            text.push(Line::from(vec![Span::styled(
                format!(" {hint_line}"),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )]));
        }
    }

    text.push(Line::from(""));
    text.push(Line::from(vec![
        Span::raw(" Press "),
        Span::styled(
            "[Esc]",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" to return to dashboard."),
    ]));

    // Compute content height dynamically — cap to available space.
    let content_height = u16::try_from(text.len())
        .unwrap_or(u16::MAX)
        .min(inner.height);
    let chunks = Layout::vertical([
        Constraint::Min(0),
        Constraint::Length(content_height),
        Constraint::Min(0),
    ])
    .split(inner);

    frame.render_widget(Paragraph::new(text).alignment(Alignment::Center), chunks[1]);
}
