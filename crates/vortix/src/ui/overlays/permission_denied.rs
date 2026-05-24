use crate::constants;
use ratatui::{
    layout::{Alignment, Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

pub fn render(frame: &mut Frame, action: &str) {
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
        .title(" Elevated Privileges Required ");

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let chunks = Layout::vertical([
        Constraint::Min(0),
        Constraint::Length(8),
        Constraint::Min(0),
    ])
    .split(inner);

    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " ACCESS DENIED: ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "{} needs root privileges to {action}.",
                constants::APP_NAME
            )),
        ]),
        Line::from(""),
        Line::from(vec![Span::raw(
            " VPN management involves modifying network interfaces and routes,",
        )]),
        Line::from(vec![Span::raw(" which is a privileged system operation.")]),
        Line::from(""),
        Line::from(vec![
            Span::raw(format!(
                " Recommendation: Restart {} with ",
                constants::APP_NAME
            )),
            Span::styled(
                format!("sudo {}", constants::APP_NAME),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw(" Press "),
            Span::styled(
                "[Esc]",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" to return to dashboard."),
        ]),
    ];

    frame.render_widget(Paragraph::new(text).alignment(Alignment::Center), chunks[1]);
}
