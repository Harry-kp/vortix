//! Help overlay

use crate::app::App;
use ratatui::{
    layout::{Constraint, Flex, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

/// Render help overlay
#[allow(clippy::too_many_lines)]
pub fn render(frame: &mut Frame, _app: &App) {
    let area = centered_rect(80, 80, frame.area());

    // Clear the background
    frame.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Vortix Information ");

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let key_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    let desc_style = Style::default().fg(Color::White);
    let header_style = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let subtle_style = Style::default().fg(Color::DarkGray);

    let lines = vec![
        Line::from(vec![
            Span::raw("  "),
            Span::styled(
                "VORTIX",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" - Professional VPN Manager "),
            Span::styled(format!("v{}", env!("CARGO_PKG_VERSION")), subtle_style),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("Documentation & Support: ", subtle_style),
            Span::styled(
                "https://vortix.io",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::UNDERLINED),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("GLOBAL CONTROLS", header_style),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("Tab", key_style),
            Span::raw("       "),
            Span::styled("Switch Focus (Sidebar/Logs)", desc_style),
            Span::raw("   "),
            Span::styled("?", key_style),
            Span::raw("         "),
            Span::styled("Toggle Help", desc_style),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("q", key_style),
            Span::raw("         "),
            Span::styled("Quit Application", desc_style),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("PROFILES SIDEBAR", header_style),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("j/k", key_style),
            Span::raw("       "),
            Span::styled("Navigate List", desc_style),
            Span::raw("          "),
            Span::raw("          "),
            Span::styled("c/Enter", key_style),
            Span::raw("     "),
            Span::styled("Connect/Toggle/Switch", desc_style),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("x", key_style),
            Span::raw("         "),
            Span::styled("Safe Delete", desc_style),
            Span::raw("         "),
            Span::styled("i", key_style),
            Span::raw("         "),
            Span::styled("Import .conf/.ovpn", desc_style),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("VPN CONNECTION", header_style),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("1-5", key_style),
            Span::raw("       "),
            Span::styled("Connect to Slot 1-5", desc_style),
            Span::raw("            "),
            Span::styled("d/r", key_style),
            Span::raw("       "),
            Span::styled("Disconnect/Reconnect", desc_style),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("ACTIVITY LOG", header_style),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("j/k", key_style),
            Span::raw("       "),
            Span::styled("Scroll Logs", desc_style),
            Span::raw("             "),
            Span::styled("t", key_style),
            Span::raw("         "),
            Span::styled("Run Leak Test", desc_style),
        ]),
        Line::from(""),
        Line::from(""),
        Line::from(Span::styled(
            "                      Press any key to close",
            subtle_style,
        )),
    ];

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, inner);
}

/// Create a centered rectangle
fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::vertical([Constraint::Percentage(percent_y)]).flex(Flex::Center);
    let horizontal = Layout::horizontal([Constraint::Percentage(percent_x)]).flex(Flex::Center);

    let [area] = vertical.areas(area);
    let [area] = horizontal.areas(area);
    area
}
