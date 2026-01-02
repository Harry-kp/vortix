//! Footer widget with keybinding hints

use crate::app::{App, ConnectionState};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

/// Render dashboard footer
pub fn render_dashboard(frame: &mut Frame, app: &App, area: Rect) {
    let mut hints = vec![
        ("Enter", "Connect"),
        ("d", "Disconnect"),
        ("1-5", "Quick"),
        ("Tab", "Switch Panel"),
        ("i", "Import"),
        ("?", "Help"),
        ("q", "Quit"),
    ];

    // Dynamic adjustments
    if matches!(app.connection_state, ConnectionState::Connecting { .. }) {
        hints = vec![("Esc", "Cancel Connection")];
    } else if matches!(app.connection_state, ConnectionState::Connected { .. }) {
        // Change "Connect" to "Toggle" or similar if we want, but "Enter = Connect" is standard
        // "d" is already there.
        // We might want to clarify Enter navigates or toggles.
        hints[0] = ("Enter", "Toggle/Switch");
    }

    render_hints(frame, area, &hints);
}

fn render_hints(frame: &mut Frame, area: Rect, hints: &[(&str, &str)]) {
    let mut spans = Vec::new();
    spans.push(Span::raw(" "));

    for (i, (key, action)) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("  ", Style::default().fg(Color::DarkGray)));
        }
        spans.push(Span::styled(
            "[",
            Style::default().fg(Color::Rgb(60, 60, 60)),
        ));
        spans.push(Span::styled(
            *key,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            "]",
            Style::default().fg(Color::Rgb(60, 60, 60)),
        ));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(*action, Style::default().fg(Color::DarkGray)));
    }

    let line = Line::from(spans);
    let area_width = area.width as usize;
    let line_width = line.width();

    frame.render_widget(Paragraph::new(line), area);

    // Subtle version at the end
    let version = "v0.1.0-alpha · vortix.io ".to_string();
    if area_width > line_width + version.len() + 2 {
        #[allow(clippy::cast_possible_truncation)]
        let version_area = Rect::new(
            area.x + area.width - version.len() as u16,
            area.y,
            version.len() as u16,
            1,
        );
        frame.render_widget(
            Paragraph::new(Span::styled(
                version,
                Style::default().fg(Color::Rgb(60, 60, 60)),
            )),
            version_area,
        );
    }
}
