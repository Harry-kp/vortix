//! Footer widget with context-aware keybinding hints

use crate::app::App;
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

/// Render dashboard footer with context-aware shortcuts
pub fn render_dashboard(frame: &mut Frame, app: &App, area: Rect) {
    // Config overlay takes priority
    if app.show_config {
        let hints = vec![
            ("↑↓", "Scroll"),
            ("g", "Top"),
            ("G", "End"),
            ("Esc", "Close"),
        ];
        render_hints(frame, area, &hints, None);
        return;
    }

    // Determine focused panel name for display
    let panel_name = match &app.focused_panel {
        crate::app::FocusedPanel::Sidebar => "Profiles",
        crate::app::FocusedPanel::ConnectionDetails => "Details",
        crate::app::FocusedPanel::Chart => "Chart",
        crate::app::FocusedPanel::Security => "Security",
        crate::app::FocusedPanel::Logs => "Logs",
    };

    // Build essential global hints
    let mut hints = Vec::new();

    // Only show 1-9 hint if there are profiles
    if !app.profiles.is_empty() {
        hints.push(("1-9", "Quick Connect"));
    }

    hints.extend_from_slice(&[
        ("i", "Import"),
        ("d", "Disconnect"),
        ("Tab", "Switch Panel"),
        ("K", "Kill Switch"),
        ("x", "Menu"),
        ("q", "Quit"),
    ]);

    render_hints(frame, area, &hints, Some(panel_name));
}

fn render_hints(frame: &mut Frame, area: Rect, hints: &[(&str, &str)], panel_name: Option<&str>) {
    use ratatui::layout::{Constraint, Layout};

    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Horizontal)
        .constraints([
            Constraint::Min(0),     // Hints (left)
            Constraint::Length(16), // Branding (right)
        ])
        .split(area);

    // 1. Render hints on the left with optional panel indicator
    let mut hint_spans = Vec::new();
    let mut current_width = 0;
    let max_width = chunks[0].width as usize;

    // Add panel indicator if provided
    if let Some(panel) = panel_name {
        let panel_indicator = format!("[{panel}] ");
        hint_spans.push(Span::styled(
            panel_indicator.clone(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));
        current_width += panel_indicator.len();
    } else {
        hint_spans.push(Span::raw(" "));
        current_width += 1;
    }

    for (i, (key, action)) in hints.iter().enumerate() {
        // Calculate item width: "key" + " " + "action" + " | " (separator)
        // Separator is 3 chars " | " for i > 0
        let sep_width = if i > 0 { 3 } else { 0 };
        let item_width = key.len() + 1 + action.len() + sep_width;

        if current_width + item_width > max_width {
            break;
        }

        if i > 0 {
            hint_spans.push(Span::styled(
                " │ ",
                Style::default().fg(Color::Rgb(50, 50, 50)),
            ));
        }
        hint_spans.push(Span::styled(
            *key,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));
        hint_spans.push(Span::raw(" "));
        hint_spans.push(Span::styled(*action, Style::default().fg(Color::DarkGray)));

        current_width += item_width;
    }
    frame.render_widget(Paragraph::new(Line::from(hint_spans)), chunks[0]);

    // 2. Render branding on the right
    let branding = Line::from(vec![Span::styled(
        format!(
            "{} v{} ",
            crate::constants::APP_NAME,
            crate::constants::APP_VERSION
        ),
        Style::default().fg(crate::theme::NORD_POLAR_NIGHT_4),
    )]);
    frame.render_widget(
        Paragraph::new(branding).alignment(ratatui::layout::Alignment::Right),
        chunks[1],
    );
}
