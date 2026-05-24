//! Reusable confirmation dialog overlay.

use crate::theme;
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

/// Everything that varies between confirmation dialogs.
pub struct ConfirmDialogConfig<'a> {
    pub title: &'a str,
    pub body: Vec<Line<'a>>,
    pub border_color: Color,
    pub confirm_selected: bool,
    pub width: u16,
    pub height: u16,
}

/// Render a centered confirmation dialog with [Y]es / [N]o buttons.
pub fn render(frame: &mut Frame, config: ConfirmDialogConfig) {
    let area = frame.area();
    let width = config.width.min(area.width.saturating_sub(4));
    let height = config.height.min(area.height.saturating_sub(2));
    let overlay = Rect {
        x: (area.width / 2).saturating_sub(width / 2),
        y: (area.height / 2).saturating_sub(height / 2),
        width,
        height,
    };

    frame.render_widget(Clear, overlay);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(config.border_color))
        .title(Span::styled(
            config.title,
            Style::default()
                .fg(config.border_color)
                .add_modifier(Modifier::BOLD),
        ));

    let inner = block.inner(overlay);
    frame.render_widget(block, overlay);

    let yes_style = if config.confirm_selected {
        Style::default()
            .fg(Color::Black)
            .bg(config.border_color)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme::TEXT_SECONDARY)
    };
    let no_style = if config.confirm_selected {
        Style::default().fg(theme::TEXT_SECONDARY)
    } else {
        Style::default()
            .fg(Color::Black)
            .bg(theme::ACCENT_PRIMARY)
            .add_modifier(Modifier::BOLD)
    };

    let yes_label = if config.confirm_selected {
        "▸ [Y]es "
    } else {
        "  [Y]es "
    };
    let no_label = if config.confirm_selected {
        "  [N]o "
    } else {
        "▸ [N]o "
    };

    let mut lines = config.body;
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("     ", Style::default()),
        Span::styled(yes_label, yes_style),
        Span::styled("  ", Style::default()),
        Span::styled(no_label, no_style),
    ]));

    frame.render_widget(Paragraph::new(lines), inner);
}
