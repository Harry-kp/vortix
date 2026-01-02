//! Toast notification overlay

use crate::app::App;
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

/// Render toast notification
pub fn render(frame: &mut Frame, app: &App) {
    if let Some(ref toast) = app.toast {
        // Position at bottom center
        let area = frame.area();
        // Create a "big rectangle" - narrow width, more height
        let width = (area.width / 3).clamp(30, 60);

        // Calculate dynamic height based on text length + vertical padding
        let inner_width = width.saturating_sub(4) as usize; // More horizontal padding
        let text_len = toast.message.len();
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let text_lines = if inner_width > 0 {
            (text_len as f64 / inner_width as f64).ceil() as u16
        } else {
            1
        };

        // Ensure it's vertically longer (min height + padding)
        let height = (text_lines + 4).max(7); // +4 for padding, min 7 rows

        let toast_area = Rect {
            x: (area.width / 2).saturating_sub(width / 2), // True center X
            y: (area.height / 2).saturating_sub(height / 2), // True center Y
            width,
            height,
        };

        // Clear the background
        frame.render_widget(Clear, toast_area);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Rgb(136, 192, 208)))
            .title(Span::styled(
                " INFO ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Rgb(136, 192, 208))
                    .add_modifier(Modifier::BOLD),
            ));

        // Create a vertical layout inside the toast to center the text
        let inner_area = block.inner(toast_area);
        frame.render_widget(block, toast_area);

        let vertical_chunks = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(text_lines),
            Constraint::Fill(1),
        ])
        .split(inner_area);

        let paragraph = Paragraph::new(toast.message.clone())
            .wrap(ratatui::widgets::Wrap { trim: true })
            .alignment(Alignment::Center);

        frame.render_widget(paragraph, vertical_chunks[1]);
    }
}
