//! Toast notification overlay

use crate::app::App;
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

/// Render toast notification (anchored to top-right corner)
pub fn render(frame: &mut Frame, app: &App) {
    if let Some(ref toast) = app.toast {
        let area = frame.area();
        let width = (area.width / 3)
            .clamp(28, 50)
            .min(area.width.saturating_sub(2));

        let inner_width = width.saturating_sub(4) as usize;
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

        let height = (text_lines + 4).max(5);

        let toast_area = Rect {
            x: area.width.saturating_sub(width + 1),
            y: 1,
            width,
            height,
        };

        frame.render_widget(Clear, toast_area);

        let t = crate::theme::current();
        let (title, bg_color, border_color) = match toast.toast_type {
            crate::state::ToastType::Info => (" INFO ", t.toast_info, t.toast_info),
            crate::state::ToastType::Success => (" SUCCESS ", t.toast_success, t.toast_success),
            crate::state::ToastType::Warning => (" WARNING ", t.toast_warning, t.toast_warning),
            crate::state::ToastType::Error => (" ERROR ", t.toast_error, t.toast_error),
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(Span::styled(
                title,
                Style::default()
                    .fg(Color::Black)
                    .bg(bg_color)
                    .add_modifier(Modifier::BOLD),
            ))
            .title_bottom(Span::styled(
                " Esc dismiss ",
                Style::default().fg(Color::DarkGray),
            ));

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
