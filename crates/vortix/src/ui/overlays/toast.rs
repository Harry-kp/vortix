//! Toast notification overlay

use crate::app::App;
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};
use unicode_width::UnicodeWidthStr;

fn toast_geometry(area: Rect, message: &str) -> Option<(Rect, u16)> {
    if area.width < 6 || area.height < 5 {
        return None;
    }
    let width = (area.width / 3)
        .clamp(28, 50)
        .min(area.width.saturating_sub(2));
    let inner_width = usize::from(width.saturating_sub(4)).max(1);
    let estimated_lines = message.lines().fold(0usize, |total, line| {
        total.saturating_add(line.width().max(1).div_ceil(inner_width))
    });
    let estimated_lines = u16::try_from(estimated_lines).unwrap_or(u16::MAX).max(1);
    let height = estimated_lines
        .saturating_add(4)
        .max(5)
        .min(area.height.saturating_sub(2));
    let text_lines = estimated_lines.min(height.saturating_sub(2));
    Some((
        Rect {
            x: area.width.saturating_sub(width + 1),
            y: 1,
            width,
            height,
        },
        text_lines,
    ))
}

/// Render toast notification (anchored to top-right corner)
pub fn render(frame: &mut Frame, app: &App) {
    if let Some(ref toast) = app.toast {
        let area = frame.area();
        let Some((toast_area, text_lines)) = toast_geometry(area, &toast.message) else {
            return;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_toast_never_exceeds_the_terminal() {
        let area = Rect::new(0, 0, 80, 12);
        let (toast, text_lines) = toast_geometry(area, &"DNS failure ".repeat(80)).unwrap();
        assert!(toast.right() <= area.right());
        assert!(toast.bottom() <= area.bottom());
        assert!(text_lines <= toast.height.saturating_sub(2));
    }

    #[test]
    fn tiny_terminal_suppresses_an_unreadable_toast() {
        assert!(toast_geometry(Rect::new(0, 0, 5, 4), "error").is_none());
    }
}
