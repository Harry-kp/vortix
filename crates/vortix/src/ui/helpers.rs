use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::{
    style::Style,
    widgets::{Block, Clear},
    Frame,
};
use unicode_width::UnicodeWidthChar;

/// Clear an area and repaint the active theme's owned surface.
pub(crate) fn clear_area(frame: &mut Frame, area: Rect) {
    frame.render_widget(Clear, area);
    frame.render_widget(
        Block::default().style(
            Style::default()
                .fg(crate::theme::current().text_primary)
                .bg(crate::theme::current().panel_bg),
        ),
        area,
    );
}

/// Center a rectangle sized as a percentage of the parent area.
pub(crate) fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::vertical([Constraint::Percentage(percent_y)]).flex(Flex::Center);
    let horizontal = Layout::horizontal([Constraint::Percentage(percent_x)]).flex(Flex::Center);

    let [area] = vertical.areas(area);
    let [area] = horizontal.areas(area);
    area
}

/// Center a rectangle with fixed pixel dimensions.
pub(crate) fn centered_rect_fixed(width: u16, height: u16, area: Rect) -> Rect {
    let vertical = Layout::vertical([Constraint::Length(height)]).flex(Flex::Center);
    let horizontal = Layout::horizontal([Constraint::Length(width)]).flex(Flex::Center);

    let [area] = vertical.areas(area);
    let [area] = horizontal.areas(area);
    area
}

/// Truncate text to a terminal-column budget, including the ellipsis.
pub(crate) fn truncate_to_width(text: &str, max_width: usize) -> String {
    let sanitized: String = text
        .chars()
        .map(|character| {
            if character.is_control() {
                '\u{FFFD}'
            } else {
                character
            }
        })
        .collect();
    let sanitized_width = sanitized
        .chars()
        .map(|character| character.width().unwrap_or(1))
        .sum::<usize>();

    if sanitized_width <= max_width {
        return sanitized;
    }
    if max_width <= 3 {
        return ".".repeat(max_width);
    }

    let content_width = max_width - 3;
    let mut width = 0;
    let mut truncated = String::new();
    for character in sanitized.chars() {
        let character_width = character.width().unwrap_or(1);
        if width + character_width > content_width {
            break;
        }
        truncated.push(character);
        width += character_width;
    }
    truncated.push_str("...");
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};
    use unicode_width::UnicodeWidthStr;

    #[test]
    fn centered_rect_fixed_centers_within_area() {
        let area = Rect::new(0, 0, 100, 50);
        let r = centered_rect_fixed(20, 10, area);
        assert_eq!(r.width, 20);
        assert_eq!(r.height, 10);
        assert_eq!(r.x, 40); // (100 - 20) / 2
        assert_eq!(r.y, 20); // (50 - 10) / 2
    }

    #[test]
    fn centered_rect_fixed_clamps_to_area() {
        let area = Rect::new(0, 0, 10, 10);
        let r = centered_rect_fixed(30, 30, area);
        assert!(r.width <= area.width);
        assert!(r.height <= area.height);
    }

    #[test]
    fn centered_rect_percentage_scales() {
        let area = Rect::new(0, 0, 100, 100);
        let r = centered_rect(50, 50, area);
        assert_eq!(r.width, 50);
        assert_eq!(r.height, 50);
    }

    #[test]
    fn truncates_wide_text_to_terminal_column_budget() {
        let truncated = truncate_to_width("office-世界-network", 12);
        assert!(truncated.width() <= 12);
        assert!(truncated.ends_with("..."));
    }

    #[test]
    fn truncation_sanitizes_terminal_controls_even_when_text_fits() {
        assert_eq!(
            truncate_to_width("profile\u{1b}[31m\n", 32),
            "profile�[31m�"
        );
    }

    #[test]
    fn sanitized_controls_consume_terminal_width_when_truncated() {
        let truncated = truncate_to_width("\u{1b}abcdef", 5);
        assert_eq!(truncated, "�a...");
        assert_eq!(truncated.width(), 5);
    }

    #[test]
    fn clear_area_paints_each_fixed_palette_and_leaves_terminal_adaptive() {
        for choice in [
            crate::theme::ThemeChoice::Synthwave,
            crate::theme::ThemeChoice::Terminal,
            crate::theme::ThemeChoice::CatppuccinMocha,
            crate::theme::ThemeChoice::Dracula,
            crate::theme::ThemeChoice::Nord,
            crate::theme::ThemeChoice::GruvboxDark,
            crate::theme::ThemeChoice::TokyoNight,
        ] {
            let mut terminal = Terminal::new(TestBackend::new(2, 1)).unwrap();
            crate::theme::with_choice(choice, || {
                terminal
                    .draw(|frame| clear_area(frame, frame.area()))
                    .unwrap();
            });
            let cell = &terminal.backend().buffer()[(0, 0)];
            assert_eq!(cell.bg, choice.palette().panel_bg, "{choice:?}");
            assert_eq!(cell.fg, choice.palette().text_primary, "{choice:?}");
        }
    }
}
