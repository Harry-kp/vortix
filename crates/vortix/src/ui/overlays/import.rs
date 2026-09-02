use crate::{constants, theme};
use ratatui::{
    layout::Alignment,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

fn display_character(character: char) -> char {
    if character.is_control() {
        '\u{fffd}'
    } else {
        character
    }
}

fn suffix_window(characters: &[char], budget: usize) -> String {
    let mut width = 0;
    let mut start = characters.len();
    for (index, character) in characters.iter().enumerate().rev() {
        let character_width = display_character(*character).width().unwrap_or(1);
        let ellipsis = usize::from(index > 0);
        if width + character_width + ellipsis > budget {
            break;
        }
        width += character_width;
        start = index;
    }
    let mut output = String::new();
    if start > 0 && budget > 0 {
        output.push('…');
    }
    output.extend(characters[start..].iter().copied().map(display_character));
    output
}

fn prefix_window(characters: &[char], budget: usize) -> String {
    let mut width = 0;
    let mut end = 0;
    for (index, character) in characters.iter().enumerate() {
        let character_width = display_character(*character).width().unwrap_or(1);
        let ellipsis = usize::from(index + 1 < characters.len());
        if width + character_width + ellipsis > budget {
            break;
        }
        width += character_width;
        end = index + 1;
    }
    let mut output = characters[..end]
        .iter()
        .copied()
        .map(display_character)
        .collect::<String>();
    if end < characters.len() && budget > 0 {
        output.push('…');
    }
    output
}

/// Window a long path around its insertion cursor so the cursor is always
/// visible without widening the compact import dialog.
fn visible_path(path: &str, cursor: usize, max_width: usize) -> (String, String, String) {
    let characters = path.chars().collect::<Vec<_>>();
    let cursor = cursor.min(characters.len());
    let cursor_character = characters
        .get(cursor)
        .copied()
        .map_or('█', display_character);
    let cursor_text = cursor_character.to_string();
    let remaining = max_width.saturating_sub(cursor_text.width());
    let (left_budget, right_budget) = if cursor == characters.len() {
        (remaining, 0)
    } else if cursor == 0 {
        (0, remaining)
    } else {
        (remaining.div_ceil(2), remaining / 2)
    };
    let after_start = cursor + usize::from(cursor < characters.len());
    (
        suffix_window(&characters[..cursor], left_budget),
        cursor_text,
        prefix_window(&characters[after_start..], right_budget),
    )
}

pub fn render(frame: &mut Frame, path: &str, cursor: usize) {
    let area = frame.area();
    let popup_area = crate::ui::helpers::centered_rect_fixed(
        58.min(area.width.saturating_sub(2)),
        12.min(area.height.saturating_sub(2)),
        area,
    );

    crate::ui::helpers::clear_area(frame, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::current().accent_primary))
        .title(constants::TITLE_IMPORT_PROFILE)
        .title_bottom(Line::from(constants::TITLE_IMPORT_FOOTER).centered());

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let (before, cursor_char, after) =
        visible_path(path, cursor, usize::from(inner.width.saturating_sub(3)));

    let text = vec![
        Line::from(Span::styled(
            constants::PROMPT_IMPORT_PATH,
            Style::default().fg(theme::current().text_primary),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" > ", Style::default().fg(theme::current().text_secondary)),
            Span::styled(before, Style::default().fg(theme::current().text_primary)),
            Span::styled(
                cursor_char,
                Style::default()
                    .fg(theme::current().accent_secondary)
                    .add_modifier(Modifier::REVERSED)
                    .add_modifier(Modifier::SLOW_BLINK),
            ),
            Span::styled(after, Style::default().fg(theme::current().text_primary)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Directory paths import every supported profile.",
            Style::default().fg(theme::current().accent_secondary),
        )),
        Line::from(Span::styled(
            constants::LABEL_SUPPORTED_FORMATS,
            Style::default().fg(theme::current().text_secondary),
        )),
        Line::from(vec![
            Span::styled(
                format!("  {}", constants::EXT_CONF),
                Style::default().fg(theme::current().nord_purple),
            ),
            Span::styled(
                format!(" → {}", constants::PROTO_WIREGUARD),
                Style::default().fg(theme::current().text_secondary),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                format!("  {}", constants::EXT_OVPN),
                Style::default().fg(theme::current().warning),
            ),
            Span::styled(
                format!(" → {}", constants::PROTO_OPENVPN),
                Style::default().fg(theme::current().text_secondary),
            ),
        ]),
    ];

    frame.render_widget(Paragraph::new(text).alignment(Alignment::Left), inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};

    #[test]
    fn supported_formats_remain_visible_at_minimum_terminal_size() {
        let mut terminal = Terminal::new(TestBackend::new(60, 20)).unwrap();
        terminal
            .draw(|frame| render(frame, "/tmp/profiles", 13))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let output = buffer
            .content
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<String>();
        assert!(output.contains(".conf"), "{output}");
        assert!(output.contains("WireGuard"), "{output}");
        assert!(output.contains(".ovpn"), "{output}");
        assert!(output.contains("OpenVPN"), "{output}");
    }

    #[test]
    fn long_path_keeps_the_cursor_visible_inside_the_fixed_dialog() {
        let path = "/Users/harshit/Library/Application Support/vortix/profiles/imports";
        let (before, cursor, after) = visible_path(path, path.chars().count(), 20);
        assert!(before.starts_with('…'), "{before}");
        assert_eq!(cursor, "█");
        assert!(after.is_empty());
        assert!(before.width() + cursor.width() <= 20);
    }

    #[test]
    fn path_window_sanitizes_control_characters_without_changing_cursor_position() {
        let (before, cursor, after) = visible_path("ab\u{1b}cd", 2, 20);
        assert_eq!(before, "ab");
        assert_eq!(cursor, "�");
        assert_eq!(after, "cd");
    }
}
