//! Action Menu overlay for context-sensitive actions.
//!
//! Provides a lazydocker-style popup menu triggered by 'x'.

use crate::message::ActionMenuItem;
use crate::theme;
use crate::ui::helpers::centered_rect_fixed;
use ratatui::{
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState},
    Frame,
};

/// Render the action menu overlay
#[allow(clippy::cast_possible_truncation)]
pub fn render(
    frame: &mut Frame,
    items: &[ActionMenuItem],
    list_state: &mut ListState,
    title: &str,
) {
    // Calculate menu dimensions based on content
    let max_label_len = items.iter().map(|i| i.label.len()).max().unwrap_or(20);
    let max_key_len = items.iter().map(|i| i.key.len()).max().unwrap_or(1);
    let menu_width = (max_key_len + max_label_len + 8).min(60) as u16; // key + padding + label
    let menu_height = (items.len().max(1) + 2).min(15) as u16; // items + borders

    let area = centered_rect_fixed(menu_width, menu_height, frame.area());

    // Clear background
    frame.render_widget(Clear, area);

    // Build the block
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER_FOCUSED))
        .title(format!(" {title} "));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Build list items
    let list_items: Vec<ListItem> = if items.is_empty() {
        vec![ListItem::new(Line::from(vec![Span::styled(
            " No actions available ",
            Style::default().fg(theme::NORD_POLAR_NIGHT_4),
        )]))]
    } else {
        items
            .iter()
            .map(|item| {
                let line = Line::from(vec![
                    Span::styled(
                        format!(" {} ", item.key),
                        Style::default()
                            .fg(theme::ACCENT_PRIMARY)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" "),
                    Span::styled(item.label, Style::default().fg(theme::TEXT_PRIMARY)),
                ]);
                ListItem::new(line)
            })
            .collect()
    };

    let list = List::new(list_items);

    if items.is_empty() {
        frame.render_widget(list, inner);
    } else {
        let list = list
            .highlight_style(
                Style::default()
                    .bg(theme::ROW_SELECTED_BG)
                    .fg(theme::ROW_SELECTED_FG)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");
        frame.render_stateful_widget(list, inner, list_state);
    }
}
