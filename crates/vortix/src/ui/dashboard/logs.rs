use crate::app::App;
use crate::{constants, logger, theme, utils};
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap},
    Frame,
};

#[allow(clippy::too_many_lines)]
pub(super) fn render(frame: &mut Frame, app: &mut App, area: Rect) {
    let is_focused = app.should_draw_focus(&crate::app::FocusedPanel::Logs);
    let border_style = if is_focused {
        Style::default().fg(theme::BORDER_FOCUSED)
    } else {
        Style::default().fg(theme::BORDER_DEFAULT)
    };

    let filter_label = match app.log_level_filter {
        Some(logger::LogLevel::Error) => " Err",
        Some(logger::LogLevel::Warning) => " Warn+",
        Some(logger::LogLevel::Info) => " Info+",
        None | Some(_) => "",
    };

    let title = if app.logs_auto_scroll {
        format!(" Event Log [Live{filter_label}] ")
    } else {
        format!(" Event Log [Paused{filter_label}] ")
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(title);

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let raw_logs = logger::get_logs();
    let all_logs: Vec<_> = if let Some(min_level) = app.log_level_filter {
        raw_logs
            .into_iter()
            .filter(|e| e.level >= min_level)
            .collect()
    } else {
        raw_logs
    };

    if all_logs.is_empty() {
        frame.render_widget(
            Paragraph::new("No activity yet").alignment(Alignment::Center),
            inner,
        );
        return;
    }

    let visible_lines = inner.height as usize;

    let lines: Vec<Line> = all_logs
        .iter()
        .map(|entry| {
            let time_str = utils::format_system_time_local(entry.timestamp);
            let level_tag = entry.level.prefix();

            let cat = format!(
                "{:<width$}",
                entry.category,
                width = constants::LOG_CATEGORY_WIDTH
            );

            let level_style = match entry.level {
                logger::LogLevel::Error => Style::default().fg(theme::ERROR),
                logger::LogLevel::Warning => Style::default().fg(theme::WARNING),
                logger::LogLevel::Info => Style::default().fg(theme::NORD_FROST_3),
                logger::LogLevel::Debug => Style::default().fg(Color::DarkGray),
            };

            let msg_style = match entry.level {
                logger::LogLevel::Error => Style::default().fg(theme::ERROR),
                logger::LogLevel::Warning => Style::default().fg(theme::WARNING),
                logger::LogLevel::Info => {
                    if entry.message.contains("Connected") || entry.message.contains("secure") {
                        Style::default().fg(theme::SUCCESS)
                    } else {
                        Style::default().fg(theme::INACTIVE)
                    }
                }
                logger::LogLevel::Debug => Style::default().fg(Color::DarkGray),
            };

            Line::from(vec![
                Span::styled(
                    format!("[{time_str}] "),
                    Style::default().fg(theme::TEXT_SECONDARY),
                ),
                Span::styled(format!("{level_tag} "), level_style),
                Span::styled(
                    format!("{cat}  "),
                    Style::default().fg(theme::NORD_POLAR_NIGHT_4),
                ),
                Span::styled(entry.message.clone(), msg_style),
            ])
        })
        .collect();

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });

    let total_visual_lines = paragraph.line_count(inner.width);
    let max_scroll = total_visual_lines.saturating_sub(visible_lines);
    app.logs_max_scroll = u16::try_from(max_scroll).unwrap_or(u16::MAX);

    let scroll_pos = if app.logs_auto_scroll {
        max_scroll
    } else {
        (app.logs_scroll as usize).min(max_scroll)
    };

    #[allow(clippy::cast_possible_truncation)]
    let paragraph = paragraph.scroll((scroll_pos as u16, 0));

    frame.render_widget(paragraph, inner);

    // Scrollbar
    let scrollbar = Scrollbar::default()
        .orientation(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("↑"))
        .end_symbol(Some("↓"))
        .style(Style::default().fg(theme::NORD_POLAR_NIGHT_4))
        .thumb_style(Style::default().fg(theme::ACCENT_PRIMARY));

    let mut scrollbar_state = ScrollbarState::new(max_scroll).position(scroll_pos);

    frame.render_stateful_widget(
        scrollbar,
        area.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut scrollbar_state,
    );
}
