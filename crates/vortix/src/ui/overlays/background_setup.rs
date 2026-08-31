//! One dense, keyboard-only overlay for Background setup and recovery.

use crate::background::{
    BackgroundFocus, BackgroundModeRecord, BackgroundOverlayState, BackgroundWorkflow,
};
use crate::theme;
use crate::ui::helpers::centered_rect_fixed;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

#[must_use]
pub fn max_scroll(
    mode: &BackgroundModeRecord,
    workflow: BackgroundWorkflow,
    terminal_width: u16,
    terminal_height: u16,
) -> u16 {
    let width = terminal_width.saturating_sub(2).clamp(30, 74);
    let height = terminal_height.saturating_sub(2).clamp(10, 22);
    let content_width = width.saturating_sub(2);
    let content_height = height.saturating_sub(5);
    let wrapped = Paragraph::new(content_lines(mode, workflow))
        .wrap(Wrap { trim: true })
        .line_count(content_width);
    u16::try_from(wrapped)
        .unwrap_or(u16::MAX)
        .saturating_sub(content_height)
}

fn content_lines(mode: &BackgroundModeRecord, workflow: BackgroundWorkflow) -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(
            mode.state.display_name(),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(format!(
            "Signal: {} (never color-only)",
            mode.state.header_signal()
        )),
        Line::from(""),
        Line::from(workflow.description()),
        Line::from(""),
        Line::from(format!("Reason: {}", mode.reason)),
        Line::from(format!("Authority: {}", mode.authority.display_name())),
        Line::from(format!("Protection: {}", mode.protection.display_name())),
        Line::from(""),
        Line::from("Trusted setup boundary:"),
        Line::from("• confirmation comes before terminal suspension"),
        Line::from("• only a verified absolute package bootstrap may be elevated"),
        Line::from("• no shell and no administrator password collection"),
        Line::from("• terminal restoration is owned by the outer typed effect runner"),
        Line::from(""),
        Line::from("Prepared release status:"),
        Line::from("• enrollment and remote mutation require an enrollment-capable release"),
        Line::from("• confirming now invokes no privileged process"),
        Line::from("• Standard mode remains fully available"),
    ]
}

pub fn render(frame: &mut Frame, mode: &BackgroundModeRecord, state: &BackgroundOverlayState) {
    let outer = frame.area();
    let width = outer.width.saturating_sub(2).min(74);
    let height = outer.height.saturating_sub(2).min(22);
    let area = centered_rect_fixed(width.max(30), height.max(10), outer);
    crate::ui::helpers::clear_area(frame, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::current().border_focused))
        .title(format!(" {} ", state.workflow.title()));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(3)])
        .split(inner);

    frame.render_widget(
        Paragraph::new(content_lines(mode, state.workflow))
            .wrap(Wrap { trim: true })
            .scroll((state.scroll, 0)),
        chunks[0],
    );

    let button = |label: &'static str, selected: bool| {
        if selected {
            Span::styled(
                format!("[ {label} ]"),
                Style::default()
                    .fg(theme::current().row_selected_fg)
                    .bg(theme::current().row_selected_bg)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::raw(format!("  {label}  "))
        }
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            button("Continue", state.focus == BackgroundFocus::Continue),
            Span::raw("   "),
            button("Cancel", state.focus == BackgroundFocus::Cancel),
        ]))
        .alignment(Alignment::Center)
        .block(Block::default().title(" Tab/Shift-Tab · Enter · Esc before commit ")),
        chunks[1],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};

    #[test]
    fn setup_overlay_fits_and_keeps_non_color_controls_at_80_by_24() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                render(
                    frame,
                    &BackgroundModeRecord::prepared_standard(),
                    &BackgroundOverlayState::new(BackgroundWorkflow::Setup),
                );
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                text.push_str(buffer[(x, y)].symbol());
            }
        }
        assert!(text.contains("Background setup"));
        assert!(text.contains("Continue"));
        assert!(text.contains("Cancel"));
        assert!(text.contains("Tab/Shift-Tab"));
    }

    #[test]
    fn wrapped_narrow_content_has_a_reachable_bottom() {
        let mode = BackgroundModeRecord::prepared_standard();
        let workflow = BackgroundWorkflow::Recover;
        let scroll = max_scroll(&mode, workflow, 40, 14);
        assert!(scroll > 0, "wrapped content must expose scroll at 40x14");

        let backend = TestBackend::new(40, 14);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = BackgroundOverlayState::new(workflow);
        state.scroll = scroll;
        terminal.draw(|frame| render(frame, &mode, &state)).unwrap();
        let buffer = terminal.backend().buffer();
        let text = buffer
            .content
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<String>();
        assert!(text.contains("Standard mode remains fully"), "{text}");
    }
}
