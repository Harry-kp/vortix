//! Hook editor overlay rendering (plan 017 U5).
//!
//! Render-only; input handling lives in `crate::app::input` via
//! `App::handle_hook_edit_keys`.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::state::hook_edit::{HookEditField, HookEditState, HookEditTarget, EVENT_KINDS};
use crate::theme;

#[allow(clippy::too_many_lines)]
pub fn render(frame: &mut Frame, state: &HookEditState) {
    let area = frame.area();
    let width = area.width.saturating_sub(4).min(78);
    let height = area.height.saturating_sub(2).min(28);
    if width == 0 || height == 0 {
        return;
    }
    let overlay = Rect {
        x: (area.width / 2).saturating_sub(width / 2),
        y: (area.height / 2).saturating_sub(height / 2),
        width,
        height,
    };
    frame.render_widget(Clear, overlay);

    let title = match state.target {
        HookEditTarget::AddingNew => " Add Hook ",
        HookEditTarget::EditingExisting { .. } => " Edit Hook ",
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::ACCENT_PRIMARY))
        .title(Span::styled(
            title,
            Style::default()
                .fg(theme::ACCENT_PRIMARY)
                .add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " Tab cycles · Ctrl-S save · Esc cancel ",
            Style::default().fg(theme::KEY_HINT_DESC),
        ));
    let inner = block.inner(overlay);
    frame.render_widget(block, overlay);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // event picker
            Constraint::Length(2), // name
            Constraint::Min(4),    // command textarea (label + body)
            Constraint::Length(2), // timeout
            Constraint::Length(2), // env header
            Constraint::Min(2),    // env rows
            Constraint::Length(1), // enabled
            Constraint::Length(1), // validation error
            Constraint::Length(1), // buttons
        ])
        .split(inner);

    render_event_picker(frame, chunks[0], state);
    render_named_input(
        frame,
        chunks[1],
        "Name",
        &state.name,
        state.name_cursor,
        state.focused == HookEditField::Name,
    );
    render_command(frame, chunks[2], state);
    render_named_input(
        frame,
        chunks[3],
        "Timeout (secs, blank=5)",
        &state.timeout_input,
        state.timeout_cursor,
        state.focused == HookEditField::Timeout,
    );
    render_env(frame, chunks[4], chunks[5], state);
    render_enabled(frame, chunks[6], state);
    render_validation(frame, chunks[7], state);
    render_buttons(frame, chunks[8], state);
}

fn render_event_picker(frame: &mut Frame, area: Rect, state: &HookEditState) {
    let focused = state.focused == HookEditField::Event;
    let label = label_span("Event:", focused);
    let mut spans = vec![label, Span::raw(" ")];
    for (i, kind) in EVENT_KINDS.iter().enumerate() {
        let selected = i == state.event_idx;
        let style = if selected {
            Style::default()
                .fg(theme::ACCENT_PRIMARY)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::TEXT_SECONDARY)
        };
        if selected {
            spans.push(Span::styled(format!("[{kind}]"), style));
        } else {
            spans.push(Span::styled(format!(" {kind} "), style));
        }
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_named_input(
    frame: &mut Frame,
    area: Rect,
    label: &str,
    text: &str,
    cursor: usize,
    focused: bool,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(area);
    frame.render_widget(Paragraph::new(label_span(label, focused)), chunks[0]);
    frame.render_widget(
        Paragraph::new(Line::from(focused_inline(text, cursor, focused))),
        chunks[1],
    );
}

fn render_command(frame: &mut Frame, area: Rect, state: &HookEditState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(3)])
        .split(area);
    let focused = state.focused == HookEditField::Command;
    frame.render_widget(
        Paragraph::new(label_span(
            "Command (multi-line shell — saved as sh -c):",
            focused,
        )),
        chunks[0],
    );
    state.command.render(frame, chunks[1], focused);
}

fn render_env(frame: &mut Frame, header_area: Rect, rows_area: Rect, state: &HookEditState) {
    let env_add_focused = state.focused == HookEditField::EnvAdd;
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            label_span("Env vars:", false),
            Span::raw("  "),
            Span::styled(
                if env_add_focused { "[+ Add]" } else { " + Add " },
                if env_add_focused {
                    Style::default()
                        .fg(theme::ACCENT_PRIMARY)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme::TEXT_SECONDARY)
                },
            ),
            Span::styled(
                "  (Enter on +Add to add, Del on row to remove)",
                Style::default().fg(theme::TEXT_SECONDARY),
            ),
        ])),
        header_area,
    );

    if state.env.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "  (no env vars)",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
            rows_area,
        );
        return;
    }

    let mut lines: Vec<Line> = Vec::with_capacity(state.env.len());
    for (i, row) in state.env.iter().enumerate() {
        let key_focused = state.focused == HookEditField::EnvKey(i);
        let val_focused = state.focused == HookEditField::EnvValue(i);
        let mut spans = vec![Span::raw(format!("  {:2}. ", i + 1))];
        spans.extend(focused_inline(&row.key, row.key_cursor, key_focused));
        spans.push(Span::raw(" = "));
        spans.extend(focused_inline(&row.value, row.value_cursor, val_focused));
        lines.push(Line::from(spans));
    }
    frame.render_widget(Paragraph::new(lines), rows_area);
}

fn render_enabled(frame: &mut Frame, area: Rect, state: &HookEditState) {
    let focused = state.focused == HookEditField::Enabled;
    let mark = if state.enabled { "[x]" } else { "[ ]" };
    let style = if focused {
        Style::default()
            .fg(theme::ACCENT_PRIMARY)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!("{mark} Enabled"), style),
            Span::styled(
                "  (space toggles)",
                Style::default().fg(theme::TEXT_SECONDARY),
            ),
        ])),
        area,
    );
}

fn render_validation(frame: &mut Frame, area: Rect, state: &HookEditState) {
    if let Some(err) = &state.validation_error {
        frame.render_widget(
            Paragraph::new(Span::styled(
                format!("⚠ {err}"),
                Style::default()
                    .fg(theme::ERROR)
                    .add_modifier(Modifier::BOLD),
            )),
            area,
        );
    }
}

fn render_buttons(frame: &mut Frame, area: Rect, state: &HookEditState) {
    let save_focused = state.focused == HookEditField::Save;
    let cancel_focused = state.focused == HookEditField::Cancel;
    let save = if save_focused { "[ Save ]" } else { "  Save  " };
    let cancel = if cancel_focused {
        "[ Cancel ]"
    } else {
        "  Cancel  "
    };
    let save_style = if save_focused {
        Style::default()
            .fg(theme::SUCCESS)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme::TEXT_SECONDARY)
    };
    let cancel_style = if cancel_focused {
        Style::default()
            .fg(theme::WARNING)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme::TEXT_SECONDARY)
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw("  "),
            Span::styled(save, save_style),
            Span::raw("    "),
            Span::styled(cancel, cancel_style),
        ])),
        area,
    );
}

fn label_span(text: &str, focused: bool) -> Span<'static> {
    let style = if focused {
        Style::default()
            .fg(theme::ACCENT_PRIMARY)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(theme::TEXT_SECONDARY)
            .add_modifier(Modifier::BOLD)
    };
    Span::styled(text.to_string(), style)
}

fn focused_inline(text: &str, cursor: usize, focused: bool) -> Vec<Span<'static>> {
    if !focused {
        return vec![Span::raw(text.to_string())];
    }
    let chars: Vec<char> = text.chars().collect();
    if cursor >= chars.len() {
        return vec![
            Span::raw(text.to_string()),
            Span::styled(" ", Style::default().add_modifier(Modifier::REVERSED)),
        ];
    }
    let before: String = chars[..cursor].iter().collect();
    let at: String = chars[cursor].to_string();
    let after: String = chars[cursor + 1..].iter().collect();
    vec![
        Span::raw(before),
        Span::styled(at, Style::default().add_modifier(Modifier::REVERSED)),
        Span::raw(after),
    ]
}
