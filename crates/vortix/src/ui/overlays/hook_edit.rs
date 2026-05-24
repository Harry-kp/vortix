//! Hook editor overlay rendering (plan 017 U5, refreshed by plan 018).
//!
//! Render-only; input handling lives in `crate::app::input` via
//! `App::handle_hook_edit_keys`.
//!
//! Plan 018 redesign:
//! - Event picker collapses to a one-line arrow-cycle widget.
//! - Command textarea is wrapped in a bordered Block so the editable
//!   area is visible even when empty.
//! - Single-line inputs (Name, Timeout) render with a thin underline
//!   so the field boundary is obvious at rest.
//! - Save/Cancel always render with `[ ]` brackets; focus is shown
//!   by colour + bold, not bracket-vs-no-bracket.
//! - Modal width up to 96 columns (was 78) — fits long shell
//!   commands and the full event list comfortably.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::state::hook_edit::{HookEditField, HookEditState, HookEditTarget, EVENT_KINDS};
use crate::theme;

const OVERLAY_WIDTH: u16 = 96;
const OVERLAY_MAX_HEIGHT: u16 = 32;

pub fn render(frame: &mut Frame, state: &HookEditState) {
    let area = frame.area();
    let width = area.width.saturating_sub(4).min(OVERLAY_WIDTH);
    let height = area.height.saturating_sub(2).min(OVERLAY_MAX_HEIGHT);
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

    // Vertical layout with explicit per-section sizing. Command box
    // gets a Min slot so it grows on tall terminals; everything
    // else is fixed.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(1), // event picker (arrow row)
            Constraint::Length(1), // spacer
            Constraint::Length(1), // name label
            Constraint::Length(1), // name value
            Constraint::Length(1), // name underline
            Constraint::Length(1), // spacer
            Constraint::Length(1), // command label
            Constraint::Min(6),    // command bordered box
            Constraint::Length(1), // spacer
            Constraint::Length(1), // timeout label
            Constraint::Length(1), // timeout value
            Constraint::Length(1), // timeout underline
            Constraint::Length(1), // spacer
            Constraint::Length(1), // env header
            Constraint::Min(2),    // env rows
            Constraint::Length(1), // spacer
            Constraint::Length(1), // enabled checkbox
            Constraint::Length(1), // validation error (when present)
            Constraint::Length(1), // spacer
            Constraint::Length(1), // buttons
        ])
        .split(inner);

    render_event_picker(frame, chunks[0], state);
    render_input_with_underline(
        frame,
        chunks[2],
        chunks[3],
        chunks[4],
        "Name",
        &state.name,
        state.name_cursor,
        state.focused == HookEditField::Name,
    );
    render_command(frame, chunks[6], chunks[7], state);
    render_input_with_underline(
        frame,
        chunks[9],
        chunks[10],
        chunks[11],
        "Timeout (secs, blank = 5)",
        &state.timeout_input,
        state.timeout_cursor,
        state.focused == HookEditField::Timeout,
    );
    render_env(frame, chunks[13], chunks[14], state);
    render_enabled(frame, chunks[16], state);
    render_validation(frame, chunks[17], state);
    render_buttons(frame, chunks[19], state);
}

/// One-line arrow-cycle event picker: `◀  post_connect  ▶`. The
/// selected event sits centered; arrows pick up accent colour when
/// the field is focused.
fn render_event_picker(frame: &mut Frame, area: Rect, state: &HookEditState) {
    let focused = state.focused == HookEditField::Event;
    let arrow_style = if focused {
        Style::default()
            .fg(theme::ACCENT_PRIMARY)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme::TEXT_SECONDARY)
    };
    let value_style = if focused {
        Style::default()
            .fg(theme::ACCENT_PRIMARY)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme::TEXT_PRIMARY)
    };
    let label_style = if focused {
        Style::default()
            .fg(theme::ACCENT_PRIMARY)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(theme::TEXT_SECONDARY)
            .add_modifier(Modifier::BOLD)
    };
    let counter = format!("({}/{})", state.event_idx + 1, EVENT_KINDS.len());
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Event: ", label_style),
            Span::styled("◀ ", arrow_style),
            Span::styled(format!("{:^18}", EVENT_KINDS[state.event_idx]), value_style),
            Span::styled(" ▶", arrow_style),
            Span::raw("   "),
            Span::styled(counter, Style::default().fg(theme::TEXT_SECONDARY)),
            if focused {
                Span::styled(
                    "   (← / → to cycle)",
                    Style::default().fg(theme::TEXT_SECONDARY),
                )
            } else {
                Span::raw("")
            },
        ])),
        area,
    );
}

/// Three-row labelled input: label / value-with-cursor / underline.
/// The underline picks up accent colour when focused so the field
/// boundary is unambiguous even with empty text.
#[allow(clippy::too_many_arguments)]
fn render_input_with_underline(
    frame: &mut Frame,
    label_area: Rect,
    value_area: Rect,
    underline_area: Rect,
    label: &str,
    text: &str,
    cursor: usize,
    focused: bool,
) {
    frame.render_widget(Paragraph::new(label_span(label, focused)), label_area);
    frame.render_widget(
        Paragraph::new(Line::from(focused_inline(text, cursor, focused))),
        value_area,
    );
    let underline_style = if focused {
        Style::default().fg(theme::ACCENT_PRIMARY)
    } else {
        Style::default().fg(theme::TEXT_SECONDARY)
    };
    let line: String = "─".repeat(usize::from(underline_area.width));
    frame.render_widget(
        Paragraph::new(Span::styled(line, underline_style)),
        underline_area,
    );
}

/// Command field: a label row followed by the textarea wrapped in
/// a bordered Block. Border colour reflects focus state so the
/// active field is obvious.
fn render_command(frame: &mut Frame, label_area: Rect, body_area: Rect, state: &HookEditState) {
    let focused = state.focused == HookEditField::Command;
    frame.render_widget(
        Paragraph::new(label_span(
            "Command (multi-line shell — saved as sh -c):",
            focused,
        )),
        label_area,
    );
    let border_color = if focused {
        theme::ACCENT_PRIMARY
    } else {
        theme::TEXT_SECONDARY
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));
    let inner = block.inner(body_area);
    frame.render_widget(block, body_area);
    if state.command.is_empty() && !focused {
        // Hint when empty and unfocused so users know what goes in
        // the box. The TextArea itself shows the cursor when focused.
        frame.render_widget(
            Paragraph::new(Span::styled(
                "  (Tab here to type; e.g.  notify-send \"VPN $VORTIX_PROFILE connected\")",
                Style::default()
                    .fg(theme::TEXT_SECONDARY)
                    .add_modifier(Modifier::DIM),
            )),
            inner,
        );
    } else {
        state.command.render(frame, inner, focused);
    }
}

fn render_env(frame: &mut Frame, header_area: Rect, rows_area: Rect, state: &HookEditState) {
    let env_add_focused = state.focused == HookEditField::EnvAdd;
    let add_style = if env_add_focused {
        Style::default()
            .fg(theme::ACCENT_PRIMARY)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme::TEXT_SECONDARY)
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            label_span("Env vars:", false),
            Span::raw("    "),
            Span::styled("[ + Add ]", add_style),
            Span::styled(
                "   (Enter on +Add to add · Del on empty row to remove)",
                Style::default().fg(theme::TEXT_SECONDARY),
            ),
        ])),
        header_area,
    );

    if state.env.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "    (no env vars)",
                Style::default()
                    .fg(theme::TEXT_SECONDARY)
                    .add_modifier(Modifier::DIM),
            )),
            rows_area,
        );
        return;
    }

    let mut lines: Vec<Line> = Vec::with_capacity(state.env.len());
    for (i, row) in state.env.iter().enumerate() {
        let key_focused = state.focused == HookEditField::EnvKey(i);
        let val_focused = state.focused == HookEditField::EnvValue(i);
        let mut spans = vec![Span::styled(
            format!("  {:>2}. ", i + 1),
            Style::default().fg(theme::TEXT_SECONDARY),
        )];
        let key_chars = row.key.chars().count();
        let key_pad = 20usize.saturating_sub(key_chars);
        spans.extend(focused_inline(&row.key, row.key_cursor, key_focused));
        spans.push(Span::raw(" ".repeat(key_pad)));
        spans.push(Span::styled(" = ", Style::default().fg(theme::TEXT_SECONDARY)));
        spans.extend(focused_inline(&row.value, row.value_cursor, val_focused));
        lines.push(Line::from(spans));
    }
    frame.render_widget(Paragraph::new(lines), rows_area);
}

fn render_enabled(frame: &mut Frame, area: Rect, state: &HookEditState) {
    let focused = state.focused == HookEditField::Enabled;
    let mark = if state.enabled { "[x]" } else { "[ ]" };
    let mark_style = if focused {
        Style::default()
            .fg(theme::ACCENT_PRIMARY)
            .add_modifier(Modifier::BOLD)
    } else if state.enabled {
        Style::default()
            .fg(theme::SUCCESS)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme::TEXT_SECONDARY)
    };
    let label_style = if focused {
        Style::default()
            .fg(theme::ACCENT_PRIMARY)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme::TEXT_PRIMARY)
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!("{mark} "), mark_style),
            Span::styled("Enabled", label_style),
            Span::styled(
                "   (space toggles)",
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

/// Buttons always render with `[ ]` brackets so they read as buttons
/// at rest. Focus is shown by colour + bold.
fn render_buttons(frame: &mut Frame, area: Rect, state: &HookEditState) {
    let save_focused = state.focused == HookEditField::Save;
    let cancel_focused = state.focused == HookEditField::Cancel;
    let save_style = if save_focused {
        Style::default()
            .fg(theme::SUCCESS)
            .add_modifier(Modifier::BOLD)
            .add_modifier(Modifier::REVERSED)
    } else {
        Style::default()
            .fg(theme::SUCCESS)
            .add_modifier(Modifier::BOLD)
    };
    let cancel_style = if cancel_focused {
        Style::default()
            .fg(theme::WARNING)
            .add_modifier(Modifier::BOLD)
            .add_modifier(Modifier::REVERSED)
    } else {
        Style::default()
            .fg(theme::TEXT_SECONDARY)
            .add_modifier(Modifier::BOLD)
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw("  "),
            Span::styled(" [ Save ] ", save_style),
            Span::raw("      "),
            Span::styled(" [ Cancel ] ", cancel_style),
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
