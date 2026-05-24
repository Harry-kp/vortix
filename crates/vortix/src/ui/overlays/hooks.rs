//! Lifecycle-hooks overlay (plan 016 U4).
//!
//! Shows the most recent fires from [`crate::app::App::recent_hook_events`]
//! so the user can audit hook behaviour without leaving the TUI. Read-
//! only — toggled by `H` in the dashboard and by an entry in the bulk
//! action menu.

use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};
use vortix_core::engine::HookOutcomeLabel;

use crate::app::App;
use crate::theme;

const OVERLAY_WIDTH: u16 = 82;
const OVERLAY_MAX_HEIGHT: u16 = 32;
const MAX_ROWS: usize = 10;
const MAX_REGISTERED_ROWS: usize = 12;

#[allow(clippy::too_many_lines)]
pub fn render(frame: &mut Frame, app: &App) {
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

    let mut lines: Vec<Line> = Vec::new();

    // Header — counts (active + disabled), then config errors banner.
    let active_count = app.registered_hooks.iter().filter(|h| h.is_enabled()).count();
    let disabled_count = app.registered_hooks.len() - active_count;
    lines.push(Line::from(vec![
        Span::styled(
            "  Registered: ",
            Style::default().fg(theme::TEXT_SECONDARY),
        ),
        Span::styled(
            format!("{active_count} active"),
            Style::default()
                .fg(theme::SUCCESS)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" · {disabled_count} disabled"),
            Style::default().fg(theme::TEXT_SECONDARY),
        ),
        Span::styled(
            "    (running registry: ",
            Style::default().fg(theme::TEXT_SECONDARY),
        ),
        Span::styled(
            app.registered_hooks_count.to_string(),
            Style::default().fg(theme::TEXT_SECONDARY),
        ),
        Span::styled(
            " — restart vortix to apply changes)",
            Style::default().fg(theme::TEXT_SECONDARY),
        ),
    ]));
    lines.push(Line::from(""));

    if !app.hook_config_errors.is_empty() {
        lines.push(Line::from(Span::styled(
            "  Config issues:",
            Style::default()
                .fg(theme::WARNING)
                .add_modifier(Modifier::BOLD),
        )));
        for err in &app.hook_config_errors {
            let budget = usize::from(width).saturating_sub(4).max(20);
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    truncate(err, budget),
                    Style::default().fg(theme::WARNING),
                ),
            ]));
        }
        lines.push(Line::from(""));
    }

    // Registered-hooks list (plan 017 U6).
    lines.push(Line::from(Span::styled(
        "  Registered hooks:",
        Style::default()
            .fg(theme::ACCENT_PRIMARY)
            .add_modifier(Modifier::BOLD),
    )));
    if app.registered_hooks.is_empty() {
        lines.push(Line::from(Span::styled(
            "    (none configured — press 'a' to add one)",
            Style::default().fg(theme::TEXT_SECONDARY),
        )));
    } else {
        let selected = app.hooks_overlay_selected.min(
            app.registered_hooks.len().saturating_sub(1),
        );
        for (i, cfg) in app
            .registered_hooks
            .iter()
            .enumerate()
            .take(MAX_REGISTERED_ROWS)
        {
            let is_selected = i == selected;
            let active = cfg.is_enabled();
            let marker = if is_selected { "▶ " } else { "  " };
            let status_marker = if active { "    " } else { "[off]" };
            let cmd_preview = command_preview(&cfg.command);
            let name = hook_label(cfg);
            let row_style = if !active {
                Style::default()
                    .fg(theme::TEXT_SECONDARY)
                    .add_modifier(Modifier::DIM)
            } else if is_selected {
                Style::default()
                    .fg(theme::ACCENT_PRIMARY)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme::TEXT_PRIMARY)
            };
            let budget = usize::from(width).saturating_sub(40).max(20);
            lines.push(Line::from(vec![
                Span::styled(marker.to_string(), row_style),
                Span::styled(
                    format!("{status_marker} "),
                    if active {
                        Style::default().fg(theme::SUCCESS)
                    } else {
                        Style::default()
                            .fg(theme::WARNING)
                            .add_modifier(Modifier::BOLD)
                    },
                ),
                Span::styled(format!("{:<14} ", truncate(&cfg.event, 13)), row_style),
                Span::styled(format!("{:<16} ", truncate(&name, 15)), row_style),
                Span::styled(
                    truncate(&cmd_preview, budget),
                    Style::default().fg(theme::TEXT_SECONDARY),
                ),
            ]));
        }
        if app.registered_hooks.len() > MAX_REGISTERED_ROWS {
            lines.push(Line::from(Span::styled(
                format!(
                    "    … {} more (not shown)",
                    app.registered_hooks.len() - MAX_REGISTERED_ROWS
                ),
                Style::default().fg(theme::TEXT_SECONDARY),
            )));
        }
    }
    lines.push(Line::from(""));

    if app.recent_hook_events.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No hook fires recorded yet.",
            Style::default().fg(theme::TEXT_SECONDARY),
        )));
        lines.push(Line::from(Span::styled(
            "  Connect or disconnect a profile to trigger configured hooks.",
            Style::default().fg(theme::TEXT_SECONDARY),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "  Recent fires (newest first):",
            Style::default()
                .fg(theme::ACCENT_PRIMARY)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));

        for report in app.recent_hook_events.iter().take(MAX_ROWS) {
            let (label, style) = match report.record.outcome {
                HookOutcomeLabel::Success => (
                    "OK",
                    Style::default()
                        .fg(theme::SUCCESS)
                        .add_modifier(Modifier::BOLD),
                ),
                HookOutcomeLabel::Failed => (
                    "FAIL",
                    Style::default()
                        .fg(theme::ERROR)
                        .add_modifier(Modifier::BOLD),
                ),
                HookOutcomeLabel::TimedOut => (
                    "TIMEOUT",
                    Style::default()
                        .fg(theme::WARNING)
                        .add_modifier(Modifier::BOLD),
                ),
                HookOutcomeLabel::Aborted => (
                    "ABORT",
                    Style::default()
                        .fg(theme::WARNING)
                        .add_modifier(Modifier::BOLD),
                ),
                _ => ("?", Style::default().fg(theme::TEXT_SECONDARY)),
            };

            let exit = report
                .record
                .exit_code
                .map_or_else(|| "  -".to_string(), |c| format!("{c:>3}"));

            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(format!("{label:<8}"), style),
                Span::styled(
                    format!("{:<20} ", truncate(&report.hook_name, 19)),
                    Style::default().fg(theme::TEXT_PRIMARY),
                ),
                Span::styled(
                    format!("{:<14} ", truncate(&report.event_kind, 13)),
                    Style::default().fg(theme::TEXT_SECONDARY),
                ),
                Span::styled(
                    format!("exit={exit}"),
                    Style::default().fg(theme::TEXT_SECONDARY),
                ),
            ]));

            // Show the first non-empty stderr line indented underneath.
            if let Some(detail) = report
                .record
                .stderr
                .lines()
                .find(|l| !l.trim().is_empty())
            {
                let budget = usize::from(width).saturating_sub(10).max(20);
                lines.push(Line::from(vec![
                    Span::raw("           "),
                    Span::styled(
                        truncate(detail, budget),
                        Style::default().fg(theme::TEXT_SECONDARY),
                    ),
                ]));
            }
        }
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::ACCENT_PRIMARY))
        .title(Span::styled(
            " Lifecycle Hooks ",
            Style::default()
                .fg(theme::ACCENT_PRIMARY)
                .add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " j/k move · a add · e edit · d delete · t toggle · H/Esc close ",
            Style::default().fg(theme::KEY_HINT_DESC),
        ));

    let inner = block.inner(overlay);
    frame.render_widget(block, overlay);

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(paragraph, inner);
}

/// Best-effort label for a registered hook — mirrors the form's
/// `derive_name_from_cfg` logic (plan 017 U5): `VORTIX_HOOK_NAME` env
/// var wins, otherwise `event:program-basename`.
fn hook_label(cfg: &vortix_config::HookConfig) -> String {
    if let Some(n) = cfg.env.get("VORTIX_HOOK_NAME") {
        return n.clone();
    }
    let program = cfg
        .command
        .first()
        .and_then(|s| s.rsplit('/').next())
        .unwrap_or("hook");
    program.to_string()
}

/// One-line shell preview for the command field. `sh -c X` patterns
/// show the inner shell snippet (first line if multi-line); literal
/// argv shows space-joined args.
fn command_preview(argv: &[String]) -> String {
    if argv.len() == 3 && (argv[0] == "sh" || argv[0] == "bash") && argv[1] == "-c" {
        return argv[2].lines().next().unwrap_or("").to_string();
    }
    argv.join(" ")
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else if max <= 1 {
        "…".to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}
