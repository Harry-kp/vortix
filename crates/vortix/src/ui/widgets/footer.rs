//! Footer widget with context-aware keybinding hints

use crate::app::{focused_tunnel_action, App, FocusedTunnelAction};
use crate::vortix_core::engine::registry::TunnelSnapshot;
use crate::vortix_core::engine::state::Connection;
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};
use unicode_width::UnicodeWidthStr;

/// Render dashboard footer with context-aware shortcuts.
///
/// Hints are split into two groups: context-specific (truncatable on narrow
/// terminals) and critical (always visible). `render_hints` reserves space
/// for critical hints before laying out context-specific ones, so `?` (Help)
/// and `q` (Quit) never disappear — even on 60-column terminals.
pub fn render_dashboard(frame: &mut Frame, app: &App, area: Rect) {
    if app.show_config {
        let hints = vec![
            ("↑↓", "Scroll"),
            ("g", "Top"),
            ("G", "End"),
            ("Esc", "Close"),
        ];
        render_hints(frame, area, &hints, &[], None);
        return;
    }

    let panel_name = match &app.focused_panel {
        crate::app::FocusedPanel::Sidebar => "Profiles",
        crate::app::FocusedPanel::ConnectionDetails => "Details",
        crate::app::FocusedPanel::Chart => "Chart",
        crate::app::FocusedPanel::Security => "Security",
        crate::app::FocusedPanel::Logs => "Logs",
    };
    let snapshots = app.registry.snapshot_all();
    let focused_state = (app.focused_panel == crate::app::FocusedPanel::Sidebar)
        .then(|| focused_profile_state(app, &snapshots))
        .flatten();

    let mut context_hints = Vec::new();

    match &app.focused_panel {
        crate::app::FocusedPanel::Sidebar => {
            let connection_action = focused_profile_action(focused_state);
            context_hints.extend_from_slice(&[
                ("j/k", "Navigate"),
                ("c", connection_action),
                ("v", "View Config"),
                ("R", "Rename"),
                ("i", "Import"),
                ("DEL", "Delete"),
            ]);
        }
        crate::app::FocusedPanel::Logs => {
            context_hints.extend_from_slice(&[
                ("j/k", "Scroll"),
                ("g/G", "Top/End"),
                ("f", "Filter"),
                ("L", "Clear"),
            ]);
        }
        crate::app::FocusedPanel::Chart
        | crate::app::FocusedPanel::Security
        | crate::app::FocusedPanel::ConnectionDetails => {
            context_hints.push(("f", "Flip"));
            context_hints.push(("z", "Zoom"));
        }
    }

    // Reflects what `d` will do against the most relevant tunnel. Priority:
    // Disconnecting (already tearing down → Force Kill) > Connecting /
    // Reconnecting / AwaitingUserInput (in-flight → Cancel) > Connected
    // (steady → Disconnect). When no tunnel is active but a prior session
    // exists, surface `r Reconnect`.
    let active_state = snapshots
        .iter()
        .map(|snapshot| &snapshot.state)
        .filter(|st| !matches!(st, Connection::Disconnected { .. }))
        .min_by_key(|st| match st {
            Connection::Disconnecting { .. } => 0,
            Connection::Connecting { .. }
            | Connection::Reconnecting { .. }
            | Connection::AwaitingUserInput { .. } => 1,
            Connection::Connected { .. } => 2,
            Connection::Disconnected { .. } => 3,
        });
    let disconnect_hint = if app.focused_panel == crate::app::FocusedPanel::Sidebar {
        focused_disconnect_hint(focused_state)
    } else {
        global_disconnect_hint(active_state, app.runtime.last_connected_profile.is_some())
    };
    if let Some(disconnect_hint) = disconnect_hint {
        context_hints.push(disconnect_hint);
    }

    let critical_hints = [
        ("Tab", "Panel"),
        ("K", "KillSw"),
        ("?", "Help"),
        ("q", "Quit"),
    ];

    render_hints(
        frame,
        area,
        &context_hints,
        &critical_hints,
        Some(panel_name),
    );
}

/// Label the focused row's primary action without falling back to another
/// active tunnel. This mirrors the sidebar `c` key's profile-scoped behavior.
fn focused_profile_state<'a>(app: &App, snapshots: &'a [TunnelSnapshot]) -> Option<&'a Connection> {
    let profile_id = app
        .profile_list_state
        .selected()
        .and_then(|index| app.runtime.profiles.get(index))
        .map(|profile| &profile.id)?;
    snapshots
        .iter()
        .find(|snapshot| snapshot.profile_id == *profile_id)
        .map(|snapshot| &snapshot.state)
}

fn focused_profile_action(state: Option<&Connection>) -> &'static str {
    match focused_tunnel_action(state) {
        FocusedTunnelAction::Connect => "Connect",
        FocusedTunnelAction::Cancel => "Cancel",
        FocusedTunnelAction::Disconnect => "Disconnect",
        FocusedTunnelAction::ForceDisconnect => "Force Kill",
    }
}

fn focused_disconnect_hint(state: Option<&Connection>) -> Option<(&'static str, &'static str)> {
    match focused_tunnel_action(state) {
        FocusedTunnelAction::ForceDisconnect => Some(("d", "Force Kill")),
        FocusedTunnelAction::Cancel => Some(("d", "Cancel")),
        FocusedTunnelAction::Disconnect => Some(("d", "Disconnect")),
        FocusedTunnelAction::Connect => None,
    }
}

fn global_disconnect_hint(
    state: Option<&Connection>,
    can_reconnect: bool,
) -> Option<(&'static str, &'static str)> {
    focused_disconnect_hint(state).or_else(|| can_reconnect.then_some(("r", "Reconnect")))
}

/// Terminal display width of a hint item: `key action` plus optional separator.
fn hint_display_width(key: &str, action: &str, needs_sep: bool) -> usize {
    let sep = if needs_sep { " │ ".width() } else { 0 };
    key.width() + 1 + action.width() + sep
}

/// Render hint spans for one group, appending to `spans`.
/// Returns the number of **display columns** consumed.
fn push_hint_spans<'a>(
    spans: &mut Vec<Span<'a>>,
    hints: &[(&'a str, &'a str)],
    budget: usize,
    current_width: usize,
    needs_leading_sep: bool,
) -> usize {
    let mut used = 0;
    for (i, (key, action)) in hints.iter().enumerate() {
        let need_sep = needs_leading_sep || i > 0;
        let item_width = hint_display_width(key, action, need_sep);

        if current_width + used + item_width > budget {
            break;
        }

        if need_sep {
            spans.push(Span::styled(
                " │ ",
                Style::default().fg(crate::theme::current().separator),
            ));
        }
        spans.push(Span::styled(
            *key,
            Style::default()
                .fg(crate::theme::current().key_hint)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            *action,
            Style::default().fg(crate::theme::current().key_hint_desc),
        ));

        used += item_width;
    }
    used
}

/// Lay out footer hints so that `critical_hints` (Help, Quit, etc.) are always
/// visible at the end, and `context_hints` fill the remaining space — truncating
/// gracefully when the terminal is narrow.
fn render_hints(
    frame: &mut Frame,
    area: Rect,
    context_hints: &[(&str, &str)],
    critical_hints: &[(&str, &str)],
    panel_name: Option<&str>,
) {
    use ratatui::layout::{Constraint, Layout};

    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(16)])
        .split(area);

    let max_width = chunks[0].width as usize;
    let mut hint_spans: Vec<Span<'_>> = Vec::new();
    let mut current_width: usize = 0;

    // Panel indicator (allocated once — only string that needs formatting)
    if let Some(panel) = panel_name {
        let indicator = format!("[{panel}] ");
        current_width += indicator.width();
        hint_spans.push(Span::styled(
            indicator,
            Style::default()
                .fg(crate::theme::current().key_hint)
                .add_modifier(Modifier::BOLD),
        ));
    } else {
        hint_spans.push(Span::raw(" "));
        current_width += 1;
    }

    // Reserve width for critical hints so they are never truncated
    let critical_width: usize = critical_hints
        .iter()
        .enumerate()
        .map(|(i, (k, a))| hint_display_width(k, a, i > 0))
        .sum();
    // Extra separator between the two groups
    let group_sep = if !context_hints.is_empty() && !critical_hints.is_empty() {
        3
    } else {
        0
    };
    let reserved = critical_width + group_sep;

    // Context hints fill whatever space is left after reserving for critical
    let context_budget = max_width.saturating_sub(reserved);
    let context_used = push_hint_spans(
        &mut hint_spans,
        context_hints,
        context_budget,
        current_width,
        false,
    );
    current_width += context_used;

    // Critical hints — always rendered
    let has_context = context_used > 0;
    push_hint_spans(
        &mut hint_spans,
        critical_hints,
        max_width,
        current_width,
        has_context,
    );

    frame.render_widget(Paragraph::new(Line::from(hint_spans)), chunks[0]);

    // Branding
    let branding = Line::from(vec![Span::styled(
        format!(
            "{} v{} ",
            crate::constants::APP_NAME,
            crate::constants::APP_VERSION
        ),
        Style::default().fg(crate::theme::current().nord_polar_night_4),
    )]);
    frame.render_widget(
        Paragraph::new(branding).alignment(ratatui::layout::Alignment::Right),
        chunks[1],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hint_width_ascii_no_sep() {
        assert_eq!(hint_display_width("q", "Quit", false), 6); // "q Quit"
    }

    #[test]
    fn hint_width_ascii_with_sep() {
        // " │ " (3 display cols) + "q Quit" (6) = 9
        assert_eq!(hint_display_width("q", "Quit", true), 9);
    }

    #[test]
    fn hint_width_unicode_arrows() {
        // "↑↓" is 2 display columns, "Scroll" is 6, space is 1 → 9
        assert_eq!(hint_display_width("↑↓", "Scroll", false), 9);
    }

    #[test]
    fn push_spans_respects_budget() {
        let hints: &[(&str, &str)] = &[("a", "AAA"), ("b", "BBB"), ("c", "CCC")];
        let mut spans = Vec::new();
        // budget only fits first item: "a AAA" = 5 cols
        let used = push_hint_spans(&mut spans, hints, 8, 0, false);
        assert_eq!(used, 5);
        assert_eq!(spans.len(), 3); // key + space + action
    }

    #[test]
    fn push_spans_empty_on_zero_budget() {
        let hints: &[(&str, &str)] = &[("q", "Quit")];
        let mut spans = Vec::new();
        let used = push_hint_spans(&mut spans, hints, 0, 0, false);
        assert_eq!(used, 0);
        assert!(spans.is_empty());
    }

    #[test]
    fn push_spans_includes_separator() {
        let hints: &[(&str, &str)] = &[("a", "A"), ("b", "B")];
        let mut spans = Vec::new();
        let used = push_hint_spans(&mut spans, hints, 100, 0, false);
        // "a A" (3) + " │ " (3) + "b B" (3) = 9
        assert_eq!(used, 9);
        // first: key+space+action (3), sep (1), second: key+space+action (3) = 7
        assert_eq!(spans.len(), 7);
    }

    #[test]
    fn focused_footer_labels_match_profile_scoped_shortcuts() {
        use crate::vortix_core::engine::state::{ConnectionHealth, DetailedConnectionInfo};
        use crate::vortix_core::profile::ProfileId;
        use std::time::{Duration, SystemTime};

        let profile_id = ProfileId::new("focused");
        let now = SystemTime::UNIX_EPOCH;
        let connecting = Connection::Connecting {
            profile_id: profile_id.clone(),
            started_at: now,
            attempt: 1,
            retry_budget_remaining: Duration::ZERO,
        };
        let connected = Connection::Connected {
            profile_id: profile_id.clone(),
            since: now,
            health: ConnectionHealth::Healthy,
            details: Box::new(DetailedConnectionInfo::default()),
        };
        let disconnecting = Connection::Disconnecting {
            profile_id,
            started_at: now,
        };

        assert_eq!(focused_profile_action(None), "Connect");
        assert_eq!(focused_disconnect_hint(None), None);
        assert_eq!(focused_profile_action(Some(&connecting)), "Cancel");
        assert_eq!(
            focused_disconnect_hint(Some(&connecting)),
            Some(("d", "Cancel"))
        );
        assert_eq!(focused_profile_action(Some(&connected)), "Disconnect");
        assert_eq!(
            focused_disconnect_hint(Some(&connected)),
            Some(("d", "Disconnect"))
        );
        assert_eq!(focused_profile_action(Some(&disconnecting)), "Force Kill");
        assert_eq!(
            focused_disconnect_hint(Some(&disconnecting)),
            Some(("d", "Force Kill"))
        );
    }
}
