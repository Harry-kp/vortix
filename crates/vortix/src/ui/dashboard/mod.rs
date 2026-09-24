mod chart;
mod connection_details;
mod header;
mod logs;
mod security;
mod sidebar;

use super::helpers::centered_rect;
use crate::app::{App, FocusedPanel, InputMode};
use crate::{constants, message, ui::theme};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};
use unicode_width::UnicodeWidthStr;

/// Render the dashboard view
pub fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.area();

    if area.width < constants::MIN_TERMINAL_WIDTH || area.height < constants::MIN_TERMINAL_HEIGHT {
        let msg = format!(
            "Terminal too small ({}\u{00d7}{})\nResize to at least {}\u{00d7}{}",
            area.width,
            area.height,
            constants::MIN_TERMINAL_WIDTH,
            constants::MIN_TERMINAL_HEIGHT,
        );
        frame.render_widget(
            Paragraph::new(msg)
                .alignment(Alignment::Center)
                .style(Style::default().fg(theme::current().accent_primary)),
            centered_rect(80, 30, area),
        );
        return;
    }

    // 1. Technical Header (1 row)
    // 2. Main Content (Flexible)
    // 3. Command Footer (1 row)
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(area);

    header::render(frame, app, chunks[0]);
    super::footer::render_dashboard(frame, app, chunks[2]);

    // Main Content: Left Sidebar (Profiles + Details) | Right Workspace
    // Expanded sidebar from 25% to 32% for better Connection Details display
    let main_layout = Layout::horizontal([Constraint::Percentage(32), Constraint::Percentage(68)])
        .split(chunks[1]);

    // Sidebar: Profiles (Top) | Connection Details (Bottom)
    let sidebar_layout = Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(main_layout[0]);

    sidebar::render(frame, app, sidebar_layout[0]);
    render_animated_panel(
        frame,
        app,
        &FocusedPanel::ConnectionDetails,
        sidebar_layout[1],
        |f, a, r| {
            connection_details::render(f, a, r);
        },
    );

    // Right Workspace: Top (Chart) | Bottom (Security + Logs)
    let workspace_chunks =
        Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(main_layout[1]);

    render_animated_panel(
        frame,
        app,
        &FocusedPanel::Chart,
        workspace_chunks[0],
        |f, a, r| {
            chart::render(f, a, r);
        },
    );

    // Bottom Dash: Left (Security Guard) | Right (Event Log)
    let dash_chunks = Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(workspace_chunks[1]);

    render_animated_panel(
        frame,
        app,
        &FocusedPanel::Security,
        dash_chunks[0],
        |f, a, r| {
            security::render(f, a, r);
        },
    );
    logs::render(frame, app, dash_chunks[1]);

    // Register Click Areas
    app.panel_areas
        .insert(crate::app::FocusedPanel::Sidebar, sidebar_layout[0]);
    app.panel_areas.insert(
        crate::app::FocusedPanel::ConnectionDetails,
        sidebar_layout[1],
    );
    app.panel_areas
        .insert(crate::app::FocusedPanel::Chart, workspace_chunks[0]);
    app.panel_areas
        .insert(crate::app::FocusedPanel::Security, dash_chunks[0]);
    app.panel_areas
        .insert(crate::app::FocusedPanel::Logs, dash_chunks[1]);

    render_overlays(frame, app);

    // Auto-promote notification surfaces as a top-right toast (set in
    // `detect_primary_change_for_banner`). No central banner widget,
    // no [u] revert hotkey — the user decides what action to take.

    // Render Zoomed Panel Overlay (if active)
    if let Some(panel) = &app.zoomed_panel {
        let zoom_area = centered_rect(90, 90, frame.area());
        crate::ui::helpers::clear_area(frame, zoom_area);

        match panel {
            FocusedPanel::Sidebar => sidebar::render(frame, app, zoom_area),
            FocusedPanel::ConnectionDetails => {
                render_animated_panel(frame, app, panel, zoom_area, |f, a, r| {
                    connection_details::render(f, a, r);
                });
            }
            FocusedPanel::Chart => {
                render_animated_panel(frame, app, panel, zoom_area, |f, a, r| {
                    chart::render(f, a, r);
                });
            }
            FocusedPanel::Security => {
                render_animated_panel(frame, app, panel, zoom_area, |f, a, r| {
                    security::render(f, a, r);
                });
            }
            FocusedPanel::Logs => logs::render(frame, app, zoom_area),
        }
    }
}

/// Compute a horizontally-narrowed rect for the card-flip animation.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn animated_rect(area: Rect, width_ratio: f32) -> Rect {
    if area.width == 0 || area.height == 0 {
        return area;
    }
    let mut new_width = (f32::from(area.width) * width_ratio).max(1.0) as u16;
    if new_width > area.width {
        new_width = area.width;
    }
    let x_offset = (area.width.saturating_sub(new_width)) / 2;
    Rect::new(area.x + x_offset, area.y, new_width, area.height)
}

/// Render a panel with optional flip animation (horizontal card-flip effect).
fn render_animated_panel(
    frame: &mut Frame,
    app: &App,
    panel: &FocusedPanel,
    area: Rect,
    render_fn: impl FnOnce(&mut Frame, &App, Rect),
) {
    if let Some(state) = app.flip_states.get(panel) {
        if state.is_animating() {
            crate::ui::helpers::clear_area(frame, area);
            let narrow = animated_rect(area, state.width_ratio());
            if narrow.width >= constants::FLIP_ANIMATION_MIN_WIDTH {
                render_fn(frame, app, narrow);
            } else {
                let edge = Paragraph::new(Line::from(Span::raw("│"))).alignment(Alignment::Center);
                frame.render_widget(edge, narrow);
            }
            return;
        }
    }
    render_fn(frame, app, area);
}

fn render_overlays(frame: &mut Frame, app: &mut App) {
    match &app.input_mode {
        InputMode::Import { path, cursor } => {
            super::overlays::import::render(frame, path, *cursor);
        }
        InputMode::ConfirmDelete {
            name,
            confirm_selected,
            ..
        } => render_delete_confirm(frame, name, *confirm_selected),
        InputMode::AuthPrompt {
            profile_name,
            username,
            username_cursor,
            password,
            password_cursor,
            otp,
            otp_cursor,
            focused_field,
            save_credentials,
            connect_after,
            reveal_secrets,
            static_challenge_prompt,
            ..
        } => super::overlays::auth::render(
            frame,
            profile_name,
            username,
            *username_cursor,
            password,
            *password_cursor,
            otp,
            *otp_cursor,
            focused_field,
            *save_credentials,
            *connect_after,
            static_challenge_prompt.as_deref(),
            *reveal_secrets,
        ),
        InputMode::Rename {
            new_name, cursor, ..
        } => super::overlays::rename::render(frame, new_name, *cursor),
        InputMode::Help { scroll, tab } => super::overlays::help::render(frame, *scroll, *tab),
        InputMode::Search { query, cursor } => {
            super::overlays::search::render(frame, app, query, *cursor, app.runtime.profiles.len());
        }
        InputMode::ConfirmDefaultRouteTakeover {
            from,
            to_name,
            confirm_selected,
            ..
        } => render_default_route_takeover_confirm(frame, from, to_name, *confirm_selected),
        InputMode::ConfirmRouteOverlap {
            with_profile_id,
            overlapping_cidrs,
            to_name,
            confirm_selected,
            ..
        } => render_route_overlap_confirm(
            frame,
            app,
            with_profile_id,
            overlapping_cidrs,
            to_name,
            *confirm_selected,
        ),
        InputMode::ConfirmDisconnectAll {
            count,
            confirm_selected,
        } => render_disconnect_all_confirm(frame, *count, *confirm_selected),
        InputMode::Normal => {}
    }

    if app.show_config {
        super::overlays::config_viewer::render(frame, app);
    }

    if app.show_action_menu || app.show_bulk_menu {
        let (actions, title) = if app.show_bulk_menu {
            (message::get_bulk_actions(), " Bulk Actions ")
        } else {
            (message::get_single_actions(&app.focused_panel), " Actions ")
        };

        super::overlays::action_menu::render(frame, &actions, &mut app.action_menu_state, title);
    }
}

/// The overlay confirming a profile deletion.
fn render_delete_confirm(frame: &mut Frame, name: &str, confirm_selected: bool) {
    use super::overlays::confirm_dialog::{self, ConfirmDialogConfig};

    let dialog_w: u16 = 50;
    let prefix = "Are you sure you want to delete ";
    let name_budget = usize::from(dialog_w)
        .saturating_sub(4 + prefix.len() + 1)
        .max(3);
    let truncated = crate::ui::helpers::truncate_to_width(name, name_budget);

    confirm_dialog::render(
        frame,
        ConfirmDialogConfig {
            title: " Confirm Deletion ",
            body: vec![
                Line::from(""),
                Line::from(vec![
                    Span::raw(prefix),
                    Span::styled(
                        truncated,
                        Style::default()
                            .fg(theme::current().accent_primary)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("?"),
                ]),
            ],
            border_color: theme::current().error,
            confirm_selected,
            confirm_label: "Delete",
            width: dialog_w,
            height: 7,
        },
    );
}

/// The overlay confirming that every active tunnel should come down.
fn render_disconnect_all_confirm(frame: &mut Frame, count: usize, confirm_selected: bool) {
    use super::overlays::confirm_dialog::{self, ConfirmDialogConfig};

    // Shift+D from the sidebar
    // with N>1 active tunnels opens this confirm dialog before
    // tearing them all down.
    confirm_dialog::render(
        frame,
        ConfirmDialogConfig {
            title: " Disconnect All ",
            body: vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled(
                        "Disconnect all ",
                        Style::default().fg(theme::current().text_secondary),
                    ),
                    Span::styled(
                        count.to_string(),
                        Style::default()
                            .fg(theme::current().warning)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        " tunnels?",
                        Style::default().fg(theme::current().text_secondary),
                    ),
                ]),
            ],
            border_color: theme::current().warning,
            confirm_selected,
            confirm_label: "Disconnect all",
            width: 50,
            height: 7,
        },
    );
}

/// The overlay offering to hand the default route to another profile.
fn render_default_route_takeover_confirm(
    frame: &mut Frame,
    from: &str,
    to_name: &str,
    confirm_selected: bool,
) {
    use super::overlays::confirm_dialog::{self, ConfirmDialogConfig};

    // Both VPNs declare a default route (0.0.0.0/0), and only one can hold the
    // kernel default route at a time, so the two cannot both be the exit.
    // Switch (disconnect the old, connect the new) or cancel — there is no
    // "keep both" here; a second full-tunnel cannot coexist with the first.
    let inner_width = usize::from(
        64_u16
            .min(frame.area().width.saturating_sub(4))
            .saturating_sub(2),
    );
    let switch_from_width = inner_width.saturating_sub("[Y] Switch — disconnect ".width());
    let cancel_from_width = inner_width.saturating_sub("[Esc] Cancel — keep ".width());
    let switch_from = crate::ui::helpers::truncate_to_width(from, switch_from_width);
    let cancel_from = crate::ui::helpers::truncate_to_width(from, cancel_from_width);
    confirm_dialog::render(
        frame,
        ConfirmDialogConfig {
            title: " Already connected ",
            body: vec![
                Line::from(vec![
                    Span::styled(
                        crate::ui::helpers::truncate_to_width(to_name, inner_width),
                        Style::default().fg(theme::current().success),
                    ),
                    Span::styled(
                        " also wants to handle all",
                        Style::default().fg(theme::current().text_secondary),
                    ),
                ]),
                Line::from(vec![Span::styled(
                    "your internet traffic.",
                    Style::default().fg(theme::current().text_secondary),
                )]),
                Line::from(""),
                Line::from(vec![
                    Span::styled(
                        "[Y] Switch — disconnect ",
                        Style::default()
                            .fg(theme::current().warning)
                            .add_modifier(ratatui::style::Modifier::BOLD),
                    ),
                    Span::styled(
                        switch_from,
                        Style::default().fg(theme::current().accent_primary),
                    ),
                ]),
                Line::from(vec![
                    Span::styled(
                        "[Esc] Cancel — keep ",
                        Style::default().fg(theme::current().text_secondary),
                    ),
                    Span::styled(
                        cancel_from,
                        Style::default().fg(theme::current().accent_primary),
                    ),
                ]),
            ],
            border_color: theme::current().warning,
            confirm_selected,
            confirm_label: "Switch",
            width: 64,
            height: 10,
        },
    );
}

/// The overlay offering to drop a tunnel whose networks the new one needs.
fn render_route_overlap_confirm(
    frame: &mut Frame,
    app: &App,
    with_profile_id: &crate::profile::ProfileId,
    overlapping_cidrs: &[crate::cidr::Cidr],
    to_name: &str,
    confirm_selected: bool,
) {
    use super::overlays::confirm_dialog::{self, ConfirmDialogConfig};

    let inner_width = usize::from(
        56_u16
            .min(frame.area().width.saturating_sub(4))
            .saturating_sub(2),
    );
    let with_name = app
        .runtime
        .profiles
        .iter()
        .find(|profile| profile.id == *with_profile_id)
        .map_or_else(
            || format!("ProfileMissing:{with_profile_id}"),
            |profile| profile.name.clone(),
        );
    // Both names now share the first line as "<new> and <current>",
    // so they split one budget rather than each owning a line.
    let name_budget = inner_width.saturating_sub(" and ".width()) / 2;
    let with_t = crate::ui::helpers::truncate_to_width(&with_name, name_budget);
    let with_t2 = crate::ui::helpers::truncate_to_width(
        &with_name,
        inner_width.saturating_sub("connecting disconnects .".width()),
    );
    let to_t = crate::ui::helpers::truncate_to_width(to_name, name_budget);
    // Display up to two overlapping CIDRs inline; the rest collapse
    // into a "+N more" tail so a wide AllowedIPs set doesn't blow
    // the dialog height.
    let cidr_budget = inner_width.saturating_sub("both want to carry ".width());
    let cidr_summary = if overlapping_cidrs.is_empty() {
        String::from("(unknown)")
    } else if overlapping_cidrs.len() > 2 {
        let head = overlapping_cidrs
            .iter()
            .take(2)
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let tail = format!(", +{} more", overlapping_cidrs.len() - 2);
        format!(
            "{}{}",
            crate::ui::helpers::truncate_to_width(&head, cidr_budget.saturating_sub(tail.width())),
            tail
        )
    } else {
        let summary = overlapping_cidrs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        crate::ui::helpers::truncate_to_width(&summary, cidr_budget)
    };
    confirm_dialog::render(
        frame,
        ConfirmDialogConfig {
            // "Route Overlap" named the internal conflict kind, not
            // the user's situation, and the three fragments below it
            // never said what pressing Connect would do. The takeover
            // dialog next door already speaks plainly; this one says
            // the same three things it does — who is contending, over
            // what, and what happens next.
            title: " Already connected ",
            body: vec![
                Line::from(vec![
                    Span::styled(to_t, Style::default().fg(theme::current().success)),
                    Span::styled(
                        " and ",
                        Style::default().fg(theme::current().text_secondary),
                    ),
                    Span::styled(with_t, Style::default().fg(theme::current().accent_primary)),
                ]),
                Line::from(vec![
                    Span::styled(
                        "both want to carry ",
                        Style::default().fg(theme::current().text_secondary),
                    ),
                    Span::styled(cidr_summary, Style::default().fg(theme::current().warning)),
                ]),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "Only one tunnel can carry a network, so",
                    Style::default().fg(theme::current().text_secondary),
                )]),
                Line::from(vec![
                    Span::styled(
                        "connecting disconnects ",
                        Style::default().fg(theme::current().text_secondary),
                    ),
                    Span::styled(
                        with_t2,
                        Style::default().fg(theme::current().accent_primary),
                    ),
                    Span::styled(".", Style::default().fg(theme::current().text_secondary)),
                ]),
            ],
            border_color: theme::current().warning,
            confirm_selected,
            confirm_label: "Connect",
            width: 56,
            height: 10,
        },
    );
}

#[cfg(test)]
mod overlay_tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};

    #[test]
    fn takeover_dialog_offers_only_switch_or_cancel() {
        let mut app = App::new_test();
        app.input_mode = InputMode::ConfirmDefaultRouteTakeover {
            from: "existing-primary-profile-with-a-deliberately-long-name".to_string(),
            to_profile_id: crate::profile::ProfileId::new(
                "incoming-primary-profile-with-a-deliberately-long-name",
            ),
            to_name: "incoming-primary-profile-with-a-deliberately-long-name".to_string(),
            confirm_selected: true,
        };
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| render_overlays(frame, &mut app))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let output = buffer
            .content
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<String>();
        assert!(output.contains("existing-primary-profile"), "{output}");
        assert!(output.contains("incoming-primary-pro"), "{output}");
        assert!(output.contains("[Y] Switch — disconnect"), "{output}");
        assert!(output.contains("[Esc] Cancel — keep"), "{output}");
        // "Keep both" was removed: a second default-route tunnel cannot coexist.
        assert!(!output.contains("Keep both"), "{output}");
    }

    /// The overlap dialog used to read "Route Overlap / Connect X / Overlaps
    /// with Y / on 10.250.0.0/24?" — the internal conflict kind as a title,
    /// three fragments, and no statement of what confirming would do. The one
    /// fact that distinguishes it from a default-route takeover is that both
    /// VPNs stay connected, and it never said so.
    #[test]
    fn the_overlap_dialog_says_what_confirming_does() {
        let mut app = App::new_test();
        app.input_mode = InputMode::ConfirmRouteOverlap {
            with_profile_id: crate::profile::ProfileId::new("held"),
            overlapping_cidrs: vec!["10.250.0.0/24".parse().unwrap()],
            to_profile_id: crate::profile::ProfileId::new("incoming"),
            to_name: "wg07".to_string(),
            confirm_selected: true,
        };
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| render_overlays(frame, &mut app))
            .unwrap();
        let output = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<String>();

        assert!(
            !output.contains("Route Overlap"),
            "the title named an internal conflict kind, not the situation: {output}"
        );
        assert!(
            output.contains("both want to carry"),
            "the dialog must name what is actually contended: {output}"
        );
        assert!(
            output.contains("10.250.0.0/24"),
            "the contended network must be shown: {output}"
        );
        assert!(
            output.contains("connecting disconnects"),
            "the dialog must say the other tunnel stops: {output}"
        );
        assert!(
            !output.contains("Both stay connected"),
            "two profiles cannot carry the same network, so nothing may promise they do: {output}"
        );
    }

    #[test]
    fn overlap_dialog_keeps_long_ipv6_details_and_choices_within_bounds() {
        let mut app = App::new_test();
        let existing = crate::profile::ProfileId::new(
            "existing-profile-with-a-name-that-is-far-too-long-for-the-dialog",
        );
        app.input_mode = InputMode::ConfirmRouteOverlap {
            with_profile_id: existing,
            overlapping_cidrs: vec![
                "2001:db8:1234:5678:90ab:cdef:1234:5678/128"
                    .parse()
                    .unwrap(),
                "2001:db8:ffff:eeee:dddd:cccc:bbbb:aaaa/128"
                    .parse()
                    .unwrap(),
                "2001:db8:1::/64".parse().unwrap(),
                "2001:db8:2::/64".parse().unwrap(),
                "2001:db8:3::/64".parse().unwrap(),
            ],
            to_profile_id: crate::profile::ProfileId::new("incoming"),
            to_name: "incoming-profile-with-an-equally-long-human-readable-name".to_string(),
            confirm_selected: true,
        };
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| render_overlays(frame, &mut app))
            .unwrap();
        let output = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<String>();
        assert!(output.contains("..."), "{output}");
        assert!(output.contains("+3 more"), "{output}");
        assert!(output.contains("[Y] Connect"), "{output}");
        assert!(output.contains("[N] Cancel"), "{output}");
    }
}
