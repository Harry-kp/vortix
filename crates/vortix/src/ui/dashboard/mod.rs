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
        InputMode::ConfirmSwitch {
            current_id,
            to_name,
            shared,
            confirm_selected,
            ..
        } => render_switch_confirm(frame, app, current_id, shared, to_name, *confirm_selected),
        InputMode::ConfirmDisconnectAll {
            count,
            confirm_selected,
        } => render_disconnect_all_confirm(frame, *count, *confirm_selected),
        InputMode::WhatsNew { from, scroll } => {
            super::overlays::whats_new::render(frame, from, *scroll);
        }
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

/// The dialog offering to switch to a profile that conflicts with a running
/// tunnel: both want all traffic, or both want the same networks.
fn render_switch_confirm(
    frame: &mut Frame,
    app: &App,
    current_id: &crate::profile::ProfileId,
    shared: &[crate::cidr::Cidr],
    to_name: &str,
    confirm_selected: bool,
) {
    use super::overlays::confirm_dialog::{self, ConfirmDialogConfig};

    let inner_width = usize::from(
        64_u16
            .min(frame.area().width.saturating_sub(4))
            .saturating_sub(2),
    );
    let current = app.profile_display_name(current_id);
    let fit = |text: &str, prefix: &str| {
        crate::ui::helpers::truncate_to_width(text, inner_width.saturating_sub(prefix.width()))
    };
    let muted = Style::default().fg(theme::current().text_secondary);
    // Up to two networks inline; the rest collapse into "+N more".
    let what = if shared.is_empty() {
        "all your internet traffic.".to_owned()
    } else {
        let head = shared
            .iter()
            .take(2)
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let tail = if shared.len() > 2 {
            format!(", +{} more", shared.len() - 2)
        } else {
            String::new()
        };
        format!("{}{tail}", fit(&head, &tail))
    };
    let to_line = if shared.is_empty() {
        " also wants to handle"
    } else {
        " also wants to carry"
    };
    confirm_dialog::render(
        frame,
        ConfirmDialogConfig {
            title: " Already connected ",
            body: vec![
                Line::from(vec![
                    Span::styled(
                        fit(to_name, to_line),
                        Style::default().fg(theme::current().success),
                    ),
                    Span::styled(to_line, muted),
                ]),
                Line::from(Span::styled(
                    what,
                    if shared.is_empty() {
                        muted
                    } else {
                        Style::default().fg(theme::current().warning)
                    },
                )),
                Line::from(""),
                Line::from(vec![
                    Span::styled(
                        "[Y] Switch — disconnect ",
                        Style::default()
                            .fg(theme::current().warning)
                            .add_modifier(ratatui::style::Modifier::BOLD),
                    ),
                    Span::styled(
                        fit(&current, "[Y] Switch — disconnect "),
                        Style::default().fg(theme::current().accent_primary),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("[Esc] Cancel — keep ", muted),
                    Span::styled(
                        fit(&current, "[Esc] Cancel — keep "),
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

#[cfg(test)]
mod overlay_tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};

    fn render(app: &mut App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| render_overlays(frame, app)).unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect()
    }

    fn switch(current: &str, to: &str, shared: Vec<crate::cidr::Cidr>) -> InputMode {
        InputMode::ConfirmSwitch {
            current_id: crate::profile::ProfileId::new(current),
            to_profile_id: crate::profile::ProfileId::new(to),
            to_name: to.to_string(),
            shared,
            confirm_selected: true,
        }
    }

    #[test]
    fn a_full_tunnel_conflict_offers_only_switch_or_cancel() {
        let mut app = App::new_test();
        app.input_mode = switch(
            "existing-primary-profile-with-a-deliberately-long-name",
            "incoming-primary-profile-with-a-deliberately-long-name",
            Vec::new(),
        );
        let output = render(&mut app);
        assert!(output.contains("existing-primary"), "{output}");
        assert!(output.contains("incoming-primary"), "{output}");
        assert!(output.contains("all your internet traffic"), "{output}");
        assert!(output.contains("[Y] Switch — disconnect"), "{output}");
        assert!(output.contains("[Esc] Cancel — keep"), "{output}");
        assert!(!output.contains("Keep both"), "{output}");
    }

    /// Both conflicts are the same choice, so they share one dialog; only the
    /// line saying what is contended differs.
    #[test]
    fn a_network_conflict_names_the_networks_in_the_same_dialog() {
        let mut app = App::new_test();
        app.input_mode = switch("held", "wg07", vec!["10.250.0.0/24".parse().unwrap()]);
        let output = render(&mut app);
        assert!(output.contains("also wants to carry"), "{output}");
        assert!(output.contains("10.250.0.0/24"), "{output}");
        assert!(output.contains("[Y] Switch — disconnect"), "{output}");
        assert!(output.contains("[Esc] Cancel — keep"), "{output}");
        assert!(!output.contains("Route Overlap"), "{output}");
    }

    #[test]
    fn long_names_and_many_networks_stay_within_the_dialog() {
        let mut app = App::new_test();
        app.input_mode = switch(
            "existing-profile-with-a-name-that-is-far-too-long-for-the-dialog",
            "incoming-profile-with-an-equally-long-human-readable-name",
            [
                "2001:db8:1234:5678:90ab:cdef:1234:5678/128",
                "2001:db8:ffff:eeee:dddd:cccc:bbbb:aaaa/128",
                "2001:db8:1::/64",
                "2001:db8:2::/64",
                "2001:db8:3::/64",
            ]
            .iter()
            .map(|cidr| cidr.parse().unwrap())
            .collect(),
        );
        let output = render(&mut app);
        assert!(output.contains("..."), "{output}");
        assert!(output.contains("+3 more"), "{output}");
        assert!(output.contains("[Y] Switch"), "{output}");
        assert!(output.contains("[N] Cancel"), "{output}");
    }
}
