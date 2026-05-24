mod chart;
mod connection_details;
mod header;
mod logs;
mod security;
mod sidebar;

use super::helpers::centered_rect;
use crate::app::{App, FocusedPanel, InputMode};
use crate::{constants, message, theme, utils};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Clear, Paragraph},
    Frame,
};

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
                .style(Style::default().fg(theme::ACCENT_PRIMARY)),
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
    super::widgets::footer::render_dashboard(frame, app, chunks[2]);

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

    // Render Zoomed Panel Overlay (if active)
    if let Some(panel) = &app.zoomed_panel {
        let zoom_area = centered_rect(90, 90, frame.area());
        frame.render_widget(Clear, zoom_area);

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
fn animated_rect(area: Rect, width_ratio: f64) -> Rect {
    if area.width == 0 || area.height == 0 {
        return area;
    }
    let mut new_width = (f64::from(area.width) * width_ratio).max(1.0) as u16;
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
    if let Some(anim) = &app.flip_animation {
        if anim.panel == *panel {
            frame.render_widget(Clear, area);
            let ratio = anim.width_ratio();
            let narrow = animated_rect(area, ratio);
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

#[allow(clippy::too_many_lines)]
fn render_overlays(frame: &mut Frame, app: &mut App) {
    use super::overlays::confirm_dialog::{self, ConfirmDialogConfig};

    match &app.input_mode {
        InputMode::DependencyError { protocol, missing } => {
            super::overlays::dependency_alert::render(frame, *protocol, missing);
        }
        InputMode::PermissionDenied { action } => {
            super::overlays::permission_denied::render(frame, action);
        }
        InputMode::Import { path, cursor } => {
            super::overlays::import::render(frame, path, *cursor);
        }
        InputMode::ConfirmDelete {
            name,
            confirm_selected,
            ..
        } => {
            let dialog_w: u16 = 50;
            let prefix = "Are you sure you want to delete ";
            let name_budget = usize::from(dialog_w)
                .saturating_sub(4 + prefix.len() + 1)
                .max(3);
            let truncated = utils::truncate(name, name_budget);

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
                                    .fg(theme::ACCENT_PRIMARY)
                                    .add_modifier(Modifier::BOLD),
                            ),
                            Span::raw("?"),
                        ]),
                    ],
                    border_color: theme::ERROR,
                    confirm_selected: *confirm_selected,
                    width: dialog_w,
                    height: 7,
                },
            );
        }
        InputMode::AuthPrompt {
            profile_name,
            username,
            username_cursor,
            password,
            password_cursor,
            focused_field,
            save_credentials,
            connect_after,
            ..
        } => super::overlays::auth::render(
            frame,
            profile_name,
            username,
            *username_cursor,
            password,
            *password_cursor,
            focused_field,
            *save_credentials,
            *connect_after,
        ),
        InputMode::Rename {
            new_name, cursor, ..
        } => super::overlays::rename::render(frame, new_name, *cursor),
        InputMode::Help { scroll } => super::overlays::help::render(frame, *scroll),
        InputMode::Search { query, cursor } => {
            super::overlays::search::render(frame, app, query, *cursor, app.profiles.len());
        }
        InputMode::ConfirmSwitch {
            from,
            to_name,
            confirm_selected,
            ..
        } => {
            let max = 28;
            let from_t = utils::truncate(from, max);
            let to_t = utils::truncate(to_name, max);
            confirm_dialog::render(
                frame,
                ConfirmDialogConfig {
                    title: " Switch Profile ",
                    body: vec![
                        Line::from(vec![
                            Span::styled(
                                "Disconnect from ",
                                Style::default().fg(theme::TEXT_SECONDARY),
                            ),
                            Span::styled(from_t, Style::default().fg(theme::ACCENT_PRIMARY)),
                        ]),
                        Line::from(vec![
                            Span::styled(
                                "and connect to ",
                                Style::default().fg(theme::TEXT_SECONDARY),
                            ),
                            Span::styled(to_t, Style::default().fg(theme::SUCCESS)),
                            Span::styled("?", Style::default().fg(theme::TEXT_SECONDARY)),
                        ]),
                    ],
                    border_color: theme::WARNING,
                    confirm_selected: *confirm_selected,
                    width: 50,
                    height: 7,
                },
            );
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
