use crate::app::{App, ConnectionState, InputMode, Protocol};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        canvas::{Canvas, Line as CanvasLine},
        Block, Borders, Cell, Clear, Paragraph, Row, Table,
    },
    Frame,
};

use super::widgets;
use crate::theme;

/// Render the dashboard view
pub fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.area();

    // 1. Technical Header (1 row)
    // 2. Main Content (Flexible)
    // 3. Command Footer (1 row)
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(area);

    render_cockpit_header(frame, app, chunks[0]);
    widgets::footer::render_dashboard(frame, app, chunks[2]);

    // Main Content: Left Sidebar (Profiles) | Right Workspace
    let main_layout = Layout::horizontal([Constraint::Percentage(25), Constraint::Percentage(75)])
        .split(chunks[1]);

    // Sidebar: Profiles (Top) | Details (Bottom)
    let sidebar_layout = Layout::vertical([Constraint::Percentage(65), Constraint::Percentage(35)])
        .split(main_layout[0]);

    render_profiles_sidebar(frame, app, sidebar_layout[0]);
    render_connection_details(frame, app, sidebar_layout[1]);

    // Right Workspace: Top (Chart) | Bottom (Stats + Logs)
    let workspace_chunks =
        Layout::vertical([Constraint::Percentage(65), Constraint::Percentage(35)])
            .split(main_layout[1]);

    render_throughput_chart(frame, app, workspace_chunks[0]);

    // Bottom Dash: Left (Security Guard) | Right (Event Log)
    let dash_chunks = Layout::horizontal([
        Constraint::Percentage(45), // Increased from 40% to prevent overflow
        Constraint::Percentage(55),
    ])
    .split(workspace_chunks[1]);

    render_security_guard(frame, app, dash_chunks[0]);
    render_activity_log(frame, app, dash_chunks[1]);

    // Overlays still take priority
    match &app.input_mode {
        InputMode::DependencyError { protocol, missing } => {
            render_dependency_alert(frame, *protocol, missing);
        }
        InputMode::PermissionDenied { action } => render_permission_denied(frame, action),
        InputMode::Import { path } => render_import_overlay(frame, path),
        InputMode::ConfirmDelete { name, .. } => render_delete_confirm(frame, name),
        _ => {}
    }

    if app.show_help {
        super::overlays::help::render(frame, app);
    }
}

fn render_import_overlay(frame: &mut Frame, path: &str) {
    let area = frame.area();
    let popup_layout = Layout::vertical([
        Constraint::Percentage(30),
        Constraint::Percentage(40),
        Constraint::Percentage(30),
    ])
    .split(area);

    let popup_area = Layout::horizontal([
        Constraint::Percentage(15),
        Constraint::Percentage(70),
        Constraint::Percentage(15),
    ])
    .split(popup_layout[1])[1];

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::ACCENT_PRIMARY))
        .title(" Import VPN Profile ")
        .title_bottom(Line::from(" [Enter] Import  [Esc] Cancel ").centered());

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            "Enter path to your VPN config file:",
            Style::default().fg(Color::White),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" > ", Style::default().fg(Color::DarkGray)),
            Span::styled(path, Style::default().fg(Color::White)),
            Span::styled(
                "█",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::SLOW_BLINK),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Supported formats:",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(vec![
            Span::styled("  .conf", Style::default().fg(Color::Magenta)),
            Span::styled(" → WireGuard", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled("  .ovpn", Style::default().fg(Color::Yellow)),
            Span::styled(" → OpenVPN", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Example: ~/Downloads/my-vpn.conf",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    frame.render_widget(Paragraph::new(text).alignment(Alignment::Left), inner);
}

fn render_cockpit_header(frame: &mut Frame, app: &App, area: Rect) {
    let (status_text, color, profile_name, _location, since) = match &app.connection_state {
        ConnectionState::Disconnected => ("○ DISCONNECTED", theme::ERROR, "None", "None", None),
        ConnectionState::Connecting { profile, .. } => (
            "◐ CONNECTING",
            theme::WARNING,
            profile.as_str(),
            "...",
            None,
        ),
        ConnectionState::Connected {
            profile,
            server_location,
            since,
            ..
        } => (
            "● CONNECTED",
            theme::SUCCESS,
            profile.as_str(),
            server_location.as_str(),
            Some(*since),
        ),
    };

    let uptime = if let Some(s) = since {
        crate::utils::format_duration(s.elapsed())
    } else {
        "00:00:00".to_string()
    };

    let protocol = if matches!(app.connection_state, ConnectionState::Disconnected) {
        "Idle".to_string()
    } else {
        app.profiles
            .iter()
            .find(|p| p.name == profile_name)
            .map_or_else(|| "UDP/WireGuard".to_string(), |p| p.protocol.to_string())
    };

    let line = Line::from(vec![
        Span::styled(
            format!(" VORTIX v{} ", env!("CARGO_PKG_VERSION")),
            Style::default()
                .fg(theme::ACCENT_SECONDARY)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
        Span::raw("Status: "),
        Span::styled(
            status_text,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(" ({profile_name})")),
        Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
        Span::raw("IP: "),
        Span::styled(&app.public_ip, Style::default().fg(theme::TEXT_PRIMARY)),
        Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
        Span::raw("Protocol: "),
        Span::styled(protocol, Style::default().fg(theme::NORD_GREEN)),
        Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
        Span::raw("Uptime: "),
        Span::styled(uptime, Style::default().fg(theme::ACCENT_SECONDARY)),
    ]);

    frame.render_widget(Paragraph::new(line), area);
}

fn render_profiles_sidebar(frame: &mut Frame, app: &mut App, area: Rect) {
    let is_focused = matches!(app.focused_panel, crate::app::FocusedPanel::Sidebar);
    let border_style = if is_focused {
        Style::default().fg(theme::BORDER_FOCUSED)
    } else {
        Style::default().fg(theme::BORDER_DEFAULT)
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(" Profiles ");

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.profiles.is_empty() {
        frame.render_widget(
            Paragraph::new("No profiles found").alignment(Alignment::Center),
            inner,
        );
        return;
    }

    let active_profile = match &app.connection_state {
        ConnectionState::Connected { profile, .. }
        | ConnectionState::Connecting { profile, .. } => Some(profile.clone()),
        ConnectionState::Disconnected => None,
    };

    let items: Vec<Row> = app
        .profiles
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let is_selected = app.profile_list_state.selected() == Some(i);
            let is_active = active_profile.as_ref() == Some(&p.name);

            // 1. Index (1, 2, 3...)
            let index = format!("{}.", i + 1);

            // 2. Protocol Icon
            let proto = match p.protocol {
                crate::app::Protocol::WireGuard => "WG",
                crate::app::Protocol::OpenVPN => "OV",
            };

            // 3. Status Indicator (Simple)
            let status_char = if is_active { "●" } else { " " };

            let spans = vec![
                Span::styled(
                    format!("{index:>3} "),
                    Style::default().fg(theme::NORD_POLAR_NIGHT_4),
                ),
                Span::styled(
                    status_char,
                    if is_active {
                        Style::default().fg(theme::SUCCESS)
                    } else {
                        Style::default()
                    },
                ),
                Span::raw(" "),
                Span::styled(
                    format!("[{proto}] "),
                    Style::default().fg(theme::ACCENT_SECONDARY),
                ),
                Span::raw(&p.name),
            ];

            let style = if is_selected {
                Style::default()
                    .bg(theme::ROW_SELECTED_BG)
                    .fg(theme::ROW_SELECTED_FG)
                    .add_modifier(Modifier::BOLD)
            } else if is_active {
                Style::default().fg(theme::SUCCESS)
            } else {
                Style::default().fg(theme::INACTIVE)
            };

            Row::new(vec![Cell::from(Line::from(spans))]).style(style)
        })
        .collect();

    let table = Table::new(items, [Constraint::Min(0)]);
    frame.render_stateful_widget(table, inner, &mut app.profile_list_state);
}

fn render_throughput_chart(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER_DEFAULT))
        .title(" Network Throughput ");

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Layout: Stats (Top) | Chart (Bottom)
    let chunks = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(inner);

    // 1. Render Numeric Stats (Top row)
    let stats_line = Line::from(vec![
        Span::styled(" ▲ UP: ", Style::default().fg(theme::NORD_GREEN)),
        Span::styled(
            format!("{:<10}", crate::utils::format_bytes_speed(app.current_up)),
            Style::default().fg(theme::TEXT_PRIMARY),
        ),
        Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
        Span::styled(" ▼ DOWN: ", Style::default().fg(theme::NORD_FROST_2)),
        Span::styled(
            format!("{:<10}", crate::utils::format_bytes_speed(app.current_down)),
            Style::default().fg(theme::TEXT_PRIMARY),
        ),
        Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
        Span::styled(" ⇌ PING: ", Style::default().fg(theme::TEXT_SECONDARY)),
        Span::styled(
            format!("{}ms", app.latency_ms),
            Style::default().fg(theme::TEXT_PRIMARY),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(stats_line).alignment(Alignment::Center),
        chunks[0],
    );

    // Peak detection for dynamic Y-axis scaling
    let max_down = app.down_history.iter().map(|(_, y)| *y).fold(0.0, f64::max);
    let max_up = app.up_history.iter().map(|(_, y)| *y).fold(0.0, f64::max);
    let peak = (max_down.max(max_up) * 1.2).max(1024.0 * 1024.0 * 0.5);

    let canvas = Canvas::default()
        .block(Block::default())
        .x_bounds([0.0, 60.0])
        .y_bounds([0.0, peak])
        .paint(|ctx| {
            // Draw Streams
            for i in 0..app.down_history.len() - 1 {
                ctx.draw(&CanvasLine {
                    x1: app.down_history[i].0,
                    y1: app.down_history[i].1,
                    x2: app.down_history[i + 1].0,
                    y2: app.down_history[i + 1].1,
                    color: theme::ACCENT_PRIMARY, // Frost Blue
                });
            }
            for i in 0..app.up_history.len() - 1 {
                ctx.draw(&CanvasLine {
                    x1: app.up_history[i].0,
                    y1: app.up_history[i].1,
                    x2: app.up_history[i + 1].0,
                    y2: app.up_history[i + 1].1,
                    color: theme::SUCCESS, // Aurora Green
                });
            }

            // Peak Label
            ctx.print(
                0.0,
                peak,
                Span::styled(
                    format!("{:.1} MB/s", peak / 1024.0 / 1024.0),
                    Style::default().fg(theme::NORD_POLAR_NIGHT_4),
                ),
            );
        });

    frame.render_widget(canvas, chunks[1]);
}

fn render_security_guard(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER_DEFAULT))
        .title(" Security Guard ");

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // 1. Security Logic
    let is_connected = !matches!(app.connection_state, ConnectionState::Disconnected);
    let ipv6_leaking = app.ipv6_leak;

    // DNS is "leaking" if it's pointing to a home router while we think we are on VPN
    let dns_leaking = app.dns_server.starts_with("192.168.") || app.dns_server.starts_with("172.1");

    let (heartbeat, heartbeat_color, status_msg) = if !is_connected {
        (" EXPOSED ", theme::WARNING, "Unsecured")
    } else if ipv6_leaking || dns_leaking {
        (" VULNERABLE ", theme::ERROR, "Risk Found")
    } else {
        (" SECURE ", theme::SUCCESS, "Protected")
    };

    // 2. Human-Readable Status Lines
    let mut audit = vec![
        Line::from(vec![
            Span::styled(
                heartbeat,
                Style::default()
                    .bg(heartbeat_color)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" - {status_msg}")),
        ]),
        Line::from(""),
    ];

    if is_connected {
        // Active Audit Mode: Technical Details
        audit.extend(vec![
            Line::from(vec![
                Span::styled("  Node : ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(&app.isp, Style::default().fg(theme::TEXT_PRIMARY)),
            ]),
            Line::from(vec![
                Span::styled("  DNS  : ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(
                    if dns_leaking { "EXPOSED" } else { "SECURE" },
                    Style::default().fg(if dns_leaking {
                        theme::ERROR
                    } else {
                        theme::ACCENT_SECONDARY
                    }),
                ),
            ]),
            Line::from(vec![
                Span::styled("  IPv6 : ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(
                    if ipv6_leaking { "LEAKING" } else { "SECURE" },
                    Style::default().fg(if ipv6_leaking {
                        theme::ERROR
                    } else {
                        theme::SUCCESS
                    }),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Enc  : ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled("ACTIVE", Style::default().fg(theme::SUCCESS)),
                Span::styled(
                    format!(" [{}]", app.cipher.chars().take(8).collect::<String>()),
                    Style::default().fg(theme::NORD_POLAR_NIGHT_4),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Hash : ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(&app.handshake, Style::default().fg(theme::ACCENT_SECONDARY)),
            ]),
        ]);
    } else {
        // Awareness Mode: Educational Warning
        audit.extend(vec![
            Line::from(Span::styled(
                "  Connection is UNENCRYPTED.",
                Style::default().fg(Color::Rgb(180, 180, 180)),
            )),
            Line::from(Span::styled(
                "  Your IP/traffic is visible.",
                Style::default().fg(Color::Rgb(180, 180, 180)),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    "  💡 TIP: ",
                    Style::default()
                        .fg(theme::ACCENT_SECONDARY)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "Select a profile & [Enter].",
                    Style::default().fg(theme::INACTIVE),
                ),
            ]),
        ]);
    }

    frame.render_widget(Paragraph::new(audit), inner);
}

fn render_dependency_alert(frame: &mut Frame, protocol: Protocol, missing: &[String]) {
    let area = frame.area();
    let popup_layout = Layout::vertical([
        Constraint::Percentage(25),
        Constraint::Percentage(50),
        Constraint::Percentage(25),
    ])
    .split(area);

    let popup_area = Layout::horizontal([
        Constraint::Percentage(25),
        Constraint::Percentage(50),
        Constraint::Percentage(25),
    ])
    .split(popup_layout[1])[1];

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red))
        .title(" System Dependency Missing ");

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let chunks = Layout::vertical([
        Constraint::Min(0),
        Constraint::Length(8),
        Constraint::Min(0),
    ])
    .split(inner);

    let pkg = if protocol == Protocol::WireGuard {
        "wireguard-tools"
    } else {
        "openvpn"
    };

    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " ERROR: ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "Missing system tools required for {protocol} sessions."
            )),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw(" Missing: "),
            Span::styled(missing.join(", "), Style::default().fg(Color::Yellow)),
        ]),
        Line::from(""),
        Line::from(vec![Span::raw(
            " To fix this, please run the following in your terminal:",
        )]),
        Line::from(vec![Span::styled(
            format!(" brew install {pkg}"),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::raw(" Press "),
            Span::styled(
                "[Esc]",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" to return to dashboard."),
        ]),
    ];

    frame.render_widget(Paragraph::new(text).alignment(Alignment::Center), chunks[1]);
}

fn render_permission_denied(frame: &mut Frame, action: &str) {
    let area = frame.area();
    let popup_layout = Layout::vertical([
        Constraint::Percentage(25),
        Constraint::Percentage(50),
        Constraint::Percentage(25),
    ])
    .split(area);

    let popup_area = Layout::horizontal([
        Constraint::Percentage(25),
        Constraint::Percentage(50),
        Constraint::Percentage(25),
    ])
    .split(popup_layout[1])[1];

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red))
        .title(" Elevated Privileges Required ");

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let chunks = Layout::vertical([
        Constraint::Min(0),
        Constraint::Length(8),
        Constraint::Min(0),
    ])
    .split(inner);

    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " ACCESS DENIED: ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("Vortix needs root privileges to {action}.")),
        ]),
        Line::from(""),
        Line::from(vec![Span::raw(
            " VPN management involves modifying network interfaces and routes,",
        )]),
        Line::from(vec![Span::raw(" which is a privileged system operation.")]),
        Line::from(""),
        Line::from(vec![
            Span::raw(" Recommendation: Restart Vortix with "),
            Span::styled(
                "sudo vortix",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw(" Press "),
            Span::styled(
                "[Esc]",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" to return to dashboard."),
        ]),
    ];

    frame.render_widget(Paragraph::new(text).alignment(Alignment::Center), chunks[1]);
}

fn render_delete_confirm(frame: &mut Frame, name: &str) {
    let area = frame.area();
    let popup_layout = Layout::vertical([
        Constraint::Percentage(40),
        Constraint::Percentage(20),
        Constraint::Percentage(40),
    ])
    .split(area);

    let popup_area = Layout::horizontal([
        Constraint::Percentage(25),
        Constraint::Percentage(50),
        Constraint::Percentage(25),
    ])
    .split(popup_layout[1])[1];

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::ERROR))
        .title(" Confirm Deletion ");

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("Are you sure you want to delete "),
            Span::styled(
                name,
                Style::default()
                    .fg(theme::ACCENT_PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("?"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " [Y] Yes, Delete ",
                Style::default()
                    .fg(theme::ERROR)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("    "),
            Span::styled(
                " [N] Cancel ",
                Style::default().fg(theme::NORD_POLAR_NIGHT_4),
            ),
        ]),
    ];

    frame.render_widget(Paragraph::new(text).alignment(Alignment::Center), inner);
}

fn render_activity_log(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = matches!(app.focused_panel, crate::app::FocusedPanel::Logs);
    let border_style = if is_focused {
        Style::default().fg(theme::BORDER_FOCUSED)
    } else {
        Style::default().fg(theme::BORDER_DEFAULT)
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(" Event Log ");

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.logs.is_empty() {
        frame.render_widget(
            Paragraph::new("No activity yet").alignment(Alignment::Center),
            inner,
        );
        return;
    }

    let logs: Vec<Line> = app
        .logs
        .iter()
        .map(|msg| {
            let (timestamp, content) = if let Some(idx) = msg.find(' ') {
                (&msg[..idx], &msg[idx + 1..])
            } else {
                ("", msg.as_str())
            };

            let style = if content.contains("Error") || content.contains("Failed") {
                Style::default().fg(theme::ERROR)
            } else if content.contains("Connected") || content.contains("SUCCESS") {
                Style::default().fg(theme::SUCCESS)
            } else if content.contains("Starting") || content.contains("Initiated") {
                Style::default().fg(theme::ACCENT_SECONDARY)
            } else if content.contains("WARN") || content.contains("spike") {
                Style::default().fg(theme::WARNING)
            } else {
                Style::default().fg(theme::INACTIVE)
            };

            Line::from(vec![
                Span::styled(
                    format!("[{timestamp} ] "),
                    Style::default().fg(theme::TEXT_SECONDARY),
                ),
                Span::styled(content, style),
            ])
        })
        .collect();

    #[allow(clippy::cast_possible_truncation)]
    let scroll_offset = if app.logs_auto_scroll {
        logs.len().saturating_sub(inner.height as usize) as u16
    } else {
        app.logs_scroll
    };

    frame.render_widget(
        Paragraph::new(logs)
            .wrap(ratatui::widgets::Wrap { trim: true })
            .scroll((scroll_offset, 0)),
        inner,
    );
}

// === Helper Utilities ===

fn render_connection_details(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER_DEFAULT))
        .title(" Connection Details ");

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if let ConnectionState::Connected { details, .. } = &app.connection_state {
        let text = vec![
            Line::from(vec![
                Span::styled("Int. IP    : ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(
                    &details.internal_ip,
                    Style::default()
                        .fg(theme::ACCENT_PRIMARY)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Endpoint   : ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(
                    crate::utils::truncate(&details.endpoint, 20),
                    Style::default().fg(theme::TEXT_PRIMARY),
                ),
            ]),
            Line::from(vec![
                Span::styled("Handshake  : ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(
                    crate::utils::truncate(&details.latest_handshake, 25),
                    Style::default().fg(theme::NORD_YELLOW),
                ),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "Session Data:",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
            Line::from(vec![
                Span::styled("  ↓ ", Style::default().fg(theme::NORD_FROST_3)), // Blueish
                Span::styled(
                    &details.transfer_rx,
                    Style::default().fg(theme::TEXT_PRIMARY),
                ),
                Span::styled("   ↑ ", Style::default().fg(theme::NORD_GREEN)), // Greenish
                Span::styled(
                    &details.transfer_tx,
                    Style::default().fg(theme::TEXT_PRIMARY),
                ),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("MTU        : ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(&details.mtu, Style::default().fg(theme::TEXT_PRIMARY)),
            ]),
            Line::from(vec![
                Span::styled("Listen Port: ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(
                    &details.listen_port,
                    Style::default().fg(theme::TEXT_PRIMARY),
                ),
            ]),
            Line::from(vec![
                Span::styled("Public Key : ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(
                    crate::utils::truncate(&details.public_key, 12),
                    Style::default().fg(theme::NORD_POLAR_NIGHT_4),
                ),
            ]),
        ];

        frame.render_widget(Paragraph::new(text), inner);
    } else {
        frame.render_widget(
            Paragraph::new("No active connection")
                .alignment(Alignment::Center)
                .style(Style::default().fg(theme::INACTIVE)),
            inner,
        );
    }
}
