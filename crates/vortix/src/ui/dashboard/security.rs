use crate::app::{App, ConnectionState};
use crate::{constants, theme, utils};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

#[allow(clippy::too_many_lines)]
pub(super) fn render(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.should_draw_focus(&crate::app::FocusedPanel::Security);
    let border_style = if is_focused {
        Style::default().fg(theme::BORDER_FOCUSED)
    } else {
        Style::default().fg(theme::BORDER_DEFAULT)
    };

    if app.effective_flipped(&crate::app::FocusedPanel::Security) {
        render_back(frame, app, area, border_style);
        return;
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(" Security Guard ");

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Security checks
    let is_connected = !matches!(app.connection_state, ConnectionState::Disconnected);
    let ipv6_leaking = app.ipv6_leak;

    if !is_connected {
        // Disconnected state - show warning
        let audit = vec![
            Line::from(vec![Span::styled(
                " ⚠ EXPOSED ",
                Style::default()
                    .bg(theme::WARNING)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(""),
            Line::from(Span::styled(
                "Your traffic is unencrypted.",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
            Line::from(Span::styled(
                "Connect to a VPN profile.",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
        ];
        frame.render_widget(Paragraph::new(audit), inner);
        return;
    }

    // DNS leak: if current DNS matches the pre-VPN DNS, queries may not be tunneled.
    // A changed DNS (even private like 10.8.0.1) means the VPN pushed its own resolver.
    let dns_leaking = match &app.real_dns {
        Some(real_dns) => &app.dns_server == real_dns,
        None => false, // can't determine yet, assume OK
    };

    // Check if IP is actually masked (different from real IP captured when disconnected)
    let ip_status = match &app.real_ip {
        Some(real)
            if !app.public_ip.is_empty()
                && app.public_ip != constants::MSG_DETECTING
                && app.public_ip != constants::MSG_FETCHING
                && !app.public_ip.starts_with("Error") =>
        {
            if &app.public_ip == real {
                (false, true, Some(real.clone())) // LEAK! same IP as real
            } else {
                (true, false, Some(real.clone())) // masked (different IP)
            }
        }
        _ => (false, false, None), // unknown (still checking)
    };
    let (ip_masked, ip_leaking, real_ip_opt) = ip_status;

    // Get encryption info from connection details
    let encryption_info = match &app.connection_state {
        ConnectionState::Connected { details, .. } => {
            if details.public_key == "OpenVPN" || details.public_key.is_empty() {
                // OpenVPN
                if details.latest_handshake.starts_with("Cipher:") {
                    details.latest_handshake.replace("Cipher: ", "")
                } else {
                    "AES-256-GCM".to_string()
                }
            } else {
                // WireGuard
                "ChaCha20-Poly1305".to_string()
            }
        }
        _ => "N/A".to_string(),
    };

    // Security checklist with pass/fail indicators
    let check_pass = Span::styled("✓ ", Style::default().fg(theme::SUCCESS));
    let check_fail = Span::styled("✗ ", Style::default().fg(theme::ERROR));
    let check_warn = Span::styled("● ", Style::default().fg(theme::WARNING));

    // Truncate values to fit panel
    let max_val = inner.width.saturating_sub(15) as usize;

    let mut audit = vec![
        Line::from(vec![Span::styled(
            "   PROTECTED",
            Style::default()
                .fg(if ip_masked && !dns_leaking && !ipv6_leaking {
                    theme::SUCCESS
                } else {
                    theme::WARNING
                })
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
    ];

    // IP Masked - show both masked and real
    if let Some(real_ip) = real_ip_opt {
        audit.push(Line::from(vec![
            if ip_masked {
                check_pass.clone()
            } else if ip_leaking {
                check_fail.clone()
            } else {
                check_warn.clone()
            },
            Span::styled("IP Masked  : ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(
                utils::truncate(&app.public_ip, max_val),
                Style::default().fg(if ip_masked {
                    theme::SUCCESS
                } else {
                    theme::ERROR
                }),
            ),
        ]));
        audit.push(Line::from(vec![
            Span::styled("  Real IP: ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(
                format!("{real_ip} (hidden)"),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    } else {
        audit.push(Line::from(vec![
            check_warn.clone(),
            Span::styled("IP Masked  : ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled("Checking...", Style::default().fg(theme::WARNING)),
        ]));
    }

    audit.push(Line::from(""));

    // DNS Check with provider name if possible
    let dns_provider = if app.dns_server.contains("1.1.1.1") {
        " (Cloudflare)"
    } else if app.dns_server.contains("8.8.8.8") || app.dns_server.contains("8.8.4.4") {
        " (Google)"
    } else if app.dns_server.contains("9.9.9.9") {
        " (Quad9)"
    } else {
        ""
    };

    audit.push(Line::from(vec![
        if dns_leaking {
            check_fail.clone()
        } else {
            check_pass.clone()
        },
        Span::styled("DNS Secure : ", Style::default().fg(theme::TEXT_SECONDARY)),
        Span::styled(
            utils::truncate(&app.dns_server, max_val),
            Style::default().fg(if dns_leaking {
                theme::ERROR
            } else {
                theme::SUCCESS
            }),
        ),
    ]));
    if !dns_provider.is_empty() {
        audit.push(Line::from(vec![
            Span::styled("  Provider: ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(dns_provider, Style::default().fg(Color::DarkGray)),
        ]));
    }
    if let Some(real_dns) = &app.real_dns {
        if dns_leaking {
            let real_dns_display = format!("{real_dns} (same!)");
            audit.push(Line::from(vec![
                Span::styled("  Pre-VPN : ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(
                    utils::truncate(&real_dns_display, max_val),
                    Style::default().fg(theme::ERROR),
                ),
            ]));
        }
    }

    audit.push(Line::from(""));

    // IPv6 Check
    audit.push(Line::from(vec![
        if ipv6_leaking {
            check_fail.clone()
        } else {
            check_pass.clone()
        },
        Span::styled("IPv6       : ", Style::default().fg(theme::TEXT_SECONDARY)),
        Span::styled(
            if ipv6_leaking { "Leaking" } else { "Blocked" },
            Style::default().fg(if ipv6_leaking {
                theme::ERROR
            } else {
                theme::SUCCESS
            }),
        ),
    ]));

    audit.push(Line::from(""));

    // Kill Switch Status
    let (ks_icon, ks_text, ks_color) = match (app.killswitch_mode, app.killswitch_state) {
        (crate::state::KillSwitchMode::Off, _) => (check_fail.clone(), "Off", theme::INACTIVE),
        (_, crate::state::KillSwitchState::Blocking) => {
            (check_warn.clone(), "Blocking (Strict)", theme::ERROR)
        }
        (crate::state::KillSwitchMode::Auto, crate::state::KillSwitchState::Armed) => {
            (check_pass.clone(), "Armed (Auto)", theme::SUCCESS)
        }
        (crate::state::KillSwitchMode::AlwaysOn, crate::state::KillSwitchState::Armed) => {
            (check_pass.clone(), "Armed (Strict)", theme::WARNING)
        }
        _ => (check_warn.clone(), "Unknown", theme::WARNING),
    };

    audit.push(Line::from(vec![
        ks_icon,
        Span::styled("Kill Switch: ", Style::default().fg(theme::TEXT_SECONDARY)),
        Span::styled(ks_text, Style::default().fg(ks_color)),
    ]));

    audit.push(Line::from(""));

    // Encryption Info
    audit.push(Line::from(vec![
        check_pass,
        Span::styled("Encryption : ", Style::default().fg(theme::TEXT_SECONDARY)),
        Span::styled(encryption_info, Style::default().fg(theme::NORD_YELLOW)),
    ]));

    let last_checked_text = match app.last_security_check {
        Some(t) => {
            let secs = t.elapsed().as_secs();
            if secs < 5 {
                "Last checked: just now".to_string()
            } else if secs < 60 {
                format!("Last checked: {secs}s ago")
            } else {
                format!("Last checked: {}m ago", secs / 60)
            }
        }
        None => "Last checked: pending...".to_string(),
    };
    audit.push(Line::from(""));
    audit.push(Line::from(vec![Span::styled(
        last_checked_text,
        Style::default().fg(Color::DarkGray),
    )]));

    let available_height = inner.height as usize;
    if available_height > 0 && audit.len() > available_height {
        let mut compacted = Vec::with_capacity(available_height);
        let mut blank_budget = 2usize;

        for line in audit {
            let is_blank =
                line.spans.is_empty() || line.spans.iter().all(|s| s.content.trim().is_empty());
            if is_blank {
                if blank_budget == 0 {
                    continue;
                }
                blank_budget -= 1;
            }
            compacted.push(line);
            if compacted.len() == available_height {
                break;
            }
        }
        audit = compacted;
    }

    frame.render_widget(Paragraph::new(audit), inner);
}

fn render_back(frame: &mut Frame, app: &App, area: Rect, border_style: Style) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(constants::TITLE_FLIP_CONNECTIONS_AUDIT)
        .title_bottom(
            Line::from(Span::styled(
                constants::FLIP_BACK_HINT,
                Style::default().fg(theme::KEY_HINT_DESC),
            ))
            .right_aligned(),
        );

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let is_connected = !matches!(app.connection_state, ConnectionState::Disconnected);

    let text = if is_connected {
        vec![
            Line::from(Span::styled(
                "Active Connections Audit",
                Style::default()
                    .fg(theme::ACCENT_PRIMARY)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Per-socket VPN routing verification",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
            Line::from(Span::styled(
                "  will be available in a future release.",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  This view will show which connections",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
            Line::from(Span::styled(
                "  are routed through the VPN tunnel vs",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
            Line::from(Span::styled(
                "  bypassing it (split-tunnel detection).",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  See: github.com/Harry-kp/vortix/issues/168",
                Style::default().fg(theme::NORD_POLAR_NIGHT_4),
            )),
        ]
    } else {
        vec![
            Line::from(Span::styled(
                "Active Connections Audit",
                Style::default()
                    .fg(theme::INACTIVE)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Connect to a VPN to see",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
            Line::from(Span::styled(
                "  connection routing details.",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
        ]
    };

    let max_lines = inner.height as usize;
    let mut text = text;
    text.truncate(max_lines);
    frame.render_widget(Paragraph::new(text), inner);
}
