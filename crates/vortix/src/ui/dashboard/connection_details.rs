use crate::app::{App, ConnectionState};
use crate::state::QualityLevel;
use crate::{constants, theme, utils};
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

#[allow(clippy::too_many_lines, clippy::similar_names)]
pub(super) fn render(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.should_draw_focus(&crate::app::FocusedPanel::ConnectionDetails);
    let border_style = if is_focused {
        Style::default().fg(theme::BORDER_FOCUSED)
    } else {
        Style::default().fg(theme::BORDER_DEFAULT)
    };

    if app.effective_flipped(&crate::app::FocusedPanel::ConnectionDetails) {
        render_back(frame, app, area, border_style);
        return;
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(" Connection Details ");

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if let ConnectionState::Connected { details, .. } = &app.connection_state {
        let is_openvpn = details.public_key == "OpenVPN" || details.public_key.is_empty();

        // MTU value
        let mtu_str = if details.mtu.is_empty() {
            "-".to_string()
        } else {
            details.mtu.clone()
        };

        let mut text = vec![
            // Row 1: VPN IP @ Interface
            Line::from(vec![
                Span::styled("VPN IP  : ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(
                    &details.internal_ip,
                    Style::default()
                        .fg(theme::ACCENT_PRIMARY)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(
                        " @ {}",
                        if details.interface.is_empty() {
                            "-"
                        } else {
                            &details.interface
                        }
                    ),
                    Style::default().fg(theme::TEXT_SECONDARY),
                ),
            ]),
            // Row 2: Server (clearer than "Remote")
            Line::from(vec![
                Span::styled("Server  : ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(&details.endpoint, Style::default().fg(theme::TEXT_PRIMARY)),
            ]),
            // Row 3: Exit Node (ISP | Location) — adaptive truncation
            {
                let label_overhead = 10 + 2 + 1; // "Exit    : " + " (" + ")"
                let available = (inner.width as usize).saturating_sub(label_overhead);
                let isp_budget = (available * 60 / 100).min(available);
                let loc_budget = available.saturating_sub(isp_budget);
                Line::from(vec![
                    Span::styled("Exit    : ", Style::default().fg(theme::TEXT_SECONDARY)),
                    Span::styled(
                        utils::truncate(&app.isp, isp_budget),
                        Style::default().fg(theme::TEXT_PRIMARY),
                    ),
                    Span::styled(" (", Style::default().fg(theme::TEXT_SECONDARY)),
                    Span::styled(
                        utils::truncate(&app.location, loc_budget),
                        Style::default().fg(theme::TEXT_PRIMARY),
                    ),
                    Span::styled(")", Style::default().fg(theme::TEXT_SECONDARY)),
                ])
            },
        ];

        // Row 4: Crypto/Protocol Info
        let (proto_label, proto_value, proto_color) = if is_openvpn {
            let cipher = if details.latest_handshake.starts_with("Cipher:") {
                details.latest_handshake.replace("Cipher: ", "")
            } else if details.latest_handshake.is_empty() {
                "AES-256-GCM".to_string()
            } else {
                details.latest_handshake.clone()
            };
            ("Crypto  : ", cipher, theme::NORD_YELLOW)
        } else {
            // For WireGuard, show last handshake time
            let handshake_str = if details.latest_handshake.is_empty() {
                "ChaCha20-Poly1305".to_string()
            } else {
                format!("ChaCha20 ({})", details.latest_handshake)
            };
            ("Crypto  : ", handshake_str, theme::NORD_YELLOW)
        };

        text.push(Line::from(vec![
            Span::styled(proto_label, Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(
                if proto_value.is_empty() {
                    "-"
                } else {
                    &proto_value
                },
                Style::default().fg(proto_color),
            ),
        ]));

        // Row 5: Transfer Stats with MTU
        text.push(Line::from(vec![
            Span::styled("Transfer: ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled("↓", Style::default().fg(theme::NORD_FROST_3)),
            Span::styled(
                if details.transfer_rx.is_empty() {
                    "0"
                } else {
                    &details.transfer_rx
                },
                Style::default().fg(theme::TEXT_PRIMARY),
            ),
            Span::styled(" ↑", Style::default().fg(theme::NORD_GREEN)),
            Span::styled(
                if details.transfer_tx.is_empty() {
                    "0"
                } else {
                    &details.transfer_tx
                },
                Style::default().fg(theme::TEXT_PRIMARY),
            ),
            Span::styled(" (MTU:", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(mtu_str, Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(")", Style::default().fg(theme::TEXT_SECONDARY)),
        ]));

        text.push(Line::from(""));

        // Row 6: Quality Metrics (Unified high-density)
        let quality_status =
            match QualityLevel::from_metrics(app.latency_ms, app.packet_loss, app.jitter_ms) {
                QualityLevel::Unknown => ("UNKNOWN", theme::TEXT_SECONDARY),
                QualityLevel::Poor => ("POOR", theme::NORD_RED),
                QualityLevel::Fair => ("FAIR", theme::NORD_YELLOW),
                QualityLevel::Excellent => ("EXCELLENT", theme::NORD_GREEN),
            };

        text.push(Line::from(vec![
            Span::styled("Quality: ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(
                quality_status.0,
                Style::default()
                    .fg(quality_status.1)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));

        let latency_color = if app.latency_ms < 50 {
            theme::NORD_GREEN
        } else if app.latency_ms < 150 {
            theme::NORD_YELLOW
        } else {
            theme::NORD_RED
        };
        text.push(Line::from(vec![
            Span::styled(
                "  ├─ Ping (Latency)   : ",
                Style::default().fg(theme::TEXT_SECONDARY),
            ),
            Span::styled(
                format!("{}ms", app.latency_ms),
                Style::default().fg(latency_color),
            ),
        ]));

        let jitter_color = if app.jitter_ms < 5 {
            theme::NORD_GREEN
        } else if app.jitter_ms < 15 {
            theme::NORD_YELLOW
        } else {
            theme::NORD_RED
        };
        text.push(Line::from(vec![
            Span::styled(
                "  ├─ Stability (Jitter): ",
                Style::default().fg(theme::TEXT_SECONDARY),
            ),
            Span::styled(
                format!("±{}ms", app.jitter_ms),
                Style::default().fg(jitter_color),
            ),
        ]));

        text.push(Line::from(vec![
            Span::styled(
                "  └─ Reliability (Loss): ",
                Style::default().fg(theme::TEXT_SECONDARY),
            ),
            Span::styled(
                format!("{:.1}%", app.packet_loss),
                Style::default().fg(if app.packet_loss < 1.0 {
                    theme::NORD_GREEN
                } else {
                    theme::NORD_RED
                }),
            ),
        ]));

        // Stats Footer Row
        text.push(Line::from(""));
        let rel_spans = vec![
            Span::styled("Stats   : ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled("PID ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(
                details.pid.map_or("-".to_string(), |p| p.to_string()),
                Style::default().fg(theme::TEXT_PRIMARY),
            ),
            Span::styled(" | Drops ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(
                format!("{}", app.connection_drops),
                Style::default().fg(if app.connection_drops > 0 {
                    theme::NORD_RED
                } else {
                    theme::TEXT_PRIMARY
                }),
            ),
        ];

        text.push(Line::from(rel_spans));

        frame.render_widget(Paragraph::new(text), inner);
    } else {
        let max_lines = inner.height as usize;
        let mut text: Vec<Line> = vec![
            Line::from(Span::styled(
                "Not Connected",
                Style::default()
                    .fg(theme::INACTIVE)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
        ];

        if let Some(idx) = app.profile_list_state.selected() {
            if let Some(profile) = app.profiles.get(idx) {
                text.push(Line::from(vec![
                    Span::styled("Profile : ", Style::default().fg(theme::TEXT_SECONDARY)),
                    Span::styled(&profile.name, Style::default().fg(theme::ACCENT_PRIMARY)),
                ]));
                text.push(Line::from(vec![
                    Span::styled("Protocol: ", Style::default().fg(theme::TEXT_SECONDARY)),
                    Span::styled(
                        profile.protocol.to_string(),
                        Style::default().fg(theme::TEXT_PRIMARY),
                    ),
                ]));
                text.push(Line::from(vec![
                    Span::styled("Config  : ", Style::default().fg(theme::TEXT_SECONDARY)),
                    Span::styled(
                        utils::truncate(
                            &profile.config_path.display().to_string(),
                            inner.width.saturating_sub(10) as usize,
                        ),
                        Style::default().fg(theme::TEXT_SECONDARY),
                    ),
                ]));
                if let Some(last_used) = profile.last_used {
                    text.push(Line::from(vec![
                        Span::styled("Last use: ", Style::default().fg(theme::TEXT_SECONDARY)),
                        Span::styled(
                            utils::format_relative_time(last_used),
                            Style::default().fg(theme::TEXT_PRIMARY),
                        ),
                    ]));
                }

                text.push(Line::from(""));

                // Pre-VPN network info
                if !app.public_ip.is_empty() {
                    text.push(Line::from(vec![
                        Span::styled("Your IP : ", Style::default().fg(theme::TEXT_SECONDARY)),
                        Span::styled(&app.public_ip, Style::default().fg(theme::WARNING)),
                    ]));
                }
                if !app.isp.is_empty()
                    && app.isp != "Unknown"
                    && app.isp != constants::MSG_DETECTING
                {
                    text.push(Line::from(vec![
                        Span::styled("ISP     : ", Style::default().fg(theme::TEXT_SECONDARY)),
                        Span::styled(&app.isp, Style::default().fg(theme::TEXT_PRIMARY)),
                    ]));
                }
                if !app.dns_server.is_empty() && app.dns_server != constants::MSG_DETECTING {
                    text.push(Line::from(vec![
                        Span::styled("DNS     : ", Style::default().fg(theme::TEXT_SECONDARY)),
                        Span::styled(&app.dns_server, Style::default().fg(theme::TEXT_PRIMARY)),
                    ]));
                }
            }
        } else {
            text.push(Line::from(vec![Span::styled(
                "Select a profile from the sidebar",
                Style::default().fg(theme::TEXT_SECONDARY),
            )]));
        }

        text.truncate(max_lines);
        frame.render_widget(Paragraph::new(text), inner);
    }
}

fn render_back(frame: &mut Frame, app: &App, area: Rect, border_style: Style) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(constants::TITLE_FLIP_QUALITY_TIMELINE)
        .title_bottom(
            Line::from(Span::styled(
                constants::FLIP_BACK_HINT,
                Style::default().fg(theme::KEY_HINT_DESC),
            ))
            .right_aligned(),
        );

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let latency_color = if app.latency_ms < 50 {
        theme::NORD_GREEN
    } else if app.latency_ms < 150 {
        theme::NORD_YELLOW
    } else {
        theme::NORD_RED
    };

    let text = vec![
        Line::from(Span::styled(
            "Session Quality History",
            Style::default()
                .fg(theme::ACCENT_PRIMARY)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Latency : ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(
                format!("{}ms", app.latency_ms),
                Style::default().fg(latency_color),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Jitter  : ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(
                format!("±{}ms", app.jitter_ms),
                Style::default().fg(theme::TEXT_PRIMARY),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Loss    : ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(
                format!("{:.1}%", app.packet_loss),
                Style::default().fg(theme::TEXT_PRIMARY),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Sparkline history & session stats",
            Style::default().fg(theme::TEXT_SECONDARY),
        )),
        Line::from(Span::styled(
            "  will be available in a future release.",
            Style::default().fg(theme::TEXT_SECONDARY),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  See: github.com/Harry-kp/vortix/issues/167",
            Style::default().fg(theme::NORD_POLAR_NIGHT_4),
        )),
    ];

    let max_lines = inner.height as usize;
    let mut text = text;
    text.truncate(max_lines);
    frame.render_widget(Paragraph::new(text), inner);
}
