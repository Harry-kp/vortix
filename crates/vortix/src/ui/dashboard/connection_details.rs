use crate::app::App;
use crate::state::QualityLevel;
use crate::vortix_core::engine::state::Connection;
use crate::vortix_core::profile::ProfileId;
use crate::{constants, theme, utils};
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

/// Render the Connection Details panel for the focused profile.
///
/// Multi-connection plan U6 Stage B: looks up the snapshot for the
/// currently-selected profile (focused via the sidebar's
/// `profile_list_state`). Telemetry rows scope to the primary tunnel per
/// H7 — when the focused profile is a secondary the panel renders
/// "Latency: n/a (secondary tunnel)" instead of primary-scoped metrics.
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

    // Focused profile = sidebar selection, falling back to the primary if
    // nothing is selected (so the panel still has useful content when the
    // user is browsing other panels).
    let focused_profile_id = app
        .profile_list_state
        .selected()
        .and_then(|idx| app.runtime.profiles.get(idx))
        .map(|p| ProfileId::new(&p.name))
        .or_else(|| app.registry.primary().cloned());

    let focused_snap = focused_profile_id
        .as_ref()
        .and_then(|id| app.registry.snapshot(id));
    let primary_id = app.registry.primary();
    let is_focused_primary = matches!(
        (&focused_profile_id, primary_id),
        (Some(focused), Some(primary)) if focused == primary
    );

    if let Some(snap) = focused_snap.as_ref() {
        if let Connection::Connected { details, .. } = &snap.state {
            render_connected(frame, app, inner, details, is_focused_primary);
            return;
        }
    }

    render_disconnected(frame, app, inner);
}

#[allow(clippy::too_many_lines)]
fn render_connected(
    frame: &mut Frame,
    app: &App,
    inner: Rect,
    details: &crate::vortix_core::engine::state::DetailedConnectionInfo,
    is_focused_primary: bool,
) {
    let is_openvpn = details.public_key == "OpenVPN" || details.public_key.is_empty();

    let mtu_str = if details.mtu.is_empty() {
        "-".to_string()
    } else {
        details.mtu.clone()
    };

    let mut text = vec![
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
        Line::from(vec![
            Span::styled("Server  : ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(&details.endpoint, Style::default().fg(theme::TEXT_PRIMARY)),
        ]),
        {
            let label_overhead = 10 + 2 + 1;
            let available = (inner.width as usize).saturating_sub(label_overhead);
            let isp_budget = (available * 60 / 100).min(available);
            let loc_budget = available.saturating_sub(isp_budget);
            Line::from(vec![
                Span::styled("Exit    : ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(
                    utils::truncate(&app.runtime.isp, isp_budget),
                    Style::default().fg(theme::TEXT_PRIMARY),
                ),
                Span::styled(" (", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(
                    utils::truncate(&app.runtime.location, loc_budget),
                    Style::default().fg(theme::TEXT_PRIMARY),
                ),
                Span::styled(")", Style::default().fg(theme::TEXT_SECONDARY)),
            ])
        },
    ];

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

    if is_focused_primary {
        let quality_status = match QualityLevel::from_metrics(
            app.runtime.latency_ms,
            app.runtime.packet_loss,
            app.runtime.jitter_ms,
        ) {
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

        let latency_color = if app.runtime.latency_ms < 50 {
            theme::NORD_GREEN
        } else if app.runtime.latency_ms < 150 {
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
                format!("{}ms", app.runtime.latency_ms),
                Style::default().fg(latency_color),
            ),
        ]));

        let jitter_color = if app.runtime.jitter_ms < 5 {
            theme::NORD_GREEN
        } else if app.runtime.jitter_ms < 15 {
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
                format!("±{}ms", app.runtime.jitter_ms),
                Style::default().fg(jitter_color),
            ),
        ]));

        text.push(Line::from(vec![
            Span::styled(
                "  └─ Reliability (Loss): ",
                Style::default().fg(theme::TEXT_SECONDARY),
            ),
            Span::styled(
                format!("{:.1}%", app.runtime.packet_loss),
                Style::default().fg(if app.runtime.packet_loss < 1.0 {
                    theme::NORD_GREEN
                } else {
                    theme::NORD_RED
                }),
            ),
        ]));
    } else {
        // H7: telemetry is primary-only. Secondaries explicitly say so.
        text.push(Line::from(vec![
            Span::styled("Latency: ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(
                "n/a (secondary tunnel)",
                Style::default().fg(theme::INACTIVE),
            ),
        ]));
    }

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
            format!("{}", app.runtime.connection_drops),
            Style::default().fg(if app.runtime.connection_drops > 0 {
                theme::NORD_RED
            } else {
                theme::TEXT_PRIMARY
            }),
        ),
    ];

    text.push(Line::from(rel_spans));

    frame.render_widget(Paragraph::new(text), inner);
}

fn render_disconnected(frame: &mut Frame, app: &App, inner: Rect) {
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
        if let Some(profile) = app.runtime.profiles.get(idx) {
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

            if !app.runtime.public_ip.is_empty() {
                text.push(Line::from(vec![
                    Span::styled("Your IP : ", Style::default().fg(theme::TEXT_SECONDARY)),
                    Span::styled(&app.runtime.public_ip, Style::default().fg(theme::WARNING)),
                ]));
            }
            if !app.runtime.isp.is_empty()
                && app.runtime.isp != "Unknown"
                && app.runtime.isp != constants::MSG_DETECTING
            {
                text.push(Line::from(vec![
                    Span::styled("ISP     : ", Style::default().fg(theme::TEXT_SECONDARY)),
                    Span::styled(&app.runtime.isp, Style::default().fg(theme::TEXT_PRIMARY)),
                ]));
            }
            if !app.runtime.dns_server.is_empty()
                && app.runtime.dns_server != constants::MSG_DETECTING
            {
                text.push(Line::from(vec![
                    Span::styled("DNS     : ", Style::default().fg(theme::TEXT_SECONDARY)),
                    Span::styled(
                        &app.runtime.dns_server,
                        Style::default().fg(theme::TEXT_PRIMARY),
                    ),
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

    let latency_color = if app.runtime.latency_ms < 50 {
        theme::NORD_GREEN
    } else if app.runtime.latency_ms < 150 {
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
                format!("{}ms", app.runtime.latency_ms),
                Style::default().fg(latency_color),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Jitter  : ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(
                format!("±{}ms", app.runtime.jitter_ms),
                Style::default().fg(theme::TEXT_PRIMARY),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Loss    : ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(
                format!("{:.1}%", app.runtime.packet_loss),
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
