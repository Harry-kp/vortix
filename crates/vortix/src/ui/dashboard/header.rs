use crate::app::{App, ConnectionState, Protocol};
use crate::state::QualityLevel;
use crate::{constants, theme, utils};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

#[allow(clippy::too_many_lines)]
pub(super) fn render(frame: &mut Frame, app: &App, area: Rect) {
    let (status_text, color, profile_name, _location_text, _iface_text, since) =
        get_connection_info(app);

    let ks_indicator = get_killswitch_indicator(app);

    // Build header based on connection state
    let line = match &app.connection_state {
        ConnectionState::Disconnected => {
            // When disconnected, show "Real IP" label to clarify
            Line::from(vec![
                Span::styled(
                    status_text,
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
                Span::styled("Your IP: ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(&app.public_ip, Style::default().fg(theme::TEXT_PRIMARY)),
                Span::styled(" (Unprotected)", Style::default().fg(theme::WARNING)),
                Span::styled(" │", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
                ks_indicator,
            ])
        }
        ConnectionState::Connecting { started, .. }
        | ConnectionState::Disconnecting { started, .. } => {
            let elapsed = started.elapsed().as_secs();
            let spinner_frames = ['◐', '◓', '◑', '◒'];
            #[allow(clippy::cast_possible_truncation)]
            let spinner = spinner_frames[(elapsed as usize) % spinner_frames.len()];
            let action = if matches!(app.connection_state, ConnectionState::Connecting { .. }) {
                "CONNECTING"
            } else {
                "DISCONNECTING"
            };
            Line::from(vec![
                Span::styled(
                    format!("{spinner} {action}"),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" ({profile_name})"),
                    Style::default().fg(theme::TEXT_SECONDARY),
                ),
                Span::styled(
                    format!(" {elapsed}s"),
                    Style::default().fg(theme::ACCENT_SECONDARY),
                ),
                Span::styled(" │", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
                ks_indicator,
            ])
        }
        ConnectionState::Connected { .. } => {
            // Connected - show VPN IP, uptime, and quality
            let elapsed = since.map_or(0, |s| s.elapsed().as_secs());
            let uptime = if elapsed >= 86400 {
                format!(
                    "▲{}d {:02}:{:02}:{:02}",
                    elapsed / 86400,
                    (elapsed % 86400) / 3600,
                    (elapsed % 3600) / 60,
                    elapsed % 60,
                )
            } else if elapsed >= 3600 {
                format!(
                    "▲{:02}:{:02}:{:02}",
                    elapsed / 3600,
                    (elapsed % 3600) / 60,
                    elapsed % 60,
                )
            } else {
                format!("▲{:02}:{:02}", elapsed / 60, elapsed % 60)
            };

            let quality_indicator =
                match QualityLevel::from_metrics(app.latency_ms, app.packet_loss, app.jitter_ms) {
                    QualityLevel::Unknown => ("─────", theme::TEXT_SECONDARY),
                    QualityLevel::Poor => ("●●○○○", theme::NORD_RED),
                    QualityLevel::Fair => ("●●●○○", theme::NORD_YELLOW),
                    QualityLevel::Excellent => ("●●●●●", theme::NORD_GREEN),
                };

            let proto_tag = app
                .profiles
                .iter()
                .find(|p| p.name == profile_name)
                .map_or("", |p| match p.protocol {
                    Protocol::WireGuard => "WG",
                    Protocol::OpenVPN => "OVPN",
                });

            let proto_suffix = if proto_tag.is_empty() {
                ")".to_string()
            } else {
                format!("/{proto_tag})")
            };

            let mut header_spans = vec![
                Span::styled(
                    status_text,
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" ({profile_name}"),
                    Style::default().fg(theme::TEXT_SECONDARY),
                ),
                Span::styled(proto_suffix, Style::default().fg(theme::NORD_FROST_2)),
                Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
                Span::styled("VPN: ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(&app.public_ip, Style::default().fg(theme::SUCCESS)),
            ];

            // Add location if available (from real-time IP geolocation)
            if !app.location.is_empty()
                && app.location != "Unknown"
                && app.location != constants::MSG_DETECTING
            {
                // Adaptive: use ~25% of terminal width for location, min 10
                let loc_budget = (area.width as usize / 4).max(10);
                header_spans.push(Span::styled(
                    " @ ",
                    Style::default().fg(theme::TEXT_SECONDARY),
                ));
                header_spans.push(Span::styled(
                    utils::truncate(&app.location, loc_budget),
                    Style::default().fg(theme::ACCENT_PRIMARY),
                ));
            }

            header_spans.extend_from_slice(&[
                Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
                Span::styled(uptime, Style::default().fg(theme::ACCENT_SECONDARY)),
                Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
                Span::styled(
                    quality_indicator.0,
                    Style::default().fg(quality_indicator.1),
                ),
                Span::styled(" │", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
                ks_indicator,
            ]);

            Line::from(header_spans)
        }
    };

    frame.render_widget(Paragraph::new(line), area);
}

fn get_connection_info(
    app: &App,
) -> (
    &'static str,
    Color,
    &str,
    &str,
    &str,
    Option<std::time::Instant>,
) {
    match &app.connection_state {
        ConnectionState::Disconnected => {
            ("○ DISCONNECTED", theme::ERROR, "None", "None", "-", None)
        }
        ConnectionState::Connecting { profile, .. } => {
            ("⟳ CONNECTING", theme::WARNING, profile, "...", "...", None)
        }
        ConnectionState::Disconnecting { profile, .. } => (
            "⏻ DISCONNECTING",
            theme::WARNING,
            profile,
            "...",
            "...",
            None,
        ),
        ConnectionState::Connected {
            profile,
            since,
            details,
            ..
        } => (
            "● CONNECTED",
            theme::SUCCESS,
            profile,
            &app.location,
            &details.interface,
            Some(*since),
        ),
    }
}

/// Get kill switch indicator for the header bar.
/// Self-explanatory labels: KS:Off, KS:Auto, KS:Strict, KS:BLOCK
fn get_killswitch_indicator(app: &App) -> Span<'static> {
    use crate::state::{KillSwitchMode, KillSwitchState};

    match (app.killswitch_mode, app.killswitch_state) {
        // Kill switch is OFF
        (KillSwitchMode::Off, _) | (_, KillSwitchState::Disabled) => {
            Span::styled(" KS:Off ", Style::default().fg(theme::INACTIVE))
        }
        // BLOCKING - critical state, user needs to know internet is blocked
        (_, KillSwitchState::Blocking) => Span::styled(
            " KS:BLOCK ",
            Style::default()
                .fg(theme::ERROR)
                .add_modifier(Modifier::BOLD),
        ),
        // Auto mode - armed and monitoring
        (KillSwitchMode::Auto, KillSwitchState::Armed) => {
            Span::styled(" KS:Auto ", Style::default().fg(theme::SUCCESS))
        }
        // Strict mode - armed and monitoring
        (KillSwitchMode::AlwaysOn, KillSwitchState::Armed) => {
            Span::styled(" KS:Strict ", Style::default().fg(theme::WARNING))
        }
    }
}
