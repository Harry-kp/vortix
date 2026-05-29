use crate::app::App;
use crate::state::QualityLevel;
use crate::vortix_core::engine::state::Connection;
use crate::{constants, theme, utils};
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

/// Render the header bar from the primary tunnel's `TunnelSnapshot`.
///
/// Multi-connection plan U6 Stage B: tunnel reads come from
/// `app.registry.snapshot(app.registry.primary())`; telemetry
/// (latency/loss/jitter/IP/location) stays on `app.runtime` per H7's
/// primary-only scoping. When secondary tunnels exist the count is
/// surfaced as `(+N more)`.
#[allow(clippy::too_many_lines)]
pub(super) fn render(frame: &mut Frame, app: &App, area: Rect) {
    let primary = app.registry.primary().cloned();
    let primary_snap = primary.as_ref().and_then(|id| app.registry.snapshot(id));

    let ks_indicator = get_killswitch_indicator(app);

    let line = match primary_snap.as_ref().map(|s| &s.state) {
        None | Some(Connection::Disconnected { .. }) => {
            Line::from(vec![
                Span::styled(
                    "○ DISCONNECTED",
                    Style::default()
                        .fg(theme::ERROR)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
                Span::styled("Your IP: ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(
                    &app.runtime.public_ip,
                    Style::default().fg(theme::TEXT_PRIMARY),
                ),
                Span::styled(" (Unprotected)", Style::default().fg(theme::WARNING)),
                Span::styled(" │", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
                ks_indicator,
            ])
        }
        Some(
            Connection::Connecting { started_at, .. }
            | Connection::Disconnecting { started_at, .. }
            | Connection::Reconnecting { started_at, .. },
        ) => {
            let snap = primary_snap.as_ref().expect("transitional => snapshot present");
            let profile_name = snap.profile_id.as_str();
            let elapsed = started_at.elapsed().map_or(0, |d| d.as_secs());
            let spinner_frames = ['◐', '◓', '◑', '◒'];
            #[allow(clippy::cast_possible_truncation)]
            let spinner = spinner_frames[(elapsed as usize) % spinner_frames.len()];
            let action = match snap.state {
                Connection::Disconnecting { .. } => "DISCONNECTING",
                Connection::Reconnecting { .. } => "RECONNECTING",
                _ => "CONNECTING",
            };
            Line::from(vec![
                Span::styled(
                    format!("{spinner} {action}"),
                    Style::default()
                        .fg(theme::WARNING)
                        .add_modifier(Modifier::BOLD),
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
        Some(Connection::AwaitingUserInput { .. }) => Line::from(vec![
            Span::styled(
                "? AWAITING INPUT",
                Style::default()
                    .fg(theme::WARNING)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" │", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
            ks_indicator,
        ]),
        Some(Connection::Connected {
            details, since, ..
        }) => {
            let snap = primary_snap.as_ref().expect("connected => snapshot present");
            let profile_name = snap.profile_id.as_str();

            let elapsed = since.elapsed().map_or(0, |d| d.as_secs());
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

            let quality_indicator = match QualityLevel::from_metrics(
                app.runtime.latency_ms,
                app.runtime.packet_loss,
                app.runtime.jitter_ms,
            ) {
                QualityLevel::Unknown => ("─────", theme::TEXT_SECONDARY),
                QualityLevel::Poor => ("●●○○○", theme::NORD_RED),
                QualityLevel::Fair => ("●●●○○", theme::NORD_YELLOW),
                QualityLevel::Excellent => ("●●●●●", theme::NORD_GREEN),
            };

            // Protocol tag derived from the runtime's profile catalog —
            // the registry stores `ProfileId`, not the `Protocol` enum.
            let proto_tag = app
                .runtime
                .profiles
                .iter()
                .find(|p| p.name == profile_name)
                .map_or("", |p| match p.protocol {
                    crate::state::Protocol::WireGuard => "WG",
                    crate::state::Protocol::OpenVPN => "OVPN",
                });

            let proto_suffix = if proto_tag.is_empty() {
                ")".to_string()
            } else {
                format!("/{proto_tag})")
            };

            // Show "(+N more)" suffix when secondary tunnels exist.
            let tunnel_count = app.registry.tunnel_count();
            let extras = tunnel_count.saturating_sub(1);
            let extras_suffix = if extras > 0 {
                format!(" (+{extras} more)")
            } else {
                String::new()
            };

            let mut header_spans = vec![
                Span::styled(
                    "● CONNECTED",
                    Style::default()
                        .fg(theme::SUCCESS)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" ({profile_name}"),
                    Style::default().fg(theme::TEXT_SECONDARY),
                ),
                Span::styled(proto_suffix, Style::default().fg(theme::NORD_FROST_2)),
                Span::styled(extras_suffix, Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
                Span::styled("VPN: ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(&app.runtime.public_ip, Style::default().fg(theme::SUCCESS)),
            ];

            if !app.runtime.location.is_empty()
                && app.runtime.location != "Unknown"
                && app.runtime.location != constants::MSG_DETECTING
            {
                let loc_budget = (area.width as usize / 4).max(10);
                header_spans.push(Span::styled(
                    " @ ",
                    Style::default().fg(theme::TEXT_SECONDARY),
                ));
                header_spans.push(Span::styled(
                    utils::truncate(&app.runtime.location, loc_budget),
                    Style::default().fg(theme::ACCENT_PRIMARY),
                ));
            }

            // Surface the interface name so users on N-tunnel setups can
            // see which tunnel currently owns the default route.
            if !details.interface.is_empty() {
                header_spans.push(Span::styled(
                    format!(" [{}]", details.interface),
                    Style::default().fg(theme::TEXT_SECONDARY),
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

/// Get kill switch indicator for the header bar.
/// Self-explanatory labels: KS:Off, KS:Auto, KS:Strict, KS:BLOCK
fn get_killswitch_indicator(app: &App) -> Span<'static> {
    use crate::state::{KillSwitchMode, KillSwitchState};

    match (app.runtime.killswitch_mode, app.runtime.killswitch_state) {
        (KillSwitchMode::Off, _) | (_, KillSwitchState::Disabled) => {
            Span::styled(" KS:Off ", Style::default().fg(theme::INACTIVE))
        }
        (_, KillSwitchState::Blocking) => Span::styled(
            " KS:BLOCK ",
            Style::default()
                .fg(theme::ERROR)
                .add_modifier(Modifier::BOLD),
        ),
        (KillSwitchMode::Auto, KillSwitchState::Armed) => {
            Span::styled(" KS:Auto ", Style::default().fg(theme::SUCCESS))
        }
        (KillSwitchMode::AlwaysOn, KillSwitchState::Armed) => {
            Span::styled(" KS:Strict ", Style::default().fg(theme::WARNING))
        }
    }
}
