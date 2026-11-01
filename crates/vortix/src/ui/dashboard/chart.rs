use crate::app::App;
use crate::ui::helpers;
use crate::{constants, ui::theme};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{
        canvas::{Canvas, Line as CanvasLine},
        Block, Borders, Paragraph,
    },
    Frame,
};

/// Current up/down rates and the session's cumulative transfer. When the
/// padded, labelled form is wider than `width`, the rate words and padding go
/// so the session totals stay on screen.
fn stats_line(app: &App, session_rx: &str, session_tx: &str, width: usize) -> Line<'static> {
    let up = helpers::format_bytes_speed(app.runtime.current_up);
    let down = helpers::format_bytes_speed(app.runtime.current_down);
    let line = |[up_label, down_label, session_label]: [&str; 3], up: String, down: String| {
        let t = theme::current();
        let rule = Style::default().fg(t.nord_polar_night_4);
        Line::from(vec![
            Span::styled(up_label.to_string(), Style::default().fg(t.success)),
            Span::styled(up, Style::default().fg(t.text_primary)),
            Span::styled(" │ ", rule),
            Span::styled(
                down_label.to_string(),
                Style::default().fg(t.accent_primary),
            ),
            Span::styled(down, Style::default().fg(t.text_primary)),
            Span::styled(" │ ", rule),
            Span::styled(
                session_label.to_string(),
                Style::default().fg(t.text_secondary),
            ),
            Span::styled("↓", Style::default().fg(t.nord_frost_3)),
            Span::styled(session_rx.to_string(), Style::default().fg(t.text_primary)),
            Span::styled(" ↑", Style::default().fg(t.success)),
            Span::styled(session_tx.to_string(), Style::default().fg(t.text_primary)),
        ])
    };
    let full = line(
        [" ▲ UP: ", " ▼ DOWN: ", " Session: "],
        format!("{up:<10}"),
        format!("{down:<10}"),
    );
    if full.width() <= width {
        full
    } else {
        line(["▲", "▼", "Session "], up, down)
    }
}

pub(super) fn render(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.should_draw_focus(&crate::app::FocusedPanel::Chart);
    let border_style = if is_focused {
        Style::default().fg(theme::current().border_focused)
    } else {
        Style::default().fg(theme::current().border_default)
    };
    if app.effective_flipped(&crate::app::FocusedPanel::Chart) {
        render_back(frame, app, area, border_style);
        return;
    }

    let max_down = app.runtime.down_history.iter().copied().fold(0.0, f64::max);
    let max_up = app.runtime.up_history.iter().copied().fold(0.0, f64::max);
    let peak = (max_down.max(max_up) * 1.2).max(500_000.0);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let scale = crate::ui::helpers::format_bytes_speed(peak as u64);
    let peak_label = format!(" Peak: {scale} ");

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(" Network Throughput ")
        .title_bottom(helpers::border_hint(constants::FLIP_ROUTES_HINT))
        .title(
            Line::from(Span::styled(
                peak_label,
                Style::default().fg(theme::current().nord_polar_night_4),
            ))
            .right_aligned(),
        )
        .title_bottom(
            Line::from(Span::styled(
                format!(" Scale: 0 – {scale} "),
                Style::default().fg(theme::current().key_hint_desc),
            ))
            .right_aligned(),
        );

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(inner);

    // Session totals derived from the primary tunnel's snapshot.
    let primary_snap = app.primary_id().and_then(|id| app.tunnel(id));
    let (session_rx, session_tx) = match primary_snap {
        Some(tunnel) if tunnel.phase == crate::control::Phase::Up => (
            helpers::transfer_text(&tunnel.details.transfer_rx),
            helpers::transfer_text(&tunnel.details.transfer_tx),
        ),
        _ => ("0 B".to_string(), "0 B".to_string()),
    };

    frame.render_widget(
        Paragraph::new(stats_line(
            app,
            &session_rx,
            &session_tx,
            chunks[0].width as usize,
        ))
        .alignment(Alignment::Center),
        chunks[0],
    );

    let hist_len = app.runtime.down_history.len();
    #[allow(clippy::cast_precision_loss)]
    let x_max = constants::NETWORK_HISTORY_SIZE as f64;
    let canvas = Canvas::default()
        .block(Block::default())
        .background_color(theme::current().panel_bg)
        .x_bounds([0.0, x_max])
        .y_bounds([0.0, peak])
        .paint(|ctx| {
            // Down first so the up series wins wherever the two overlap.
            for (history, color) in [
                (&app.runtime.down_history, theme::current().accent_primary),
                (&app.runtime.up_history, theme::current().success),
            ] {
                #[allow(clippy::cast_precision_loss)]
                for i in 0..hist_len.saturating_sub(1) {
                    let (y1, y2) = (history[i], history[i + 1]);
                    if y1 > 0.0 || y2 > 0.0 {
                        ctx.draw(&CanvasLine {
                            x1: i as f64,
                            y1,
                            x2: (i + 1) as f64,
                            y2,
                            color,
                        });
                    }
                }
            }
        });
    frame.render_widget(canvas, chunks[1]);
}

/// The flip side: where the focused profile's traffic goes. Its routes (a
/// mesh network's routed networks) and who it talks to (a mesh network's
/// peers, else the server), the same layout for every kind of VPN.
fn render_back(frame: &mut Frame, app: &App, area: Rect, border_style: Style) {
    let profile_id = app
        .selected_profile_id()
        .or_else(|| app.primary_id().cloned());
    let tunnel = profile_id.as_ref().and_then(|id| app.tunnel(id));
    let title = tunnel.map_or_else(
        || constants::TITLE_FLIP_ROUTES.to_string(),
        |tunnel| {
            format!(
                "{}· {} ({}) ",
                constants::TITLE_FLIP_ROUTES,
                tunnel.name,
                tunnel.protocol
            )
        },
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .padding(ratatui::widgets::Padding::horizontal(1))
        .title(title)
        .title_bottom(helpers::border_hint(constants::FLIP_BACK_HINT));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let width = usize::from(inner.width);
    let dim = Style::default().fg(theme::current().text_secondary);
    let Some(tunnel) = tunnel else {
        let text = if profile_id.is_some() {
            "Not connected: connect it to see its routes and peers."
        } else {
            "Select a profile to see its routes and peers."
        };
        frame.render_widget(
            Paragraph::new(helpers::wrapped_lines(text, width, 0, dim)),
            inner,
        );
        return;
    };
    let heading = |text: &str| {
        Line::styled(
            text.to_string(),
            Style::default().fg(theme::current().accent_primary),
        )
    };
    let mut lines = vec![heading("Routes")];
    if tunnel.details.networks.is_empty() {
        lines.extend(
            tunnel
                .routes
                .iter()
                .map(|route| mark_line(true, &route.to_string(), "", width)),
        );
    } else {
        let names = column(
            tunnel
                .details
                .networks
                .iter()
                .map(|network| network.name.as_str()),
            width,
        );
        lines.extend(tunnel.details.networks.iter().map(|network| {
            let exit = if network.is_exit_node() {
                "  exit node"
            } else {
                ""
            };
            mark_line(
                network.selected,
                &format!(
                    "{:<names$} {}{exit}",
                    helpers::truncate_to_width(&network.name, names),
                    network.range
                ),
                "",
                width,
            )
        }));
    }
    if lines.len() == 1 {
        lines.push(Line::styled("none", dim));
    }
    lines.push(Line::from(""));
    lines.push(heading("Peers"));
    if tunnel.details.peers.is_empty() {
        let handshake = helpers::nonempty_or(&tunnel.details.latest_handshake, "");
        lines.push(mark_line(
            true,
            helpers::nonempty_or(&tunnel.details.endpoint, "none"),
            handshake,
            width,
        ));
    } else {
        lines.extend(peer_lines(&tunnel.details.peers, width));
    }
    lines.truncate(usize::from(inner.height));
    frame.render_widget(Paragraph::new(lines), inner);
}

/// A name column as wide as the longest name, but at most half the panel.
fn column<'a>(names: impl Iterator<Item = &'a str>, width: usize) -> usize {
    names
        .map(unicode_width::UnicodeWidthStr::width)
        .max()
        .unwrap_or(0)
        .min(width / 2)
}

/// `● text  detail`, green when in use, grey otherwise, fitted to the panel.
fn mark_line(active: bool, text: &str, detail: &str, width: usize) -> Line<'static> {
    let t = theme::current();
    let (mark, color) = if active {
        ("●", t.success)
    } else {
        ("○", t.text_secondary)
    };
    let text = if detail.is_empty() {
        text.to_string()
    } else {
        format!("{text}  {detail}")
    };
    helpers::fit_line(
        Line::from(vec![
            Span::styled(format!("{mark} "), Style::default().fg(color)),
            Span::styled(text, Style::default().fg(t.text_primary)),
        ]),
        width,
    )
}

/// One line per mesh peer, connected first: name, address, direct or relayed, latency.
fn peer_lines(peers: &[crate::tunnel::MeshPeer], width: usize) -> Vec<Line<'static>> {
    let t = theme::current();
    let mut peers = peers.to_vec();
    peers.sort_by(|a, b| b.connected.cmp(&a.connected).then(a.name.cmp(&b.name)));
    let names = column(peers.iter().map(|peer| peer.name.as_str()), width);
    peers
        .iter()
        .map(|peer| {
            let (mark, color, path) = match (peer.connected, peer.relayed) {
                (false, _) => ("○", t.text_secondary, "offline"),
                (true, true) => ("●", t.warning, "relayed"),
                (true, false) => ("●", t.success, "direct"),
            };
            let latency = peer
                .latency
                .map(|latency| format!("{} ms", latency.as_millis()))
                .unwrap_or_default();
            helpers::fit_line(
                Line::from(vec![
                    Span::styled(format!("{mark} "), Style::default().fg(color)),
                    Span::styled(
                        format!(
                            "{:<names$} {:<16} {path:<8} {latency}",
                            helpers::truncate_to_width(&peer.name, names),
                            peer.address
                        ),
                        Style::default().fg(t.text_primary),
                    ),
                ]),
                width,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn back_of(app: &mut App, name: &str, protocol: crate::profile::ProtocolKind) -> String {
        app.runtime
            .profiles
            .push(crate::config::profiles::VpnProfile {
                id: crate::profile::ProfileId::new(name),
                name: name.into(),
                protocol,
                config_path: "/tmp/x".into(),
                location: String::new(),
                last_used: None,
                group: None,
            });
        app.profile_list_state
            .select(Some(app.runtime.profiles.len() - 1));
        if !app.is_flipped(&crate::app::FocusedPanel::Chart) {
            let state = app.flip_state_mut(crate::app::FocusedPanel::Chart);
            state.flip();
            while state.is_animating() {
                state.tick();
            }
        }
        crate::ui::dashboard::render_to_string(80, 14, |frame, area| render(frame, app, area))
    }

    /// The back of the chart lists a `NetBird` network's routed networks (whole
    /// names, which one is the exit node) and its peers, connected first.
    #[test]
    fn the_back_shows_a_mesh_networks_routes_and_peers() {
        let mut app = App::new_test();
        let mut mesh = crate::app::connection::test_view("work", crate::control::Phase::Up);
        mesh.protocol = crate::profile::ProtocolKind::Mesh(crate::mesh::MeshDriver::NetBird);
        mesh.details.networks = vec![
            crate::tunnel::RoutedNetwork {
                name: "euc1-stag-001-public-nic-v1.bsstag.com".into(),
                range: "10.20.0.0/16".into(),
                selected: true,
            },
            crate::tunnel::RoutedNetwork {
                name: "Exit Node".into(),
                range: "0.0.0.0/0, ::/0".into(),
                selected: false,
            },
        ];
        let peer = |name: &str, connected, relayed| crate::tunnel::MeshPeer {
            name: name.into(),
            address: "100.90.0.1".into(),
            connected,
            relayed,
            latency: connected.then(|| std::time::Duration::from_millis(7)),
        };
        mesh.details.peers = vec![peer("asleep", false, false), peer("gw", true, true)];
        app.set_tunnels_for_test(vec![mesh], None);
        let screen = back_of(
            &mut app,
            "work",
            crate::profile::ProtocolKind::Mesh(crate::mesh::MeshDriver::NetBird),
        );
        for shown in [
            "Routes & peers · work (NetBird)",
            "euc1-stag-001-public-nic-v1.bsstag.com",
            "exit node",
            "relayed",
            "offline",
            "[f] flip back",
        ] {
            assert!(screen.contains(shown), "{shown}: {screen}");
        }
        assert!(
            screen.find("gw").unwrap() < screen.find("asleep").unwrap(),
            "connected first"
        );
    }

    /// A `WireGuard` tunnel shows what it routes and its server.
    #[test]
    fn the_back_shows_a_wireguard_tunnels_routes_and_server() {
        let mut app = App::new_test();
        let mut wg = crate::app::connection::test_view("home", crate::control::Phase::Up);
        wg.routes = vec!["10.8.0.0/24".parse().unwrap()];
        wg.details.endpoint = "203.0.113.7:51820".into();
        app.set_tunnels_for_test(vec![wg], None);
        let screen = back_of(&mut app, "home", crate::profile::ProtocolKind::WireGuard);
        for shown in ["home (WireGuard)", "10.8.0.0/24", "203.0.113.7:51820"] {
            assert!(screen.contains(shown), "{shown}: {screen}");
        }
    }

    /// The chart is 52 cells wide inside its border in an 80-column terminal.
    #[test]
    fn session_totals_stay_visible_at_80_columns() {
        let mut app = App::new_test();
        app.runtime.current_up = 12_300_000;
        app.runtime.current_down = 45_600_000;
        let line = stats_line(&app, "1.21GiB", "300.5MiB", 52);
        let text = line.to_string();
        assert!(line.width() <= 52, "{text}");
        assert!(text.contains("↓1.21GiB ↑300.5MiB"), "{text}");
    }

    #[test]
    fn a_wide_chart_keeps_the_rate_labels() {
        let app = App::new_test();
        let text = stats_line(&app, "0 B", "0 B", 120).to_string();
        assert!(text.contains("UP:") && text.contains("DOWN:"), "{text}");
    }
}
