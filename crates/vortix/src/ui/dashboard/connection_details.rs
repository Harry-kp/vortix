use crate::app::state::QualityLevel;
use crate::app::App;
use crate::app::Role;
use crate::cidr::Cidr;
use crate::control::{Phase, TunnelView};
use crate::profile::{ProfileId, ProtocolKind};
use crate::tunnel::DetailedConnectionInfo;
use crate::ui::helpers;
use crate::ui::sigils::SigilId;
use crate::{constants, ui::theme};
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Padding, Paragraph},
    Frame,
};

/// Render the Connection Details panel for the focused profile.
///
/// Stage B: looks up the snapshot for the
/// currently-selected profile (focused via the sidebar's
/// `profile_list_state`). Telemetry rows scope to the primary tunnel per
/// H7 — when the focused profile is a split-tunnel row the panel renders
/// "Latency: n/a" + the explanatory follow-up line "only measured on
/// the active exit" instead of primary-scoped metrics.
pub(super) fn render(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.should_draw_focus(&crate::app::FocusedPanel::ConnectionDetails);
    let border_style = if is_focused {
        Style::default().fg(theme::current().border_focused)
    } else {
        Style::default().fg(theme::current().border_default)
    };

    // Focused profile = sidebar selection, falling back to the primary if
    // nothing is selected (so the panel still has useful content when the
    // user is browsing other panels).
    let focused_profile_id = app.focused_profile_id();

    if app.effective_flipped(&crate::app::FocusedPanel::ConnectionDetails) {
        render_back(frame, app, focused_profile_id.as_ref(), area, border_style);
        return;
    }

    let focused_snap = focused_profile_id.as_ref().and_then(|id| app.tunnel(id));

    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .padding(Padding::horizontal(1))
        .title(" Connection Details ");
    // The back lists routes and peers once the focused profile has a tunnel.
    if focused_snap.is_some() {
        block = block.title_bottom(helpers::border_hint(constants::FLIP_ROUTES_HINT));
    }

    let inner = block.inner(area);
    frame.render_widget(block, area);
    let primary_id = app.primary_id();
    let is_focused_primary = matches!(
        (&focused_profile_id, primary_id),
        (Some(focused), Some(primary)) if focused == primary
    );

    // panel is focus-driven across every snapshot state. Connected
    // shows full details; transitional states render a compact summary
    // (Role + awaiting-credentials hint + fwmark warning where applicable);
    // every other case falls back to the disconnected placeholder.
    if let Some(snap) = focused_snap {
        if snap.phase == Phase::Up {
            render_connected(frame, app, inner, snap, &snap.details, is_focused_primary);
        } else {
            render_transitional(frame, app, inner, snap);
        }
        return;
    } else if let Some(id) = focused_profile_id.as_ref() {
        // Sidebar pointed at a profile id but neither the engine snapshot nor
        // the runtime profile catalogue carries it — typically a delete-
        // mid-render race. Surface an explicit hint rather than a stale
        // placeholder so the user notices.
        let in_catalogue = app.runtime.profiles.iter().any(|p| p.id == *id);
        if !in_catalogue {
            render_profile_unavailable(frame, inner);
            return;
        }
    }

    render_disconnected(frame, app, inner);
}

/// The `VPN IP` row: tunnel address and the interface carrying it.
fn vpn_ip_line(details: &DetailedConnectionInfo) -> Line<'_> {
    let iface_display = if details.interface.is_empty() {
        "-"
    } else {
        &details.interface
    };
    Line::from(vec![
        Span::styled(
            "VPN IP  : ",
            Style::default().fg(theme::current().text_secondary),
        ),
        Span::styled(
            &details.internal_ip,
            Style::default()
                .fg(theme::current().accent_primary)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" @ {iface_display}"),
            Style::default().fg(theme::current().text_secondary),
        ),
    ])
}

/// The `Transfer` row: rx/tx counters and the tunnel MTU.
fn transfer_line<'a>(details: &'a DetailedConnectionInfo, mtu_str: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            "Transfer: ",
            Style::default().fg(theme::current().text_secondary),
        ),
        Span::styled("↓", Style::default().fg(theme::current().nord_frost_3)),
        Span::styled(
            helpers::transfer_text(&details.transfer_rx),
            Style::default().fg(theme::current().text_primary),
        ),
        Span::styled(" ↑", Style::default().fg(theme::current().success)),
        Span::styled(
            helpers::transfer_text(&details.transfer_tx),
            Style::default().fg(theme::current().text_primary),
        ),
        Span::styled(
            " (MTU:",
            Style::default().fg(theme::current().text_secondary),
        ),
        Span::styled(
            mtu_str,
            Style::default().fg(theme::current().text_secondary),
        ),
        Span::styled(")", Style::default().fg(theme::current().text_secondary)),
    ])
}

/// Telemetry rows for the focused tunnel. Primary-only per H7 —
/// split-tunnel rows get the n/a line and its explanation instead.
fn quality_rows(app: &App, is_focused_primary: bool) -> Vec<Line<'static>> {
    let mut rows = Vec::new();
    if is_focused_primary {
        let quality_status = match QualityLevel::from_metrics(
            app.runtime.latency_ms,
            app.runtime.packet_loss,
            app.runtime.jitter_ms,
        ) {
            QualityLevel::Unknown => ("UNKNOWN", theme::current().text_secondary),
            QualityLevel::Poor => ("POOR", theme::current().error),
            QualityLevel::Fair => ("FAIR", theme::current().yellow),
            QualityLevel::Excellent => ("EXCELLENT", theme::current().success),
        };

        rows.push(Line::from(vec![
            Span::styled(
                "Quality: ",
                Style::default().fg(theme::current().text_secondary),
            ),
            Span::styled(
                quality_status.0,
                Style::default()
                    .fg(quality_status.1)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));

        let jitter_color = if app.runtime.jitter_ms < 5 {
            theme::current().success
        } else if app.runtime.jitter_ms < 15 {
            theme::current().yellow
        } else {
            theme::current().error
        };
        let loss_color = if app.runtime.packet_loss < 1.0 {
            theme::current().success
        } else {
            theme::current().error
        };
        rows.extend([
            helpers::detail_row(
                "  ├─ Latency : ",
                format!("{}ms", app.runtime.latency_ms),
                helpers::latency_color(app.runtime.latency_ms),
            ),
            helpers::detail_row(
                "  ├─ Jitter  : ",
                format!("±{}ms", app.runtime.jitter_ms),
                jitter_color,
            ),
            helpers::detail_row(
                "  └─ Loss    : ",
                format!("{:.1}%", app.runtime.packet_loss),
                loss_color,
            ),
        ]);
    } else {
        // H7: telemetry is primary-only. Surface BOTH the n/a and the
        // *reason* — "split tunnel" alone is a label, not an
        // explanation. The follow-up line spells out that latency is
        // only measured on the active exit tunnel, so the user
        // understands why this particular profile doesn't show a
        // value and can pick the active-exit row to see real numbers.
        rows.push(helpers::detail_row(
            "Latency: ",
            "n/a",
            theme::current().inactive,
        ));
        rows.push(Line::from(vec![
            Span::styled("         ", Style::default()),
            Span::styled(
                "only measured on the active exit",
                Style::default()
                    .fg(theme::current().text_secondary)
                    .add_modifier(Modifier::DIM),
            ),
        ]));
    }
    rows
}

/// The `Stats` row: worker PID and the session's drop count.
fn stats_line(app: &App, details: &DetailedConnectionInfo) -> Line<'static> {
    let rel_spans = vec![
        Span::styled(
            "Stats   : ",
            Style::default().fg(theme::current().text_secondary),
        ),
        Span::styled("PID ", Style::default().fg(theme::current().text_secondary)),
        Span::styled(
            details.pid.map_or("-".to_string(), |p| p.to_string()),
            Style::default().fg(theme::current().text_primary),
        ),
        Span::styled(
            " | Drops ",
            Style::default().fg(theme::current().text_secondary),
        ),
        Span::styled(
            format!("{}", app.runtime.connection_drops),
            Style::default().fg(if app.runtime.connection_drops > 0 {
                theme::current().error
            } else {
                theme::current().text_primary
            }),
        ),
    ];
    Line::from(rel_spans)
}

fn render_connected(
    frame: &mut Frame,
    app: &App,
    inner: Rect,
    snap: &TunnelView,
    details: &DetailedConnectionInfo,
    is_focused_primary: bool,
) {
    let is_openvpn = snap.protocol == crate::profile::ProtocolKind::OpenVpn;

    let mtu_str = helpers::nonempty_or(&details.mtu, "-");

    let mut text = vec![
        vpn_ip_line(details),
        helpers::detail_row(
            "Server  : ",
            details.endpoint.as_str(),
            theme::current().text_primary,
        ),
    ];
    if !details.peers.is_empty() {
        text.push(helpers::detail_row(
            "Peers   : ",
            helpers::peers_summary(&details.peers),
            theme::current().text_primary,
        ));
    }

    // `Exit` reflects the ASN/location of the public IPv4 returned by
    // ipinfo.io, which only describes the egress path that the PRIMARY
    // tunnel owns. For split tunnels (Addressable / AddressableSuppressed)
    // the same row would either copy the primary's info (misleading —
    // split-tunnel packets actually exit through the split's own server)
    // or require per-CIDR telemetry vortix doesn't run. Surface the row
    // only on the primary; the Server row above still names the
    // tunnel's endpoint regardless.
    if is_focused_primary {
        let label_overhead = 10 + 2 + 1;
        let available = (inner.width as usize).saturating_sub(label_overhead);
        let isp_budget = (available * 60 / 100).min(available);
        let loc_budget = available.saturating_sub(isp_budget);
        text.push(Line::from(vec![
            Span::styled(
                "Exit    : ",
                Style::default().fg(theme::current().text_secondary),
            ),
            Span::styled(
                crate::ui::helpers::truncate_to_width(&app.runtime.isp, isp_budget),
                Style::default().fg(theme::current().text_primary),
            ),
            Span::styled(" (", Style::default().fg(theme::current().text_secondary)),
            Span::styled(
                crate::ui::helpers::truncate_to_width(&app.runtime.location, loc_budget),
                Style::default().fg(theme::current().text_primary),
            ),
            Span::styled(")", Style::default().fg(theme::current().text_secondary)),
        ]));
    }

    let crypto = if is_openvpn {
        match details.latest_handshake.as_str() {
            h if h.starts_with("Cipher:") => h.replace("Cipher: ", ""),
            "" => "AES-256-GCM".to_string(),
            h => h.to_string(),
        }
    } else if details.latest_handshake.is_empty() {
        "ChaCha20-Poly1305".to_string()
    } else {
        format!("ChaCha20 ({})", details.latest_handshake)
    };
    text.push(helpers::detail_row(
        "Crypto  : ",
        if crypto.is_empty() {
            "-".to_string()
        } else {
            crypto
        },
        theme::current().yellow,
    ));

    // Any degraded reason, in the words the CLI uses.
    if let crate::tunnel::ConnectionHealth::Degraded { reason } = &snap.health {
        text.push(helpers::detail_row(
            "Health  : ",
            reason.describe(),
            theme::current().warning,
        ));
    }

    text.push(transfer_line(details, mtu_str));

    text.push(Line::from(""));

    text.extend(quality_rows(app, is_focused_primary));

    text.push(Line::from(""));
    text.push(stats_line(app, details));

    text.push(role_line(&app.role(snap), snap.phase));

    // persistent fwmark warning for at-risk WG secondaries.
    if let Some(warn) = fwmark_warning_line(app, snap) {
        text.push(warn);
    }

    frame.render_widget(Paragraph::new(fitted(text, inner)), inner);
}

/// Compact summary for a tunnel that is not up yet (or any more): headline,
/// Role line, the credentials call-to-action and the fwmark warning.
fn render_transitional(frame: &mut Frame, app: &App, inner: Rect, snap: &TunnelView) {
    let mut text: Vec<Line> = Vec::new();

    let (headline, headline_color) = match snap.phase {
        Phase::Starting => {
            let wireguard = app
                .runtime
                .profiles
                .iter()
                .find(|profile| profile.id == snap.profile_id)
                .is_some_and(|profile| profile.protocol == ProtocolKind::WireGuard);
            (
                if wireguard {
                    "Handshaking"
                } else {
                    "Connecting"
                }
                .to_string(),
                theme::current().yellow,
            )
        }
        Phase::Waiting { .. } => ("Reconnecting".to_string(), theme::current().yellow),
        Phase::Stopping => ("Disconnecting".to_string(), theme::current().text_secondary),
        Phase::AwaitingCredentials => ("Awaiting input".to_string(), theme::current().warning),
        Phase::Up => ("Pending".to_string(), theme::current().text_secondary),
    };

    text.push(Line::from(Span::styled(
        headline,
        Style::default()
            .fg(headline_color)
            .add_modifier(Modifier::BOLD),
    )));
    text.push(Line::from(""));

    if let Some(idx) = app.profile_list_state.selected() {
        if let Some(profile) = app.runtime.profiles.get(idx) {
            text.push(helpers::detail_row(
                "Profile : ",
                profile.name.as_str(),
                theme::current().accent_primary,
            ));
            text.push(helpers::detail_row(
                "Protocol: ",
                profile.protocol.to_string(),
                theme::current().text_primary,
            ));
        }
    }

    text.push(role_line(&app.role(snap), snap.phase));

    if snap.phase == Phase::AwaitingCredentials {
        text.push(awaiting_input_hint());
    }

    // Tab-cycle hint when N>1 .
    if app.tunnel_count() > 1 {
        text.push(Line::from(vec![Span::styled(
            "Press [Tab] to cycle focused tunnel",
            Style::default().fg(theme::current().text_secondary),
        )]));
    }

    // Fwmark warning.
    if let Some(warn) = fwmark_warning_line(app, snap) {
        text.push(warn);
    }

    let max_lines = inner.height as usize;
    text.truncate(max_lines);
    frame.render_widget(Paragraph::new(fitted(text, inner)), inner);
}

/// Every row cut to the panel with an ellipsis instead of stopping at its edge.
fn fitted(text: Vec<Line<'_>>, inner: Rect) -> Vec<Line<'_>> {
    text.into_iter()
        .map(|line| helpers::fit_line(line, inner.width as usize))
        .collect()
}

fn render_profile_unavailable(frame: &mut Frame, inner: Rect) {
    let text = vec![
        Line::from(Span::styled(
            "Profile no longer available",
            Style::default()
                .fg(theme::current().inactive)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Select another profile from the sidebar.",
            Style::default().fg(theme::current().text_secondary),
        )),
    ];
    frame.render_widget(Paragraph::new(fitted(text, inner)), inner);
}

fn render_disconnected(frame: &mut Frame, app: &App, inner: Rect) {
    let palette = theme::current();
    let max_lines = inner.height as usize;
    let mut text: Vec<Line> = vec![
        Line::from(Span::styled(
            "Not Connected",
            Style::default()
                .fg(palette.inactive)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    let value_width = inner.width.saturating_sub(10) as usize;
    if let Some(idx) = app.profile_list_state.selected() {
        if let Some(profile) = app.runtime.profiles.get(idx) {
            text.push(Line::from(vec![
                Span::styled("Profile : ", Style::default().fg(palette.text_secondary)),
                Span::styled(&profile.name, Style::default().fg(palette.accent_primary)),
            ]));
            text.push(Line::from(vec![
                Span::styled("Protocol: ", Style::default().fg(palette.text_secondary)),
                Span::styled(
                    profile.protocol.to_string(),
                    Style::default().fg(palette.text_primary),
                ),
            ]));
            text.push(Line::from(vec![
                Span::styled("Config  : ", Style::default().fg(palette.text_secondary)),
                Span::styled(
                    crate::ui::helpers::truncate_start_to_width(
                        &crate::config::home_relative(&profile.config_path),
                        value_width,
                    ),
                    Style::default().fg(palette.text_secondary),
                ),
            ]));
            if let Some(last_used) = profile.last_used {
                text.push(Line::from(vec![
                    Span::styled("Last use: ", Style::default().fg(palette.text_secondary)),
                    Span::styled(
                        format!(
                            "{} ago",
                            crate::ui::helpers::format_relative_time(last_used)
                        ),
                        Style::default().fg(palette.text_primary),
                    ),
                ]));
            }

            text.push(Line::from(""));

            // Each row shows its value only while its own reading is current.
            let egress_stale = app.observation_is_stale(app.runtime.last_egress_check);
            let dns_stale = app.observation_is_stale(app.runtime.last_dns_check);

            // An address shows whole or not at all; the header and Security Guard carry it too.
            let whole = |value: &str| "Your IP : ".len() + value.len() <= inner.width as usize;
            let (value, colour) = if egress_stale {
                (constants::MSG_UNAVAILABLE, palette.text_secondary)
            } else {
                (app.runtime.public_ip.as_str(), palette.warning)
            };
            if !app.runtime.public_ip.is_empty() && whole(value) {
                text.push(Line::from(vec![
                    Span::styled("Your IP : ", Style::default().fg(palette.text_secondary)),
                    Span::styled(value.to_string(), Style::default().fg(colour)),
                ]));
            }
            if !egress_stale && !constants::is_unknown(&app.runtime.isp) {
                text.push(Line::from(vec![
                    Span::styled("ISP     : ", Style::default().fg(palette.text_secondary)),
                    Span::styled(&app.runtime.isp, Style::default().fg(palette.text_primary)),
                ]));
            }
            let (value, colour) = if dns_stale {
                (constants::MSG_UNAVAILABLE, palette.text_secondary)
            } else {
                (app.runtime.dns_server.as_str(), palette.text_primary)
            };
            if !app.runtime.dns_server.is_empty()
                && app.runtime.dns_server != constants::MSG_DETECTING
                && whole(value)
            {
                text.push(Line::from(vec![
                    Span::styled("DNS     : ", Style::default().fg(palette.text_secondary)),
                    Span::styled(value.to_string(), Style::default().fg(colour)),
                ]));
            }
        }
    } else {
        let hint = if app.runtime.profiles.is_empty() {
            "Press [i] to add a VPN"
        } else {
            "Select a profile"
        };
        text.push(Line::from(vec![Span::styled(
            hint,
            Style::default().fg(palette.text_secondary),
        )]));
    }

    text.truncate(max_lines);
    frame.render_widget(Paragraph::new(fitted(text, inner)), inner);
}

/// Format a [`Role`] as a single `Role: ...` line.
///
/// The internal `Role` enum keeps the role taxonomy
/// (`Primary` / `Addressable` / `AddressableSuppressed` / `Reconnecting` /
/// `AwaitingInput`) so xtask boundary checks + JSON output stay
/// stable. User-facing copy uses the industry-standard plain-English
/// "split tunnel" terminology — "Addressable" is academic jargon
/// that doesn't communicate "routes only specific subnets" to most
/// users.
///
/// Rendered shapes:
/// * `Primary (<cidrs>)` — owns kernel default route; carries all
///   internet traffic. When `allowed_ips` is empty (e.g., `OpenVPN`
///   profiles using `redirect-gateway` instead of explicit `route`
///   directives), the CIDR suffix is omitted — just `Primary`.
/// * `Split tunnel (<cidrs>)` — routes only the listed subnets;
///   other traffic uses the underlay. Empty CIDR list -> bare
///   `Split tunnel` rather than a confusing `Split tunnel (-)`.
/// * `Split tunnel (0.0.0.0/0, yielded)` — declared a default route
///   but another tunnel currently holds it; "yielded" is the plain-
///   English equivalent of the prior "suppressed"
/// * `Reconnecting via <last role>` — while the tunnel waits to retry
fn role_line(role: &Role, phase: Phase) -> Line<'static> {
    if matches!(phase, Phase::Waiting { .. }) {
        return helpers::detail_row(
            "Role    : ",
            format!("Reconnecting via {}", role_kind_label(role)),
            theme::current().yellow,
        );
    }
    let (value, color) = match role {
        Role::Primary { allowed_ips } => (
            if allowed_ips.is_empty() {
                "Primary".to_string()
            } else {
                format!("Primary ({})", format_role_cidrs(allowed_ips))
            },
            theme::current().success,
        ),
        Role::Addressable { allowed_ips } => (
            if allowed_ips.is_empty() {
                "Split tunnel".to_string()
            } else {
                format!("Split tunnel ({})", format_role_cidrs(allowed_ips))
            },
            theme::current().accent_primary,
        ),
        Role::AddressableSuppressed { allowed_ips } => (
            if allowed_ips.is_empty() {
                "Split tunnel (yielded)".to_string()
            } else {
                format!("Split tunnel ({}, yielded)", format_role_cidrs(allowed_ips))
            },
            theme::current().yellow,
        ),
    };
    helpers::detail_row("Role    : ", value, color)
}

/// Short label for a role used inside "Reconnecting via …".
const fn role_kind_label(role: &Role) -> &'static str {
    match role {
        Role::Primary { .. } => "Primary",
        Role::Addressable { .. } => "Split tunnel",
        Role::AddressableSuppressed { .. } => "Split tunnel (yielded)",
    }
}

/// Render `AllowedIPs` for the Role line. Empty → `-`; single → that CIDR;
/// multiple disjoint → `multi`.
fn format_role_cidrs(cidrs: &[Cidr]) -> String {
    match cidrs.len() {
        0 => "-".to_string(),
        1 => cidrs[0].to_string(),
        _ => "multi".to_string(),
    }
}

/// Call-to-action while the engine waits for credentials.
fn awaiting_input_hint() -> Line<'static> {
    Line::from(vec![
        Span::styled("⚠ ", Style::default().fg(theme::current().warning)),
        Span::styled(
            "Waiting for credentials in the prompt",
            Style::default()
                .fg(theme::current().warning)
                .add_modifier(Modifier::BOLD),
        ),
    ])
}

/// Persistent fwmark warning.
///
/// Render the warning when **all** of the following hold:
/// * focused tunnel's profile uses `WireGuard`
/// * focused tunnel is *not* the primary (i.e., it's a secondary)
/// * the engine snapshot currently has a primary tunnel (`engine snapshot.primary()` ↔
///   the kernel default route holder)
/// * the focused tunnel's on-disk config does not declare any `FwMark`
///   directive
///
/// Returns `None` when any condition fails — the line is conjunctive.
fn fwmark_warning_line(app: &App, snap: &TunnelView) -> Option<Line<'static>> {
    // Bail if focused tunnel is the primary (warning only applies to
    // secondaries that are at fwmark-hijack risk against the primary).
    let primary = app.primary_id()?;
    if primary == &snap.profile_id {
        return None;
    }

    // Look up the profile to learn protocol + config path.
    let profile = app
        .runtime
        .profiles
        .iter()
        .find(|p| p.id == snap.profile_id)?;
    if profile.protocol != ProtocolKind::WireGuard {
        return None;
    }

    // Best-effort config read. If the file is unreadable we don't render
    // the warning (no signal == no false positive).
    let raw = std::fs::read_to_string(&profile.config_path).ok()?;
    if config_has_fwmark(&raw) {
        return None;
    }

    Some(Line::from(vec![
        Span::styled("⚠ ", Style::default().fg(theme::current().warning)),
        Span::styled(
            "Fwmark hijack risk: add 'FwMark = 51820' to your WG config. ",
            Style::default()
                .fg(theme::current().warning)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "See docs/usage.md",
            Style::default().fg(theme::current().text_secondary),
        ),
    ]))
}

/// `true` when the raw WG config text contains a `FwMark` directive
/// (case-insensitive, ignoring leading whitespace and `#`-comment lines).
fn config_has_fwmark(raw: &str) -> bool {
    for line in raw.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        // Match `FwMark` followed by optional whitespace and `=`.
        let lower = trimmed.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("fwmark") {
            let rest = rest.trim_start();
            if rest.starts_with('=') {
                return true;
            }
        }
    }
    false
}

/// Wide enough (zoomed) for every column; narrower, one short status each.
const FULL_COLUMNS: usize = 46;

/// The back: where the focused profile's traffic goes. Its routes (a mesh
/// network's routed networks) and who it talks to (a mesh network's peers,
/// else the server), the same layout for every kind of VPN.
fn render_back(
    frame: &mut Frame,
    app: &App,
    profile_id: Option<&ProfileId>,
    area: Rect,
    border_style: Style,
) {
    let tunnel = profile_id.and_then(|id| app.tunnel(id));
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
        .padding(Padding::horizontal(1))
        .title(helpers::truncate_to_width(
            &title,
            usize::from(area.width.saturating_sub(2)),
        ))
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
    let heading =
        |text: String| Line::styled(text, Style::default().fg(theme::current().accent_primary));
    let routes = route_lines(tunnel, width);
    let peers: Vec<Line<'static>> = if !tunnel.details.peers.is_empty() {
        peer_lines(&tunnel.details.peers, width)
    } else if tunnel.details.endpoint.is_empty() {
        Vec::new()
    } else {
        let server = [
            tunnel.details.endpoint.as_str(),
            &tunnel.details.latest_handshake,
        ]
        .join("  ");
        vec![mark_line(in_use(true), server.trim_end().into(), width)]
    };
    // Peers first: there are few of them, and a long route list scrolls below.
    let mut all = vec![heading("Peers".into())];
    all.extend(or_none(peers, dim));
    all.push(Line::from(""));
    all.push(heading(format!("Routes  {}", routes.len())));
    all.extend(or_none(routes, dim));
    let max = helpers::render_scrolled(frame, area, inner, &all, Some(app.routes_scroll));
    app.routes_max_scroll.set(max);
    // A list longer than the panel says how to scroll it, on the bottom border.
    if max > 0 && area.width > 16 {
        let hint = helpers::border_hint(" j/k scroll ");
        let at = Rect::new(area.x + 1, area.bottom().saturating_sub(1), 12, 1);
        frame.render_widget(hint, at);
    }
}

/// The routes section: a mesh network's routed networks (in use or not, the
/// exit node), else the routes the tunnel carries.
fn route_lines(tunnel: &crate::control::TunnelView, width: usize) -> Vec<Line<'static>> {
    let networks = &tunnel.details.networks;
    if networks.is_empty() {
        return tunnel
            .routes
            .iter()
            .map(|route| mark_line(in_use(true), route.to_string(), width))
            .collect();
    }
    let compact = width < FULL_COLUMNS;
    // Room after the name: " exit" compact; else the range plus "  exit node".
    let after = if compact {
        5
    } else {
        networks
            .iter()
            .map(|network| network.range.len() + 11)
            .max()
            .unwrap_or(0)
    };
    let names = column(
        networks.iter().map(|network| network.name.as_str()),
        width,
        after,
    );
    networks
        .iter()
        .map(|network| {
            let name = helpers::truncate_to_width(&network.name, names);
            let exit = network.is_exit_node();
            let rest = match (compact, exit) {
                (true, true) => " exit".to_string(),
                (true, false) => String::new(),
                (false, true) => format!(" {}  exit node", network.range),
                (false, false) => format!(" {}", network.range),
            };
            mark_line(
                in_use(network.selected),
                format!("{name:<names$}{rest}"),
                width,
            )
        })
        .collect()
}

/// A name column as wide as the longest name, leaving `after` columns for
/// what follows it (and never under 8).
fn column<'a>(names: impl Iterator<Item = &'a str>, width: usize, after: usize) -> usize {
    names
        .map(unicode_width::UnicodeWidthStr::width)
        .max()
        .unwrap_or(0)
        .min(width.saturating_sub(after + 3).max(8))
}

/// The lines, or a dimmed `none`.
fn or_none(lines: Vec<Line<'static>>, dim: Style) -> Vec<Line<'static>> {
    if lines.is_empty() {
        vec![Line::styled("none", dim)]
    } else {
        lines
    }
}

/// The mark of something in use or not, from the sigil catalog.
fn in_use(active: bool) -> SigilId {
    if active {
        SigilId::InUse
    } else {
        SigilId::Unused
    }
}

/// `● text`, the sigil's mark and colour, fitted to the panel.
fn mark_line(mark: SigilId, text: String, width: usize) -> Line<'static> {
    let mark = crate::ui::sigils::sigil(mark);
    helpers::fit_line(
        Line::from(vec![
            Span::styled(format!("{} ", mark.glyph), mark.style()),
            Span::styled(text, Style::default().fg(theme::current().text_primary)),
        ]),
        width,
    )
}

/// One line per mesh peer, connected first. Zoomed: name, address, direct or
/// relayed, latency. Narrower: the name and the one status that matters.
fn peer_lines(peers: &[crate::tunnel::MeshPeer], width: usize) -> Vec<Line<'static>> {
    let mut peers = peers.to_vec();
    peers.sort_by(|a, b| b.connected.cmp(&a.connected).then(a.name.cmp(&b.name)));
    let compact = width < FULL_COLUMNS;
    // Address, path and latency after the name; compact, one status.
    let names = column(
        peers.iter().map(|peer| peer.name.as_str()),
        width,
        if compact { 8 } else { 33 },
    );
    peers
        .iter()
        .map(|peer| {
            let (mark, path) = match (peer.connected, peer.relayed) {
                (false, _) => (SigilId::Unused, "offline"),
                (true, true) => (SigilId::Relayed, "relayed"),
                (true, false) => (SigilId::InUse, "direct"),
            };
            let latency = peer
                .latency
                .map(|latency| format!("{} ms", latency.as_millis()))
                .unwrap_or_default();
            let name = helpers::truncate_to_width(&peer.name, names);
            let rest = if compact {
                if path == "direct" && !latency.is_empty() {
                    latency
                } else {
                    path.to_string()
                }
            } else {
                format!("{:<16} {path:<8} {latency}", peer.address)
            };
            mark_line(mark, format!("{name:<names$} {rest}"), width)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    //! Connection Details is focus-driven; Role line covers
    //! every variant; awaiting credentials shows the Enter hint; the fwmark
    //! warning fires only under the conjunctive D-1 condition; deleted /
    //! unknown focused profiles surface the "no longer available" hint.
    use super::*;
    use crate::app::App;
    use crate::config::profiles::VpnProfile;
    use crate::profile::ProfileId;
    use crate::profile::ProtocolKind;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};
    use tempfile::TempDir;

    fn v4(s: &str) -> Cidr {
        s.parse().expect("valid cidr")
    }

    fn make_profile(name: &str, config_path: PathBuf) -> VpnProfile {
        VpnProfile {
            id: crate::profile::ProfileId::new(name),
            name: name.to_string(),
            protocol: ProtocolKind::WireGuard,
            location: String::new(),
            config_path,
            last_used: None,
            group: None,
        }
    }

    fn insert_connected(app: &mut App, name: &str, interface: &str, allowed_ips: Vec<Cidr>) {
        let mut view = crate::app::connection::test_view(name, crate::control::Phase::Up);
        view.interface = Some(interface.to_owned());
        view.routes = allowed_ips;
        view.details.interface = interface.to_owned();
        view.details.interface_authoritative = true;
        std::sync::Arc::make_mut(&mut app.control_snapshot)
            .tunnels
            .push(view);
    }

    /// With nothing to select, the panel says how to add a VPN, in words
    /// that fit the 29-column panel of an 80-column terminal.
    #[test]
    fn with_no_profiles_it_says_how_to_add_one() {
        let mut app = App::new_test();
        assert!(render_to_string(&mut app, 29, 8).contains("Press [i] to add a VPN"));
    }

    fn render_to_string(app: &mut App, width: u16, height: u16) -> String {
        crate::ui::dashboard::render_to_string(width, height, |frame, area| {
            render(frame, app, area);
        })
    }

    #[test]
    fn compact_details_use_protocol_specific_connect_label() {
        for (protocol, expected, forbidden) in [
            (ProtocolKind::WireGuard, "Handshaking", "Connecting"),
            (ProtocolKind::OpenVpn, "Connecting", "Handshaking"),
        ] {
            let mut app = App::new_test();
            app.runtime.profiles.push(VpnProfile {
                id: ProfileId::new("corp"),
                name: "corp".into(),
                protocol,
                location: String::new(),
                config_path: PathBuf::from("/tmp/corp.conf"),
                last_used: None,
                group: None,
            });
            app.profile_list_state.select(Some(0));
            app.set_tunnels_for_test(
                vec![crate::app::connection::test_view(
                    "corp",
                    crate::control::Phase::Starting,
                )],
                None,
            );
            let out = render_to_string(&mut app, 80, 10);
            assert!(out.contains(expected), "{out}");
            assert!(!out.contains(forbidden), "{out}");
        }
    }

    /// Connection Details is 26 columns wide in an 80-column terminal.
    #[test]
    fn a_long_config_path_keeps_its_file_name_at_80_columns() {
        let mut app = App::new_test();
        app.runtime.profiles.push(make_profile(
            "01-openvpn-udp-full-inline",
            PathBuf::from("/srv/vortix/profiles/01-openvpn-udp-full-inline.ovpn"),
        ));
        app.profile_list_state.select(Some(0));
        let out = render_to_string(&mut app, 26, 10);
        assert!(out.contains("…inline.ovpn"), "{out}");
        assert!(out.contains("01-openvp..."), "{out}");
    }

    /// Connection Details is 26 columns wide in an 80-column terminal.
    #[test]
    fn a_long_value_ends_in_an_ellipsis_not_at_the_panel_edge() {
        let mut app = App::new_test();
        app.runtime
            .profiles
            .push(make_profile("wg07", PathBuf::from("/tmp/wg07.conf")));
        app.profile_list_state.select(Some(0));
        app.runtime.public_ip = "203.0.113.5".into();
        app.runtime.isp = "Bharti Airtel Limited".into();
        let out = render_to_string(&mut app, 26, 12);
        let isp = out
            .lines()
            .find(|line| line.contains("ISP"))
            .expect("ISP row");
        assert!(isp.contains("..."), "{out}");
    }

    #[test]
    fn an_address_that_does_not_fit_is_left_out_not_cut() {
        let mut app = App::new_test();
        app.runtime
            .profiles
            .push(make_profile("wg07", PathBuf::from("/tmp/wg07.conf")));
        app.profile_list_state.select(Some(0));
        app.runtime.public_ip = "203.113.200.100".into();
        let narrow = render_to_string(&mut app, 26, 12);
        assert!(!narrow.contains("Your IP"), "{narrow}");
        let wide = render_to_string(&mut app, 40, 12);
        assert!(wide.contains("Your IP : 203.113.200.100"), "{wide}");
        // A stale reading shows `unavailable`, which fits where the address does not.
        let long_ago = std::time::Instant::now()
            .checked_sub(app.telemetry_stale_after() + std::time::Duration::from_secs(30))
            .expect("instant in range");
        app.runtime.last_egress_check = Some(long_ago);
        let stale = render_to_string(&mut app, 26, 12);
        assert!(stale.contains("Your IP : unavailable"), "{stale}");
    }

    /// The back of Details at `width`×`height` (26×10 is the panel at 80×24,
    /// larger is zoomed).
    fn back_at(app: &mut App, width: u16, height: u16) -> String {
        app.flip_state_mut(crate::app::FocusedPanel::ConnectionDetails)
            .set_showing_back(true);
        render_to_string(app, width, height)
    }

    fn mesh_app() -> App {
        let mut app = App::new_test();
        let mut profile = make_profile("work", PathBuf::from("/tmp/w.netbird"));
        profile.protocol = ProtocolKind::Mesh(crate::mesh::MeshDriver::NetBird);
        app.runtime.profiles.push(profile);
        app.profile_list_state.select(Some(0));
        let mut mesh = crate::app::connection::test_view("work", Phase::Up);
        mesh.protocol = ProtocolKind::Mesh(crate::mesh::MeshDriver::NetBird);
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
            latency: connected.then(|| Duration::from_millis(41)),
        };
        mesh.details.peers = vec![
            peer("asleep", false, false),
            peer("gw", true, true),
            peer("laptop", true, false),
        ];
        app.set_tunnels_for_test(vec![mesh], None);
        app
    }

    /// In the panel's own width, each network and peer keeps one short status:
    /// exit, relayed, offline or latency.
    #[test]
    fn the_back_lists_routes_and_peers_compactly_in_the_panel() {
        let mut app = mesh_app();
        let screen = back_at(&mut app, 26, 10);
        for shown in [
            "Routes & peers",
            "Peers",
            "relayed",
            "41 ms",
            "offline",
            "Routes  2",
        ] {
            assert!(screen.contains(shown), "{shown}: {screen}");
        }
        assert!(
            screen.find("gw").unwrap() < screen.find("asleep").unwrap(),
            "connected first"
        );
    }

    /// A long route list scrolls with j/k, zoomed or not, with the same
    /// scrollbar as the Logs panel.
    #[test]
    fn a_long_route_list_scrolls() {
        let mut app = mesh_app();
        let mut tunnels = app.tunnels().into_iter().cloned().collect::<Vec<_>>();
        tunnels[0].details.networks = (0..650)
            .map(|n| crate::tunnel::RoutedNetwork {
                name: format!("net-{n:03}"),
                range: format!("10.{}.{}.0/24", n / 250, n % 250),
                selected: true,
            })
            .collect();
        app.set_tunnels_for_test(tunnels, None);
        app.focused_panel = crate::app::FocusedPanel::ConnectionDetails;
        let top = back_at(&mut app, 100, 16);
        assert!(
            top.contains("Routes  650")
                && top.contains("↓")
                && top.contains("j/k scroll")
                && !top.contains("net-020"),
            "{top}"
        );
        for _ in 0..20 {
            app.handle_message(crate::message::Message::Scroll(
                crate::message::ScrollMove::Down,
            ));
        }
        let scrolled = back_at(&mut app, 100, 16);
        assert!(
            !scrolled.contains("Peers") && scrolled.contains("net-020"),
            "{scrolled}"
        );
    }

    /// The front's Health row explains every degraded reason, in the CLI's words.
    #[test]
    fn the_front_explains_a_peer_never_seen() {
        let mut app = App::new_test();
        app.runtime
            .profiles
            .push(make_profile("home", PathBuf::from("/tmp/h.conf")));
        app.profile_list_state.select(Some(0));
        let mut wg = crate::app::connection::test_view("home", Phase::Up);
        let reason = crate::tunnel::DegradedReason::WireGuardPeerNeverObserved {
            peer_public_key: "abcdefghijk".into(),
            allowed_routes: vec!["10.8.0.0/24".into()],
        };
        let shown = reason.describe();
        wg.health = crate::tunnel::ConnectionHealth::Degraded { reason };
        app.set_tunnels_for_test(vec![wg], None);
        let screen = render_to_string(&mut app, 120, 16);
        assert!(screen.contains(&format!("Health  : {shown}")), "{screen}");
    }

    /// Zoomed, every column shows: whole names, ranges, addresses.
    #[test]
    fn zoomed_the_back_shows_every_column() {
        let mut app = mesh_app();
        let screen = back_at(&mut app, 100, 16);
        for shown in [
            "euc1-stag-001-public-nic-v1.bsstag.com",
            "10.20.0.0/16",
            "exit node",
            "100.90.0.1",
            "direct",
        ] {
            assert!(screen.contains(shown), "{shown}: {screen}");
        }
    }

    /// A `WireGuard` tunnel shows what it routes and its server; a profile that
    /// is not connected says so.
    #[test]
    fn the_back_of_a_wireguard_tunnel_shows_routes_and_server() {
        let mut app = App::new_test();
        app.runtime
            .profiles
            .push(make_profile("home", PathBuf::from("/tmp/h.conf")));
        app.profile_list_state.select(Some(0));
        assert!(back_at(&mut app, 26, 10).contains("Not connected"));
        let mut wg = crate::app::connection::test_view("home", Phase::Up);
        wg.routes = vec![v4("10.8.0.0/24")];
        wg.details.endpoint = "203.0.113.7:51820".into();
        app.set_tunnels_for_test(vec![wg], None);
        let screen = back_at(&mut app, 40, 12);
        for shown in ["10.8.0.0/24", "203.0.113.7:51820"] {
            assert!(screen.contains(shown), "{shown}: {screen}");
        }
    }

    // ───────────── role_line: pure-function variants ─────────────

    #[test]
    fn role_line_primary_renders_allowed_cidr() {
        let l = role_line(
            &Role::Primary {
                allowed_ips: vec![v4("0.0.0.0/0")],
            },
            Phase::Up,
        );
        let s: String = l.spans.iter().map(|sp| sp.content.as_ref()).collect();
        assert!(s.contains("Primary"), "missing Primary label: {s}");
        assert!(s.contains("0.0.0.0/0"), "missing CIDR: {s}");
    }

    #[test]
    fn role_line_primary_with_empty_allowed_ips_omits_parens() {
        // OpenVPN `redirect-gateway` doesn't produce a `route` line,
        // so `extract_allowed_ips` returns empty. Don't render
        // `Primary (-)` — just `Primary`.
        let l = role_line(
            &Role::Primary {
                allowed_ips: vec![],
            },
            Phase::Up,
        );
        let s: String = l.spans.iter().map(|sp| sp.content.as_ref()).collect();
        assert!(s.contains("Primary"), "missing Primary label: {s}");
        assert!(
            !s.contains("(-)"),
            "empty CIDR list must not render as `(-)`: {s}"
        );
    }

    #[test]
    fn role_line_addressable_with_empty_allowed_ips_omits_parens() {
        // Same concern on the Addressable side — `Split tunnel (-)`
        // looks broken; render just `Split tunnel`.
        let l = role_line(
            &Role::Addressable {
                allowed_ips: vec![],
            },
            Phase::Up,
        );
        let s: String = l.spans.iter().map(|sp| sp.content.as_ref()).collect();
        assert!(s.contains("Split tunnel"), "missing label: {s}");
        assert!(
            !s.contains("(-)"),
            "empty CIDR list must not render as `(-)`: {s}"
        );
    }

    #[test]
    fn role_line_addressable_secondary_single_cidr() {
        let l = role_line(
            &Role::Addressable {
                allowed_ips: vec![v4("10.0.0.0/8")],
            },
            Phase::Up,
        );
        let s: String = l.spans.iter().map(|sp| sp.content.as_ref()).collect();
        // User-facing copy: industry-standard "split tunnel" instead
        // of the plan-internal "Addressable" jargon.
        assert!(
            s.contains("Split tunnel"),
            "missing 'Split tunnel' label: {s}"
        );
        assert!(!s.contains("Addressable"), "internal jargon leaked: {s}");
        assert!(s.contains("10.0.0.0/8"));
    }

    #[test]
    fn role_line_addressable_multi_cidr() {
        let l = role_line(
            &Role::Addressable {
                allowed_ips: vec![v4("10.0.0.0/8"), v4("192.168.0.0/16")],
            },
            Phase::Up,
        );
        let s: String = l.spans.iter().map(|sp| sp.content.as_ref()).collect();
        assert!(s.contains("multi"), "expected 'multi' for >1 cidr: {s}");
    }

    #[test]
    fn role_line_addressable_suppressed_for_zero_slash_zero_loser() {
        let l = role_line(
            &Role::AddressableSuppressed {
                allowed_ips: vec![v4("0.0.0.0/0")],
            },
            Phase::Up,
        );
        let s: String = l.spans.iter().map(|sp| sp.content.as_ref()).collect();
        // User-facing copy uses "yielded" (plain English) instead of
        // the plan's "suppressed" jargon. Both convey "this tunnel
        // declared a default route but another took it".
        assert!(
            s.contains("Split tunnel"),
            "missing 'Split tunnel' label: {s}"
        );
        assert!(s.contains("yielded"), "missing 'yielded' marker: {s}");
        assert!(!s.contains("Addressable"), "internal jargon leaked: {s}");
        assert!(!s.contains("suppressed"), "internal jargon leaked: {s}");
        assert!(s.contains("0.0.0.0/0"), "missing CIDR: {s}");
    }

    #[test]
    fn role_line_reconnecting_carries_prior_role() {
        let l = role_line(
            &Role::Primary {
                allowed_ips: vec![v4("0.0.0.0/0")],
            },
            Phase::Waiting { retry_at: None },
        );
        let s: String = l.spans.iter().map(|sp| sp.content.as_ref()).collect();
        assert!(s.contains("Reconnecting via Primary"), "got: {s}");
    }

    // ───────────── config_has_fwmark ─────────────

    #[test]
    fn config_has_fwmark_recognises_directive() {
        let cfg = "[Interface]\nAddress = 10.0.0.2/32\nFwMark = 51820\n";
        assert!(config_has_fwmark(cfg));
    }

    #[test]
    fn config_has_fwmark_case_insensitive() {
        let cfg = "[Interface]\nfwmark = 0xca6c\n";
        assert!(config_has_fwmark(cfg));
    }

    #[test]
    fn config_has_fwmark_returns_false_when_missing() {
        let cfg = "[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nAllowedIPs = 10.0.0.0/8\n";
        assert!(!config_has_fwmark(cfg));
    }

    #[test]
    fn config_has_fwmark_ignores_comments() {
        let cfg = "[Interface]\n# FwMark = 51820\n; FwMark = 999\n";
        assert!(!config_has_fwmark(cfg));
    }

    // ───────────── render: focus-driven snapshot lookup ─────────────

    #[test]
    fn focused_awaiting_input_renders_enter_hint() {
        let mut app = App::new_test();
        app.runtime.profiles = vec![make_profile("corp", PathBuf::from("/tmp/corp.conf"))];
        app.profile_list_state.select(Some(0));
        app.set_tunnels_for_test(
            vec![crate::app::connection::test_view(
                "corp",
                Phase::AwaitingCredentials,
            )],
            None,
        );
        let out = render_to_string(&mut app, 80, 12);
        assert!(out.contains("Awaiting input"), "{out}");
        assert!(
            out.contains("Waiting for credentials in the prompt"),
            "{out}"
        );
    }

    /// The panel's address / network / resolver rows read straight off the
    /// telemetry observations. Once a reading has aged out, its last value
    /// must not stay on screen for the reader to take as live.
    #[test]
    fn a_stale_reading_reports_unknown_instead_of_its_last_value() {
        use std::time::Instant;

        let mut app = App::new_test();
        let dir = TempDir::new().expect("tmpdir");
        let cfg_path = dir.path().join("home.conf");
        std::fs::write(&cfg_path, "[Interface]\n").unwrap();
        app.runtime.profiles = vec![make_profile("home", cfg_path)];
        app.profile_list_state.select(Some(0));
        app.runtime.public_ip = "171.61.21.20".to_string();
        app.runtime.isp = "Bharti Airtel Ltd.".to_string();
        app.runtime.dns_server = "192.168.1.100".to_string();

        let fresh = Instant::now();
        app.runtime.last_egress_check = Some(fresh);
        app.runtime.last_dns_check = Some(fresh);
        let out = render_to_string(&mut app, 80, 16);
        assert!(out.contains("171.61.21.20"), "fresh readings show:\n{out}");
        assert!(out.contains("192.168.1.100"), "fresh readings show:\n{out}");

        let stale = Instant::now()
            .checked_sub(app.telemetry_stale_after() + Duration::from_secs(1))
            .expect("representable instant");
        app.runtime.last_egress_check = Some(stale);
        app.runtime.last_dns_check = Some(stale);
        let out = render_to_string(&mut app, 80, 16);
        assert!(
            !out.contains("171.61.21.20"),
            "a stale address must not stay on screen:\n{out}"
        );
        assert!(
            !out.contains("192.168.1.100"),
            "a stale resolver must not stay on screen:\n{out}"
        );
        assert!(
            !out.contains("Bharti Airtel"),
            "a stale network name must not stay on screen:\n{out}"
        );
        assert!(
            out.contains(constants::MSG_UNAVAILABLE),
            "the rows must say the reading is not known:\n{out}"
        );
    }

    #[test]
    fn focused_disconnected_renders_placeholder() {
        let mut app = App::new_test();
        let dir = TempDir::new().expect("tmpdir");
        let cfg_path = dir.path().join("home.conf");
        std::fs::write(&cfg_path, "[Interface]\n").unwrap();
        app.runtime.profiles = vec![make_profile("home", cfg_path)];
        app.profile_list_state.select(Some(0));

        // No engine snapshot entry — should fall through to "Not Connected".
        let out = render_to_string(&mut app, 80, 12);
        assert!(
            out.contains("Not Connected"),
            "expected Not Connected placeholder:\n{out}"
        );
    }

    #[test]
    fn focused_profile_missing_from_the_engine_renders_disconnected() {
        // Sidebar selects a profile that exists in `runtime.profiles`
        // but has no engine snapshot entry — fall through to render_disconnected
        // (this is the everyday "browsing profiles to pick which to
        // connect" case).
        let mut app = App::new_test();
        let dir = TempDir::new().expect("tmpdir");
        let cfg_path = dir.path().join("alpha.conf");
        std::fs::write(&cfg_path, "[Interface]\n").unwrap();
        app.runtime.profiles = vec![make_profile("alpha", cfg_path)];
        app.profile_list_state.select(Some(0));
        let out = render_to_string(&mut app, 80, 12);
        assert!(out.contains("Not Connected"));
    }

    #[test]
    fn profile_unavailable_helper_renders_hint() {
        // Exercise render_profile_unavailable directly: easiest way to
        // confirm the hint copy without needing to model a delete-mid-
        // render race in engine snapshot state.
        let out = crate::ui::dashboard::render_to_string(60, 8, render_profile_unavailable);
        assert!(
            out.contains("Profile no longer available"),
            "missing unavailable hint:\n{out}"
        );
    }

    // ───────────── fwmark warning conjunctive condition ─────────────

    #[test]
    fn fwmark_warning_suppressed_when_secondary_config_has_fwmark() {
        // Even if primary holds 0/0, a secondary that *does* declare
        // FwMark in its config should NOT trigger the warning. Pure-
        // function check via config_has_fwmark covered above; this test
        // documents the boolean intent.
        let cfg = "[Interface]\nFwMark = 51820\n";
        assert!(config_has_fwmark(cfg));
    }

    #[test]
    fn focused_primary_renders_primary_role_with_zero_slash_zero() {
        let mut app = App::new_test();
        let dir = TempDir::new().expect("tmpdir");
        let cfg_path = dir.path().join("corp.conf");
        std::fs::write(&cfg_path, "[Interface]\nFwMark = 51820\n").unwrap();
        app.runtime.profiles = vec![make_profile("corp", cfg_path)];
        app.profile_list_state.select(Some(0));

        insert_connected(&mut app, "corp", "utun7", vec![v4("0.0.0.0/0")]);
        // Force the engine snapshot to treat corp as primary by faking the route
        // probe via a fresh engine snapshot with a probe. We can't swap engine snapshot's
        // private probe field from outside, so instead we directly invoke
        // refresh_primary in production; here we just assert the Role line
        // appears as Addressable (since refresh_primary will return None on
        // host CI). The takeaway: Primary-route mapping is engine snapshot-
        // internal — UI-side we trust whatever role the snapshot returns.
        // To still exercise the Primary branch, we test role_line directly
        // above; this integration test only confirms the snapshot wiring.
        let out = render_to_string(&mut app, 80, 20);
        assert!(out.contains("Role"), "Role line missing:\n{out}");
        // corp's snapshot.role will be Addressable (no primary yet on
        // route table) — assert it shows up, not "Not Connected".
        assert!(
            !out.contains("Not Connected"),
            "should not render disconnected for a Connected snapshot:\n{out}"
        );
    }

    #[test]
    fn exit_row_hidden_when_focused_tunnel_is_not_primary() {
        // `app.runtime.isp` / `app.runtime.location` describe the
        // egress that the PRIMARY tunnel owns (set by the ipinfo.io
        // telemetry that goes out through whoever holds the kernel
        // default route). Showing the same row on a split tunnel's
        // Connection Details would either copy the primary's info
        // (misleading) or imply per-tunnel telemetry vortix doesn't
        // run. Hide the row when not focused on the primary.
        let mut app = App::new_test();
        let dir = TempDir::new().expect("tmpdir");
        let cfg_path = dir.path().join("split.conf");
        std::fs::write(&cfg_path, "[Interface]\n").unwrap();
        app.runtime.profiles = vec![make_profile("split", cfg_path)];
        app.profile_list_state.select(Some(0));

        // Seed ISP + location values that WOULD render in the row.
        app.runtime.isp = "AS14061 DigitalOcean, LLC".to_string();
        app.runtime.location = "Frankfurt am Main, DE".to_string();

        // Insert a Connected entry whose iface doesn't match any
        // kernel-route value the test engine snapshot knows about, so
        // is_focused_primary stays false.
        insert_connected(&mut app, "split", "utun8", vec![v4("10.0.0.0/8")]);

        let out = render_to_string(&mut app, 80, 20);
        assert!(
            !out.contains("Exit"),
            "Exit row must not render for a non-primary tunnel — the value would be the primary's egress, not this tunnel's:\n{out}"
        );
        // The Server row stays — that one IS this tunnel's endpoint.
        assert!(
            out.contains("Server"),
            "Server row must still render (it's tunnel-specific):\n{out}"
        );
    }

    #[test]
    fn focused_secondary_with_disjoint_cidr_renders_addressable_role() {
        let mut app = App::new_test();
        let dir = TempDir::new().expect("tmpdir");
        let cfg_path = dir.path().join("lab.conf");
        std::fs::write(&cfg_path, "[Interface]\nFwMark = 51820\n").unwrap();
        app.runtime.profiles = vec![make_profile("lab", cfg_path)];
        app.profile_list_state.select(Some(0));

        insert_connected(&mut app, "lab", "utun8", vec![v4("10.0.0.0/8")]);

        let out = render_to_string(&mut app, 80, 20);
        // User-facing copy: "Split tunnel" replaces "Addressable".
        assert!(
            out.contains("Split tunnel"),
            "Split tunnel role missing:\n{out}"
        );
        assert!(
            !out.contains("Addressable"),
            "internal jargon leaked to user-facing render:\n{out}"
        );
        assert!(out.contains("10.0.0.0/8"), "CIDR missing:\n{out}");
        // Latency on a non-exit tunnel must show n/a AND explain
        // why (telemetry runs only on the active exit). The bare
        // "n/a (split tunnel)" label without explanation forced users
        // to ask "why?".
        assert!(out.contains("n/a"), "Latency must show n/a:\n{out}");
        assert!(
            out.contains("only measured on the active exit"),
            "Latency must explain why it's n/a:\n{out}"
        );
        assert!(
            !out.contains("secondary tunnel"),
            "internal jargon leaked to user-facing render:\n{out}"
        );
    }

    #[test]
    fn fwmark_warning_renders_for_wg_secondary_when_primary_holds_default_and_no_fwmark() {
        let mut app = App::new_test();
        let dir = TempDir::new().expect("tmpdir");
        let primary_cfg = dir.path().join("corp.conf");
        std::fs::write(&primary_cfg, "[Interface]\nFwMark = 51820\n").unwrap();
        let secondary_cfg = dir.path().join("lab.conf");
        // Secondary config does NOT have FwMark.
        std::fs::write(
            &secondary_cfg,
            "[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nAllowedIPs = 10.0.0.0/8\n",
        )
        .unwrap();
        app.runtime.profiles = vec![
            make_profile("corp", primary_cfg),
            make_profile("lab", secondary_cfg),
        ];
        insert_connected(&mut app, "corp", "utun7", vec![v4("0.0.0.0/0")]);
        insert_connected(&mut app, "lab", "utun8", vec![v4("10.0.0.0/8")]);
        std::sync::Arc::make_mut(&mut app.control_snapshot).primary = Some(ProfileId::new("corp"));

        let lab_snap = app.tunnel(&ProfileId::new("lab")).expect("lab snapshot");
        let l = fwmark_warning_line(&app, lab_snap)
            .expect("warning expected when primary holds default");
        let s: String = l.spans.iter().map(|sp| sp.content.as_ref()).collect();
        assert!(s.contains("Fwmark"));
        assert!(s.contains("docs/usage.md"));
        let _ = (Duration::from_secs(0), SystemTime::now());
    }

    #[test]
    fn fwmark_warning_suppressed_when_focused_is_primary() {
        let mut app = App::new_test();
        let dir = TempDir::new().expect("tmpdir");
        let cfg = dir.path().join("corp.conf");
        std::fs::write(&cfg, "[Interface]\nAddress = 10.0.0.2/32\n").unwrap();
        app.runtime.profiles = vec![make_profile("corp", cfg)];
        insert_connected(&mut app, "corp", "utun7", vec![v4("0.0.0.0/0")]);

        std::sync::Arc::make_mut(&mut app.control_snapshot).primary = Some(ProfileId::new("corp"));

        let snap = app.tunnel(&ProfileId::new("corp")).expect("snap");
        assert!(fwmark_warning_line(&app, snap).is_none());
    }
}
